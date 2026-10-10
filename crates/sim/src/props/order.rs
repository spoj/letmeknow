//! Kinds get positions in log order; chat may pass a gap and show the passed position late.

use std::collections::{BTreeMap, BTreeSet};

use lmk_proto::Bytes;

use super::short;
use crate::trace::{Trace, Verdict, What};

const CHAT: &str = lmk_proto::group::CHAT;
const OWN: &str = "own chat";

/// What a member has counted, opened (with its kind, its own chat messages apart, which chat does not show) and lost.
#[derive(Default)]
struct Member<'a> {
    keys: BTreeMap<&'a Bytes, &'a Bytes>,
    counted: BTreeSet<(&'a Bytes, u64)>,
    opened: BTreeMap<(&'a Bytes, u64), &'a str>,
    lost: BTreeSet<(&'a Bytes, u64)>,
    /// Positions chat passed over, in any session.
    passed: BTreeSet<(&'a Bytes, u64)>,
    /// This session's: the last position handed to each kind, the positions chat showed, and the highest.
    handed: BTreeMap<(&'a Bytes, &'a str), u64>,
    shown: BTreeSet<(&'a Bytes, u64)>,
    top: BTreeMap<&'a Bytes, u64>,
}

impl Member<'_> {
    /// The counted positions strictly between two, that are neither opened as another kind nor lost.
    fn gaps<'b>(&'b self, group: &'b Bytes, from: u64, to: u64, kind: &'b str) -> impl Iterator<Item = u64> + 'b {
        self.counted
            .range((group, from + 1)..(group, to))
            .map(|(_, p)| *p)
            .filter(move |p| self.opened.get(&(group, *p)).is_none_or(|k| *k == kind) && !self.lost.contains(&(group, *p)))
    }
}

/// Within a session, a kind other than chat is handed positions in increasing order, each after every counted position
/// before it was opened as another kind or lost; chat shows each position once, in increasing order but for those it
/// passed over (`missing`) before, and passes over nothing it does not name but the member's own messages.
pub fn kind_order(t: &Trace) -> Result<(), String> {
    let mut members: BTreeMap<usize, Member> = BTreeMap::new();
    for o in &t.0 {
        let when = super::clock(o.at);
        match &o.what {
            What::Up { m } | What::Down { m } => {
                let s = members.entry(*m).or_default();
                s.handed.clear();
                s.shown.clear();
                s.top.clear();
            }
            What::Read { m, group, position, verdict: Verdict::Counted { .. }, .. } => drop(members.entry(*m).or_default().counted.insert((group, *position))),
            What::Roster { m, key, group, .. } => drop(members.entry(*m).or_default().keys.insert(group, key)),
            What::Opened { m, group, position, kind, sender, .. } => {
                let s = members.entry(*m).or_default();
                let own = kind == CHAT && s.keys.get(group) == Some(&sender);
                s.opened.insert((group, *position), if own { OWN } else { kind });
            }
            What::Lost { m, group, positions } => members.entry(*m).or_default().lost.extend(positions.iter().map(|p| (group, *p))),
            What::Handed { m, group, kind, position } => {
                let s = members.entry(*m).or_default();
                if let Some(&last) = s.handed.get(&(group, kind.as_str())) {
                    if *position <= last {
                        return Err(format!("m{m}'s {kind} was handed {position} of {} after {last}, at {when}", short(group)));
                    }
                    if let Some(gap) = s.gaps(group, last, *position, kind).next() {
                        return Err(format!("m{m}'s {kind} was handed {position} of {} past {gap}, neither taken nor lost, at {when}", short(group)));
                    }
                }
                s.handed.insert((group, kind), *position);
            }
            What::Shown { m, group, position, missing } => {
                let s = members.entry(*m).or_default();
                if !s.shown.insert((group, *position)) {
                    return Err(format!("m{m} showed {position} of {} twice, at {when}", short(group)));
                }
                match s.top.get(group) {
                    Some(&top) if *position < top && !s.passed.contains(&(group, *position)) => {
                        return Err(format!("m{m} showed {position} of {} after {top}, not having passed it over, at {when}", short(group)));
                    }
                    Some(&top) if *position > top => {
                        if let Some(gap) = s.gaps(group, top, *position, CHAT).find(|p| !missing.contains(p)) {
                            return Err(format!("m{m} showed {position} of {} past {gap} without naming it missing, at {when}", short(group)));
                        }
                    }
                    _ => {}
                }
                s.passed.extend(missing.iter().map(|p| (group, *p)));
                let top = s.top.entry(group).or_default();
                *top = (*top).max(*position);
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::props::build::*;

    fn opened(position: u64, kind: &str) -> What {
        What::Opened { m: 0, group: g(), position, kind: kind.into(), sender: key(1), plaintext: [0; 32] }
    }

    fn handed(position: u64) -> What {
        What::Handed { m: 0, group: g(), kind: "devices".into(), position }
    }

    fn shown(position: u64, missing: &[u64]) -> What {
        What::Shown { m: 0, group: g(), position, missing: ps(missing) }
    }

    fn counted_at(positions: &[u64]) -> Vec<(u64, What)> {
        positions.iter().map(|p| (0, read(0, *p, 1, counted(*p as u8)))).collect()
    }

    #[test]
    fn a_kind_waits_at_a_gap_until_it_fills_or_is_lost() {
        let ok = [counted_at(&[1, 2, 3]), vec![(1, opened(1, "devices")), (1, handed(1)), (2, opened(2, CHAT)), (3, opened(3, "devices")), (3, handed(3))]].concat();
        assert!(kind_order(&trace(ok)).is_ok());
        let passed = [counted_at(&[1, 2, 3]), vec![(1, handed(1)), (3, handed(3))]].concat();
        assert!(kind_order(&trace(passed)).unwrap_err().contains("past 2"));
        let lost = [counted_at(&[1, 2, 3]), vec![(1, handed(1)), (2, What::Lost { m: 0, group: g(), positions: ps(&[2]) }), (3, handed(3))]].concat();
        assert!(kind_order(&trace(lost)).is_ok());
        let back = [counted_at(&[1, 2]), vec![(1, handed(2)), (2, handed(1))]].concat();
        assert!(kind_order(&trace(back)).is_err());
        let restarted = [counted_at(&[1, 2]), vec![(1, handed(2)), (2, What::Up { m: 0 }), (3, handed(2))]].concat();
        assert!(kind_order(&trace(restarted)).is_ok(), "what a kind took but had not acknowledged comes again");
    }

    #[test]
    fn chat_passes_gaps_it_names_and_shows_them_late() {
        let late = [counted_at(&[1, 2, 3]), vec![(1, shown(1, &[])), (2, shown(3, &[2])), (3, shown(2, &[]))]].concat();
        assert!(kind_order(&trace(late)).is_ok());
        let unnamed = [counted_at(&[1, 2, 3]), vec![(1, shown(1, &[])), (2, shown(3, &[]))]].concat();
        assert!(kind_order(&trace(unnamed)).unwrap_err().contains("without naming it missing"));
        let back = [counted_at(&[1, 2, 3]), vec![(1, shown(1, &[])), (2, shown(3, &[2])), (3, shown(1, &[]))]].concat();
        assert!(kind_order(&trace(back)).unwrap_err().contains("twice"));
        let unpassed = [counted_at(&[1, 2, 3]), vec![(1, shown(3, &[])), (3, shown(2, &[]))]].concat();
        assert!(kind_order(&trace(unpassed)).unwrap_err().contains("not having passed it over"));
        let other = [counted_at(&[1, 2, 3]), vec![(1, shown(1, &[])), (1, opened(2, "lost")), (2, shown(3, &[]))]].concat();
        assert!(kind_order(&trace(other)).is_ok(), "a core payload is not chat's");
        let mine = What::Opened { m: 0, group: g(), position: 2, kind: CHAT.into(), sender: key(0), plaintext: [0; 32] };
        let own = [vec![(0, roster(0, 1, &[0, 1]))], counted_at(&[1, 2, 3]), vec![(1, shown(1, &[])), (1, mine), (2, shown(3, &[]))]].concat();
        assert!(kind_order(&trace(own)).is_ok(), "chat does not show the member's own messages");
    }
}
