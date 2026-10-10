//! The gate: what a member sends and takes of a group, other than what checks itself, it exchanges only with members of
//! its current epoch, and `state` and live payloads only once it has read its log to the head.

use std::collections::BTreeMap;

use lmk_proto::Bytes;

use super::short;
use crate::trace::{Frame, Key, Leaf, Trace, What};

/// What the checks track of each member's groups as the trace goes: its current leaves, and those before with when they
/// changed, the head it last read from the service, and the last position it judged.
#[derive(Default)]
struct Seen<'a> {
    leaves: BTreeMap<(usize, &'a Bytes), &'a [Leaf]>,
    before: BTreeMap<(usize, &'a Bytes), (&'a [Leaf], u64)>,
    heads: BTreeMap<(usize, &'a Bytes), u64>,
    read: BTreeMap<(usize, &'a Bytes), u64>,
}

impl<'a> Seen<'a> {
    fn take(&mut self, o: &'a crate::trace::Obs) {
        match &o.what {
            What::Roster { m, group, leaves, .. } => {
                if let Some(before) = self.leaves.insert((*m, group), leaves) {
                    self.before.insert((*m, group), (before, o.at));
                }
            }
            What::Head { m, group, head } => drop(self.heads.insert((*m, group), *head)),
            What::Joined { m, group, start: position, .. } | What::Read { m, group, position, .. } => drop(self.read.insert((*m, group), *position)),
            _ => {}
        }
    }

    fn behind(&self, m: usize, group: &'a Bytes) -> bool {
        self.heads.get(&(m, group)).is_some_and(|head| self.read.get(&(m, group)).copied().unwrap_or(0) < *head)
    }

    fn has(&self, m: usize, group: &'a Bytes, keep: impl Fn(&Leaf) -> bool) -> bool {
        self.leaves.get(&(m, group)).is_some_and(|leaves| leaves.iter().any(keep))
    }
}

/// A member writes a group's frames to a peer only while the peer's iroh key is in a leaf of the member's current
/// epoch, but the answer that admits a joiner; and `state` and live payloads only once it has read its log to the head
/// as last read.
pub fn gate(t: &Trace) -> Result<(), String> {
    let mut seen = Seen::default();
    for o in &t.0 {
        seen.take(o);
        let What::Out { m, to: Some(to), group, frame } = &o.what else { continue };
        if matches!(frame, Frame::Admitted { .. }) {
            continue;
        }
        // A frame handed to the transport before a step applied the peer's removal may be written just after it.
        let just = seen.before.get(&(*m, group)).is_some_and(|(leaves, at)| *at == o.at && leaves.iter().any(|leaf| leaf.iroh == *to));
        if !seen.has(*m, group, |leaf| leaf.iroh == *to) && !just {
            return Err(format!("m{m} wrote {frame:?} of {} to {}, not in its current epoch, at {}", short(group), short(to), super::clock(o.at)));
        }
        if matches!(frame, Frame::State | Frame::Live) && seen.behind(*m, group) {
            return Err(format!("m{m} wrote {frame:?} of {} behind its log's head, at {}", short(group), super::clock(o.at)));
        }
    }
    Ok(())
}

fn taken_from_current(t: &Trace, what: &str, taken: impl Fn(&What) -> Option<(usize, &Bytes, &Key)>) -> Result<(), String> {
    let mut seen = Seen::default();
    for o in &t.0 {
        seen.take(o);
        let Some((m, group, sender)) = taken(&o.what) else { continue };
        if !seen.has(m, group, |leaf| leaf.key == *sender) {
            return Err(format!("m{m} took {what} of {} from {}, not in its current epoch, at {}", short(group), short(sender), super::clock(o.at)));
        }
        if seen.behind(m, group) {
            return Err(format!("m{m} took {what} of {} behind its log's head, at {}", short(group), super::clock(o.at)));
        }
    }
    Ok(())
}

/// A live payload is taken only from a sender (its session key) in the receiver's current epoch, and only once the
/// receiver has read its log to the head as last read.
pub fn live_current(t: &Trace) -> Result<(), String> {
    taken_from_current(t, "a live payload", |what| match what {
        What::Live { m, group, sender, .. } => Some((*m, group, sender)),
        _ => None,
    })
}

/// A kind's state is taken only from a member of the receiver's current epoch, and only at its log's head: a removed
/// member pushing state changes nothing.
pub fn state_from_members(t: &Trace) -> Result<(), String> {
    taken_from_current(t, "a state", |what| match what {
        What::StateTaken { m, group, from } => Some((*m, group, from)),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::props::build::*;

    fn out(m: usize, to: usize, frame: Frame) -> What {
        What::Out { m, to: Some(iroh(to)), group: g(), frame }
    }

    #[test]
    fn the_gate_admits_members_of_the_current_epoch() {
        let t = trace(vec![(1, roster(0, 1, &[0, 1])), (2, out(0, 1, Frame::Entries)), (3, roster(0, 2, &[0])), (4, out(0, 2, Frame::Files))]);
        assert!(gate(&t).unwrap_err().contains("m0 wrote Files"));
        let t = trace(vec![(1, roster(0, 1, &[0, 1])), (2, out(0, 1, Frame::Entries)), (3, roster(0, 2, &[0])), (4, out(0, 1, Frame::Entries))]);
        assert!(gate(&t).unwrap_err().contains("m0 wrote Entries"), "m1 was removed");
    }

    #[test]
    fn no_state_or_live_while_behind() {
        let head = |head| What::Head { m: 0, group: g(), head };
        let ok = trace(vec![(1, roster(0, 1, &[0, 1])), (2, head(3)), (3, read(0, 3, 1, counted(1))), (4, out(0, 1, Frame::State))]);
        assert!(gate(&ok).is_ok());
        let behind = trace(vec![(1, roster(0, 1, &[0, 1])), (2, read(0, 2, 1, counted(1))), (3, head(3)), (4, out(0, 1, Frame::Live))]);
        assert!(gate(&behind).unwrap_err().contains("behind"));
    }

    #[test]
    fn live_payloads_only_from_current_members() {
        let live = |sender| What::Live { m: 0, group: g(), sender: key(sender), epoch: 1 };
        assert!(live_current(&trace(vec![(1, roster(0, 1, &[0, 1])), (2, live(1))])).is_ok());
        let removed = trace(vec![(1, roster(0, 1, &[0, 1])), (2, roster(0, 2, &[0])), (3, live(1))]);
        assert!(live_current(&removed).unwrap_err().contains("not in its current epoch"));
    }

    #[test]
    fn state_only_from_current_members_at_the_head() {
        let state = |from| What::StateTaken { m: 0, group: g(), from: key(from) };
        assert!(state_from_members(&trace(vec![(1, roster(0, 1, &[0, 1])), (2, state(1))])).is_ok());
        assert!(state_from_members(&trace(vec![(1, roster(0, 2, &[0, 1])), (2, state(2))])).is_err(), "a removed member pushing state");
        let behind = trace(vec![(1, roster(0, 1, &[0, 1, 2])), (2, What::Head { m: 0, group: g(), head: 5 }), (3, state(2))]);
        assert!(state_from_members(&behind).unwrap_err().contains("behind"), "a member back after days, its roster stale");
    }
}
