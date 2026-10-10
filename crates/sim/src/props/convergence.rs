//! Convergence, the main property: members that overlap, directly or through carriers, end with the same readable
//! messages since their start, except known losses; and a loss happens only where the design allows it.

use std::collections::{BTreeMap, BTreeSet};

use lmk_proto::Bytes;

use super::{CARRY, inside, judged, quiets, removed, short, through};
use crate::trace::{Frame, Hash, Positions, Trace, Verdict, What};

/// How long a member waits, without progress, before it applies a commit that deletes keys of positions it lacks.
pub const STALL: u64 = 10_000;
/// How long after coming online a member waits at the earliest before such a commit, so that dials can land.
pub const ONLINE_WAIT: u64 = 3_000;

/// Members that opened a position opened the same plaintext. At the end of a quiet period, of a group's active members
/// at its latest epoch, each holds, has opened or has lost every position since its start that another holds, but those
/// it read longer than H ago, which it may have let go.
pub fn convergence(t: &Trace) -> Result<(), String> {
    let mut plain: BTreeMap<(&Bytes, u64), (usize, &Hash)> = BTreeMap::new();
    let mut read: BTreeMap<(usize, &Bytes, u64), u64> = BTreeMap::new();
    for o in &t.0 {
        if let What::Read { m, group, position, .. } = &o.what {
            read.insert((*m, group, *position), o.at);
        }
        let What::Opened { m, group, position, plaintext, .. } = &o.what else { continue };
        match plain.get(&(group, *position)) {
            Some((j, theirs)) if *theirs != plaintext => {
                return Err(format!("m{m} and m{j} opened different plaintexts at {position} of {}", short(group)));
            }
            Some(_) => {}
            None => drop(plain.insert((group, *position), (*m, plaintext))),
        }
    }
    for (at, views) in quiets(t) {
        let inside = inside(views);
        for a in &inside {
            for b in inside.iter().filter(|b| b.m != a.m && b.group == a.group) {
                let kept = |p: &u64| read.get(&(a.m, &a.group, *p)).is_none_or(|read| read + CARRY > at);
                if let Some(p) = b.held.range(a.start + 1..).find(|p| !a.held.contains(p) && !a.opened.contains(p) && !a.lost.contains(p) && kept(p)) {
                    return Err(format!("m{} lacks position {p} of {}, which m{} holds, at {}", a.m, short(&a.group), b.m, super::clock(at)));
                }
            }
        }
    }
    Ok(())
}

/// A member loses a counted position, never one of its own messages, only:
/// - at its own removal, of its current or prior epoch;
/// - by applying the commit that deletes the keys of the position's epoch, no sooner than 3 seconds after it came online
///   or joined,
///   while no connected member's latest summary on the current connection held the position or was fetching it, or after
///   10 seconds without progress (no summary or ciphertext of the group, no new connection);
/// - or because no member could open the position at all.
///
/// Not checked: a loss beyond openmls's out-of-order window, as openmls tells no generations, and the simulator sends
/// far fewer than 1,000 messages per sender and epoch.
pub fn loss_allowed(t: &Trace) -> Result<(), String> {
    let judged = judged(t);
    let mut opened: BTreeSet<(&Bytes, u64)> = BTreeSet::new();
    let mut own: BTreeSet<(usize, &Bytes, &Bytes)> = BTreeSet::new();
    for o in &t.0 {
        match &o.what {
            What::Opened { group, position, .. } => drop(opened.insert((group, *position))),
            What::Send { m, group, id, .. } => drop(own.insert((*m, group, id))),
            _ => {}
        }
    }
    for (i, o) in t.0.iter().enumerate() {
        let What::Lost { m, group, positions } = &o.what else { continue };
        let earlier = through(t, i);
        for &p in positions {
            let Some(j) = judged.get(&(group, p)) else {
                return Err(format!("m{m} lost position {p} of {}, which no member judged", short(group)));
            };
            let Verdict::Counted { id } = j.verdict else {
                return Err(format!("m{m} lost position {p} of {}, which is no counted message", short(group)));
            };
            if own.contains(&(*m, group, id)) {
                return Err(format!("m{m} lost its own message at {p} of {}", short(group)));
            }
            let allowed = removed(earlier, *m, group, j.epoch) || deletion(t, *m, group, p, j.epoch) || !opened.contains(&(group, p));
            if !allowed {
                return Err(format!("m{m} lost position {p} of {} at {}, which the design does not allow", short(group), super::clock(o.at)));
            }
        }
    }
    Ok(())
}

/// Whether a member applied the commit deleting the keys of `epoch` when it could give `p` up.
fn deletion(t: &Trace, m: usize, group: &Bytes, p: u64, epoch: u64) -> bool {
    let applied = t.0.iter().find_map(|o| match &o.what {
        What::Read { m: j, group: g, epoch: e, verdict: Verdict::Commit { .. }, .. } if *j == m && g == group && *e == epoch + 1 => Some(o.at),
        _ => None,
    });
    let Some(at) = applied else { return false };
    let online = |o: &&crate::trace::Obs| match &o.what {
        What::Up { m: j } => *j == m,
        What::Joined { m: j, group: g, .. } => *j == m && g == group,
        _ => false,
    };
    let up = t.0.iter().take_while(|o| o.at <= at).filter(online).map(|o| o.at).last().unwrap_or(0);
    at >= up + ONLINE_WAIT && (!covered(t, m, group, p, at) || stalled(t, m, group, at))
}

/// Whether a frame sent on a connection at `at` arrived: its connection was not cut or closed before.
fn delivered(t: &Trace, conn: usize, at: u64) -> bool {
    !t.0.iter().any(|o| o.at < at && matches!(o.what, What::Cut { conn: c } | What::Closed { conn: c } if c == conn))
}

/// Whether a connected member's latest summary on its connection showed `p` held or being fetched, as of `at`.
fn covered(t: &Trace, m: usize, group: &Bytes, p: u64, at: u64) -> bool {
    let mut latest: BTreeMap<(usize, usize), (&Positions, &Positions)> = BTreeMap::new();
    for o in t.0.iter().take_while(|o| o.at <= at) {
        if let What::In { m: j, from, conn, group: g, frame: Frame::Hello { held, fetching, .. } } = &o.what
            && *j == m
            && g == group
            && delivered(t, *conn, o.at)
        {
            latest.insert((*from, *conn), (held, fetching));
        }
    }
    let open = |conn: usize| !t.0.iter().any(|o| o.at <= at && matches!(o.what, What::Closed { conn: c } if c == conn));
    latest.iter().any(|((_, conn), (held, fetching))| open(*conn) && (held.contains(&p) || fetching.contains(&p)))
}

/// Whether no ciphertext of the group and no summary unlike the one before on its connection reached a member, and no
/// connection opened to it, in the 10 seconds before `at`.
fn stalled(t: &Trace, m: usize, group: &Bytes, at: u64) -> bool {
    let mut last: BTreeMap<usize, &Frame> = BTreeMap::new();
    let mut progress = false;
    for o in t.0.iter().take_while(|o| o.at <= at) {
        let recent = o.at > at.saturating_sub(STALL);
        match &o.what {
            What::In { m: j, conn, group: g, frame: frame @ Frame::Hello { .. }, .. } if *j == m && g == group && delivered(t, *conn, o.at) => {
                let changed = last.insert(*conn, frame) != Some(frame);
                progress |= recent && changed;
            }
            What::In { m: j, conn, group: g, frame: Frame::Messages { .. }, .. } => progress |= recent && *j == m && g == group && delivered(t, *conn, o.at),
            What::Connected { a, b, .. } => progress |= recent && (*a == m || *b == m),
            _ => {}
        }
    }
    !progress
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::props::build::*;
    use crate::trace::Answer;

    #[test]
    fn convergence_needs_what_others_hold() {
        let mut a = view(0, 2, &[0, 1]);
        let mut b = view(1, 2, &[0, 1]);
        b.held = ps(&[3, 4]);
        a.held = ps(&[3]);
        a.lost = ps(&[4]);
        assert!(convergence(&trace(vec![(1, What::Quiet { views: vec![a.clone(), b.clone()] })])).is_ok());
        a.lost.clear();
        assert!(convergence(&trace(vec![(1, What::Quiet { views: vec![a.clone(), b.clone()] })])).unwrap_err().contains("m0 lacks position 4"));
        a.start = 4;
        assert!(convergence(&trace(vec![(1, What::Quiet { views: vec![a, b] })])).is_ok(), "before its start");
    }

    #[test]
    fn convergence_needs_one_plaintext_per_position() {
        let opened = |m, plaintext| What::Opened { m, group: g(), position: 2, kind: "chat".into(), sender: key(2), plaintext };
        assert!(convergence(&trace(vec![(1, opened(0, [1; 32])), (2, opened(1, [1; 32]))])).is_ok());
        assert!(convergence(&trace(vec![(1, opened(0, [1; 32])), (2, opened(1, [2; 32]))])).is_err());
    }

    /// m1 counted position 2 in epoch 1, which m0 opened; it then applies commits to epochs 2 and 3 at 5 s, losing it.
    fn base() -> Vec<(u64, What)> {
        vec![
            (0, What::Up { m: 1 }),
            (0, roster(1, 1, &[0, 1])),
            (1_000, read(1, 2, 1, counted(1))),
            (1_000, What::Opened { m: 0, group: g(), position: 2, kind: "chat".into(), sender: key(0), plaintext: [0; 32] }),
            (1_100, read(1, 3, 1, commit(0))),
        ]
    }

    fn lose(at: u64) -> Vec<(u64, What)> {
        vec![(at, read(1, 4, 2, commit(0))), (at, What::Lost { m: 1, group: g(), positions: ps(&[2]) })]
    }

    fn hello(at: u64, conn: usize, held: &[u64]) -> (u64, What) {
        (at, What::In { m: 1, from: 0, conn, group: g(), frame: Frame::Hello { head: 9, held: ps(held), fetching: ps(&[]) } })
    }

    #[test]
    fn a_loss_at_a_commit_is_allowed_when_no_connected_summary_holds_it() {
        let ok = [base(), lose(5_000)].concat();
        assert!(loss_allowed(&trace(ok)).is_ok());
        let held = [base(), vec![hello(4_000, 1, &[2])], lose(5_000)].concat();
        assert!(loss_allowed(&trace(held)).unwrap_err().contains("does not allow"));
        let cut = [base(), vec![(3_000, What::Cut { conn: 1 }), hello(4_000, 1, &[2])], lose(5_000)].concat();
        assert!(loss_allowed(&trace(cut)).is_ok(), "the summary never arrived");
        let closed = [base(), vec![hello(4_000, 1, &[2]), (4_500, What::Closed { conn: 1 })], lose(5_000)].concat();
        assert!(loss_allowed(&trace(closed)).is_ok(), "no longer connected");
        let stalled = [base(), vec![hello(4_000, 1, &[2])], lose(14_001)].concat();
        assert!(loss_allowed(&trace(stalled)).is_ok(), "10 seconds without progress");
        let again = [base(), vec![hello(4_000, 1, &[2]), hello(5_000, 1, &[2])], lose(14_500)].concat();
        assert!(loss_allowed(&trace(again)).is_ok(), "the same summary again is no progress");
        let changed = [base(), vec![hello(4_000, 1, &[2]), hello(5_000, 1, &[2, 3])], lose(14_500)].concat();
        assert!(loss_allowed(&trace(changed)).is_err());
        let fetching = [base(), vec![(4_000, What::In { m: 1, from: 0, conn: 1, group: g(), frame: Frame::Hello { head: 9, held: ps(&[]), fetching: ps(&[2]) } })], lose(5_000)].concat();
        assert!(loss_allowed(&trace(fetching)).is_err(), "a carrier still fetching it");
    }

    #[test]
    fn a_loss_waits_for_dials_after_coming_online() {
        let soon = [base(), vec![(3_000, What::Up { m: 1 })], lose(5_000)].concat();
        assert!(loss_allowed(&trace(soon)).is_err());
    }

    #[test]
    fn own_messages_are_never_lost() {
        let own = [base(), vec![(900, What::Send { m: 1, group: g(), id: id(1), answer: Answer::Pending })], lose(5_000)].concat();
        assert!(loss_allowed(&trace(own)).unwrap_err().contains("its own message"));
    }

    #[test]
    fn a_loss_at_removal_is_allowed() {
        let removal = Verdict::Commit { committer: key(0), added: vec![], removed: vec![key(1)] };
        let mut held = [base(), vec![hello(4_000, 1, &[2])]].concat();
        held.extend([(5_000, read(1, 4, 2, removal)), (5_000, What::Lost { m: 1, group: g(), positions: ps(&[2]) })]);
        assert!(loss_allowed(&trace(held)).is_ok());
    }

    #[test]
    fn a_position_no_member_opened_may_be_lost() {
        let mut never = base();
        never.remove(3);
        never.extend([hello(4_000, 1, &[2])]);
        never.extend(lose(5_000));
        assert!(loss_allowed(&trace(never)).is_ok());
    }
}
