//! Duties, run at the log's head on durable state: they converge, each due action taken once; and known losses are
//! announced, and reach every member that overlaps.

use std::collections::BTreeSet;

use lmk_proto::Bytes;

use super::{CONVERGE, TIMER, UPDATE, inside, judged, quiets, removed, short, through};
use crate::trace::{Trace, Verdict, What};

/// By the end of a quiet period: a member that asked to leave a group holds it no more, if another member of it runs and
/// every member running had whole paths for the slow timer's period before, after the leave was asked (a pass that
/// fails to commit runs again on the timer); every member that ran with whole paths, in the group, for T and the slow
/// timer updated its leaf in that time; and no member announced the loss of one position twice.
pub fn duties(t: &Trace) -> Result<(), String> {
    let mut announced: BTreeSet<(usize, &Bytes, u64)> = BTreeSet::new();
    for o in &t.0 {
        if let What::Announced { m, group, positions, .. } = &o.what
            && let Some(p) = positions.iter().find(|p| !announced.insert((*m, group, **p)))
        {
            return Err(format!("m{m} announced its loss of {p} of {} twice", short(group)));
        }
    }
    for (at, views) in quiets(t) {
        let before = |o: &&crate::trace::Obs| o.at <= at;
        let since = at.saturating_sub(TIMER);
        for o in t.0.iter().take_while(|o| o.at < since) {
            let What::Leaving { m, group } = &o.what else { continue };
            let back = t.0.iter().take_while(before).any(|j| j.at > o.at && matches!(&j.what, What::Joined { m: n, group: g, .. } if n == m && g == group));
            let holds = views.iter().any(|v| v.m == *m && v.group == *group);
            let others = views.iter().any(|v| v.m != *m && v.group == *group && v.active());
            let settled = views.iter().filter(|v| v.group == *group).all(|v| whole(t, v.m, since, at));
            if !back && holds && others && settled {
                return Err(format!("m{m} asked to leave {} at {}, and still holds it at {}", short(group), super::clock(o.at), super::clock(at)));
            }
        }
        let Some(since) = at.checked_sub(UPDATE) else { continue };
        for v in inside(views) {
            let joined = t.0.iter().take_while(before).any(|o| o.at > since && matches!(&o.what, What::Joined { m, group, .. } if *m == v.m && *group == v.group));
            if joined || !whole(t, v.m, since, at) {
                continue;
            }
            let updated = t.0.iter().take_while(before).any(|o| {
                o.at > since && matches!(&o.what, What::Read { group, verdict: Verdict::Commit { committer, .. }, .. } if *group == v.group && *committer == v.key)
            });
            if !updated {
                return Err(format!("m{} has not updated its leaf in {} since {}, by {}", v.m, short(&v.group), super::clock(since), super::clock(at)));
            }
        }
    }
    Ok(())
}

/// Whether a member ran with whole paths from `from` to `to`: up and not cut off at `from`, and neither stopped,
/// started nor disrupted since.
fn whole(t: &Trace, m: usize, from: u64, to: u64) -> bool {
    let (mut up, mut cut) = (false, false);
    for o in t.0.iter().take_while(|o| o.at <= to) {
        match o.what {
            What::Up { m: j } | What::Down { m: j } | What::Disrupted { m: j } if j == m && o.at > from => return false,
            What::Up { m: j } if j == m => up = true,
            What::Down { m: j } if j == m => up = false,
            What::Disrupted { m: j } if j == m => cut = true,
            What::Reconnected { m: j } if j == m && o.at <= from => cut = false,
            _ => {}
        }
    }
    up && !cut
}

/// Every known loss but those at one's own removal is announced by the end of the next quiet period the member is in
/// the group for, in the same membership; and each announcement reaches, by then, every member of the group whose start is before it: it opened
/// the announcement, which its kinds and client learn from, or lost it too.
pub fn losses_announced(t: &Trace) -> Result<(), String> {
    let judged = judged(t);
    for (i, o) in t.0.iter().enumerate() {
        let after = quiets(t).filter(|(at, _)| *at >= o.at + CONVERGE);
        match &o.what {
            What::Lost { m, group, positions } => {
                let earlier = through(t, i);
                let epoch = |p: &u64| judged.get(&(group, *p)).map_or(0, |j| j.epoch);
                if positions.iter().all(|p| removed(earlier, *m, group, epoch(p))) {
                    continue;
                }
                for (at, views) in after {
                    let again = t.0.iter().any(|j| j.at > o.at && j.at <= at && matches!(&j.what, What::Joined { m: n, group: g, .. } if n == m && g == group));
                    if again || !views.iter().any(|v| v.m == *m && v.group == *group && v.active()) {
                        continue;
                    }
                    let told: BTreeSet<u64> = t.0.iter().take_while(|o| o.at <= at).flat_map(|o| match &o.what {
                        What::Announced { m: j, group: g, positions, .. } if j == m && g == group => positions.iter().copied().collect(),
                        _ => Vec::new(),
                    }).collect();
                    if let Some(p) = positions.iter().find(|p| !told.contains(p)) {
                        return Err(format!("m{m} lost {p} of {} at {}, and had not announced it by {}", short(group), super::clock(o.at), super::clock(at)));
                    }
                }
            }
            What::Announced { m, group, position, positions } => {
                for (at, views) in after {
                    for v in views.iter().filter(|v| v.m != *m && v.group == *group && v.active() && v.start < *position) {
                        let learnt = t.0.iter().take_while(|o| o.at <= at).any(|o| match &o.what {
                            What::Opened { m: j, group: g, position: p, .. } => *j == v.m && g == group && p == position,
                            What::Lost { m: j, group: g, positions } => *j == v.m && g == group && positions.contains(position),
                            _ => false,
                        });
                        if !learnt {
                            return Err(format!("m{} did not learn that m{m} lost {positions:?} of {}, announced at {position}, by {}", v.m, short(group), super::clock(at)));
                        }
                    }
                }
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
    use crate::trace::View;

    fn quiet(at: u64, views: Vec<View>) -> (u64, What) {
        (at, What::Quiet { views })
    }

    #[test]
    fn a_leaver_is_gone_once_its_members_ran_whole_for_the_slow_timer() {
        let base = vec![(0, What::Up { m: 0 }), (0, What::Up { m: 1 }), (1_000, What::Leaving { m: 1, group: g() })];
        let at = TIMER + 2_000;
        let still = [base.clone(), vec![quiet(at, vec![view(0, 2, &[0, 1]), view(1, 2, &[0, 1])])]].concat();
        assert!(duties(&trace(still)).unwrap_err().contains("still holds it"));
        let gone = [base.clone(), vec![quiet(at, vec![view(0, 3, &[0])])]].concat();
        assert!(duties(&trace(gone)).is_ok());
        let alone = [base.clone(), vec![quiet(at, vec![view(1, 2, &[0, 1])])]].concat();
        assert!(duties(&trace(alone)).is_ok(), "no other member runs to commit its removal");
        let cut = [base, vec![(at - 5_000, What::Disrupted { m: 0 }), quiet(at, vec![view(0, 2, &[0, 1]), view(1, 2, &[0, 1])])]].concat();
        assert!(duties(&trace(cut)).is_ok(), "the pass may have failed, and the timer not run since");
    }

    #[test]
    fn a_member_updates_its_leaf_every_t() {
        let day = UPDATE + 10;
        let update = |at, by| (at, read(1, 5, 2, commit(by)));
        let quiet = |at| quiet(at, vec![view(0, 3, &[0, 1]), view(1, 3, &[0, 1])]);
        let base = vec![(0, What::Up { m: 0 }), (0, What::Up { m: 1 }), (0, What::Joined { m: 0, key: key(0), group: g(), start: 0 })];
        assert!(duties(&trace([base.clone(), vec![update(day - 100, 0), update(day - 50, 1), quiet(day)]].concat())).is_ok());
        assert!(duties(&trace([base.clone(), vec![update(day - 50, 1), quiet(day)]].concat())).unwrap_err().contains("m0 has not updated"));
        assert!(duties(&trace([base.clone(), vec![quiet(day - 20)]].concat())).is_ok(), "not running for T yet");
        let restarted = vec![(day - 1_000, What::Down { m: 0 }), (day - 900, What::Up { m: 0 }), update(day - 50, 1), quiet(day)];
        assert!(duties(&trace([base, restarted].concat())).is_ok(), "the slow timer may not have run since");
    }

    #[test]
    fn no_loss_announced_twice() {
        let announce = |position| (position, What::Announced { m: 0, group: g(), position, positions: ps(&[2, 3]) });
        assert!(duties(&trace(vec![announce(5)])).is_ok());
        assert!(duties(&trace(vec![announce(5), announce(6)])).unwrap_err().contains("twice"));
    }

    #[test]
    fn every_loss_is_announced_and_reaches_every_member() {
        let lost = (1_000, What::Lost { m: 0, group: g(), positions: ps(&[2]) });
        let mut v1 = view(1, 3, &[0, 1]);
        let views = |v1: &View| vec![view(0, 3, &[0, 1]), v1.clone()];
        let unannounced = vec![(0, roster(0, 1, &[0, 1])), (0, read(0, 2, 1, counted(2))), lost.clone(), quiet(200_000, views(&v1))];
        assert!(losses_announced(&trace(unannounced.clone())).unwrap_err().contains("had not announced"));
        let announced = (2_000, What::Announced { m: 0, group: g(), position: 7, positions: ps(&[2]) });
        let untold = [unannounced.clone(), vec![announced.clone()]].concat();
        assert!(losses_announced(&trace(untold)).unwrap_err().contains("m1 did not learn"));
        let told = (3_000, What::Opened { m: 1, group: g(), position: 7, kind: "lost".into(), sender: key(0), plaintext: [0; 32] });
        assert!(losses_announced(&trace([unannounced.clone(), vec![announced.clone(), told]].concat())).is_ok());
        v1.start = 8;
        let later = vec![(0, roster(0, 1, &[0, 1])), (0, read(0, 2, 1, counted(2))), lost, announced, quiet(200_000, views(&v1))];
        assert!(losses_announced(&trace(later)).is_ok(), "m1 joined after the announcement");
    }
}
