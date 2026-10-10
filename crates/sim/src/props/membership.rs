//! Membership: members judge every commit alike, so members at one epoch agree, and all catch up when quiet.

use std::collections::BTreeMap;

use lmk_proto::Bytes;

use super::{inside, quiets, short};
use crate::trace::{Trace, What};

/// A member's leaves at an epoch, by session and iroh key, and its settings there.
type Seen<'a> = (usize, Vec<(&'a Bytes, &'a Bytes)>, &'a String);

/// Members active at one epoch of a group see the same leaves (session and iroh keys) and settings.
pub fn agreement(t: &Trace) -> Result<(), String> {
    let mut seen: BTreeMap<(&Bytes, u64), Seen> = BTreeMap::new();
    for o in &t.0 {
        let What::Roster { m, key, group, epoch, leaves, settings } = &o.what else { continue };
        if !leaves.iter().any(|leaf| leaf.key == *key) {
            continue;
        }
        let mut ours: Vec<(&Bytes, &Bytes)> = leaves.iter().map(|leaf| (&leaf.key, &leaf.iroh)).collect();
        ours.sort();
        match seen.get(&(group, *epoch)) {
            Some((j, theirs, s)) if *theirs != ours || *s != settings => {
                return Err(format!("m{m} and m{j} disagree on {} at epoch {epoch}", short(group)));
            }
            Some(_) => {}
            None => drop(seen.insert((group, *epoch), (*m, ours, settings))),
        }
    }
    Ok(())
}

/// At the end of a quiet period, every running member that holds a group is active in it at the latest epoch an active
/// member is at: it applied every commit, its own removal included.
pub fn caught_up(t: &Trace) -> Result<(), String> {
    for (at, views) in quiets(t) {
        let inside = inside(views);
        for v in views {
            let Some(latest) = inside.iter().find(|w| w.group == v.group) else { continue };
            if !inside.iter().any(|w| w.m == v.m && w.group == v.group) {
                return Err(format!("m{} is at epoch {} of {}, not {}, at {}", v.m, v.epoch, short(&v.group), latest.epoch, super::clock(at)));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::props::build::*;

    #[test]
    fn agreement_holds_when_members_at_an_epoch_agree() {
        let t = trace(vec![(1, roster(0, 1, &[0, 1])), (2, roster(1, 1, &[0, 1])), (3, roster(1, 2, &[1])), (4, roster(0, 2, &[1, 2]))]);
        assert!(agreement(&t).is_ok(), "m0's view at epoch 2 does not count: it is not in it");
        let t = trace(vec![(1, roster(0, 1, &[0, 1])), (2, roster(1, 1, &[0, 1, 2]))]);
        assert!(agreement(&t).unwrap_err().contains("disagree"));
    }

    #[test]
    fn caught_up_needs_every_holder_at_the_latest_epoch() {
        let t = trace(vec![(1, What::Quiet { views: vec![view(0, 3, &[0, 1]), view(1, 3, &[0, 1])] })]);
        assert!(caught_up(&t).is_ok());
        let t = trace(vec![(1, What::Quiet { views: vec![view(0, 3, &[0]), view(1, 2, &[0, 1])] })]);
        assert!(caught_up(&t).unwrap_err().contains("m1 is at epoch 2"), "a removed member that never read its removal");
    }
}
