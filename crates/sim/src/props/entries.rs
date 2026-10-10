//! The group log: every member judges every entry alike, from the log alone; forgeries change nothing; a join whose
//! answer was lost costs a retry, not a stranded leaf.

use std::collections::{BTreeMap, BTreeSet};

use lmk_proto::Bytes;

use super::{judged, short};
use crate::trace::{Answer, Dropped, Hash, Trace, Verdict, What};

/// Every member that judged a position judged the same entry, in the same epoch, alike; a member reads its log strictly
/// in order from its start, each position once, across restarts; an id counts once per epoch; and a member opens only
/// positions it counted.
pub fn strict_entries(t: &Trace) -> Result<(), String> {
    let mut first: BTreeMap<(&Bytes, u64), (usize, &Hash, u64, &Verdict)> = BTreeMap::new();
    let mut cursor: BTreeMap<(usize, &Bytes), u64> = BTreeMap::new();
    let mut ids: BTreeMap<(&Bytes, u64, &Bytes), u64> = BTreeMap::new();
    let mut counted: BTreeSet<(usize, &Bytes, u64)> = BTreeSet::new();
    for o in &t.0 {
        match &o.what {
            What::Joined { m, group, start, .. } => drop(cursor.insert((*m, group), *start)),
            What::Read { m, group, position, entry, epoch, verdict } => {
                let g = short(group);
                match cursor.get(&(*m, group)) {
                    Some(c) if *position != c + 1 => return Err(format!("m{m} read {position} of {g} after {c}")),
                    None => return Err(format!("m{m} read {position} of {g}, which it never joined")),
                    Some(_) => drop(cursor.insert((*m, group), *position)),
                }
                match first.get(&(group, *position)) {
                    Some((j, e, ep, v)) if (*e, *ep, *v) != (entry, *epoch, verdict) => {
                        return Err(format!("m{m} and m{j} judged {position} of {g} apart: {verdict:?} in epoch {epoch}, {v:?} in epoch {ep}"));
                    }
                    Some(_) => {}
                    None => drop(first.insert((group, *position), (*m, entry, *epoch, verdict))),
                }
                if let Verdict::Counted { id } = verdict {
                    if let Some(other) = ids.get(&(group, *epoch, id)).filter(|p| **p != *position) {
                        return Err(format!("{} counted at {other} and {position} of {g}", short(id)));
                    }
                    ids.insert((group, *epoch, id), *position);
                    counted.insert((*m, group, *position));
                }
            }
            What::Opened { m, group, position, .. } if !counted.contains(&(*m, group, *position)) => {
                return Err(format!("m{m} opened {position} of {}, which it had not counted", short(group)));
            }
            _ => {}
        }
    }
    Ok(())
}

/// A forged entry whose MAC does not verify (junk, a replay, another log's entry, a commit under another's leaf with a
/// bad signature) is skipped by every member, and a forged message with a MAC that verifies (a member's) is opened by
/// none; and no member drops a group as copied unless its state was. That the claimed sender's messages still open is
/// `loss-allowed`'s to check.
pub fn forgery(t: &Trace) -> Result<(), String> {
    let mut forged: BTreeMap<(&Bytes, u64), bool> = BTreeMap::new();
    let mut copied: BTreeSet<(usize, &Bytes)> = BTreeSet::new();
    for o in &t.0 {
        match &o.what {
            What::Forged { group, position, mac } => drop(forged.insert((group, *position), *mac)),
            What::Copied { m, group } => drop(copied.insert((*m, group))),
            What::Read { m, group, position, verdict, .. } if forged.get(&(group, *position)) == Some(&false) && *verdict != Verdict::Skipped => {
                return Err(format!("m{m} took the forged entry at {position} of {}: {verdict:?}", short(group)));
            }
            What::Opened { m, group, position, .. } if forged.contains_key(&(group, *position)) => {
                return Err(format!("m{m} opened the forged message at {position} of {}", short(group)));
            }
            What::Dropped { m, group, reason: Dropped::Copied } if !copied.contains(&(*m, group)) => {
                return Err(format!("m{m} dropped {} as copied, which it was not", short(group)));
            }
            _ => {}
        }
    }
    Ok(())
}

/// A join answered ok starts at the only Add of the joiner's key since its last membership of the group, however
/// many answers were lost on the way: since its last join, or the last Remove of its key, as of a leaf a join left
/// stranded when it gave up.
pub fn admission(t: &Trace) -> Result<(), String> {
    let mut adds: BTreeMap<(&Bytes, &Bytes), BTreeSet<u64>> = BTreeMap::new();
    let mut removes: BTreeMap<(&Bytes, &Bytes), BTreeSet<u64>> = BTreeMap::new();
    for ((group, position), j) in judged(t) {
        if let Verdict::Commit { added, removed, .. } = j.verdict {
            for key in added {
                adds.entry((group, key)).or_default().insert(position);
            }
            for key in removed {
                removes.entry((group, key)).or_default().insert(position);
            }
        }
    }
    let mut last: BTreeMap<(usize, &Bytes), u64> = BTreeMap::new();
    for o in &t.0 {
        let What::Join { m, key, group, answer: Answer::Position(start) } = &o.what else { continue };
        let removed = removes.get(&(group, key)).and_then(|removes| removes.range(..*start).next_back()).copied().unwrap_or(0);
        let since = last.insert((*m, group), *start).unwrap_or(0).max(removed);
        let ours: Vec<u64> = adds.get(&(group, key)).into_iter().flatten().copied().filter(|p| *p > since && *p <= *start).collect();
        if ours != [*start] {
            return Err(format!("m{m} joined {} at {start}, its key added at {ours:?}", short(group)));
        }
        let joined = t.0.iter().any(|j| matches!(&j.what, What::Joined { m: n, group: g, start: s, .. } if n == m && g == group && s == start));
        if !joined {
            return Err(format!("m{m} was answered it joined {} at {start}, but never did", short(group)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::props::build::*;

    fn joined(m: usize, start: u64) -> What {
        What::Joined { m, key: key(m), group: g(), start }
    }

    #[test]
    fn members_judge_alike_in_order() {
        let ok = vec![(0, joined(0, 0)), (0, joined(1, 1)), (1, read(0, 1, 0, commit(0))), (2, read(0, 2, 1, counted(1))), (2, read(1, 2, 1, counted(1)))];
        assert!(strict_entries(&trace(ok.clone())).is_ok());
        let apart = [ok.clone(), vec![(3, read(0, 3, 1, counted(2))), (3, read(1, 3, 1, Verdict::Skipped))]].concat();
        assert!(strict_entries(&trace(apart)).unwrap_err().contains("apart"));
        let skipping = [ok.clone(), vec![(3, read(0, 4, 1, counted(2)))]].concat();
        assert!(strict_entries(&trace(skipping)).unwrap_err().contains("read 4 of 07 after 2"));
        let twice = [ok.clone(), vec![(3, read(0, 3, 1, counted(1)))]].concat();
        assert!(strict_entries(&trace(twice)).unwrap_err().contains("counted at 2 and 3"));
        let opened = |m, position| What::Opened { m, group: g(), position, kind: "chat".into(), sender: key(0), plaintext: [0; 32] };
        assert!(strict_entries(&trace([ok.clone(), vec![(3, opened(1, 2))]].concat())).is_ok());
        assert!(strict_entries(&trace([ok, vec![(3, opened(1, 3))]].concat())).is_err());
    }

    #[test]
    fn forgeries_change_nothing() {
        let forged = |position, mac| What::Forged { group: g(), position, mac };
        let ok = vec![(0, forged(2, false)), (1, read(0, 2, 1, Verdict::Skipped)), (1, forged(3, true)), (2, read(0, 3, 1, counted(3)))];
        assert!(forgery(&trace(ok.clone())).is_ok());
        assert!(forgery(&trace(vec![(0, forged(2, false)), (1, read(0, 2, 1, commit(1)))])).unwrap_err().contains("took the forged entry"));
        let opened = What::Opened { m: 0, group: g(), position: 3, kind: "chat".into(), sender: key(1), plaintext: [0; 32] };
        assert!(forgery(&trace([ok, vec![(3, opened)]].concat())).is_err());
        let dropped = What::Dropped { m: 0, group: g(), reason: Dropped::Copied };
        assert!(forgery(&trace(vec![(1, dropped.clone())])).unwrap_err().contains("which it was not"));
        assert!(forgery(&trace(vec![(0, What::Copied { m: 0, group: g() }), (1, dropped)])).is_ok());
    }

    #[test]
    fn a_retried_join_starts_at_its_one_add() {
        let add = |position, k: Bytes| read(0, position, 1, Verdict::Commit { committer: key(0), added: vec![k], removed: vec![] });
        let join = |start| What::Join { m: 1, key: key(1), group: g(), answer: Answer::Position(start) };
        let ok = vec![(1, add(3, key(1))), (2, joined(1, 3)), (2, join(3))];
        assert!(admission(&trace(ok)).is_ok());
        let twice = vec![(1, add(3, key(1))), (1, add(4, key(1))), (2, joined(1, 4)), (2, join(4))];
        assert!(admission(&trace(twice)).unwrap_err().contains("added at [3, 4]"), "a stranded leaf at 3");
        let never = vec![(1, add(3, key(1))), (2, join(3))];
        assert!(admission(&trace(never)).unwrap_err().contains("never did"));
        let remove = read(0, 4, 2, Verdict::Commit { committer: key(0), added: vec![], removed: vec![key(1)] });
        let removed = vec![(1, add(3, key(1))), (1, remove), (1, add(5, key(1))), (2, joined(1, 5)), (2, join(5))];
        assert!(admission(&trace(removed)).is_ok(), "the leaf a join gave up on was removed");
    }
}
