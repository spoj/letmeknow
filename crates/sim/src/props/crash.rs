//! Crash consistency: nothing leaves a node before it is saved, and saved state never disagrees with itself.

use std::collections::BTreeMap;

use lmk_proto::Bytes;

use super::short;
use crate::trace::{Frame, Positions, Saved, Trace, What};

/// What a member's storage held of each group as it started again after a crash covers everything it wrote before
/// the crash: each entry it appended is saved for posting, or it had read it, or a commit or a refusal made it moot; its
/// log's head, the positions it judged and those it holds (but those read longer than H ago) are at least those its
/// summaries, pushes and admissions showed. And each restored group's records agree: a verdict for every position kept
/// from its start to its cursor, openmls's epoch one past its last commit's,
/// held positions among those judged, pending sends sealed in no later epoch, and summaries kept only of its leaves.
pub fn crash_consistency(t: &Trace) -> Result<(), String> {
    for o in &t.0 {
        if let What::Restored { m, group, saved } = &o.what {
            consistent(saved).map_err(|why| format!("m{m}'s records of {} as it started at {}: {why}", short(group), super::clock(o.at)))?;
        }
    }
    let mut since: BTreeMap<usize, usize> = BTreeMap::new();
    for (i, o) in t.0.iter().enumerate() {
        match o.what {
            What::Up { m } => drop(since.insert(m, i)),
            What::Down { m } => {
                let from = since.get(&m).copied().unwrap_or(0);
                let restored: BTreeMap<&Bytes, &Saved> = t.0[i..]
                    .iter()
                    .skip_while(|n| !matches!(n.what, What::Up { m: j } if j == m))
                    .skip(1)
                    .map_while(|n| match &n.what {
                        What::Restored { m: j, group, saved } if *j == m => Some((group, saved)),
                        _ => None,
                    })
                    .collect();
                covered(&t.0[from..i], m, &restored).map_err(|why| format!("m{m} crashed at {}: {why}", super::clock(o.at)))?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn consistent(saved: &Saved) -> Result<(), String> {
    let from = saved.start.max(saved.expired) + 1;
    let expected: Positions = (from..=saved.head).collect();
    if saved.judged != expected {
        return Err(format!("verdicts for {:?}, not {from}..={}", saved.judged, saved.head));
    }
    if let Some((p, e)) = saved.commits.last()
        && e + 1 != saved.epoch
    {
        return Err(format!("openmls at epoch {}, its last commit at {p} judged in {e}", saved.epoch));
    }
    if let Some(p) = saved.held.iter().find(|p| !saved.judged.contains(p)) {
        return Err(format!("holds {p}, which it has not judged"));
    }
    if let Some(e) = saved.sends.iter().find(|e| **e > saved.epoch) {
        return Err(format!("a send sealed in epoch {e}, past {}", saved.epoch));
    }
    if let Some(k) = saved.summaries.iter().find(|k| !saved.roster.contains(k)) {
        return Err(format!("keeps the summary of {}, not a member", short(k)));
    }
    Ok(())
}

/// Whether what a member's storage held after its crash covers what it wrote in its session before.
fn covered(session: &[crate::trace::Obs], m: usize, restored: &BTreeMap<&Bytes, &Saved>) -> Result<(), String> {
    for (i, o) in session.iter().enumerate() {
        let What::Out { m: j, group, frame, .. } = &o.what else { continue };
        let Some(saved) = restored.get(group).filter(|_| *j == m) else { continue };
        let g = short(group);
        let kept = |positions: &Positions| positions.range(saved.expired + 1..).copied().collect::<Positions>();
        match frame {
            Frame::Append { entries } => {
                let rest = &session[i..];
                let moot = rest.iter().any(|n| match &n.what {
                    What::Read { m: j, group: h, verdict: crate::trace::Verdict::Commit { .. }, .. } => *j == m && h == group,
                    _ => false,
                });
                let read = |e: &crate::trace::Hash| session.iter().any(|n| matches!(&n.what, What::Read { m: j, group: h, entry, .. } if *j == m && h == group && entry == e));
                if let Some(e) = entries.iter().find(|e| !moot && !saved.entries.contains(e) && !read(e)) {
                    return Err(format!("it appended {} to {g}, which it had not saved", hex::encode(&e[..4])));
                }
            }
            Frame::Hello { head, held, .. } if *head > saved.logged || !kept(held).is_subset(&saved.held) => {
                return Err(format!("its summary of {g} showed head {head} and {held:?}, its storage {} and {:?}", saved.logged, saved.held));
            }
            Frame::Messages { positions } if !kept(positions).is_subset(&saved.held) => {
                return Err(format!("it pushed {positions:?} of {g}, its storage held {:?}", saved.held));
            }
            Frame::Admitted { position } if *position > saved.head => {
                return Err(format!("it admitted a joiner at {position} of {g}, its storage at {}", saved.head));
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

    fn saved(head: u64, held: &[u64]) -> Saved {
        Saved { epoch: 2, start: 0, head, logged: head, judged: (1..=head).collect(), commits: vec![(1, 1)], held: ps(held), ..Saved::default() }
    }

    fn crash(out: Frame, after: Saved) -> Trace {
        trace(vec![
            (0, What::Up { m: 0 }),
            (1, What::Out { m: 0, to: Some(iroh(1)), group: g(), frame: out }),
            (2, What::Down { m: 0 }),
            (3, What::Up { m: 0 }),
            (3, What::Restored { m: 0, group: g(), saved: after }),
        ])
    }

    #[test]
    fn nothing_leaves_before_it_is_saved() {
        let hello = Frame::Hello { head: 3, held: ps(&[2, 3]), fetching: ps(&[]) };
        assert!(crash_consistency(&crash(hello.clone(), saved(3, &[2, 3]))).is_ok());
        assert!(crash_consistency(&crash(hello, saved(2, &[2]))).unwrap_err().contains("its summary"));
        assert!(crash_consistency(&crash(Frame::Messages { positions: ps(&[3]) }, saved(3, &[2]))).unwrap_err().contains("pushed"));
        assert!(crash_consistency(&crash(Frame::Admitted { position: 4 }, saved(3, &[]))).unwrap_err().contains("admitted"));
        let append = Frame::Append { entries: vec![[9; 32]] };
        assert!(crash_consistency(&crash(append.clone(), saved(3, &[]))).unwrap_err().contains("not saved"));
        assert!(crash_consistency(&crash(append, Saved { entries: vec![[9; 32]], ..saved(3, &[]) })).is_ok());
    }

    #[test]
    fn saved_records_agree() {
        let restored = |saved| trace(vec![(0, What::Up { m: 0 }), (0, What::Restored { m: 0, group: g(), saved })]);
        assert!(crash_consistency(&restored(saved(3, &[2]))).is_ok());
        assert!(crash_consistency(&restored(Saved { judged: ps(&[1, 3]), ..saved(3, &[]) })).unwrap_err().contains("verdicts"));
        assert!(crash_consistency(&restored(Saved { epoch: 3, ..saved(3, &[]) })).unwrap_err().contains("openmls at epoch 3"));
        assert!(crash_consistency(&restored(Saved { sends: vec![3], ..saved(3, &[]) })).is_err());
        assert!(crash_consistency(&restored(Saved { summaries: vec![key(1)], roster: vec![key(0)], ..saved(3, &[]) })).is_err());
        assert!(crash_consistency(&restored(saved(3, &[4]))).unwrap_err().contains("not judged"));
    }
}
