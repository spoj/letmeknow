//! Sending: the node owns a held send until its entry counts.

use super::{CONVERGE, judged, quiets, short};
use crate::trace::{Answer, Trace, Verdict, What};

/// A send answered with a position counts its id there; one answered pending is reported sent, naming the id it was
/// answered with, at a position that counts its message by the id it is reported with, sealed again if a commit came
/// first, by the end of the next quiet period its sender is in the group for, in the same membership.
pub fn send_settles(t: &Trace) -> Result<(), String> {
    let judged = judged(t);
    let counts = |group, position, id| judged.get(&(group, position)).is_none_or(|j| *j.verdict == Verdict::Counted { id: Clone::clone(id) });
    let own = |m, group, position| t.0.iter().any(|o| matches!(&o.what, What::Opened { m: j, group: g, position: p, .. } if *j == m && g == group && *p == position));
    for o in &t.0 {
        match &o.what {
            What::Send { m, group, id, answer: Answer::Position(p) } if !counts(group, *p, id) => {
                return Err(format!("m{m}'s send of {} was answered at {p} of {}, which does not count it", short(id), short(group)));
            }
            What::Sent { m, group, id, position: p, .. } if !matches!(judged.get(&(group, *p)).map(|j| j.verdict), Some(Verdict::Counted { id: counted }) if counted == id) || !own(*m, group, *p) => {
                return Err(format!("m{m}'s pending send of {} was sent at {p} of {}, which does not count its message", short(id), short(group)));
            }
            What::Send { m, group, id, answer: Answer::Pending } => {
                for (at, views) in quiets(t).filter(|(at, _)| *at >= o.at + CONVERGE) {
                    let sent = t.0.iter().take_while(|n| n.at <= at).any(|n| matches!(&n.what, What::Sent { m: j, group: g, answered: i, .. } if j == m && g == group && i == id));
                    let again = t.0.iter().any(|n| n.at > o.at && n.at <= at && matches!(&n.what, What::Joined { m: j, group: g, .. } if j == m && g == group));
                    if !sent && !again && views.iter().any(|v| v.m == *m && v.group == *group && v.active()) {
                        return Err(format!("m{m}'s pending send of {} to {} was not sent by {}", short(id), short(group), super::clock(at)));
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

    fn send(answer: Answer) -> (u64, What) {
        (0, What::Send { m: 0, group: g(), id: id(1), answer })
    }

    #[test]
    fn a_send_counts_where_it_says() {
        assert!(send_settles(&trace(vec![send(Answer::Position(3)), (1, read(1, 3, 1, counted(1)))])).is_ok());
        assert!(send_settles(&trace(vec![send(Answer::Position(3)), (1, read(1, 3, 1, counted(2)))])).is_err());
    }

    #[test]
    fn a_pending_send_is_finished() {
        let quiet = (CONVERGE + 10, What::Quiet { views: vec![view(0, 1, &[0, 1])] });
        assert!(send_settles(&trace(vec![send(Answer::Pending), quiet.clone()])).unwrap_err().contains("not sent"));
        let sent = (5, What::Sent { m: 0, group: g(), id: id(2), answered: id(1), position: 3 });
        let own = (4, What::Opened { m: 0, group: g(), position: 3, kind: "chat".into(), sender: key(0), plaintext: [0; 32] });
        assert!(send_settles(&trace(vec![send(Answer::Pending), (4, read(1, 3, 1, counted(2))), own.clone(), sent.clone(), quiet.clone()])).is_ok(), "sealed again");
        let first = (5, What::Sent { m: 0, group: g(), id: id(1), answered: id(1), position: 3 });
        assert!(send_settles(&trace(vec![send(Answer::Pending), (4, read(1, 3, 1, counted(2))), own, first, quiet.clone()])).is_err(), "by its final id");
        assert!(send_settles(&trace(vec![send(Answer::Pending), (4, read(1, 3, 1, counted(2))), sent, quiet])).unwrap_err().contains("does not count its message"));
    }
}
