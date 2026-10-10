//! The 0.13 properties, a module per area, each a pure check over a run's trace (`crate::trace`), named in failures.
//! A property whose observations the node cannot record yet is pending: skipped in runs unless `--pending`, and listed
//! with what it needs. `LMK_SIM_SKIP` names properties to leave unchecked while a bug is triaged.

mod convergence;
mod crash;
mod duties;
mod entries;
mod identity;
mod membership;
mod order;
mod peer;
mod send;

use std::collections::BTreeMap;

use lmk_proto::Bytes;

use crate::trace::{Key, Obs, Trace, Verdict, View, What};

/// How long members stay connected and undisturbed in a quiet period before they must agree: well under the 5-minute
/// resync.
pub const CONVERGE: u64 = 90_000;
/// How long after a device is taken off every member holding its sessions' certificates has read the key log entry
/// that names it: a copy of a key log is fresh for 10 minutes.
pub const KEYS_READ: u64 = 11 * 60_000;
/// T, the leaf update period, by default, and the slow timer that may run a due update late.
pub const UPDATE: u64 = 86_400_000 + 3_600_000;

pub struct Property {
    pub name: &'static str,
    pub check: fn(&Trace) -> Result<(), String>,
    /// For a pending property, what the node must record first.
    pub needs: Option<&'static str>,
}

pub const PROPERTIES: &[Property] = &[
    Property { name: "agreement", check: membership::agreement, needs: None },
    Property { name: "caught-up", check: membership::caught_up, needs: None },
    Property { name: "gate", check: peer::gate, needs: None },
    Property { name: "revocation", check: identity::revocation, needs: None },
    Property { name: "live-current", check: peer::live_current, needs: None },
    Property { name: "convergence", check: convergence::convergence, needs: Some("Node::positions; Event::Opened") },
    Property {
        name: "loss-allowed",
        check: convergence::loss_allowed,
        needs: Some("Event::Read, Event::Lost, Event::Opened, Event::Live {epoch, generation}; 0.13 hello and messages frames"),
    },
    Property { name: "kind-order", check: order::kind_order, needs: Some("Event::Read, Event::Opened, Event::Handed; ClientEvent::Message {position, missing}") },
    Property { name: "strict-entries", check: entries::strict_entries, needs: Some("Event::Joined, Event::Read, Event::Opened") },
    Property { name: "forgery", check: entries::forgery, needs: Some("Event::Read, Event::Opened, Event::Dropped; forged entries in 0.13's format") },
    Property { name: "admission-retry", check: entries::admission, needs: Some("Event::Joined, Event::Read; join's answer with its start") },
    Property { name: "duties", check: duties::duties, needs: Some("Event::Read, Event::Announced; Node::positions") },
    Property { name: "losses-announced", check: duties::losses_announced, needs: Some("Event::Lost, Event::Announced, ClientEvent::Lost; Node::positions") },
    Property { name: "crash-consistency", check: crash::crash_consistency, needs: Some("lmk_node::saved; Event::Read; 0.13 frames; storage snapshots of committed steps") },
    Property { name: "send-settles", check: send::send_settles, needs: Some("send's answer {id, position | pending}; ClientEvent::Sent; Event::Read") },
    Property { name: "state-from-members", check: peer::state_from_members, needs: Some("Event::State {from}; Event::Read, Event::Head") },
];

/// The first property a trace breaks, of those checked: all, with `pending`, else those the node can feed, either way
/// but those `LMK_SIM_SKIP` names.
pub fn check(trace: &Trace, pending: bool) -> Option<(&'static str, String)> {
    let skip = std::env::var("LMK_SIM_SKIP").unwrap_or_default();
    let mut sorted = trace.clone();
    sorted.0.sort_by_key(|o| o.at);
    PROPERTIES
        .iter()
        .filter(|p| (pending || p.needs.is_none()) && !skip.split(',').any(|s| s == p.name))
        .find_map(|p| (p.check)(&sorted).err().map(|text| (p.name, text)))
}

pub fn pending() -> impl Iterator<Item = &'static Property> {
    PROPERTIES.iter().filter(|p| p.needs.is_some())
}

/// How each position of each group was judged, as the first member to judge it did.
pub(crate) struct Judged<'a> {
    pub epoch: u64,
    pub verdict: &'a Verdict,
}

pub(crate) fn judged(t: &Trace) -> BTreeMap<(&Bytes, u64), Judged<'_>> {
    let mut judged = BTreeMap::new();
    for o in &t.0 {
        if let What::Read { group, position, epoch, verdict, .. } = &o.what {
            judged.entry((group, *position)).or_insert(Judged { epoch: *epoch, verdict });
        }
    }
    judged
}

/// Each quiet period's end, with the views then.
pub(crate) fn quiets(t: &Trace) -> impl Iterator<Item = (u64, &[View])> {
    t.0.iter().filter_map(|o| match &o.what {
        What::Quiet { views } => Some((o.at, views.as_slice())),
        _ => None,
    })
}

/// Of a quiet period's views, those active in their group at its latest epoch any active member is at.
pub(crate) fn inside(views: &[View]) -> Vec<&View> {
    let mut latest: BTreeMap<&Bytes, u64> = BTreeMap::new();
    for v in views.iter().filter(|v| v.active()) {
        let e = latest.entry(&v.group).or_default();
        *e = (*e).max(v.epoch);
    }
    views.iter().filter(|v| v.active() && latest[&v.group] == v.epoch).collect()
}

/// A member's session key in a group, as its last roster of it among these observations shows.
pub(crate) fn key_of<'a>(obs: &'a [Obs], m: usize, group: &Bytes) -> Option<&'a Key> {
    obs.iter().rev().find_map(|o| match &o.what {
        What::Roster { m: j, key, group: g, .. } if *j == m && g == group => Some(key),
        _ => None,
    })
}

/// The last commit a member applied in a group among these observations: when, the epoch it was judged in, and whom it
/// removed.
pub(crate) fn last_commit<'a>(obs: &'a [Obs], m: usize, group: &Bytes) -> Option<(u64, u64, &'a [Key])> {
    obs.iter().rev().find_map(|o| match &o.what {
        What::Read { m: j, group: g, epoch, verdict: Verdict::Commit { removed, .. }, .. } if *j == m && g == group => Some((o.at, *epoch, removed.as_slice())),
        _ => None,
    })
}

/// Whether a member's latest commit among these observations removed it, in an epoch at most one past `epoch`.
pub(crate) fn removed(obs: &[Obs], m: usize, group: &Bytes, epoch: u64) -> bool {
    let key = key_of(obs, m, group);
    last_commit(obs, m, group).is_some_and(|(_, e, removed)| key.is_some_and(|key| removed.contains(key)) && epoch + 1 >= e)
}

pub(crate) fn short(bytes: &Bytes) -> String {
    hex::encode(&bytes.0[..bytes.0.len().min(4)])
}

pub(crate) fn clock(at: u64) -> String {
    crate::clock(at)
}

#[cfg(test)]
pub(crate) mod build {
    use super::*;
    use crate::trace::{Leaf, Positions};

    pub fn g() -> Bytes {
        Bytes(vec![7])
    }

    pub fn key(m: usize) -> Key {
        Bytes(vec![100 + m as u8])
    }

    pub fn iroh(m: usize) -> Bytes {
        Bytes(vec![200 + m as u8])
    }

    pub fn id(n: u8) -> Bytes {
        Bytes(vec![50, n])
    }

    pub fn leaf(m: usize) -> Leaf {
        Leaf { key: key(m), iroh: iroh(m), identity: None, device: None }
    }

    pub fn ps(positions: &[u64]) -> Positions {
        positions.iter().copied().collect()
    }

    pub fn roster(m: usize, epoch: u64, members: &[usize]) -> What {
        What::Roster { m, key: key(m), group: g(), epoch, leaves: members.iter().map(|j| leaf(*j)).collect(), settings: String::new() }
    }

    pub fn read(m: usize, position: u64, epoch: u64, verdict: Verdict) -> What {
        What::Read { m, group: g(), position, entry: [position as u8; 32], epoch, verdict }
    }

    pub fn counted(n: u8) -> Verdict {
        Verdict::Counted { id: id(n) }
    }

    pub fn commit(by: usize) -> Verdict {
        Verdict::Commit { committer: key(by), added: vec![], removed: vec![] }
    }

    pub fn view(m: usize, epoch: u64, members: &[usize]) -> View {
        View {
            m,
            key: key(m),
            group: g(),
            epoch,
            leaves: members.iter().map(|j| leaf(*j)).collect(),
            start: 0,
            head: 0,
            held: Positions::new(),
            opened: Positions::new(),
            lost: Positions::new(),
        }
    }

    /// A trace of observations at the times given.
    pub fn trace(obs: Vec<(u64, What)>) -> Trace {
        Trace(obs.into_iter().map(|(at, what)| Obs { at, what }).collect())
    }
}
