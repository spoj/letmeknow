//! 0.13's peer protocol without I/O, across a member's connections: when `hello` goes, the summaries peers sent on
//! their current connection, the entries they lack, repair by pull, and the wait before a commit that deletes an
//! epoch's keys. The node feeds it what it knows, polls it at least every quarter second, and sends what it returns.
//! Times are milliseconds.

use std::collections::{BTreeMap, BTreeSet};

use lmk_proto::{
    Bytes,
    head::Head,
    peer::{Frame, Item, Summary},
    ranges::Ranges,
};
use serde::{Deserialize, Serialize};

/// A peer's iroh key.
pub type Key = [u8; 32];

/// How long changes gather before their `hello`.
pub const DEBOUNCE: u64 = 1_000;
/// How often every summary goes to every peer.
pub const PERIOD: u64 = 5 * 60_000;
/// How long after its entry is read a position is not asked for, as its push is likely on the way.
pub const HOLD_OFF: u64 = 2_000;
/// How long after the last frame from a holder its request is given up.
pub const TIMEOUT: u64 = 10_000;
/// The ciphertext an answer to `want` carries, about.
pub const ANSWER: usize = 1 << 20;
/// The wait before a commit: never ends sooner after coming online, and ends at the latest after this long without
/// progress.
pub const ONLINE: u64 = 3_000;
pub const QUIET: u64 = 10_000;

/// This member's state of a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Own {
    pub head: Head,
    /// Within H, as in its summary.
    pub held: Ranges,
    pub read: Ranges,
    /// The counted positions since its start, within H, that it lacks.
    pub lacking: Ranges,
    /// The heads of the key logs of the group's members' identities.
    pub keys: Vec<Head>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    Frame(Key, Frame),
    /// Send the peer the entries of `log` after `after`, up to this member's head.
    Entries { peer: Key, log: Bytes, after: u64 },
}

/// A peer's latest summary of a group and when it was heard: the node saves it, overwriting the last, whatever the
/// gate, and deletes it when it applies the peer's Remove. Saved ones serve display and Away only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heard {
    pub peer: Bytes,
    pub summary: Summary,
    pub at: u64,
}

/// Before a commit that deletes an epoch's keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Wait,
    Apply,
    /// Apply, and record these positions as known losses.
    Lose(Ranges),
}

pub struct Peers {
    /// When the member came online: its first connection after none. Until then, and while it has none, its wait
    /// before a commit ends only after `QUIET`, as no dial has landed yet.
    online: u64,
    /// When every summary last went to every peer.
    full: u64,
    /// Since when some group's summary has changed unsent.
    changed: Option<u64>,
    groups: BTreeMap<Bytes, Group>,
    conns: BTreeMap<Key, Conn>,
}

struct Group {
    own: Own,
    /// When the member came to hold it: it joined, or started.
    since: u64,
    fetching: Ranges,
    dirty: bool,
    /// The last new summary, connection or ciphertext.
    progress: u64,
    /// Positions read recently, and when.
    read: Vec<(Ranges, u64)>,
    /// The positions the member waits for before a commit, asked without the hold-off.
    urgent: Ranges,
    request: Option<Request>,
    /// Per holder, the positions not to ask it again until its next summary.
    struck: BTreeMap<Key, Ranges>,
}

struct Request {
    holder: Key,
    at: u64,
}

struct Conn {
    last: u64,
    /// A request to it timed out, and it has sent nothing since.
    stalled: bool,
    served: BTreeSet<Bytes>,
    heard: BTreeMap<Bytes, Summary>,
    /// Per log, the longest the peer showed or was sent.
    theirs: BTreeMap<Bytes, u64>,
    /// Every served group's summary goes at the next poll, as after connecting.
    full: bool,
    /// Groups whose summary goes at the next poll, as the gate opened, or the peer's first summary of it came.
    opened: BTreeSet<Bytes>,
}

impl Peers {
    /// For a member that came online `now`.
    pub fn new(now: u64) -> Self {
        Self { online: 0, full: now, changed: None, groups: BTreeMap::new(), conns: BTreeMap::new() }
    }

    /// This member's state of a group, new or changed.
    pub fn group(&mut self, group: Bytes, own: Own, now: u64) {
        let Some(g) = self.groups.get_mut(&group) else {
            let g = Group {
                own,
                since: now,
                fetching: Ranges::default(),
                dirty: true,
                progress: now,
                read: Vec::new(),
                urgent: Ranges::default(),
                request: None,
                struck: BTreeMap::new(),
            };
            self.groups.insert(group, g);
            self.changed.get_or_insert(now);
            return;
        };
        if own.head.length > g.own.head.length {
            g.read.push((Ranges::range(g.own.head.length + 1, own.head.length), now));
        }
        if !g.own.lacking.intersection(&own.held).is_empty() {
            g.progress = now;
        }
        let o = &g.own;
        if (o.head.length, &o.held, &o.read, &o.keys) != (own.head.length, &own.held, &own.read, &own.keys) {
            g.dirty = true;
            self.changed.get_or_insert(now);
        }
        g.own = own;
    }

    pub fn forget(&mut self, group: &Bytes) {
        self.groups.remove(group);
        for c in self.conns.values_mut() {
            c.heard.remove(group);
        }
    }

    /// A connection to the peer opened, replacing any other, with the groups the gate admits it to.
    pub fn connect(&mut self, peer: Key, served: BTreeSet<Bytes>, now: u64) {
        if self.conns.is_empty() {
            self.online = now;
        }
        self.disconnect(&peer);
        let conn = Conn {
            last: now,
            stalled: false,
            served,
            heard: BTreeMap::new(),
            theirs: BTreeMap::new(),
            full: true,
            opened: BTreeSet::new(),
        };
        self.conns.insert(peer, conn);
        for g in self.groups.values_mut() {
            g.progress = now;
        }
    }

    pub fn disconnect(&mut self, peer: &Key) {
        self.conns.remove(peer);
        for g in self.groups.values_mut() {
            g.request.take_if(|r| r.holder == *peer);
            g.struck.remove(peer);
        }
    }

    /// The groups the gate admits the peer to, as they change.
    pub fn served(&mut self, peer: &Key, served: BTreeSet<Bytes>, now: u64) {
        let c = self.conns.get_mut(peer).expect("a connected peer");
        for (id, g) in &mut self.groups {
            if served.contains(id) && !c.served.contains(id) {
                c.opened.insert(id.clone());
                if c.heard.contains_key(id) {
                    g.progress = now;
                }
            }
            if !served.contains(id) {
                g.request.take_if(|r| r.holder == *peer);
            }
        }
        c.served = served;
    }

    /// A frame from the peer, which the node handles too. Returns the summaries to save.
    pub fn frame(&mut self, peer: &Key, frame: &Frame, now: u64) -> Vec<Heard> {
        let c = self.conns.get_mut(peer).expect("a connected peer");
        c.last = now;
        c.stalled = false;
        let mut heard = Vec::new();
        match frame {
            Frame::Hello { groups, heads } => {
                for head in heads {
                    let longest = c.theirs.entry(head.log.clone()).or_default();
                    *longest = (*longest).max(head.length);
                }
                for summary in groups {
                    let Some(g) = self.groups.get_mut(&summary.group) else { continue };
                    let longest = c.theirs.entry(summary.head.log.clone()).or_default();
                    *longest = (*longest).max(summary.head.length);
                    g.struck.remove(peer);
                    if c.served.contains(&summary.group) && c.heard.get(&summary.group) != Some(summary) {
                        g.progress = now;
                    }
                    // The peer may have taken none of ours, as one that joined since we sent it.
                    if c.served.contains(&summary.group) && !c.heard.contains_key(&summary.group) {
                        c.opened.insert(summary.group.clone());
                    }
                    c.heard.insert(summary.group.clone(), summary.clone());
                    heard.push(Heard { peer: Bytes::from(*peer), summary: summary.clone(), at: now });
                }
            }
            Frame::Messages { group, answers: Some(answers), .. } => {
                if let Some(g) = self.groups.get_mut(group) {
                    let struck = g.struck.entry(*peer).or_default();
                    *struck = struck.union(answers);
                    g.request.take_if(|r| r.holder == *peer);
                }
            }
            _ => {}
        }
        heard
    }

    /// Whether to apply a commit that would delete the keys of an epoch whose counted positions in `lacking` this
    /// member lacks. While it waits, those positions are asked without the hold-off. The summaries of `undecided` peers,
    /// whom the gate may admit once it can check them, hold the wait too.
    pub fn wait(&mut self, group: &Bytes, lacking: &Ranges, undecided: &BTreeSet<Key>, now: u64) -> Decision {
        let g = self.groups.get_mut(group).expect("a group of ours");
        let counted = |(k, c): &(&Key, &Conn)| c.served.contains(group) || undecided.contains(*k);
        let peers: Vec<&Summary> = self.conns.iter().filter(counted).filter_map(|(_, c)| c.heard.get(group)).collect();
        let online = if self.conns.is_empty() { 0 } else { now - self.online.max(g.since) };
        let decision = wait(lacking, &peers, online, now - g.progress);
        g.urgent = if decision == Decision::Wait { lacking.clone() } else { Ranges::default() };
        decision
    }

    /// This member's summary of a group.
    pub fn summary(&self, group: &Bytes) -> Summary {
        summary(group, &self.groups[group])
    }

    /// The positions of a group this member lacks and is fetching now.
    pub fn fetching(&self, group: &Bytes) -> Ranges {
        fetching(group, &self.groups[group], &self.conns)
    }

    /// What is due: entries peers lack, then `hello`s, then requests.
    pub fn poll(&mut self, now: u64) -> Vec<Out> {
        for g in self.groups.values_mut() {
            if let Some(r) = &g.request {
                let c = self.conns.get_mut(&r.holder).expect("requests go to connected peers");
                if now - c.last.max(r.at) >= TIMEOUT {
                    c.stalled = true;
                    g.request = None;
                }
            }
        }
        for (id, g) in &mut self.groups {
            g.read.retain(|&(_, at)| now - at < HOLD_OFF);
            let fetching = fetching(id, g, &self.conns);
            if fetching != g.fetching {
                g.fetching = fetching;
                g.dirty = true;
                self.changed.get_or_insert(now);
            }
        }
        let mut out = self.hellos(now);
        for (id, g) in &mut self.groups {
            if g.request.is_none()
                && let Some((holder, positions)) = choose(id, g, &self.conns)
            {
                g.request = Some(Request { holder, at: now });
                out.push(Out::Frame(holder, Frame::Want { group: id.clone(), positions }));
            }
        }
        out
    }

    /// The entries each peer lacks of the logs of the groups served to it, and the `hello`s due.
    fn hellos(&mut self, now: u64) -> Vec<Out> {
        let periodic = now - self.full >= PERIOD;
        if periodic {
            self.full = now;
        }
        let due = periodic || self.changed.is_some_and(|since| now - since >= DEBOUNCE);
        let mut out = Vec::new();
        for (key, c) in &mut self.conns {
            let served: Vec<(&Bytes, &Group)> = c.served.iter().filter_map(|id| Some((id, self.groups.get(id)?))).collect();
            for (_, g) in &served {
                for head in std::iter::once(&g.own.head).chain(&g.own.keys) {
                    if let Some(theirs) = c.theirs.get_mut(&head.log)
                        && *theirs < head.length
                    {
                        out.push(Out::Entries { peer: *key, log: head.log.clone(), after: *theirs });
                        *theirs = head.length;
                    }
                }
            }
            let send: Vec<&(&Bytes, &Group)> = served.iter().filter(|(id, g)| periodic || c.full || c.opened.contains(*id) || due && g.dirty).collect();
            if !send.is_empty() {
                let mut heads: Vec<Head> = send.iter().flat_map(|(_, g)| g.own.keys.iter().cloned()).collect();
                heads.sort_by(|a, b| a.log.cmp(&b.log));
                heads.dedup_by(|a, b| a.log == b.log);
                let groups = send.iter().map(|(id, g)| summary(id, g)).collect();
                out.push(Out::Frame(*key, Frame::Hello { groups, heads }));
            }
            c.full = false;
            c.opened.clear();
        }
        if due {
            self.changed = None;
            for g in self.groups.values_mut() {
                g.dirty = false;
            }
        }
        out
    }
}

fn summary(id: &Bytes, g: &Group) -> Summary {
    Summary { group: id.clone(), head: g.own.head.clone(), held: g.own.held.clone(), read: g.own.read.clone(), fetching: g.fetching.clone() }
}

/// The current-connection summaries of the peers the gate admits to the group.
fn holders<'a>(id: &'a Bytes, conns: &'a BTreeMap<Key, Conn>) -> impl Iterator<Item = (&'a Key, &'a Conn, &'a Summary)> {
    conns.iter().filter(|(_, c)| c.served.contains(id)).filter_map(|(k, c)| Some((k, c, c.heard.get(id)?)))
}

/// What the member lacks that a holder it may ask holds.
fn fetching(id: &Bytes, g: &Group, conns: &BTreeMap<Key, Conn>) -> Ranges {
    let empty = Ranges::default();
    holders(id, conns).fold(Ranges::default(), |acc, (k, _, s)| acc.union(&g.own.lacking.intersection(&s.held).difference(g.struck.get(k).unwrap_or(&empty))))
}

/// The holder holding the first askable position, the lowest key among several, and what it may be asked.
fn choose(id: &Bytes, g: &Group, conns: &BTreeMap<Key, Conn>) -> Option<(Key, Ranges)> {
    let held_off = g.read.iter().fold(Ranges::default(), |acc, (read, _)| acc.union(read)).difference(&g.urgent);
    let askable = g.own.lacking.difference(&held_off);
    let empty = Ranges::default();
    holders(id, conns)
        .filter(|(_, c, _)| !c.stalled)
        .filter_map(|(k, _, s)| {
            let positions = askable.intersection(&s.held).difference(g.struck.get(k).unwrap_or(&empty));
            Some((positions.first()?, *k, positions))
        })
        .min_by_key(|&(first, k, _)| (first, k))
        .map(|(_, k, positions)| (k, positions))
}

/// The wait before a commit that deletes an epoch's keys, given the epoch's counted positions the member lacks, the
/// current-connection summaries of the connected peers the gate admits, and the time since it came online (0 while it
/// has no connection) and since its last progress.
pub fn wait(lacking: &Ranges, peers: &[&Summary], online: u64, quiet: u64) -> Decision {
    if lacking.is_empty() {
        return Decision::Apply;
    }
    let pending = peers.iter().any(|s| !lacking.intersection(&s.held.union(&s.fetching)).is_empty());
    if quiet < QUIET && (pending || online < ONLINE) { Decision::Wait } else { Decision::Lose(lacking.clone()) }
}

/// The answer to a `want`: the asked ciphertexts this member holds, in position order, until about `ANSWER` bytes.
/// `held` is its summary's; a want the gate does not take gets an empty `held`, so its asker moves on.
pub fn answer(group: Bytes, asked: &Ranges, held: &Ranges, mut ciphertext: impl FnMut(u64) -> Option<Vec<u8>>) -> Frame {
    let (mut items, mut size) = (Vec::new(), 0);
    for position in asked.intersection(held).iter() {
        if size >= ANSWER {
            return Frame::Messages { group, items, answers: Some(asked.through(position - 1)) };
        }
        if let Some(ciphertext) = ciphertext(position) {
            size += ciphertext.len();
            items.push(Item { position, ciphertext: Bytes(ciphertext) });
        }
    }
    Frame::Messages { group, items, answers: Some(asked.clone()) }
}

/// Whether a member acts on a frame of a group from a peer. What checks itself is taken from anyone: summaries are
/// kept whatever the gate (and used only while it admits the peer), entries are checked against their head, and of
/// `messages` a peer the gate does not admit gives only ciphertexts matching counted entries. Until the member has
/// applied its log to the head, it takes no `state` or live payloads.
pub fn takes(frame: &Frame, admitted: bool, at_head: bool) -> bool {
    match frame {
        Frame::Hello { .. } | Frame::Entries { .. } | Frame::Messages { .. } => true,
        Frame::State { .. } | Frame::Live { .. } => admitted && at_head,
        Frame::Want { .. } | Frame::WantFiles { .. } | Frame::Have { .. } => admitted,
    }
}

/// Whether a member sends a frame of a group to a peer: only to one the gate admits, and `state` and live payloads
/// only once it has applied its log to the head.
pub fn sends(frame: &Frame, admitted: bool, at_head: bool) -> bool {
    match frame {
        Frame::State { .. } | Frame::Live { .. } => admitted && at_head,
        _ => admitted,
    }
}

#[cfg(test)]
mod tests;
