//! The peer protocol without I/O, across a member's connections: which peers to dial and close, which summaries they
//! are sent, repair by pull, and the wait before a commit that deletes an epoch's keys. The node feeds it state and
//! frames, polls it, and sends what it returns. Times are milliseconds.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem,
};

use lmk_proto::{
    Bytes,
    head::Head,
    peer::{At, Frame, Seqs, Signed, Summary, Version},
    ranges::Ranges,
};
use sha2::{Digest, Sha256};

/// A peer's iroh key.
pub type Key = [u8; 32];
/// A membership: its leaf signature key and the epoch it joined in.
pub type Membership = (Bytes, u64);
/// Positions by membership.
type Set = BTreeMap<Membership, Ranges>;

pub const DEBOUNCE: u64 = 1_000;
pub const PERIOD: u64 = 300_000;
pub const TIMEOUT: u64 = 10_000;
pub const ANSWER: usize = 1 << 20;
pub const K: usize = 6;
const MESH: usize = 7;
pub const REDIAL: u64 = 10_000;
pub const BACKOFF: u64 = 10_000;
pub const MAX_BACKOFF: u64 = 600_000;
pub const PROBE: u64 = 60_000;
pub const RECENT: u64 = 7_200_000;
pub const IDLE: u64 = 300_000;
pub const STRANGER: u64 = 30_000;
pub const MAX_CONNECTIONS: usize = 128;
/// From when a wait starts, or the member came online, whichever is later, until it gives up.
pub const WAIT: u64 = 120_000;
/// From then, how long a wait holds though no summary shows a holder: a member back online hears the others' summaries
/// within it.
pub const HEAR: u64 = 15_000;
pub const DIALS: usize = 4;

/// This member's state of a group, handed in on every change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Own {
    /// This member's own membership.
    pub me: Membership,
    pub epoch: u64,
    /// The current epoch's log, and its newest signed head held.
    pub log: [u8; 32],
    pub head: Option<Head>,
    /// The earlier logs' newest signed heads held.
    pub earlier: Vec<Head>,
    /// The other current members, with their iroh keys.
    pub members: Vec<(Membership, Key)>,
    /// Seqs the node wants now.
    pub wanted: Vec<Seqs>,
    /// Seqs the node holds sealed in an ended epoch, which it wants sealed again: offered only to holders whose summary
    /// of this epoch lists them sealed.
    pub stale: Vec<Seqs>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    Frame(Key, Frame),
    /// Send the peer the entries of `log` after `after`, up to this member's head.
    Entries { peer: Key, log: Bytes, after: u64 },
    Dial(Key),
    Close(Key),
}

/// A verified summary and when it came.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heard {
    pub signed: Signed,
    pub summary: Summary,
    pub at: u64,
}

pub struct Peers {
    me: Key,
    rng: u64,
    /// When the member last went from no connections to one.
    online: u64,
    /// When the last periodic `hello` went.
    full: u64,
    /// When a change to a `hello` arose, unsent.
    changed: Option<u64>,
    redial: u64,
    probe: u64,
    groups: BTreeMap<Bytes, Group>,
    conns: BTreeMap<Key, Conn>,
    backoff: BTreeMap<Key, Backoff>,
    /// Peers with a `Dial` in flight.
    dialing: BTreeSet<Key>,
}

struct Group {
    own: Own,
    /// The kept summaries of the current memberships, own included.
    heard: BTreeMap<Membership, Heard>,
    /// Per holder and membership, the seqs it covered without sending, struck for the epoch.
    struck: BTreeMap<(Key, Membership), Ranges>,
    request: Option<Request>,
    /// The seqs of a wait in progress, asked at once.
    waiting: Set,
}

struct Request {
    holder: Key,
    asked: Set,
    /// The epoch it was made in: once this member is in a later one, its answer or silence strikes nothing.
    epoch: u64,
    at: u64,
}

struct Conn {
    dialed: bool,
    served: BTreeSet<Bytes>,
    /// When it last served a group, or connected.
    served_at: u64,
    /// Its last directed traffic.
    active: u64,
    /// Whether its `hello` is due at the next poll.
    hello: bool,
    /// Groups whose `versions` are due at the next poll.
    opened: BTreeSet<Bytes>,
    /// Per group, the memberships whose summaries go at the next poll.
    pending: BTreeMap<Bytes, BTreeSet<Membership>>,
    /// Per group and membership, the newest version the peer holds or was sent.
    known: BTreeMap<Bytes, BTreeMap<Membership, u64>>,
    /// Per log, the longest the peer showed or was sent.
    theirs: BTreeMap<[u8; 32], u64>,
}

#[derive(Default)]
struct Backoff {
    failures: u32,
    until: u64,
}

impl Peers {
    /// For a member, with iroh key `me`, that came online `now`.
    pub fn new(now: u64, seed: u64, me: Key) -> Self {
        Self {
            me,
            rng: seed,
            online: now,
            full: now,
            changed: None,
            redial: now,
            probe: now + PROBE,
            groups: BTreeMap::new(),
            conns: BTreeMap::new(),
            backoff: BTreeMap::new(),
            dialing: BTreeSet::new(),
        }
    }

    /// This member's state of a group, new or changed.
    pub fn group(&mut self, id: Bytes, own: Own, now: u64) {
        let changed = match self.groups.get_mut(&id) {
            Some(g) => {
                if own.epoch > g.own.epoch {
                    g.struck.clear();
                }
                g.heard.retain(|m, _| *m == own.me || own.members.iter().any(|(n, _)| n == m));
                let changed = (g.own.epoch, g.own.log, &g.own.head) != (own.epoch, own.log, &own.head);
                g.own = own;
                changed
            }
            None => {
                let group = Group { own, heard: BTreeMap::new(), struck: BTreeMap::new(), request: None, waiting: Set::new() };
                self.groups.insert(id, group);
                true
            }
        };
        if changed {
            self.changed.get_or_insert(now);
        }
    }

    pub fn forget(&mut self, id: &Bytes) {
        self.groups.remove(id);
        for c in self.conns.values_mut() {
            c.served.remove(id);
            c.opened.remove(id);
            c.pending.remove(id);
            c.known.remove(id);
        }
    }

    /// A connection to the peer, replacing any other, with the groups the gate admits it to.
    pub fn connect(&mut self, peer: Key, served: BTreeSet<Bytes>, dialed: bool, now: u64) {
        self.disconnect(&peer);
        if self.conns.is_empty() {
            self.online = now;
        }
        self.backoff.remove(&peer);
        let conn = Conn {
            dialed,
            served_at: now,
            active: now,
            hello: true,
            opened: served.clone(),
            served,
            pending: BTreeMap::new(),
            known: BTreeMap::new(),
            theirs: BTreeMap::new(),
        };
        self.conns.insert(peer, conn);
    }

    pub fn disconnect(&mut self, peer: &Key) {
        self.conns.remove(peer);
        for g in self.groups.values_mut() {
            g.request.take_if(|r| r.holder == *peer);
        }
    }

    /// The groups the gate admits the peer to now.
    pub fn served(&mut self, peer: &Key, served: BTreeSet<Bytes>, now: u64) {
        let Some(c) = self.conns.get_mut(peer).filter(|c| c.served != served) else { return };
        let newly: Vec<Bytes> = served.difference(&c.served).cloned().collect();
        if !newly.is_empty() {
            c.hello = true;
            c.opened.extend(newly);
        }
        if !served.is_empty() {
            c.served_at = now;
        }
        c.known.retain(|id, _| served.contains(id));
        c.pending.retain(|id, _| served.contains(id));
        c.served = served;
        for (id, g) in &mut self.groups {
            if !c.served.contains(id) {
                g.request.take_if(|r| r.holder == *peer);
            }
        }
    }

    /// The peers connected now.
    pub fn connected(&self) -> Vec<Key> {
        self.conns.keys().copied().collect()
    }

    pub fn is_connected(&self, peer: &Key) -> bool {
        self.conns.contains_key(peer)
    }

    /// Whether a peer is connected, and the gate admits it to the group.
    pub fn serves(&self, peer: &Key, group: &Bytes) -> bool {
        self.conns.get(peer).is_some_and(|c| c.served.contains(group))
    }

    /// A dial `Out::Dial` asked for has ended.
    pub fn dialed(&mut self, peer: &Key, ok: bool, now: u64) {
        self.dialing.remove(peer);
        if !ok {
            let b = self.backoff.entry(*peer).or_default();
            b.failures += 1;
            b.until = now + (BACKOFF << (b.failures - 1).min(6)).min(MAX_BACKOFF);
        }
    }

    /// Directed traffic on the connection: a want, an answer, files, admission, state.
    pub fn used(&mut self, peer: &Key, now: u64) {
        if let Some(c) = self.conns.get_mut(peer) {
            c.active = now;
        }
    }

    /// A frame from a connected peer, after the node's own checks. `Summaries` go to `summary`.
    pub fn frame(&mut self, peer: &Key, frame: &Frame, now: u64) -> Vec<Out> {
        let Some(c) = self.conns.get_mut(peer) else { return Vec::new() };
        match frame {
            Frame::Hello { groups } => {
                for (log, length) in groups.iter().map(|at| (at.log, at.head.as_ref().map_or(0, |h| h.length))) {
                    let theirs = c.theirs.entry(log).or_default();
                    *theirs = (*theirs).max(length);
                }
                Vec::new()
            }
            Frame::Versions { group, versions } => {
                let Some(g) = self.groups.get(group) else { return Vec::new() };
                if !c.served.contains(group) {
                    return Vec::new();
                }
                // What the peer lists is what it holds: a summary sent it that it does not list was dropped, and is sent again.
                let known = c.known.entry(group.clone()).or_default();
                *known = versions.iter().map(|v| ((v.key.clone(), v.joined), v.version)).collect();
                let mut items = Vec::new();
                for (m, h) in &g.heard {
                    let k = known.entry(m.clone()).or_default();
                    if *k < h.summary.version {
                        *k = h.summary.version;
                        items.push(h.signed.clone());
                    }
                }
                if items.is_empty() {
                    Vec::new()
                } else {
                    vec![Out::Frame(*peer, Frame::Summaries { group: group.clone(), items })]
                }
            }
            Frame::Held { group, items, answers: Some(answers) } => {
                c.active = now;
                if let Some(g) = self.groups.get_mut(group)
                    && let Some(r) = g.request.take_if(|r| r.holder == *peer)
                    && r.epoch == g.own.epoch
                {
                    // An answer short of `ANSWER` bytes, or covering nothing, is all the holder has of what was asked.
                    let whole = answers.is_empty() || items.iter().map(|item| item.0.len()).sum::<usize>() < ANSWER;
                    let covered = if whole { r.asked } else { to_set(answers) };
                    for (m, seqs) in covered {
                        let struck = g.struck.entry((*peer, m)).or_default();
                        *struck = struck.union(&seqs);
                    }
                }
                Vec::new()
            }
            Frame::Want { .. } => {
                c.active = now;
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// A verified summary, from a peer or, with `from: None`, this member's own. Returns whether it was kept.
    pub fn summary(&mut self, group: &Bytes, heard: Heard, from: Option<Key>) -> bool {
        let Some(g) = self.groups.get_mut(group) else { return false };
        let m = (heard.summary.member.clone(), heard.summary.joined);
        let version = heard.summary.version;
        let current = m == g.own.me || g.own.members.iter().any(|(n, _)| *n == m);
        if !current || g.heard.get(&m).is_some_and(|h| h.summary.version >= version) {
            return false;
        }
        g.heard.insert(m.clone(), heard);
        for (k, c) in &mut self.conns {
            if !c.served.contains(group) {
                continue;
            }
            let known = c.known.entry(group.clone()).or_default().entry(m.clone()).or_default();
            if *known >= version {
                continue;
            }
            *known = version;
            if Some(*k) != from {
                c.pending.entry(group.clone()).or_default().insert(m.clone());
            }
        }
        true
    }

    /// The kept summaries of the group, own included.
    pub fn heard(&self, group: &Bytes) -> impl Iterator<Item = &Heard> {
        self.groups.get(group).into_iter().flat_map(|g| g.heard.values())
    }

    /// The connected peers the group is served to.
    pub fn neighbours(&self, group: &Bytes) -> Vec<Key> {
        self.conns.iter().filter(|(_, c)| c.served.contains(group)).map(|(k, _)| *k).collect()
    }

    pub fn full_mesh(&self, group: &Bytes) -> bool {
        self.groups[group].own.members.len() < MESH
    }

    /// Whether to wait before applying a commit that deletes the keys of an epoch, given the seqs of that epoch the
    /// member lacks (kept ones of the epoch the commit ends): not once the holders were tried. `read` is when the node
    /// read the commit.
    pub fn wait(&mut self, group: &Bytes, lacking: &[Seqs], read: u64, now: u64) -> bool {
        let lack = to_set(lacking);
        let since = read.max(self.online);
        let untried = !lack.is_empty() && now < since + WAIT && (now < since + HEAR || self.holder(group, lacking, now));
        self.groups.get_mut(group).expect("a group of ours").waiting = if untried { lack } else { Set::new() };
        untried
    }

    /// Whether a holder of any of `lacking`, by its summary, may still be asked: connected and not struck, or not
    /// connected and past its backoff.
    pub fn holder(&self, group: &Bytes, lacking: &[Seqs], now: u64) -> bool {
        let (lack, g) = (to_set(lacking), &self.groups[group]);
        holds(g).iter().any(|(k, held, _)| self.untried(group, k, now) && !offer(&lack, held, &g.struck, k).is_empty())
    }

    /// What is due, in order: request timeouts, entries and `hello`s, `versions` and summaries, repair, dials, closes.
    pub fn poll(&mut self, now: u64) -> Vec<Out> {
        self.timeouts(now);
        let mut out = self.hellos(now);
        out.extend(self.sync());
        out.extend(self.repair(now));
        out.extend(self.dials(now));
        out.extend(self.closes(now));
        out
    }

    fn random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn backing(&self, peer: &Key, now: u64) -> bool {
        self.backoff.get(peer).is_some_and(|b| now < b.until)
    }

    /// Whether a holder may still be asked: connected and served, or not connected and not backing off or dialing.
    fn untried(&self, group: &Bytes, peer: &Key, now: u64) -> bool {
        match self.conns.get(peer) {
            Some(c) => c.served.contains(group),
            None => self.dialing.contains(peer) || !self.backing(peer, now),
        }
    }

    fn recent(&self, g: &Group, member: &Membership, peer: &Key, now: u64) -> bool {
        self.conns.contains_key(peer) || g.heard.get(member).is_some_and(|h| now < h.summary.time.min(h.at) + RECENT)
    }

    /// The members the group targets: all members in a full mesh, else the best `K` by rank, recent ones first.
    fn targets(&self, group: &Bytes, now: u64) -> Vec<Key> {
        let g = &self.groups[group];
        let mut ranked: Vec<(bool, [u8; 32], Key)> = g
            .own
            .members
            .iter()
            .filter(|(_, k)| !self.backing(k, now))
            .map(|(m, k)| (!self.recent(g, m, k, now), rank(group, &self.me, k), *k))
            .collect();
        ranked.sort();
        ranked.iter().take(K).map(|(_, _, k)| *k).collect()
    }

    fn targeted(&self, now: u64) -> BTreeSet<Key> {
        self.groups.keys().flat_map(|id| self.targets(id, now)).collect()
    }

    /// Dials in flight to the group's members.
    fn flight(&self, group: &Bytes) -> usize {
        self.groups[group].own.members.iter().filter(|(_, k)| self.dialing.contains(k)).count()
    }

    fn timeouts(&mut self, now: u64) {
        for g in self.groups.values_mut() {
            if let Some(r) = g.request.take_if(|r| now - r.at >= TIMEOUT)
                && r.epoch == g.own.epoch
            {
                for (m, asked) in r.asked {
                    let struck = g.struck.entry((r.holder, m)).or_default();
                    *struck = struck.union(&asked);
                }
            }
        }
    }

    /// `entries` to peers that lack them, and `hello`s.
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
                for head in g.own.head.iter().chain(&g.own.earlier) {
                    if let Some(theirs) = c.theirs.get_mut(&head.log_ref)
                        && *theirs < head.length
                    {
                        out.push(Out::Entries { peer: *key, log: Bytes(head.log_ref.to_vec()), after: *theirs });
                        *theirs = head.length;
                    }
                }
            }
            if c.hello || due {
                c.hello = false;
                if !served.is_empty() {
                    let groups = served.iter().map(|(id, g)| At { group: (*id).clone(), log: g.own.log, head: g.own.head.clone() }).collect();
                    out.push(Out::Frame(*key, Frame::Hello { groups }));
                }
            }
        }
        if due {
            self.changed = None;
        }
        out
    }

    /// `versions` of the groups opened to peers, and the summaries pending for them.
    fn sync(&mut self) -> Vec<Out> {
        let mut out = Vec::new();
        for (key, c) in &mut self.conns {
            for id in mem::take(&mut c.opened) {
                if !c.served.contains(&id) {
                    continue;
                }
                let Some(g) = self.groups.get(&id) else { continue };
                let versions: Vec<Version> = g.heard.iter().map(|(m, h)| Version { key: m.0.clone(), joined: m.1, version: h.summary.version }).collect();
                out.push(Out::Frame(*key, Frame::Versions { group: id, versions }));
            }
            for (id, members) in mem::take(&mut c.pending) {
                if !c.served.contains(&id) {
                    continue;
                }
                let Some(g) = self.groups.get(&id) else { continue };
                let items: Vec<Signed> = members.iter().filter_map(|m| g.heard.get(m)).map(|h| h.signed.clone()).collect();
                if !items.is_empty() {
                    out.push(Out::Frame(*key, Frame::Summaries { group: id, items }));
                }
            }
        }
        out
    }

    fn repair(&mut self, now: u64) -> Vec<Out> {
        let mut out = Vec::new();
        for id in self.groups.keys().cloned().collect::<Vec<_>>() {
            let g = &self.groups[&id];
            let epoch = g.own.epoch;
            let holders = holds(g);
            let mut waiting: Vec<(Option<(Membership, u64)>, Key)> = holders
                .iter()
                .filter(|(k, _, _)| !self.conns.contains_key(k) && !self.dialing.contains(k) && !self.backing(k, now))
                .map(|(k, held, _)| (lowest(&offer(&g.waiting, held, &g.struck, k)), *k))
                .filter(|(lowest, _)| lowest.is_some())
                .collect();
            waiting.sort();
            let wanted = union(to_set(&g.own.wanted), &g.waiting);
            let stale = to_set(&g.own.stale);
            let offers: Vec<(Key, Set)> = holders.iter().map(|(k, held, sealed)| (*k, union(offer(&wanted, held, &g.struck, k), &offer(&stale, sealed, &g.struck, k)))).filter(|(_, o)| !o.is_empty()).collect();
            let idle = g.request.is_none();
            let request = offers
                .iter()
                .filter(|(k, _)| self.conns.get(k).is_some_and(|c| c.served.contains(&id)))
                .min_by_key(|(k, o)| (lowest(o), *k))
                .map(|(k, o)| (*k, o.clone()));
            let request = if idle { request } else { None };
            let dial = if idle && request.is_none() && self.flight(&id) == 0 {
                offers.iter().filter(|(k, _)| !self.conns.contains_key(k) && !self.dialing.contains(k) && !self.backing(k, now)).min_by_key(|(k, o)| (lowest(o), *k)).map(|(k, _)| *k)
            } else {
                None
            };
            for k in waiting.into_iter().map(|(_, k)| k).chain(dial) {
                if self.flight(&id) >= DIALS {
                    break;
                }
                if self.dialing.insert(k) {
                    out.push(Out::Dial(k));
                }
            }
            if let Some((holder, asked)) = request {
                let asked: Set = asked.into_iter().map(|(m, r)| (m, r.iter().take(512).collect::<Ranges>())).collect();
                let wants = to_seqs(&asked);
                self.conns.get_mut(&holder).expect("a connected holder").active = now;
                self.groups.get_mut(&id).expect("a group of ours").request = Some(Request { holder, asked, epoch, at: now });
                out.push(Out::Frame(holder, Frame::Want { group: id, epoch, wants }));
            }
        }
        out
    }

    fn dials(&mut self, now: u64) -> Vec<Out> {
        let mut out = Vec::new();
        if now >= self.redial {
            self.redial = now + REDIAL;
            for id in self.groups.keys().cloned().collect::<Vec<_>>() {
                for k in self.targets(&id, now) {
                    if self.flight(&id) >= DIALS {
                        break;
                    }
                    if !self.conns.contains_key(&k) && self.dialing.insert(k) {
                        out.push(Out::Dial(k));
                    }
                }
            }
        }
        if now >= self.probe {
            self.probe = now + PROBE;
            let seen: BTreeSet<Key> = self
                .groups
                .values()
                .flat_map(|g| g.own.members.iter().filter(|(m, k)| self.recent(g, m, k, now) && !self.conns.contains_key(k) && !self.dialing.contains(k) && !self.backing(k, now)).map(|(_, k)| *k))
                .collect();
            let seen: Vec<Key> = seen.into_iter().collect();
            if !seen.is_empty() {
                let k = seen[self.random() as usize % seen.len()];
                self.dialing.insert(k);
                out.push(Out::Dial(k));
            }
        }
        out
    }

    fn closes(&mut self, now: u64) -> Vec<Out> {
        let targeted = self.targeted(now);
        let mut close: Vec<Key> = self
            .conns
            .iter()
            .filter(|(k, c)| if c.served.is_empty() { now - c.served_at >= STRANGER } else { c.dialed && !targeted.contains(*k) && now - c.active >= IDLE })
            .map(|(k, _)| *k)
            .collect();
        while self.conns.len() - close.len() > MAX_CONNECTIONS {
            let Some(k) = self.conns.iter().filter(|(k, _)| !targeted.contains(*k) && !close.contains(*k)).min_by_key(|(_, c)| c.active).map(|(k, _)| *k) else {
                break;
            };
            close.push(k);
        }
        let mut out = Vec::new();
        for k in close {
            self.disconnect(&k);
            out.push(Out::Close(k));
        }
        out
    }
}

fn rank(group: &Bytes, a: &Key, b: &Key) -> [u8; 32] {
    let (low, high) = if a <= b { (a, b) } else { (b, a) };
    Sha256::new().chain_update(b"letmeknow neighbours v1\0").chain_update(&group.0).chain_update(low).chain_update(high).finalize().into()
}

fn membership(seq: &Seqs) -> Membership {
    (seq.key.clone(), seq.joined)
}

fn to_set(seqs: &[Seqs]) -> Set {
    let mut set = Set::new();
    for s in seqs {
        let positions = set.entry(membership(s)).or_default();
        *positions = positions.union(&s.seqs);
    }
    set
}

fn to_seqs(set: &Set) -> Vec<Seqs> {
    set.iter().map(|((key, joined), seqs)| Seqs { key: key.clone(), joined: *joined, seqs: seqs.clone() }).collect()
}

/// Each member with a kept summary, what that summary says it holds, and what it shows sealed in this epoch.
fn holds(g: &Group) -> Vec<(Key, Set, Set)> {
    g.own.members.iter().filter_map(|(m, k)| {
        let summary = &g.heard.get(m)?.summary;
        let sealed = if summary.epoch == g.own.epoch { to_set(&summary.sealed) } else { Set::new() };
        Some((*k, to_set(&summary.held), sealed))
    }).collect()
}

fn union(mut a: Set, b: &Set) -> Set {
    for (m, seqs) in b {
        let all = a.entry(m.clone()).or_default();
        *all = all.union(seqs);
    }
    a
}

/// The positions of `want` that a holder holds and is not struck for.
fn offer(want: &Set, held: &Set, struck: &BTreeMap<(Key, Membership), Ranges>, peer: &Key) -> Set {
    let mut offer = Set::new();
    for (m, wanted) in want {
        let Some(held) = held.get(m) else { continue };
        let struck = struck.get(&(*peer, m.clone())).cloned().unwrap_or_default();
        let positions = wanted.intersection(held).difference(&struck);
        if !positions.is_empty() {
            offer.insert(m.clone(), positions);
        }
    }
    offer
}

fn lowest(set: &Set) -> Option<(Membership, u64)> {
    set.iter().find_map(|(m, seqs)| Some((m.clone(), seqs.first()?)))
}

/// The `Held` answer to a `want`: the asked ciphertexts this member holds, in order, until about `ANSWER` bytes, and
/// the asked seqs covered.
pub fn answer(group: Bytes, asked: &[Seqs], held: &[Seqs], mut ciphertext: impl FnMut(&Bytes, u64, u64) -> Option<Vec<u8>>) -> Frame {
    let asked = to_set(asked);
    let held = to_set(held);
    let mut covered = asked.clone();
    let mut items = Vec::new();
    let mut size = 0;
    'asked: for (m, r) in &asked {
        let Some(h) = held.get(m) else { continue };
        for s in r.intersection(h).iter() {
            if size >= ANSWER {
                covered.retain(|n, _| n <= m);
                covered.insert(m.clone(), r.through(s - 1));
                break 'asked;
            }
            if let Some(c) = ciphertext(&m.0, m.1, s) {
                size += c.len();
                items.push(Bytes(c));
            }
        }
    }
    Frame::Held { group, items, answers: Some(to_seqs(&covered)) }
}

/// Whether a member acts on a frame from a peer: `hello` and `entries` from anyone, the rest only from admitted peers.
pub fn takes(frame: &Frame, admitted: bool) -> bool {
    matches!(frame, Frame::Hello { .. } | Frame::Entries { .. }) || admitted
}

#[cfg(test)]
mod tests;
