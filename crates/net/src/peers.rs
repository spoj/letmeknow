//! The peer protocol without I/O, across a member's connections: which peers to dial and close, the summaries
//! neighbours exchange, whom they know to be online, repair by pull, and the wait before a commit that deletes an
//! epoch's keys. The node feeds it state and frames, polls it when `next` says or something changed, and sends what it
//! returns. Nothing in it is periodic: a member dials as it starts, as its groups change, as a neighbour tells it of a
//! member online it did not know of, and as it has something to push, so of two members the later one online dials.
//! Times are milliseconds.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem,
};

use lmk_proto::{
    Bytes,
    head::Head,
    peer::{At, Frame, Seqs, Signed, Summary},
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
pub const TIMEOUT: u64 = 10_000;
/// How long a request for messages its holder announced waits for the answer: one may be 16 MiB, through a relay that
/// passes 1 MiB a second, shared.
pub const LARGE_TIMEOUT: u64 = 120_000;
pub const ANSWER: usize = 1 << 20;
pub const K: usize = 6;
const MESH: usize = 7;
pub const BACKOFF: u64 = 10_000;
pub const MAX_BACKOFF: u64 = 600_000;
/// How long a sighting, or a summary heard, shows a member online.
pub const RECENT: u64 = 7_200_000;
/// How much fresher than the one a neighbour was last told a sighting must be to be told again.
pub const RETELL: u64 = 1_800_000;
/// How often `poll` is due while a repair or a wait is on.
pub const BUSY: u64 = 250;
pub const IDLE: u64 = 300_000;
pub const STRANGER: u64 = 30_000;
pub const MAX_CONNECTIONS: usize = 128;
/// From when a wait starts, or the member came online, whichever is later, until it gives up.
pub const WAIT: u64 = 120_000;
/// From then, how long a wait holds though no summary shows a holder: a member back online hears its neighbours'
/// summaries within it.
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
    /// The signed intros of the current memberships, own included, with their versions: each goes to every neighbour
    /// not told it.
    pub intros: BTreeMap<Membership, (u64, Signed)>,
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
    /// When the member last went from no connections to one.
    online: u64,
    /// When a change to a `hello` arose, unsent.
    changed: Option<u64>,
    /// The groups whose targets are dialed at the next poll.
    dial: BTreeSet<Bytes>,
    groups: BTreeMap<Bytes, Group>,
    conns: BTreeMap<Key, Conn>,
    backoff: BTreeMap<Key, Backoff>,
    /// Peers with a `Dial` in flight.
    dialing: BTreeSet<Key>,
}

struct Group {
    own: Own,
    /// The kept summaries of the current memberships, own included: neighbours', as they came.
    heard: BTreeMap<Membership, Heard>,
    /// When each other member was last known online: connected to this member until then, or to a neighbour that said so.
    seen: BTreeMap<Key, u64>,
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
    /// When it times out: `TIMEOUT` after it was made, or `LARGE_TIMEOUT` if it asks for what the holder announced.
    until: u64,
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
    /// Groups whose own summary is due at the next poll.
    opened: BTreeSet<Bytes>,
    /// Per group, the version of the own summary it was sent.
    sent: BTreeMap<Bytes, u64>,
    /// Per log, the longest the peer showed or was sent.
    theirs: BTreeMap<[u8; 32], u64>,
    /// Per group, the latest sighting of each member the peer told or was told.
    told: BTreeMap<Bytes, BTreeMap<Key, u64>>,
    /// Per group, the latest version of each membership's intro the peer told or was told.
    introduced: BTreeMap<Bytes, BTreeMap<Membership, u64>>,
    /// Per group, the held messages the peer announced it holds.
    has: BTreeMap<Bytes, Set>,
}

#[derive(Default)]
struct Backoff {
    failures: u32,
    until: u64,
    /// When its last dial failed: no sighting from before shows it online.
    failed: u64,
}

impl Peers {
    /// For a member, with iroh key `me`, that came online `now`.
    pub fn new(now: u64, me: Key) -> Self {
        Self {
            me,
            online: now,
            changed: None,
            dial: BTreeSet::new(),
            groups: BTreeMap::new(),
            conns: BTreeMap::new(),
            backoff: BTreeMap::new(),
            dialing: BTreeSet::new(),
        }
    }

    /// This member's state of a group, new or changed. A new group, or one whose members changed, dials its targets.
    pub fn group(&mut self, id: Bytes, own: Own, now: u64) {
        let (changed, members) = match self.groups.get_mut(&id) {
            Some(g) => {
                if own.epoch > g.own.epoch {
                    g.struck.clear();
                }
                g.heard.retain(|m, _| *m == own.me || own.members.iter().any(|(n, _)| n == m));
                g.seen.retain(|k, _| own.members.iter().any(|(_, n)| n == k));
                let changed = (g.own.epoch, g.own.log, &g.own.head, &g.own.intros) != (own.epoch, own.log, &own.head, &own.intros);
                let members = g.own.members != own.members;
                g.own = own;
                (changed, members)
            }
            None => {
                let group = Group { own, heard: BTreeMap::new(), seen: BTreeMap::new(), struck: BTreeMap::new(), request: None, waiting: Set::new() };
                self.groups.insert(id.clone(), group);
                (true, true)
            }
        };
        if changed {
            self.changed.get_or_insert(now);
        }
        if members {
            self.dial.insert(id);
        }
    }

    /// The member has something to push in the group: its targets not connected are dialed.
    pub fn push(&mut self, id: &Bytes) {
        self.dial.insert(id.clone());
    }

    pub fn forget(&mut self, id: &Bytes) {
        self.groups.remove(id);
        self.dial.remove(id);
        for c in self.conns.values_mut() {
            c.served.remove(id);
            c.opened.remove(id);
            c.sent.remove(id);
            c.told.remove(id);
            c.introduced.remove(id);
            c.has.remove(id);
        }
    }

    /// A connection to the peer, replacing any other, with the groups the gate admits it to. The other neighbours of
    /// those groups are told of it.
    pub fn connect(&mut self, peer: Key, served: BTreeSet<Bytes>, dialed: bool, now: u64) {
        self.disconnect(&peer, now);
        if self.conns.is_empty() {
            self.online = now;
        }
        if !served.is_empty() {
            self.changed.get_or_insert(now);
        }
        self.backoff.remove(&peer);
        let conn = Conn { dialed, served_at: now, active: now, hello: true, opened: served.clone(), served, sent: BTreeMap::new(), theirs: BTreeMap::new(), told: BTreeMap::new(), introduced: BTreeMap::new(), has: BTreeMap::new() };
        self.conns.insert(peer, conn);
    }

    /// The connection to the peer ended: a member was online until now.
    pub fn disconnect(&mut self, peer: &Key, now: u64) {
        self.conns.remove(peer);
        for g in self.groups.values_mut() {
            g.request.take_if(|r| r.holder == *peer);
            if g.own.members.iter().any(|(_, k)| k == peer) {
                g.seen.insert(*peer, now);
            }
        }
    }

    /// The groups the gate admits the peer to now.
    pub fn served(&mut self, peer: &Key, served: BTreeSet<Bytes>, now: u64) {
        let Some(c) = self.conns.get_mut(peer).filter(|c| c.served != served) else { return };
        let newly: Vec<Bytes> = served.difference(&c.served).cloned().collect();
        if !newly.is_empty() {
            c.hello = true;
            c.opened.extend(newly);
            self.changed.get_or_insert(now);
        }
        if !served.is_empty() {
            c.served_at = now;
        }
        c.sent.retain(|id, _| served.contains(id));
        c.told.retain(|id, _| served.contains(id));
        c.introduced.retain(|id, _| served.contains(id));
        c.has.retain(|id, _| served.contains(id));
        c.served = served;
        for (id, g) in &mut self.groups {
            if !c.served.contains(id) {
                g.request.take_if(|r| r.holder == *peer);
            }
        }
    }

    /// The peer sent what shows it is past this member in a group, as a message of a later epoch: a `hello` tells it where
    /// this member is, so that it sends the entries this member lacks.
    pub fn behind(&mut self, peer: &Key) {
        if let Some(c) = self.conns.get_mut(peer) {
            c.hello = true;
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

    /// A dial `Out::Dial` asked for has ended. A failed one backs off, and its groups dial their next targets.
    pub fn dialed(&mut self, peer: &Key, ok: bool, now: u64) {
        self.dialing.remove(peer);
        if !ok {
            let b = self.backoff.entry(*peer).or_default();
            b.failures += 1;
            b.until = now + (BACKOFF << (b.failures - 1).min(6)).min(MAX_BACKOFF);
            b.failed = now;
            let of: Vec<Bytes> = self.groups.iter().filter(|(_, g)| g.own.members.iter().any(|(_, k)| k == peer)).map(|(id, _)| id.clone()).collect();
            self.dial.extend(of);
        }
    }

    /// Directed traffic on the connection: a want, an answer, files, admission, state.
    pub fn used(&mut self, peer: &Key, now: u64) {
        if let Some(c) = self.conns.get_mut(peer) {
            c.active = now;
        }
    }

    /// A frame from a connected peer, after the node's own checks: a `hello`'s intros after the node took them into
    /// `Own`. A `summary` goes to `summary`.
    pub fn frame(&mut self, peer: &Key, frame: &Frame, now: u64) {
        let Some(c) = self.conns.get_mut(peer) else { return };
        match frame {
            Frame::Hello { groups } => {
                for (log, length) in groups.iter().map(|at| (at.log, at.head.as_ref().map_or(0, |h| h.length))) {
                    let theirs = c.theirs.entry(log).or_default();
                    *theirs = (*theirs).max(length);
                }
                let served: Vec<&At> = groups.iter().filter(|at| c.served.contains(&at.group)).collect();
                for at in served {
                    self.saw(peer, &at.group, &at.seen, now);
                    let Some(g) = self.groups.get(&at.group) else { continue };
                    let c = self.conns.get_mut(peer).expect("a connected peer");
                    let introduced = c.introduced.entry(at.group.clone()).or_default();
                    for (m, (version, _)) in g.own.intros.iter().filter(|(_, (_, signed))| at.intros.contains(signed)) {
                        introduced.insert(m.clone(), *version);
                    }
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
            }
            Frame::Want { .. } => c.active = now,
            Frame::Have { group, held } if c.served.contains(group) => {
                let has = c.has.entry(group.clone()).or_default();
                *has = union(mem::take(has), &to_set(held));
            }
            _ => {}
        }
    }

    /// A verified summary: a neighbour's, which goes no further, or this member's own, with `own`, which goes to every
    /// neighbour the group is served to. Returns whether it was kept.
    pub fn summary(&mut self, group: &Bytes, heard: Heard, own: bool) -> bool {
        let Some(g) = self.groups.get_mut(group) else { return false };
        let m = (heard.summary.member.clone(), heard.summary.joined);
        let current = m == g.own.me || g.own.members.iter().any(|(n, _)| *n == m);
        if !current || g.heard.get(&m).is_some_and(|h| h.summary.version >= heard.summary.version) {
            return false;
        }
        g.heard.insert(m, heard);
        if own {
            for c in self.conns.values_mut().filter(|c| c.served.contains(group)) {
                c.opened.insert(group.clone());
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
    /// began waiting, for this commit or, as it was made before then, for an earlier one.
    pub fn wait(&mut self, group: &Bytes, lacking: &[Seqs], read: u64, now: u64) -> bool {
        let lack = to_set(lacking);
        let since = read.max(self.online);
        let untried = !lack.is_empty() && now < since + WAIT && (now < since + HEAR || self.holder(group, lacking, now));
        self.groups.get_mut(group).expect("a group of ours").waiting = if untried { lack } else { Set::new() };
        untried
    }

    /// Whether a holder of any of `lacking`, by its summary or what it announced, may still be asked: connected and not
    /// struck, or not connected and past its backoff.
    pub fn holder(&self, group: &Bytes, lacking: &[Seqs], now: u64) -> bool {
        let (lack, g) = (to_set(lacking), &self.groups[group]);
        self.holds(group).iter().any(|(k, held, _)| self.untried(group, k, now) && !offer(&lack, held, &g.struck, k).is_empty())
    }

    /// What is due, in order: request timeouts, entries and `hello`s, own summaries, repair, dials, closes.
    pub fn poll(&mut self, now: u64) -> Vec<Out> {
        self.timeouts(now);
        let mut out = self.hellos(now);
        out.extend(self.sync());
        out.extend(self.repair(now));
        out.extend(self.dials(now));
        out.extend(self.closes(now));
        out
    }

    /// When `poll` is next due, if nothing changes before: `BUSY` after `now` while a repair or a wait is on.
    pub fn next(&self, now: u64) -> Option<u64> {
        let busy = self.groups.values().any(|g| g.request.is_some() || !g.own.wanted.is_empty() || !g.own.stale.is_empty() || !g.waiting.is_empty());
        let dial = self.dial.iter().any(|id| self.groups.contains_key(id) && self.flight(id) < DIALS);
        let due = dial || self.conns.values().any(|c| c.hello || !c.opened.is_empty());
        let targeted = self.targeted(now);
        let closes = self.conns.iter().filter_map(|(k, c)| match () {
            _ if c.served.is_empty() => Some(c.served_at + STRANGER),
            _ if c.dialed && !targeted.contains(k) => Some(c.active + IDLE),
            _ => None,
        });
        let times = [due.then_some(now), busy.then_some(now + BUSY), self.changed.map(|since| since + DEBOUNCE)];
        times.into_iter().flatten().chain(closes).min()
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

    /// Whether a sighting at `at` shows the member online now: within `RECENT`, and since its last failed dial.
    fn alive(&self, peer: &Key, at: u64, now: u64) -> bool {
        now < at + RECENT && self.backoff.get(peer).is_none_or(|b| at > b.failed)
    }

    /// How sure this member is that a member is online, surest first: connected, seen online, heard from within
    /// `RECENT`, or none of these.
    fn tier(&self, g: &Group, member: &Membership, peer: &Key, now: u64) -> u8 {
        match () {
            _ if self.conns.contains_key(peer) => 0,
            _ if g.seen.get(peer).is_some_and(|at| self.alive(peer, *at, now)) => 1,
            _ if g.heard.get(member).is_some_and(|h| now < h.at + RECENT) => 2,
            _ => 3,
        }
    }

    /// Takes the sightings of a group's members that a neighbour told: as told to it, and as this member's own when
    /// fresher. One of a member this member did not know to be online is news: it tells its neighbours, and dials the
    /// group's targets again.
    fn saw(&mut self, peer: &Key, group: &Bytes, seen: &BTreeMap<Bytes, u64>, now: u64) {
        let Some(g) = self.groups.get(group) else { return };
        let members: BTreeSet<&Key> = g.own.members.iter().map(|(_, k)| k).collect();
        let sightings: Vec<(Key, u64)> = seen
            .iter()
            .filter_map(|(key, ago)| Key::try_from(key.0.as_slice()).ok().filter(|k| members.contains(k)).map(|k| (k, now.saturating_sub(*ago))))
            .collect();
        let known = |k: &Key| self.conns.contains_key(k) || g.seen.get(k).is_some_and(|at| self.alive(k, *at, now));
        let news = sightings.iter().any(|(k, at)| self.alive(k, *at, now) && !known(k));
        let told = self.conns.get_mut(peer).expect("a connected peer").told.entry(group.clone()).or_default();
        let mine = &mut self.groups.get_mut(group).expect("a group of ours").seen;
        for (k, at) in sightings {
            for latest in [told.entry(k).or_default(), mine.entry(k).or_default()] {
                *latest = (*latest).max(at);
            }
        }
        if news {
            self.changed.get_or_insert(now);
            self.dial.insert(group.clone());
        }
    }

    /// When this member last knew each of the group's members it ever knew online to be: now for its neighbours.
    fn sightings(&self, group: &Bytes, now: u64) -> BTreeMap<Key, u64> {
        let mut seen = self.groups[group].seen.clone();
        seen.extend(self.neighbours(group).into_iter().map(|k| (k, now)));
        seen
    }

    /// For each of the group's members this member ever knew online, when it last knew, and whether it is connected to
    /// it now.
    pub fn presence(&self, group: &Bytes, now: u64) -> BTreeMap<Key, (u64, bool)> {
        let Some(g) = self.groups.get(group) else { return BTreeMap::new() };
        let mut presence: BTreeMap<Key, (u64, bool)> = g.seen.iter().map(|(k, at)| (*k, (*at, false))).collect();
        presence.extend(g.own.members.iter().filter(|(_, k)| self.conns.contains_key(k)).map(|(_, k)| (*k, (now, true))));
        presence
    }

    /// The members the group targets: all members in a full mesh, else the best `K` by rank, the surest to be online
    /// first.
    fn targets(&self, group: &Bytes, now: u64) -> Vec<Key> {
        let g = &self.groups[group];
        let mut ranked: Vec<(u8, [u8; 32], Key)> = g
            .own
            .members
            .iter()
            .filter(|(_, k)| !self.backing(k, now))
            .map(|(m, k)| (self.tier(g, m, k, now), rank(group, &self.me, k), *k))
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

    /// Each member with a kept summary or announcements on its connection, what it holds by them, and what its summary
    /// shows sealed in this epoch.
    fn holds(&self, group: &Bytes) -> Vec<(Key, Set, Set)> {
        let g = &self.groups[group];
        g.own.members.iter().filter_map(|(m, k)| {
            let summary = g.heard.get(m).map(|h| &h.summary);
            let announced = self.conns.get(k).and_then(|c| c.has.get(group));
            if summary.is_none() && announced.is_none() {
                return None;
            }
            let held = summary.map_or_else(Set::new, |s| to_set(&s.held));
            let held = match announced {
                Some(announced) => union(held, announced),
                None => held,
            };
            let sealed = summary.filter(|s| s.epoch == g.own.epoch).map_or_else(Set::new, |s| to_set(&s.sealed));
            Some((*k, held, sealed))
        }).collect()
    }

    fn timeouts(&mut self, now: u64) {
        for g in self.groups.values_mut() {
            if let Some(r) = g.request.take_if(|r| now >= r.until)
                && r.epoch == g.own.epoch
            {
                for (m, asked) in r.asked {
                    let struck = g.struck.entry((r.holder, m)).or_default();
                    *struck = struck.union(&asked);
                }
            }
        }
    }

    /// `entries` to peers that lack them, and `hello`s: each tells the peer the sightings it was not told, or was told
    /// `RETELL` staler, and the intros it was not told.
    fn hellos(&mut self, now: u64) -> Vec<Out> {
        let due = self.changed.is_some_and(|since| now - since >= DEBOUNCE);
        let sightings: BTreeMap<Bytes, BTreeMap<Key, u64>> = match due || self.conns.values().any(|c| c.hello) {
            true => self.groups.keys().map(|id| (id.clone(), self.sightings(id, now))).collect(),
            false => BTreeMap::new(),
        };
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
                    let groups = served
                        .iter()
                        .map(|(id, g)| {
                            let told = c.told.entry((*id).clone()).or_default();
                            let untold: BTreeMap<Key, u64> = sightings[*id].iter().filter(|(k, at)| *k != key && told.get(*k).is_none_or(|t| **at > t + RETELL)).map(|(k, at)| (*k, *at)).collect();
                            told.extend(&untold);
                            let seen = untold.iter().map(|(k, at)| (Bytes(k.to_vec()), now - at)).collect();
                            let introduced = c.introduced.entry((*id).clone()).or_default();
                            let mut intros = Vec::new();
                            for (m, (version, signed)) in &g.own.intros {
                                if introduced.get(m).is_none_or(|told| told < version) {
                                    introduced.insert(m.clone(), *version);
                                    intros.push(signed.clone());
                                }
                            }
                            At { group: (*id).clone(), log: g.own.log, head: g.own.head.clone(), seen, intros }
                        })
                        .collect();
                    out.push(Out::Frame(*key, Frame::Hello { groups }));
                }
            }
        }
        if due {
            self.changed = None;
        }
        out
    }

    /// This member's own summary of each group opened to a peer, unless the peer was sent it.
    fn sync(&mut self) -> Vec<Out> {
        let mut out = Vec::new();
        for (key, c) in &mut self.conns {
            for id in mem::take(&mut c.opened) {
                let Some(h) = self.groups.get(&id).and_then(|g| g.heard.get(&g.own.me)) else { continue };
                let sent = c.sent.entry(id.clone()).or_default();
                if c.served.contains(&id) && *sent < h.summary.version {
                    *sent = h.summary.version;
                    out.push(Out::Frame(*key, Frame::Summary { group: id, summary: h.signed.clone() }));
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
            let holders = self.holds(&id);
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
                let c = self.conns.get_mut(&holder).expect("a connected holder");
                c.active = now;
                let announced = c.has.get(&id).is_some_and(|has| !offer(&asked, has, &BTreeMap::new(), &holder).is_empty());
                let until = now + if announced { LARGE_TIMEOUT } else { TIMEOUT };
                self.groups.get_mut(&id).expect("a group of ours").request = Some(Request { holder, asked, epoch, until });
                out.push(Out::Frame(holder, Frame::Want { group: id, epoch, wants }));
            }
        }
        out
    }

    /// The targets not connected of each group due to dial, `DIALS` at a time: a group stays due until each was dialed.
    fn dials(&mut self, now: u64) -> Vec<Out> {
        let mut out = Vec::new();
        for id in mem::take(&mut self.dial) {
            if !self.groups.contains_key(&id) {
                continue;
            }
            let undialed: Vec<Key> = self.targets(&id, now).into_iter().filter(|k| !self.conns.contains_key(k) && !self.dialing.contains(k)).collect();
            for k in undialed {
                if self.flight(&id) >= DIALS {
                    self.dial.insert(id.clone());
                    break;
                }
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
            self.disconnect(&k, now);
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
