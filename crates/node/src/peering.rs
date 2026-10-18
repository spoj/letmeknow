//! The node's side of the peer protocol (`lmk_net::peers`): it hands `Peers` this session's state of each group and the
//! frames peers send, takes those frames by the gate, signs this session's summaries and checks members', answers
//! `want` from the sealings it holds, passes live payloads on, and sends what `Peers` produces once the step commits.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::{EndpointId, RelayUrl};
use lmk_core::provider::Provider;
use lmk_membership::Contradiction;
use lmk_net::Groups;
use lmk_net::peers::{self, Own};
use lmk_proto::Bytes;
use lmk_proto::head::Head;
use lmk_proto::links::FileLink;
use lmk_proto::peer::{At, Frame, SUMMARY, Seqs, Signed, Summary};
use n0_future::StreamExt;
use n0_future::task::spawn;
use n0_future::time::{Duration, sleep};
use serde::{Deserialize, Serialize};

use crate::logs::Of;
use crate::{Event, Inner, Lost, LostOf, Member, Node, Out, State, days, get, now, put};

/// How often `Peers` is polled.
const POLL: Duration = Duration::from_millis(250);
/// How long a live payload goes on, in hops.
const HOPS: u8 = 6;
/// A membership's live payloads are allowed ten times what its held messages are.
const LIVE_SCALE: f64 = 10.0;
/// A member signs its summary at least this often.
const RESIGN: u64 = 60 * 60 * 1000;
/// How many summaries of memberships not known yet a group keeps.
const UNVERIFIED: usize = 32;

/// A member's latest summary of a group: what it holds, what its client showed, and when it was signed, at most when
/// it came.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heard {
    pub member: Member,
    pub joined: u64,
    pub held: Vec<Seqs>,
    pub shown: Vec<Seqs>,
    pub at: u64,
}

/// A summary as saved.
#[derive(Serialize, Deserialize)]
struct Saved {
    signed: Signed,
    at: u64,
}

/// Where a member said it was: its home relay, and when the summary that said so was signed. Saved when the relay
/// changes, with that summary's time; the newest time is held in memory.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Hint {
    pub relay: String,
    time: u64,
}

pub(crate) fn hint_key(key: &[u8]) -> Vec<u8> {
    [b"node/hint/".as_slice(), key].concat()
}

fn heard_key(gid: &[u8], key: &[u8], joined: u64) -> Vec<u8> {
    [b"node/heard/".as_slice(), gid, b"/", key, b"/", &joined.to_be_bytes()].concat()
}

/// The group a frame other than `hello` and `entries` is of.
fn group_of(frame: &Frame) -> Option<&Bytes> {
    match frame {
        Frame::Hello { .. } | Frame::Entries { .. } => None,
        Frame::Versions { group, .. }
        | Frame::Summaries { group, .. }
        | Frame::Held { group, .. }
        | Frame::Want { group, .. }
        | Frame::WantFiles { group, .. }
        | Frame::Have { group, .. }
        | Frame::Live { group, .. } => Some(group),
    }
}

impl<P: Provider> State<P> {
    /// Now, never before an earlier step's now.
    pub(crate) fn tick(&mut self) -> u64 {
        self.time = self.time.max(now());
        self.time
    }

    /// Whether this session has applied the group's log to its head as last read.
    pub(crate) fn at_head(&self, gid: &[u8]) -> bool {
        self.groups.get(gid).is_some_and(|g| self.held_to(gid).is_ok_and(|held| g.rec.position >= held))
    }

    /// This session's state of a group, as `Peers` takes it.
    fn own(&mut self, gid: &[u8], now: u64) -> Own {
        let mut logs = self.group_logs(gid);
        let log = logs.pop().unwrap();
        let heads = |logs: &[Vec<u8>]| logs.iter().filter_map(|log| self.logs.get(log)?.head.clone()).collect();
        let (head, earlier) = (self.logs[&log].head.clone(), heads(&logs));
        let me = self.me(gid).to_vec();
        let g = self.groups.get_mut(gid).unwrap();
        let (wanted, stale) = g.wanted(now, &me);
        let public = g.public.iter().filter_map(|log| self.logs.get(log)?.head.clone()).collect();
        let members = g.mls.members().into_iter().filter(|m| m.key != me).filter_map(|m| {
            let iroh = m.leaf.as_ref()?.key.0.as_slice().try_into().ok()?;
            Some(((Bytes(m.key.clone()), g.mls.joined(&m.key)?), iroh))
        });
        Own {
            me: (Bytes(me.clone()), g.mls.joined(&me).unwrap_or_default()),
            epoch: g.mls.epoch(),
            log: log.as_slice().try_into().unwrap(),
            head,
            public,
            earlier,
            members: members.collect(),
            wanted,
            stale,
        }
    }

    /// The relay a member last said it was on, which a dial to it tries first.
    pub(crate) fn hint_of(&self, peer: &EndpointId) -> Option<RelayUrl> {
        self.hints.get(&Bytes(peer.as_bytes().to_vec())).and_then(|hint| hint.relay.parse().ok())
    }

    /// Hands `Peers` this session's state of a group.
    pub(crate) fn refresh(&mut self, gid: &[u8]) {
        let now = self.tick();
        let own = self.own(gid, now);
        self.peers.group(Bytes(gid.to_vec()), own, now);
    }

    /// Hands `Peers` the gate, and this session's state of each group: at each poll, before `Peers` sends anything. A
    /// step hands it only a group added (`add_group`) or moved to a new epoch (`apply`), whose frames may follow at once.
    pub(crate) fn tell_peers(&mut self) {
        self.gate();
        let gids: Vec<Vec<u8>> = self.groups.keys().cloned().collect();
        for gid in gids {
            self.refresh(&gid);
        }
    }

    fn served_to(&self, peer: &EndpointId) -> BTreeSet<Bytes> {
        self.groups.keys().filter(|gid| self.serves(gid, peer)).map(|gid| Bytes(gid.clone())).collect()
    }

    /// Works out again, once the rosters or the public logs changed, which groups the gate admits each connected peer to,
    /// and which public logs each group follows.
    pub(crate) fn gate(&mut self) {
        if !std::mem::take(&mut self.gate) {
            return;
        }
        let now = self.tick();
        let gids: Vec<Vec<u8>> = self.groups.keys().cloned().collect();
        for gid in &gids {
            let mut public: Vec<Vec<u8>> = self.identities(gid).iter().filter_map(|identity| self.public_log(&identity.id.0)).collect();
            public.sort();
            public.dedup();
            self.groups.get_mut(gid).unwrap().public = public;
        }
        let peers: Vec<EndpointId> = self.served.keys().copied().collect();
        for peer in peers {
            let served = self.served_to(&peer);
            if self.served[&peer] != served {
                self.peers.served(peer.as_bytes(), served.clone(), now);
                self.served.insert(peer, served);
            }
        }
    }

    /// Whether the gate admits a connected peer to a group.
    pub(crate) fn admitted(&mut self, gid: &[u8], peer: &EndpointId) -> bool {
        self.gate();
        self.served.get(peer).is_some_and(|served| served.contains(&Bytes(gid.to_vec())))
    }

    /// Sends a frame of a group to a peer once the step commits, if the gate lets it go.
    pub(crate) fn emit(&mut self, gid: &[u8], peer: EndpointId, frame: Frame) {
        if peers::sends(&frame, self.admitted(gid, &peer), self.at_head(gid)) {
            self.out.push(Out::Frame { peer, frame });
        }
    }

    /// What of a frame goes to a peer as it is written, by the gate as it is then: a step may have removed the peer
    /// since another queued the frame.
    pub(crate) fn admissible(&mut self, peer: &EndpointId, frame: Frame) -> Option<Frame> {
        if let Frame::Hello { groups, heads } = frame {
            let groups = groups.into_iter().filter(|at| self.admitted(&at.group.0, peer)).collect();
            return Some(Frame::Hello { groups, heads });
        }
        let group = match &frame {
            // Every `want` is answered, with nothing if the gate refuses it.
            Frame::Held { items, answers: Some(_), .. } if items.is_empty() => None,
            // A group's earlier logs go to whom they were queued for: a peer that showed it holds the log, or a member
            // its last commit removed.
            Frame::Entries { log, .. } => match self.logs.get(&log.0).map(|log| &log.of) {
                Some(Of::Group(group)) if self.groups.get(&group.0).is_some_and(|g| g.rec.log == *log) => Some(group),
                _ => None,
            },
            frame => group_of(frame),
        };
        let Some(gid) = group.map(|group| group.0.clone()) else { return Some(frame) };
        peers::sends(&frame, self.admitted(&gid, peer), self.at_head(&gid)).then_some(frame)
    }

    /// Sends a frame of a group to every neighbour the gate lets it go to.
    pub(crate) fn broadcast(&mut self, gid: &[u8], frame: Frame) {
        for peer in self.peers.neighbours(&Bytes(gid.to_vec())) {
            if let Ok(peer) = EndpointId::from_bytes(&peer) {
                self.emit(gid, peer, frame.clone());
            }
        }
    }

    /// This session's summary of a group, signed and handed to `Peers`, when it changed and its last is old enough, or
    /// hourly.
    fn sign(&mut self, gid: &[u8], now: u64) -> Result<()> {
        let g = self.group(gid)?;
        let gap = (g.mls.members().len() as u64 * 250).max(1000);
        if !g.mls.active() || !(g.changed && now >= g.rec.signed + gap || now >= g.rec.signed + RESIGN) {
            return Ok(());
        }
        let me = self.me(gid).to_vec();
        let epoch = g.mls.epoch();
        let list = |of: fn(&crate::Author) -> &lmk_proto::ranges::Ranges| g.rec.authors.iter().filter_map(|a| a.seqs(of(a))).collect();
        let sealed = g.rec.authors.iter().filter_map(|a| a.seqs(&a.sealed.iter().filter(|(_, sealed)| **sealed == epoch).map(|(seq, _)| *seq).collect())).collect();
        let summary = Summary {
            group: Bytes(gid.to_vec()),
            member: Bytes(me.clone()),
            joined: g.mls.joined(&me).context("a member of its group")?,
            version: (g.rec.version + 1).max(now),
            time: now,
            epoch,
            relay: self.home.clone(),
            held: list(|a| &a.servable),
            sealed,
            shown: list(|a| &a.shown),
            lost: list(|a| &a.lost),
        };
        let body = serde_json::to_vec(&summary)?;
        let sig = self.session_of(gid).sign(&[SUMMARY, &body].concat());
        let g = self.group_mut(gid)?;
        (g.rec.version, g.rec.signed, g.changed) = (summary.version, now, false);
        self.save(gid)?;
        let heard = peers::Heard { signed: Signed { body: Bytes(body), sig: Bytes(sig) }, summary, at: now };
        self.peers.summary(&Bytes(gid.to_vec()), heard, None);
        Ok(())
    }

    /// Takes members' summaries a peer passed on: each checked against its membership, kept if newer, saved, and its
    /// losses told once. One of a membership this session does not know yet is kept a while.
    fn summaries(&mut self, gid: &[u8], peer: EndpointId, items: Vec<Signed>) -> Result<()> {
        let now = self.tick();
        let group = Bytes(gid.to_vec());
        for signed in items {
            let Ok(summary) = serde_json::from_slice::<Summary>(&signed.body.0) else { continue };
            if summary.group != group || summary.member.0 == self.me(gid) {
                continue;
            }
            let g = self.groups.get_mut(gid).unwrap();
            if g.mls.joined(&summary.member.0) != Some(summary.joined) {
                if summary.joined > g.mls.epoch() && g.unverified.len() < UNVERIFIED {
                    g.unverified.push((peer, signed));
                }
                continue;
            }
            if !lmk_core::device::verify(&summary.member.0, SUMMARY, &signed.body.0, &signed.sig.0) {
                continue;
            }
            let heard = peers::Heard { signed: signed.clone(), summary: summary.clone(), at: now };
            if !self.peers.summary(&group, heard, Some(*peer.as_bytes())) {
                continue;
            }
            if summary.epoch == self.group(gid)?.mls.epoch() {
                self.at(gid, &summary.member.0, summary.epoch)?;
                self.save(gid)?;
            }
            if let Some(relay) = &summary.relay
                && relay.parse::<RelayUrl>().is_ok_and(|url| url.scheme() == "https")
                && let Some(leaf) = self.group(gid)?.mls.members().into_iter().find(|m| m.key == summary.member.0).and_then(|m| m.leaf)
                && self.hints.get(&leaf.key).is_none_or(|hint| hint.time <= summary.time)
            {
                let moved = self.hints.get(&leaf.key).is_none_or(|hint| hint.relay != *relay);
                let hint = Hint { relay: relay.clone(), time: summary.time };
                if moved {
                    put(&self.provider, &hint_key(&leaf.key.0), &hint)?;
                }
                self.hints.insert(leaf.key, hint);
            }
            put(&self.provider, &heard_key(gid, &summary.member.0, summary.joined), &Saved { signed, at: now })?;
            let g = self.groups.get_mut(gid).unwrap();
            let membership = (summary.member.clone(), summary.joined);
            if !g.rec.heard.contains(&membership) {
                g.rec.heard.push(membership);
            }
            for held in &summary.held {
                if let Some(&(_, last)) = held.seqs.ranges().last() {
                    g.learn(&held.key.0, held.joined, last, now);
                }
            }
            self.told(gid, &summary)?;
            self.events.push(Event::Heard { group: group.clone() });
        }
        self.save(gid)
    }

    /// The losses a member's summary tells that it did not tell before: each seq once.
    fn told(&mut self, gid: &[u8], summary: &Summary) -> Result<()> {
        let me = self.me(gid).to_vec();
        let g = self.group_mut(gid)?;
        let mut messages = Vec::new();
        // Losses are told to their author alone, and only of seqs it knows it sent.
        for lost in summary.lost.iter().filter(|lost| lost.key.0 == me) {
            let Some(last) = g.author(&lost.key.0, lost.joined).map(|a| a.last().max(a.cut)) else { continue };
            let seqs = lost.seqs.intersection(&lmk_proto::ranges::Ranges::range(1, last));
            let of = |(k, j, s): &&mut (Bytes, u64, Seqs)| *k == summary.member && *j == summary.joined && s.key == lost.key && s.joined == lost.joined;
            let new = match g.rec.told.iter_mut().find(of) {
                Some((_, _, told)) => {
                    let new = seqs.difference(&told.seqs);
                    told.seqs = told.seqs.union(&new);
                    new
                }
                None if !seqs.is_empty() => {
                    g.rec.told.push((summary.member.clone(), summary.joined, Seqs { key: lost.key.clone(), joined: lost.joined, seqs: seqs.clone() }));
                    seqs
                }
                None => continue,
            };
            if !new.is_empty() {
                messages.push((lost.key.clone(), lost.joined, new));
            }
        }
        if messages.is_empty() {
            return Ok(());
        }
        let mut lost = Vec::new();
        for (key, joined, seqs) in messages {
            let mut ids = Vec::new();
            if key.0 == me {
                for seq in seqs.iter() {
                    ids.extend(self.id_at(gid, &key.0, joined, seq)?);
                }
            }
            lost.push(LostOf { from: self.member_by_key(gid, &key.0), joined, seqs: seqs.iter().collect(), ids });
        }
        let member = self.member_by_key(gid, &summary.member.0);
        self.events.push(Event::Lost(Lost { group: Bytes(gid.to_vec()), member, messages: lost }));
        Ok(())
    }

    /// Takes again the summaries kept until a commit made their memberships known.
    pub(crate) fn reverify(&mut self, gid: &[u8]) -> Result<()> {
        let unverified = std::mem::take(&mut self.group_mut(gid)?.unverified);
        for (peer, signed) in unverified {
            self.summaries(gid, peer, vec![signed])?;
        }
        Ok(())
    }

    /// Hands `Peers` a group's saved summaries, as the node starts.
    pub(crate) fn load_heard(&mut self, gid: &[u8]) -> Result<()> {
        let group = Bytes(gid.to_vec());
        for (key, joined) in self.group(gid)?.rec.heard.clone() {
            let Some(saved) = get::<Saved>(&self.provider, &heard_key(gid, &key.0, joined))? else { continue };
            let summary = serde_json::from_slice(&saved.signed.body.0)?;
            self.peers.summary(&group, peers::Heard { signed: saved.signed, summary, at: saved.at }, None);
        }
        Ok(())
    }

    /// Drops the hints of members, by iroh key, that no group of this session has any longer.
    pub(crate) fn unhint(&mut self, keys: Vec<Bytes>) -> Result<()> {
        for key in keys {
            let held = self.groups.values().any(|g| g.mls.members().iter().any(|m| m.leaf.as_ref().is_some_and(|leaf| leaf.key == key)));
            if !held && self.hints.remove(&key).is_some() {
                self.provider.delete(&hint_key(&key.0))?;
            }
        }
        Ok(())
    }

    /// Deletes a member's summary of a group, as its Remove applies.
    pub(crate) fn unhear(&mut self, gid: &[u8], key: &[u8]) -> Result<()> {
        let g = self.group_mut(gid)?;
        let gone: Vec<(Bytes, u64)> = g.rec.heard.iter().filter(|(k, _)| k.0 == key).cloned().collect();
        g.rec.heard.retain(|(k, _)| k.0 != key);
        g.rec.told.retain(|(k, _, _)| k.0 != key);
        for (key, joined) in gone {
            self.provider.delete(&heard_key(gid, &key.0, joined))?;
        }
        Ok(())
    }

    /// Deletes every saved summary of a group.
    pub(crate) fn forget_heard(&mut self, gid: &[u8]) -> Result<()> {
        for (key, joined) in self.group(gid)?.rec.heard.clone() {
            self.provider.delete(&heard_key(gid, &key.0, joined))?;
        }
        Ok(())
    }

    /// The answer to a member's `want`: the sealings it can open, in its epoch or the one before, of messages sent since
    /// it joined. One the gate does not admit gets nothing, so its asker moves on.
    fn answer(&mut self, gid: &[u8], peer: EndpointId, epoch: u64, wants: &[Seqs]) -> Result<Frame> {
        let group = Bytes(gid.to_vec());
        let admitted = self.admitted(gid, &peer);
        let joined = self.joined_of(gid, &peer);
        let g = self.group(gid)?;
        let held: Vec<Seqs> = if admitted { g.rec.authors.iter().filter_map(|a| a.seqs(&a.servable)).collect() } else { Vec::new() };
        let sealing = |key: &Bytes, joined_: u64, seq: u64| {
            let record = self.record_at(gid, &key.0, joined_, seq).ok()??;
            let (sealed, ciphertext) = record.sealing?;
            (sealed + 1 >= epoch && sealed <= epoch && record.header.epoch >= joined).then_some(ciphertext.0)
        };
        Ok(peers::answer(group, wants, &held, sealing))
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Polls every `POLL`: signs summaries, seals this session's messages again in a new epoch, reads on in groups
    /// that wait before a commit, opens what waited unopened, gives up what holds dependents too long, and sends what
    /// `Peers` has due.
    pub(crate) async fn polling(self: Arc<Self>) {
        loop {
            sleep(POLL).await;
            let mut st = self.lock();
            if let Err(error) = self.poll(&mut st) {
                self.warn(None, format!("{error:#}"));
            }
        }
    }

    fn poll(&self, st: &mut State<P>) -> Result<()> {
        let gids: Vec<Vec<u8>> = st.groups.keys().cloned().collect();
        let now = st.tick();
        for gid in &gids {
            // One group's failure stops neither the others nor the peers' poll.
            if let Err(error) = self.poll_group(st, gid, now) {
                tracing::warn!("polling a group: {error:#}");
            }
        }
        st.tell_peers();
        let now = st.tick();
        for out in st.peers.poll(now) {
            self.out(st, out)?;
        }
        Ok(())
    }

    fn poll_group(&self, st: &mut State<P>, gid: &[u8], now: u64) -> Result<()> {
        let Some(g) = st.groups.get(gid) else { return Ok(()) };
        if !g.mls.active() {
            return Ok(());
        }
        let (waiting, unopened) = (g.waiting, !g.unopened.is_empty());
        st.sign(gid, now)?;
        self.reseal(st, gid)?;
        if waiting {
            self.advance(st, gid)?;
        }
        if unopened && st.groups.contains_key(gid) {
            self.take(st, gid, None, Vec::new(), true)?;
        }
        if st.groups.contains_key(gid) {
            self.give_up(st, gid)?;
        }
        Ok(())
    }

    fn out(&self, st: &mut State<P>, out: peers::Out) -> Result<()> {
        let endpoint = |key: [u8; 32]| EndpointId::from_bytes(&key).expect("peers are connected by their iroh keys");
        match out {
            peers::Out::Frame(key, frame) => st.out.push(Out::Frame { peer: endpoint(key), frame }),
            peers::Out::Entries { peer, log, after } => {
                if let Some(head) = st.log(&log.0)?.head.clone().filter(|head| head.length > after) {
                    let entries = st.entries(&log.0, after);
                    st.out.push(Out::Frame { peer: endpoint(peer), frame: Frame::Entries { log, entries, head } });
                }
            }
            peers::Out::Dial(key) => st.out.push(Out::Dial(endpoint(key))),
            peers::Out::Close(key) => st.out.push(Out::Close(endpoint(key))),
        }
        Ok(())
    }

    /// A connection, a disconnection or a frame from a peer, each in a step of its own.
    pub(crate) fn peer_event(self: &Arc<Self>, event: lmk_net::Event) {
        let mut st = self.lock();
        let now = st.tick();
        match event {
            lmk_net::Event::Connected(peer, dialed) => {
                let served = st.served_to(&peer);
                st.served.insert(peer, served.clone());
                st.peers.connect(*peer.as_bytes(), served, dialed, now);
            }
            lmk_net::Event::Disconnected(peer) => {
                st.served.remove(&peer);
                st.peers.disconnect(peer.as_bytes());
            }
            lmk_net::Event::Frame(peer, frame) if st.served.contains_key(&peer) => {
                if let Err(error) = self.frame(&mut st, peer, frame) {
                    self.warn(None, format!("a frame from {}: {error:#}", peer.fmt_short()));
                }
            }
            lmk_net::Event::Home(relay) => {
                st.home = Some(relay.to_string());
                for g in st.groups.values_mut() {
                    g.changed = true;
                }
            }
            _ => {}
        }
    }

    fn frame(self: &Arc<Self>, st: &mut State<P>, peer: EndpointId, frame: Frame) -> Result<()> {
        let (key, now) = (*peer.as_bytes(), st.tick());
        if let Frame::Hello { groups, heads } = frame {
            let heads: Vec<Head> = heads.into_iter().filter(|head| self.vouched(st, head, &peer)).collect();
            // An `at` of a log this session does not hold, of an epoch it has not reached or has dropped, is taken unchecked.
            let shown = |at: &At| at.head.as_ref().is_none_or(|head| head.log_ref == at.log && (!st.logs.contains_key(at.log.as_slice()) || self.vouched(st, head, &peer)));
            let groups: Vec<At> = groups.into_iter().filter(|at| st.groups.contains_key(&at.group.0) && shown(at)).collect();
            for out in st.peers.frame(&key, &Frame::Hello { groups: groups.clone(), heads }, now) {
                self.out(st, out)?;
            }
            let shows = |head: &Option<Head>| head.as_ref().map(|head| (head.length, head.hash));
            for at in groups {
                let gid = at.group.0;
                let log = &st.group(&gid)?.rec.log.0;
                if at.log.as_slice() == log && shows(&at.head) == shows(&st.log(log)?.head) && st.admitted(&gid, &peer) {
                    self.synced(st, &gid, peer)?;
                }
            }
            return Ok(());
        }
        if let Frame::Entries { log, entries, head } = frame {
            if log.0 == head.log_ref && self.vouched(st, &head, &peer) {
                self.take_entries(st, &log.0, head.length.saturating_sub(entries.len() as u64), entries, head)?;
            }
            return Ok(());
        }
        let Some(gid) = group_of(&frame).map(|gid| gid.0.clone()) else { return Ok(()) };
        let held = st.groups.contains_key(&gid);
        if !held || !peers::takes(&frame, st.admitted(&gid, &peer), st.at_head(&gid)) {
            // A `want` refused, or of a group this session does not hold, is answered with nothing, so its asker moves on.
            if let Frame::Want { group, wants, .. } = frame {
                st.out.push(Out::Frame { peer, frame: Frame::Held { group, items: Vec::new(), answers: Some(wants) } });
            }
            return Ok(());
        }
        for out in st.peers.frame(&key, &frame, now) {
            self.out(st, out)?;
        }
        match frame {
            Frame::Summaries { items, .. } => st.summaries(&gid, peer, items)?,
            Frame::Held { items, answers, .. } => self.take(st, &gid, Some(peer), items.into_iter().map(|item| item.0).collect(), answers.is_none())?,
            Frame::Want { epoch, wants, .. } => {
                st.peers.used(&key, now);
                let answer = st.answer(&gid, peer, epoch, &wants)?;
                st.out.push(Out::Frame { peer, frame: answer });
            }
            Frame::Live { group, hops, item } => {
                let g = st.group(&gid)?;
                let Ok((sender, payload, id)) = g.mls.open_live(&st.provider, &item.0) else { return Ok(()) };
                let membership = (Bytes(sender.key.clone()), g.mls.joined(&sender.key).context("a live payload's sender has no membership")?);
                let Some(forward) = st.peers.live(&group, id, Some(key), hops, now) else { return Ok(()) };
                if !st.group_mut(&gid)?.live.entry(membership).or_default().take(item.0.len(), LIVE_SCALE, now) {
                    return Ok(());
                }
                for to in forward {
                    let frame = Frame::Live { group: group.clone(), hops: hops.min(HOPS) - 1, item: item.clone() };
                    st.out.push(Out::Frame { peer: EndpointId::from_bytes(&to)?, frame });
                }
                let sender = st.member(&gid, &sender).context("the sender has no letmeknow credential")?;
                st.events.push(Event::Live { group, sender, payload });
            }
            _ => {}
        }
        Ok(())
    }

    /// Whether a head a peer showed of a log this session follows is signed by its service and agrees with this
    /// session's copy; a contradiction is reported.
    fn vouched(&self, st: &State<P>, head: &Head, peer: &EndpointId) -> bool {
        let id = head.log_ref.as_slice();
        let Some(log) = st.logs.get(id) else { return false };
        let checked = log.frontier(id).and_then(|frontier| frontier.check(head, st.hash_at(id, head.length)?));
        match checked {
            Ok(()) => true,
            Err(error) => {
                match error.downcast_ref::<Contradiction>() {
                    Some(contradiction) => self.contradicted(st, id, contradiction, &peer.fmt_short().to_string()),
                    None => tracing::warn!("{} showed a head its service did not sign: {error:#}", peer.fmt_short()),
                }
                false
            }
        }
    }

    /// A neighbour's `hello` shows this session's head of the group's log.
    fn synced(self: &Arc<Self>, st: &mut State<P>, gid: &[u8], peer: EndpointId) -> Result<()> {
        let member = st.by_iroh(gid, &peer);
        st.events.push(Event::Synced { group: Bytes(gid.to_vec()), member });
        st.out.push(Out::WantFiles { peer, group: gid.to_vec() });
        // A file only this session held may have reached the peer since.
        let pending = st.group(gid)?.rec.pending.clone();
        for hash in pending {
            let (inner, gid) = (self.clone(), gid.to_vec());
            spawn(async move {
                if inner.net().holders(&gid, hash).any(|holder| holder == peer).await {
                    let mut st = inner.lock();
                    if let Ok(g) = st.group_mut(&gid) {
                        g.rec.pending.retain(|pending| *pending != hash);
                        st.save(&gid).ok();
                    }
                }
            });
        }
        Ok(())
    }

    /// Seals a live payload and sends it to the neighbours, or to one member alone.
    pub(crate) fn send_live(&self, st: &mut State<P>, gid: &[u8], payload: &serde_json::Value, to: Option<EndpointId>) -> Result<()> {
        if !st.at_head(gid) {
            return Ok(());
        }
        let now = st.tick();
        let g = st.group(gid)?;
        let (item, id) = g.mls.seal_live(&st.provider, st.session_of(gid), payload)?;
        let group = Bytes(gid.to_vec());
        match to {
            Some(peer) => st.emit(gid, peer, Frame::Live { group, hops: 0, item: Bytes(item) }),
            None => {
                for peer in st.peers.live(&group, id, None, HOPS, now).unwrap_or_default() {
                    st.emit(gid, EndpointId::from_bytes(&peer)?, Frame::Live { group: group.clone(), hops: HOPS, item: Bytes(item.clone()) });
                }
            }
        }
        Ok(())
    }
}

impl<P: Provider + Send + 'static> Node<P> {
    /// The relay a member last said it was on, which a dial to it tries first.
    pub fn hint(&self, key: &[u8]) -> Option<String> {
        self.inner.lock().hints.get(&Bytes(key.to_vec())).map(|hint| hint.relay.clone())
    }

    /// The other current members' latest summaries of the group, whatever the gate.
    pub fn heard(&self, gid: &[u8]) -> Result<Vec<Heard>> {
        let st = self.inner.lock();
        let g = st.group(gid)?;
        let me = st.me(gid);
        let group = Bytes(gid.to_vec());
        let heard = st.peers.heard(&group).filter(|heard| heard.summary.member.0 != me && g.mls.joined(&heard.summary.member.0) == Some(heard.summary.joined));
        let heard = heard.map(|heard| Heard {
            member: st.member_by_key(gid, &heard.summary.member.0),
            joined: heard.summary.joined,
            held: heard.summary.held.clone(),
            shown: heard.summary.shown.clone(),
            at: heard.summary.time.min(heard.at),
        });
        Ok(heard.collect())
    }

    /// The other members not connected that no summary was heard from for H: away.
    pub fn away(&self, gid: &[u8]) -> Result<Vec<Member>> {
        let (heard, since, me, online) = (self.heard(gid)?, self.carried_since(gid)?, self.key_in(gid), self.online(gid)?);
        let away = |m: &Member| m.key != me && !online.iter().any(|o| o.key == m.key) && !heard.iter().any(|h| h.member.key == m.key && h.at >= since);
        Ok(self.members(gid)?.into_iter().filter(away).collect())
    }

    /// This session's held messages no other member that may have them holds yet: they need this session until one does.
    /// Their ids and payloads.
    pub fn only_here(&self, gid: &[u8]) -> Result<Vec<(Bytes, serde_json::Value)>> {
        let st = self.inner.lock();
        let g = st.group(gid)?;
        let me = st.me(gid);
        let Some(mine) = g.current(me) else { return Ok(Vec::new()) };
        let mut unkept = Vec::new();
        for seq in mine.cut + 1..=mine.last() {
            if let Some(record) = st.record_at(gid, me, mine.joined, seq)?
                && st.unheld(gid, &record)?
            {
                unkept.push((record.id, record.header.payload));
            }
        }
        Ok(unkept)
    }

    /// Marks held messages of the group shown, as its client printed or displayed them: its summaries carry them, and
    /// its next messages depend on them.
    pub fn mark_shown(&self, gid: &[u8], ids: &[Bytes]) -> Result<()> {
        let mut st = self.inner.lock();
        for id in ids {
            let Some(record) = st.record(gid, &id.0)? else { continue };
            let g = st.group_mut(gid)?;
            if let Some(author) = g.author_mut(&record.header.author.0, record.header.joined)
                && !author.shown.contains(record.header.seq)
            {
                author.shown.insert(record.header.seq);
                g.changed = true;
            }
        }
        st.save(gid)
    }

    /// Whether this session's client showed a held message.
    pub fn shown(&self, gid: &[u8], id: &[u8]) -> Result<bool> {
        let st = self.inner.lock();
        let Some(record) = st.record(gid, id)? else { return Ok(false) };
        let g = st.group(gid)?;
        Ok(g.author(&record.header.author.0, record.header.joined).is_some_and(|a| a.shown.contains(record.header.seq)))
    }

    /// H ago.
    fn carried_since(&self, gid: &[u8]) -> Result<u64> {
        Ok(now().saturating_sub(days(self.settings(gid)?.carry)))
    }
}

impl<P: Provider + Send + 'static> Groups for Inner<P> {
    fn groups(&self) -> Vec<Vec<u8>> {
        self.lock().groups.keys().cloned().collect()
    }

    fn is_member(&self, group: &[u8], peer: &EndpointId) -> bool {
        self.lock().serves(group, peer)
    }

    fn files(&self, group: &[u8]) -> Vec<FileLink> {
        let st = self.lock();
        let Some(g) = st.groups.get(group) else {
            return Vec::new();
        };
        g.rec.held(g.mls.settings().carry)
    }

    fn admit(&self, peer: &EndpointId, frame: Frame) -> Option<Frame> {
        self.lock().admissible(peer, frame)
    }
}
