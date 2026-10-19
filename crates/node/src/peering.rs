//! The node's side of the peer protocol (`lmk_net::peers`): it hands `Peers` this session's state of each group and the
//! frames peers send, takes those frames by the gate, signs this session's summaries and checks its neighbours', answers
//! `want` from the sealings it holds, and sends what `Peers` produces once the step commits. It polls when a step
//! changed something, and when `Peers` or a group's timed work is next due: never while idle.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::{EndpointId, RelayUrl};
use lmk_membership::Contradiction;
use lmk_net::Groups;
use lmk_net::peers::{self, Own};
use lmk_proto::Bytes;
use lmk_proto::head::Head;
use lmk_proto::peer::{At, Frame, SUMMARY, Seqs, Signed, Summary};
use n0_future::time::{Duration, timeout};
use serde::{Deserialize, Serialize};

use crate::{G, Inner, Member, Node, Out, State, get, now, put};

/// How many summaries of memberships not known yet a group keeps.
const UNVERIFIED: usize = 32;
/// How many hellos of groups it has not added yet this session keeps.
const EARLY: usize = 32;

/// A member's latest summary of a group: what it holds, and when it was signed, at most when it came.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heard {
    pub member: Member,
    pub joined: u64,
    pub held: Vec<Seqs>,
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
        Frame::Summary { group, .. } | Frame::Held { group, .. } | Frame::Want { group, .. } | Frame::Have { group, .. } => Some(group),
    }
}

/// How long a member waits after signing a summary of a group before it signs the next: longer in larger groups.
fn gap(g: &G) -> u64 {
    (g.mls.members().len() as u64 * 250).max(1000)
}

impl State {
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
        let me = self.me().to_vec();
        let g = self.groups.get_mut(gid).unwrap();
        let (wanted, stale) = g.wanted(now, &me);
        let members = g.mls.members().into_iter().filter(|m| m.key != me).filter_map(|m| {
            let iroh = m.leaf.as_ref()?.key.0.as_slice().try_into().ok()?;
            Some(((Bytes(m.key.clone()), g.mls.joined(&m.key)?), iroh))
        });
        Own {
            me: (Bytes(me.clone()), g.mls.joined(&me).unwrap_or_default()),
            epoch: g.mls.epoch(),
            log: log.as_slice().try_into().unwrap(),
            head,
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

    /// Works out again, once the rosters changed, which groups the gate admits each connected peer to.
    pub(crate) fn gate(&mut self) {
        if !std::mem::take(&mut self.gate) {
            return;
        }
        let now = self.tick();
        for peer in self.peers.connected() {
            let served = self.served_to(&EndpointId::from_bytes(&peer).expect("a connected peer's key"));
            self.peers.served(&peer, served, now);
        }
    }

    /// Whether the gate admits a connected peer to a group.
    pub(crate) fn admitted(&mut self, gid: &[u8], peer: &EndpointId) -> bool {
        self.gate();
        self.peers.serves(peer.as_bytes(), &Bytes(gid.to_vec()))
    }

    /// Sends a frame of a group to a peer once the step commits, if the gate lets it go.
    pub(crate) fn emit(&mut self, gid: &[u8], peer: EndpointId, frame: Frame) {
        if self.admitted(gid, &peer) {
            self.out.push(Out::Frame { peer, frame });
        }
    }

    /// What of a frame goes to a peer as it is written, by the gate as it is then: a step may have removed the peer
    /// since another queued the frame.
    pub(crate) fn admissible(&mut self, peer: &EndpointId, frame: Frame) -> Option<Frame> {
        if let Frame::Hello { groups } = frame {
            let groups = groups.into_iter().filter(|at| self.admitted(&at.group.0, peer)).collect();
            return Some(Frame::Hello { groups });
        }
        let group = match &frame {
            // Every `want` is answered, with nothing if the gate refuses it.
            Frame::Held { items, answers: Some(_), .. } if items.is_empty() => None,
            // A group's earlier logs go to whom they were queued for: a peer that showed it holds the log, or a member
            // its last commit removed.
            Frame::Entries { log, .. } => self.logs.get(&log.0).map(|l| &l.group).filter(|group| self.groups.get(&group.0).is_some_and(|g| g.rec.log == *log)),
            frame => group_of(frame),
        };
        let Some(gid) = group.map(|group| group.0.clone()) else { return Some(frame) };
        self.admitted(&gid, peer).then_some(frame)
    }

    /// Sends a frame of a group to every neighbour the gate lets it go to, and dials the group's targets not connected.
    pub(crate) fn broadcast(&mut self, gid: &[u8], frame: Frame) {
        self.peers.push(&Bytes(gid.to_vec()));
        for peer in self.peers.neighbours(&Bytes(gid.to_vec())) {
            if let Ok(peer) = EndpointId::from_bytes(&peer) {
                self.emit(gid, peer, frame.clone());
            }
        }
    }

    /// This session's summary of a group, signed and handed to `Peers` for its neighbours, when it changed and its last
    /// is old enough.
    fn sign(&mut self, gid: &[u8], now: u64) -> Result<()> {
        let g = self.group(gid)?;
        if !g.mls.active() || !g.changed || now < g.rec.signed + gap(g) {
            return Ok(());
        }
        let me = self.me().to_vec();
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
        };
        let body = serde_json::to_vec(&summary)?;
        let sig = self.session.sign(&[SUMMARY, &body].concat());
        let g = self.group_mut(gid)?;
        (g.rec.version, g.rec.signed, g.changed) = (summary.version, now, false);
        self.save(gid)?;
        let heard = peers::Heard { signed: Signed { body: Bytes(body), sig: Bytes(sig) }, summary, at: now };
        self.peers.summary(&Bytes(gid.to_vec()), heard, true);
        Ok(())
    }

    /// When the poll is next due, if no step changes anything before: at once, or `BUSY` on, while a group has timed
    /// work on, its summary's gap after it changed, or when `Peers` says.
    pub(crate) fn next_poll(&self) -> Option<u64> {
        let now = now();
        let mut next = self.peers.next(now);
        for g in self.groups.values().filter(|g| g.mls.active()) {
            let pending = g.rec.authors.iter().any(|a| !a.held.difference(&a.delivered).is_empty());
            let busy = g.waiting || pending || !g.unopened.is_empty() || !g.fresh.is_empty() || g.rec.resealed < g.mls.epoch();
            let times = [busy.then_some(now + peers::BUSY), g.changed.then(|| g.rec.signed + gap(g))];
            next = times.into_iter().flatten().chain(next).min();
        }
        next
    }

    /// Takes a neighbour's own summary: checked against its membership, kept if newer, and saved. One of a membership
    /// this session does not know yet is kept a while.
    fn summary(&mut self, gid: &[u8], peer: EndpointId, signed: Signed) -> Result<()> {
        let now = self.tick();
        let group = Bytes(gid.to_vec());
        let Ok(summary) = serde_json::from_slice::<Summary>(&signed.body.0) else { return Ok(()) };
        if summary.group != group || summary.member.0 == self.me() {
            return Ok(());
        }
        let g = self.groups.get_mut(gid).unwrap();
        if g.mls.joined(&summary.member.0) != Some(summary.joined) {
            if summary.joined > g.mls.epoch() && g.unverified.len() < UNVERIFIED {
                g.unverified.push((peer, signed));
            }
            return Ok(());
        }
        let leaf = g.mls.members().into_iter().find(|m| m.key == summary.member.0).and_then(|m| m.leaf);
        if leaf.as_ref().is_none_or(|leaf| leaf.key.0 != peer.as_bytes()) || !lmk_core::group::verify(&summary.member.0, SUMMARY, &signed.body.0, &signed.sig.0) {
            return Ok(());
        }
        let heard = peers::Heard { signed: signed.clone(), summary: summary.clone(), at: now };
        if !self.peers.summary(&group, heard, false) {
            return Ok(());
        }
        if summary.epoch == self.group(gid)?.mls.epoch() {
            self.at(gid, &summary.member.0, summary.epoch)?;
        }
        if let Some(relay) = &summary.relay
            && relay.parse::<RelayUrl>().is_ok_and(|url| url.scheme() == "https")
            && let Some(leaf) = leaf
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
        self.save(gid)
    }

    /// Takes again the summaries kept until a commit made their memberships known.
    pub(crate) fn reverify(&mut self, gid: &[u8]) -> Result<()> {
        let unverified = std::mem::take(&mut self.group_mut(gid)?.unverified);
        for (peer, signed) in unverified {
            self.summary(gid, peer, signed)?;
        }
        Ok(())
    }

    /// Hands `Peers` a group's saved summaries, as the node starts.
    pub(crate) fn load_heard(&mut self, gid: &[u8]) -> Result<()> {
        let group = Bytes(gid.to_vec());
        for (key, joined) in self.group(gid)?.rec.heard.clone() {
            let Some(saved) = get::<Saved>(&self.provider, &heard_key(gid, &key.0, joined))? else { continue };
            let summary = serde_json::from_slice(&saved.signed.body.0)?;
            self.peers.summary(&group, peers::Heard { signed: saved.signed, summary, at: saved.at }, false);
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

impl Inner {
    /// Polls as a step changed something, and when the next timed work is due: signs summaries, seals this session's
    /// messages again in a new epoch, reads on in groups that wait before a commit, opens what waited unopened, gives up
    /// what holds dependents too long, and sends what `Peers` has due.
    pub(crate) async fn polling(self: Arc<Self>) {
        loop {
            let poked = self.poke.notified();
            let next = {
                let mut st = self.lock();
                if let Err(error) = self.poll(&mut st) {
                    self.warn(None, format!("{error:#}"));
                }
                st.quiet = true;
                st.next_poll()
            };
            match next {
                Some(at) => drop(timeout(Duration::from_millis(at.saturating_sub(now())), poked).await),
                None => poked.await,
            }
        }
    }

    fn poll(&self, st: &mut State) -> Result<()> {
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

    fn poll_group(&self, st: &mut State, gid: &[u8], now: u64) -> Result<()> {
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

    fn out(&self, st: &mut State, out: peers::Out) -> Result<()> {
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
                st.peers.connect(*peer.as_bytes(), served, dialed, now);
            }
            lmk_net::Event::Disconnected(peer) => {
                st.peers.disconnect(peer.as_bytes(), now);
            }
            lmk_net::Event::Frame(peer, frame) if st.peers.is_connected(peer.as_bytes()) => {
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

    fn frame(self: &Arc<Self>, st: &mut State, peer: EndpointId, frame: Frame) -> Result<()> {
        let (key, now) = (*peer.as_bytes(), st.tick());
        if let Frame::Hello { groups } = frame {
            // An `at` of a log this session does not hold, of an epoch it has not reached or has dropped, is taken unchecked.
            let shown = |at: &At| at.head.as_ref().is_none_or(|head| head.log_ref == at.log && (!st.logs.contains_key(at.log.as_slice()) || self.vouched(st, head, &peer)));
            let (held, early): (Vec<At>, Vec<At>) = groups.into_iter().partition(|at| st.groups.contains_key(&at.group.0));
            let groups: Vec<At> = held.into_iter().filter(|at| shown(at)).collect();
            st.peers.frame(&key, &Frame::Hello { groups }, now);
            // A joiner's admitter says where it is as it applies the Add, which may be before the Welcome adds the group here.
            st.early_hellos.extend(early.into_iter().map(|at| (peer, at)));
            let excess = st.early_hellos.len().saturating_sub(EARLY);
            st.early_hellos.drain(..excess);
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
        if !held || !peers::takes(&frame, st.admitted(&gid, &peer)) {
            // A `want` refused, or of a group this session does not hold, is answered with nothing, so its asker moves on.
            if let Frame::Want { group, wants, .. } = frame {
                st.out.push(Out::Frame { peer, frame: Frame::Held { group, items: Vec::new(), answers: Some(wants) } });
            }
            return Ok(());
        }
        st.peers.frame(&key, &frame, now);
        match frame {
            Frame::Summary { summary, .. } => {
                st.summary(&gid, peer, summary)?;
                self.heard.notify_waiters();
            }
            Frame::Held { items, answers, .. } => self.take(st, &gid, Some(peer), items.into_iter().map(|item| item.0).collect(), answers.is_none())?,
            Frame::Want { epoch, wants, .. } => {
                st.peers.used(&key, now);
                let answer = st.answer(&gid, peer, epoch, &wants)?;
                st.out.push(Out::Frame { peer, frame: answer });
            }
            // No push brings what was announced: it is wanted at once, of the peers that announced it.
            Frame::Have { held, .. } => {
                let g = st.group_mut(&gid)?;
                for held in &held {
                    if let Some(author) = g.author_mut(&held.key.0, held.joined)
                        && let Some(&(_, last)) = held.seqs.ranges().last()
                    {
                        author.known = author.known.max(last);
                    }
                }
                st.save(&gid)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Whether a head a peer showed of a log this session follows is signed by its service and agrees with this
    /// session's copy; a contradiction is reported.
    fn vouched(&self, st: &State, head: &Head, peer: &EndpointId) -> bool {
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
}

impl Node {
    /// The relay a member last said it was on, which a dial to it tries first.
    pub fn hint(&self, key: &[u8]) -> Option<String> {
        self.inner.lock().hints.get(&Bytes(key.to_vec())).map(|hint| hint.relay.clone())
    }

    /// The other current members' latest summaries of the group, whatever the gate.
    pub fn heard(&self, gid: &[u8]) -> Result<Vec<Heard>> {
        let st = self.inner.lock();
        let g = st.group(gid)?;
        let me = st.me();
        let group = Bytes(gid.to_vec());
        let heard = st.peers.heard(&group).filter(|heard| heard.summary.member.0 != me && g.mls.joined(&heard.summary.member.0) == Some(heard.summary.joined));
        let heard = heard.map(|heard| Heard {
            member: st.member_by_key(gid, &heard.summary.member.0),
            joined: heard.summary.joined,
            held: heard.summary.held.clone(),
            at: heard.summary.time.min(heard.at),
        });
        Ok(heard.collect())
    }

    /// This session's chat messages no other member that may have them holds yet: they need this session until one does.
    /// Their ids and payloads.
    pub fn only_here(&self, gid: &[u8]) -> Result<Vec<(Bytes, serde_json::Value)>> {
        let st = self.inner.lock();
        let g = st.group(gid)?;
        let me = st.me();
        let Some(mine) = g.current(me) else { return Ok(Vec::new()) };
        let mut unkept = Vec::new();
        for seq in mine.cut + 1..=mine.last() {
            if let Some(record) = st.record_at(gid, me, mine.joined, seq)?
                && !lmk_proto::group::Control::TYPES.contains(&lmk_proto::group::type_of(&record.header.payload))
                && st.unheld(gid, &record)?
            {
                unkept.push((record.id, record.header.payload));
            }
        }
        Ok(unkept)
    }

    /// Marks held messages of the group shown, as its client printed or displayed them: its next messages depend on them.
    pub fn mark_shown(&self, gid: &[u8], ids: &[Bytes]) -> Result<()> {
        let mut st = self.inner.lock();
        for id in ids {
            if let Some(record) = st.record(gid, &id.0)? {
                st.show(gid, &record)?;
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
}

impl Groups for Inner {
    fn admit(&self, peer: &EndpointId, frame: Frame) -> Option<Frame> {
        self.lock().admissible(peer, frame)
    }
}
