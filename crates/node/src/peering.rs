//! The node's side of the peer protocol (`lmk_net::peers`): it hands `Peers` this session's state of each group and the
//! frames peers send, takes those frames by the gate, answers `want` from the ciphertexts it carries, saves each peer's
//! latest summary of each group, and sends what `Peers` produces once the step commits.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use iroh::EndpointId;
use lmk_core::provider::Provider;
use lmk_membership::Contradiction;
use lmk_net::peers::{self, Own};
use lmk_proto::Bytes;
use lmk_proto::group::Service;
use lmk_proto::head::Head;
use lmk_proto::peer::{Frame, Summary};
use lmk_proto::ranges::Ranges;
use n0_future::task::spawn;
use n0_future::time::{Duration, sleep};

use crate::logs::empty;
use crate::reading::ciphertext_key;
use crate::{Event, Inner, Member, Node, Out, State, Work, days, endpoint_id, get, now, put};

/// How often `Peers` is polled.
const POLL: Duration = Duration::from_millis(250);

/// A member's latest summary of a group, as saved: what it held and read within H, and when it was heard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heard {
    pub member: Member,
    pub held: Ranges,
    pub read: Ranges,
    pub at: u64,
}

fn heard_key(gid: &[u8], peer: &[u8]) -> Vec<u8> {
    [b"node/heard/".as_slice(), gid, b"/", peer].concat()
}

/// The peers whose summaries of a group are saved.
fn heard_index(gid: &[u8]) -> Vec<u8> {
    [b"node/heard/".as_slice(), gid].concat()
}

pub(crate) fn load_heard(provider: &impl Provider, gid: &[u8]) -> Result<BTreeMap<Bytes, peers::Heard>> {
    let peers: Vec<Bytes> = get(provider, &heard_index(gid))?.unwrap_or_default();
    let heard = |peer: Bytes| Ok((peer.clone(), get(provider, &heard_key(gid, &peer.0))?.context("a summary without its record")?));
    peers.into_iter().map(heard).collect()
}

pub(crate) fn forget_heard<'a>(provider: &impl Provider, gid: &[u8], peers: impl Iterator<Item = &'a Bytes>) -> Result<()> {
    for peer in peers {
        provider.delete(&heard_key(gid, &peer.0))?;
    }
    provider.delete(&heard_index(gid))
}

fn endpoint(key: peers::Key) -> EndpointId {
    EndpointId::from_bytes(&key).expect("peers are connected by their iroh keys")
}

/// The group a frame other than `hello` and `entries` is of.
fn group_of(frame: &Frame) -> Option<&Bytes> {
    match frame {
        Frame::Hello { .. } | Frame::Entries { .. } => None,
        Frame::Messages { group, .. }
        | Frame::Want { group, .. }
        | Frame::WantFiles { group, .. }
        | Frame::Have { group, .. }
        | Frame::State { group, .. }
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
        self.groups.get(gid).zip(self.logs.get(gid)).is_some_and(|(g, log)| g.rec.position >= log.logged)
    }

    /// This session's state of a group, as its summary shows it.
    fn own(&self, gid: &[u8]) -> Own {
        let g = &self.groups[gid];
        let kept = Ranges::range(g.rec.expired + 1, g.rec.position);
        Own {
            head: self.logs.get(gid).map_or_else(|| empty(gid), |log| log.head(gid)),
            held: kept.difference(&g.rec.lacking).difference(&g.rec.lost),
            read: g.rec.read.union(&kept.difference(&g.rec.messages)),
            lacking: g.rec.lacking.clone(),
            keys: g.keys.iter().filter_map(|log| Some(self.logs.get(log)?.head(log))).collect(),
        }
    }

    /// Hands `Peers` this session's state of a group.
    pub(crate) fn refresh(&mut self, gid: &[u8]) {
        let (own, now) = (self.own(gid), self.tick());
        self.peers.group(Bytes(gid.to_vec()), own, now);
    }

    /// Hands `Peers` what a step changed: the gate, and this session's state of each group.
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

    /// Works out again, once the rosters or the key logs changed, which groups the gate admits each connected peer to,
    /// and which key logs each group follows.
    fn gate(&mut self) {
        if !std::mem::take(&mut self.gate) {
            return;
        }
        let now = self.tick();
        let gids: Vec<Vec<u8>> = self.groups.keys().cloned().collect();
        for gid in &gids {
            let mut keys: Vec<Vec<u8>> = self.identities(gid).iter().map(|identity| lmk_proto::identity::address(&identity.id.0).to_vec()).collect();
            keys.retain(|log| self.logs.contains_key(log));
            keys.sort();
            keys.dedup();
            self.groups.get_mut(gid).unwrap().keys = keys;
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

    /// Sends a frame of a group to every connected peer the gate lets it go to.
    pub(crate) fn broadcast(&mut self, gid: &[u8], frame: Frame) {
        let peers: Vec<EndpointId> = self.served.keys().copied().collect();
        for peer in peers {
            self.emit(gid, peer, frame.clone());
        }
    }

    /// Saves a peer's summary of a group, over the last.
    fn hear(&mut self, heard: peers::Heard) -> Result<()> {
        let gid = heard.summary.group.0.clone();
        let g = self.groups.get_mut(&gid).context("this session is not in that group")?;
        let new = g.heard.insert(heard.peer.clone(), heard.clone()).is_none();
        put(&self.provider, &heard_key(&gid, &heard.peer.0), &heard)?;
        if new {
            put(&self.provider, &heard_index(&gid), &g.heard.keys().collect::<Vec<_>>())?;
        }
        Ok(())
    }

    /// Deletes a peer's summary of a group, as its Remove applies.
    pub(crate) fn unhear(&mut self, gid: &[u8], peer: &[u8]) -> Result<()> {
        let g = self.groups.get_mut(gid).context("this session is not in that group")?;
        if g.heard.remove(&Bytes(peer.to_vec())).is_none() {
            return Ok(());
        }
        self.provider.delete(&heard_key(gid, peer))?;
        put(&self.provider, &heard_index(gid), &g.heard.keys().collect::<Vec<_>>())
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    pub(crate) async fn polling(self: Arc<Self>) {
        loop {
            sleep(POLL).await;
            let mut st = self.lock();
            if let Err(error) = self.poll(&mut st) {
                self.warn(None, format!("{error:#}"));
            }
        }
    }

    /// Sends what `Peers` has due; reads on in groups that wait before a commit, and opens what no longer waits on a
    /// missing position.
    fn poll(&self, st: &mut State<P>) -> Result<()> {
        let gids: Vec<Vec<u8>> = st.groups.keys().cloned().collect();
        let now = st.tick();
        for out in st.peers.poll(now) {
            match out {
                peers::Out::Frame(key, frame) => st.out.push(Out::Frame { peer: endpoint(key), frame }),
                peers::Out::Entries { peer, log, after } => {
                    let entries = st.entries(&log.0, after);
                    if !entries.is_empty() {
                        let head = st.log(&log.0)?.head(&log.0);
                        st.out.push(Out::Frame { peer: endpoint(peer), frame: Frame::Entries { log, entries, head } });
                    }
                }
            }
        }
        for gid in &gids {
            let Some(g) = st.groups.get(gid) else { continue };
            if g.waiting {
                self.advance(st, gid)?;
            } else if !g.rec.unopened.is_empty() {
                self.open_ready(st, gid)?;
                self.kind_advance(st, gid)?;
            }
        }
        Ok(())
    }

    /// A connection, a disconnection or a frame from a peer, each in a step of its own.
    pub(crate) fn peer_event(self: &Arc<Self>, event: lmk_net::Event) {
        let mut st = self.lock();
        let now = st.tick();
        match event {
            lmk_net::Event::Connected(peer) => {
                let served = st.served_to(&peer);
                st.served.insert(peer, served.clone());
                st.peers.connect(*peer.as_bytes(), served, now);
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
            _ => {}
        }
    }

    fn frame(self: &Arc<Self>, st: &mut State<P>, peer: EndpointId, frame: Frame) -> Result<()> {
        let (key, now) = (*peer.as_bytes(), st.tick());
        if let Frame::Hello { groups, heads } = frame {
            let heads: Vec<Head> = heads.into_iter().filter(|head| self.vouched(st, head, &peer)).collect();
            let ours = |s: &Summary| s.head.log == s.group && st.groups.contains_key(&s.group.0);
            let groups: Vec<Summary> = groups.into_iter().filter(|s| ours(s) && self.vouched(st, &s.head, &peer)).collect();
            for heard in st.peers.frame(&key, &Frame::Hello { groups: groups.clone(), heads }, now) {
                st.hear(heard)?;
            }
            for summary in groups {
                let gid = summary.group.0;
                let head = st.log(&gid)?.head(&gid);
                if st.admitted(&gid, &peer) && (summary.head.length, &summary.head.hash) == (head.length, &head.hash) {
                    self.synced(st, &gid, peer)?;
                }
            }
            return Ok(());
        }
        st.peers.frame(&key, &frame, now);
        match frame {
            Frame::Entries { log, entries, head } => {
                if self.vouched(st, &head, &peer) {
                    self.take_entries(st, &log.0, entries, head)?;
                }
            }
            Frame::Want { group, positions } if st.groups.contains_key(&group.0) => {
                let held = if st.admitted(&group.0, &peer) { st.own(&group.0).held } else { Ranges::default() };
                let provider = &st.provider;
                let answer = peers::answer(group.clone(), &positions, &held, |position| provider.get(&ciphertext_key(&group.0, position)).ok().flatten());
                st.out.push(Out::Frame { peer, frame: answer });
            }
            frame => {
                let Some(gid) = group_of(&frame).filter(|gid| st.groups.contains_key(&gid.0)).map(|gid| gid.0.clone()) else { return Ok(()) };
                let admitted = st.admitted(&gid, &peer);
                if !peers::takes(&frame, admitted, st.at_head(&gid)) {
                    return Ok(());
                }
                match frame {
                    Frame::Messages { items, .. } => {
                        for item in items {
                            self.take(st, &gid, peer, &item.ciphertext.0, admitted)?;
                        }
                    }
                    Frame::Live { items, .. } => {
                        for item in items {
                            self.live(st, &gid, &item.0)?;
                        }
                    }
                    Frame::State { link: Some(link), .. } => drop(self.work.send(Work::State { group: gid, link, by: peer })),
                    Frame::State { link: None, .. } => drop(self.work.send(Work::StateWanted { group: gid, by: peer })),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Whether a head a peer showed of a log this session follows is signed by its service and agrees with this
    /// session's chain; a contradiction is reported.
    fn vouched(&self, st: &State<P>, head: &Head, peer: &EndpointId) -> bool {
        let Some(log) = st.logs.get(&head.log.0) else { return false };
        let signed = match &log.service {
            _ if head.length == 0 => head.hash == empty(&head.log.0).hash,
            Service::Serve { key, .. } => {
                let key: Option<[u8; 32]> = key.0.clone().try_into().ok();
                key.and_then(|key| VerifyingKey::from_bytes(&key).ok()).is_some_and(|key| head.verify(&key))
            }
            Service::Folder(_) => true,
            Service::Newer(_) => false,
        };
        if !signed {
            tracing::warn!("{} showed a head its service did not sign", peer.fmt_short());
            return false;
        }
        let ours = log.chain.as_ref().and_then(|chain| chain.hash_at(head.length));
        if ours.is_some_and(|ours| ours[..] != head.hash.0[..]) {
            let contradiction = Contradiction { ours: log.head(&head.log.0), theirs: head.clone() };
            self.contradicted(st, &head.log.0, &contradiction, &peer.fmt_short().to_string());
            return false;
        }
        true
    }

    /// A connected member's `hello` shows this session's head of the group's log.
    fn synced(self: &Arc<Self>, st: &mut State<P>, gid: &[u8], peer: EndpointId) -> Result<()> {
        let member = st.by_iroh(gid, &peer);
        self.events.send(Event::Synced { group: Bytes(gid.to_vec()), member }).ok();
        st.out.push(Out::WantFiles { peer, group: gid.to_vec() });
        if st.group(gid)?.rec.kind.as_ref().is_some_and(|kind| kind.behind) {
            self.ask_state(st, gid, Some(peer));
        }
        // A file only this session held may have reached the peer since.
        let pending = st.group(gid)?.rec.pending.iter().filter_map(|p| <[u8; 32]>::try_from(p.id.0.as_slice()).ok()).collect::<Vec<_>>();
        for hash in pending {
            let (inner, gid) = (self.clone(), gid.to_vec());
            spawn(async move {
                if inner.net().holders(&gid, hash).await.contains(&peer) {
                    let mut st = inner.lock();
                    if let Ok(g) = st.group_mut(&gid) {
                        g.rec.pending.retain(|pending| pending.id.0 != hash);
                        st.save(&gid).ok();
                    }
                }
            });
        }
        Ok(())
    }
}

impl<P: Provider + Send + 'static> Node<P> {
    /// The other current members' latest summaries of the group, as saved, whatever the gate.
    pub fn heard(&self, gid: &[u8]) -> Result<Vec<Heard>> {
        let st = self.inner.lock();
        let heard = st.group(gid)?.heard.values().filter_map(|heard| {
            let member = st.in_leaf(gid, &endpoint_id(&heard.peer.0)?)?;
            let member = st.member(gid, &member)?;
            Some(Heard { member, held: heard.summary.held.clone(), read: heard.summary.read.clone(), at: heard.at })
        });
        Ok(heard.collect())
    }

    /// The other members no summary was heard from for H: away, and their summaries no longer count as holding.
    pub fn away(&self, gid: &[u8]) -> Result<Vec<Member>> {
        let (heard, since, me) = (self.heard(gid)?, self.carried_since(gid)?, self.key_in(gid));
        let away = |m: &Member| m.key != me && !heard.iter().any(|h| h.member.key == m.key && h.at >= since);
        Ok(self.members(gid)?.into_iter().filter(away).collect())
    }

    /// This session's own counted positions within H that no other member's summary shows held, but an away one's.
    pub fn only_here(&self, gid: &[u8]) -> Result<Ranges> {
        let since = self.carried_since(gid)?;
        let held = self.heard(gid)?.iter().filter(|h| h.at >= since).fold(Ranges::default(), |held, h| held.union(&h.held));
        Ok(self.inner.lock().group(gid)?.rec.own.difference(&held))
    }

    /// Marks positions of the group read, as its client showed or printed them: its summaries carry them.
    pub fn mark_read(&self, gid: &[u8], positions: &Ranges) -> Result<()> {
        let mut st = self.inner.lock();
        let rec = &mut st.group_mut(gid)?.rec;
        rec.read = rec.read.union(positions).difference(&Ranges::range(0, rec.expired));
        st.save(gid)
    }

    /// H ago.
    fn carried_since(&self, gid: &[u8]) -> Result<u64> {
        Ok(now().saturating_sub(days(self.settings(gid)?.carry)))
    }
}
