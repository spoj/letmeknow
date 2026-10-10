//! Reading a group's log strictly in order: each position's epoch and verdict is recorded in the step that applies it.
//! A message entry counts once per id per epoch; its ciphertext, which may come before or after it, is carried for H
//! and opened in position order within its epoch. Before a commit that deletes an epoch's keys while this session lacks
//! some of its messages, it syncs with the members online.

use std::collections::HashSet;

use anyhow::{Context, Result};
use iroh::EndpointId;
use lmk_core::group::{self as core, Verdict};
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::group::{Control, type_of};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Event, Inner, Message, Out, State, Work, days, get, message_key, now, put};

/// How long a missing counted position holds up the later ones of its epoch before they open past it, in
/// milliseconds; it still opens if it comes later.
const PASS: u64 = 10 * 1000;
/// How long the wait before a commit that deletes an epoch's keys goes on without progress, in milliseconds.
const STALL: u64 = 10 * 1000;
/// The bytes of ciphertexts a group keeps that came before their entries were read.
const EARLY: usize = 4 << 20;

/// A position of a group's log, as this session judged it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Pos {
    /// The epoch current when it was read.
    pub epoch: u64,
    /// When it was read, in milliseconds.
    pub at: u64,
    pub judged: Judged,
    /// A counted position this session can no longer open.
    #[serde(default)]
    pub lost: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Judged {
    /// A commit applied, this session's own or not.
    Commit { own: bool },
    Skipped,
    /// A message entry that counts: its message's id.
    Counted { id: Bytes },
}

fn pos_key(gid: &[u8], position: u64) -> Vec<u8> {
    [b"node/pos/".as_slice(), gid, b"/", &position.to_be_bytes()].concat()
}

/// The position at which an id first counted.
fn id_key(gid: &[u8], id: &[u8]) -> Vec<u8> {
    [b"node/id/".as_slice(), gid, b"/", id].concat()
}

pub(crate) fn ciphertext_key(gid: &[u8], position: u64) -> Vec<u8> {
    [b"node/ciphertext/".as_slice(), gid, b"/", &position.to_be_bytes()].concat()
}

/// The wait before applying the commit at `position`, which deletes the keys of an epoch whose counted positions this
/// session lacks: a sync with each member online, as 0.12's sync carries ciphertexts.
pub(crate) struct Wait {
    position: u64,
    /// The members online whose sync has not ended yet.
    peers: HashSet<EndpointId>,
    /// When it last made progress: a sync ended, a member came online, or a ciphertext came.
    progress: u64,
}

/// What moves a wait on.
pub(crate) enum Progress {
    Synced(EndpointId),
    Connected(EndpointId),
    Disconnected(EndpointId),
    Ciphertext,
}

/// The wait's rule, apart from how ciphertexts move: it ends once no member online is left to sync with, or after
/// `STALL` without progress.
fn waited(wait: &Wait, now: u64) -> bool {
    wait.peers.is_empty() || now >= wait.progress + STALL
}

impl<P: Provider> State<P> {
    pub(crate) fn pos(&self, gid: &[u8], position: u64) -> Result<Option<Pos>> {
        get(&self.provider, &pos_key(gid, position))
    }

    /// The position at which a message's id first counted, while it is held.
    pub(crate) fn position_of(&self, gid: &[u8], id: &[u8]) -> Result<Option<u64>> {
        get(&self.provider, &id_key(gid, id))
    }

    fn held(&self, gid: &[u8], position: u64) -> Result<bool> {
        Ok(self.provider.get(&ciphertext_key(gid, position))?.is_some())
    }

    /// The group's held messages this session opened and holds, in log order.
    pub(crate) fn messages(&self, gid: &[u8]) -> Result<Vec<Message>> {
        let rec = &self.group(gid)?.rec;
        let mut messages = Vec::new();
        for position in rec.expired + 1..=rec.position {
            if let Some(Pos { judged: Judged::Counted { id }, .. }) = self.pos(gid, position)?
                && let Some(message) = get::<Message>(&self.provider, &message_key(&id.0))?.filter(|m| m.position == position)
            {
                messages.push(message);
            }
        }
        Ok(messages)
    }

    /// The held ciphertexts of counted positions, from epoch `from`: their epochs and ids.
    pub(crate) fn carried(&self, gid: &[u8], from: u64) -> Result<Vec<(u64, [u8; 32])>> {
        let rec = &self.group(gid)?.rec;
        let mut carried = Vec::new();
        for position in rec.expired + 1..=rec.position {
            if let Some(Pos { epoch, judged: Judged::Counted { id }, .. }) = self.pos(gid, position)?
                && epoch >= from
                && self.held(gid, position)?
            {
                carried.push((epoch, id.0.as_slice().try_into()?));
            }
        }
        Ok(carried)
    }

    /// A carried ciphertext, by its epoch and id.
    pub(crate) fn ciphertext(&self, gid: &[u8], epoch: u64, id: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(position) = self.position_of(gid, id)? else { return Ok(None) };
        if self.pos(gid, position)?.is_none_or(|pos| pos.epoch != epoch) {
            return Ok(None);
        }
        self.provider.get(&ciphertext_key(gid, position))
    }

    /// Drops what this session kept of the positions read longer than H ago, and the invites and file links as old.
    pub(crate) fn expire(&mut self, gid: &[u8]) -> Result<()> {
        let g = self.group_mut(gid)?;
        let before = now().saturating_sub(days(g.mls.settings().carry));
        g.rec.files.retain(|(_, at)| *at >= before);
        g.rec.invites.retain(|rule| rule.expires >= before);
        let (mut position, last) = (g.rec.expired, g.rec.position);
        while position < last && self.pos(gid, position + 1)?.is_none_or(|pos| pos.at < before) {
            position += 1;
        }
        self.expire_to(gid, position)
    }

    /// Drops what this session kept of positions up to `to`.
    pub(crate) fn expire_to(&mut self, gid: &[u8], to: u64) -> Result<()> {
        let rec = &self.group(gid)?.rec;
        let (from, to) = (rec.expired + 1, to.min(rec.position));
        for position in from..=to {
            if let Some(Pos { judged: Judged::Counted { id }, .. }) = self.pos(gid, position)? {
                if self.position_of(gid, &id.0)? == Some(position) {
                    self.provider.delete(&id_key(gid, &id.0))?;
                }
                if get::<Message>(&self.provider, &message_key(&id.0))?.is_some_and(|m| m.position == position) {
                    self.provider.delete(&message_key(&id.0))?;
                }
                self.provider.delete(&ciphertext_key(gid, position))?;
            }
            self.provider.delete(&pos_key(gid, position))?;
        }
        let rec = &mut self.group_mut(gid)?.rec;
        rec.expired = rec.expired.max(to);
        rec.unopened.retain(|position, _| *position > to);
        self.save(gid)
    }

    /// The counted positions of the epoch before the current one, whose keys the next commit deletes, that this
    /// session lacks.
    fn lacking(&self, gid: &[u8]) -> Result<Vec<u64>> {
        let g = self.group(gid)?;
        let prior = g.mls.epoch().checked_sub(1);
        let mut lacking = Vec::new();
        for (position, (epoch, _)) in &g.rec.unopened {
            if Some(*epoch) == prior && !self.held(gid, *position)? {
                lacking.push(*position);
            }
        }
        Ok(lacking)
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Reads the stored entries of a group's log this session has not judged yet, in order, then opens what it can and
    /// hands its kind what is next in order.
    pub(crate) fn advance(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        let logged = st.log(gid)?.logged;
        while let Some(g) = st.groups.get(gid)
            && g.rec.position < logged
            && g.mls.active()
        {
            let position = g.rec.position + 1;
            let entry = st.provider.get(&crate::logs::entry_key(gid, position))?.context("a stored entry is missing")?;
            if !self.judge(st, gid, position, &entry)? {
                break;
            }
        }
        if st.groups.contains_key(gid) {
            st.save(gid)?;
            self.open_ready(st, gid)?;
            self.kind_advance(st, gid)?;
        }
        self.advanced.notify_waiters();
        Ok(())
    }

    /// Judges and applies the entry at the next position; false if it waits, or the group is gone from this session.
    fn judge(&self, st: &mut State<P>, gid: &[u8], position: u64, entry: &[u8]) -> Result<bool> {
        let now = now();
        let g = st.groups.get_mut(gid).unwrap();
        let epoch = g.mls.epoch();
        let judged = match g.mls.judge(&st.provider, entry)? {
            Verdict::Message { id } => {
                let counted = match st.position_of(gid, &id)? {
                    Some(earlier) => st.pos(gid, earlier)?.is_some_and(|pos| pos.epoch == epoch),
                    None => false,
                };
                if counted {
                    Judged::Skipped
                } else {
                    self.count(st, gid, position, epoch, id, now)?;
                    Judged::Counted { id: Bytes(id.to_vec()) }
                }
            }
            Verdict::Skipped { .. } => Judged::Skipped,
            Verdict::Copied => {
                let text = "a copy of this session's state committed in the group, so this session stops using it: join it again, or revoke this device if it may be stolen";
                self.warn(Some(gid), text.into());
                self.work.send(Work::Gone(gid.to_vec())).ok();
                return Ok(false);
            }
            Verdict::Commit { removes } => {
                if !self.cleared(st, gid, position)? {
                    return Ok(false);
                }
                self.before_commit(st, gid, removes)?;
                let g = st.groups.get_mut(gid).unwrap();
                let applied = g.mls.apply(&st.provider, entry)?;
                g.wait = None;
                let current = g.mls.epoch();
                g.early.retain(|early| core::header(early).is_ok_and(|(epoch, _)| epoch >= current));
                let members = g.mls.members();
                g.rec.leaves.retain(|(key, _)| members.iter().any(|m| m.key == key.0));
                let by = members.into_iter().find(|m| m.index == applied.by);
                let own = applied.own;
                let gone = applied.gone;
                st.scrub = true;
                st.out.push(Out::Changed(gid.to_vec()));
                let core::Applied { added, how, invite, removed, settings, .. } = applied;
                self.work.send(Work::Applied { group: gid.to_vec(), by, added, how, invite, removed, settings, gone }).ok();
                let pos = Pos { epoch, at: now, judged: Judged::Commit { own }, lost: false };
                put(&st.provider, &pos_key(gid, position), &pos)?;
                st.group_mut(gid)?.rec.position = position;
                return Ok(!gone);
            }
        };
        put(&st.provider, &pos_key(gid, position), &Pos { epoch, at: now, judged, lost: false })?;
        st.group_mut(gid)?.rec.position = position;
        Ok(true)
    }

    /// A message entry counts: its ciphertext is this session's own send, one that came early, or yet to come.
    fn count(&self, st: &mut State<P>, gid: &[u8], position: u64, epoch: u64, id: [u8; 32], now: u64) -> Result<()> {
        put(&st.provider, &id_key(gid, &id), &position)?;
        st.group_mut(gid)?.rec.unopened.insert(position, (epoch, now));
        if let Some((handle, send)) = st.own_send(gid, &id)? {
            return self.counted(st, gid, position, handle, send);
        }
        let g = st.group_mut(gid)?;
        let early = g.early.iter().position(|ciphertext| <[u8; 32]>::from(Sha256::digest(ciphertext)) == id);
        if let Some(early) = early.filter(|early| core::header(&g.early[*early]).is_ok_and(|(sealed, _)| sealed == epoch)) {
            let ciphertext = g.early.remove(early);
            st.provider.put(&ciphertext_key(gid, position), &ciphertext)?;
        }
        Ok(())
    }

    /// Takes a held ciphertext from a peer, if it fills a counted position: one whose epoch, in its clear header, is the
    /// position's. One that comes before its entry is kept a while if it is for the current epoch or the next. A live
    /// one goes to the kind.
    pub(crate) fn take(&self, st: &mut State<P>, gid: &[u8], ciphertext: &[u8]) -> Result<()> {
        let Ok(g) = st.group(gid) else { return Ok(()) };
        let Ok((epoch, live)) = core::header(ciphertext) else { return Ok(()) };
        if ciphertext.len() > core::MAX_MESSAGE {
            return Ok(());
        }
        if live {
            return self.live(st, gid, ciphertext);
        }
        let current = g.mls.epoch();
        let id: [u8; 32] = Sha256::digest(ciphertext).into();
        match st.position_of(gid, &id)? {
            Some(position) => {
                let fills = st.pos(gid, position)?.is_some_and(|pos| pos.epoch == epoch) && g.rec.unopened.contains_key(&position);
                if fills && !st.held(gid, position)? {
                    st.provider.put(&ciphertext_key(gid, position), ciphertext)?;
                    self.progress(st, gid, Progress::Ciphertext)?;
                    self.open_ready(st, gid)?;
                    self.kind_advance(st, gid)?;
                }
            }
            None if epoch == current || epoch == current + 1 => {
                let g = st.group_mut(gid)?;
                let size: usize = g.early.iter().map(Vec::len).sum();
                if size + ciphertext.len() <= EARLY && !g.early.iter().any(|early| early == ciphertext) {
                    g.early.push(ciphertext.to_vec());
                }
            }
            None => {}
        }
        Ok(())
    }

    /// A live payload: taken only once this session applied its log to its head as last read, and only from a sender
    /// in its current epoch, by leaf index and key.
    fn live(&self, st: &mut State<P>, gid: &[u8], ciphertext: &[u8]) -> Result<()> {
        let logged = st.log(gid)?.logged;
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        if g.rec.position < logged || g.wait.is_some() {
            return Ok(());
        }
        let opened = match g.mls.open(&st.provider, ciphertext) {
            Ok(opened) if opened.live && opened.current == Some(opened.index) => opened,
            Ok(_) => return Ok(()),
            Err(error) => {
                tracing::debug!("a live message did not open: {error:#}");
                return Ok(());
            }
        };
        let sender = g.mls.members().into_iter().find(|m| Some(m.index) == opened.current).context("a current member")?;
        let sender = st.member(gid, &sender).context("the sender has no letmeknow credential")?;
        self.events.send(Event::Live { group: Bytes(gid.to_vec()), sender, payload: opened.payload }).ok();
        Ok(())
    }

    /// Opens the held counted positions in position order within each epoch; one missing holds up the later ones of its
    /// epoch for `PASS` after its entry was read.
    pub(crate) fn open_ready(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        let now = now();
        let mut blocked = HashSet::new();
        for (position, (epoch, at)) in st.group(gid)?.rec.unopened.clone() {
            if blocked.contains(&epoch) {
                continue;
            }
            if st.held(gid, position)? {
                self.open(st, gid, position, epoch)?;
            } else if now < at + PASS {
                blocked.insert(epoch);
            }
        }
        st.save(gid)
    }

    /// Before a commit applies, which deletes the prior epoch's keys: opens what this session holds of that epoch,
    /// and of the current one too if the commit removes it; what it lacks of them is lost to it.
    fn before_commit(&self, st: &mut State<P>, gid: &[u8], removes: bool) -> Result<()> {
        let current = st.group(gid)?.mls.epoch();
        let ending = |epoch: u64| epoch + 1 == current || removes && epoch == current;
        for (position, (epoch, _)) in st.group(gid)?.rec.unopened.clone() {
            if !ending(epoch) {
                continue;
            }
            if st.held(gid, position)? {
                self.open(st, gid, position, epoch)?;
            } else {
                self.lose(st, gid, position)?;
            }
        }
        Ok(())
    }

    /// Opens a counted position's ciphertext and hands its plaintext on, or records it lost.
    fn open(&self, st: &mut State<P>, gid: &[u8], position: u64, epoch: u64) -> Result<()> {
        let ciphertext = st.provider.get(&ciphertext_key(gid, position))?.context("a held ciphertext is missing")?;
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        let opened = match g.mls.open(&st.provider, &ciphertext) {
            Ok(opened) => opened,
            Err(error) => {
                tracing::debug!("a message did not open: {error:#}");
                return self.lose(st, gid, position);
            }
        };
        g.rec.unopened.remove(&position);
        let members = g.mls.members();
        let sender = members.into_iter().find(|m| m.key == opened.sender.key.0).unwrap_or(core::Member {
            index: opened.index,
            key: opened.sender.key.0.clone(),
            credential: Some(opened.sender.clone()),
            leaf: None,
        });
        let sender = st.member(gid, &sender).context("the sender has no letmeknow credential")?;
        let message = Message { id: Bytes(opened.id.to_vec()), group: Bytes(gid.to_vec()), epoch, position, at: now(), sender, payload: opened.payload };
        self.deliver(st, gid, message, false)
    }

    fn lose(&self, st: &mut State<P>, gid: &[u8], position: u64) -> Result<()> {
        st.group_mut(gid)?.rec.unopened.remove(&position);
        let mut pos = st.pos(gid, position)?.context("a counted position has its record")?;
        pos.lost = true;
        put(&st.provider, &pos_key(gid, position), &pos)
    }

    /// Hands a held message's plaintext to its consumer, in this step: the core takes its own payloads as records; the
    /// kind's go out as events, but this session's own, and to the kind in log order (`kind_advance`).
    pub(crate) fn deliver(&self, st: &mut State<P>, gid: &[u8], message: Message, own: bool) -> Result<()> {
        put(&st.provider, &message_key(&message.id.0), &message)?;
        let group = Bytes(gid.to_vec());
        if !Control::TYPES.contains(&type_of(&message.payload)) {
            if !own {
                self.events.send(Event::Message(message)).ok();
            }
            return Ok(());
        }
        match serde_json::from_value(message.payload)? {
            Control::Leave => {
                st.group_mut(gid)?.rec.leaves.push((message.sender.key, message.epoch));
                st.save(gid)?;
                self.leavers(st, gid)?;
            }
            Control::Introduce { identity, name, how, to } => {
                let me = Bytes(Sha256::digest(st.session.key())[..8].to_vec());
                if !own && (to.is_empty() || to.contains(&me)) {
                    self.events.send(Event::Introduced { group, by: message.sender, identity, name, how }).ok();
                }
            }
            Control::Invite { hash, expires, label, to } => {
                let rec = &mut st.group_mut(gid)?.rec;
                if !rec.invites.iter().any(|rule| rule.hash == hash) {
                    rec.invites.push(crate::Rule { hash, expires, label, to, by: message.sender.key });
                }
            }
        }
        Ok(())
    }

    /// Whether the commit at `position` may apply now. It deletes the keys of the epoch before the current one: while
    /// this session lacks counted positions of that epoch, it first syncs with each member online.
    fn cleared(&self, st: &mut State<P>, gid: &[u8], position: u64) -> Result<bool> {
        if st.lacking(gid)?.is_empty() {
            return Ok(true);
        }
        let now = now();
        if let Some(wait) = st.group(gid)?.wait.as_ref().filter(|wait| wait.position == position) {
            return Ok(waited(wait, now));
        }
        let connected = self.net.get().map(|net| net.connected()).unwrap_or_default();
        let peers: HashSet<EndpointId> = connected.into_iter().filter(|peer| st.serves(gid, peer)).collect();
        for peer in &peers {
            st.out.push(Out::Served { peer: *peer, group: gid.to_vec() });
        }
        let wait = Wait { position, peers, progress: now };
        let over = waited(&wait, now);
        st.group_mut(gid)?.wait = Some(wait);
        if !over {
            self.work.send(Work::Wait(gid.to_vec())).ok();
        }
        Ok(over)
    }

    /// Moves a group's wait on, and reads on once it is over.
    pub(crate) fn progress(&self, st: &mut State<P>, gid: &[u8], progress: Progress) -> Result<()> {
        let now = now();
        let Some(wait) = st.groups.get_mut(gid).and_then(|g| g.wait.as_mut()) else { return Ok(()) };
        let moved = match progress {
            Progress::Synced(peer) => wait.peers.remove(&peer),
            Progress::Disconnected(peer) => {
                wait.peers.remove(&peer);
                false
            }
            Progress::Connected(peer) => wait.peers.insert(peer),
            Progress::Ciphertext => true,
        };
        if moved {
            wait.progress = now;
        }
        let over = waited(wait, now);
        if let (Progress::Connected(peer), true) = (progress, moved) {
            st.out.push(Out::Served { peer, group: gid.to_vec() });
        }
        if over {
            self.advance(st, gid)?;
        }
        Ok(())
    }

    /// Reads on once a group's wait is over without progress.
    pub(crate) fn wait_over(&self, st: &mut State<P>, gid: &[u8]) -> Result<bool> {
        let Some(wait) = st.groups.get(gid).and_then(|g| g.wait.as_ref()) else { return Ok(true) };
        if !waited(wait, now()) {
            return Ok(false);
        }
        self.advance(st, gid)?;
        Ok(true)
    }
}
