//! Reading a group's log strictly in order: each position's epoch and verdict is recorded in the step that applies it.
//! A message entry counts once per id per epoch; its ciphertext, which may come before or after it, is carried for H
//! and opened in position order within its epoch. Before a commit that deletes an epoch's keys while this session lacks
//! some of its messages, it waits as `Peers::wait` decides, fetching them from the members that hold them.

use std::collections::HashSet;

use anyhow::{Context, Result};
use iroh::EndpointId;
use lmk_core::group::{self as core, Verdict};
use lmk_core::provider::Provider;
use lmk_net::peers::{Decision, HOLD_OFF};
use lmk_proto::Bytes;
use lmk_proto::group::{Control, type_of};
use lmk_proto::ranges::Ranges;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Dropped, Event, Inner, Judgement, Message, Observation, State, Work, days, get, message_key, now, put};

/// The bytes of ciphertexts a group keeps from one peer that came before their entries were read.
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

pub(crate) fn pos_key(gid: &[u8], position: u64) -> Vec<u8> {
    [b"node/pos/".as_slice(), gid, b"/", &position.to_be_bytes()].concat()
}

/// The position at which an id first counted.
fn id_key(gid: &[u8], id: &[u8]) -> Vec<u8> {
    [b"node/id/".as_slice(), gid, b"/", id].concat()
}

pub(crate) fn ciphertext_key(gid: &[u8], position: u64) -> Vec<u8> {
    [b"node/ciphertext/".as_slice(), gid, b"/", &position.to_be_bytes()].concat()
}

impl<P: Provider> State<P> {
    pub(crate) fn pos(&self, gid: &[u8], position: u64) -> Result<Option<Pos>> {
        get(&self.provider, &pos_key(gid, position))
    }

    /// The position at which a message's id first counted, while it is held.
    pub(crate) fn position_of(&self, gid: &[u8], id: &[u8]) -> Result<Option<u64>> {
        get(&self.provider, &id_key(gid, id))
    }

    pub(crate) fn held(&self, gid: &[u8], position: u64) -> Result<bool> {
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
        let gone = Ranges::range(0, rec.expired);
        for kept in [&mut rec.messages, &mut rec.own, &mut rec.lacking, &mut rec.lost, &mut rec.read] {
            *kept = kept.difference(&gone);
        }
        rec.losses.retain(|position, _| *position > to);
        self.save(gid)
    }

    /// The counted positions of the epoch before the current one, whose keys the next commit deletes, that this
    /// session lacks.
    fn lacking(&self, gid: &[u8]) -> Result<Ranges> {
        let g = self.group(gid)?;
        let prior = g.mls.epoch().checked_sub(1);
        let unopened = g.rec.unopened.iter().filter(|(_, (epoch, _))| Some(*epoch) == prior).map(|(position, _)| *position);
        Ok(unopened.collect::<Ranges>().intersection(&g.rec.lacking))
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
            if st.group(gid)?.rec.position == logged {
                self.work.send(Work::Duties(gid.to_vec())).ok();
            }
        }
        self.advanced.notify_waiters();
        Ok(())
    }

    /// Judges and applies the entry at the next position; false if it waits, or the group is gone from this session.
    fn judge(&self, st: &mut State<P>, gid: &[u8], position: u64, entry: &[u8]) -> Result<bool> {
        let now = now();
        let g = st.groups.get_mut(gid).unwrap();
        let epoch = g.mls.epoch();
        let read = |verdict| Observation::Read { group: Bytes(gid.to_vec()), position, entry: Sha256::digest(entry).into(), epoch, verdict };
        let judged = match g.mls.judge(&st.provider, entry)? {
            Verdict::Message { id } => {
                let counted = match st.position_of(gid, &id)? {
                    Some(earlier) => st.pos(gid, earlier)?.is_some_and(|pos| pos.epoch == epoch),
                    None => false,
                };
                if counted {
                    Judged::Skipped
                } else {
                    st.observe(|| read(Judgement::Counted { id: Bytes(id.to_vec()) }));
                    self.count(st, gid, position, epoch, id, now)?;
                    Judged::Counted { id: Bytes(id.to_vec()) }
                }
            }
            Verdict::Skipped { .. } => Judged::Skipped,
            Verdict::Copied => {
                let text = "a copy of this session's state committed in the group, so this session stops using it: join it again, or revoke this device if it may be stolen";
                self.warn(Some(gid), text.into());
                st.observe(|| Observation::Dropped { group: Bytes(gid.to_vec()), reason: Dropped::Copied });
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
                let current = g.mls.epoch();
                g.early.retain(|(_, early)| core::header(early).is_ok_and(|(epoch, _)| epoch >= current));
                let members = g.mls.members();
                g.rec.leaves.retain(|(key, _)| members.iter().any(|m| m.key == key.0));
                let by = members.into_iter().find(|m| m.index == applied.by);
                let own = applied.own;
                let gone = applied.gone;
                if own {
                    g.rec.updated = now;
                }
                st.scrub = true;
                st.gate = true;
                for leaf in applied.removed.iter().filter_map(|m| m.leaf.as_ref()) {
                    st.unhear(gid, &leaf.key.0)?;
                }
                let core::Applied { added, how, invite, removed, settings, .. } = applied;
                let keys = |members: &[core::Member]| members.iter().map(|m| Bytes(m.key.clone())).collect();
                let verdict = Judgement::Commit { committer: Bytes(by.as_ref().map(|by| by.key.clone()).unwrap_or_default()), added: keys(&added), removed: keys(&removed) };
                st.observe(|| read(verdict));
                self.work.send(Work::Applied { group: gid.to_vec(), by, added, how, invite, removed, settings, gone }).ok();
                let pos = Pos { epoch, at: now, judged: Judged::Commit { own }, lost: false };
                put(&st.provider, &pos_key(gid, position), &pos)?;
                st.group_mut(gid)?.rec.position = position;
                return Ok(!gone);
            }
        };
        if judged == Judged::Skipped {
            st.observe(|| read(Judgement::Skipped));
        }
        put(&st.provider, &pos_key(gid, position), &Pos { epoch, at: now, judged, lost: false })?;
        st.group_mut(gid)?.rec.position = position;
        Ok(true)
    }

    /// A message entry counts: its ciphertext is this session's own send, one that came early, or yet to come.
    fn count(&self, st: &mut State<P>, gid: &[u8], position: u64, epoch: u64, id: [u8; 32], now: u64) -> Result<()> {
        put(&st.provider, &id_key(gid, &id), &position)?;
        let rec = &mut st.group_mut(gid)?.rec;
        rec.unopened.insert(position, (epoch, now));
        rec.messages.insert(position);
        if let Some((handle, send)) = st.own_send(gid, &id)? {
            return self.counted(st, gid, position, handle, send);
        }
        let g = st.group_mut(gid)?;
        let early = g.early.iter().position(|(_, ciphertext)| <[u8; 32]>::from(Sha256::digest(ciphertext)) == id);
        match early.filter(|early| core::header(&g.early[*early].1).is_ok_and(|(sealed, _)| sealed == epoch)) {
            Some(early) => {
                let (_, ciphertext) = g.early.remove(early);
                st.provider.put(&ciphertext_key(gid, position), &ciphertext)?;
            }
            None => g.rec.lacking.insert(position),
        }
        Ok(())
    }

    /// Takes held ciphertexts from a peer, each if it fills a counted position: one whose epoch, in its clear header, is
    /// the position's. One that comes before its entry, from a peer the gate admits, is kept a while if it is for the
    /// current epoch or the next, within `EARLY` per peer. Then reads on, if reading waited for them, or opens them.
    pub(crate) fn take_all(&self, st: &mut State<P>, gid: &[u8], peer: EndpointId, ciphertexts: &[&[u8]], admitted: bool) -> Result<()> {
        let mut filled = false;
        for ciphertext in ciphertexts {
            filled |= self.take(st, gid, peer, ciphertext, admitted)?;
        }
        if !filled {
            return Ok(());
        }
        if st.group(gid)?.waiting {
            return self.advance(st, gid);
        }
        self.open_ready(st, gid)?;
        self.kind_advance(st, gid)
    }

    /// Takes one held ciphertext; whether it filled a counted position.
    fn take(&self, st: &mut State<P>, gid: &[u8], peer: EndpointId, ciphertext: &[u8], admitted: bool) -> Result<bool> {
        let g = st.group(gid)?;
        let Ok((epoch, false)) = core::header(ciphertext) else { return Ok(false) };
        if ciphertext.len() > core::MAX_MESSAGE {
            return Ok(false);
        }
        let current = g.mls.epoch();
        let id: [u8; 32] = Sha256::digest(ciphertext).into();
        match st.position_of(gid, &id)? {
            Some(position) => {
                if st.pos(gid, position)?.is_some_and(|pos| pos.epoch == epoch) && g.rec.lacking.contains(position) {
                    st.provider.put(&ciphertext_key(gid, position), ciphertext)?;
                    st.group_mut(gid)?.rec.lacking.remove(position);
                    return Ok(true);
                }
            }
            None if admitted && (epoch == current || epoch == current + 1) => {
                let g = st.group_mut(gid)?;
                let size: usize = g.early.iter().filter(|(from, _)| *from == peer).map(|(_, early)| early.len()).sum();
                if size + ciphertext.len() <= EARLY && !g.early.iter().any(|(_, early)| early == ciphertext) {
                    g.early.push((peer, ciphertext.to_vec()));
                }
            }
            None => {}
        }
        Ok(false)
    }

    /// A live payload, which the gate let in once this session applied its log to its head as last read: taken only
    /// from a sender in its current epoch, by leaf index and key.
    pub(crate) fn live(&self, st: &mut State<P>, gid: &[u8], ciphertext: &[u8]) -> Result<()> {
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        if !core::header(ciphertext).is_ok_and(|(_, live)| live) {
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
        st.observe(|| Observation::Live { group: Bytes(gid.to_vec()), sender: sender.key.clone(), epoch: opened.epoch });
        self.events.send(Event::Live { group: Bytes(gid.to_vec()), sender, payload: opened.payload }).ok();
        Ok(())
    }

    /// Opens the held counted positions in position order within each epoch; one missing holds up the later ones of its
    /// epoch while `holds_up`, then they open past it, and it opens still if it comes while its epoch's keys are kept.
    pub(crate) fn open_ready(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        let mut blocked = HashSet::new();
        for (position, (epoch, at)) in st.group(gid)?.rec.unopened.clone() {
            if blocked.contains(&epoch) {
                continue;
            }
            if st.held(gid, position)? {
                self.open(st, gid, position, epoch)?;
            } else if self.holds_up(st, gid, position, at) {
                blocked.insert(epoch);
            }
        }
        st.save(gid)
    }

    /// Whether a counted position missing here, whose entry was read at `at`, holds up the later ones of its epoch: while
    /// it is being fetched, or while its push is likely on the way (its entry was read under `HOLD_OFF` ago).
    pub(crate) fn holds_up(&self, st: &State<P>, gid: &[u8], position: u64, at: u64) -> bool {
        st.peers.fetching(&Bytes(gid.to_vec())).contains(position) || now() < at + HOLD_OFF
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
        let message = Message { id: Bytes(opened.id.to_vec()), group: Bytes(gid.to_vec()), epoch, position, at: now(), sender, payload: opened.payload, missing: Vec::new() };
        self.deliver(st, gid, message, false)
    }

    fn lose(&self, st: &mut State<P>, gid: &[u8], position: u64) -> Result<()> {
        let rec = &mut st.group_mut(gid)?.rec;
        rec.unopened.remove(&position);
        rec.lacking.remove(position);
        rec.lost.insert(position);
        st.observe(|| Observation::Lost { group: Bytes(gid.to_vec()), position });
        self.work.send(Work::Duties(gid.to_vec())).ok();
        let mut pos = st.pos(gid, position)?.context("a counted position has its record")?;
        pos.lost = true;
        put(&st.provider, &pos_key(gid, position), &pos)
    }

    /// Hands a held message's plaintext to its consumer, in this step: the core takes its own payloads as records; the
    /// kind's go out as events in position order (`show`), but this session's own, and to the kind in log order
    /// (`kind_advance`). One that opens after later ones were shown goes out now.
    pub(crate) fn deliver(&self, st: &mut State<P>, gid: &[u8], message: Message, own: bool) -> Result<()> {
        put(&st.provider, &message_key(&message.id.0), &message)?;
        let group = Bytes(gid.to_vec());
        let kind = match type_of(&message.payload) {
            core if Control::TYPES.contains(&core) => core.to_owned(),
            _ => st.group(gid)?.mls.settings().kind,
        };
        let plaintext = Sha256::digest(serde_json::to_vec(&message.payload)?).into();
        st.observe(|| Observation::Opened { group: group.clone(), position: message.position, kind, sender: message.sender.key.clone(), plaintext });
        if !Control::TYPES.contains(&type_of(&message.payload)) {
            let rec = &mut st.group_mut(gid)?.rec;
            if !own && message.position <= rec.shown {
                rec.missing.retain(|missing| *missing != message.position);
                self.events.send(Event::Message(message)).ok();
            }
            return Ok(());
        }
        match serde_json::from_value(message.payload)? {
            Control::Leave => {
                st.group_mut(gid)?.rec.leaves.push((message.sender.key, message.epoch));
                st.save(gid)?;
                self.work.send(Work::Duties(gid.to_vec())).ok();
            }
            Control::Lost { positions } => self.announced(st, gid, message.position, message.sender, positions)?,
            Control::Introduce { identity, name, how, to } => {
                let me = Bytes(Sha256::digest(st.me(gid))[..8].to_vec());
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
    /// this session lacks counted positions of that epoch, it waits as `Peers::wait` decides, fetching them meanwhile;
    /// what it lacks once it applies the commit is lost (`before_commit`).
    fn cleared(&self, st: &mut State<P>, gid: &[u8], position: u64) -> Result<bool> {
        let lacking = st.lacking(gid)?;
        // The gate and this session's state as the step so far left them: a member a commit added may hold what this one
        // lacks, and a ciphertext taken is progress.
        st.gate();
        st.refresh(gid);
        let now = st.tick();
        let undecided = st.undecided(gid);
        let waiting = st.peers.wait(&Bytes(gid.to_vec()), &lacking, &undecided, now) == Decision::Wait;
        if waiting {
            tracing::debug!("waiting at position {position} for {:?}", lacking.ranges());
        }
        st.group_mut(gid)?.waiting = waiting;
        Ok(!waiting)
    }
}
