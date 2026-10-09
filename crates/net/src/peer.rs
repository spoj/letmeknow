//! A `peer` stream: hello and head swap, log entries, negentropy message sync, live messages, want
//! and have, joiners' requests, and kinds' state links. Every group frame is served only to a member
//! with a valid certificate of the identity it speaks as, and every log's entries only to such a
//! member of a group that follows it; certificates go to every member.
//!
//! Negentropy tells only its initiator what each side lacks, so a sync runs two rounds: the
//! dialer initiates and pushes what the acceptor lacks, then ends its round with an empty
//! `reconcile`; the acceptor then does the same the other way.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use anyhow::{Result, bail, ensure};
use iroh::EndpointId;
use lmk_proto::{
    Answer, Bytes, frame,
    head::Head,
    identity::Envelope,
    peer::{Admitted, Below, Frame, Hello, Join},
};
use lmk_transport::{Conn, RecvStream, SendStream};
use sha2::{Digest, Sha256};
use n0_future::{task::spawn, time::sleep};
use negentropy::{Negentropy, NegentropyStorageVector};
use tokio::sync::{mpsc, oneshot};

use crate::{Event, Inner, Taken, sync};

/// Raw ciphertext bytes per `messages` frame, well under a frame's limit once in base64.
const BATCH: usize = 8 << 20;
/// The messages of a group kept for a peer that has not shown it yet.
const WAITING: usize = 256;

/// Takes the answer to a `want`; `None` for wants sent on catching up, whose answers start downloads.
type HaveReply = Option<oneshot::Sender<Vec<[u8; 32]>>>;

pub(crate) enum Input {
    Frame(Frame),
    Closed,
    Send(Frame),
    Changed(Bytes),
    /// This session serves the peer the group again.
    Served(Bytes),
    /// Time to sync every group again.
    Resync,
    Want { group: Bytes, files: Vec<[u8; 32]>, reply: HaveReply },
    Join { join: Join, reply: oneshot::Sender<Answer<Admitted>> },
}

struct Session {
    inner: Arc<Inner>,
    peer: EndpointId,
    dialer: bool,
    send: SendStream,
    input: mpsc::UnboundedSender<Input>,
    groups: HashMap<Bytes, Group>,
    /// Our `want`s awaiting their `have`, in order.
    wants: HashMap<Bytes, VecDeque<HaveReply>>,
    /// Our requests to be admitted awaiting their answer, by id.
    joins: HashMap<u64, oneshot::Sender<Answer<Admitted>>>,
    logs: HashMap<Bytes, Log>,
    /// The certificates shown the peer since the last resync, by signature.
    shown: HashSet<Bytes>,
    /// Messages of groups the peer has not shown in a `hello` yet, so would drop: sent once it does.
    waiting: HashMap<Bytes, VecDeque<Frame>>,
}

#[derive(Default)]
struct Log {
    /// The newest head the peer showed.
    theirs: Option<Head>,
    /// The longest head the peer showed beyond our log, judged once our log reaches it.
    longer: Option<Head>,
}

#[derive(Default)]
struct Group {
    theirs: Option<Hello>,
    /// The length of the group's log we last started a sync at.
    synced: Option<u64>,
    initiator: Option<Round>,
    responder: Option<Negentropy<'static, NegentropyStorageVector>>,
    /// The dialer's sync is under way, and whether another should follow it.
    busy: bool,
    again: bool,
    /// The dialer's sync was under way at the last resync too: the peer, which stopped serving this session the group
    /// meanwhile, dropped it.
    stale: bool,
}

struct Round {
    negentropy: Negentropy<'static, NegentropyStorageVector>,
    items: Items,
}

/// Each item's epoch, and its place in the order this session took the items.
type Items = HashMap<[u8; 32], (u64, usize)>;

/// Runs the connection's one peer stream; the connection closes with it.
pub(crate) async fn run(
    inner: Arc<Inner>,
    conn: Conn,
    dialer: bool,
    send: SendStream,
    mut recv: RecvStream,
    input: mpsc::UnboundedSender<Input>,
    mut rx: mpsc::UnboundedReceiver<Input>,
) {
    let peer = conn.remote_id();
    let (ticker, resync) = (input.clone(), inner.config.resync);
    spawn(async move {
        loop {
            sleep(resync).await;
            if ticker.send(Input::Resync).is_err() {
                return;
            }
        }
    });
    let reader = input.clone();
    spawn(async move {
        while let Ok(frame) = frame::read_known(&mut recv).await {
            if reader.send(Input::Frame(frame)).is_err() {
                return;
            }
        }
        reader.send(Input::Closed).ok();
    });
    let mut session = Session {
        inner,
        peer,
        dialer,
        send,
        input,
        groups: HashMap::new(),
        wants: HashMap::new(),
        joins: HashMap::new(),
        logs: HashMap::new(),
        shown: HashSet::new(),
        waiting: HashMap::new(),
    };
    let result = async {
        session.hello().await?;
        while let Some(input) = rx.recv().await {
            match input {
                Input::Frame(frame) => session.frame(frame).await?,
                Input::Closed => break,
                Input::Send(frame) => session.send(frame).await?,
                Input::Changed(group) => session.changed(group).await?,
                Input::Served(group) => {
                    session.groups.remove(&group);
                    session.changed(group).await?
                }
                Input::Resync => session.resync().await?,
                Input::Want { group, files, reply } => {
                    session.wants.entry(group.clone()).or_default().push_back(reply);
                    let files = files.into_iter().map(Bytes::from).collect();
                    session.write(&Frame::Want { group, files }).await?;
                }
                Input::Join { join, reply } => {
                    let id = session.joins.keys().max().map_or(0, |id| id + 1);
                    session.joins.insert(id, reply);
                    session.write(&Frame::Join { id, join }).await?;
                }
            }
        }
        anyhow::Ok(())
    }
    .await;
    if let Err(e) = result {
        tracing::debug!("peer stream with {} ended: {e:#}", peer.fmt_short());
    }
    // A connection another replaced hands that one the messages it had yet to send.
    let next = session.inner.links.lock().unwrap().get(&peer).filter(|link| link.conn.stable_id() != conn.stable_id()).map(|link| link.input.clone());
    if let Some(next) = next {
        let unsent = std::iter::from_fn(|| rx.try_recv().ok()).filter_map(|input| match input {
            Input::Send(frame @ Frame::Messages { .. }) => Some(frame),
            _ => None,
        });
        for frame in session.waiting.into_values().flatten().chain(unsent) {
            next.send(Input::Send(frame)).ok();
        }
    }
    conn.close(b"peer stream ended");
}

impl Session {
    async fn write(&mut self, frame: &Frame) -> Result<()> {
        frame::write(&mut self.send, frame).await
    }

    /// Writes a frame, but keeps messages of a group the peer has not shown in a `hello` yet, the latest `WAITING`,
    /// for a peer of revision 1 or later, which shows a group it joins.
    async fn send(&mut self, frame: Frame) -> Result<()> {
        if let Frame::Messages { group, .. } = &frame
            && self.groups.get(group).is_none_or(|state| state.theirs.is_none())
            && self.inner.groups.revision(&group.0, &self.peer) >= 1
        {
            let waiting = self.waiting.entry(group.clone()).or_default();
            if waiting.len() == WAITING {
                waiting.pop_front();
            }
            waiting.push_back(frame);
            return Ok(());
        }
        self.write(&frame).await
    }

    fn member(&self, group: &[u8]) -> bool {
        self.inner.groups.is_member(group, &self.peer)
    }

    /// The groups the peer is in a leaf of, whether or not this session serves it.
    fn leaves(&self) -> Vec<Vec<u8>> {
        self.inner.groups.groups().into_iter().filter(|g| self.inner.groups.in_leaf(g, &self.peer)).collect()
    }

    /// The groups both are in.
    fn shared(&self) -> Vec<Vec<u8>> {
        self.inner.groups.groups().into_iter().filter(|g| self.member(g)).collect()
    }

    /// The logs this session follows for groups both are in.
    fn logs(&self, groups: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut logs: Vec<Vec<u8>> = groups.iter().flat_map(|g| self.inner.groups.logs(g)).collect();
        logs.sort();
        logs.dedup();
        logs
    }

    async fn hello(&mut self) -> Result<()> {
        let shared = self.shared();
        self.send_hello(&shared).await
    }

    /// Sends our state of these groups, and the certificates of the members of every group the peer is in that it has
    /// not been shown: a peer this session does not serve still learns of the certificates it needs to serve this one.
    async fn send_hello(&mut self, groups: &[Vec<u8>]) -> Result<()> {
        let hellos: Vec<Hello> = groups
            .iter()
            .map(|g| {
                let theirs = self.groups.get(&Bytes(g.clone())).is_some_and(|state| state.theirs.is_some());
                Hello { anew: !theirs && self.inner.groups.revision(g, &self.peer) >= 1, ..self.inner.groups.hello(g) }
            })
            .collect();
        let heads: Vec<Head> = self.logs(groups).iter().map(|log| self.inner.groups.head(log)).collect();
        let certificates: Vec<Envelope> = self.inner.groups.certificates(&self.leaves()).into_iter().filter(|c| self.shown.insert(c.sig.clone())).collect();
        if hellos.is_empty() && certificates.is_empty() {
            return Ok(());
        }
        self.write(&Frame::Hello { groups: hellos, heads, certificates }).await
    }

    async fn frame(&mut self, frame: Frame) -> Result<()> {
        match frame {
            Frame::Hello { groups, heads, certificates } => {
                if !self.leaves().is_empty() {
                    for certificate in certificates {
                        self.inner.groups.certificate(certificate);
                    }
                }
                let shared = self.shared();
                let logs = self.logs(&shared);
                // A session ignores what a hello shows of a group it does not serve the peer yet or a log it does not
                // follow yet, so a hello that shows us a group we had none for, or a log we are behind on, or that asks
                // for it, gets ours in return, before any sync of it, whose first round needs it: the peer forwards and
                // syncs by it.
                let mut answer = false;
                for theirs in heads.into_iter().filter(|head| logs.contains(&head.log.0)) {
                    let log = theirs.log.clone();
                    if let Err(e) = self.judge(&log, &theirs) {
                        tracing::warn!("hello from {}: {e:#}", self.peer.fmt_short());
                        continue;
                    }
                    answer |= theirs.length > self.inner.groups.head(&log.0).length;
                    self.logs.entry(log.clone()).or_default().theirs = Some(theirs);
                    self.forward(&log).await?;
                }
                let groups: Vec<Hello> = groups.into_iter().filter(|hello| shared.contains(&hello.group.0)).collect();
                for hello in &groups {
                    let state = self.groups.entry(hello.group.clone()).or_default();
                    answer |= state.theirs.is_none() || hello.anew;
                    // The peer dropped its state of the group, and with it any round of ours it was in.
                    if hello.anew {
                        *state = Group::default();
                    }
                    state.theirs = Some(hello.clone());
                }
                if answer {
                    self.send_hello(&shared).await?;
                }
                for hello in &groups {
                    for frame in self.waiting.remove(&hello.group).unwrap_or_default() {
                        self.write(&frame).await?;
                    }
                }
                for hello in groups {
                    self.sync(&hello.group).await?;
                }
            }
            Frame::Entries { log, entries, head } => self.on_entries(log, entries, head).await?,
            Frame::Reconcile { group, msg } if self.member(&group.0) => self.on_reconcile(group, msg).await?,
            Frame::Messages { group, items, below } if self.member(&group.0) => {
                if !below.is_empty() {
                    let below = below.iter().filter_map(|b| Some((b.epoch, b.id.0.as_slice().try_into().ok()?))).collect();
                    self.inner.groups.below(&group.0, below);
                }
                let mut held = Vec::new();
                for item in items {
                    if self.inner.groups.receive(&group.0, &item.0) == Taken::Held {
                        held.push(Bytes::from(<[u8; 32]>::from(Sha256::digest(&item.0))));
                    }
                }
                if !held.is_empty() {
                    self.write(&Frame::Receipt { group, held }).await?;
                }
            }
            Frame::Receipt { group, held } => {
                let held = held.iter().filter_map(|id| <[u8; 32]>::try_from(&id.0[..]).ok()).collect();
                self.inner.events.send(Event::Receipt { group: group.0, peer: self.peer, held }).ok();
            }
            Frame::State { group, link } if self.member(&group.0) => self.inner.groups.state(&group.0, self.peer, link),
            Frame::Want { group, files } => {
                let mut have = Vec::new();
                if self.member(&group.0) {
                    let linked = self.inner.groups.files(&group.0);
                    for file in files {
                        let Ok(hash) = <[u8; 32]>::try_from(&file.0[..]) else { continue };
                        if linked.iter().any(|link| link.hash == hash) && self.inner.files.serve(&hash).await? {
                            have.push(file);
                        }
                    }
                }
                self.write(&Frame::Have { group, files: have }).await?;
            }
            Frame::Have { group, files } => self.on_have(group, files),
            Frame::Join { id, join } => {
                let (admit, peer, input) = (self.inner.admit.clone(), self.peer, self.input.clone());
                spawn(async move {
                    let frame = match admit.join(peer, join).await {
                        Answer::Ok(admitted) => Frame::Admitted { id, admitted },
                        Answer::Refused { refused } => Frame::Refused { id, refused },
                    };
                    input.send(Input::Send(frame)).ok();
                });
            }
            Frame::Admitted { id, admitted } => {
                if let Some(reply) = self.joins.remove(&id) {
                    reply.send(Answer::Ok(admitted)).ok();
                }
            }
            Frame::Refused { id, refused } => {
                if let Some(reply) = self.joins.remove(&id) {
                    reply.send(Answer::Refused { refused }).ok();
                }
            }
            _ => tracing::debug!("{} sent a frame for a group it is not in", self.peer.fmt_short()),
        }
        Ok(())
    }

    /// Checks a signed head of a log from the peer against our chain, now or, if it is longer, once our chain reaches
    /// it; reports a contradiction.
    fn judge(&mut self, log: &Bytes, theirs: &Head) -> Result<()> {
        ensure!(self.inner.groups.verify_head(&log.0, theirs), "a head the service did not sign");
        let ours = self.inner.groups.head(&log.0);
        let state = self.logs.entry(log.clone()).or_default();
        if theirs.length > ours.length && state.longer.as_ref().is_none_or(|longer| longer.length < theirs.length) {
            state.longer = Some(theirs.clone());
        }
        self.judge_longer(log)?;
        self.contradiction(log, &ours, theirs)
    }

    /// Judges the longest head the peer showed of a log, once our chain has reached it.
    fn judge_longer(&mut self, log: &Bytes) -> Result<()> {
        let ours = self.inner.groups.head(&log.0);
        let longer = self.logs.get_mut(log).and_then(|state| state.longer.take_if(|longer| longer.length <= ours.length));
        match longer {
            Some(longer) => self.contradiction(log, &ours, &longer),
            None => Ok(()),
        }
    }

    fn contradiction(&self, log: &Bytes, ours: &Head, theirs: &Head) -> Result<()> {
        if sync::contradicts(theirs, ours, |n| self.inner.groups.chain(&log.0, n)) {
            let event = Event::Contradiction { log: log.0.clone(), peer: self.peer, ours: ours.clone(), theirs: theirs.clone() };
            self.inner.events.send(event).ok();
            bail!("the service showed us different logs");
        }
        Ok(())
    }

    /// Sends the entries of a log the peer lacks, judged by the head it showed.
    async fn forward(&mut self, log: &Bytes) -> Result<()> {
        let Some(theirs) = self.logs.get(log).and_then(|state| state.theirs.clone()) else { return Ok(()) };
        let mine = self.inner.groups.head(&log.0);
        if theirs.length < mine.length {
            let entries = self.inner.groups.entries(&log.0, theirs.length);
            if !entries.is_empty() {
                self.write(&Frame::Entries { log: log.clone(), entries, head: mine }).await?;
            }
        }
        Ok(())
    }

    /// Starts syncing a group's messages once both hold the same log of it.
    async fn sync(&mut self, group: &Bytes) -> Result<()> {
        let mine = self.inner.groups.head(&group.0);
        let alike = self.logs.get(group).and_then(|state| state.theirs.as_ref()).is_some_and(|theirs| (theirs.length, &theirs.hash) == (mine.length, &mine.hash));
        let state = self.groups.entry(group.clone()).or_default();
        if !alike || state.theirs.is_none() || state.synced == Some(mine.length) {
            return Ok(());
        }
        state.synced = Some(mine.length);
        self.inner.events.send(Event::InStep { group: group.0.clone(), peer: self.peer }).ok();
        self.want(group).await?;
        if self.dialer {
            let state = self.groups.get_mut(group).unwrap();
            if state.busy {
                state.again = true;
            } else {
                state.busy = true;
                self.initiate(group).await?;
            }
        }
        Ok(())
    }

    /// Asks for the files the group links that we lack, within our limit.
    async fn want(&mut self, group: &Bytes) -> Result<()> {
        let mut files = Vec::new();
        for link in self.inner.groups.files(&group.0) {
            if link.size <= self.inner.config.file_limit && !self.inner.files.has(&link.hash).await? {
                files.push(Bytes::from(link.hash));
            }
        }
        if !files.is_empty() {
            self.wants.entry(group.clone()).or_default().push_back(None);
            self.write(&Frame::Want { group: group.clone(), files }).await?;
        }
        Ok(())
    }

    fn on_have(&mut self, group: Bytes, files: Vec<Bytes>) {
        let Some(reply) = self.wants.get_mut(&group).and_then(VecDeque::pop_front) else { return };
        let hashes: Vec<[u8; 32]> = files.iter().filter_map(|f| f.0[..].try_into().ok()).collect();
        match reply {
            Some(reply) => {
                reply.send(hashes).ok();
            }
            None => {
                let links = self.inner.groups.files(&group.0);
                for link in links.iter().filter(|link| hashes.contains(&link.hash)) {
                    self.inner.offer(link, self.peer);
                }
            }
        }
    }

    async fn on_entries(&mut self, log: Bytes, entries: Vec<Bytes>, head: Head) -> Result<()> {
        let shared = self.shared();
        if !self.logs(&shared).contains(&log.0) {
            tracing::debug!("{} sent entries of a log we share no group of", self.peer.fmt_short());
            return Ok(());
        }
        if let Err(e) = self.judge(&log, &head) {
            tracing::warn!("entries from {}: {e:#}", self.peer.fmt_short());
            return Ok(());
        }
        let mine = self.inner.groups.head(&log.0);
        let Some(start) = head.length.checked_sub(entries.len() as u64) else { return Ok(()) };
        if head.length <= mine.length || start > mine.length {
            return Ok(());
        }
        let Some(from) = self.inner.groups.chain(&log.0, start) else { return Ok(()) };
        if sync::extend(from, &entries)[..] != head.hash.0[..] {
            tracing::warn!("entries from {} do not end at their head", self.peer.fmt_short());
            return Ok(());
        }
        let new = entries[(mine.length - start) as usize..].to_vec();
        match self.inner.groups.apply(&log.0, new, head) {
            Ok(()) => {
                for group in shared.into_iter().filter(|g| self.inner.groups.logs(g).contains(&log.0)) {
                    self.inner.changed(&group);
                }
            }
            Err(e) => tracing::warn!("entries from {} not taken: {e:#}", self.peer.fmt_short()),
        }
        Ok(())
    }

    async fn changed(&mut self, group: Bytes) -> Result<()> {
        if !self.member(&group.0) {
            self.groups.remove(&group);
            return self.send_hello(&[]).await;
        }
        let logs = self.inner.groups.logs(&group.0);
        for log in &logs {
            if let Err(e) = self.judge_longer(&Bytes(log.clone())) {
                tracing::warn!("a head from {}: {e:#}", self.peer.fmt_short());
                return Ok(());
            }
        }
        for log in logs {
            self.forward(&Bytes(log)).await?;
        }
        self.send_hello(std::slice::from_ref(&group.0)).await?;
        self.sync(&group).await
    }

    /// Swaps heads again and syncs every group anew, whatever it has synced already.
    async fn resync(&mut self) -> Result<()> {
        self.shown.clear();
        for state in self.groups.values_mut() {
            if state.busy && state.stale {
                *state = Group { theirs: state.theirs.take(), ..Group::default() };
            }
            state.stale = state.busy;
            state.synced = None;
        }
        for group in self.inner.groups.groups() {
            if self.member(&group) {
                self.changed(Bytes(group)).await?;
            }
        }
        self.send_hello(&[]).await
    }

    fn storage(&self, group: &Bytes) -> Option<(NegentropyStorageVector, Items)> {
        let theirs = self.groups.get(group)?.theirs.as_ref()?;
        let items = self.inner.groups.items(&group.0, sync::lowest(&self.inner.groups.hello(&group.0), theirs));
        Some((sync::storage(&items), items.into_iter().enumerate().map(|(at, (epoch, id))| (id, (epoch, at))).collect()))
    }

    async fn initiate(&mut self, group: &Bytes) -> Result<()> {
        let Some((storage, items)) = self.storage(group) else { return Ok(()) };
        let mut negentropy = Negentropy::owned(storage, 0)?;
        let msg = Bytes(negentropy.initiate()?);
        self.groups.get_mut(group).unwrap().initiator = Some(Round { negentropy, items });
        self.write(&Frame::Reconcile { group: group.clone(), msg }).await
    }

    async fn on_reconcile(&mut self, group: Bytes, msg: Bytes) -> Result<()> {
        let Some(state) = self.groups.get_mut(&group) else { return Ok(()) };
        if msg.0.is_empty() {
            // The other side's round is over.
            state.responder = None;
            if !self.dialer {
                return self.initiate(&group).await;
            }
            let again = std::mem::take(&mut state.again);
            state.busy = again;
            self.inner.events.send(Event::Synced { group: group.0.clone(), peer: self.peer }).ok();
            if again {
                self.initiate(&group).await?;
            }
            return Ok(());
        }
        if let Some(round) = &mut state.initiator {
            let (mut have, mut need) = (Vec::new(), Vec::new());
            let next = round.negentropy.reconcile_with_ids(&msg.0, &mut have, &mut need)?;
            // In the order this session took them, which is about each sender's: MLS opens a sender's messages at most
            // 1000 out of order.
            let mut have: Vec<[u8; 32]> = have.iter().map(|id| id.to_bytes()).collect();
            have.sort_by_key(|id| round.items[id].1);
            let have: Vec<(u64, [u8; 32])> = have.into_iter().map(|id| (round.items[&id].0, id)).collect();
            if next.is_none() {
                state.initiator = None;
            }
            self.push(&group, have).await?;
            let msg = Bytes(next.unwrap_or_default());
            let done = msg.0.is_empty();
            self.write(&Frame::Reconcile { group: group.clone(), msg }).await?;
            if done && !self.dialer {
                self.inner.events.send(Event::Synced { group: group.0.clone(), peer: self.peer }).ok();
            }
            return Ok(());
        }
        if state.responder.is_none() {
            let Some((storage, _)) = self.storage(&group) else { return Ok(()) };
            self.groups.get_mut(&group).unwrap().responder = Some(Negentropy::owned(storage, 0)?);
        }
        let reply = self.groups.get_mut(&group).unwrap().responder.as_mut().unwrap().reconcile(&msg.0)?;
        self.write(&Frame::Reconcile { group, msg: Bytes(reply) }).await
    }

    /// Sends held messages the peer lacks; of those below its floor, only their epochs and ids.
    async fn push(&mut self, group: &Bytes, have: Vec<(u64, [u8; 32])>) -> Result<()> {
        let floor = self.groups[group].theirs.as_ref().map_or(0, |theirs| theirs.floor);
        let (have, below): (Vec<_>, Vec<_>) = have.into_iter().partition(|&(epoch, _)| epoch >= floor);
        let mut below: Vec<Below> = below.into_iter().map(|(epoch, id)| Below { epoch, id: Bytes::from(id) }).collect();
        let mut items = Vec::new();
        let mut size = 0;
        for (_, id) in have {
            let Some(message) = self.inner.groups.message(&group.0, &id) else { continue };
            size += message.len();
            items.push(Bytes(message));
            if size >= BATCH {
                let below = std::mem::take(&mut below);
                self.write(&Frame::Messages { group: group.clone(), items: std::mem::take(&mut items), below }).await?;
                size = 0;
            }
        }
        if !items.is_empty() || !below.is_empty() {
            self.write(&Frame::Messages { group: group.clone(), items, below }).await?;
        }
        Ok(())
    }
}
