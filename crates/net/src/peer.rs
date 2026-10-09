//! A `peer` stream: hello and head swap, commits, negentropy message sync, live messages, doc
//! catch-up, want and have, and join requests. Every group frame is served only to a member.
//!
//! Negentropy tells only its initiator what each side lacks, so a sync runs two rounds: the
//! dialer initiates and pushes what the acceptor lacks, then ends its round with an empty
//! `reconcile`; the acceptor then does the same the other way.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use anyhow::{Result, bail, ensure};
use iroh::{
    EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
};
use lmk_proto::{
    Answer, Bytes, frame,
    head::Head,
    peer::{Admitted, Frame, Hello, List, Refusal},
};
use sha2::{Digest, Sha256};
use n0_future::{task::spawn, time::sleep};
use negentropy::{Negentropy, NegentropyStorageVector};
use tokio::sync::{mpsc, oneshot};

use crate::{Event, Inner, Taken, sync};

/// Raw ciphertext bytes per `messages` frame, well under a frame's limit once in base64.
const BATCH: usize = 8 << 20;

/// Takes the answer to a `want`; `None` for wants sent on catching up, whose answers start downloads.
type HaveReply = Option<oneshot::Sender<Vec<[u8; 32]>>>;

pub(crate) enum Input {
    Frame(Frame),
    Closed,
    Send(Frame),
    Changed(Bytes),
    /// Time to sync every group again.
    Resync,
    Want { group: Bytes, files: Vec<[u8; 32]>, reply: HaveReply },
    Join { group: Bytes, key_package: Bytes, reply: oneshot::Sender<Answer<Admitted>> },
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
    joins: HashMap<Bytes, oneshot::Sender<Answer<Admitted>>>,
    /// The newest head of each device list either side has shown the other.
    lists: HashMap<Bytes, Head>,
}

#[derive(Default)]
struct Group {
    theirs: Option<Hello>,
    /// The longest head the peer showed beyond our log, judged once our log reaches it.
    longer: Option<Head>,
    /// The log length we last started a sync at.
    synced: Option<u64>,
    initiator: Option<Round>,
    responder: Option<Negentropy<'static, NegentropyStorageVector>>,
    /// The dialer's sync is under way, and whether another should follow it.
    busy: bool,
    again: bool,
}

struct Round {
    negentropy: Negentropy<'static, NegentropyStorageVector>,
    epochs: HashMap<[u8; 32], u64>,
}

/// Runs the connection's one peer stream; the connection closes with it.
pub(crate) async fn run(
    inner: Arc<Inner>,
    conn: Connection,
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
        while let Ok(frame) = frame::read(&mut recv).await {
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
        lists: HashMap::new(),
    };
    let result = async {
        session.hello().await?;
        while let Some(input) = rx.recv().await {
            match input {
                Input::Frame(frame) => session.frame(frame).await?,
                Input::Closed => break,
                Input::Send(frame) => session.write(&frame).await?,
                Input::Changed(group) => session.changed(group).await?,
                Input::Resync => session.resync().await?,
                Input::Want { group, files, reply } => {
                    session.wants.entry(group.clone()).or_default().push_back(reply);
                    let files = files.into_iter().map(Bytes::from).collect();
                    session.write(&Frame::Want { group, files }).await?;
                }
                Input::Join { group, key_package, reply } => {
                    session.joins.insert(group.clone(), reply);
                    session.write(&Frame::Join { group, key_package }).await?;
                }
            }
        }
        anyhow::Ok(())
    }
    .await;
    if let Err(e) = result {
        tracing::debug!("peer stream with {} ended: {e:#}", peer.fmt_short());
    }
    conn.close(0u32.into(), b"peer stream ended");
}

impl Session {
    async fn write(&mut self, frame: &Frame) -> Result<()> {
        frame::write(&mut self.send, frame).await
    }

    fn member(&self, group: &[u8]) -> bool {
        self.inner.groups.is_member(group, &self.peer)
    }

    async fn hello(&mut self) -> Result<()> {
        let shared: Vec<Vec<u8>> = self.inner.groups.groups().into_iter().filter(|g| self.member(g)).collect();
        let groups = shared.iter().map(|g| self.inner.groups.hello(g)).collect();
        let lists = self.unshown(&shared);
        self.write(&Frame::Hello { groups, lists }).await
    }

    /// The device lists of the identities in these groups whose newest head the peer has not seen.
    fn unshown(&mut self, groups: &[Vec<u8>]) -> Vec<List> {
        let lists = self.inner.groups.lists(groups);
        lists.into_iter().filter(|list| self.lists.insert(list.identity.clone(), list.head.clone()).as_ref() != Some(&list.head)).collect()
    }

    async fn frame(&mut self, frame: Frame) -> Result<()> {
        match frame {
            Frame::Hello { groups, lists } => {
                if !lists.is_empty() && self.inner.groups.groups().iter().any(|g| self.member(g)) {
                    for list in lists {
                        self.lists.insert(list.identity.clone(), list.head.clone());
                        self.inner.groups.list(self.peer, list);
                    }
                }
                for hello in groups {
                    if self.member(&hello.group.0) {
                        self.on_hello(hello).await?;
                    }
                }
            }
            Frame::Commits { group, entries, head } if self.member(&group.0) => self.on_commits(group, entries, head).await?,
            Frame::Reconcile { group, msg } if self.member(&group.0) => self.on_reconcile(group, msg).await?,
            Frame::Messages { group, items } if self.member(&group.0) => {
                let (mut held, mut refused) = (Vec::new(), Vec::new());
                for item in items {
                    let id = Bytes::from(<[u8; 32]>::from(Sha256::digest(&item.0)));
                    match self.inner.groups.receive(&group.0, &item.0) {
                        Taken::Held => held.push(id),
                        Taken::Refused(reason) => refused.push(Refusal { id, reason }),
                        Taken::Waiting => {}
                    }
                }
                if !held.is_empty() || !refused.is_empty() {
                    self.write(&Frame::Receipt { group, held, refused }).await?;
                }
            }
            Frame::Receipt { group, held, refused } => {
                let id = |id: &Bytes| <[u8; 32]>::try_from(&id.0[..]).ok();
                let held = held.iter().filter_map(id).collect();
                let refused = refused.iter().filter_map(|r| Some((id(&r.id)?, r.reason.clone()))).collect();
                self.inner.events.send(Event::Receipt { group: group.0, peer: self.peer, held, refused }).ok();
            }
            Frame::Doc { group, snapshot } if self.member(&group.0) => {
                if self.inner.groups.doc(&group.0).is_some_and(|ours| ours[..] != snapshot.0[..]) {
                    let sv = Bytes(self.inner.groups.doc_sv(&group.0));
                    self.write(&Frame::DocSv { group, sv }).await?;
                }
            }
            Frame::DocSv { group, sv } if self.member(&group.0) => match self.inner.groups.diff(&group.0, &sv.0) {
                Ok(diff) => self.write(&Frame::Messages { group, items: vec![Bytes(diff)] }).await?,
                Err(e) => tracing::warn!("no diff for {}: {e:#}", self.peer.fmt_short()),
            },
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
            Frame::Join { group, key_package } => {
                let (admit, peer, input) = (self.inner.admit.clone(), self.peer, self.input.clone());
                spawn(async move {
                    let frame = match admit.join(peer, group.0.clone(), key_package.0).await {
                        Answer::Ok(admitted) => Frame::Admitted { group, admitted },
                        Answer::Refused { refused } => Frame::Refused { group, refused },
                    };
                    input.send(Input::Send(frame)).ok();
                });
            }
            Frame::Admitted { group, admitted } => {
                if let Some(reply) = self.joins.remove(&group) {
                    reply.send(Answer::Ok(admitted)).ok();
                }
            }
            Frame::Refused { group, refused } => {
                if let Some(reply) = self.joins.remove(&group) {
                    reply.send(Answer::Refused { refused }).ok();
                }
            }
            _ => tracing::debug!("{} sent a frame for a group it is not in", self.peer.fmt_short()),
        }
        Ok(())
    }

    /// Checks a signed head from the peer against our chain, now or, if it is longer, once our chain reaches it;
    /// reports a contradiction.
    fn judge(&mut self, group: &Bytes, ours: &Head, theirs: &Head) -> Result<()> {
        ensure!(self.inner.groups.verify_head(&group.0, theirs), "a head the service did not sign");
        let state = self.groups.entry(group.clone()).or_default();
        if theirs.length > ours.length && state.longer.as_ref().is_none_or(|longer| longer.length < theirs.length) {
            state.longer = Some(theirs.clone());
        }
        self.judge_longer(group, ours)?;
        self.contradiction(group, ours, theirs)
    }

    /// Judges the longest head the peer showed, once our chain has reached it.
    fn judge_longer(&mut self, group: &Bytes, ours: &Head) -> Result<()> {
        let longer = self.groups.get_mut(group).and_then(|state| state.longer.take_if(|longer| longer.length <= ours.length));
        match longer {
            Some(longer) => self.contradiction(group, ours, &longer),
            None => Ok(()),
        }
    }

    fn contradiction(&self, group: &Bytes, ours: &Head, theirs: &Head) -> Result<()> {
        if sync::contradicts(theirs, ours, |n| self.inner.groups.chain(&group.0, n)) {
            self.inner
                .events
                .send(Event::Contradiction { group: group.0.clone(), peer: self.peer, ours: ours.clone(), theirs: theirs.clone() })
                .ok();
            bail!("the service showed us different logs");
        }
        Ok(())
    }

    async fn on_hello(&mut self, theirs: Hello) -> Result<()> {
        let group = theirs.group.clone();
        let mine = self.inner.groups.hello(&group.0);
        if let Err(e) = self.judge(&group, &mine.head, &theirs.head) {
            tracing::warn!("hello from {}: {e:#}", self.peer.fmt_short());
            return Ok(());
        }
        self.groups.entry(group.clone()).or_default().theirs = Some(theirs);
        self.catch_up(&group, &mine).await
    }

    /// Sends the entries the peer lacks, and starts syncing once both logs are alike.
    async fn catch_up(&mut self, group: &Bytes, mine: &Hello) -> Result<()> {
        let Some(theirs) = self.groups.get(group).and_then(|g| g.theirs.clone()) else { return Ok(()) };
        if theirs.head.length < mine.head.length {
            let entries = self.inner.groups.entries(&group.0, theirs.head.length);
            self.write(&Frame::Commits { group: group.clone(), entries, head: mine.head.clone() }).await?;
        }
        let state = self.groups.get_mut(group).unwrap();
        if (theirs.head.length, &theirs.head.hash) != (mine.head.length, &mine.head.hash) || state.synced == Some(mine.head.length)
        {
            return Ok(());
        }
        state.synced = Some(mine.head.length);
        if let Some(snapshot) = self.inner.groups.doc(&group.0) {
            self.write(&Frame::Doc { group: group.clone(), snapshot: snapshot.into() }).await?;
        }
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

    async fn on_commits(&mut self, group: Bytes, entries: Vec<Bytes>, head: Head) -> Result<()> {
        let mine = self.inner.groups.hello(&group.0).head;
        if let Err(e) = self.judge(&group, &mine, &head) {
            tracing::warn!("commits from {}: {e:#}", self.peer.fmt_short());
            return Ok(());
        }
        let Some(start) = head.length.checked_sub(entries.len() as u64) else { return Ok(()) };
        if head.length <= mine.length || start > mine.length {
            return Ok(());
        }
        let Some(from) = self.inner.groups.chain(&group.0, start) else { return Ok(()) };
        if sync::extend(from, &entries)[..] != head.hash.0[..] {
            tracing::warn!("commits from {} do not end at their head", self.peer.fmt_short());
            return Ok(());
        }
        let new = entries[(mine.length - start) as usize..].to_vec();
        match self.inner.groups.apply(&group.0, new, head) {
            Ok(()) => self.inner.changed(&group.0),
            Err(e) => tracing::warn!("commits from {} not applied: {e:#}", self.peer.fmt_short()),
        }
        Ok(())
    }

    async fn changed(&mut self, group: Bytes) -> Result<()> {
        if !self.member(&group.0) {
            self.groups.remove(&group);
            return Ok(());
        }
        let mine = self.inner.groups.hello(&group.0);
        if let Err(e) = self.judge_longer(&group, &mine.head) {
            tracing::warn!("a head from {}: {e:#}", self.peer.fmt_short());
            return Ok(());
        }
        let lists = self.unshown(std::slice::from_ref(&group.0));
        self.write(&Frame::Hello { groups: vec![mine.clone()], lists }).await?;
        self.catch_up(&group, &mine).await
    }

    /// Swaps heads again and syncs every group anew, whatever it has synced already.
    async fn resync(&mut self) -> Result<()> {
        for state in self.groups.values_mut() {
            state.synced = None;
        }
        for group in self.inner.groups.groups() {
            if self.member(&group) {
                self.changed(Bytes(group)).await?;
            }
        }
        Ok(())
    }

    fn storage(&self, group: &Bytes) -> Option<(NegentropyStorageVector, HashMap<[u8; 32], u64>)> {
        let theirs = self.groups.get(group)?.theirs.as_ref()?;
        let items = self.inner.groups.items(&group.0, sync::lowest(&self.inner.groups.hello(&group.0), theirs));
        Some((sync::storage(&items), items.into_iter().map(|(epoch, id)| (id, epoch)).collect()))
    }

    async fn initiate(&mut self, group: &Bytes) -> Result<()> {
        let Some((storage, epochs)) = self.storage(group) else { return Ok(()) };
        let mut negentropy = Negentropy::owned(storage, 0)?;
        let msg = Bytes(negentropy.initiate()?);
        self.groups.get_mut(group).unwrap().initiator = Some(Round { negentropy, epochs });
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
            let have: Vec<(u64, [u8; 32])> = have.iter().map(|id| (round.epochs[&id.to_bytes()], id.to_bytes())).collect();
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

    /// Sends held messages the peer lacks, none below its floor.
    async fn push(&mut self, group: &Bytes, have: Vec<(u64, [u8; 32])>) -> Result<()> {
        let floor = self.groups[group].theirs.as_ref().map_or(0, |theirs| theirs.floor);
        let mut items = Vec::new();
        let mut size = 0;
        for (_, id) in have.into_iter().filter(|&(epoch, _)| epoch >= floor) {
            let Some(message) = self.inner.groups.message(&group.0, &id) else { continue };
            size += message.len();
            items.push(Bytes(message));
            if size >= BATCH {
                self.write(&Frame::Messages { group: group.clone(), items: std::mem::take(&mut items) }).await?;
                size = 0;
            }
        }
        if !items.is_empty() {
            self.write(&Frame::Messages { group: group.clone(), items }).await?;
        }
        Ok(())
    }
}
