use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use iroh::EndpointId;
use lmk_core::provider::Provider;
use lmk_membership::{Frontier, Proof};
use lmk_proto::{Bytes, epoch::Anchor, head::{self, Head}, peer::Frame};
use n0_future::boxed::BoxFuture;
use sha2::{Digest, Sha256};

use crate::{Inner, Out, State, Work, get, now, put};
use crate::archive::{Batch, RawPage};
use crate::logs::{AUDIT_LIMIT, DIGESTS, EVIDENCE_LIMIT, Log, Of, RAW_LIMIT, Usage};

const TEMP_LIMIT: u64 = 256 << 20;
const SPECULATIVE_LIMIT: u64 = 128 << 20;
const SETUP_LIFETIME: u64 = 60_000;
const MIN_RATE: u64 = 32 << 10;
const AUDIT_PERIOD: u64 = 5_000;

pub trait ProofTemp: Send + Sync {
    fn write(&self, target: Batch, after: u64, bytes: Vec<u8>) -> BoxFuture<Result<()>>;
    fn read(&self, target: Batch, after: u64) -> BoxFuture<Result<Vec<u8>>>;
    fn remove(&self, target: Batch) -> BoxFuture<Result<()>>;
    fn close(&self) -> BoxFuture<Result<()>>;
}

#[derive(Clone)]
struct Ask {
    peer: EndpointId,
    group: Bytes,
    anchor: Anchor,
    previous: bool,
    foreground: bool,
    trusted: bool,
    steps: u32,
    not_before: u64,
}

struct Candidate {
    proof: Proof,
    after: u64,
}

enum Stage {
    Describe,
    Offered,
    Digests(Candidate),
    Raw(u64),
    Busy,
    Cleaning,
}

struct Ticket {
    ask: Ask,
    target: Option<Head>,
    other: Option<Head>,
    cut: Option<u64>,
    next: Option<Ask>,
    token: Batch,
    stage: Stage,
    deadline: u64,
    requested: u64,
    published: bool,
    temporary: u64,
    retention: u64,
    cancelled: bool,
}

#[derive(Default)]
pub(crate) struct Jobs {
    live: HashMap<EndpointId, Ticket>,
    pending: VecDeque<Ask>,
    ready: VecDeque<EndpointId>,
    audits: HashMap<(EndpointId, Vec<u8>), (u64, u64)>,
}

impl<P: Provider> State<P> {
    pub(crate) fn associated(&self, gid: &[u8], anchor: &Anchor) -> bool {
        self.logs.get(anchor.log_ref.as_slice()).is_some_and(|log| matches!(&log.of, Of::Group { group, anchor: ours } if group.0 == gid && ours == anchor))
    }

    fn physical(&self, gid: &[u8], anchor: &Anchor) -> bool {
        self.logs.get(anchor.log_ref.as_slice()).is_some_and(|log| matches!(&log.of, Of::Group { group, anchor: ours }
            if group.0 == gid && (ours.service, ours.log_ref, ours.epoch) == (anchor.service, anchor.log_ref, anchor.epoch)))
    }

    pub(crate) fn conflicting(&self, gid: &[u8]) -> bool {
        self.logs.values().any(|log| log.conflict.is_some() && matches!(&log.of, Of::Group { group, .. } if group.0 == gid))
    }

    pub(crate) fn compatible(&self, gid: &[u8], peer: &EndpointId) -> bool {
        !self.conflicting(gid) && self.peers.anchor(peer.as_bytes(), &Bytes(gid.to_vec())).is_some_and(|anchor| self.associated(gid, anchor))
    }

    pub(crate) fn raw_reader(&self, gid: &[u8], anchor: &Anchor, peer: &EndpointId) -> bool {
        self.associated(gid, anchor) && self.log(&anchor.log_ref).is_ok_and(|log| log.raw && log.readers.iter().any(|key| key.0 == peer.as_bytes()))
    }

    pub(crate) fn expire_raw(&mut self, gid: &[u8]) -> Result<()> {
        let floor = if self.groups.contains_key(gid) { self.admission_floor(gid)? } else { None };
        let sources: Vec<_> = self.logs.iter().filter_map(|(id, log)| {
            let Of::Group { group, anchor } = &log.of else { return None };
            (group.0 == gid && log.raw && log.raw_until.is_some_and(|until| until <= now())
                && floor.is_none_or(|floor| anchor.epoch < floor)).then(|| id.clone())
        }).collect();
        let mut usage: Usage = get(&self.provider, b"node/archive-usage")?.unwrap_or_default();
        for id in sources {
            let log = self.logs.get_mut(&id).unwrap();
            usage.raw -= log.entries.take().map_or(0, |r| r.bytes);
            log.logged = 0;
            log.raw = false;
            log.readers.clear();
            let pins = log.pins(&[1]);
            self.save_log(&id)?;
            self.out.push(Out::ArchivePins(pins));
        }
        put(&self.provider, b"node/archive-usage", &usage)
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    fn queue_history(&self, ask: Ask) {
        let mut jobs = self.proofs.lock().unwrap();
        if jobs.pending.len() >= 512 || jobs.pending.iter().any(|a| a.peer == ask.peer && a.group == ask.group && a.anchor == ask.anchor && a.previous == ask.previous)
            || jobs.live.get(&ask.peer).is_some_and(|t| t.ask.group == ask.group && t.ask.anchor == ask.anchor && t.ask.previous == ask.previous) { return; }
        jobs.pending.push_back(ask);
        self.proof_wake.notify_one();
    }

    pub(crate) fn request_history(&self, st: &mut State<P>, peer: EndpointId, summary: &lmk_proto::peer::Summary) -> Result<()> {
        let gid = &summary.group.0;
        if st.in_leaf(gid, &peer).is_none() || st.conflicting(gid) { return Ok(()); }
        let log = st.active(gid)?;
        if summary.anchor.epoch <= log.anchor()?.epoch && summary.head.as_ref().is_none_or(|h| h.log_ref != log.log_ref || h.length <= log.logged) { return Ok(()); }
        if log.cut.is_some() { return Ok(()); }
        self.queue_history(Ask { peer, group: Bytes(gid.to_vec()), anchor: log.anchor()?.clone(), previous: false, foreground: true, trusted: true, steps: 0, not_before: 0 });
        Ok(())
    }

    pub(crate) fn audit_history(&self, st: &State<P>, peer: EndpointId, gid: &[u8], foreign: Option<Anchor>) -> Result<()> {
        if st.in_leaf(gid, &peer).is_none() || st.conflicting(gid) { return Ok(()); }
        let mut jobs = self.proofs.lock().unwrap();
        let cursor = jobs.audits.entry((peer, gid.to_vec())).or_default();
        if cursor.1 + AUDIT_PERIOD > now() { return Ok(()); }
        cursor.1 = now();
        let anchor = if let Some(anchor) = foreign { anchor } else {
            let mut sources: Vec<_> = st.logs.values().filter_map(|log| match &log.of {
                Of::Group { group, anchor } if group.0 == gid && log.closed.is_some() => Some(anchor.clone()),
                _ => None,
            }).collect();
            sources.sort_by_key(|anchor| anchor.epoch);
            if sources.is_empty() { return Ok(()); }
            let anchor = sources.iter().find(|a| a.epoch >= cursor.0).unwrap_or(&sources[0]).clone();
            cursor.0 = anchor.epoch + 1;
            anchor
        };
        let previous = !st.physical(gid, &anchor);
        let trusted = st.associated(gid, &anchor);
        drop(jobs);
        self.queue_history(Ask { peer, group: Bytes(gid.to_vec()), anchor, previous, foreground: false, trusted, steps: 0, not_before: 0 });
        Ok(())
    }

    pub(crate) fn retire_history(&self, id: &[u8]) {
        let mut jobs = self.proofs.lock().unwrap();
        jobs.pending.retain(|ask| !ask.foreground || ask.anchor.log_ref != id);
        for ticket in jobs.live.values_mut().filter(|t| t.ask.foreground && t.ask.anchor.log_ref == id) { ticket.cancelled = true; }
        self.proof_wake.notify_one();
    }

    pub(crate) fn disconnected_history(&self, peer: EndpointId) {
        let mut jobs = self.proofs.lock().unwrap();
        jobs.pending.retain(|ask| ask.peer != peer);
        if let Some(ticket) = jobs.live.get_mut(&peer) { ticket.cancelled = true; }
        self.proof_wake.notify_one();
    }

    pub(crate) async fn history_scheduler(self: Arc<Self>) {
        loop {
            self.proof_wake.notified().await;
            let clean: Vec<_> = {
                let mut jobs = self.proofs.lock().unwrap();
                let foreground: std::collections::HashSet<_> = jobs.pending.iter().filter(|ask| ask.foreground).map(|ask| ask.peer).collect();
                let foreground_waiting = jobs.live.len() >= 8 && !foreground.is_empty();
                for (peer, ticket) in &mut jobs.live {
                    ticket.cancelled |= now() >= ticket.deadline || !ticket.ask.foreground && (foreground_waiting || foreground.contains(peer));
                }
                jobs.live.iter_mut().filter_map(|(peer, ticket)| {
                    if ticket.cancelled && !matches!(ticket.stage, Stage::Busy | Stage::Cleaning) {
                        ticket.stage = Stage::Cleaning;
                        Some((*peer, ticket.token, ticket.published))
                    } else { None }
                }).collect()
            };
            for (peer, token, published) in clean {
                let inner = self.clone();
                self.spawn(async move {
                    if let Err(error) = inner.finish_history(peer, token, published).await { tracing::debug!("proof cleanup: {error:#}"); }
                });
            }
            let mut st = self.lock();
            let mut jobs = self.proofs.lock().unwrap();
            let waiting = jobs.pending.len();
            for _ in 0..waiting {
                let ask = jobs.pending.pop_front().unwrap();
                if ask.not_before > now() || jobs.live.contains_key(&ask.peer) || jobs.live.len() >= 8 || !ask.foreground && jobs.live.values().filter(|t| !t.ask.foreground).count() >= 4 {
                    jobs.pending.push_back(ask);
                    continue;
                }
                if !st.groups.contains_key(&ask.group.0) || st.conflicting(&ask.group.0) { continue; }
                let peer = ask.peer;
                jobs.live.insert(peer, Ticket { ask, target: None, other: None, cut: None, next: None, token: lmk_core::random(), stage: Stage::Describe,
                    deadline: now() + SETUP_LIFETIME, requested: 0, published: false, temporary: 0, retention: 0, cancelled: false });
                jobs.ready.push_back(peer);
            }
            let offered: Vec<_> = jobs.live.iter().filter_map(|(peer, ticket)| (!ticket.cancelled && matches!(ticket.stage, Stage::Offered)).then_some(*peer)).collect();
            for peer in offered {
                let ticket = &jobs.live[&peer];
                let target = ticket.target.as_ref().unwrap().clone();
                let reserve = target.length * 32 + target.length.div_ceil(DIGESTS) * 91 + 8192;
                let temporary = target.length * 64 + target.length.div_ceil(DIGESTS) * 16_384 + 8192;
                let usage: Usage = match get(&st.provider, b"node/archive-usage") { Ok(Some(usage)) => usage, Ok(None) => Usage::default(), Err(error) => { self.stop(&mut st, &error); return; } };
                let retained = jobs.live.values().map(|t| t.retention).sum::<u64>();
                let total = jobs.live.values().map(|t| t.temporary).sum::<u64>();
                let speculative = jobs.live.values().filter(|t| !t.ask.foreground).map(|t| t.temporary).sum::<u64>();
                let foreground = ticket.ask.foreground;
                let fits = total + temporary <= TEMP_LIMIT && usage.evidence + retained + reserve <= if foreground { EVIDENCE_LIMIT } else { AUDIT_LIMIT }
                    && (foreground || speculative + temporary <= SPECULATIVE_LIMIT);
                if !fits {
                    if foreground { for ticket in jobs.live.values_mut().filter(|t| !t.ask.foreground) { ticket.cancelled = true; } }
                    else { jobs.live.get_mut(&peer).unwrap().cancelled = true; }
                    continue;
                }
                let ticket = jobs.live.get_mut(&peer).unwrap();
                let proof = Frontier::empty(ticket.ask.anchor.service, ticket.ask.anchor.log_ref).proof(target.clone()).expect("offered head was checked");
                ticket.stage = Stage::Digests(Candidate { proof, after: 0 });
                ticket.temporary = temporary;
                ticket.retention = reserve;
                ticket.deadline = now() + SETUP_LIFETIME + target.length * 32 * 1000 / MIN_RATE;
                jobs.ready.push_back(peer);
            }
            let retries: Vec<_> = jobs.live.iter().filter_map(|(peer, ticket)|
                (!ticket.cancelled && now() >= ticket.requested + 2000 && matches!(ticket.stage, Stage::Describe | Stage::Digests(_) | Stage::Raw(_))).then_some(*peer)).collect();
            for peer in retries { if !jobs.ready.contains(&peer) { jobs.ready.push_back(peer); } }
            while let Some(peer) = jobs.ready.pop_front() {
                let Some(ticket) = jobs.live.get_mut(&peer).filter(|t| !t.cancelled) else { continue };
                let ask = &ticket.ask;
                let frame = match &ticket.stage {
                    Stage::Describe => Frame::HistoryRequest { group: ask.group.clone(), anchor: ask.anchor.clone(), previous: ask.previous },
                    Stage::Digests(c) => Frame::SegmentRequest { group: ask.group.clone(), anchor: ask.anchor.clone(), target: ticket.target.clone().unwrap(), after: c.after, raw: false },
                    Stage::Raw(after) => Frame::SegmentRequest { group: ask.group.clone(), anchor: ask.anchor.clone(), target: ticket.target.clone().unwrap(), after: *after, raw: true },
                    _ => continue,
                };
                ticket.requested = now();
                st.frame_out(peer, frame);
            }
        }
    }

    async fn finish_history(&self, peer: EndpointId, token: Batch, published: bool) -> Result<()> {
        {
            let mut jobs = self.proofs.lock().unwrap();
            let ticket = jobs.live.get_mut(&peer).context("missing proof reservation")?;
            ticket.stage = Stage::Cleaning;
            ticket.published |= published;
        }
        let cleaned = async {
            self.proof_temp.remove(token).await?;
            if !self.proofs.lock().unwrap().live[&peer].published { self.archive.0.discard(token).await?; }
            anyhow::Ok(())
        }.await;
        if let Err(error) = cleaned {
            let mut jobs = self.proofs.lock().unwrap();
            let ticket = jobs.live.get_mut(&peer).unwrap();
            ticket.stage = Stage::Offered;
            ticket.cancelled = true;
            return Err(error);
        }
        let next = {
            let mut jobs = self.proofs.lock().unwrap();
            let ticket = jobs.live.remove(&peer).context("missing proof reservation")?;
            jobs.ready.retain(|ready| *ready != peer);
            ensure!(ticket.token == token, "proof ownership changed");
            if ticket.cancelled { None } else { ticket.next }
        };
        if let Some(next) = next { self.queue_history(next); }
        self.proof_wake.notify_one();
        Ok(())
    }

    pub(crate) async fn history(self: &Arc<Self>, peer: EndpointId, frame: Frame, receipt: lmk_net::Receipt) -> Result<()> {
        let group = match &frame {
            Frame::HistoryRequest { group, .. } | Frame::History { group, .. } | Frame::SegmentRequest { group, .. } | Frame::Segment { group, .. } => group,
            _ => unreachable!(),
        };
        if self.lock().in_leaf(&group.0, &peer).is_none() { return Ok(()); }
        match frame {
            Frame::HistoryRequest { group, anchor, previous } => {
                let mut st = self.lock();
                if !st.associated(&group.0, &anchor) { return Ok(()); }
                let log = if previous {
                    st.logs.values().find(|log| log.transition.as_ref().is_some_and(|w| w.successor().is_ok_and(|next| next == anchor)))
                } else { st.logs.get(anchor.log_ref.as_slice()) };
                let transition = log.and_then(|log| log.transition.clone());
                let head = log.and_then(|log| log.head.clone());
                let other = log.and_then(|log| log.conflict.as_ref().map(|(_, head)| head.clone()));
                let cut = log.and_then(|log| log.cut);
                st.frame_out(peer, Frame::History { group, anchor, previous, transition, head, other, cut });
            }
            Frame::History { group, anchor, previous, transition, head, other, cut } => {
                let (token, mut ask) = {
                    let mut jobs = self.proofs.lock().unwrap();
                    let Some(ticket) = jobs.live.get_mut(&peer) else { return Ok(()) };
                    if !matches!(ticket.stage, Stage::Describe) || ticket.ask.group != group || ticket.ask.anchor != anchor || ticket.ask.previous != previous { return Ok(()); }
                    ticket.stage = Stage::Busy;
                    (ticket.token, ticket.ask.clone())
                };
                let accepted = async {
                    let (physical, next) = {
                    let mut st = self.lock();
                    let mut next = None;
                    if previous {
                        let Some(witness) = transition else { return Ok(false) };
                        ensure!(witness.group.as_slice() == group.0 && witness.successor()? == anchor, "history body is not hash linked to requested root");
                        let source = witness.source.clone();
                        if source.epoch == 0 { ensure!(source == Anchor::genesis(&witness.group, source.service, source.log_ref), "invalid history genesis"); }
                        if ask.trusted && !st.physical(&group.0, &source) {
                            let usage: Usage = get(&st.provider, b"node/archive-usage")?.unwrap_or_default();
                            ensure!(usage.evidence + 4096 <= AUDIT_LIMIT, "ancestor metadata audit deferred");
                            let service = lmk_proto::group::Service::Serve { key: Bytes(source.service.to_vec()), relay: String::new(), addrs: Vec::new(), rest: Default::default() };
                            let mut log = Log::new(Of::Group { group: group.clone(), anchor: source.clone() }, service, source.log_ref, Vec::new());
                            log.raw = false;
                            log.cut = Some(witness.cut);
                            log.closed = Some(now());
                            log.transition = Some(witness);
                            self.critical(&mut st, |st| st.add_log(&source.log_ref, log))?;
                        }
                        if source.epoch > 0 {
                            next = Some(Ask { anchor: source.clone(), previous: true, steps: (ask.steps + 1) % 64,
                                not_before: if ask.steps == 63 { now() + AUDIT_PERIOD } else { 0 }, ..ask.clone() });
                        }
                        ask.anchor = source;
                        ask.previous = false;
                    } else if !ask.foreground && anchor.epoch > 0
                        && !st.logs.values().any(|log| log.transition.as_ref().is_some_and(|w| w.successor().is_ok_and(|next| next == anchor))) {
                        next = Some(Ask { previous: true, trusted: st.associated(&group.0, &anchor), ..ask.clone() });
                    }
                    (st.physical(&group.0, &ask.anchor), next)
                    };
                    {
                        let mut jobs = self.proofs.lock().unwrap();
                        let ticket = jobs.live.get_mut(&peer).unwrap();
                        ticket.ask = ask.clone();
                        ticket.next = next;
                    }
                    if !physical { return Ok(false); }
                    let Some(mut target) = head else { return Ok(false) };
                    let mut other = other;
                    if other.as_ref().is_some_and(|h| h.length > target.length) { std::mem::swap(&mut target, other.as_mut().unwrap()); }
                    let empty = Frontier::empty(ask.anchor.service, ask.anchor.log_ref);
                    empty.proof(target.clone())?;
                    ensure!(target.length <= lmk_proto::membership::MAX_LOG_LENGTH, "unsupported proof length");
                    if let Some(other) = &other {
                        empty.proof(other.clone())?;
                        if other.length == target.length && other.hash != target.hash {
                            self.contradicted(&mut self.lock(), &ask.anchor.log_ref, other.clone(), target)?;
                            return Ok(false);
                        }
                    }
                    let lane = self.archiving(&ask.anchor.log_ref);
                    let _lane = lane.lock().await;
                    let log = self.lock().log(&ask.anchor.log_ref)?.clone();
                    if log.conflict.is_some() { return Ok(false); }
                    if target.length <= log.length() {
                        let hash = if target.length == 0 { *empty.hash() } else { self.archive.hash_at(log.digests.context("head without evidence")?, target.length).await? };
                        if target.hash != hash {
                            self.contradicted(&mut self.lock(), &ask.anchor.log_ref, log.head.unwrap(), target)?;
                            return Ok(false);
                        }
                    }
                    let mut jobs = self.proofs.lock().unwrap();
                    let ticket = jobs.live.get_mut(&peer).unwrap();
                    ticket.target = Some(target.clone());
                    ticket.other = other;
                    ticket.cut = cut;
                    if target.length > log.length() {
                        ticket.stage = Stage::Offered;
                    } else if ticket.ask.foreground && log.cut.is_none() && log.logged < target.length {
                        ticket.stage = Stage::Raw(log.logged);
                        ticket.deadline = now() + SETUP_LIFETIME + lmk_proto::membership::MAX_LOG_BYTES * 1000 / MIN_RATE;
                        jobs.ready.push_back(peer);
                    } else { return Ok(false); }
                    self.proof_wake.notify_one();
                    Ok(true)
                }.await;
                if !matches!(accepted, Ok(true)) { self.finish_history(peer, token, false).await?; }
                accepted?;
            }
            Frame::SegmentRequest { group, anchor, target, after, raw } => {
                Frontier::empty(anchor.service, anchor.log_ref).proof(target.clone())?;
                {
                    let st = self.lock();
                    if !st.associated(&group.0, &anchor) || raw && !st.raw_reader(&group.0, &anchor, &peer) { return Ok(()); }
                }
                let _serving = self.history_serving.acquire().await?;
                let lane = self.archiving(&anchor.log_ref);
                let _lane = lane.lock().await;
                let log = {
                    let st = self.lock();
                    if !st.associated(&group.0, &anchor) || raw && !st.raw_reader(&group.0, &anchor, &peer) { return Ok(()); }
                    st.log(&anchor.log_ref)?.clone()
                };
                Frontier::empty(anchor.service, anchor.log_ref).proof(target.clone())?;
                let root = if log.conflict.as_ref().is_some_and(|(_, h)| (h.length, h.hash) == (target.length, target.hash)) { log.foreign }
                    else if log.head.as_ref().is_some_and(|h| h.length >= target.length) { log.digests } else { None };
                let root = root.context("requested cover is not retained")?;
                ensure!(target.length <= root.end && after < target.length && self.archive.hash_at(root, target.length).await? == target.hash, "requested cover differs from retained path");
                let end = if raw { log.logged.min(log.cut.unwrap_or(u64::MAX)).min(target.length) } else { target.length };
                ensure!(after < end, "raw prefix ends before request");
                let mut entries = Vec::new();
                let mut bytes = 0;
                if raw {
                    let root = log.entries.context("raw prefix expired")?;
                    let page = self.archive.raw(root, after + 1).await?;
                    for entry in page.entries.into_iter().skip((after - page.after) as usize) {
                        if bytes + entry.0.len() > 1 << 20 || after + entries.len() as u64 == end || entries.len() == DIGESTS as usize { break; }
                        bytes += entry.0.len();
                        entries.push(entry);
                    }
                }
                let count = if raw { entries.len() } else { (end - after).min(DIGESTS) as usize };
                let page = self.archive.digests(root, after, count).await?;
                let digests = Bytes(page.values.into_iter().flatten().collect());
                self.lock().frame_out(peer, Frame::Segment { group, anchor, target, after, digests, entries });
            }
            Frame::Segment { .. } => self.segment(peer, frame, receipt).await?,
            _ => unreachable!(),
        }
        Ok(())
    }

    async fn segment(self: &Arc<Self>, peer: EndpointId, frame: Frame, receipt: lmk_net::Receipt) -> Result<()> {
        let Frame::Segment { group, anchor, target, after, digests, entries } = frame else { unreachable!() };
        let (token, stage, deadline) = {
            let mut jobs = self.proofs.lock().unwrap();
            let Some(ticket) = jobs.live.get_mut(&peer) else { return Ok(()) };
            let expected = match &ticket.stage { Stage::Digests(c) => c.after, Stage::Raw(after) => *after, _ => return Ok(()) };
            if ticket.cancelled || ticket.ask.group != group || ticket.ask.anchor != anchor || ticket.target.as_ref() != Some(&target) || expected != after { return Ok(()); }
            (ticket.token, std::mem::replace(&mut ticket.stage, Stage::Busy), ticket.deadline)
        };
        let mut receipt = Some(receipt);
        let mut published = false;
        let received = async {
            ensure!(now() < deadline && !digests.0.is_empty() && digests.0.len() % 32 == 0 && digests.0.len() <= DIGESTS as usize * 32, "invalid digest page");
            match stage {
                Stage::Digests(mut candidate) => {
                    ensure!(entries.is_empty() && digests.0.len() as u64 / 32 == (target.length - after).min(DIGESTS), "proof page is not contiguous/full");
                    let values: Vec<[u8; 32]> = digests.0.chunks_exact(32).map(|d| d.try_into().unwrap()).collect();
                    candidate.proof.push(&values)?;
                    self.proof_temp.write(token, after, digests.0).await?;
                    candidate.after += values.len() as u64;
                    drop(values);
                    drop(receipt.take());
                    if candidate.after < target.length {
                        let mut jobs = self.proofs.lock().unwrap();
                        jobs.live.get_mut(&peer).unwrap().stage = Stage::Digests(candidate);
                        jobs.ready.push_back(peer);
                        self.proof_wake.notify_one();
                        return Ok(false);
                    }
                    candidate.proof.finish()?;
                    let lane = self.archiving(&anchor.log_ref);
                    let _lane = lane.lock().await;
                    let log = self.lock().log(&anchor.log_ref)?.clone();
                    if log.conflict.is_some() { return Ok(true); }
                    if target.length <= log.length() {
                        let hash = self.archive.hash_at(log.digests.context("missing digest root")?, target.length).await?;
                        if hash != target.hash { self.contradicted(&mut self.lock(), &anchor.log_ref, log.head.unwrap(), target.clone())?; }
                        return Ok(true);
                    }
                    let against = log.head.clone().or_else(|| self.proofs.lock().unwrap().live[&peer].other.clone());
                    let mut at_short = head::start(&anchor.service, &anchor.log_ref);
                    if let Some(short) = &against {
                        for cursor in (0..short.length).step_by(DIGESTS as usize) {
                            let bytes = self.proof_temp.read(token, cursor).await?;
                            for digest in bytes.chunks_exact(32).take((short.length - cursor).min(DIGESTS) as usize) { at_short = head::next_digest(&at_short, digest.try_into()?); }
                        }
                    }
                    let conflict = against.as_ref().is_some_and(|head| head.hash != at_short);
                    let mut root = if conflict { None } else { log.digests };
                    let skip = root.map_or(0, |r| r.end);
                    let mut hash = head::start(&anchor.service, &anchor.log_ref);
                    for cursor in (0..target.length).step_by(DIGESTS as usize) {
                        ensure!(!self.proofs.lock().unwrap().live[&peer].cancelled && now() < deadline, "proof promotion cancelled");
                        let bytes = self.proof_temp.read(token, cursor).await?;
                        let count = (target.length - cursor).min(DIGESTS) as usize;
                        ensure!(bytes.len() == count * 32, "scratch chunk changed");
                        let values: Vec<[u8; 32]> = bytes.chunks_exact(32).map(|d| d.try_into().unwrap()).collect();
                        let start = skip.saturating_sub(cursor).min(count as u64) as usize;
                        for digest in &values[..start] { hash = head::next_digest(&hash, digest); }
                        if start < count { root = Some(self.archive.append_digests(token, root, cursor + start as u64, hash, &values[start..]).await?); }
                        for digest in &values[start..] { hash = head::next_digest(&hash, digest); }
                    }
                    ensure!(hash == target.hash, "scratch changed after proof verification");
                    let root = root.context("empty proof target")?;
                    ensure!(!self.proofs.lock().unwrap().live[&peer].cancelled, "proof promotion cancelled");
                    let pins = {
                        let mut st = self.lock();
                        self.critical(&mut st, |st| {
                            let mut usage: Usage = get(&st.provider, b"node/archive-usage")?.unwrap_or_default();
                            usage.evidence += root.bytes - if conflict { 0 } else { log.digests.map_or(0, |r| r.bytes) };
                            ensure!(usage.evidence <= EVIDENCE_LIMIT, "required evidence capacity exhausted");
                            put(&st.provider, b"node/archive-usage", &usage)?;
                            let saved = st.logs.get_mut(anchor.log_ref.as_slice()).unwrap();
                            if conflict { saved.foreign = Some(root); } else { saved.digests = Some(root); saved.head = Some(target.clone()); }
                            let pins = saved.pins(&[if conflict { 2 } else { 0 }]);
                            st.save_log(&anchor.log_ref)?;
                            if conflict { self.contradicted(st, &anchor.log_ref, against.unwrap(), target.clone())?; }
                            Ok(pins)
                        })?
                    };
                    published = true;
                    self.durable().await?;
                    self.archive.0.publish(token, pins).await?;
                    if conflict { return Ok(true); }
                    self.proof_temp.remove(token).await?;
                    let mut jobs = self.proofs.lock().unwrap();
                    let ticket = jobs.live.get_mut(&peer).unwrap();
                    ticket.temporary = 0;
                    ticket.retention = 0;
                    if !ticket.ask.foreground || log.cut.is_some() || log.closed.is_some() { return Ok(true); }
                    ticket.stage = Stage::Raw(log.logged);
                    ticket.deadline = now() + SETUP_LIFETIME + lmk_proto::membership::MAX_LOG_BYTES * 1000 / MIN_RATE;
                    jobs.ready.push_back(peer);
                    self.proof_wake.notify_one();
                    Ok(false)
                }
                Stage::Raw(_) => {
                    ensure!(!entries.is_empty() && entries.len() * 32 == digests.0.len() && entries.iter().map(|entry| entry.0.len()).sum::<usize>() <= 1 << 20, "raw page size");
                    drop(digests);
                    let lane = self.archiving(&anchor.log_ref);
                    let _lane = lane.lock().await;
                    let log = self.lock().log(&anchor.log_ref)?.clone();
                    if log.conflict.is_some() || log.cut.is_some() || log.closed.is_some() || log.logged != after { return Ok(true); }
                    let page = self.archive.digests(log.digests.context("raw page before proof")?, after, entries.len()).await?;
                    for (entry, digest) in entries.iter().zip(&page.values) { ensure!(<[u8; 32]>::from(Sha256::digest(&entry.0)) == *digest, "raw entry does not match verified proof"); }
                    drop(receipt.take());
                    ensure!(!self.proofs.lock().unwrap().live[&peer].cancelled, "raw promotion cancelled");
                    let bytes = entries.iter().map(|e| e.0.len() as u64).sum::<u64>();
                    let cursor = after + entries.len() as u64;
                    let root = self.archive.append_raw(token, log.entries, &RawPage { after, before: page.before, entries, head: None }).await?;
                    ensure!(!self.proofs.lock().unwrap().live[&peer].cancelled, "raw promotion cancelled");
                    let pins = {
                        let mut st = self.lock();
                        if st.log(&anchor.log_ref)?.cut.is_some() || st.log(&anchor.log_ref)?.closed.is_some() { return Ok(true); }
                        self.critical(&mut st, |st| {
                            let mut usage: Usage = get(&st.provider, b"node/archive-usage")?.unwrap_or_default();
                            usage.raw += root.bytes - log.entries.map_or(0, |r| r.bytes);
                            ensure!(usage.raw <= RAW_LIMIT, "raw replay capacity exhausted");
                            put(&st.provider, b"node/archive-usage", &usage)?;
                            let saved = st.logs.get_mut(anchor.log_ref.as_slice()).unwrap();
                            saved.entries = Some(root);
                            saved.logged = cursor;
                            saved.wire_bytes += bytes;
                            let pins = saved.pins(&[1]);
                            st.save_log(&anchor.log_ref)?;
                            Ok(pins)
                        })?
                    };
                    published = true;
                    self.durable().await?;
                    self.archive.0.publish(token, pins).await?;
                    self.work.send(Work::Advance(group.0)).ok();
                    let mut jobs = self.proofs.lock().unwrap();
                    let ticket = jobs.live.get_mut(&peer).unwrap();
                    if cursor >= ticket.cut.unwrap_or(target.length) { return Ok(true); }
                    ticket.stage = Stage::Raw(cursor);
                    jobs.ready.push_back(peer);
                    self.proof_wake.notify_one();
                    Ok(false)
                }
                _ => unreachable!(),
            }
        }.await;
        if !matches!(received, Ok(false)) {
            if published && let Err(error) = &received { self.stop(&mut self.lock(), error); }
            self.finish_history(peer, token, published).await?;
        }
        received.map(|_| ())
    }
}
