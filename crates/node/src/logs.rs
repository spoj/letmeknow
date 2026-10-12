use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use lmk_core::provider::Provider;
use lmk_core::public::{PublicLog, Verdict};
use lmk_membership::client::ServeClient;
use lmk_membership::{Frontier, VerifiedPage};
use lmk_proto::Bytes;
use lmk_proto::epoch::{Anchor, Transition};
use lmk_proto::group::{IdentityRef, Service};
use lmk_proto::head::{self, Head};
use n0_future::task::spawn;
use n0_future::time::{Duration, sleep, timeout};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Event, Inner, MEMBER_WAIT, REREAD, State, Work, get, put};

pub(crate) const NOT_FOLLOWED: &str = "this session does not follow that log";
pub(crate) const DIGESTS: u64 = 1024;
pub(crate) const EVIDENCE_LIMIT: u64 = 512 << 20;
pub(crate) const AUDIT_LIMIT: u64 = 384 << 20;
pub(crate) const RAW_LIMIT: u64 = 4 << 30;

pub(crate) struct Clients {
    endpoint: iroh::Endpoint,
    clients: Mutex<HashMap<String, ServeClient>>,
}

impl Clients {
    pub fn new(endpoint: iroh::Endpoint) -> Self {
        Self { endpoint, clients: Mutex::default() }
    }

    pub fn client(&self, service: &Service) -> Result<ServeClient> {
        let name = serde_json::to_string(service)?;
        let mut clients = self.clients.lock().unwrap();
        if let Some(client) = clients.get(&name) {
            return Ok(client.clone());
        }
        let client = ServeClient::for_service(self.endpoint.clone(), service)?;
        clients.insert(name, client.clone());
        Ok(client)
    }
}

pub(crate) fn authority(service: &Service) -> Result<[u8; 32]> {
    let Service::Serve { key, .. } = service else { anyhow::bail!("unsupported membership service") };
    Ok(key.0.as_slice().try_into()?)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Of {
    Group { group: Bytes, anchor: Anchor },
    Public(Bytes),
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Log {
    pub of: Of,
    pub service: Service,
    pub log_ref: [u8; 32],
    pub head: Option<Head>,
    pub digests: Option<crate::archive::Root>,
    pub entries: Option<crate::archive::Root>,
    pub foreign: Option<crate::archive::Root>,
    pub logged: u64,
    pub wire_bytes: u64,
    pub public_at: u64,
    pub cut: Option<u64>,
    pub closed: Option<u64>,
    pub raw_until: Option<u64>,
    pub transition: Option<Transition>,
    pub readers: Vec<Bytes>,
    pub raw: bool,
    pub at: u64,
    pub conflict: Option<(Head, Head)>,
}

impl Log {
    pub fn new(of: Of, service: Service, log_ref: [u8; 32], readers: Vec<Bytes>) -> Self {
        Self { of, service, log_ref, head: None, digests: None, entries: None, foreign: None, logged: 0,
            wire_bytes: 0, public_at: 0, cut: None, closed: None, raw_until: None, transition: None, readers,
            raw: true, at: 0, conflict: None }
    }

    pub fn frontier(&self) -> Result<Frontier> {
        let service = authority(&self.service)?;
        match &self.head {
            Some(head) => Frontier::from_head(service, self.log_ref, head.clone()),
            None => Ok(Frontier::empty(service, self.log_ref)),
        }
    }

    pub fn raw_frontier(&self) -> Result<Frontier> {
        if self.logged == self.length() { self.frontier() }
        else { Ok(Frontier::empty(authority(&self.service)?, self.log_ref)) }
    }

    pub fn length(&self) -> u64 { self.head.as_ref().map_or(0, |head| head.length) }

    pub fn anchor(&self) -> Result<&Anchor> {
        let Of::Group { anchor, .. } = &self.of else { anyhow::bail!("not an epoch source") };
        Ok(anchor)
    }

    pub fn pins(&self, slots: &[u8]) -> crate::archive::Pins {
        [self.digests, self.entries, self.foreign].into_iter().enumerate().filter(|(slot, _)| slots.contains(&(*slot as u8)))
            .map(|(kind, root)| ([self.log_ref.as_slice(), &[kind as u8]].concat(), root.map(|r| r.hash))).collect()
    }

    pub fn rotate(&self) -> bool {
        self.length() >= lmk_proto::membership::MAX_LOG_LENGTH - 1024
            || self.wire_bytes >= lmk_proto::membership::MAX_LOG_BYTES - (8 << 20)
    }
}

pub(crate) struct Replay {
    pub id: Vec<u8>,
    pub page: crate::archive::RawPage,
    pub hashes: Vec<[u8; 32]>,
}

impl Replay {
    pub fn hash_at(&self, id: &[u8], position: u64) -> Option<[u8; 32]> {
        (self.id == id && position > self.page.after).then(|| self.hashes.get((position - self.page.after - 1) as usize).copied()).flatten()
    }
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Usage {
    pub evidence: u64,
    pub raw: u64,
}

pub(crate) fn log_key(id: &[u8]) -> Vec<u8> { [b"node/log/".as_slice(), id].concat() }

pub(crate) fn public_key(id: &[u8]) -> Vec<u8> { [b"node/public/".as_slice(), id].concat() }

impl<P: Provider> State<P> {
    pub(crate) fn load_logs(provider: &P) -> Result<BTreeMap<Vec<u8>, Log>> {
        let ids = get::<Vec<Bytes>>(provider, b"node/logs")?.unwrap_or_default();
        ids.into_iter().map(|id| Ok((id.0.clone(), get(provider, &log_key(&id.0))?.context("a log without its record")?))).collect()
    }

    pub(crate) fn log(&self, id: &[u8]) -> Result<&Log> {
        self.logs.get(id).context(NOT_FOLLOWED)
    }

    pub(crate) fn active(&self, gid: &[u8]) -> Result<&Log> {
        self.log(&self.group(gid)?.rec.active.0)
    }

    pub(crate) fn capability(&self, id: &[u8]) -> Result<[u8; 32]> {
        let log = self.log(id)?;
        ensure!(log.cut.is_none() && log.closed.is_none() && log.conflict.is_none(), "source is closed or conflicting");
        match &log.of {
            Of::Public(public) => Ok(lmk_proto::public::address(&public.0)),
            Of::Group { group, anchor } => {
                let g = self.group(&group.0)?;
                ensure!(!self.conflicting(&group.0), "group has conflicting signed history");
                ensure!(g.rec.active.0 == id && g.mls.epoch() == anchor.epoch, "retired epoch source");
                g.mls.capability(&self.provider)
            }
        }
    }

    pub(crate) fn save_log(&self, id: &[u8]) -> Result<()> {
        put(&self.provider, &log_key(id), self.log(id)?)
    }

    fn save_logs(&self) -> Result<()> {
        put(&self.provider, b"node/logs", &self.logs.keys().map(|id| Bytes(id.clone())).collect::<Vec<_>>())
    }

    pub(crate) fn add_log(&mut self, id: &[u8], log: Log) -> Result<()> {
        ensure!(!self.logs.contains_key(id), "epoch source already installed");
        let mut usage: Usage = get(&self.provider, b"node/archive-usage")?.unwrap_or_default();
        usage.evidence += serde_json::to_vec(&log)?.len() as u64 + 4096;
        ensure!(usage.evidence <= EVIDENCE_LIMIT, "source metadata quota exhausted");
        put(&self.provider, b"node/archive-usage", &usage)?;
        self.logs.insert(id.to_vec(), log);
        self.save_log(id)?;
        self.save_logs()
    }

    pub(crate) fn public_ref(&self, public: &[u8]) -> Option<Vec<u8>> {
        self.logs.iter().find_map(|(id, log)| matches!(&log.of, Of::Public(owner) if owner.0 == public).then(|| id.clone()))
    }

    pub(crate) fn groups_of(&self, id: &[u8]) -> Vec<Vec<u8>> {
        match self.logs.get(id).map(|log| &log.of) {
            Some(Of::Group { group, .. }) => vec![group.0.clone()],
            Some(Of::Public(public)) => self.groups.keys().filter(|gid| {
                self.identities(gid).iter().any(|identity| identity.id == *public)
                    || self.groups[*gid].mls.settings().public.as_ref() == Some(public)
            }).cloned().collect(),
            None => Vec::new(),
        }
    }

    pub(crate) fn hash_at(&self, id: &[u8], position: u64) -> Result<Option<[u8; 32]>> {
        let log = self.log(id)?;
        if position == 0 { return Ok(Some(*Frontier::empty(authority(&log.service)?, log.log_ref).hash())); }
        if position == log.length() { return Ok(log.head.as_ref().map(|h| h.hash)); }
        Ok(self.replay.as_ref().and_then(|page| page.hash_at(id, position)))
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    pub(crate) fn follow(self: &Arc<Self>, id: &[u8]) {
        let (inner, id) = (self.clone(), id.to_vec());
        let key = id.clone();
        let task = spawn(async move {
            loop {
                if inner.durable().await.is_err() { return; }
                let source = {
                    let st = inner.lock();
                    st.capability(&id).and_then(|capability| Ok((capability, st.log(&id)?.service.clone(), st.log(&id)?.raw_frontier()?)))
                };
                let Ok((capability, service, frontier)) = source else { return };
                let followed = async {
                    let mut subscription = inner.clients.client(&service)?.subscribe(vec![(capability, frontier)]).await?;
                    loop {
                        match timeout(REREAD, subscription.next()).await {
                            Ok(Some(page)) => inner.stored(&id, page?).await?,
                            Ok(None) => break,
                            Err(_) => { inner.read(&id).await?; break; }
                        }
                        if inner.lock().capability(&id).is_err() { break; }
                    }
                    anyhow::Ok(())
                }.await;
                if let Err(error) = followed {
                    inner.log_error(&id, &error);
                }
                sleep(Duration::from_secs(2)).await;
            }
        });
        if let Some(old) = self.follows.lock().unwrap().insert(key, task) { old.abort(); }
    }

    pub(crate) fn unfollow(&self, id: &[u8]) {
        self.retire_history(id);
        if let Some(task) = self.follows.lock().unwrap().remove(id) { task.abort(); }
    }

    pub(crate) async fn read_group(&self, gid: &[u8]) -> Result<()> {
        let id = self.lock().group(gid)?.rec.active.0.clone();
        self.read(&id).await
    }

    pub(crate) async fn read(&self, id: &[u8]) -> Result<()> {
        self.durable().await?;
        let (capability, service, mut frontier) = {
            let st = self.lock();
            let log = st.log(id)?;
            if log.cut.is_some() || log.closed.is_some() { return Ok(()); }
            (st.capability(id)?, log.service.clone(), log.raw_frontier()?)
        };
        loop {
            if self.lock().capability(id).is_err() { return Ok(()); }
            let result = self.clients.client(&service)?.read(&capability, &frontier).await;
            let page = match result {
                Ok(page) => page,
                Err(error) => { self.log_error(id, &error); return Err(error); }
            };
            let more = !page.page().entries.is_empty();
            frontier = Frontier::from_head(authority(&service)?, id.try_into()?, page.page().head.clone())?;
            self.stored(id, page).await?;
            if !more { return Ok(()); }
        }
    }

    pub(crate) fn archiving(&self, id: &[u8]) -> Arc<tokio::sync::Mutex<()>> {
        self.archiving.lock().unwrap().entry(id.to_vec()).or_default().clone()
    }

    pub(crate) async fn stored(&self, id: &[u8], verified: VerifiedPage) -> Result<()> {
        let lane = self.archiving(id);
        let _lane = lane.lock().await;
        let page = verified.into_page();
        if page.entries.is_empty() { return Ok(()); }
        let log = self.lock().log(id)?.clone();
        if log.cut.is_some() || log.closed.is_some() { return Ok(()); }
        ensure!(page.after <= log.length() && page.after <= log.logged, "raw prefix gap");
        let before = if page.after == 0 { head::start(&authority(&log.service)?, &log.log_ref) }
            else { self.archive.hash_at(log.digests.context("missing digest root")?, page.after).await? };
        if page.head.length <= log.length() && self.archive.hash_at(log.digests.context("missing digest root")?, page.head.length).await? != page.head.hash {
            self.contradicted(&mut self.lock(), id, log.head.unwrap(), page.head)?;
            return Ok(());
        }
        if page.head.length <= log.logged { return Ok(()); }
        let values: Vec<[u8; 32]> = page.entries.iter().map(|entry| Sha256::digest(&entry.0).into()).collect();
        let hashes: Vec<_> = values.iter().scan(before, |hash, digest| { *hash = head::next_digest(hash, digest); Some(*hash) }).collect();
        ensure!(hashes.last() == Some(&page.head.hash), "page does not extend retained prefix");
        let raw_skip = (log.logged - page.after) as usize;
        let raw_before = if raw_skip == 0 { before } else { hashes[raw_skip - 1] };
        let raw = crate::archive::RawPage { after: log.logged, before: raw_before, entries: page.entries.into_iter().skip(raw_skip).collect(), head: Some(page.head.clone()) };
        let batch = lmk_core::random();
        let roots = async {
            let digests = if page.head.length > log.length() {
                let skip = (log.length() - page.after) as usize;
                let before = if skip == 0 { before } else { hashes[skip - 1] };
                self.archive.append_digests(batch, log.digests, log.length(), before, &values[skip..]).await?
            } else { log.digests.context("missing retained digest root")? };
            let entries = self.archive.append_raw(batch, log.entries, &raw).await?;
            anyhow::Ok((digests, entries))
        }.await;
        let (digests, entries) = match roots {
            Ok(roots) => roots,
            Err(error) => { self.archive.0.discard(batch).await?; return Err(error); }
        };
        let pins = {
            let mut st = self.lock();
            let current = st.log(id)?;
            if current.cut.is_some() || current.closed.is_some() {
                None
            } else {
                Some(self.critical(&mut st, |st| {
                    let mut usage: Usage = get(&st.provider, b"node/archive-usage")?.unwrap_or_default();
                    usage.evidence += digests.bytes - log.digests.map_or(0, |r| r.bytes);
                    usage.raw += entries.bytes - log.entries.map_or(0, |r| r.bytes);
                    ensure!(usage.evidence <= EVIDENCE_LIMIT && usage.raw <= RAW_LIMIT, "required epoch retention quota exhausted");
                    put(&st.provider, b"node/archive-usage", &usage)?;
                    let log = st.logs.get_mut(id).unwrap();
                    log.digests = Some(digests);
                    log.entries = Some(entries);
                    log.logged = page.head.length;
                    if page.head.length > log.length() { log.head = Some(page.head); }
                    log.wire_bytes += raw.entries.iter().map(|e| e.0.len() as u64).sum::<u64>();
                    log.at = crate::now();
                    let pins = log.pins(&[0, 1]);
                    st.save_log(id)?;
                    Ok(pins)
                })?)
            }
        };
        let Some(pins) = pins else { return self.archive.0.discard(batch).await };
        self.durable().await?;
        if let Err(error) = self.archive.0.publish(batch, pins).await {
            self.stop(&mut self.lock(), &error);
            return Err(error);
        }
        self.check(&mut self.lock(), id)
    }

    pub(crate) fn check(&self, st: &mut State<P>, id: &[u8]) -> Result<()> {
        match st.log(id)?.of.clone() {
            Of::Group { group, .. } => {
                if st.groups.get(&group.0).is_some_and(|g| g.rec.active.0 == id) { self.advance(st, &group.0)?; }
            }
            Of::Public(public) => { self.work.send(Work::Public(public.0)).ok(); }
        }
        Ok(())
    }

    pub(crate) async fn load(&self, gid: &[u8]) -> Result<()> {
        let next = {
            let st = self.lock();
            st.group(gid).and_then(|g| {
                let log = st.active(gid)?;
                let local = g.rec.position.checked_sub(log.anchor()?.base).context("cursor before source")? + 1;
                Ok((g.rec.active.0.clone(), log.entries.filter(|r| local <= r.end), local))
            })
        };
        let (id, root, local) = match next {
            Ok(next) => next,
            Err(_) => { self.lock().loading.remove(gid); return Ok(()); }
        };
        let Some(root) = root else { self.lock().loading.remove(gid); return Ok(()) };
        let page = self.archive.raw(root, local).await;
        let mut st = self.lock();
        st.loading.remove(gid);
        if st.groups.get(gid).is_none_or(|g| g.rec.active.0 != id) { return Ok(()); }
        let page = match page {
            Ok(page) => page,
            Err(_) if st.log(&id)?.entries != Some(root) => { self.advance(&mut st, gid)?; return Ok(()); }
            Err(error) => { self.stop(&mut st, &error); return Err(error); }
        };
        let mut h = page.before;
        let hashes = page.entries.iter().map(|e| { h = head::next(&h, &e.0); h }).collect();
        st.replay = Some(Replay { id, page, hashes });
        self.advance(&mut st, gid)
    }

    pub(crate) async fn public_page(&self, peer: iroh::EndpointId, id: &[u8], after: u64) -> Result<()> {
        let _serving = self.history_serving.acquire().await?;
        let lane = self.archiving(id);
        let _lane = lane.lock().await;
        let root = self.lock().log(id)?.entries;
        let Some(root) = root.filter(|r| after < r.end) else { return Ok(()) };
        let page = self.archive.raw(root, after + 1).await?;
        let head = page.head.context("public page without its signed cover")?;
        let entries = page.entries.into_iter().skip((after - page.after) as usize).collect();
        self.lock().frame_out(peer, lmk_proto::peer::Frame::Entries { log: Bytes(id.to_vec()), entries, head });
        Ok(())
    }

    pub(crate) fn log_error(&self, id: &[u8], error: &anyhow::Error) {
        if let Some(lmk_membership::Contradiction { ours, theirs }) = error.downcast_ref::<lmk_membership::Contradiction>() {
            let mut st = self.lock();
            if let Err(error) = self.contradicted(&mut st, id, ours.clone(), theirs.clone()) {
                self.stop(&mut st, &error);
            }
        }
    }

    pub(crate) fn contradicted(&self, st: &mut State<P>, id: &[u8], ours: Head, theirs: Head) -> Result<()> {
        let log = st.log(id)?;
        if log.conflict.is_some() { return Ok(()); }
        let key = ed25519_dalek::VerifyingKey::from_bytes(&authority(&log.service)?)?;
        ensure!(ours.log_ref == log.log_ref && theirs.log_ref == log.log_ref && ours.verify(&key) && theirs.verify(&key), "invalid conflict authority");
        self.critical(st, |st| {
            st.logs.get_mut(id).unwrap().conflict = Some((ours, theirs));
            st.save_log(id)
        })?;
        for group in st.groups_of(id) {
            st.events.push(Event::Warning { group: Some(Bytes(group)), text: "membership service signed incompatible physical history; group stopped".into() });
        }
        self.unfollow(id);
        Ok(())
    }

    pub(crate) async fn refresh_all(self: &Arc<Self>) {
        let unread: Vec<IdentityRef> = {
            let mut st = self.lock();
            let st = &mut *st;
            let mut unread = Vec::new();
            for credential in st.groups.values().flat_map(|g| g.mls.members()).filter_map(|m| m.credential) {
                let Some(certificate) = &credential.certificate else { continue };
                let identity = &certificate.identity;
                let read = match st.public.get(&identity.id.0) {
                    None => true,
                    Some(log) => log.verify(&credential) == Verdict::Unverified && st.unlisted.insert((identity.id.0.clone(), certificate.device.0.clone())),
                };
                if read && !unread.contains(identity) { unread.push(identity.clone()); }
            }
            unread
        };
        for identity in unread {
            if let Err(error) = timeout(MEMBER_WAIT, self.read_public(&identity)).await.map_err(anyhow::Error::from).and_then(|r| r) {
                tracing::debug!("reading identity authority: {error:#}");
            }
        }
    }

    pub(crate) async fn read_public(self: &Arc<Self>, identity: &IdentityRef) -> Result<PublicLog> {
        let capability = lmk_proto::public::address(&identity.id.0);
        if self.lock().public_ref(&identity.id.0).is_none() {
            let mut service = identity.membership.clone();
            for authenticating in [false, true] {
                let key = authority(&service)?;
                let client = self.clients.client(&service)?;
                let mut frontier = Frontier::empty(key, head::reference(&key, &capability));
                loop {
                    let page = client.read(&capability, &frontier).await?;
                    if let Some(first) = page.page().entries.iter().find_map(|entry| PublicLog::created(identity.id.0.as_slice().try_into().unwrap(), &entry.0)) {
                        if authenticating { ensure!(first.membership == service, "public authority mismatch"); }
                        service = first.membership;
                        break;
                    }
                    ensure!(!page.page().entries.is_empty(), "public log has no valid first entry");
                    frontier = page.frontier().clone();
                }
            }
            let id = head::reference(&authority(&service)?, &capability);
            {
                let mut st = self.lock();
                if st.public_ref(&identity.id.0).is_none() {
                    self.critical(&mut st, |st| st.add_log(&id, Log::new(Of::Public(identity.id.clone()), service, id, Vec::new())))?;
                }
            }
            self.durable().await?;
            self.follow(&id);
        }
        let id = self.lock().public_ref(&identity.id.0).context("missing public source")?;
        self.read(&id).await?;
        self.replayed(&identity.id.0).await?;
        self.lock().public.get(&identity.id.0).cloned().context("the public log has no valid first entry")
    }

    pub(crate) async fn replayed(&self, public: &[u8]) -> Result<()> {
        loop {
            let (id, log, state) = {
                let st = self.lock();
                let id = st.public_ref(public).context("missing public source")?;
                let log = st.log(&id)?.clone();
                (id, log, st.public.get(public).cloned())
            };
            let Some(root) = log.entries.filter(|r| log.public_at < r.end) else { return Ok(()) };
            let page = self.archive.raw(root, log.public_at + 1).await?;
            let mut state = state;
            let through = page.after + page.entries.len() as u64;
            for entry in page.entries.into_iter().skip((log.public_at - page.after) as usize) {
                match &mut state {
                    Some(state) => { state.apply(&entry.0); }
                    None => state = PublicLog::created(public.try_into()?, &entry.0),
                }
            }
            let mut st = self.lock();
            if st.log(&id)?.public_at != log.public_at { continue; }
            self.critical(&mut st, |st| {
                if let Some(state) = state {
                    ensure!(state.membership == log.service, "public authority mismatch");
                    put(&st.provider, &public_key(public), &state)?;
                    st.public.insert(public.to_vec(), state);
                }
                st.logs.get_mut(&id).unwrap().public_at = through;
                st.save_log(&id)?;
                st.gate = true;
                for gid in st.groups_of(&id) { self.work.send(Work::Duties(gid)).ok(); }
                st.events.push(Event::Public { identity: Bytes(public.to_vec()) });
                Ok(())
            })?;
        }
    }
}
