//! Bounded membership work. Only capabilities cross the service request boundary.

use std::{collections::{BTreeMap, HashMap}, hash::Hash, net::{IpAddr, Ipv4Addr}, sync::{Arc, Mutex}, time::Duration};

use anyhow::{Result, ensure};
use ed25519_dalek::Signer;
use iroh::{endpoint::{Connection, RecvStream, SendStream}, protocol::{AcceptError, ProtocolHandler}};
use lmk_proto::{Bytes, clock::now, frame::{self, Open, Stream}, head::{self, Head}, membership::{self, Answer, Append, Appended, Heads, Known, Latest, Moved, Page, Read, Refusal, Reply, Request, Subscribed, refusal_message}};
use n0_future::task::AbortOnDropHandle;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::{OwnedSemaphorePermit, Semaphore, mpsc}, time::{Instant, timeout}};

use crate::{Refused, store::{DAY_MS, DISK_BYTES, Stats, Store}};

const MAX_CONNECTIONS: usize = 2048;
const MAX_STREAMS: usize = 1024;
/// A session's requests and subscriptions to one service at once, one subscription per log it follows there: under
/// QUIC's 100 streams a peer may open, so that a stream over it is refused rather than left waiting.
pub const CONNECTION_STREAMS: usize = 64;
const DB_WORK: usize = 4;
pub const MAX_SUBSCRIBERS: usize = 4096;
const LAG: usize = 8;
/// Bytes in flight over the whole service and over each connection, in KiB permits.
const MEMORY: usize = 256 << 20;
const CONNECTION_MEMORY: usize = 16 << 20;
const KIB: usize = 1 << 10;
/// Bound of a reply that is not a page: an append's, a head's or a refusal.
const SMALL_REPLY: usize = 4 << 10;
/// How long a request waits for a slot of `DB_WORK` or for memory before it is refused as busy. Work that started runs
/// to its end: a refusal tells the client the work was not done.
const DB_WAIT: Duration = Duration::from_secs(2);
const MINUTE: u64 = 60_000;
/// The largest entry a public log takes.
const PUBLIC_ENTRY: usize = 16 << 10;
/// A /48's budget, in /64s.
const WIDE: u64 = 16;
const IN_ALL: [((), u64); 1] = [((), 1)];
/// Keys a quota tracks at once: a source past them is refused, so a flood of addresses cannot grow memory.
const KEYS: usize = 1 << 20;

#[derive(Clone, Debug)]
pub struct Policy {
    /// Per connection on the iroh protocol; per address over HTTPS.
    pub appends_per_minute: u32,
    pub retention_days: u64,
    pub disk: u64,
    /// Over HTTPS, per address from here down.
    pub append_bytes_per_day: u64,
    pub reads_per_minute: u32,
    pub read_bytes_per_minute: u64,
    pub new_logs_per_day: u64,
    pub new_public_logs_per_day: u64,
    /// Stored entries a day to each public log, from any address.
    pub public_appends_per_day: u64,
    /// New logs a day from all addresses.
    pub new_logs_per_day_in_all: u64,
    pub requests_at_once: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            appends_per_minute: 600, retention_days: 365, disk: DISK_BYTES,
            append_bytes_per_day: 256 << 20, reads_per_minute: 600, read_bytes_per_minute: 64 << 20,
            new_logs_per_day: 2_000, new_public_logs_per_day: 10, public_appends_per_day: 10,
            new_logs_per_day_in_all: 250_000, requests_at_once: 8,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Route { Append, Read, Heads }

impl Route {
    pub fn parse(path: &str) -> Option<Self> {
        match path {
            "/membership/1/append" => Some(Self::Append),
            "/membership/1/read" => Some(Self::Read),
            "/membership/1/heads" => Some(Self::Heads),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct Service(Arc<Inner>);

struct Inner {
    store: Store,
    policy: Policy,
    budgets: Mutex<Budgets>,
    at_once: Arc<Semaphore>,
    subscribers: Mutex<Subscribers>,
    connections: Semaphore,
    streams: Arc<Semaphore>,
    work: Arc<Semaphore>,
    memory: Arc<Semaphore>,
    expiry: Mutex<Option<AbortOnDropHandle<()>>>,
}

#[derive(Default)]
struct Subscribers {
    next: u64,
    records: BTreeMap<u64, (Vec<[u8; 32]>, mpsc::Sender<Head>)>,
}

impl Subscribers {
    fn add(&mut self, refs: Vec<[u8; 32]>, sender: mpsc::Sender<Head>) -> Result<u64> {
        ensure!(self.records.len() < MAX_SUBSCRIBERS, Refused("busy".into()));
        self.next += 1;
        self.records.insert(self.next, (refs, sender));
        Ok(self.next)
    }

    fn notify(&mut self, head: &Head) {
        self.records.retain(|_, (refs, sender)| !refs.contains(&head.log_ref) || sender.try_send(head.clone()).is_ok());
    }
}

/// What each key spent in the current window of `period` milliseconds, against `limit` times its scale.
struct Quota<K> {
    period: u64,
    limit: u64,
    window: u64,
    spent: HashMap<K, u64>,
}

impl<K: Clone + Eq + Hash> Quota<K> {
    fn new(period: u64, limit: u64) -> Self { Self { period, limit, window: 0, spent: HashMap::new() } }

    fn fits(&mut self, at: u64, keys: &[(K, u64)], amount: u64) -> bool {
        self.roll(at);
        keys.iter().all(|(key, scale)| {
            let spent = self.spent.get(key).copied();
            let room = spent.is_some() || self.spent.len() < KEYS;
            room && spent.unwrap_or(0) + amount <= self.limit * scale
        })
    }

    fn charge(&mut self, at: u64, keys: &[(K, u64)], amount: u64) {
        self.roll(at);
        for (key, _) in keys { *self.spent.entry(key.clone()).or_default() += amount; }
    }

    fn take(&mut self, at: u64, keys: &[(K, u64)], amount: u64) -> bool {
        let fits = self.fits(at, keys, amount);
        if fits { self.charge(at, keys, amount); }
        fits
    }

    fn roll(&mut self, at: u64) {
        if at / self.period != self.window {
            self.window = at / self.period;
            self.spent.clear();
        }
    }
}

/// What an address's budgets are drawn from: an IPv4 address, mapped or not; an IPv6 address's /64, and its /48.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Source { V4(Ipv4Addr), Net64(u64), Net48(u64) }

fn sources(from: IpAddr) -> Vec<(Source, u64)> {
    match from {
        IpAddr::V4(v4) => vec![(Source::V4(v4), 1)],
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => vec![(Source::V4(v4), 1)],
            None => {
                let bits = u128::from(v6);
                vec![(Source::Net64((bits >> 64) as u64), 1), (Source::Net48((bits >> 80) as u64), WIDE)]
            }
        },
    }
}

struct Budgets {
    appends: Quota<Source>,
    append_bytes: Quota<Source>,
    reads: Quota<Source>,
    read_bytes: Quota<Source>,
    new_logs: Quota<Source>,
    new_public_logs: Quota<Source>,
    public_appends: Quota<[u8; 32]>,
    new_logs_in_all: Quota<()>,
}

impl Budgets {
    fn new(policy: &Policy) -> Self {
        Self {
            appends: Quota::new(MINUTE, policy.appends_per_minute.into()),
            append_bytes: Quota::new(DAY_MS, policy.append_bytes_per_day),
            reads: Quota::new(MINUTE, policy.reads_per_minute.into()),
            read_bytes: Quota::new(MINUTE, policy.read_bytes_per_minute),
            new_logs: Quota::new(DAY_MS, policy.new_logs_per_day),
            new_public_logs: Quota::new(DAY_MS, policy.new_public_logs_per_day),
            public_appends: Quota::new(DAY_MS, policy.public_appends_per_day),
            new_logs_in_all: Quota::new(DAY_MS, policy.new_logs_per_day_in_all),
        }
    }
}

struct Registration { inner: Arc<Inner>, id: u64 }
impl Drop for Registration {
    fn drop(&mut self) { self.inner.subscribers.lock().unwrap().records.remove(&self.id); }
}

/// Permits for bytes in flight, from the connection's budget and the service's. Taking `bytes` takes twice as many,
/// as a body is held as bytes and as its decoded value.
struct Hold { connection: OwnedSemaphorePermit, service: OwnedSemaphorePermit }

impl Hold {
    async fn take(connection: &Arc<Semaphore>, service: &Arc<Semaphore>, bytes: usize) -> Result<Self> {
        let kib = (2 * bytes).div_ceil(KIB);
        let (connection, service) = timeout(DB_WAIT, async {
            tokio::join!(connection.clone().acquire_many_owned(kib as u32), service.clone().acquire_many_owned(kib as u32))
        }).await.map_err(|_| Refused("busy".into()))?;
        Ok(Self { connection: connection?, service: service? })
    }

    /// Keeps permits for `bytes` of what was taken; the rest are released.
    fn shrink(&mut self, bytes: usize) {
        let kib = (2 * bytes).div_ceil(KIB);
        self.connection = self.connection.split(kib).unwrap();
        self.service = self.service.split(kib).unwrap();
    }
}

async fn receive<T: DeserializeOwned>(recv: &mut RecvStream, connection: &Arc<Semaphore>, service: &Arc<Semaphore>) -> Result<(T, Hold)> {
    let len = membership::read_len(recv).await?;
    let hold = Hold::take(connection, service, len).await?;
    Ok((membership::read_body(recv, len).await?, hold))
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Service") }
}

impl Service {
    pub fn new(mut store: Store, policy: Policy) -> Self {
        store.disk = policy.disk;
        let service = Self(Arc::new(Inner {
            store, budgets: Mutex::new(Budgets::new(&policy)), at_once: Arc::new(Semaphore::new(policy.requests_at_once)), policy,
            subscribers: Mutex::default(), connections: Semaphore::new(MAX_CONNECTIONS),
            streams: Arc::new(Semaphore::new(MAX_STREAMS)), work: Arc::new(Semaphore::new(DB_WORK)),
            memory: Arc::new(Semaphore::new(MEMORY / KIB)), expiry: Mutex::default(),
        }));
        let weak = Arc::downgrade(&service.0);
        let expiry = n0_future::task::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                let before = (now() / DAY_MS).saturating_sub(inner.policy.retention_days);
                if Service(inner).work(move |inner| inner.store.expire(before)).await.is_err() {
                    tracing::warn!("membership expiry deferred");
                }
            }
        });
        *service.0.expiry.lock().unwrap() = Some(AbortOnDropHandle::new(expiry));
        service
    }

    async fn work<T: Send + 'static>(&self, f: impl FnOnce(&Inner) -> Result<T> + Send + 'static) -> Result<T> {
        let permit = timeout(DB_WAIT, self.0.work.clone().acquire_owned()).await.map_err(|_| Refused("busy".into()))??;
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || { let _permit = permit; f(&inner) }).await?
    }

    pub async fn stats(&self) -> Result<Stats> { self.work(|inner| inner.store.stats()).await }

    /// Answers one request on the HTTPS routes: the body is the route's, and the answer is an `Answer` as JSON. An error
    /// is the service's own failure, which is no answer.
    pub async fn post(&self, route: Route, from: IpAddr, body: &[u8]) -> Result<Vec<u8>> {
        let sources = sources(from);
        let at = now();
        let answer = match route {
            Route::Append => self.answer(body, self.append(&sources, at, body).await),
            Route::Read => self.answer(body, self.read(&sources, at, body).await),
            Route::Heads => self.answer(body, self.heads(&sources, at, body).await),
        }?;
        if !matches!(route, Route::Append) {
            self.0.budgets.lock().unwrap().read_bytes.charge(at, &sources, answer.len() as u64);
        }
        Ok(answer)
    }

    async fn append(&self, sources: &[(Source, u64)], at: u64, body: &[u8]) -> Result<Appended> {
        let Append { capability, entries, public } = decode(body)?;
        ensure!(!public || entries.iter().all(|e| e.0.len() <= PUBLIC_ENTRY), Refused("size".into()));
        let reference = head::reference(&self.0.store.key().verifying_key().to_bytes(), &capability);
        let bytes: u64 = entries.iter().map(|e| e.0.len() as u64).sum();
        let count = entries.len() as u64;
        let _slot = self.slot().await?;
        let may_start = {
            let mut budgets = self.0.budgets.lock().unwrap();
            ensure!(budgets.appends.take(at, sources, 1) && budgets.append_bytes.take(at, sources, bytes)
                && (!public || budgets.public_appends.fits(at, &[(reference, 1)], count)), Refused("rate".into()));
            budgets.new_logs.fits(at, sources, 1) && budgets.new_logs_in_all.fits(at, &IN_ALL, 1)
                && (!public || budgets.new_public_logs.fits(at, sources, 1))
        };
        let appended = self.work(move |inner| {
            ensure!(may_start || inner.store.length(&reference)? > 0, Refused("rate".into()));
            inner.store.append(&reference, &entries, public)
        }).await?;
        let mut budgets = self.0.budgets.lock().unwrap();
        if public { budgets.public_appends.charge(at, &[(reference, 1)], count); }
        if appended.position == 1 {
            budgets.new_logs.charge(at, sources, 1);
            budgets.new_logs_in_all.charge(at, &IN_ALL, 1);
            if public { budgets.new_public_logs.charge(at, sources, 1); }
        }
        Ok(appended)
    }

    async fn read(&self, sources: &[(Source, u64)], at: u64, body: &[u8]) -> Result<Page> {
        let Read { capability, after } = decode(body)?;
        let reference = head::reference(&self.0.store.key().verifying_key().to_bytes(), &capability);
        let _slot = self.slot().await?;
        {
            let mut budgets = self.0.budgets.lock().unwrap();
            ensure!(budgets.reads.take(at, sources, 1) && budgets.read_bytes.fits(at, sources, 0), Refused("rate".into()));
        }
        self.work(move |inner| inner.store.read(&reference, after)).await
    }

    async fn heads(&self, sources: &[(Source, u64)], at: u64, body: &[u8]) -> Result<Moved> {
        let Heads { logs } = decode(body)?;
        let service = self.0.store.key().verifying_key().to_bytes();
        let logs: Vec<([u8; 32], u64)> = logs.iter().map(|Known(capability, length)| (head::reference(&service, capability), *length)).collect();
        let _slot = self.slot().await?;
        {
            let mut budgets = self.0.budgets.lock().unwrap();
            ensure!(budgets.reads.take(at, sources, 1) && budgets.read_bytes.fits(at, sources, 0), Refused("rate".into()));
        }
        let heads = self.work(move |inner| inner.store.moved(&logs)).await?;
        Ok(Moved { heads })
    }

    async fn slot(&self) -> Result<OwnedSemaphorePermit> {
        Ok(timeout(DB_WAIT, self.0.at_once.clone().acquire_owned()).await.map_err(|_| Refused("busy".into()))??)
    }

    fn answer<T: Serialize>(&self, body: &[u8], result: Result<T>) -> Result<Vec<u8>> {
        let answer = match result {
            Ok(value) => Answer::Ok(value),
            Err(error) => {
                let Some(Refused(code)) = error.downcast_ref::<Refused>() else { return Err(error) };
                let Some(refusal) = Refusal::from_code(code) else { return Err(error) };
                let sig = self.0.store.key().sign(&refusal_message(refusal, body));
                Answer::Refused { refusal, sig: Bytes(sig.to_bytes().to_vec()) }
            }
        };
        Ok(serde_json::to_vec(&answer)?)
    }

    async fn stream(&self, mut send: SendStream, mut recv: RecvStream, appends: &Mutex<Window>, connection: &Arc<Semaphore>, work_slot: OwnedSemaphorePermit) -> Result<()> {
        match self.exchange(&mut send, &mut recv, appends, connection, work_slot).await {
            Err(error) if error.is::<Refused>() => {
                reply::<()>(&mut send, Err(error), Hold::take(connection, &self.0.memory, 0).await?).await?;
                send.shutdown().await?;
                Ok(())
            }
            result => result,
        }
    }

    async fn exchange(&self, send: &mut SendStream, recv: &mut RecvStream, appends: &Mutex<Window>, connection: &Arc<Semaphore>, work_slot: OwnedSemaphorePermit) -> Result<()> {
        let (request, request_hold) = timeout(Duration::from_secs(15), async {
            let (open, _) = receive::<Open>(recv, connection, &self.0.memory).await?;
            ensure!(open.stream == Stream::Membership, Refused("policy".into()));
            receive::<Request>(recv, connection, &self.0.memory).await
        }).await?.map_err(|error| if error.is::<Refused>() { error } else { Refused("policy".into()).into() })?;
        let service = self.0.store.key().verifying_key().to_bytes();
        match request {
            Request::Append { capability, entries, public } => {
                let d = head::reference(&service, &capability);
                let reply_hold = Hold::take(connection, &self.0.memory, SMALL_REPLY).await?;
                let answer = if !appends.lock().unwrap().take(self.0.policy.appends_per_minute) {
                    Err(Refused("rate".into()).into())
                } else {
                    // Subscribers hear of what committed, even if this request goes no further.
                    self.work(move |inner| {
                        let appended = inner.store.append(&d, &entries, public)?;
                        inner.subscribers.lock().unwrap().notify(&appended.head);
                        Ok(appended)
                    }).await
                };
                reply(send, answer, reply_hold).await?;
            }
            Request::Read { capability, after } => {
                let d = head::reference(&service, &capability);
                let mut reply_hold = Hold::take(connection, &self.0.memory, membership::MAX_BODY).await?;
                let answer = self.work(move |inner| inner.store.read(&d, after)).await;
                reply_hold.shrink(answer.as_ref().map_or(SMALL_REPLY, |page| membership::encoded_page_bytes(&page.entries)));
                reply(send, answer, reply_hold).await?;
            }
            Request::Head { capability } => {
                let d = head::reference(&service, &capability);
                let reply_hold = Hold::take(connection, &self.0.memory, SMALL_REPLY).await?;
                reply(send, self.work(move |inner| Ok(Latest { head: inner.store.head(&d)? })).await, reply_hold).await?;
            }
            Request::Subscribe { capabilities } => {
                drop(work_slot);
                drop(request_hold);
                let refs = capabilities.iter().map(|c| head::reference(&service, c)).collect();
                return self.subscribe(send, recv, refs, connection).await;
            }
        }
        send.shutdown().await?;
        Ok(())
    }

    async fn subscribe(&self, send: &mut SendStream, recv: &mut RecvStream, refs: Vec<[u8; 32]>, connection: &Arc<Semaphore>) -> Result<()> {
        let (sender, mut notices) = mpsc::channel(LAG);
        let id = self.0.subscribers.lock().unwrap().add(refs.clone(), sender);
        let id = match id {
            Ok(id) => id,
            Err(error) => {
                reply::<Subscribed>(send, Err(error), Hold::take(connection, &self.0.memory, SMALL_REPLY).await?).await?;
                return Ok(());
            }
        };
        let _registration = Registration { inner: self.0.clone(), id };
        let forward = async {
            reply(send, Ok(Subscribed {}), Hold::take(connection, &self.0.memory, SMALL_REPLY).await?).await?;
            for d in refs {
                let reply_hold = Hold::take(connection, &self.0.memory, SMALL_REPLY).await?;
                reply(send, self.work(move |inner| Ok(Latest { head: inner.store.head(&d)? })).await, reply_hold).await?;
            }
            while let Some(head) = notices.recv().await {
                reply(send, Ok(Latest { head }), Hold::take(connection, &self.0.memory, SMALL_REPLY).await?).await?;
            }
            anyhow::bail!("membership subscription lagged")
        };
        tokio::select! {
            result = forward => result,
            _ = recv.read_u8() => Ok(()),
        }
    }
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| Refused("policy".into()).into())
}

async fn reply<T: serde::Serialize>(send: &mut SendStream, result: Result<T>, _hold: Hold) -> Result<()> {
    let answer = match result {
        Ok(value) => Reply::Ok(value),
        Err(error) => {
            let Some(Refused(code)) = error.downcast_ref::<Refused>() else { return Err(error) };
            let Some(reason) = Refusal::from_code(code) else { return Err(error) };
            Reply::Refused(reason)
        }
    };
    timeout(Duration::from_secs(30), frame::write(send, &answer)).await??;
    Ok(())
}

struct Window { start: Instant, count: u32 }
impl Window {
    fn take(&mut self, limit: u32) -> bool {
        if self.start.elapsed() >= Duration::from_secs(60) { *self = Self { start: Instant::now(), count: 0 }; }
        if self.count >= limit { return false; }
        self.count += 1;
        true
    }
}

impl ProtocolHandler for Service {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let Ok(_connection) = self.0.connections.try_acquire() else { conn.close(1u32.into(), b"busy"); return Ok(()); };
        let appends = Arc::new(Mutex::new(Window { start: Instant::now(), count: 0 }));
        let memory = Arc::new(Semaphore::new(CONNECTION_MEMORY / KIB));
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                stream = conn.accept_bi() => {
                    let Ok((send, recv)) = stream else { break };
                    while tasks.try_join_next().is_some() {}
                    if tasks.len() >= CONNECTION_STREAMS { continue; }
                    let Ok(global) = self.0.streams.clone().try_acquire_owned() else { continue };
                    let (service, appends, memory) = (self.clone(), appends.clone(), memory.clone());
                    tasks.spawn(async move {
                        if service.stream(send, recv, &appends, &memory, global).await.is_err() { tracing::debug!("membership stream ended"); }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscriber_capacity_and_backpressure() {
        let mut subscribers = Subscribers::default();
        let mut receivers = Vec::new();
        for _ in 0..MAX_SUBSCRIBERS {
            let (tx, rx) = mpsc::channel(LAG);
            subscribers.add(vec![[7; 32]], tx).unwrap();
            receivers.push(rx);
        }
        assert!(subscribers.add(vec![[7; 32]], mpsc::channel(LAG).0).is_err());
        let head = Head::sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]), &[7; 32], 1, [1; 32], 0);
        for _ in 0..LAG { subscribers.notify(&head); }
        assert_eq!(subscribers.records.len(), MAX_SUBSCRIBERS);
        subscribers.notify(&head);
        assert!(subscribers.records.is_empty());
        assert!(receivers.iter().all(|r| r.len() == LAG));
    }

    #[test]
    fn a_quota_refuses_new_keys_past_its_capacity() {
        let mut quota = Quota::new(MINUTE, 2);
        for key in 0..KEYS as u64 { quota.charge(0, &[(key, 1)], 1); }
        assert!(quota.fits(0, &[(0, 1)], 1));
        assert!(!quota.fits(0, &[(KEYS as u64, 1)], 1));
        assert!(quota.fits(MINUTE, &[(KEYS as u64, 1)], 1));
    }

    #[tokio::test]
    async fn requests_at_once_are_bounded_and_refused_busy() {
        let dir = tempfile::tempdir().unwrap();
        let policy = Policy { requests_at_once: 1, ..Policy::default() };
        let service = Service::new(Store::initialize(&dir.path().join("state")).unwrap(), policy);
        service.0.expiry.lock().unwrap().take();
        let body = serde_json::to_vec(&Read { capability: [1; 32], after: 0 }).unwrap();
        let held = service.slot().await.unwrap();
        let answer = service.post(Route::Read, "192.0.2.1".parse().unwrap(), &body).await.unwrap();
        assert!(matches!(serde_json::from_slice::<Answer<Page>>(&answer).unwrap(), Answer::Refused { refusal: Refusal::Busy, .. }));
        drop(held);
        let answer = service.post(Route::Read, "192.0.2.1".parse().unwrap(), &body).await.unwrap();
        assert!(matches!(serde_json::from_slice::<Answer<Page>>(&answer).unwrap(), Answer::Ok(_)));
    }

    #[tokio::test]
    async fn running_db_work_is_not_cut_off() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        let service = Service::new(Store::initialize(&path).unwrap(), Policy::default());
        service.0.expiry.lock().unwrap().take();
        let (release, wait) = std::sync::mpsc::channel();
        let running = tokio::spawn({
            let service = service.clone();
            async move { service.work(move |_| { wait.recv().unwrap(); Ok(()) }).await }
        });
        tokio::time::sleep(DB_WAIT + Duration::from_millis(500)).await;
        release.send(()).unwrap();
        running.await.unwrap().unwrap();
        drop(service);
    }

    #[tokio::test]
    async fn blocking_work_is_bounded_and_cancellation_does_not_free_running_slots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        let service = Service::new(Store::initialize(&path).unwrap(), Policy::default());
        service.0.expiry.lock().unwrap().take();
        let mut jobs = Vec::new();
        let mut releases = Vec::new();
        for _ in 0..DB_WORK {
            let (entered, inside) = tokio::sync::oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel();
            let service = service.clone();
            jobs.push(tokio::spawn(async move { service.work(move |_| { entered.send(()).unwrap(); wait.recv().unwrap(); Ok(()) }).await }));
            inside.await.unwrap();
            releases.push(release);
        }
        assert_eq!(service.work(|_| Ok(())).await.unwrap_err().downcast::<Refused>().unwrap().0, "busy");
        assert_eq!(service.stats().await.unwrap_err().downcast::<Refused>().unwrap().0, "busy");
        for job in &jobs { job.abort(); }
        for job in jobs { assert!(job.await.unwrap_err().is_cancelled()); }
        assert_eq!(service.0.work.available_permits(), 0);
        for release in releases { release.send(()).unwrap(); }
        let all = service.0.work.acquire_many(DB_WORK as u32).await.unwrap();
        drop(all);
        drop(service);
    }
}
