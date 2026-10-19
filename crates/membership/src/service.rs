//! Bounded membership work. Only capabilities cross the service request boundary.

use std::{collections::HashMap, net::{IpAddr, Ipv4Addr}, sync::{Arc, Mutex}, time::Duration};

use anyhow::{Result, ensure};
use ed25519_dalek::Signer;
use lmk_proto::{Bytes, clock::now, membership::{Answer, Append, Appended, Expiry, HEAD_LOGS, Heads, Known, MAX_BODY, Moved, Page, Read, Refusal, expiry_message, refusal_message}};
use n0_future::task::AbortOnDropHandle;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{sync::Semaphore, time::timeout};

use crate::{Expired, Refused, store::{DAY_MS, DISK_BYTES, Log, Store}};

/// How long a request waits for a slot of `Policy::db_work` before it is refused as busy. Work that started runs to its end: a
/// refusal tells the client the work was not done.
const DB_WAIT: Duration = Duration::from_secs(2);
const MINUTE: u64 = 60_000;
/// A /48's budget, in /64s.
const WIDE: u64 = 16;
/// /64s a /48 tracks in one window of a quota: past them, its /64s are charged to the /48 alone.
const NETS: u64 = 16;

#[derive(Clone, Debug)]
pub struct Policy {
    pub retention_days: u64,
    pub disk: u64,
    /// Per address from here down.
    pub appends_per_minute: u32,
    pub append_bytes_per_day: u64,
    pub reads_per_minute: u32,
    pub read_bytes_per_minute: u64,
    pub new_logs_per_day: u64,
    /// Per source: an IPv4 address, a /64, and a /48 at `WIDE` times as many.
    pub requests_at_once: usize,
    /// Bodies and answers in flight, a body counted twice: as bytes and as its decoded value.
    pub bytes_at_once: u64,
    /// Over all addresses.
    pub bytes_at_once_in_all: u64,
    /// Requests that work on the database at once.
    pub db_work: usize,
    /// Sources each quota tracks at once: a source past them is refused, so a flood of addresses cannot grow memory.
    pub sources: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            appends_per_minute: 600, retention_days: 7, disk: DISK_BYTES,
            append_bytes_per_day: 256 << 20, reads_per_minute: 600, read_bytes_per_minute: 64 << 20,
            new_logs_per_day: 2_000,
            requests_at_once: 8, bytes_at_once: 16 << 20, bytes_at_once_in_all: 256 << 20,
            db_work: 4, sources: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Route { Append, Read, Heads }

impl Route {
    pub fn parse(path: &str) -> Option<Self> {
        match path {
            "/membership/5/append" => Some(Self::Append),
            "/membership/5/read" => Some(Self::Read),
            "/membership/5/heads" => Some(Self::Heads),
            _ => None,
        }
    }

    /// The most an answer takes: a page, or a few signed heads.
    fn answer_bytes(self) -> u64 {
        match self {
            Self::Read => MAX_BODY as u64,
            Self::Heads => (HEAD_LOGS << 10) as u64,
            Self::Append => 4 << 10,
        }
    }
}

#[derive(Clone)]
pub struct Service(Arc<Inner>);

struct Inner {
    store: Store,
    policy: Policy,
    budgets: Mutex<Budgets>,
    in_flight: Mutex<InFlight>,
    work: Arc<Semaphore>,
    expiry: Mutex<Option<AbortOnDropHandle<()>>>,
}

/// What each key spent in the current window of `period` milliseconds, against `limit` times its scale.
struct Quota {
    period: u64,
    limit: u64,
    sources: usize,
    window: u64,
    spent: HashMap<Source, u64>,
    /// The /64s each /48 tracks in `spent`.
    nets: HashMap<u64, u64>,
}

impl Quota {
    fn new(period: u64, limit: u64, sources: usize) -> Self { Self { period, limit, sources, window: 0, spent: HashMap::new(), nets: HashMap::new() } }

    fn tracks(&self, key: &Source) -> bool {
        self.spent.contains_key(key) || key.net48().is_none_or(|net| self.nets.get(&net).copied().unwrap_or(0) < NETS)
    }

    fn fits(&mut self, at: u64, keys: &[(Source, u64)], amount: u64) -> bool {
        self.roll(at);
        let full = self.spent.len() >= self.sources;
        keys.iter().filter(|(key, _)| self.tracks(key)).all(|(key, scale)| {
            (!full || self.spent.contains_key(key)) && self.spent.get(key).copied().unwrap_or(0) + amount <= self.limit * scale
        })
    }

    fn charge(&mut self, at: u64, keys: &[(Source, u64)], amount: u64) {
        self.roll(at);
        for (key, _) in keys {
            if !self.tracks(key) { continue; }
            if let Some(net) = key.net48().filter(|_| !self.spent.contains_key(key)) { *self.nets.entry(net).or_default() += 1; }
            *self.spent.entry(*key).or_default() += amount;
        }
    }

    fn take(&mut self, at: u64, keys: &[(Source, u64)], amount: u64) -> bool {
        let fits = self.fits(at, keys, amount);
        if fits { self.charge(at, keys, amount); }
        fits
    }

    fn roll(&mut self, at: u64) {
        if at / self.period != self.window {
            self.window = at / self.period;
            self.spent.clear();
            self.nets.clear();
        }
    }
}

/// What an address's budgets are drawn from: an IPv4 address, mapped or not; an IPv6 address's /64, and its /48.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Source { V4(Ipv4Addr), Net64(u64), Net48(u64) }

impl Source {
    fn net48(&self) -> Option<u64> {
        match self { Source::Net64(net) => Some(net >> 16), _ => None }
    }
}

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
    appends: Quota,
    append_bytes: Quota,
    reads: Quota,
    read_bytes: Quota,
    new_logs: Quota,
}

impl Budgets {
    fn new(policy: &Policy) -> Self {
        Self {
            appends: Quota::new(MINUTE, policy.appends_per_minute.into(), policy.sources),
            append_bytes: Quota::new(DAY_MS, policy.append_bytes_per_day, policy.sources),
            reads: Quota::new(MINUTE, policy.reads_per_minute.into(), policy.sources),
            read_bytes: Quota::new(MINUTE, policy.read_bytes_per_minute, policy.sources),
            new_logs: Quota::new(DAY_MS, policy.new_logs_per_day, policy.sources),
        }
    }
}

#[derive(Default)]
struct InFlight { bytes: u64, sources: HashMap<Source, Held> }

#[derive(Default, Clone, Copy)]
struct Held { requests: u64, bytes: u64 }

/// A request and its bytes, counted in flight from its sources until it is dropped.
pub struct Admission { sources: Vec<(Source, u64)>, bytes: u64, service: Arc<Inner> }

impl Admission {
    /// Keeps `bytes` of those admitted, once only the answer is left.
    pub fn keep(&mut self, bytes: usize) {
        let freed = self.bytes - bytes as u64;
        self.bytes = bytes as u64;
        let mut in_flight = self.service.in_flight.lock().unwrap();
        in_flight.bytes -= freed;
        for (source, _) in &self.sources { in_flight.sources.get_mut(source).unwrap().bytes -= freed; }
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        let mut in_flight = self.service.in_flight.lock().unwrap();
        in_flight.bytes -= self.bytes;
        for (source, _) in &self.sources {
            let held = in_flight.sources.get_mut(source).unwrap();
            held.requests -= 1;
            held.bytes -= self.bytes;
            if held.requests == 0 { in_flight.sources.remove(source); }
        }
    }
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Service") }
}

impl Service {
    pub fn new(mut store: Store, policy: Policy) -> Self {
        store.disk = policy.disk;
        let service = Self(Arc::new(Inner {
            store, budgets: Mutex::new(Budgets::new(&policy)), in_flight: Mutex::default(),
            work: Arc::new(Semaphore::new(policy.db_work)), expiry: Mutex::default(), policy,
        }));
        let weak = Arc::downgrade(&service.0);
        let expiry = n0_future::task::spawn(async move {
            let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(60), Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                let service = Service(inner);
                while service.expire().await {}
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

    /// One pass of expiry, as `Store::expire` runs it; whether more is left.
    pub async fn expire(&self) -> bool {
        let before = now().saturating_sub(self.0.policy.retention_days * DAY_MS);
        match self.work(move |inner| inner.store.expire(before)).await {
            Ok(more) => more,
            Err(_) => {
                tracing::warn!("membership expiry deferred");
                false
            }
        }
    }

    /// Counts a request from `from` to `route` in flight, with a body of `body` bytes and its answer, unless that is
    /// more than the service or one of its sources has room for.
    pub fn admit(&self, from: IpAddr, route: Route, body: usize) -> Option<Admission> {
        let sources = sources(from);
        let bytes = 2 * body as u64 + route.answer_bytes();
        let policy = &self.0.policy;
        let mut in_flight = self.0.in_flight.lock().unwrap();
        let full = |(source, scale): &(Source, u64)| {
            let held = in_flight.sources.get(source).copied().unwrap_or_default();
            held.requests >= policy.requests_at_once as u64 * scale || held.bytes + bytes > policy.bytes_at_once * scale
        };
        if in_flight.bytes + bytes > policy.bytes_at_once_in_all || sources.iter().any(full) { return None; }
        in_flight.bytes += bytes;
        for (source, _) in &sources {
            let held = in_flight.sources.entry(*source).or_default();
            held.requests += 1;
            held.bytes += bytes;
        }
        Some(Admission { sources, bytes, service: self.0.clone() })
    }

    /// Answers one request on the HTTPS routes: the body is the route's, and the answer is an `Answer` as JSON. An error
    /// is the service's own failure, which is no answer.
    pub async fn post(&self, route: Route, admission: &Admission, body: &[u8]) -> Result<Vec<u8>> {
        let sources = &admission.sources;
        let at = now();
        let answer = match route {
            Route::Append => self.answer(body, self.append(sources, at, body).await),
            Route::Read => self.answer(body, self.read(sources, at, body).await),
            Route::Heads => self.answer(body, self.heads(sources, at, body).await),
        }?;
        if !matches!(route, Route::Append) {
            self.0.budgets.lock().unwrap().read_bytes.charge(at, sources, answer.len() as u64);
        }
        Ok(answer)
    }

    async fn append(&self, sources: &[(Source, u64)], at: u64, body: &[u8]) -> Result<Appended> {
        let Append { capability, entries } = decode(body)?;
        let log = self.0.store.log(&capability);
        let bytes: u64 = entries.iter().map(|e| e.0.len() as u64).sum();
        let may_start = {
            let mut budgets = self.0.budgets.lock().unwrap();
            ensure!(budgets.appends.take(at, sources, 1) && budgets.append_bytes.take(at, sources, bytes), Refused("rate".into()));
            budgets.new_logs.fits(at, sources, 1)
        };
        let (appended, started) = self.work(move |inner| {
            let started = !inner.store.records(&log)?;
            ensure!(may_start || !started, Refused("rate".into()));
            Ok((inner.store.append(&log, &entries)?, started))
        }).await?;
        if started {
            self.0.budgets.lock().unwrap().new_logs.charge(at, sources, 1);
        }
        Ok(appended)
    }

    async fn read(&self, sources: &[(Source, u64)], at: u64, body: &[u8]) -> Result<Page> {
        let Read { capability, after } = decode(body)?;
        let log = self.0.store.log(&capability);
        {
            let mut budgets = self.0.budgets.lock().unwrap();
            ensure!(budgets.reads.take(at, sources, 1) && budgets.read_bytes.fits(at, sources, 0), Refused("rate".into()));
        }
        self.work(move |inner| inner.store.read(&log, after)).await
    }

    async fn heads(&self, sources: &[(Source, u64)], at: u64, body: &[u8]) -> Result<Moved> {
        let Heads { logs } = decode(body)?;
        let logs: Vec<(Log, u64)> = logs.iter().map(|Known(capability, length)| (self.0.store.log(capability), *length)).collect();
        {
            let mut budgets = self.0.budgets.lock().unwrap();
            ensure!(budgets.reads.take(at, sources, 1) && budgets.read_bytes.fits(at, sources, 0), Refused("rate".into()));
        }
        let (heads, gone) = self.work(move |inner| inner.store.moved(&logs)).await?;
        let expired = gone.iter().map(|log_ref| Expiry { log_ref: *log_ref, sig: self.expiry(log_ref) }).collect();
        Ok(Moved { heads, expired })
    }

    fn expiry(&self, log_ref: &[u8; 32]) -> Bytes {
        Bytes(self.0.store.key().sign(&expiry_message(log_ref)).to_bytes().to_vec())
    }

    fn answer<T: Serialize>(&self, body: &[u8], result: Result<T>) -> Result<Vec<u8>> {
        let answer = match result {
            Ok(value) => Answer::Ok(value),
            Err(error) => {
                if let Some(Expired(log_ref)) = error.downcast_ref::<Expired>() {
                    Answer::Expired { sig: self.expiry(log_ref) }
                } else {
                    let Some(Refused(code)) = error.downcast_ref::<Refused>() else { return Err(error) };
                    let Some(refusal) = Refusal::from_code(code) else { return Err(error) };
                    let sig = self.0.store.key().sign(&refusal_message(refusal, body));
                    Answer::Refused { refusal, sig: Bytes(sig.to_bytes().to_vec()) }
                }
            }
        };
        Ok(serde_json::to_vec(&answer)?)
    }
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| Refused("policy".into()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quota_refuses_new_keys_past_its_capacity() {
        let mut quota = Quota::new(MINUTE, 2, 100);
        let v4 = |key: usize| Source::V4(Ipv4Addr::from(key as u32));
        for key in 0..100 { quota.charge(0, &[(v4(key), 1)], 1); }
        assert!(quota.fits(0, &[(v4(0), 1)], 1));
        assert!(!quota.fits(0, &[(v4(100), 1)], 1));
        assert!(quota.fits(MINUTE, &[(v4(100), 1)], 1));
    }

    #[test]
    fn a_net48_tracks_only_some_of_its_nets() {
        let mut quota = Quota::new(MINUTE, 2, 1 << 20);
        let net64 = |i: u32| sources(format!("2001:db8:0:{i:x}::1").parse().unwrap());
        for i in 0..1_000 { quota.charge(0, &net64(i), 1); }
        assert_eq!(quota.spent.len(), 1 + NETS as usize);
        assert!(quota.fits(0, &sources("192.0.2.1".parse().unwrap()), 1));
    }

    fn service(policy: Policy) -> (tempfile::TempDir, Service) {
        let dir = tempfile::tempdir().unwrap();
        let service = Service::new(Store::initialize(&dir.path().join("state")).unwrap(), policy);
        service.0.expiry.lock().unwrap().take();
        (dir, service)
    }

    #[tokio::test]
    async fn requests_at_once_are_counted_per_source() {
        let (_dir, service) = service(Policy { requests_at_once: 1, ..Policy::default() });
        let admit = |from: &str| service.admit(from.parse().unwrap(), Route::Heads, 0);
        let held = admit("192.0.2.1").unwrap();
        assert!(admit("192.0.2.1").is_none());
        assert!(admit("::ffff:192.0.2.1").is_none(), "a mapped address counts as its IPv4 address");
        assert!(admit("192.0.2.2").is_some());
        drop(held);
        assert!(admit("192.0.2.1").is_some());
        let wide: Vec<_> = (0..WIDE).map(|i| admit(&format!("2001:db8:0:{i:x}::1")).unwrap()).collect();
        assert!(admit(&format!("2001:db8:0:{WIDE:x}::1")).is_none());
        assert!(admit("2001:db9::1").is_some());
        drop(wide);
    }

    #[tokio::test]
    async fn bytes_in_flight_are_bounded_per_source_until_the_answer_is_dropped() {
        let (_dir, service) = service(Policy::default());
        let one: IpAddr = "192.0.2.1".parse().unwrap();
        let mut held = service.admit(one, Route::Append, MAX_BODY).unwrap();
        assert!(service.admit(one, Route::Append, MAX_BODY).is_none(), "a body counts twice, with its answer");
        assert!(service.admit("192.0.2.2".parse().unwrap(), Route::Append, MAX_BODY).is_some());
        held.keep(100);
        let mut reads: Vec<_> = (0..3).map(|_| service.admit(one, Route::Read, 0).unwrap()).collect();
        assert!(service.admit(one, Route::Read, 0).is_none());
        reads.pop();
        assert!(service.admit(one, Route::Read, 0).is_some());
        drop((held, reads));
    }

    #[tokio::test]
    async fn bytes_in_flight_are_bounded_in_all() {
        let (_dir, service) = service(Policy::default());
        let per = 2 * MAX_BODY as u64 + Route::Append.answer_bytes();
        let admit = |i: u64| service.admit(IpAddr::from(Ipv4Addr::from(i as u32)), Route::Append, MAX_BODY);
        let mut held: Vec<_> = (0..Policy::default().bytes_at_once_in_all / per).map(|i| admit(i).unwrap()).collect();
        assert!(admit(1 << 20).is_none());
        held.pop();
        assert!(admit(1 << 20).is_some());
    }

    #[tokio::test]
    async fn running_db_work_is_not_cut_off() {
        let (_dir, service) = service(Policy::default());
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
        let (_dir, service) = service(Policy::default());
        let mut jobs = Vec::new();
        let mut releases = Vec::new();
        for _ in 0..Policy::default().db_work {
            let (entered, inside) = tokio::sync::oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel();
            let service = service.clone();
            jobs.push(tokio::spawn(async move { service.work(move |_| { entered.send(()).unwrap(); wait.recv().unwrap(); Ok(()) }).await }));
            inside.await.unwrap();
            releases.push(release);
        }
        assert_eq!(service.work(|_| Ok(())).await.unwrap_err().downcast::<Refused>().unwrap().0, "busy");
        for job in &jobs { job.abort(); }
        for job in jobs { assert!(job.await.unwrap_err().is_cancelled()); }
        assert_eq!(service.0.work.available_permits(), 0);
        for release in releases { release.send(()).unwrap(); }
        let all = service.0.work.acquire_many(Policy::default().db_work as u32).await.unwrap();
        drop(all);
        drop(service);
    }
}
