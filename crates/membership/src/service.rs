//! Bounded membership work. Only capabilities cross the service request boundary.

use std::{collections::HashMap, hash::Hash, net::{IpAddr, Ipv4Addr}, sync::{Arc, Mutex}, time::Duration};

use anyhow::{Result, ensure};
use ed25519_dalek::Signer;
use lmk_proto::{Bytes, clock::now, membership::{Answer, Append, Appended, Expiry, Heads, Known, Moved, Page, Read, Refusal, expiry_message, refusal_message}};
use n0_future::task::AbortOnDropHandle;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{sync::Semaphore, time::timeout};

use crate::{Expired, Refused, store::{DAY_MS, DISK_BYTES, Log, Stats, Store}};

const DB_WORK: usize = 4;
/// How long a request waits for a slot of `DB_WORK` before it is refused as busy. Work that started runs to its end: a
/// refusal tells the client the work was not done.
const DB_WAIT: Duration = Duration::from_secs(2);
const MINUTE: u64 = 60_000;
/// The largest entry a public log takes.
const PUBLIC_ENTRY: usize = 16 << 10;
/// A /48's budget, in /64s.
const WIDE: u64 = 16;
/// Keys a quota tracks at once: a source past them is refused, so a flood of addresses cannot grow memory.
const KEYS: usize = 1 << 20;
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
    pub new_public_logs_per_day: u64,
    /// Stored entries a day to each public log.
    pub public_appends_per_day: u64,
    /// Per source: an IPv4 address, a /64, and a /48 at `WIDE` times as many.
    pub requests_at_once: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            appends_per_minute: 600, retention_days: 30, disk: DISK_BYTES,
            append_bytes_per_day: 256 << 20, reads_per_minute: 600, read_bytes_per_minute: 64 << 20,
            new_logs_per_day: 2_000, new_public_logs_per_day: 10, public_appends_per_day: 10,
            requests_at_once: 8,
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
    in_flight: Mutex<HashMap<Source, u64>>,
    work: Arc<Semaphore>,
    expiry: Mutex<Option<AbortOnDropHandle<()>>>,
}

/// What each key spent in the current window of `period` milliseconds, against `limit` times its scale.
struct Quota<K> {
    period: u64,
    limit: u64,
    window: u64,
    spent: HashMap<K, u64>,
    /// The /64s each /48 tracks in `spent`.
    nets: HashMap<u64, u64>,
}

trait Key: Clone + Eq + Hash {
    fn net48(&self) -> Option<u64> { None }
}

impl Key for ([u8; 32], Source) {
    fn net48(&self) -> Option<u64> { self.1.net48() }
}

impl<K: Key> Quota<K> {
    fn new(period: u64, limit: u64) -> Self { Self { period, limit, window: 0, spent: HashMap::new(), nets: HashMap::new() } }

    fn tracks(&self, key: &K) -> bool {
        self.spent.contains_key(key) || key.net48().is_none_or(|net| self.nets.get(&net).copied().unwrap_or(0) < NETS)
    }

    fn fits(&mut self, at: u64, keys: &[(K, u64)], amount: u64) -> bool {
        self.roll(at);
        let full = self.spent.len() >= KEYS;
        keys.iter().filter(|(key, _)| self.tracks(key)).all(|(key, scale)| {
            (!full || self.spent.contains_key(key)) && self.spent.get(key).copied().unwrap_or(0) + amount <= self.limit * scale
        })
    }

    fn charge(&mut self, at: u64, keys: &[(K, u64)], amount: u64) {
        self.roll(at);
        for (key, _) in keys {
            if !self.tracks(key) { continue; }
            if let Some(net) = key.net48().filter(|_| !self.spent.contains_key(key)) { *self.nets.entry(net).or_default() += 1; }
            *self.spent.entry(key.clone()).or_default() += amount;
        }
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
            self.nets.clear();
        }
    }
}

/// What an address's budgets are drawn from: an IPv4 address, mapped or not; an IPv6 address's /64, and its /48.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Source { V4(Ipv4Addr), Net64(u64), Net48(u64) }

impl Key for Source {
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
    appends: Quota<Source>,
    append_bytes: Quota<Source>,
    reads: Quota<Source>,
    read_bytes: Quota<Source>,
    new_logs: Quota<Source>,
    new_public_logs: Quota<Source>,
    public_appends: Quota<([u8; 32], Source)>,
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
        }
    }
}

/// A request counted in flight from its sources until it is dropped.
pub struct Admission { sources: Vec<(Source, u64)>, service: Arc<Inner> }

impl Drop for Admission {
    fn drop(&mut self) {
        let mut in_flight = self.service.in_flight.lock().unwrap();
        for (source, _) in &self.sources {
            let count = in_flight.get_mut(source).unwrap();
            *count -= 1;
            if *count == 0 { in_flight.remove(source); }
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
            store, budgets: Mutex::new(Budgets::new(&policy)), in_flight: Mutex::default(), policy,
            work: Arc::new(Semaphore::new(DB_WORK)), expiry: Mutex::default(),
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

    pub async fn stats(&self) -> Result<Stats> { self.work(|inner| inner.store.stats()).await }

    /// One pass of expiry, as `Store::expire` runs it; whether more is left.
    pub async fn expire(&self) -> bool {
        let before = (now() / DAY_MS).saturating_sub(self.0.policy.retention_days);
        match self.work(move |inner| inner.store.expire(before)).await {
            Ok(more) => more,
            Err(_) => {
                tracing::warn!("membership expiry deferred");
                false
            }
        }
    }

    /// Counts a request from `from` in flight, unless one of its sources already has its requests at once.
    pub fn admit(&self, from: IpAddr) -> Option<Admission> {
        let sources = sources(from);
        let at_once = self.0.policy.requests_at_once as u64;
        let mut in_flight = self.0.in_flight.lock().unwrap();
        if sources.iter().any(|(source, scale)| in_flight.get(source).copied().unwrap_or(0) >= at_once * scale) { return None; }
        for (source, _) in &sources { *in_flight.entry(*source).or_default() += 1; }
        Some(Admission { sources, service: self.0.clone() })
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
        let Append { capability, entries, public } = decode(body)?;
        ensure!(!public || entries.iter().all(|e| e.0.len() <= PUBLIC_ENTRY), Refused("size".into()));
        let log = self.0.store.log(&capability);
        let bytes: u64 = entries.iter().map(|e| e.0.len() as u64).sum();
        let count = entries.len() as u64;
        {
            let mut budgets = self.0.budgets.lock().unwrap();
            ensure!(budgets.appends.take(at, sources, 1) && budgets.append_bytes.take(at, sources, bytes), Refused("rate".into()));
        }
        if public && count == 1 {
            let entry = entries[0].0.clone();
            if let Some(touched) = self.work({ let log = log.clone(); move |inner| inner.store.touch(&log, &entry) }).await? {
                return Ok(touched);
            }
        }
        let per_log: Vec<_> = sources.iter().map(|(source, scale)| ((log.reference, *source), *scale)).collect();
        let may_start = {
            let mut budgets = self.0.budgets.lock().unwrap();
            ensure!(!public || budgets.public_appends.fits(at, &per_log, count), Refused("rate".into()));
            budgets.new_logs.fits(at, sources, 1) && (!public || budgets.new_public_logs.fits(at, sources, 1))
        };
        let (appended, stored) = self.work({ let log = log.clone(); move |inner| {
            ensure!(may_start || inner.store.length(&log)? > 0, Refused("rate".into()));
            inner.store.append(&log, &entries, public)
        } }).await?;
        let mut budgets = self.0.budgets.lock().unwrap();
        if public { budgets.public_appends.charge(at, &per_log, stored); }
        if appended.position == 1 {
            budgets.new_logs.charge(at, sources, 1);
            if public { budgets.new_public_logs.charge(at, sources, 1); }
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
        let mut quota = Quota::new(MINUTE, 2);
        let v4 = |key: usize| Source::V4(Ipv4Addr::from(key as u32));
        for key in 0..KEYS { quota.charge(0, &[(v4(key), 1)], 1); }
        assert!(quota.fits(0, &[(v4(0), 1)], 1));
        assert!(!quota.fits(0, &[(v4(KEYS), 1)], 1));
        assert!(quota.fits(MINUTE, &[(v4(KEYS), 1)], 1));
    }

    #[test]
    fn a_net48_tracks_only_some_of_its_nets() {
        let mut quota = Quota::new(MINUTE, 2);
        let net64 = |i: u32| sources(format!("2001:db8:0:{i:x}::1").parse().unwrap());
        for i in 0..1_000 { quota.charge(0, &net64(i), 1); }
        assert_eq!(quota.spent.len(), 1 + NETS as usize);
        assert!(quota.fits(0, &sources("192.0.2.1".parse().unwrap()), 1));
    }

    #[tokio::test]
    async fn requests_at_once_are_counted_per_source() {
        let dir = tempfile::tempdir().unwrap();
        let service = Service::new(Store::initialize(&dir.path().join("state")).unwrap(), Policy { requests_at_once: 1, ..Policy::default() });
        service.0.expiry.lock().unwrap().take();
        let one: IpAddr = "192.0.2.1".parse().unwrap();
        let held = service.admit(one).unwrap();
        assert!(service.admit(one).is_none());
        assert!(service.admit("192.0.2.2".parse().unwrap()).is_some());
        drop(held);
        assert!(service.admit(one).is_some());
        let net64 = |i: u32| -> IpAddr { format!("2001:db8:0:{i:x}::1").parse().unwrap() };
        let wide: Vec<_> = (0..WIDE as u32).map(|i| service.admit(net64(i)).unwrap()).collect();
        assert!(service.admit(net64(WIDE as u32)).is_none());
        assert!(service.admit("2001:db9::1".parse().unwrap()).is_some());
        drop(wide);
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
