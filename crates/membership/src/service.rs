//! Bounded membership work. Only capabilities cross the service request boundary.

use std::{collections::BTreeMap, sync::{Arc, Mutex}, time::Duration};

use anyhow::{Result, ensure};
use iroh::{endpoint::{Connection, RecvStream, SendStream}, protocol::{AcceptError, ProtocolHandler}};
use lmk_proto::{clock::now, frame::{self, Open, Stream}, head::{self, Head}, membership::{self, Latest, Refusal, Reply, Request, Subscribed}};
use n0_future::task::AbortOnDropHandle;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::{OwnedSemaphorePermit, Semaphore, mpsc}, time::{Instant, timeout}};

use crate::{Refused, store::{DAY_MS, Stats, Store}};

pub const MAX_CONNECTIONS: usize = 64;
pub const MAX_STREAMS: usize = 64;
pub const CONNECTION_STREAMS: usize = 8;
pub const DB_WORK: usize = 4;
pub const MAX_SUBSCRIBERS: usize = 64;
pub const LAG: usize = 8;
pub const DB_DEADLINE: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct Policy {
    pub appends_per_minute: u32,
    pub retention_days: u64,
}

impl Default for Policy {
    fn default() -> Self { Self { appends_per_minute: 600, retention_days: 365 } }
}

#[derive(Clone)]
pub struct Service(Arc<Inner>);

struct Inner {
    store: Store,
    policy: Policy,
    subscribers: Mutex<Subscribers>,
    connections: Semaphore,
    streams: Arc<Semaphore>,
    work: Arc<Semaphore>,
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

struct Registration { inner: Arc<Inner>, id: u64 }
impl Drop for Registration {
    fn drop(&mut self) { self.inner.subscribers.lock().unwrap().records.remove(&self.id); }
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Service") }
}

impl Service {
    pub fn new(store: Store, policy: Policy) -> Self {
        let service = Self(Arc::new(Inner {
            store, policy, subscribers: Mutex::default(), connections: Semaphore::new(MAX_CONNECTIONS),
            streams: Arc::new(Semaphore::new(MAX_STREAMS)), work: Arc::new(Semaphore::new(DB_WORK)), expiry: Mutex::default(),
        }));
        let weak = Arc::downgrade(&service.0);
        let expiry = n0_future::task::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                let before = (now() / DAY_MS).saturating_sub(inner.policy.retention_days);
                if Service(inner).work(move |store| store.expire(before)).await.is_err() {
                    tracing::warn!("membership expiry deferred");
                }
            }
        });
        *service.0.expiry.lock().unwrap() = Some(AbortOnDropHandle::new(expiry));
        service
    }

    async fn work<T: Send + 'static>(&self, f: impl FnOnce(&Store) -> Result<T> + Send + 'static) -> Result<T> {
        let permit = self.0.work.clone().try_acquire_owned().map_err(|_| Refused("busy".into()))?;
        let inner = self.0.clone();
        timeout(DB_DEADLINE, tokio::task::spawn_blocking(move || { let _permit = permit; f(&inner.store) }))
            .await.map_err(|_| Refused("busy".into()))??
    }

    pub async fn stats(&self) -> Result<Stats> { self.work(Store::stats).await }

    async fn stream(&self, mut send: SendStream, mut recv: RecvStream, appends: &Mutex<Window>, work_slot: OwnedSemaphorePermit) -> Result<()> {
        let request = timeout(Duration::from_secs(15), async {
            let open: Open = membership::read_frame(&mut recv).await?;
            ensure!(open.stream == Stream::Membership, "unexpected stream");
            membership::read_frame::<Request, _>(&mut recv).await
        }).await?;
        let request = match request {
            Ok(request) => request,
            Err(_) => {
                reply::<()>(&mut send, Err(Refused("policy".into()).into())).await?;
                send.shutdown().await?;
                return Ok(());
            }
        };
        let service = self.0.store.key().verifying_key().to_bytes();
        match request {
            Request::Append { capability, entries, public } => {
                let d = head::reference(&service, &capability);
                let answer = if !appends.lock().unwrap().take(self.0.policy.appends_per_minute) {
                    Err(Refused("rate".into()).into())
                } else {
                    self.work(move |store| store.append(&d, &entries, public)).await
                };
                if let Ok(appended) = &answer { self.0.subscribers.lock().unwrap().notify(&appended.head); }
                reply(&mut send, answer).await?;
            }
            Request::Read { capability, after } => {
                let d = head::reference(&service, &capability);
                reply(&mut send, self.work(move |store| store.read(&d, after)).await).await?;
            }
            Request::Head { capability } => {
                let d = head::reference(&service, &capability);
                reply(&mut send, self.work(move |store| Ok(Latest { head: store.head(&d)? })).await).await?;
            }
            Request::Subscribe { capabilities } => {
                drop(work_slot);
                let refs = capabilities.iter().map(|c| head::reference(&service, c)).collect();
                return self.subscribe(send, recv, refs).await;
            }
        }
        send.shutdown().await?;
        Ok(())
    }

    async fn subscribe(&self, mut send: SendStream, mut recv: RecvStream, refs: Vec<[u8; 32]>) -> Result<()> {
        let (sender, mut notices) = mpsc::channel(LAG);
        let id = self.0.subscribers.lock().unwrap().add(refs.clone(), sender);
        let id = match id {
            Ok(id) => id,
            Err(error) => { reply::<Subscribed>(&mut send, Err(error)).await?; return Ok(()); }
        };
        let _registration = Registration { inner: self.0.clone(), id };
        let forward = async {
            reply(&mut send, Ok(Subscribed {})).await?;
            for d in refs {
                reply(&mut send, self.work(move |store| Ok(Latest { head: store.head(&d)? })).await).await?;
            }
            while let Some(head) = notices.recv().await { reply(&mut send, Ok(Latest { head })).await?; }
            anyhow::bail!("membership subscription lagged")
        };
        tokio::select! {
            result = forward => result,
            _ = recv.read_u8() => Ok(()),
        }
    }
}

async fn reply<T: serde::Serialize>(send: &mut SendStream, result: Result<T>) -> Result<()> {
    let answer = match result {
        Ok(value) => Reply::Ok(value),
        Err(error) => {
            let Some(Refused(code)) = error.downcast_ref::<Refused>() else { return Err(error) };
            let code = match code.as_str() {
                "policy" => Refusal::Policy, "size" => Refusal::Size, "rate" => Refusal::Rate,
                "busy" => Refusal::Busy, "quota" => Refusal::Quota, "expired" => Refusal::Expired,
                _ => return Err(error),
            };
            Reply::Refused(code)
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
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                stream = conn.accept_bi() => {
                    let Ok((send, recv)) = stream else { break };
                    while tasks.try_join_next().is_some() {}
                    if tasks.len() >= CONNECTION_STREAMS { continue; }
                    let Ok(global) = self.0.streams.clone().try_acquire_owned() else { continue };
                    let (service, appends) = (self.clone(), appends.clone());
                    tasks.spawn(async move {
                        if service.stream(send, recv, &appends, global).await.is_err() { tracing::debug!("membership stream ended"); }
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

    #[tokio::test]
    async fn timed_out_db_jobs_keep_their_slots_until_the_work_ends() {
        let path = std::env::temp_dir().join(format!("lmk-deadline-{}", hex::encode(lmk_proto::random::random::<16>())));
        let service = Service::new(Store::initialize(&path).unwrap(), Policy::default());
        service.0.expiry.lock().unwrap().take();
        let (release, wait) = std::sync::mpsc::channel();
        let result = service.work(move |_| { wait.recv().unwrap(); Ok(()) }).await;
        assert_eq!(result.unwrap_err().downcast::<Refused>().unwrap().0, "busy");
        assert_eq!(service.0.work.available_permits(), DB_WORK - 1);
        release.send(()).unwrap();
        drop(service.0.work.acquire_many(DB_WORK as u32).await.unwrap());
        service.stats().await.unwrap();
        drop(service);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[tokio::test]
    async fn blocking_work_is_bounded_and_cancellation_does_not_free_running_slots() {
        let path = std::env::temp_dir().join(format!("lmk-work-{}", hex::encode(lmk_proto::random::random::<16>())));
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
        std::fs::remove_dir_all(path).unwrap();
    }
}
