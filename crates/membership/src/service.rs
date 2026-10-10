//! The membership service over iroh: `membership` streams on the `letmeknow/1` ALPN.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use iroh::protocol::{AcceptError, ProtocolHandler};
use lmk_proto::{
    Answer, Bytes,
    clock::now,
    frame,
    frame::{Open, Stream},
    membership::{Latest, Notice, Request},
};
use lmk_transport::{Conn, IrohConnection, RecvStream, SendStream};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::store::Store;

/// What the service accepts. Anyone may create a log, by appending to it.
#[derive(Clone, Debug)]
pub struct Policy {
    pub max_entry: usize,
    pub max_log_id: usize,
    pub appends_per_minute: u32,
    pub page_bytes: usize,
    pub retention: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_entry: 1 << 20,
            max_log_id: 64,
            appends_per_minute: 60,
            page_bytes: 4 << 20,
            retention: Duration::from_secs(365 * 24 * 3600),
        }
    }
}

#[derive(Clone)]
pub struct Service(Arc<Inner>);

struct Inner {
    store: Store,
    policy: Policy,
    subscribers: Mutex<Subscribers>,
}

/// How many notices a subscription may fall behind before it is dropped; its client subscribes again and reads.
const LAG: usize = 1024;

/// The subscriptions, by id, and the ids subscribed to each log: an append wakes only its log's.
#[derive(Default)]
struct Subscribers {
    next: u64,
    senders: HashMap<u64, mpsc::Sender<Arc<Notice>>>,
    logs: HashMap<Bytes, HashSet<u64>>,
}

impl Subscribers {
    fn add(&mut self, sender: mpsc::Sender<Arc<Notice>>) -> u64 {
        self.next += 1;
        self.senders.insert(self.next, sender);
        self.next
    }

    fn set(&mut self, id: u64, logs: Vec<Bytes>) {
        for subscribed in self.logs.values_mut() {
            subscribed.remove(&id);
        }
        if self.senders.contains_key(&id) {
            for log in logs {
                self.logs.entry(log).or_default().insert(id);
            }
        }
        self.logs.retain(|_, subscribed| !subscribed.is_empty());
    }

    fn remove(&mut self, id: u64) {
        self.senders.remove(&id);
        self.set(id, Vec::new());
    }

    fn notify(&mut self, notice: Arc<Notice>) {
        let ids: Vec<u64> = self.logs.get(&notice.log).into_iter().flatten().copied().collect();
        for id in ids {
            if self.senders[&id].try_send(notice.clone()).is_err() {
                self.remove(id);
            }
        }
    }
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Service")
    }
}

impl Service {
    /// Serves `store`, and expires its entries hourly.
    pub fn new(store: Store, policy: Policy) -> Self {
        let service = Service(Arc::new(Inner {
            store,
            policy,
            subscribers: Mutex::default(),
        }));
        let weak = Arc::downgrade(&service.0);
        tokio::spawn(async move {
            let mut hourly = tokio::time::interval(Duration::from_secs(3600));
            loop {
                hourly.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                let before = now().saturating_sub(inner.policy.retention.as_millis() as u64);
                if let Err(err) = inner.store.expire(before) {
                    tracing::warn!("expiring entries: {err:#}");
                }
            }
        });
        service
    }

    async fn stream(&self, mut send: SendStream, mut recv: RecvStream, appends: &Mutex<Window>) -> Result<()> {
        let open: Open = frame::read(&mut recv).await?;
        if open.stream != Stream::Membership {
            return Ok(());
        }
        let (store, policy) = (&self.0.store, &self.0.policy);
        let Ok(request) = serde_json::from_slice(&frame::read_body(&mut recv).await?) else {
            frame::write(&mut send, &refused::<()>("unknown request")).await?;
            send.shutdown().await?;
            return Ok(());
        };
        match request {
            Request::Append { log, entries } => {
                let answer = if entries.iter().any(|entry| entry.0.len() > policy.max_entry) {
                    refused("size")
                } else if log.0.len() > policy.max_log_id || entries.is_empty() {
                    refused("policy")
                } else if !appends.lock().unwrap().take(policy.appends_per_minute) {
                    refused("rate")
                } else {
                    let appended = store.append(&log.0, &entries)?;
                    let last = appended.position + entries.len() as u64 - 1;
                    let mut subscribers = self.0.subscribers.lock().unwrap();
                    for (position, entry) in (appended.position..).zip(entries) {
                        // Each notice's head covers its own entry, as a read of it would.
                        let head = if position == last { appended.head.clone() } else { store.head_at(&log.0, position)? };
                        subscribers.notify(Arc::new(Notice { log: log.clone(), position, entry, head }));
                    }
                    Answer::Ok(appended)
                };
                frame::write(&mut send, &answer).await?;
            }
            Request::Read { log, after } => {
                let answer = match store.read(&log.0, after, policy.page_bytes)? {
                    Some(page) => Answer::Ok(page),
                    None => refused("expired"),
                };
                frame::write(&mut send, &answer).await?;
            }
            Request::Head { log } => {
                frame::write(
                    &mut send,
                    &Answer::Ok(Latest {
                        head: store.head(&log.0)?,
                    }),
                )
                .await?;
            }
            Request::Subscribe { logs } => return self.subscribe(send, recv, logs).await,
        }
        send.shutdown().await?;
        Ok(())
    }

    async fn subscribe(&self, send: SendStream, mut recv: RecvStream, logs: Vec<Bytes>) -> Result<()> {
        let (sender, notices) = mpsc::channel(LAG);
        let id = {
            let mut subscribers = self.0.subscribers.lock().unwrap();
            let id = subscribers.add(sender);
            subscribers.set(id, logs);
            id
        };
        let (requests, changes) = mpsc::channel(1);
        tokio::spawn(async move {
            while let Ok(request) = frame::read_known::<Request, _>(&mut recv).await
                && requests.send(request).await.is_ok()
            {}
        });
        let served = self.notices(id, send, notices, changes).await;
        self.0.subscribers.lock().unwrap().remove(id);
        served
    }

    async fn notices(
        &self,
        id: u64,
        mut send: SendStream,
        mut notices: mpsc::Receiver<Arc<Notice>>,
        mut changes: mpsc::Receiver<Request>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                biased;
                notice = notices.recv() => match notice {
                    Some(notice) => frame::write(&mut send, &*notice).await?,
                    None => anyhow::bail!("the subscription fell behind"),
                },
                request = changes.recv() => match request {
                    Some(Request::Subscribe { logs }) => self.0.subscribers.lock().unwrap().set(id, logs),
                    Some(_) => anyhow::bail!("only subscribe on a subscription"),
                    None => return Ok(()),
                },
            }
        }
    }
}

fn refused<T>(reason: &str) -> Answer<T> {
    Answer::Refused { refused: reason.into() }
}

/// Appends counted per connection, in fixed one-minute windows.
struct Window {
    start: Instant,
    count: u32,
}

impl Window {
    fn take(&mut self, limit: u32) -> bool {
        if self.start.elapsed() >= Duration::from_secs(60) {
            *self = Window {
                start: Instant::now(),
                count: 0,
            };
        }
        self.count += 1;
        self.count <= limit
    }
}

impl Service {
    /// Serves a connection's streams until it closes.
    pub async fn accept(&self, conn: Conn) {
        let appends = Arc::new(Mutex::new(Window {
            start: Instant::now(),
            count: 0,
        }));
        while let Ok((send, recv)) = conn.accept_bi().await {
            let (service, appends) = (self.clone(), appends.clone());
            tokio::spawn(async move {
                if let Err(err) = service.stream(send, recv, &appends).await {
                    tracing::debug!("membership stream: {err:#}");
                }
            });
        }
    }
}

impl ProtocolHandler for Service {
    async fn accept(&self, conn: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        Service::accept(self, Arc::new(IrohConnection(conn))).await;
        Ok(())
    }
}
