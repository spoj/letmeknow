//! The membership service over iroh: `membership` streams on the `letmeknow/1` ALPN.

use std::{
    collections::HashSet,
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
use tokio::sync::{broadcast, mpsc};
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
    notices: broadcast::Sender<Arc<Notice>>,
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
            notices: broadcast::channel(1024).0,
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
            Request::Append { log, entry } => {
                let answer = if entry.0.len() > policy.max_entry {
                    refused("size")
                } else if log.0.len() > policy.max_log_id {
                    refused("policy")
                } else if !appends.lock().unwrap().take(policy.appends_per_minute) {
                    refused("rate")
                } else {
                    let appended = store.append(&log.0, &entry.0)?;
                    let notice = Notice {
                        log,
                        position: appended.position,
                        entry,
                        head: appended.head.clone(),
                    };
                    let _ = self.0.notices.send(Arc::new(notice));
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

    async fn subscribe(&self, mut send: SendStream, mut recv: RecvStream, logs: Vec<Bytes>) -> Result<()> {
        let mut notices = self.0.notices.subscribe();
        let mut logs: HashSet<Bytes> = logs.into_iter().collect();
        let (requests, mut changes) = mpsc::channel(1);
        tokio::spawn(async move {
            while let Ok(request) = frame::read_known::<Request, _>(&mut recv).await
                && requests.send(request).await.is_ok()
            {}
        });
        loop {
            tokio::select! {
                biased;
                notice = notices.recv() => {
                    let notice = notice?;
                    if logs.contains(&notice.log) {
                        frame::write(&mut send, &*notice).await?;
                    }
                }
                request = changes.recv() => match request {
                    Some(Request::Subscribe { logs: new }) => logs = new.into_iter().collect(),
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
