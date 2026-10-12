//! A client with explicit caller-owned trust anchors, never a shared history cache.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use iroh::{Endpoint, EndpointAddr, PublicKey, endpoint::Connection};
use lmk_proto::{
    Bytes, clock, frame::{self, ALPN, Open, Stream}, group::Service, head::{self, Head},
    membership::{self, Appended, Latest, Page, Reply, Request, Subscribed},
};
use n0_future::task::AbortOnDropHandle;
use serde::de::DeserializeOwned;
use tokio::{io::AsyncWriteExt, sync::{Mutex, Semaphore, mpsc}};

use crate::{Contradiction, Forged, Frontier, InvalidProof, Refused, Subscription, Unreached, VerifiedPage, WrongLog};

pub const MAX_IN_FLIGHT: usize = 4;

// Transport errors can include a peer's arbitrary application-close reason.
fn safe_error(error: anyhow::Error) -> anyhow::Error {
    if error.is::<Refused>() || error.is::<Unreached>() || error.is::<Forged>() || error.is::<WrongLog>()
        || error.is::<InvalidProof>() || error.is::<Contradiction>() { error }
    else { anyhow::anyhow!("membership transport interrupted") }
}

fn record_time(sent: u64, head: &Head) -> Result<()> {
    ensure!(head.time <= i64::MAX as u64, InvalidProof);
    clock::heard(sent, clock::now(), head.time);
    Ok(())
}

#[derive(Clone)]
pub struct ServeClient(Arc<Inner>);

struct Inner {
    endpoint: Endpoint,
    addr: EndpointAddr,
    key: [u8; 32],
    conn: Mutex<Option<Connection>>,
    requests: Semaphore,
}

impl ServeClient {
    pub fn new(endpoint: Endpoint, key: &[u8], relay: &str, addrs: &[String]) -> Result<Self> {
        let key: [u8; 32] = key.try_into().context("a service key is 32 bytes")?;
        let mut addr = EndpointAddr::new(PublicKey::from_bytes(&key)?);
        if !relay.is_empty() { addr = addr.with_relay_url(relay.parse()?); }
        for a in addrs { addr = addr.with_ip_addr(a.parse()?); }
        Ok(Self(Arc::new(Inner { endpoint, addr, key, conn: Mutex::default(), requests: Semaphore::new(MAX_IN_FLIGHT) })))
    }

    pub fn for_service(endpoint: Endpoint, service: &Service) -> Result<Self> {
        let Service::Serve { key, relay, addrs, .. } = service else { anyhow::bail!("unsupported membership service") };
        Self::new(endpoint, &key.0, relay, addrs)
    }

    async fn connection(&self) -> Result<Connection> {
        let mut conn = self.0.conn.lock().await;
        if let Some(c) = conn.as_ref() && c.close_reason().is_none() { return Ok(c.clone()); }
        let c = self.0.endpoint.connect(self.0.addr.clone(), ALPN).await.map_err(|_| Unreached)?;
        *conn = Some(c.clone());
        Ok(c)
    }

    async fn request<T: DeserializeOwned>(&self, request: Request) -> Result<T> {
        let _request = self.0.requests.try_acquire().map_err(|_| Refused("busy".into()))?;
        n0_future::time::timeout(Duration::from_secs(30), async {
            let connection = self.connection().await?;
            let (mut send, mut recv) = connection.open_bi().await?;
            frame::write(&mut send, &Open { stream: Stream::Membership }).await?;
            frame::write(&mut send, &request).await?;
            send.shutdown().await?;
            match membership::read_frame::<Reply<T>, _>(&mut recv).await? {
                Reply::Ok(answer) => Ok(answer),
                Reply::Refused(reason) => Err(Refused(reason.code().into()).into()),
            }
        }).await?.map_err(safe_error)
    }

    pub async fn append(&self, capability: &[u8; 32], entries: &[Vec<u8>], public: bool) -> Result<Appended> {
        ensure!(!entries.is_empty() && entries.len() <= membership::APPEND_ROWS
            && entries.iter().all(|e| !e.is_empty() && e.len() <= membership::MAX_ENTRY)
            && entries.iter().map(Vec::len).sum::<usize>() <= membership::APPEND_BYTES, Refused("size".into()));
        let sent = clock::now();
        let appended: Appended = self.request(Request::Append {
            capability: *capability, entries: entries.iter().cloned().map(Bytes).collect(), public,
        }).await?;
        Frontier::empty(self.0.key, head::reference(&self.0.key, capability)).check(&appended.head, None)?;
        ensure!(appended.position > 0 && appended.position.checked_add(entries.len() as u64 - 1) == Some(appended.head.length), InvalidProof);
        record_time(sent, &appended.head)?;
        Ok(appended)
    }

    pub async fn read(&self, capability: &[u8; 32], anchor: &Frontier) -> Result<VerifiedPage> {
        ensure!(anchor.service() == &self.0.key && anchor.log_ref() == &head::reference(&self.0.key, capability), WrongLog);
        let sent = clock::now();
        let page: Page = self.request(Request::Read { capability: *capability, after: anchor.length() }).await?;
        let page = anchor.verify_page(page)?;
        record_time(sent, &page.page().head)?;
        Ok(page)
    }

    pub async fn head(&self, capability: &[u8; 32]) -> Result<Head> {
        let sent = clock::now();
        let Latest { head } = self.request(Request::Head { capability: *capability }).await?;
        Frontier::empty(self.0.key, head::reference(&self.0.key, capability)).check(&head, None)?;
        record_time(sent, &head)?;
        Ok(head)
    }

    pub async fn subscribe(&self, mut logs: Vec<([u8; 32], Frontier)>) -> Result<Subscription> {
        ensure!(!logs.is_empty() && logs.len() <= membership::SUBSCRIBE_LOGS, Refused("policy".into()));
        for (i, (capability, anchor)) in logs.iter().enumerate() {
            ensure!(anchor.service() == &self.0.key && anchor.log_ref() == &head::reference(&self.0.key, capability), WrongLog);
            ensure!(!logs[..i].iter().any(|(c, _)| c == capability), Refused("policy".into()));
        }
        let request_slot = self.0.requests.try_acquire().map_err(|_| Refused("busy".into()))?;
        let (send, recv) = n0_future::time::timeout(Duration::from_secs(30), async {
            let (mut send, mut recv) = self.connection().await?.open_bi().await?;
            frame::write(&mut send, &Open { stream: Stream::Membership }).await?;
            frame::write(&mut send, &Request::Subscribe { capabilities: logs.iter().map(|(c, _)| *c).collect() }).await?;
            match membership::read_frame::<Reply<Subscribed>, _>(&mut recv).await? {
                Reply::Ok(_) => Ok((send, recv)),
                Reply::Refused(reason) => Err(anyhow::Error::from(Refused(reason.code().into()))),
            }
        }).await?.map_err(safe_error)?;
        drop(request_slot);
        let (out, pages) = mpsc::channel(1);
        let client = self.clone();
        let reader = AbortOnDropHandle::new(n0_future::task::spawn(async move {
            let _send = send;
            let mut recv = recv;
            let result: Result<()> = async {
                loop {
                    let latest = match membership::read_frame::<Reply<Latest>, _>(&mut recv).await? {
                        Reply::Ok(latest) => latest,
                        Reply::Refused(reason) => return Err(Refused(reason.code().into()).into()),
                    };
                    let (capability, frontier) = logs.iter_mut().find(|(_, f)| f.log_ref() == &latest.head.log_ref).ok_or(WrongLog)?;
                    frontier.check(&latest.head, None)?;
                    while frontier.length() < latest.head.length {
                        let page = client.read(capability, frontier).await?;
                        ensure!(!page.page().entries.is_empty(), InvalidProof);
                        let mut hash = *frontier.hash();
                        let mut at_target = None;
                        for (offset, entry) in page.page().entries.iter().enumerate() {
                            hash = head::next(&hash, &entry.0);
                            if frontier.length() + offset as u64 + 1 == latest.head.length { at_target = Some(hash); }
                        }
                        *frontier = page.frontier().clone();
                        let checked = frontier.check(&latest.head, at_target);
                        // Retain the complete longer path before reporting a conflicting shorter signed hint.
                        out.send(Ok(page)).await.map_err(|_| anyhow::anyhow!("subscription closed"))?;
                        checked?;
                    }
                }
            }.await;
            if let Err(error) = result { let _ = out.send(Err(safe_error(error))).await; }
        }));
        Ok(Subscription { pages, reader })
    }
}

#[cfg(test)]
#[test]
fn unrepresentable_signed_time_cannot_overflow_the_shared_clock() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let head = Head::sign(&key, &[8; 32], 1, [9; 32], 1 << 63);
    assert!(head.verify(&key.verifying_key()));
    assert!(record_time(0, &head).unwrap_err().is::<InvalidProof>());
}
