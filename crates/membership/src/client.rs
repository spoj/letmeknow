//! A client of `letmeknow serve`, over iroh.

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use iroh::{Endpoint, EndpointAddr, PublicKey, endpoint::Connection};
use lmk_proto::{
    Answer, Bytes, frame,
    frame::{Open, Stream},
    group::Service,
    head::Head,
    membership::{Appended, Latest, Notice, Page, Request},
};
use serde::de::DeserializeOwned;
use tokio::sync::{Mutex, mpsc};

use crate::{ALPN, Chain, Membership, Refused, Subscription, chain::Chains};

#[derive(Clone)]
pub struct ServeClient(Arc<Inner>);

struct Inner {
    endpoint: Endpoint,
    addr: EndpointAddr,
    chains: Chains,
    conn: Mutex<Option<Connection>>,
}

impl ServeClient {
    /// A client of the service at `key`, reached through its relay or direct addresses.
    pub fn new(endpoint: Endpoint, key: &[u8], relay: &str, addrs: &[String]) -> Result<Self> {
        let key: [u8; 32] = key.try_into().context("a service key is 32 bytes")?;
        let mut addr = EndpointAddr::new(PublicKey::from_bytes(&key)?);
        if !relay.is_empty() {
            addr = addr.with_relay_url(relay.parse()?);
        }
        for a in addrs {
            addr = addr.with_ip_addr(a.parse()?);
        }
        let chains = Chains::new(Some(VerifyingKey::from_bytes(&key)?));
        Ok(ServeClient(Arc::new(Inner { endpoint, addr, chains, conn: Mutex::default() })))
    }

    pub fn for_service(endpoint: Endpoint, service: &Service) -> Result<Self> {
        let Service::Serve { key, relay, addrs } = service else { anyhow::bail!("not a serve service") };
        Self::new(endpoint, &key.0, relay, addrs)
    }

    async fn connection(&self) -> Result<Connection> {
        let mut conn = self.0.conn.lock().await;
        if let Some(c) = conn.as_ref()
            && c.close_reason().is_none()
        {
            return Ok(c.clone());
        }
        let c = self.0.endpoint.connect(self.0.addr.clone(), ALPN).await?;
        *conn = Some(c.clone());
        Ok(c)
    }

    async fn request<T: DeserializeOwned>(&self, request: Request) -> Result<T> {
        let (mut send, mut recv) = self.connection().await?.open_bi().await?;
        frame::write(&mut send, &Open { stream: Stream::Membership }).await?;
        frame::write(&mut send, &request).await?;
        send.finish()?;
        match frame::read(&mut recv).await? {
            Answer::Ok(answer) => Ok(answer),
            Answer::Refused { refused } => Err(Refused(refused).into()),
        }
    }

    /// Checks a notice and passes it on, first reading any entries it skips past.
    async fn deliver(&self, notice: Notice, out: &mpsc::Sender<Result<Notice>>) -> Result<()> {
        let log = notice.log.0.clone();
        let after = notice.position.checked_sub(1).context("a notice at position 0")?;
        let len = self.0.chains.get(&log).map(|c| c.len());
        if let Some(mut len) = len
            && after > len
        {
            while len < notice.position {
                let page = self.read(&log, len).await?;
                ensure!(!page.entries.is_empty(), "the service withholds entries it announced");
                for entry in page.entries {
                    len += 1;
                    let head = page.head.clone();
                    out.send(Ok(Notice { log: notice.log.clone(), position: len, entry, head })).await?;
                }
            }
            return self.0.chains.head(&log, &notice.head);
        }
        self.0.chains.page(&log, after, std::slice::from_ref(&notice.entry), &notice.head)?;
        if len.is_none_or(|len| notice.position > len) {
            out.send(Ok(notice)).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Membership for ServeClient {
    async fn append(&self, log: &[u8], entry: &[u8]) -> Result<Appended> {
        let appended: Appended = self.request(Request::Append { log: log.into(), entry: entry.into() }).await?;
        let after = appended.position.checked_sub(1).context("appended at position 0")?;
        self.0.chains.page(log, after, &[entry.into()], &appended.head)?;
        Ok(appended)
    }

    async fn read(&self, log: &[u8], after: u64) -> Result<Page> {
        let page: Page = self.request(Request::Read { log: log.into(), after }).await?;
        self.0.chains.page(log, after, &page.entries, &page.head)?;
        Ok(page)
    }

    async fn head(&self, log: &[u8]) -> Result<Head> {
        let Latest { head } = self.request(Request::Head { log: log.into() }).await?;
        self.0.chains.head(log, &head)?;
        Ok(head)
    }

    async fn subscribe(&self, logs: Vec<Bytes>) -> Result<Subscription> {
        let (mut send, mut recv) = self.connection().await?.open_bi().await?;
        frame::write(&mut send, &Open { stream: Stream::Membership }).await?;
        frame::write(&mut send, &Request::Subscribe { logs }).await?;
        let (out, notices) = mpsc::channel(64);
        let client = self.clone();
        tokio::spawn(async move {
            let _send = send;
            let result: Result<()> = async {
                loop {
                    let notice = frame::read(&mut recv).await?;
                    client.deliver(notice, &out).await?;
                }
            }
            .await;
            if let Err(err) = result {
                let _ = out.send(Err(err)).await;
            }
        });
        Ok(Subscription(notices))
    }

    fn chain(&self, log: &[u8]) -> Option<Chain> {
        self.0.chains.get(log)
    }

    fn set_chain(&self, chain: Chain) {
        self.0.chains.set(chain)
    }
}
