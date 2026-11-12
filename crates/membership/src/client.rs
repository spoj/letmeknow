//! A client of the membership service's HTTPS routes, with caller-owned trust anchors, never a shared history cache. What
//! a route answers is checked here against the service's key: pages, heads, refusals and expiries count only when it
//! signed them, and a reply it did not sign is `WrongDirectory`.

use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, anyhow, bail, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use lmk_proto::{
    Bytes, clock, directory::Directory, group::Service, head::{self, Head},
    membership::{self, Answer, Append, Appended, Expiry, Heads, Known, Moved, Page, Read, refusal_message},
};
use n0_future::boxed::BoxFuture;
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::Semaphore;

use crate::{Expired, Frontier, Refused, Unsupported, WrongDirectory, WrongLog};

/// Resolves a domain to the directory its service publishes.
pub type Resolve = Arc<dyn Fn(String) -> BoxFuture<Result<Directory>> + Send + Sync>;

/// Posts a body to a route of the membership service at a domain, and answers the reply, as `answered` reads it.
pub type Post = Arc<dyn Fn(String, &'static str, Vec<u8>) -> BoxFuture<Result<Vec<u8>>> + Send + Sync>;

/// The reply of a route from its status and body, which a shell reads no further than `MAX_BODY` plus one byte.
pub fn answered(domain: &str, status: u16, body: Vec<u8>) -> Result<Vec<u8>> {
    match status {
        200 => {
            ensure!(body.len() <= membership::MAX_BODY, "the membership service at {domain} sent more than a reply may be");
            Ok(body)
        }
        404 => Err(Unsupported(domain.into()).into()),
        _ => bail!("the membership service at {domain} answered {status}"),
    }
}

/// Posts over https, for at most 30 s a request, on a client that trusts what its roots say.
pub fn https(http: reqwest::Client) -> Post {
    Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| -> BoxFuture<Result<Vec<u8>>> {
        let http = http.clone();
        Box::pin(async move {
            let mut response = http.post(format!("https://{domain}{route}")).body(body)
                .timeout(std::time::Duration::from_secs(30)).send().await?;
            let status = response.status().as_u16();
            let mut reply = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                reply.extend_from_slice(&chunk);
                if reply.len() > membership::MAX_BODY {
                    break;
                }
            }
            answered(&domain, status, reply)
        })
    })
}

/// The directory of a service: what its domain publishes, which must name the service's key.
pub async fn directory(resolve: &Resolve, service: &Service) -> Result<Directory> {
    let Service::Serve { key, domain, .. } = service else { bail!("unsupported membership service") };
    let directory = resolve(domain.clone()).await?;
    if directory.key.as_slice() != key.0.as_slice() {
        return Err(WrongDirectory(domain.clone()).into());
    }
    Ok(directory)
}

/// Requests in flight to one service: three pages and their requests fit the 16 MiB a service takes in flight from one
/// source by default, past which it answers at once with a 503.
const IN_FLIGHT: usize = 3;

#[derive(Clone)]
pub struct ServeClient(Arc<Inner>);

struct Inner {
    post: Post,
    domain: String,
    key: VerifyingKey,
    sets_clock: bool,
    slots: Semaphore,
    /// Once a route answered 404, the client stops: the service runs another minor, and asking again answers the same.
    stopped: OnceLock<Unsupported>,
}

impl ServeClient {
    pub fn for_service(post: Post, service: &Service, sets_clock: bool) -> Result<Self> {
        let Service::Serve { key, domain, .. } = service else { bail!("unsupported membership service") };
        let key = VerifyingKey::from_bytes(key.0.as_slice().try_into().context("a service key is 32 bytes")?).context("a service key")?;
        Ok(Self(Arc::new(Inner { post, domain: domain.clone(), key, sets_clock, slots: Semaphore::new(IN_FLIGHT), stopped: OnceLock::new() })))
    }

    /// Posts a body to a route and answers its reply. A refusal or an expiry must be signed, and an expiry is of the one
    /// log the request is for: `heads` names many logs, and its expiries come in its answer.
    async fn request<T: DeserializeOwned>(&self, route: &'static str, body: Vec<u8>, log_ref: Option<[u8; 32]>) -> Result<T> {
        if let Some(stopped) = self.0.stopped.get() {
            return Err(stopped.clone().into());
        }
        let _slot = self.0.slots.acquire().await?;
        let reply = match (self.0.post)(self.0.domain.clone(), route, body.clone()).await {
            Ok(reply) => reply,
            Err(error) => {
                if let Some(unsupported) = error.downcast_ref::<Unsupported>() {
                    _ = self.0.stopped.set(unsupported.clone());
                }
                return Err(error);
            }
        };
        match serde_json::from_slice::<Answer<T>>(&reply).map_err(|_| anyhow!("an invalid membership reply"))? {
            Answer::Ok(value) => Ok(value),
            Answer::Refused { refusal, sig } => {
                let signed = Signature::from_slice(&sig.0).is_ok_and(|sig| self.0.key.verify_strict(&refusal_message(refusal, &body), &sig).is_ok());
                ensure!(signed, WrongDirectory(self.0.domain.clone()));
                Err(Refused(refusal.code().into()).into())
            }
            Answer::Expired { sig } => {
                let Some(log_ref) = log_ref else { bail!("an invalid membership reply") };
                ensure!(Expiry { log_ref, sig }.verify(&self.0.key), WrongDirectory(self.0.domain.clone()));
                Err(Expired(log_ref).into())
            }
        }
    }

    /// Appends entries to a log, at least one.
    pub async fn append(&self, capability: &[u8; 32], entries: &[Vec<u8>]) -> Result<Appended> {
        ensure!((1..=membership::APPEND_ROWS).contains(&entries.len())
            && entries.iter().all(|e| !e.is_empty() && e.len() <= membership::MAX_ENTRY)
            && entries.iter().map(Vec::len).sum::<usize>() <= membership::APPEND_BYTES, Refused("size".into()));
        let sent = clock::now();
        let body = json(&Append { capability: *capability, entries: entries.iter().cloned().map(Bytes).collect() })?;
        let appended: Appended = self.request("/membership/6/append", body, Some(head::reference(self.0.key.as_bytes(), capability))).await?;
        ensure!(appended.head.verify(&self.0.key), WrongDirectory(self.0.domain.clone()));
        Frontier::empty(*self.0.key.as_bytes(), head::reference(self.0.key.as_bytes(), capability)).check(&appended.head, None)?;
        self.heard(sent, &appended.head);
        Ok(appended)
    }

    pub async fn read(&self, capability: &[u8; 32], anchor: &Frontier) -> Result<Page> {
        ensure!(anchor.service() == self.0.key.as_bytes() && anchor.log_ref() == &head::reference(self.0.key.as_bytes(), capability), WrongLog);
        let sent = clock::now();
        let body = json(&Read { capability: *capability, after: anchor.length() })?;
        let page: Page = self.request("/membership/6/read", body, Some(*anchor.log_ref())).await?;
        ensure!(page.head.verify(&self.0.key), WrongDirectory(self.0.domain.clone()));
        let page = anchor.verify_page(page)?;
        self.heard(sent, &page.head);
        Ok(page)
    }

    /// The head of each log, or its expiry once the service let it go, in the order asked, from one request per
    /// `HEAD_LOGS` logs. Each is asked at a length no log has, so that the service answers every one, signed: one with no
    /// answer the service's key signed is `WrongDirectory`.
    pub async fn heads(&self, capabilities: &[[u8; 32]]) -> Result<Vec<Result<Head, Expiry>>> {
        let mut answers = Vec::new();
        for chunk in capabilities.chunks(membership::HEAD_LOGS) {
            let sent = clock::now();
            let logs = chunk.iter().map(|capability| Known(*capability, u64::MAX)).collect();
            let Moved { heads, expired } = self.request("/membership/6/heads", json(&Heads { logs })?, None).await?;
            for capability in chunk {
                let log_ref = head::reference(self.0.key.as_bytes(), capability);
                if let Some(head) = heads.iter().find(|head| head.log_ref == log_ref && head.verify(&self.0.key)) {
                    self.heard(sent, head);
                    answers.push(Ok(head.clone()));
                    continue;
                }
                let expiry = expired.iter().find(|expiry| expiry.log_ref == log_ref && expiry.verify(&self.0.key));
                answers.push(Err(expiry.cloned().ok_or_else(|| WrongDirectory(self.0.domain.clone()))?));
            }
        }
        Ok(answers)
    }

    fn heard(&self, sent: u64, head: &Head) {
        if self.0.sets_clock {
            clock::heard(sent, clock::now(), head.time);
        }
    }
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}
