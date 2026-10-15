//! A client of the membership service's HTTPS routes, with caller-owned trust anchors, never a shared history cache. What
//! a route answers is checked here: pages and heads against the service's key, and refusals, which act only when signed.

use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, anyhow, bail, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use lmk_proto::{
    Bytes, clock, directory::Directory, group::Service, head::{self, Head},
    membership::{self, Answer, Append, Appended, Heads, Known, Moved, Page, Read, refusal_message},
};
use n0_future::boxed::BoxFuture;
use serde::{Serialize, de::DeserializeOwned};

use crate::{Forged, Frontier, Refused, Unsupported, VerifiedPage, WrongDirectory, WrongLog};

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

/// Posts over https, for at most 30 s a request: the native shells' `Post`, on a client that trusts what its roots say.
#[cfg(not(target_arch = "wasm32"))]
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

#[derive(Clone)]
pub struct ServeClient(Arc<Inner>);

struct Inner {
    post: Post,
    domain: String,
    key: VerifyingKey,
    /// Once a route answered 404, the client stops: the service runs another minor, and asking again answers the same.
    stopped: OnceLock<Unsupported>,
}

impl ServeClient {
    pub fn for_service(post: Post, service: &Service) -> Result<Self> {
        let Service::Serve { key, domain, .. } = service else { bail!("unsupported membership service") };
        let key = VerifyingKey::from_bytes(key.0.as_slice().try_into().context("a service key is 32 bytes")?).context("a service key")?;
        Ok(Self(Arc::new(Inner { post, domain: domain.clone(), key, stopped: OnceLock::new() })))
    }

    async fn request<T: DeserializeOwned>(&self, route: &'static str, body: Vec<u8>) -> Result<T> {
        if let Some(stopped) = self.0.stopped.get() {
            return Err(stopped.clone().into());
        }
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
                let sig = Signature::from_slice(&sig.0).map_err(|_| Forged)?;
                ensure!(self.0.key.verify_strict(&refusal_message(refusal, &body), &sig).is_ok(), Forged);
                Err(Refused(refusal.code().into()).into())
            }
        }
    }

    pub async fn append(&self, capability: &[u8; 32], entries: &[Vec<u8>], public: bool) -> Result<Appended> {
        ensure!(!entries.is_empty() && entries.len() <= membership::APPEND_ROWS
            && entries.iter().all(|e| !e.is_empty() && e.len() <= membership::MAX_ENTRY)
            && entries.iter().map(Vec::len).sum::<usize>() <= membership::APPEND_BYTES, Refused("size".into()));
        let sent = clock::now();
        let body = json(&Append { capability: *capability, entries: entries.iter().cloned().map(Bytes).collect(), public })?;
        let appended: Appended = self.request("/membership/1/append", body).await?;
        Frontier::empty(*self.0.key.as_bytes(), head::reference(self.0.key.as_bytes(), capability)).check(&appended.head, None)?;
        ensure!(appended.position > 0 && appended.position.checked_add(entries.len() as u64 - 1) == Some(appended.head.length), crate::InvalidProof);
        record_time(sent, &appended.head)?;
        Ok(appended)
    }

    pub async fn read(&self, capability: &[u8; 32], anchor: &Frontier) -> Result<VerifiedPage> {
        ensure!(anchor.service() == self.0.key.as_bytes() && anchor.log_ref() == &head::reference(self.0.key.as_bytes(), capability), WrongLog);
        let sent = clock::now();
        let page: Page = self.request("/membership/1/read", json(&Read { capability: *capability, after: anchor.length() })?).await?;
        let page = anchor.verify_page(page)?;
        record_time(sent, &page.page().head)?;
        Ok(page)
    }

    /// The heads of the logs whose length differs from the one given, from one request per `HEAD_LOGS` logs. A log
    /// missing from the answer is unchanged at the time of the request.
    pub async fn heads(&self, logs: &[Known]) -> Result<Vec<Head>> {
        let mut moved = Vec::new();
        for chunk in logs.chunks(membership::HEAD_LOGS) {
            let sent = clock::now();
            let Moved { heads } = self.request("/membership/1/heads", json(&Heads { logs: chunk.to_vec() })?).await?;
            for head in heads {
                if !head.verify(&self.0.key) {
                    return Err(WrongDirectory(self.0.domain.clone()).into());
                }
                ensure!(chunk.iter().any(|Known(capability, _)| head::reference(self.0.key.as_bytes(), capability) == head.log_ref), WrongLog);
                record_time(sent, &head)?;
                moved.push(head);
            }
        }
        Ok(moved)
    }
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

fn record_time(sent: u64, head: &Head) -> Result<()> {
    ensure!(head.time <= i64::MAX as u64, crate::InvalidProof);
    clock::heard(sent, clock::now(), head.time);
    Ok(())
}

#[cfg(test)]
#[test]
fn unrepresentable_signed_time_cannot_overflow_the_shared_clock() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let head = Head::sign(&key, &[8; 32], 1, [9; 32], 1 << 63);
    assert!(head.verify(&key.verifying_key()));
    assert!(record_time(0, &head).unwrap_err().is::<crate::InvalidProof>());
}
