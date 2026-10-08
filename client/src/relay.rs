use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use reqwest::{Response, StatusCode};
use reqwest_websocket::{Upgrade, WebSocket};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Clone)]
pub struct Relay(reqwest::Client);

/// A blob takes up to 10 MiB, which a slow link needs minutes for.
const BLOB_TIMEOUT: Duration = Duration::from_secs(600);

/// Whether a page whose entries are `sizes` bytes holds everything after its cursor. The relay ends a page early only
/// before an entry that would take it past 2 MiB, and entries are at most 1 MiB, so a page of at most 1 MiB is whole:
/// there is no need to ask for the next, empty one.
pub fn whole(sizes: impl Iterator<Item = usize>) -> bool {
    sizes.sum::<usize>() <= 1024 * 1024
}

#[derive(Deserialize)]
struct Frame {
    seq: u64,
    #[serde(default)]
    at: u64,
    data: String,
}

/// What a socket announces: a new entry's seq, and the entry itself unless it is large.
#[derive(Deserialize)]
pub struct Notice {
    pub seq: u64,
    pub data: Option<String>,
}

impl Relay {
    pub fn new() -> Result<Self> {
        Ok(Self(reqwest::Client::builder().timeout(Duration::from_secs(45)).build()?))
    }

    /// Posts an MLS message. `None` means the relay rejected it for a stale epoch.
    pub async fn post(&self, relay: &str, gid: &str, data: &[u8]) -> Result<Option<u64>> {
        let response = self.0.post(format!("{relay}/g/{gid}/messages")).body(data.to_vec()).send().await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(None);
        }
        let body: Value = ok(response).await?.json().await?;
        Ok(Some(body["seq"].as_u64().context("relay response lacks seq")?))
    }

    pub async fn fetch(&self, relay: &str, gid: &str, after: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let url = format!("{relay}/g/{gid}/messages?after={after}");
        let frames: Vec<Frame> = ok(self.0.get(url).send().await?).await?.json().await?;
        frames.into_iter().map(|f| Ok((f.seq, B64.decode(f.data)?))).collect()
    }

    /// Stores a blob in the group, or refreshes it: the relay keeps it for its message TTL from now.
    pub async fn put_blob(&self, relay: &str, gid: &str, hash: &str, sealed: &[u8]) -> Result<()> {
        ok(self.0.put(format!("{relay}/g/{gid}/blobs/{hash}")).timeout(BLOB_TIMEOUT).body(sealed.to_vec()).send().await?).await?;
        Ok(())
    }

    pub async fn get_blob(&self, relay: &str, gid: &str, hash: &str) -> Result<Vec<u8>> {
        Ok(ok(self.0.get(format!("{relay}/g/{gid}/blobs/{hash}")).timeout(BLOB_TIMEOUT).send().await?).await?.bytes().await?.to_vec())
    }

    /// Keeps a blob the relay has for another 7 days; false if it has none.
    pub async fn keep_blob(&self, relay: &str, gid: &str, hash: &str) -> Result<bool> {
        let response = self.0.post(format!("{relay}/g/{gid}/blobs/{hash}")).send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        ok(response).await?;
        Ok(true)
    }

    /// Opens a socket on which the relay announces each new message of a group (`g/<gid>`) or entry of a box
    /// (`b/<address>`), as a `Notice`.
    pub async fn subscribe(&self, relay: &str, path: &str) -> Result<WebSocket> {
        Ok(self.0.get(format!("{relay}/{path}/ws?messages")).upgrade().send().await?.into_websocket().await?)
    }

    /// Appends to a box: an append-only log the relay keeps in the order it takes entries.
    pub async fn append(&self, relay: &str, address: &str, data: &str) -> Result<u64> {
        let body: Value = ok(self.0.post(format!("{relay}/b/{address}")).body(data.to_owned()).send().await?).await?.json().await?;
        body["seq"].as_u64().context("relay response lacks seq")
    }

    /// A page of a box's entries after `after`, waiting up to `wait` seconds for one: (seq, when the relay took it in
    /// milliseconds since the epoch, data).
    pub async fn entries(&self, relay: &str, address: &str, after: u64, wait: u64) -> Result<Vec<(u64, u64, String)>> {
        let url = format!("{relay}/b/{address}?after={after}&wait={wait}");
        let frames: Vec<Frame> = ok(self.0.get(url).send().await?).await?.json().await?;
        frames.into_iter().map(|f| Ok((f.seq, f.at, String::from_utf8(B64.decode(f.data)?)?))).collect()
    }

    /// `false` means the slot is taken.
    pub async fn create_invite(&self, relay: &str, id: &str, ttl: u64, owner: &str, pake: &str) -> Result<bool> {
        let body = json!({ "ttl": ttl, "owner": owner, "pake": pake });
        let response = self.0.put(format!("{relay}/i/{id}")).json(&body).send().await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(false);
        }
        ok(response).await?;
        Ok(true)
    }

    pub async fn invite_post(&self, relay: &str, id: &str, action: &str, data: &str, owner: Option<&str>) -> Result<()> {
        let mut request = self.0.post(format!("{relay}/i/{id}/{action}")).json(&json!({ "data": data }));
        if let Some(owner) = owner {
            request = request.bearer_auth(owner);
        }
        ok(request.send().await?).await?;
        Ok(())
    }

    pub async fn invite_get(&self, relay: &str, id: &str, action: &str, wait: u64) -> Result<Option<String>> {
        let response = ok(self.0.get(format!("{relay}/i/{id}/{action}?wait={wait}")).send().await?).await?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        let body: Value = response.json().await?;
        Ok(Some(body["data"].as_str().context("relay response lacks data")?.to_owned()))
    }
}

/// The relay's answer to a request it refused.
#[derive(Debug)]
pub struct Refused(StatusCode, String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "relay answered {}: {}", self.0, self.1)
    }
}

impl std::error::Error for Refused {}

/// Whether trying again may help: the relay was not reached, the connection dropped, or it failed (5xx) rather than
/// refused (4xx).
pub fn transient(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Refused>().is_none_or(|refused| refused.0.is_server_error())
}

async fn ok(response: Response) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    Err(Refused(status, response.text().await.unwrap_or_default().trim().to_owned()).into())
}
