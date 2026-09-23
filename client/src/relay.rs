use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use reqwest::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Clone)]
pub struct Relay(reqwest::Client);

#[derive(Deserialize)]
struct Frame {
    seq: u64,
    data: String,
}

impl Relay {
    pub fn new() -> Result<Self> {
        Ok(Self(reqwest::Client::builder().timeout(Duration::from_secs(45)).build()?))
    }

    /// Posts an MLS message. `None` means the relay rejected a commit for a stale epoch.
    pub async fn post(&self, relay: &str, gid: &str, data: &[u8]) -> Result<Option<u64>> {
        let response = self.0.post(format!("{relay}/g/{gid}/messages")).body(data.to_vec()).send().await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(None);
        }
        let body: Value = ok(response).await?.json().await?;
        Ok(Some(body["seq"].as_u64().context("relay response lacks seq")?))
    }

    pub async fn fetch(&self, relay: &str, gid: &str, after: u64, wait: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let url = format!("{relay}/g/{gid}/messages?after={after}&wait={wait}");
        let frames: Vec<Frame> = ok(self.0.get(url).send().await?).await?.json().await?;
        frames.into_iter().map(|f| Ok((f.seq, B64.decode(f.data)?))).collect()
    }

    pub async fn create_invite(&self, relay: &str, id: &str, ttl: u64, owner: &str) -> Result<()> {
        let body = json!({ "ttl": ttl, "owner": owner });
        ok(self.0.put(format!("{relay}/i/{id}")).json(&body).send().await?).await?;
        Ok(())
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

async fn ok(response: Response) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    bail!("relay answered {status}: {}", response.text().await.unwrap_or_default().trim())
}
