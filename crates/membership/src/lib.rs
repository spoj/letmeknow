//! Membership logs: the store and service behind `letmeknow serve`, and its client.

pub mod chain;
pub mod client;
#[cfg(not(target_arch = "wasm32"))]
pub mod service;
#[cfg(not(target_arch = "wasm32"))]
pub mod store;

use anyhow::Result;
use lmk_proto::membership::Notice;
use tokio::sync::mpsc;

pub use chain::{Chain, Contradiction, Forged};

/// The service refused a request: an append as `size`, `rate` or `policy`, a read as `expired`.
#[derive(Debug, thiserror::Error)]
#[error("the membership service refused: {0}")]
pub struct Refused(pub String);

/// The request certainly did not reach the service: it could not be reached.
#[derive(Debug, thiserror::Error)]
#[error("the membership service is unavailable: {0}")]
pub struct Unreached(pub String);

/// Notices until the subscription ends; on an error or end, subscribe again.
pub struct Subscription(mpsc::Receiver<Result<Notice>>);

impl Subscription {
    pub async fn next(&mut self) -> Option<Result<Notice>> {
        self.0.recv().await
    }
}
