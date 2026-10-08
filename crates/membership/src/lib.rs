//! Membership logs: the store and service behind `letmeknow serve`, and clients for both kinds of service.

pub mod chain;
pub mod client;
pub mod folder;
pub mod service;
pub mod store;

use anyhow::Result;
use async_trait::async_trait;
use lmk_proto::{
    Bytes,
    head::Head,
    membership::{Appended, Notice, Page},
};
use tokio::sync::mpsc;

pub use chain::{Chain, Contradiction, Forged};

/// The one ALPN all of letmeknow's own protocols share.
pub const ALPN: &[u8] = b"letmeknow/1";

/// The service refused an append: `size`, `rate` or `policy`.
#[derive(Debug, thiserror::Error)]
#[error("the membership service refused: {0}")]
pub struct Refused(pub String);

/// A membership service, as a client sees it. Every head it returns has been checked against the client's chain:
/// a bad signature is a [`Forged`] error, a head that contradicts the chain a [`Contradiction`].
#[async_trait]
pub trait Membership: Send + Sync {
    async fn append(&self, log: &[u8], entry: &[u8]) -> Result<Appended>;
    /// One page of the entries after `after`.
    async fn read(&self, log: &[u8], after: u64) -> Result<Page>;
    async fn head(&self, log: &[u8]) -> Result<Head>;
    /// New entries of these logs, in order. Once the client's chain of a log has started, notices continue it
    /// without gaps; read first to catch up, since a subscription brings only what arrives after it.
    async fn subscribe(&self, logs: Vec<Bytes>) -> Result<Subscription>;
    /// The client's chain of a log, to persist.
    fn chain(&self, log: &[u8]) -> Option<Chain>;
    /// Restores a persisted chain.
    fn set_chain(&self, chain: Chain);
}

/// Notices until the subscription ends; on an error or end, subscribe again.
pub struct Subscription(mpsc::Receiver<Result<Notice>>);

impl Subscription {
    pub async fn next(&mut self) -> Option<Result<Notice>> {
        self.0.recv().await
    }
}
