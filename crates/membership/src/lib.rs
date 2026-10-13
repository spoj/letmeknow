//! Membership authentication, clients, and the disposable authority's service/store.

pub mod chain;
pub mod client;
#[cfg(not(target_arch = "wasm32"))]
pub mod service;
#[cfg(not(target_arch = "wasm32"))]
pub mod store;

use anyhow::Result;
use n0_future::task::AbortOnDropHandle;
use tokio::sync::mpsc;

pub use chain::{Contradiction, Forged, Frontier, InvalidProof, Proof, VerifiedPage, WrongLog};

#[derive(Debug, thiserror::Error)]
#[error("the membership service refused: {0}")]
pub struct Refused(pub String);

#[derive(Debug, thiserror::Error)]
#[error("the membership service could not be reached")]
pub struct Unreached;

/// The directory a domain publishes names another key than the service it was fetched for; the domain's name.
#[derive(Debug, thiserror::Error)]
#[error("the directory of {0} names another key than the service")]
pub struct WrongDirectory(pub String);

pub struct Subscription {
    pages: mpsc::Receiver<Result<VerifiedPage>>,
    reader: AbortOnDropHandle<()>,
}

impl Subscription {
    pub async fn next(&mut self) -> Option<Result<VerifiedPage>> { self.pages.recv().await }

    pub async fn cancel(self) {
        self.reader.abort();
        let _ = self.reader.await;
    }
}
