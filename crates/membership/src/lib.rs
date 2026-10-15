//! Membership authentication, clients, and the disposable authority's service/store.

pub mod chain;
pub mod client;
#[cfg(not(target_arch = "wasm32"))]
pub mod service;
#[cfg(not(target_arch = "wasm32"))]
pub mod store;

pub use chain::{Contradiction, Forged, Frontier, InvalidProof, Proof, VerifiedPage, WrongLog};

#[derive(Debug, thiserror::Error)]
#[error("the membership service refused: {0}")]
pub struct Refused(pub String);

/// A service that answers 404 to a route runs another minor, which its text says.
#[derive(Clone, Debug, thiserror::Error)]
#[error("the membership service at {0} runs another minor: {1}")]
pub struct Unsupported(pub String, pub String);

/// A head the domain's service signed with another key than the group's: the domain's name.
#[derive(Debug, thiserror::Error)]
#[error("the directory of {0} names another key than the service")]
pub struct WrongDirectory(pub String);
