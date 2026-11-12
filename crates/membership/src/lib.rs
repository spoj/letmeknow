//! Membership authentication, clients, and the disposable authority's service/store.

pub mod chain;
pub mod client;
pub mod service;
pub mod store;

pub use chain::{Contradiction, Forged, Frontier, InvalidProof, WrongLog};

#[derive(Debug, thiserror::Error)]
#[error("the membership service refused: {0}")]
pub struct Refused(pub String);

/// A log the service let go, by its reference: its entries are gone, and it cannot start again.
#[derive(Debug, thiserror::Error)]
#[error("the membership service let that log go")]
pub struct Expired(pub [u8; 32]);

/// A service that answers 404 to a route runs another minor. Its text is not shown: a page reads it as the service's.
#[derive(Clone, Debug, thiserror::Error)]
#[error("the membership service at {0} runs another minor")]
pub struct Unsupported(pub String);

/// The domain's service signs with another key than the group's, as a reply that key did not sign, or a directory naming
/// another, shows: the domain's name.
#[derive(Debug, thiserror::Error)]
#[error("the membership service at {0} signs with another key than the group's")]
pub struct WrongDirectory(pub String);
