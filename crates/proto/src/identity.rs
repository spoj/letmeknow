//! An identity's key log, where it lives, and the certificates its key signs for sessions.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Bytes, group::Service};

pub const ENTRY_CONTEXT: &[u8] = b"letmeknow identity key v1\0";
pub const CERTIFICATE_CONTEXT: &[u8] = b"letmeknow certificate v1\0";

/// Signed bytes: a key log entry before sealing, or a certificate. `sig` is over the context ‖ `body`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Envelope {
    /// JSON, as signed.
    pub body: Bytes,
    pub sig: Bytes,
}

/// A key log entry's body: signed by the key before it, the first by its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    /// SHA-256 of the previous entry's body; none in the first.
    pub prev: Option<Bytes>,
    /// The identity's new public key.
    pub key: Bytes,
    /// In the first entry only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// In the first entry only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<Service>,
}

/// A certificate's body: an identity's key vouches that a session of one of its devices speaks for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certified {
    pub identity: Bytes,
    /// The session's MLS signature key.
    pub key: Bytes,
    pub name: String,
    /// The name of the device that certified it.
    pub device: String,
    /// The name of the device that added that device to the identity; none for its first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    /// Milliseconds since the Unix epoch.
    pub expires: u64,
}

/// An identity's id: SHA-256 of its first entry's body.
pub fn id(first_body: &[u8]) -> [u8; 32] {
    Sha256::digest(first_body).into()
}

/// The log id of an identity's key log.
pub fn address(id: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(b"letmeknow identity address\0").chain_update(id).finalize().into()
}

/// The ChaCha20-Poly1305 key its entries are sealed under.
pub fn key(id: &[u8]) -> [u8; 32] {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, id).expand(b"letmeknow identity log key", &mut key).expect("32 bytes is a valid length");
    key
}
