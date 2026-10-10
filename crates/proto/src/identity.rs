//! An identity's key log, where it lives, and what a device's key signs for a session that speaks as it.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Bytes, group::Service};

pub const ENTRY_CONTEXT: &[u8] = b"letmeknow identity key v1\0";
pub const CERTIFICATE_CONTEXT: &[u8] = b"letmeknow certificate v1\0";

/// A key log entry before sealing. `sig` is over `ENTRY_CONTEXT` ‖ `body`.
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
    /// The identity's key from this entry on.
    pub key: Bytes,
    /// The identity's devices.
    pub devices: Vec<Listed>,
    /// In the first entry only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// In the first entry only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<Service>,
}

/// A device on an identity's list: its key in the identity's devices group, and its name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Listed {
    pub key: Bytes,
    pub name: String,
}

/// What a device's key signs, after `CERTIFICATE_CONTEXT`, for a session that speaks as the identity.
pub fn certified(session: &[u8], identity: &[u8]) -> Vec<u8> {
    [CERTIFICATE_CONTEXT, session, identity].concat()
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
