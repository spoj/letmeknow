//! An identity's device list: its entries, and where they live.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Bytes, group::Service};

pub const ENTRY_CONTEXT: &[u8] = b"letmeknow device list v1\0";

/// An entry before sealing: `sig` is by `by` over `ENTRY_CONTEXT` ‖ `body`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// JSON of a `Body`, as signed.
    pub body: Bytes,
    pub sig: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    /// SHA-256 of the previous entry's body; none on `create`.
    pub prev: Option<Bytes>,
    pub op: Op,
    pub device: Bytes,
    pub device_name: String,
    pub by: Bytes,
    /// On `create` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// On `create` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<Service>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Create,
    Add,
    Remove,
}

/// An identity's id: SHA-256 of its first entry's body.
pub fn id(first_body: &[u8]) -> [u8; 32] {
    Sha256::digest(first_body).into()
}

/// The log id of an identity's device list.
pub fn address(id: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(b"letmeknow device list address\0").chain_update(id).finalize().into()
}

/// The ChaCha20-Poly1305 key its entries are sealed under.
pub fn key(id: &[u8]) -> [u8; 32] {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, id).expand(b"letmeknow device list key", &mut key).expect("32 bytes is a valid length");
    key
}
