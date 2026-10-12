//! A public log, where it lives, and what a writer of an identity's signs for a session that speaks for it.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Bytes, group::Service};

pub const ENTRY_CONTEXT: &[u8] = b"letmeknow public log v2\0";
pub const CERTIFICATE_CONTEXT: &[u8] = b"letmeknow certificate v2\0";

/// A public log entry before sealing. `sig` is `by`'s, over `ENTRY_CONTEXT` ‖ `body`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Envelope {
    /// JSON, as signed.
    pub body: Bytes,
    /// The key of the writer that signed it.
    pub by: Bytes,
    pub sig: Bytes,
}

/// A public log entry's body: signed by a writer of the entry before, the first by one of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    /// SHA-256 of the previous entry's body; none in the first.
    pub prev: Option<Bytes>,
    /// The log's writers from this entry on: an identity's devices. None in the closing entry, after which no entry
    /// counts.
    pub writers: Vec<Bytes>,
    /// In the first entry only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<Service>,
}

/// The device-signed claims. Lengths count UTF-8 bytes; the service route remains an untrusted lookup hint.
pub fn certified(session: &[u8; 32], identity: &[u8; 32], device: &[u8; 32], name: &str, device_name: &str) -> Vec<u8> {
    [CERTIFICATE_CONTEXT, session, identity, device, &(name.len() as u64).to_be_bytes(), name.as_bytes(),
        &(device_name.len() as u64).to_be_bytes(), device_name.as_bytes()].concat()
}

/// A public log's id: SHA-256 of its first entry's body.
pub fn id(first_body: &[u8]) -> [u8; 32] {
    Sha256::digest(first_body).into()
}

/// The membership log id of a public log.
pub fn address(id: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(b"letmeknow public log address\0").chain_update(id).finalize().into()
}

/// The ChaCha20-Poly1305 key its entries are sealed under.
pub fn key(id: &[u8]) -> [u8; 32] {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, id).expand(b"letmeknow public log key", &mut key).expect("32 bytes is a valid length");
    key
}
