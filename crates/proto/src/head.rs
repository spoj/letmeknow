//! A log's hash chain, and the heads a membership service signs over it.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Bytes;

/// h₀ of a log's chain.
pub fn start(log: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(b"letmeknow log v1\0").chain_update(log).finalize().into()
}

/// hₙ from hₙ₋₁ and entryₙ.
pub fn next(prev: &[u8; 32], entry: &[u8]) -> [u8; 32] {
    let entry: [u8; 32] = Sha256::digest(entry).into();
    Sha256::new().chain_update(prev).chain_update(entry).finalize().into()
}

/// A membership service's signed statement: this log had `length` entries, ending in `hash`, at `time`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    pub log: Bytes,
    pub length: u64,
    pub hash: Bytes,
    /// Milliseconds since the Unix epoch.
    pub time: u64,
    pub sig: Bytes,
}

fn signed(log: &[u8], length: u64, hash: &[u8], time: u64) -> Vec<u8> {
    let mut bytes = b"letmeknow head v1\0".to_vec();
    bytes.extend_from_slice(&(log.len() as u16).to_be_bytes());
    bytes.extend_from_slice(log);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(hash);
    bytes.extend_from_slice(&time.to_be_bytes());
    bytes
}

impl Head {
    pub fn sign(key: &SigningKey, log: &[u8], length: u64, hash: [u8; 32], time: u64) -> Self {
        let sig = key.sign(&signed(log, length, &hash, time));
        Head { log: log.into(), length, hash: hash.into(), time, sig: sig.to_bytes().into() }
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        let Ok(sig) = Signature::from_slice(&self.sig.0) else {
            return false;
        };
        self.hash.0.len() == 32 && key.verify(&signed(&self.log.0, self.length, &self.hash.0, self.time), &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut hash = start(b"log");
        for entry in [b"a".as_slice(), b"b"] {
            hash = next(&hash, entry);
        }
        let head = Head::sign(&key, b"log", 2, hash, 1);
        assert!(head.verify(&key.verifying_key()));
        let forged = Head { length: 3, ..head.clone() };
        assert!(!forged.verify(&key.verifying_key()));
        let json = serde_json::to_string(&head).unwrap();
        assert_eq!(serde_json::from_str::<Head>(&json).unwrap(), head);
    }
}
