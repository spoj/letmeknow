//! A log's hash chain, and the heads a membership service signs over it.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Bytes, membership::fixed32};

pub fn reference(service: &[u8; 32], capability: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(b"letmeknow log reference v1\0").chain_update(service).chain_update(capability).finalize().into()
}

/// The key a log's entries and state are sealed under at rest: the capability's, which only the log's members hold.
pub fn sealing(capability: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(b"letmeknow log sealing v1\0").chain_update(capability).finalize().into()
}

pub fn start(service: &[u8; 32], log_ref: &[u8; 32]) -> [u8; 32] {
    Sha256::new().chain_update(b"letmeknow log v2\0").chain_update(service).chain_update(log_ref).finalize().into()
}

pub fn next(prev: &[u8; 32], entry: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(prev).chain_update(Sha256::digest(entry)).finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    #[serde(with = "fixed32")]
    pub log_ref: [u8; 32],
    pub length: u64,
    #[serde(with = "fixed32")]
    pub hash: [u8; 32],
    pub time: u64,
    #[serde(deserialize_with = "signature")]
    pub sig: Bytes,
}

pub(crate) fn signature<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
    let bytes = crate::membership::decode_bytes::<D, 64>(d)?;
    if bytes.len() != 64 {
        return Err(serde::de::Error::custom("signature length"));
    }
    Ok(Bytes(bytes))
}

fn signed(service: &[u8; 32], log_ref: &[u8; 32], length: u64, hash: &[u8; 32], time: u64) -> Vec<u8> {
    let mut bytes = b"letmeknow head v2\0".to_vec();
    bytes.extend_from_slice(service);
    bytes.extend_from_slice(log_ref);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(hash);
    bytes.extend_from_slice(&time.to_be_bytes());
    bytes
}

impl Head {
    pub fn sign(key: &SigningKey, log_ref: &[u8; 32], length: u64, hash: [u8; 32], time: u64) -> Self {
        let sig = key.sign(&signed(key.verifying_key().as_bytes(), log_ref, length, &hash, time));
        Head { log_ref: *log_ref, length, hash, time, sig: sig.to_bytes().into() }
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        let Ok(sig) = Signature::from_slice(&self.sig.0) else { return false };
        key.verify_strict(&signed(key.as_bytes(), &self.log_ref, self.length, &self.hash, self.time), &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_and_authority_binding() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let s = key.verifying_key().to_bytes();
        let c = [9; 32];
        let d = reference(&s, &c);
        assert_eq!(d, <[u8; 32]>::from(Sha256::digest([b"letmeknow log reference v1\0".as_slice(), &s, &c].concat())));
        assert_ne!(reference(&s, &d), d);
        assert_ne!(reference(&[8; 32], &c), d);
        let h0 = start(&s, &d);
        assert_eq!(h0, <[u8; 32]>::from(Sha256::digest([b"letmeknow log v2\0".as_slice(), &s, &d].concat())));
        let h = next(&h0, b"opaque");
        let head = Head::sign(&key, &d, 1, h, 42);
        let bytes = [b"letmeknow head v2\0".as_slice(), &s, &d, &1u64.to_be_bytes(), &h, &42u64.to_be_bytes()].concat();
        assert_eq!(head.sig.0, key.sign(&bytes).to_bytes());
        assert!(head.verify(&key.verifying_key()));
        assert!(!head.verify(&SigningKey::from_bytes(&[8; 32]).verifying_key()));
        assert!(!Head { log_ref: c, ..head.clone() }.verify(&key.verifying_key()));
        assert!(!Head { length: 2, ..head.clone() }.verify(&key.verifying_key()));
        assert_eq!(serde_json::from_slice::<Head>(&serde_json::to_vec(&head).unwrap()).unwrap(), head);
    }
}
