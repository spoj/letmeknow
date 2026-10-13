//! A held message's plaintext, inside its MLS application message: `body ‖ sig`, where `body` is its header's JSON and
//! `sig` its author's Ed25519 signature, by its leaf's signature key, over `HELD ‖ body`. Its id is the hash of the
//! plaintext, the same in every epoch its author seals it in.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::Bytes;

/// What a held message's signature covers, before its body.
pub const HELD: &[u8] = b"letmeknow held v1\0";

/// A held message's header, signed whole by its author.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub group: Bytes,
    /// The author's leaf signature key, and the epoch its membership began in: a key admitted again starts anew.
    pub author: Bytes,
    pub joined: u64,
    /// The author's count of held messages in the group: 1, 2, 3, … across epochs.
    pub seq: u64,
    /// The id of the author's message at `seq - 1`; none at seq 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Bytes>,
    /// The frontier of what the author's client had shown: at most one message per membership, none the author's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<Ref>,
    /// A message in that shown past.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Bytes>,
    /// A JSON object with a `type`: the core's, or the group's kind's.
    pub payload: Value,
}

/// A message by its author's membership and seq, and its id; in a cut, a membership's seq and the id there, empty at
/// seq 0. Carried as `[key, joined, seq, id]`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(from = "(Bytes, u64, u64, Bytes)", into = "(Bytes, u64, u64, Bytes)")]
pub struct Ref {
    pub key: Bytes,
    pub joined: u64,
    pub seq: u64,
    pub id: Bytes,
}

impl From<(Bytes, u64, u64, Bytes)> for Ref {
    fn from((key, joined, seq, id): (Bytes, u64, u64, Bytes)) -> Self {
        Ref { key, joined, seq, id }
    }
}

impl From<Ref> for (Bytes, u64, u64, Bytes) {
    fn from(r: Ref) -> Self {
        (r.key, r.joined, r.seq, r.id)
    }
}

impl Ref {
    /// The membership it is of.
    pub fn membership(&self) -> (Bytes, u64) {
        (self.key.clone(), self.joined)
    }
}

impl Header {
    /// The plaintext of this header signed by `sign`, which signs `HELD ‖ body`.
    pub fn sign(&self, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
        let body = serde_json::to_vec(self).expect("a header serializes");
        let sig = sign(&[HELD, &body].concat());
        [body, sig].concat()
    }

    /// The header of a plaintext, shaped as one must be; its signature is checked against its author by `verify`, which
    /// gets the key, `HELD ‖ body` and the signature.
    pub fn open(plaintext: &[u8], verify: impl FnOnce(&[u8], &[u8], &[u8]) -> bool) -> Result<Self> {
        ensure!(plaintext.len() > 64, "a held message too short to be signed");
        let (body, sig) = plaintext.split_at(plaintext.len() - 64);
        let header: Header = serde_json::from_slice(body).context("a held message's header")?;
        ensure!(verify(&header.author.0, &[HELD, body].concat(), sig), "a held message its author did not sign");
        ensure!(header.seq >= 1 && header.prev.is_some() == (header.seq > 1), "a held message out of its author's sequence");
        ensure!(header.payload["type"].is_string(), "a payload without a type");
        let mut authors: Vec<&Bytes> = header.deps.iter().map(|dep| &dep.key).collect();
        authors.sort();
        authors.dedup();
        ensure!(
            authors.len() == header.deps.len() && !authors.contains(&&header.author) && header.deps.iter().all(|dep| dep.seq >= 1),
            "a held message's deps name a member twice, its author, or nothing"
        );
        Ok(header)
    }
}

/// A held message's id: SHA-256 of its plaintext.
pub fn id(plaintext: &[u8]) -> [u8; 32] {
    Sha256::digest(plaintext).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use serde_json::json;

    fn header(key: &SigningKey) -> Header {
        Header {
            group: Bytes(vec![1; 16]),
            author: Bytes(key.verifying_key().to_bytes().to_vec()),
            joined: 3,
            seq: 2,
            prev: Some(Bytes(vec![4; 32])),
            deps: vec![Ref { key: Bytes(vec![5; 32]), joined: 0, seq: 7, id: Bytes(vec![6; 32]) }],
            reply_to: None,
            payload: json!({ "type": "message", "content": "hi" }),
        }
    }

    fn verify(key: &[u8], signed: &[u8], sig: &[u8]) -> bool {
        let key = ed25519_dalek::VerifyingKey::from_bytes(key.try_into().unwrap()).unwrap();
        key.verify_strict(signed, &Signature::from_slice(sig).unwrap()).is_ok()
    }

    #[test]
    fn signed_headers_round_trip_and_bind_their_bytes() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let plaintext = header(&key).sign(|signed| key.sign(signed).to_bytes().to_vec());
        assert_eq!(Header::open(&plaintext, verify).unwrap(), header(&key));
        assert_eq!(id(&plaintext), id(&header(&key).sign(|signed| key.sign(signed).to_bytes().to_vec())), "signing is deterministic");
        let text = String::from_utf8(plaintext[..plaintext.len() - 64].to_vec()).unwrap();
        assert!(text.contains(r#""deps":[["#), "{text}");
        let mut forged = plaintext.clone();
        forged[10] ^= 1;
        assert!(Header::open(&forged, verify).is_err());
        let other = SigningKey::from_bytes(&[8; 32]);
        let mut theirs = header(&key);
        theirs.author = Bytes(other.verifying_key().to_bytes().to_vec());
        assert!(Header::open(&theirs.sign(|signed| key.sign(signed).to_bytes().to_vec()), verify).is_err(), "signed by another key");
    }

    #[test]
    fn malformed_headers_are_refused() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let sign = |h: Header| h.sign(|signed| key.sign(signed).to_bytes().to_vec());
        let me = Bytes(key.verifying_key().to_bytes().to_vec());
        let cases = [
            Header { prev: None, ..header(&key) },
            Header { seq: 1, ..header(&key) },
            Header { payload: json!({ "content": "untyped" }), ..header(&key) },
            Header { deps: vec![Ref { key: me, joined: 3, seq: 1, id: Bytes(vec![1; 32]) }], ..header(&key) },
            Header { deps: vec![header(&key).deps[0].clone(), header(&key).deps[0].clone()], ..header(&key) },
        ];
        for case in cases {
            assert!(Header::open(&sign(case.clone()), verify).is_err(), "{case:?}");
        }
        assert!(Header::open(&sign(Header { seq: 1, prev: None, ..header(&key) }), verify).is_ok());
    }
}
