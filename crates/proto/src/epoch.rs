use anyhow::{Result, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::Bytes;

const TRANSITION: &[u8] = b"letmeknow transition v1\0";
const ADMISSION: &[u8] = b"letmeknow admission checkpoint v1\0";
pub const TRANSITION_BYTES: usize = TRANSITION.len() + 16 + 3 * 8 + 8 * 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub epoch: u64,
    #[serde(with = "fixed")]
    pub service: [u8; 32],
    #[serde(with = "fixed")]
    pub log_ref: [u8; 32],
    pub base: u64,
    #[serde(with = "fixed")]
    pub history: [u8; 32],
}

impl Anchor {
    pub fn genesis(group: &[u8; 16], service: [u8; 32], log_ref: [u8; 32]) -> Self {
        let history = Sha256::digest([
            b"letmeknow history genesis v1\0".as_slice(), group, &0u64.to_be_bytes(),
            &service, &log_ref, &0u64.to_be_bytes(),
        ].concat()).into();
        Self { epoch: 0, service, log_ref, base: 0, history }
    }

    pub fn position(&self, local: u64) -> Result<u64> {
        self.base.checked_add(local).ok_or_else(|| anyhow::anyhow!("global position overflow"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub group: [u8; 16],
    pub source: Anchor,
    pub cut: u64,
    pub cut_hash: [u8; 32],
    pub terminal_wire_digest: [u8; 32],
    pub inner_entry_digest: [u8; 32],
    pub successor_service: [u8; 32],
    pub successor_ref: [u8; 32],
}

impl Transition {
    pub fn encode(&self) -> Vec<u8> {
        [
            TRANSITION, &self.group, &self.source.epoch.to_be_bytes(), &self.source.service,
            &self.source.log_ref, &self.source.base.to_be_bytes(), &self.source.history,
            &self.cut.to_be_bytes(), &self.cut_hash, &self.terminal_wire_digest,
            &self.inner_entry_digest, &self.successor_service, &self.successor_ref,
        ].concat()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == TRANSITION_BYTES && bytes.starts_with(TRANSITION), "invalid transition encoding");
        let mut rest = &bytes[TRANSITION.len()..];
        fn take<const N: usize>(rest: &mut &[u8]) -> [u8; N] {
            let (value, tail) = rest.split_at(N);
            *rest = tail;
            value.try_into().unwrap()
        }
        let group = take(&mut rest);
        let source = Anchor {
            epoch: u64::from_be_bytes(take(&mut rest)), service: take(&mut rest), log_ref: take(&mut rest),
            base: u64::from_be_bytes(take(&mut rest)), history: take(&mut rest),
        };
        let witness = Self {
            group, source, cut: u64::from_be_bytes(take(&mut rest)), cut_hash: take(&mut rest),
            terminal_wire_digest: take(&mut rest), inner_entry_digest: take(&mut rest),
            successor_service: take(&mut rest), successor_ref: take(&mut rest),
        };
        witness.successor()?;
        Ok(witness)
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    pub fn successor(&self) -> Result<Anchor> {
        ensure!(self.cut > 0, "empty transition cut");
        Ok(Anchor {
            epoch: self.source.epoch.checked_add(1).ok_or_else(|| anyhow::anyhow!("epoch overflow"))?,
            service: self.successor_service, log_ref: self.successor_ref,
            base: self.source.position(self.cut)?, history: self.hash(),
        })
    }
}

impl Serialize for Transition {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Bytes(self.encode()).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Transition {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::decode(&Bytes::deserialize(d)?.0).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub transition: Transition,
    #[serde(with = "fixed")]
    pub package: [u8; 32],
    #[serde(with = "fixed")]
    pub added_key: [u8; 32],
    #[serde(with = "fixed")]
    pub signer: [u8; 32],
    pub signature: Bytes,
}

impl Checkpoint {
    pub fn signed(&self, welcome: &[u8]) -> Vec<u8> {
        [ADMISSION, &self.transition.hash(), Sha256::digest(welcome).as_slice(), &self.package, &self.added_key].concat()
    }

    pub fn verify(&self, welcome: &[u8]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.signer) else { return false };
        let Ok(signature) = Signature::from_slice(&self.signature.0) else { return false };
        !key.is_weak() && key.verify_strict(&self.signed(welcome), &signature).is_ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateLink {
    pub link: String,
    pub anchor: Anchor,
    pub position: u64,
    #[serde(with = "fixed")]
    pub prefix: [u8; 32],
}

pub mod fixed {
    use super::*;

    pub fn serialize<S: Serializer, const N: usize>(value: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        Bytes(value.to_vec()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
        Bytes::deserialize(d)?.0.try_into().map_err(|_| serde::de::Error::custom("wrong fixed byte length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn canonical_transition_and_admission() {
        let source = Anchor::genesis(&[1; 16], [2; 32], [3; 32]);
        let w = Transition {
            group: [1; 16], source, cut: 7, cut_hash: [4; 32], terminal_wire_digest: [5; 32],
            inner_entry_digest: [6; 32], successor_service: [2; 32], successor_ref: [7; 32],
        };
        let bytes = w.encode();
        assert_eq!(bytes.len(), TRANSITION_BYTES);
        assert_eq!(&bytes[TRANSITION.len() + 16..TRANSITION.len() + 24], &0u64.to_be_bytes());
        assert_eq!(Transition::decode(&bytes).unwrap(), w);
        assert!(Transition::decode(&[bytes.clone(), vec![0]].concat()).is_err());
        let mut bad = w.clone();
        bad.cut = 0;
        assert!(bad.successor().is_err());
        bad.cut = 1;
        bad.source.base = u64::MAX;
        assert!(bad.successor().is_err());
        let next = w.successor().unwrap();
        assert_eq!((next.epoch, next.base, next.history), (1, 7, w.hash()));
        let key = SigningKey::from_bytes(&[8; 32]);
        let mut checkpoint = Checkpoint {
            transition: w, package: [9; 32], added_key: [10; 32], signer: key.verifying_key().to_bytes(), signature: Bytes::default(),
        };
        checkpoint.signature = Bytes(key.sign(&checkpoint.signed(b"welcome")).to_bytes().to_vec());
        assert!(checkpoint.verify(b"welcome"));
        assert!(!checkpoint.verify(b"another welcome"));
        checkpoint.package[0] ^= 1;
        assert!(!checkpoint.verify(b"welcome"));
    }
}
