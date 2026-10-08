//! A reader's own hash chain of a log, and the checks it makes on a service's heads.

use std::{collections::HashMap, sync::Mutex};

use anyhow::{Result, ensure};
use ed25519_dalek::VerifyingKey;
use lmk_proto::{
    Bytes,
    head::{self, Head},
};

/// A head whose signature is not the service's.
#[derive(Debug, thiserror::Error)]
#[error("a head for log {} is not signed by the membership service", hex::encode(&.0.log.0))]
pub struct Forged(pub Head);

/// Two heads that cannot both be true: proof that the service showed different logs.
#[derive(Debug, thiserror::Error)]
#[error("the membership service contradicted itself on log {}: length {} vs {}", hex::encode(&.ours.log.0), .ours.length, .theirs.length)]
pub struct Contradiction {
    /// The newest head the reader's chain rests on.
    pub ours: Head,
    pub theirs: Head,
}

/// The hashes h_start..=h_len of a log, and the newest head covering h_len. A chain starts at 0, or, for a reader
/// that joined later, at the first head it was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    pub start: u64,
    pub hashes: Vec<[u8; 32]>,
    pub head: Head,
}

impl Chain {
    pub fn new(log: &[u8]) -> Self {
        let h0 = head::start(log);
        let head = Head { log: log.into(), length: 0, hash: h0.into(), time: 0, sig: Bytes::default() };
        Chain { start: 0, hashes: vec![h0], head }
    }

    pub fn anchored(head: Head) -> Self {
        let hash = head.hash.0.as_slice().try_into().expect("a verified head's hash is 32 bytes");
        Chain { start: head.length, hashes: vec![hash], head }
    }

    pub fn len(&self) -> u64 {
        self.start + self.hashes.len() as u64 - 1
    }

    pub fn hash_at(&self, position: u64) -> Option<[u8; 32]> {
        position.checked_sub(self.start).and_then(|i| self.hashes.get(i as usize)).copied()
    }

    /// Fails if `head` contradicts this chain: another hash at a length it covers.
    pub fn check(&self, head: &Head) -> Result<(), Contradiction> {
        match self.hash_at(head.length) {
            Some(hash) if hash.as_slice() != head.hash.0 => {
                Err(Contradiction { ours: self.head.clone(), theirs: head.clone() })
            }
            _ => Ok(()),
        }
    }

    /// Adds `entries`, which follow position `after` (within the chain) and end at `head`.
    pub fn extend(&mut self, after: u64, entries: &[Bytes], head: &Head) -> Result<(), Contradiction> {
        let contradiction = || Contradiction { ours: self.head.clone(), theirs: head.clone() };
        let mut hash = self.hash_at(after).expect("after is within the chain");
        let mut position = after;
        let mut fresh = Vec::new();
        for entry in entries {
            hash = head::next(&hash, &entry.0);
            position += 1;
            match self.hash_at(position) {
                Some(ours) if ours != hash => return Err(contradiction()),
                Some(_) => {}
                None => fresh.push(hash),
            }
        }
        if position != head.length || hash.as_slice() != head.hash.0 {
            return Err(contradiction());
        }
        self.hashes.extend(fresh);
        if head.length >= self.head.length {
            self.head = head.clone();
        }
        Ok(())
    }
}

/// A client's chains, and the service key its heads must carry (none for a folder).
pub(crate) struct Chains {
    key: Option<VerifyingKey>,
    chains: Mutex<HashMap<Vec<u8>, Chain>>,
}

impl Chains {
    pub fn new(key: Option<VerifyingKey>) -> Self {
        Chains { key, chains: Mutex::default() }
    }

    pub fn get(&self, log: &[u8]) -> Option<Chain> {
        self.chains.lock().unwrap().get(log).cloned()
    }

    pub fn set(&self, chain: Chain) {
        self.chains.lock().unwrap().insert(chain.head.log.0.clone(), chain);
    }

    fn signed(&self, log: &[u8], head: &Head) -> Result<()> {
        ensure!(head.log.0 == log, "a head for another log");
        if let Some(key) = &self.key {
            ensure!(head.verify(key), Forged(head.clone()));
        }
        Ok(())
    }

    pub fn head(&self, log: &[u8], head: &Head) -> Result<()> {
        self.signed(log, head)?;
        if let Some(chain) = self.chains.lock().unwrap().get(log) {
            chain.check(head)?;
        }
        Ok(())
    }

    /// Checks entries after `after` that end at `head`, and extends the chain with them where it can.
    pub fn page(&self, log: &[u8], after: u64, entries: &[Bytes], head: &Head) -> Result<()> {
        self.signed(log, head)?;
        let mut chains = self.chains.lock().unwrap();
        let chain = chains.entry(log.to_vec()).or_insert_with(|| {
            if after == 0 { Chain::new(log) } else { Chain::anchored(head.clone()) }
        });
        if entries.is_empty() || after > chain.len() || after < chain.start {
            chain.check(head)?;
        } else {
            chain.extend(after, entries, head)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn chain_of(log: &[u8], entries: &[&[u8]]) -> Vec<[u8; 32]> {
        let mut hashes = vec![head::start(log)];
        for entry in entries {
            hashes.push(head::next(hashes.last().unwrap(), entry));
        }
        hashes
    }

    fn bytes(entries: &[&[u8]]) -> Vec<Bytes> {
        entries.iter().map(|e| Bytes(e.to_vec())).collect()
    }

    #[test]
    fn verifies_and_extends() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let chains = Chains::new(Some(key.verifying_key()));
        let hashes = chain_of(b"log", &[b"a", b"b", b"c"]);
        let head2 = Head::sign(&key, b"log", 2, hashes[2], 1);
        chains.page(b"log", 0, &bytes(&[b"a", b"b"]), &head2).unwrap();
        let head3 = Head::sign(&key, b"log", 3, hashes[3], 2);
        chains.page(b"log", 1, &bytes(&[b"b", b"c"]), &head3).unwrap();
        assert_eq!(chains.get(b"log").unwrap().len(), 3);
        chains.head(b"log", &head2).unwrap();

        let forged = Head::sign(&SigningKey::from_bytes(&[2; 32]), b"log", 3, hashes[3], 2);
        assert!(chains.head(b"log", &forged).unwrap_err().is::<Forged>());

        let other = chain_of(b"log", &[b"a", b"x"]);
        let split = Head::sign(&key, b"log", 2, other[2], 3);
        let err = chains.head(b"log", &split).unwrap_err().downcast::<Contradiction>().unwrap();
        assert_eq!((err.ours, err.theirs), (head3.clone(), split.clone()));
        assert!(chains.page(b"log", 1, &bytes(&[b"x"]), &split).unwrap_err().is::<Contradiction>());

        let lying = Head::sign(&key, b"log", 4, hashes[3], 4);
        assert!(chains.page(b"log", 3, &bytes(&[b"d"]), &lying).unwrap_err().is::<Contradiction>());
        assert_eq!(chains.get(b"log").unwrap().head, head3);
    }

    #[test]
    fn anchors_a_late_reader() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let chains = Chains::new(Some(key.verifying_key()));
        let hashes = chain_of(b"log", &[b"a", b"b", b"c"]);
        let head3 = Head::sign(&key, b"log", 3, hashes[3], 1);
        chains.page(b"log", 2, &bytes(&[b"c"]), &head3).unwrap();
        let chain = chains.get(b"log").unwrap();
        assert_eq!((chain.start, chain.len()), (3, 3));
        chains.head(b"log", &Head::sign(&key, b"log", 1, hashes[1], 2)).unwrap();
    }
}
