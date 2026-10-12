//! Constant-space authentication. Callers retain complete verified digest paths separately.

use anyhow::{Result, ensure};
use ed25519_dalek::VerifyingKey;
use lmk_proto::{head::{self, Head}, membership::{Page, PAGE_ROWS, valid_page}};

#[derive(Debug, thiserror::Error)]
#[error("invalid membership signature")]
pub struct Forged;

#[derive(Debug, thiserror::Error)]
#[error("unexpected membership authority or reference")]
pub struct WrongLog;

#[derive(Debug, thiserror::Error)]
#[error("invalid membership proof")]
pub struct InvalidProof;

#[derive(Debug, thiserror::Error)]
#[error("the membership service signed incompatible histories")]
pub struct Contradiction {
    pub ours: Head,
    pub theirs: Head,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier {
    service: [u8; 32],
    log_ref: [u8; 32],
    length: u64,
    hash: [u8; 32],
    head: Option<Head>,
}

impl Frontier {
    pub fn empty(service: [u8; 32], log_ref: [u8; 32]) -> Self {
        Self { service, log_ref, length: 0, hash: head::start(&service, &log_ref), head: None }
    }

    /// The caller authenticates the anchor's association/admission; a latest RPC is not an anchor.
    pub fn from_head(service: [u8; 32], log_ref: [u8; 32], head: Head) -> Result<Self> {
        let mut frontier = Self::empty(service, log_ref);
        frontier.check(&head, None)?;
        frontier.length = head.length;
        frontier.hash = head.hash;
        frontier.head = Some(head);
        Ok(frontier)
    }

    pub fn service(&self) -> &[u8; 32] { &self.service }
    pub fn log_ref(&self) -> &[u8; 32] { &self.log_ref }
    pub fn length(&self) -> u64 { self.length }
    pub fn hash(&self) -> &[u8; 32] { &self.hash }
    pub fn head(&self) -> Option<&Head> { self.head.as_ref() }

    /// `hash_at` must come from the caller's retained, independently verified path to this frontier.
    pub fn check(&self, head: &Head, hash_at: Option<[u8; 32]>) -> Result<()> {
        ensure!(head.log_ref == self.log_ref, WrongLog);
        let key = VerifyingKey::from_bytes(&self.service).map_err(|_| WrongLog)?;
        ensure!(head.verify(&key), Forged);
        let hash = if head.length == self.length { Some(self.hash) } else if head.length < self.length { hash_at } else { None };
        if hash.is_some_and(|hash| head.hash != hash) {
            if let Some(ours) = &self.head {
                return Err(Contradiction { ours: ours.clone(), theirs: head.clone() }.into());
            }
            return Err(InvalidProof.into());
        }
        if head.length == 0 {
            ensure!(head.hash == head::start(&self.service, &self.log_ref), InvalidProof);
        }
        Ok(())
    }

    pub fn proof(&self, target: Head) -> Result<Proof> {
        self.check(&target, None)?;
        ensure!(target.length >= self.length, InvalidProof);
        Ok(Proof { service: self.service, log_ref: self.log_ref, position: self.length, hash: self.hash, target })
    }

    pub fn verify_page(&self, page: Page) -> Result<VerifiedPage> {
        let mut proof = self.proof(page.head.clone())?;
        ensure!(page.after == self.length && valid_page(&page.entries), InvalidProof);
        ensure!(page.after.checked_add(page.entries.len() as u64) == Some(page.head.length), InvalidProof);
        for entry in &page.entries {
            proof.hash = head::next(&proof.hash, &entry.0);
            proof.position += 1;
        }
        let frontier = proof.finish()?;
        Ok(VerifiedPage { page, frontier })
    }
}

pub struct Proof {
    service: [u8; 32],
    log_ref: [u8; 32],
    position: u64,
    hash: [u8; 32],
    target: Head,
}

impl Proof {
    pub fn push(&mut self, digests: &[[u8; 32]]) -> Result<()> {
        ensure!(digests.len() <= PAGE_ROWS, InvalidProof);
        let end = self.position.checked_add(digests.len() as u64).ok_or(InvalidProof)?;
        ensure!(end <= self.target.length, InvalidProof);
        for digest in digests { self.hash = head::next_digest(&self.hash, digest); }
        self.position = end;
        Ok(())
    }

    pub fn finish(self) -> Result<Frontier> {
        ensure!(self.position == self.target.length && self.hash == self.target.hash, InvalidProof);
        Ok(Frontier { service: self.service, log_ref: self.log_ref, length: self.position, hash: self.hash, head: Some(self.target) })
    }
}

#[derive(Debug)]
pub struct VerifiedPage {
    page: Page,
    frontier: Frontier,
}

impl VerifiedPage {
    pub fn page(&self) -> &Page { &self.page }
    pub fn into_page(self) -> Page { self.page }
    pub fn frontier(&self) -> &Frontier { &self.frontier }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use lmk_proto::Bytes;

    fn page(key: &SigningKey, d: &[u8; 32], entries: &[&[u8]]) -> Page {
        let hash = entries.iter().fold(head::start(key.verifying_key().as_bytes(), d), |h, e| head::next(&h, e));
        Page { after: 0, entries: entries.iter().map(|e| Bytes(e.to_vec())).collect(), head: Head::sign(key, d, entries.len() as u64, hash, 42) }
    }

    #[test]
    fn empty_signatures_and_expected_destination() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let s = key.verifying_key().to_bytes();
        let d = head::reference(&s, &[8; 32]);
        let empty = Frontier::empty(s, d);
        assert!(empty.head().is_none());
        let signed = empty.verify_page(page(&key, &d, &[])).unwrap();
        assert_eq!(signed.frontier().hash(), empty.hash());
        assert!(signed.frontier().head().unwrap().verify(&key.verifying_key()));
        assert!(empty.verify_page(page(&key, &[2; 32], &[])).unwrap_err().is::<WrongLog>());
        assert!(empty.verify_page(page(&SigningKey::from_bytes(&[9; 32]), &d, &[])).unwrap_err().is::<Forged>());
        let unsigned = Head { sig: Bytes::default(), ..page(&key, &d, &[]).head };
        assert!(Frontier::from_head(s, d, unsigned).unwrap_err().is::<Forged>());
        let impossible = Head::sign(&key, &d, 0, [0; 32], 0);
        assert!(Frontier::from_head(s, d, impossible).unwrap_err().is::<InvalidProof>());
    }

    #[test]
    fn only_independently_authenticated_conflicts_are_evidence() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let s = key.verifying_key().to_bytes();
        let d = head::reference(&s, &[8; 32]);
        let empty = Frontier::empty(s, d);
        let short = page(&key, &d, &[b"a"]).head;
        let long = page(&key, &d, &[b"a", b"b"]);
        let mut tampered = long.clone();
        tampered.entries[0] = Bytes(b"tampered".to_vec());
        assert!(empty.verify_page(tampered).unwrap_err().is::<InvalidProof>());
        assert!(empty.head().is_none());
        let verified = empty.verify_page(long.clone()).unwrap();
        verified.frontier().check(&short, Some(short.hash)).unwrap();
        let resigned = Head::sign(&key, &d, 2, long.head.hash, 100);
        verified.frontier().check(&resigned, None).unwrap();
        let fork = page(&key, &d, &[b"x"]).head;
        verified.frontier().check(&fork, None).unwrap();
        let err = verified.frontier().check(&fork, Some(short.hash)).unwrap_err().downcast::<Contradiction>().unwrap();
        assert_eq!((err.ours, err.theirs), (long.head.clone(), fork));
        let equal_fork = page(&key, &d, &[b"x", b"y"]).head;
        assert!(verified.frontier().check(&equal_fork, None).unwrap_err().is::<Contradiction>());
        let shorter = Frontier::from_head(s, d, short).unwrap();
        let bad_extension = Page { after: 1, entries: vec![Bytes(b"garbage".to_vec())], head: long.head };
        assert!(shorter.verify_page(bad_extension).unwrap_err().is::<InvalidProof>());
    }

    #[test]
    fn rolling_proof_has_no_eight_mib_total_ceiling() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let s = key.verifying_key().to_bytes();
        let d = head::reference(&s, &[8; 32]);
        let empty = Frontier::empty(s, d);
        let digest = [4; 32];
        let n = (8 << 20) / 32 + 1;
        let hash = (0..n).fold(*empty.hash(), |h, _| head::next_digest(&h, &digest));
        let target = Head::sign(&key, &d, n, hash, 0);
        let mut proof = empty.proof(target.clone()).unwrap();
        let chunk = [digest; PAGE_ROWS];
        for _ in 0..n / PAGE_ROWS as u64 { proof.push(&chunk).unwrap(); }
        proof.push(&[digest]).unwrap();
        assert_eq!(proof.finish().unwrap().head(), Some(&target));
        let mut bad = empty.proof(Head::sign(&key, &d, 1, hash, 0)).unwrap();
        bad.push(&[digest]).unwrap();
        assert!(bad.finish().unwrap_err().is::<InvalidProof>());
    }
}
