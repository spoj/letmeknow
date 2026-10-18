//! Constant-space authentication. Callers retain complete verified digest paths separately.

use anyhow::{Result, ensure};
use ed25519_dalek::VerifyingKey;
use lmk_proto::{head::{self, Head}, membership::{Page, valid_page}};

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

    /// Checks a page extends this frontier to its head, and returns it.
    pub fn verify_page(&self, page: Page) -> Result<Page> {
        self.check(&page.head, None)?;
        ensure!(page.after == self.length && valid_page(&page.entries), InvalidProof);
        ensure!(page.after.checked_add(page.entries.len() as u64) == Some(page.head.length), InvalidProof);
        let hash = page.entries.iter().fold(self.hash, |hash, entry| head::next(&hash, &entry.0));
        ensure!(hash == page.head.hash, InvalidProof);
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use lmk_proto::{Bytes, membership::PAGE_ROWS};

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
        assert_eq!(&signed.head.hash, empty.hash());
        assert!(signed.head.verify(&key.verifying_key()));
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
        let frontier = Frontier::from_head(s, d, empty.verify_page(long.clone()).unwrap().head).unwrap();
        frontier.check(&short, Some(short.hash)).unwrap();
        let resigned = Head::sign(&key, &d, 2, long.head.hash, 100);
        frontier.check(&resigned, None).unwrap();
        let fork = page(&key, &d, &[b"x"]).head;
        frontier.check(&fork, None).unwrap();
        let err = frontier.check(&fork, Some(short.hash)).unwrap_err().downcast::<Contradiction>().unwrap();
        assert_eq!((err.ours, err.theirs), (long.head.clone(), fork));
        let equal_fork = page(&key, &d, &[b"x", b"y"]).head;
        assert!(frontier.check(&equal_fork, None).unwrap_err().is::<Contradiction>());
        let shorter = Frontier::from_head(s, d, short).unwrap();
        let bad_extension = Page { after: 1, entries: vec![Bytes(b"garbage".to_vec())], head: long.head };
        assert!(shorter.verify_page(bad_extension).unwrap_err().is::<InvalidProof>());
    }

    #[test]
    fn pages_chain_without_a_total_ceiling() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let s = key.verifying_key().to_bytes();
        let d = head::reference(&s, &[8; 32]);
        let mut frontier = Frontier::empty(s, d);
        for _ in 0..3 {
            let entries = vec![Bytes(vec![4; 32]); PAGE_ROWS];
            let hash = entries.iter().fold(*frontier.hash(), |h, e| head::next(&h, &e.0));
            let length = frontier.length() + PAGE_ROWS as u64;
            let page = Page { after: frontier.length(), entries, head: Head::sign(&key, &d, length, hash, 0) };
            frontier = Frontier::from_head(s, d, frontier.verify_page(page).unwrap().head).unwrap();
        }
        assert_eq!(frontier.length(), 3 * PAGE_ROWS as u64);
    }
}
