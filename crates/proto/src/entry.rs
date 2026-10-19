//! A group log's entries: each a commit with its committer's signature.

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

const COMMIT: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub commit: Vec<u8>,
    /// The committer's signature, with its leaf key, over `signed(commit)`.
    pub sig: Vec<u8>,
}

/// What a commit entry's signature covers.
const COMMIT_SIGNED: &[u8] = b"letmeknow commit v2\0";

pub fn signed(commit: &[u8]) -> Vec<u8> {
    [COMMIT_SIGNED, commit].concat()
}

/// What a Welcome's signature covers: the entry of the commit it came with, the cut the joiner starts at (as JSON), and
/// the Welcome.
const WELCOME_SIGNED: &[u8] = b"letmeknow welcome v2\0";

pub fn welcome_signed(entry: &[u8], cut: &[u8], welcome: &[u8]) -> Vec<u8> {
    [WELCOME_SIGNED, Sha256::digest(entry).as_slice(), Sha256::digest(cut).as_slice(), welcome].concat()
}

impl Entry {
    /// `1 ‖ u32 length ‖ commit ‖ signature`.
    pub fn encode(&self) -> Vec<u8> {
        [&[COMMIT][..], &(self.commit.len() as u32).to_be_bytes(), &self.commit, &self.sig].concat()
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let (&kind, mut rest) = bytes.split_first().context("an empty entry")?;
        ensure!(kind == COMMIT, "an entry of unknown kind {kind}");
        let mut take = |n: usize| -> Result<&[u8]> {
            ensure!(rest.len() >= n, "a truncated entry");
            let (taken, left) = rest.split_at(n);
            rest = left;
            Ok(taken)
        };
        let length = u32::from_be_bytes(take(4)?.try_into()?) as usize;
        let commit = take(length)?.to_vec();
        let sig = take(64)?.to_vec();
        ensure!(rest.is_empty(), "an entry with bytes left over");
        Ok(Entry { commit, sig })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_round_trip_without_a_welcome() {
        let entry = Entry { commit: vec![1, 2, 3], sig: vec![5; 64] };
        assert_eq!(entry.encode(), [&[1, 0, 0, 0, 3, 1, 2, 3][..], &[5u8; 64][..]].concat(), "an entry is its commit and signature");
        assert_eq!(Entry::parse(&entry.encode()).unwrap(), entry);
        assert!(Entry::parse(&[2; 65]).is_err(), "0.16's message entries are no entry");
        assert!(Entry::parse(&entry.encode()[..20]).is_err());
        assert!(Entry::parse(&[entry.encode(), vec![0]].concat()).is_err());
    }
}
