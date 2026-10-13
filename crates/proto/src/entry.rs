//! A group log's entries: each a commit with its Welcome and its committer's signature.

use anyhow::{Context, Result, ensure};

const COMMIT: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    /// The committer's signature, with its leaf key, over `signed(commit, welcome)`.
    pub sig: Vec<u8>,
}

/// What a commit entry's signature covers, before its commit and Welcome.
const COMMIT_SIGNED: &[u8] = b"letmeknow commit v1\0";

/// What a commit entry's signature covers.
pub fn signed(commit: &[u8], welcome: Option<&[u8]>) -> Vec<u8> {
    let welcome = welcome.unwrap_or_default();
    [COMMIT_SIGNED, &(commit.len() as u32).to_be_bytes(), commit, welcome].concat()
}

impl Entry {
    /// `1 ‖ u32 length ‖ commit ‖ u32 length ‖ Welcome ‖ signature`.
    pub fn encode(&self) -> Vec<u8> {
        let welcome = self.welcome.as_deref().unwrap_or_default();
        let lengths = [(self.commit.len() as u32).to_be_bytes(), (welcome.len() as u32).to_be_bytes()];
        [&[COMMIT], &lengths[0][..], &self.commit, &lengths[1][..], welcome, &self.sig].concat()
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
        let length = u32::from_be_bytes(take(4)?.try_into()?) as usize;
        let welcome = Some(take(length)?.to_vec()).filter(|welcome| !welcome.is_empty());
        let sig = take(64)?.to_vec();
        ensure!(rest.is_empty(), "an entry with bytes left over");
        Ok(Entry { commit, welcome, sig })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_round_trip() {
        let commit = Entry { commit: vec![1, 2, 3], welcome: Some(vec![4]), sig: vec![5; 64] };
        assert_eq!(Entry::parse(&commit.encode()).unwrap(), commit);
        let bare = Entry { commit: vec![1], welcome: None, sig: vec![5; 64] };
        assert_eq!(Entry::parse(&bare.encode()).unwrap(), bare);
        assert!(Entry::parse(&[2; 65]).is_err(), "0.16's message entries are no entry");
        assert!(Entry::parse(&commit.encode()[..20]).is_err());
        assert!(Entry::parse(&[commit.encode(), vec![0]].concat()).is_err());
    }
}
