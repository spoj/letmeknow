//! A group log's entries, by their leading byte: a commit with its Welcome and its committer's signature, or a held
//! message's id and MAC.

use anyhow::{Context, Result, bail, ensure};

const COMMIT: u8 = 1;
const MESSAGE: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Commit {
        commit: Vec<u8>,
        welcome: Option<Vec<u8>>,
        /// The committer's signature, with its leaf key, over `signed(commit, welcome)`.
        sig: Vec<u8>,
    },
    Message {
        /// SHA-256 of the message's ciphertext.
        id: [u8; 32],
        /// HMAC-SHA256 of `id`, keyed by the epoch's `MLS-Exporter("letmeknow entry", "", 32)`.
        mac: [u8; 32],
    },
}

/// What a commit entry's signature covers.
pub fn signed(commit: &[u8], welcome: Option<&[u8]>) -> Vec<u8> {
    let welcome = welcome.unwrap_or_default();
    [b"letmeknow commit".as_slice(), &(commit.len() as u32).to_be_bytes(), commit, welcome].concat()
}

impl Entry {
    /// `1 ‖ u32 length ‖ commit ‖ u32 length ‖ Welcome ‖ signature`, or `2 ‖ id ‖ MAC`.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Entry::Commit { commit, welcome, sig } => {
                let welcome = welcome.as_deref().unwrap_or_default();
                let lengths = [(commit.len() as u32).to_be_bytes(), (welcome.len() as u32).to_be_bytes()];
                [&[COMMIT], &lengths[0][..], commit, &lengths[1][..], welcome, sig].concat()
            }
            Entry::Message { id, mac } => [&[MESSAGE], &id[..], &mac[..]].concat(),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let (&kind, mut rest) = bytes.split_first().context("an empty entry")?;
        let mut take = |n: usize| -> Result<&[u8]> {
            ensure!(rest.len() >= n, "a truncated entry");
            let (taken, left) = rest.split_at(n);
            rest = left;
            Ok(taken)
        };
        let entry = match kind {
            COMMIT => {
                let length = u32::from_be_bytes(take(4)?.try_into()?) as usize;
                let commit = take(length)?.to_vec();
                let length = u32::from_be_bytes(take(4)?.try_into()?) as usize;
                let welcome = Some(take(length)?.to_vec()).filter(|welcome| !welcome.is_empty());
                let sig = take(64)?.to_vec();
                Entry::Commit { commit, welcome, sig }
            }
            MESSAGE => Entry::Message { id: take(32)?.try_into()?, mac: take(32)?.try_into()? },
            other => bail!("an entry of unknown kind {other}"),
        };
        ensure!(rest.is_empty(), "an entry with bytes left over");
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_round_trip() {
        let commit = Entry::Commit { commit: vec![1, 2, 3], welcome: Some(vec![4]), sig: vec![5; 64] };
        assert_eq!(Entry::parse(&commit.encode()).unwrap(), commit);
        let bare = Entry::Commit { commit: vec![1], welcome: None, sig: vec![5; 64] };
        assert_eq!(Entry::parse(&bare.encode()).unwrap(), bare);
        let message = Entry::Message { id: [7; 32], mac: [8; 32] };
        assert_eq!(message.encode().len(), 65);
        assert_eq!(Entry::parse(&message.encode()).unwrap(), message);
        assert!(Entry::parse(&[3]).is_err());
        assert!(Entry::parse(&message.encode()[..64]).is_err());
        assert!(Entry::parse(&[message.encode(), vec![0]].concat()).is_err());
    }
}
