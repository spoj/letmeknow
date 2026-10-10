//! 0.13's `peer` stream between two members sharing groups.

use serde::{Deserialize, Serialize};

use crate::{Bytes, head::Head, ranges::Ranges};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame {
    /// The sender's summaries of groups, and the heads of the key logs their members follow.
    Hello { groups: Vec<Summary>, heads: Vec<Head> },
    /// Entries of a log the other lacks, ending at `head`.
    Entries { log: Bytes, entries: Vec<Bytes>, head: Head },
    /// Ciphertexts of counted positions: pushed at send, or the answer to `want`, whose positions up to where the
    /// sender stopped are `answers`.
    Messages {
        group: Bytes,
        items: Vec<Item>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answers: Option<Ranges>,
    },
    /// Message positions asked of one holder.
    Want { group: Bytes, positions: Ranges },
    /// BLAKE3 hashes of files.
    WantFiles { group: Bytes, files: Vec<Bytes> },
    Have { group: Bytes, files: Vec<Bytes> },
    /// A file link to the state of the group's kind; without one, a request for one.
    State {
        group: Bytes,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        link: Option<String>,
    },
    /// Live payloads' MLS ciphertexts.
    Live { group: Bytes, items: Vec<Bytes> },
}

/// A member's state of a group. Ranges count positions with no message (commits, skipped entries) as covered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub group: Bytes,
    /// The group log's head: the last position read from the service.
    pub head: Head,
    /// Within H: the positions it holds, has read (chat), and is fetching.
    pub held: Ranges,
    pub read: Ranges,
    pub fetching: Ranges,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub position: u64,
    pub ciphertext: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        let want = Frame::Want { group: Bytes(vec![1]), positions: Ranges::from(vec![(1, 10), (13, 50)]) };
        assert_eq!(serde_json::to_string(&want).unwrap(), r#"{"want":{"group":"AQ","positions":[[1,10],[13,50]]}}"#);
        let push = Frame::Messages { group: Bytes(vec![1]), items: vec![Item { position: 3, ciphertext: Bytes(vec![2]) }], answers: None };
        let text = serde_json::to_string(&push).unwrap();
        assert_eq!(text, r#"{"messages":{"group":"AQ","items":[{"position":3,"ciphertext":"Ag"}]}}"#);
        assert_eq!(serde_json::from_str::<Frame>(&text).unwrap(), push);
        let files: Frame = serde_json::from_str(r#"{"want_files":{"group":"AQ","files":[]}}"#).unwrap();
        assert!(matches!(files, Frame::WantFiles { .. }));
    }
}
