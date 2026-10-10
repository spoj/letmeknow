//! The `peer` stream between two members sharing groups, and the `admission` stream on which a joiner asks a member to
//! admit it.

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

/// A joiner's request, the one frame it writes on an `admission` stream: an invite's secret, or the group open to the
/// identity its KeyPackage's credential speaks as. The member answers with an `Answer<Admitted>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Join {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Bytes>,
    pub key_package: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admitted {
    /// The Welcome of the commit entry that added the joiner.
    pub welcome: Bytes,
    /// The Add's position in the group's log: the joiner reads on from there.
    pub position: u64,
    /// A file link to the state of the group's kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
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
        assert!(serde_json::from_str::<Frame>(r#"{"doc":{"group":"AQ"}}"#).is_err(), "a kind has no frames");
        let join = Join { secret: Some(Bytes(vec![2])), group: None, key_package: Bytes(vec![3]) };
        assert_eq!(serde_json::to_string(&join).unwrap(), r#"{"secret":"Ag","key_package":"Aw"}"#);
    }
}
