//! A `peer` stream between two sessions that share groups, and an `invite` stream.

use serde::{Deserialize, Serialize};

use crate::{Bytes, head::Head};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame {
    Hello { groups: Vec<Hello> },
    /// Log entries the other lacks, ending at `head`.
    Commits { group: Bytes, entries: Vec<Bytes>, head: Head },
    /// A negentropy message.
    Reconcile { group: Bytes, msg: Bytes },
    /// MLS ciphertexts.
    Messages { group: Bytes, items: Vec<Bytes> },
    /// SHA-256 of the doc's `txn.snapshot().encode_v1()`.
    Doc { group: Bytes, snapshot: Bytes },
    /// A Yjs state vector; answered by a `diff` message.
    DocSv { group: Bytes, sv: Bytes },
    /// BLAKE3 hashes of files.
    Want { group: Bytes, files: Vec<Bytes> },
    Have { group: Bytes, files: Vec<Bytes> },
    /// A request to join an open group.
    Join { group: Bytes, key_package: Bytes },
    Admitted { group: Bytes, admitted: Admitted },
    Refused { group: Bytes, refused: String },
}

/// One group's state, in `hello`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub group: Bytes,
    pub epoch: u64,
    pub head: Head,
    /// The lowest epoch the sender accepts.
    pub floor: u64,
    /// The epoch the sender joined.
    pub joined: u64,
}

/// The joiner's request on an `invite` stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRequest {
    pub secret: Bytes,
    #[serde(flatten)]
    pub joiner: Joiner,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Joiner {
    Member { key_package: Bytes },
    Device { device: Bytes, device_name: String },
}

/// The answer to an invite or a join: answered as `Answer<Admitted>` on an `invite` stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admitted {
    pub welcome: Bytes,
    /// The log position the joiner reads from.
    pub position: u64,
    /// For a doc: a file link to its state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_request_shapes() {
        let member = InviteRequest { secret: Bytes(vec![1]), joiner: Joiner::Member { key_package: Bytes(vec![2]) } };
        let json = serde_json::to_string(&member).unwrap();
        assert_eq!(json, r#"{"secret":"AQ","key_package":"Ag"}"#);
        assert_eq!(serde_json::from_str::<InviteRequest>(&json).unwrap(), member);
        let device: InviteRequest = serde_json::from_str(r#"{"secret":"AQ","device":"Aw","device_name":"phone"}"#).unwrap();
        assert_eq!(device.joiner, Joiner::Device { device: Bytes(vec![3]), device_name: "phone".into() });
    }
}
