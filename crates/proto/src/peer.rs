//! A `peer` stream between two sessions that share groups, and an `invite` stream.

use serde::{Deserialize, Serialize};

use crate::{Bytes, head::Head};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame {
    /// The sender's state of the groups both are in, and the newest signed heads it holds of their logs.
    Hello { groups: Vec<Hello>, heads: Vec<Head> },
    /// Entries of a log the other lacks, ending at `head`.
    Entries { log: Bytes, entries: Vec<Bytes>, head: Head },
    /// A negentropy message.
    Reconcile { group: Bytes, msg: Bytes },
    /// MLS ciphertexts.
    Messages { group: Bytes, items: Vec<Bytes> },
    /// The answer to `messages`: the ids of the items the receiver took, and of those it refused.
    Receipt { group: Bytes, held: Vec<Bytes>, refused: Vec<Refusal> },
    /// BLAKE3 hashes of files.
    Want { group: Bytes, files: Vec<Bytes> },
    Have { group: Bytes, files: Vec<Bytes> },
    /// A request to join an open group.
    Join { group: Bytes, key_package: Bytes },
    Admitted { group: Bytes, admitted: Admitted },
    Refused { group: Bytes, refused: String },
    /// A file link to the state of the group's kind, which the sender's kind hands this member; without one, a request
    /// for one.
    State {
        group: Bytes,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        link: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub id: Bytes,
    pub reason: String,
}

/// One group's state, in `hello`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub group: Bytes,
    pub epoch: u64,
    /// The lowest epoch the sender accepts.
    pub floor: u64,
    /// The epoch the sender joined.
    pub joined: u64,
}

/// The joiner's request on an `invite` stream. For a device link, the KeyPackage's credential names the new device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRequest {
    pub secret: Bytes,
    pub key_package: Bytes,
}

/// The answer to an invite or a join: answered as `Answer<Admitted>` on an `invite` stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admitted {
    pub welcome: Bytes,
    /// The log position the joiner reads from.
    pub position: u64,
    /// A file link to the state of the group's kind, or of a devices group's contacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    /// The ids of the messages from before the joiner's epoch that the inviter holds, which the joiner never gets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub before: Vec<Bytes>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        let hello = Frame::Hello { groups: vec![], heads: vec![] };
        assert_eq!(serde_json::to_string(&hello).unwrap(), r#"{"hello":{"groups":[],"heads":[]}}"#);
        let state: Frame = serde_json::from_str(r#"{"state":{"group":"AQ","link":"lmk:x"}}"#).unwrap();
        assert!(matches!(state, Frame::State { .. }));
        assert!(serde_json::from_str::<Frame>(r#"{"doc":{"group":"AQ"}}"#).is_err(), "a kind has no frames");
    }
}
