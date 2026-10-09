//! A `peer` stream between two sessions, which share groups or one of which asks the other to admit it.

use serde::{Deserialize, Serialize};

use crate::{Bytes, head::Head, identity::Envelope};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame {
    /// The sender's state of the groups both are in, the newest signed heads it holds of their logs, and the
    /// certificates it holds of their members.
    Hello {
        groups: Vec<Hello>,
        heads: Vec<Head>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        certificates: Vec<Envelope>,
    },
    /// Entries of a log the other lacks, ending at `head`.
    Entries { log: Bytes, entries: Vec<Bytes>, head: Head },
    /// A negentropy message.
    Reconcile { group: Bytes, msg: Bytes },
    /// MLS ciphertexts, and the messages the receiver lacks below its floor, which it gives up.
    Messages {
        group: Bytes,
        items: Vec<Bytes>,
        below: Vec<Below>,
    },
    /// The answer to `messages`: the ids of the items the receiver took.
    Receipt { group: Bytes, held: Vec<Bytes> },
    /// BLAKE3 hashes of files.
    Want { group: Bytes, files: Vec<Bytes> },
    Have { group: Bytes, files: Vec<Bytes> },
    /// A request to be admitted, answered by `admitted` or `refused` with the same `id`.
    Join {
        id: u64,
        #[serde(flatten)]
        join: Join,
    },
    Admitted { id: u64, admitted: Admitted },
    Refused { id: u64, refused: String },
    /// A file link to the state of the group's kind, which the sender's kind hands this member; without one, a request
    /// for one.
    State {
        group: Bytes,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        link: Option<String>,
    },
}

/// A message the receiver lacks that is older than its floor, so that it records it as given up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Below {
    pub epoch: u64,
    pub id: Bytes,
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

/// A joiner's request: an invite's secret, or the group open to the identity its certificate proves it speaks as.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Join {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Bytes>,
    pub key_package: Bytes,
    /// The certificate of the identity the joiner speaks as, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Envelope>,
}

/// The answer to a join.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admitted {
    pub welcome: Bytes,
    /// The log position the joiner reads from.
    pub position: u64,
    /// A file link to the state of the group's kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    /// The ids of the messages from before the joiner's epoch that the admitting member holds, which the joiner never gets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub before: Vec<Bytes>,
    /// The certificates the admitting member holds of the group's members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<Envelope>,
    /// The logs of the kind's order the admitting member reads from where it is, the current one last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logs: Vec<KindLog>,
}

/// A log of a group's kind: its id, and the position in the kind's order that its first entry follows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindLog {
    pub id: Bytes,
    pub after: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        let hello = Frame::Hello { groups: vec![], heads: vec![], certificates: vec![] };
        assert_eq!(serde_json::to_string(&hello).unwrap(), r#"{"hello":{"groups":[],"heads":[]}}"#);
        let messages = Frame::Messages { group: Bytes(vec![1]), items: vec![], below: vec![] };
        assert_eq!(serde_json::to_string(&messages).unwrap(), r#"{"messages":{"group":"AQ","items":[],"below":[]}}"#);
        let state: Frame = serde_json::from_str(r#"{"state":{"group":"AQ","link":"lmk:x"}}"#).unwrap();
        assert!(matches!(state, Frame::State { .. }));
        assert!(serde_json::from_str::<Frame>(r#"{"doc":{"group":"AQ"}}"#).is_err(), "a kind has no frames");
        let join = Frame::Join { id: 7, join: Join { secret: Some(Bytes(vec![2])), group: None, key_package: Bytes(vec![3]), certificate: None } };
        let text = serde_json::to_string(&join).unwrap();
        assert_eq!(text, r#"{"join":{"id":7,"secret":"Ag","key_package":"Aw"}}"#);
        assert_eq!(serde_json::from_str::<Frame>(&text).unwrap(), join);
    }
}
