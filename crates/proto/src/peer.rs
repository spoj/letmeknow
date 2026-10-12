//! The `peer` stream between two members sharing groups, and the `admission` stream on which a joiner asks a member to
//! admit it.

use serde::{Deserialize, Serialize};

use crate::{Bytes, epoch::{Anchor, Checkpoint, StateLink, Transition}, head::Head, ranges::Ranges};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame {
    /// The sender's summaries of groups, and the heads of the public logs their members follow.
    Hello { #[serde(deserialize_with = "list::<_, _, 8192>")] groups: Vec<Summary>, #[serde(deserialize_with = "list::<_, _, 8192>")] heads: Vec<Head> },
    /// Entries of a log the other lacks, ending at `head`.
    Entries { log: Bytes, #[serde(deserialize_with = "list::<_, _, 1024>")] entries: Vec<Bytes>, head: Head },
    HistoryRequest { group: Bytes, anchor: Anchor, previous: bool },
    History { group: Bytes, anchor: Anchor, previous: bool, transition: Option<Transition>, head: Option<Head>, other: Option<Head>, cut: Option<u64> },
    SegmentRequest { group: Bytes, anchor: Anchor, target: Head, after: u64, raw: bool },
    Segment { group: Bytes, anchor: Anchor, target: Head, after: u64, digests: Bytes, #[serde(deserialize_with = "list::<_, _, 1024>")] entries: Vec<Bytes> },
    /// Ciphertexts of counted positions: pushed at send, or the answer to `want`, whose positions up to where the
    /// sender stopped are `answers`.
    Messages {
        group: Bytes,
        anchor: Anchor,
        #[serde(deserialize_with = "list::<_, _, 1024>")]
        items: Vec<Item>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answers: Option<Ranges>,
    },
    /// Message positions asked of one holder.
    Want { group: Bytes, anchor: Anchor, positions: Ranges },
    /// BLAKE3 hashes of files.
    WantFiles { group: Bytes, #[serde(deserialize_with = "list::<_, _, 1024>")] files: Vec<Bytes> },
    Have { group: Bytes, #[serde(deserialize_with = "list::<_, _, 1024>")] files: Vec<Bytes> },
    /// A file link to the state of the group's kind; without one, a request for one.
    State {
        group: Bytes,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        link: Option<StateLink>,
    },
    /// Live payloads' MLS ciphertexts.
    Live { group: Bytes, #[serde(deserialize_with = "list::<_, _, 1024>")] items: Vec<Bytes> },
}

fn list<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>, const N: usize>(d: D) -> Result<Vec<T>, D::Error> {
    struct Visitor<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for Visitor<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "at most {N} items") }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut items = Vec::new();
            while let Some(item) = seq.next_element()? {
                if items.len() == N { return Err(serde::de::Error::custom("too many items")); }
                items.push(item);
            }
            Ok(items)
        }
    }
    d.deserialize_seq(Visitor::<T, N>(std::marker::PhantomData))
}

/// A member's state of a group. Ranges count positions with no message (commits, skipped entries) as covered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub group: Bytes,
    pub anchor: Anchor,
    pub position: u64,
    pub head: Option<Head>,
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

/// A joiner's request, the one frame it writes on an `admission` stream: an invite's secret, and its KeyPackage. The
/// member answers with an `Answer<Admitted>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Join {
    pub secret: Bytes,
    pub key_package: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admitted {
    /// The Welcome of the commit entry that added the joiner.
    pub welcome: Bytes,
    pub checkpoint: Checkpoint,
    /// A file link to the state of the group's kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<StateLink>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        let want = Frame::Want { group: Bytes(vec![1]), anchor: Anchor::genesis(&[1; 16], [0; 32], [1; 32]), positions: Ranges::from(vec![(1, 10), (13, 50)]) };
        assert_eq!(serde_json::to_value(&want).unwrap(), serde_json::json!({"want": {"group": "AQ", "anchor": Anchor::genesis(&[1; 16], [0; 32], [1; 32]), "positions": [[1,10],[13,50]]}}));
        let push = Frame::Messages { group: Bytes(vec![1]), anchor: Anchor::genesis(&[1; 16], [0; 32], [1; 32]), items: vec![Item { position: 3, ciphertext: Bytes(vec![2]) }], answers: None };
        let text = serde_json::to_string(&push).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&text).unwrap(), serde_json::json!({"messages": {"group": "AQ", "anchor": Anchor::genesis(&[1; 16], [0; 32], [1; 32]), "items": [{"position":3,"ciphertext":"Ag"}]}}));
        assert_eq!(serde_json::from_str::<Frame>(&text).unwrap(), push);
        let files: Frame = serde_json::from_str(r#"{"want_files":{"group":"AQ","files":[]}}"#).unwrap();
        assert!(matches!(files, Frame::WantFiles { .. }));
        assert!(serde_json::from_str::<Frame>(r#"{"doc":{"group":"AQ"}}"#).is_err(), "a kind has no frames");
        let join = Join { secret: Bytes(vec![2]), key_package: Bytes(vec![3]) };
        assert_eq!(serde_json::to_string(&join).unwrap(), r#"{"secret":"Ag","key_package":"Aw"}"#);
    }
}
