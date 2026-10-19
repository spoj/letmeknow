//! The `peer` stream between two members sharing groups, and the `admission` stream on which a joiner asks a member to
//! admit it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use serde_json::Value;

use crate::{Bytes, head::Head, leading, membership::fixed32, ranges::Ranges};

/// What a summary's signature covers, before its body.
pub const SUMMARY: &[u8] = b"letmeknow summary v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame {
    /// Where the sender is in each group it shares with the receiver, and whom of it the sender knows to be online.
    Hello { groups: Vec<At> },
    /// Entries of a log the other lacks, by its reference, ending at `head`.
    Entries { log: Bytes, entries: Vec<Bytes>, head: Head },
    /// The sender's own signed summary of the group, on connecting and as it changes; it goes no further.
    Summary { group: Bytes, summary: Signed },
    /// Held messages' ciphertexts: pushed, or the answer to `want`, which covered `answers`.
    Held {
        group: Bytes,
        items: Vec<Bytes>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answers: Option<Vec<Seqs>>,
    },
    /// Held messages asked of one holder, sealed so that a member in `epoch` can open them: by membership and seq.
    Want {
        group: Bytes,
        epoch: u64,
        wants: Vec<Seqs>,
    },
    /// Held messages the sender holds that are too large to push, by membership and seq: a member that lacks one asks
    /// for it.
    Have { group: Bytes, held: Vec<Seqs> },
}

/// Where a member is in a group: its current epoch's log, by its reference, with its newest signed head held.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct At {
    pub group: Bytes,
    #[serde(with = "fixed32")]
    pub log: [u8; 32],
    pub head: Option<Head>,
    /// Members the sender knows to be online, by iroh key, with how many milliseconds ago it last knew: 0 for those it
    /// is connected to. Only sightings it has not told the receiver, or told it half an hour staler.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seen: BTreeMap<Bytes, u64>,
}

/// A membership's seqs, carried as `[key, joined, seqs]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<Value>", into = "(Bytes, u64, Ranges)")]
pub struct Seqs {
    pub key: Bytes,
    pub joined: u64,
    pub seqs: Ranges,
}

impl TryFrom<Vec<Value>> for Seqs {
    type Error = serde_json::Error;
    fn try_from(values: Vec<Value>) -> serde_json::Result<Self> {
        let (key, joined, seqs) = leading(values, 3)?;
        Ok(Seqs { key, joined, seqs })
    }
}

impl From<Seqs> for (Bytes, u64, Ranges) {
    fn from(s: Seqs) -> Self {
        (s.key, s.joined, s.seqs)
    }
}

/// A member's state of a group, as it signs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub group: Bytes,
    /// Its membership: its leaf signature key, and the epoch it joined in.
    pub member: Bytes,
    pub joined: u64,
    /// Grows with each summary the membership signs.
    pub version: u64,
    /// When it signed it, by its clock, in milliseconds.
    pub time: u64,
    pub epoch: u64,
    /// Per membership with any, the seqs it holds a sealing of, to serve.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held: Vec<Seqs>,
    /// Per membership with any, the unkept seqs it holds sealed in `epoch`: a commit of that epoch keeps them on its word.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sealed: Vec<Seqs>,
}

/// A signed summary: `body` a `Summary`'s JSON, `sig` its member's signature over `SUMMARY ‖ body`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub body: Bytes,
    pub sig: Bytes,
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
    /// The log entry that added the joiner.
    pub commit: Bytes,
    /// The Welcome to the joiner; the whole cut of the epoch the entry ended, where the joiner starts; and the
    /// committer's signature over the entry, the cut and the Welcome (`welcome_signed`).
    pub welcome: Bytes,
    pub cut: Vec<crate::held::Ref>,
    pub sig: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        let wants = vec![Seqs { key: Bytes(vec![2]), joined: 3, seqs: Ranges::from(vec![(1, 10), (13, 50)]) }];
        let want = Frame::Want { group: Bytes(vec![1]), epoch: 4, wants };
        let text = serde_json::to_string(&want).unwrap();
        assert_eq!(text, r#"{"want":{"group":"AQ","epoch":4,"wants":[["Ag",3,[[1,10],[13,50]]]]}}"#);
        assert_eq!(serde_json::from_str::<Frame>(&text).unwrap(), want);
        let push = Frame::Held { group: Bytes(vec![1]), items: vec![Bytes(vec![2])], answers: None };
        assert_eq!(serde_json::to_string(&push).unwrap(), r#"{"held":{"group":"AQ","items":["Ag"]}}"#);
        let have = Frame::Have { group: Bytes(vec![1]), held: vec![Seqs { key: Bytes(vec![2]), joined: 3, seqs: Ranges::from(vec![(7, 7)]) }] };
        assert_eq!(serde_json::to_string(&have).unwrap(), r#"{"have":{"group":"AQ","held":[["Ag",3,[[7,7]]]]}}"#);
        assert!(serde_json::from_str::<Frame>(r#"{"doc":{"group":"AQ"}}"#).is_err(), "a frame this version does not know");
        let summary = r#"{"group":"AQ","member":"Ag","joined":0,"version":1,"time":2,"epoch":3}"#;
        let parsed: Summary = serde_json::from_str(summary).unwrap();
        assert_eq!(serde_json::to_string(&parsed).unwrap(), summary);
        let at = At { group: Bytes(vec![1]), log: [0; 32], head: None, seen: BTreeMap::from([(Bytes(vec![2]), 5)]) };
        let text = serde_json::to_string(&at).unwrap();
        assert!(text.ends_with(r#""head":null,"seen":{"Ag":5}}"#), "{text}");
        assert_eq!(serde_json::from_str::<At>(&text).unwrap(), at);
        let quiet = At { seen: BTreeMap::new(), ..at };
        let text = serde_json::to_string(&quiet).unwrap();
        assert!(text.ends_with(r#""head":null}"#), "a hello of 0.22.3 and before: {text}");
        assert_eq!(serde_json::from_str::<At>(&text).unwrap(), quiet);
        let join = Join { secret: Bytes(vec![2]), key_package: Bytes(vec![3]) };
        assert_eq!(serde_json::to_string(&join).unwrap(), r#"{"secret":"Ag","key_package":"Aw"}"#);
    }
}
