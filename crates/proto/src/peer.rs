//! The `peer` stream between two members sharing groups, and the `admission` stream on which a joiner asks a member to
//! admit it.

use serde::{Deserialize, Serialize};

use serde_json::Value;

use crate::{Bytes, head::Head, leading, membership::fixed32, ranges::Ranges};

/// What a summary's signature covers, before its body.
pub const SUMMARY: &[u8] = b"letmeknow summary v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame {
    /// Where the sender is in each group it shares with the receiver.
    Hello { groups: Vec<At> },
    /// Entries of a log the other lacks, by its reference, ending at `head`.
    Entries { log: Bytes, entries: Vec<Bytes>, head: Head },
    /// The versions of the summaries the sender holds, on connecting: each side then sends the other what it lacks.
    Versions { group: Bytes, versions: Vec<Version> },
    /// Members' signed summaries of the group: the sender's own, and those it passes on.
    Summaries { group: Bytes, items: Vec<Signed> },
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
}

/// Where a member is in a group: its current epoch's log, by its reference, with its newest signed head held.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct At {
    pub group: Bytes,
    #[serde(with = "fixed32")]
    pub log: [u8; 32],
    pub head: Option<Head>,
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

/// The version of a membership's summary, carried as `[key, joined, version]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<Value>", into = "(Bytes, u64, u64)")]
pub struct Version {
    pub key: Bytes,
    pub joined: u64,
    pub version: u64,
}

impl TryFrom<Vec<Value>> for Version {
    type Error = serde_json::Error;
    fn try_from(values: Vec<Value>) -> serde_json::Result<Self> {
        let (key, joined, version) = leading(values, 3)?;
        Ok(Version { key, joined, version })
    }
}

impl From<Version> for (Bytes, u64, u64) {
    fn from(v: Version) -> Self {
        (v.key, v.joined, v.version)
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
    /// The signer's home relay, when it knows one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// Per membership with any, the seqs it holds a sealing of, to serve.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held: Vec<Seqs>,
    /// Per membership with any, the unkept seqs it holds sealed in `epoch`: a commit of that epoch keeps them on its word.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sealed: Vec<Seqs>,
    /// Per membership with any, the seqs its client has shown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shown: Vec<Seqs>,
    /// Per membership with any, the seqs it lost.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lost: Vec<Seqs>,
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
    /// The log entry that added the joiner: its cut is where the joiner starts.
    pub commit: Bytes,
    /// The Welcome to the joiner, and the committer's signature over it and the entry (`welcome_signed`).
    pub welcome: Bytes,
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
        assert!(serde_json::from_str::<Frame>(r#"{"doc":{"group":"AQ"}}"#).is_err(), "a frame this version does not know");
        let summary = r#"{"group":"AQ","member":"Ag","joined":0,"version":1,"time":2,"epoch":3}"#;
        let parsed: Summary = serde_json::from_str(summary).unwrap();
        assert_eq!(parsed.relay, None);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), summary);
        let join = Join { secret: Bytes(vec![2]), key_package: Bytes(vec![3]) };
        assert_eq!(serde_json::to_string(&join).unwrap(), r#"{"secret":"Ag","key_package":"Aw"}"#);
    }
}
