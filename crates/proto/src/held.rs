//! A held message: an MLS application message whose plaintext is its header's JSON, and whose authenticated data, clear
//! on the wire, claims whose it is. MLS authenticates its author; its id is the hash of the plaintext, the same in every
//! epoch its author seals it in.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Bytes, leading};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub group: Bytes,
    /// The author's leaf signature key, and the epoch its membership began in: a key admitted again starts anew.
    pub author: Bytes,
    pub joined: u64,
    /// The membership's count of held messages in the group: 1, 2, 3, … across epochs.
    pub seq: u64,
    /// The id of the membership's message at `seq - 1`; none at seq 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Bytes>,
    /// The frontier of what the author's client had shown: at most one message per membership, none the author's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<Ref>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Bytes>,
    /// A JSON object with a `type`: the core's, or the group's kind's.
    pub payload: Value,
}

/// A message by its author's membership and seq, and its id; in a cut, a membership's seq and the id there, empty at
/// seq 0. Carried as `[key, joined, seq, id]`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<Value>", into = "(Bytes, u64, u64, Bytes)")]
pub struct Ref {
    pub key: Bytes,
    pub joined: u64,
    pub seq: u64,
    pub id: Bytes,
}

impl TryFrom<Vec<Value>> for Ref {
    type Error = serde_json::Error;
    fn try_from(values: Vec<Value>) -> serde_json::Result<Self> {
        let (key, joined, seq, id) = leading(values, 4)?;
        Ok(Ref { key, joined, seq, id })
    }
}

impl From<Ref> for (Bytes, u64, u64, Bytes) {
    fn from(r: Ref) -> Self {
        (r.key, r.joined, r.seq, r.id)
    }
}

/// Whose a held message is, as its authenticated data claims before it is opened: `[key, joined, seq]`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<Value>", into = "(Bytes, u64, u64)")]
pub struct Claim {
    pub key: Bytes,
    pub joined: u64,
    pub seq: u64,
}

impl TryFrom<Vec<Value>> for Claim {
    type Error = serde_json::Error;
    fn try_from(values: Vec<Value>) -> serde_json::Result<Self> {
        let (key, joined, seq) = leading(values, 3)?;
        Ok(Claim { key, joined, seq })
    }
}

impl From<Claim> for (Bytes, u64, u64) {
    fn from(c: Claim) -> Self {
        (c.key, c.joined, c.seq)
    }
}

impl Header {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a header serializes")
    }

    /// The header of a plaintext, shaped as one must be.
    pub fn open(plaintext: &[u8]) -> Result<Self> {
        let header: Header = serde_json::from_slice(plaintext).context("a held message's header")?;
        ensure!(header.seq >= 1 && header.prev.is_some() == (header.seq > 1), "a held message out of its author's sequence");
        ensure!(header.payload["type"].is_string(), "a payload without a type");
        let mut memberships: Vec<(&Bytes, u64)> = header.deps.iter().map(|dep| (&dep.key, dep.joined)).collect();
        memberships.sort();
        memberships.dedup();
        ensure!(
            memberships.len() == header.deps.len()
                && !memberships.contains(&(&header.author, header.joined))
                && header.deps.iter().all(|dep| dep.seq >= 1),
            "a held message's deps name a membership twice, its author's, or nothing"
        );
        Ok(header)
    }

    pub fn claim(&self) -> Claim {
        Claim { key: self.author.clone(), joined: self.joined, seq: self.seq }
    }
}

/// A held message's id: SHA-256 of its plaintext.
pub fn id(plaintext: &[u8]) -> [u8; 32] {
    Sha256::digest(plaintext).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn header() -> Header {
        Header {
            group: Bytes(vec![1; 16]),
            author: Bytes(vec![9; 32]),
            joined: 3,
            seq: 2,
            prev: Some(Bytes(vec![4; 32])),
            deps: vec![Ref { key: Bytes(vec![5; 32]), joined: 0, seq: 7, id: Bytes(vec![6; 32]) }],
            reply_to: None,
            payload: json!({ "type": "message", "content": "hi" }),
        }
    }

    #[test]
    fn headers_round_trip() {
        let plaintext = header().encode();
        assert_eq!(Header::open(&plaintext).unwrap(), header());
        let text = String::from_utf8(plaintext).unwrap();
        assert!(text.contains(r#""deps":[["BQ"#), "{text}");
        let claim = serde_json::to_string(&header().claim()).unwrap();
        assert!(claim.starts_with(r#"["CQkJ"#) && claim.ends_with(r#"",3,2]"#), "{claim}");
        assert_eq!(serde_json::from_str::<Claim>(&claim).unwrap(), header().claim());
    }

    #[test]
    fn tuples_ignore_what_later_releases_append() {
        let dep: Ref = serde_json::from_str(r#"["BQ",0,7,"Bg",{"later":1}]"#).unwrap();
        assert_eq!(dep, Ref { key: Bytes(vec![5]), joined: 0, seq: 7, id: Bytes(vec![6]) });
        let claim: Claim = serde_json::from_str(r#"["CQ",3,2,"more"]"#).unwrap();
        assert_eq!(claim, Claim { key: Bytes(vec![9]), joined: 3, seq: 2 });
        assert!(serde_json::from_str::<Ref>(r#"["BQ",0,7]"#).is_err(), "too few");
    }

    #[test]
    fn malformed_headers_are_refused() {
        let me = Ref { key: Bytes(vec![9; 32]), joined: 3, seq: 1, id: Bytes(vec![1; 32]) };
        let cases = [
            Header { prev: None, ..header() },
            Header { seq: 1, ..header() },
            Header { payload: json!({ "content": "untyped" }), ..header() },
            Header { deps: vec![me.clone()], ..header() },
            Header { deps: vec![header().deps[0].clone(), header().deps[0].clone()], ..header() },
        ];
        for case in cases {
            assert!(Header::open(&case.encode()).is_err(), "{case:?}");
        }
        assert!(Header::open(&Header { seq: 1, prev: None, ..header() }.encode()).is_ok());
        let earlier = Ref { joined: 1, ..me };
        assert!(Header::open(&Header { deps: vec![earlier], ..header() }.encode()).is_ok(), "the author's earlier membership");
    }
}
