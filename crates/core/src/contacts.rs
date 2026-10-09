//! An identity's contacts: its names for other identities, and how it knows them.

use lmk_proto::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum How {
    /// It invited them, or scanned their code in person.
    Verified,
    /// A contact introduced them, and the introduction was accepted.
    Introduced,
    /// A way a newer letmeknow named.
    #[serde(untagged)]
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub how: How,
    /// The introducer's identity id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<Bytes>,
    /// Milliseconds since the Unix epoch.
    pub at: u64,
    /// Fields a newer letmeknow added, kept when this one hands the contact on.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}
