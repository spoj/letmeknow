//! The wire formats of PROTOCOL.md, shared by every crate.

pub mod clock;
pub mod frame;
pub mod group;
pub mod head;
pub mod identity;
pub mod links;
pub mod membership;
pub mod peer;
pub mod random;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Bytes, carried in JSON as unpadded base64url.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(pub Vec<u8>);

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        URL_SAFE_NO_PAD.decode(text).map(Bytes).map_err(serde::de::Error::custom)
    }
}

impl From<&[u8]> for Bytes {
    fn from(bytes: &[u8]) -> Self {
        Bytes(bytes.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for Bytes {
    fn from(bytes: [u8; N]) -> Self {
        Bytes(bytes.to_vec())
    }
}

/// The answer to a request: what was asked for, or why not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Answer<T> {
    Refused { refused: String },
    Ok(T),
}
