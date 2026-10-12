//! The wire formats, shared by every crate.

pub mod clock;
pub mod entry;
pub mod epoch;
pub mod frame;
pub mod group;
pub mod head;
pub mod public;
pub mod links;
pub mod membership;
pub mod peer;
pub mod random;
pub mod ranges;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Bytes, carried in JSON as unpadded base64url.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(pub Vec<u8>);

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&base64::display::Base64Display::new(&self.0, &URL_SAFE_NO_PAD))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Bytes;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("base64url bytes") }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Bytes, E> {
                URL_SAFE_NO_PAD.decode(value).map(Bytes).map_err(E::custom)
            }
        }
        d.deserialize_str(Visitor)
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
