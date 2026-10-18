//! What a group's MLS state carries for us, and the plaintext of its application messages.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{Bytes, directory};

pub const PROTOCOL: u32 = 9;
/// This release's protocol revision, which grows with each compatible addition; a leaf without one is revision 0.
pub const REVISION: u32 = 0;
/// The private-use extension types: settings in the group context, and leaf data.
pub const SETTINGS_EXTENSION: u16 = 0xff01;
pub const LEAF_EXTENSION: u16 = 0xff02;

/// T's default: daily.
pub const UPDATE: u32 = 24 * 60 * 60;

/// Where a log lives: the membership service whose key is `key`, which its domain's directory names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Serve {
        key: Bytes,
        #[serde(deserialize_with = "directory::deserialize_domain")]
        domain: String,
        #[serde(flatten)]
        rest: Map<String, Value>,
    },
    /// A kind of service a newer letmeknow made, kept as it is.
    #[serde(untagged)]
    Newer(Value),
}

/// The group context extension `SETTINGS_EXTENSION`, fixed when the group is made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub protocol: u32,
    /// H: how many days members carry the group's messages for others.
    pub carry: u32,
    /// T: how many seconds a member's leaf goes between updates.
    pub update: u32,
    pub membership: Service,
}

/// The leaf node extension `LEAF_EXTENSION`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    /// The session's iroh key.
    pub key: Bytes,
    /// The session's protocol revision.
    #[serde(default)]
    pub revision: u32,
}

/// The core's own payloads. The plaintext of an MLS application message is JSON with a `type`; every type but these
/// is a chat's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// The sender asks to be removed.
    Leave,
    /// An invite, which any member admits a joiner by once: SHA-256 of its secret, and when it expires (milliseconds).
    Invite { hash: Bytes, expires: u64 },
}

impl Control {
    pub const TYPES: [&str; 2] = ["leave", "invite"];
}

/// A payload's `type`.
pub fn type_of(payload: &serde_json::Value) -> &str {
    payload["type"].as_str().unwrap_or_default()
}

/// A chat message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename = "message")]
pub struct ChatMessage {
    pub content: String,
    /// Fingerprints; empty addresses the group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<Bytes>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub urgent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Attachment>,
    /// When the sender sent it, by its clock: milliseconds since the Unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub name: String,
    pub data: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shapes() {
        let leave = serde_json::to_string(&Control::Leave).unwrap();
        assert_eq!(leave, r#"{"type":"leave"}"#);
        let message = ChatMessage { content: "hi".into(), to: vec![], urgent: false, attachment: None, sent_at: Some(5) };
        assert_eq!(serde_json::to_string(&message).unwrap(), r#"{"type":"message","content":"hi","sent_at":5}"#);
        let service = Service::Serve { key: Bytes(vec![1]), domain: "localhost:8443".into(), rest: Default::default() };
        assert_eq!(serde_json::to_string(&service).unwrap(), r#"{"serve":{"key":"AQ","domain":"localhost:8443"}}"#);
    }

    #[test]
    fn unknown_values_parse_to_the_catch_all() {
        let service: Service = serde_json::from_str(r#"{"s3":{"bucket":"b"}}"#).unwrap();
        assert!(matches!(service, Service::Newer(_)));
        assert_eq!(serde_json::to_string(&service).unwrap(), r#"{"s3":{"bucket":"b"}}"#);
        let uncanonical: Service = serde_json::from_str(r#"{"serve":{"key":"AQ","domain":"Relay.example"}}"#).unwrap();
        assert!(matches!(uncanonical, Service::Newer(_)), "a domain that is not canonical is not a service this version knows");
    }

    #[test]
    fn records_take_fields_this_version_does_not_know() {
        let text = r#"{"protocol":4,"carry":7,"update":86400,"membership":{"serve":{"key":"Ag","domain":"h.example","future":"t"}},"color":"red"}"#;
        let settings: Settings = serde_json::from_str(text).unwrap();
        let Service::Serve { rest, .. } = &settings.membership else { panic!("a service this version knows") };
        assert_eq!(rest["future"], "t");
        let leaf: Leaf = serde_json::from_str(r#"{"key":"AQ"}"#).unwrap();
        assert_eq!(leaf.revision, 0);
    }
}
