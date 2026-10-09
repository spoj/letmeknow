//! What a group's MLS state carries for us, and the plaintext of its application messages.

use serde::{Deserialize, Serialize};

use crate::Bytes;

pub const PROTOCOL: u32 = 1;
/// The private-use extension types: settings in the group context, and leaf data.
pub const SETTINGS_EXTENSION: u16 = 0xff01;
pub const LEAF_EXTENSION: u16 = 0xff02;

/// The one kind every client supports, built in. Every other kind is a plugin's.
pub const CHAT: &str = "chat";

/// The kinds a leaf that lists none supports: those of 0.10.
fn legacy_kinds() -> Vec<String> {
    vec![CHAT.into(), "doc".into()]
}

/// Where a log lives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Serve { key: Bytes, relay: String, addrs: Vec<String> },
    Folder(String),
}

/// The group context extension `SETTINGS_EXTENSION`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub protocol: u32,
    pub kind: String,
    pub name: String,
    pub open: Vec<Named>,
    pub keep: u32,
    pub membership: Service,
    /// Marks an identity's devices group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices_of: Option<Bytes>,
    /// Only in a devices group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub openings: Vec<Opening>,
}

/// An identity, by id, with the name its group knows it by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Named {
    pub id: Bytes,
    pub name: String,
}

/// A group open to an identity, as its devices group records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opening {
    pub group: Bytes,
    pub kind: String,
    pub name: String,
    pub membership: Service,
    /// The iroh keys of its members when last refreshed.
    pub members: Vec<Bytes>,
}

/// The leaf node extension `LEAF_EXTENSION`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    /// The session's iroh key.
    pub key: Bytes,
    pub relay: String,
    /// The kinds the session supports.
    #[serde(default = "legacy_kinds")]
    pub kinds: Vec<String>,
}

/// The identity bytes of a session's basic credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub name: String,
    pub device: Bytes,
    /// The device key's signature over `SESSION_CONTEXT` ‖ the session's public key.
    pub device_sig: Bytes,
    pub device_name: String,
    pub identity: Option<IdentityRef>,
}

pub const SESSION_CONTEXT: &[u8] = b"letmeknow session v1\0";

/// An identity, by id and the service that keeps its device list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRef {
    pub id: Bytes,
    pub membership: Service,
}

/// The core's own payloads. The plaintext of an MLS application message is JSON with a `type`; every type but these
/// belongs to the group's kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// The sender asks to be removed.
    Leave,
    /// Who an identity is to the sender.
    Introduce {
        identity: IdentityRef,
        name: String,
        how: How,
        /// Fingerprints of the members it is for; empty for the group.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        to: Vec<Bytes>,
    },
}

impl Control {
    pub const TYPES: [&str; 2] = ["leave", "introduce"];
}

/// A payload's `type`.
pub fn type_of(payload: &serde_json::Value) -> &str {
    payload["type"].as_str().unwrap_or_default()
}

/// Whether members hold a payload: those of these types always, and others when their sender marks them so.
pub fn held_by_type(payload: &serde_json::Value) -> bool {
    matches!(type_of(payload), "message" | "leave")
}

/// A chat message, the payload of the built-in kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename = "message")]
pub struct ChatMessage {
    pub content: String,
    /// Tips of what the sender had read: message ids.
    pub after: Vec<Bytes>,
    /// Fingerprints; empty addresses the group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Bytes>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub urgent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Attachment>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// A file link (see `links::FileLink`).
    pub link: String,
    pub name: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub media_type: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum How {
    Invite,
    Open,
    Introduce,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shapes() {
        let leave = serde_json::to_string(&Control::Leave).unwrap();
        assert_eq!(leave, r#"{"type":"leave"}"#);
        let message = ChatMessage {
            content: "hi".into(),
            after: vec![],
            to: vec![],
            reply_to: None,
            urgent: false,
            attachment: None,
        };
        assert_eq!(serde_json::to_string(&message).unwrap(), r#"{"type":"message","content":"hi","after":[]}"#);
        let folder = serde_json::to_string(&Service::Folder("/tmp/x".into())).unwrap();
        assert_eq!(folder, r#"{"folder":"/tmp/x"}"#);
    }

    #[test]
    fn a_leaf_without_kinds_is_a_0_10_one() {
        let leaf: Leaf = serde_json::from_str(r#"{"key":"AA","relay":"https://letmeknow.dev"}"#).unwrap();
        assert_eq!(leaf.kinds, ["chat", "doc"]);
    }
}
