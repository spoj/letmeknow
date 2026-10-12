//! What a group's MLS state carries for us, and the plaintext of its application messages.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::Bytes;
use crate::ranges::Ranges;

pub const PROTOCOL: u32 = 5;
/// This release's protocol revision, which grows with each compatible addition; a leaf without one is revision 0.
pub const REVISION: u32 = 0;
/// The private-use extension types: settings in the group context, and leaf data.
pub const SETTINGS_EXTENSION: u16 = 0xff01;
pub const LEAF_EXTENSION: u16 = 0xff02;

/// The kind every client supports, built in. Every other kind is a plugin's, but `IDENTITY`.
pub const CHAT: &str = "chat";
/// The built-in kind of an identity's group, whose members are its devices; sessions do not join it.
pub const IDENTITY: &str = "identity";
/// T's default: daily.
pub const UPDATE: u32 = 24 * 60 * 60;

/// Where a log lives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Serve {
        key: Bytes,
        relay: String,
        addrs: Vec<String>,
        #[serde(flatten)]
        rest: Map<String, Value>,
    },
    /// A kind of service a newer letmeknow made, kept as it is.
    #[serde(untagged)]
    Newer(Value),
}

/// The group context extension `SETTINGS_EXTENSION`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub protocol: u32,
    pub kind: String,
    pub name: String,
    /// H: how many days members carry the group's messages, and the files they link, for others.
    pub carry: u32,
    /// T: how many seconds a member's leaf goes between updates.
    pub update: u32,
    pub membership: Service,
    /// The id of the group's public log, which its kind keeps: an identity's group's is the identity's id, on
    /// `membership`. Fixed when the group is made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<Bytes>,
    /// Fields a newer letmeknow added, kept when this one rewrites the settings.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// The leaf node extension `LEAF_EXTENSION`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    /// The session's iroh key.
    pub key: Bytes,
    pub relay: String,
    /// The kinds the session supports.
    pub kinds: Vec<String>,
    /// The session's protocol revision.
    #[serde(default)]
    pub revision: u32,
}

/// The identity bytes of a member's basic credential: its name, its MLS signature key, and the certificate of the
/// identity it speaks as.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub name: String,
    pub key: Bytes,
    pub certificate: Option<Box<Certificate>>,
}

impl Credential {
    pub fn identity(&self) -> Option<&IdentityRef> {
        self.certificate.as_ref().map(|certificate| &certificate.identity)
    }
}

/// That a session speaks as an identity: its device's key on the identity's list, and that key's signature over
/// `identity::certified(session key, identity id)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    pub identity: IdentityRef,
    pub device: Bytes,
    pub sig: Bytes,
}

/// An identity, by id and the service that keeps its public log.
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
    /// An invite, which any member admits a joiner by once: SHA-256 of its secret, when it expires (milliseconds), and
    /// whom it is for.
    Invite {
        hash: Bytes,
        expires: u64,
        /// The only identity that may join by it (`invite --to`), or device whose sessions only may (`add`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<Bytes>,
    },
    /// Counted positions of the group's log the sender can no longer open.
    Lost { positions: Vec<u64> },
}

impl Control {
    pub const TYPES: [&str; 3] = ["leave", "invite", "lost"];
}

/// A payload's `type`.
pub fn type_of(payload: &serde_json::Value) -> &str {
    payload["type"].as_str().unwrap_or_default()
}

/// A chat message, the payload of the built-in kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename = "message")]
pub struct ChatMessage {
    pub content: String,
    /// The positions of the group's log the sender had read when it sent this.
    pub read: Ranges,
    /// Fingerprints; empty addresses the group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Bytes>,
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
    /// A file link (see `links::FileLink`).
    pub link: String,
    pub name: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub media_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum How {
    Invite,
    /// A way a newer letmeknow named.
    #[serde(untagged)]
    Other(String),
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
            read: Ranges::range(1, 3),
            to: vec![],
            reply_to: None,
            urgent: false,
            attachment: None,
            sent_at: Some(5),
        };
        assert_eq!(serde_json::to_string(&message).unwrap(), r#"{"type":"message","content":"hi","read":[[1,3]],"sent_at":5}"#);
        let service = Service::Serve { key: Bytes(vec![1]), relay: "https://r".into(), addrs: vec![], rest: Default::default() };
        assert_eq!(serde_json::to_string(&service).unwrap(), r#"{"serve":{"key":"AQ","relay":"https://r","addrs":[]}}"#);
    }

    #[test]
    fn unknown_values_parse_to_the_catch_all() {
        assert_eq!(serde_json::from_str::<How>(r#""vouched""#).unwrap(), How::Other("vouched".into()));
        let service: Service = serde_json::from_str(r#"{"s3":{"bucket":"b"}}"#).unwrap();
        assert!(matches!(service, Service::Newer(_)));
        assert_eq!(serde_json::to_string(&service).unwrap(), r#"{"s3":{"bucket":"b"}}"#);
    }

    #[test]
    fn records_keep_fields_this_version_does_not_know() {
        let text = r#"{"protocol":4,"kind":"chat","name":"Plan","carry":7,"update":86400,"membership":{"serve":{"key":"Ag","relay":"r","addrs":[],"ticket":"t"}},"color":"red"}"#;
        let settings: Settings = serde_json::from_str(text).unwrap();
        let renamed = Settings { name: "Release".into(), ..settings };
        assert_eq!(serde_json::to_string(&renamed).unwrap(), text.replace("Plan", "Release"));
        let leaf: Leaf = serde_json::from_str(r#"{"key":"AQ","relay":"r","kinds":["chat"]}"#).unwrap();
        assert_eq!(leaf.revision, 0);
    }
}
