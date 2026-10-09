//! What a group's MLS state carries for us, and the plaintext of its application messages.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::Bytes;

pub const PROTOCOL: u32 = 2;
/// This release's protocol revision, which grows with each compatible addition; a leaf without one is revision 0.
pub const REVISION: u32 = 1;
/// The revision from which a member's update may rename it: every member must name it or a later one.
pub const RENAME_REVISION: u32 = 1;
/// The revision from which an `introduce` is held: every member must name it or a later one.
pub const INTRODUCE_REVISION: u32 = 1;
/// The revision from which a commit that removes members in a group with a kind's log must end that log: every member
/// must name it or a later one.
pub const END_REVISION: u32 = 1;
/// The private-use extension types: settings in the group context, and leaf data.
pub const SETTINGS_EXTENSION: u16 = 0xff01;
pub const LEAF_EXTENSION: u16 = 0xff02;

/// The kind every client supports, built in. Every other kind is a plugin's, but `DEVICES`.
pub const CHAT: &str = "chat";
/// The built-in kind of an identity's devices group, which devices join and sessions do not.
pub const DEVICES: &str = "devices";

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
    Folder(String),
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
    pub open: Vec<Named>,
    pub keep: u32,
    pub membership: Service,
    /// Fields a newer letmeknow added, kept when this one rewrites the settings.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// An identity, by id, with the name its group knows it by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Named {
    pub id: Bytes,
    pub name: String,
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// A group open to an identity, as its devices group keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opening {
    pub group: Bytes,
    pub kind: String,
    pub name: String,
    pub membership: Service,
    /// The iroh keys of its members when last refreshed.
    pub members: Vec<Bytes>,
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

/// The identity bytes of a member's basic credential: its name, its MLS signature key, and the identity it speaks as,
/// which a certificate proves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub name: String,
    pub key: Bytes,
    pub identity: Option<IdentityRef>,
}

/// An identity, by id and the service that keeps its key log.
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
    /// The messages the sender gave up since it last said so.
    Refused { messages: Vec<Refusal> },
    /// An invite, which any member admits a joiner by once: SHA-256 of its secret, when it expires (milliseconds), and
    /// whom it is for.
    Invite {
        hash: Bytes,
        expires: u64,
        /// `--for`: the inviter's name for whoever joins by it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        /// `--to`: the only identity that may join by it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<Bytes>,
    },
}

impl Control {
    pub const TYPES: [&str; 4] = ["leave", "introduce", "refused", "invite"];
}

/// A message a member gave up, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub id: Bytes,
    pub reason: Reason,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Larger than the member takes.
    Size,
    /// Sealed under an epoch whose keys the member no longer holds, or below its floor.
    Old,
    /// From a member removed more than 5 minutes before it arrived.
    Removed,
    /// It did not open.
    Unreadable,
    /// A reason a newer letmeknow gave.
    #[serde(untagged)]
    Other(String),
}

/// A payload's `type`.
pub fn type_of(payload: &serde_json::Value) -> &str {
    payload["type"].as_str().unwrap_or_default()
}

/// Whether members hold a payload: those of these types always, and others when their sender marks them so.
pub fn held_by_type(payload: &serde_json::Value) -> bool {
    matches!(type_of(payload), "message" | "leave" | "refused" | "invite")
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum How {
    Invite,
    Open,
    Introduce,
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
    fn unknown_values_parse_to_the_catch_all() {
        let refused: Control = serde_json::from_str(r#"{"type":"refused","messages":[{"id":"AQ","reason":"quota"},{"id":"Ag","reason":"old"}]}"#).unwrap();
        let Control::Refused { messages } = refused else { panic!() };
        assert_eq!(messages.iter().map(|m| m.reason.clone()).collect::<Vec<_>>(), [Reason::Other("quota".into()), Reason::Old]);
        let introduce = r#"{"type":"introduce","identity":{"id":"AQ","membership":{"folder":"/x"}},"name":"Bob","how":"met"}"#;
        let Control::Introduce { how, .. } = serde_json::from_str(introduce).unwrap() else { panic!() };
        assert_eq!(how, How::Other("met".into()));
        let service: Service = serde_json::from_str(r#"{"s3":{"bucket":"b"}}"#).unwrap();
        assert!(matches!(service, Service::Newer(_)));
        assert_eq!(serde_json::to_string(&service).unwrap(), r#"{"s3":{"bucket":"b"}}"#);
    }

    #[test]
    fn records_keep_fields_this_version_does_not_know() {
        let text = r#"{"protocol":2,"kind":"chat","name":"Plan","open":[{"id":"AQ","name":"Bob","since":1}],"keep":90,"membership":{"serve":{"key":"Ag","relay":"r","addrs":[],"ticket":"t"}},"color":"red"}"#;
        let settings: Settings = serde_json::from_str(text).unwrap();
        let renamed = Settings { name: "Release".into(), ..settings };
        assert_eq!(serde_json::to_string(&renamed).unwrap(), text.replace("Plan", "Release"));
        let leaf: Leaf = serde_json::from_str(r#"{"key":"AQ","relay":"r","kinds":["chat"]}"#).unwrap();
        assert_eq!(leaf.revision, 0, "a leaf without a revision is 0.12.1's");
    }
}
