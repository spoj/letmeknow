//! What a group's MLS state carries for us, and the plaintext of its application messages.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{Bytes, directory};

pub const PROTOCOL: u32 = 15;
/// What a device's certificate of a session covers, before the session's key.
pub const DEVICE: &[u8] = b"letmeknow device v1\0";
/// What a session's iroh key signs in its leaf, before the session's key.
pub const LEAF: &[u8] = b"letmeknow leaf v1\0";
/// What a member's leave covers, before the group's id and the epoch its membership began in.
pub const LEAVE: &[u8] = b"letmeknow leave v1\0";
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

/// The group context extension `SETTINGS_EXTENSION`. Only its admins change it, and only its lists, of keys each in its
/// one form (`is_key`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub protocol: u32,
    /// H: how many days members carry the group's messages for others.
    pub carry: u32,
    /// T: how many seconds a member's leaf goes between updates.
    pub update: u32,
    pub membership: Service,
    /// Session keys and device keys: a member is an admin by its own, or by the device that certified it.
    pub admins: Vec<Bytes>,
    /// Device keys whose sessions any member may add.
    pub admitted: Vec<Bytes>,
}

/// The leaf node extension `LEAF_EXTENSION`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    /// The session's iroh key.
    pub key: Bytes,
    /// That the session holds the iroh key: the iroh key's signature over `LEAF ‖ session key`.
    pub proof: Bytes,
    /// The domain of the session's own membership service, whose relay it lives on.
    pub home: String,
    /// The certificate of the session by the device it runs on.
    pub device: Option<Device>,
}

/// A device's certificate that a session runs on it: its signature over `DEVICE ‖ session key`, by `algorithm`:
/// `ed25519`, or `p256`, ECDSA on P-256 with SHA-256, whose key is SEC1-encoded, compressed, and whose signature is
/// r ‖ s.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub algorithm: String,
    pub key: Bytes,
    pub sig: Bytes,
}

impl Device {
    /// An Ed25519 device key's certificate of the session with key `session`.
    pub fn sign(key: &SigningKey, session: &[u8]) -> Self {
        let sig = key.sign(&[DEVICE, session].concat());
        Device { algorithm: "ed25519".into(), key: key.verifying_key().to_bytes().into(), sig: sig.to_bytes().into() }
    }

    /// Whether it certifies the session with key `session`.
    pub fn verify(&self, session: &[u8]) -> bool {
        let signed = [DEVICE, session].concat();
        match self.algorithm.as_str() {
            "ed25519" => {
                let (Ok(key), Ok(sig)) = (<[u8; 32]>::try_from(self.key.0.as_slice()), Signature::from_slice(&self.sig.0)) else { return false };
                VerifyingKey::from_bytes(&key).is_ok_and(|key| key.verify_strict(&signed, &sig).is_ok())
            }
            "p256" => {
                use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
                let (Ok(key), Ok(sig)) = (VerifyingKey::from_sec1_bytes(&self.key.0), Signature::from_slice(&self.sig.0)) else { return false };
                self.key.0.len() == 33 && key.verify(&signed, &sig).is_ok()
            }
            _ => false,
        }
    }
}

/// Whether `key` is a key in the one form a session's or a device's has: Ed25519's 32 bytes, or P-256's 33, compressed.
pub fn is_key(key: &[u8]) -> bool {
    <[u8; 32]>::try_from(key).is_ok_and(|key| VerifyingKey::from_bytes(&key).is_ok())
        || key.len() == 33 && p256::ecdsa::VerifyingKey::from_sec1_bytes(key).is_ok()
}

/// The core's own payloads. The plaintext of an MLS application message is JSON with a `type`; every type but these
/// is a chat's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// The sender asks to be removed: `sig` is its signature over `LEAVE ‖ group ‖ joined`, its membership's first epoch
    /// as 8 bytes, with which any member may commit its removal.
    Leave { sig: Bytes },
    /// An invite the sender made, which any member admits a joiner by once: its hash, over the group, the sender's
    /// membership and what its secret gives (`Invited::new`), and when it expires (milliseconds).
    Invite { hash: Bytes, expires: u64 },
    /// The sender gave up on these seqs: each author is told of its own.
    Lost { lost: Vec<crate::peer::Seqs> },
    /// The sender is in the epoch it sealed this in, as no commit or message of its own showed lately.
    Present,
}

impl Control {
    pub const TYPES: [&str; 4] = ["leave", "invite", "lost", "present"];
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
        let leave = serde_json::to_string(&Control::Leave { sig: Bytes(vec![1]) }).unwrap();
        assert_eq!(leave, r#"{"type":"leave","sig":"AQ"}"#);
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
        let text = r#"{"protocol":4,"carry":7,"update":86400,"membership":{"serve":{"key":"Ag","domain":"h.example","future":"t"}},"admins":["AQ"],"admitted":[],"color":"red"}"#;
        let settings: Settings = serde_json::from_str(text).unwrap();
        let Service::Serve { rest, .. } = &settings.membership else { panic!("a service this version knows") };
        assert_eq!((&rest["future"], &settings.admins[..]), (&serde_json::json!("t"), &[Bytes(vec![1])][..]));
        let leaf: Leaf = serde_json::from_str(r#"{"key":"AQ","proof":"Ag","home":"h.example","device":null,"later":1}"#).unwrap();
        assert_eq!(leaf.home, "h.example");
    }

    #[test]
    fn a_device_certifies_one_session_by_ed25519_or_p256() {
        let (session, other) = ([1; 32], [2; 32]);
        let device = Device::sign(&SigningKey::from_bytes(&[7; 32]), &session);
        assert!(device.verify(&session));
        assert!(!device.verify(&other), "another session's");
        assert!(!Device { algorithm: "p256".into(), ..device.clone() }.verify(&session));
        assert!(!Device { algorithm: "rsa".into(), ..device.clone() }.verify(&session), "an algorithm this release does not know");

        use p256::ecdsa::signature::Signer as _;
        let key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let sig: p256::ecdsa::Signature = key.sign(&[DEVICE, &session].concat());
        let encoded = key.verifying_key().to_encoded_point(true);
        let device = Device { algorithm: "p256".into(), key: Bytes::from(encoded.as_bytes()), sig: sig.to_bytes().as_slice().into() };
        assert_eq!(device.sig.0.len(), 64, "r and s");
        assert!(device.verify(&session));
        assert!(!device.verify(&other));
        let uncompressed = Bytes::from(key.verifying_key().to_encoded_point(false).as_bytes());
        assert!(!Device { key: uncompressed, ..device.clone() }.verify(&session), "a P-256 key has one form: 33 bytes, compressed");
        assert!(!Device { algorithm: "ed25519".into(), ..device }.verify(&session));
    }

    #[test]
    fn a_key_has_one_form() {
        let ed25519 = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let p256 = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let (compressed, uncompressed) = (p256.verifying_key().to_encoded_point(true), p256.verifying_key().to_encoded_point(false));
        assert!(is_key(&ed25519) && is_key(compressed.as_bytes()));
        assert!(!is_key(uncompressed.as_bytes()), "a P-256 key uncompressed");
        assert!(!is_key(&[2; 32]) && !is_key(&[4; 33]), "no point");
    }
}
