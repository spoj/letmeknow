//! A `peer` stream between two sessions that share groups, and an `invite` stream.

use serde::de::Error;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value, json};

use crate::{Bytes, head::Head};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame {
    Hello {
        groups: Vec<Hello>,
        /// Device lists of the identities in those groups.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        lists: Vec<List>,
    },
    /// Log entries the other lacks, ending at `head`.
    Commits { group: Bytes, entries: Vec<Bytes>, head: Head },
    /// A negentropy message.
    Reconcile { group: Bytes, msg: Bytes },
    /// MLS ciphertexts.
    Messages { group: Bytes, items: Vec<Bytes> },
    /// The answer to `messages`: the ids of the items the receiver took, and of those it refused.
    Receipt { group: Bytes, held: Vec<Bytes>, refused: Vec<Refusal> },
    /// BLAKE3 hashes of files.
    Want { group: Bytes, files: Vec<Bytes> },
    Have { group: Bytes, files: Vec<Bytes> },
    /// A request to join an open group.
    Join { group: Bytes, key_package: Bytes },
    Admitted { group: Bytes, admitted: Admitted },
    Refused { group: Bytes, refused: String },
    /// A file link to the state of the group's kind, which the sender's kind hands this member.
    State { group: Bytes, link: String },
    /// A frame of the group's kind.
    #[serde(untagged)]
    Kind(KindFrame),
}

/// The core's frame names; every other name belongs to a kind.
const CORE: [&str; 11] = ["hello", "commits", "reconcile", "messages", "receipt", "want", "have", "join", "admitted", "refused", "state"];

/// `{"<name>": {"group", ...body}}`: a frame of the group's kind, which the core passes on unread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindFrame {
    pub name: String,
    pub group: Bytes,
    pub body: Map<String, Value>,
}

impl KindFrame {
    /// From a kind's `{"<name>": {...}}`.
    pub fn new(group: Bytes, frame: Value) -> anyhow::Result<Self> {
        let Value::Object(frame) = frame else { anyhow::bail!("a frame is an object") };
        let mut entries = frame.into_iter();
        let (Some((name, Value::Object(body))), None) = (entries.next(), entries.next()) else {
            anyhow::bail!("a frame is {{\"<name>\": {{...}}}}")
        };
        anyhow::ensure!(!CORE.contains(&name.as_str()), "{name} is a frame of the core");
        Ok(KindFrame { name, group, body })
    }

    /// As the kind sees it: `{"<name>": {...}}`.
    pub fn value(&self) -> Value {
        json!({ &self.name: self.body })
    }
}

impl Serialize for KindFrame {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut body = Map::new();
        body.insert("group".into(), json!(self.group));
        body.extend(self.body.clone());
        let mut map = s.serialize_map(Some(1))?;
        map.serialize_entry(&self.name, &body)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for KindFrame {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut frame = Value::deserialize(d)?;
        let group = frame.as_object_mut().and_then(|f| f.values_mut().next()).and_then(|body| body.as_object_mut()?.remove("group"));
        let group = serde_json::from_value(group.ok_or_else(|| D::Error::custom("a frame names its group"))?).map_err(D::Error::custom)?;
        KindFrame::new(group, frame).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub id: Bytes,
    pub reason: String,
}

/// One group's state, in `hello`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub group: Bytes,
    pub epoch: u64,
    pub head: Head,
    /// The lowest epoch the sender accepts.
    pub floor: u64,
    /// The epoch the sender joined.
    pub joined: u64,
}

/// An identity's device list as its membership service showed it: every entry, and the service's signed head over
/// them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct List {
    pub identity: Bytes,
    pub entries: Vec<Bytes>,
    pub head: Head,
}

/// The joiner's request on an `invite` stream. For a device link, the KeyPackage's credential names the new device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRequest {
    pub secret: Bytes,
    pub key_package: Bytes,
}

/// The answer to an invite or a join: answered as `Answer<Admitted>` on an `invite` stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admitted {
    pub welcome: Bytes,
    /// The log position the joiner reads from.
    pub position: u64,
    /// A file link to the state of the group's kind, or of a devices group's contacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    /// The ids of the messages from before the joiner's epoch that the inviter holds, which the joiner never gets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub before: Vec<Bytes>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hello_without_lists_is_as_before() {
        let old = r#"{"hello":{"groups":[]}}"#;
        let hello: Frame = serde_json::from_str(old).unwrap();
        assert_eq!(hello, Frame::Hello { groups: vec![], lists: vec![] });
        assert_eq!(serde_json::to_string(&hello).unwrap(), old);
    }

    #[test]
    fn a_kind_frame_keeps_its_wire_form() {
        let doc = r#"{"doc":{"group":"AQ","snapshot":"Ag"}}"#;
        let frame: Frame = serde_json::from_str(doc).unwrap();
        let Frame::Kind(kind) = &frame else { panic!("{frame:?}") };
        assert_eq!((kind.name.as_str(), &kind.group, kind.value()), ("doc", &Bytes(vec![1]), json!({ "doc": { "snapshot": "Ag" } })));
        assert_eq!(serde_json::to_string(&frame).unwrap(), doc);
        let state: Frame = serde_json::from_str(r#"{"state":{"group":"AQ","link":"lmk:x"}}"#).unwrap();
        assert!(matches!(state, Frame::State { .. }));
        assert!(serde_json::from_str::<Frame>(r#"{"hello":{"groups":"no"}}"#).is_err());
    }
}
