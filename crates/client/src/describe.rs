//! Members as this client shows them: their names, their identities, and who added them.

use lmk_node::{Claim, Member};
use lmk_proto::Bytes;
use lmk_proto::group::{How, IdentityRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fp;

/// A member, or only the iroh key of an endpoint that is not one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Described {
    /// Its session name: its own claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub you: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Known>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<AddedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh: Option<Bytes>,
}

/// Whose an identity is, to this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// One of this device's own.
    #[serde(rename = "self")]
    Own,
    /// Another's: its name is only its own claim.
    Unknown,
}

/// An identity a member speaks as, as this one knows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Known {
    pub id: Bytes,
    /// This device's name for it, if it is its own, or else its own claim.
    pub name: String,
    pub how: Standing,
    /// Why it is not verified: its device is not on the identity's list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Another identity's device, added to it after its first devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_device: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddedBy {
    pub fp: String,
    pub how: How,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// What describing a group's members takes, gathered once.
pub struct Describer {
    pub(crate) me: Bytes,
    pub(crate) name: String,
    pub(crate) identities: Vec<(IdentityRef, String)>,
    pub(crate) members: Vec<Member>,
}

impl Describer {
    pub fn describe(&self, member: &Member) -> Described {
        if member.key.0.is_empty() {
            return Described { iroh: Some(member.iroh.clone()), ..Described::default() };
        }
        let added_by = member.added.as_ref().map(|(by, how)| AddedBy {
            fp: fp(&by.0),
            how: how.clone(),
            name: self.members.iter().find(|m| &m.key == by).map(|adder| adder.name.clone()),
        });
        Described {
            name: Some(member.name.clone()),
            fp: Some(fp(&member.key.0)),
            device: Some(member.device_name.clone()),
            you: member.key == self.me,
            identity: member.identity.as_ref().map(|claim| self.known(claim)),
            added_by,
            iroh: None,
        }
    }

    /// The member with this key, or this client itself before it is one.
    pub fn describe_key(&self, key: &Bytes) -> Described {
        match self.members.iter().find(|m| &m.key == key) {
            Some(member) => self.describe(member),
            None if *key == self.me => Described { name: Some(self.name.clone()), fp: Some(fp(&key.0)), you: true, ..Described::default() },
            None => Described { fp: Some(fp(&key.0)), ..Described::default() },
        }
    }

    /// An identity as this one knows it: one of this device's own, or another's, by its own claim.
    fn known(&self, claim: &Claim) -> Known {
        let own = self.identities.iter().find(|(identity, _)| identity.id == claim.identity.id);
        let (name, how) = match own {
            Some((_, name)) => (name.clone(), Standing::Own),
            None => (claim.name.clone(), Standing::Unknown),
        };
        Known {
            id: claim.identity.id.clone(),
            name,
            how,
            error: claim.error.clone(),
            new_device: (claim.added && own.is_none()).then(|| "a device added to the identity after its first".into()),
        }
    }
}

/// Whether a described member answers to `name`, in any case: its name, the first word of it, or its identity's name
/// when the identity is this device's own.
pub fn answers(member: &Value, name: &str) -> bool {
    let (name, own) = (name.to_lowercase(), member["name"].as_str().unwrap_or_default().to_lowercase());
    let first: String = own.chars().take_while(|c| c.is_alphanumeric()).collect();
    let identity = &member["identity"];
    own == name
        || first == name
        || identity["error"].is_null()
            && identity["how"] == "self"
            && identity["name"].as_str().is_some_and(|identity| identity.to_lowercase() == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lmk_proto::group::Service;
    use serde_json::json;

    fn member(name: &str, key: u8, identity: Option<(u8, &str)>) -> Member {
        let identity = identity.map(|(id, claimed)| Claim {
            identity: IdentityRef { id: Bytes(vec![id]), membership: Service::Folder("/logs".into()) },
            name: claimed.into(),
            error: None,
            added: false,
        });
        Member { key: Bytes(vec![key]), iroh: Bytes(vec![key]), revision: 1, name: name.into(), device_name: "laptop".into(), identity, added: None }
    }

    #[test]
    fn an_identity_is_this_devices_own_or_known_by_its_own_claim() {
        let own = IdentityRef { id: Bytes(vec![10]), membership: Service::Folder("/logs".into()) };
        let describer = Describer {
            me: Bytes(vec![1]),
            name: "Ann".into(),
            identities: vec![(own, "Ann".into())],
            members: vec![member("Claude", 1, Some((10, "Ann Smith"))), member("Bob", 2, Some((20, "Robert")))],
        };
        let shown = |m: &Member| serde_json::to_value(describer.describe(m)).unwrap();
        let ann = shown(&describer.members[0]);
        assert_eq!(ann["identity"], json!({ "id": "Cg", "name": "Ann", "how": "self" }));
        assert_eq!(ann["you"], true);
        let bob = shown(&describer.members[1]);
        assert_eq!(bob, json!({ "name": "Bob", "fp": crate::fp(&[2]), "device": "laptop", "identity": { "id": "FA", "name": "Robert", "how": "unknown" } }));
        // An identity's name addresses its sessions only when it is this device's own.
        assert!(answers(&ann, "ANN") && answers(&ann, "claude") && answers(&bob, "bob") && !answers(&bob, "robert"));
        let peer = Member { key: Bytes::default(), ..member("", 3, None) };
        assert_eq!(shown(&peer), json!({ "iroh": "Aw" }));
    }
}
