//! Members as this client shows them: their names, their identities as this one knows them, and who added them.

use lmk_core::contacts::{self, Contact};
use lmk_node::{Claim, Member};
use lmk_proto::Bytes;
use lmk_proto::group::{How, IdentityRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{b64, fp};

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
    /// Its name is a contact's, whom it does not speak as: "not your Bob".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Known>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<AddedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh: Option<Bytes>,
}

/// How this identity knows another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// One of this device's own.
    #[serde(rename = "self")]
    Own,
    Verified,
    Introduced,
    /// Only its own claim.
    Unknown,
}

/// An identity a member speaks as, as this one knows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Known {
    pub id: Bytes,
    /// This identity's name for it, or else its own claim.
    pub name: String,
    pub how: Standing,
    /// The contact that introduced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub introducer_absent: bool,
    /// `name` is its own claim.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub claim: bool,
    /// It uses the name of a contact it is not: "not your Bob".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// Who in this client's groups vouched for it, and as whom.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub introduced: Vec<Introduced>,
    /// Why it is not verified: its device is not on the identity's list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Another identity's device, added to it after its first devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_device: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Introduced {
    pub by: Described,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddedBy {
    pub fp: String,
    pub how: How,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// An introduction of an identity that is neither this one nor a contact: someone's word, until accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Introduction {
    pub identity: Bytes,
    pub name: String,
    /// The introducer, as this client showed it then.
    pub by: Described,
    /// The introducer's identity id, or its session key if it speaks as none.
    pub by_id: Bytes,
}

/// What describing a group's members takes, gathered once.
pub struct Describer {
    pub(crate) me: Bytes,
    pub(crate) name: String,
    pub(crate) identities: Vec<(IdentityRef, String)>,
    pub(crate) contacts: Vec<(Bytes, Contact)>,
    pub(crate) introductions: Vec<Introduction>,
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
        // Speaking as no identity, it answers to the name all the same.
        let speaks = member.identity.as_ref().filter(|claim| claim.error.is_none()).map(|claim| &claim.identity.id);
        let own = speaks.is_some_and(|id| self.identities.iter().any(|(identity, _)| &identity.id == id));
        let named: Vec<_> = self.contacts.iter().filter(|(_, c)| c.name.eq_ignore_ascii_case(&member.name)).collect();
        let warning = named
            .first()
            .filter(|_| !own && !named.iter().any(|(id, _)| Some(id) == speaks))
            .map(|(_, c)| format!("not your {}", c.name));
        Described {
            name: Some(member.name.clone()),
            fp: Some(fp(&member.key.0)),
            device: Some(member.device_name.clone()),
            you: member.key == self.me,
            warning,
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

    /// An identity as this one knows it: its own, a contact (verified or introduced), or unknown: only its own claim,
    /// with the introductions others made of it.
    fn known(&self, claim: &Claim) -> Known {
        let id = &claim.identity.id;
        let own = self.identities.iter().find(|(identity, _)| &identity.id == id);
        let contact = self.contacts.iter().find(|(cid, _)| cid == id).map(|(_, contact)| contact);
        let mut known = Known {
            id: id.clone(),
            name: claim.name.clone(),
            how: Standing::Unknown,
            by: None,
            introducer_absent: false,
            claim: false,
            warning: None,
            introduced: Vec::new(),
            error: claim.error.clone(),
            new_device: (claim.added && own.is_none()).then(|| "a device added to the identity after its first".into()),
        };
        if let Some((_, name)) = own {
            (known.name, known.how) = (name.clone(), Standing::Own);
        } else if let Some(contact) = contact {
            known.name = contact.name.clone();
            known.how = match contact.how {
                contacts::How::Verified => Standing::Verified,
                // A way a newer letmeknow named counts for no more than an introduction.
                contacts::How::Introduced | contacts::How::Other(_) => Standing::Introduced,
            };
            if let Some(by) = &contact.by {
                known.by = Some(self.contacts.iter().find(|(cid, _)| cid == by).map_or_else(|| b64(&by.0), |(_, c)| c.name.clone()));
                known.introducer_absent = !self.members.iter().any(|m| m.identity.as_ref().is_some_and(|c| &c.identity.id == by));
            }
        } else {
            known.claim = true;
            if self.contacts.iter().any(|(_, c)| c.name.eq_ignore_ascii_case(&claim.name)) {
                known.warning = Some(format!("not your {}", claim.name));
            }
            known.introduced = self
                .introductions
                .iter()
                .filter(|i| &i.identity == id)
                .map(|i| Introduced { by: i.by.clone(), name: i.name.clone() })
                .collect();
        }
        known
    }

}

/// Whether a described member answers to `name`, in any case: its name, the first word of it, or its identity's name
/// when this identity knows it: a contact's name, or one of its own.
pub fn answers(member: &Value, name: &str) -> bool {
    let (name, own) = (name.to_lowercase(), member["name"].as_str().unwrap_or_default().to_lowercase());
    let first: String = own.chars().take_while(|c| c.is_alphanumeric()).collect();
    let identity = &member["identity"];
    own == name
        || first == name
        || identity["error"].is_null()
            && identity["how"] != "unknown"
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
    fn a_stranger_shows_its_claim_who_vouched_for_it_and_whose_name_it_takes() {
        let ann = member("Ann", 1, Some((10, "Ann")));
        let bob = member("Bob", 2, Some((20, "Bob")));
        let contact = Contact { name: "Bob".into(), how: contacts::How::Verified, by: None, at: 0, rest: Default::default() };
        let vouched = Introduction { identity: Bytes(vec![20]), name: "Robert (Acme)".into(), by: Described { name: Some("Ann".into()), ..Described::default() }, by_id: Bytes(vec![10]) };
        let describer = Describer {
            me: Bytes(vec![1]),
            name: "Ann".into(),
            identities: Vec::new(),
            contacts: vec![(Bytes(vec![30]), contact)],
            introductions: vec![vouched],
            members: vec![ann, bob.clone()],
        };
        let shown = serde_json::to_value(describer.describe(&bob)).unwrap();
        let identity = json!({ "id": "FA", "name": "Bob", "how": "unknown", "claim": true, "warning": "not your Bob", "introduced": [{ "by": { "name": "Ann" }, "name": "Robert (Acme)" }] });
        assert_eq!(shown, json!({ "name": "Bob", "fp": crate::fp(&[2]), "device": "laptop", "warning": "not your Bob", "identity": identity }));
        // A session name copying a contact's is flagged too, speaking as no identity; the contact's own session is not.
        let anonymous = serde_json::to_value(describer.describe(&member("bob", 4, None))).unwrap();
        assert_eq!(anonymous["warning"], "not your Bob");
        let real = serde_json::to_value(describer.describe(&member("Bob", 5, Some((30, "Robert"))))).unwrap();
        assert!(real.get("warning").is_none() && real["identity"]["how"] == "verified", "{real}");
        let mut failing = member("Bob", 6, Some((30, "Robert")));
        failing.identity.as_mut().unwrap().error = Some("a bad certificate".into());
        assert_eq!(serde_json::to_value(describer.describe(&failing)).unwrap()["warning"], "not your Bob", "a claim that fails proves nothing");
        let peer = Member { key: Bytes::default(), ..member("", 3, None) };
        assert_eq!(serde_json::to_value(describer.describe(&peer)).unwrap(), json!({ "iroh": "Aw" }));
        // Of two contacts named alike, either's session is theirs.
        let other = Contact { name: "bob".into(), how: contacts::How::Verified, by: None, at: 0, rest: Default::default() };
        let alike = Describer { contacts: vec![(Bytes(vec![40]), other), describer.contacts[0].clone()], ..describer };
        assert!(serde_json::to_value(alike.describe(&member("Bob", 5, Some((30, "Robert"))))).unwrap().get("warning").is_none());
    }
}
