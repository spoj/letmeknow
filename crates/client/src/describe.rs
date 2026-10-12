//! Members as this client shows them: by their identities and devices, and who added them.

use lmk_node::{Claim, Member};
use lmk_proto::Bytes;
use lmk_proto::group::{How, IdentityRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fp;

/// A member, or only the iroh key of an endpoint that is not one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Described {
    /// How it shows: its identity's name and its device's, as "Ann · laptop", and its handle where another member of
    /// the group shows so too; its fingerprint where it speaks for no identity, or for one that failed the check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    /// Its session's handle; none for a browser, its device's only session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddedBy {
    pub fp: String,
    pub how: How,
}

/// What describing a group's members takes, gathered once.
pub struct Describer {
    pub(crate) me: Bytes,
    pub(crate) identity: Option<(IdentityRef, String)>,
    pub(crate) members: Vec<Member>,
}

impl Describer {
    pub fn describe(&self, member: &Member) -> Described {
        if member.key.0.is_empty() {
            return Described { iroh: Some(member.iroh.clone()), ..Described::default() };
        }
        let identity = member.identity.as_ref().map(|claim| self.known(claim));
        let name = match &identity {
            Some(known) if known.error.is_none() => {
                let twin = self.members.iter().any(|m| {
                    m.key != member.key && m.device_name == member.device_name && m.identity.as_ref().is_some_and(|c| c.identity.id == known.id)
                });
                if twin && !member.name.is_empty() {
                    format!("{} · {} ({})", known.name, member.device_name, member.name)
                } else {
                    format!("{} · {}", known.name, member.device_name)
                }
            }
            _ => fp(&member.key.0),
        };
        Described {
            name: Some(name),
            fp: Some(fp(&member.key.0)),
            handle: Some(member.name.clone()).filter(|handle| !handle.is_empty()),
            device: Some(member.device_name.clone()),
            you: member.key == self.me,
            identity,
            added_by: member.added.as_ref().map(|(by, how)| AddedBy { fp: fp(&by.0), how: how.clone() }),
            iroh: None,
        }
    }

    /// The member with this key, or else its fingerprint: a former member's, or this client's before it is one.
    pub fn describe_key(&self, key: &Bytes) -> Described {
        match self.members.iter().find(|m| &m.key == key) {
            Some(member) => self.describe(member),
            None => Described { name: Some(fp(&key.0)), fp: Some(fp(&key.0)), you: *key == self.me, ..Described::default() },
        }
    }

    /// An identity as this one knows it: this device's own, or another's, by its own claim.
    fn known(&self, claim: &Claim) -> Known {
        let own = self.identity.as_ref().filter(|(identity, _)| identity.id == claim.identity.id);
        let (name, how) = match own {
            Some((_, name)) => (name.clone(), Standing::Own),
            None => (claim.name.clone(), Standing::Unknown),
        };
        Known {
            id: claim.identity.id.clone(),
            name,
            how,
            error: claim.error.clone(),
        }
    }
}

/// How a member shows: this session as "you"; another of your own identity's as its device, with its handle where that
/// device has several sessions in the group, as "laptop (swift-koala)"; another identity's as "Ann · laptop", that
/// identity's own claim; one that speaks for no identity, or failed the check, by its fingerprint.
pub fn shown(member: &Value) -> String {
    if member["you"] == true {
        return "you".into();
    }
    let name = member["name"].as_str().unwrap_or_default();
    match member["identity"]["name"].as_str() {
        Some(own) if member["identity"]["how"] == "self" => name.strip_prefix(&format!("{own} · ")).unwrap_or(name).into(),
        _ => name.into(),
    }
}

/// Whether a described member answers to `name`, in any case: its identity's name, its device's or its handle, or the
/// first word of one.
pub fn answers(member: &Value, name: &str) -> bool {
    let name = name.to_lowercase();
    [&member["identity"]["name"], &member["device"], &member["handle"]].into_iter().filter_map(Value::as_str).any(|own| {
        let own = own.to_lowercase();
        own == name || own.split(|c: char| !c.is_alphanumeric()).next() == Some(name.as_str())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn member(handle: &str, key: u8, identity: Option<(u8, &str)>) -> Member {
        let identity = identity.map(|(id, claimed)| Claim {
            identity: IdentityRef { id: Bytes(vec![id]), membership: crate::letmeknow_dev() },
            name: claimed.into(),
            error: None,
        });
        Member { key: Bytes(vec![key]), iroh: Bytes(vec![key]), revision: 1, name: handle.into(), device_name: "laptop".into(), identity, added: None }
    }

    #[test]
    fn a_member_shows_as_its_identity_and_device_and_its_handle_where_another_shows_so_too() {
        let own = IdentityRef { id: Bytes(vec![10]), membership: crate::letmeknow_dev() };
        let mut eve = member("eve", 5, Some((20, "Robert")));
        eve.identity.as_mut().unwrap().error = Some("its device is not on the identity's list".into());
        let describer = Describer {
            me: Bytes(vec![1]),
            identity: Some((own, "Ann".into())),
            members: vec![
                member("claude", 1, Some((10, "Ann Smith"))),
                member("", 2, Some((20, "Robert"))),
                member("swift-koala", 3, Some((10, "Ann Smith"))),
                member("dan", 4, None),
                eve,
            ],
        };
        let shown = |m: &Member| serde_json::to_value(describer.describe(m)).unwrap();
        let claude = shown(&describer.members[0]);
        assert_eq!(claude["identity"], json!({ "id": "Cg", "name": "Ann", "how": "self" }));
        assert_eq!((&claude["name"], &claude["you"]), (&json!("Ann · laptop (claude)"), &json!(true)));
        let bob = shown(&describer.members[1]);
        assert_eq!(bob, json!({ "name": "Robert · laptop", "fp": crate::fp(&[2]), "device": "laptop", "identity": { "id": "FA", "name": "Robert", "how": "unknown" } }));
        let (dan, eve) = (shown(&describer.members[3]), shown(&describer.members[4]));
        assert_eq!((&dan["name"], &eve["name"]), (&dan["fp"], &eve["fp"]), "no identity, or one that failed the check: a fingerprint");
        assert!(["ANN", "claude", "Laptop"].iter().all(|name| answers(&claude, name)) && answers(&bob, "robert") && answers(&dan, "dan"));
        assert!(!answers(&claude, "smith") && !answers(&bob, "bob"));
        let peer = Member { key: Bytes::default(), ..member("", 9, None) };
        assert_eq!(shown(&peer), json!({ "iroh": "CQ" }));
    }
}
