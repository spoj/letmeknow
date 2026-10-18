//! Members as this client shows them: by their fingerprints, and who added them.

use lmk_node::Member;
use lmk_proto::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::fp;

/// A member, or only the iroh key of an endpoint that is not one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Described {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub you: bool,
    /// The fingerprint of the member that added it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh: Option<Bytes>,
}

/// What describing a group's members takes, gathered once.
pub struct Describer {
    pub(crate) me: Bytes,
    pub(crate) members: Vec<Member>,
}

impl Describer {
    pub fn describe(&self, member: &Member) -> Described {
        if member.key.0.is_empty() {
            return Described { iroh: Some(member.iroh.clone()), ..Described::default() };
        }
        Described { fp: Some(fp(&member.key.0)), you: member.key == self.me, added_by: member.added.as_ref().map(|by| fp(&by.0)), iroh: None }
    }

    /// The member with this key, or else its fingerprint: a former member's, or this client's before it is one.
    pub fn describe_key(&self, key: &Bytes) -> Described {
        match self.members.iter().find(|m| &m.key == key) {
            Some(member) => self.describe(member),
            None => Described { fp: Some(fp(&key.0)), you: *key == self.me, ..Described::default() },
        }
    }
}

/// How a member shows: this session as "you", another by its fingerprint.
pub fn shown(member: &Value) -> String {
    if member["you"] == true {
        return "you".into();
    }
    member["fp"].as_str().unwrap_or_default().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_member_shows_by_its_fingerprint_and_who_added_it() {
        let member = |key: u8, added: Option<u8>| Member { key: Bytes(vec![key]), iroh: Bytes(vec![key]), revision: 1, added: added.map(|by| Bytes(vec![by])) };
        let describer = Describer { me: Bytes(vec![1]), members: vec![member(1, None), member(2, Some(1))] };
        let shows = |m: &Member| serde_json::to_value(describer.describe(m)).unwrap();
        assert_eq!(shows(&describer.members[0]), json!({ "fp": fp(&[1]), "you": true }));
        assert_eq!(shows(&describer.members[1]), json!({ "fp": fp(&[2]), "added_by": fp(&[1]) }));
        assert_eq!(shown(&shows(&describer.members[0])), "you");
        assert_eq!(shown(&shows(&describer.members[1])), fp(&[2]));
        let peer = Member { key: Bytes::default(), ..member(9, None) };
        assert_eq!(shows(&peer), json!({ "iroh": "CQ" }));
    }
}
