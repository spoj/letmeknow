//! Invite links.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::directory;

pub const INVITE_PREFIX: &str = "https://letmeknow.dev/i#";
/// letmeknow.dev's domain: where its service publishes its directory.
pub const DOMAIN: &str = "relay.letmeknow.dev";
/// letmeknow.dev's relay, which links leave out.
pub const RELAY: &str = "https://relay.letmeknow.dev";
/// letmeknow.dev's membership service key, hex. Its routes are at `DOMAIN`.
pub const MEMBERSHIP_KEY: &str = "c777450e239b6e64bafc6d8f9beb413515d24e1913b45c98f1696059ca139ed0";

/// `https://letmeknow.dev/i#11.<secret>.<domain>.<member>[.<member>...]`, every field after the version in unpadded
/// base64url: the domain is the group's service's, and each member is its iroh key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub secret: [u8; 16],
    pub domain: String,
    /// The members a joiner asks, in turn.
    pub members: Vec<[u8; 32]>,
}

impl Invite {
    pub fn link(&self) -> String {
        let mut link = format!("{INVITE_PREFIX}11.{}.{}", URL_SAFE_NO_PAD.encode(self.secret), URL_SAFE_NO_PAD.encode(&self.domain));
        for member in &self.members {
            link.push('.');
            link.push_str(&URL_SAFE_NO_PAD.encode(member));
        }
        link
    }

    pub fn parse(link: &str) -> Result<Self> {
        let fragment = link.split_once('#').context("an invite link has a part after #")?.1;
        let mut fields = fragment.split('.');
        match fields.next() {
            Some("11") => {}
            Some("10") => bail!("this invite link is from letmeknow 0.21, whose groups this version cannot join: ask for an invite to a group made with letmeknow 0.22"),
            _ => bail!("this invite link is from another version of letmeknow"),
        }
        let secret = URL_SAFE_NO_PAD.decode(fields.next().context("no secret")?)?.try_into().ok().context("a secret is 16 bytes")?;
        let domain = String::from_utf8(URL_SAFE_NO_PAD.decode(fields.next().context("no domain")?)?)?;
        directory::check_domain(&domain)?;
        let members = fields
            .map(|member| URL_SAFE_NO_PAD.decode(member)?.try_into().ok().context("a key is 32 bytes"))
            .collect::<Result<Vec<[u8; 32]>>>()?;
        ensure!(!members.is_empty(), "an invite link names a member");
        Ok(Invite { secret, domain, members })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What deploy/deploy.sh checks the service it installs against is the service built in here.
    #[test]
    fn the_deployed_service_is_the_built_in_one() {
        let backend: serde_json::Value = serde_json::from_str(include_str!("../../../deploy/backend.json")).unwrap();
        let directory = serde_json::json!({ "key": MEMBERSHIP_KEY, "relay": RELAY, "relays": [RELAY] });
        assert_eq!(backend, serde_json::json!({ "domain": DOMAIN, "directory": directory }));
    }

    #[test]
    fn invite_round_trip() {
        let members = vec![[1; 32], [3; 32]];
        let invite = Invite { secret: [2; 16], domain: "relay.example:8443".into(), members: members.clone() };
        assert_eq!(Invite::parse(&invite.link()).unwrap(), invite);
        assert!(Invite::parse("https://letmeknow.dev/i#11.AA.AA").is_err());
        assert!(Invite::parse("https://letmeknow.dev/i#11.AgICAgICAgICAgICAgICAg.AA").is_err(), "a link names a member");
        let link = Invite { secret: [2; 16], domain: "relay.example".into(), members }.link();
        assert!(Invite::parse(&link.replacen("#11.", "#10.", 1)).unwrap_err().to_string().contains("letmeknow 0.21"));
        assert!(Invite::parse(&link.replacen("#11.", "#9.", 1)).unwrap_err().to_string().contains("another version"));
        assert!(Invite::parse(&link.replacen("#11.", "#12.", 1)).unwrap_err().to_string().contains("another version"));
    }

    #[test]
    fn invite_refuses_a_domain_that_is_not_canonical() {
        let link = |domain: &str| format!("https://letmeknow.dev/i#11.{}.{}.{}", URL_SAFE_NO_PAD.encode([2; 16]), URL_SAFE_NO_PAD.encode(domain), URL_SAFE_NO_PAD.encode([1; 32]));
        assert!(Invite::parse(&link("relay.example")).is_ok());
        for domain in ["Relay.example", "relay.example:443", "relay.example.", "u@relay.example", "127.0.0.1:8443", "relay.example/x"] {
            assert!(Invite::parse(&link(domain)).is_err(), "{domain}");
        }
    }

}
