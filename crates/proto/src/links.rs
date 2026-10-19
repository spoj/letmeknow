//! Invite links.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::directory;

pub const INVITE_PREFIX: &str = "https://letmeknow.dev/i#";
/// letmeknow.dev's domain: where its service publishes its directory, and runs its relay.
pub const DOMAIN: &str = "relay.letmeknow.dev";
/// letmeknow.dev's membership service key, hex. Its routes are at `DOMAIN`.
pub const MEMBERSHIP_KEY: &str = "c777450e239b6e64bafc6d8f9beb413515d24e1913b45c98f1696059ca139ed0";

/// `https://letmeknow.dev/i#12.<secret>.<domain>.<member>[.<member>...]`, every field after the version in unpadded
/// base64url: the domain is the group's service's, and each member is its iroh key, then its own service's domain unless
/// that is the group's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub secret: [u8; 16],
    pub domain: String,
    /// The members a joiner asks, in turn: each one's iroh key, and the domain of its own service, whose relay it lives on.
    pub members: Vec<([u8; 32], String)>,
}

impl Invite {
    pub fn link(&self) -> String {
        let mut link = format!("{INVITE_PREFIX}12.{}.{}", URL_SAFE_NO_PAD.encode(self.secret), URL_SAFE_NO_PAD.encode(&self.domain));
        for (key, home) in &self.members {
            let home = if *home == self.domain { "" } else { home.as_str() };
            link.push('.');
            link.push_str(&URL_SAFE_NO_PAD.encode([key.as_slice(), home.as_bytes()].concat()));
        }
        link
    }

    pub fn parse(link: &str) -> Result<Self> {
        let fragment = link.split_once('#').context("an invite link has a part after #")?.1;
        let mut fields = fragment.split('.');
        ensure!(fields.next() == Some("12"), "this invite link is from another version of letmeknow");
        let secret = URL_SAFE_NO_PAD.decode(fields.next().context("no secret")?)?.try_into().ok().context("a secret is 16 bytes")?;
        let domain = String::from_utf8(URL_SAFE_NO_PAD.decode(fields.next().context("no domain")?)?)?;
        directory::check_domain(&domain)?;
        let member = |field: &str| -> Result<([u8; 32], String)> {
            let bytes = URL_SAFE_NO_PAD.decode(field)?;
            let (key, home) = bytes.split_at_checked(32).context("a key is 32 bytes")?;
            let home = if home.is_empty() { domain.clone() } else { String::from_utf8(home.to_vec())? };
            directory::check_domain(&home)?;
            Ok((key.try_into()?, home))
        };
        let members = fields.map(member).collect::<Result<Vec<_>>>()?;
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
        let directory = serde_json::json!({ "key": MEMBERSHIP_KEY });
        assert_eq!(backend, serde_json::json!({ "domain": DOMAIN, "directory": directory }));
    }

    #[test]
    fn invite_round_trip() {
        let members = vec![([1; 32], "relay.example:8443".to_owned()), ([3; 32], "other.example".into())];
        let invite = Invite { secret: [2; 16], domain: "relay.example:8443".into(), members: members.clone() };
        assert_eq!(Invite::parse(&invite.link()).unwrap(), invite);
        assert_eq!(invite.link().split('#').nth(1).unwrap().split('.').nth(3).unwrap(), URL_SAFE_NO_PAD.encode([1; 32]), "a member at the group's service names no domain");
        let elsewhere = |home: &[u8]| format!("https://letmeknow.dev/i#12.{}.{}.{}", URL_SAFE_NO_PAD.encode([2; 16]), URL_SAFE_NO_PAD.encode("relay.example"), URL_SAFE_NO_PAD.encode([[1; 32].as_slice(), home].concat()));
        assert!(Invite::parse(&elsewhere(b"Other.example")).is_err(), "a member's domain is canonical");
        assert!(Invite::parse(&elsewhere(&[0xff])).is_err());
        assert!(Invite::parse("https://letmeknow.dev/i#12.AA.AA").is_err());
        assert!(Invite::parse("https://letmeknow.dev/i#12.AgICAgICAgICAgICAgICAg.AA").is_err(), "a link names a member");
        let link = Invite { secret: [2; 16], domain: "relay.example".into(), members }.link();
        assert!(Invite::parse(&link.replacen("#12.", "#11.", 1)).unwrap_err().to_string().contains("another version"));
        assert!(Invite::parse(&link.replacen("#12.", "#13.", 1)).unwrap_err().to_string().contains("another version"));
    }

    #[test]
    fn invite_refuses_a_domain_that_is_not_canonical() {
        let link = |domain: &str| format!("https://letmeknow.dev/i#12.{}.{}.{}", URL_SAFE_NO_PAD.encode([2; 16]), URL_SAFE_NO_PAD.encode(domain), URL_SAFE_NO_PAD.encode([1; 32]));
        assert!(Invite::parse(&link("relay.example")).is_ok());
        for domain in ["Relay.example", "relay.example:443", "relay.example.", "u@relay.example", "127.0.0.1:8443", "relay.example/x"] {
            assert!(Invite::parse(&link(domain)).is_err(), "{domain}");
        }
    }

}
