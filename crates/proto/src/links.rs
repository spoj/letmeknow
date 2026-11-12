//! Invite links.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::directory;

/// The digits of a run's length in a link that URL Defense v3 rewrote.
const RUNS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub const INVITE_PREFIX: &str = "https://letmeknow.dev/i#";
/// letmeknow.dev's domain: where its service publishes its directory, and runs its relay.
pub const DOMAIN: &str = "relay.letmeknow.dev";
/// letmeknow.dev's membership service key, hex. Its routes are at `DOMAIN`.
pub const MEMBERSHIP_KEY: &str = "4b0be3befd0c240033aa446df4d24b69ff758fa93593123e525c98f7c46ae046";

/// `https://letmeknow.dev/i#15.<secret>.<domain>.<key>.<group>.<by>.<joined>.<member>[.<member>...]`, every field after
/// the version in unpadded base64url: the domain and key are the group's service's; the group is the one it admits to,
/// `by` the session key of the member that made it, and `joined` the epoch that member's membership began in, 8 bytes
/// big-endian; and each member is its iroh key, then its own service's domain unless that is the group's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub secret: [u8; 16],
    pub domain: String,
    pub key: [u8; 32],
    pub group: [u8; 16],
    pub by: [u8; 32],
    pub joined: u64,
    /// The members a joiner asks, in turn: each one's iroh key, and the domain of its own service, whose relay it lives on.
    pub members: Vec<([u8; 32], String)>,
}

impl Invite {
    pub fn link(&self) -> String {
        let fields = [self.secret.as_slice(), self.domain.as_bytes(), &self.key, &self.group, &self.by, &self.joined.to_be_bytes()];
        let mut link = format!("{INVITE_PREFIX}15.{}", fields.map(|field| URL_SAFE_NO_PAD.encode(field)).join("."));
        for (key, home) in &self.members {
            let home = if *home == self.domain { "" } else { home.as_str() };
            link.push('.');
            link.push_str(&URL_SAFE_NO_PAD.encode([key.as_slice(), home.as_bytes()].concat()));
        }
        link
    }

    pub fn parse(link: &str) -> Result<Self> {
        // A mail gateway's URL Defense v3 wraps a link as `.../v3/__<link>__;<replaced>!...`: each `*` of the link stands
        // for the next of the characters `replaced` lists, in base64url, and `**` with a base64url digit for a run of them,
        // two at `A`.
        let mut unwrapped = String::new();
        let link = match link.split_once("/v3/__").and_then(|(_, wrapped)| wrapped.split_once("__;")) {
            Some((wrapped, rest)) => {
                let replaced = String::from_utf8(URL_SAFE_NO_PAD.decode(rest.split('!').next().unwrap())?)?;
                let (mut replaced, mut chars) = (replaced.chars(), wrapped.chars().peekable());
                while let Some(c) = chars.next() {
                    if c != '*' {
                        unwrapped.push(c);
                    } else if chars.next_if_eq(&'*').is_some() {
                        let run = chars.next().and_then(|digit| RUNS.find(digit)).context("a rewritten invite link names its runs' lengths")?;
                        unwrapped.extend(replaced.by_ref().take(run + 2));
                    } else {
                        unwrapped.extend(replaced.next());
                    }
                }
                unwrapped.as_str()
            }
            None => link,
        };
        let fragment = link.split_once('#').context("an invite link has a part after #")?.1;
        let mut fields = fragment.split('.');
        ensure!(fields.next() == Some("15"), "this invite link is from another version of letmeknow");
        let secret = URL_SAFE_NO_PAD.decode(fields.next().context("no secret")?)?.try_into().ok().context("a secret is 16 bytes")?;
        let domain = String::from_utf8(URL_SAFE_NO_PAD.decode(fields.next().context("no domain")?)?)?;
        directory::check_domain(&domain)?;
        let key = URL_SAFE_NO_PAD.decode(fields.next().context("no service key")?)?.try_into().ok().context("a service key is 32 bytes")?;
        let group = URL_SAFE_NO_PAD.decode(fields.next().context("no group")?)?.try_into().ok().context("a group is 16 bytes")?;
        let by = URL_SAFE_NO_PAD.decode(fields.next().context("no inviter")?)?.try_into().ok().context("an inviter's key is 32 bytes")?;
        let joined = URL_SAFE_NO_PAD.decode(fields.next().context("no inviter's epoch")?)?.try_into().ok().context("an inviter's epoch is 8 bytes")?;
        let member = |field: &str| -> Result<([u8; 32], String)> {
            let bytes = URL_SAFE_NO_PAD.decode(field)?;
            let (key, home) = bytes.split_at_checked(32).context("a key is 32 bytes")?;
            let home = if home.is_empty() { domain.clone() } else { String::from_utf8(home.to_vec())? };
            directory::check_domain(&home)?;
            Ok((key.try_into()?, home))
        };
        let members = fields.map(member).collect::<Result<Vec<_>>>()?;
        ensure!(!members.is_empty(), "an invite link names a member");
        Ok(Invite { secret, domain, key, group, by, joined: u64::from_be_bytes(joined), members })
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
        let invite = Invite { secret: [2; 16], domain: "relay.example:8443".into(), key: [8; 32], group: [4; 16], by: [5; 32], joined: 6, members: members.clone() };
        assert_eq!(Invite::parse(&invite.link()).unwrap(), invite);
        assert_eq!(invite.link().split('#').nth(1).unwrap().split('.').nth(7).unwrap(), URL_SAFE_NO_PAD.encode([1; 32]), "a member at the group's service names no domain");
        let alone = Invite { domain: "relay.example".into(), members: vec![members[0].clone()], ..invite.clone() }.link();
        let unnamed = alone.rsplit_once('.').unwrap().0;
        let elsewhere = |home: &[u8]| format!("{unnamed}.{}", URL_SAFE_NO_PAD.encode([[1; 32].as_slice(), home].concat()));
        assert!(Invite::parse(&elsewhere(b"Other.example")).is_err(), "a member's domain is canonical");
        assert!(Invite::parse(&elsewhere(&[0xff])).is_err());
        assert!(Invite::parse("https://letmeknow.dev/i#15.AA.AA").is_err());
        assert!(Invite::parse(unnamed).unwrap_err().to_string().contains("names a member"));
        let link = Invite { domain: "relay.example".into(), members, ..invite }.link();
        assert!(Invite::parse(&link.replacen("#15.", "#14.", 1)).unwrap_err().to_string().contains("another version"));
        assert!(Invite::parse(&link.replacen("#15.", "#16.", 1)).unwrap_err().to_string().contains("another version"));
    }

    /// A link that a mail gateway's URL Defense v3 rewrote parses as the invite it wraps.
    #[test]
    fn invite_unwraps_url_defense_v3() {
        let invite = Invite { secret: [2; 16], domain: "relay.example".into(), key: [8; 32], group: [4; 16], by: [5; 32], joined: 6, members: vec![([1; 32], "relay.example".into())] };
        let link = invite.link();
        for (rewritten, replaced) in [(link.replace('#', "*"), "#"), (link.replace("#15", "**B"), "#15"), (link.replace("i#", "**A"), "i#")] {
            let wrapped = format!("https://urldefense.com/v3/__{rewritten}__;{}!!recipient!signature$", URL_SAFE_NO_PAD.encode(replaced));
            assert_eq!(Invite::parse(&wrapped).unwrap(), invite, "{wrapped}");
        }
        // A published sample: https://github.com/cardi/proofpoint-url-decoder/issues/4
        let sample = "https://urldefense.com/v3/__https://contact.framasoft.org/*newsletter__;Iw!!LIr3w8kk_Xxm!6BNqFLJ13q7N5_lf3XQFlmTtgY5CkKjhfcIn4ybAhA1_gx_y07jmQ4uvR2QZ$";
        assert!(Invite::parse(sample).unwrap_err().to_string().contains("another version"), "its * stands for #");
    }

    #[test]
    fn invite_refuses_a_domain_that_is_not_canonical() {
        let link = |domain: &str| Invite { secret: [2; 16], domain: domain.into(), key: [8; 32], group: [4; 16], by: [5; 32], joined: 6, members: vec![([1; 32], domain.into())] }.link();
        assert!(Invite::parse(&link("relay.example")).is_ok());
        for domain in ["Relay.example", "relay.example:443", "relay.example.", "u@relay.example", "127.0.0.1:8443", "relay.example/x"] {
            assert!(Invite::parse(&link(domain)).is_err(), "{domain}");
        }
    }

}
