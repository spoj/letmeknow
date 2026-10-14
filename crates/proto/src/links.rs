//! Invite links and file links.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::directory;

pub const INVITE_PREFIX: &str = "https://letmeknow.dev/i#";
/// letmeknow.dev's domain: where its service publishes its directory.
pub const DOMAIN: &str = "relay.letmeknow.dev";
/// letmeknow.dev's relay, which links leave out.
pub const RELAY: &str = "https://relay.letmeknow.dev";
/// letmeknow.dev's membership service: its iroh key, hex. It is reached through `RELAY`.
pub const MEMBERSHIP_KEY: &str = "7fdc5178ea2da4c7c282d34dd183e6fb109e8afdcb61ffd3f1a9a7c715e50518";

/// `https://letmeknow.dev/i#8.<g|d>.<secret>.<domain>.<member>[.<member>...]`, every field after the kind in unpadded
/// base64url: the domain is the group's service's, and each member is its iroh key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub device: bool,
    pub secret: [u8; 16],
    pub domain: String,
    /// The members a joiner asks, in turn.
    pub members: Vec<[u8; 32]>,
}

impl Invite {
    pub fn link(&self) -> String {
        let kind = if self.device { "d" } else { "g" };
        let mut link = format!("{INVITE_PREFIX}8.{kind}.{}.{}", URL_SAFE_NO_PAD.encode(self.secret), URL_SAFE_NO_PAD.encode(&self.domain));
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
            Some("8") => {}
            Some("7") => bail!("this invite link is from letmeknow 0.18, whose groups this version cannot join: ask for an invite to a group made with letmeknow 0.19"),
            _ => bail!("this invite link is from another version of letmeknow"),
        }
        let device = match fields.next() {
            Some("d") => true,
            Some("g") => false,
            _ => bail!("unknown invite kind"),
        };
        let secret = URL_SAFE_NO_PAD.decode(fields.next().context("no secret")?)?.try_into().ok().context("a secret is 16 bytes")?;
        let domain = String::from_utf8(URL_SAFE_NO_PAD.decode(fields.next().context("no domain")?)?)?;
        directory::check_domain(&domain)?;
        let members = fields
            .map(|member| URL_SAFE_NO_PAD.decode(member)?.try_into().ok().context("a key is 32 bytes"))
            .collect::<Result<Vec<[u8; 32]>>>()?;
        ensure!(!members.is_empty(), "an invite link names a member");
        Ok(Invite { device, secret, domain, members })
    }
}

/// `lmk:<BLAKE3 of the ciphertext, hex>.<plaintext size>#<key, hex>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileLink {
    pub hash: [u8; 32],
    pub size: u64,
    pub key: [u8; 32],
}

impl FileLink {
    pub fn link(&self) -> String {
        format!("lmk:{}.{}#{}", hex::encode(self.hash), self.size, hex::encode(self.key))
    }

    pub fn parse(link: &str) -> Result<Self> {
        let rest = link.strip_prefix("lmk:").context("a file link starts with lmk:")?;
        let (located, key) = rest.split_once('#').context("a file link has a key after #")?;
        let (hash, size) = located.split_once('.').context("a file link has a size")?;
        Ok(FileLink {
            hash: hex::decode(hash)?.try_into().ok().context("a hash is 32 bytes")?,
            size: size.parse()?,
            key: hex::decode(key)?.try_into().ok().context("a key is 32 bytes")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_round_trip() {
        let members = vec![[1; 32], [3; 32]];
        for device in [false, true] {
            let invite = Invite { device, secret: [2; 16], domain: "relay.example:8443".into(), members: members.clone() };
            assert_eq!(Invite::parse(&invite.link()).unwrap(), invite);
        }
        assert!(Invite::parse("https://letmeknow.dev/i#8.g.AA.AA").is_err());
        assert!(Invite::parse("https://letmeknow.dev/i#8.g.AgICAgICAgICAgICAgICAg.AA").is_err(), "a link names a member");
        let link = Invite { device: false, secret: [2; 16], domain: "relay.example".into(), members }.link();
        assert!(Invite::parse(&link.replacen("#8.", "#7.", 1)).unwrap_err().to_string().contains("letmeknow 0.18"));
        assert!(Invite::parse(&link.replacen("#8.", "#6.", 1)).unwrap_err().to_string().contains("another version"));
        assert!(Invite::parse(&link.replacen("#8.", "#9.", 1)).unwrap_err().to_string().contains("another version"));
    }

    #[test]
    fn invite_refuses_a_domain_that_is_not_canonical() {
        let link = |domain: &str| format!("https://letmeknow.dev/i#8.g.{}.{}.{}", URL_SAFE_NO_PAD.encode([2; 16]), URL_SAFE_NO_PAD.encode(domain), URL_SAFE_NO_PAD.encode([1; 32]));
        assert!(Invite::parse(&link("relay.example")).is_ok());
        for domain in ["Relay.example", "relay.example:443", "relay.example.", "u@relay.example", "127.0.0.1:8443", "relay.example/x"] {
            assert!(Invite::parse(&link(domain)).is_err(), "{domain}");
        }
    }

    #[test]
    fn file_round_trip() {
        let file = FileLink { hash: [3; 32], size: 12345, key: [4; 32] };
        assert_eq!(FileLink::parse(&file.link()).unwrap(), file);
    }
}
