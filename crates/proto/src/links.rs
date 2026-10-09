//! Invite links and file links.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub const INVITE_PREFIX: &str = "https://letmeknow.dev/i#";
/// letmeknow.dev's relay, which links leave out.
pub const RELAY: &str = "https://letmeknow.dev";
/// letmeknow.dev's membership service: its iroh key, hex. It is reached through `RELAY`.
pub const MEMBERSHIP_KEY: &str = "50d422869a41e313ef48fa00284557a0c3d15374280b7f3d5d35a35c2393370f";

/// `https://letmeknow.dev/i#2.<g|d>.<secret>.<member>[.<member>...]`, where each member is its iroh key, then `~` and
/// its relay when that is not letmeknow.dev's; every field after the kind in unpadded base64url.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub device: bool,
    pub secret: [u8; 16],
    /// The members a joiner asks, in turn.
    pub members: Vec<Address>,
}

/// A member to dial: its iroh key, and its relay when it is not letmeknow.dev's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub key: [u8; 32],
    pub relay: Option<String>,
}

impl Invite {
    pub fn link(&self) -> String {
        let mut link = format!("{INVITE_PREFIX}2.{}.{}", if self.device { "d" } else { "g" }, URL_SAFE_NO_PAD.encode(self.secret));
        for member in &self.members {
            link.push('.');
            link.push_str(&URL_SAFE_NO_PAD.encode(member.key));
            if let Some(relay) = &member.relay {
                link.push('~');
                link.push_str(&URL_SAFE_NO_PAD.encode(relay));
            }
        }
        link
    }

    pub fn parse(link: &str) -> Result<Self> {
        let fragment = link.split_once('#').context("an invite link has a part after #")?.1;
        let mut fields = fragment.split('.');
        ensure!(fields.next() == Some("2"), "unknown invite link version");
        let device = match fields.next() {
            Some("d") => true,
            Some("g") => false,
            _ => bail!("unknown invite kind"),
        };
        let secret =
            URL_SAFE_NO_PAD.decode(fields.next().context("no secret")?)?.try_into().ok().context("a secret is 16 bytes")?;
        let members = fields
            .map(|member| {
                let (key, relay) = match member.split_once('~') {
                    Some((key, relay)) => (key, Some(String::from_utf8(URL_SAFE_NO_PAD.decode(relay)?)?)),
                    None => (member, None),
                };
                let key = URL_SAFE_NO_PAD.decode(key)?.try_into().ok().context("a key is 32 bytes")?;
                Ok(Address { key, relay })
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(!members.is_empty(), "an invite link names a member");
        Ok(Invite { device, secret, members })
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
        let members = vec![Address { key: [1; 32], relay: None }, Address { key: [3; 32], relay: Some("https://relay.example/".into()) }];
        for device in [false, true] {
            let invite = Invite { device, secret: [2; 16], members: members.clone() };
            assert_eq!(Invite::parse(&invite.link()).unwrap(), invite);
        }
        assert!(Invite::parse("https://letmeknow.dev/i#2.g.AA.AA").is_err());
        assert!(Invite::parse("https://letmeknow.dev/i#2.g.AgICAgICAgICAgICAgICAg").is_err(), "a link names a member");
    }

    #[test]
    fn file_round_trip() {
        let file = FileLink { hash: [3; 32], size: 12345, key: [4; 32] };
        assert_eq!(FileLink::parse(&file.link()).unwrap(), file);
    }
}
