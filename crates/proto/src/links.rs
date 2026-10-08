//! Invite links and file links.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub const INVITE_PREFIX: &str = "https://letmeknow.dev/i#";

/// `https://letmeknow.dev/i#1.<g|d>.<key>.<secret>[.<relay>]`, every field after the kind in unpadded base64url.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub device: bool,
    /// The inviter's iroh key.
    pub key: [u8; 32],
    pub secret: [u8; 16],
    /// The inviter's relay, when it is not letmeknow.dev's.
    pub relay: Option<String>,
}

impl Invite {
    pub fn link(&self) -> String {
        let mut link = format!(
            "{INVITE_PREFIX}1.{}.{}.{}",
            if self.device { "d" } else { "g" },
            URL_SAFE_NO_PAD.encode(self.key),
            URL_SAFE_NO_PAD.encode(self.secret)
        );
        if let Some(relay) = &self.relay {
            link.push('.');
            link.push_str(&URL_SAFE_NO_PAD.encode(relay));
        }
        link
    }

    pub fn parse(link: &str) -> Result<Self> {
        let fragment = link.split_once('#').context("an invite link has a part after #")?.1;
        let mut fields = fragment.split('.');
        ensure!(fields.next() == Some("1"), "unknown invite link version");
        let device = match fields.next() {
            Some("g") => false,
            Some("d") => true,
            _ => bail!("unknown invite kind"),
        };
        let key = URL_SAFE_NO_PAD.decode(fields.next().context("no key")?)?.try_into().ok().context("a key is 32 bytes")?;
        let secret =
            URL_SAFE_NO_PAD.decode(fields.next().context("no secret")?)?.try_into().ok().context("a secret is 16 bytes")?;
        let relay = fields.next().map(|relay| URL_SAFE_NO_PAD.decode(relay)).transpose()?.map(String::from_utf8).transpose()?;
        ensure!(fields.next().is_none(), "too many fields in the invite link");
        Ok(Invite { device, key, secret, relay })
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
        for relay in [None, Some("https://relay.example/".to_string())] {
            let invite = Invite { device: relay.is_some(), key: [1; 32], secret: [2; 16], relay };
            assert_eq!(Invite::parse(&invite.link()).unwrap(), invite);
        }
        assert!(Invite::parse("https://letmeknow.dev/i#2.g.AA.AA").is_err());
    }

    #[test]
    fn file_round_trip() {
        let file = FileLink { hash: [3; 32], size: 12345, key: [4; 32] };
        assert_eq!(FileLink::parse(&file.link()).unwrap(), file);
    }
}
