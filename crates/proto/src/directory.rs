//! A service's directory, published at `https://<domain>/.well-known/letmeknow.json`.

use anyhow::{Result, ensure};
use http::uri::Authority;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::links::{DOMAIN, MEMBERSHIP_KEY, RELAY};

/// The largest body `parse` reads.
const MAX_BYTES: usize = 64 << 10;
const MAX_RELAYS: usize = 16;
const MAX_ADDRS: usize = 4;

/// The service's iroh key, the `host:port` addresses its membership is dialed at, the relay the service lives on, and
/// the relays its deployment's sessions live on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Directory {
    #[serde(with = "hex_key")]
    pub key: [u8; 32],
    pub addrs: Vec<String>,
    pub relay: String,
    pub relays: Vec<String>,
}

impl Directory {
    pub fn parse(body: &[u8]) -> Result<Self> {
        ensure!(body.len() <= MAX_BYTES, "a directory is at most 64 KB");
        let directory: Directory = serde_json::from_slice(body)?;
        directory.check()?;
        Ok(directory)
    }

    /// Refuses what a client would not dial: relays that are not `https` URLs, and addresses without a port.
    pub fn check(&self) -> Result<()> {
        ensure!((1..=MAX_RELAYS).contains(&self.relays.len()), "a directory names 1 to 16 relays");
        for relay in self.relays.iter().chain([&self.relay]) {
            ensure!(Url::parse(relay).is_ok_and(|url| url.scheme() == "https"), "a relay is an https URL, not {relay}");
        }
        ensure!(self.addrs.len() <= MAX_ADDRS, "a directory names at most 4 addresses");
        for addr in &self.addrs {
            ensure!(addr.parse::<Authority>()?.port_u16().is_some(), "an address is host:port, not {addr}");
        }
        Ok(())
    }

    /// Where `domain` publishes its directory.
    pub fn url(domain: &str) -> String {
        format!("https://{domain}/.well-known/letmeknow.json")
    }

    /// letmeknow.dev's directory, used while no fetch has succeeded.
    pub fn builtin() -> Self {
        Directory {
            key: hex::decode(MEMBERSHIP_KEY).expect("MEMBERSHIP_KEY is hex").try_into().expect("MEMBERSHIP_KEY is 32 bytes"),
            addrs: vec![format!("{DOMAIN}:7843")],
            relay: RELAY.into(),
            relays: vec![RELAY.into()],
        }
    }
}

mod hex_key {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(key: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(key))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        hex::decode(text).ok().and_then(|key| key.try_into().ok()).ok_or_else(|| D::Error::custom("a key is 32 bytes of hex"))
    }
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;

    /// `relay` is a raw JSON value, a quoted string.
    fn body(key: &str, addrs: &str, relay: &str, relays: &str) -> String {
        format!(r#"{{"key":"{key}","addrs":{addrs},"relay":{relay},"relays":{relays}}}"#)
    }

    #[test]
    fn builtin_round_trips() {
        let builtin = Directory::builtin();
        assert_eq!(Directory::parse(&serde_json::to_vec(&builtin).unwrap()).unwrap(), builtin);
        assert_eq!(builtin.addrs, ["relay.letmeknow.dev:7843"]);
        assert_eq!(builtin.relay, RELAY);
        assert_eq!(builtin.relays, [RELAY]);
    }

    #[test]
    fn parses_what_serve_publishes() {
        let key = "ab".repeat(32);
        let parsed = Directory::parse(
            body(&key, r#"["h.example:7843"]"#, r#""https://h.example""#, r#"["https://h.example","https://r.example:8443"]"#).as_bytes(),
        )
        .unwrap();
        assert_eq!(parsed.key, [0xab; 32]);
        assert_eq!(parsed.addrs, ["h.example:7843"]);
        assert_eq!(parsed.relay, "https://h.example");
        assert_eq!(parsed.relays, ["https://h.example", "https://r.example:8443"]);
        assert!(Directory::parse(body(&key, "[]", r#""https://h.example""#, r#"["https://h.example"]"#).as_bytes()).is_ok(), "no addresses is allowed");
    }

    #[test]
    fn refuses_what_clients_cannot_use() {
        let key = "ab".repeat(32);
        let refused = |text: String| Directory::parse(text.as_bytes()).unwrap_err().to_string();
        let ok = r#""https://h""#;
        assert!(refused(body(&"ab".repeat(31), "[]", ok, r#"["https://h"]"#)).contains("32 bytes of hex"));
        assert!(refused(body(&"zz".repeat(32), "[]", ok, r#"["https://h"]"#)).contains("32 bytes of hex"));
        assert!(refused(body(&key, "[]", ok, "[]")).contains("1 to 16 relays"));
        assert!(refused(body(&key, "[]", ok, &format!("[{}]", vec![r#""https://h""#; 17].join(",")))).contains("1 to 16 relays"));
        assert!(refused(body(&key, "[]", ok, r#"["http://h"]"#)).contains("https URL"));
        assert!(refused(body(&key, "[]", ok, r#"["h.example"]"#)).contains("https URL"));
        assert!(refused(body(&key, "[]", ok, r#"["https://"]"#)).contains("https URL"));
        assert!(refused(body(&key, "[]", r#""http://h""#, r#"["https://h"]"#)).contains("https URL"));
        assert!(refused(body(&key, "[]", r#""h.example""#, r#"["https://h"]"#)).contains("https URL"));
        assert!(refused(body(&key, "[]", "\"\"", r#"["https://h"]"#)).contains("https URL"));
        assert!(refused(format!(r#"{{"key":"{key}","addrs":[],"relays":["https://h"]}}"#)).contains("relay"));
        assert!(refused(body(&key, r#"["h:1","h:1","h:1","h:1","h:1"]"#, ok, r#"["https://h"]"#)).contains("4 addresses"));
        assert!(refused(body(&key, r#"["h.example"]"#, ok, r#"["https://h"]"#)).contains("host:port"));
        assert!(refused(body(&key, r#"["h.example:"]"#, ok, r#"["https://h"]"#)).contains("host:port"));
        assert!(refused(body(&key, r#"["h.example:99999"]"#, ok, r#"["https://h"]"#)).contains("host:port"));
        assert!(refused(body(&key, r#"["h/x:1"]"#, ok, r#"["https://h"]"#)).contains("invalid"));
        let padded = format!(r#"{{"key":"{key}","addrs":[],"relay":"https://h","relays":["https://h"],"pad":"{}"}}"#, "x".repeat(MAX_BYTES));
        assert!(refused(padded).contains("64 KB"));
    }

    #[test]
    fn url_names_the_well_known_file() {
        assert_eq!(Directory::url("relay.letmeknow.dev"), "https://relay.letmeknow.dev/.well-known/letmeknow.json");
        assert_eq!(Directory::url("localhost:8443"), "https://localhost:8443/.well-known/letmeknow.json");
    }
}
