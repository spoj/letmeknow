//! A service's directory, published at `https://<domain>/.well-known/letmeknow.json`.

use anyhow::{Result, ensure};
use http::uri::Authority;
use serde::{Deserialize, Deserializer, Serialize};
use url::{Host, Url};

use crate::links::{DOMAIN, MEMBERSHIP_KEY, RELAY};

/// The largest body `parse` reads.
pub const MAX_BYTES: usize = 64 << 10;
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

/// Checks a service's domain as it is written: `host` or `host:port`, lowercase LDH labels, no trailing dot, no IP
/// literal, and no port 443 (the default) or other non-canonical port.
pub fn check_domain(domain: &str) -> Result<()> {
    let (host, port) = domain.split_once(':').map_or((domain, None), |(host, port)| (host, Some(port)));
    let label = |label: &&str| {
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let labels: Vec<&str> = host.split('.').collect();
    let domain_host = matches!(Host::parse(host), Ok(Host::Domain(_)));
    let port_ok = port.is_none_or(|port| port.parse::<u16>().is_ok_and(|n| n.to_string() == port && n != 0 && n != 443));
    ensure!(host.len() <= 253 && labels.iter().all(label) && domain_host && port_ok, "a domain is a canonical host or host:port, not {domain}");
    Ok(())
}

/// A service's domain, checked as it is read.
pub fn deserialize_domain<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let domain = String::deserialize(d)?;
    check_domain(&domain).map_err(serde::de::Error::custom)?;
    Ok(domain)
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
    fn domains_are_canonical_hosts() {
        for domain in ["relay.letmeknow.dev", "localhost:8443", "localhost", "a-b.example:7843", "h.example:1"] {
            assert!(check_domain(domain).is_ok(), "{domain}");
        }
        for domain in [
            "", ":8443", "localhost:", "localhost:443", "localhost:0443", "localhost:+8443", "localhost:0", "localhost:65536",
            "Relay.example", "relay.example.", "a..b", "-a.example", "a-.example", "a_b.example", "127.0.0.1", "127.0.0.1:8443",
            "[::1]:8443", "u@h.example", "h.example/x", "h.example?x", "h.example#x", "h.example:8443/x", "h .example",
            "h.example:8443:1", "0x7f000001", "0x7f000001:8443", "a.0x7f", "a.0x", "1.2.3",
        ] {
            assert!(check_domain(domain).is_err(), "{domain}");
        }
        assert!(check_domain(&format!("{}.example", "a".repeat(64))).is_err(), "a label is at most 63 bytes");
    }

    #[test]
    fn url_names_the_well_known_file() {
        assert_eq!(Directory::url("relay.letmeknow.dev"), "https://relay.letmeknow.dev/.well-known/letmeknow.json");
        assert_eq!(Directory::url("localhost:8443"), "https://localhost:8443/.well-known/letmeknow.json");
    }
}
