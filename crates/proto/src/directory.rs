//! A service's directory, published at `https://<domain>/.well-known/letmeknow.json`.

use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};
use url::Host;

use crate::links::MEMBERSHIP_KEY;

/// The largest body `parse` reads.
pub const MAX_BYTES: usize = 64 << 10;

/// The service's key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Directory {
    #[serde(with = "hex_key")]
    pub key: [u8; 32],
}

impl Directory {
    pub fn parse(body: &[u8]) -> Result<Self> {
        ensure!(body.len() <= MAX_BYTES, "a directory is at most 64 KB");
        Ok(serde_json::from_slice(body)?)
    }

    /// Where `domain` publishes its directory.
    pub fn url(domain: &str) -> String {
        format!("https://{domain}/.well-known/letmeknow.json")
    }

    /// letmeknow.dev's directory, used while no fetch has succeeded.
    pub fn builtin() -> Self {
        Directory { key: hex::decode(MEMBERSHIP_KEY).expect("MEMBERSHIP_KEY is hex").try_into().expect("MEMBERSHIP_KEY is 32 bytes") }
    }
}

/// The relay a service runs beside it, at its domain: the sessions whose own service it is live on it.
pub fn relay_url(domain: &str) -> String {
    format!("https://{domain}")
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

    #[test]
    fn builtin_round_trips() {
        let builtin = Directory::builtin();
        assert_eq!(Directory::parse(&serde_json::to_vec(&builtin).unwrap()).unwrap(), builtin);
    }

    #[test]
    fn parses_what_serve_publishes() {
        let key = "ab".repeat(32);
        assert_eq!(Directory::parse(format!(r#"{{"key":"{key}"}}"#).as_bytes()).unwrap().key, [0xab; 32]);
        let refused = |text: String| Directory::parse(text.as_bytes()).unwrap_err().to_string();
        assert!(refused(format!(r#"{{"key":"{}"}}"#, "ab".repeat(31))).contains("32 bytes of hex"));
        assert!(refused(format!(r#"{{"key":"{}"}}"#, "zz".repeat(32))).contains("32 bytes of hex"));
        assert!(refused(format!(r#"{{"key":"{key}","pad":"{}"}}"#, "x".repeat(MAX_BYTES))).contains("64 KB"));
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
