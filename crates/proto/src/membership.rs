//! Capability-addressed membership streams. References in replies confer no access.

use std::{fmt, marker::PhantomData};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::{Error, SeqAccess, Visitor}};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{Bytes, head::{self, Head}};

pub const MAX_BODY: usize = 4 << 20;
pub const MAX_ENTRY: usize = 1 << 20;
pub const APPEND_ROWS: usize = 64;
pub const APPEND_BYTES: usize = 2 << 20;
pub const PAGE_ROWS: usize = 1024;
pub const SUBSCRIBE_LOGS: usize = 32;
pub const HEAD_LOGS: usize = 256;
pub const PAGE_OVERHEAD: usize = 512;

pub(crate) fn decode_bytes<'de, D: Deserializer<'de>, const MAX: usize>(d: D) -> Result<Vec<u8>, D::Error> {
    struct Encoded<const MAX: usize>;
    impl<'de, const MAX: usize> Visitor<'de> for Encoded<MAX> {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("bounded base64url bytes") }
        fn visit_str<E: Error>(self, text: &str) -> Result<Self::Value, E> {
            if text.len() > (MAX * 4).div_ceil(3) { return Err(E::custom("byte limit")); }
            let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| E::custom("invalid base64url"))?;
            if bytes.len() > MAX { return Err(E::custom("byte limit")); }
            Ok(bytes)
        }
    }
    d.deserialize_str(Encoded::<MAX>)
}

pub(crate) mod fixed32 {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        decode_bytes::<D, 32>(d)?.try_into().map_err(|_| Error::custom("expected 32 bytes"))
    }
}

#[derive(Serialize, Deserialize)]
struct Capability(#[serde(with = "fixed32")] [u8; 32]);

struct Entry(Bytes);
impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(Bytes(decode_bytes::<D, MAX_ENTRY>(d)?)))
    }
}

fn bounded<'de, D: Deserializer<'de>, T: Deserialize<'de>, const MAX: usize>(d: D) -> Result<Vec<T>, D::Error> {
    struct List<T, const MAX: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for List<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("bounded list") }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut items = Vec::new();
            while items.len() < MAX {
                let Some(item) = seq.next_element()? else { return Ok(items) };
                items.push(item);
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(Error::custom("row limit"));
            }
            Ok(items)
        }
    }
    d.deserialize_seq(List::<T, MAX>(PhantomData))
}

fn append_entries<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Bytes>, D::Error> {
    let entries: Vec<Bytes> = bounded::<D, Entry, APPEND_ROWS>(d)?.into_iter().map(|e| e.0).collect();
    if !valid_append(&entries) { return Err(Error::custom("append limit")); }
    Ok(entries)
}

fn page_entries<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Bytes>, D::Error> {
    let entries: Vec<Bytes> = bounded::<D, Entry, PAGE_ROWS>(d)?.into_iter().map(|e| e.0).collect();
    if !valid_page(&entries) { return Err(Error::custom("page limit")); }
    Ok(entries)
}

mod capabilities {
    use super::*;
    pub fn serialize<S: Serializer>(caps: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(caps.len()))?;
        for cap in caps { seq.serialize_element(&Capability(*cap))?; }
        seq.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        let caps: Vec<_> = bounded::<D, Capability, SUBSCRIBE_LOGS>(d)?.into_iter().map(|c| c.0).collect();
        if caps.is_empty() || caps.iter().enumerate().any(|(i, c)| caps[..i].contains(c)) {
            return Err(Error::custom("subscription shape"));
        }
        Ok(caps)
    }
}

fn known_logs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Known>, D::Error> {
    bounded::<D, Known, HEAD_LOGS>(d)
}

fn moved_heads<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Head>, D::Error> {
    bounded::<D, Head, HEAD_LOGS>(d)
}

pub fn encoded_entry_bytes(entry: &Bytes) -> usize { (entry.0.len() * 4).div_ceil(3) + 3 }

pub fn valid_append(entries: &[Bytes]) -> bool {
    !entries.is_empty() && entries.len() <= APPEND_ROWS
        && entries.iter().all(|e| !e.0.is_empty() && e.0.len() <= MAX_ENTRY)
        && entries.iter().map(|e| e.0.len()).sum::<usize>() <= APPEND_BYTES
}

pub fn encoded_page_bytes(entries: &[Bytes]) -> usize { PAGE_OVERHEAD + entries.iter().map(encoded_entry_bytes).sum::<usize>() }

pub fn valid_page(entries: &[Bytes]) -> bool {
    entries.len() <= PAGE_ROWS && entries.iter().all(|e| !e.0.is_empty() && e.0.len() <= MAX_ENTRY)
        && encoded_page_bytes(entries) <= MAX_BODY
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    Append {
        #[serde(with = "fixed32")]
        capability: [u8; 32],
        #[serde(deserialize_with = "append_entries")]
        entries: Vec<Bytes>,
        public: bool,
    },
    Read { #[serde(with = "fixed32")] capability: [u8; 32], after: u64 },
    Head { #[serde(with = "fixed32")] capability: [u8; 32] },
    Subscribe { #[serde(with = "capabilities")] capabilities: Vec<[u8; 32]> },
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("membership request (redacted)") }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Appended {
    pub position: u64,
    pub head: Head,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub after: u64,
    #[serde(deserialize_with = "page_entries")]
    pub entries: Vec<Bytes>,
    pub head: Head,
}

impl fmt::Debug for Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Page").field("after", &self.after).field("rows", &self.entries.len()).field("head", &self.head).finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Latest { pub head: Head }

/// The bodies of the HTTPS routes; each route takes one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Append {
    #[serde(with = "fixed32")]
    pub capability: [u8; 32],
    #[serde(deserialize_with = "append_entries")]
    pub entries: Vec<Bytes>,
    pub public: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Read {
    #[serde(with = "fixed32")]
    pub capability: [u8; 32],
    pub after: u64,
}

/// A log, and the length its requester holds.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Known(#[serde(with = "fixed32")] pub [u8; 32], pub u64);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heads {
    #[serde(deserialize_with = "known_logs")]
    pub logs: Vec<Known>,
}

/// The heads of the logs a `Heads` request named whose length differs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Moved {
    #[serde(deserialize_with = "moved_heads")]
    pub heads: Vec<Head>,
}

/// What the HTTPS routes answer: the value, or a refusal the service signs over `refusal_message`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer<T> {
    Ok(T),
    Refused {
        refusal: Refusal,
        #[serde(deserialize_with = "head::signature")]
        sig: Bytes,
    },
}

pub fn refusal_message(refusal: Refusal, request: &[u8]) -> Vec<u8> {
    [b"letmeknow refusal v1\0".as_slice(), refusal.code().as_bytes(), &Sha256::digest(request)].concat()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Subscribed {}

// Externally tagged: an untagged answer buffers arbitrary arrays before their bounded visitors run.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply<T> {
    Ok(T),
    Refused(Refusal),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal { Policy, Size, Rate, Busy, Quota, Expired }

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::Policy => "policy", Self::Size => "size", Self::Rate => "rate",
            Self::Busy => "busy", Self::Quota => "quota", Self::Expired => "expired",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        [Self::Policy, Self::Size, Self::Rate, Self::Busy, Self::Quota, Self::Expired].into_iter().find(|r| r.code() == code)
    }
}

pub async fn read_frame<T: serde::de::DeserializeOwned, R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<T> {
    let len = read_len(r).await?;
    read_body(r, len).await
}

/// The caller reserves memory for the body before `read_body` allocates it.
pub async fn read_len<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<usize> {
    let len = r.read_u32().await? as usize;
    anyhow::ensure!(len <= MAX_BODY, "membership frame limit");
    Ok(len)
}

pub async fn read_body<T: serde::de::DeserializeOwned, R: AsyncRead + Unpin>(r: &mut R, len: usize) -> anyhow::Result<T> {
    let mut body = vec![0; len];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|_| anyhow::anyhow!("invalid membership frame"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_are_bounded_while_decoding() {
        let entries = |n| format!("[{}]", vec!["\"\""; n].join(","));
        let text = format!(r#"{{"append":{{"capability":"{}","entries":{},"public":false}}}}"#, URL_SAFE_NO_PAD.encode([7; 32]), entries(100_000));
        let error = serde_json::from_str::<Request>(&text).unwrap_err();
        assert!(error.column() < 512, "must stop before decoding the oversized list");
        let caps = vec![URL_SAFE_NO_PAD.encode([7; 32]); 100_000];
        let text = format!(r#"{{"subscribe":{{"capabilities":{}}}}}"#, serde_json::to_string(&caps).unwrap());
        assert!(serde_json::from_str::<Request>(&text).unwrap_err().column() < 2048);
        let text = format!(r#"{{"ok":{{"after":0,"entries":{}}}}}"#, entries(100_000));
        assert!(serde_json::from_str::<Reply<Page>>(&text).unwrap_err().column() < 4096,
            "reply decoding must not buffer the unbounded list before invoking its visitor");
    }

    #[tokio::test]
    async fn frame_errors_do_not_echo_requests_or_refusals() {
        let bytes = crate::frame::encode(&serde_json::json!({"private arbitrary request body": ["credential"]}));
        let error = read_frame::<Request, _>(&mut bytes.as_slice()).await.unwrap_err();
        assert_eq!(format!("{error:#}"), "invalid membership frame");
        let bytes = crate::frame::encode(&serde_json::json!({"refused": "private arbitrary refusal"}));
        let error = read_frame::<Reply<()>, _>(&mut bytes.as_slice()).await.unwrap_err();
        assert_eq!(format!("{error:#}"), "invalid membership frame");
    }

    #[test]
    fn heads_are_bounded_and_refusals_carry_a_64_byte_signature() {
        let log = format!(r#"["{}",1]"#, URL_SAFE_NO_PAD.encode([7; 32]));
        let logs = |n: usize| format!(r#"{{"logs":[{}]}}"#, vec![log.as_str(); n].join(","));
        assert!(serde_json::from_str::<Heads>(&logs(HEAD_LOGS)).is_ok());
        assert!(serde_json::from_str::<Heads>(&logs(HEAD_LOGS + 1)).is_err());
        let sig = URL_SAFE_NO_PAD.encode([9; 64]);
        let refused = format!(r#"{{"refused":{{"refusal":"rate","sig":"{sig}"}}}}"#);
        assert!(matches!(serde_json::from_str::<Answer<()>>(&refused).unwrap(), Answer::Refused { refusal: Refusal::Rate, .. }));
        let short = URL_SAFE_NO_PAD.encode([9; 63]);
        assert!(serde_json::from_str::<Answer<()>>(&refused.replace(&sig, &short)).is_err());
        assert_eq!(Refusal::from_code("quota").map(Refusal::code), Some("quota"));
        assert!(Refusal::from_code("nope").is_none());
        assert!(refusal_message(Refusal::Rate, b"a").starts_with(b"letmeknow refusal v1\0rate"));
        assert_ne!(refusal_message(Refusal::Rate, b"a"), refusal_message(Refusal::Busy, b"a"));
        assert_ne!(refusal_message(Refusal::Rate, b"a"), refusal_message(Refusal::Rate, b"b"));
    }

    #[test]
    fn maximum_envelope_and_redaction() {
        let request = Request::Append { capability: [7; 32], entries: vec![Bytes(vec![9; MAX_ENTRY])], public: false };
        let body = serde_json::to_vec(&request).unwrap();
        assert!(body.len() < MAX_BODY);
        assert_eq!(serde_json::from_slice::<Request>(&body).unwrap(), request);
        assert_eq!(format!("{request:?}"), "membership request (redacted)");
        assert!(!valid_append(&vec![Bytes(vec![1]); APPEND_ROWS + 1]));
        assert!(!valid_append(&[Bytes(vec![1; MAX_ENTRY + 1])]));
        assert!(!valid_append(&vec![Bytes(vec![1; MAX_ENTRY]); 3]));
        assert!(serde_json::from_str::<Request>(r#"{"head":{"log":"AQ"}}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"head":{"capability":"AQ"}}"#).is_err());
    }
}
