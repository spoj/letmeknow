//! What the session process and the browser share: MLS settings, the invite exchange and the message format.
use crate::entity::Identity;
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, Payload as Aad}};
use hkdf::Hkdf;
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::random::OpenMlsRand;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
pub const INVITE_TTL_S: u64 = 600;
pub const INVITE_SLOTS: usize = 999;
pub const PAKE_ID: &[u8] = b"letmeknow invite v2";
const MAX_PAST_EPOCHS: usize = 5;
const WORDS: &str = include_str!("words.txt");

/// The kinds of group: the one thing a group shares, fixed when it is made. A chat shares messages in order; a document
/// (`doc`) shares one text that its members edit at once.
pub const CHAT: &str = "chat";
pub const DOC: &str = "doc";
pub const KINDS: [&str; 2] = [CHAT, DOC];

/// A message as both transports carry it: MLS plaintext on the relay, the body of a folder file. `settings` belongs to
/// every kind of group, each other type to one kind.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Payload {
    Settings(Settings),
    /// A session joined a folder group, whose members are whoever wrote to it. A relay group's members are its MLS group's.
    Joined,
    Message(Message),
    Edit(Edit),
}

impl Payload {
    /// The kind of group this type belongs to; `None` for every kind.
    pub fn kind(&self) -> Option<&'static str> {
        match self {
            Payload::Settings(_) | Payload::Joined => None,
            Payload::Message(_) => Some(CHAT),
            Payload::Edit(_) => Some(DOC),
        }
    }

    /// The messages this one comes after (a chat message's read frontier), for ordering a folder's files.
    pub fn after(&self) -> &[String] {
        match self {
            Payload::Message(message) => &message.after,
            _ => &[],
        }
    }
}

/// A chat message.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Message {
    /// `None` in a session's log once delivered, unless `listen --keep-log`.
    pub content: Option<String>,
    /// The sender's read frontier: the latest messages it had seen.
    pub after: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub urgent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Attachment>,
}

/// A file sent with a message: a blob's link (`lmk:<hash>#<key>`; in a folder group, a path in the folder), its name,
/// size in bytes and media type, which may be empty.
#[derive(Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub link: String,
    pub name: String,
    pub size: u64,
    #[serde(default, rename = "type", skip_serializing_if = "String::is_empty")]
    pub media: String,
}

/// A change to a document: a Yjs update, v1, in base64. The snapshot a member posts after adding someone is the whole
/// state, as one.
#[derive(Clone, Serialize, Deserialize)]
pub struct Edit {
    pub update: String,
}

/// A group's settings, posted whole whenever one changes; the latest a member has seen wins, except that `kind` never
/// changes. A new member gets them with its welcome.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Entities whose sessions may join without an invite.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open: Vec<Opened>,
    /// Hex key that seals join requests to the members; set when the group is first opened.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub requests: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Opened {
    pub id: String,
    pub name: String,
}

pub fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .build()
}

pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .build()
}

/// Two words from the EFF short wordlist: the secret part of an invite code.
pub fn invite_words(rand: &RustCrypto) -> Result<String> {
    let words: Vec<&str> = WORDS.lines().collect();
    Ok(format!("{}-{}", words[random_below(rand, words.len())?], words[random_below(rand, words.len())?]))
}

pub fn random_below(rand: &RustCrypto, n: usize) -> Result<usize> {
    Ok(u32::from_le_bytes(rand.random_array()?) as usize % n)
}

pub fn invite_key(secret: &[u8], id: &str) -> [u8; 32] {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(format!("letmeknow invite v2 {id}").as_bytes(), &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

pub fn seal(rand: &RustCrypto, key: &[u8; 32], label: &[u8], plaintext: &[u8]) -> Result<String> {
    Ok(B64.encode(seal_bytes(rand, key, label, plaintext)?))
}

pub fn open(key: &[u8; 32], label: &[u8], data: &str) -> Result<Vec<u8>> {
    open_bytes(key, label, &B64.decode(data)?).map_err(|_| anyhow::anyhow!("cannot decrypt: wrong invite code or tampered data"))
}

fn seal_bytes(rand: &RustCrypto, key: &[u8; 32], label: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; 12] = rand.random_array()?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let sealed = cipher
        .encrypt(&nonce.into(), Aad { msg: plaintext, aad: label })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok([nonce.as_slice(), &sealed].concat())
}

fn open_bytes(key: &[u8; 32], label: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < 12 {
        bail!("sealed data too short");
    }
    let (nonce, sealed) = bytes.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().expect("12 bytes");
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher.decrypt(&nonce.into(), Aad { msg: sealed, aad: label }).map_err(|_| anyhow::anyhow!("cannot decrypt: wrong key or tampered data"))
}

/// The most a blob holds: the relay takes 10 MiB, sealed.
pub const MAX_BLOB_BYTES: usize = 10 * 1024 * 1024;

/// A blob is a file that a message or a document links as `lmk:<hash>#<key>`: sealed under a fresh key, which travels in
/// the link, and stored on the relay by the SHA-256 of the sealed bytes.
pub fn seal_blob(rand: &RustCrypto, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_bytes(rand, key, b"blob", plaintext)
}

pub fn blob_link(key: &[u8; 32], sealed: &[u8]) -> String {
    format!("lmk:{}#{}", digest(sealed), hex::encode(key))
}

pub fn open_blob(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    open_bytes(key, b"blob", sealed)
}

/// Every blob `text` links, as (hash, key), in order and once each.
pub fn blob_links(text: &str) -> Vec<(String, [u8; 32])> {
    let mut links: Vec<(String, [u8; 32])> = Vec::new();
    for (at, _) in text.match_indices("lmk:") {
        let link = text[at + 4..].get(..129).filter(|l| l.as_bytes()[64] == b'#');
        let Some((hash, key)) = link.map(|l| (&l[..64], &l[65..])) else { continue };
        let key = hex::decode(key).ok().and_then(|k| <[u8; 32]>::try_from(k).ok());
        if let Some(key) = key
            && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && !links.iter().any(|(h, _)| h == hash)
        {
            links.push((hash.to_owned(), key));
        }
    }
    links
}

/// The file extension of an image the browser shows inline, by its first bytes: PNG, JPEG, GIF or WebP.
pub fn image_type(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0x89, b'P', b'N', b'G', ..] => Some("png"),
        [0xff, 0xd8, 0xff, ..] => Some("jpg"),
        [b'G', b'I', b'F', b'8', ..] => Some("gif"),
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("webp"),
        _ => None,
    }
}

/// "joined"/"left" lines for a commit, computed before it is merged.
pub fn membership_changes(mls: &MlsGroup, staged: &StagedCommit, by: &Value) -> Vec<Value> {
    let gid = String::from_utf8_lossy(mls.group_id().as_slice());
    let added = staged.add_proposals().map(|p| {
        let leaf = p.add_proposal().key_package().leaf_node();
        json!({ "type": "joined", "group": gid, "member": person(leaf.credential(), leaf.signature_key().as_slice()), "by": by })
    });
    // A member that left proposed its own removal, which another member committed: it is `by`.
    let removed = staged.remove_proposals().filter_map(|p| {
        let leaf = p.remove_proposal().removed();
        let m = mls.member_at(leaf)?;
        let member = person(&m.credential, &m.signature_key);
        let left = matches!(p.sender(), Sender::Member(sender) if *sender == leaf);
        Some(json!({ "type": "left", "group": gid, "by": if left { &member } else { by }, "member": member }))
    });
    added.chain(removed).collect()
}

/// A member as its credential describes it. `as` lists the entities it claims to speak as, not yet checked against their lists.
pub fn person(credential: &Credential, signature_key: &[u8]) -> Value {
    let identity = BasicCredential::try_from(credential.clone()).map(|c| Identity::parse(c.identity())).unwrap_or_default();
    let mut person = json!({ "name": identity.name, "fp": fingerprint(signature_key) });
    if let Some(device) = identity.device(signature_key) {
        person["device"] = json!(device);
    }
    if !identity.path.is_empty() {
        person["as"] = json!(identity.path);
    }
    person
}

pub fn fingerprint(signature_key: &[u8]) -> String {
    hex::encode(&Sha256::digest(signature_key)[..8])
}

pub fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blob_opens_with_the_key_in_its_link() {
        let key = [7; 32];
        let sealed = seal_blob(&RustCrypto::default(), &key, b"pixels").unwrap();
        let link = blob_link(&key, &sealed);
        let text = format!("# Plan\n![chart]({link}) and again [here]({link}), not lmk:{} or lmk:short", "0".repeat(64));
        let links = blob_links(&text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].0, digest(&sealed));
        assert_eq!(open_blob(&links[0].1, &sealed).unwrap(), b"pixels");
        assert!(open_blob(&[0; 32], &sealed).is_err());
        assert_eq!(sealed.len(), 6 + 12 + 16);
    }
}
