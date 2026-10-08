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

/// A message as both transports carry it: MLS plaintext on the relay, the body of a folder file.
#[derive(Clone, Serialize, Deserialize)]
pub struct Payload {
    /// `None` in a session's log once delivered, unless `listen --keep-log`.
    pub content: Option<String>,
    pub after: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "one_or_many")]
    pub to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub urgent: bool,
    /// Base64 file content. Recipients get it as a private file; the session's log never holds it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<String>,
}

/// Reads `to` as a list, or as the single fingerprint that 0.4 wrote, so older folder files and stored messages still parse.
fn one_or_many<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum To {
        One(String),
        Many(Vec<String>),
    }
    Ok(match To::deserialize(deserializer)? {
        To::One(fp) => vec![fp],
        To::Many(fps) => fps,
    })
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
    let nonce: [u8; 12] = rand.random_array()?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let sealed = cipher
        .encrypt(&nonce.into(), Aad { msg: plaintext, aad: label })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok(B64.encode([nonce.as_slice(), &sealed].concat()))
}

pub fn open(key: &[u8; 32], label: &[u8], data: &str) -> Result<Vec<u8>> {
    let bytes = B64.decode(data)?;
    if bytes.len() < 12 {
        bail!("sealed data too short");
    }
    let (nonce, sealed) = bytes.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().expect("12 bytes");
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(&nonce.into(), Aad { msg: sealed, aad: label })
        .map_err(|_| anyhow::anyhow!("cannot decrypt: wrong invite code or tampered data"))
}

/// "joined"/"left" lines for a commit, computed before it is merged.
pub fn membership_changes(mls: &MlsGroup, staged: &StagedCommit, by: &Value) -> Vec<Value> {
    let gid = String::from_utf8_lossy(mls.group_id().as_slice());
    let added = staged.add_proposals().map(|p| {
        let leaf = p.add_proposal().key_package().leaf_node();
        json!({ "type": "joined", "group": gid, "member": person(leaf.credential(), leaf.signature_key().as_slice()), "by": by })
    });
    let removed = staged.remove_proposals().filter_map(|p| mls.member_at(p.remove_proposal().removed())).map(|m| {
        json!({ "type": "left", "group": gid, "member": person(&m.credential, &m.signature_key), "by": by })
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
