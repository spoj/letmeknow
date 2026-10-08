//! Entities. An entity is an id and a list; being on the list lets an entity act as part of it.
//! Sessions and devices have keys and are entities with nothing on their lists. Keyless entities
//! ("Matthew", a team) keep their list on the relay, where each entry is signed by a keyed member.
use crate::proto::{digest, fingerprint};
use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What a session's MLS credential says about it. Before 0.7 a credential held only the name, as plain text.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    /// The device that holds this session, and its signature over the session's key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<Note>,
    /// Entities this session speaks as, innermost first. The first lists the device, or the session itself when it has
    /// no device (a browser); each later one lists the one before.
    #[serde(default, rename = "as", skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Note {
    pub key: String,
    pub sig: String,
}

impl Identity {
    pub fn parse(bytes: &[u8]) -> Self {
        serde_json::from_slice(bytes).unwrap_or_else(|_| Self { name: String::from_utf8_lossy(bytes).into_owned(), ..Self::default() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializable")
    }

    /// The id of the device holding the session whose key is `session_key`, if the device's signature checks out.
    pub fn device(&self, session_key: &[u8]) -> Option<String> {
        let note = self.device.as_ref()?;
        let key = hex::decode(&note.key).ok()?;
        verify(&key, &note_payload(session_key), &note.sig).ok()?;
        Some(fingerprint(&key))
    }

    /// The entity that the first entry of `path` must list: the device, or the session itself.
    pub fn holder(&self, session_key: &[u8]) -> String {
        self.device(session_key).unwrap_or_else(|| fingerprint(session_key))
    }
}

/// A device's signature saying that the session with `session_key` is one of its own.
pub fn note(device: &impl Signer, device_key: &[u8], session_key: &[u8]) -> Result<Note> {
    let sig = device.sign(&note_payload(session_key)).map_err(|e| anyhow::anyhow!("signing: {e:?}"))?;
    Ok(Note { key: hex::encode(device_key), sig: hex::encode(sig) })
}

fn note_payload(session_key: &[u8]) -> Vec<u8> {
    [b"letmeknow session ".as_slice(), session_key].concat()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    /// Set for members with a key of their own; only they sign entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub name: String,
}

/// One entry of a list as stored on the relay: `body` is exactly the JSON its signer signed.
#[derive(Serialize, Deserialize)]
struct Signed {
    body: String,
    sig: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Body {
    /// The first entry, signed by the first member. The entity's id is the hash of this entry.
    Create { name: String, nonce: String, member: Member },
    /// `prev` is the hash of the entry before, so an old entry cannot be posted again later.
    Add { prev: String, by: String, member: Member },
    Remove { prev: String, by: String, id: String },
}

/// An entity's list, replayed from its entries in relay order. Entries that do not follow the last valid one, or
/// whose signer is not a keyed member at that point, are ignored: this is what makes a removal final.
#[derive(Clone)]
pub struct List {
    pub id: String,
    pub name: String,
    pub members: Vec<Member>,
    last: String,
}

/// Starts an entity named `name` with `member`, which signs the first entry. Returns the entity's id and that entry.
pub fn create(signer: &impl Signer, member: Member, name: &str, nonce: &[u8]) -> Result<(String, Vec<u8>)> {
    let entry = sign(signer, &Body::Create { name: name.into(), nonce: hex::encode(nonce), member })?;
    Ok((entity_id(&entry), entry))
}

fn entity_id(entry: &[u8]) -> String {
    digest(entry)[..16].to_owned()
}

impl List {
    pub fn replay(id: &str, entries: &[Vec<u8>]) -> Result<Self> {
        let first = entries.first().context("entity not found")?;
        if entity_id(first) != id {
            bail!("entity {id} not found");
        }
        let Body::Create { name, member, .. } = check(first, |_| member_key(first))? else { bail!("entity {id} not found") };
        let mut list = Self { id: id.to_owned(), name, members: vec![member], last: digest(first) };
        for entry in &entries[1..] {
            let Ok(body) = check(entry, |by| list.key_of(by)) else { continue };
            match body {
                Body::Add { prev, member, .. } if prev == list.last => {
                    list.members.retain(|m| m.id != member.id);
                    list.members.push(member);
                }
                Body::Remove { prev, id, .. } if prev == list.last => list.members.retain(|m| m.id != id),
                _ => continue,
            }
            list.last = digest(entry);
        }
        Ok(list)
    }

    pub fn get(&self, id: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.id == id)
    }

    pub fn add(&self, signer: &impl Signer, by: &str, member: Member) -> Result<Vec<u8>> {
        if let Some(key) = &member.key
            && fingerprint(&hex::decode(key)?) != member.id
        {
            bail!("the new member's id does not match its key");
        }
        sign(signer, &Body::Add { prev: self.last.clone(), by: by.into(), member })
    }

    pub fn remove(&self, signer: &impl Signer, by: &str, id: &str) -> Result<Vec<u8>> {
        sign(signer, &Body::Remove { prev: self.last.clone(), by: by.into(), id: id.into() })
    }

    fn key_of(&self, by: &str) -> Option<Vec<u8>> {
        hex::decode(self.get(by)?.key.as_ref()?).ok()
    }
}

/// The key of the member that a first entry names; it signs that entry itself.
fn member_key(entry: &[u8]) -> Option<Vec<u8>> {
    let signed: Signed = serde_json::from_slice(entry).ok()?;
    let Ok(Body::Create { member, .. }) = serde_json::from_str(&signed.body) else { return None };
    hex::decode(member.key?).ok()
}

fn sign(signer: &impl Signer, body: &Body) -> Result<Vec<u8>> {
    let body = serde_json::to_string(body)?;
    let sig = hex::encode(signer.sign(body.as_bytes()).map_err(|e| anyhow::anyhow!("signing: {e:?}"))?);
    Ok(serde_json::to_vec(&Signed { body, sig })?)
}

/// Parses an entry and checks its signature by the key `key_of` gives for its signer.
fn check(entry: &[u8], key_of: impl Fn(&str) -> Option<Vec<u8>>) -> Result<Body> {
    let signed: Signed = serde_json::from_slice(entry)?;
    let body: Body = serde_json::from_str(&signed.body)?;
    let by = match &body {
        Body::Create { member, .. } => &member.id,
        Body::Add { by, .. } | Body::Remove { by, .. } => by,
    };
    let key = key_of(by).context("signer is not a keyed member")?;
    if fingerprint(&key) != *by {
        bail!("signer key does not match its id");
    }
    verify(&key, signed.body.as_bytes(), &signed.sig)?;
    Ok(body)
}

fn verify(key: &[u8], payload: &[u8], sig: &str) -> Result<()> {
    let key = VerifyingKey::from_bytes(key.try_into().context("bad key")?)?;
    Ok(key.verify_strict(payload, &Signature::from_slice(&hex::decode(sig)?)?)?)
}

/// Where something that only holders of `secret` may read lives on the relay, and the key that seals it there.
pub fn place(label: &str, secret: &[u8]) -> (String, [u8; 32]) {
    let address = hex::encode(&Sha256::digest([format!("letmeknow {label} ").as_bytes(), secret].concat())[..16]);
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(format!("letmeknow {label} key").as_bytes(), &mut key)
        .expect("32 bytes is a valid HKDF output length");
    (address, key)
}

/// An entry in an entity's inbox: a group its sessions may join without an invite, or no longer may.
#[derive(Clone, Serialize, Deserialize)]
pub struct Opening {
    pub group: String,
    pub relay: String,
    #[serde(default)]
    pub name: String,
    /// Key that seals join requests to the group's members.
    pub requests: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub closed: bool,
}

/// What a session posts to join an open group: its key package, and a key to seal the welcome back to it.
#[derive(Serialize, Deserialize)]
pub struct JoinRequest {
    pub key_package: String,
    pub reply: String,
}
