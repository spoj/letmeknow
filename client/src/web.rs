//! The browser client's member, compiled to WebAssembly. Everything that touches a key happens here, with the same
//! OpenMLS and protocol code as the session process; JavaScript does the networking, storage and interface.
//! Results that are not bytes are JSON strings.
use crate::entity::{self, Identity, List, place};
use crate::proto::{CIPHERSUITE, PAKE_ID, create_config, fingerprint, invite_key, join_config, membership_changes, person};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand};
use serde::Deserialize;
use serde_json::{Value, json};
use spake2::{Ed25519Group, Password, Spake2};
use std::collections::HashMap;
use std::sync::RwLock;
use wasm_bindgen::prelude::*;

type R<T> = Result<T, JsError>;

fn err(error: anyhow::Error) -> JsError {
    JsError::new(&format!("{error:#}"))
}

#[derive(Default)]
struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }

    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }

    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

#[derive(Deserialize)]
struct Saved {
    name: String,
    signer: SignatureKeyPair,
    groups: Vec<String>,
    /// The MLS storage's keys and values, hex.
    storage: Vec<(String, String)>,
}

/// A browser's member. It has one key: it is a session and its own device, so an entity lists it directly.
#[wasm_bindgen]
pub struct Member {
    provider: Provider,
    signer: SignatureKeyPair,
    name: String,
    groups: HashMap<String, MlsGroup>,
}

#[wasm_bindgen]
impl Member {
    #[wasm_bindgen(constructor)]
    pub fn new(name: &str) -> R<Member> {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519)?;
        Ok(Self { provider: Provider::default(), signer, name: name.to_owned(), groups: HashMap::new() })
    }

    pub fn load(saved: &str) -> R<Member> {
        let saved: Saved = serde_json::from_str(saved)?;
        let values = saved.storage.into_iter().map(|(k, v)| Ok((hex::decode(k)?, hex::decode(v)?))).collect::<Result<_, hex::FromHexError>>()?;
        let provider = Provider { crypto: RustCrypto::default(), storage: MemoryStorage { values: RwLock::new(values) } };
        let mut groups = HashMap::new();
        for gid in saved.groups {
            let mls = MlsGroup::load(provider.storage(), &GroupId::from_slice(gid.as_bytes()))?.ok_or_else(|| JsError::new("missing MLS state"))?;
            groups.insert(gid, mls);
        }
        Ok(Self { provider, signer: saved.signer, name: saved.name, groups })
    }

    /// The member's whole state as JSON, for IndexedDB.
    pub fn save(&self) -> R<String> {
        let values = self.provider.storage.values.read().map_err(|_| JsError::new("storage lock poisoned"))?;
        let storage: Vec<(String, String)> = values.iter().map(|(k, v)| (hex::encode(k), hex::encode(v))).collect();
        let groups: Vec<&String> = self.groups.keys().collect();
        Ok(json!({ "name": self.name, "signer": self.signer, "groups": groups, "storage": storage }).to_string())
    }

    pub fn fp(&self) -> String {
        fingerprint(self.signer.public())
    }

    /// This member as an entity list holds it: {"id", "key", "name"}.
    pub fn entry(&self) -> String {
        json!({ "id": self.fp(), "key": hex::encode(self.signer.public()), "name": self.name }).to_string()
    }

    /// Starts an entity named `name` with this member on its list: {"id", "address", "entry"}, the entry sealed for the relay.
    pub fn entity_create(&self, name: &str) -> R<String> {
        let member: entity::Member = serde_json::from_str(&self.entry())?;
        let nonce: [u8; 16] = self.provider.rand().random_array()?;
        let (id, entry) = entity::create(&self.signer, member, name, &nonce).map_err(err)?;
        let (address, key) = place("list", id.as_bytes());
        Ok(json!({ "id": id, "address": address, "entry": seal_with(&self.provider, &key, "list", &entry)? }).to_string())
    }

    /// Signs an entry adding `member` ({"id", "key", "name"}) to the list replayed from `entries`, sealed for the relay.
    pub fn entity_add(&self, id: &str, entries: &str, member: &str) -> R<String> {
        let entry = replay(id, entries)?.add(&self.signer, &self.fp(), serde_json::from_str(member)?).map_err(err)?;
        seal_with(&self.provider, &place("list", id.as_bytes()).1, "list", &entry)
    }

    pub fn entity_remove(&self, id: &str, entries: &str, member: &str) -> R<String> {
        let entry = replay(id, entries)?.remove(&self.signer, &self.fp(), member).map_err(err)?;
        seal_with(&self.provider, &place("list", id.as_bytes()).1, "list", &entry)
    }

    /// Creates a group in which this member speaks as the entities in `path` (a JSON array, innermost first).
    pub fn create_group(&mut self, path: &str) -> R<String> {
        let gid = hex::encode(self.provider.rand().random_array::<16>()?);
        let mls = MlsGroup::new_with_group_id(&self.provider, &self.signer, &create_config(), GroupId::from_slice(gid.as_bytes()), self.credential(path)?)?;
        self.groups.insert(gid.clone(), mls);
        Ok(gid)
    }

    pub fn key_package(&self, path: &str) -> R<Vec<u8>> {
        let bundle = KeyPackage::builder().build(CIPHERSUITE, &self.provider, &self.signer, self.credential(path)?)?;
        Ok(MlsMessageOut::from(bundle.key_package().clone()).to_bytes()?)
    }

    /// Joins the group `gid` from a welcome message.
    pub fn join(&mut self, gid: &str, welcome: &[u8]) -> R<()> {
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact_bytes(welcome)?.extract() else {
            return Err(JsError::new("not a welcome message"));
        };
        let mls = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)?.into_group(&self.provider)?;
        if mls.group_id().as_slice() != gid.as_bytes() {
            return Err(JsError::new("welcome is for a different group"));
        }
        self.groups.insert(gid.to_owned(), mls);
        Ok(())
    }

    pub fn leave(&mut self, gid: &str) -> R<()> {
        if let Some(mut mls) = self.groups.remove(gid) {
            mls.delete(self.provider.storage())?;
        }
        Ok(())
    }

    /// The members of a group as their credentials describe them; `as` is not yet checked against the entities' lists.
    pub fn members(&self, gid: &str) -> R<String> {
        let mls = self.group(gid)?;
        let members: Vec<Value> = mls
            .members()
            .map(|m| {
                let mut entry = person(&m.credential, &m.signature_key);
                entry["you"] = json!(m.index == mls.own_leaf_index());
                entry
            })
            .collect();
        Ok(Value::Array(members).to_string())
    }

    pub fn epoch(&self, gid: &str) -> R<u64> {
        Ok(self.group(gid)?.epoch().as_u64())
    }

    pub fn encrypt(&mut self, gid: &str, payload: &[u8]) -> R<Vec<u8>> {
        let mls = self.groups.get_mut(gid).ok_or_else(|| JsError::new("unknown group"))?;
        Ok(mls.create_message(&self.provider, &self.signer, payload)?.to_bytes()?)
    }

    /// Commits adding the member with this key package: {"commit", "welcome"} (base64). Settle once the relay answers.
    pub fn add(&mut self, gid: &str, key_package: &[u8]) -> R<String> {
        let MlsMessageBodyIn::KeyPackage(key_package) = MlsMessageIn::tls_deserialize_exact_bytes(key_package)?.extract() else {
            return Err(JsError::new("not a key package"));
        };
        let key_package = key_package.validate(self.provider.crypto(), ProtocolVersion::Mls10)?;
        let mls = self.groups.get_mut(gid).ok_or_else(|| JsError::new("unknown group"))?;
        let (commit, welcome, _) = mls.add_members(&self.provider, &self.signer, &[key_package])?;
        Ok(json!({ "commit": b64(&commit.to_bytes()?), "welcome": b64(&welcome.to_bytes()?) }).to_string())
    }

    /// Commits removing the member with fingerprint `fp`. Settle once the relay answers.
    pub fn remove(&mut self, gid: &str, fp: &str) -> R<Vec<u8>> {
        let mls = self.groups.get_mut(gid).ok_or_else(|| JsError::new("unknown group"))?;
        let target = mls
            .members()
            .find(|m| fingerprint(&m.signature_key) == fp && m.index != mls.own_leaf_index())
            .ok_or_else(|| JsError::new("no such member"))?;
        Ok(mls.remove_members(&self.provider, &self.signer, &[target.index])?.0.to_bytes()?)
    }

    /// A proposal to remove this member, which another member commits: MLS lets no member commit its own removal.
    pub fn leave_proposal(&mut self, gid: &str) -> R<Vec<u8>> {
        let mls = self.groups.get_mut(gid).ok_or_else(|| JsError::new("unknown group"))?;
        Ok(mls.leave_group(&self.provider, &self.signer)?.to_bytes()?)
    }

    /// The member a key package describes, to check a join request before adding it.
    pub fn applicant(&self, key_package: &[u8]) -> R<String> {
        let MlsMessageBodyIn::KeyPackage(key_package) = MlsMessageIn::tls_deserialize_exact_bytes(key_package)?.extract() else {
            return Err(JsError::new("not a key package"));
        };
        let key_package = key_package.validate(self.provider.crypto(), ProtocolVersion::Mls10)?;
        let leaf = key_package.leaf_node();
        Ok(person(leaf.credential(), leaf.signature_key().as_slice()).to_string())
    }

    /// An empty commit that replaces this member's keys. Settle once the relay answers.
    pub fn update_key(&mut self, gid: &str) -> R<Vec<u8>> {
        let provider = &self.provider;
        let mls = self.groups.get_mut(gid).ok_or_else(|| JsError::new("unknown group"))?;
        let commit = mls
            .commit_builder()
            .consume_proposal_store(false)
            .force_self_update(true)
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), &self.signer, |_| true)?
            .stage_commit(provider)?
            .into_commit();
        Ok(commit.to_bytes()?)
    }

    /// Commits the removals other members asked for. Settle once the relay answers.
    pub fn commit_proposals(&mut self, gid: &str) -> R<Vec<u8>> {
        let mls = self.groups.get_mut(gid).ok_or_else(|| JsError::new("unknown group"))?;
        Ok(mls.commit_to_pending_proposals(&self.provider, &self.signer)?.0.to_bytes()?)
    }

    /// Whether a commit this member built waits for the relay's answer.
    pub fn pending(&self, gid: &str) -> R<bool> {
        Ok(self.group(gid)?.pending_commit().is_some())
    }

    /// After the relay took (`accepted`) or refused what was just built: merges a pending commit and returns its
    /// "joined"/"left" lines, or drops it.
    pub fn settle(&mut self, gid: &str, accepted: bool) -> R<String> {
        let me = json!({ "name": self.name, "fp": self.fp() });
        let mls = self.groups.get_mut(gid).ok_or_else(|| JsError::new("unknown group"))?;
        if !accepted {
            mls.clear_pending_commit(self.provider.storage())?;
            return Ok("[]".into());
        }
        let Some(staged) = mls.pending_commit() else { return Ok("[]".into()) };
        let changes = membership_changes(mls, staged, &me);
        mls.merge_pending_commit(&self.provider)?;
        Ok(Value::Array(changes).to_string())
    }

    /// Decrypts a message from the relay: {"sender", "payload"}, {"proposal": true} (commit it), or
    /// {"sender", "changes", "removed"} for a commit.
    pub fn process(&mut self, gid: &str, data: &[u8]) -> R<String> {
        let message = MlsMessageIn::tls_deserialize_exact_bytes(data)?.try_into_protocol_message()?;
        let mls = self.groups.get_mut(gid).ok_or_else(|| JsError::new("unknown group"))?;
        let processed = mls.process_message(&self.provider, message)?;
        let sender = match processed.sender() {
            Sender::Member(leaf) => mls.member_at(*leaf).map(|m| person(&m.credential, &m.signature_key)),
            _ => None,
        }
        .ok_or_else(|| JsError::new("message from a non-member"))?;
        let result = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                json!({ "sender": sender, "payload": serde_json::from_slice::<Value>(&message.into_bytes())? })
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                if !matches!(proposal.proposal(), Proposal::Remove(_)) {
                    return Err(JsError::new("unsupported proposal"));
                }
                mls.store_pending_proposal(self.provider.storage(), *proposal)?;
                json!({ "proposal": true })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let changes = membership_changes(mls, &staged, &sender);
                let removed = staged.self_removed();
                mls.merge_staged_commit(&self.provider, *staged)?;
                if removed {
                    self.leave(gid)?;
                }
                json!({ "sender": sender, "changes": changes, "removed": removed })
            }
            _ => return Err(JsError::new("unsupported message")),
        };
        Ok(result.to_string())
    }

    fn group(&self, gid: &str) -> R<&MlsGroup> {
        self.groups.get(gid).ok_or_else(|| JsError::new("unknown group"))
    }

    fn credential(&self, path: &str) -> R<CredentialWithKey> {
        let identity = Identity { name: self.name.clone(), device: None, path: serde_json::from_str(path)? };
        Ok(CredentialWithKey { credential: BasicCredential::new(identity.to_bytes()).into(), signature_key: self.signer.public().into() })
    }
}

/// One side of an invite's password-authenticated key exchange: both sides start it from the code's two words.
#[wasm_bindgen]
pub struct Pake {
    spake: Option<Spake2<Ed25519Group>>,
    message: Vec<u8>,
}

#[wasm_bindgen]
impl Pake {
    #[wasm_bindgen(constructor)]
    pub fn new(words: &str) -> Pake {
        let (spake, message) = Spake2::<Ed25519Group>::start_symmetric(&Password::new(words.to_lowercase()), &spake2::Identity::new(PAKE_ID));
        Pake { spake: Some(spake), message }
    }

    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    /// The key both sides share, from the other side's message and the invite's slot.
    pub fn finish(&mut self, theirs: &[u8], slot: &str) -> R<Vec<u8>> {
        let spake = self.spake.take().ok_or_else(|| JsError::new("already finished"))?;
        let secret = spake.finish(theirs).map_err(|e| JsError::new(&format!("{e:?}")))?;
        Ok(invite_key(&secret, slot).to_vec())
    }
}

#[wasm_bindgen]
pub fn invite_words() -> R<String> {
    crate::proto::invite_words(&RustCrypto::default()).map_err(err)
}

#[wasm_bindgen]
pub fn random(bytes: usize) -> R<Vec<u8>> {
    Ok(RustCrypto::default().random_vec(bytes)?)
}

#[wasm_bindgen]
pub fn seal(key: &[u8], label: &str, data: &[u8]) -> R<String> {
    seal_with(&Provider::default(), &key32(key)?, label, data)
}

#[wasm_bindgen]
pub fn open(key: &[u8], label: &str, data: &str) -> R<Vec<u8>> {
    crate::proto::open(&key32(key)?, label.as_bytes(), data).map_err(err)
}

/// A blob (an image a file links) sealed under its own fresh `key`; it is stored by the SHA-256 of the result.
#[wasm_bindgen]
pub fn blob_seal(key: &[u8], data: &[u8]) -> R<Vec<u8>> {
    crate::proto::seal_blob(&RustCrypto::default(), &key32(key)?, data).map_err(err)
}

#[wasm_bindgen]
pub fn blob_open(key: &[u8], sealed: &[u8]) -> R<Vec<u8>> {
    crate::proto::open_blob(&key32(key)?, sealed).map_err(err)
}

/// Where something derived from `secret` lives on the relay: {"address", "key"} (hex).
#[wasm_bindgen]
pub fn locate(label: &str, secret: &[u8]) -> String {
    let (address, key) = place(label, secret);
    json!({ "address": address, "key": hex::encode(key) }).to_string()
}

/// An entity's list replayed from its sealed entries (a JSON array): {"id", "name", "members"}.
#[wasm_bindgen]
pub fn entity_list(id: &str, entries: &str) -> R<String> {
    let list = replay(id, entries)?;
    Ok(json!({ "id": list.id, "name": list.name, "members": list.members }).to_string())
}

fn replay(id: &str, entries: &str) -> R<List> {
    let key = place("list", id.as_bytes()).1;
    let sealed: Vec<String> = serde_json::from_str(entries)?;
    let entries: Vec<Vec<u8>> = sealed.iter().filter_map(|e| crate::proto::open(&key, b"list", e).ok()).collect();
    List::replay(id, &entries).map_err(err)
}

fn seal_with(provider: &Provider, key: &[u8; 32], label: &str, data: &[u8]) -> R<String> {
    crate::proto::seal(provider.rand(), key, label.as_bytes(), data).map_err(err)
}

fn key32(key: &[u8]) -> R<[u8; 32]> {
    key.try_into().map_err(|_| JsError::new("keys are 32 bytes"))
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
