//! Sessions and groups on OpenMLS: epoch-sealed commit entries judged strictly in order, each carrying the cut of the
//! epoch it ends; held messages as application messages whose plaintext is their header, claiming in the clear whose
//! they are; and live payloads sealed under a key exported from the epoch.

use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit, Payload}};
use lmk_proto::Bytes;
use lmk_proto::clock::{corrected, now};
use lmk_proto::entry::{Entry, signed, welcome_signed};
use lmk_proto::group::{Certificate, Credential, How, IDENTITY, LEAF_EXTENSION, Leaf, PROTOCOL, SETTINGS_EXTENSION, Service, Settings};
use lmk_proto::held::{self, Claim, Header, Ref};
use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;
use openmls_traits::storage::StorageProvider as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::provider::Provider;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;
/// The largest message ciphertext taken, and sent.
pub const MAX_MESSAGE: usize = 1 << 20;
/// More than an application message's ciphertext adds to its plaintext.
pub const FRAMING: usize = 1024;
/// How far one cut may move a membership's.
pub const MAX_CUT_STEP: u64 = 100_000;
const ADDRESS_LABEL: &str = "letmeknow epoch log address v1";
const SEALING_LABEL: &str = "letmeknow epoch log sealing v1";
const ENVELOPE_DOMAIN: &[u8] = b"letmeknow epoch envelope v1\0";
const MAX_INNER: usize = (1 << 20) - 45;
const LIVE_LABEL: &str = "letmeknow live";
/// What a live payload's key is bound to, and its author's signature covers, before the group and epoch.
const LIVE: &[u8] = b"letmeknow live v1\0";
const NEIGHBOURS_LABEL: &str = "letmeknow neighbours";

fn service_key(settings: &Settings) -> Result<[u8; 32]> {
    let Service::Serve { key, .. } = &settings.membership else { bail!("unsupported membership service authority") };
    let key = key.0.as_slice().try_into().context("membership service authority is not 32 bytes")?;
    let authority = ed25519_dalek::VerifyingKey::from_bytes(&key).context("invalid membership service authority")?;
    ensure!(!authority.is_weak(), "weak membership service authority");
    Ok(key)
}

fn capabilities() -> Capabilities {
    let ours = [ExtensionType::Unknown(SETTINGS_EXTENSION), ExtensionType::Unknown(LEAF_EXTENSION)];
    Capabilities::new(None, Some(&[CIPHERSUITE]), Some(&ours), None, None)
}

fn context_extensions(settings: &Settings) -> Result<Extensions<GroupContext>> {
    let required = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Unknown(SETTINGS_EXTENSION), ExtensionType::Unknown(LEAF_EXTENSION)],
        &[],
        &[],
    );
    Ok(Extensions::from_vec(vec![
        Extension::RequiredCapabilities(required),
        Extension::Unknown(SETTINGS_EXTENSION, UnknownExtension(serde_json::to_vec(settings)?)),
    ])?)
}

fn leaf_extensions(leaf: &Leaf) -> Result<Extensions<LeafNode>> {
    Ok(Extensions::single(Extension::Unknown(LEAF_EXTENSION, UnknownExtension(serde_json::to_vec(leaf)?)))?)
}

fn settings_of(extensions: &Extensions<GroupContext>) -> Result<Settings> {
    Ok(serde_json::from_slice(&extensions.unknown(SETTINGS_EXTENSION).context("no settings")?.0)?)
}

/// Application-message keys of the current and the prior epoch only; exporters are current-epoch only.
fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(1)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(1000, 100_000))
        .build()
}

/// Our credential inside an MLS credential, if it is one.
pub fn credential_of(credential: &openmls::prelude::Credential) -> Option<Credential> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    serde_json::from_slice(basic.identity()).ok()
}

/// Whose a held message's ciphertext claims to be, and the epoch it was sealed in, as its clear framing shows them:
/// `open` checks the claim.
pub fn claim(bytes: &[u8]) -> Result<(Claim, u64)> {
    let MlsMessageBodyIn::PrivateMessage(message) = parse::<MlsMessageIn>(bytes)?.extract() else { bail!("not a private message") };
    ensure!(message.content_type() == ContentType::Application, "not an application message");
    Ok((serde_json::from_slice(message.aad()).context("a held message's claim")?, message.epoch().as_u64()))
}

fn parse<T: tls_codec::DeserializeBytes>(bytes: &[u8]) -> Result<T> {
    Ok(T::tls_deserialize_exact_bytes(bytes)?)
}

/// One MLS member: its signature key, its credential, and its leaf data.
pub struct Session {
    signer: SignatureKeyPair,
    pub credential: Credential,
    pub leaf: Leaf,
}

#[derive(Serialize, Deserialize)]
struct SessionRecord {
    public: Bytes,
    credential: Credential,
    leaf: Leaf,
}

impl Session {
    /// A new session with a fresh MLS key, speaking as no identity; a provider holds one session.
    pub fn create<P: Provider>(provider: &P, name: &str, leaf: Leaf) -> Result<Self> {
        let signer = crate::device::signer(&crate::random());
        let session = Self::with_signer(provider, signer, name, leaf)?;
        session.save(provider)?;
        Ok(session)
    }

    /// A member with the given MLS key beside the provider's own session, which it does not replace: a device's key in
    /// one identity's group.
    pub fn with_signer<P: Provider>(provider: &P, signer: SignatureKeyPair, name: &str, leaf: Leaf) -> Result<Self> {
        signer.store(provider.storage())?;
        let credential = Credential { name: name.into(), key: signer.public().into(), certificate: None };
        Ok(Session { credential, signer, leaf })
    }

    pub fn load<P: Provider>(provider: &P) -> Result<Self> {
        let record: SessionRecord = serde_json::from_slice(&provider.get(b"session")?.context("no session here")?)?;
        let signer = SignatureKeyPair::read(provider.storage(), &record.public.0, SignatureScheme::ED25519)
            .context("the session's key is missing")?;
        Ok(Session { signer, credential: record.credential, leaf: record.leaf })
    }

    fn save<P: Provider>(&self, provider: &P) -> Result<()> {
        let record = SessionRecord {
            public: self.signer.public().into(),
            credential: self.credential.clone(),
            leaf: self.leaf.clone(),
        };
        provider.put(b"session", &serde_json::to_vec(&record)?)
    }

    /// The session's MLS signature key.
    pub fn key(&self) -> &[u8] {
        self.signer.public()
    }

    /// Its signature over `bytes`, which begin with what they are for, as `peer::SUMMARY` does.
    pub fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        self.signer.sign(bytes).expect("an Ed25519 key signs")
    }

    /// Changes the leaf that new KeyPackages carry; each group needs a commit with `Change::leaf` too.
    pub fn set_leaf<P: Provider>(&mut self, provider: &P, leaf: Leaf) -> Result<()> {
        self.leaf = leaf;
        self.save(provider)
    }

    fn with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(serde_json::to_vec(&self.credential).unwrap()).into(),
            signature_key: self.signer.public().into(),
        }
    }

    /// A KeyPackage, as it travels to a member that admits it. It never expires: that member judges freshness.
    pub fn key_package<P: Provider>(&self, provider: &P) -> Result<Vec<u8>> {
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .leaf_node_extensions(leaf_extensions(&self.leaf)?)
            .key_package_lifetime(Lifetime::init(0, u64::MAX))
            .build(CIPHERSUITE, provider, &self.signer, self.with_key())?;
        Ok(MlsMessageOut::from(bundle.key_package().clone()).to_bytes()?)
    }
}

/// Validates a KeyPackage as it arrives at a member that admits it, and returns its credential.
pub fn key_package_credential<P: Provider>(provider: &P, key_package: &[u8]) -> Result<Credential> {
    let key_package = key_package_in(provider, key_package)?;
    leaf_credential(key_package.leaf_node())
}

/// A leaf's credential, which must name the leaf's own signature key.
fn leaf_credential(leaf: &LeafNode) -> Result<Credential> {
    let credential = credential_of(leaf.credential()).context("not a letmeknow credential")?;
    ensure!(credential.key.0 == leaf.signature_key().as_slice(), "a credential that names another key");
    Ok(credential)
}

pub fn key_package_reference<P: Provider>(provider: &P, key_package: &[u8]) -> Result<[u8; 32]> {
    Ok(key_package_in(provider, key_package)?.hash_ref(provider.crypto())?.as_slice().try_into()?)
}

fn key_package_in<P: Provider>(provider: &P, bytes: &[u8]) -> Result<KeyPackage> {
    let MlsMessageBodyIn::KeyPackage(key_package) = parse::<MlsMessageIn>(bytes)?.extract() else {
        bail!("not a KeyPackage")
    };
    Ok(key_package.validate(provider.crypto(), ProtocolVersion::Mls10)?)
}

/// Everything one commit changes, all inline. The default is an empty key update.
#[derive(Clone, Debug, Default)]
pub struct Change {
    pub add: Vec<Vec<u8>>,
    /// How the added members came in, carried in the commit's authenticated data.
    pub how: Option<How>,
    /// SHA-256 of the secret of the invite the added member came in by, carried in the commit's authenticated data.
    pub invite: Option<Bytes>,
    /// Leaf indices.
    pub remove: Vec<u32>,
    pub settings: Option<Settings>,
    pub leaf: Option<Leaf>,
    /// A new name in the committer's credential.
    pub name: Option<String>,
    pub certificate: Option<Certificate>,
    /// The cut of the epoch the commit ends: for each member, by key, the seq up to which the committer holds every
    /// held message, sealed in this epoch, and the id there (see `Group::cut`).
    pub cut: Vec<Ref>,
}

/// A commit's authenticated data, inside its sealed entry: how the members it adds came in, the cut of the epoch it
/// ends, and when it was made, by the committer's corrected clock.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Aad {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    how: Option<How>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invite: Option<Bytes>,
    #[serde(default)]
    cut: Vec<Ref>,
    #[serde(default)]
    time: u64,
}

/// A message this session holds no key for: sealed in an epoch it never was in or whose keys it deleted, too far behind
/// the newest of its sender's it opened, or opened before.
#[derive(Debug)]
pub struct Unheld;

impl std::fmt::Display for Unheld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sealed under an epoch whose keys this session does not hold")
    }
}

impl std::error::Error for Unheld {}

/// A commit's sealed wire entry, and for an Add the Welcome that admits its joiner.
pub struct Commit {
    pub entry: Vec<u8>,
    pub admission: Option<Admission>,
}

/// An Add's Welcome, and the committer's signature over it and the commit entry (`welcome_signed`). Only the committer
/// keeps it, to answer the joiner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Admission {
    pub welcome: Vec<u8>,
    pub sig: Vec<u8>,
}

/// A member as its leaf shows it.
#[derive(Clone, Debug)]
pub struct Member {
    pub index: u32,
    pub key: Vec<u8>,
    pub credential: Option<Credential>,
    pub leaf: Option<Leaf>,
}

impl Member {
    fn of(group: &MlsGroup, index: LeafNodeIndex) -> Option<Self> {
        let member = group.member_at(index)?;
        let leaf = group.public_group().leaf(index)?;
        Some(Member {
            index: index.u32(),
            key: member.signature_key,
            credential: credential_of(&member.credential),
            leaf: leaf_of(leaf.extensions()),
        })
    }
}

fn leaf_of(extensions: &Extensions<LeafNode>) -> Option<Leaf> {
    serde_json::from_slice(&extensions.unknown(LEAF_EXTENSION)?.0).ok()
}

/// A log entry as judged in the current epoch, before anything of it is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The first valid commit for this epoch: apply it next.
    Commit {
        /// It removes this session.
        removes: bool,
        /// When its committer made it, by its corrected clock.
        time: u64,
    },
    /// A commit from this session's own leaf, signed with its key, that this session did not make: its state was copied.
    Copied,
    Skipped {
        reason: String,
        /// This session's own commit was invalid and was cleared.
        lost: bool,
    },
}

/// What a commit did.
#[derive(Clone, Debug)]
pub struct Applied {
    /// The committer's leaf index, in the epoch it committed in.
    pub by: u32,
    /// This session's own commit.
    pub own: bool,
    /// This session's pending commit lost the race and was cleared: redo its change.
    pub lost: bool,
    /// As their KeyPackages show them; `index` is their new leaf.
    pub added: Vec<Member>,
    pub how: Option<How>,
    pub removed: Vec<Member>,
    pub settings: bool,
    /// This session was removed.
    pub gone: bool,
    /// The cut of the epoch it ended, by the members of that epoch: the removed ones' last.
    pub cut: Vec<Ref>,
    /// For a commit this session made that adds a member: its Welcome.
    pub admission: Option<Admission>,
}

/// A member's held message, decrypted and verified.
#[derive(Clone, Debug)]
pub struct Opened {
    /// `held::id` of the plaintext.
    pub id: [u8; 32],
    /// The epoch it was sealed in.
    pub epoch: u64,
    pub sender: Credential,
    pub header: Header,
    pub plaintext: Vec<u8>,
}

/// Who added whom, as the log showed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Added {
    pub member: Credential,
    pub by: Credential,
    pub how: Option<How>,
    /// SHA-256 of the secret of the invite it came in by.
    pub invite: Option<Bytes>,
    /// The epoch the Add moves into.
    pub epoch: u64,
    pub key_package_ref: [u8; 32],
    /// When this session applied the Add, in milliseconds.
    pub at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Posted {
    inner: Bytes,
    wire: Bytes,
    // OpenMLS drops the original KeyPackage serialization when saving a pending commit.
    add_refs: Vec<[u8; 32]>,
    admission: Option<Admission>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct State {
    posted: Option<Posted>,
    /// Its authenticated data.
    aad: Aad,
    added: Vec<Added>,
    /// The cut state: per current member, by key, how far its held messages are kept, as the commits applied say.
    cut: Vec<Ref>,
    /// The cut of the commit that ended the previous epoch: its members, the removed ones at their final cuts.
    ended: Vec<Ref>,
}

pub struct Group {
    mls: MlsGroup,
    state: State,
}

/// openmls's default lifetime for a creator's leaf, an hour before now to 12 weeks after, by our clock, not the system's.
fn creator_lifetime() -> Lifetime {
    let now = now() / 1000;
    Lifetime::init(now - 3600, now + 12 * 7 * 86400)
}

impl Group {
    pub fn create<P: Provider>(provider: &P, session: &Session, settings: &Settings) -> Result<Self> {
        ensure!(settings.protocol == PROTOCOL, "settings name protocol {}", settings.protocol);
        service_key(settings)?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities())
            .with_group_context_extensions(context_extensions(settings)?)
            .with_leaf_node_extensions(leaf_extensions(&session.leaf)?)?
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(1)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(1000, 100_000))
            .lifetime(creator_lifetime())
            .build();
        let id = GroupId::from_slice(&crate::random::<16>());
        let mls = MlsGroup::new_with_group_id(provider, &session.signer, &config, id, session.with_key())?;
        let cut = vec![Ref { key: Bytes(session.key().to_vec()), joined: 0, seq: 0, id: Bytes::default(), epoch: 0 }];
        let group = Group { state: State { cut, ..State::default() }, mls };
        group.save(provider)?;
        Ok(group)
    }

    /// Joins by the Welcome that admitted this session to the commit entry it came with, whose signatures it checks against
    /// the Welcome's sender, its committer, and whose cut, which it cannot judge, is where it starts: the cut state of the
    /// members it names, and every other at seq 0 of the new epoch. OpenMLS consumes a package during `build_from_welcome`,
    /// before `into_group`, so an error here rolls back this call's writes, the package's consumption included.
    pub fn join<P: Provider>(provider: &P, entry: &[u8], welcome_bytes: &[u8], welcome_sig: &[u8], expected_package: &[u8; 32]) -> Result<Self> {
        let Entry { commit, sig } = Entry::parse(entry)?;
        let MlsMessageBodyIn::Welcome(welcome) = parse::<MlsMessageIn>(welcome_bytes)?.extract() else {
            bail!("not a Welcome")
        };
        let MlsMessageBodyIn::PrivateMessage(message) = parse::<MlsMessageIn>(&commit)?.extract() else { bail!("not a commit") };
        ensure!(message.content_type() == ContentType::Commit, "not a commit");
        let aad: Aad = serde_json::from_slice(message.aad()).context("a commit's authenticated data")?;
        provider.savepoint()?;
        let result = (|| {
            let builder = StagedWelcome::build_from_welcome(provider, &join_config(), welcome)?;
            let package = builder.processed_welcome().own_key_package().context("Welcome did not use a saved KeyPackage")?;
            ensure!(package.hash_ref(provider.crypto())?.as_slice() == expected_package, "Welcome used another KeyPackage");
            let staged = builder.skip_lifetime_validation().build()?;
            let committer = staged.welcome_sender()?.signature_key().as_slice().to_vec();
            let settings = settings_of(staged.group_context().extensions())?;
            ensure!(
                settings.protocol == PROTOCOL,
                "this group runs protocol {}; this client runs {PROTOCOL}",
                settings.protocol
            );
            service_key(&settings)?;
            ensure!(staged.group_context().group_id().as_slice().len() == 16, "group ID is not 16 bytes");
            let mls = staged.into_group(provider)?;
            let named = |m: &openmls::group::Member| credential_of(&m.credential).is_some_and(|c| c.key.0 == m.signature_key);
            ensure!(mls.members().all(|m| named(&m)), "a member whose credential names another key than its leaf's");
            let epoch = mls.epoch().as_u64();
            ensure!(message.group_id() == mls.group_id() && message.epoch().as_u64() + 1 == epoch, "a commit entry of another group or epoch");
            ensure!(
                provider.crypto().verify_signature(SignatureScheme::ED25519, &signed(&commit), &committer, &sig).is_ok(),
                "a commit entry its Welcome's sender did not sign"
            );
            ensure!(
                provider.crypto().verify_signature(SignatureScheme::ED25519, &welcome_signed(entry, welcome_bytes), &committer, welcome_sig).is_ok(),
                "a Welcome its sender did not sign"
            );
            ensure!(aad.cut.windows(2).all(|pair| pair[0].key < pair[1].key) && aad.cut.iter().all(well_formed), "a malformed cut");
            let cut = mls.members().map(|m| {
                let found = aad.cut.iter().find(|r| r.key.0 == m.signature_key).cloned();
                found.unwrap_or(Ref { key: Bytes(m.signature_key), joined: epoch, seq: 0, id: Bytes::default(), epoch: 0 })
            });
            let mut cut: Vec<Ref> = cut.collect();
            cut.sort();
            let group = Group { state: State { cut, ended: aad.cut, ..State::default() }, mls };
            group.save(provider)?;
            Ok(group)
        })();
        if result.is_ok() {
            provider.release()?;
        } else {
            provider.rollback_to()?;
        }
        result
    }

    pub fn load<P: Provider>(provider: &P, id: &[u8]) -> Result<Self> {
        let mls = MlsGroup::load(provider.storage(), &GroupId::from_slice(id))?.context("no such group")?;
        let state = serde_json::from_slice(&provider.get(&state_key(id))?.context("no state for the group")?)?;
        Ok(Group { mls, state })
    }

    fn save<P: Provider>(&self, provider: &P) -> Result<()> {
        provider.put(&state_key(self.id()), &serde_json::to_vec(&self.state)?)
    }

    /// Deletes the group's state, once this session has left it. openmls keeps the key pairs of the epoch a removing
    /// commit ends, so the previous epoch's go too.
    pub fn delete<P: Provider>(mut self, provider: &P) -> Result<()> {
        let storage = provider.storage();
        self.mls.delete(storage)?;
        let previous = GroupEpoch::from(self.epoch().saturating_sub(1));
        storage.delete_encryption_epoch_key_pairs(self.mls.group_id(), &previous, self.own_index())?;
        provider.delete(&state_key(self.id()))
    }

    pub fn id(&self) -> &[u8] {
        self.mls.group_id().as_slice()
    }

    pub fn epoch(&self) -> u64 {
        self.mls.epoch().as_u64()
    }

    pub fn settings(&self) -> Settings {
        settings_of(self.mls.extensions()).expect("every epoch's settings were checked")
    }

    pub fn active(&self) -> bool {
        self.mls.is_active()
    }

    pub fn own_index(&self) -> u32 {
        self.mls.own_leaf_index().u32()
    }

    /// The entry of the pending commit, to post again until the log shows it or another commit wins.
    pub fn posted(&self) -> Option<&[u8]> {
        self.state.posted.as_ref().map(|posted| posted.wire.0.as_slice())
    }

    pub fn epoch_authenticator(&self) -> &[u8] {
        self.mls.epoch_authenticator().as_slice()
    }

    pub fn members(&self) -> Vec<Member> {
        self.mls.members().filter_map(|member| Member::of(&self.mls, member.index)).collect()
    }

    /// Leaf liveness after exact package-reference matching, not a package-identity test.
    pub fn unchanged<P: Provider>(&self, provider: &P, key_package: &[u8]) -> Result<bool> {
        let key_package = key_package_in(provider, key_package)?;
        let leaf = key_package.leaf_node();
        let Some(member) = self.mls.members().find(|m| m.signature_key == leaf.signature_key().as_slice()) else { return Ok(false) };
        Ok(self.mls.public_group().leaf(member.index).is_some_and(|ours| ours.encryption_key() == leaf.encryption_key()))
    }

    /// Who added whom, as the log showed it since this session joined, but the records forgotten.
    pub fn added(&self) -> &[Added] {
        &self.state.added
    }

    /// Forgets the records of who added whom that `keep` does not keep.
    pub fn forget_added<P: Provider>(&mut self, provider: &P, keep: impl Fn(&Added) -> bool) -> Result<()> {
        self.state.added.retain(keep);
        self.save(provider)
    }

    /// Whether a commit this session applied added a member by the invite whose secret hashes to `hash`.
    pub fn used(&self, hash: &[u8]) -> bool {
        self.state.added.iter().any(|added| added.invite.as_ref().is_some_and(|invite| invite.0 == hash))
    }

    /// The cut state: per current member, by key, the seq up to which the group keeps its held messages, and the id
    /// there. A commit carries the next cut, of the epoch it ends.
    pub fn cut(&self) -> &[Ref] {
        &self.state.cut
    }

    /// The epoch the current membership of the member with key `key` began in.
    pub fn joined(&self, key: &[u8]) -> Option<u64> {
        self.state.cut.iter().find(|r| r.key.0 == key).map(|r| r.joined)
    }

    /// The current epoch's secret that ranks members as one another's neighbours.
    pub fn neighbour_secret<P: Provider>(&self, provider: &P) -> Result<[u8; 32]> {
        Ok(self.mls.export_secret(provider.crypto(), NEIGHBOURS_LABEL, &[], 32)?.try_into().unwrap())
    }

    fn epoch_context(&self) -> Result<([u8; 32], Vec<u8>)> {
        let service = service_key(&self.settings())?;
        Ok((service, [self.id(), &self.epoch().to_be_bytes(), &service].concat()))
    }

    pub fn capability<P: Provider>(&self, provider: &P) -> Result<[u8; 32]> {
        let (_, context) = self.epoch_context()?;
        Ok(self.mls.export_secret(provider.crypto(), ADDRESS_LABEL, &context, 32)?.try_into().unwrap())
    }

    fn seal_entry<P: Provider>(&self, provider: &P, inner: &[u8]) -> Result<Vec<u8>> {
        ensure!(inner.len() <= MAX_INNER, "entry exceeds the 1 MiB envelope limit");
        Entry::parse(inner)?;
        let bucket = (inner.len() + 45).next_power_of_two().max(1024);
        let mut plaintext = vec![0; bucket - 41];
        plaintext[..4].copy_from_slice(&(inner.len() as u32).to_be_bytes());
        plaintext[4..4 + inner.len()].copy_from_slice(inner);
        let nonce = crate::random::<24>();
        let (service, context) = self.epoch_context()?;
        let key = self.mls.export_secret(provider.crypto(), SEALING_LABEL, &context, 32)?;
        let reference = lmk_proto::head::reference(&service, &self.capability(provider)?);
        let aad = [ENVELOPE_DOMAIN, &context, &reference, &(bucket as u32).to_be_bytes()].concat();
        let ciphertext = XChaCha20Poly1305::new_from_slice(&key).unwrap().encrypt((&nonce).into(), Payload { msg: &plaintext, aad: &aad })?;
        Ok([&[1], nonce.as_slice(), &ciphertext].concat())
    }

    /// Opens only the current epoch's outer envelope, returning the encoded Entry. `judge` checks its inner signature.
    pub fn open_entry<P: Provider>(&self, provider: &P, wire: &[u8]) -> Result<Vec<u8>> {
        let bucket = wire.len();
        ensure!((1024..=1 << 20).contains(&bucket) && bucket.is_power_of_two(), "invalid envelope bucket");
        ensure!(wire[0] == 1, "unsupported envelope version");
        let (service, context) = self.epoch_context()?;
        let key = self.mls.export_secret(provider.crypto(), SEALING_LABEL, &context, 32)?;
        let reference = lmk_proto::head::reference(&service, &self.capability(provider)?);
        let aad = [ENVELOPE_DOMAIN, &context, &reference, &(bucket as u32).to_be_bytes()].concat();
        let nonce: &[u8; 24] = wire[1..25].try_into()?;
        let plaintext = XChaCha20Poly1305::new_from_slice(&key).unwrap().decrypt(nonce.into(), Payload { msg: &wire[25..], aad: &aad })
            .map_err(|_| anyhow::anyhow!("invalid epoch envelope authentication"))?;
        let length = u32::from_be_bytes(plaintext[..4].try_into()?) as usize;
        ensure!(length <= plaintext.len() - 4, "invalid envelope inner length");
        ensure!((length + 45).next_power_of_two().max(1024) == bucket, "noncanonical envelope bucket");
        ensure!(plaintext[4 + length..].iter().all(|byte| *byte == 0), "nonzero envelope padding");
        let inner = &plaintext[4..4 + length];
        Entry::parse(inner)?;
        Ok(inner.to_vec())
    }

    /// Runs `f` under a savepoint, kept if `keep` says so of its result; else rolled back, and the group reloaded from
    /// storage, so that nothing of it is left.
    fn guarded<P: Provider, T>(&mut self, provider: &P, keep: impl FnOnce(&Result<T>) -> bool, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let state = self.state.clone();
        let aad = self.mls.aad().to_vec();
        provider.savepoint()?;
        let result = f(self);
        if keep(&result) {
            provider.release()?;
        } else {
            provider.rollback_to()?;
            let id = self.mls.group_id().clone();
            self.mls = MlsGroup::load(provider.storage(), &id)?.context("the group is gone from storage")?;
            self.mls.set_aad(aad);
            self.state = state;
        }
        result
    }

    /// Builds a commit and keeps it pending, with its whole entry saved: post that next, then read the log.
    pub fn commit<P: Provider>(&mut self, provider: &P, session: &Session, change: Change) -> Result<Commit> {
        ensure!(self.state.posted.is_none(), "a commit is already pending");
        if let Some(settings) = &change.settings {
            service_key(settings)?;
        }
        self.guarded(provider, Result::is_ok, |g| {
            // One staged but never saved, so never posted.
            g.mls.clear_pending_commit(provider.storage())?;
            let adds = change.add.iter().map(|bytes| key_package_in(provider, bytes)).collect::<Result<Vec<_>>>()?;
            let aad = Aad { how: change.how, invite: change.invite, cut: change.cut, time: corrected() };
            g.mls.set_aad(serde_json::to_vec(&aad)?);
            let mut parameters = LeafNodeParameters::builder();
            if let Some(leaf) = &change.leaf {
                parameters = parameters.with_extensions(leaf_extensions(leaf)?);
            }
            if change.name.is_some() || change.certificate.is_some() {
                let own = g.mls.own_leaf_node().context("no leaf of its own")?;
                let mut credential = credential_of(own.credential()).context("not a letmeknow credential")?;
                if let Some(name) = change.name {
                    credential.name = name;
                }
                if let Some(certificate) = change.certificate {
                    let unchanged = credential.certificate.as_deref() == Some(&certificate);
                    let same = credential.certificate.as_ref().is_some_and(|old| old.identity.id == certificate.identity.id && old.device == certificate.device);
                    credential.certificate = Some(Box::new(certificate));
                    ensure!(unchanged || (same && crate::public::verify_certificate(&credential)), "an update changed the member's authorization or has invalid claims");
                }
                parameters = parameters.with_credential_with_key(CredentialWithKey {
                    credential: BasicCredential::new(serde_json::to_vec(&credential)?).into(),
                    signature_key: session.signer.public().into(),
                });
            }
            let mut builder = g
                .mls
                .commit_builder()
                .consume_proposal_store(false)
                .force_self_update(true)
                .propose_adds(adds)
                .propose_removals(change.remove.into_iter().map(LeafNodeIndex::new));
            if let Some(settings) = &change.settings {
                builder = builder.propose_group_context_extensions(context_extensions(settings)?)?;
            }
            builder = builder.leaf_node_parameters(parameters.build());
            let bundle = builder
                .load_psks(provider.storage())?
                .build(provider.rand(), provider.crypto(), &session.signer, |_| true)?
                .stage_commit(provider)?;
            rules(&g.mls, g.mls.pending_commit().unwrap(), g.mls.own_leaf_index(), &aad, &g.state.cut)?;
            let (commit, welcome, _) = bundle.into_messages();
            let commit = commit.to_bytes()?;
            let sig = session.sign(&signed(&commit));
            let entry = Entry { commit, sig }.encode();
            let admission = welcome
                .map(|welcome| -> Result<Admission> {
                    let welcome = welcome.to_bytes()?;
                    let sig = session.sign(&welcome_signed(&entry, &welcome));
                    Ok(Admission { welcome, sig })
                })
                .transpose()?;
            let wire = g.seal_entry(provider, &entry)?;
            let add_refs = g.mls.pending_commit().unwrap().add_proposals()
                .map(|add| Ok(add.add_proposal().key_package().hash_ref(provider.crypto())?.as_slice().try_into()?))
                .collect::<Result<_>>()?;
            g.state.posted = Some(Posted { inner: Bytes(entry), wire: Bytes(wire.clone()), add_refs, admission: admission.clone() });
            g.state.aad = aad;
            g.save(provider)?;
            Ok(Commit { entry: wire, admission })
        })
    }

    /// Explicitly abandons a pending commit. A refusal does not prove an earlier attempt was never accepted.
    pub fn cancel<P: Provider>(&mut self, provider: &P) -> Result<()> {
        self.mls.clear_pending_commit(provider.storage())?;
        self.state.posted = None;
        self.save(provider)
    }

    /// Judges the next log entry in the current epoch: the first valid commit for it, whose signature verifies under its
    /// committer's leaf key, is to be applied (`apply`). What openmls does as it stages a commit leaves no trace.
    pub fn judge<P: Provider>(&mut self, provider: &P, entry: &[u8]) -> Result<Verdict> {
        if !self.mls.is_active() {
            return Ok(Verdict::Skipped { reason: "removed from the group".into(), lost: false });
        }
        let skipped = |error: anyhow::Error| Verdict::Skipped { reason: format!("{error:#}"), lost: false };
        let entry = match self.open_entry(provider, entry) {
            Ok(entry) => entry,
            Err(error) => return Ok(skipped(error)),
        };
        if self.state.posted.as_ref().is_some_and(|posted| posted.inner.0 == entry) {
            let staged = self.mls.pending_commit().expect("a posted commit is pending");
            if let Err(error) = rules(&self.mls, staged, self.mls.own_leaf_index(), &self.state.aad, &self.state.cut) {
                self.state.posted = None;
                self.mls.clear_pending_commit(provider.storage())?;
                self.save(provider)?;
                return Ok(Verdict::Skipped { reason: error.to_string(), lost: true });
            }
            return Ok(Verdict::Commit { removes: false, time: self.state.aad.time });
        }
        match Entry::parse(&entry) {
            Err(error) => Ok(skipped(error)),
            Ok(Entry { commit, sig }) => {
                let staged = self.guarded(provider, |_| false, |g| g.stage(provider, &commit, &sig));
                Ok(match staged {
                    Ok(Staged::Copied) => Verdict::Copied,
                    Ok(Staged::Commit(staged, _, aad)) => Verdict::Commit { removes: staged.self_removed(), time: aad.time },
                    Err(error) => skipped(error),
                })
            }
        }
    }

    /// Applies a commit `judge` found valid.
    pub fn apply<P: Provider>(&mut self, provider: &P, entry: &[u8]) -> Result<Applied> {
        let entry = self.open_entry(provider, entry)?;
        self.guarded(provider, Result::is_ok, |g| {
            if g.state.posted.as_ref().is_some_and(|posted| posted.inner.0 == entry) {
                let by = g.mls.own_leaf_index();
                let staged = g.mls.pending_commit().expect("a posted commit is pending");
                let aad = g.state.aad.clone();
                let mut applied = observe(provider, &g.mls, &mut g.state, staged, by, aad, true)?;
                applied.admission = g.state.posted.take().and_then(|posted| posted.admission);
                g.mls.merge_pending_commit(provider)?;
                return g.merged(provider, applied);
            }
            let Entry { commit, sig } = Entry::parse(&entry)?;
            let Staged::Commit(staged, by, aad) = g.stage(provider, &commit, &sig)? else { bail!("not a commit to apply") };
            let applied = observe(provider, &g.mls, &mut g.state, &staged, by, aad, false)?;
            g.state.posted = None;
            g.mls.clear_pending_commit(provider.storage())?;
            g.mls.merge_staged_commit(provider, *staged)?;
            g.merged(provider, applied)
        })
    }

    fn stage<P: Provider>(&mut self, provider: &P, commit: &[u8], sig: &[u8]) -> Result<Staged> {
        let message = parse::<MlsMessageIn>(commit)?.try_into_protocol_message()?;
        ensure!(message.content_type() == ContentType::Commit, "not a commit");
        let processed = self.mls.process_message(provider, message)?;
        let aad: Aad = serde_json::from_slice(processed.aad()).context("a commit's authenticated data")?;
        let Sender::Member(by) = *processed.sender() else { bail!("not from a member") };
        let key = self.mls.member_at(by).context("from no member")?.signature_key;
        let signed = provider.crypto().verify_signature(SignatureScheme::ED25519, &signed(commit), &key, sig).is_ok();
        let staged = match processed.into_content() {
            ProcessedMessageContent::OwnPrivateMessage if signed => return Ok(Staged::Copied),
            ProcessedMessageContent::OwnPrivateMessage => bail!("from this session's leaf, not signed by its key"),
            ProcessedMessageContent::StagedCommitMessage(staged) => staged,
            _ => bail!("not a commit"),
        };
        ensure!(signed, "a commit entry its committer did not sign");
        rules(&self.mls, &staged, by, &aad, &self.state.cut)?;
        Ok(Staged::Commit(staged, by, aad))
    }

    /// Records what a merged commit did: the added members' leaves, and the cut state of the new epoch: the cut, less
    /// the members it removed, with those it added at seq 0.
    fn merged<P: Provider>(&mut self, provider: &P, mut applied: Applied) -> Result<Applied> {
        let members = self.members();
        for member in &mut applied.added {
            member.index = members.iter().find(|m| m.key == member.key).expect("an added member is in the tree").index;
        }
        let epoch = self.epoch();
        let mut cut: Vec<Ref> = applied.cut.iter().filter(|r| members.iter().any(|m| m.key == r.key.0)).cloned().collect();
        cut.extend(applied.added.iter().map(|m| Ref { key: Bytes(m.key.clone()), joined: epoch, seq: 0, id: Bytes::default(), epoch: 0 }));
        cut.sort();
        self.state.cut = cut;
        self.state.ended = applied.cut.clone();
        self.save(provider)?;
        Ok(applied)
    }

    /// Seals a held message's plaintext, its header's JSON, as an application message of the current epoch, claiming
    /// its membership and seq. One whose ciphertext could be over `MAX_MESSAGE` fails before it uses any of the sender's
    /// keys.
    pub fn seal<P: Provider>(&mut self, provider: &P, session: &Session, plaintext: &[u8]) -> Result<Vec<u8>> {
        let size = plaintext.len() + FRAMING;
        ensure!(size <= MAX_MESSAGE, "the message is {size} bytes, over the 1 MiB members take");
        self.mls.set_aad(serde_json::to_vec(&Header::open(plaintext)?.claim())?);
        Ok(self.mls.create_message(provider, &session.signer, plaintext)?.to_bytes()?)
    }

    /// Decrypts a member's held message and checks its header: of this group, its author the sender, as it claimed, of
    /// the membership its author had in the epoch it was sealed in, and within its final cut if that membership ended.
    /// What openmls does with one it rejects leaves no trace: it advances the claimed sender's keys before it checks the
    /// signature.
    pub fn open<P: Provider>(&mut self, provider: &P, bytes: &[u8]) -> Result<Opened> {
        let message = parse::<MlsMessageIn>(bytes)?.try_into_protocol_message()?;
        ensure!(message.content_type() == ContentType::Application, "not an application message");
        let processed = self.guarded(provider, |result| matches!(result, Ok(Ok(_))), |g| Ok(g.mls.process_message(provider, message)))?;
        let processed = match processed {
            Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(MessageDecryptionError::SecretTreeError(
                SecretTreeError::TooDistantInThePast | SecretTreeError::SecretReuseError,
            )))) => return Err(Unheld.into()),
            processed => processed?,
        };
        let epoch = processed.epoch().as_u64();
        let claim: Claim = serde_json::from_slice(processed.aad()).context("a held message's claim")?;
        let sender = credential_of(processed.credential()).context("the sender has no letmeknow credential")?;
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            bail!("not an application message")
        };
        let plaintext = message.into_bytes();
        let header = Header::open(&plaintext)?;
        ensure!(header.group.0 == self.id(), "a held message of another group");
        ensure!(header.author == sender.key && header.claim() == claim, "a held message its sender did not author, or claimed otherwise");
        let cuts = if epoch == self.epoch() { &self.state.cut } else { &self.state.ended };
        let membership = cuts.iter().find(|r| r.key == header.author).context("a held message of no membership")?;
        ensure!(membership.joined == header.joined, "a held message of another membership of its author");
        let ended = self.joined(&header.author.0) != Some(header.joined);
        ensure!(!ended || header.seq <= membership.seq, "a held message past its membership's final cut");
        Ok(Opened { id: held::id(&plaintext), epoch, sender, header, plaintext })
    }

    /// What a live payload's key and signature are bound to: the group and the current epoch.
    fn live_context(&self, epoch: u64) -> Vec<u8> {
        [LIVE, self.id(), &epoch.to_be_bytes()].concat()
    }

    /// Seals a live payload under the current epoch's live key, signed by this session: `epoch ‖ nonce ‖ ciphertext` of
    /// `body ‖ sig`, the body `{"author", "nonce", "payload"}`, and its id, as `open_live` gives it. It uses none of the MLS
    /// ratchet.
    pub fn seal_live<P: Provider>(&self, provider: &P, session: &Session, payload: &Value) -> Result<(Vec<u8>, [u8; 32])> {
        let epoch = self.epoch();
        let context = self.live_context(epoch);
        let nonce = Bytes(crate::random::<16>().to_vec());
        let body = serde_json::to_vec(&Live { author: Bytes(session.key().to_vec()), nonce, payload: payload.clone() })?;
        let sig = session.sign(&[&context, &body[..]].concat());
        let id = held::id(&sig);
        let plaintext = [body, sig].concat();
        let size = plaintext.len() + FRAMING;
        ensure!(size <= MAX_MESSAGE, "the payload is {size} bytes, over the 1 MiB members take");
        let key = self.mls.export_secret(provider.crypto(), LIVE_LABEL, &context, 32)?;
        let nonce = crate::random::<24>();
        let ciphertext = XChaCha20Poly1305::new_from_slice(&key).unwrap().encrypt((&nonce).into(), Payload { msg: &plaintext, aad: &context })?;
        Ok(([&epoch.to_be_bytes()[..], &nonce, &ciphertext].concat(), id))
    }

    /// Opens a live payload sealed in the current epoch by a current member, its signature checked: the member, the
    /// payload, and its id, the hash of the signature, which a replay sealed anew keeps.
    pub fn open_live<P: Provider>(&self, provider: &P, wire: &[u8]) -> Result<(Member, Value, [u8; 32])> {
        ensure!(wire.len() > 8 + 24 + 64 + 16, "a live payload too short");
        let epoch = u64::from_be_bytes(wire[..8].try_into().unwrap());
        ensure!(epoch == self.epoch(), "a live payload of another epoch");
        let context = self.live_context(epoch);
        let key = self.mls.export_secret(provider.crypto(), LIVE_LABEL, &context, 32)?;
        let nonce: &[u8; 24] = wire[8..32].try_into().unwrap();
        let plaintext = XChaCha20Poly1305::new_from_slice(&key).unwrap().decrypt(nonce.into(), Payload { msg: &wire[32..], aad: &context })
            .map_err(|_| anyhow::anyhow!("a live payload that does not open in this epoch"))?;
        ensure!(plaintext.len() > 64, "a live payload without its signature");
        let (body, sig) = plaintext.split_at(plaintext.len() - 64);
        let live: Live = serde_json::from_slice(body)?;
        let index = self.mls.members().find(|m| m.signature_key == live.author.0).context("a live payload from no current member")?.index;
        let member = Member::of(&self.mls, index).context("a live payload from no current member")?;
        ensure!(crate::device::verify(&live.author.0, &context, body, sig), "a live payload its author did not sign");
        ensure!(live.payload["type"].is_string(), "a payload without a type");
        Ok((member, live.payload, held::id(sig)))
    }
}

/// A live payload's signed body.
#[derive(Serialize, Deserialize)]
struct Live {
    author: Bytes,
    /// Random: a payload sent again is another payload, which dedup lets through; a replay keeps its id.
    nonce: Bytes,
    payload: Value,
}

/// A commit entry staged, or found to be from a copy of this session's state.
enum Staged {
    Commit(Box<StagedCommit>, LeafNodeIndex, Aad),
    Copied,
}

/// Records what a commit does, before it is merged.
fn observe<P: Provider>(
    provider: &P,
    group: &MlsGroup,
    state: &mut State,
    staged: &StagedCommit,
    by: LeafNodeIndex,
    aad: Aad,
    own: bool,
) -> Result<Applied> {
    let committer = group.member_at(by).and_then(|member| credential_of(&member.credential));
    let removed: Vec<Member> =
        staged.remove_proposals().filter_map(|remove| Member::of(group, remove.remove_proposal().removed())).collect();
    let added: Vec<Member> = staged
        .add_proposals()
        .map(|add| {
            let leaf = add.add_proposal().key_package().leaf_node();
            Member {
                // Set once merged.
                index: 0,
                key: leaf.signature_key().as_slice().to_vec(),
                credential: credential_of(leaf.credential()),
                leaf: leaf_of(leaf.extensions()),
            }
        })
        .collect();
    let epoch = staged.epoch().as_u64();
    if let Some(committer) = &committer {
        let records = staged.add_proposals().enumerate().map(|(index, add)| {
            let key_package_ref = if own {
                state.posted.as_ref().unwrap().add_refs[index]
            } else {
                add.add_proposal().key_package().hash_ref(provider.crypto())?.as_slice().try_into()?
            };
            Ok(Added {
                member: leaf_credential(add.add_proposal().key_package().leaf_node())?,
                by: committer.clone(), how: aad.how.clone(), invite: aad.invite.clone(), epoch, key_package_ref, at: now(),
            })
        }).collect::<Result<Vec<_>>>()?;
        state.added.extend(records);
    }
    Ok(Applied {
        by: by.u32(),
        own,
        lost: !own && state.posted.is_some(),
        added,
        how: aad.how,
        removed,
        settings: staged.queued_proposals().any(|p| matches!(p.proposal(), Proposal::GroupContextExtensions(_))),
        gone: staged.self_removed(),
        cut: aad.cut,
        admission: None,
    })
}

fn state_key(id: &[u8]) -> Vec<u8> {
    [b"group/".as_slice(), id].concat()
}

/// Whether a cut entry's id fits its seq: none at seq 0, else 32 bytes.
fn well_formed(r: &Ref) -> bool {
    r.id.0.len() == if r.seq == 0 { 0 } else { 32 }
}

/// The app's rules on a commit, from MLS state alone, binding the committer too: changes inline only, of the kinds we
/// make; added members whose credentials name their own keys, and none it removes; settings that parse, at this
/// protocol, with the kind and the public log unchanged; only name or signed same-identity/device claim updates to the
/// committer's credential; and a cut that names every member of the cut state `cut`, by key, in order, at its
/// membership, never below it nor more than `MAX_CUT_STEP` past it.
fn rules(group: &MlsGroup, staged: &StagedCommit, by: LeafNodeIndex, aad: &Aad, cut: &[Ref]) -> Result<()> {
    let removed: Vec<Vec<u8>> = staged.remove_proposals().filter_map(|r| group.member_at(r.remove_proposal().removed())).map(|m| m.signature_key).collect();
    for proposal in staged.queued_proposals() {
        ensure!(proposal.proposal_or_ref_type() == ProposalOrRefType::Proposal, "a proposal by reference");
        match proposal.proposal() {
            Proposal::Add(add) => {
                let credential = leaf_credential(add.key_package().leaf_node())?;
                ensure!(!removed.contains(&credential.key.0), "a commit that adds a key it removes");
            }
            Proposal::Remove(_) | Proposal::GroupContextExtensions(_) => {}
            other => bail!("a {:?} proposal", other.proposal_type()),
        }
    }
    ensure!(aad.how.is_some() || staged.add_proposals().next().is_none(), "an Add that does not say how its members came in");
    let named = aad.cut.len() == cut.len() && aad.cut.iter().zip(cut).all(|(new, old)| new.key == old.key && new.joined == old.joined);
    ensure!(named, "a cut that does not name each member once, in order, at its membership");
    for (new, old) in aad.cut.iter().zip(cut) {
        ensure!(well_formed(new), "a cut whose id does not fit its seq");
        ensure!(new.seq > old.seq || (new.seq == old.seq && new.id == old.id && new.epoch == old.epoch), "a cut below the last");
        ensure!(new.seq - old.seq <= MAX_CUT_STEP, "a cut too far past the last");
    }
    let old = settings_of(group.extensions())?;
    let new = settings_of(staged.group_context().extensions())?;
    ensure!(new.protocol == PROTOCOL, "settings name protocol {}", new.protocol);
    ensure!(new.kind == old.kind, "the kind changed");
    ensure!(new.public == old.public, "the public log changed");
    let authority = service_key(&new)?;
    if old.kind == IDENTITY {
        ensure!(authority == service_key(&old)?, "an identity group's service authority changed");
    }
    if let Some(leaf) = staged.update_path_leaf_node() {
        let member = group.member_at(by).context("not a member")?;
        let before = credential_of(&member.credential).context("not a letmeknow credential")?;
        let after = leaf_credential(leaf)?;
        ensure!(before.key == after.key && after.key.0 == member.signature_key, "an update changed the member's key");
        if before.certificate != after.certificate {
            let same = before.certificate.as_ref().zip(after.certificate.as_ref())
                .is_some_and(|(old, new)| old.identity.id == new.identity.id && old.device == new.device);
            ensure!(same && crate::public::verify_certificate(&after), "an update changed the member's authorization or has invalid claims");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "group_tests.rs"]
pub(crate) mod tests;
