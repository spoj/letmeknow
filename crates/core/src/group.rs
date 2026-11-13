//! Sessions and groups on OpenMLS: epoch-sealed commit entries judged strictly in order, each carrying the cut of the
//! epoch it ends; held messages as application messages whose plaintext is their header, naming in the clear which
//! message they are, each sealing signed by its author.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit, Payload}};
use lmk_proto::Bytes;
use lmk_proto::clock::now;
use lmk_proto::directory::check_domain;
use lmk_proto::entry::{Entry, signed, welcome_signed};
use lmk_proto::group::{LEAF, LEAF_EXTENSION, LEAVE, Leaf, PROTOCOL, SETTINGS_EXTENSION, Service, Settings, is_key};
use lmk_proto::held::{self, Cut, Header, Ref, SEALING};
use openmls::prelude::*;
use openmls::schedule::{ExternalPsk, PreSharedKeyId, Psk};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;
use openmls_traits::storage::StorageProvider as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::provider::SqliteProvider;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;
/// The largest message ciphertext taken, and sent.
pub const MAX_MESSAGE: usize = 16 << 20;
/// More than a held message's sealing adds to its plaintext.
pub const FRAMING: usize = 1024;
/// How far one cut may move a membership's.
pub const MAX_CUT_STEP: u64 = 100_000;
const ADDRESS_LABEL: &str = "letmeknow epoch log address v1";
const SEALING_LABEL: &str = "letmeknow epoch log sealing v1";
const ENVELOPE_DOMAIN: &[u8] = b"letmeknow epoch envelope v1\0";
const INVITE_DOMAIN: &[u8] = b"letmeknow invite v1\0";
const INVITE_USE_DOMAIN: &[u8] = b"letmeknow invite use v1\0";
/// The id of the external PSK by which an Add binds the cut it ends (`bind`).
const CUT_PSK: &[u8] = b"letmeknow cut v1";
const MAX_INNER: usize = (1 << 20) - 45;

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

/// Which message a sealing of the group `group` claims to be, as the clear framing of its MLS ciphertext shows it, with
/// the epoch it was sealed in and the signature that follows the ciphertext, once that verifies by the key the claim
/// names (`SEALING`): the cut entry the sealing proves. `open` checks the claim.
pub fn claim(group: &[u8], sealing: &[u8]) -> Result<Cut> {
    let (bytes, sig) = sealing.split_at(sealing.len().checked_sub(64).context("a sealing without its signature")?);
    let MlsMessageBodyIn::PrivateMessage(message) = parse::<MlsMessageIn>(bytes)?.extract() else { bail!("not a private message") };
    ensure!(message.content_type() == ContentType::Application, "not an application message");
    let Ref { key, joined, seq, id, epoch } = serde_json::from_slice(message.aad()).context("a held message's claim")?;
    let sealed = message.epoch().as_u64();
    let claimed = Cut { key, joined, seq, id, epoch, sealed, digest: Bytes(Sha256::digest(bytes).to_vec()), sig: Bytes(sig.to_vec()) };
    ensure!(well_formed(group, &claimed), "a sealing its claimed author did not sign");
    Ok(claimed)
}

fn parse<T: tls_codec::DeserializeBytes>(bytes: &[u8]) -> Result<T> {
    Ok(T::tls_deserialize_exact_bytes(bytes)?)
}

/// One MLS member: its signature key, which is all its credential says, and its leaf data.
pub struct Session {
    signer: SignatureKeyPair,
    pub leaf: Leaf,
}

#[derive(Serialize, Deserialize)]
struct SessionRecord {
    public: Bytes,
    leaf: Leaf,
}

impl Session {
    /// A new session with a fresh MLS key, and the leaf `leaf` makes for that key; a provider holds one session.
    pub fn create(provider: &SqliteProvider, leaf: impl FnOnce(&[u8]) -> Leaf) -> Result<Self> {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519)?;
        signer.store(provider.storage())?;
        let session = Session { leaf: leaf(signer.public()), signer };
        session.save(provider)?;
        Ok(session)
    }

    pub fn load(provider: &SqliteProvider) -> Result<Self> {
        let record: SessionRecord = serde_json::from_slice(&provider.get(b"session")?.context("no session here")?)?;
        let signer = SignatureKeyPair::read(provider.storage(), &record.public.0, SignatureScheme::ED25519)
            .context("the session's key is missing")?;
        Ok(Session { signer, leaf: record.leaf })
    }

    fn save(&self, provider: &SqliteProvider) -> Result<()> {
        let record = SessionRecord { public: self.signer.public().into(), leaf: self.leaf.clone() };
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
    pub fn set_leaf(&mut self, provider: &SqliteProvider, leaf: Leaf) -> Result<()> {
        self.leaf = leaf;
        self.save(provider)
    }

    fn with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.signer.public().to_vec()).into(),
            signature_key: self.signer.public().into(),
        }
    }

    /// A KeyPackage, as it travels to a member that admits it. It never expires: that member judges freshness.
    pub fn key_package(&self, provider: &SqliteProvider) -> Result<Vec<u8>> {
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .leaf_node_extensions(leaf_extensions(&self.leaf)?)
            .key_package_lifetime(Lifetime::init(0, u64::MAX))
            .build(CIPHERSUITE, provider, &self.signer, self.with_key())?;
        Ok(MlsMessageOut::from(bundle.key_package().clone()).to_bytes()?)
    }
}

/// Validates a KeyPackage as it arrives at a member that admits it, and returns its session key and leaf data, proven.
pub fn key_package_leaf(provider: &SqliteProvider, key_package: &[u8]) -> Result<(Vec<u8>, Leaf)> {
    let key_package = key_package_in(provider, key_package)?;
    let leaf = key_package.leaf_node();
    Ok((leaf.signature_key().as_slice().to_vec(), proven(leaf)?))
}

pub fn key_package_reference(provider: &SqliteProvider, key_package: &[u8]) -> Result<[u8; 32]> {
    Ok(key_package_in(provider, key_package)?.hash_ref(provider.crypto())?.as_slice().try_into()?)
}

pub fn delete_key_package(provider: &SqliteProvider, key_package: &[u8]) -> Result<()> {
    let key_package = key_package_in(provider, key_package)?;
    Ok(provider.storage().delete_key_package(&key_package.hash_ref(provider.crypto())?)?)
}

fn key_package_in(provider: &SqliteProvider, bytes: &[u8]) -> Result<KeyPackage> {
    let MlsMessageBodyIn::KeyPackage(key_package) = parse::<MlsMessageIn>(bytes)?.extract() else {
        bail!("not a KeyPackage")
    };
    let key_package = key_package.validate(provider.crypto(), ProtocolVersion::Mls10)?;
    ensure!(*key_package.life_time() == Lifetime::init(0, u64::MAX), "a KeyPackage with a bounded lifetime");
    Ok(key_package)
}

/// Everything one commit changes, all inline. The default is an empty key update. Only a commit that adds and changes
/// nothing else goes without an update path.
#[derive(Clone, Debug, Default)]
pub struct Change {
    pub add: Vec<Vec<u8>>,
    /// The invite the added member came in by, carried in the commit's authenticated data.
    pub invite: Option<Invited>,
    /// Leaf indices.
    pub remove: Vec<u32>,
    /// The leaves of members it removes (`Group::leave`), carried in its authenticated data: with them a member that is
    /// no admin may remove them.
    pub left: Vec<Bytes>,
    pub leaf: Option<Leaf>,
    /// New settings, which only an admin commits: its admins and admitted devices changed.
    pub settings: Option<Settings>,
    /// The cut of the epoch the commit ends: for each member, by key, the seq up to which the committer holds every
    /// held message, sealed in this epoch, and the id there with its author's proof of that sealing (`claim`; see
    /// `Group::cut`). The commit carries the entries that moved.
    pub cut: Vec<Cut>,
}

/// The invite an Add's member came in by: the session key of the member that made it, the epoch that member's membership
/// began in, and `used`, which its secret gives (`Invited::new`), from which every member derives its hash. Naming the
/// hash alone uses nothing, and an Add, which every member of its epoch reads whether it wins the epoch or not, shows no
/// secret that joins.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invited {
    pub by: Bytes,
    pub joined: u64,
    pub used: Bytes,
}

impl Invited {
    /// The invite whose secret is `secret`: `used` is SHA-256 of `INVITE_USE_DOMAIN` and `secret`.
    pub fn new(by: Bytes, joined: u64, secret: &[u8]) -> Self {
        Invited { by, joined, used: Bytes(Sha256::digest([INVITE_USE_DOMAIN, secret].concat()).to_vec()) }
    }

    /// The invite's hash, as its maker shares it: SHA-256 of `INVITE_DOMAIN`, the group's id, `by`, `joined` (8 bytes)
    /// and `used`.
    pub fn hash(&self, group: &[u8]) -> Bytes {
        Bytes(Sha256::digest([INVITE_DOMAIN, group, &self.by.0, &self.joined.to_be_bytes(), &self.used.0].concat()).to_vec())
    }
}

/// A commit's authenticated data, inside its sealed entry: the invite the member it adds came in by, the leaves of
/// members it removes, and the entries of the cut state it moves.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Aad {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invite: Option<Invited>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    left: Vec<Bytes>,
    #[serde(default)]
    moved: Vec<Cut>,
}

/// A commit's sealed wire entry, and for an Add the Welcome that admits its joiner.
pub struct Commit {
    pub entry: Vec<u8>,
    pub admission: Option<Admission>,
}

/// An Add's Welcome, the whole cut of the epoch its commit ended, where the joiner starts, and the committer's signature
/// over the commit entry, the cut and the Welcome (`welcome_signed`). Only the committer keeps it, to answer the joiner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Admission {
    pub welcome: Vec<u8>,
    pub cut: Vec<Cut>,
    pub sig: Vec<u8>,
}

/// A member as its leaf shows it.
#[derive(Clone, Debug)]
pub struct Member {
    pub index: u32,
    pub key: Vec<u8>,
    pub leaf: Leaf,
}

impl Member {
    fn of(group: &MlsGroup, index: LeafNodeIndex) -> Option<Self> {
        let member = group.member_at(index)?;
        let leaf = group.public_group().leaf(index)?;
        Some(Member { index: index.u32(), key: member.signature_key, leaf: leaf_of(leaf.extensions()).expect("a member's leaf carries its data") })
    }
}

fn leaf_of(extensions: &Extensions<LeafNode>) -> Option<Leaf> {
    serde_json::from_slice(&extensions.unknown(LEAF_EXTENSION)?.0).ok()
}

/// A leaf node's data, which must hold of its session: a home that is a domain, the proof of its iroh key (`LEAF`), and
/// the certificate of the device it names, if any.
fn proven(leaf: &LeafNode) -> Result<Leaf> {
    let key = leaf.signature_key().as_slice();
    let data = leaf_of(leaf.extensions()).context("a leaf without its data")?;
    ensure!(check_domain(&data.home).is_ok(), "a leaf whose home is no domain");
    ensure!(verify(&data.key.0, LEAF, key, &data.proof.0), "a leaf its iroh key did not sign");
    ensure!(data.device.as_ref().is_none_or(|device| device.verify(key)), "a leaf its device did not certify");
    Ok(data)
}

/// Whether a session, by its key and its leaf data, is one of the settings' admins: by its key, or by the device that
/// certified it.
fn admin(settings: &Settings, key: &[u8], leaf: Option<&Leaf>) -> bool {
    let device = leaf.and_then(|leaf| leaf.device.as_ref());
    settings.admins.iter().any(|admin| admin.0 == key) || device.is_some_and(|device| settings.admins.contains(&device.key))
}

/// Whether the settings let any member add a session, by its leaf data: the device that certified it is admitted, or an
/// admin.
fn admits(settings: &Settings, leaf: &Leaf) -> bool {
    leaf.device.as_ref().is_some_and(|device| settings.admitted.contains(&device.key) || settings.admins.contains(&device.key))
}

/// Whether `sig` is the leave of the member with key `key` of the group `group`, whose cut state `cut` names it.
fn left(group: &[u8], cut: &[Cut], key: &[u8], sig: &[u8]) -> bool {
    cut.iter().find(|r| r.key.0 == key).is_some_and(|r| verify(key, LEAVE, &[group, &r.joined.to_be_bytes()].concat(), sig))
}

/// A log entry as judged in the current epoch, before anything of it is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The first valid commit for this epoch: apply it next.
    Commit {
        /// It removes this session.
        removes: bool,
    },
    /// A commit from this session's own leaf, signed with its key, that this session did not make: its state was copied.
    Copied,
    Skipped { reason: String },
}

/// What a commit did.
#[derive(Clone, Debug)]
pub struct Applied {
    /// The committer's leaf index, in the epoch it committed in.
    pub by: u32,
    /// This session's own commit.
    pub own: bool,
    /// As their KeyPackages show them; `index` is their new leaf.
    pub added: Vec<Member>,
    pub removed: Vec<Member>,
    /// This session was removed.
    pub gone: bool,
    /// It carried an update path: its committer's leaf is new.
    pub updated: bool,
    /// The cut of the epoch it ended, by the members of that epoch: the removed ones' last.
    pub cut: Vec<Cut>,
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
    pub header: Header,
    pub plaintext: Vec<u8>,
}

/// An Add, as the log showed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Added {
    /// The session key of the member it added.
    pub member: Bytes,
    /// The hash of the invite it came in by (`Invited::hash`).
    pub invite: Bytes,
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
    cut: Vec<Cut>,
    /// The cut of the commit that ended the previous epoch: its members, the removed ones at their final cuts.
    ended: Vec<Cut>,
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
    /// A new group, of this session alone, whose admins are this session and the device that certified it, whatever
    /// `settings` name.
    pub fn create(provider: &SqliteProvider, session: &Session, settings: &Settings) -> Result<Self> {
        ensure!(settings.protocol == PROTOCOL, "settings name protocol {}", settings.protocol);
        service_key(settings)?;
        let device = session.leaf.device.as_ref().map(|device| device.key.clone());
        let admins = [Bytes(session.key().to_vec())].into_iter().chain(device).collect();
        let settings = Settings { admins, ..settings.clone() };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities())
            .with_group_context_extensions(context_extensions(&settings)?)
            .with_leaf_node_extensions(leaf_extensions(&session.leaf)?)?
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(1)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(1000, 100_000))
            .lifetime(creator_lifetime())
            .build();
        let id = GroupId::from_slice(&crate::random::<16>());
        let mls = MlsGroup::new_with_group_id(provider, &session.signer, &config, id, session.with_key())?;
        let cut = vec![Cut { key: Bytes(session.key().to_vec()), ..Cut::default() }];
        let group = Group { state: State { cut, ..State::default() }, mls };
        group.save(provider)?;
        Ok(group)
    }

    /// Joins the group `gid` of the service at `domain` whose key is `key`, as an invite link names them, by the admission
    /// that admitted this session to the commit entry it came with, whose signatures it checks against the Welcome's
    /// sender, its committer, and whose cut is where it starts: the whole cut of the epoch the Add ended, which the Add
    /// binds into the epoch it begins (`bind`), so that a Welcome into the members' epoch opens only with theirs, and
    /// every member that cut does not name, as the Add added it, at seq 0 of the new epoch. Every leaf of the group is
    /// proven (`proven`), and names an iroh key no other names; its settings hold keys each in its one form (`is_key`).
    /// OpenMLS consumes a package during `build_from_welcome`, before `into_group`, so an error here rolls back this
    /// call's writes, the package's consumption included.
    pub fn join(provider: &SqliteProvider, entry: &[u8], admission: &Admission, expected_package: &[u8; 32], gid: &[u8; 16], domain: &str, key: &[u8; 32]) -> Result<Self> {
        let Entry { commit, sig } = Entry::parse(entry)?;
        let Admission { welcome: welcome_bytes, cut: ended, sig: welcome_sig } = admission;
        let MlsMessageBodyIn::Welcome(welcome) = parse::<MlsMessageIn>(welcome_bytes)?.extract() else {
            bail!("not a Welcome")
        };
        let MlsMessageBodyIn::PrivateMessage(message) = parse::<MlsMessageIn>(&commit)?.extract() else { bail!("not a commit") };
        ensure!(message.content_type() == ContentType::Commit, "not a commit");
        provider.savepoint()?;
        let result = (|| {
            bind(provider, ended)?;
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
            ensure!(settings.admins.iter().chain(&settings.admitted).all(|key| is_key(&key.0)), "a group whose settings hold a key that is neither Ed25519 nor compressed P-256");
            ensure!(staged.group_context().group_id().as_slice() == gid, "a Welcome into another group than the link names");
            ensure!(
                matches!(&settings.membership, Service::Serve { domain: theirs, key: their_key, .. } if theirs == domain && their_key.0 == key),
                "a Welcome into a group of another service than the link names"
            );
            let mls = staged.into_group(provider)?;
            ensure!(mls.members().all(|m| names_its_key(&m.credential, &m.signature_key)), "a member whose credential names another key");
            let leaves = mls.members().filter_map(|m| mls.public_group().leaf(m.index)).map(proven).collect::<Result<Vec<_>>>()?;
            let irohs: BTreeSet<&Bytes> = leaves.iter().map(|leaf| &leaf.key).collect();
            ensure!(irohs.len() == leaves.len(), "a group whose leaves name one iroh key twice");
            let epoch = mls.epoch().as_u64();
            ensure!(message.group_id() == mls.group_id() && message.epoch().as_u64() + 1 == epoch, "a commit entry of another group or epoch");
            ensure!(
                provider.crypto().verify_signature(SignatureScheme::ED25519, &signed(&commit), &committer, &sig).is_ok(),
                "a commit entry its Welcome's sender did not sign"
            );
            ensure!(
                provider.crypto().verify_signature(SignatureScheme::ED25519, &welcome_signed(entry, &serde_json::to_vec(ended)?, welcome_bytes), &committer, welcome_sig).is_ok(),
                "a Welcome its sender did not sign"
            );
            let cut = mls.members().map(|m| {
                let found = ended.iter().find(|r| r.key.0 == m.signature_key).cloned();
                found.unwrap_or(Cut { key: Bytes(m.signature_key), joined: epoch, ..Cut::default() })
            });
            let mut cut: Vec<Cut> = cut.collect();
            cut.sort();
            let group = Group { state: State { cut, ended: ended.clone(), ..State::default() }, mls };
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

    pub fn load(provider: &SqliteProvider, id: &[u8]) -> Result<Self> {
        let mls = MlsGroup::load(provider.storage(), &GroupId::from_slice(id))?.context("no such group")?;
        let state = serde_json::from_slice(&provider.get(&state_key(id))?.context("no state for the group")?)?;
        Ok(Group { mls, state })
    }

    fn save(&self, provider: &SqliteProvider) -> Result<()> {
        provider.put(&state_key(self.id()), &serde_json::to_vec(&self.state)?)
    }

    /// Deletes the group's state, once this session has left it. openmls keeps the key pairs of the epoch a removing
    /// commit ends, so the previous epoch's go too.
    pub fn delete(mut self, provider: &SqliteProvider) -> Result<()> {
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

    /// Whether the member with key `key` is an admin: by its key, or by the device its leaf names.
    pub fn admin(&self, key: &[u8]) -> bool {
        let leaf = self.members().into_iter().find(|m| m.key == key).map(|m| m.leaf);
        admin(&self.settings(), key, leaf.as_ref())
    }

    /// Whether any member may add the session with leaf data `leaf`: its device is admitted, or an admin.
    pub fn admits(&self, leaf: &Leaf) -> bool {
        admits(&self.settings(), leaf)
    }

    /// This session's leave of its membership, for its `leave` to carry: a commit that removes it may carry the leave in
    /// its authenticated data, so that any member may commit it.
    pub fn leave(&self, session: &Session) -> Result<Bytes> {
        let joined = self.joined(session.key()).context("a member of its group")?;
        Ok(Bytes(session.sign(&[LEAVE, self.id(), &joined.to_be_bytes()].concat())))
    }

    /// Whether `sig` is the leave of the current membership of the member with key `key`.
    pub fn left(&self, key: &[u8], sig: &[u8]) -> bool {
        left(self.id(), &self.state.cut, key, sig)
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
    pub fn unchanged(&self, provider: &SqliteProvider, key_package: &[u8]) -> Result<bool> {
        let key_package = key_package_in(provider, key_package)?;
        let leaf = key_package.leaf_node();
        let Some(member) = self.mls.members().find(|m| m.signature_key == leaf.signature_key().as_slice()) else { return Ok(false) };
        Ok(self.mls.public_group().leaf(member.index).is_some_and(|ours| ours.encryption_key() == leaf.encryption_key()))
    }

    /// Who added whom, as the log showed it since this session joined, but the records forgotten.
    pub fn added(&self) -> &[Added] {
        &self.state.added
    }

    /// Forgets the records of Adds that `keep` does not keep.
    pub fn forget_added(&mut self, provider: &SqliteProvider, keep: impl Fn(&Added) -> bool) -> Result<()> {
        self.state.added.retain(keep);
        self.save(provider)
    }

    /// Whether a commit this session applied added a member by the invite whose hash is `hash` (`Invited::hash`).
    pub fn used(&self, hash: &[u8]) -> bool {
        self.state.added.iter().any(|added| added.invite.0 == hash)
    }

    /// The cut state: per current member, by key, the seq up to which the group keeps its held messages, and the id
    /// there with its author's proof of a sealing of it. A commit carries the next cut, of the epoch it ends.
    pub fn cut(&self) -> &[Cut] {
        &self.state.cut
    }

    /// The epoch the current membership of the member with key `key` began in.
    pub fn joined(&self, key: &[u8]) -> Option<u64> {
        self.state.cut.iter().find(|r| r.key.0 == key).map(|r| r.joined)
    }

    fn epoch_context(&self) -> Result<([u8; 32], Vec<u8>)> {
        let service = service_key(&self.settings())?;
        Ok((service, [self.id(), &self.epoch().to_be_bytes(), &service].concat()))
    }

    pub fn capability(&self, provider: &SqliteProvider) -> Result<[u8; 32]> {
        let (_, context) = self.epoch_context()?;
        Ok(self.mls.export_secret(provider.crypto(), ADDRESS_LABEL, &context, 32)?.try_into().unwrap())
    }

    fn seal_entry(&self, provider: &SqliteProvider, inner: &[u8]) -> Result<Vec<u8>> {
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
    pub fn open_entry(&self, provider: &SqliteProvider, wire: &[u8]) -> Result<Vec<u8>> {
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
    fn guarded<T>(&mut self, provider: &SqliteProvider, keep: impl FnOnce(&Result<T>) -> bool, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
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
    pub fn commit(&mut self, provider: &SqliteProvider, session: &Session, change: Change) -> Result<Commit> {
        ensure!(self.state.posted.is_none(), "a commit is already pending");
        self.guarded(provider, Result::is_ok, |g| {
            // One staged but never saved, so never posted.
            g.mls.clear_pending_commit(provider.storage())?;
            let adds = change.add.iter().map(|bytes| key_package_in(provider, bytes)).collect::<Result<Vec<_>>>()?;
            let moved: Vec<Cut> = change.cut.iter().filter(|r| !g.state.cut.contains(r)).cloned().collect();
            let ended = ending(&g.state.cut, &moved);
            let aad = Aad { invite: change.invite, left: change.left, moved };
            g.mls.set_aad(serde_json::to_vec(&aad)?);
            let mut parameters = LeafNodeParameters::builder();
            if let Some(leaf) = &change.leaf {
                parameters = parameters.with_extensions(leaf_extensions(leaf)?);
            }
            let mut builder = g
                .mls
                .commit_builder()
                .consume_proposal_store(false)
                .force_self_update(change.add.is_empty() || change.leaf.is_some())
                .propose_adds(adds)
                .propose_removals(change.remove.into_iter().map(LeafNodeIndex::new));
            if !change.add.is_empty() {
                builder = builder.add_proposal(Proposal::PreSharedKey(Box::new(PreSharedKeyProposal::new(bind(provider, &ended)?))));
            }
            if let Some(settings) = &change.settings {
                builder = builder.propose_group_context_extensions(context_extensions(settings)?)?;
            }
            let builder = builder.leaf_node_parameters(parameters.build());
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
                    let sig = session.sign(&welcome_signed(&entry, &serde_json::to_vec(&ended)?, &welcome));
                    Ok(Admission { welcome, cut: ended.clone(), sig })
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
    pub fn cancel(&mut self, provider: &SqliteProvider) -> Result<()> {
        self.mls.clear_pending_commit(provider.storage())?;
        self.state.posted = None;
        self.save(provider)
    }

    /// Judges the next log entry in the current epoch: the first valid commit for it, whose signature verifies under its
    /// committer's leaf key, is to be applied (`apply`). What openmls does as it stages a commit leaves no trace.
    pub fn judge(&mut self, provider: &SqliteProvider, entry: &[u8]) -> Result<Verdict> {
        if !self.mls.is_active() {
            return Ok(Verdict::Skipped { reason: "removed from the group".into() });
        }
        let skipped = |error: anyhow::Error| Verdict::Skipped { reason: format!("{error:#}") };
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
                return Ok(Verdict::Skipped { reason: error.to_string() });
            }
            return Ok(Verdict::Commit { removes: false });
        }
        match Entry::parse(&entry) {
            Err(error) => Ok(skipped(error)),
            Ok(Entry { commit, sig }) => {
                let staged = self.guarded(provider, |_| false, |g| g.stage(provider, &commit, &sig))?;
                Ok(match staged {
                    Ok(Staged::Copied) => Verdict::Copied,
                    Ok(Staged::Commit(staged, _, _)) => Verdict::Commit { removes: staged.self_removed() },
                    Err(error) => skipped(error),
                })
            }
        }
    }

    /// Applies a commit `judge` found valid.
    pub fn apply(&mut self, provider: &SqliteProvider, entry: &[u8]) -> Result<Applied> {
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
            let Staged::Commit(staged, by, aad) = g.stage(provider, &commit, &sig)?? else { bail!("not a commit to apply") };
            let applied = observe(provider, &g.mls, &mut g.state, &staged, by, aad, false)?;
            g.state.posted = None;
            g.mls.clear_pending_commit(provider.storage())?;
            g.mls.merge_staged_commit(provider, *staged)?;
            g.merged(provider, applied)
        })
    }

    /// Stages a commit entry: the inner error is the entry's, which skips it; the outer is this session's own, as its
    /// storage failing, which judges nothing.
    fn stage(&mut self, provider: &SqliteProvider, commit: &[u8], sig: &[u8]) -> Result<Result<Staged>> {
        let parsed = (|| {
            let MlsMessageBodyIn::PrivateMessage(message) = parse::<MlsMessageIn>(commit)?.extract() else { bail!("not a commit") };
            ensure!(message.content_type() == ContentType::Commit, "not a commit");
            let aad: Aad = serde_json::from_slice(message.aad()).context("a commit's authenticated data")?;
            Ok((message, aad))
        })();
        let (message, aad) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => return Ok(Err(error)),
        };
        bind(provider, &ending(&self.state.cut, &aad.moved))?;
        let processed = match self.mls.process_message(provider, message) {
            Err(ProcessMessageError::StorageError(error)) => return Err(error.into()),
            Err(error) => return Ok(Err(error.into())),
            Ok(processed) => processed,
        };
        Ok((|| {
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
        })())
    }

    /// Records what a merged commit did: the added members' leaves, and the cut state of the new epoch: the cut, less
    /// the members it removed, with those it added at seq 0.
    fn merged(&mut self, provider: &SqliteProvider, mut applied: Applied) -> Result<Applied> {
        let members = self.members();
        for member in &mut applied.added {
            member.index = members.iter().find(|m| m.key == member.key).expect("an added member is in the tree").index;
        }
        let epoch = self.epoch();
        let mut cut: Vec<Cut> = applied.cut.iter().filter(|r| members.iter().any(|m| m.key == r.key.0)).cloned().collect();
        cut.extend(applied.added.iter().map(|m| Cut { key: Bytes(m.key.clone()), joined: epoch, ..Cut::default() }));
        cut.sort();
        self.state.cut = cut;
        self.state.ended = applied.cut.clone();
        self.save(provider)?;
        Ok(applied)
    }

    /// Seals a held message's plaintext, its header's JSON, as an application message of the current epoch, claiming
    /// in the clear which message it is, and signs the sealing: its MLS ciphertext, then that signature (`claim`). One
    /// whose sealing could be over `MAX_MESSAGE` fails before it uses any of the sender's keys.
    pub fn seal(&mut self, provider: &SqliteProvider, session: &Session, plaintext: &[u8]) -> Result<Vec<u8>> {
        let size = plaintext.len() + FRAMING;
        ensure!(size <= MAX_MESSAGE, "the message is {size} bytes, over the 16 MiB members take");
        let h = Header::open(plaintext)?;
        let claim = Ref { key: h.author, joined: h.joined, seq: h.seq, id: Bytes(held::id(plaintext).to_vec()), epoch: h.epoch };
        self.mls.set_aad(serde_json::to_vec(&claim)?);
        let bytes = self.mls.create_message(provider, &session.signer, plaintext)?.to_bytes()?;
        let sig = session.sign(&[SEALING, &held::sealing(self.id(), &claim, self.epoch(), &Sha256::digest(&bytes))].concat());
        Ok([bytes, sig].concat())
    }

    /// Decrypts a member's sealing of a held message, once its signature verifies (`claim`), and checks its header: of
    /// this group, its author the sender, the message its sealing claimed, of the membership its author had in the epoch
    /// it was sealed in, and within its final cut if that membership ended.
    pub fn open(&mut self, provider: &SqliteProvider, sealing: &[u8]) -> Result<Opened> {
        let claimed = claim(self.id(), sealing)?;
        let message = parse::<MlsMessageIn>(&sealing[..sealing.len() - 64])?.try_into_protocol_message()?;
        let processed = self.mls.process_message(provider, message)?;
        let epoch = processed.epoch().as_u64();
        let sender = processed.credential().serialized_content().to_vec();
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            bail!("not an application message")
        };
        let plaintext = message.into_bytes();
        let header = Header::open(&plaintext)?;
        let id = held::id(&plaintext);
        ensure!(header.group.0 == self.id(), "a held message of another group");
        let opened = Cut { key: header.author.clone(), joined: header.joined, seq: header.seq, id: Bytes(id.to_vec()), epoch: header.epoch, ..claimed.clone() };
        ensure!(header.author.0 == sender && opened == claimed, "a held message its sender did not author, or claimed otherwise");
        let cuts = if epoch == self.epoch() { &self.state.cut } else { &self.state.ended };
        let membership = cuts.iter().find(|r| r.key == header.author).context("a held message of no membership")?;
        ensure!(membership.joined == header.joined, "a held message of another membership of its author");
        let ended = self.joined(&header.author.0) != Some(header.joined);
        ensure!(!ended || header.seq <= membership.seq, "a held message past its membership's final cut");
        Ok(Opened { id, epoch, header, plaintext })
    }
}

/// A commit entry staged, or found to be from a copy of this session's state.
enum Staged {
    Commit(Box<StagedCommit>, LeafNodeIndex, Aad),
    Copied,
}

/// Records what a commit does, before it is merged.
fn observe(
    provider: &SqliteProvider,
    group: &MlsGroup,
    state: &mut State,
    staged: &StagedCommit,
    by: LeafNodeIndex,
    aad: Aad,
    own: bool,
) -> Result<Applied> {
    let removed: Vec<Member> =
        staged.remove_proposals().filter_map(|remove| Member::of(group, remove.remove_proposal().removed())).collect();
    let added: Vec<Member> = staged
        .add_proposals()
        .map(|add| {
            let leaf = add.add_proposal().key_package().leaf_node();
            // `index` is set once merged.
            Member { index: 0, key: leaf.signature_key().as_slice().to_vec(), leaf: leaf_of(leaf.extensions()).expect("`rules` proved an Add's leaf") }
        })
        .collect();
    let epoch = staged.epoch().as_u64();
    if let Some(invite) = &aad.invite {
        let invite = invite.hash(group.group_id().as_slice());
        let records = staged.add_proposals().enumerate().map(|(index, add)| {
            let key_package_ref = if own {
                state.posted.as_ref().unwrap().add_refs[index]
            } else {
                add.add_proposal().key_package().hash_ref(provider.crypto())?.as_slice().try_into()?
            };
            let member = Bytes(add.add_proposal().key_package().leaf_node().signature_key().as_slice().to_vec());
            Ok(Added { member, invite: invite.clone(), epoch, key_package_ref, at: now() })
        }).collect::<Result<Vec<_>>>()?;
        state.added.extend(records);
    }
    let cut = ending(&state.cut, &aad.moved);
    Ok(Applied {
        by: by.u32(),
        own,
        added,
        removed,
        gone: staged.self_removed(),
        updated: staged.update_path_leaf_node().is_some(),
        cut,
        admission: None,
    })
}

fn state_key(id: &[u8]) -> Vec<u8> {
    [b"group/".as_slice(), id].concat()
}

/// Whether a cut entry of the group `group` fits its seq: at seq 0 with nothing else, else with a 32-byte id and its
/// author's signature of the sealing it names (`SEALING`).
fn well_formed(group: &[u8], c: &Cut) -> bool {
    if c.seq == 0 {
        return *c == Cut { key: c.key.clone(), joined: c.joined, ..Cut::default() };
    }
    let named = Ref { key: c.key.clone(), joined: c.joined, seq: c.seq, id: c.id.clone(), epoch: c.epoch };
    c.id.0.len() == 32 && verify(&c.key.0, SEALING, &held::sealing(group, &named, c.sealed, &c.digest.0), &c.sig.0)
}

/// The whole cut of the epoch a commit ends: the cut state `cut`, with the entries the commit moves.
fn ending(cut: &[Cut], moved: &[Cut]) -> Vec<Cut> {
    cut.iter().map(|r| moved.iter().find(|m| m.key == r.key).unwrap_or(r).clone()).collect()
}

/// Makes SHA-256 of the JSON of `cut`, the whole cut of the epoch an Add ends, the secret of the PSK `CUT_PSK`, and
/// returns that PSK for the Add to propose. A member binds its cut state, moved as a commit says, before it stages the
/// commit, and a joiner its admission's cut before it opens its Welcome: a commit bound to another cut then fails its
/// confirmation tag, and a Welcome bound to another does not decrypt.
fn bind(provider: &SqliteProvider, cut: &[Cut]) -> Result<PreSharedKeyId> {
    let psk = PreSharedKeyId::new(CIPHERSUITE, provider.rand(), Psk::External(ExternalPsk::new(CUT_PSK.to_vec())))?;
    psk.store(provider, &Sha256::digest(serde_json::to_vec(cut)?))?;
    Ok(psk)
}

/// The app's rules on a commit, from MLS state alone and the commit, binding the committer too: changes inline only, of
/// the kinds we make: Adds, of KeyPackages that never expire, which name the invite they came in by, and none of a key
/// it removes, of sessions whose device is admitted or an admin unless the committer is an admin, with one PSK, by
/// which the commit binds the cut it ends (`bind`); Removes, of members that signed their leave unless the committer is
/// an admin; and settings, by an admin, that change only the admins and admitted devices, to keys each in its one form
/// (`is_key`), and leave an admin; the committer's key unchanged; every leaf it brings, by an Add or its update path,
/// proven (`proven`), and no two members' leaves naming one iroh key once it applies; and cut entries that each name a
/// member of the cut state `cut` once, by key, in order, at its membership, past its entry there by at most
/// `MAX_CUT_STEP`, each its member's proof of a sealing in the epoch the commit ends.
fn rules(group: &MlsGroup, staged: &StagedCommit, by: LeafNodeIndex, aad: &Aad, cut: &[Cut]) -> Result<()> {
    let settings = settings_of(group.extensions())?;
    let committer = Member::of(group, by).context("not a member")?;
    let admin = admin(&settings, &committer.key, Some(&committer.leaf));
    let removed: Vec<Vec<u8>> = staged.remove_proposals().filter_map(|r| group.member_at(r.remove_proposal().removed())).map(|m| m.signature_key).collect();
    // The leaves once it applies: of the members it keeps, its committer's as its update path leaves it, and its Adds'.
    let kept = group.members().filter(|m| m.index != by && !removed.contains(&m.signature_key));
    let mut leaves: Vec<Leaf> = kept.filter_map(|m| Member::of(group, m.index)).map(|m| m.leaf).collect();
    for proposal in staged.queued_proposals() {
        ensure!(proposal.proposal_or_ref_type() == ProposalOrRefType::Proposal, "a proposal by reference");
        match proposal.proposal() {
            Proposal::Add(add) => {
                ensure!(*add.key_package().life_time() == Lifetime::init(0, u64::MAX), "a KeyPackage with a bounded lifetime");
                let leaf = add.key_package().leaf_node();
                let key = leaf.signature_key().as_slice();
                ensure!(names_its_key(leaf.credential(), key), "a credential that names another key");
                ensure!(!removed.iter().any(|removed| removed == key), "a commit that adds a key it removes");
                let leaf = proven(leaf)?;
                ensure!(admin || admits(&settings, &leaf), "an Add by a member that is no admin, of a session whose device is neither admitted nor an admin");
                leaves.push(leaf);
            }
            Proposal::Remove(remove) => {
                let key = group.member_at(remove.removed()).context("a Remove of no member")?.signature_key;
                let signed = aad.left.iter().any(|sig| left(group.group_id().as_slice(), cut, &key, &sig.0));
                ensure!(admin || signed, "a Remove by a member that is no admin, of a member that did not sign its leave");
            }
            Proposal::GroupContextExtensions(_) => {
                ensure!(admin, "a settings change by a member that is no admin");
                let new = settings_of(staged.group_context().extensions())?;
                ensure!(*staged.group_context().extensions() == context_extensions(&new)?, "a settings change with other context extensions");
                let fixed = |s: &Settings| (s.protocol, s.carry, s.update, s.membership.clone());
                ensure!(fixed(&new) == fixed(&settings), "a settings change of more than the admins and admitted devices");
                ensure!(!new.admins.is_empty(), "a settings change that leaves the group no admin");
                ensure!(new.admins.iter().chain(&new.admitted).all(|key| is_key(&key.0)), "a settings change with a key that is neither Ed25519 nor compressed P-256");
            }
            Proposal::PreSharedKey(_) => {}
            other => bail!("a {:?} proposal", other.proposal_type()),
        }
    }
    ensure!(aad.invite.is_some() == staged.add_proposals().next().is_some(), "an Add that names no invite, or an invite with no Add");
    ensure!(aad.moved.windows(2).all(|pair| pair[0].key < pair[1].key), "a cut that does not name each member once, in order");
    for new in &aad.moved {
        let old = cut.iter().find(|old| old.key == new.key && old.joined == new.joined).context("a cut that names no member at its membership")?;
        ensure!(new.seq > old.seq, "a cut below the last");
        ensure!(new.seq - old.seq <= MAX_CUT_STEP, "a cut too far past the last");
        ensure!(new.sealed == group.epoch().as_u64(), "a cut of a sealing of another epoch than the one the commit ends");
        ensure!(well_formed(group.group_id().as_slice(), new), "a cut its member did not sign");
    }
    match staged.update_path_leaf_node() {
        Some(leaf) => {
            let member = group.member_at(by).context("not a member")?;
            ensure!(leaf.signature_key().as_slice() == member.signature_key, "an update changed the member's key");
            ensure!(names_its_key(leaf.credential(), &member.signature_key), "a credential that names another key");
            leaves.push(proven(leaf)?);
        }
        None => leaves.push(committer.leaf),
    }
    let irohs: BTreeSet<&Bytes> = leaves.iter().map(|leaf| &leaf.key).collect();
    ensure!(irohs.len() == leaves.len(), "a commit after which two leaves name one iroh key");
    // The one PSK an Add's joiner can join by is `bind`'s: members hold no other external PSK, and a Welcome takes no
    // resumption PSK of the kind a commit may propose.
    ensure!(staged.psk_proposals().count() == usize::from(staged.add_proposals().next().is_some()), "an Add that does not bind the cut it ends, or a PSK with no Add");
    Ok(())
}

/// Whether a member's credential names its leaf's signature key, as each must: a held message's sender is known by its
/// credential, which openmls keeps of past epochs' members too.
fn names_its_key(credential: &Credential, key: &[u8]) -> bool {
    credential.serialized_content() == key
}

/// Checks an Ed25519 signature by `key` over `context` ‖ `bytes`.
pub fn verify(key: &[u8], context: &[u8], bytes: &[u8], sig: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (<[u8; 32]>::try_from(key), ed25519_dalek::Signature::from_slice(sig)) else {
        return false;
    };
    ed25519_dalek::VerifyingKey::from_bytes(&key).is_ok_and(|key| key.verify_strict(&[context, bytes].concat(), &sig).is_ok())
}

#[cfg(test)]
#[path = "group_tests.rs"]
pub(crate) mod tests;
