//! Sessions and groups on openmls, protocol version 2 (PROTOCOL.md, Commits).

use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use lmk_proto::Bytes;
use lmk_proto::clock::now;
use lmk_proto::group::{Control, Credential, How, LEAF_EXTENSION, Leaf, PROTOCOL, RENAME_REVISION, SETTINGS_EXTENSION, Settings, held_by_type};
use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::provider::Provider;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// How long a removed member's messages are still taken after its removal was applied, in milliseconds.
pub const REMOVED_GRACE: u64 = 5 * 60 * 1000;
/// The largest message ciphertext taken, and sent.
pub const MAX_MESSAGE: usize = 1 << 20;
/// More than an application message's ciphertext adds to its payload and authenticated data.
const FRAMING: usize = 1024;

/// How long this client keeps ended epochs' keys: a count cap, and an age from when it applied the commit that began each.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    pub epochs: usize,
    pub age: Duration,
}

impl Default for Window {
    fn default() -> Self {
        Window { epochs: 256, age: Duration::from_secs(7 * 24 * 3600) }
    }
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

fn join_config(window: Window) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(window.epochs)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(1000, 100_000))
        .build()
}

/// Our credential inside an MLS credential, if it is one.
pub fn credential_of(credential: &openmls::prelude::Credential) -> Option<Credential> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    serde_json::from_slice(basic.identity()).ok()
}

/// The epoch an MLS message was sent in, which its header shows.
pub fn epoch_of(bytes: &[u8]) -> Result<u64> {
    Ok(parse::<MlsMessageIn>(bytes)?.try_into_protocol_message()?.epoch().as_u64())
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
        let key = ed25519_dalek::SigningKey::from_bytes(&crate::random());
        let signer = SignatureKeyPair::from_raw(SignatureScheme::ED25519, key.to_bytes().to_vec(), key.verifying_key().to_bytes().to_vec());
        Self::create_with(provider, signer, name, leaf)
    }

    /// A session with the given MLS key: a device's own (`Device::signer`).
    pub fn create_with<P: Provider>(provider: &P, signer: SignatureKeyPair, name: &str, leaf: Leaf) -> Result<Self> {
        signer.store(provider.storage())?;
        let credential = Credential { name: name.into(), key: signer.public().into(), identity: None };
        let session = Session { credential, signer, leaf };
        session.save(provider)?;
        Ok(session)
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

/// The leaf data a KeyPackage carries.
pub fn key_package_leaf<P: Provider>(provider: &P, key_package: &[u8]) -> Result<Leaf> {
    leaf_of(key_package_in(provider, key_package)?.leaf_node().extensions()).context("a KeyPackage without our leaf data")
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
    /// For a removal in a group with a kind's log: the position in the kind's order where the log ends, carried in the
    /// commit's authenticated data.
    pub end: Option<u64>,
    /// Leaf indices.
    pub remove: Vec<u32>,
    pub settings: Option<Settings>,
    pub leaf: Option<Leaf>,
    /// A new name in the committer's credential, which only `Group::renames` allows.
    pub name: Option<String>,
}

/// A commit's authenticated data: how the members it adds came in, and where the kind's log ends.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Aad {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    how: Option<How>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invite: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    end: Option<u64>,
}

/// An application message's authenticated data: a payload its sender marks as held.
#[derive(Default, Serialize, Deserialize)]
struct Marks {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    held: bool,
}

/// A message sealed under an epoch whose keys this session does not hold: one it never was in, or one past its key
/// window.
#[derive(Debug)]
pub struct Unheld;

impl std::fmt::Display for Unheld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sealed under an epoch whose keys this session does not hold")
    }
}

impl std::error::Error for Unheld {}

/// A message from a member removed more than 5 minutes before it first reached this session.
#[derive(Debug)]
pub struct Removed;

impl std::fmt::Display for Removed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("from a member removed more than 5 minutes before")
    }
}

impl std::error::Error for Removed {}

/// A commit to post, and for an add, the Welcome to send once the log has taken it.
pub struct Commit {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
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

/// What a log entry did.
#[derive(Clone, Debug)]
pub enum Applied {
    /// The first valid commit for this group's epoch: it is now applied.
    Commit {
        /// The committer's leaf index, in the epoch it committed in.
        by: u32,
        /// This session's own commit.
        own: bool,
        /// This session's pending commit lost the race and was cleared: redo its change.
        lost: bool,
        /// As their KeyPackages show them; `index` is their new leaf.
        added: Vec<Member>,
        how: Option<How>,
        /// SHA-256 of the secret of the invite the added member came in by.
        invite: Option<Bytes>,
        /// Where the kind's log ends, as the commit says.
        end: Option<u64>,
        removed: Vec<Member>,
        settings: bool,
        /// This session was removed.
        gone: bool,
    },
    Skipped {
        reason: String,
        /// This session's own commit was invalid and was cleared.
        lost: bool,
    },
}

/// A member's message, decrypted and verified.
#[derive(Clone, Debug)]
pub struct Opened {
    /// SHA-256 of the ciphertext.
    pub id: [u8; 32],
    pub epoch: u64,
    /// The sender's leaf index in that epoch.
    pub index: u32,
    /// The sender's leaf index now, if it is still a member.
    pub current: Option<u32>,
    /// The sender's signature key.
    pub key: Vec<u8>,
    pub sender: Credential,
    pub payload: serde_json::Value,
    /// Whether members hold it (see `seal`).
    pub held: bool,
}

/// Who added whom, as the log showed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Added {
    pub member: Credential,
    pub by: Credential,
    pub how: Option<How>,
    /// SHA-256 of the secret of the invite it came in by.
    pub invite: Option<Bytes>,
    /// The epoch the add started.
    pub epoch: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    /// The bytes of this session's pending commit, as posted.
    posted: Option<Bytes>,
    /// Its authenticated data.
    aad: Aad,
    window: Window,
    joined: u64,
    /// Removed members' keys, with when their removal was applied.
    removed: Vec<(Bytes, u64)>,
    added: Vec<Added>,
    /// When the current epoch began here, and the ended epochs before it, oldest first, in milliseconds, as far back as
    /// this client recorded them.
    #[serde(default)]
    began: Vec<u64>,
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
    pub fn create<P: Provider>(provider: &P, session: &Session, settings: &Settings, window: Window) -> Result<Self> {
        ensure!(settings.protocol == PROTOCOL, "settings name protocol {}", settings.protocol);
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities())
            .with_group_context_extensions(context_extensions(settings)?)
            .with_leaf_node_extensions(leaf_extensions(&session.leaf)?)?
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(window.epochs)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(1000, 100_000))
            .lifetime(creator_lifetime())
            .build();
        let id = GroupId::from_slice(&crate::random::<16>());
        let mls = MlsGroup::new_with_group_id(provider, &session.signer, &config, id, session.with_key())?;
        let group = Group { state: State { window, joined: mls.epoch().as_u64(), began: vec![now()], ..State::default() }, mls };
        group.save(provider)?;
        Ok(group)
    }

    /// Joins from a Welcome; refuses a group that runs another protocol version.
    pub fn join<P: Provider>(provider: &P, welcome: &[u8], window: Window) -> Result<Self> {
        let MlsMessageBodyIn::Welcome(welcome) = parse::<MlsMessageIn>(welcome)?.extract() else {
            bail!("not a Welcome")
        };
        let staged = StagedWelcome::build_from_welcome(provider, &join_config(window), welcome)?
            .skip_lifetime_validation()
            .build()?;
        let settings = settings_of(staged.group_context().extensions())?;
        ensure!(
            settings.protocol == PROTOCOL,
            "this group runs protocol {}; this client runs {PROTOCOL}",
            settings.protocol
        );
        let mls = staged.into_group(provider)?;
        let group = Group { state: State { window, joined: mls.epoch().as_u64(), began: vec![now()], ..State::default() }, mls };
        group.save(provider)?;
        Ok(group)
    }

    pub fn load<P: Provider>(provider: &P, id: &[u8]) -> Result<Self> {
        let mls = MlsGroup::load(provider.storage(), &GroupId::from_slice(id))?.context("no such group")?;
        let state = serde_json::from_slice(&provider.get(&state_key(id))?.context("no state for the group")?)?;
        Ok(Group { mls, state })
    }

    fn save<P: Provider>(&self, provider: &P) -> Result<()> {
        provider.put(&state_key(self.id()), &serde_json::to_vec(&self.state)?)
    }

    /// Deletes the group's state, once this session has left it.
    pub fn delete<P: Provider>(mut self, provider: &P) -> Result<()> {
        self.mls.delete(provider.storage())?;
        provider.delete(&state_key(self.id()))
    }

    pub fn id(&self) -> &[u8] {
        self.mls.group_id().as_slice()
    }

    pub fn epoch(&self) -> u64 {
        self.mls.epoch().as_u64()
    }

    /// The epoch this session joined at.
    pub fn joined(&self) -> u64 {
        self.state.joined
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

    pub fn pending(&self) -> bool {
        self.state.posted.is_some()
    }

    /// The bytes of the pending commit, to post again when it is not known whether the log took them.
    pub fn posted(&self) -> Option<&[u8]> {
        self.state.posted.as_ref().map(|posted| posted.0.as_slice())
    }

    pub fn epoch_authenticator(&self) -> &[u8] {
        self.mls.epoch_authenticator().as_slice()
    }

    pub fn members(&self) -> Vec<Member> {
        self.mls.members().filter_map(|member| Member::of(&self.mls, member.index)).collect()
    }

    /// Whether a member may rename itself in an update: every member's leaf names `RENAME_REVISION` or a later one.
    pub fn renames(&self) -> bool {
        renames(&self.mls)
    }

    /// Who added whom, as the log showed it since this session joined.
    pub fn added(&self) -> &[Added] {
        &self.state.added
    }

    /// Whether a commit this session applied added a member by the invite whose secret hashes to `hash`.
    pub fn used(&self, hash: &[u8]) -> bool {
        self.state.added.iter().any(|added| added.invite.as_ref().is_some_and(|invite| invite.0 == hash))
    }

    /// 16 bytes the current epoch's exporter secret derives under `label`: the same for every member of the epoch, and
    /// unknown to all others.
    pub fn exported<P: Provider>(&self, provider: &P, label: &str) -> Result<[u8; 16]> {
        let secret = self.mls.export_secret(provider.crypto(), label, &[], 16)?;
        Ok(secret.try_into().expect("16 bytes"))
    }

    /// Builds a commit and keeps it pending, with its bytes saved: post them next, then read the log.
    pub fn commit<P: Provider>(&mut self, provider: &P, session: &Session, change: Change) -> Result<Commit> {
        ensure!(self.state.posted.is_none(), "a commit is already pending");
        // One staged but never saved, so never posted.
        self.mls.clear_pending_commit(provider.storage())?;
        let adds = change.add.iter().map(|bytes| key_package_in(provider, bytes)).collect::<Result<Vec<_>>>()?;
        let aad = Aad { how: change.how, invite: change.invite, end: change.end };
        if aad.how.is_some() || aad.end.is_some() {
            self.mls.set_aad(serde_json::to_vec(&aad)?);
        }
        let mut parameters = LeafNodeParameters::builder();
        if let Some(leaf) = &change.leaf {
            parameters = parameters.with_extensions(leaf_extensions(leaf)?);
        }
        if let Some(name) = &change.name {
            let own = self.mls.own_leaf_node().context("no leaf of its own")?;
            let credential = Credential { name: name.clone(), ..credential_of(own.credential()).context("not a letmeknow credential")? };
            parameters = parameters.with_credential_with_key(CredentialWithKey {
                credential: BasicCredential::new(serde_json::to_vec(&credential)?).into(),
                signature_key: session.signer.public().into(),
            });
        }
        let mut builder = self
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
        if let Err(error) = rules(&self.mls, self.mls.pending_commit().unwrap(), self.mls.own_leaf_index()) {
            self.mls.clear_pending_commit(provider.storage())?;
            return Err(error);
        }
        let (commit, welcome, _) = bundle.into_messages();
        let commit = commit.to_bytes()?;
        self.state.posted = Some(Bytes(commit.clone()));
        self.state.aad = aad;
        self.save(provider)?;
        Ok(Commit { commit, welcome: welcome.map(|welcome| welcome.to_bytes()).transpose()? })
    }

    /// Drops the pending commit, when the log refused it.
    pub fn cancel<P: Provider>(&mut self, provider: &P) -> Result<()> {
        self.mls.clear_pending_commit(provider.storage())?;
        self.state.posted = None;
        self.save(provider)
    }

    /// Applies the next log entry: the first valid commit for this epoch; any other entry is skipped.
    /// `now` is milliseconds since the Unix epoch.
    pub fn apply<P: Provider>(&mut self, provider: &P, entry: &[u8], now: u64) -> Result<Applied> {
        if !self.mls.is_active() {
            return Ok(Applied::Skipped { reason: "removed from the group".into(), lost: false });
        }
        if self.state.posted.as_ref().is_some_and(|posted| posted.0 == entry) {
            self.state.posted = None;
            let by = self.mls.own_leaf_index();
            let staged = self.mls.pending_commit().expect("a posted commit is pending");
            if let Err(error) = rules(&self.mls, staged, by) {
                self.mls.clear_pending_commit(provider.storage())?;
                self.save(provider)?;
                return Ok(Applied::Skipped { reason: error.to_string(), lost: true });
            }
            let aad = self.state.aad.clone();
            let applied = observe(&self.mls, &mut self.state, staged, by, aad, true, false, now);
            self.mls.merge_pending_commit(provider)?;
            return self.merged(provider, applied);
        }
        let (staged, by, aad) = match self.stage(provider, entry) {
            Ok(staged) => staged,
            Err(error) => return Ok(Applied::Skipped { reason: format!("{error:#}"), lost: false }),
        };
        let lost = self.state.posted.take().is_some();
        self.mls.clear_pending_commit(provider.storage())?;
        let applied = observe(&self.mls, &mut self.state, &staged, by, aad, false, lost, now);
        self.mls.merge_staged_commit(provider, staged)?;
        self.merged(provider, applied)
    }

    fn stage<P: Provider>(
        &mut self,
        provider: &P,
        entry: &[u8],
    ) -> Result<(StagedCommit, LeafNodeIndex, Aad)> {
        let message = parse::<MlsMessageIn>(entry)?.try_into_protocol_message()?;
        ensure!(message.content_type() == ContentType::Commit, "not a commit");
        let processed = self.mls.process_message(provider, message)?;
        let aad = serde_json::from_slice::<Aad>(processed.aad()).unwrap_or_default();
        let Sender::Member(by) = *processed.sender() else { bail!("not from a member") };
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            bail!("not a commit from another member")
        };
        rules(&self.mls, &staged, by)?;
        Ok((*staged, by, aad))
    }

    fn merged<P: Provider>(&mut self, provider: &P, mut applied: Applied) -> Result<Applied> {
        if let Applied::Commit { added, .. } = &mut applied {
            let members = self.members();
            for member in added {
                member.index = members.iter().find(|m| m.key == member.key).map_or(0, |m| m.index);
            }
        }
        self.state.began.push(now());
        self.expire(provider)?;
        self.save(provider)?;
        Ok(applied)
    }

    /// Drops ended epochs' keys beyond this client's window. Applying a commit does this too; call it now and then.
    /// openmls dates epochs by the system clock, so the epochs within the window are also counted by the dates
    /// recorded here, which a simulator's clock decides.
    pub fn expire<P: Provider>(&mut self, provider: &P) -> Result<()> {
        let window = self.state.window;
        let since = now().saturating_sub(window.age.as_millis() as u64);
        let kept = match self.state.began.split_last() {
            Some((current, _)) if *current < since => 0,
            Some((_, ended)) => ended.iter().rev().position(|began| *began < since).unwrap_or(window.epochs),
            None => window.epochs,
        }
        .min(window.epochs);
        self.mls.delete_past_epoch_secrets(provider, PastEpochDeletion::older_than_duration(window.age).max_past_epochs(kept))?;
        let began = &mut self.state.began;
        began.drain(..began.len().saturating_sub(kept + 1));
        Ok(())
    }

    pub fn set_window<P: Provider>(&mut self, provider: &P, window: Window) -> Result<()> {
        self.state.window = window;
        // First: openmls's own resize, on a smaller cap, keeps the oldest epochs rather than the newest.
        self.expire(provider)?;
        self.mls.set_configuration(provider.storage(), &join_config(window))?;
        self.save(provider)
    }

    /// Seals a payload as an application message; returns its id and ciphertext. A payload members hold that is not
    /// held by its type is marked so in the message's authenticated data. One whose ciphertext could be over
    /// `MAX_MESSAGE` fails before it uses any of the sender's keys.
    pub fn seal<P: Provider>(
        &mut self,
        provider: &P,
        session: &Session,
        payload: &serde_json::Value,
        held: bool,
    ) -> Result<([u8; 32], Vec<u8>)> {
        let aad = if held && !held_by_type(payload) { serde_json::to_vec(&Marks { held })? } else { Vec::new() };
        let payload = serde_json::to_vec(payload)?;
        let size = payload.len() + aad.len() + FRAMING;
        ensure!(size <= MAX_MESSAGE, "the message is {size} bytes, over the 1 MiB members take");
        self.mls.set_aad(aad);
        let message = self.mls.create_message(provider, &session.signer, &payload)?.to_bytes()?;
        Ok((Sha256::digest(&message).into(), message))
    }

    /// Asks the others to commit this session's removal.
    pub fn leave<P: Provider>(&mut self, provider: &P, session: &Session) -> Result<([u8; 32], Vec<u8>)> {
        self.seal(provider, session, &serde_json::to_value(Control::Leave)?, true)
    }

    /// Decrypts and verifies a member's message. `now` (milliseconds) is when it first reached this session; a removed
    /// member's message that first reached it more than 5 minutes after the removal fails with `Removed`. A message
    /// under an epoch whose keys this session does not hold fails with `Unheld`.
    pub fn open<P: Provider>(&mut self, provider: &P, bytes: &[u8], now: u64) -> Result<Opened> {
        let message = parse::<MlsMessageIn>(bytes)?.try_into_protocol_message()?;
        ensure!(message.content_type() == ContentType::Application, "not an application message");
        let unheld = message.epoch() < self.mls.epoch();
        let processed = match self.mls.process_message(provider, message) {
            Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
            ))) if unheld => return Err(Unheld.into()),
            processed => processed?,
        };
        let epoch = processed.epoch().as_u64();
        let marks = serde_json::from_slice::<Marks>(processed.aad()).unwrap_or_default();
        let sender = credential_of(processed.credential()).context("the sender has no letmeknow credential")?;
        let Sender::Member(index) = *processed.sender() else { bail!("not from a member") };
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            bail!("not an application message")
        };
        let current = self.members().into_iter().find(|member| member.key == sender.key.0);
        let mut key = current.as_ref().map(|member| member.key.clone()).unwrap_or_default();
        if current.is_none()
            && let Some((removed, at)) = self.state.removed.iter().rev().find(|(key, _)| *key == sender.key)
        {
            if now > at + REMOVED_GRACE {
                return Err(Removed.into());
            }
            key = removed.0.clone();
        }
        let payload: serde_json::Value = serde_json::from_slice(&message.into_bytes())?;
        ensure!(payload["type"].is_string(), "a payload without a type");
        Ok(Opened {
            held: marks.held || held_by_type(&payload),
            id: Sha256::digest(bytes).into(),
            epoch,
            index: index.u32(),
            current: current.map(|member| member.index),
            key,
            sender,
            payload,
        })
    }
}

/// Records what a commit does, before it is merged.
#[allow(clippy::too_many_arguments)]
fn observe(
    group: &MlsGroup,
    state: &mut State,
    staged: &StagedCommit,
    by: LeafNodeIndex,
    aad: Aad,
    own: bool,
    lost: bool,
    now: u64,
) -> Applied {
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
        let credentials = added.iter().filter_map(|member| member.credential.clone());
        state.added.extend(credentials.map(|member| Added { member, by: committer.clone(), how: aad.how.clone(), invite: aad.invite.clone(), epoch }));
    }
    state.removed.extend(removed.iter().map(|member| (Bytes(member.key.clone()), now)));
    Applied::Commit {
        by: by.u32(),
        own,
        lost,
        added,
        how: aad.how,
        invite: aad.invite,
        end: aad.end,
        removed,
        settings: staged.queued_proposals().any(|p| matches!(p.proposal(), Proposal::GroupContextExtensions(_))),
        gone: staged.self_removed(),
    }
}

fn state_key(id: &[u8]) -> Vec<u8> {
    [b"group/".as_slice(), id].concat()
}

/// The app's rules on a commit, from MLS state alone, binding the committer too: changes inline only, of the kinds we
/// make; added members whose credentials name their own keys; settings that parse, at protocol 1, with the kind
/// unchanged; and no update of the committer's leaf that changes its credential, but its name where `renames` allows.
fn rules(group: &MlsGroup, staged: &StagedCommit, by: LeafNodeIndex) -> Result<()> {
    for proposal in staged.queued_proposals() {
        ensure!(proposal.proposal_or_ref_type() == ProposalOrRefType::Proposal, "a proposal by reference");
        match proposal.proposal() {
            Proposal::Add(add) => _ = leaf_credential(add.key_package().leaf_node())?,
            Proposal::Remove(_) | Proposal::GroupContextExtensions(_) => {}
            other => bail!("a {:?} proposal", other.proposal_type()),
        }
    }
    let old = settings_of(group.extensions())?;
    let new = settings_of(staged.group_context().extensions())?;
    ensure!(new.protocol == PROTOCOL, "settings name protocol {}", new.protocol);
    ensure!(new.kind == old.kind, "the kind changed");
    if let Some(leaf) = staged.update_path_leaf_node() {
        let before = group.member_at(by).and_then(|member| credential_of(&member.credential));
        let after = credential_of(leaf.credential());
        let renamed = before.clone().zip(after.clone()).is_some_and(|(before, after)| Credential { name: after.name.clone(), ..before } == after);
        ensure!(before == after || renamed && renames(group), "an update changed the member's credential");
    }
    Ok(())
}

fn renames(group: &MlsGroup) -> bool {
    group.members().all(|member| Member::of(group, member.index).and_then(|m| m.leaf).is_some_and(|leaf| leaf.revision >= RENAME_REVISION))
}

#[cfg(test)]
#[path = "group_tests.rs"]
pub(crate) mod tests;
