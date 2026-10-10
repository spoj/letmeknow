//! Sessions and groups on openmls, protocol version 3: a group's log of commits and held messages' entries
//! (`lmk_proto::entry`), judged strictly in order, and the messages its members seal and open.

use anyhow::{Context, Result, bail, ensure};
use lmk_proto::Bytes;
use lmk_proto::clock::now;
use lmk_proto::entry::{Entry, signed};
use lmk_proto::group::{Control, Credential, How, LEAF_EXTENSION, Leaf, PROTOCOL, SETTINGS_EXTENSION, Settings};
use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;
use openmls_traits::types::HashType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::provider::Provider;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// The largest message ciphertext taken, and sent.
pub const MAX_MESSAGE: usize = 1 << 20;
/// More than an application message's ciphertext adds to its payload and authenticated data.
pub const FRAMING: usize = 1024;
/// The exporter label of the key that MACs an epoch's message entries.
const ENTRY_LABEL: &str = "letmeknow entry";

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

/// Keys of the current and the prior epoch only.
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

/// What an application message's clear header shows: the epoch it was sealed in, and whether its sender marked it
/// live.
pub fn header(bytes: &[u8]) -> Result<(u64, bool)> {
    let MlsMessageBodyIn::PrivateMessage(message) = parse::<MlsMessageIn>(bytes)?.extract() else { bail!("not a private message") };
    let marks = serde_json::from_slice::<Marks>(message.aad()).unwrap_or_default();
    Ok((message.epoch().as_u64(), marks.live))
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
        let session = Self::with_signer(provider, signer, name, leaf)?;
        session.save(provider)?;
        Ok(session)
    }

    /// A member with the given MLS key beside the provider's own session, which it does not replace: a device's key in
    /// one identity's devices group.
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
    /// Leaf indices.
    pub remove: Vec<u32>,
    pub settings: Option<Settings>,
    pub leaf: Option<Leaf>,
    /// A new name in the committer's credential.
    pub name: Option<String>,
}

/// A commit's authenticated data: how the members it adds came in.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Aad {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    how: Option<How>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invite: Option<Bytes>,
}

/// An application message's authenticated data, in the clear: a live payload is marked so; a held one has an entry.
#[derive(Default, Serialize, Deserialize)]
struct Marks {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    live: bool,
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

/// A commit's log entry, to post, with the Welcome it carries if it adds members.
pub struct Commit {
    pub entry: Vec<u8>,
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

/// A log entry as judged in the current epoch, before anything of it is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The first valid commit for this epoch: apply it next.
    Commit {
        /// It removes this session.
        removes: bool,
    },
    /// A message entry whose MAC verifies under this epoch.
    Message { id: [u8; 32] },
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
    /// SHA-256 of the secret of the invite the added member came in by.
    pub invite: Option<Bytes>,
    pub removed: Vec<Member>,
    pub settings: bool,
    /// This session was removed.
    pub gone: bool,
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
    pub sender: Credential,
    pub payload: serde_json::Value,
    /// A live payload, not held.
    pub live: bool,
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
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    /// This session's pending commit's whole entry, as posted.
    posted: Option<Bytes>,
    /// Its authenticated data.
    aad: Aad,
    joined: u64,
    added: Vec<Added>,
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
        let group = Group { state: State { joined: mls.epoch().as_u64(), ..State::default() }, mls };
        group.save(provider)?;
        Ok(group)
    }

    /// Joins from a Welcome; refuses a group that runs another protocol version.
    pub fn join<P: Provider>(provider: &P, welcome: &[u8]) -> Result<Self> {
        let MlsMessageBodyIn::Welcome(welcome) = parse::<MlsMessageIn>(welcome)?.extract() else {
            bail!("not a Welcome")
        };
        let staged = StagedWelcome::build_from_welcome(provider, &join_config(), welcome)?
            .skip_lifetime_validation()
            .build()?;
        let settings = settings_of(staged.group_context().extensions())?;
        ensure!(
            settings.protocol == PROTOCOL,
            "this group runs protocol {}; this client runs {PROTOCOL}",
            settings.protocol
        );
        let mls = staged.into_group(provider)?;
        let group = Group { state: State { joined: mls.epoch().as_u64(), ..State::default() }, mls };
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

    /// The entry of the pending commit, to post again until the log shows it or another commit wins.
    pub fn posted(&self) -> Option<&[u8]> {
        self.state.posted.as_ref().map(|posted| posted.0.as_slice())
    }

    pub fn epoch_authenticator(&self) -> &[u8] {
        self.mls.epoch_authenticator().as_slice()
    }

    pub fn members(&self) -> Vec<Member> {
        self.mls.members().filter_map(|member| Member::of(&self.mls, member.index)).collect()
    }

    /// Whether a member's leaf is still the one this KeyPackage brought: it has not updated since its Add.
    pub fn unchanged<P: Provider>(&self, provider: &P, key_package: &[u8]) -> Result<bool> {
        let key_package = key_package_in(provider, key_package)?;
        let leaf = key_package.leaf_node();
        let Some(member) = self.mls.members().find(|m| m.signature_key == leaf.signature_key().as_slice()) else { return Ok(false) };
        Ok(self.mls.public_group().leaf(member.index).is_some_and(|ours| ours.encryption_key() == leaf.encryption_key()))
    }

    /// Who added whom, as the log showed it since this session joined.
    pub fn added(&self) -> &[Added] {
        &self.state.added
    }

    /// Whether a commit this session applied added a member by the invite whose secret hashes to `hash`.
    pub fn used(&self, hash: &[u8]) -> bool {
        self.state.added.iter().any(|added| added.invite.as_ref().is_some_and(|invite| invite.0 == hash))
    }

    /// The MAC of a message entry naming `id` in the current epoch.
    fn mac<P: Provider>(&self, provider: &P, id: &[u8]) -> Result<[u8; 32]> {
        let key = self.mls.export_secret(provider.crypto(), ENTRY_LABEL, &[], 32)?;
        Ok(provider.crypto().hmac(HashType::Sha2_256, &key, id)?.as_slice().try_into()?)
    }

    /// The log entry of a message sealed in the current epoch.
    pub fn entry<P: Provider>(&self, provider: &P, id: &[u8; 32]) -> Result<Vec<u8>> {
        Ok(Entry::Message { id: *id, mac: self.mac(provider, id)? }.encode())
    }

    /// Runs `f` under a savepoint, kept if `keep` says so of its result; else rolled back, and the group reloaded from
    /// storage, so that nothing of it is left.
    fn guarded<P: Provider, T>(&mut self, provider: &P, keep: impl FnOnce(&Result<T>) -> bool, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        provider.savepoint()?;
        let result = f(self);
        if keep(&result) {
            provider.release()?;
        } else {
            provider.rollback_to()?;
            let id = self.mls.group_id().clone();
            self.mls = MlsGroup::load(provider.storage(), &id)?.context("the group is gone from storage")?;
        }
        result
    }

    /// Builds a commit and keeps it pending, with its whole entry saved: post that next, then read the log.
    pub fn commit<P: Provider>(&mut self, provider: &P, session: &Session, change: Change) -> Result<Commit> {
        ensure!(self.state.posted.is_none(), "a commit is already pending");
        // One staged but never saved, so never posted.
        self.mls.clear_pending_commit(provider.storage())?;
        let adds = change.add.iter().map(|bytes| key_package_in(provider, bytes)).collect::<Result<Vec<_>>>()?;
        let aad = Aad { how: change.how, invite: change.invite };
        if aad.how.is_some() {
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
        if let Err(error) = rules(&self.mls, self.mls.pending_commit().unwrap(), self.mls.own_leaf_index(), &aad) {
            self.mls.clear_pending_commit(provider.storage())?;
            return Err(error);
        }
        let (commit, welcome, _) = bundle.into_messages();
        let commit = commit.to_bytes()?;
        let welcome = welcome.map(|welcome| welcome.to_bytes()).transpose()?;
        let sig = session.signer.sign(&signed(&commit, welcome.as_deref())).map_err(|error| anyhow::anyhow!("signing: {error:?}"))?;
        let entry = Entry::Commit { commit, welcome: welcome.clone(), sig }.encode();
        self.state.posted = Some(Bytes(entry.clone()));
        self.state.aad = aad;
        self.save(provider)?;
        Ok(Commit { entry, welcome })
    }

    /// Drops the pending commit, when the log refused it.
    pub fn cancel<P: Provider>(&mut self, provider: &P) -> Result<()> {
        self.mls.clear_pending_commit(provider.storage())?;
        self.state.posted = None;
        self.save(provider)
    }

    /// Judges the next log entry in the current epoch: the first valid commit for it, whose signature verifies under its
    /// committer's leaf key, is to be applied (`apply`); a message entry counts if its MAC verifies. What openmls does
    /// as it stages a commit leaves no trace.
    pub fn judge<P: Provider>(&mut self, provider: &P, entry: &[u8]) -> Result<Verdict> {
        if !self.mls.is_active() {
            return Ok(Verdict::Skipped { reason: "removed from the group".into(), lost: false });
        }
        if self.state.posted.as_ref().is_some_and(|posted| posted.0 == entry) {
            let staged = self.mls.pending_commit().expect("a posted commit is pending");
            if let Err(error) = rules(&self.mls, staged, self.mls.own_leaf_index(), &self.state.aad) {
                self.state.posted = None;
                self.mls.clear_pending_commit(provider.storage())?;
                self.save(provider)?;
                return Ok(Verdict::Skipped { reason: error.to_string(), lost: true });
            }
            return Ok(Verdict::Commit { removes: false });
        }
        let skipped = |error: anyhow::Error| Verdict::Skipped { reason: format!("{error:#}"), lost: false };
        match Entry::parse(entry) {
            Err(error) => Ok(skipped(error)),
            Ok(Entry::Message { id, mac }) if mac == self.mac(provider, &id)? => Ok(Verdict::Message { id }),
            Ok(Entry::Message { .. }) => Ok(skipped(anyhow::anyhow!("a MAC that does not verify in this epoch"))),
            Ok(Entry::Commit { commit, welcome, sig }) => {
                let staged = self.guarded(provider, |_| false, |g| g.stage(provider, &commit, welcome.as_deref(), &sig));
                Ok(match staged {
                    Ok(Staged::Copied) => Verdict::Copied,
                    Ok(Staged::Commit(staged, ..)) => Verdict::Commit { removes: staged.self_removed() },
                    Err(error) => skipped(error),
                })
            }
        }
    }

    /// Applies a commit `judge` found valid.
    pub fn apply<P: Provider>(&mut self, provider: &P, entry: &[u8]) -> Result<Applied> {
        if self.state.posted.as_ref().is_some_and(|posted| posted.0 == entry) {
            self.state.posted = None;
            let by = self.mls.own_leaf_index();
            let staged = self.mls.pending_commit().expect("a posted commit is pending");
            let aad = self.state.aad.clone();
            let applied = observe(&self.mls, &mut self.state, staged, by, aad, true, false);
            self.mls.merge_pending_commit(provider)?;
            return self.merged(provider, applied);
        }
        let Entry::Commit { commit, welcome, sig } = Entry::parse(entry)? else { bail!("not a commit") };
        let Staged::Commit(staged, by, aad) = self.stage(provider, &commit, welcome.as_deref(), &sig)? else { bail!("not a commit to apply") };
        let lost = self.state.posted.take().is_some();
        self.mls.clear_pending_commit(provider.storage())?;
        let applied = observe(&self.mls, &mut self.state, &staged, by, aad, false, lost);
        self.mls.merge_staged_commit(provider, *staged)?;
        self.merged(provider, applied)
    }

    fn stage<P: Provider>(&mut self, provider: &P, commit: &[u8], welcome: Option<&[u8]>, sig: &[u8]) -> Result<Staged> {
        let message = parse::<MlsMessageIn>(commit)?.try_into_protocol_message()?;
        ensure!(message.content_type() == ContentType::Commit, "not a commit");
        let processed = self.mls.process_message(provider, message)?;
        let aad = serde_json::from_slice::<Aad>(processed.aad()).unwrap_or_default();
        let Sender::Member(by) = *processed.sender() else { bail!("not from a member") };
        let key = self.mls.member_at(by).context("from no member")?.signature_key;
        let signed = provider.crypto().verify_signature(SignatureScheme::ED25519, &signed(commit, welcome), &key, sig).is_ok();
        let staged = match processed.into_content() {
            ProcessedMessageContent::OwnPrivateMessage if signed => return Ok(Staged::Copied),
            ProcessedMessageContent::OwnPrivateMessage => bail!("from this session's leaf, not signed by its key"),
            ProcessedMessageContent::StagedCommitMessage(staged) => staged,
            _ => bail!("not a commit"),
        };
        ensure!(signed, "a commit entry its committer did not sign");
        rules(&self.mls, &staged, by, &aad)?;
        Ok(Staged::Commit(staged, by, aad))
    }

    fn merged<P: Provider>(&mut self, provider: &P, mut applied: Applied) -> Result<Applied> {
        let members = self.members();
        for member in &mut applied.added {
            member.index = members.iter().find(|m| m.key == member.key).map_or(0, |m| m.index);
        }
        self.save(provider)?;
        Ok(applied)
    }

    /// Seals a payload as an application message; returns its id and ciphertext. A live payload is marked so in the
    /// message's authenticated data. One whose ciphertext could be over `MAX_MESSAGE` fails before it uses any of the
    /// sender's keys.
    pub fn seal<P: Provider>(
        &mut self,
        provider: &P,
        session: &Session,
        payload: &serde_json::Value,
        live: bool,
    ) -> Result<([u8; 32], Vec<u8>)> {
        let aad = if live { serde_json::to_vec(&Marks { live })? } else { Vec::new() };
        let payload = serde_json::to_vec(payload)?;
        let size = payload.len() + aad.len() + FRAMING;
        ensure!(size <= MAX_MESSAGE, "the message is {size} bytes, over the 1 MiB members take");
        self.mls.set_aad(aad);
        let message = self.mls.create_message(provider, &session.signer, &payload)?.to_bytes()?;
        Ok((Sha256::digest(&message).into(), message))
    }

    /// Asks the others to commit this session's removal.
    pub fn leave<P: Provider>(&mut self, provider: &P, session: &Session) -> Result<([u8; 32], Vec<u8>)> {
        self.seal(provider, session, &serde_json::to_value(Control::Leave)?, false)
    }

    /// Decrypts and verifies a member's message. One under an epoch whose keys this session does not hold fails with
    /// `Unheld`. What openmls does with one it rejects leaves no trace: it advances the claimed sender's keys before it
    /// checks the signature.
    pub fn open<P: Provider>(&mut self, provider: &P, bytes: &[u8]) -> Result<Opened> {
        let message = parse::<MlsMessageIn>(bytes)?.try_into_protocol_message()?;
        ensure!(message.content_type() == ContentType::Application, "not an application message");
        let unheld = message.epoch() < self.mls.epoch();
        let processed = self.guarded(provider, |result| matches!(result, Ok(Ok(_))), |g| Ok(g.mls.process_message(provider, message)))?;
        let processed = match processed {
            Err(ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(MessageDecryptionError::SecretTreeError(
                SecretTreeError::TooDistantInThePast,
            )))) if unheld => return Err(Unheld.into()),
            processed => processed?,
        };
        let epoch = processed.epoch().as_u64();
        let marks = serde_json::from_slice::<Marks>(processed.aad()).unwrap_or_default();
        let sender = credential_of(processed.credential()).context("the sender has no letmeknow credential")?;
        let Sender::Member(index) = *processed.sender() else { bail!("not from a member") };
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            bail!("not an application message")
        };
        let current = self.members().into_iter().find(|member| member.key == sender.key.0).map(|member| member.index);
        let payload: serde_json::Value = serde_json::from_slice(&message.into_bytes())?;
        ensure!(payload["type"].is_string(), "a payload without a type");
        Ok(Opened { id: Sha256::digest(bytes).into(), epoch, index: index.u32(), current, sender, payload, live: marks.live })
    }
}

/// A commit entry staged, or found to be from a copy of this session's state.
enum Staged {
    Commit(Box<StagedCommit>, LeafNodeIndex, Aad),
    Copied,
}

/// Records what a commit does, before it is merged.
fn observe(
    group: &MlsGroup,
    state: &mut State,
    staged: &StagedCommit,
    by: LeafNodeIndex,
    aad: Aad,
    own: bool,
    lost: bool,
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
    Applied {
        by: by.u32(),
        own,
        lost,
        added,
        how: aad.how,
        invite: aad.invite,
        removed,
        settings: staged.queued_proposals().any(|p| matches!(p.proposal(), Proposal::GroupContextExtensions(_))),
        gone: staged.self_removed(),
    }
}

fn state_key(id: &[u8]) -> Vec<u8> {
    [b"group/".as_slice(), id].concat()
}

/// The app's rules on a commit, from MLS state alone, binding the committer too: changes inline only, of the kinds we
/// make; added members whose credentials name their own keys; settings that parse, at this protocol, with the kind
/// unchanged; and no update of the committer's leaf that changes its credential but its name.
fn rules(group: &MlsGroup, staged: &StagedCommit, by: LeafNodeIndex, aad: &Aad) -> Result<()> {
    for proposal in staged.queued_proposals() {
        ensure!(proposal.proposal_or_ref_type() == ProposalOrRefType::Proposal, "a proposal by reference");
        match proposal.proposal() {
            Proposal::Add(add) => _ = leaf_credential(add.key_package().leaf_node())?,
            Proposal::Remove(_) | Proposal::GroupContextExtensions(_) => {}
            other => bail!("a {:?} proposal", other.proposal_type()),
        }
    }
    ensure!(aad.how.is_some() || staged.add_proposals().next().is_none(), "an Add that does not say how its members came in");
    let old = settings_of(group.extensions())?;
    let new = settings_of(staged.group_context().extensions())?;
    ensure!(new.protocol == PROTOCOL, "settings name protocol {}", new.protocol);
    ensure!(new.kind == old.kind, "the kind changed");
    if let Some(leaf) = staged.update_path_leaf_node() {
        let before = group.member_at(by).and_then(|member| credential_of(&member.credential));
        let after = leaf_credential(leaf)?;
        ensure!(before.is_some_and(|before| Credential { name: after.name.clone(), ..before } == after), "an update changed the member's credential");
    }
    Ok(())
}

#[cfg(test)]
#[path = "group_tests.rs"]
pub(crate) mod tests;
