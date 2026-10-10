//! One member's session over lmk-core, lmk-net and lmk-membership: its groups and their logs, its held messages and
//! files, the invites it shares and the joiners it admits, and its members' identities: their key logs and certificates.
//! A group's kind sees its content through the channels here (held messages in log order, live ones, files, and a state
//! link for joiners), and nothing of the rest; the core reads only its own payloads (`Control`). The devices kind
//! (`devices`) is built on those channels. It stores everything through the core's `Provider`, so the same code runs
//! natively (SQLite) and in the browser (memory the web client persists), one transaction per step (`Step`): nothing a
//! step produces leaves the node before its transaction commits.

pub mod devices;
mod groups;
mod kind;
mod logs;
mod reading;
mod sending;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use anyhow::{Context, Result, bail, ensure};
use iroh::tls::CaTlsConfig;
use iroh::{EndpointId, RelayMap, RelayUrl, SecretKey};
use lmk_core::device::Device;
use lmk_core::group::{self as core, Change, Group, Session};
use lmk_core::identity::{KeyLog, certified, check};
use lmk_membership::Contradiction;
use lmk_core::provider::Provider;
use lmk_membership::Refused;
use lmk_net::{Net, Network};
use lmk_proto::group::{Control, Credential, DEVICES, How, IdentityRef, Leaf, Opening, REVISION, Settings};
use lmk_proto::identity::Envelope;
use lmk_proto::links::{Address, FileLink, Invite, RELAY};
use lmk_proto::peer::{Admitted, Frame, Join};
use lmk_proto::{Answer, Bytes};
use n0_future::boxed::BoxFuture;
use n0_future::task::{JoinHandle, spawn};
use n0_future::time::{Duration, sleep, timeout};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

pub use lmk_core;
pub use lmk_net::{Disk, Fetch};
pub use lmk_proto::clock::now;

/// How often a session replaces its keys in each group.
const KEY_UPDATE: Duration = Duration::from_secs(24 * 60 * 60);
/// Why a send's outcome never came.
const UNFINISHED: &str = "the send ended unfinished, as this session stopped or left the group";
/// How long `send` waits for its entry to count before it answers that the send is pending.
const SEND_WAIT: Duration = Duration::from_secs(5);
/// How long some waits for other members last: for those online to hold a file, for added members' certificates.
const MEMBER_WAIT: Duration = Duration::from_secs(5);
/// How often members not connected are dialed again.
const REDIAL: Duration = Duration::from_secs(10);
/// How often connected members sync their groups again.
const RESYNC: Duration = Duration::from_secs(5 * 60);
/// How often files no group holds any longer are deleted.
const COLLECT: Duration = Duration::from_secs(60 * 60);
/// How long a copy of a key log counts as fresh, in milliseconds.
const KEYS_FRESH: u64 = 10 * 60 * 1000;
/// How long a member connected to this session may go without a valid certificate of the identity it speaks as before
/// it is removed, in milliseconds.
const CERTIFICATE_GRACE: u64 = 60 * 1000;
/// How long a fetch keeps looking for a member that holds the file.
const FETCH_TRIES: u32 = 12;
/// How long a member admitting a joiner waits for the state of the group's kind.
const SNAPSHOT_WAIT: Duration = Duration::from_secs(10);
/// How long a session whose kind is behind waits before it asks a member for the kind's state again, in milliseconds.
const STATE_ASK: u64 = 60 * 1000;
const COMMIT_TRIES: u32 = 5;
/// How long an invite is valid, in milliseconds.
const INVITE_VALID: u64 = 10 * 60 * 1000;
/// How many members besides the inviter a link names: those that took the invite first.
const LINK_MEMBERS: usize = 3;
/// How long a joiner waits to reach the members it asks, all at once, and then for each one's answer.
const DIAL_WAIT: Duration = Duration::from_secs(30);
const JOIN_WAIT: Duration = Duration::from_secs(30);

pub struct Config {
    /// The session's name, fixed when it is created.
    pub name: String,
    /// The device whose key is the session's: a device's node, or a browser's one session.
    pub device: Option<Device>,
    pub relay: RelayUrl,
    pub ca: CaTlsConfig,
    /// `LETMEKNOW_HOME`, where sessions of one device publish their addresses.
    pub home: Option<PathBuf>,
    /// Where files are kept; in memory if none.
    pub files: Option<PathBuf>,
    pub disk: Option<Arc<dyn Disk>>,
    /// The largest file fetched without being asked.
    pub file_limit: u64,
    /// The kinds this session supports, `chat` among them.
    pub kinds: Vec<String>,
    /// Where committed steps are not durable yet when they commit, as in the browser: makes them so, before anything
    /// they produced leaves the node.
    pub durable: Option<Durable>,
}

/// Makes the steps committed so far durable.
pub type Durable = Arc<dyn Fn() -> BoxFuture<Result<()>> + Send + Sync>;

/// A group member, from its leaf and credential, and its certificate checked against its identity's key log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The session key: the MLS signature key.
    pub key: Bytes,
    /// The iroh key its leaf names.
    pub iroh: Bytes,
    /// The protocol revision its leaf names.
    #[serde(default)]
    pub revision: u32,
    pub name: String,
    /// The name of its device, as its certificate says.
    pub device_name: String,
    pub identity: Option<Claim>,
    /// Who added it, by session key, and how; none for the group's creator and this session.
    pub added: Option<(Bytes, How)>,
}

/// The identity a member speaks as, its certificate checked against the identity's key log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub identity: IdentityRef,
    /// The identity's own name, from its key log: a claim.
    pub name: String,
    /// Why the check failed, if it did.
    pub error: Option<String>,
    /// For a device another device of its identity added: that device's name, as the certificate claims.
    pub added_by_device: Option<String>,
}

/// A held message of the group, opened: a payload of its kind, or one of the core's.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: Bytes,
    pub group: Bytes,
    pub epoch: u64,
    /// Its entry's position in the group's log.
    pub position: u64,
    /// When it reached this session, in milliseconds since the Unix epoch.
    pub at: u64,
    pub sender: Member,
    pub payload: Value,
}

/// A held message of the kind, at its position in the group's log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub position: u64,
    pub id: Bytes,
    pub from: Member,
    pub payload: Value,
}

/// A held send: its message's id, and its entry's position once that counts; none while the send is pending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub id: Bytes,
    pub position: Option<u64>,
}

/// Why a held send failed: the membership service certainly did not take it.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Nothing reached the service.
    #[error("unavailable: the group's membership service could not be reached")]
    Unavailable,
    #[error("rate: the group's membership service refused more appends for now")]
    Rate,
    #[error("size: {0}")]
    Size(String),
    #[error("the group's membership service refused: {0}")]
    Refused(String),
}

/// What this session sent that no other member holds yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub id: Bytes,
    /// `message` or `file`.
    pub what: String,
}

#[derive(Debug)]
pub enum Event {
    /// A member was added. `introduces`: this session made the invite it came in by, or admitted it by an opening, so it
    /// tells the group who the member is to it; `label` is that invite's `--for`.
    Joined {
        group: Bytes,
        member: Member,
        by: Member,
        how: How,
        introduces: bool,
        label: Option<String>,
    },
    Left {
        group: Bytes,
        member: Member,
        by: Member,
    },
    /// This session was removed, by `by` as it applied the commit, or else with no `by`: by a commit applied before it
    /// stopped, left the only member of a group it asked to leave, or away past its log's retention. The group is gone
    /// from it.
    Removed {
        group: Bytes,
        by: Option<Member>,
    },
    Settings {
        group: Bytes,
        settings: Settings,
        by: Member,
    },
    /// A held payload of the group's kind, opened; never one of this session's own.
    Message(Message),
    /// A live payload of the group's kind: not held.
    Live {
        group: Bytes,
        sender: Member,
        payload: Value,
    },
    /// A sync of the group's held messages with a member finished: this session holds every message that member held
    /// for it and could open.
    Synced { group: Bytes },
    /// This session and a connected member hold the same log of the group: a time to compare the kind's state.
    InStep {
        group: Bytes,
        member: Member,
    },
    /// The state of the group's kind that `from` handed this session: beside the Welcome that admitted it, or later.
    State {
        group: Bytes,
        from: Member,
        data: Vec<u8>,
    },
    /// Held messages were kept for the kind, in log order (see `Node::entries`).
    Logged {
        group: Bytes,
    },
    /// A member is being admitted, or asks for it: the state of the group's kind to hand it, if any.
    Snapshot {
        group: Bytes,
        reply: oneshot::Sender<Option<Vec<u8>>>,
    },
    Introduced {
        group: Bytes,
        by: Member,
        identity: IdentityRef,
        name: String,
        how: How,
    },
    /// A send that `send` answered as pending counts now: `id` as `send` answered it.
    Sent {
        group: Bytes,
        id: Bytes,
        position: u64,
    },
    /// A file is held whole.
    File([u8; 32]),
    Warning {
        group: Option<Bytes>,
        text: String,
    },
}

impl Event {
    /// The group an event concerns, if one.
    pub fn group(&self) -> Option<&Bytes> {
        match self {
            Event::Joined { group, .. }
            | Event::Left { group, .. }
            | Event::Removed { group, .. }
            | Event::Settings { group, .. }
            | Event::Live { group, .. }
            | Event::Synced { group }
            | Event::InStep { group, .. }
            | Event::State { group, .. }
            | Event::Logged { group }
            | Event::Snapshot { group, .. }
            | Event::Introduced { group, .. }
            | Event::Sent { group, .. } => Some(group),
            Event::Message(message) => Some(&message.group),
            Event::Warning { group, .. } => group.as_ref(),
            Event::File(_) => None,
        }
    }
}

/// A group's own record, beside its MLS state and its log.
#[derive(Default, Serialize, Deserialize)]
struct Rec {
    /// The last position of its log read and judged.
    position: u64,
    /// The position this session started after: the Add that brought it in, or 0 for the group's creator.
    start: u64,
    /// Positions up to here were read longer than H ago, and what this session kept of them is gone.
    expired: u64,
    /// Counted positions not opened yet, nor lost: their epoch, and when their entry was read.
    unopened: BTreeMap<u64, (u64, u64)>,
    /// This session's held sends whose entries have not counted yet, oldest first.
    sends: Vec<Bytes>,
    pending: Vec<Pending>,
    /// File links, with when they were linked: those the kind holds (its files added, and those its held messages
    /// link) and states handed to or by this session. Each is held for the group's H.
    files: Vec<(String, u64)>,
    /// The state handed to or by this session last, held however old.
    state: Option<String>,
    /// The files the kind links now, held while it does.
    links: Vec<String>,
    /// What the kind took of the group's held messages, once it follows them.
    kind: Option<kind::Kind>,
    /// The invites shared with the group, kept for H after they expire.
    invites: Vec<Rule>,
    /// Counted `leave`s: each sender's key, and the epoch it was sealed in; kept until moot.
    leaves: Vec<(Bytes, u64)>,
}

/// An invite, as its inviter shared it with the group.
#[derive(Clone, Serialize, Deserialize)]
struct Rule {
    /// SHA-256 of its secret.
    hash: Bytes,
    expires: u64,
    label: Option<String>,
    to: Option<Bytes>,
    /// The inviter's session key.
    by: Bytes,
}

impl Rec {
    fn link(&mut self, link: String) {
        self.files.push((link, now()));
    }

    /// The files this session holds for the group: those linked within H, the latest state, and those the kind links
    /// now.
    fn held(&self, carry: u32) -> Vec<FileLink> {
        let since = now().saturating_sub(days(carry));
        let linked = self.files.iter().filter(|(_, at)| *at >= since).map(|(link, _)| link).chain(&self.state);
        linked.chain(&self.links).filter_map(|link| FileLink::parse(link).ok()).collect()
    }
}

/// H, in milliseconds.
fn days(days: u32) -> u64 {
    days as u64 * 24 * 3600 * 1000
}

pub(crate) struct G {
    mls: Group,
    rec: Rec,
    /// Ciphertexts that came before their entries were read: of the current epoch or the next.
    early: Vec<Vec<u8>>,
    /// When this session last asked a member for the kind's state, or was handed one, in milliseconds.
    asked: u64,
    /// The wait before the commit that deletes an epoch's keys while this session lacks some of its messages.
    wait: Option<reading::Wait>,
}

pub(crate) struct State<P> {
    provider: P,
    /// What the current step produced for the peers, sent once it commits.
    out: Vec<Out>,
    /// The current step deleted what should leave no copy: scrub once it commits.
    scrub: bool,
    session: Session,
    /// The session's own name, which its credential names in its groups.
    name: String,
    /// The device's name, which its credential names in its devices groups, where this is a device's node.
    device: Option<String>,
    groups: BTreeMap<Vec<u8>, G>,
    /// The logs this session follows, by id.
    logs: BTreeMap<Vec<u8>, logs::Log>,
    /// Key logs, by identity id.
    keys: BTreeMap<Vec<u8>, KeyLog>,
    /// Members' certificates, this session's own among them, by session key and identity id.
    certificates: BTreeMap<(Vec<u8>, Vec<u8>), Envelope>,
    /// Members' certificates that lost to a valid one while not valid themselves, as one by a key this session has
    /// not read yet is: taken again when their identity's key log grows.
    ahead: BTreeMap<(Vec<u8>, Vec<u8>), Envelope>,
    /// Members connected to this session without a valid certificate, by session key: since when.
    uncertified: BTreeMap<Vec<u8>, u64>,
    /// `send`s waiting for their entries to count, by the id they started with.
    waiters: HashMap<Vec<u8>, Vec<oneshot::Sender<sending::Outcome>>>,
}

/// What a step produced for the peers.
pub(crate) enum Out {
    /// A held message whose entry counts, or a live one, to the members online.
    Push { group: Vec<u8>, ciphertext: Vec<u8> },
    Frame { peer: EndpointId, frame: Frame },
    /// This session's state of a group changed: its peers hear.
    Changed(Vec<u8>),
    /// This session serves a peer a group anew: they sync it again.
    Served { peer: EndpointId, group: Vec<u8> },
}

/// One step: the state, locked, with a transaction open on its storage; committed when the step ends, and only then
/// what it produced goes out.
pub(crate) struct Step<'a, P: Provider + Send + 'static> {
    guard: MutexGuard<'a, State<P>>,
    inner: &'a Inner<P>,
}

impl<P: Provider + Send + 'static> Deref for Step<'_, P> {
    type Target = State<P>;

    fn deref(&self) -> &State<P> {
        &self.guard
    }
}

impl<P: Provider + Send + 'static> DerefMut for Step<'_, P> {
    fn deref_mut(&mut self) -> &mut State<P> {
        &mut self.guard
    }
}

impl<P: Provider + Send + 'static> Drop for Step<'_, P> {
    fn drop(&mut self) {
        if let Err(error) = self.guard.provider.commit() {
            tracing::error!("committing a step: {error:#}");
        }
        if std::mem::take(&mut self.guard.scrub)
            && let Err(error) = self.guard.provider.scrub()
        {
            self.inner.warn(None, format!("{error:#}"));
        }
        let out = std::mem::take(&mut self.guard.out);
        if !out.is_empty() {
            self.inner.outbox.send(out).ok();
        }
    }
}

pub(crate) enum Work {
    Applied {
        group: Vec<u8>,
        by: Option<core::Member>,
        added: Vec<core::Member>,
        how: Option<How>,
        invite: Option<Bytes>,
        removed: Vec<core::Member>,
        settings: bool,
        gone: bool,
    },
    /// A log to read from its service.
    Read(Vec<u8>),
    Remove {
        group: Vec<u8>,
        key: Vec<u8>,
    },
    /// A group this session is out of, by no one's commit.
    Gone(Vec<u8>),
    Fetch {
        group: Vec<u8>,
        link: FileLink,
    },
    /// A state a member handed this session.
    State {
        group: Vec<u8>,
        link: String,
        by: EndpointId,
    },
    /// A member asks for the state of the group's kind.
    StateWanted {
        group: Vec<u8>,
        by: EndpointId,
    },
    /// Held sends of a group to append.
    Send(Vec<u8>),
    /// A group waits before a commit: read on once the wait is over.
    Wait(Vec<u8>),
    Net(lmk_net::Event),
}

/// A log, and the lengths and hashes of two heads of it that contradict each other.
type Contradicted = (Vec<u8>, [(u64, Vec<u8>); 2]);

pub(crate) struct Inner<P> {
    state: Mutex<State<P>>,
    net: OnceLock<Net>,
    clients: logs::Clients,
    /// The tasks that follow logs at their services, by log id.
    follows: Mutex<HashMap<Vec<u8>, JoinHandle<()>>>,
    relay: RelayUrl,
    file_limit: u64,
    kinds: Vec<String>,
    events: mpsc::UnboundedSender<Event>,
    work: mpsc::UnboundedSender<Work>,
    /// What steps produced for the peers, in order, sent once durable.
    outbox: mpsc::UnboundedSender<Vec<Out>>,
    durable: Option<Durable>,
    committing: tokio::sync::Mutex<()>,
    /// Woken whenever a group's log is read further, for sends waiting to reach its head.
    advanced: tokio::sync::Notify,
    reading: Mutex<HashSet<Vec<u8>>>,
    /// The groups whose held sends are being appended.
    sending: Mutex<HashSet<Vec<u8>>>,
    /// The removals under way, by group and member key.
    removing: Mutex<HashSet<(Vec<u8>, Vec<u8>)>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// The contradictions reported, each once.
    contradictions: Mutex<HashSet<Contradicted>>,
}

/// One member's session. Clones share it.
pub struct Node<P> {
    inner: Arc<Inner<P>>,
}

impl<P> Clone for Node<P> {
    fn clone(&self) -> Self {
        Node { inner: self.inner.clone() }
    }
}

fn get<T: DeserializeOwned>(provider: &impl Provider, key: &[u8]) -> Result<Option<T>> {
    Ok(provider.get(key)?.map(|bytes| serde_json::from_slice(&bytes)).transpose()?)
}

fn put<T: Serialize>(provider: &impl Provider, key: &[u8], value: &T) -> Result<()> {
    provider.put(key, &serde_json::to_vec(value)?)
}

fn rec_key(gid: &[u8]) -> Vec<u8> {
    [b"node/group/".as_slice(), gid].concat()
}

fn kind_key(key: &str) -> Vec<u8> {
    [b"kind/", key.as_bytes()].concat()
}

fn message_key(id: &[u8]) -> Vec<u8> {
    [b"node/message/".as_slice(), id].concat()
}

fn endpoint_id(key: &[u8]) -> Option<EndpointId> {
    EndpointId::from_bytes(key.try_into().ok()?).ok()
}

impl<P: Provider> State<P> {
    /// What the credential of the group this session makes or joins next names: its identity, and in a devices group
    /// the device's name, else its own.
    fn speak(&mut self, identity: Option<IdentityRef>, devices: bool) {
        self.session.credential.identity = identity;
        self.session.credential.name = match &self.device {
            Some(device) if devices => device.clone(),
            _ => self.name.clone(),
        };
    }

    fn group(&self, gid: &[u8]) -> Result<&G> {
        self.groups.get(gid).context("this session is not in that group")
    }

    fn group_mut(&mut self, gid: &[u8]) -> Result<&mut G> {
        self.groups.get_mut(gid).context("this session is not in that group")
    }

    fn save(&self, gid: &[u8]) -> Result<()> {
        put(&self.provider, &rec_key(gid), &self.group(gid)?.rec)
    }

    fn save_groups(&self) -> Result<()> {
        let gids: Vec<Bytes> = self.groups.keys().map(|gid| Bytes(gid.clone())).collect();
        put(&self.provider, b"node/groups", &gids)
    }

    /// The iroh key of the member with a fingerprint: the first 8 bytes of SHA-256 of its session key, hex.
    fn by_fp(&self, gid: &[u8], fp: &str) -> Result<EndpointId> {
        let members = self.group(gid)?.mls.members();
        let member = members.iter().find(|m| hex(&Sha256::digest(&m.key)[..8]) == fp).with_context(|| format!("no member {fp}"))?;
        member.leaf.as_ref().and_then(|leaf| endpoint_id(&leaf.key.0)).context("a member without an iroh key")
    }

    /// A member as events show it, if it has a letmeknow credential.
    fn member(&self, gid: &[u8], member: &core::Member) -> Option<Member> {
        let credential = member.credential.clone()?;
        let g = self.groups.get(gid);
        let added = g.and_then(|g| {
            let added = g.mls.added().iter().rev().find(|added| added.member.key == credential.key)?;
            let by = g.mls.members().into_iter().find(|m| m.key == added.by.key.0);
            Some((Bytes(by.map(|by| by.key).unwrap_or_default()), added.how.clone().unwrap_or(How::Invite)))
        });
        let claim = credential.identity.as_ref().map(|identity| self.claim(&credential, identity));
        let device_name = claim.as_ref().and_then(|(_, device)| device.clone()).unwrap_or_default();
        Some(Member {
            key: Bytes(member.key.clone()),
            iroh: member.leaf.as_ref().map(|leaf| leaf.key.clone()).unwrap_or_default(),
            revision: member.leaf.as_ref().map_or(0, |leaf| leaf.revision),
            name: credential.name,
            device_name,
            identity: claim.map(|(claim, _)| claim),
            added,
        })
    }

    /// The certificate held of a member speaking as an identity.
    fn certificate(&self, credential: &Credential, identity: &[u8]) -> Option<&Envelope> {
        self.certificates.get(&(credential.key.0.clone(), identity.to_vec()))
    }

    /// The identity a member speaks as, checked; and its device's name, if its certificate checks out.
    fn claim(&self, credential: &Credential, identity: &IdentityRef) -> (Claim, Option<String>) {
        let identity = identity.clone();
        let Some(log) = self.keys.get(&identity.id.0) else {
            let error = Some("its identity's key could not be read yet".into());
            return (Claim { identity, name: String::new(), error, added_by_device: None }, None);
        };
        let name = log.name.clone();
        match check(self.certificate(credential, &identity.id.0), credential, log, now()) {
            Ok(certified) => (Claim { identity, name, error: None, added_by_device: certified.added_by }, Some(certified.device)),
            Err(error) => (Claim { identity, name, error: Some(error.into()), added_by_device: None }, None),
        }
    }

    fn members(&self, gid: &[u8]) -> Result<Vec<Member>> {
        let g = self.group(gid)?;
        Ok(g.mls.members().iter().filter_map(|member| self.member(gid, member)).collect())
    }

    /// The member whose leaf names an iroh key, or a bare one.
    fn by_iroh(&self, gid: &[u8], iroh: &EndpointId) -> Member {
        let found = self.groups.get(gid).and_then(|g| {
            let members = g.mls.members();
            let member = members.iter().find(|m| m.leaf.as_ref().is_some_and(|leaf| leaf.key.0 == iroh.as_bytes()))?;
            self.member(gid, member)
        });
        found.unwrap_or_else(|| Member {
            key: Bytes::default(),
            iroh: Bytes(iroh.as_bytes().to_vec()),
            revision: 0,
            name: String::new(),
            device_name: String::new(),
            identity: None,
            added: None,
        })
    }

    /// The member of a group whose leaf names an iroh key.
    fn in_leaf(&self, gid: &[u8], peer: &EndpointId) -> Option<core::Member> {
        let members = self.groups.get(gid)?.mls.members();
        members.into_iter().find(|m| m.leaf.as_ref().is_some_and(|leaf| leaf.key.0 == peer.as_bytes()))
    }

    /// Whether this session serves a peer a group: it is a member and, speaking as an identity, has shown a valid
    /// certificate of it.
    fn serves(&self, gid: &[u8], peer: &EndpointId) -> bool {
        let Some(member) = self.in_leaf(gid, peer) else { return false };
        let Some((credential, identity)) = member.credential.as_ref().and_then(|c| Some((c, c.identity.as_ref()?))) else {
            return true;
        };
        let log = self.keys.get(&identity.id.0);
        log.is_some_and(|log| check(self.certificate(credential, &identity.id.0), credential, log, now()).is_ok())
    }

    /// The groups this session serves each of these peers.
    fn served(&self, peers: &[EndpointId]) -> Vec<(Vec<u8>, EndpointId)> {
        let gids = self.groups.keys();
        gids.flat_map(|gid| peers.iter().filter(|peer| self.serves(gid, peer)).map(|peer| (gid.clone(), *peer))).collect()
    }

    /// The identities a group's members speak as.
    fn identities(&self, gid: &[u8]) -> Vec<IdentityRef> {
        let Some(g) = self.groups.get(gid) else { return Vec::new() };
        g.mls.members().into_iter().filter_map(|m| m.credential?.identity).collect()
    }

    /// Persists the certificates held of this session, and apart those of its groups' members: 0.12.1 takes every
    /// certificate under `node/certificates` for the session's own.
    fn save_certificates(&self) -> Result<()> {
        let me = self.session.key();
        let members: HashSet<Vec<u8>> = self.groups.values().flat_map(|g| g.mls.members()).map(|m| m.key).collect();
        let (own, held): (Vec<_>, Vec<_>) =
            self.certificates.iter().filter(|((key, _), _)| key == me || members.contains(key)).partition(|((key, _), _)| key == me);
        put(&self.provider, b"node/certificates", &own.into_iter().map(|(_, c)| c).collect::<Vec<_>>())?;
        put(&self.provider, b"node/member-certificates", &held.into_iter().map(|(_, c)| c).collect::<Vec<_>>())
    }

    /// A new group's records, its MLS state, and its log, read after `rec.position`.
    fn add_group(&mut self, mls: Group, rec: Rec) -> Result<Vec<u8>> {
        let gid = mls.id().to_vec();
        self.add_log(&gid, logs::Log::new(logs::Of::Group, mls.settings().membership, rec.position))?;
        self.groups.insert(gid.clone(), G { mls, rec, early: Vec::new(), asked: 0, wait: None });
        self.save(&gid)?;
        self.save_groups()?;
        Ok(gid)
    }
}

/// The session's iroh key, made on first use.
pub fn iroh_key(provider: &impl Provider) -> Result<SecretKey> {
    Ok(match provider.get(b"node/iroh")? {
        Some(bytes) => SecretKey::from_bytes(&bytes.as_slice().try_into().context("an iroh key is 32 bytes")?),
        None => {
            let key = SecretKey::from_bytes(&lmk_core::random());
            provider.put(b"node/iroh", &key.to_bytes())?;
            key
        }
    })
}

impl<P: Provider + Send + 'static> Node<P> {
    /// Opens the session in `provider`, creating it on first use, and starts its peers.
    pub async fn start(provider: P, mut config: Config) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
        let relays = RelayMap::from(iroh::RelayConfig::new(config.relay.clone(), Some(Default::default())));
        let ca = std::mem::take(&mut config.ca);
        let endpoint = lmk_net::builder(relays).secret_key(iroh_key(&provider)?).ca_tls_config(ca).bind().await?;
        Self::start_on(provider, config, Network::Iroh(endpoint)).await
    }

    /// Opens the session on a network of the caller's, whose key is `iroh_key`'s.
    pub async fn start_on(provider: P, config: Config, network: Network) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
        let transport = network.transport();
        let leaf = Leaf { key: Bytes(transport.id().as_bytes().to_vec()), relay: config.relay.to_string(), kinds: config.kinds.clone(), revision: REVISION };
        let mut session = match (provider.get(b"session")?, &config.device) {
            (Some(_), _) => Session::load(&provider)?,
            (None, Some(device)) => Session::create_with(&provider, device.signer(), &config.name, leaf.clone())?,
            (None, None) => Session::create(&provider, &config.name, leaf.clone())?,
        };
        if session.leaf != leaf {
            session.set_leaf(&provider, leaf)?;
        }
        let clients = logs::Clients::new(transport);
        let logs = State::load_logs(&provider)?;
        for log in logs.values() {
            if let Some(chain) = &log.chain {
                clients.client(&log.service)?.set_chain(chain.clone());
            }
        }
        let mut groups = BTreeMap::new();
        for gid in get::<Vec<Bytes>>(&provider, b"node/groups")?.unwrap_or_default() {
            let mls = Group::load(&provider, &gid.0)?;
            let rec: Rec = get(&provider, &rec_key(&gid.0))?.context("a group without its record")?;
            groups.insert(gid.0, G { mls, rec, early: Vec::new(), asked: 0, wait: None });
        }
        let (events, events_rx) = mpsc::unbounded_channel();
        let (work, work_rx) = mpsc::unbounded_channel();
        let (outbox, outbox_rx) = mpsc::unbounded_channel();
        let mut held: Vec<Envelope> = get(&provider, b"node/certificates")?.unwrap_or_default();
        held.extend(get::<Vec<Envelope>>(&provider, b"node/member-certificates")?.unwrap_or_default());
        let certificates = held
            .into_iter()
            .filter_map(|c| {
                let certified = certified(&c)?;
                Some(((certified.key.0, certified.identity.0), c))
            })
            .collect();
        let state = State {
            provider,
            out: Vec::new(),
            scrub: false,
            name: session.credential.name.clone(),
            device: config.device.as_ref().map(|device| device.name.clone()),
            session,
            groups,
            logs,
            keys: BTreeMap::new(),
            certificates,
            ahead: BTreeMap::new(),
            uncertified: BTreeMap::new(),
            waiters: HashMap::new(),
        };
        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            net: OnceLock::new(),
            clients,
            follows: Mutex::default(),
            relay: config.relay.clone(),
            file_limit: config.file_limit,
            kinds: config.kinds,
            events,
            work: work.clone(),
            outbox,
            durable: config.durable,
            committing: tokio::sync::Mutex::new(()),
            advanced: tokio::sync::Notify::new(),
            reading: Mutex::default(),
            sending: Mutex::default(),
            removing: Mutex::default(),
            tasks: Mutex::default(),
            contradictions: Mutex::default(),
        });
        let net_config = lmk_net::Config {
            home: config.home,
            files: config.files,
            disk: config.disk,
            file_limit: config.file_limit,
            resync: RESYNC,
            collect: COLLECT,
        };
        let (net, mut net_events) =
            Net::spawn(network, net_config, inner.clone(), Arc::new(groups::Admitter(inner.clone()))).await?;
        inner.net.set(net).ok();
        inner.spawn(async move {
            while let Some(event) = net_events.recv().await {
                work.send(Work::Net(event)).ok();
            }
        });
        inner.spawn(inner.clone().drive(work_rx));
        inner.spawn(inner.clone().send_out(outbox_rx));
        let (gids, followed): (Vec<Vec<u8>>, Vec<Vec<u8>>) = {
            let st = inner.lock();
            let followed = st.logs.iter().filter(|(_, log)| !matches!(log.of, logs::Of::Identity(_))).map(|(id, _)| id.clone());
            (st.groups.keys().cloned().collect(), followed.collect())
        };
        for log in &followed {
            inner.follow(log);
        }
        {
            let mut st = inner.lock();
            let identities: Vec<Bytes> = st.logs.values().filter_map(|log| match &log.of {
                logs::Of::Identity(id) => Some(id.clone()),
                _ => None,
            }).collect();
            for id in identities {
                if let Err(error) = inner.keyed(&mut st, &id.0) {
                    inner.warn(None, format!("the key log of {}: {error:#}", hex(&id.0)));
                }
            }
        }
        {
            // A session removed by a commit it applied before it stopped is told so now; its sends go on.
            let st = inner.lock();
            for gid in &gids {
                let g = st.group(gid)?;
                if !g.mls.active() {
                    inner.work.send(Work::Gone(gid.clone())).ok();
                    continue;
                }
                if let Err(error) = inner.leavers(&st, gid) {
                    inner.warn(Some(gid), format!("{error:#}"));
                }
                if !g.rec.sends.is_empty() {
                    inner.work.send(Work::Send(gid.clone())).ok();
                }
            }
        }
        inner.spawn(inner.clone().resume(gids));
        inner.spawn(inner.clone().redial());
        inner.spawn(inner.clone().passing());
        Ok((Node { inner }, events_rx))
    }

    /// Stops the peers and every task.
    pub async fn shutdown(&self) -> Result<()> {
        for task in self.inner.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
        for (_, follow) in self.inner.follows.lock().unwrap().drain() {
            follow.abort();
        }
        self.inner.net().shutdown().await
    }

    /// This session's key: its MLS signature key.
    pub fn key(&self) -> Bytes {
        Bytes(self.inner.lock().session.key().to_vec())
    }

    /// Its peers: what a transport of the caller's hands the connections peers open, and the files they fetch.
    pub fn net(&self) -> &Net {
        self.inner.net()
    }

    /// This session's iroh key and relay.
    pub fn address(&self) -> ([u8; 32], RelayUrl) {
        (*self.inner.net().id().as_bytes(), self.inner.relay.clone())
    }

    pub fn groups(&self) -> Vec<Bytes> {
        self.inner.lock().groups.keys().map(|gid| Bytes(gid.clone())).collect()
    }

    pub fn settings(&self, gid: &[u8]) -> Result<Settings> {
        Ok(self.inner.lock().group(gid)?.mls.settings())
    }

    pub fn epoch(&self, gid: &[u8]) -> Result<u64> {
        Ok(self.inner.lock().group(gid)?.mls.epoch())
    }

    /// The epoch this session joined the group at.
    pub fn joined(&self, gid: &[u8]) -> Result<u64> {
        Ok(self.inner.lock().group(gid)?.mls.joined())
    }

    pub fn members(&self, gid: &[u8]) -> Result<Vec<Member>> {
        self.inner.lock().members(gid)
    }

    /// The members connected now.
    pub fn online(&self, gid: &[u8]) -> Result<Vec<Member>> {
        let connected = self.inner.net().connected();
        let members = self.members(gid)?;
        Ok(members.into_iter().filter(|m| connected.iter().any(|peer| peer.as_bytes()[..] == m.iroh.0[..])).collect())
    }

    /// What this session sent to a group that no other member holds yet.
    pub fn only_here(&self, gid: &[u8]) -> Result<Vec<Pending>> {
        Ok(self.inner.lock().group(gid)?.rec.pending.clone())
    }

    /// The kinds this session supports.
    pub fn kinds(&self) -> &[String] {
        &self.inner.kinds
    }

    /// A new group with this session its only member, speaking as `identity`.
    pub fn create(&self, settings: Settings, identity: Option<IdentityRef>) -> Result<Bytes> {
        ensure!(self.inner.kinds.contains(&settings.kind), "this session does not support {} groups", settings.kind);
        let gid = {
            let mut st = self.inner.lock();
            let st = &mut *st;
            st.speak(identity, settings.kind == DEVICES);
            let mls = Group::create(&st.provider, &st.session, &settings)?;
            st.add_group(mls, Rec::default())?
        };
        self.inner.follow(&gid);
        Ok(Bytes(gid))
    }

    /// An invite into a group, `--for` a contact name or `--to` an identity: shared with the members as a held
    /// message, and a link that names this session and up to three members that took it.
    pub async fn invite(&self, gid: &[u8], label: Option<String>, to: Option<Bytes>) -> Result<Invite> {
        let secret: [u8; 16] = lmk_core::random();
        let hash = Bytes(Sha256::digest(secret).to_vec());
        let expires = now() + INVITE_VALID;
        let device = {
            let mut st = self.inner.lock();
            let by = Bytes(st.session.key().to_vec());
            let g = st.group_mut(gid)?;
            g.rec.invites.push(Rule { hash: hash.clone(), expires, label: label.clone(), to: to.clone(), by });
            st.save(gid)?;
            st.group(gid)?.mls.settings().kind == DEVICES
        };
        let rule = serde_json::to_value(Control::Invite { hash, expires, label, to })?;
        self.send(gid, &rule).await?;
        // The members online, which took the invite once it counted, admit by it too.
        let online = self.online(gid)?;
        let st = self.inner.lock();
        let mut members = vec![address(*self.inner.net().id().as_bytes(), self.inner.relay.as_str())];
        for member in online.iter().take(LINK_MEMBERS) {
            let Some(leaf) = endpoint_id(&member.iroh.0).and_then(|peer| st.in_leaf(gid, &peer)?.leaf) else { continue };
            members.push(address(*endpoint_id(&leaf.key.0).context("an iroh key")?.as_bytes(), &leaf.relay));
        }
        Ok(Invite { device, secret, members })
    }

    /// Joins through an invite link, speaking as `identity`: asks the members it names in turn. Returns the group, and
    /// the iroh key of the member that admitted this session.
    pub async fn join(&self, link: &Invite, identity: Option<IdentityRef>) -> Result<(Bytes, [u8; 32])> {
        let ours: RelayUrl = RELAY.parse()?;
        let members = link
            .members
            .iter()
            .map(|member| Ok((EndpointId::from_bytes(&member.key)?, member.relay.as_ref().map_or(Ok(ours.clone()), |relay| relay.parse())?)))
            .collect::<Result<Vec<_>>>()?;
        self.ask(members, Some(Bytes(link.secret.to_vec())), None, identity, link.device).await
    }

    /// Asks the members of an open group to admit this session in turn, speaking as `identity`, with its certificate.
    pub async fn join_open(&self, opening: &Opening, identity: IdentityRef) -> Result<Bytes> {
        ensure!(self.inner.kinds.contains(&opening.kind), "this session does not support {} groups", opening.kind);
        self.certificate(&identity.id.0).context("this session has no certificate of that identity yet")?;
        let members = opening.members.iter().filter_map(|key| endpoint_id(&key.0)).map(|peer| (peer, self.inner.relay.clone())).collect();
        Ok(self.ask(members, None, Some(opening.group.clone()), Some(identity), false).await?.0)
    }

    /// Asks members in turn to admit this session, by an invite's secret or a group open to `identity`.
    async fn ask(
        &self,
        members: Vec<(EndpointId, RelayUrl)>,
        secret: Option<Bytes>,
        group: Option<Bytes>,
        identity: Option<IdentityRef>,
        devices: bool,
    ) -> Result<(Bytes, [u8; 32])> {
        let join = {
            let mut st = self.inner.lock();
            let certificate = identity.as_ref().and_then(|identity| st.certificate(&st.session.credential, &identity.id.0).cloned());
            st.speak(identity, devices);
            Join { secret, group, key_package: Bytes(st.session.key_package(&st.provider)?), certificate }
        };
        let dialed = n0_future::join_all(members.iter().map(|(peer, relay)| timeout(DIAL_WAIT, self.inner.net().dial(*peer, relay.clone())))).await;
        let mut refusal = anyhow::anyhow!("no member the invite names is online");
        for ((peer, relay), dialed) in members.into_iter().zip(dialed) {
            if !matches!(dialed, Ok(Ok(()))) {
                tracing::debug!("{} is not online", peer.fmt_short());
                continue;
            }
            match timeout(JOIN_WAIT, self.inner.net().join(peer, relay, join.clone())).await {
                Ok(Ok(Answer::Ok(admitted))) => return Ok((self.inner.welcomed(admitted, peer).await?, *peer.as_bytes())),
                Ok(Ok(Answer::Refused { refused })) => refusal = anyhow::anyhow!("refused: {refused}"),
                Ok(Err(error)) => tracing::debug!("asking {} to admit this session: {error:#}", peer.fmt_short()),
                Err(_) => tracing::debug!("{} did not answer", peer.fmt_short()),
            }
        }
        Err(refusal)
    }

    /// Removes a member. Returns whether this session's commit removed it, which it need not once another's did.
    pub async fn remove(&self, gid: &[u8], key: &[u8]) -> Result<bool> {
        ensure!(self.inner.lock().group(gid)?.mls.members().iter().any(|m| m.key == key), "not a member");
        let remove = |g: &Group| Ok(g.members().into_iter().find(|m| m.key == key).map(|member| Change { remove: vec![member.index], ..Change::default() }));
        Ok(self.inner.commit(gid, remove).await?.is_some())
    }

    /// Changes the group's settings, from the current ones.
    pub async fn change_settings(&self, gid: &[u8], change: impl Fn(Settings) -> Settings) -> Result<Settings> {
        self.inner
            .commit(gid, |g| {
                let settings = change(g.settings());
                Ok((settings != g.settings()).then(|| Change { settings: Some(settings), ..Change::default() }))
            })
            .await?;
        self.settings(gid)
    }

    /// Asks the others to remove this session, or forgets a group it is alone in.
    pub async fn leave(&self, gid: &[u8]) -> Result<Option<Sent>> {
        if self.members(gid)?.len() == 1 {
            self.inner.forget(gid)?;
            return Ok(None);
        }
        Ok(Some(self.send(gid, &json!({ "type": "leave" })).await?))
    }

    /// Sends a held payload: the node seals it, appends its entry to the group's log, and pushes it to the members
    /// online once the entry counts. Answers its position once it counts; or after a few seconds without the service's
    /// answer, that it is pending: the node finishes the send, after a restart too, and tells `Event::Sent`. Fails only
    /// when the service certainly did not take it (`SendError`).
    pub async fn send(&self, gid: &[u8], payload: &Value) -> Result<Sent> {
        let (id, mut counted) = self.inner.held_send(gid, payload)?;
        let position = match timeout(SEND_WAIT, &mut counted).await {
            Ok(counted) => Some(counted.context(UNFINISHED)?.map_err(|error| anyhow::anyhow!(error))?),
            Err(_) => self.inner.pending(&id, &mut counted)?,
        };
        Ok(match position {
            Some(position) => Sent { id: self.inner.sent_id(gid, position)?, position: Some(position) },
            None => Sent { id, position: None },
        })
    }

    /// Sends a held payload and waits as long as it takes for its entry to count; answers its position.
    pub async fn send_counted(&self, gid: &[u8], payload: &Value) -> Result<u64> {
        let (_, counted) = self.inner.held_send(gid, payload)?;
        counted.await.context(UNFINISHED)?.map_err(|error| anyhow::anyhow!(error))
    }

    /// Seals a live payload, not held, and sends it to the members online, or to the one with fingerprint `to`.
    pub fn send_live(&self, gid: &[u8], payload: &Value, to: Option<&str>) -> Result<()> {
        let mut st = self.inner.lock();
        let st = &mut *st;
        let peer = to.map(|fp| st.by_fp(gid, fp)).transpose()?;
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        let ciphertext = g.mls.seal(&st.provider, &st.session, payload, true)?.1;
        st.out.push(match peer {
            Some(peer) => Out::Frame { peer, frame: Frame::Messages { group: Bytes(gid.to_vec()), items: vec![Bytes(ciphertext)] } },
            None => Out::Push { group: gid.to_vec(), ciphertext },
        });
        Ok(())
    }

    /// Holds files for the group's H from now, as those a held message links, unless it holds them already; fetches
    /// those within this session's limit.
    pub fn hold(&self, gid: &[u8], links: &[String]) -> Result<()> {
        let parsed = links.iter().map(|link| FileLink::parse(link)).collect::<Result<Vec<_>>>()?;
        let mut st = self.inner.lock();
        let rec = &mut st.group_mut(gid)?.rec;
        for link in links {
            if !rec.files.iter().any(|(held, _)| held == link) {
                rec.link(link.clone());
            }
        }
        st.save(gid)?;
        self.inner.fetch_within_limit(gid, parsed);
        Ok(())
    }

    /// The files the group's kind links now, held while it does; fetches those new within this session's limit.
    pub fn set_links(&self, gid: &[u8], links: Vec<String>) -> Result<()> {
        let mut st = self.inner.lock();
        let rec = &mut st.group_mut(gid)?.rec;
        let new = links.iter().filter(|link| !rec.links.contains(link)).map(|link| FileLink::parse(link)).collect::<Result<Vec<_>>>()?;
        rec.links = links;
        st.save(gid)?;
        self.inner.fetch_within_limit(gid, new);
        Ok(())
    }

    /// Hands the member with fingerprint `to` a state of the group's kind, as a file it fetches.
    pub async fn hand_state(&self, gid: &[u8], to: &str, data: Vec<u8>) -> Result<()> {
        let peer = self.inner.lock().by_fp(gid, to)?;
        let link = self.inner.state_file(gid, data).await?;
        self.inner.lock().out.push(Out::Frame { peer, frame: Frame::State { group: Bytes(gid.to_vec()), link: Some(link) } });
        Ok(())
    }

    /// The files a group holds.
    pub fn linked(&self, gid: &[u8]) -> Vec<FileLink> {
        lmk_net::Groups::files(&*self.inner, gid)
    }

    /// Whether this session serves a peer a group, by the serving rules.
    pub fn serves(&self, gid: &[u8], peer: &EndpointId) -> bool {
        lmk_net::Groups::is_member(&*self.inner, gid, peer)
    }

    /// Whether this session lost a held message: its entry counted, and it can no longer open it.
    pub fn lost(&self, gid: &[u8], id: &[u8]) -> bool {
        let st = self.inner.lock();
        st.position_of(gid, id).ok().flatten().and_then(|position| st.pos(gid, position).ok().flatten()).is_some_and(|pos| pos.lost)
    }

    /// A held message, opened.
    pub fn message(&self, id: &[u8]) -> Result<Option<Message>> {
        get(&self.inner.lock().provider, &message_key(id))
    }

    /// The group's held messages this session opened and holds, in log order.
    pub fn messages(&self, gid: &[u8]) -> Result<Vec<Message>> {
        self.inner.lock().messages(gid)
    }

    /// Replaces a held message's payload, as when its text is forgotten; it is still served to members as ciphertext.
    pub fn redact(&self, id: &[u8], payload: Value) -> Result<()> {
        let mut st = self.inner.lock();
        let Some(mut message) = get::<Message>(&st.provider, &message_key(id))? else {
            return Ok(());
        };
        message.payload = payload;
        put(&st.provider, &message_key(id), &message)?;
        st.scrub = true;
        Ok(())
    }

    /// A record of a kind built into the client, kept with the session's own.
    pub fn record(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.lock().provider.get(&kind_key(key))
    }

    pub fn put_record(&self, key: &str, value: &[u8]) -> Result<()> {
        self.inner.lock().provider.put(&kind_key(key), value)
    }

    pub fn delete_record(&self, key: &str) -> Result<()> {
        self.inner.lock().provider.delete(&kind_key(key))
    }

    /// Leaves in this session's files no copy of what it deleted.
    pub fn scrub(&self) -> Result<()> {
        self.inner.lock().scrub = true;
        Ok(())
    }

    /// Seals a file and holds it for a group.
    pub async fn add_file(&self, gid: &[u8], bytes: Vec<u8>) -> Result<FileLink> {
        let link = self.inner.net().add_file(std::io::Cursor::new(bytes)).await?;
        let mut st = self.inner.lock();
        st.group_mut(gid)?.rec.link(link.link());
        st.save(gid)?;
        Ok(link)
    }

    /// A file's plaintext, if it is held whole.
    pub async fn file(&self, link: &FileLink) -> Result<Option<Vec<u8>>> {
        if !self.inner.net().has(link.hash).await? {
            return Ok(None);
        }
        let mut plain = Vec::new();
        self.inner.net().read_file(link, &mut plain).await?;
        Ok(Some(plain))
    }

    /// The files this session's groups link now, which it holds.
    pub fn files(&self) -> Vec<FileLink> {
        self.groups().iter().flat_map(|gid| lmk_net::Groups::files(&*self.inner, &gid.0)).collect()
    }

    /// Fetches a file the group links, whatever its size; `Event::File` follows.
    pub fn fetch(&self, gid: &[u8], link: FileLink) {
        self.inner.work.send(Work::Fetch { group: gid.to_vec(), link }).ok();
    }

    /// The members online that hold a file whole, as soon as one does, waiting up to `wait`; none at once if no member
    /// is online.
    pub async fn holders(&self, gid: &[u8], link: &FileLink, wait: Duration) -> Vec<Member> {
        let deadline = now() + wait.as_millis() as u64;
        loop {
            let holders = self.inner.net().holders(gid, link.hash).await;
            if !holders.is_empty() || now() >= deadline || self.online(gid).is_ok_and(|online| online.is_empty()) {
                let st = self.inner.lock();
                return holders.iter().map(|peer| st.by_iroh(gid, peer)).collect();
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Waits until another member online holds a file this session added, or a few seconds; returns them. If none does,
    /// the file is pending until one fetches it.
    pub async fn spread(&self, gid: &[u8], link: &FileLink) -> Vec<Member> {
        let holders = self.holders(gid, link, MEMBER_WAIT).await;
        let mut st = self.inner.lock();
        if holders.is_empty()
            && let Ok(g) = st.group_mut(gid)
        {
            g.rec.pending.push(Pending { id: Bytes(link.hash.to_vec()), what: "file".into() });
            st.save(gid).ok();
        }
        holders
    }

    // Identities: their key logs, and certificates.

    /// The newest copy of an identity's key log, read from its service unless a copy is fresh.
    pub async fn key_log(&self, identity: &IdentityRef) -> Result<KeyLog> {
        let fresh = {
            let st = self.inner.lock();
            let read = st.logs.get(&lmk_proto::identity::address(&identity.id.0)[..]).is_some_and(|log| log.at + KEYS_FRESH >= now());
            st.keys.get(&identity.id.0).filter(|_| read).cloned()
        };
        match fresh {
            Some(log) => Ok(log),
            None => self.inner.read_keys(identity).await,
        }
    }

    /// An identity's key log, read from its service now.
    pub async fn read_key_log(&self, identity: &IdentityRef) -> Result<KeyLog> {
        self.inner.read_keys(identity).await
    }

    /// The key log held of an identity, however old.
    pub fn held_key_log(&self, identity: &[u8]) -> Option<KeyLog> {
        self.inner.lock().keys.get(identity).cloned()
    }

    /// Appends a sealed entry to an identity's key log, and reads the log.
    pub async fn append_identity(&self, identity: &IdentityRef, entry: &[u8]) -> Result<KeyLog> {
        let log = lmk_proto::identity::address(&identity.id.0);
        self.inner.clients.client(&identity.membership)?.append(&log, &[entry.to_vec()]).await?;
        self.inner.read_keys(identity).await
    }

    /// The identities this session speaks as in its groups.
    pub fn spoken(&self) -> Vec<IdentityRef> {
        let st = self.inner.lock();
        let mut spoken: Vec<IdentityRef> = Vec::new();
        for g in st.groups.values() {
            let me = g.mls.members().into_iter().find(|m| m.key == st.session.key());
            if let Some(identity) = me.and_then(|me| me.credential?.identity)
                && !spoken.contains(&identity)
            {
                spoken.push(identity);
            }
        }
        spoken
    }

    /// This session's certificate of an identity, if it holds one.
    pub fn certificate(&self, identity: &[u8]) -> Option<Envelope> {
        let st = self.inner.lock();
        st.certificate(&st.session.credential, identity).cloned()
    }

    /// Holds a certificate of this session, which it shows its peers, and reads the identity's key log, so that, if a
    /// new key is why, its peers take the new entries from this session.
    pub fn set_certificate(&self, certificate: Envelope) -> Result<()> {
        let certified = certified(&certificate).context("a certificate that does not parse")?;
        let mut st = self.inner.lock();
        ensure!(certified.key.0 == st.session.key(), "a certificate of another session");
        let address = lmk_proto::identity::address(&certified.identity.0);
        if st.logs.contains_key(&address[..]) {
            self.inner.work.send(Work::Read(address.to_vec())).ok();
        }
        let key = (certified.key.0, certified.identity.0);
        st.certificates.insert(key, certificate);
        st.save_certificates()?;
        let gids: Vec<Vec<u8>> = st.groups.keys().cloned().collect();
        st.out.extend(gids.into_iter().map(Out::Changed));
        Ok(())
    }

    /// The device's name, where this is a device's node.
    pub fn device_name(&self) -> Option<String> {
        self.inner.lock().device.clone()
    }

    /// Renames the device, in its credential in each devices group.
    pub async fn rename_device(&self, name: &str) -> Result<()> {
        self.inner.lock().device = Some(name.into());
        for gid in self.groups() {
            self.inner.commit(&gid.0, |g| Ok(renaming(g, Some(name)).map(|name| Change { name: Some(name), ..Change::default() }))).await?;
        }
        Ok(())
    }

    /// What a group this session is in looks like as an opening.
    pub fn opening(&self, gid: &[u8]) -> Result<Opening> {
        let st = self.inner.lock();
        let g = st.group(gid)?;
        let settings = g.mls.settings();
        let members = g.mls.members().into_iter().filter_map(|m| Some(m.leaf?.key)).collect();
        Ok(Opening {
            group: Bytes(gid.to_vec()),
            kind: settings.kind,
            name: settings.name,
            membership: settings.membership,
            members,
            rest: Default::default(),
        })
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    fn net(&self) -> &Net {
        self.net.get().expect("the peers start with the node")
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|task| !task.is_finished());
        tasks.push(spawn(task));
    }

    /// The browser runs on one thread, and its tasks end with the page. They are not kept: there, a task cannot ask
    /// whether tasks are finished, its own among them.
    #[cfg(target_arch = "wasm32")]
    fn spawn(&self, task: impl Future<Output = ()> + 'static) {
        spawn(task);
    }

    fn warn(&self, group: Option<&[u8]>, text: String) {
        self.events.send(Event::Warning { group: group.map(|gid| Bytes(gid.to_vec())), text }).ok();
    }

    /// Starts a step.
    pub(crate) fn lock(&self) -> Step<'_, P> {
        let guard = self.state.lock().unwrap();
        if let Err(error) = guard.provider.begin() {
            tracing::error!("starting a step: {error:#}");
        }
        Step { guard, inner: self }
    }

    /// Makes the steps committed so far durable, before what they produced leaves the node.
    async fn durable(&self) -> Result<()> {
        match &self.durable {
            Some(durable) => durable().await,
            None => Ok(()),
        }
    }

    /// Sends what steps produced for the peers, in order, once it is durable.
    async fn send_out(self: Arc<Self>, mut outbox: mpsc::UnboundedReceiver<Vec<Out>>) {
        while let Some(out) = outbox.recv().await {
            if let Err(error) = self.durable().await {
                self.warn(None, format!("saving this session's state: {error:#}"));
            }
            let Some(net) = self.net.get() else { continue };
            for out in out {
                match out {
                    Out::Push { group, ciphertext } => drop(net.send(&group, ciphertext)),
                    Out::Frame { peer, frame } => drop(net.frame(peer, frame)),
                    Out::Changed(group) => net.changed(&group),
                    Out::Served { peer, group } => net.served(peer, &group),
                }
            }
        }
    }

    /// Catches up on each group, replaces this session's keys, then again daily.
    async fn resume(self: Arc<Self>, gids: Vec<Vec<u8>>) {
        self.refresh_all().await;
        self.dial_all();
        let mut gids = gids;
        loop {
            for gid in &gids {
                let (leaf, device) = {
                    let st = self.lock();
                    (st.session.leaf.clone(), st.device.clone())
                };
                let change = |g: &Group| Ok(Some(Change { leaf: Some(leaf.clone()), name: renaming(g, device.as_deref()), ..Change::default() }));
                let updated = async {
                    self.read(gid).await.context("catching up")?;
                    self.commit(gid, change).await.context("key update")
                };
                // Unless the group was left meanwhile, as when a device leaves its identity as it starts.
                if let Err(error) = updated.await
                    && self.lock().groups.contains_key(gid)
                {
                    self.warn(Some(gid), format!("{error:#}"));
                }
            }
            sleep(KEY_UPDATE).await;
            let mut st = self.lock();
            gids = st.groups.keys().cloned().collect();
            for gid in &gids {
                if let Err(error) = st.expire(gid) {
                    self.warn(Some(gid), format!("{error:#}"));
                }
            }
            st.scrub = true;
        }
    }

    async fn redial(self: Arc<Self>) {
        loop {
            sleep(REDIAL).await;
            self.dial_all();
            self.refresh_all().await;
        }
    }

    /// Dials every member of every group that is not connected.
    fn dial_all(self: &Arc<Self>) {
        let connected = self.net().connected();
        let me = self.net().id();
        let leaves: BTreeSet<(EndpointId, String)> = {
            let st = self.lock();
            st.groups
                .values()
                .flat_map(|g| g.mls.members())
                .filter_map(|m| Some((endpoint_id(&m.leaf.as_ref()?.key.0)?, m.leaf?.relay)))
                .filter(|(peer, _)| *peer != me && !connected.contains(peer))
                .collect()
        };
        for (peer, relay) in leaves {
            let Ok(relay) = relay.parse() else { continue };
            let net = self.net().clone();
            spawn(async move {
                if let Err(error) = net.dial(peer, relay).await {
                    tracing::debug!("dialing {}: {error:#}", peer.fmt_short());
                }
            });
        }
    }

    /// Commits a change built on the group's current epoch, posts its entry, and reads the log until it is known whether
    /// it won its epoch; if another commit won, builds it again. Returns the Welcome, if it adds, and the position; none
    /// once the change has no effect (`None`), and it commits nothing. An entry posted before, which the log may or may
    /// not have taken, is posted again first: only the service's refusal drops it.
    async fn commit(&self, gid: &[u8], change: impl Fn(&Group) -> Result<Option<Change>>) -> Result<Option<(Option<Vec<u8>>, u64)>> {
        let _committing = self.committing.lock().await;
        for _ in 0..COMMIT_TRIES {
            self.caught_up(gid).await?;
            let (entry, welcome, ours, service) = {
                let mut st = self.lock();
                let st = &mut *st;
                let g = st.groups.get_mut(gid).context("this session is not in that group")?;
                let service = g.mls.settings().membership;
                match g.mls.posted() {
                    Some(posted) => (posted.to_vec(), None, false, service),
                    None => {
                        let Some(change) = change(&g.mls)? else { return Ok(None) };
                        let commit = g.mls.commit(&st.provider, &st.session, change)?;
                        (commit.entry, commit.welcome, true, service)
                    }
                }
            };
            self.durable().await?;
            let position = match self.clients.client(&service)?.append(gid, std::slice::from_ref(&entry)).await {
                Ok(appended) => appended.position,
                Err(error) if error.is::<Refused>() => {
                    let mut st = self.lock();
                    let st = &mut *st;
                    st.groups.get_mut(gid).context("left the group")?.mls.cancel(&st.provider)?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
            self.caught_up(gid).await?;
            let st = self.lock();
            ensure!(st.group(gid)?.rec.position >= position, "the log did not show the commit it took");
            if ours && st.pos(gid, position)?.is_some_and(|pos| pos.judged == reading::Judged::Commit { own: true }) {
                return Ok(Some((welcome, position)));
            }
        }
        bail!("the group kept changing over {COMMIT_TRIES} tries; try again")
    }

    /// Reads the group's log, and waits until this session applied it to the head it read.
    async fn caught_up(&self, gid: &[u8]) -> Result<()> {
        self.read(gid).await?;
        loop {
            let advanced = self.advanced.notified();
            {
                let st = self.lock();
                let g = st.group(gid)?;
                ensure!(g.mls.active(), "this session was removed from the group");
                if g.rec.position >= st.log(gid)?.logged {
                    return Ok(());
                }
            }
            advanced.await;
        }
    }

    /// Joins a group from the Welcome a member at `by` sent.
    async fn welcomed(self: &Arc<Self>, admitted: Admitted, by: EndpointId) -> Result<Bytes> {
        let gid = {
            let mut st = self.lock();
            let st = &mut *st;
            let mls = Group::join(&st.provider, &admitted.welcome.0)?;
            ensure!(!st.groups.contains_key(mls.id()), "this session is in that group already");
            let rec = Rec { position: admitted.position, start: admitted.position, expired: admitted.position, ..Rec::default() };
            let gid = st.add_group(mls, rec)?;
            for certificate in admitted.certificates {
                groups::take_certificate(st, certificate);
            }
            if admitted.doc.is_some() {
                st.groups.get_mut(&gid).unwrap().asked = now();
            }
            gid
        };
        if let Err(error) = self.read(&gid).await {
            self.warn(Some(&gid), format!("reading the group's log: {error:#}"));
        }
        self.follow(&gid);
        self.refresh_all().await;
        self.lock().out.push(Out::Changed(gid.clone()));
        self.dial_all();
        if let Some(link) = admitted.doc {
            self.state_from(&gid, link, by);
        }
        Ok(Bytes(gid))
    }

    /// Takes a state `by` handed this session, once it is fetched, and tells the group's kind.
    pub(crate) fn state_from(self: &Arc<Self>, gid: &[u8], link: String, by: EndpointId) {
        let (inner, gid) = (self.clone(), gid.to_vec());
        self.spawn(async move {
            let taken = async {
                let file = FileLink::parse(&link)?;
                {
                    let mut st = inner.lock();
                    let rec = &mut st.group_mut(&gid)?.rec;
                    rec.link(link.clone());
                    rec.state = Some(link);
                    st.save(&gid)?;
                }
                inner.fetched(&gid, &file).await?;
                let mut data = Vec::new();
                inner.net().read_file(&file, &mut data).await?;
                let from = inner.lock().by_iroh(&gid, &by);
                inner.events.send(Event::State { group: Bytes(gid.clone()), from, data }).ok();
                anyhow::Ok(())
            };
            if let Err(error) = taken.await {
                inner.warn(Some(&gid), format!("the group's state did not arrive: {error:#}"));
            }
        });
    }

    /// Seals a state of the group's kind as a file to hand a member; holds it.
    pub(crate) async fn state_file(&self, gid: &[u8], data: Vec<u8>) -> Result<String> {
        let link = self.net().add_file(std::io::Cursor::new(data)).await?.link();
        let mut st = self.lock();
        let rec = &mut st.group_mut(gid)?.rec;
        rec.link(link.clone());
        rec.state = Some(link.clone());
        st.save(gid)?;
        Ok(link)
    }

    /// Fetches, in the background, the files linked anew that are within this session's limit.
    fn fetch_within_limit(&self, gid: &[u8], links: Vec<FileLink>) {
        for link in links.into_iter().filter(|link| link.size <= self.file_limit) {
            self.work.send(Work::Fetch { group: gid.to_vec(), link }).ok();
        }
    }

    /// Fetches a file from the members online, trying for a while.
    async fn fetched(&self, gid: &[u8], link: &FileLink) -> Result<()> {
        let mut last = anyhow::anyhow!("no member online holds the file");
        for _ in 0..FETCH_TRIES {
            match self.net().fetch(gid, link).await {
                Ok(()) => return Ok(()),
                Err(error) => last = error,
            }
            sleep(MEMBER_WAIT).await;
        }
        Err(last)
    }

    /// Reads the key logs of the identities in this session's groups that are not fresh, or that a member's
    /// certificate needs read anew, then has the members removed that went too long without a valid certificate.
    async fn refresh_all(&self) {
        let stale: Vec<IdentityRef> = {
            let st = self.lock();
            let mut identities: Vec<IdentityRef> = st.groups.keys().flat_map(|gid| st.identities(gid)).collect();
            identities.dedup();
            let since = |id: &[u8]| {
                let members = st.groups.values().flat_map(|g| g.mls.members());
                let speaking = members.filter(|m| m.credential.as_ref().is_some_and(|c| c.identity.as_ref().is_some_and(|i| i.id.0 == id)));
                speaking.filter_map(|m| st.uncertified.get(&m.key).copied()).min()
            };
            identities
                .into_iter()
                .filter(|identity| {
                    let read = st.logs.get(&lmk_proto::identity::address(&identity.id.0)[..]).map(|log| log.at);
                    read.is_none_or(|at| at + KEYS_FRESH < now() || since(&identity.id.0).is_some_and(|since| at < since))
                })
                .collect()
        };
        let mut read = HashSet::new();
        for identity in stale {
            if read.insert(identity.id.clone())
                && let Err(error) = timeout(MEMBER_WAIT, self.read_keys(&identity)).await.map_err(anyhow::Error::from).and_then(|r| r)
            {
                tracing::debug!("the key log of {}: {error:#}", hex(&identity.id.0));
            }
        }
        self.revoke();
    }

    /// Waits a while for the certificates of added members that speak as identities, which the member that admitted them and they show.
    async fn await_certificates(&self, gid: &[u8], added: &[core::Member]) {
        let deadline = now() + MEMBER_WAIT.as_millis() as u64;
        let missing = || {
            let st = self.lock();
            let speaking = added.iter().filter_map(|m| Some((m.credential.as_ref()?, m.credential.as_ref()?.identity.as_ref()?)));
            speaking.into_iter().any(|(credential, identity)| st.certificate(credential, &identity.id.0).is_none())
        };
        while missing() && now() < deadline && self.lock().groups.contains_key(gid) {
            sleep(Duration::from_millis(200)).await;
        }
    }

    /// Has the members removed whose certificates are of a device taken off their identity, and those connected to this
    /// session that have gone `CERTIFICATE_GRACE` without a valid certificate of the identity they speak as, judged by a
    /// key log read since.
    fn revoke(&self) {
        let connected = self.net().connected();
        let mut st = self.lock();
        let st = &mut *st;
        self.remove_revoked(st);
        let now = now();
        let mut seen = HashSet::new();
        for (gid, g) in &st.groups {
            for member in g.mls.members() {
                let (Some(credential), Some(leaf)) = (&member.credential, &member.leaf) else { continue };
                let Some(identity) = &credential.identity else { continue };
                let Some(log) = st.keys.get(&identity.id.0) else { continue };
                if member.key == st.session.key()
                    || check(st.certificates.get(&(member.key.clone(), identity.id.0.clone())), credential, log, now).is_ok()
                    || !endpoint_id(&leaf.key.0).is_some_and(|peer| connected.contains(&peer))
                {
                    continue;
                }
                seen.insert(member.key.clone());
                let since = *st.uncertified.entry(member.key.clone()).or_insert(now);
                let read = st.logs.get(&lmk_proto::identity::address(&identity.id.0)[..]).map_or(0, |log| log.at);
                if read >= since && now >= since + CERTIFICATE_GRACE {
                    self.work.send(Work::Remove { group: gid.clone(), key: member.key.clone() }).ok();
                }
            }
        }
        st.uncertified.retain(|key, _| seen.contains(key));
    }

    /// Has the members removed whose certificates are of a device taken off their identity, connected or not.
    fn remove_revoked(&self, st: &State<P>) {
        for (gid, g) in &st.groups {
            for member in g.mls.members().into_iter().filter(|m| m.key != st.session.key()) {
                let Some(identity) = member.credential.as_ref().and_then(|c| c.identity.as_ref()) else { continue };
                let certificate = st.certificates.get(&(member.key.clone(), identity.id.0.clone()));
                if let (Some(log), Some(certificate)) = (st.keys.get(&identity.id.0), certificate)
                    && log.revokes(certificate)
                {
                    self.work.send(Work::Remove { group: gid.clone(), key: member.key.clone() }).ok();
                }
            }
        }
    }

    /// Reads an identity's key log from its service.
    async fn read_keys(&self, identity: &IdentityRef) -> Result<KeyLog> {
        let address = lmk_proto::identity::address(&identity.id.0);
        {
            let mut st = self.lock();
            if !st.logs.contains_key(&address[..]) {
                let of = logs::Of::Identity(identity.id.clone());
                st.add_log(&address, logs::Log::new(of, identity.membership.clone(), 0))?;
            }
        }
        self.read(&address).await?;
        self.lock().keys.get(&identity.id.0).cloned().context("the key log has no valid first entry")
    }

    /// Replays an identity's key log, against which its members' certificates are checked.
    pub(crate) fn keyed(&self, st: &mut State<P>, id: &[u8]) -> Result<()> {
        let entries = st.entries(&lmk_proto::identity::address(id), 0);
        if entries.is_empty() {
            return Ok(());
        }
        let log = KeyLog::replay(id.try_into()?, entries.iter().map(|entry| entry.0.as_slice()))?;
        let peers = self.net().connected();
        let before = st.served(&peers);
        st.keys.insert(id.to_vec(), log);
        let ahead: Vec<Envelope> = st.ahead.extract_if(.., |(_, identity), _| identity == id).map(|(_, certificate)| certificate).collect();
        for certificate in ahead {
            groups::take_certificate(st, certificate);
        }
        for (group, peer) in st.served(&peers).into_iter().filter(|served| !before.contains(served)) {
            st.out.push(Out::Served { peer, group });
        }
        self.remove_revoked(st);
        Ok(())
    }

    /// Leaves a group behind: its state and records go.
    fn forget(&self, gid: &[u8]) -> Result<()> {
        let mut st = self.lock();
        st.expire_to(gid, u64::MAX)?;
        let st = &mut *st;
        let g = st.groups.remove(gid).context("this session is not in that group")?;
        self.unfollow(gid);
        st.drop_log(gid)?;
        for id in &g.rec.sends {
            st.provider.delete(&sending::send_key(&id.0))?;
            st.waiters.remove(&id.0);
        }
        for position in g.rec.kind.iter().flat_map(|kind| &kind.kept) {
            st.provider.delete(&kind::kept_key(gid, *position))?;
        }
        st.provider.delete(&rec_key(gid))?;
        g.mls.delete(&st.provider)?;
        st.save_groups()?;
        st.scrub = true;
        st.out.push(Out::Changed(gid.to_vec()));
        self.advanced.notify_waiters();
        Ok(())
    }

    /// Handles what the group logic and the peers hand on, one at a time.
    async fn drive(self: Arc<Self>, mut work: mpsc::UnboundedReceiver<Work>) {
        while let Some(item) = work.recv().await {
            match item {
                Work::Applied { group, by, added, how, invite, removed, settings, gone } => {
                    self.applied(&group, by, added, how, invite, removed, settings, gone).await
                }
                Work::Read(log) => {
                    if self.reading.lock().unwrap().insert(log.clone()) {
                        let inner = self.clone();
                        self.spawn(async move {
                            if let Err(error) = inner.read(&log).await {
                                tracing::debug!("reading {}: {error:#}", hex(&log));
                            }
                            inner.reading.lock().unwrap().remove(&log);
                        });
                    }
                }
                Work::Remove { group, key } => {
                    if self.removing.lock().unwrap().insert((group.clone(), key.clone())) {
                        let inner = self.clone();
                        self.spawn(async move {
                            if let Err(error) = (Node { inner: inner.clone() }).remove(&group, &key).await
                                && inner
                                    .state
                                    .lock()
                                    .unwrap()
                                    .group(&group)
                                    .is_ok_and(|g| g.mls.members().iter().any(|m| m.key == key))
                            {
                                inner.warn(Some(&group), format!("removing a member: {error:#}"));
                            }
                            inner.removing.lock().unwrap().remove(&(group, key));
                        });
                    }
                }
                Work::Gone(group) => self.gone(&group, None),
                Work::Fetch { group, link } => {
                    if self.net().has(link.hash).await.unwrap_or(false) {
                        self.events.send(Event::File(link.hash)).ok();
                        continue;
                    }
                    let inner = self.clone();
                    self.spawn(async move {
                        if let Err(error) = inner.fetched(&group, &link).await {
                            tracing::debug!("fetching {}: {error:#}", link.link());
                        }
                    });
                }
                Work::State { group, link, by } => self.state_from(&group, link, by),
                Work::StateWanted { group, by } => self.hand_snapshot(&group, by),
                Work::Send(gid) => {
                    if self.sending.lock().unwrap().insert(gid.clone()) {
                        let inner = self.clone();
                        self.spawn(async move {
                            inner.sends(&gid).await;
                            inner.sending.lock().unwrap().remove(&gid);
                        });
                    }
                }
                Work::Wait(gid) => {
                    let inner = self.clone();
                    self.spawn(async move {
                        loop {
                            sleep(Duration::from_secs(1)).await;
                            let mut st = inner.lock();
                            match inner.wait_over(&mut st, &gid) {
                                Ok(false) => {}
                                Ok(true) => return,
                                Err(error) => return inner.warn(Some(&gid), format!("{error:#}")),
                            }
                        }
                    });
                }
                Work::Net(event) => self.net_event(event),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn applied(
        self: &Arc<Self>,
        gid: &[u8],
        by: Option<core::Member>,
        added: Vec<core::Member>,
        how: Option<How>,
        invite: Option<Bytes>,
        removed: Vec<core::Member>,
        settings: bool,
        gone: bool,
    ) {
        if !added.is_empty() {
            self.refresh_all().await;
            self.dial_all();
            self.await_certificates(gid, &added).await;
        }
        let group = Bytes(gid.to_vec());
        let st = self.lock();
        if !added.is_empty()
            && let Err(error) = st.save_certificates()
        {
            self.warn(Some(gid), format!("{error:#}"));
        }
        let by = by.and_then(|by| st.member(gid, &by));
        if gone {
            drop(st);
            self.gone(gid, by);
            return;
        }
        let Some(by) = by else { return };
        let how = how.unwrap_or(How::Invite);
        let me = st.session.key().to_vec();
        let rule = st.group(gid).ok().and_then(|g| g.rec.invites.iter().find(|rule| Some(&rule.hash) == invite.as_ref()).cloned());
        let introduces = match how {
            How::Open => by.key.0 == me,
            _ => rule.as_ref().is_some_and(|rule| rule.by.0 == me),
        };
        let label = rule.and_then(|rule| rule.label).filter(|_| introduces);
        for member in &added {
            if let Some(member) = st.member(gid, member) {
                let event = Event::Joined { group: group.clone(), member, by: by.clone(), how: how.clone(), introduces, label: label.clone() };
                self.events.send(event).ok();
            }
        }
        for member in &removed {
            if let Some(member) = st.member(gid, member) {
                self.events.send(Event::Left { group: group.clone(), member, by: by.clone() }).ok();
            }
        }
        if settings && let Ok(g) = st.group(gid) {
            self.events.send(Event::Settings { group, settings: g.mls.settings(), by }).ok();
        }
        if !removed.is_empty()
            && let Err(error) = self.leavers(&st, gid)
        {
            self.warn(Some(gid), format!("{error:#}"));
        }
    }

    /// Tells that this session is out of a group, then forgets it, unless it did so already.
    fn gone(&self, gid: &[u8], by: Option<Member>) {
        if !self.lock().groups.contains_key(gid) {
            return;
        }
        self.events.send(Event::Removed { group: Bytes(gid.to_vec()), by }).ok();
        if let Err(error) = self.forget(gid) {
            self.warn(Some(gid), format!("{error:#}"));
        }
    }

    /// Has the members removed whose counted `leave`, sealed since the Add that brought them in last, this session holds;
    /// has the group gone once this session's own counted and it is the only member left.
    fn leavers(&self, st: &State<P>, gid: &[u8]) -> Result<()> {
        let Ok(g) = st.group(gid) else { return Ok(()) };
        let added = |key: &[u8]| g.mls.added().iter().rev().find(|added| added.member.key.0 == key).map_or(0, |added| added.epoch);
        let leaving: HashSet<&[u8]> = g.rec.leaves.iter().filter(|(key, epoch)| *epoch >= added(&key.0)).map(|(key, _)| key.0.as_slice()).collect();
        let me = st.session.key();
        let members = g.mls.members();
        if members.len() == 1 && leaving.contains(me) {
            self.work.send(Work::Gone(gid.to_vec())).ok();
        }
        for member in members.into_iter().filter(|m| m.key != me && leaving.contains(m.key.as_slice())) {
            self.work.send(Work::Remove { group: gid.to_vec(), key: member.key }).ok();
        }
        Ok(())
    }

    fn net_event(self: &Arc<Self>, event: lmk_net::Event) {
        match event {
            lmk_net::Event::Contradiction { log, peer, ours, theirs } => {
                let st = self.lock();
                self.contradicted(&st, &log, &Contradiction { ours, theirs }, &peer.fmt_short().to_string());
            }
            lmk_net::Event::Fetched(hash) => {
                let mut st = self.lock();
                let gids: Vec<Vec<u8>> = st.groups.keys().cloned().collect();
                for gid in gids {
                    let g = st.groups.get_mut(&gid).unwrap();
                    let before = g.rec.pending.len();
                    g.rec.pending.retain(|pending| pending.id.0 != hash);
                    if g.rec.pending.len() != before {
                        st.save(&gid).ok();
                    }
                }
                self.events.send(Event::File(hash)).ok();
            }
            lmk_net::Event::Synced { group, peer } => {
                self.events.send(Event::Synced { group: Bytes(group.clone()) }).ok();
                let mut st = self.lock();
                if let Err(error) = self.leavers(&st, &group) {
                    self.warn(Some(&group), format!("{error:#}"));
                }
                if let Err(error) = self.progress(&mut st, &group, reading::Progress::Synced(peer)) {
                    self.warn(Some(&group), format!("{error:#}"));
                }
                drop(st);
                // A file only this session held may have reached the peer since.
                let pending: Vec<[u8; 32]> = {
                    let st = self.lock();
                    let Ok(g) = st.group(&group) else { return };
                    g.rec
                        .pending
                        .iter()
                        .filter(|p| p.what == "file")
                        .filter_map(|p| p.id.0.as_slice().try_into().ok())
                        .collect()
                };
                for hash in pending {
                    let (net, inner, group) = (self.net().clone(), self.clone(), group.clone());
                    spawn(async move {
                        if net.holders(&group, hash).await.contains(&peer) {
                            let mut st = inner.lock();
                            if let Ok(g) = st.group_mut(&group) {
                                g.rec.pending.retain(|pending| pending.id.0 != hash);
                                st.save(&group).ok();
                            }
                        }
                    });
                }
            }
            lmk_net::Event::InStep { group, peer } => {
                let mut st = self.lock();
                if st.group(&group).is_ok_and(|g| g.rec.kind.as_ref().is_some_and(|kind| kind.behind)) {
                    self.ask_state(&mut st, &group, Some(peer));
                }
                let member = st.by_iroh(&group, &peer);
                self.events.send(Event::InStep { group: Bytes(group), member }).ok();
            }
            lmk_net::Event::Connected(peer) => {
                let mut st = self.lock();
                let gids: Vec<Vec<u8>> = st.groups.keys().filter(|gid| st.serves(gid, &peer)).cloned().collect();
                for gid in gids {
                    if let Err(error) = self.progress(&mut st, &gid, reading::Progress::Connected(peer)) {
                        self.warn(Some(&gid), format!("{error:#}"));
                    }
                }
            }
            lmk_net::Event::Disconnected(peer) => {
                let mut st = self.lock();
                let gids: Vec<Vec<u8>> = st.groups.keys().cloned().collect();
                for gid in gids {
                    if let Err(error) = self.progress(&mut st, &gid, reading::Progress::Disconnected(peer)) {
                        self.warn(Some(&gid), format!("{error:#}"));
                    }
                }
            }
        }
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Reports a log that its service showed differently, here and at `there`, unless it reported those two heads of it
    /// already.
    pub(crate) fn contradicted(&self, st: &State<P>, log: &[u8], contradiction: &Contradiction, there: &str) {
        let Contradiction { ours, theirs } = contradiction;
        let mut heads = [(ours.length, ours.hash.0.clone()), (theirs.length, theirs.hash.0.clone())];
        heads.sort();
        if !self.contradictions.lock().unwrap().insert((log.to_vec(), heads)) {
            return;
        }
        let what = match st.logs.get(log).map(|l| &l.of) {
            Some(logs::Of::Identity(_)) => "a key log",
            _ => "the group's log",
        };
        let text = format!(
            "the membership service showed {there} another version of {what}: length {} with hash {} here, length {} with hash {} there",
            ours.length,
            hex(&ours.hash.0),
            theirs.length,
            hex(&theirs.hash.0)
        );
        let groups = st.groups_of(log);
        if groups.is_empty() {
            self.warn(None, text.clone());
        }
        for gid in groups {
            self.warn(Some(&gid), text.clone());
        }
    }
}

/// The name this session takes in a group: in a devices group, the device's, where its credential names another.
fn renaming(g: &Group, device: Option<&str>) -> Option<String> {
    let own = g.members().into_iter().find(|m| m.index == g.own_index())?.credential?;
    let device = device.filter(|device| g.settings().kind == DEVICES && own.name != *device)?;
    Some(device.to_owned())
}

/// A member to dial, as an invite link names it.
fn address(key: [u8; 32], relay: &str) -> Address {
    let ours = RELAY.parse::<RelayUrl>().ok();
    Address { key, relay: (relay.parse::<RelayUrl>().ok() != ours).then(|| relay.to_string()) }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_holds_files_linked_within_h_its_state_and_its_kinds_links() {
        let link = |n: u8| FileLink { hash: [n; 32], size: 1, key: [0; 32] }.link();
        let old = now() - 3 * 24 * 3600 * 1000;
        let files = vec![(link(1), old), (link(2), now()), (link(3), old)];
        let rec = Rec { files, state: Some(link(3)), links: vec![link(4)], ..Rec::default() };
        let held: Vec<u8> = rec.held(2).iter().map(|file| file.hash[0]).collect();
        assert_eq!(held, [2, 3, 4]);
    }
}
