//! One member's session over lmk-core, lmk-net and lmk-membership: its groups and their logs, its held messages and
//! files, the invites it shares and the joiners it admits, and its members' identities: their key logs, against which
//! their credentials' certificates are checked. A group's kind sees its content through the channels here (held
//! messages in log order, live ones, files, and a state link for joiners), and nothing of the rest; the core reads only
//! its own payloads (`Control`). The devices kind (`devices`) is built on those channels. It stores everything through
//! the core's `Provider`, so the same code runs natively (SQLite) and in the browser (memory the web client persists),
//! one transaction per step (`Step`): nothing a step produces leaves the node before its transaction commits.

mod admission;
mod api;
pub mod devices;
mod duties;
mod groups;
mod kind;
mod logs;
mod peering;
mod reading;
mod sending;
mod tasks;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use anyhow::{Context, Result};
use iroh::tls::CaTlsConfig;
use iroh::{EndpointId, RelayUrl, SecretKey};
use lmk_core::device::{Device, signer};
use lmk_core::group::{self as core, Group, Session};
use lmk_core::identity::{KeyLog, Verdict};
use lmk_core::provider::Provider;
use lmk_net::peers::{self, Peers};
use lmk_net::Net;
use lmk_proto::group::{Certificate, Credential, How, IdentityRef, Settings};
use lmk_proto::links::FileLink;
use lmk_proto::peer::Frame;
use lmk_proto::ranges::Ranges;
use lmk_proto::Bytes;
use n0_future::boxed::BoxFuture;
use n0_future::task::{JoinHandle, spawn};
use n0_future::time::Duration;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

pub use lmk_core;
pub use lmk_net::{Disk, Fetch};
pub use peering::Heard;
pub use lmk_proto::clock::now;

/// Why a send's outcome never came.
const UNFINISHED: &str = "the send ended unfinished, as this session stopped or left the group";
/// How long `send` waits for its entry to count before it answers that the send is pending.
const SEND_WAIT: Duration = Duration::from_secs(5);
/// How long some waits for other members last: for those online to hold a file or an invite, for added members'
/// certificates.
const MEMBER_WAIT: Duration = Duration::from_secs(5);
/// How often a followed log is read again whole.
const REREAD: Duration = Duration::from_secs(5 * 60);
/// How long a member admitting a joiner waits for the state of the group's kind.
const SNAPSHOT_WAIT: Duration = Duration::from_secs(10);
/// How long a session whose kind is behind waits before it asks a member for the kind's state again, in milliseconds.
const STATE_ASK: u64 = 60 * 1000;

pub struct Config {
    /// The session's name, fixed when it is created.
    pub name: String,
    /// The device, where this is a device's node or a browser's one session: its name is its credential's in its
    /// devices groups, each of which this node joins with a key of its own, the device's key on that identity.
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
    /// Told what each step did once it commits, as a simulator checks it. It must not call the node.
    pub observe: Option<Observe>,
}

/// Makes the steps committed so far durable.
pub type Durable = Arc<dyn Fn() -> BoxFuture<Result<()>> + Send + Sync>;

pub type Observe = Arc<dyn Fn(Observation) + Send + Sync>;

/// What a step did to a group, for `Config::observe`.
#[derive(Clone, Debug)]
pub enum Observation {
    /// A position of the group's log judged, in the epoch current then; `entry` is SHA-256 of its bytes.
    Read { group: Bytes, position: u64, entry: [u8; 32], epoch: u64, verdict: Judgement },
    /// This session is in the group with `key` from after `start`: its Add, or 0 for the group's creator.
    Joined { group: Bytes, key: Bytes, start: u64 },
    /// The last position of the group's log held.
    Head { group: Bytes, head: u64 },
    /// A counted position opened, or one of this session's own: of the group's kind or a core payload's type, with
    /// SHA-256 of its payload.
    Opened { group: Bytes, position: u64, kind: String, sender: Bytes, plaintext: [u8; 32] },
    Lost { group: Bytes, position: u64 },
    /// This session's own `lost` counted at `position`.
    Announced { group: Bytes, position: u64, positions: Vec<u64> },
    /// A position kept for a kind other than chat.
    Handed { group: Bytes, kind: String, position: u64 },
    Live { group: Bytes, sender: Bytes, epoch: u64 },
    /// A state of the group's kind taken from the member with key `from`.
    State { group: Bytes, from: Bytes },
    /// This session let go of the group other than by its removal.
    Dropped { group: Bytes, reason: Dropped },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Judgement {
    Commit { committer: Bytes, added: Vec<Bytes>, removed: Vec<Bytes> },
    Counted { id: Bytes },
    Skipped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
    Retention,
    Copied,
    /// It asked to leave, and its leaf was the group's only one.
    Forgotten,
}

/// A group member, from its leaf and credential, and its credential's certificate checked against its identity's key
/// log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The session key: the MLS signature key.
    pub key: Bytes,
    /// The iroh key its leaf names.
    pub iroh: Bytes,
    /// The protocol revision its leaf names.
    pub revision: u32,
    pub name: String,
    /// The name of its device, as its identity's key log lists it.
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
    /// Why it is not verified, if it is not: its device is not on the identity's list.
    pub error: Option<String>,
    /// Its device was added to the identity after the identity's first devices.
    pub added: bool,
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
    /// The counted positions before it that were passed over unopened, as it is handed on in position order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<u64>,
}

/// Counted positions a member can no longer open: as it announced them, or this session's own as it learns them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lost {
    pub group: Bytes,
    /// Where it is told in log order: the announcement's position, or this session's own lost position.
    pub position: u64,
    pub member: Member,
    pub positions: Vec<u64>,
    /// The ids of the lost messages, those this session knows.
    pub ids: Vec<Bytes>,
}

/// What the kind takes in log order: its held messages, and the losses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Item {
    Entry(Entry),
    Lost(Lost),
}

impl Item {
    pub fn position(&self) -> u64 {
        match self {
            Item::Entry(entry) => entry.position,
            Item::Lost(lost) => lost.position,
        }
    }
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
    /// This session's commit removed members whose devices their identities' key logs dropped. `added`: the members
    /// still in the group that they added, or that came in by invites they made, which only a member's `remove` takes out.
    Revoked {
        group: Bytes,
        removed: Vec<Member>,
        added: Vec<Member>,
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
    /// A held payload of the group's kind, opened, in position order; never one of this session's own. One opened after
    /// later ones were handed on comes when it opens.
    Message(Message),
    /// Losses that concern this session's user: its own, as it announced them, and other members' of its messages.
    Lost(Lost),
    /// A live payload of the group's kind: not held.
    Live {
        group: Bytes,
        sender: Member,
        payload: Value,
    },
    /// A connected member's `hello` shows the same head of the group's log as this session's: a time to compare the
    /// kind's state.
    Synced {
        group: Bytes,
        member: Member,
    },
    /// A member's summary of the group was heard: who holds and read what may have changed (`Node::heard`).
    Heard {
        group: Bytes,
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
    /// An identity's key log grew, as this session read it.
    Keys { identity: Bytes },
    /// A pass of a devices group's duties ran: the devices kind runs its own.
    Duties {
        group: Bytes,
    },
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
            | Event::Revoked { group, .. }
            | Event::Removed { group, .. }
            | Event::Settings { group, .. }
            | Event::Live { group, .. }
            | Event::Synced { group, .. }
            | Event::Heard { group }
            | Event::Duties { group }
            | Event::State { group, .. }
            | Event::Logged { group }
            | Event::Snapshot { group, .. }
            | Event::Introduced { group, .. }
            | Event::Sent { group, .. } => Some(group),
            Event::Message(message) => Some(&message.group),
            Event::Lost(lost) => Some(&lost.group),
            Event::Warning { group, .. } => group.as_ref(),
            Event::File(_) | Event::Keys { .. } => None,
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
    /// The files this session added that no other member held yet.
    pending: Vec<[u8; 32]>,
    /// File links, with when they were linked: those the kind holds (its files added, and those its held messages
    /// link) and states handed to or by this session. Each is held for the group's H.
    files: Vec<(String, u64)>,
    /// The files the kind links now, held while it does.
    links: Vec<String>,
    /// What the kind took of the group's held messages, once it follows them.
    kind: Option<kind::Kind>,
    /// The invites shared with the group, kept for H after they expire.
    invites: Vec<Rule>,
    /// The current members added since this session's start: each one's key, and its start, the position of its Add.
    starts: Vec<(Bytes, u64)>,
    /// Counted `leave`s: each sender's key, and the epoch it was sealed in; kept until moot.
    leaves: Vec<(Bytes, u64)>,
    /// This session asked to leave: it asks the others to remove it until one does.
    leaving: bool,
    /// When this session's leaf was last updated, in milliseconds.
    updated: u64,
    /// Counted `lost`s, by position: the sender's key, and the positions it lost.
    losses: BTreeMap<u64, (Bytes, Vec<u64>)>,
    /// The last position handed on as events in position order, and the counted ones passed over unopened since the
    /// last message handed on.
    shown: u64,
    missing: Vec<u64>,
    /// Of the positions kept (after `expired`): the counted ones; those of this session's sends; those lacking their
    /// ciphertext, which this session can still open; this session's known losses; and those its client marked read.
    messages: Ranges,
    own: Ranges,
    lacking: Ranges,
    lost: Ranges,
    read: Ranges,
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

    /// The files this session holds for the group: those linked within H, and those the kind links now.
    fn held(&self, carry: u32) -> Vec<FileLink> {
        let since = now().saturating_sub(days(carry));
        let linked = self.files.iter().filter(|(_, at)| *at >= since).map(|(link, _)| link);
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
    /// Ciphertexts that came before their entries were read, of the current epoch or the next, and the peers that sent
    /// them.
    early: Vec<(EndpointId, Vec<u8>)>,
    /// When this session last asked a member for the kind's state, or was handed one, in milliseconds.
    asked: u64,
    /// Reading waits before a commit that deletes the keys of an epoch whose messages this session lacks.
    waiting: bool,
    /// Each peer's latest summary of the group, by its iroh key, as saved.
    heard: BTreeMap<Bytes, peers::Heard>,
    /// The key logs this session follows of the identities the group's members speak as.
    keys: Vec<Vec<u8>>,
}

impl G {
    fn new(mls: Group, rec: Rec, heard: BTreeMap<Bytes, peers::Heard>) -> Self {
        G { mls, rec, early: Vec::new(), asked: 0, waiting: false, heard, keys: Vec::new() }
    }
}

pub(crate) struct State<P> {
    provider: P,
    /// What the current step produced for the peers, sent once it commits.
    out: Vec<Out>,
    /// The current step deleted what should leave no copy: scrub once it commits.
    scrub: bool,
    /// What the current step did, told `Config::observe` once it commits; kept only while there is one.
    observed: Vec<Observation>,
    observing: bool,
    session: Session,
    /// The device's name, which its credential names in its devices groups, where this is a device's node.
    device: Option<String>,
    groups: BTreeMap<Vec<u8>, G>,
    /// The logs this session follows, by id.
    logs: BTreeMap<Vec<u8>, logs::Log>,
    /// Key logs, by identity id.
    keys: BTreeMap<Vec<u8>, KeyLog>,
    /// The identities and devices this session read a key log again for, as members' certificates named devices it
    /// did not list.
    unlisted: HashSet<(Vec<u8>, Vec<u8>)>,
    /// In each devices group, this node's own key there, the device's key on that identity: its seed, and the member.
    device_keys: BTreeMap<Vec<u8>, ([u8; 32], Session)>,
    /// `send`s waiting for their entries to count, by the id they started with.
    waiters: HashMap<Vec<u8>, Vec<oneshot::Sender<sending::Outcome>>>,
    peers: Peers,
    /// The peers connected now, and the groups the gate admits each to.
    served: BTreeMap<EndpointId, BTreeSet<Bytes>>,
    /// The rosters or the key logs changed since `served` was worked out.
    gate: bool,
    /// The latest time a step saw, in milliseconds: `Peers` takes no time from before.
    time: u64,
}

/// What a step produced for the peers.
pub(crate) enum Out {
    Frame { peer: EndpointId, frame: Frame },
    /// Ask the peer for the files the group links that this session lacks.
    WantFiles { peer: EndpointId, group: Vec<u8> },
    /// A send's outcome, for those waiting on it.
    Outcome { waiters: Vec<oneshot::Sender<sending::Outcome>>, outcome: sending::Outcome },
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
        self.guard.tell_peers();
        if let Err(error) = self.guard.provider.commit() {
            tracing::error!("committing a step: {error:#}");
        }
        if std::mem::take(&mut self.guard.scrub)
            && let Err(error) = self.guard.provider.scrub()
        {
            self.inner.warn(None, format!("{error:#}"));
        }
        if let Some(observe) = &self.inner.observe {
            for observation in std::mem::take(&mut self.guard.observed) {
                observe(observation);
            }
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
    /// A group's duties to run.
    Duties(Vec<u8>),
    /// A group this session is out of, by no one's commit.
    Gone(Vec<u8>),
    Fetch {
        group: Vec<u8>,
        link: FileLink,
    },
    /// Held sends of a group to append.
    Send(Vec<u8>),
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
    observe: Option<Observe>,
    committing: tokio::sync::Mutex<()>,
    /// Woken whenever a group's log is read further, for sends waiting to reach its head.
    advanced: tokio::sync::Notify,
    /// Woken whenever a peer's summary is heard.
    heard: tokio::sync::Notify,
    reading: Mutex<HashSet<Vec<u8>>>,
    /// The groups whose held sends are being appended.
    sending: Mutex<HashSet<Vec<u8>>>,
    /// The groups whose duties run, each with whether another pass is due once it ends.
    passing: Mutex<HashMap<Vec<u8>, bool>>,
    /// The groups with a timer for their next update.
    timers: Mutex<HashSet<Vec<u8>>>,
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

fn device_key_key(gid: &[u8]) -> Vec<u8> {
    [b"node/device-key/".as_slice(), gid].concat()
}

fn endpoint_id(key: &[u8]) -> Option<EndpointId> {
    EndpointId::from_bytes(key.try_into().ok()?).ok()
}

impl<P: Provider> State<P> {
    pub(crate) fn observe(&mut self, observation: impl FnOnce() -> Observation) {
        if self.observing {
            self.observed.push(observation());
        }
    }

    /// What the credential of the group this session makes or joins next names: the certificate of its identity.
    fn speak(&mut self, identity: Option<Certificate>) {
        self.session.credential.certificate = identity.map(Box::new);
    }

    /// A new device key, for a devices group this node makes or joins, whose credential names the device.
    fn device_key(&self) -> Result<([u8; 32], Session)> {
        let seed = lmk_core::random();
        Ok((seed, self.keyed(seed)?))
    }

    fn keyed(&self, seed: [u8; 32]) -> Result<Session> {
        Session::with_signer(&self.provider, signer(&seed), self.device.as_deref().unwrap_or_default(), self.session.leaf.clone())
    }

    /// This session as a member of a group: in a devices group, the device's key there.
    fn session_of(&self, gid: &[u8]) -> &Session {
        self.device_keys.get(gid).map_or(&self.session, |(_, session)| session)
    }

    /// This session's key in a group.
    fn me(&self, gid: &[u8]) -> &[u8] {
        self.session_of(gid).key()
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
        let claim = credential.identity().map(|identity| self.claim(&credential, identity));
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

    /// The identity a member speaks as, checked; and its device's name, if its identity lists the device.
    fn claim(&self, credential: &Credential, identity: &IdentityRef) -> (Claim, Option<String>) {
        let identity = identity.clone();
        let Some(log) = self.keys.get(&identity.id.0) else {
            let error = Some("its identity's key log could not be read yet".into());
            return (Claim { identity, name: String::new(), error, added: false }, None);
        };
        let name = log.name.clone();
        let error = match log.verify(credential) {
            Verdict::Verified { device, added } => return (Claim { identity, name, error: None, added }, Some(device)),
            Verdict::Unverified => "its device is not on its identity's list",
            Verdict::Dropped => "its device was taken off its identity",
        };
        (Claim { identity, name, error: Some(error.into()), added: false }, None)
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

    /// Whether this session serves a peer a group: it is a member and, speaking as an identity, its device is on the
    /// identity's list.
    fn serves(&self, gid: &[u8], peer: &EndpointId) -> bool {
        let Some(member) = self.in_leaf(gid, peer) else { return false };
        let Some((credential, identity)) = member.credential.as_ref().and_then(|c| Some((c, c.identity()?))) else {
            return true;
        };
        let log = self.keys.get(&identity.id.0);
        log.is_some_and(|log| matches!(log.verify(credential), Verdict::Verified { .. }))
    }

    /// The connected peers in a leaf of the group the gate cannot check yet: their identities' key logs are unread.
    fn undecided(&self, gid: &[u8]) -> BTreeSet<[u8; 32]> {
        let unread = |member: core::Member| member.credential?.identity().is_some_and(|identity| !self.keys.contains_key(&identity.id.0)).then_some(());
        self.served.keys().filter(|peer| self.in_leaf(gid, peer).and_then(unread).is_some()).map(|peer| *peer.as_bytes()).collect()
    }

    /// The identities a group's members speak as.
    fn identities(&self, gid: &[u8]) -> Vec<IdentityRef> {
        let Some(g) = self.groups.get(gid) else { return Vec::new() };
        g.mls.members().into_iter().filter_map(|m| Some(m.credential?.certificate?.identity)).collect()
    }

    /// A new group's records, its MLS state, and its log, read after `rec.position`.
    fn add_group(&mut self, mls: Group, mut rec: Rec) -> Result<Vec<u8>> {
        let gid = mls.id().to_vec();
        (rec.updated, rec.shown) = (now(), rec.position);
        let own = mls.members().into_iter().find(|m| m.index == mls.own_index()).context("a member of its group")?;
        let (key, start) = (Bytes(own.key), rec.start);
        self.observe(|| Observation::Joined { group: Bytes(gid.clone()), key, start });
        self.add_log(&gid, logs::Log::new(logs::Of::Group, mls.settings().membership, rec.position))?;
        self.groups.insert(gid.clone(), G::new(mls, rec, BTreeMap::new()));
        self.save(&gid)?;
        self.save_groups()?;
        self.gate = true;
        Ok(gid)
    }
}

/// A group's counted positions, of those kept: those whose ciphertext this session holds, those it opened or sent, and
/// its known losses; with its start, and the last position it judged.
#[derive(Clone, Debug)]
pub struct Positions {
    pub start: u64,
    pub head: u64,
    pub held: Ranges,
    pub opened: Ranges,
    pub lost: Ranges,
}

/// A group's records as storage holds them, which a session starts from.
#[derive(Clone, Debug)]
pub struct Saved {
    /// openmls's.
    pub epoch: u64,
    pub start: u64,
    /// What this session kept of positions up to here is gone, read longer than H ago.
    pub expired: u64,
    /// The last position judged, and the last held.
    pub head: u64,
    pub logged: u64,
    /// The kept positions with a verdict, and the commits among them with the epoch each was judged in.
    pub judged: Vec<u64>,
    pub commits: Vec<(u64, u64)>,
    /// As the summary shows it.
    pub held: Ranges,
    /// SHA-256 of the entries saved for posting: a staged commit's, and pending sends'.
    pub entries: Vec<[u8; 32]>,
    /// The epochs pending sends are sealed in.
    pub sends: Vec<u64>,
    /// The iroh keys of the peers whose summaries are kept, and of the current epoch's leaves.
    pub summaries: Vec<Bytes>,
    pub roster: Vec<Bytes>,
}

/// A group's records, read from storage alone; none if this session holds none of it.
pub fn saved(provider: &impl Provider, gid: &[u8]) -> Result<Option<Saved>> {
    let Some(rec) = get::<Rec>(provider, &rec_key(gid))? else { return Ok(None) };
    let mls = Group::load(provider, gid)?;
    let log: logs::Log = get(provider, &logs::log_key(gid))?.context("a group without its log")?;
    let (mut judged, mut commits) = (Vec::new(), Vec::new());
    for position in rec.expired + 1..=rec.position {
        let Some(pos) = get::<reading::Pos>(provider, &reading::pos_key(gid, position))? else { continue };
        judged.push(position);
        if let reading::Judged::Commit { .. } = pos.judged {
            commits.push((position, pos.epoch));
        }
    }
    let mut entries: Vec<[u8; 32]> = mls.posted().map(|posted| Sha256::digest(posted).into()).into_iter().collect();
    let mut sends = Vec::new();
    for handle in &rec.sends {
        let (epoch, entry) = sending::sealed(provider, &handle.0)?;
        entries.push(Sha256::digest(entry).into());
        sends.push(epoch);
    }
    Ok(Some(Saved {
        epoch: mls.epoch(),
        start: rec.start,
        expired: rec.expired,
        head: rec.position,
        logged: log.logged,
        judged,
        commits,
        held: Ranges::range(rec.expired + 1, rec.position).difference(&rec.lacking).difference(&rec.lost),
        entries,
        sends,
        summaries: peering::load_heard(provider, gid)?.into_keys().collect(),
        roster: mls.members().into_iter().filter_map(|m| Some(m.leaf?.key)).collect(),
    }))
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

}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_holds_files_linked_within_h_and_its_kinds_links() {
        let link = |n: u8| FileLink { hash: [n; 32], size: 1, key: [0; 32] }.link();
        let old = now() - 3 * 24 * 3600 * 1000;
        let files = vec![(link(1), old), (link(2), now())];
        let rec = Rec { files, links: vec![link(3)], ..Rec::default() };
        let held: Vec<u8> = rec.held(2).iter().map(|file| file.hash[0]).collect();
        assert_eq!(held, [2, 3]);
    }
}
