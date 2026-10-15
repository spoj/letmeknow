//! One member's session over lmk-core, lmk-net and lmk-membership: its groups and their logs of commits, its held
//! messages and files, the invites it shares and the joiners it admits, and its members' identities: their public logs,
//! against which their credentials' certificates are checked. Held messages travel between members and are delivered
//! in causal order; commits keep them, by their cuts. A group's kind sees its content through the channels here (held
//! messages as delivered, live ones, files, and a state link for joiners), and nothing of the rest; the core reads only
//! its own payloads (`Control`). The identity kind (`devices`) is built on those channels. It stores everything through
//! the core's `Provider`, so the same code runs natively (SQLite) and in the browser (memory the web client persists),
//! one transaction per step (`Step`): nothing a step produces leaves the node before its transaction commits.

mod admission;
mod api;
pub mod identity;
mod duties;
mod groups;
mod held;
mod kind;
mod logs;
mod peering;
mod reading;
mod sending;
mod tasks;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use anyhow::{Context, Result};
use iroh::tls::CaTlsConfig;
use iroh::{EndpointId, RelayUrl, SecretKey};
use lmk_core::device::{Device, signer};
use lmk_core::group::{self as core, Group, Session};
use lmk_core::public::{PublicLog, Verdict};
use lmk_core::provider::Provider;
use lmk_membership::client::{Post, Resolve};
use lmk_net::peers::Peers;
use lmk_net::Net;
use lmk_proto::group::{Certificate, Credential, How, IdentityRef, Settings};
use lmk_proto::links::FileLink;
use lmk_proto::peer::{Frame, Seqs, Signed};
use lmk_proto::Bytes;
use n0_future::boxed::BoxFuture;
use n0_future::task::{JoinHandle, spawn};
use n0_future::time::Duration;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

use held::Author;

pub use lmk_core;
pub use lmk_net::Disk;
pub use peering::Heard;
pub use lmk_proto::clock::now;

/// How long an invite is valid, in milliseconds.
pub const INVITE_VALID: u64 = 10 * 60 * 1000;
/// How often files no group holds any longer are deleted.
pub const COLLECT: Duration = Duration::from_secs(60 * 60);
const PERSISTENCE_FAILED: &str = "local persistence failed";
/// How long some waits for other members last: for those online to hold a file or an invite, for added members'
/// certificates.
const MEMBER_WAIT: Duration = Duration::from_secs(5);
/// How long a member admitting a joiner waits for the state of the group's kind.
const SNAPSHOT_WAIT: Duration = Duration::from_secs(10);

pub struct Config {
    /// The name its credential gives it in groups but identity groups, fixed when it is created: a session process's
    /// handle, or empty for a device's node.
    pub handle: String,
    /// The device, where this is a device's node or a browser's one session: its name is its credential's in its
    /// identity groups, each of which this node joins with a key of its own, the device's key on that identity.
    pub device: Option<Device>,
    /// The relays of this session's directory: the relays it lives on unless `chosen` names others, and the fallback of
    /// every dial.
    pub relays: Vec<RelayUrl>,
    /// The relays this session lives on instead of its directory's; every dial hints them.
    pub chosen: Vec<RelayUrl>,
    /// Resolves a domain to its directory, as the shell holds it.
    pub resolve: Resolve,
    /// Posts to a membership service's routes, as the shell does over https.
    pub post: Post,
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

/// Makes the steps committed so far durable. A failure stops dependent output until the node restarts.
pub type Durable = Arc<dyn Fn() -> BoxFuture<Result<()>> + Send + Sync>;

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
    /// Its credential's name: its device's name in an identity group, and in any other its session's handle.
    pub name: String,
    /// Its authorized certificate's private device label.
    pub device_name: String,
    pub identity: Option<Claim>,
    /// Who added it, by session key, and how; none for the group's creator and this session.
    pub added: Option<(Bytes, How)>,
}

/// The identity a member speaks as, its certificate checked against the identity's public log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub identity: IdentityRef,
    /// Its authorized device's signed private name claim.
    pub name: String,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<Observation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub names: Vec<String>,
    pub other_ids: Vec<Bytes>,
}

/// A held message of the group as this session delivered it: a payload of its kind, or one of the core's.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: Bytes,
    pub group: Bytes,
    /// Its place in this session's delivery order of the group.
    pub index: u64,
    /// When it was delivered here, in milliseconds since the Unix epoch.
    pub at: u64,
    pub sender: Member,
    /// Its author's membership began in epoch `joined`; it is that membership's `seq`th held message.
    pub joined: u64,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Bytes>,
    pub payload: Value,
    /// The seqs its requirements reached that this session gave up on, each named once.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<Seqs>,
    /// Messages that needed it were delivered without it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub late: bool,
    /// Its `reply_to` is not in its causal past, as far as this session knows that past whole.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reply_outside: bool,
}

/// Held messages a member can no longer have, as this session found its own or a member's summary told them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lost {
    pub group: Bytes,
    pub member: Member,
    pub messages: Vec<LostOf>,
}

/// Seqs of one author's membership lost, with the ids this session knows: only of its own messages, told by others.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LostOf {
    pub from: Member,
    pub joined: u64,
    pub seqs: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<Bytes>,
}

/// The directory moved on from the one a writer intent was derived from.
#[derive(Debug, thiserror::Error)]
#[error("the directory advanced; derive the writer intent again")]
pub struct Advanced;

/// Why `send` refused a held message: nothing of it was kept.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("rate: more held messages than members take for now; wait a little")]
    Rate,
    #[error("size: {0}")]
    Size(String),
}

#[derive(Debug)]
pub enum Event {
    Joined {
        group: Bytes,
        member: Member,
        by: Member,
        how: How,
    },
    Left {
        group: Bytes,
        member: Member,
        by: Member,
    },
    /// This session's commit removed members whose devices their identities' public logs dropped. `added`: the members
    /// still in the group that they added, or that came in by invites they made, which only a member's `remove` takes out.
    Revoked {
        group: Bytes,
        removed: Vec<Member>,
        added: Vec<Member>,
    },
    /// This session was removed, by `by` as it applied the commit, or else with no `by`: by a commit applied before it
    /// stopped, left the only member of a group it asked to leave, or away past its log's retention. The group, of kind
    /// `kind`, is gone from it, with its messages no cut kept: `not_kept`, by id.
    Removed {
        group: Bytes,
        kind: String,
        by: Option<Member>,
        not_kept: Vec<Bytes>,
    },
    Settings {
        group: Bytes,
        settings: Settings,
        by: Member,
    },
    /// A held payload of the group's kind, delivered, in causal order; never one of this session's own.
    Message(Message),
    /// Losses: this session's own, and those members' summaries tell, each seq once.
    Lost(Lost),
    /// A live payload of the group's kind: not held.
    Live {
        group: Bytes,
        sender: Member,
        payload: Value,
    },
    /// A neighbour's `hello` shows the same head of the group's log as this session's: a time to compare the kind's
    /// state.
    Synced {
        group: Bytes,
        member: Member,
    },
    /// Receipts or member presentation changed: a summary, accepted MLS change, or directory replay.
    Heard {
        group: Bytes,
    },
    /// The state of the group's kind that `from` handed this session: beside the Welcome that admitted it, or later.
    State {
        group: Bytes,
        from: Member,
        data: Vec<u8>,
    },
    /// A member is being admitted, or asks for it: the state of the group's kind to hand it, if any.
    Snapshot {
        group: Bytes,
        reply: oneshot::Sender<Option<Vec<u8>>>,
    },
    /// A file is held whole.
    File([u8; 32]),
    /// An identity's public log grew, as this session read it.
    Public { identity: Bytes },
    /// A pass of an identity group's duties ran: the identity kind runs its own.
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
            | Event::Snapshot { group, .. } => Some(group),
            Event::Message(message) => Some(&message.group),
            Event::Lost(lost) => Some(&lost.group),
            Event::Warning { group, .. } => group.as_ref(),
            Event::File(_) | Event::Public { .. } => None,
        }
    }
}

/// A group's own record, beside its MLS state and its log.
#[derive(Default, Serialize, Deserialize)]
struct Rec {
    /// The last position of its logs read and judged, counted from where this session started.
    position: u64,
    /// Its current log, by reference: its epoch's, which every commit moves on from; and the position the log starts
    /// after.
    log: Bytes,
    base: u64,
    /// The epoch this session's own last commit moved the group to.
    committed: u64,
    /// The files this session added that no other member held yet.
    pending: Vec<[u8; 32]>,
    /// File links, with when they were linked: those the kind holds (its files added, and those its held messages
    /// link) and states handed to or by this session. Each is held for the group's H.
    files: Vec<(String, u64)>,
    /// The files the kind links now, held while it does.
    links: Vec<String>,
    /// The invites shared with the group, kept for H after they expire.
    invites: Vec<Rule>,
    /// The `leave`s opened: each one's membership, and its seq.
    leaves: Vec<(Bytes, u64, u64)>,
    /// This session asked to leave: it is in the group until a member removes it.
    leaving: bool,
    /// When this session's leaf was last updated, in milliseconds.
    updated: u64,
    /// The memberships this session knows of in the group: the current ones, and those ended within H.
    authors: Vec<Author>,
    /// The last delivery index given, and the first one whose message is still kept.
    index: u64,
    first: u64,
    /// What the last commit applied kept above this session's baselines, held before the next one applies.
    keep: Vec<Seqs>,
    /// This session's summary: its last version, and when it was signed.
    version: u64,
    signed: u64,
    /// The memberships whose summaries are saved.
    heard: Vec<(Bytes, u64)>,
    /// The seqs members' summaries told lost, each told once: the reporter's membership, and the author's seqs.
    told: Vec<(Bytes, u64, Seqs)>,
    /// The epochs whose ending commits are saved, with when they applied.
    commits: Vec<(u64, u64)>,
    /// The member to ask for the state, and its epoch: once this session is at or past that epoch, it asks that member
    /// until a state opens.
    wanted: Option<([u8; 32], u64)>,
    /// The members this session answered a request for the state, with the epoch it answered in.
    answered: Vec<([u8; 32], u64)>,
    /// The epoch this session's messages past its cut were last sealed again in.
    resealed: u64,
}

/// An invite, as its inviter shared it with the group.
#[derive(Clone, Serialize, Deserialize)]
struct Rule {
    /// SHA-256 of its secret.
    hash: Bytes,
    expires: u64,
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
    /// Ciphertexts of the next epoch, and the peers that sent them.
    early: Vec<(EndpointId, Vec<u8>)>,
    /// Ciphertexts taken but not opened yet, past the window or the bucket: by claim, with their epoch.
    unopened: BTreeMap<(Bytes, u64, u64), (u64, Vec<u8>)>,
    /// The flood buckets of the group's memberships, and this session's own.
    buckets: BTreeMap<(Bytes, u64), held::Bucket>,
    sending: held::Bucket,
    /// The flood buckets of the memberships' live payloads.
    live: BTreeMap<(Bytes, u64), held::Bucket>,
    /// The hashes of ciphertexts taken lately.
    seen: VecDeque<[u8; 32]>,
    /// Seqs that came to be known lately, and when: not asked for until `HOLD_OFF` passed.
    fresh: Vec<(Bytes, u64, lmk_proto::ranges::Ranges, u64)>,
    /// The position of the commit reading waits at, and when it was read.
    reading: Option<(u64, u64)>,
    /// Reading waits before a commit that deletes the keys of an epoch whose kept messages this session lacks.
    waiting: bool,
    /// The seqs an update waits to fetch before it commits, and when it first waited, in this epoch.
    fetch: Option<(Vec<Seqs>, u64)>,
    /// The public logs this session follows of the identities the group's members speak as.
    public: Vec<Vec<u8>>,
    /// Summaries of memberships this session does not know yet, as a joiner's before its Add applies here.
    unverified: Vec<(EndpointId, Signed)>,
    /// This session's summary changed since it was signed.
    changed: bool,
}

impl G {
    fn new(mls: Group, rec: Rec) -> Self {
        G {
            mls,
            rec,
            early: Vec::new(),
            unopened: BTreeMap::new(),
            buckets: BTreeMap::new(),
            sending: held::Bucket::default(),
            live: BTreeMap::new(),
            seen: VecDeque::new(),
            fresh: Vec::new(),
            reading: None,
            waiting: false,
            fetch: None,
            public: Vec::new(),
            unverified: Vec::new(),
            changed: true,
        }
    }

    /// The seq of the `leave` of the current membership of the member with key `key`, if it asked to leave.
    fn left(&self, key: &[u8]) -> Option<u64> {
        let joined = self.mls.joined(key)?;
        self.rec.leaves.iter().find(|(by, at, _)| by.0 == key && *at == joined).map(|(_, _, seq)| *seq)
    }
}

pub(crate) struct State<P> {
    provider: P,
    /// What the current step produced for the peers, sent once it commits.
    out: Vec<Out>,
    /// The current step deleted what should leave no copy: scrub once it commits.
    scrub: bool,
    /// What the current step tells the session, sent once it commits.
    events: Vec<Event>,
    session: Session,
    /// The device's name, which its credential names in its identity groups, where this is a device's node.
    device: Option<String>,
    groups: BTreeMap<Vec<u8>, G>,
    /// The logs this session follows, by id.
    logs: BTreeMap<Vec<u8>, logs::Log>,
    /// Public logs, by id.
    public: BTreeMap<Vec<u8>, PublicLog>,
    bindings: Vec<(Bytes, String)>,
    notified: BTreeSet<(Bytes, String)>,
    /// The identities and devices this session read a public log again for, as members' certificates named devices it
    /// did not list.
    unlisted: HashSet<(Vec<u8>, Vec<u8>)>,
    /// In each identity group, this node's own key there, the device's key on that identity: its seed, and the member.
    device_keys: BTreeMap<Vec<u8>, ([u8; 32], Session)>,
    peers: Peers,
    /// The peers connected now, and the groups the gate admits each to.
    served: BTreeMap<EndpointId, BTreeSet<Bytes>>,
    /// The rosters or the public logs changed since `served` was worked out.
    gate: bool,
    /// This endpoint's home relay, as net last reported it.
    home: Option<String>,
    /// Where each member last said it was, by iroh key.
    hints: BTreeMap<Bytes, peering::Hint>,
    /// The latest time a step saw, in milliseconds: `Peers` takes no time from before.
    time: u64,
}

/// What a step produced for the peers.
pub(crate) enum Out {
    Frame { peer: EndpointId, frame: Frame },
    /// Ask the peer for the files the group links that this session lacks.
    WantFiles { peer: EndpointId, group: Vec<u8> },
    Dial(EndpointId),
    Close(EndpointId),
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
        // Nothing a step produced may leave unless it committed, and its state in memory no longer matches storage.
        if let Err(error) = self.guard.provider.commit() {
            tracing::error!("committing a step: {error:#}; stopping");
            std::process::abort();
        }
        if std::mem::take(&mut self.guard.scrub)
            && let Err(error) = self.guard.provider.scrub()
        {
            self.inner.warn(None, format!("{error:#}"));
        }
        let events = std::mem::take(&mut self.guard.events);
        let out = std::mem::take(&mut self.guard.out);
        if !out.is_empty() || !events.is_empty() {
            self.inner.outbox.send((out, events)).ok();
        }
    }
}

pub(crate) enum Work {
    Applied {
        group: Vec<u8>,
        by: Option<core::Member>,
        added: Vec<core::Member>,
        how: Option<How>,
        removed: Vec<core::Member>,
        settings: bool,
        gone: bool,
    },
    /// A group's new log, read once from its service, so that its peers' entries are taken.
    Read(Vec<u8>),
    /// A group's duties to run.
    Duties(Vec<u8>),
    /// A group this session is out of, by no one's commit.
    Gone(Vec<u8>),
    Fetch {
        group: Vec<u8>,
        link: FileLink,
    },
}

/// A log, and the lengths and hashes of two heads of it that contradict each other.
type Contradicted = (Vec<u8>, [(u64, Vec<u8>); 2]);

pub(crate) struct Inner<P> {
    state: Mutex<State<P>>,
    net: OnceLock<Net>,
    clients: logs::Clients,
    resolve: Resolve,
    relays: Vec<RelayUrl>,
    chosen: Vec<RelayUrl>,
    file_limit: u64,
    kinds: Vec<String>,
    events: mpsc::UnboundedSender<Event>,
    work: mpsc::UnboundedSender<Work>,
    /// Peer output and client events from steps, in order, released once durable.
    outbox: mpsc::UnboundedSender<(Vec<Out>, Vec<Event>)>,
    durable: Option<Durable>,
    persistence_error: Mutex<Option<String>>,
    committing: tokio::sync::Mutex<()>,
    /// Woken whenever a group's log is read further, for commits waiting to reach its head.
    advanced: tokio::sync::Notify,
    /// Woken whenever a peer's summary is heard.
    heard: tokio::sync::Notify,
    /// The groups whose duties run, each with whether another pass is due once it ends.
    passing: Mutex<HashMap<Vec<u8>, bool>>,
    /// When each group's next timed pass of its duties is due.
    timers: Mutex<HashMap<Vec<u8>, u64>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// The contradictions reported, each once.
    contradictions: Mutex<HashSet<Contradicted>>,
    /// The warnings given, each once: a service that signs with another key, or that runs another minor.
    warned: Mutex<HashSet<String>>,
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


fn device_key_key(gid: &[u8]) -> Vec<u8> {
    [b"node/device-key/".as_slice(), gid].concat()
}

fn endpoint_id(key: &[u8]) -> Option<EndpointId> {
    EndpointId::from_bytes(key.try_into().ok()?).ok()
}

impl<P: Provider> State<P> {
    /// What the credential of the group this session makes or joins next names: the certificate of its identity.
    fn speak(&mut self, identity: Option<Certificate>) {
        self.session.credential.certificate = identity.map(Box::new);
    }

    /// A new device key, for an identity group this node makes or joins, whose credential names the device.
    fn device_key(&self) -> Result<([u8; 32], Session)> {
        let seed = lmk_core::random();
        Ok((seed, self.keyed(seed)?))
    }

    fn keyed(&self, seed: [u8; 32]) -> Result<Session> {
        Session::with_signer(&self.provider, signer(&seed), self.device.as_deref().unwrap_or_default(), self.session.leaf.clone())
    }

    /// This session as a member of a group: in an identity group, the device's key there.
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
        let member = members.iter().find(|m| crate::fp(&m.key) == fp).with_context(|| format!("no member {fp}"))?;
        member.leaf.as_ref().and_then(|leaf| endpoint_id(&leaf.key.0)).context("a member without an iroh key")
    }

    /// A member as events show it, if it has a letmeknow credential.
    fn member(&self, gid: &[u8], member: &core::Member) -> Option<Member> {
        let credential = member.credential.clone()?;
        let g = self.groups.get(gid);
        let added = g.and_then(|g| {
            let added = g.mls.added().iter().rev().find(|added| added.member.key == credential.key)?;
            Some((added.by.key.clone(), added.how.clone().unwrap_or(How::Invite)))
        });
        let claim = credential.identity().map(|identity| {
            if credential.key.0 != member.key {
                return (Claim { identity: identity.clone(), name: String::new(), error: Some("its credential does not name its actual session key".into()), observed: None }, None);
            }
            self.claim(&credential, identity)
        });
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

    fn claim(&self, credential: &Credential, identity: &IdentityRef) -> (Claim, Option<String>) {
        let mut identity = identity.clone();
        let Some(log) = self.public.get(&identity.id.0) else {
            let error = Some("its identity's public log could not be read yet".into());
            return (Claim { identity, name: String::new(), error, observed: None }, None);
        };
        identity.membership = log.membership.clone();
        let error = match log.verify(credential) {
            Verdict::Authorized => {
                let c = credential.certificate.as_ref().unwrap();
                let names: Vec<String> = self.bindings.iter().filter(|(id, _)| *id == identity.id).map(|(_, name)| name.clone()).collect();
                let mut other_ids = Vec::new();
                for (id, name) in &self.bindings {
                    if *id != identity.id && name.to_lowercase() == c.name.to_lowercase() && !other_ids.contains(id) {
                        other_ids.push(id.clone());
                    }
                }
                let observed = (!names.is_empty()).then_some(Observation { names, other_ids });
                return (Claim { identity, name: c.name.clone(), error: None, observed }, Some(c.device_name.clone()));
            }
            Verdict::Unverified => "its session certificate is invalid or its device is not authorized in the directory view held here",
            Verdict::Dropped => "its device was taken off the identity in the directory view held here",
        };
        (Claim { identity, name: String::new(), error: Some(error.into()), observed: None }, None)
    }

    fn observe_identities(&mut self) -> Result<()> {
        let mut claims = Vec::new();
        for (gid, g) in &self.groups {
            if !g.mls.active() {
                continue;
            }
            for member in g.mls.members() {
                let Some(credential) = member.credential.filter(|c| c.key.0 == member.key) else { continue };
                let Some(c) = &credential.certificate else { continue };
                if self.public.get(&c.identity.id.0).is_some_and(|log| log.verify(&credential) == Verdict::Authorized) {
                    claims.push((Bytes(gid.clone()), c.identity.id.clone(), c.name.clone(), credential));
                }
            }
        }
        let mut bindings = self.bindings.clone();
        let mut fresh = BTreeSet::new();
        for (_, id, name, _) in &claims {
            let pair = (id.clone(), name.clone());
            if !bindings.contains(&pair) {
                bindings.push(pair.clone());
                fresh.insert(pair);
            }
        }
        if !fresh.is_empty() {
            put(&self.provider, b"node/identity-bindings", &bindings)?;
            self.bindings = bindings;
        }
        for (group, id, name, credential) in claims {
            let pair = (id.clone(), name.clone());
            let observed = self.claim(&credential, credential.identity().unwrap()).0.observed.unwrap();
            let changed = observed.names.len() > 1 || !observed.other_ids.is_empty();
            if (!fresh.contains(&pair) && !changed) || !self.notified.insert(pair.clone()) {
                continue;
            }
            let identity = serde_json::to_string(&id)?;
            let mut text = if fresh.contains(&pair) {
                format!("First locally observed identity claim: {name:?} — {identity}.")
            } else {
                format!("Previously observed identity-name change or shared name: {name:?} — {identity}.")
            };
            if observed.names.len() > 1 {
                text.push_str(&format!(" Same identity ID, changed name claims; first observed here as {:?}; observed names: {:?}.", observed.names[0], observed.names));
            }
            if !observed.other_ids.is_empty() {
                text.push_str(&format!(" This full name is also claimed by identities {}. Names are not unique; confirm the full identity ID with your operator before assuming continuity.", serde_json::to_string(&observed.other_ids)?));
            }
            text.push_str(" Its device is authorized in the authenticated directory view held here; the person or organization has not been independently verified.");
            self.events.push(Event::Warning { group: Some(group), text });
        }
        Ok(())
    }

    fn members(&self, gid: &[u8]) -> Result<Vec<Member>> {
        let g = self.group(gid)?;
        Ok(g.mls.members().iter().filter_map(|member| self.member(gid, member)).collect())
    }

    /// The member whose leaf names an iroh key, or a bare one.
    fn by_iroh(&self, gid: &[u8], iroh: &EndpointId) -> Member {
        self.in_leaf(gid, iroh).and_then(|member| self.member(gid, &member)).unwrap_or_else(|| Member {
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
        let log = self.public.get(&identity.id.0);
        credential.key.0 == member.key && log.is_some_and(|log| log.verify(credential) == Verdict::Authorized)
    }

    /// The identities a group's members speak as.
    fn identities(&self, gid: &[u8]) -> Vec<IdentityRef> {
        let Some(g) = self.groups.get(gid) else { return Vec::new() };
        g.mls.members().into_iter().filter_map(|m| Some(m.credential?.certificate?.identity)).collect()
    }

    /// A new group's records, its MLS state, and the log of its epoch. Its memberships start at their cuts: this
    /// session holds nothing of what came before.
    fn add_group(&mut self, mls: Group, mut rec: Rec) -> Result<Vec<u8>> {
        let gid = mls.id().to_vec();
        let base = rec.position;
        rec.updated = now();
        rec.resealed = mls.epoch();
        rec.authors = mls.cut().iter().map(|r| Author::new(r.key.clone(), r.joined, r.seq)).collect();
        self.groups.insert(gid.clone(), G::new(mls, rec));
        self.next_log(&gid, base)?;
        self.save_groups()?;
        self.observe_identities()?;
        self.gate = true;
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
        // A step outside a transaction could commit half of what it does.
        if let Err(error) = guard.provider.begin() {
            tracing::error!("starting a step: {error:#}; stopping");
            std::process::abort();
        }
        Step { guard, inner: self }
    }

    /// Makes the steps committed so far durable, before what they produced leaves the node.
    async fn durable(&self) -> Result<()> {
        if let Some(error) = &*self.persistence_error.lock().unwrap() {
            anyhow::bail!(error.clone());
        }
        let saved = match &self.durable {
            Some(durable) => durable().await,
            None => Ok(()),
        };
        let mut failed = self.persistence_error.lock().unwrap();
        if let Err(error) = saved {
            failed.get_or_insert_with(|| format!("{PERSISTENCE_FAILED}: {error:#}; output stopped until restart"));
        }
        match &*failed {
            Some(error) => Err(anyhow::anyhow!(error.clone())),
            None => Ok(()),
        }
    }

}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A member's fingerprint: the first 8 bytes of SHA-256 of its session key, hex.
pub fn fp(key: &[u8]) -> String {
    hex(&Sha256::digest(key)[..8])
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
