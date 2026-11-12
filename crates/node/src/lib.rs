//! One member's session over lmk-core, lmk-net and lmk-membership: its groups and their logs of commits, its held
//! messages, and the invites it shares and the joiners it admits. Held messages travel between members and are
//! delivered in causal order; commits keep them, by their cuts. A chat sees a group's content as its held messages are
//! delivered, and nothing of the rest; the core reads only its own payloads (`Control`). It stores everything in one
//! SQLite database (the core's `SqliteProvider`), one transaction per step (`Step`): nothing a step produces leaves the
//! node before its transaction commits.

mod admission;
mod api;
mod duties;
mod groups;
mod held;
mod logs;
mod peering;
mod reading;
mod sending;
mod tasks;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use anyhow::{Context, Result};
use iroh::tls::CaTlsConfig;
use iroh::{EndpointId, SecretKey};
use lmk_core::group::{self as core, Group, Session};
use lmk_core::provider::SqliteProvider;
use lmk_membership::client::Post;
use lmk_net::peers::Peers;
use lmk_net::Net;
use lmk_proto::group::{Device, Service};
use lmk_proto::head::Head;
use lmk_proto::links::Invite;
use lmk_proto::membership::Expiry;
use lmk_proto::peer::{At, Frame, Seqs, Signed};
use lmk_proto::Bytes;
use n0_future::task::{JoinHandle, spawn};
use n0_future::time::Duration;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use held::Author;

pub use lmk_core;
pub use peering::Heard;
pub use tasks::{create, groups};
pub use lmk_net::peers::RECENT;
pub use lmk_proto::clock::now;

/// How long an invite is valid, in milliseconds.
pub const INVITE_VALID: u64 = 10 * 60 * 1000;
/// How long an invite waits for the members online to hold it.
const MEMBER_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Config {
    /// The domain of this session's own membership service, whose relay it lives on and which sets its clock.
    pub home: String,
    /// Posts to a membership service's routes, as the shell does over https.
    pub post: Post,
    pub ca: CaTlsConfig,
    /// The key of the device it runs on: its leaf carries the device's certificate of it.
    pub device: ed25519_dalek::SigningKey,
}

/// When a member was last known online, in milliseconds since the epoch, and whether this session is connected to it now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    pub at: u64,
    pub connected: bool,
}

/// A group member, from its leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The session key: the MLS signature key.
    pub key: Bytes,
    /// The iroh key its leaf names.
    pub iroh: Bytes,
    /// The domain of its own service, whose relay it lives on, as its leaf names it.
    pub home: String,
    /// The device that certified it, as its leaf names it.
    pub device: Option<Device>,
}

impl From<&core::Member> for Member {
    fn from(member: &core::Member) -> Self {
        Member {
            key: Bytes(member.key.clone()),
            iroh: member.leaf.key.clone(),
            home: member.leaf.home.clone(),
            device: member.leaf.device.clone(),
        }
    }
}

/// A held message of the group as this session delivered it: a chat message, or one of the core's.
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
}

/// Held messages a member can no longer have, as this session found its own or a member's summary told them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lost {
    pub group: Bytes,
    pub member: Member,
    pub messages: Vec<LostOf>,
}

/// Seqs of one author's membership lost, with the ids this session knows: only of its own chat messages, told by others.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LostOf {
    pub from: Member,
    pub joined: u64,
    pub seqs: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<Bytes>,
}

/// Why `send` refused a held message: nothing of it was kept.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("rate: more held messages than members take for now; wait a little")]
    Rate,
    #[error("size: {0}")]
    Size(String),
    #[error("let go: the membership service let the group's log go; this session leaves the group unless a member online brings what it missed")]
    LetGo,
}

#[derive(Debug)]
pub enum Event {
    Joined {
        group: Bytes,
        member: Member,
        by: Member,
    },
    Left {
        group: Bytes,
        member: Member,
        by: Member,
    },
    /// This session was removed, by `by` as it applied the commit, or else with no `by`: by a commit it applied but could
    /// not forget the group at, as it starts again; left the only member of a group it asked to leave; or away past its
    /// log's retention. The group is gone from it, with its chat messages no cut kept: `not_kept`, by id.
    Removed {
        group: Bytes,
        by: Option<Member>,
        not_kept: Vec<Bytes>,
    },
    /// A held payload, delivered, in causal order; never one of this session's own.
    Message(Message),
    /// Losses: this session's own, and those members' summaries tell, each seq once.
    Lost(Lost),
    Warning {
        group: Option<Bytes>,
        text: String,
    },
}

impl Event {
    /// The group an event concerns, if one.
    pub fn group(&self) -> Option<&Bytes> {
        match self {
            Event::Joined { group, .. } | Event::Left { group, .. } | Event::Removed { group, .. } => Some(group),
            Event::Message(message) => Some(&message.group),
            Event::Lost(lost) => Some(&lost.group),
            Event::Warning { group, .. } => group.as_ref(),
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
    /// The invites shared with the group, one per inviter's membership and hash, kept for H after they expire.
    invites: Vec<Rule>,
    /// The `leave`s opened: each one's membership, its seq, and the member's leave it carries (`Group::leave`).
    leaves: Vec<(Bytes, u64, u64, Bytes)>,
    /// This session asked to leave: it is in the group until a member removes it.
    leaving: bool,
    /// When this session's leaf was last updated, in milliseconds.
    updated: u64,
    /// The signed intros of the current memberships, this session's own included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    intros: Vec<Signed>,
    /// The group delivered a message or changed its members since this session's leaf was last updated: an update is
    /// due once T passed.
    stirred: bool,
    /// When this session last asked which members' logs their services let go, in milliseconds.
    evicted: u64,
    /// The latest epoch this session's own commit or message showed it in, and when it last did: while it is behind, a
    /// `present` is due `PRESENT` after that.
    present: u64,
    presented: u64,
    /// The seqs this session lost and has not told the group of yet.
    lost: Vec<Seqs>,
    /// The memberships this session knows of in the group: the current ones, and those ended within H.
    authors: Vec<Author>,
    /// The messages of others its client showed that no other it showed since depends on, directly: the deps of its
    /// next message.
    frontier: Vec<lmk_proto::held::Ref>,
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
    /// The epochs whose ending commits are saved, with when they applied.
    commits: Vec<(u64, u64)>,
    /// The epoch this session's messages past its cut were last sealed again in.
    resealed: u64,
    /// The latest epoch each other member showed itself in, as far as this session knows: by its Add or latest commit, a
    /// message, a summary in the current epoch, or the epoch its intro names. One it knows none of is taken to be at
    /// `since`.
    members: Vec<(Bytes, u64)>,
    /// The epoch this session joined in.
    since: u64,
    /// The epochs behind the current one that members are at, each with its log's capability and service: this session's
    /// own, and members' claims.
    epochs: Vec<Epoch>,
}

/// An epoch behind a group's current one, with its log's capability and service: a member still in it reads that log.
#[derive(Clone, Serialize, Deserialize)]
struct Epoch {
    epoch: u64,
    capability: [u8; 32],
    service: Service,
    /// The member whose intro named it, where this session holds no capability of its own of that epoch: it counts for
    /// that member alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    member: Option<Bytes>,
    /// The service's expiry of its log, once this session asked or a neighbour told it: the members in it are left
    /// behind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expired: Option<Expiry>,
    /// The service answered this session's own ask with a head of length 0: its log held the commit that ended the
    /// epoch, so the service let it go and forgot it, and the members in it are left behind. No neighbour shows that, as
    /// a member could keep such a head from before that commit.
    forgotten: bool,
}

/// An invite, as its inviter shared it with the group, or kept for one member.
#[derive(Clone, Serialize, Deserialize)]
struct Rule {
    /// Its hash (`Invited::hash`).
    hash: Bytes,
    expires: u64,
    /// The inviter's session key.
    by: Bytes,
    /// The epoch the inviter's membership began in, which the invite dies with.
    joined: u64,
    /// The only session key it admits, when made for one member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to: Option<Bytes>,
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
    /// Ciphertexts taken but not opened yet, past the window or the bucket: by claim, the latest sealing of each, with its
    /// epoch.
    unopened: BTreeMap<(Bytes, u64, u64), (u64, Vec<u8>)>,
    /// The flood buckets of the group's memberships, and this session's own.
    buckets: BTreeMap<(Bytes, u64), held::Bucket>,
    sending: held::Bucket,
    /// The hashes of ciphertexts taken lately.
    seen: VecDeque<[u8; 32]>,
    /// Seqs that came to be known lately, and when: not asked for until `HOLD_OFF` passed.
    fresh: Vec<(Bytes, u64, lmk_proto::ranges::Ranges, u64)>,
    /// The wait of the run of commits reading is in: when it began, moved on by the time between them; and the position
    /// of the commit last judged, and when, which is when it applied once reading is past it. A commit held within
    /// `HEAR` of the one before it applying continues the run: the commits this session missed while away wait once for
    /// them all, not once for each epoch.
    reading: Option<(u64, u64, u64)>,
    /// Reading waits before a commit that deletes the keys of an epoch whose kept messages this session lacks.
    waiting: bool,
    /// The seqs an update waits to fetch before it commits, and when it first waited, in this epoch.
    fetch: Option<(Vec<Seqs>, u64)>,
    /// Summaries of memberships this session does not know yet, as a joiner's before its Add applies here.
    unverified: Vec<(EndpointId, Signed)>,
    /// Intros of memberships this session does not know yet, or naming an epoch it has not reached, each as its member
    /// signed it: by membership, its latest, with its version.
    early_intros: BTreeMap<(Bytes, u64), (u64, Signed)>,
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
            seen: VecDeque::new(),
            fresh: Vec::new(),
            reading: None,
            waiting: false,
            fetch: None,
            unverified: Vec::new(),
            early_intros: BTreeMap::new(),
            changed: true,
        }
    }

    /// The epoch the other member with key `key` is in, as far as this session knows (`Rec::members`).
    fn at_epoch(&self, key: &[u8]) -> u64 {
        self.rec.members.iter().find(|(member, _)| member.0 == key).map_or(self.rec.since, |(_, epoch)| *epoch)
    }

    /// The seq of the `leave` of the current membership of the member with key `key`, if it asked to leave, and the leave
    /// it carries.
    fn left(&self, key: &[u8]) -> Option<(u64, &Bytes)> {
        let joined = self.mls.joined(key)?;
        self.rec.leaves.iter().find(|(by, at, _, _)| by.0 == key && *at == joined).map(|(_, _, seq, sig)| (*seq, sig))
    }
}

pub(crate) struct State {
    provider: SqliteProvider,
    /// What the current step produced for the peers, sent once it commits.
    out: Vec<Out>,
    /// The current step deleted what should leave no copy: scrub once it commits.
    scrub: bool,
    /// What the current step tells the session, sent once it commits.
    events: Vec<Event>,
    session: Session,
    groups: BTreeMap<Vec<u8>, G>,
    /// The logs this session follows, by id.
    logs: BTreeMap<Vec<u8>, logs::Log>,
    peers: Peers,
    /// The rosters changed since the groups the gate admits each connected peer to were worked out.
    gate: bool,
    /// The current step is the poll's own: its end wakes no poll.
    quiet: bool,
    /// The latest hello of each connected peer that named groups not added yet: taken once the group is, and dropped
    /// as the peer disconnects.
    early_hellos: Vec<(EndpointId, At)>,
    /// The links of the joins in flight: the members they name are read whole (`Groups::serves`).
    joins: Vec<Invite>,
    /// Logs not followed yet, each whole and of at most a page, as the service of one of this session's groups signed it,
    /// with the peers that sent them, at most `TOLD`: taken once the log is followed.
    early_entries: Vec<(EndpointId, Bytes, Vec<Bytes>, Head)>,
    /// The latest time a step saw, in milliseconds: `Peers` takes no time from before.
    time: u64,
}

/// What a step produced for the peers.
pub(crate) enum Out {
    Frame { peer: EndpointId, frame: Frame },
    Dial(EndpointId),
    Close(EndpointId),
}

/// One step: the state, locked, with a transaction open on its storage; committed when the step ends, and only then
/// what it produced goes out.
pub(crate) struct Step<'a> {
    guard: MutexGuard<'a, State>,
    inner: &'a Inner,
}

impl Deref for Step<'_> {
    type Target = State;

    fn deref(&self) -> &State {
        &self.guard
    }
}

impl DerefMut for Step<'_> {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.guard
    }
}

impl Drop for Step<'_> {
    fn drop(&mut self) {
        self.guard.gate();
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
        if !std::mem::take(&mut self.guard.quiet) {
            self.inner.poke.notify_one();
        }
    }
}

pub(crate) enum Work {
    /// A group's duties to run.
    Duties(Vec<u8>),
    /// A group this session is out of, by no one's commit.
    Gone(Vec<u8>),
}

/// A log, and the lengths and hashes of two heads of it that contradict each other.
type Contradicted = (Vec<u8>, [(u64, Vec<u8>); 2]);

pub(crate) struct Inner {
    state: Mutex<State>,
    net: OnceLock<Net>,
    clients: logs::Clients,
    /// The domain of this session's own service, whose relay it lives on.
    home: String,
    events: mpsc::UnboundedSender<Event>,
    work: mpsc::UnboundedSender<Work>,
    /// Peer output and client events from steps, in order.
    outbox: mpsc::UnboundedSender<(Vec<Out>, Vec<Event>)>,
    /// Each group's commit lock, held while one of its commits is built, posted and read back.
    committing: Mutex<HashMap<Vec<u8>, Arc<tokio::sync::Mutex<()>>>>,
    /// Woken whenever a group's log is read further, for commits waiting to reach its head.
    advanced: tokio::sync::Notify,
    /// Woken whenever a peer's summary is heard.
    heard: tokio::sync::Notify,
    /// Woken at the end of each step but the poll's own, for the poll.
    poke: tokio::sync::Notify,
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
pub struct Node {
    inner: Arc<Inner>,
}

impl Clone for Node {
    fn clone(&self) -> Self {
        Node { inner: self.inner.clone() }
    }
}

fn get<T: DeserializeOwned>(provider: &SqliteProvider, key: &[u8]) -> Result<Option<T>> {
    Ok(provider.get(key)?.map(|bytes| serde_json::from_slice(&bytes)).transpose()?)
}

fn put<T: Serialize>(provider: &SqliteProvider, key: &[u8], value: &T) -> Result<()> {
    provider.put(key, &serde_json::to_vec(value)?)
}

fn rec_key(gid: &[u8]) -> Vec<u8> {
    [b"node/group/".as_slice(), gid].concat()
}

fn endpoint_id(key: &[u8]) -> Option<EndpointId> {
    EndpointId::from_bytes(key.try_into().ok()?).ok()
}

impl State {
    /// This session's key.
    fn me(&self) -> &[u8] {
        self.session.key()
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

    fn members(&self, gid: &[u8]) -> Result<Vec<Member>> {
        Ok(self.group(gid)?.mls.members().iter().map(Member::from).collect())
    }

    /// The member of a group whose leaf names an iroh key.
    fn in_leaf(&self, gid: &[u8], peer: &EndpointId) -> Option<core::Member> {
        let members = self.groups.get(gid)?.mls.members();
        members.into_iter().find(|m| m.leaf.key.0 == peer.as_bytes())
    }

    /// The epoch the membership of a peer's member began in: what was sent before it is not the peer's to have; nothing
    /// is, of a peer that is not a member.
    fn joined_of(&self, gid: &[u8], peer: &EndpointId) -> u64 {
        self.in_leaf(gid, peer).and_then(|m| self.groups.get(gid)?.mls.joined(&m.key)).unwrap_or(u64::MAX)
    }

    /// Whether this session serves a peer a group: it is a member.
    fn serves(&self, gid: &[u8], peer: &EndpointId) -> bool {
        self.in_leaf(gid, peer).is_some()
    }

    /// A new group's records, its MLS state, and the log of its epoch. Its memberships start at their cuts: this
    /// session holds nothing of what came before.
    fn add_group(&mut self, mls: Group, mut rec: Rec) -> Result<Vec<u8>> {
        let gid = mls.id().to_vec();
        let base = rec.position;
        (rec.resealed, rec.since) = (mls.epoch(), mls.epoch());
        rec.authors = mls.cut().iter().map(|r| Author::new(r.key.clone(), r.joined, r.seq)).collect();
        self.groups.insert(gid.clone(), G::new(mls, rec));
        self.next_log(&gid, base)?;
        self.present(&gid)?;
        self.save_groups()?;
        self.gate = true;
        self.refresh(&gid);
        // The early hellos' sightings count only from peers the gate admits to the group.
        self.gate();
        let now = self.tick();
        let (early, others) = std::mem::take(&mut self.early_hellos).into_iter().partition(|(_, at)| at.group.0 == gid);
        self.early_hellos = others;
        for signed in early.iter().flat_map(|(_, at)| at.intros.clone()) {
            self.intro(&gid, signed)?;
        }
        for (_, at) in &early {
            self.take_expiries(&gid, &at.expired, &[])?;
        }
        self.refresh(&gid);
        for (peer, at) in early {
            self.peers.frame(peer.as_bytes(), &Frame::Hello { groups: vec![at] }, now);
        }
        Ok(gid)
    }
}

/// The session's iroh key, made on first use.
pub fn iroh_key(provider: &SqliteProvider) -> Result<SecretKey> {
    Ok(match provider.get(b"node/iroh")? {
        Some(bytes) => SecretKey::from_bytes(&bytes.as_slice().try_into().context("an iroh key is 32 bytes")?),
        None => {
            let key = SecretKey::from_bytes(&lmk_core::random());
            provider.put(b"node/iroh", &key.to_bytes())?;
            key
        }
    })
}

impl Inner {
    fn net(&self) -> &Net {
        self.net.get().expect("the peers start with the node")
    }

    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|task| !task.is_finished());
        tasks.push(spawn(task));
    }

    fn warn(&self, group: Option<&[u8]>, text: String) {
        self.events.send(Event::Warning { group: group.map(|gid| Bytes(gid.to_vec())), text }).ok();
    }

    /// Starts a step.
    pub(crate) fn lock(&self) -> Step<'_> {
        let guard = self.state.lock().unwrap();
        // A step outside a transaction could commit half of what it does.
        if let Err(error) = guard.provider.begin() {
            tracing::error!("starting a step: {error:#}; stopping");
            std::process::abort();
        }
        Step { guard, inner: self }
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
    use lmk_proto::group::{PROTOCOL, Settings, UPDATE};
    use lmk_testing::Relay;

    async fn node(relay: &Relay, post: Post) -> Node {
        let device = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let config = Config { home: relay.domain.clone(), post, ca: relay.ca(), device };
        Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config).await.unwrap().0
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_signed_log_fork_is_reported_once_from_the_service_or_entries() {
        use ed25519_dalek::SigningKey;
        use lmk_membership::Contradiction;
        use lmk_proto::{head::{self, Head}, membership::{Answer, Page, Read}};

        let relay = lmk_testing::relay().await;
        let key = SigningKey::from_bytes(&[7; 32]);
        let service = Service::Serve { key: Bytes(key.verifying_key().to_bytes().to_vec()), domain: relay.domain.clone(), rest: Default::default() };
        for from_service in [true, false] {
            let signing = key.clone();
            let post: Post = Arc::new(move |_, route, body| {
                assert!(route.ends_with("/read"));
                let read: Read = serde_json::from_slice(&body).unwrap();
                let id = head::reference(signing.verifying_key().as_bytes(), &read.capability);
                let hash = head::next(&head::start(signing.verifying_key().as_bytes(), &id), b"theirs");
                let head = Head::sign(&signing, &id, 1, hash, now());
                Box::pin(async move { Ok(serde_json::to_vec(&Answer::Ok(Page { after: read.after, entries: vec![], head })).unwrap()) })
            });
            let config = Config { home: relay.domain.clone(), post, ca: relay.ca(), device: SigningKey::from_bytes(&[9; 32]) };
            let (alice, mut events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config).await.unwrap();
            let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: service.clone(), admins: vec![], admitted: vec![] };
            let gid = alice.create(settings).unwrap();
            let id: [u8; 32] = alice.log(&gid.0).unwrap().0.try_into().unwrap();
            let start = head::start(key.verifying_key().as_bytes(), &id);
            let ours = Head::sign(&key, &id, 1, head::next(&start, b"ours"), now());
            let theirs = Head::sign(&key, &id, 1, head::next(&start, b"theirs"), now());
            {
                let mut st = alice.inner.lock();
                st.provider.put(&logs::entry_key(&id, 1), &[ours.hash.as_slice(), b"ours"].concat()).unwrap();
                st.logs.get_mut(id.as_slice()).unwrap().head = Some(ours.clone());
                st.save_log(&id).unwrap();
            }
            for _ in 0..2 {
                if from_service {
                    let error = alice.inner.read(&id).await.unwrap_err();
                    let contradiction = error.downcast_ref::<Contradiction>().unwrap();
                    assert_eq!((&contradiction.ours, contradiction.theirs.hash), (&ours, theirs.hash));
                } else {
                    alice.inner.take_entries(&mut alice.inner.lock(), &id, 0, vec![Bytes(b"theirs".to_vec())], theirs.clone()).unwrap();
                }
            }
            alice.inner.contradicted(&alice.inner.lock(), &id, &Contradiction { ours: theirs.clone(), theirs: ours.clone() }, "a peer");
            let Event::Warning { group, text } = events.try_recv().unwrap() else { panic!("a fork must warn") };
            assert_eq!(group, Some(gid));
            assert_eq!(text, format!(
                "the membership service showed this session another version of the group's log: length 1 with hash {} here, length 1 with hash {} there",
                hex(&ours.hash), hex(&theirs.hash)
            ));
            assert!(events.try_recv().is_err(), "the same heads, even reversed, warn only once");
            {
                let st = alice.inner.lock();
                assert_eq!(st.log(&id).unwrap().head.as_ref(), Some(&ours));
                assert_eq!(st.entry(&id, 1).unwrap().unwrap(), b"ours");
            }
            alice.shutdown().await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_head_past_the_signed_range_is_refused() {
        use ed25519_dalek::SigningKey;
        use lmk_proto::head::{self, Head};

        let relay = lmk_testing::relay().await;
        let key = SigningKey::from_bytes(&[7; 32]);
        let service = Service::Serve { key: Bytes(key.verifying_key().to_bytes().to_vec()), domain: "foreign.example".into(), rest: Default::default() };
        let alice = node(&relay, relay.post()).await;
        let gid = alice.create(Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: service, admins: vec![], admitted: vec![] }).unwrap();
        let log = alice.log(&gid.0).unwrap();
        let id: [u8; 32] = log.0.as_slice().try_into().unwrap();
        let start = head::start(key.verifying_key().as_bytes(), &id);
        let head = Head::sign(&key, &id, 1, head::next(&start, b"skipped"), u64::MAX);
        let peer = SecretKey::from_bytes(&[8; 32]).public();
        alice.inner.peer_event(lmk_net::Event::Connected(peer, false));
        alice.inner.peer_event(lmk_net::Event::Frame(peer, Frame::Entries { log: log.clone(), entries: vec![Bytes(b"skipped".to_vec())], head }));
        {
            let st = alice.inner.lock();
            assert!(!st.log(&id).unwrap().stale());
            assert_eq!(st.log(&id).unwrap().at, 0);
            assert!(st.log(&id).unwrap().head.is_none());
        }
        alice.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_commit_refused_for_good_is_no_longer_pending() {
        use ed25519_dalek::{Signer, SigningKey};
        use lmk_membership::Refused;
        use lmk_proto::{head::{self, Head}, membership::{Answer, Append, Page, Read, Refusal, refusal_message}};

        let relay = lmk_testing::relay().await;
        let key = SigningKey::from_bytes(&[7; 32]);
        let service = Service::Serve { key: Bytes(key.verifying_key().to_bytes().to_vec()), domain: relay.domain.clone(), rest: Default::default() };
        for refusal in [Refusal::Policy, Refusal::Size] {
            let signing = key.clone();
            let post: Post = Arc::new(move |_, route, body| {
                let answer = if route.ends_with("/append") {
                    let append: Append = serde_json::from_slice(&body).unwrap();
                    assert_eq!(append.entries.len(), 1);
                    Answer::Refused { refusal, sig: Bytes(signing.sign(&refusal_message(refusal, &body)).to_bytes().to_vec()) }
                } else {
                    assert!(route.ends_with("/read"));
                    let read: Read = serde_json::from_slice(&body).unwrap();
                    assert_eq!(read.after, 0);
                    let id = head::reference(signing.verifying_key().as_bytes(), &read.capability);
                    let head = Head::sign(&signing, &id, 0, head::start(signing.verifying_key().as_bytes(), &id), now());
                    Answer::Ok(Page { after: 0, entries: vec![], head })
                };
                Box::pin(async move { Ok(serde_json::to_vec(&answer).unwrap()) })
            });
            let alice = node(&relay, post).await;
            let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: service.clone(), admins: vec![], admitted: vec![] };
            let gid = alice.create(settings).unwrap();
            let before = alice.settings(&gid.0).unwrap();
            let epoch = alice.epoch(&gid.0).unwrap();
            for device in [8, 9] {
                let admitted = Bytes(SigningKey::from_bytes(&[device; 32]).verifying_key().to_bytes().to_vec());
                let error = alice.change_settings(&gid.0, |settings| settings.admitted.push(admitted.clone())).await.unwrap_err();
                assert!(matches!(error.downcast_ref::<Refused>(), Some(Refused(code)) if code == refusal.code()), "{error:#}");
                let st = alice.inner.lock();
                let group = &st.group(&gid.0).unwrap().mls;
                assert!(group.posted().is_none(), "a permanent refusal cancels the pending commit");
                assert_eq!(group.epoch(), epoch);
                assert_eq!(group.settings(), before);
                assert!(Group::load(&st.provider, &gid.0).unwrap().posted().is_none(), "cancellation is stored");
            }
            alice.shutdown().await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_commit_refused_for_now_stays_pending_only_if_posted_before() {
        use std::collections::VecDeque;
        use ed25519_dalek::Signer;
        use lmk_membership::Refused;
        use lmk_proto::membership::{Answer, Refusal, refusal_message};

        enum Fault {
            Refuse(Refusal),
            Lost,
        }

        let relay = lmk_testing::relay().await;
        let store_dir = tempfile::tempdir().unwrap();
        let store = lmk_membership::store::Store::initialize(&store_dir.path().join("s")).unwrap();
        let service_key = store.key().clone();
        let service = Service::Serve { key: Bytes(service_key.verifying_key().to_bytes().to_vec()), domain: relay.domain.clone(), rest: Default::default() };
        let mem_svc = lmk_membership::service::Service::new(store, lmk_membership::service::Policy::default());
        let faults: Arc<Mutex<VecDeque<Fault>>> = Arc::default();
        let queued = faults.clone();
        let post: Post = Arc::new(move |_, route, body| {
            let mem_svc = mem_svc.clone();
            let service_key = service_key.clone();
            let fault = if route.ends_with("/append") { queued.lock().unwrap().pop_front() } else { None };
            Box::pin(async move {
                match fault {
                    Some(Fault::Refuse(refusal)) => {
                        let sig = Bytes(service_key.sign(&refusal_message(refusal, &body)).to_bytes().to_vec());
                        Ok(serde_json::to_vec(&Answer::<()>::Refused { refusal, sig }).unwrap())
                    }
                    Some(Fault::Lost) => anyhow::bail!("lost append reply"),
                    None => {
                        let parsed = lmk_membership::service::Route::parse(route).unwrap();
                        let adm = mem_svc.admit("127.0.0.1".parse().unwrap(), parsed, body.len()).unwrap();
                        mem_svc.post(parsed, &adm, &body).await
                    }
                }
            })
        });
        let key = |seed: u8| Bytes::from(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes());
        let alice = node(&relay, post.clone()).await;
        let bob = node(&relay, post).await;
        let gid = alice.create(Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: service, admins: vec![], admitted: vec![] }).unwrap();

        for (i, refusal) in [Refusal::Busy, Refusal::Rate, Refusal::Quota].into_iter().enumerate() {
            faults.lock().unwrap().push_back(Fault::Refuse(refusal));
            let error = alice.change_settings(&gid.0, |s| s.admitted.push(key(i as u8 + 1))).await.unwrap_err();
            assert!(matches!(error.downcast_ref::<Refused>(), Some(Refused(code)) if code == refusal.code()), "{error:#}");
            let st = alice.inner.lock();
            assert!(st.group(&gid.0).unwrap().mls.posted().is_none(), "a fresh commit refused with {} is dropped", refusal.code());
            assert!(Group::load(&st.provider, &gid.0).unwrap().posted().is_none());
        }

        let link = alice.invite(&gid.0, INVITE_VALID, None).await.unwrap();
        faults.lock().unwrap().push_back(Fault::Refuse(Refusal::Rate));
        let error = bob.join(&link).await.unwrap_err();
        assert!(format!("{error:#}").contains("rate"), "{error:#}");
        assert!(bob.groups().is_empty());

        alice.change_settings(&gid.0, |s| s.admitted.push(key(5))).await.unwrap();
        assert_eq!(alice.settings(&gid.0).unwrap().admitted, [key(5)]);
        assert!(!alice.members(&gid.0).unwrap().iter().any(|m| m.key == bob.key()));
        assert_eq!(bob.join(&link).await.unwrap().0, gid);
        bob.shutdown().await.unwrap();
        alice.caught_up(&gid.0).await.unwrap();

        faults.lock().unwrap().extend([Fault::Lost, Fault::Refuse(Refusal::Rate), Fault::Refuse(Refusal::Busy)]);
        let error = alice.change_settings(&gid.0, |s| s.admitted.push(key(6))).await.unwrap_err();
        assert!(matches!(error.downcast_ref::<Refused>(), Some(Refused(code)) if code == "rate"), "{error:#}");
        let kept = alice.inner.lock().group(&gid.0).unwrap().mls.posted().expect("kept after a lost earlier try").to_vec();

        let error = alice.change_settings(&gid.0, |s| s.admitted.push(key(7))).await.unwrap_err();
        assert!(matches!(error.downcast_ref::<Refused>(), Some(Refused(code)) if code == "busy"), "{error:#}");
        assert_eq!(alice.inner.lock().group(&gid.0).unwrap().mls.posted(), Some(kept.as_slice()));

        alice.change_settings(&gid.0, |s| s.admitted.push(key(7))).await.unwrap();
        assert_eq!(alice.settings(&gid.0).unwrap().admitted, [key(5), key(6), key(7)]);
        alice.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn only_the_sessions_own_service_sets_its_clock() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use ed25519_dalek::SigningKey;
        use lmk_proto::clock::corrected;
        use lmk_proto::{head::{self, Head}, membership::{Answer, Append, Appended, Heads, Moved, Page, Read}};

        let relay = lmk_testing::relay().await;
        let (own_key, other_key) = (SigningKey::from_bytes(&[7; 32]), SigningKey::from_bytes(&[8; 32]));
        let service = |key: &SigningKey, domain: &str| Service::Serve {
            key: Bytes(key.verifying_key().to_bytes().to_vec()),
            domain: domain.into(),
            rest: Default::default(),
        };
        let (own, foreign, wrong_home) = (
            service(&own_key, &relay.domain),
            service(&other_key, "foreign.example"),
            service(&other_key, &relay.domain),
        );
        let own_shift = Arc::new(AtomicU64::new(3_600_000));
        let home_domain = relay.domain.clone();
        let (own_signing, other_signing, shift) = (own_key.clone(), other_key.clone(), own_shift.clone());
        let post: Post = Arc::new(move |domain, route, body| {
            let own_offset = shift.load(Ordering::Relaxed);
            let is_home = domain == home_domain;
            let signing = if is_home { own_signing.clone() } else { other_signing.clone() };
            Box::pin(async move {
                if is_home && own_offset > 0 {
                    n0_future::time::sleep(Duration::from_millis(10)).await;
                }
                let time = now() + if is_home { own_offset } else { 6 * 86_400_000 };
                let s = signing.verifying_key().to_bytes();
                let reply = if route.ends_with("/append") {
                    let append: Append = serde_json::from_slice(&body).unwrap();
                    let id = head::reference(&s, &append.capability);
                    let hash = append.entries.iter().fold(head::start(&s, &id), |h, e| head::next(&h, &e.0));
                    serde_json::to_vec(&Answer::Ok(Appended { head: Head::sign(&signing, &id, append.entries.len() as u64, hash, time) })).unwrap()
                } else if route.ends_with("/read") {
                    let read: Read = serde_json::from_slice(&body).unwrap();
                    let id = head::reference(&s, &read.capability);
                    let head = Head::sign(&signing, &id, 0, head::start(&s, &id), time);
                    serde_json::to_vec(&Answer::Ok(Page { after: read.after, entries: vec![], head })).unwrap()
                } else {
                    assert!(route.ends_with("/heads"));
                    let heads: Heads = serde_json::from_slice(&body).unwrap();
                    let id = head::reference(&s, &heads.logs[0].0);
                    let head = Head::sign(&signing, &id, 0, head::start(&s, &id), time);
                    serde_json::to_vec(&Answer::Ok(Moved { heads: vec![head], expired: vec![] })).unwrap()
                };
                Ok(reply)
            })
        });
        let alice = node(&relay, post).await;
        let group_on = |membership| alice.create(Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership, admins: vec![], admitted: vec![] }).unwrap();

        let foreign_gid = group_on(foreign.clone());
        alice.read_group(&foreign_gid.0).await.unwrap();
        let foreign_log = alice.log(&foreign_gid.0).unwrap();
        let foreign_cap = alice.inner.lock().capability(&foreign_log.0).unwrap();
        alice.inner.clients.client(&foreign).unwrap().append(&foreign_cap, &[b"x".to_vec()]).await.unwrap();
        alice.inner.clients.client(&foreign).unwrap().heads(&[foreign_cap]).await.unwrap();
        assert!(corrected().abs_diff(now()) < 5_000, "a foreign service set the clock: {}", corrected() - now());

        let wrong_gid = group_on(wrong_home.clone());
        let wrong_log = alice.log(&wrong_gid.0).unwrap();
        let wrong_cap = alice.inner.lock().capability(&wrong_log.0).unwrap();
        assert!(alice.read_group(&wrong_gid.0).await.is_err());
        assert!(alice.inner.clients.client(&wrong_home).unwrap().append(&wrong_cap, &[b"x".to_vec()]).await.is_err());
        assert!(alice.inner.clients.client(&wrong_home).unwrap().heads(&[wrong_cap]).await.is_err());
        assert!(corrected().abs_diff(now()) < 5_000, "another key at the home domain set the clock: {}", corrected() - now());

        let own_gid = group_on(own);
        alice.read_group(&own_gid.0).await.unwrap();
        assert!(corrected().abs_diff(now() + 3_600_000) < 5_000, "the own service sets the clock: {}", corrected() - now());
        own_shift.store(0, Ordering::Relaxed);
        alice.read_group(&own_gid.0).await.unwrap();
        alice.shutdown().await.unwrap();
    }

    /// A group is handed to `Peers` as it is added, and its new members as their Add applies, before the next poll: a
    /// joiner's summary that arrives at once is kept.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_joiners_summary_right_after_its_add_is_kept() {
        let relay = lmk_testing::relay().await;
        let (alice, bob, carol) = (node(&relay, relay.post()).await, node(&relay, relay.post()).await, node(&relay, relay.post()).await);
        let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
        let gid = bob.create(settings.clone()).unwrap();
        alice.join(&bob.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        // Alice no longer polls.
        let tasks: Vec<_> = alice.inner.tasks.lock().unwrap().drain(..).collect();
        for task in &tasks {
            task.abort();
        }
        let other = alice.create(settings).unwrap();
        alice.inner.lock().peers.full_mesh(&other);
        carol.join(&bob.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.read_group(&gid.0).await.unwrap();
        let mut st = alice.inner.lock();
        let (member, epoch) = (carol.key(), st.group(&gid.0).unwrap().mls.epoch());
        let joined = st.group(&gid.0).unwrap().mls.joined(&member.0).expect("Alice applied Carol's Add");
        let summary = serde_json::from_value(serde_json::json!({ "group": gid, "member": member, "joined": joined, "version": 1, "time": now(), "epoch": epoch })).unwrap();
        let heard = lmk_net::peers::Heard { signed: Signed { body: Bytes(Vec::new()), sig: Bytes(Vec::new()) }, summary, at: now() };
        assert!(st.peers.summary(&gid, heard, false));
        drop(st);
        for node in [bob, carol] {
            node.shutdown().await.unwrap();
        }
    }

    /// An intro of a membership not known yet, or naming an epoch not reached yet, waits only once its member's signature
    /// holds, and only its membership's latest; those of memberships not known take at most 32 places, which a known
    /// member's does not share: no flood keeps a member's intro from waiting until its epoch comes.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_early_intro_waits_signed_its_memberships_latest_apart_from_unknown_ones() {
        use ed25519_dalek::{Signer, SigningKey};
        use lmk_proto::peer::{INTRO, Intro, Shown};

        let relay = lmk_testing::relay().await;
        let (alice, bob) = (node(&relay, relay.post()).await, node(&relay, relay.post()).await);
        let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
        let gid = alice.create(settings).unwrap();
        bob.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        let epoch = bob.epoch(&gid.0).unwrap();
        n0_future::time::timeout(Duration::from_secs(60), async {
            while alice.epoch(&gid.0).unwrap() < epoch {
                n0_future::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.unwrap();
        // Bob takes no frames, and reads no further, while Alice moves the group on and signs her intros in its next epoch.
        for task in bob.inner.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
        let device = Bytes(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes().to_vec());
        alice.change_settings(&gid.0, |settings| settings.admitted.push(device.clone())).await.unwrap();
        let alice_key = alice.key();
        let own = || alice.inner.lock().group(&gid.0).unwrap().intros().find(|(intro, _)| intro.member == alice_key).unwrap().1.clone();
        let first = own();
        alice.set_intro(&gid.0, Some("newer".into())).unwrap();
        let newer = own();
        let unknown = |seed: u8, version: u64| {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let shown = Shown { epoch: epoch + 1, capability: [0; 32] };
            let intro = Intro { group: gid.clone(), member: Bytes(key.verifying_key().to_bytes().to_vec()), joined: epoch + 1, version, shown, text: None };
            let body = serde_json::to_vec(&intro).unwrap();
            Signed { sig: Bytes(key.sign(&[INTRO, &body].concat()).to_bytes().to_vec()), body: Bytes(body) }
        };
        let mut st = bob.inner.lock();
        let forged = Signed { sig: Bytes(st.session.sign(&[INTRO, &first.body.0].concat())), body: first.body.clone() };
        let waiting = |st: &State| st.group(&gid.0).unwrap().early_intros.len();
        for version in 1..=40 {
            st.intro(&gid.0, unknown(1, version)).unwrap();
        }
        assert_eq!(waiting(&st), 1, "a membership's latest intro waits in place of its earlier ones");
        for seed in 2..=40 {
            st.intro(&gid.0, unknown(seed, 1)).unwrap();
        }
        assert_eq!(waiting(&st), 32, "those of memberships not known take at most 32 places");
        for _ in 0..32 {
            st.intro(&gid.0, forged.clone()).unwrap();
        }
        assert_eq!(waiting(&st), 32, "an intro its member did not sign does not wait");
        for signed in [first, newer] {
            st.intro(&gid.0, signed).unwrap();
        }
        assert_eq!(waiting(&st), 33, "a known member's intro waits apart");
        drop(st);
        bob.read_group(&gid.0).await.unwrap();
        assert_eq!(bob.intros(&gid.0).unwrap().get(&alice_key).map(String::as_str), Some("newer"));
        for node in [alice, bob] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_message_whose_memberships_record_is_gone_counts_as_shown() {
        let relay = lmk_testing::relay().await;
        let (alice, bob) = (node(&relay, relay.post()).await, node(&relay, relay.post()).await);
        let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
        let gid = alice.create(settings).unwrap();
        bob.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        let first = alice.send(&gid.0, &serde_json::json!({ "type": "message", "content": "hi" }), None).await.unwrap();
        n0_future::time::timeout(Duration::from_secs(60), async {
            while bob.message(&gid.0, &first.0).unwrap().is_none() {
                n0_future::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.unwrap();
        assert!(!bob.shown(&gid.0, &first.0).unwrap());
        bob.inner.lock().group_mut(&gid.0).unwrap().rec.authors.retain(|a| a.key != alice.key());
        assert!(bob.shown(&gid.0, &first.0).unwrap());
        for node in [alice, bob] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_rate_refused_send_keeps_the_next_messages_deps() {
        let relay = lmk_testing::relay().await;
        let (alice, bob) = (node(&relay, relay.post()).await, node(&relay, relay.post()).await);
        let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
        let gid = alice.create(settings).unwrap();
        bob.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        let text = serde_json::json!({ "type": "message", "content": "hi" });
        let first = alice.send(&gid.0, &text, None).await.unwrap();
        n0_future::time::timeout(Duration::from_secs(60), async {
            while bob.message(&gid.0, &first.0).unwrap().is_none() {
                n0_future::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.unwrap();
        bob.mark_shown(&gid.0, std::slice::from_ref(&first)).unwrap();
        {
            let mut st = bob.inner.lock();
            let g = st.group_mut(&gid.0).unwrap();
            // No refill during the send, regardless of the wall clock.
            while g.sending.take(0, 1.0, u64::MAX) {}
            let refused = bob.inner.send(&mut st, &gid.0, &text, None).unwrap_err();
            assert!(matches!(refused.downcast_ref(), Some(SendError::Rate)), "{refused:#}");
        }
        bob.inner.lock().group_mut(&gid.0).unwrap().sending = held::Bucket::default();
        let next = bob.send(&gid.0, &text, None).await.unwrap();
        let after = bob.send(&gid.0, &text, None).await.unwrap();
        {
            let st = bob.inner.lock();
            assert_eq!(st.record(&gid.0, &next.0).unwrap().unwrap().header.deps.iter().map(|r| r.id.clone()).collect::<Vec<_>>(), [first]);
            assert!(st.record(&gid.0, &after.0).unwrap().unwrap().header.deps.is_empty(), "the successful send covered the frontier");
        }
        for node in [alice, bob] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_rate_refused_leave_does_not_mark_the_group_leaving() {
        let relay = lmk_testing::relay().await;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("bob.db");
        let start = || async {
            let config = Config { home: relay.domain.clone(), post: relay.post(), ca: relay.ca(), device: ed25519_dalek::SigningKey::from_bytes(&[9; 32]) };
            Node::start(SqliteProvider::open(&db).unwrap(), config).await.unwrap().0
        };
        let (alice, bob) = (node(&relay, relay.post()).await, start().await);
        let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
        let gid = alice.create(settings).unwrap();
        bob.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        {
            let mut st = bob.inner.lock();
            let g = st.group_mut(&gid.0).unwrap();
            while g.sending.take(0, 1.0, u64::MAX) {}
        }
        let refused = bob.leave(&gid.0).unwrap_err();
        assert!(matches!(refused.downcast_ref(), Some(SendError::Rate)), "{refused:#}");
        assert!(!bob.leaving(&gid.0));
        bob.shutdown().await.unwrap();
        let bob = start().await;
        assert!(!bob.leaving(&gid.0));
        let id = bob.leave(&gid.0).unwrap().unwrap();
        assert!(bob.leaving(&gid.0));
        assert_eq!(bob.leave(&gid.0).unwrap(), Some(id));
        for node in [alice, bob] {
            node.shutdown().await.unwrap();
        }
    }

    /// Two members that chatted, once all is delivered and said, poll for nothing: no timed work is due.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_idle_session_polls_for_nothing() {
        let relay = lmk_testing::relay().await;
        let (alice, bob) = (node(&relay, relay.post()).await, node(&relay, relay.post()).await);
        let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
        let gid = alice.create(settings).unwrap();
        bob.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        let text = serde_json::json!({ "type": "message", "content": "hi" });
        alice.send(&gid.0, &text, None).await.unwrap();
        let idle = |node: &Node| node.inner.lock().next_poll().is_none_or(|at| at > now() + 60_000);
        let quiet = async {
            while !(idle(&alice) && idle(&bob)) {
                n0_future::time::sleep(Duration::from_millis(500)).await;
            }
        };
        n0_future::time::timeout(Duration::from_secs(60), quiet).await.expect("both go idle");
        for node in [alice, bob] {
            node.shutdown().await.unwrap();
        }
    }
    /// A seq a session knows of that no member holds, as one a dep or a `have` named and its author never sent, is
    /// waited for with no poll.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_seq_no_member_holds_is_waited_for_with_no_poll() {
        let relay = lmk_testing::relay().await;
        let (alice, bob) = (node(&relay, relay.post()).await, node(&relay, relay.post()).await);
        let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
        let gid = alice.create(settings).unwrap();
        bob.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        {
            let mut st = bob.inner.lock();
            let now = st.tick();
            let g = st.group_mut(&gid.0).unwrap();
            let known = g.current(&alice.key().0).unwrap().known;
            g.learn(&alice.key().0, 0, known + 1, now);
        }
        let idle = |node: &Node| node.inner.lock().next_poll().is_none_or(|at| at > now() + 60_000);
        let quiet = async {
            while !(idle(&alice) && idle(&bob)) {
                n0_future::time::sleep(Duration::from_millis(500)).await;
            }
        };
        n0_future::time::timeout(Duration::from_secs(60), quiet).await.expect("both go idle");
        assert!(!bob.inner.lock().group(&gid.0).unwrap().current(&alice.key().0).unwrap().wanted().is_empty(), "Bob still wants it");
        for node in [alice, bob] {
            node.shutdown().await.unwrap();
        }
    }
}
