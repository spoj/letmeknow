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
use lmk_proto::group::Service;
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
pub use lmk_proto::clock::now;

/// How long an invite is valid, in milliseconds.
pub const INVITE_VALID: u64 = 10 * 60 * 1000;
/// How long an invite waits for the members online to hold it.
const MEMBER_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Config {
    /// The domain of this session's own membership service, whose relay it lives on.
    pub home: String,
    /// Posts to a membership service's routes, as the shell does over https.
    pub post: Post,
    pub ca: CaTlsConfig,
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
    /// The protocol revision its leaf names.
    pub revision: u32,
    /// The domain of its own service, whose relay it lives on, as its leaf names it.
    pub home: String,
}

impl From<&core::Member> for Member {
    fn from(member: &core::Member) -> Self {
        Member {
            key: Bytes(member.key.clone()),
            iroh: member.leaf.as_ref().map(|leaf| leaf.key.clone()).unwrap_or_default(),
            revision: member.leaf.as_ref().map_or(0, |leaf| leaf.revision),
            home: member.leaf.as_ref().map(|leaf| leaf.home.clone()).unwrap_or_default(),
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

/// Seqs of one author's membership lost, with the ids this session knows: only of its own messages, told by others.
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
    #[error("behind: the group moved on, and this session has not caught up yet; send again")]
    Behind,
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
    /// This session was removed, by `by` as it applied the commit, or else with no `by`: by a commit applied before it
    /// stopped, left the only member of a group it asked to leave, or away past its log's retention. The group is gone
    /// from it, with its messages no cut kept: `not_kept`, by id.
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
    /// The invites shared with the group, kept for H after they expire.
    invites: Vec<Rule>,
    /// The `leave`s opened: each one's membership, and its seq.
    leaves: Vec<(Bytes, u64, u64)>,
    /// This session asked to leave: it is in the group until a member removes it.
    leaving: bool,
    /// When this session's leaf was last updated, in milliseconds.
    updated: u64,
    /// The group delivered a message or changed its members since this session's leaf was last updated: an update is
    /// due once T passed.
    stirred: bool,
    /// When this session last asked which members' logs their services let go, in milliseconds.
    evicted: u64,
    /// The latest epoch this session's own commit or message showed it in, and when the group moved past it: while
    /// it is behind, a `present` is due `PRESENT` after that.
    present: u64,
    passed: u64,
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
    /// The epoch each other member is surely at: its join epoch, its latest commit's, or a summary's in the current epoch.
    members: Vec<(Bytes, u64)>,
    /// The epochs behind the current one that members are at, each with its log's capability and service.
    epochs: Vec<Epoch>,
}

/// An epoch behind a group's current one, with its log's capability and service: a member still in it reads that log.
#[derive(Clone, Serialize, Deserialize)]
struct Epoch {
    epoch: u64,
    capability: [u8; 32],
    service: Service,
}

/// An invite, as its inviter shared it with the group, or kept for one member.
#[derive(Clone, Serialize, Deserialize)]
struct Rule {
    /// SHA-256 of its secret.
    hash: Bytes,
    expires: u64,
    /// The inviter's session key.
    by: Bytes,
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
    /// Ciphertexts taken but not opened yet, past the window or the bucket: by claim, with their epoch.
    unopened: BTreeMap<(Bytes, u64, u64), (u64, Vec<u8>)>,
    /// The flood buckets of the group's memberships, and this session's own.
    buckets: BTreeMap<(Bytes, u64), held::Bucket>,
    sending: held::Bucket,
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
    /// Summaries of memberships this session does not know yet, as a joiner's before its Add applies here.
    unverified: Vec<(EndpointId, Signed)>,
    /// This session's summary changed since it was signed.
    changed: bool,
    /// Epochs behind this session's whose logs their services let go, as the check before its last commit found.
    lapsed: Vec<u64>,
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
            changed: true,
            lapsed: Vec::new(),
        }
    }

    /// Whether the member with key `key` is in an epoch whose log its service let go.
    fn left_behind(&self, key: &[u8]) -> bool {
        self.rec.members.iter().any(|(member, epoch)| member.0 == key && self.lapsed.contains(epoch))
    }

    /// The seq of the `leave` of the current membership of the member with key `key`, if it asked to leave.
    fn left(&self, key: &[u8]) -> Option<u64> {
        let joined = self.mls.joined(key)?;
        self.rec.leaves.iter().find(|(by, at, _)| by.0 == key && *at == joined).map(|(_, _, seq)| *seq)
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
    /// Hellos of groups not added yet, with the peers that sent them: taken once the group is.
    early_hellos: Vec<(EndpointId, At)>,
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
    Applied {
        group: Vec<u8>,
        by: Option<core::Member>,
        added: Vec<core::Member>,
        removed: Vec<core::Member>,
        gone: bool,
    },
    /// A group's duties to run.
    Duties(Vec<u8>),
    /// A group's current log, just found let go: read again once `WAIT` passed.
    Lapsed(Vec<u8>),
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
        members.into_iter().find(|m| m.leaf.as_ref().is_some_and(|leaf| leaf.key.0 == peer.as_bytes()))
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
        (rec.resealed, rec.present) = (mls.epoch(), mls.epoch());
        let own = mls.own_index();
        rec.members = mls.members().into_iter().filter(|m| m.index != own).map(|m| (Bytes(m.key), mls.epoch())).collect();
        rec.authors = mls.cut().iter().map(|r| Author::new(r.key.clone(), r.joined, r.seq)).collect();
        self.groups.insert(gid.clone(), G::new(mls, rec));
        self.next_log(&gid, base)?;
        self.save_groups()?;
        self.gate = true;
        self.refresh(&gid);
        // The early hellos' sightings count only from peers the gate admits to the group.
        self.gate();
        let now = self.tick();
        let (early, others) = std::mem::take(&mut self.early_hellos).into_iter().partition(|(_, at)| at.group.0 == gid);
        self.early_hellos = others;
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
        let config = Config { home: relay.domain.clone(), post, ca: relay.ca() };
        Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config).await.unwrap().0
    }

    /// A group is handed to `Peers` as it is added, and its new members as their Add applies, before the next poll: a
    /// joiner's summary that arrives at once is kept.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_joiners_summary_right_after_its_add_is_kept() {
        let relay = lmk_testing::relay().await;
        let (alice, bob, carol) = (node(&relay, relay.post()).await, node(&relay, relay.post()).await, node(&relay, relay.post()).await);
        let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone() };
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

    /// Two members that chatted, once all is delivered and said, poll for nothing: no timed work is due.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_idle_session_polls_for_nothing() {
        let relay = lmk_testing::relay().await;
        let (alice, bob) = (node(&relay, relay.post()).await, node(&relay, relay.post()).await);
        let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone() };
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
}
