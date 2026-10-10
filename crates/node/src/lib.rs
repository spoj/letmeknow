//! One member's session over lmk-core, lmk-net and lmk-membership: its groups and their logs, its held messages and
//! files, the invites it shares and the joiners it admits, and its members' identities: their key logs, against which
//! their credentials' certificates are checked. A group's kind sees its
//! content through the channels here (held and live messages, files, its log, and a state link for
//! joiners), and nothing of the rest; the core reads only its own payloads (`Control`). The devices kind (`devices`) is
//! built on those channels. It stores everything through the core's `Provider`, so the same code runs natively (SQLite)
//! and in the browser (memory the web client persists).

pub mod devices;
mod groups;
mod kindlog;
mod logs;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result, bail, ensure};
use iroh::tls::CaTlsConfig;
use iroh::{EndpointId, RelayMap, RelayUrl, SecretKey};
use lmk_core::device::{Device, signer};
use lmk_core::group::{self as core, Change, Group, Session, Window};
use lmk_core::identity::{KeyLog, Verdict};
use lmk_membership::Contradiction;
use lmk_core::provider::Provider;
use lmk_membership::Refused;
use lmk_net::{Net, Network};
use lmk_proto::group::{
    CHAT, Certificate, Control, Credential, DEVICES, How, INTRODUCE_REVISION, IdentityRef, Leaf, Opening, RENAME_REVISION, REVISION, Reason, Refusal, Settings,
    held_by_type, type_of,
};
use lmk_proto::links::{Address, FileLink, Invite, RELAY};
use lmk_proto::peer::{Admitted, Frame, Join, KindLog as LogRef};
use lmk_proto::{Answer, Bytes};
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
/// How long `send` waits for the members it wrote to.
const RECEIPT_WAIT: Duration = Duration::from_secs(5);
/// How long a member gathers the messages it gives up before it reports them.
const REPORT_WAIT: Duration = Duration::from_secs(1);
/// How often members not connected are dialed again.
const REDIAL: Duration = Duration::from_secs(10);
/// How often connected members sync their groups again.
const RESYNC: Duration = Duration::from_secs(5 * 60);
/// How often files no group holds any longer are deleted.
const COLLECT: Duration = Duration::from_secs(60 * 60);
/// How long a fetch keeps looking for a member that holds the file.
const FETCH_TRIES: u32 = 12;
/// How long a member admitting a joiner waits for the state of the group's kind.
const SNAPSHOT_WAIT: Duration = Duration::from_secs(10);
/// How long a session behind its group's kind log waits before it asks a member for the kind's state again, in
/// milliseconds.
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
    pub window: Window,
    /// The kinds this session supports, `chat` among them.
    pub kinds: Vec<String>,
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
    #[serde(default)]
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

/// A message held for the group: a held payload of its kind, or a request to leave.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: Bytes,
    pub group: Bytes,
    pub epoch: u64,
    /// When it reached this session, in milliseconds since the Unix epoch.
    pub at: u64,
    pub sender: Member,
    pub payload: Value,
}

/// An entry of the kind's log, taken: its position, and the held message it names.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub position: u64,
    pub id: Bytes,
    pub from: Member,
    pub payload: Value,
}

/// Who held a message, and who refused it, as `send` waited.
#[derive(Clone, Debug, Default)]
pub struct Delivery {
    pub held: Vec<Member>,
    pub refused: Vec<(Member, Reason)>,
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
    /// A held payload of the group's kind.
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
    /// Entries of the kind's log were taken (see `Node::entries`).
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
    /// A member took a message this session sent, after `send` stopped waiting.
    Held {
        group: Bytes,
        id: Bytes,
        by: Member,
    },
    /// A member reports that it gave up messages this session sent, after `send` stopped waiting.
    Refused {
        group: Bytes,
        by: Member,
        messages: Vec<Refusal>,
    },
    /// A file is held whole.
    File([u8; 32]),
    /// An identity's key log grew, as this session read it.
    Keys { identity: Bytes },
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
            | Event::Synced { group }
            | Event::InStep { group, .. }
            | Event::State { group, .. }
            | Event::Logged { group }
            | Event::Snapshot { group, .. }
            | Event::Introduced { group, .. }
            | Event::Held { group, .. }
            | Event::Refused { group, .. } => Some(group),
            Event::Message(message) => Some(&message.group),
            Event::Warning { group, .. } => group.as_ref(),
            Event::File(_) | Event::Keys { .. } => None,
        }
    }
}

/// A group's own record, beside its MLS state and its logs.
#[derive(Default, Serialize, Deserialize)]
struct Rec {
    /// The last position of its log applied.
    position: u64,
    items: Vec<Item>,
    /// Messages this session could not open, so that sync does not offer them again, and those from before it joined
    /// that the member that admitted it held, as of epoch 0.
    given_up: Vec<(u64, Bytes)>,
    /// Those it gave up and has not reported to the group yet.
    unreported: Vec<Refusal>,
    /// The newest epoch of the messages it dropped after `keep`: what it lacks up to there, it may have had, and does
    /// not report.
    expired: u64,
    pending: Vec<Pending>,
    /// File links, with when they were linked: those the kind holds (its files added, and those its held messages
    /// link) and states handed to or by this session. Each is held for the group's `keep`.
    files: Vec<(String, u64)>,
    /// The state handed to or by this session last, held however old.
    state: Option<String>,
    /// The files the kind links now, held while it does.
    links: Vec<String>,
    /// The kind's log, once the kind follows it.
    log: Option<kindlog::KindLog>,
    /// The logs of the kind's order this session reads from where it is, in order; the last is current.
    kind_logs: Vec<LogRef>,
    /// The invites shared with the group, kept for `keep` after they expire.
    invites: Vec<Rule>,
    /// The session keys of the members this session ended the kind's log to remove, until it applies a commit that
    /// removes them: it removes them again as it starts and at each resync, as after a crash before posting the commit.
    #[serde(default)]
    removing: Vec<Bytes>,
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

    /// The files this session holds for the group: those linked within `keep`, the latest state, and those the kind
    /// links now.
    fn held(&self, keep: u32) -> Vec<FileLink> {
        let since = now().saturating_sub(keep as u64 * 24 * 3600 * 1000);
        let linked = self.files.iter().filter(|(_, at)| *at >= since).map(|(link, _)| link).chain(&self.state);
        linked.chain(&self.links).filter_map(|link| FileLink::parse(link).ok()).collect()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Item {
    epoch: u64,
    id: Bytes,
    at: u64,
    /// Its place in the kind's log, once an entry there named it.
    position: Option<u64>,
}

pub(crate) struct G {
    mls: Group,
    rec: Rec,
    /// Ciphertexts from epochs this session has not reached.
    future: Vec<Vec<u8>>,
    /// The position at which this session's own commit was last applied.
    own_at: Option<u64>,
    /// When this session last asked a member for the kind's state, or was handed one, in milliseconds.
    asked: u64,
}

pub(crate) struct State<P> {
    provider: P,
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
    /// `send`s waiting for receipts.
    waiters: HashMap<[u8; 32], mpsc::UnboundedSender<(EndpointId, Option<Reason>)>>,
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
    /// A log to follow at its service.
    Follow(Vec<u8>),
    Remove {
        group: Vec<u8>,
        key: Vec<u8>,
    },
    /// A group with members whose devices their identities' key logs dropped.
    Revoke(Vec<u8>),
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
    /// Messages were given up: report them in a moment.
    Report(Vec<u8>),
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
    window: Window,
    kinds: Vec<String>,
    events: mpsc::UnboundedSender<Event>,
    work: mpsc::UnboundedSender<Work>,
    committing: tokio::sync::Mutex<()>,
    /// Woken whenever a kind's log is applied further, for appends waiting to catch up.
    advanced: tokio::sync::Notify,
    reading: Mutex<HashSet<Vec<u8>>>,
    /// The removals under way, by group and member key.
    removing: Mutex<HashSet<(Vec<u8>, Vec<u8>)>>,
    /// The groups whose dropped devices' members are being removed.
    revoking: Mutex<HashSet<Vec<u8>>>,
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

fn ciphertext_key(id: &[u8]) -> Vec<u8> {
    [b"node/ciphertext/".as_slice(), id].concat()
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

    /// The groups this session serves each of these peers.
    fn served(&self, peers: &[EndpointId]) -> Vec<(Vec<u8>, EndpointId)> {
        let gids = self.groups.keys();
        gids.flat_map(|gid| peers.iter().filter(|peer| self.serves(gid, peer)).map(|peer| (gid.clone(), *peer))).collect()
    }

    /// The identities a group's members speak as.
    fn identities(&self, gid: &[u8]) -> Vec<IdentityRef> {
        let Some(g) = self.groups.get(gid) else { return Vec::new() };
        g.mls.members().into_iter().filter_map(|m| Some(m.credential?.certificate?.identity)).collect()
    }

    /// A new group's records, its MLS state, and its log, read after `rec.position`.
    fn add_group(&mut self, mls: Group, rec: Rec) -> Result<Vec<u8>> {
        let gid = mls.id().to_vec();
        self.add_log(&gid, logs::Log::new(logs::Of::Group, mls.settings().membership, rec.position))?;
        self.groups.insert(gid.clone(), G { mls, rec, future: Vec::new(), own_at: None, asked: 0 });
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
        let mut session = match provider.get(b"session")? {
            Some(_) => Session::load(&provider)?,
            None => Session::create(&provider, &config.name, leaf.clone())?,
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
            groups.insert(gid.0, G { mls, rec, future: Vec::new(), own_at: None, asked: 0 });
        }
        let (events, events_rx) = mpsc::unbounded_channel();
        let (work, work_rx) = mpsc::unbounded_channel();
        let mut state = State {
            provider,
            device: config.device.as_ref().map(|device| device.name.clone()),
            session,
            groups,
            logs,
            keys: BTreeMap::new(),
            unlisted: HashSet::new(),
            device_keys: BTreeMap::new(),
            waiters: HashMap::new(),
        };
        for gid in state.groups.keys().cloned().collect::<Vec<_>>() {
            if let Some(seed) = get::<Bytes>(&state.provider, &device_key_key(&gid))? {
                let seed: [u8; 32] = seed.0.as_slice().try_into().context("a device key is 32 bytes")?;
                let session = state.keyed(seed)?;
                state.device_keys.insert(gid, (seed, session));
            }
        }
        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            net: OnceLock::new(),
            clients,
            follows: Mutex::default(),
            relay: config.relay.clone(),
            file_limit: config.file_limit,
            window: config.window,
            kinds: config.kinds,
            events,
            work: work.clone(),
            committing: tokio::sync::Mutex::new(()),
            advanced: tokio::sync::Notify::new(),
            reading: Mutex::default(),
            removing: Mutex::default(),
            revoking: Mutex::default(),
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
        let (gids, followed): (Vec<Vec<u8>>, Vec<Vec<u8>>) = {
            let st = inner.state.lock().unwrap();
            (st.groups.keys().cloned().collect(), st.logs.keys().cloned().collect())
        };
        for log in &followed {
            inner.follow(log);
        }
        {
            let mut st = inner.state.lock().unwrap();
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
            // A session removed by a commit it applied before it stopped is told so now.
            let st = inner.state.lock().unwrap();
            for gid in &gids {
                if !st.group(gid)?.mls.active() {
                    inner.work.send(Work::Gone(gid.clone())).ok();
                } else if let Err(error) = inner.leavers(&st, gid) {
                    inner.warn(Some(gid), format!("{error:#}"));
                }
            }
        }
        inner.spawn(inner.clone().resume(gids));
        inner.spawn(inner.clone().finish_removals());
        inner.spawn(inner.clone().redial());
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
        Bytes(self.inner.state.lock().unwrap().session.key().to_vec())
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
        self.inner.state.lock().unwrap().groups.keys().map(|gid| Bytes(gid.clone())).collect()
    }

    pub fn settings(&self, gid: &[u8]) -> Result<Settings> {
        Ok(self.inner.state.lock().unwrap().group(gid)?.mls.settings())
    }

    pub fn epoch(&self, gid: &[u8]) -> Result<u64> {
        Ok(self.inner.state.lock().unwrap().group(gid)?.mls.epoch())
    }

    /// The epoch this session joined the group at.
    pub fn joined(&self, gid: &[u8]) -> Result<u64> {
        Ok(self.inner.state.lock().unwrap().group(gid)?.mls.joined())
    }

    pub fn members(&self, gid: &[u8]) -> Result<Vec<Member>> {
        self.inner.state.lock().unwrap().members(gid)
    }

    /// The members connected now.
    pub fn online(&self, gid: &[u8]) -> Result<Vec<Member>> {
        let connected = self.inner.net().connected();
        let members = self.members(gid)?;
        Ok(members.into_iter().filter(|m| connected.iter().any(|peer| peer.as_bytes()[..] == m.iroh.0[..])).collect())
    }

    /// What this session sent to a group that no other member holds yet.
    pub fn only_here(&self, gid: &[u8]) -> Result<Vec<Pending>> {
        Ok(self.inner.state.lock().unwrap().group(gid)?.rec.pending.clone())
    }

    /// The kinds this session supports.
    pub fn kinds(&self) -> &[String] {
        &self.inner.kinds
    }

    /// A new group with this session its only member, speaking as `identity`; a devices group with a new device key. A
    /// group of any kind but chat gets a log of its own.
    pub fn create(&self, settings: Settings, identity: Option<Certificate>) -> Result<Bytes> {
        ensure!(self.inner.kinds.contains(&settings.kind), "this session does not support {} groups", settings.kind);
        let gid = {
            let mut st = self.inner.state.lock().unwrap();
            let st = &mut *st;
            st.speak(identity);
            let device_key = (settings.kind == DEVICES).then(|| st.device_key()).transpose()?;
            let session = device_key.as_ref().map_or(&st.session, |(_, session)| session);
            let mls = Group::create(&st.provider, session, &settings, self.inner.window)?;
            let id = Bytes(mls.exported(&st.provider, kindlog::LOG_LABEL)?.to_vec());
            let kind_logs = if settings.kind == CHAT { Vec::new() } else { vec![LogRef { id, after: 0 }] };
            let gid = st.add_group(mls, Rec { kind_logs, ..Rec::default() })?;
            if let Some((seed, session)) = device_key {
                put(&st.provider, &device_key_key(&gid), &Bytes(seed.to_vec()))?;
                st.device_keys.insert(gid.clone(), (seed, session));
            }
            gid
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
            let mut st = self.inner.state.lock().unwrap();
            let by = Bytes(st.me(gid).to_vec());
            let g = st.group_mut(gid)?;
            g.rec.invites.push(Rule { hash: hash.clone(), expires, label: label.clone(), to: to.clone(), by });
            st.save(gid)?;
            st.group(gid)?.mls.settings().kind == DEVICES
        };
        let rule = serde_json::to_value(Control::Invite { hash, expires, label, to })?;
        let (id, delivery) = self.send(gid, &rule, true).await?;
        // Members that take it later can admit by it too, but nothing waits for them: it is not pending here.
        let mut st = self.inner.state.lock().unwrap();
        st.group_mut(gid)?.rec.pending.retain(|pending| pending.id != id);
        st.save(gid)?;
        let mut members = vec![address(*self.inner.net().id().as_bytes(), self.inner.relay.as_str())];
        for member in delivery.held.iter().take(LINK_MEMBERS) {
            let Some(leaf) = endpoint_id(&member.iroh.0).and_then(|peer| st.in_leaf(gid, &peer)?.leaf) else { continue };
            members.push(address(*endpoint_id(&leaf.key.0).context("an iroh key")?.as_bytes(), &leaf.relay));
        }
        Ok(Invite { device, secret, members })
    }

    /// Joins through an invite link, speaking as `identity`: asks the members it names in turn. A device link joins
    /// with a new device key. Returns the group, and the iroh key of the member that admitted this session.
    pub async fn join(&self, link: &Invite, identity: Option<Certificate>) -> Result<(Bytes, [u8; 32])> {
        let ours: RelayUrl = RELAY.parse()?;
        let members = link
            .members
            .iter()
            .map(|member| Ok((EndpointId::from_bytes(&member.key)?, member.relay.as_ref().map_or(Ok(ours.clone()), |relay| relay.parse())?)))
            .collect::<Result<Vec<_>>>()?;
        self.ask(members, Some(Bytes(link.secret.to_vec())), None, identity, link.device).await
    }

    /// Asks the members of an open group to admit this session in turn, speaking as the identity `identity` certifies.
    pub async fn join_open(&self, opening: &Opening, identity: Certificate) -> Result<Bytes> {
        ensure!(self.inner.kinds.contains(&opening.kind), "this session does not support {} groups", opening.kind);
        let members = opening.members.iter().filter_map(|key| endpoint_id(&key.0)).map(|peer| (peer, self.inner.relay.clone())).collect();
        Ok(self.ask(members, None, Some(opening.group.clone()), Some(identity), false).await?.0)
    }

    /// Asks members in turn to admit this session, by an invite's secret or a group open to `identity`.
    async fn ask(
        &self,
        members: Vec<(EndpointId, RelayUrl)>,
        secret: Option<Bytes>,
        group: Option<Bytes>,
        identity: Option<Certificate>,
        devices: bool,
    ) -> Result<(Bytes, [u8; 32])> {
        let (join, device_key) = {
            let mut st = self.inner.state.lock().unwrap();
            st.speak(identity);
            let device_key = devices.then(|| st.device_key()).transpose()?;
            let session = device_key.as_ref().map_or(&st.session, |(_, session)| session);
            (Join { secret, group, key_package: Bytes(session.key_package(&st.provider)?) }, device_key.map(|(seed, _)| seed))
        };
        let dialed = n0_future::join_all(members.iter().map(|(peer, relay)| timeout(DIAL_WAIT, self.inner.net().dial(*peer, relay.clone())))).await;
        let mut refusal = anyhow::anyhow!("no member the invite names is online");
        for ((peer, relay), dialed) in members.into_iter().zip(dialed) {
            if !matches!(dialed, Ok(Ok(()))) {
                tracing::debug!("{} is not online", peer.fmt_short());
                continue;
            }
            match timeout(JOIN_WAIT, self.inner.net().join(peer, relay, join.clone())).await {
                Ok(Ok(Answer::Ok(admitted))) => return Ok((self.inner.welcomed(admitted, peer, device_key).await?, *peer.as_bytes())),
                Ok(Ok(Answer::Refused { refused })) => refusal = anyhow::anyhow!("refused: {refused}"),
                Ok(Err(error)) => tracing::debug!("asking {} to admit this session: {error:#}", peer.fmt_short()),
                Err(_) => tracing::debug!("{} did not answer", peer.fmt_short()),
            }
        }
        Err(refusal)
    }

    /// Removes a member. Returns whether this session's commit removed it, which it need not once another's did.
    pub async fn remove(&self, gid: &[u8], key: &[u8]) -> Result<bool> {
        ensure!(self.inner.state.lock().unwrap().group(gid)?.mls.members().iter().any(|m| m.key == key), "not a member");
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
    pub async fn leave(&self, gid: &[u8]) -> Result<Option<Delivery>> {
        if self.members(gid)?.len() == 1 {
            self.inner.forget(gid)?;
            return Ok(None);
        }
        Ok(Some(self.send(gid, &json!({ "type": "leave" }), true).await?.1))
    }

    /// Seals a payload, sends it to the members online, and waits a while for their receipts. A held payload (always
    /// one held by its type, and an `introduce` where every leaf takes it) members hold for the group's `keep`, and sync.
    pub async fn send(&self, gid: &[u8], payload: &Value, held: bool) -> Result<(Bytes, Delivery)> {
        let (id, ciphertext, receipts) = {
            let mut st = self.inner.state.lock().unwrap();
            let st = &mut *st;
            let g = st.groups.get_mut(gid).context("this session is not in that group")?;
            let held = held || held_by_type(payload) || type_of(payload) == "introduce" && g.mls.revised(INTRODUCE_REVISION);
            let session = st.device_keys.get(gid).map_or(&st.session, |(_, session)| session);
            let (id, ciphertext) = g.mls.seal(&st.provider, session, payload, held)?;
            if held {
                let epoch = g.mls.epoch();
                let me = g.mls.members().into_iter().find(|m| m.key == session.key());
                let g = st.groups.get_mut(gid).unwrap();
                g.rec.items.push(Item { epoch, id: Bytes(id.to_vec()), at: now(), position: None });
                g.rec.pending.push(Pending { id: Bytes(id.to_vec()), what: "message".into() });
                st.provider.put(&ciphertext_key(&id), &ciphertext)?;
                let sender = me.and_then(|me| st.member(gid, &me)).context("this session is not in the group")?;
                let message = Message {
                    id: Bytes(id.to_vec()),
                    group: Bytes(gid.to_vec()),
                    epoch,
                    at: now(),
                    sender,
                    payload: payload.clone(),
                };
                put(&st.provider, &message_key(&id), &message)?;
                st.save(gid)?;
            }
            let (tx, rx) = mpsc::unbounded_channel();
            st.waiters.insert(id, tx);
            (id, ciphertext, rx)
        };
        let delivery = self.inner.deliver(gid, id, ciphertext, receipts).await;
        Ok((Bytes(id.to_vec()), delivery))
    }

    /// Seals a live payload, not held, and sends it to the members online, or to the one with fingerprint `to`.
    pub fn send_live(&self, gid: &[u8], payload: &Value, to: Option<&str>) -> Result<()> {
        ensure!(!held_by_type(payload), "a {} is held", lmk_proto::group::type_of(payload));
        let (ciphertext, peer) = {
            let mut st = self.inner.state.lock().unwrap();
            let st = &mut *st;
            let peer = to.map(|fp| st.by_fp(gid, fp)).transpose()?;
            let g = st.groups.get_mut(gid).context("this session is not in that group")?;
            let session = st.device_keys.get(gid).map_or(&st.session, |(_, session)| session);
            (g.mls.seal(&st.provider, session, payload, false)?.1, peer)
        };
        match peer {
            Some(peer) => _ = self.inner.net().send_to(peer, gid, ciphertext),
            None => _ = self.inner.net().send(gid, ciphertext),
        }
        Ok(())
    }

    /// Holds files for the group's `keep` from now, as those a held message links, unless it holds them already; fetches
    /// those within this session's limit.
    pub fn hold(&self, gid: &[u8], links: &[String]) -> Result<()> {
        let parsed = links.iter().map(|link| FileLink::parse(link)).collect::<Result<Vec<_>>>()?;
        let mut st = self.inner.state.lock().unwrap();
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
        let mut st = self.inner.state.lock().unwrap();
        let rec = &mut st.group_mut(gid)?.rec;
        let new = links.iter().filter(|link| !rec.links.contains(link)).map(|link| FileLink::parse(link)).collect::<Result<Vec<_>>>()?;
        rec.links = links;
        st.save(gid)?;
        self.inner.fetch_within_limit(gid, new);
        Ok(())
    }

    /// Hands the member with fingerprint `to` a state of the group's kind, as a file it fetches.
    pub async fn hand_state(&self, gid: &[u8], to: &str, data: Vec<u8>) -> Result<()> {
        let peer = self.inner.state.lock().unwrap().by_fp(gid, to)?;
        let link = self.inner.state_file(gid, data).await?;
        self.inner.net().frame(peer, Frame::State { group: Bytes(gid.to_vec()), link: Some(link) });
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

    /// Whether this session gave a message up: it refused it, or could not open it.
    pub fn given_up(&self, gid: &[u8], id: &[u8]) -> bool {
        let st = self.inner.state.lock().unwrap();
        st.group(gid).is_ok_and(|g| g.rec.given_up.iter().any(|(_, given)| given.0 == id))
    }

    /// A held message.
    pub fn message(&self, id: &[u8]) -> Result<Option<Message>> {
        get(&self.inner.state.lock().unwrap().provider, &message_key(id))
    }

    /// The group's held messages, oldest first.
    pub fn messages(&self, gid: &[u8]) -> Result<Vec<Message>> {
        let st = self.inner.state.lock().unwrap();
        let items = st.group(gid)?.rec.items.clone();
        Ok(items.iter().filter_map(|item| get(&st.provider, &message_key(&item.id.0)).ok().flatten()).collect())
    }

    /// Replaces a held message's payload, as when its text is forgotten; it is still served to members as ciphertext.
    pub fn redact(&self, id: &[u8], payload: Value) -> Result<()> {
        let st = self.inner.state.lock().unwrap();
        let Some(mut message) = get::<Message>(&st.provider, &message_key(id))? else {
            return Ok(());
        };
        message.payload = payload;
        put(&st.provider, &message_key(id), &message)?;
        st.provider.scrub()
    }

    /// A record of a kind built into the client, kept with the session's own.
    pub fn record(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.state.lock().unwrap().provider.get(&kind_key(key))
    }

    pub fn put_record(&self, key: &str, value: &[u8]) -> Result<()> {
        self.inner.state.lock().unwrap().provider.put(&kind_key(key), value)
    }

    pub fn delete_record(&self, key: &str) -> Result<()> {
        self.inner.state.lock().unwrap().provider.delete(&kind_key(key))
    }

    /// Leaves in this session's files no copy of what it deleted.
    pub fn scrub(&self) -> Result<()> {
        self.inner.state.lock().unwrap().provider.scrub()
    }

    /// Seals a file and holds it for a group.
    pub async fn add_file(&self, gid: &[u8], bytes: Vec<u8>) -> Result<FileLink> {
        let link = self.inner.net().add_file(std::io::Cursor::new(bytes)).await?;
        let mut st = self.inner.state.lock().unwrap();
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
                let st = self.inner.state.lock().unwrap();
                return holders.iter().map(|peer| st.by_iroh(gid, peer)).collect();
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Waits until another member online holds a file this session added, or a few seconds; returns them. If none does,
    /// the file is pending until one fetches it.
    pub async fn spread(&self, gid: &[u8], link: &FileLink) -> Vec<Member> {
        let holders = self.holders(gid, link, RECEIPT_WAIT).await;
        let mut st = self.inner.state.lock().unwrap();
        if holders.is_empty()
            && let Ok(g) = st.group_mut(gid)
        {
            g.rec.pending.push(Pending { id: Bytes(link.hash.to_vec()), what: "file".into() });
            st.save(gid).ok();
        }
        holders
    }

    // Identities: their key logs, and the device keys of a device's node.

    /// An identity's key log, read from its service now.
    pub async fn read_key_log(&self, identity: &IdentityRef) -> Result<KeyLog> {
        self.inner.read_keys(identity).await
    }

    /// Appends a sealed entry to an identity's key log, and reads the log.
    pub async fn append_identity(&self, identity: &IdentityRef, entry: &[u8]) -> Result<KeyLog> {
        let log = lmk_proto::identity::address(&identity.id.0);
        self.inner.clients.client(&identity.membership)?.append(&log, entry).await?;
        self.inner.read_keys(identity).await
    }

    /// The identities this session speaks as in its groups.
    pub fn spoken(&self) -> Vec<IdentityRef> {
        let st = self.inner.state.lock().unwrap();
        let mut spoken: Vec<IdentityRef> = Vec::new();
        for g in st.groups.values() {
            let me = g.mls.members().into_iter().find(|m| m.key == st.session.key());
            if let Some(identity) = me.and_then(|me| Some(me.credential?.certificate?.identity))
                && !spoken.contains(&identity)
            {
                spoken.push(identity);
            }
        }
        spoken
    }

    /// This session's key in a group: in a devices group, the device's key on its identity.
    pub fn key_in(&self, gid: &[u8]) -> Bytes {
        Bytes(self.inner.state.lock().unwrap().me(gid).to_vec())
    }

    /// A signature over `bytes` by the device's key in a devices group.
    pub fn sign(&self, gid: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
        let st = self.inner.state.lock().unwrap();
        let (seed, _) = st.device_keys.get(gid).context("not a devices group of this node")?;
        Ok(lmk_core::identity::sign(seed, bytes))
    }

    /// Reads a group's log from its service through its end, applying what it holds.
    pub async fn read_group(&self, gid: &[u8]) -> Result<()> {
        self.inner.read(gid).await
    }

    /// Asks a member online, by its iroh key, for the state of the group's kind.
    pub fn ask_state(&self, gid: &[u8], peer: &[u8]) -> Result<()> {
        let peer = endpoint_id(peer).context("an iroh key")?;
        self.inner.net().frame(peer, Frame::State { group: Bytes(gid.to_vec()), link: None });
        Ok(())
    }

    /// Tells this session's user something about a group, as a warning.
    pub fn warn(&self, gid: &[u8], text: String) {
        self.inner.warn(Some(gid), text);
    }

    /// The device's name, where this is a device's node.
    pub fn device_name(&self) -> Option<String> {
        self.inner.state.lock().unwrap().device.clone()
    }

    /// Renames the device, in its credential in each devices group whose members' leaves take a rename; the others
    /// take it once they do, at this node's next key update.
    pub async fn rename_device(&self, name: &str) -> Result<()> {
        self.inner.state.lock().unwrap().device = Some(name.into());
        for gid in self.groups() {
            self.inner.commit(&gid.0, |g| Ok(renaming(g, Some(name)).map(|name| Change { name: Some(name), ..Change::default() }))).await?;
        }
        Ok(())
    }

    /// What a group this session is in looks like as an opening.
    pub fn opening(&self, gid: &[u8]) -> Result<Opening> {
        let st = self.inner.state.lock().unwrap();
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

    /// Removes again, as it starts and then at each resync, the members this session ended a kind's log to remove.
    async fn finish_removals(self: Arc<Self>) {
        loop {
            let removing: Vec<(Vec<u8>, Vec<u8>)> = {
                let st = self.state.lock().unwrap();
                st.groups.iter().flat_map(|(gid, g)| g.rec.removing.iter().map(|key| (gid.clone(), key.0.clone()))).collect()
            };
            for (group, key) in removing {
                self.work.send(Work::Remove { group, key }).ok();
            }
            sleep(RESYNC).await;
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
                    let st = self.state.lock().unwrap();
                    (st.session.leaf.clone(), st.device.clone())
                };
                let change = |g: &Group| Ok(Some(Change { leaf: Some(leaf.clone()), name: renaming(g, device.as_deref()), ..Change::default() }));
                let updated = async {
                    self.read(gid).await.context("catching up")?;
                    self.commit(gid, change).await.context("key update")
                };
                // Unless the group was left meanwhile, as when a device leaves its identity as it starts.
                if let Err(error) = updated.await
                    && self.state.lock().unwrap().groups.contains_key(gid)
                {
                    self.warn(Some(gid), format!("{error:#}"));
                }
            }
            sleep(KEY_UPDATE).await;
            let mut st = self.state.lock().unwrap();
            let st = &mut *st;
            gids = st.groups.keys().cloned().collect();
            for gid in &gids {
                st.groups.get_mut(gid).unwrap().mls.expire(&st.provider).ok();
            }
            self.expire(st);
            if let Err(error) = st.provider.scrub() {
                self.warn(None, format!("{error:#}"));
            }
        }
    }

    /// Drops held messages and file links older than each group's `keep`; the files go at the next collection.
    fn expire(&self, st: &mut State<P>) {
        let now = now();
        let gids: Vec<Vec<u8>> = st.groups.keys().cloned().collect();
        for gid in gids {
            let g = st.groups.get_mut(&gid).unwrap();
            let before = now.saturating_sub(g.mls.settings().keep as u64 * 24 * 3600 * 1000);
            let (old, kept): (Vec<Item>, Vec<Item>) = g.rec.items.drain(..).partition(|item| item.at < before);
            g.rec.items = kept;
            g.rec.expired = old.iter().map(|item| item.epoch).fold(g.rec.expired, u64::max);
            g.rec.files.retain(|(_, at)| *at >= before);
            g.rec.invites.retain(|rule| rule.expires >= before);
            for item in old {
                st.provider.delete(&message_key(&item.id.0)).ok();
                st.provider.delete(&ciphertext_key(&item.id.0)).ok();
            }
            st.save(&gid).ok();
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
            let st = self.state.lock().unwrap();
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

    /// Applies the stored entries this session has not applied yet, then the messages that waited for them.
    fn advance(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        let mut changed = false;
        let logged = st.log(gid)?.logged;
        loop {
            let g = st.groups.get_mut(gid).unwrap();
            if g.rec.position >= logged {
                break;
            }
            let position = g.rec.position + 1;
            let entry = st.provider.get(&logs::entry_key(gid, position))?.context("a stored entry is missing")?;
            let applied = g.mls.apply(&st.provider, &entry, now())?;
            g.rec.position = position;
            let core::Applied::Commit { by, own, added, how, invite, end, removed, settings, gone, .. } = applied else {
                continue;
            };
            changed = true;
            if own {
                g.own_at = Some(position);
            }
            let by = g.mls.members().into_iter().find(|m| m.index == by);
            let end = end.filter(|_| !removed.is_empty());
            g.rec.removing.retain(|key| !removed.iter().any(|m| m.key == key.0));
            self.work.send(Work::Applied { group: gid.to_vec(), by, added, how, invite, removed, settings, gone }).ok();
            if gone {
                break;
            }
            if let Some(end) = end {
                self.moved(st, gid, end)?;
            }
        }
        st.save(gid)?;
        if changed {
            // Applying a commit deletes the secrets of epochs beyond the key window.
            if let Err(error) = st.provider.scrub() {
                self.warn(Some(gid), format!("{error:#}"));
            }
            let g = st.groups.get_mut(gid).unwrap();
            let epoch = g.mls.epoch();
            let (ready, later): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
                std::mem::take(&mut g.future).into_iter().partition(|c| core::epoch_of(c).is_ok_and(|e| e <= epoch));
            g.future = later;
            for ciphertext in ready {
                self.take(st, gid, &ciphertext);
            }
        }
        Ok(())
    }

    /// Commits a change built on the group's current epoch, posts it, and reads the log until it is known whether it
    /// won its epoch; if another commit won, builds it again. Returns the Welcome, if it adds, and the position; none
    /// once the change has no effect (`None`), and it commits nothing. A removal in a group with a kind's log first ends
    /// that log, and names where.
    async fn commit(&self, gid: &[u8], change: impl Fn(&Group) -> Result<Option<Change>>) -> Result<Option<(Option<Vec<u8>>, u64)>> {
        let _committing = self.committing.lock().await;
        let mut ended: Option<LogRef> = None;
        for _ in 0..COMMIT_TRIES {
            self.read(gid).await?;
            let (ending, service) = {
                let st = self.state.lock().unwrap();
                let g = st.group(gid)?;
                let removes = g.mls.posted().is_none() && change(&g.mls)?.is_some_and(|change| !change.remove.is_empty());
                (g.rec.kind_logs.last().filter(|_| removes).cloned(), g.mls.settings().membership)
            };
            let client = self.clients.client(&service)?;
            if let Some(log) = ending.filter(|log| ended.as_ref().is_none_or(|ended| ended.id != log.id)) {
                let position = client.append(&log.id.0, kindlog::END).await?.position;
                ended = Some(LogRef { id: log.id, after: log.after + position - 1 });
                let mut st = self.state.lock().unwrap();
                let g = st.group_mut(gid)?;
                let remove = change(&g.mls)?.map(|change| change.remove).unwrap_or_default();
                for member in g.mls.members().into_iter().filter(|m| remove.contains(&m.index)) {
                    if !g.rec.removing.iter().any(|key| key.0 == member.key) {
                        g.rec.removing.push(Bytes(member.key));
                    }
                }
                st.save(gid)?;
            }
            let (bytes, welcome, ours) = {
                let mut st = self.state.lock().unwrap();
                let st = &mut *st;
                let g = st.groups.get_mut(gid).context("this session is not in that group")?;
                g.own_at = None;
                // A commit posted before, which the log may or may not have taken: post it again.
                match g.mls.posted() {
                    Some(posted) => (posted.to_vec(), None, false),
                    None => {
                        let Some(mut change) = change(&g.mls)? else { return Ok(None) };
                        if !change.remove.is_empty() {
                            change.end = ended.as_ref().filter(|ended| g.rec.kind_logs.last().is_some_and(|log| log.id == ended.id)).map(|ended| ended.after);
                            // The kind's order moved to another log since this session ended its own: it ends that one.
                            if change.end.is_none() && !g.rec.kind_logs.is_empty() {
                                continue;
                            }
                        }
                        let session = st.device_keys.get(gid).map_or(&st.session, |(_, session)| session);
                        let commit = g.mls.commit(&st.provider, session, change)?;
                        (commit.commit, commit.welcome, true)
                    }
                }
            };
            let position = match client.append(gid, &bytes).await {
                Ok(appended) => appended.position,
                Err(error) if error.is::<Refused>() => {
                    let mut st = self.state.lock().unwrap();
                    let st = &mut *st;
                    st.groups.get_mut(gid).context("left the group")?.mls.cancel(&st.provider)?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
            self.read(gid).await?;
            let st = self.state.lock().unwrap();
            let g = st.group(gid)?;
            ensure!(g.rec.position >= position, "the log did not show the commit it took");
            if ours && g.own_at == Some(position) {
                return Ok(Some((welcome, position)));
            }
        }
        bail!("the group kept changing over {COMMIT_TRIES} tries; try again")
    }

    /// Joins a group from the Welcome a member at `by` sent: a devices group with the device key `device_key`.
    async fn welcomed(self: &Arc<Self>, admitted: Admitted, by: EndpointId, device_key: Option<[u8; 32]>) -> Result<Bytes> {
        let gid = {
            let mut st = self.state.lock().unwrap();
            let st = &mut *st;
            let mls = Group::join(&st.provider, &admitted.welcome.0, self.window)?;
            ensure!(!st.groups.contains_key(mls.id()), "this session is in that group already");
            let given_up = admitted.before.iter().map(|id| (0, id.clone())).collect();
            let rec = Rec { position: admitted.position, given_up, kind_logs: admitted.logs, ..Rec::default() };
            let gid = st.add_group(mls, rec)?;
            if let Some(seed) = device_key {
                put(&st.provider, &device_key_key(&gid), &Bytes(seed.to_vec()))?;
                let session = st.keyed(seed)?;
                st.device_keys.insert(gid.clone(), (seed, session));
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
        self.net().changed(&gid);
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
                    let mut st = inner.state.lock().unwrap();
                    let rec = &mut st.group_mut(&gid)?.rec;
                    rec.link(link.clone());
                    rec.state = Some(link);
                    st.save(&gid)?;
                }
                inner.fetched(&gid, &file).await?;
                let mut data = Vec::new();
                inner.net().read_file(&file, &mut data).await?;
                let from = inner.state.lock().unwrap().by_iroh(&gid, &by);
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
        let mut st = self.state.lock().unwrap();
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
            sleep(RECEIPT_WAIT).await;
        }
        Err(last)
    }

    /// Sends a sealed message and waits for the receipts of the members it went to.
    async fn deliver(
        &self,
        gid: &[u8],
        id: [u8; 32],
        ciphertext: Vec<u8>,
        mut receipts: mpsc::UnboundedReceiver<(EndpointId, Option<Reason>)>,
    ) -> Delivery {
        let mut waiting = self.net().send(gid, ciphertext);
        let mut answers = Vec::new();
        let _ = timeout(RECEIPT_WAIT, async {
            while !waiting.is_empty()
                && let Some((peer, refused)) = receipts.recv().await
            {
                waiting.retain(|waited| *waited != peer);
                answers.push((peer, refused));
            }
        })
        .await;
        let mut st = self.state.lock().unwrap();
        st.waiters.remove(&id);
        let mut delivery = Delivery::default();
        for (peer, refused) in answers {
            let member = st.by_iroh(gid, &peer);
            match refused {
                None => delivery.held.push(member),
                Some(reason) => delivery.refused.push((member, reason)),
            }
        }
        if !delivery.held.is_empty()
            && let Ok(g) = st.group_mut(gid)
        {
            g.rec.pending.retain(|pending| pending.id.0 != id);
            st.save(gid).ok();
        }
        delivery
    }

    /// Reads the key logs of the identities in this session's groups that it holds none of, and once more for each
    /// device a member's certificate names that its identity does not list; then has the members removed whose devices
    /// their identities dropped.
    async fn refresh_all(&self) {
        let unread: Vec<IdentityRef> = {
            let mut st = self.state.lock().unwrap();
            let st = &mut *st;
            let mut unread = Vec::new();
            for credential in st.groups.values().flat_map(|g| g.mls.members()).filter_map(|m| m.credential) {
                let Some(certificate) = &credential.certificate else { continue };
                let identity = &certificate.identity;
                let read = match st.keys.get(&identity.id.0) {
                    None => true,
                    Some(log) => log.verify(&credential) == Verdict::Unverified && st.unlisted.insert((identity.id.0.clone(), certificate.device.0.clone())),
                };
                if read && !unread.contains(identity) {
                    unread.push(identity.clone());
                }
            }
            unread
        };
        for identity in unread {
            if let Err(error) = timeout(RECEIPT_WAIT, self.read_keys(&identity)).await.map_err(anyhow::Error::from).and_then(|r| r) {
                tracing::debug!("the key log of {}: {error:#}", hex(&identity.id.0));
            }
        }
        self.revoke(&self.state.lock().unwrap());
    }

    /// Has the members removed whose devices their identities' key logs dropped: an earlier entry listed it, the current
    /// one does not.
    fn revoke(&self, st: &State<P>) {
        for (gid, g) in &st.groups {
            if g.mls.members().iter().any(|m| m.key != st.me(gid) && m.credential.as_ref().is_some_and(|c| dropped(&st.keys, c))) {
                self.work.send(Work::Revoke(gid.clone())).ok();
            }
        }
    }

    /// Removes, in one commit, every member whose device its identity's key log dropped, as the log stands for the
    /// epoch it builds on; if this session's commit removed them, tells which members they added or let in.
    async fn revoke_dropped(&self, gid: &[u8]) -> Result<()> {
        let removing = Mutex::new(Vec::new());
        let (keys, me) = {
            let st = self.state.lock().unwrap();
            (st.keys.clone(), st.me(gid).to_vec())
        };
        let committed = self
            .commit(gid, |g| {
                let dropped: Vec<core::Member> =
                    g.members().into_iter().filter(|m| m.key != me && m.credential.as_ref().is_some_and(|c| dropped(&keys, c))).collect();
                let change = (!dropped.is_empty()).then(|| Change { remove: dropped.iter().map(|m| m.index).collect(), ..Change::default() });
                *removing.lock().unwrap() = dropped;
                Ok(change)
            })
            .await?;
        if committed.is_none() {
            return Ok(());
        }
        let removed = removing.into_inner().unwrap();
        let st = self.state.lock().unwrap();
        let g = st.group(gid)?;
        let by_them = |key: &[u8]| removed.iter().any(|m| m.key == key);
        let invites: Vec<&Bytes> = g.rec.invites.iter().filter(|rule| by_them(&rule.by.0)).map(|rule| &rule.hash).collect();
        let let_in = |m: &core::Member| {
            let added = g.mls.added().iter().rev().find(|added| added.member.key.0 == m.key);
            added.is_some_and(|added| by_them(&added.by.key.0) || added.invite.as_ref().is_some_and(|invite| invites.contains(&invite)))
        };
        let added = g.mls.members().into_iter().filter(let_in).filter_map(|m| st.member(gid, &m)).collect();
        let removed = removed.iter().filter_map(|m| st.member(gid, m)).collect();
        self.events.send(Event::Revoked { group: Bytes(gid.to_vec()), removed, added }).ok();
        Ok(())
    }

    /// Reads an identity's key log from its service; a log not held yet is followed from then on.
    async fn read_keys(&self, identity: &IdentityRef) -> Result<KeyLog> {
        let address = lmk_proto::identity::address(&identity.id.0);
        {
            let mut st = self.state.lock().unwrap();
            if !st.logs.contains_key(&address[..]) {
                let of = logs::Of::Identity(identity.id.clone());
                st.add_log(&address, logs::Log::new(of, identity.membership.clone(), 0))?;
                self.work.send(Work::Follow(address.to_vec())).ok();
            }
        }
        self.read(&address).await?;
        self.state.lock().unwrap().keys.get(&identity.id.0).cloned().context("the key log has no valid first entry")
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
        for (gid, peer) in st.served(&peers).into_iter().filter(|served| !before.contains(served)) {
            self.net().served(peer, &gid);
        }
        self.revoke(st);
        self.events.send(Event::Keys { identity: Bytes(id.to_vec()) }).ok();
        Ok(())
    }

    /// Leaves a group behind: its state and records go.
    fn forget(&self, gid: &[u8]) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let st = &mut *st;
        let g = st.groups.remove(gid).context("this session is not in that group")?;
        for log in [Bytes(gid.to_vec())].into_iter().chain(g.rec.kind_logs.iter().map(|log| log.id.clone())) {
            self.unfollow(&log.0);
            st.drop_log(&log.0)?;
        }
        for position in g.rec.log.iter().flat_map(|log| &log.kept) {
            st.provider.delete(&kindlog::kept_key(gid, *position))?;
        }
        for item in &g.rec.items {
            st.provider.delete(&message_key(&item.id.0))?;
            st.provider.delete(&ciphertext_key(&item.id.0))?;
        }
        st.provider.delete(&rec_key(gid))?;
        st.provider.delete(&device_key_key(gid))?;
        st.device_keys.remove(gid);
        g.mls.delete(&st.provider)?;
        st.save_groups()?;
        st.provider.scrub()?;
        if let Some(net) = self.net.get() {
            net.changed(gid);
        }
        Ok(())
    }

    /// Handles what the group logic and the peers hand on, one at a time.
    async fn drive(self: Arc<Self>, mut work: mpsc::UnboundedReceiver<Work>) {
        while let Some(item) = work.recv().await {
            match item {
                Work::Applied { group, by, added, how, invite, removed, settings, gone } => {
                    self.applied(&group, by, added, how, invite, removed, settings, gone).await
                }
                Work::Follow(log) => self.follow(&log),
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
                Work::Revoke(group) => {
                    if self.revoking.lock().unwrap().insert(group.clone()) {
                        let inner = self.clone();
                        self.spawn(async move {
                            if let Err(error) = inner.revoke_dropped(&group).await
                                && inner.state.lock().unwrap().groups.contains_key(&group)
                            {
                                inner.warn(Some(&group), format!("removing the members of a device taken off its identity: {error:#}"));
                            }
                            inner.revoking.lock().unwrap().remove(&group);
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
                Work::Report(gid) => {
                    let inner = self.clone();
                    self.spawn(async move {
                        sleep(REPORT_WAIT).await;
                        inner.report(&gid);
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
        }
        let group = Bytes(gid.to_vec());
        let st = self.state.lock().unwrap();
        let by = by.and_then(|by| st.member(gid, &by));
        if gone {
            drop(st);
            self.gone(gid, by);
            return;
        }
        let Some(by) = by else { return };
        let how = how.unwrap_or(How::Invite);
        let me = st.me(gid).to_vec();
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
        if !self.state.lock().unwrap().groups.contains_key(gid) {
            return;
        }
        self.events.send(Event::Removed { group: Bytes(gid.to_vec()), by }).ok();
        if let Err(error) = self.forget(gid) {
            self.warn(Some(gid), format!("{error:#}"));
        }
    }

    /// Has the members removed whose `leave` this session holds, sealed since the Add that brought them in last; has the
    /// group gone once this session holds its own and is the only member left.
    fn leavers(&self, st: &State<P>, gid: &[u8]) -> Result<()> {
        let Ok(g) = st.group(gid) else { return Ok(()) };
        let added = |key: &[u8]| g.mls.added().iter().rev().find(|added| added.member.key.0 == key).map_or(0, |added| added.epoch);
        let mut leaving = HashSet::new();
        for item in &g.rec.items {
            let message: Message = get(&st.provider, &message_key(&item.id.0))?.context("a held message is missing")?;
            if type_of(&message.payload) == "leave" && message.epoch >= added(&message.sender.key.0) {
                leaving.insert(message.sender.key.0);
            }
        }
        let me = st.me(gid);
        let members = g.mls.members();
        if members.len() == 1 && leaving.contains(me) {
            self.work.send(Work::Gone(gid.to_vec())).ok();
        }
        for member in members.into_iter().filter(|m| m.key != me && leaving.contains(&m.key)) {
            self.work.send(Work::Remove { group: gid.to_vec(), key: member.key }).ok();
        }
        Ok(())
    }

    /// Tells the group, in one held notice, the messages this session gave up since it last did.
    fn report(self: &Arc<Self>, gid: &[u8]) {
        let messages = {
            let mut st = self.state.lock().unwrap();
            let Ok(g) = st.group_mut(gid) else { return };
            let messages = std::mem::take(&mut g.rec.unreported);
            if messages.is_empty() {
                return;
            }
            if let Err(error) = st.save(gid) {
                self.warn(Some(gid), format!("{error:#}"));
            }
            messages
        };
        let (node, gid) = (Node { inner: self.clone() }, gid.to_vec());
        self.spawn(async move {
            let payload = serde_json::to_value(Control::Refused { messages }).expect("JSON");
            if let Err(error) = node.send(&gid, &payload, true).await {
                node.inner.warn(Some(&gid), format!("reporting the messages this session refused: {error:#}"));
            }
        });
    }

    fn net_event(self: &Arc<Self>, event: lmk_net::Event) {
        match event {
            lmk_net::Event::Receipt { group, peer, held } => {
                let mut st = self.state.lock().unwrap();
                let mut changed = false;
                for id in held {
                    if let Some(waiter) = st.waiters.get(&id) {
                        waiter.send((peer, None)).ok();
                        continue;
                    }
                    let Ok(g) = st.group_mut(&group) else { return };
                    if !g.rec.pending.iter().any(|pending| pending.id.0 == id) {
                        continue;
                    }
                    let by = st.by_iroh(&group, &peer);
                    let (group, id) = (Bytes(group.clone()), Bytes(id.to_vec()));
                    st.group_mut(&group.0).unwrap().rec.pending.retain(|pending| pending.id != id);
                    changed = true;
                    self.events.send(Event::Held { group, id, by }).ok();
                }
                if changed {
                    st.save(&group).ok();
                }
            }
            lmk_net::Event::Contradiction { log, peer, ours, theirs } => {
                let st = self.state.lock().unwrap();
                self.contradicted(&st, &log, &Contradiction { ours, theirs }, &peer.fmt_short().to_string());
            }
            lmk_net::Event::Fetched(hash) => {
                let mut st = self.state.lock().unwrap();
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
                let mut st = self.state.lock().unwrap();
                if let Err(error) = self.leavers(&st, &group) {
                    self.warn(Some(&group), format!("{error:#}"));
                }
                // A message the kind's log names that this sync did not bring will not come from this peer.
                if self.waits(&st, &group) {
                    self.ask_state(&mut st, &group, Some(peer));
                }
                drop(st);
                self.report(&group);
                // A file only this session held may have reached the peer since.
                let pending: Vec<[u8; 32]> = {
                    let st = self.state.lock().unwrap();
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
                            let mut st = inner.state.lock().unwrap();
                            if let Ok(g) = st.group_mut(&group) {
                                g.rec.pending.retain(|pending| pending.id.0 != hash);
                                st.save(&group).ok();
                            }
                        }
                    });
                }
            }
            lmk_net::Event::InStep { group, peer } => {
                let mut st = self.state.lock().unwrap();
                if st.group(&group).is_ok_and(|g| g.rec.log.as_ref().is_some_and(|log| log.behind)) {
                    self.ask_state(&mut st, &group, Some(peer));
                }
                let member = st.by_iroh(&group, &peer);
                self.events.send(Event::InStep { group: Bytes(group), member }).ok();
            }
            lmk_net::Event::Connected(_) | lmk_net::Event::Disconnected(_) => {}
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
            Some(logs::Of::Kind(_)) => "the log of the group's kind",
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

/// The name this session takes in a group: in a devices group, the device's, where its credential names another and
/// every member's leaf takes a rename.
fn renaming(g: &Group, device: Option<&str>) -> Option<String> {
    let own = g.members().into_iter().find(|m| m.index == g.own_index())?.credential?;
    let device = device.filter(|device| g.settings().kind == DEVICES && own.name != *device && g.revised(RENAME_REVISION))?;
    Some(device.to_owned())
}

/// Whether a member's device was dropped from its identity's list, as the key logs held show it.
fn dropped(keys: &BTreeMap<Vec<u8>, KeyLog>, credential: &Credential) -> bool {
    let log = credential.identity().and_then(|identity| keys.get(&identity.id.0));
    log.is_some_and(|log| log.verify(credential) == Verdict::Dropped)
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
    fn a_group_holds_files_linked_within_keep_its_state_and_its_kinds_links() {
        let link = |n: u8| FileLink { hash: [n; 32], size: 1, key: [0; 32] }.link();
        let old = now() - 3 * 24 * 3600 * 1000;
        let files = vec![(link(1), old), (link(2), now()), (link(3), old)];
        let rec = Rec { files, state: Some(link(3)), links: vec![link(4)], ..Rec::default() };
        let held: Vec<u8> = rec.held(2).iter().map(|file| file.hash[0]).collect();
        assert_eq!(held, [2, 3, 4]);
    }
}
