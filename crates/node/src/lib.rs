//! One member's session over lmk-core, lmk-net and lmk-membership: its groups and their logs, its held messages and
//! files, the invites it shares and the joiners it admits, and its members' identities: their key logs and certificates. A group's kind sees its
//! content through the channels here (held and live messages, files, its log, and a state link for
//! joiners), and nothing of the rest; the core reads only its own payloads (`Control`). The devices kind (`devices`) is
//! built on those channels. It stores everything through the core's `Provider`, so the same code runs natively (SQLite)
//! and in the browser (memory the web client persists).

pub mod devices;
mod groups;
mod kindlog;
mod logs;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result, bail, ensure};
use iroh::tls::CaTlsConfig;
use iroh::{EndpointId, RelayMap, RelayUrl, SecretKey};
use lmk_core::device::Device;
use lmk_core::group::{self as core, Change, Group, Session, Window};
use lmk_core::identity::{KeyLog, certified, check};
use lmk_membership::Contradiction;
use lmk_core::provider::Provider;
use lmk_membership::Refused;
use lmk_net::Net;
use lmk_proto::group::{CHAT, Control, Credential, DEVICES, How, IdentityRef, Leaf, Opening, REVISION, Reason, Refusal, Settings, held_by_type};
use lmk_proto::identity::Envelope;
use lmk_proto::links::{Address, FileLink, Invite, RELAY};
use lmk_proto::peer::{Admitted, Frame, Join, KindLog as LogRef};
use lmk_proto::{Answer, Bytes};
use n0_future::task::{JoinHandle, spawn};
use n0_future::time::{Duration, SystemTime, sleep, timeout};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

pub use lmk_core;
pub use lmk_net::Disk;

/// How often a session replaces its keys in each group.
const KEY_UPDATE: Duration = Duration::from_secs(24 * 60 * 60);
/// The largest message taken.
const MAX_MESSAGE: usize = 1 << 20;
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
/// How long a copy of a key log counts as fresh, in milliseconds.
const KEYS_FRESH: u64 = 10 * 60 * 1000;
/// How long a member connected to this session may go without a valid certificate of the identity it speaks as before
/// it is removed, in milliseconds.
const CERTIFICATE_GRACE: u64 = 60 * 1000;
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
    pub window: Window,
    /// The kinds this session supports, `chat` among them.
    pub kinds: Vec<String>,
}

/// A group member, from its leaf and credential, and its certificate checked against its identity's key log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The session key: the MLS signature key.
    pub key: Bytes,
    /// The iroh key its leaf names.
    pub iroh: Bytes,
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
    /// This session was removed; the group is gone from it.
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
            | Event::Held { group, .. }
            | Event::Refused { group, .. } => Some(group),
            Event::Message(message) => Some(&message.group),
            Event::Warning { group, .. } => group.as_ref(),
            Event::File(_) => None,
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
    groups: HashMap<Vec<u8>, G>,
    /// The logs this session follows, by id.
    logs: HashMap<Vec<u8>, logs::Log>,
    /// Key logs, by identity id.
    keys: HashMap<Vec<u8>, KeyLog>,
    /// Members' certificates, this session's own among them, by session key and identity id.
    certificates: HashMap<(Vec<u8>, Vec<u8>), Envelope>,
    /// Members' certificates that lost to a valid one while not valid themselves, as one by a key this session has
    /// not read yet is: taken again when their identity's key log grows.
    ahead: HashMap<(Vec<u8>, Vec<u8>), Envelope>,
    /// Members connected to this session without a valid certificate, by session key: since when.
    uncertified: HashMap<Vec<u8>, u64>,
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
    tasks: Mutex<Vec<JoinHandle<()>>>,
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

pub fn now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64
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

fn endpoint_id(key: &[u8]) -> Option<EndpointId> {
    EndpointId::from_bytes(key.try_into().ok()?).ok()
}

impl<P: Provider> State<P> {
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
            let added = g.mls.added().iter().rev().find(|added| added.member == credential)?;
            let by = g.mls.members().into_iter().find(|m| m.credential.as_ref() == Some(&added.by));
            Some((Bytes(by.map(|by| by.key).unwrap_or_default()), added.how.clone().unwrap_or(How::Invite)))
        });
        let claim = credential.identity.as_ref().map(|identity| self.claim(&credential, identity));
        let device_name = claim.as_ref().and_then(|(_, device)| device.clone()).unwrap_or_default();
        Some(Member {
            key: Bytes(member.key.clone()),
            iroh: member.leaf.as_ref().map(|leaf| leaf.key.clone()).unwrap_or_default(),
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
        self.groups.insert(gid.clone(), G { mls, rec, future: Vec::new(), own_at: None, asked: 0 });
        self.save(&gid)?;
        self.save_groups()?;
        Ok(gid)
    }
}

impl<P: Provider + Send + 'static> Node<P> {
    /// Opens the session in `provider`, creating it on first use, and starts its peers.
    pub async fn start(provider: P, config: Config) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
        let secret = match provider.get(b"node/iroh")? {
            Some(bytes) => SecretKey::from_bytes(&bytes.as_slice().try_into().context("an iroh key is 32 bytes")?),
            None => {
                let key = SecretKey::from_bytes(&lmk_core::random());
                provider.put(b"node/iroh", &key.to_bytes())?;
                key
            }
        };
        let relays = RelayMap::from(iroh::RelayConfig::new(config.relay.clone(), Some(Default::default())));
        let endpoint = lmk_net::builder(relays).secret_key(secret).ca_tls_config(config.ca).bind().await?;
        let leaf = Leaf { key: Bytes(endpoint.id().as_bytes().to_vec()), relay: config.relay.to_string(), kinds: config.kinds.clone(), revision: REVISION };
        let mut session = match (provider.get(b"session")?, &config.device) {
            (Some(_), _) => Session::load(&provider)?,
            (None, Some(device)) => Session::create_with(&provider, device.signer(), &config.name, leaf.clone())?,
            (None, None) => Session::create(&provider, &config.name, leaf.clone())?,
        };
        if session.leaf != leaf {
            session.set_leaf(&provider, leaf)?;
        }
        let clients = logs::Clients::new(endpoint.clone());
        let logs = State::load_logs(&provider)?;
        for log in logs.values() {
            if let Some(chain) = &log.chain {
                clients.client(&log.service)?.set_chain(chain.clone());
            }
        }
        let mut groups = HashMap::new();
        for gid in get::<Vec<Bytes>>(&provider, b"node/groups")?.unwrap_or_default() {
            let mls = Group::load(&provider, &gid.0)?;
            let rec: Rec = get(&provider, &rec_key(&gid.0))?.context("a group without its record")?;
            groups.insert(gid.0, G { mls, rec, future: Vec::new(), own_at: None, asked: 0 });
        }
        let (events, events_rx) = mpsc::unbounded_channel();
        let (work, work_rx) = mpsc::unbounded_channel();
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
            session,
            groups,
            logs,
            keys: HashMap::new(),
            certificates,
            ahead: HashMap::new(),
            uncertified: HashMap::new(),
            waiters: HashMap::new(),
        };
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
            tasks: Mutex::default(),
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
            Net::spawn(endpoint, net_config, inner.clone(), Arc::new(groups::Admitter(inner.clone()))).await?;
        inner.net.set(net).ok();
        inner.spawn(async move {
            while let Some(event) = net_events.recv().await {
                work.send(Work::Net(event)).ok();
            }
        });
        inner.spawn(inner.clone().drive(work_rx));
        let (gids, followed): (Vec<Vec<u8>>, Vec<Vec<u8>>) = {
            let st = inner.state.lock().unwrap();
            let followed = st.logs.iter().filter(|(_, log)| !matches!(log.of, logs::Of::Identity(_))).map(|(id, _)| id.clone());
            (st.groups.keys().cloned().collect(), followed.collect())
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
        inner.spawn(inner.clone().resume(gids));
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

    /// A new group with this session its only member, speaking as `identity`. A group of any kind but chat gets a log
    /// of its own.
    pub fn create(&self, settings: Settings, identity: Option<IdentityRef>) -> Result<Bytes> {
        ensure!(self.inner.kinds.contains(&settings.kind), "this session does not support {} groups", settings.kind);
        let gid = {
            let mut st = self.inner.state.lock().unwrap();
            let st = &mut *st;
            st.session.credential.identity = identity;
            let mls = Group::create(&st.provider, &st.session, &settings, self.inner.window)?;
            let id = Bytes(mls.exported(&st.provider, kindlog::LOG_LABEL)?.to_vec());
            let kind_logs = if settings.kind == CHAT { Vec::new() } else { vec![LogRef { id, after: 0 }] };
            st.add_group(mls, Rec { kind_logs, ..Rec::default() })?
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
            let by = Bytes(st.session.key().to_vec());
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

    /// Joins through an invite link, speaking as `identity`: asks the members it names in turn. Returns the group, and
    /// the iroh key of the member that admitted this session.
    pub async fn join(&self, link: &Invite, identity: Option<IdentityRef>) -> Result<(Bytes, [u8; 32])> {
        let ours: RelayUrl = RELAY.parse()?;
        let members = link
            .members
            .iter()
            .map(|member| Ok((EndpointId::from_bytes(&member.key)?, member.relay.as_ref().map_or(Ok(ours.clone()), |relay| relay.parse())?)))
            .collect::<Result<Vec<_>>>()?;
        self.ask(members, Some(Bytes(link.secret.to_vec())), None, identity).await
    }

    /// Asks the members of an open group to admit this session in turn, speaking as `identity`, with its certificate.
    pub async fn join_open(&self, opening: &Opening, identity: IdentityRef) -> Result<Bytes> {
        ensure!(self.inner.kinds.contains(&opening.kind), "this session does not support {} groups", opening.kind);
        self.certificate(&identity.id.0).context("this session has no certificate of that identity yet")?;
        let members = opening.members.iter().filter_map(|key| endpoint_id(&key.0)).map(|peer| (peer, self.inner.relay.clone())).collect();
        Ok(self.ask(members, None, Some(opening.group.clone()), Some(identity)).await?.0)
    }

    /// Asks members in turn to admit this session, by an invite's secret or a group open to `identity`.
    async fn ask(
        &self,
        members: Vec<(EndpointId, RelayUrl)>,
        secret: Option<Bytes>,
        group: Option<Bytes>,
        identity: Option<IdentityRef>,
    ) -> Result<(Bytes, [u8; 32])> {
        let join = {
            let mut st = self.inner.state.lock().unwrap();
            let certificate = identity.as_ref().and_then(|identity| st.certificate(&st.session.credential, &identity.id.0).cloned());
            st.session.credential.identity = identity;
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

    pub async fn remove(&self, gid: &[u8], key: &[u8]) -> Result<()> {
        self.inner
            .commit(gid, |g| {
                let member = g.members().into_iter().find(|m| m.key == key).context("not a member")?;
                Ok(Change { remove: vec![member.index], ..Change::default() })
            })
            .await
            .map(drop)
    }

    /// Changes the group's settings, from the current ones.
    pub async fn change_settings(&self, gid: &[u8], change: impl Fn(Settings) -> Settings) -> Result<Settings> {
        self.inner.commit(gid, |g| Ok(Change { settings: Some(change(g.settings())), ..Change::default() })).await?;
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
    /// one held by its type) members hold for the group's `keep`, and sync.
    pub async fn send(&self, gid: &[u8], payload: &Value, held: bool) -> Result<(Bytes, Delivery)> {
        let held = held || held_by_type(payload);
        let (id, ciphertext, receipts) = {
            let mut st = self.inner.state.lock().unwrap();
            let st = &mut *st;
            let g = st.groups.get_mut(gid).context("this session is not in that group")?;
            let (id, ciphertext) = g.mls.seal(&st.provider, &st.session, payload, held)?;
            if held {
                let epoch = g.mls.epoch();
                let me = g.mls.members().into_iter().find(|m| m.key == st.session.key());
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
            (g.mls.seal(&st.provider, &st.session, payload, false)?.1, peer)
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

    // Identities: their key logs, and certificates.

    /// The newest copy of an identity's key log, read from its service unless a copy is fresh.
    pub async fn key_log(&self, identity: &IdentityRef) -> Result<KeyLog> {
        let fresh = {
            let st = self.inner.state.lock().unwrap();
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
        self.inner.state.lock().unwrap().keys.get(identity).cloned()
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
        let st = self.inner.state.lock().unwrap();
        st.certificate(&st.session.credential, identity).cloned()
    }

    /// Holds a certificate of this session, which it shows its peers, and reads the identity's key log, so that, if a
    /// new key is why, its peers take the new entries from this session.
    pub fn set_certificate(&self, certificate: Envelope) -> Result<()> {
        let certified = certified(&certificate).context("a certificate that does not parse")?;
        let mut st = self.inner.state.lock().unwrap();
        ensure!(certified.key.0 == st.session.key(), "a certificate of another session");
        let address = lmk_proto::identity::address(&certified.identity.0);
        if st.logs.contains_key(&address[..]) {
            self.inner.work.send(Work::Read(address.to_vec())).ok();
        }
        let key = (certified.key.0, certified.identity.0);
        st.certificates.insert(key, certificate);
        st.save_certificates()?;
        for gid in st.groups.keys() {
            self.inner.net().changed(gid);
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

    /// Catches up on each group, replaces this session's keys, then again daily.
    async fn resume(self: Arc<Self>, gids: Vec<Vec<u8>>) {
        self.refresh_all().await;
        self.dial_all();
        let mut gids = gids;
        loop {
            for gid in &gids {
                if let Err(error) = self.read(gid).await {
                    self.warn(Some(gid), format!("catching up: {error:#}"));
                    continue;
                }
                let leaf = self.state.lock().unwrap().session.leaf.clone();
                if let Err(error) =
                    self.commit(gid, |_| Ok(Change { leaf: Some(leaf.clone()), ..Change::default() })).await
                {
                    self.warn(Some(gid), format!("key update: {error:#}"));
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
        let leaves: HashSet<(EndpointId, String)> = {
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
    /// won its epoch; if another commit won, builds it again. Returns the Welcome, if it adds, and the position. A removal
    /// in a group with a kind's log first ends that log, and names where.
    async fn commit(&self, gid: &[u8], change: impl Fn(&Group) -> Result<Change>) -> Result<(Option<Vec<u8>>, u64)> {
        let _committing = self.committing.lock().await;
        let mut ended: Option<LogRef> = None;
        for _ in 0..COMMIT_TRIES {
            self.read(gid).await?;
            let (ending, service) = {
                let st = self.state.lock().unwrap();
                let g = st.group(gid)?;
                let removes = g.mls.posted().is_none() && !change(&g.mls)?.remove.is_empty();
                (g.rec.kind_logs.last().filter(|_| removes).cloned(), g.mls.settings().membership)
            };
            let client = self.clients.client(&service)?;
            if let Some(log) = ending.filter(|log| ended.as_ref().is_none_or(|ended| ended.id != log.id)) {
                let position = client.append(&log.id.0, kindlog::END).await?.position;
                ended = Some(LogRef { id: log.id, after: log.after + position - 1 });
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
                        let mut change = change(&g.mls)?;
                        if !change.remove.is_empty() {
                            change.end = ended.as_ref().filter(|ended| g.rec.kind_logs.last().is_some_and(|log| log.id == ended.id)).map(|ended| ended.after);
                        }
                        let commit = g.mls.commit(&st.provider, &st.session, change)?;
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
                return Ok((welcome, position));
            }
        }
        bail!("the group kept changing; try again")
    }

    /// Joins a group from the Welcome a member at `by` sent.
    async fn welcomed(self: &Arc<Self>, admitted: Admitted, by: EndpointId) -> Result<Bytes> {
        let gid = {
            let mut st = self.state.lock().unwrap();
            let st = &mut *st;
            let mls = Group::join(&st.provider, &admitted.welcome.0, self.window)?;
            ensure!(!st.groups.contains_key(mls.id()), "this session is in that group already");
            let given_up = admitted.before.iter().map(|id| (0, id.clone())).collect();
            let rec = Rec { position: admitted.position, given_up, kind_logs: admitted.logs, ..Rec::default() };
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

    /// Reads the key logs of the identities in this session's groups that are not fresh, or that a member's
    /// certificate needs read anew, then has the members removed that went too long without a valid certificate.
    async fn refresh_all(&self) {
        let stale: Vec<IdentityRef> = {
            let st = self.state.lock().unwrap();
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
                && let Err(error) = timeout(RECEIPT_WAIT, self.read_keys(&identity)).await.map_err(anyhow::Error::from).and_then(|r| r)
            {
                tracing::debug!("the key log of {}: {error:#}", hex(&identity.id.0));
            }
        }
        self.revoke();
    }

    /// Waits a while for the certificates of added members that speak as identities, which the member that admitted them and they show.
    async fn await_certificates(&self, gid: &[u8], added: &[core::Member]) {
        let deadline = now() + RECEIPT_WAIT.as_millis() as u64;
        let missing = || {
            let st = self.state.lock().unwrap();
            let speaking = added.iter().filter_map(|m| Some((m.credential.as_ref()?, m.credential.as_ref()?.identity.as_ref()?)));
            speaking.into_iter().any(|(credential, identity)| st.certificate(credential, &identity.id.0).is_none())
        };
        while missing() && now() < deadline && self.state.lock().unwrap().groups.contains_key(gid) {
            sleep(Duration::from_millis(200)).await;
        }
    }

    /// Has the members removed whose certificates are of a device taken off their identity, and those connected to this
    /// session that have gone `CERTIFICATE_GRACE` without a valid certificate of the identity they speak as, judged by a
    /// key log read since.
    fn revoke(&self) {
        let connected = self.net().connected();
        let mut st = self.state.lock().unwrap();
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
            let mut st = self.state.lock().unwrap();
            if !st.logs.contains_key(&address[..]) {
                let of = logs::Of::Identity(identity.id.clone());
                st.add_log(&address, logs::Log::new(of, identity.membership.clone(), 0))?;
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
        st.keys.insert(id.to_vec(), log);
        let ahead: Vec<Envelope> = st.ahead.extract_if(|(_, identity), _| identity == id).map(|(_, certificate)| certificate).collect();
        for certificate in ahead {
            groups::take_certificate(st, certificate);
        }
        self.remove_revoked(st);
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
                    let inner = self.clone();
                    self.spawn(async move {
                        let still = inner
                            .state
                            .lock()
                            .unwrap()
                            .group(&group)
                            .is_ok_and(|g| g.mls.members().iter().any(|m| m.key == key));
                        if still
                            && let Err(error) = (Node { inner: inner.clone() }).remove(&group, &key).await
                            && inner
                                .state
                                .lock()
                                .unwrap()
                                .group(&group)
                                .is_ok_and(|g| g.mls.members().iter().any(|m| m.key == key))
                        {
                            inner.warn(Some(&group), format!("removing a member: {error:#}"));
                        }
                    });
                }
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
            self.await_certificates(gid, &added).await;
        }
        let group = Bytes(gid.to_vec());
        let st = self.state.lock().unwrap();
        if !added.is_empty()
            && let Err(error) = st.save_certificates()
        {
            self.warn(Some(gid), format!("{error:#}"));
        }
        let by = by.and_then(|by| st.member(gid, &by));
        if gone {
            drop(st);
            if let Err(error) = self.forget(gid) {
                self.warn(Some(gid), format!("{error:#}"));
            }
            self.events.send(Event::Removed { group, by }).ok();
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
        drop(st);
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
                // A message the kind's log names that this sync did not bring will not come from this peer.
                let mut st = self.state.lock().unwrap();
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
    /// Reports a log that its service showed differently, here and at `there`.
    pub(crate) fn contradicted(&self, st: &State<P>, log: &[u8], contradiction: &Contradiction, there: &str) {
        let what = match st.logs.get(log).map(|l| &l.of) {
            Some(logs::Of::Kind(_)) => "the log of the group's kind",
            Some(logs::Of::Identity(_)) => "a key log",
            _ => "the group's log",
        };
        let Contradiction { ours, theirs } = contradiction;
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
