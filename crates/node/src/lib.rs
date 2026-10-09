//! One member's session over lmk-core, lmk-net and lmk-membership: its groups and their logs, its messages, docs and
//! files, its invites and joins, and the identities of its device. It stores everything through the core's
//! `Provider`, so the same code runs natively (SQLite) and in the browser (memory the web client persists).

pub mod doc;
mod groups;
mod logs;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result, bail, ensure};
use iroh::tls::CaTlsConfig;
use iroh::{EndpointId, RelayMap, RelayUrl, SecretKey};
use lmk_core::contacts::{Contact, Contacts};
use lmk_core::device::Device;
use lmk_core::group::{self as core, Change, Group, Session, Window, devices_settings, with_opening};
use lmk_core::identity::{self, DeviceList, Verdict, check};
use lmk_core::invite::{Invites, Target};
use lmk_core::provider::Provider;
use lmk_membership::{Chain, Refused};
use lmk_net::Net;
use lmk_proto::group::{Credential, How, IdentityRef, Kind, Leaf, Opening, Payload, Service, Settings};
use lmk_proto::links::{FileLink, Invite, RELAY};
use lmk_proto::peer::Admitted;
use lmk_proto::{Answer, Bytes};
use n0_future::task::{JoinHandle, spawn};
use n0_future::time::{Duration, SystemTime, sleep, timeout};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub use lmk_core;

/// How often a session replaces its keys in each group.
const KEY_UPDATE: Duration = Duration::from_secs(24 * 60 * 60);
/// The largest message taken.
const MAX_MESSAGE: usize = 1 << 20;
/// How long `send` waits for the members it wrote to.
const RECEIPT_WAIT: Duration = Duration::from_secs(5);
/// How often members not connected are dialed again.
const REDIAL: Duration = Duration::from_secs(10);
/// How often connected members sync their groups again.
const RESYNC: Duration = Duration::from_secs(5 * 60);
/// How often files no group holds any longer are deleted.
const COLLECT: Duration = Duration::from_secs(60 * 60);
/// How long a fetched device list counts as fresh, in milliseconds.
const LIST_FRESH: u64 = 10 * 60 * 1000;
/// How long a fetch keeps looking for a member that holds the file.
const FETCH_TRIES: u32 = 12;
const COMMIT_TRIES: u32 = 5;

pub struct Config {
    /// The session's name, fixed when it is created.
    pub name: String,
    /// Whether the device's own key is the session's: a device's node, or a browser.
    pub device_key: bool,
    pub relay: RelayUrl,
    pub ca: CaTlsConfig,
    /// `LETMEKNOW_HOME`, where sessions of one device publish their addresses.
    pub home: Option<PathBuf>,
    /// Where files are kept; in memory if none.
    pub files: Option<PathBuf>,
    /// The largest file fetched without being asked.
    pub file_limit: u64,
    pub window: Window,
}

/// A group member, from its leaf and credential, checked against its identity's device list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The session key: the MLS signature key.
    pub key: Bytes,
    /// The iroh key its leaf names.
    pub iroh: Bytes,
    pub name: String,
    pub device: Bytes,
    pub device_name: String,
    pub identity: Option<Claim>,
    /// Who added it, by session key, and how; none for the group's creator and this session.
    pub added: Option<(Bytes, How)>,
}

/// The identity a member speaks as, checked against its device list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub identity: IdentityRef,
    /// The identity's own name, from its device list: a claim.
    pub name: String,
    /// Why the check failed, if it did.
    pub error: Option<String>,
    /// For a device another device of its identity added: that device's name.
    pub added_by_device: Option<String>,
}

/// A message held for the group: a chat message, or a request to leave.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: Bytes,
    pub group: Bytes,
    pub epoch: u64,
    /// When it reached this session, in milliseconds since the Unix epoch.
    pub at: u64,
    pub sender: Member,
    pub payload: Payload,
}

/// Who took a message as `send` waited.
#[derive(Clone, Debug, Default)]
pub struct Delivery {
    pub held: Vec<Member>,
    pub refused: Vec<(Member, String)>,
}

/// What this session sent that no other member holds yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub id: Bytes,
    /// `message` or `file`.
    pub what: String,
}

#[derive(Clone, Debug)]
pub enum Event {
    /// A member was added. `label` is the invite's `--for`, where this session admitted it.
    Joined {
        group: Bytes,
        member: Member,
        by: Member,
        how: How,
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
    Message(Message),
    /// A doc, or the contacts of a devices group, changed by an edit or a diff from `by`.
    Edited {
        group: Bytes,
        by: Member,
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
    Refused {
        group: Bytes,
        id: Bytes,
        by: Member,
        reason: String,
    },
    /// A file is held whole.
    File([u8; 32]),
    Warning {
        group: Option<Bytes>,
        text: String,
    },
}

/// A group's own record, beside its MLS state.
#[derive(Default, Serialize, Deserialize)]
struct Rec {
    /// The last log position applied.
    position: u64,
    /// The last log position stored.
    logged: u64,
    chain: Option<Chain>,
    items: Vec<Item>,
    /// Messages this session could not open, so that sync does not offer them again.
    given_up: Vec<(u64, Bytes)>,
    pending: Vec<Pending>,
    /// File links, with when they were linked: attachments, files added, and doc states linked beside Welcomes. Each is
    /// held for the group's `keep`.
    files: Vec<(String, u64)>,
    /// The doc state linked beside the latest Welcome, held however old.
    state: Option<String>,
}

impl Rec {
    fn link(&mut self, link: String) {
        self.files.push((link, now()));
    }

    /// The files this session holds for the group: those linked within `keep`, its doc state, and the doc's current
    /// links, given its text.
    fn held(&self, keep: u32, text: Option<&str>) -> Vec<FileLink> {
        let since = now().saturating_sub(keep as u64 * 24 * 3600 * 1000);
        let linked = self.files.iter().filter(|(_, at)| *at >= since).map(|(link, _)| link).chain(&self.state);
        let mut held: Vec<FileLink> = linked.filter_map(|link| FileLink::parse(link).ok()).collect();
        held.extend(text.map(doc::links).unwrap_or_default());
        held
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Item {
    epoch: u64,
    id: Bytes,
    at: u64,
}

pub(crate) struct G {
    mls: Group,
    rec: Rec,
    /// Ciphertexts from epochs this session has not reached.
    future: Vec<Vec<u8>>,
    /// The position at which this session's own commit was last applied.
    own_at: Option<u64>,
    follow: Option<JoinHandle<()>>,
}

pub(crate) struct State<P> {
    provider: P,
    session: Session,
    device: Device,
    groups: HashMap<Vec<u8>, G>,
    invites: Invites,
    /// Joiners' session keys, and the `--for` of the invites they redeemed.
    labels: HashMap<Vec<u8>, String>,
    /// Device lists, by identity id, with when they were fetched.
    lists: HashMap<Vec<u8>, (DeviceList, u64)>,
    /// `send`s waiting for receipts.
    waiters: HashMap<[u8; 32], mpsc::UnboundedSender<(EndpointId, Option<String>)>>,
    /// For each doc, the members whose edits or diffs came in since `doc_edits` last handed them out.
    editors: HashMap<Vec<u8>, Vec<Member>>,
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
    Read(Vec<u8>),
    Remove {
        group: Vec<u8>,
        key: Vec<u8>,
    },
    Fetch {
        group: Vec<u8>,
        link: FileLink,
    },
    Net(lmk_net::Event),
}

pub(crate) struct Inner<P> {
    state: Mutex<State<P>>,
    net: OnceLock<Net>,
    logs: logs::Logs,
    relay: RelayUrl,
    file_limit: u64,
    window: Window,
    events: mpsc::UnboundedSender<Event>,
    work: mpsc::UnboundedSender<Work>,
    committing: tokio::sync::Mutex<()>,
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

fn doc_key(gid: &[u8]) -> Vec<u8> {
    [b"node/doc/".as_slice(), gid].concat()
}

fn entry_key(gid: &[u8], position: u64) -> Vec<u8> {
    [b"node/entry/".as_slice(), gid, b"/", &position.to_be_bytes()].concat()
}

fn message_key(id: &[u8]) -> Vec<u8> {
    [b"node/message/".as_slice(), id].concat()
}

fn ciphertext_key(id: &[u8]) -> Vec<u8> {
    [b"node/ciphertext/".as_slice(), id].concat()
}

/// A group whose state is a Yjs doc: a doc, or a devices group's contacts.
fn doc_like(settings: &Settings) -> bool {
    settings.kind == Kind::Doc || settings.devices_of.is_some()
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

    fn doc_state(&self, gid: &[u8]) -> Result<Vec<u8>> {
        self.provider.get(&doc_key(gid))?.context("the group has no doc")
    }

    /// Stores a doc's new state, which `by` changed.
    fn edited(&mut self, gid: &[u8], state: &[u8], by: &Member) -> Result<()> {
        self.provider.put(&doc_key(gid), state)?;
        let editors = self.editors.entry(gid.to_vec()).or_default();
        if !editors.iter().any(|e| e.key == by.key && e.iroh == by.iroh) {
            editors.push(by.clone());
        }
        Ok(())
    }

    /// A member as events show it, if it has a letmeknow credential.
    fn member(&self, gid: &[u8], member: &core::Member) -> Option<Member> {
        let credential = member.credential.clone()?;
        let g = self.groups.get(gid);
        let added = g.and_then(|g| {
            let added = g.mls.added().iter().rev().find(|added| added.member == credential)?;
            let by = g.mls.members().into_iter().find(|m| m.credential.as_ref() == Some(&added.by));
            Some((Bytes(by.map(|by| by.key).unwrap_or_default()), added.how.unwrap_or(How::Invite)))
        });
        let identity = credential.identity.clone().map(|identity| self.claim(&credential, &member.key, identity));
        Some(Member {
            key: Bytes(member.key.clone()),
            iroh: member.leaf.as_ref().map(|leaf| leaf.key.clone()).unwrap_or_default(),
            name: credential.name,
            device: credential.device,
            device_name: credential.device_name,
            identity,
            added,
        })
    }

    fn claim(&self, credential: &Credential, key: &[u8], identity: IdentityRef) -> Claim {
        let Some((list, _)) = self.lists.get(&identity.id.0) else {
            let error = Some("its identity's device list could not be read yet".into());
            return Claim { identity, name: String::new(), error, added_by_device: None };
        };
        let error = match check(credential, key, Some(list)) {
            Verdict::Verified | Verdict::NoIdentity => None,
            Verdict::NotListed => Some(format!("its device is not on {}'s device list", list.name)),
            Verdict::BadSignature => Some("its device did not sign its key".into()),
        };
        let listed = list.devices.iter().find(|listed| listed.key == credential.device).filter(|l| l.by != l.key);
        let added_by_device =
            listed.and_then(|listed| list.devices.iter().find(|by| by.key == listed.by)).map(|by| by.name.clone());
        Claim { identity, name: list.name.clone(), error, added_by_device }
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
            device: Bytes::default(),
            device_name: String::new(),
            identity: None,
            added: None,
        })
    }

    fn devices_group(&self, identity: &[u8]) -> Option<Vec<u8>> {
        self.groups
            .iter()
            .find(|(_, g)| g.mls.settings().devices_of.is_some_and(|of| of.0 == identity))
            .map(|(gid, _)| gid.clone())
    }

    /// A new group's records, and its MLS state.
    fn add_group(&mut self, mls: Group, rec: Rec, doc: Option<Vec<u8>>) -> Result<Vec<u8>> {
        let gid = mls.id().to_vec();
        if let Some(doc) = doc {
            self.provider.put(&doc_key(&gid), &doc)?;
        }
        self.groups.insert(gid.clone(), G { mls, rec, future: Vec::new(), own_at: None, follow: None });
        self.save(&gid)?;
        self.save_groups()?;
        Ok(gid)
    }
}

impl<P: Provider + Send + 'static> Node<P> {
    /// Opens the session in `provider`, creating it on first use, and starts its peers.
    pub async fn start(provider: P, device: Device, config: Config) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
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
        let leaf = Leaf { key: Bytes(endpoint.id().as_bytes().to_vec()), relay: config.relay.to_string() };
        let mut session = match provider.get(b"session")? {
            Some(_) => Session::load(&provider)?,
            None if config.device_key => {
                Session::create_with(&provider, device.signer(), &device, &config.name, None, leaf.clone())?
            }
            None => Session::create(&provider, &device, &config.name, None, leaf.clone())?,
        };
        if session.leaf != leaf {
            session.set_leaf(&provider, leaf)?;
        }
        let logs = logs::Logs::new(endpoint.clone());
        let mut groups = HashMap::new();
        for gid in get::<Vec<Bytes>>(&provider, b"node/groups")?.unwrap_or_default() {
            let mls = Group::load(&provider, &gid.0)?;
            let rec: Rec = get(&provider, &rec_key(&gid.0))?.context("a group without its record")?;
            if let Some(chain) = &rec.chain {
                logs.client(&mls.settings().membership)?.set_chain(chain.clone());
            }
            groups.insert(gid.0, G { mls, rec, future: Vec::new(), own_at: None, follow: None });
        }
        let (events, events_rx) = mpsc::unbounded_channel();
        let (work, work_rx) = mpsc::unbounded_channel();
        let state = State {
            provider,
            session,
            device,
            groups,
            invites: Invites::default(),
            labels: HashMap::new(),
            lists: HashMap::new(),
            waiters: HashMap::new(),
            editors: HashMap::new(),
        };
        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            net: OnceLock::new(),
            logs,
            relay: config.relay.clone(),
            file_limit: config.file_limit,
            window: config.window,
            events,
            work: work.clone(),
            committing: tokio::sync::Mutex::new(()),
            reading: Mutex::default(),
            tasks: Mutex::default(),
        });
        // An invite link that names no relay is reached through letmeknow.dev's.
        let net_config = lmk_net::Config {
            relay: RELAY.parse()?,
            home: config.home,
            files: config.files,
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
        let gids: Vec<Vec<u8>> = inner.state.lock().unwrap().groups.keys().cloned().collect();
        for gid in &gids {
            inner.follow(gid);
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
        for g in self.inner.state.lock().unwrap().groups.values_mut() {
            if let Some(follow) = g.follow.take() {
                follow.abort();
            }
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

    pub fn device(&self) -> Device {
        self.inner.state.lock().unwrap().device.clone()
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

    /// A new group with this session its only member, speaking as `identity`.
    pub fn create(&self, settings: Settings, identity: Option<IdentityRef>) -> Result<Bytes> {
        let gid = {
            let mut st = self.inner.state.lock().unwrap();
            let st = &mut *st;
            st.session.credential.identity = identity;
            let doc = doc_like(&settings).then(|| doc::new(""));
            let mls = Group::create(&st.provider, &st.session, &settings, self.inner.window)?;
            st.add_group(mls, Rec::default(), doc)?
        };
        self.inner.follow(&gid);
        Ok(Bytes(gid))
    }

    /// An invite link into a group, or with `Target::Device`, to this device's identity.
    pub fn invite(&self, target: Target, label: Option<String>, to: Option<Vec<u8>>) -> Result<String> {
        if let Target::Group(gid) = &target {
            ensure!(self.settings(gid)?.devices_of.is_none(), "a devices group takes devices by a device link, not an invite");
        }
        let device = matches!(target, Target::Device(_));
        let secret = self.inner.state.lock().unwrap().invites.make(target, label, to, now()).secret;
        let (key, relay) = self.address();
        let ours: RelayUrl = RELAY.parse()?;
        Ok(Invite { device, key, secret, relay: (relay != ours).then(|| relay.to_string()) }.link())
    }

    /// Joins through an invite link, speaking as `identity`; a device link adds this device to an identity.
    pub async fn join(&self, link: &Invite, identity: Option<IdentityRef>) -> Result<Bytes> {
        let key_package = {
            let mut st = self.inner.state.lock().unwrap();
            st.session.credential.identity = if link.device { None } else { identity };
            st.session.key_package(&st.provider)?
        };
        let admitted = match self.inner.net().redeem(link, key_package).await? {
            Answer::Ok(admitted) => admitted,
            Answer::Refused { refused } => bail!("refused: {refused}"),
        };
        self.inner.welcomed(admitted, link.key).await
    }

    /// Asks members of an open group to admit this session, speaking as `identity`.
    pub async fn join_open(&self, opening: &Opening, identity: IdentityRef) -> Result<Bytes> {
        let key_package = {
            let mut st = self.inner.state.lock().unwrap();
            st.session.credential.identity = Some(identity);
            st.session.key_package(&st.provider)?
        };
        let mut refusal = anyhow::anyhow!("no member of the group is online");
        for key in &opening.members {
            let Some(peer) = endpoint_id(&key.0) else {
                continue;
            };
            let asked = self.inner.net().join(peer, self.inner.relay.clone(), &opening.group.0, key_package.clone());
            match timeout(RECEIPT_WAIT * 4, asked).await {
                Ok(Ok(Answer::Ok(admitted))) => {
                    return self.inner.welcomed(admitted, *peer.as_bytes()).await;
                }
                Ok(Ok(Answer::Refused { refused })) => refusal = anyhow::anyhow!("refused: {refused}"),
                Ok(Err(error)) => tracing::debug!("asking {} to join: {error:#}", peer.fmt_short()),
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
        Ok(Some(self.send(gid, &Payload::Leave).await?.1))
    }

    /// Seals a payload and sends it to the members online; a message or leave is held for the others.
    pub async fn send(&self, gid: &[u8], payload: &Payload) -> Result<(Bytes, Delivery)> {
        let (id, ciphertext, receipts) = {
            let mut st = self.inner.state.lock().unwrap();
            let st = &mut *st;
            let g = st.groups.get_mut(gid).context("this session is not in that group")?;
            let (id, ciphertext) = g.mls.seal(&st.provider, &st.session, payload)?;
            if matches!(payload, Payload::Message { .. } | Payload::Leave) {
                let epoch = g.mls.epoch();
                let me = g.mls.members().into_iter().find(|m| m.key == st.session.key());
                let g = st.groups.get_mut(gid).unwrap();
                g.rec.items.push(Item { epoch, id: Bytes(id.to_vec()), at: now() });
                g.rec.pending.push(Pending { id: Bytes(id.to_vec()), what: "message".into() });
                if let Payload::Message { attachment: Some(attachment), .. } = payload {
                    g.rec.link(attachment.link.clone());
                }
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

    /// Forgets a held message's text; it is still served to members as ciphertext.
    pub fn redact(&self, id: &[u8]) -> Result<()> {
        let st = self.inner.state.lock().unwrap();
        let Some(mut message) = get::<Message>(&st.provider, &message_key(id))? else {
            return Ok(());
        };
        if let Payload::Message { content, .. } = &mut message.payload {
            content.clear();
        }
        put(&st.provider, &message_key(id), &message)?;
        st.provider.scrub()
    }

    /// Leaves in this session's files no copy of what it deleted.
    pub fn scrub(&self) -> Result<()> {
        self.inner.state.lock().unwrap().provider.scrub()
    }

    /// A doc's Yjs state.
    pub fn doc(&self, gid: &[u8]) -> Result<Vec<u8>> {
        self.inner.state.lock().unwrap().doc_state(gid)
    }

    /// A doc's Yjs state, with the members whose changes came in since this was last asked: the two are read together,
    /// so a change is never in the state while its editor waits for the next call.
    pub fn doc_edits(&self, gid: &[u8]) -> Result<(Vec<u8>, Vec<Member>)> {
        let mut st = self.inner.state.lock().unwrap();
        let state = st.doc_state(gid)?;
        Ok((state, st.editors.remove(gid).unwrap_or_default()))
    }

    /// Applies an edit to a doc and sends it to the members online.
    pub async fn edit(&self, gid: &[u8], update: Vec<u8>) -> Result<()> {
        self.inner.edit(gid, update).await
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

    /// A held file's ciphertext, for a browser to keep in its own storage.
    pub async fn ciphertext(&self, hash: [u8; 32]) -> Result<Vec<u8>> {
        self.inner.net().ciphertext(hash).await
    }

    /// Holds a file's ciphertext again, as `ciphertext` gave it.
    pub async fn hold(&self, ciphertext: Vec<u8>) -> Result<()> {
        self.inner.net().hold(ciphertext).await
    }

    /// Fetches a file the group links, whatever its size; `Event::File` follows.
    pub fn fetch(&self, gid: &[u8], link: FileLink) {
        self.inner.work.send(Work::Fetch { group: gid.to_vec(), link }).ok();
    }

    /// Waits until another member online holds a file this session added, or a while; returns them. If none does, the
    /// file is pending until one fetches it.
    pub async fn spread(&self, gid: &[u8], link: &FileLink) -> Vec<Member> {
        let net = self.inner.net();
        let mut holders = Vec::new();
        for _ in 0..10 {
            holders = net.holders(gid, link.hash).await;
            if !holders.is_empty() {
                break;
            }
            sleep(Duration::from_millis(500)).await;
        }
        let mut st = self.inner.state.lock().unwrap();
        if holders.is_empty()
            && let Ok(g) = st.group_mut(gid)
        {
            g.rec.pending.push(Pending { id: Bytes(link.hash.to_vec()), what: "file".into() });
            st.save(gid).ok();
        }
        holders.iter().map(|peer| st.by_iroh(gid, peer)).collect()
    }

    // Identities: their device lists, the devices group, contacts and openings.

    /// This device's identities, with their names.
    pub fn identities(&self) -> Vec<(IdentityRef, String)> {
        let st = self.inner.state.lock().unwrap();
        let name = |identity: &IdentityRef| {
            let devices =
                st.devices_group(&identity.id.0).and_then(|gid| st.groups.get(&gid).map(|g| g.mls.settings().name));
            devices.unwrap_or_default()
        };
        st.device.identities.iter().map(|identity| (identity.clone(), name(identity))).collect()
    }

    /// Starts an identity with this device on its list, and its devices group.
    pub async fn identity_create(&self, name: &str, membership: Service) -> Result<IdentityRef> {
        let (id, entry) = {
            let st = self.inner.state.lock().unwrap();
            identity::create(&st.device, name, membership.clone())
        };
        self.inner.logs.client(&membership)?.append(&lmk_proto::identity::address(&id), &entry).await?;
        let identity = IdentityRef { id: id.into(), membership: membership.clone() };
        let gid = {
            let mut st = self.inner.state.lock().unwrap();
            let st = &mut *st;
            st.device.identities.push(identity.clone());
            st.session.credential.identity = None;
            let mls =
                Group::create(&st.provider, &st.session, &devices_settings(&id, name, membership), self.inner.window)?;
            st.add_group(mls, Rec::default(), Some(Contacts::default().state()))?
        };
        self.inner.follow(&gid);
        Ok(identity)
    }

    /// An identity's device list, read from its service.
    pub async fn device_list(&self, identity: &IdentityRef) -> Result<DeviceList> {
        self.inner.list(identity).await
    }

    /// Takes a device off one of this device's identities; its sessions then leave every group this session is in.
    pub async fn remove_device(&self, identity: &IdentityRef, device: &[u8]) -> Result<()> {
        let list = self.inner.list(identity).await?;
        ensure!(list.has(device), "that device is not on the list");
        let entry = list.remove(&self.inner.state.lock().unwrap().device, device);
        self.inner
            .logs
            .client(&identity.membership)?
            .append(&lmk_proto::identity::address(&identity.id.0), &entry)
            .await?;
        self.inner.list(identity).await.map(drop)
    }

    /// The contacts of this device's identities.
    pub fn contacts(&self) -> Result<Vec<(Bytes, Contact)>> {
        let st = self.inner.state.lock().unwrap();
        let mut all = Vec::new();
        for identity in &st.device.identities {
            if let Some(gid) = st.devices_group(&identity.id.0) {
                all.extend(Contacts::load(&st.doc_state(&gid)?)?.all());
            }
        }
        Ok(all)
    }

    /// Sets a contact of this device's first identity.
    pub async fn set_contact(&self, id: &[u8], contact: &Contact) -> Result<()> {
        let (gid, update) = {
            let st = self.inner.state.lock().unwrap();
            let identity = st.device.identities.first().context("this device is on no identity")?;
            let gid = st.devices_group(&identity.id.0).context("this device is not in its identity's devices group")?;
            (gid.clone(), Contacts::load(&st.doc_state(&gid)?)?.set(id, contact))
        };
        self.inner.edit(&gid, update).await
    }

    /// The groups open to this device's identities, as their devices groups record them.
    pub fn openings(&self) -> Vec<Opening> {
        let st = self.inner.state.lock().unwrap();
        st.groups
            .values()
            .filter(|g| g.mls.settings().devices_of.is_some())
            .flat_map(|g| g.mls.settings().openings)
            .collect()
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
        })
    }

    /// Records an opening in the devices group of an identity, unless it is there already.
    pub async fn set_opening(&self, identity: &[u8], opening: Opening) -> Result<()> {
        let gid = self.inner.state.lock().unwrap().devices_group(identity).context("not a device of that identity")?;
        if self.settings(&gid)?.openings.contains(&opening) {
            return Ok(());
        }
        self.change_settings(&gid, |settings| with_opening(settings, opening.clone())).await.map(drop)
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
            g.rec.files.retain(|(_, at)| *at >= before);
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

    /// Follows a group's log: new entries as they come, catching up whenever the subscription restarts.
    fn follow(self: &Arc<Self>, gid: &[u8]) {
        let (inner, key) = (self.clone(), gid.to_vec());
        let handle = spawn(async move {
            let gid = key;
            loop {
                let service = match inner.state.lock().unwrap().group(&gid) {
                    Ok(g) => g.mls.settings().membership,
                    Err(_) => return,
                };
                let followed = async {
                    let client = inner.logs.client(&service)?;
                    let mut subscription = client.subscribe(vec![Bytes(gid.clone())]).await?;
                    inner.read(&gid).await?;
                    while let Some(notice) = subscription.next().await {
                        let notice = notice?;
                        inner.logged(&gid, notice.position - 1, vec![notice.entry], client.chain(&gid))?;
                    }
                    anyhow::Ok(())
                };
                if let Err(error) = followed.await {
                    tracing::debug!("following {}: {error:#}", hex(&gid));
                }
                sleep(Duration::from_secs(2)).await;
            }
        });
        if let Some(g) = self.state.lock().unwrap().groups.get_mut(gid) {
            g.follow = Some(handle);
        }
    }

    /// Reads a group's log from the service, through its end.
    async fn read(&self, gid: &[u8]) -> Result<()> {
        let service = self.state.lock().unwrap().group(gid)?.mls.settings().membership;
        let client = self.logs.client(&service)?;
        loop {
            let after = self.state.lock().unwrap().group(gid)?.rec.logged;
            let page = client.read(gid, after).await?;
            if client.chain(gid).is_none() {
                client.set_chain(Chain::anchored(page.head.clone()));
            }
            let more = !page.entries.is_empty();
            self.logged(gid, after, page.entries, client.chain(gid))?;
            if !more {
                return Ok(());
            }
        }
    }

    /// Stores log entries that follow position `after`, and applies what it can. `chain` is the client's, recorded
    /// when it covers just what is stored, so that a head this session shows its peers matches its entries.
    pub(crate) fn logged(&self, gid: &[u8], after: u64, entries: Vec<Bytes>, chain: Option<Chain>) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let st = &mut *st;
        let g = st.group_mut(gid)?;
        let logged = g.rec.logged;
        if after > logged {
            self.work.send(Work::Read(gid.to_vec())).ok();
            return Ok(());
        }
        for (position, entry) in (after + 1..).zip(entries).skip((logged - after) as usize) {
            st.provider.put(&entry_key(gid, position), &entry.0)?;
            st.groups.get_mut(gid).unwrap().rec.logged = position;
        }
        let g = st.groups.get_mut(gid).unwrap();
        if let Some(chain) = chain.filter(|chain| chain.length() == g.rec.logged) {
            g.rec.chain = Some(chain);
        }
        self.advance(st, gid)
    }

    /// Applies the stored entries this session has not applied yet, then the messages that waited for them.
    fn advance(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        let mut changed = false;
        loop {
            let g = st.groups.get_mut(gid).unwrap();
            if g.rec.position >= g.rec.logged {
                break;
            }
            let position = g.rec.position + 1;
            let entry = st.provider.get(&entry_key(gid, position))?.context("a stored entry is missing")?;
            let applied = g.mls.apply(&st.provider, &entry, now())?;
            g.rec.position = position;
            let core::Applied::Commit { by, own, added, how, removed, settings, gone, .. } = applied else {
                continue;
            };
            changed = true;
            if own {
                g.own_at = Some(position);
            }
            let by = g.mls.members().into_iter().find(|m| m.index == by);
            self.work.send(Work::Applied { group: gid.to_vec(), by, added, how, removed, settings, gone }).ok();
            if gone {
                break;
            }
        }
        st.save(gid)?;
        if changed {
            // Applying a commit deletes the secrets of epochs beyond the key window.
            if let Err(error) = st.provider.scrub() {
                self.warn(Some(gid), format!("{error:#}"));
            }
            if let Some(net) = self.net.get() {
                net.changed(gid);
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
    /// won its epoch; if another commit won, builds it again. Returns the Welcome, if it adds, and the position.
    async fn commit(&self, gid: &[u8], change: impl Fn(&Group) -> Result<Change>) -> Result<(Option<Vec<u8>>, u64)> {
        let _committing = self.committing.lock().await;
        for _ in 0..COMMIT_TRIES {
            self.read(gid).await?;
            let (service, bytes, welcome, ours) = {
                let mut st = self.state.lock().unwrap();
                let st = &mut *st;
                let g = st.groups.get_mut(gid).context("this session is not in that group")?;
                g.own_at = None;
                let service = g.mls.settings().membership;
                // A commit posted before, which the log may or may not have taken: post it again.
                match g.mls.posted() {
                    Some(posted) => (service, posted.to_vec(), None, false),
                    None => {
                        let commit = g.mls.commit(&st.provider, &st.session, change(&g.mls)?)?;
                        (service, commit.commit, commit.welcome, true)
                    }
                }
            };
            let client = self.logs.client(&service)?;
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

    /// Joins a group from the Welcome a member at `by` (an iroh key) sent.
    async fn welcomed(self: &Arc<Self>, admitted: Admitted, by: [u8; 32]) -> Result<Bytes> {
        let gid = {
            let mut st = self.state.lock().unwrap();
            let st = &mut *st;
            let mls = Group::join(&st.provider, &admitted.welcome.0, self.window)?;
            ensure!(!st.groups.contains_key(mls.id()), "this session is in that group already");
            let settings = mls.settings();
            if let Some(identity) = &settings.devices_of
                && !st.device.identities.iter().any(|known| known.id == *identity)
            {
                st.device
                    .identities
                    .push(IdentityRef { id: identity.clone(), membership: settings.membership.clone() });
            }
            let doc = if settings.devices_of.is_some() {
                Some(Contacts::default().state())
            } else {
                doc_like(&settings).then(|| doc::new(""))
            };
            let rec = Rec { position: admitted.position, logged: admitted.position, ..Rec::default() };
            st.add_group(mls, rec, doc)?
        };
        if let Err(error) = self.read(&gid).await {
            self.warn(Some(&gid), format!("reading the group's log: {error:#}"));
        }
        self.follow(&gid);
        self.refresh(&gid).await;
        self.dial_all();
        if let Some(link) = admitted.doc {
            let (inner, gid, link) = (self.clone(), gid.clone(), FileLink::parse(&link)?);
            self.spawn(async move {
                if let Err(error) = inner.doc_from(&gid, &link, by).await {
                    inner.warn(Some(&gid), format!("the doc's text did not arrive: {error:#}"));
                }
            });
        }
        Ok(Bytes(gid))
    }

    /// Merges a doc state linked in a Welcome, once it is fetched.
    async fn doc_from(&self, gid: &[u8], link: &FileLink, by: [u8; 32]) -> Result<()> {
        {
            let mut st = self.state.lock().unwrap();
            let rec = &mut st.group_mut(gid)?.rec;
            rec.link(link.link());
            rec.state = Some(link.link());
            st.save(gid)?;
        }
        self.fetched(gid, link).await?;
        let mut state = Vec::new();
        self.net().read_file(link, &mut state).await?;
        let mut st = self.state.lock().unwrap();
        let merged = doc::apply(&st.doc_state(gid)?, &state)?;
        let by = st.by_iroh(gid, &EndpointId::from_bytes(&by)?);
        st.edited(gid, &merged, &by)?;
        self.events.send(Event::Edited { group: Bytes(gid.to_vec()), by }).ok();
        Ok(())
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

    async fn edit(&self, gid: &[u8], update: Vec<u8>) -> Result<()> {
        let ciphertext = {
            let mut st = self.state.lock().unwrap();
            let st = &mut *st;
            let state = doc::apply(&st.doc_state(gid)?, &update)?;
            st.provider.put(&doc_key(gid), &state)?;
            let g = st.groups.get_mut(gid).unwrap();
            g.mls.seal(&st.provider, &st.session, &Payload::Edit { update: Bytes(update) })?.1
        };
        self.net().send(gid, ciphertext);
        Ok(())
    }

    /// Sends a sealed message and waits for the receipts of the members it went to.
    async fn deliver(
        &self,
        gid: &[u8],
        id: [u8; 32],
        ciphertext: Vec<u8>,
        mut receipts: mpsc::UnboundedReceiver<(EndpointId, Option<String>)>,
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

    /// Fetches the device lists of every identity in this session's groups.
    async fn refresh_all(&self) {
        let gids: Vec<Vec<u8>> = self.state.lock().unwrap().groups.keys().cloned().collect();
        for gid in gids {
            self.refresh(&gid).await;
        }
    }

    /// Fetches the device lists of the identities a group's members speak as, or its devices are of, unless fresh.
    async fn refresh(&self, gid: &[u8]) {
        let stale: Vec<IdentityRef> = {
            let st = self.state.lock().unwrap();
            let Ok(g) = st.group(gid) else { return };
            let settings = g.mls.settings();
            let devices_of =
                settings.devices_of.map(|id| IdentityRef { id, membership: settings.membership.clone() });
            let identities = g.mls.members().into_iter().filter_map(|m| m.credential?.identity).chain(devices_of);
            identities
                .filter(|identity| st.lists.get(&identity.id.0).is_none_or(|(_, at)| at + LIST_FRESH < now()))
                .collect()
        };
        for identity in stale {
            if let Err(error) =
                timeout(RECEIPT_WAIT, self.list(&identity)).await.map_err(anyhow::Error::from).and_then(|r| r)
            {
                tracing::debug!("the device list of {}: {error:#}", hex(&identity.id.0));
            }
        }
        self.revoke(&self.state.lock().unwrap(), gid);
    }

    /// Has the members of a group removed whose device left the identity they speak as or, in a devices group, the
    /// identity it is of.
    fn revoke(&self, st: &State<P>, gid: &[u8]) {
        let Ok(g) = st.group(gid) else { return };
        let devices_of = g.mls.settings().devices_of;
        for member in g.mls.members() {
            let Some(credential) = &member.credential else { continue };
            let Some(id) = credential.identity.as_ref().map(|identity| &identity.id).or(devices_of.as_ref()) else {
                continue;
            };
            if member.key != st.session.key()
                && st.lists.get(&id.0).is_some_and(|(list, _)| list.removed(&credential.device.0))
            {
                self.work.send(Work::Remove { group: gid.to_vec(), key: member.key }).ok();
            }
        }
    }

    /// Reads an identity's device list from its service.
    async fn list(&self, identity: &IdentityRef) -> Result<DeviceList> {
        let client = self.logs.client(&identity.membership)?;
        let log = lmk_proto::identity::address(&identity.id.0);
        let mut entries = Vec::new();
        loop {
            let page = client.read(&log, entries.len() as u64).await?;
            if page.entries.is_empty() {
                break;
            }
            entries.extend(page.entries);
        }
        let id: [u8; 32] = identity.id.0.as_slice().try_into().context("an identity id is 32 bytes")?;
        let list = DeviceList::replay(&id, entries.iter().map(|entry| entry.0.as_slice()))?;
        let mut st = self.state.lock().unwrap();
        st.lists.insert(identity.id.0.clone(), (list.clone(), now()));
        for gid in st.groups.keys() {
            self.revoke(&st, gid);
        }
        Ok(list)
    }

    /// Leaves a group behind: its state and records go.
    fn forget(&self, gid: &[u8]) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let st = &mut *st;
        let g = st.groups.remove(gid).context("this session is not in that group")?;
        if let Some(follow) = g.follow {
            follow.abort();
        }
        for item in &g.rec.items {
            st.provider.delete(&message_key(&item.id.0))?;
            st.provider.delete(&ciphertext_key(&item.id.0))?;
        }
        for position in 1..=g.rec.logged {
            st.provider.delete(&entry_key(gid, position))?;
        }
        st.provider.delete(&rec_key(gid))?;
        st.provider.delete(&doc_key(gid))?;
        st.editors.remove(gid);
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
                Work::Applied { group, by, added, how, removed, settings, gone } => {
                    self.applied(&group, by, added, how, removed, settings, gone).await
                }
                Work::Read(gid) => {
                    if self.reading.lock().unwrap().insert(gid.clone()) {
                        let inner = self.clone();
                        self.spawn(async move {
                            if let Err(error) = inner.read(&gid).await {
                                tracing::debug!("reading {}: {error:#}", hex(&gid));
                            }
                            inner.reading.lock().unwrap().remove(&gid);
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
        removed: Vec<core::Member>,
        settings: bool,
        gone: bool,
    ) {
        if !added.is_empty() {
            self.refresh(gid).await;
            self.dial_all();
        }
        let group = Bytes(gid.to_vec());
        let mut st = self.state.lock().unwrap();
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
        for member in &added {
            let label = st.labels.remove(&member.key);
            if let Some(member) = st.member(gid, member) {
                let how = how.unwrap_or(How::Invite);
                self.events.send(Event::Joined { group: group.clone(), member, by: by.clone(), how, label }).ok();
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

    fn net_event(self: &Arc<Self>, event: lmk_net::Event) {
        match event {
            lmk_net::Event::Receipt { group, peer, held, refused } => {
                let mut st = self.state.lock().unwrap();
                let answers =
                    held.into_iter().map(|id| (id, None)).chain(refused.into_iter().map(|(id, r)| (id, Some(r))));
                let mut changed = false;
                for (id, refused) in answers {
                    if let Some(waiter) = st.waiters.get(&id) {
                        waiter.send((peer, refused)).ok();
                        continue;
                    }
                    let Ok(g) = st.group_mut(&group) else { return };
                    if !g.rec.pending.iter().any(|pending| pending.id.0 == id) {
                        continue;
                    }
                    let by = st.by_iroh(&group, &peer);
                    let (group, id) = (Bytes(group.clone()), Bytes(id.to_vec()));
                    match refused {
                        None => {
                            st.group_mut(&group.0).unwrap().rec.pending.retain(|pending| pending.id != id);
                            changed = true;
                            self.events.send(Event::Held { group, id, by }).ok();
                        }
                        Some(reason) => _ = self.events.send(Event::Refused { group, id, by, reason }),
                    }
                }
                if changed {
                    st.save(&group).ok();
                }
            }
            lmk_net::Event::Contradiction { group, peer, ours, theirs } => {
                let text = format!(
                    "the membership service showed {} a different log: length {} with hash {} here, length {} with hash {} there",
                    peer.fmt_short(),
                    ours.length,
                    hex(&ours.hash.0),
                    theirs.length,
                    hex(&theirs.hash.0)
                );
                self.warn(Some(&group), text);
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
            lmk_net::Event::Connected(_) | lmk_net::Event::Disconnected(_) => {}
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
    fn a_group_holds_files_linked_within_keep_its_doc_state_and_its_doc_links() {
        let link = |n: u8| FileLink { hash: [n; 32], size: 1, key: [0; 32] }.link();
        let old = now() - 3 * 24 * 3600 * 1000;
        let files = vec![(link(1), old), (link(2), now()), (link(3), old)];
        let rec = Rec { files, state: Some(link(3)), ..Rec::default() };
        let text = format!("see [the plan]({})", link(4));
        let held: Vec<u8> = rec.held(2, Some(&text)).iter().map(|file| file.hash[0]).collect();
        assert_eq!(held, [2, 3, 4]);
    }
}
