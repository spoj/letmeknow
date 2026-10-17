//! The client core: what one member does on top of its lmk-node session. It answers requests, turns the node's events
//! into `ClientEvent`s with members described as this client knows them, and has its device certify it for the identity
//! it speaks as. A shell gives it storage (the node's provider), a network and the device's node, and prints what it
//! tells.

mod describe;
mod request;

pub use describe::{AddedBy, Described, Describer, Known, Standing, answers, shown};
pub use n0_future::boxed::BoxFuture;
pub use request::{IdentityOp, Request};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lmk_core::device::Device;
use lmk_core::provider::Provider;
use lmk_node::identity::{ADD_VALID, Add, Identity, Presence, SessionGroup};
use lmk_node::{Event, Heard, INVITE_VALID, Member, Message, Node};
use lmk_proto::Bytes;
use lmk_proto::group::{Attachment, CHAT, Certificate, ChatMessage, IDENTITY, How, IdentityRef, PROTOCOL, Service, Settings, UPDATE};
use lmk_proto::links::{FileLink, Invite};
use lmk_proto::peer::Seqs;
use n0_future::time::{Duration, timeout};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

/// How long a file asked for may take to arrive.
const FETCH_WAIT: Duration = Duration::from_secs(60);
const NO_IDENTITY: &str = "this device is on no identity";

pub use lmk_node::fp;

pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn message_id(hex_id: &str) -> Result<[u8; 32]> {
    hex::decode(hex_id).ok().and_then(|id| id.try_into().ok()).with_context(|| format!("{hex_id} is not a message id"))
}

/// letmeknow.dev's membership service.
pub fn letmeknow_dev() -> Service {
    let key = hex::decode(lmk_proto::links::MEMBERSHIP_KEY).unwrap();
    Service::Serve { key: Bytes(key), domain: lmk_proto::links::DOMAIN.into(), rest: Default::default() }
}

/// A membership service from its address: its domain, which only letmeknow.dev's is for now.
pub fn service(address: &str) -> Result<Service> {
    ensure!(address == lmk_proto::links::DOMAIN, "a membership service is named by its domain, such as {}: --membership <domain>, not {address}", lmk_proto::links::DOMAIN);
    Ok(letmeknow_dev())
}

pub struct Config {
    pub device: Device,
    /// For the groups and identities it creates.
    pub membership: Service,
}

/// The device's node, which keeps its identity, and certifies its sessions.
pub enum Access<P> {
    /// It runs here: the identity kind on it.
    Here(Identity<P>),
    /// Another process runs it.
    Elsewhere(Arc<dyn Remote>),
}

impl<P> Clone for Access<P> {
    fn clone(&self) -> Self {
        match self {
            Access::Here(devices) => Access::Here(devices.clone()),
            Access::Elsewhere(remote) => Access::Elsewhere(remote.clone()),
        }
    }
}

/// A device's node that another process runs.
pub trait Remote: Send + Sync {
    /// The device's state as it last published it.
    fn state(&self) -> Result<DeviceState>;
    /// A request only the device's node answers.
    fn request(&self, request: Request) -> BoxFuture<Result<Value>>;
}

/// What a device's node publishes of its state.
#[derive(Default, Serialize, Deserialize)]
pub struct DeviceState {
    /// The device's name; none until a device's node publishes its state.
    pub device: Option<String>,
    /// The device's identity, with its name.
    pub identity: Option<(IdentityRef, String)>,
    /// This device's key on its identity.
    pub key: Option<Bytes>,
}

impl DeviceState {
    pub fn of<P: Provider + Send + 'static>(devices: &Identity<P>) -> Self {
        DeviceState {
            device: devices.name(),
            identity: devices.identity(),
            key: devices.key().ok(),
        }
    }
}

/// Seqs of one author's membership that a message needed and this client gave up on.
#[derive(Debug, Serialize)]
pub struct Missing {
    pub from: Described,
    pub seqs: Vec<u64>,
}

/// Seqs of one author's membership lost, with the ids this client knows of them, in hex.
#[derive(Debug, Serialize)]
pub struct LostMessages {
    pub from: Described,
    pub seqs: Vec<u64>,
    pub ids: Vec<String>,
}

/// What the client tells its shell. Message ids and file hashes are hex.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientEvent {
    Joined { group: Bytes, member: Described, by: Described, how: How },
    Left { group: Bytes, member: Described, by: Described },
    /// This client's commit removed members whose devices were taken off their identities; `added`, the members they
    /// added or let in by their invites, stay until removed by hand.
    Revoked { group: Bytes, removed: Vec<Described>, added: Vec<Described> },
    /// This client was removed from a group; `not_kept`: its messages no cut kept, by id.
    Removed { group: Bytes, by: Option<Described>, not_kept: Vec<String> },
    /// The client let go of a group, removed or leaving: the shell drops what it keeps of it.
    Gone { group: Bytes },
    Settings { group: Bytes, settings: Settings, by: Described },
    /// A chat message, in a group that carries chat, in delivery order. `missing`: what it needed and this client gave
    /// up on; `late`: messages that needed those were delivered without them; `reply_outside`: `reply_to` is not in its
    /// causal past.
    Message {
        group: Bytes,
        id: String,
        from: Described,
        seq: u64,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        missing: Vec<Missing>,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        late: bool,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        reply_outside: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        reply_to: Option<String>,
        payload: Value,
    },
    /// Held messages lost, as `member` tells: this client's own, or as another member's summary tells, each seq once.
    Lost { group: Bytes, member: Described, messages: Vec<LostMessages> },
    /// A member's summary of the group came: who holds and read what may have changed (`Client::receipts`).
    Heard { group: Bytes },
    /// A file is held whole.
    File { hash: String },
    /// The devices of this device's identity changed.
    Identity { identity: Bytes },
    /// This client joined a group by an add that `device`, another of its identity's devices, sent: what `join` answered.
    Added { device: String, joined: Value },
    Warning { group: Option<Bytes>, text: String },
}

impl ClientEvent {
    fn group(&self) -> Option<&Bytes> {
        match self {
            ClientEvent::Joined { group, .. }
            | ClientEvent::Left { group, .. }
            | ClientEvent::Revoked { group, .. }
            | ClientEvent::Removed { group, .. }
            | ClientEvent::Gone { group }
            | ClientEvent::Settings { group, .. }
            | ClientEvent::Message { group, .. }
            | ClientEvent::Lost { group, .. }
            | ClientEvent::Heard { group } => Some(group),
            ClientEvent::Warning { group, .. } => group.as_ref(),
            ClientEvent::File { .. } | ClientEvent::Identity { .. } | ClientEvent::Added { .. } => None,
        }
    }
}

/// A chat message to send.
pub struct Chat {
    pub text: String,
    /// Fingerprints, or names the members answer to.
    pub to: Vec<String>,
    pub reply_to: Option<[u8; 32]>,
    pub urgent: bool,
    pub attachment: Option<File>,
}

pub struct File {
    pub name: String,
    pub media_type: String,
    pub data: Vec<u8>,
}

#[derive(Default)]
struct State {
    /// Files waited for, by hash.
    files: Vec<([u8; 32], oneshot::Sender<()>)>,
    /// The invite secrets this session is joining by.
    joining: HashSet<Vec<u8>>,
}

/// What another member holds and shows of a group, as its latest summary says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub member: Member,
    pub held: Vec<Seqs>,
    pub shown: Vec<Seqs>,
}

impl Receipt {
    /// Whether the member holds the message: its own it does.
    pub fn holds(&self, message: &Message) -> bool {
        self.member.key == message.sender.key || covers(&self.held, message)
    }

    /// Whether the member showed the message: its own it did.
    pub fn showed(&self, message: &Message) -> bool {
        self.member.key == message.sender.key || covers(&self.shown, message)
    }
}

fn covers(seqs: &[Seqs], message: &Message) -> bool {
    seqs.iter().any(|s| s.key == message.sender.key && s.joined == message.joined && s.seqs.contains(message.seq))
}

/// What each member but `me` holds and shows, as its latest summary says; an away member holds nothing.
pub fn receipts(members: &[Member], me: &Bytes, heard: &[Heard], away: &[Member]) -> Vec<Receipt> {
    let others = members.iter().filter(|member| member.key != *me);
    others
        .map(|member| {
            let summary = heard.iter().find(|heard| heard.member.key == member.key);
            let held = match summary {
                Some(heard) if !away.contains(member) => heard.held.clone(),
                _ => Vec::new(),
            };
            let shown = summary.map(|heard| heard.shown.clone()).unwrap_or_default();
            Receipt { member: member.clone(), held, shown }
        })
        .collect()
}

struct Inner<P> {
    node: Node<P>,
    config: Config,
    access: Mutex<Access<P>>,
    state: Mutex<State>,
    events: mpsc::UnboundedSender<ClientEvent>,
    refreshing: tokio::sync::Mutex<()>,
    /// The events of the groups `added` is joining, held until it tells of the join, which so comes first.
    adding: Mutex<HashMap<Bytes, Vec<ClientEvent>>>,
}

/// One member's client, on its node. Its methods may run at once.
pub struct Client<P> {
    inner: Arc<Inner<P>>,
}

impl<P> Clone for Client<P> {
    fn clone(&self) -> Self {
        Client { inner: self.inner.clone() }
    }
}

impl<P: Provider + Send + 'static> Client<P> {
    pub fn new(node: Node<P>, config: Config, access: Access<P>) -> (Self, mpsc::UnboundedReceiver<ClientEvent>) {
        let (events, told) = mpsc::unbounded_channel();
        let inner = Inner {
            node,
            config,
            access: Mutex::new(access),
            state: Mutex::default(),
            events,
            refreshing: tokio::sync::Mutex::new(()),
            adding: Mutex::default(),
        };
        (Client { inner: Arc::new(inner) }, told)
    }

    pub fn node(&self) -> &Node<P> {
        &self.inner.node
    }

    /// The device's node from now on, as when this process takes it over.
    pub fn set_access(&self, access: Access<P>) {
        *self.inner.access.lock().unwrap() = access;
    }

    /// The device's node, as it runs here or elsewhere.
    pub fn access(&self) -> Access<P> {
        self.inner.access.lock().unwrap().clone()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap()
    }

    fn emit(&self, event: ClientEvent) {
        let mut adding = self.inner.adding.lock().unwrap();
        match event.group().and_then(|gid| adding.get_mut(gid)) {
            Some(held) => held.push(event),
            None => _ = self.inner.events.send(event),
        }
    }

    pub fn warn(&self, group: Option<&Bytes>, text: String) {
        self.emit(ClientEvent::Warning { group: group.cloned(), text });
    }

    /// Refreshes its identity claims in the background, as when the client starts.
    pub fn start(&self) {
        let client = self.clone();
        n0_future::task::spawn(async move {
            for error in client.refresh_identity().await {
                client.warn(None, format!("refreshing identity claims: {error:#}"));
            }
        });
    }

    /// The device's state: from its node if it runs here, else as published.
    pub fn device_state(&self) -> Result<DeviceState> {
        match self.access() {
            Access::Here(devices) => Ok(DeviceState::of(&devices)),
            Access::Elsewhere(remote) => remote.state(),
        }
    }

    /// The identity kind, where the device's node runs here.
    fn devices(&self) -> Result<Identity<P>> {
        match self.access() {
            Access::Here(devices) => Ok(devices),
            Access::Elsewhere(_) => bail!("the device's node runs elsewhere"),
        }
    }

    /// This client: its fingerprint, its device, and the device's identity, with the device's key on it.
    pub fn me(&self) -> Result<Value> {
        let state = self.device_state()?;
        let identity = state.identity.map(|(identity, name)| json!({ "id": identity.id, "name": name, "device": state.key }));
        let fp = fp(&self.inner.node.key().0);
        let name = state.device.unwrap_or_else(|| self.inner.config.device.name.clone());
        Ok(json!({ "fp": fp, "device": { "name": name }, "identity": identity }))
    }

    /// Answers a request; one only the device's node answers goes to it where it runs elsewhere.
    pub async fn request(&self, request: Request) -> Result<Value> {
        if request.for_device()
            && let Access::Elsewhere(remote) = self.access()
        {
            return remote.request(request).await;
        }
        match request {
            Request::Invite { group, name, carry, membership, to, qr: _ } => self.invite(group, name, carry, membership, to).await,
            Request::Join { target } => self.join(target).await,
            Request::Add { target, group } => self.add(&target, group).await,
            Request::Deliver { add } => {
                self.devices()?.deliver(&add).await?;
                Ok(json!({}))
            }
            Request::Members { group } => {
                let gid = self.resolve(group)?;
                Ok(json!({ "group": b64(&gid.0), "members": self.described_members(&gid)? }))
            }
            Request::Groups => self.groups(),
            Request::Remove { group, member } => {
                let gid = self.resolve(group)?;
                let member = self.member(&gid, &member)?;
                ensure!(member.key != self.inner.node.key(), "to leave a group, use `leave`");
                self.inner.node.remove(&gid.0, &member.key.0).await?;
                Ok(json!({ "group": b64(&gid.0), "members": self.described_members(&gid)? }))
            }
            Request::Leave { group, end: false } => self.leave(&self.resolve(group)?).await,
            Request::Leave { group, end: true } => self.end(&self.resolve(group)?).await,
            Request::Name { group, name } => {
                let gid = self.resolve(group)?;
                let settings = self.inner.node.change_settings(&gid.0, |settings| Settings { name: name.clone(), ..settings }).await?;
                Ok(json!({ "group": b64(&gid.0), "settings": settings }))
            }
            Request::Status => self.status(),
            Request::Identity { op: IdentityOp::Leave } => self.leave_identity().await,
            Request::Identity { op } => self.identity(op).await,
            Request::Certify { key } => Ok(json!(self.devices()?.certify(&key.0)?)),
        }
    }

    // Groups.

    async fn invite(&self, group: Option<String>, name: Option<String>, carry: u32, membership: Option<String>, to: Option<String>) -> Result<Value> {
        let to = to.map(|to| URL_SAFE_NO_PAD.decode(&to).ok().filter(|id| id.len() == 32).map(Bytes).context("--to takes an identity's id, as `members` shows it")).transpose()?;
        let mut answer = json!({ "expires_in": INVITE_VALID / 1000 });
        let gid = match group {
            Some(group) => self.resolve(Some(group))?,
            None => {
                let membership = membership.map(|m| service(&m)).transpose()?.unwrap_or(self.inner.config.membership.clone());
                let settings = Settings { protocol: PROTOCOL, kind: CHAT.into(), name: name.unwrap_or_default(), carry, update: UPDATE, membership, public: None, rest: Default::default() };
                self.inner.node.create(settings, self.speaking_as().await?)?
            }
        };
        let settings = self.inner.node.settings(&gid.0)?;
        answer["group"] = json!(b64(&gid.0));
        if !settings.name.is_empty() {
            answer["name"] = json!(settings.name);
        }
        if let Some(to) = &to {
            answer["to"] = json!(to);
        }
        answer["link"] = json!(self.inner.node.invite(&gid.0, to, INVITE_VALID).await?.link());
        Ok(answer)
    }

    /// Adds a session of one of this identity's devices to a group: by an invite that admits only that device's
    /// sessions, valid for `ADD_VALID`, which the device's node hands that device in the identity group. `target` is a
    /// device's name and one of the sessions it runs, as members show them ("desk (swift-koala)"); a session's handle
    /// that only one device runs; or a device, by its name or key, whose session is the one it runs, or with none the one
    /// that next acts for it. It is refused while the group has a member of this identity on a device of
    /// that name, with that session's handle if it names one.
    async fn add(&self, target: &str, group: Option<String>) -> Result<Value> {
        let gid = self.resolve(group)?;
        let listed = Box::pin(self.request(Request::Identity { op: IdentityOp::List })).await?;
        let devices = listed["devices"].as_array().context(NO_IDENTITY)?;
        let sessions = |device: &Value| device["sessions"].as_array().cloned().unwrap_or_default();
        let runs = |device: &Value, handle: &str| sessions(device).iter().any(|session| session == handle);
        let running: Vec<&Value> = devices.iter().filter(|device| runs(device, target)).collect();
        ensure!(running.len() < 2, "several of your devices run a session {target}: add one as \"<device> ({target})\"");
        let named = target.strip_suffix(')').and_then(|target| target.rsplit_once(" ("));
        let (device, session) = match (running.first(), named) {
            (Some(device), _) => (*device, target.to_owned()),
            (None, Some((name, handle))) => {
                let device = devices.iter().find(|device| device["name"] == name && runs(device, handle));
                (device.with_context(|| format!("none of your devices {name} runs a session {handle}: see `identity list`"))?, handle.to_owned())
            }
            (None, None) => {
                let device = devices.iter().find(|device| device["name"] == target || device["key"] == target);
                let device = device.with_context(|| format!("none of your devices is {target}, nor runs a session {target}: see `identity list`"))?;
                let running = sessions(device);
                ensure!(running.len() < 2, "{target} runs several sessions: add one by its handle, as `identity list` shows them");
                (device, running.first().and_then(Value::as_str).unwrap_or_default().to_owned())
            }
        };
        let present = self.described_members(&gid)?.iter().any(|m| {
            m.identity.as_ref().is_some_and(|known| known.how == Standing::Own && known.error.is_none())
                && m.device.as_deref() == device["name"].as_str()
                && (session.is_empty() || m.handle.as_deref() == Some(session.as_str()))
        });
        ensure!(!present, "{target} is in this group already");
        let key: Bytes = serde_json::from_value(device["key"].clone())?;
        let settings = self.inner.node.settings(&gid.0)?;
        let expires = lmk_proto::clock::now() + ADD_VALID;
        let link = self.inner.node.invite(&gid.0, Some(key.clone()), ADD_VALID).await?.link();
        let add = Add { device: key, session: session.clone(), group: gid.clone(), name: settings.name, link: link.clone(), expires };
        Box::pin(self.request(Request::Deliver { add })).await?;
        Ok(json!({ "group": b64(&gid.0), "device": device["name"], "session": session, "link": link, "expires_in": ADD_VALID / 1000 }))
    }

    /// Joins `group` by an add that `device`, another of this identity's devices, sent, and tells so before any other
    /// event of the group; unless this session is in it already, having joined it otherwise meanwhile.
    pub async fn added(&self, link: &str, group: &Bytes, device: &str) -> Result<Value> {
        if self.inner.node.groups().contains(group) {
            return Ok(Value::Null);
        }
        self.inner.adding.lock().unwrap().insert(group.clone(), Vec::new());
        let joined = self.join(link.to_owned()).await;
        // Under the lock, so that no event of the group comes between.
        let mut adding = self.inner.adding.lock().unwrap();
        let held = adding.remove(group).unwrap_or_default();
        if let Ok(joined) = &joined {
            self.inner.events.send(ClientEvent::Added { device: device.to_owned(), joined: joined.clone() }).ok();
        }
        for event in held {
            self.inner.events.send(event).ok();
        }
        joined
    }

    async fn join(&self, link: String) -> Result<Value> {
        let invite = Invite::parse(link.trim())?;
        // As the node's, which share one KeyPackage per invite.
        let key = invite.secret.to_vec();
        ensure!(self.state().joining.insert(key.clone()), "this session is joining that already: wait for that join to end");
        let joined = self.join_by(invite).await;
        self.state().joining.remove(&key);
        joined
    }

    async fn join_by(&self, invite: Invite) -> Result<Value> {
        if invite.device {
            self.devices()?.join(&invite).await?;
            return Ok(json!({ "device": "this device joined the identity" }));
        }
        let node = &self.inner.node;
        let gid = node.join(&invite, self.speaking_as().await?).await?.0;
        let settings = node.settings(&gid.0)?;
        Ok(json!({ "group": b64(&gid.0), "name": settings.name, "members": self.described_members(&gid)? }))
    }

    async fn leave(&self, gid: &Bytes) -> Result<Value> {
        if self.inner.node.leave(&gid.0)?.is_none() {
            self.drop_group(gid)?;
            return Ok(json!({ "group": b64(&gid.0), "left": true }));
        }
        Ok(json!({ "group": b64(&gid.0), "left": true, "pending": true, "status": "a member removes this session once a cut keeps its leave" }))
    }

    /// Ends a group for everyone: removes the other members, and leaves it.
    pub async fn end(&self, gid: &Bytes) -> Result<Value> {
        self.inner.node.remove_others(&gid.0).await?;
        let mut answer = self.leave(gid).await?;
        answer["ended"] = json!(true);
        Ok(answer)
    }

    /// Lets go of a group the node has left: tells the shell.
    fn drop_group(&self, gid: &Bytes) -> Result<()> {
        self.emit(ClientEvent::Gone { group: gid.clone() });
        self.inner.node.scrub()
    }

    fn groups(&self) -> Result<Value> {
        let node = &self.inner.node;
        let mut groups = Vec::new();
        for gid in node.groups() {
            let settings = node.settings(&gid.0)?;
            let mut group = json!({
                "group": b64(&gid.0), "members": node.members(&gid.0)?.len(), "carry": settings.carry,
                "membership": settings.membership, "epoch": node.epoch(&gid.0)?,
            });
            if !settings.name.is_empty() {
                group["name"] = json!(settings.name);
            }
            groups.push(group);
        }
        Ok(Value::Array(groups))
    }

    fn status(&self) -> Result<Value> {
        let node = &self.inner.node;
        let mut groups = Vec::new();
        let mut only_here_count = 0;
        for gid in node.groups() {
            let describer = self.describer(&gid)?;
            let online: Vec<Described> = node.online(&gid.0)?.iter().map(|m| describer.describe(m)).collect();
            let away: Vec<Described> = node.away(&gid.0)?.iter().map(|m| describer.describe(m)).collect();
            let mut only_here: Vec<Value> =
                node.only_here(&gid.0)?.iter().map(|(id, payload)| json!({ "what": payload["type"], "id": hex::encode(&id.0) })).collect();
            only_here.extend(node.pending_files(&gid.0)?.iter().map(|hash| json!({ "what": "file", "id": hex::encode(hash) })));
            only_here_count += only_here.len();
            let mut identity_warnings = Vec::new();
            for member in &describer.members {
                if let Some(claim) = &member.identity
                    && let Some(observed) = &claim.observed
                    && (observed.names.len() > 1 || !observed.other_ids.is_empty())
                {
                    let warning = format!("Identity {} claims {:?}; locally observed names: {:?}; other IDs claiming this name: {}. Not independently verified.",
                        b64(&claim.identity.id.0), claim.name, observed.names, serde_json::to_string(&observed.other_ids)?);
                    if !identity_warnings.contains(&warning) {
                        identity_warnings.push(warning);
                    }
                }
            }
            let mut group = json!({ "group": b64(&gid.0), "online": online, "away": away, "only_here": only_here, "identity_warnings": identity_warnings });
            let name = node.settings(&gid.0)?.name;
            if !name.is_empty() {
                group["name"] = json!(name);
            }
            groups.push(group);
        }
        let mut status = json!({ "groups": groups });
        if only_here_count > 0 {
            status["warning"] = json!(format!("{only_here_count} sends are held by no other member yet; keep this session running until they are"));
        }
        Ok(status)
    }

    /// The group a request acts on: the one it names (by id or name), or else the client's one group.
    pub fn resolve(&self, group: Option<String>) -> Result<Bytes> {
        let node = &self.inner.node;
        let gids = node.groups();
        match group {
            Some(group) => {
                let named: Vec<&Bytes> =
                    gids.iter().filter(|gid| b64(&gid.0) == group || node.settings(&gid.0).is_ok_and(|s| s.name == group)).collect();
                match named[..] {
                    [gid] => Ok(gid.clone()),
                    [] => bail!("unknown group {group}"),
                    _ => bail!("several groups are named {group}; pass its id"),
                }
            }
            None => match &gids[..] {
                [gid] => Ok(gid.clone()),
                [] => bail!("this session is in no group; create one with `invite`, or join one with `join`"),
                _ => bail!("this session is in several groups; pass --group"),
            },
        }
    }

    /// Whether a group is a chat.
    pub fn chats(&self, gid: &Bytes) -> bool {
        self.inner.node.settings(&gid.0).is_ok_and(|s| s.kind == CHAT)
    }

    /// The chat a request acts on: the one it names, or else the client's one chat.
    pub fn chat(&self, group: Option<String>) -> Result<Bytes> {
        if group.is_some() {
            let gid = self.resolve(group)?;
            ensure!(self.chats(&gid), "{} is not a chat", b64(&gid.0));
            return Ok(gid);
        }
        let found: Vec<Bytes> = self.inner.node.groups().into_iter().filter(|gid| self.chats(gid)).collect();
        match &found[..] {
            [gid] => Ok(gid.clone()),
            [] => bail!("this session is in no chat; create one with `invite`, or join one with `join`"),
            _ => bail!("this session is in several chats; pass --group"),
        }
    }

    // Messages.

    /// Sends a chat message, a reply to `reply_to` if given; returns its id and the answer to `send`.
    pub async fn send(&self, gid: &Bytes, chat: Chat) -> Result<(Bytes, Value)> {
        let node = &self.inner.node;
        let mut addressed: Vec<Member> = Vec::new();
        for to in &chat.to {
            for member in self.addressed(gid, to)? {
                if !addressed.contains(&member) {
                    addressed.push(member);
                }
            }
        }
        if let Some(id) = &chat.reply_to {
            ensure!(node.message(&gid.0, id)?.is_some(), "unknown message {}", hex::encode(id));
        }
        let attachment = match chat.attachment {
            Some(File { name, media_type, data }) => {
                let size = data.len() as u64;
                let link = node.add_file(&gid.0, data).await?;
                Some((link.clone(), Attachment { link: link.link(), name, size, media_type }))
            }
            None => None,
        };
        let payload = ChatMessage {
            content: chat.text,
            to: addressed.iter().map(|m| Bytes(Sha256::digest(&m.key.0)[..8].to_vec())).collect(),
            urgent: chat.urgent,
            attachment: attachment.as_ref().map(|(_, a)| a.clone()),
            sent_at: Some(lmk_proto::clock::corrected()),
        };
        let id = node.send(&gid.0, &serde_json::to_value(payload)?, chat.reply_to.as_ref().map(|id| &id[..]))?;
        let describer = self.describer(gid)?;
        let mut answer = json!({ "id": hex::encode(&id.0) });
        if !addressed.is_empty() {
            answer["to"] = json!(addressed.iter().map(|m| fp(&m.key.0)).collect::<Vec<_>>());
        }
        if let Some((link, _)) = attachment {
            let holders = node.spread(&gid.0, &link).await;
            if holders.is_empty() {
                answer["attachment"] = json!({ "pending": true, "warning": "no other member holds the file yet; members may still be fetching it" });
            } else {
                answer["attachment"] = json!({ "held_by": holders.iter().map(|m| describer.describe(m)).collect::<Vec<_>>() });
            }
        }
        Ok((id, answer))
    }

    /// Marks held messages of a group shown, as this client showed or printed them.
    pub fn mark_shown(&self, gid: &Bytes, ids: &[Bytes]) -> Result<()> {
        self.inner.node.mark_shown(&gid.0, ids)
    }

    /// What each other member of a group holds and shows (see `receipts`).
    pub fn receipts(&self, gid: &Bytes) -> Result<Vec<Receipt>> {
        let node = &self.inner.node;
        let (members, heard, away) = (node.members(&gid.0)?, node.heard(&gid.0)?, node.away(&gid.0)?);
        Ok(receipts(&members, &node.key(), &heard, &away))
    }

    /// The members `to` addresses: a fingerprint, or a name they answer to, as long as they speak for one identity.
    pub fn addressed(&self, gid: &Bytes, to: &str) -> Result<Vec<Member>> {
        let describer = self.describer(gid)?;
        if let Some(member) = describer.members.iter().find(|m| fp(&m.key.0) == to) {
            return Ok(vec![member.clone()]);
        }
        let mut named = Vec::new();
        for member in &describer.members {
            let described = serde_json::to_value(describer.describe(member))?;
            if described["you"] != true && answers(&described, to) {
                named.push((member.clone(), described));
            }
        }
        let people: HashSet<String> =
            named.iter().map(|(m, d)| d["identity"]["id"].as_str().map_or_else(|| fp(&m.key.0), str::to_owned)).collect();
        match people.len() {
            0 => bail!("no member of {} has the fingerprint or name {to}", b64(&gid.0)),
            1 => Ok(named.into_iter().map(|(m, _)| m).collect()),
            _ => bail!(
                "{to} could be any of {}; pass fingerprints",
                named.iter().map(|(_, d)| format!("{} ({})", d["name"], d["fp"])).collect::<Vec<_>>().join(", ")
            ),
        }
    }

    fn member(&self, gid: &Bytes, member: &str) -> Result<Member> {
        let mut found = self.addressed(gid, member)?;
        ensure!(found.len() == 1, "{member} names several members; pass a fingerprint");
        Ok(found.remove(0))
    }

    /// A file a group links: held, or else fetched from the members online, waiting for it up to a minute.
    pub async fn fetched(&self, gid: &Bytes, link: &FileLink) -> Result<Vec<u8>> {
        let (arrived, arrival) = oneshot::channel();
        self.state().files.push((link.hash, arrived));
        if let Some(bytes) = self.inner.node.file(link).await? {
            return Ok(bytes);
        }
        self.inner.node.fetch(&gid.0, link.clone());
        timeout(FETCH_WAIT, arrival).await.ok().and_then(Result::ok).context("no member online holds that file; try again when one is")?;
        self.inner.node.file(link).await?.context("an arrived file is held")
    }

    // Events.

    /// Takes an event of this client's node.
    pub async fn event(&self, event: Event) {
        let group = event.group().cloned();
        if let Err(error) = self.on(event).await {
            self.warn(group.as_ref(), format!("{error:#}"));
        }
    }

    /// Takes an event of the device's node, where it is not this client's node: the identity kind takes its groups'
    /// events, and of the rest only warnings concern the user.
    pub fn device_event(&self, devices: &Identity<P>, event: Event) {
        let Some(event) = devices.on(event) else { return };
        if let Some(changed) = Self::devices_changed(devices, &event) {
            self.emit(changed);
        } else if let Event::Warning { text, .. } = event {
            self.warn(None, format!("this device: {text}"));
        }
    }

    fn devices_changed(devices: &Identity<P>, event: &Event) -> Option<ClientEvent> {
        let (Event::Joined { group, .. } | Event::Left { group, .. } | Event::Settings { group, .. } | Event::Heard { group }) = event else { return None };
        Some(ClientEvent::Identity { identity: devices.identity_of(&group.0)?.id })
    }

    async fn on(&self, event: Event) -> Result<()> {
        let node = &self.inner.node;
        match event {
            Event::Joined { group, member, by, how } => {
                let describer = self.describer(&group)?;
                self.emit(ClientEvent::Joined { group, member: describer.describe(&member), by: describer.describe(&by), how });
            }
            Event::Left { group, member, by } => {
                let describer = self.describer(&group)?;
                self.emit(ClientEvent::Left { group, member: describer.describe(&member), by: describer.describe(&by) });
            }
            Event::Revoked { group, removed, added } => {
                let describer = self.describer(&group)?;
                let (removed, added) = (removed.iter().map(|m| describer.describe(m)).collect(), added.iter().map(|m| describer.describe(m)).collect());
                self.emit(ClientEvent::Revoked { group, removed, added });
            }
            Event::Public { .. } | Event::Duties { .. } => {}
            Event::Removed { group, by, not_kept, .. } => {
                let by = by.map(|by| self.describe(&group, &by)).transpose()?;
                let not_kept = not_kept.iter().map(|id| hex::encode(&id.0)).collect();
                self.drop_group(&group)?;
                self.emit(ClientEvent::Removed { group, by, not_kept });
            }
            Event::Settings { group, settings, by } => {
                let by = self.describe(&group, &by)?;
                self.emit(ClientEvent::Settings { group, settings, by });
            }
            Event::Message(message) if message.payload["type"] == "message" && self.chats(&message.group) => {
                // Chat holds the file a message attaches.
                if let Some(link) = message.payload["attachment"]["link"].as_str() {
                    node.hold(&message.group.0, &[link.to_owned()])?;
                }
                let describer = self.describer(&message.group)?;
                let from = describer.describe(&message.sender);
                let missing: Vec<Missing> = message.missing.iter().map(|seqs| Missing { from: describer.describe_key(&seqs.key), seqs: seqs.seqs.iter().collect() }).collect();
                let id = hex::encode(&message.id.0);
                let reply_to = message.reply_to.as_ref().map(|id| hex::encode(&id.0));
                let (seq, late, reply_outside) = (message.seq, message.late, message.reply_outside);
                self.emit(ClientEvent::Message { group: message.group, id, from, seq, missing, late, reply_outside, reply_to, payload: message.payload });
            }
            // No other kind holds messages.
            Event::Message(_) => {}
            // A chat has no live payloads, and an identity group's are the identity kind's.
            Event::Live { .. } | Event::Synced { .. } => {}
            Event::Lost(lost) => {
                let describer = self.describer(&lost.group)?;
                let member = describer.describe(&lost.member);
                let messages = lost.messages.iter().map(|of| LostMessages { from: describer.describe(&of.from), seqs: of.seqs.clone(), ids: of.ids.iter().map(|id| hex::encode(&id.0)).collect() });
                self.emit(ClientEvent::Lost { group: lost.group, member, messages: messages.collect() });
            }
            Event::Heard { group } => self.emit(ClientEvent::Heard { group }),
            Event::File(hash) => {
                let arrived: Vec<oneshot::Sender<()>> = {
                    let mut st = self.state();
                    let (arrived, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut st.files).into_iter().partition(|(waited, _)| *waited == hash);
                    st.files = waiting.into_iter().filter(|(_, arrival)| !arrival.is_closed()).collect();
                    arrived.into_iter().map(|(_, arrival)| arrival).collect()
                };
                for arrival in arrived {
                    arrival.send(()).ok();
                }
                self.emit(ClientEvent::File { hash: hex::encode(hash) });
            }
            Event::Warning { group, text } => self.warn(group.as_ref(), text),
        }
        Ok(())
    }

    // Members and identities.

    /// What describes a group's members, gathered once for many.
    pub fn describer(&self, gid: &Bytes) -> Result<Describer> {
        Ok(Describer {
            me: self.inner.node.key(),
            identity: self.device_state()?.identity,
            members: self.inner.node.members(&gid.0).unwrap_or_default(),
        })
    }

    /// A member as this client shows it: its name, its identity as this one knows it, and who added it.
    pub fn describe(&self, gid: &Bytes, member: &Member) -> Result<Described> {
        Ok(self.describer(gid)?.describe(member))
    }

    /// The member of a group with this key, or this client itself before it is one.
    pub fn describe_key(&self, gid: &Bytes, key: &Bytes) -> Result<Described> {
        Ok(self.describer(gid)?.describe_key(key))
    }

    pub fn described_members(&self, gid: &Bytes) -> Result<Vec<Described>> {
        let describer = self.describer(gid)?;
        Ok(describer.members.iter().map(|m| describer.describe(m)).collect())
    }

    /// This client's groups but identity groups, as its identity's devices hear of them: each one's id and name, and its
    /// other members as they show.
    pub fn session_groups(&self) -> Result<Vec<SessionGroup>> {
        let node = &self.inner.node;
        let mut groups = Vec::new();
        for gid in node.groups() {
            // None for a group left since it was listed.
            let Ok(settings) = node.settings(&gid.0) else { continue };
            if settings.kind == IDENTITY {
                continue;
            }
            let members = self.described_members(&gid)?.into_iter().filter(|m| !m.you);
            let members = members.map(|m| Ok(shown(&serde_json::to_value(m)?))).collect::<Result<_>>()?;
            groups.push(SessionGroup { session: None, group: gid, name: settings.name, members });
        }
        Ok(groups)
    }

    /// Leaves identities this device left and refreshes signed claims in existing memberships. Each group can retry independently.
    pub async fn refresh_identity(&self) -> Vec<anyhow::Error> {
        let Ok(_refreshing) = self.inner.refreshing.try_lock() else { return Vec::new() };
        let state = match self.device_state() {
            Ok(state) => state,
            Err(error) => return vec![error],
        };
        let mut failed = Vec::new();
        let certificate = match timeout(Duration::from_secs(10), self.speaking_as()).await.map_err(anyhow::Error::from).and_then(|r| r) {
            Ok(certificate) => certificate,
            Err(error) => {
                failed.push(error);
                None
            }
        };
        let node = &self.inner.node;
        for gid in node.groups() {
            let refresh = async {
                if node.settings(&gid.0)?.kind == IDENTITY {
                    return Ok(());
                }
                let own = node.members(&gid.0)?.into_iter().find(|m| m.key == node.key()).and_then(|m| m.identity);
                let Some(own) = own else { return Ok(()) };
                // None is published before the device manager first runs.
                if state.device.is_some() && state.identity.as_ref().is_none_or(|(id, _)| id.id != own.identity.id) {
                    self.leave(&gid).await?;
                } else if let Some(certificate) = &certificate
                    && certificate.identity.id == own.identity.id
                {
                    node.recertify(&gid.0, certificate.clone()).await?;
                }
                anyhow::Ok(())
            };
            if let Err(error) = timeout(Duration::from_secs(10), refresh).await.map_err(anyhow::Error::from).and_then(|r| r) {
                failed.push(error.context(format!("group {}", b64(&gid.0))));
            }
        }
        failed
    }

    /// Takes this device off its identity, once this client left the groups it speaks as it in, as the device's node
    /// leaves those of its own client.
    async fn leave_identity(&self) -> Result<Value> {
        let (identity, _) = self.device_state()?.identity.context(NO_IDENTITY)?;
        let left = self.leave_as(&identity.id).await?;
        let ended = match self.access() {
            Access::Here(devices) => devices.leave().await?,
            Access::Elsewhere(remote) => remote.request(Request::Identity { op: IdentityOp::Leave }).await?["ended"] == true,
        };
        Ok(json!({ "identity": identity.id, "left": left, "ended": ended }))
    }

    /// Leaves the groups this client speaks as an identity in; returns them.
    async fn leave_as(&self, identity: &Bytes) -> Result<Vec<Bytes>> {
        let me = self.inner.node.key();
        let mut left = Vec::new();
        for gid in self.inner.node.groups() {
            let members = self.inner.node.members(&gid.0)?;
            if members.iter().any(|m| m.key == me && m.identity.as_ref().is_some_and(|claim| claim.identity.id == *identity)) {
                self.leave(&gid).await?;
                left.push(gid);
            }
        }
        Ok(left)
    }

    /// What a new membership speaks as: the device's certificate of this client, on its identity, if it has one.
    async fn speaking_as(&self) -> Result<Option<Certificate>> {
        if self.device_state()?.identity.is_none() {
            return Ok(None);
        }
        let key = self.inner.node.key();
        Ok(Some(match self.access() {
            Access::Here(devices) => devices.certify(&key.0)?,
            Access::Elsewhere(remote) => serde_json::from_value(remote.request(Request::Certify { key }).await?)?,
        }))
    }

    async fn identity(&self, op: IdentityOp) -> Result<Value> {
        let devices = self.devices()?;
        match op {
            IdentityOp::Create { name, membership } => {
                let membership = membership.map(|m| service(&m)).transpose()?.unwrap_or(self.inner.config.membership.clone());
                let identity = devices.create(&name, membership).await?;
                Ok(json!({ "identity": identity.id, "name": name }))
            }
            IdentityOp::Invite { .. } => {
                let (identity, name) = devices.identity().context(NO_IDENTITY)?;
                let link = devices.invite().await?;
                Ok(json!({ "identity": { "id": identity.id, "name": name }, "link": link, "expires_in": INVITE_VALID / 1000 }))
            }
            IdentityOp::List => {
                let Some((identity, name)) = devices.identity() else { return Ok(json!({ "identity": null })) };
                let me = devices.key()?;
                let listed = devices.devices()?.into_iter().map(|(key, name)| {
                    let Presence { sessions, groups } = devices.presence_of(&key);
                    json!({ "you": key == me, "sessions": sessions, "groups": groups, "key": key, "name": name })
                });
                let listed: Vec<Value> = listed.collect();
                Ok(json!({ "identity": identity.id, "name": name, "devices": listed }))
            }
            IdentityOp::Rename { name, device: true } => {
                devices.rename_device(&name).await?;
                Ok(json!({ "device": { "name": name } }))
            }
            IdentityOp::Rename { name, device: false } => {
                devices.rename(&name).await?;
                Ok(json!({ "identity": devices.identity().context(NO_IDENTITY)?.0.id, "name": name }))
            }
            IdentityOp::Leave => unreachable!("a client leaves an identity itself"),
            IdentityOp::Remove { device: removed } => {
                let (identity, _) = devices.identity().context(NO_IDENTITY)?;
                let listed = devices.devices()?;
                let (key, _) = listed.iter().find(|(key, name)| b64(&key.0) == removed || *name == removed).context("no such device")?;
                devices.remove(&key.0).await?;
                // This client's groups lose the device's sessions too, once its node reads the log without the device.
                self.inner.node.read_public(&identity).await?;
                Ok(json!({ "identity": identity.id, "removed": key }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lmk_proto::ranges::Ranges;

    fn member(key: u8) -> Member {
        Member {
            key: Bytes(vec![key]),
            iroh: Bytes(vec![key]),
            revision: 0,
            name: format!("m{key}"),
            device_name: String::new(),
            identity: None,
            added: None,
        }
    }

    fn message(sender: u8, seq: u64) -> Message {
        Message {
            id: Bytes(vec![sender, seq as u8]),
            group: Bytes::default(),
            index: seq,
            at: 0,
            sender: member(sender),
            joined: 0,
            seq,
            reply_to: None,
            payload: json!({ "type": "message", "content": "" }),
            missing: Vec::new(),
            late: false,
            reply_outside: false,
        }
    }

    fn seqs(key: u8, seqs: Ranges) -> Seqs {
        Seqs { key: Bytes(vec![key]), joined: 0, seqs }
    }

    #[test]
    fn a_receipt_holds_and_shows_what_its_summary_says_and_an_away_member_holds_nothing() {
        let members = [member(1), member(2), member(3), member(4)];
        let heard = [
            Heard { member: member(2), joined: 0, held: vec![seqs(1, Ranges::range(1, 10))], shown: vec![seqs(1, Ranges::range(1, 4))], at: 0 },
            Heard { member: member(3), joined: 0, held: vec![seqs(1, Ranges::range(1, 10))], shown: vec![seqs(1, Ranges::range(1, 2))], at: 0 },
        ];
        let got = receipts(&members, &Bytes(vec![1]), &heard, &[member(3)]);
        let got: Vec<(u8, bool, bool)> = got.iter().map(|r| (r.member.key.0[0], r.holds(&message(1, 3)), r.showed(&message(1, 3)))).collect();
        assert_eq!(got, [(2, true, true), (3, false, false), (4, false, false)]);
        assert!(receipts(&members, &Bytes(vec![1]), &heard, &[])[1].holds(&message(3, 7)), "its own messages it holds");
    }
}
