//! The client core: what one member does on top of its lmk-node session, alike in every client. It answers requests,
//! turns the node's events into `ClientEvent`s with members described as this client knows them, has its device certify
//! it for the identity it speaks as, and hosts kinds' plugins.
//! A shell gives it storage (the node's provider), a network, the device's node, the plugins' transport, and shows or
//! prints what it tells.

mod describe;
mod request;

pub use describe::{AddedBy, Described, Describer, Known, Standing, answers, shown};
pub use n0_future::boxed::BoxFuture;
pub use request::{IdentityOp, Request};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lmk_core::device::Device;
use lmk_core::provider::Provider;
use lmk_node::identity::{ADD_VALID, Add, Identity, Pending, Presence, SessionGroup};
use lmk_node::{Event, Heard, INVITE_VALID, Member, Message, Node};
use lmk_proto::Bytes;
use lmk_proto::ranges::Ranges;
use lmk_proto::group::{Attachment, CHAT, Certificate, ChatMessage, IDENTITY, How, IdentityRef, PROTOCOL, Service, Settings, UPDATE};
use lmk_proto::links::{FileLink, Invite};
use n0_future::time::{Duration, Instant, timeout};
use n0_future::{Either, FutureExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

/// How long the client waits for a plugin's answer, but to a command.
const ASK_WAIT: Duration = Duration::from_secs(60);
/// How long a plugin's `spread` waits for a member online to hold its file.
const SPREAD_WAIT: Duration = Duration::from_secs(30);
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

/// What `send` answers: the message's id, and its entry's position once it counts, or that the send is pending.
fn sent_answer(sent: &lmk_node::Sent) -> Value {
    match sent.position {
        Some(position) => json!({ "id": hex::encode(&sent.id.0), "position": position }),
        None => json!({ "id": hex::encode(&sent.id.0), "pending": true }),
    }
}

/// Adds an object's fields to another.
fn merge(into: &mut Value, from: Value) {
    if let (Some(into), Value::Object(from)) = (into.as_object_mut(), from) {
        into.extend(from);
    }
}

/// letmeknow.dev's membership service.
pub fn letmeknow_dev() -> Service {
    let key = hex::decode(lmk_proto::links::MEMBERSHIP_KEY).unwrap();
    Service::Serve { key: Bytes(key), relay: lmk_proto::links::RELAY.into(), addrs: Vec::new(), rest: Default::default() }
}

/// A membership service from its address: `letmeknow.dev`, or `<iroh key, hex>@<relay URL>`.
pub fn service(address: &str) -> Result<Service> {
    if address == "letmeknow.dev" {
        return Ok(letmeknow_dev());
    }
    let (key, relay) = address.split_once("@https://").context("a membership service is letmeknow.dev, or <key>@<relay URL>")?;
    let key = Bytes(hex::decode(key).context("a service key is hex")?);
    Ok(Service::Serve { key, relay: format!("https://{relay}"), addrs: Vec::new(), rest: Default::default() })
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

/// Kinds' plugins, through whatever carries their messages: a process's stdio, or calls into the page. What they write
/// reaches the client through the channel given to `Client::new`: each line with its kind, and `None` once a plugin
/// stopped.
pub trait Plugins: Send + Sync {
    /// The kinds it has plugins for.
    fn kinds(&self) -> Vec<String>;
    /// Starts a kind's plugin; returns the fields of its `start` besides `kind`, such as `dir`.
    fn start(&self, kind: &str) -> Result<Value>;
    fn running(&self) -> Vec<String>;
    fn send(&self, kind: &str, message: &Value) -> Result<()>;
    /// A plugin's lines ended: whether it ran steadily, and may be started again.
    fn stopped(&self, kind: &str) -> bool;
    /// Stops a kind's plugin, as no group of its kind is left; its lines end without a `None`. Plugins that are no
    /// process of their own have nothing to stop.
    fn stop(&self, _kind: &str) {}
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
    /// This client was removed from a group.
    Removed { group: Bytes, by: Option<Described> },
    /// The client let go of a group, removed or leaving: the shell drops what it keeps of it.
    Gone { group: Bytes },
    Settings { group: Bytes, settings: Settings, by: Described },
    /// A chat message, in a group that carries chat, in position order: `missing`, the counted positions before it that
    /// were passed over unopened. One that opens after later ones were shown comes when it opens, naming those passed
    /// before it that no message named yet.
    Message { group: Bytes, id: String, position: u64, missing: Vec<u64>, from: Described, payload: Value },
    /// Counted positions a member can no longer open: this client's own, or another member's of this client's messages.
    Lost { group: Bytes, member: Described, positions: Vec<u64>, ids: Vec<String> },
    /// A send that `send` answered as pending, as `answered`, counts now, at `position` in the group's log, by its
    /// final id, `id`.
    Sent { group: Bytes, id: String, answered: String, position: u64 },
    /// A sync of the group's held messages with a member ended.
    Synced { group: Bytes },
    /// A member's summary of the group came: who holds and read what may have changed (`Client::receipts`).
    Heard { group: Bytes },
    /// Another member's summary holds the `leave` that `leave` answered as pending.
    LeaveHeld { group: Bytes },
    /// A file is held whole.
    File { hash: String },
    /// An event of a kind's plugin: by the delivery policy, waking with `wake`; with `key`, it replaces a held one with
    /// the same key.
    Plugin { group: Bytes, kind: String, event: serde_json::Map<String, Value>, wake: bool, key: Option<String> },
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
            | ClientEvent::Sent { group, .. }
            | ClientEvent::Synced { group }
            | ClientEvent::Heard { group }
            | ClientEvent::LeaveHeld { group }
            | ClientEvent::Plugin { group, .. } => Some(group),
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

/// What waits for a plugin's answer.
enum Waiter {
    Answer(oneshot::Sender<Result<Value>>),
    Snapshot(oneshot::Sender<Option<Vec<u8>>>),
}

#[derive(Default)]
struct State {
    /// The kind of each group a plugin was told of.
    kind_of: HashMap<Bytes, String>,
    /// The last id this client gave a request to a plugin.
    asked: u64,
    waiting: HashMap<(String, u64), Waiter>,
    /// Files waited for, by hash.
    files: Vec<([u8; 32], oneshot::Sender<()>)>,
    /// What plugins show of their groups in `groups`.
    infos: HashMap<Bytes, Value>,
    /// The groups whose `leave` was answered pending, until another member's summary holds it.
    leaving: HashSet<Bytes>,
    /// What a group's kind is told before it opens, as a joiner's state may come: its latest state and synced of each
    /// member.
    held: HashMap<Bytes, Vec<Value>>,
    /// The invite secrets this session is joining by.
    joining: HashSet<Vec<u8>>,
}

impl State {
    fn wait_for(&mut self, kind: &str, waiter: Waiter) -> u64 {
        self.asked += 1;
        self.waiting.insert((kind.to_owned(), self.asked), waiter);
        self.asked
    }
}

/// What another member holds and read of a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub member: Member,
    pub held: Ranges,
    pub read: Ranges,
}

/// What each member but `me` holds and read: as its latest summary shows, unless it is away, and as the read ranges of
/// its chat messages show; what it read it holds.
pub fn receipts(members: &[Member], me: &Bytes, heard: &[Heard], away: &[Member], messages: &[Message]) -> Vec<Receipt> {
    let others = members.iter().filter(|member| member.key != *me);
    others
        .map(|member| {
            let summary = heard.iter().find(|heard| heard.member.key == member.key);
            let chats = messages.iter().filter(|message| message.sender.key == member.key);
            let said = chats.filter_map(|message| serde_json::from_value::<ChatMessage>(message.payload.clone()).ok());
            let read = said.fold(summary.map(|heard| heard.read.clone()).unwrap_or_default(), |read, chat| read.union(&chat.read));
            let held = match summary {
                Some(heard) if !away.contains(member) => heard.held.union(&read),
                _ => read.clone(),
            };
            Receipt { member: member.clone(), held, read }
        })
        .collect()
}

struct Inner<P> {
    node: Node<P>,
    config: Config,
    access: Mutex<Access<P>>,
    plugins: Arc<dyn Plugins>,
    lines: tokio::sync::Mutex<mpsc::UnboundedReceiver<(String, Option<Value>)>>,
    state: Mutex<State>,
    events: mpsc::UnboundedSender<ClientEvent>,
    /// Held while a pass takes the adds for this device.
    taking: tokio::sync::Mutex<()>,
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
    pub fn new(
        node: Node<P>,
        config: Config,
        access: Access<P>,
        plugins: Arc<dyn Plugins>,
        lines: mpsc::UnboundedReceiver<(String, Option<Value>)>,
    ) -> (Self, mpsc::UnboundedReceiver<ClientEvent>) {
        let (events, told) = mpsc::unbounded_channel();
        let inner = Inner {
            node,
            config,
            access: Mutex::new(access),
            plugins,
            lines: tokio::sync::Mutex::new(lines),
            state: Mutex::default(),
            events,
            taking: tokio::sync::Mutex::new(()),
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

    /// Tells the plugins of its groups' kinds of the groups, as when the client starts.
    pub async fn start(&self) {
        let client = self.clone();
        n0_future::task::spawn(async move {
            for error in client.refresh_identity().await {
                client.warn(None, format!("refreshing identity claims: {error:#}"));
            }
        });
        for gid in self.inner.node.groups() {
            if self.inner.node.settings(&gid.0).is_ok_and(|s| s.kind != CHAT && s.kind != IDENTITY)
                && let Err(error) = self.open_kind(&gid, None).await
            {
                self.warn(Some(&gid), format!("{error:#}"));
            }
        }
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
            Request::Invite { group, kind, name, args, cwd, carry, membership, to, qr: _ } => {
                self.invite(group, kind, name, (args, cwd), carry, membership, to).await
            }
            Request::Join { target, args, cwd } => self.join(target, (args, cwd)).await,
            Request::Add { target, group } => self.add(&target, group).await,
            Request::Deliver { add } => {
                self.devices()?.deliver(&add).await?;
                Ok(json!({}))
            }
            Request::Members { group } => {
                let gid = self.resolve(group)?;
                Ok(json!({ "group": b64(&gid.0), "kind": self.inner.node.settings(&gid.0)?.kind, "members": self.described_members(&gid)? }))
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

    #[allow(clippy::too_many_arguments)]
    async fn invite(
        &self,
        group: Option<String>,
        kind: String,
        name: Option<String>,
        args: (Vec<String>, String),
        carry: u32,
        membership: Option<String>,
        to: Option<String>,
    ) -> Result<Value> {
        let to = to.map(|to| URL_SAFE_NO_PAD.decode(&to).ok().filter(|id| id.len() == 32).map(Bytes).context("--to takes an identity's id, as `members` shows it")).transpose()?;
        let mut answer = json!({ "expires_in": INVITE_VALID / 1000 });
        let gid = match group {
            Some(group) => self.resolve(Some(group))?,
            None => {
                let membership = membership.map(|m| service(&m)).transpose()?.unwrap_or(self.inner.config.membership.clone());
                let settings = Settings { protocol: PROTOCOL, kind, name: name.unwrap_or_default(), carry, update: UPDATE, membership, public: None, rest: Default::default() };
                let (gid, opened) = self.create(settings, args).await?;
                merge(&mut answer, opened);
                gid
            }
        };
        let settings = self.inner.node.settings(&gid.0)?;
        answer["group"] = json!(b64(&gid.0));
        answer["kind"] = json!(settings.kind);
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
    /// that next acts for it, as a browser. It is refused while the group has a member of this identity on a device of
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
        let add = Add { device: key, session: session.clone(), group: gid.clone(), kind: settings.kind, name: settings.name, link: link.clone(), expires };
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
        let joined = self.join(link.to_owned(), (Vec::new(), String::new())).await;
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

    /// Joins the groups of the adds for this device, where this client's node is the device's own, as in a browser: as
    /// they come, and as it starts, one pass at a time. An add that fails stays, until it expires.
    pub async fn take_adds(&self) {
        let _taking = self.inner.taking.lock().await;
        let Access::Here(devices) = self.access() else { return };
        let pending = match devices.adds() {
            Ok(pending) => pending,
            Err(error) => return self.warn(None, format!("reading the adds for this device: {error:#}")),
        };
        for Pending { position, by, add } in pending {
            let taken = self.added(&add.link, &add.group, &by).await.and_then(|_| devices.take(position));
            if let Err(error) = taken {
                self.warn(None, format!("joining a group your device {by} added this one to: {error:#}"));
            }
        }
    }

    /// Makes a group, speaking as the device's identity if it has one, and tells its kind's plugin, with the arguments
    /// `invite` has for the kind and the directory they are relative to; returns its id and what the plugin answered.
    pub async fn create(&self, settings: Settings, (args, cwd): (Vec<String>, String)) -> Result<(Bytes, Value)> {
        let kind = settings.kind.clone();
        ensure!(
            kind == CHAT || self.inner.plugins.kinds().contains(&kind),
            "this session has no plugin for {kind} groups (letmeknow-kind-{kind})"
        );
        ensure!(args.is_empty() || kind != CHAT, "a chat takes no arguments");
        let gid = self.inner.node.create(settings, self.speaking_as().await?)?;
        if kind == CHAT {
            return Ok((gid, json!({})));
        }
        match self.open_kind(&gid, Some(("invite", args, cwd))).await {
            Ok(opened) => Ok((gid, opened)),
            Err(error) => {
                self.inner.node.leave(&gid.0).await?;
                self.drop_group(&gid).await?;
                Err(error)
            }
        }
    }

    async fn join(&self, link: String, args: (Vec<String>, String)) -> Result<Value> {
        let invite = Invite::parse(link.trim())?;
        // As the node's, which share one KeyPackage per invite.
        let key = invite.secret.to_vec();
        ensure!(self.state().joining.insert(key.clone()), "this session is joining that already: wait for that join to end");
        let joined = self.join_by(invite, args).await;
        self.state().joining.remove(&key);
        joined
    }

    async fn join_by(&self, invite: Invite, (args, cwd): (Vec<String>, String)) -> Result<Value> {
        if invite.device {
            self.devices()?.join(&invite).await?;
            return Ok(json!({ "device": "this device joined the identity" }));
        }
        let node = &self.inner.node;
        let gid = node.join(&invite, self.speaking_as().await?).await?.0;
        let settings = node.settings(&gid.0)?;
        let mut answer = json!({ "group": b64(&gid.0), "kind": settings.kind, "name": settings.name, "members": self.described_members(&gid)? });
        if settings.kind != CHAT {
            match self.open_kind(&gid, Some(("join", args, cwd))).await {
                Ok(opened) => merge(&mut answer, opened),
                Err(error) => {
                    // Unless it was left or removed meanwhile.
                    if node.groups().contains(&gid) {
                        node.leave(&gid.0).await?;
                    }
                    return Err(error);
                }
            }
        }
        Ok(answer)
    }

    async fn leave(&self, gid: &Bytes) -> Result<Value> {
        let gid = gid.clone();
        let Some(sent) = self.inner.node.leave(&gid.0).await? else {
            self.drop_group(&gid).await?;
            return Ok(json!({ "group": b64(&gid.0), "left": true }));
        };
        let mut answer = json!({ "group": b64(&gid.0), "left": true, "status": "another member commits the removal" });
        if sent.position.is_none() || !self.leave_held(&gid)? {
            self.state().leaving.insert(gid);
            answer["pending"] = json!(true);
        }
        Ok(answer)
    }

    /// Ends a group for everyone: removes the other members, and leaves it.
    pub async fn end(&self, gid: &Bytes) -> Result<Value> {
        self.inner.node.remove_others(&gid.0).await?;
        let mut answer = self.leave(gid).await?;
        answer["ended"] = json!(true);
        Ok(answer)
    }

    /// Whether another member's summary holds a `leave` of this client's in the group, or the session is out of the
    /// group already: removed, as its `leave` asked.
    fn leave_held(&self, gid: &Bytes) -> Result<bool> {
        let node = &self.inner.node;
        let held = || -> Result<bool> {
            let (only_here, me) = (node.only_here(&gid.0)?, node.key());
            let mut leaves = node.messages(&gid.0)?.into_iter().filter(|m| m.sender.key == me && m.payload["type"] == "leave");
            Ok(leaves.any(|leave| !only_here.contains(leave.position)))
        };
        match held() {
            Err(_) if !node.groups().contains(gid) => Ok(true),
            held => held,
        }
    }

    /// Lets go of a group the node has left: tells its kind's plugin, and the shell.
    async fn drop_group(&self, gid: &Bytes) -> Result<()> {
        let kind = {
            let mut st = self.state();
            st.infos.remove(gid);
            st.leaving.remove(gid);
            st.held.remove(gid);
            st.kind_of.remove(gid)
        };
        if let Some(kind) = kind {
            // Answered once the plugin let go of the group, so that a doc file it made is gone when `leave` returns.
            self.ask(&kind, json!({ "type": "gone", "group": b64(&gid.0) })).await?;
            if !self.state().kind_of.values().any(|k| *k == kind) {
                self.inner.plugins.stop(&kind);
            }
        }
        self.emit(ClientEvent::Gone { group: gid.clone() });
        self.inner.node.scrub()
    }

    fn groups(&self) -> Result<Value> {
        let node = &self.inner.node;
        let mut groups = Vec::new();
        for gid in node.groups() {
            let settings = node.settings(&gid.0)?;
            let mut group = json!({
                "group": b64(&gid.0), "kind": settings.kind, "members": node.members(&gid.0)?.len(), "carry": settings.carry,
                "membership": settings.membership, "epoch": node.epoch(&gid.0)?,
            });
            if !settings.name.is_empty() {
                group["name"] = json!(settings.name);
            }
            if let Some(info) = self.state().infos.get(&gid) {
                merge(&mut group, info.clone());
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
            let positions = node.only_here(&gid.0)?;
            let messages: HashMap<u64, Message> = node.messages(&gid.0)?.into_iter().map(|m| (m.position, m)).collect();
            let mut only_here: Vec<Value> = positions
                .iter()
                .map(|position| match messages.get(&position) {
                    Some(m) => json!({ "what": m.payload["type"], "id": hex::encode(&m.id.0), "position": position }),
                    None => json!({ "position": position }),
                })
                .collect();
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
            status["warning"] =
                json!(format!("{only_here_count} sends are held only by this session; keep it running until another member holds them"));
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

    /// Sends a chat message, with the positions this client read; returns its id and the answer to `send`.
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
            ensure!(node.message(id)?.is_some(), "unknown message {}", hex::encode(id));
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
            read: node.read(&gid.0)?,
            to: addressed.iter().map(|m| Bytes(Sha256::digest(&m.key.0)[..8].to_vec())).collect(),
            reply_to: chat.reply_to.map(|id| Bytes(id.to_vec())),
            urgent: chat.urgent,
            attachment: attachment.as_ref().map(|(_, a)| a.clone()),
            sent_at: Some(lmk_proto::clock::corrected()),
        };
        let sent = node.send(&gid.0, &serde_json::to_value(payload)?).await?;
        let id = sent.id.clone();
        let describer = self.describer(gid)?;
        let mut answer = sent_answer(&sent);
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

    /// Marks positions of a group read, as this client showed or printed them.
    pub fn mark_read(&self, gid: &Bytes, positions: &Ranges) -> Result<()> {
        let node = &self.inner.node;
        if positions.difference(&node.read(&gid.0)?).is_empty() {
            return Ok(());
        }
        node.mark_read(&gid.0, positions)
    }

    /// What each other member of a group holds and read (see `receipts`).
    pub fn receipts(&self, gid: &Bytes) -> Result<Vec<Receipt>> {
        let node = &self.inner.node;
        let (members, heard, away, messages) = (node.members(&gid.0)?, node.heard(&gid.0)?, node.away(&gid.0)?, node.messages(&gid.0)?);
        Ok(receipts(&members, &node.key(), &heard, &away, &messages))
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

    /// Takes an event of this client's node. Where the device's node is this node too, as in a browser, the devices
    /// kind takes its groups' events first.
    pub async fn event(&self, event: Event) {
        let event = match self.access() {
            Access::Here(devices) => {
                let Some(event) = devices.on(event) else { return };
                if let Some(changed) = Self::devices_changed(&devices, &event) {
                    let client = self.clone();
                    n0_future::task::spawn(async move {
                        for error in client.refresh_identity().await {
                            client.warn(None, format!("refreshing identity claims: {error:#}"));
                        }
                    });
                    return self.emit(changed);
                }
                if let Event::Logged { group } = &event
                    && devices.identity_of(&group.0).is_some()
                {
                    // A join waits on events, as a doc's state.
                    let client = self.clone();
                    n0_future::task::spawn(async move { client.take_adds().await });
                    return;
                }
                event
            }
            Access::Elsewhere(_) => event,
        };
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
            Event::Public { .. } | Event::Duties { .. } | Event::Logged { .. } => {}
            Event::Removed { group, by, .. } => {
                let by = by.map(|by| self.describe(&group, &by)).transpose()?;
                self.drop_group(&group).await?;
                self.emit(ClientEvent::Removed { group, by });
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
                let from = self.describe(&message.group, &message.sender)?;
                let (id, position, missing) = (hex::encode(&message.id.0), message.position, message.missing);
                self.emit(ClientEvent::Message { group: message.group, id, position, missing, from, payload: message.payload });
            }
            // No other kind holds messages.
            Event::Message(_) => {}
            Event::Live { group, sender, payload } => {
                let item = json!({ "type": "message", "from": self.describe(&group, &sender)?, "payload": payload });
                self.tell_plugin(&group, item)?;
            }
            Event::Lost(lost) => {
                let member = self.describe(&lost.group, &lost.member)?;
                let ids = lost.ids.iter().map(|id| hex::encode(&id.0)).collect();
                self.emit(ClientEvent::Lost { group: lost.group, member, positions: lost.positions, ids });
            }
            Event::Synced { group, member } => {
                let item = json!({ "type": "synced", "member": self.describe(&group, &member)? });
                self.tell_plugin(&group, item)?;
                self.emit(ClientEvent::Synced { group });
            }
            Event::Heard { group } => {
                if self.state().leaving.contains(&group) && self.leave_held(&group)? {
                    self.state().leaving.remove(&group);
                    self.emit(ClientEvent::LeaveHeld { group: group.clone() });
                }
                self.emit(ClientEvent::Heard { group });
            }
            Event::State { group, from, data } => {
                let item = json!({ "type": "state", "from": self.describe(&group, &from)?, "data": Bytes(data) });
                self.tell_plugin(&group, item)?;
            }
            Event::Snapshot { group, reply } => {
                let kind = self.state().kind_of.get(&group).cloned();
                if let Some(kind) = kind {
                    let id = self.state().wait_for(&kind, Waiter::Snapshot(reply));
                    self.inner.plugins.send(&kind, &json!({ "type": "snapshot", "id": id, "group": b64(&group.0) }))?;
                }
            }
            Event::Sent { group, id, answered, position } => {
                self.emit(ClientEvent::Sent { group, id: hex::encode(&id.0), answered: hex::encode(&answered.0), position })
            }
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

    /// This client's groups but identity groups, as its identity's devices hear of them: each one's id, name and kind,
    /// and its other members as they show.
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
            groups.push(SessionGroup { session: None, group: gid, name: settings.name, kind: settings.kind, members });
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

    // Kinds' plugins.

    /// Tells a group's kind's plugin of the group, starting the plugin if need be, with the arguments of `invite` or
    /// `join` and the directory they are relative to. Returns the plugin's answer, when it is asked one.
    async fn open_kind(&self, gid: &Bytes, args: Option<(&str, Vec<String>, String)>) -> Result<Value> {
        let settings = self.inner.node.settings(&gid.0)?;
        let kind = settings.kind.clone();
        if !self.inner.plugins.running().contains(&kind) {
            self.start_plugin(&kind).await?;
        }
        let me = self.describe_key(gid, &self.inner.node.key())?;
        let mut message = json!({ "type": "group", "group": b64(&gid.0), "settings": settings, "me": me });
        let (answer, answered) = oneshot::channel();
        // At once: the plugin hears of the group, then what was held for it, then what comes for it. A group let go of
        // while the plugin started is not told of, as letting go of it told the plugin nothing.
        let asked = {
            let mut st = self.state();
            ensure!(self.inner.node.groups().contains(gid), "{} is gone", b64(&gid.0));
            let asked = args.map(|(command, args, cwd)| {
                message["command"] = json!(command);
                message["args"] = json!(args);
                message["cwd"] = json!(cwd);
                let id = st.wait_for(&kind, Waiter::Answer(answer));
                message["id"] = json!(id);
                id
            });
            self.inner.plugins.send(&kind, &message)?;
            st.kind_of.insert(gid.clone(), kind.clone());
            for item in st.held.remove(gid).into_iter().flatten() {
                self.inner.plugins.send(&kind, &item)?;
            }
            asked
        };
        match asked {
            Some(id) => self.answered(&kind, id, answered).await,
            None => Ok(json!({})),
        }
    }

    /// Starts a kind's plugin, and waits until it answers `start`.
    async fn start_plugin(&self, kind: &str) -> Result<()> {
        let mut start = self.inner.plugins.start(kind)?;
        start["type"] = json!("start");
        start["kind"] = json!(kind);
        self.ask(kind, start).await?;
        Ok(())
    }

    /// Passes a command to a kind's plugin: `letmeknow <kind> <args>...`, run in `cwd`. The plugin's answer comes on
    /// the receiver, or an error once the plugin stops.
    pub async fn command(&self, kind: &str, args: Vec<String>, cwd: String) -> Result<oneshot::Receiver<Result<Value>>> {
        if !self.inner.plugins.running().iter().any(|running| running == kind) {
            self.start_plugin(kind).await?;
        }
        let (answer, answered) = oneshot::channel();
        let id = self.state().wait_for(kind, Waiter::Answer(answer));
        self.inner.plugins.send(kind, &json!({ "type": "command", "id": id, "args": args, "cwd": cwd }))?;
        Ok(answered)
    }

    /// Sends a plugin a message about one of its groups, if it has the group, or holds a state or synced till it does.
    fn tell_plugin(&self, gid: &Bytes, mut message: Value) -> Result<()> {
        message["group"] = json!(b64(&gid.0));
        let kinded = message["type"] != "message" && self.inner.node.settings(&gid.0).is_ok_and(|s| s.kind != CHAT && s.kind != IDENTITY);
        let mut st = self.state();
        match st.kind_of.get(gid) {
            Some(kind) => self.inner.plugins.send(kind, &message)?,
            None if kinded => {
                let held = st.held.entry(gid.clone()).or_default();
                held.retain(|item| item["type"] != message["type"] || item["member"]["fp"] != message["member"]["fp"]);
                held.push(message);
            }
            None => {}
        }
        Ok(())
    }

    /// Asks a plugin, and takes in what plugins write meanwhile, until it answers.
    async fn ask(&self, kind: &str, mut message: Value) -> Result<Value> {
        let (answer, answered) = oneshot::channel();
        let id = self.state().wait_for(kind, Waiter::Answer(answer));
        message["id"] = json!(id);
        self.inner.plugins.send(kind, &message)?;
        self.answered(kind, id, answered).await
    }

    async fn answered(&self, kind: &str, id: u64, mut answered: oneshot::Receiver<Result<Value>>) -> Result<Value> {
        let deadline = Instant::now() + ASK_WAIT;
        loop {
            // A line is taken in whole, even if the answer comes meanwhile.
            let next = async { Either::Left((&mut answered).await) }.or(async { Either::Right(self.next_line().await) });
            match timeout(deadline.saturating_duration_since(Instant::now()), next).await {
                Err(_) => {
                    self.state().waiting.remove(&(kind.to_owned(), id));
                    bail!("the {kind} plugin did not answer");
                }
                Ok(Either::Left(answer)) => return answer.map_err(|_| anyhow!("the {kind} plugin stopped"))?,
                Ok(Either::Right((from, line))) => Box::pin(self.plugin_line(from, line)).await,
            }
        }
    }

    /// The next line a plugin wrote, for `plugin_line`.
    pub async fn next_line(&self) -> (String, Option<Value>) {
        match self.inner.lines.lock().await.recv().await {
            Some(line) => line,
            None => std::future::pending().await,
        }
    }

    /// Brings every plugin into step, as before what the user acts on is shown, and before a command.
    pub async fn sync_kinds(&self) {
        for kind in self.inner.plugins.running() {
            if let Err(error) = self.ask(&kind, json!({ "type": "sync" })).await {
                self.warn(None, format!("{error:#}"));
            }
        }
    }

    /// Tells a plugin that its event with `key` of a group was shown.
    pub fn printed(&self, kind: &str, group: &str, key: &str) {
        self.inner.plugins.send(kind, &json!({ "type": "printed", "group": group, "key": key })).ok();
    }

    /// A line a plugin wrote, or `None` once it stopped, when it is started again if it ran steadily.
    pub async fn plugin_line(&self, kind: String, line: Option<Value>) {
        let Some(message) = line else {
            // What waits for its answers hears that it stopped.
            self.state().waiting.retain(|(of, _), _| *of != kind);
            if !self.inner.plugins.stopped(&kind) {
                self.warn(None, format!("the {kind} plugin stopped; it runs again once this session restarts"));
                return;
            }
            self.warn(None, format!("the {kind} plugin stopped; starting it again"));
            let restarted = async {
                self.start_plugin(&kind).await?;
                let gids: Vec<Bytes> = self.state().kind_of.iter().filter(|(_, k)| **k == kind).map(|(gid, _)| gid.clone()).collect();
                for gid in gids {
                    if let Err(error) = self.open_kind(&gid, None).await {
                        self.warn(Some(&gid), format!("{error:#}"));
                    }
                }
                anyhow::Ok(())
            };
            if let Err(error) = restarted.await {
                self.warn(None, format!("{error:#}"));
            }
            return;
        };
        if let Err(error) = self.carry_out(&kind, &message).await {
            match message.get("id") {
                Some(id) if message["type"] != "answer" => self.answer(&kind, id.clone(), Err(error)),
                _ => {
                    let gid = message["group"].as_str().and_then(|g| URL_SAFE_NO_PAD.decode(g).ok()).map(Bytes);
                    self.warn(gid.as_ref(), format!("the {kind} plugin: {error:#}"));
                }
            }
        }
    }

    /// Answers a plugin's request.
    fn answer(&self, kind: &str, id: Value, answer: Result<Value>) {
        let message = match answer {
            Ok(answer) => json!({ "type": "answer", "id": id, "answer": answer }),
            Err(error) => json!({ "type": "answer", "id": id, "error": format!("{error:#}") }),
        };
        if let Err(error) = self.inner.plugins.send(kind, &message) {
            self.warn(None, format!("{error:#}"));
        }
    }

    /// Carries out what a plugin asks, through its groups' channels.
    async fn carry_out(&self, kind: &str, message: &Value) -> Result<()> {
        let node = &self.inner.node;
        let group = || -> Result<Bytes> {
            let gid = Bytes(URL_SAFE_NO_PAD.decode(message["group"].as_str().context("no group")?)?);
            ensure!(self.state().kind_of.get(&gid).is_some_and(|k| k == kind), "not a {kind} group of this session");
            Ok(gid)
        };
        let to = message["to"].as_str();
        let id = message["id"].clone();
        match message["type"].as_str().unwrap_or_default() {
            "send" => node.send_live(&group()?.0, &message["payload"], to)?,
            // These take a while: they are answered without holding up the client.
            "spread" => {
                let (client, gid, kind) = (self.clone(), group()?, kind.to_owned());
                let link = FileLink::parse(message["link"].as_str().context("no link")?)?;
                n0_future::task::spawn(async move {
                    let holders = client.inner.node.holders(&gid.0, &link, SPREAD_WAIT).await;
                    let held_by = client.describer(&gid).map(|describer| json!({ "held_by": holders.iter().map(|m| describer.describe(m)).collect::<Vec<_>>() }));
                    client.answer(&kind, id, held_by);
                });
            }
            "add" => {
                let data = serde_json::from_value::<Bytes>(message["data"].clone())?.0;
                let link = node.add_file(&group()?.0, data).await?;
                self.answer(kind, id, Ok(json!({ "link": link.link() })));
            }
            "hold" => node.hold(&group()?.0, &serde_json::from_value::<Vec<String>>(message["links"].clone())?)?,
            "links" => node.set_links(&group()?.0, serde_json::from_value(message["links"].clone())?)?,
            "fetch" => {
                let (client, gid) = (self.clone(), group()?);
                let link = FileLink::parse(message["link"].as_str().context("no link")?)?;
                ensure!(node.linked(&gid.0).contains(&link), "the group does not link that file");
                let kind = kind.to_owned();
                n0_future::task::spawn(async move {
                    let fetched = client.fetched(&gid, &link).await.map(|data| json!({ "data": Bytes(data) }));
                    client.answer(&kind, id, fetched);
                });
            }
            "state" => {
                let data = serde_json::from_value::<Bytes>(message["data"].clone())?.0;
                node.hand_state(&group()?.0, to.context("a state goes to a member")?, data).await?;
            }
            "event" => {
                let gid = group()?;
                let event = message["event"].as_object().context("no event")?.clone();
                if event.get("type") == Some(&json!("warning")) {
                    self.warn(Some(&gid), event.get("text").and_then(Value::as_str).unwrap_or_default().to_owned());
                    return Ok(());
                }
                let key = message["key"].as_str().map(str::to_owned);
                self.emit(ClientEvent::Plugin { group: gid, kind: kind.to_owned(), event, wake: message["wake"] == true, key });
            }
            "info" => {
                let gid = group()?;
                self.state().infos.insert(gid, message["info"].clone());
            }
            "answer" => {
                let waiter = self.state().waiting.remove(&(kind.to_owned(), id.as_u64().unwrap_or_default()));
                match waiter {
                    Some(Waiter::Answer(answered)) => drop(answered.send(match &message["error"] {
                        Value::Null => Ok(message["answer"].clone()),
                        error => Err(anyhow!("{}", error.as_str().unwrap_or_default())),
                    })),
                    Some(Waiter::Snapshot(reply)) => {
                        drop(reply.send(message["answer"]["data"].as_str().and_then(|data| URL_SAFE_NO_PAD.decode(data).ok())))
                    }
                    None => {}
                }
            }
            // A newer plugin's: a request is refused, anything else skipped.
            _ if id.is_null() => {}
            other => bail!("unknown request {other:?}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn chat(sender: u8, position: u64, read: Ranges) -> Message {
        let payload = serde_json::to_value(ChatMessage { content: String::new(), read, to: Vec::new(), reply_to: None, urgent: false, attachment: None, sent_at: None });
        Message {
            id: Bytes(vec![sender, position as u8]),
            group: Bytes::default(),
            epoch: 0,
            position,
            at: 0,
            sender: member(sender),
            payload: payload.unwrap(),
            missing: Vec::new(),
        }
    }

    #[test]
    fn a_member_holds_what_its_summary_shows_but_away_and_read_what_its_messages_say_too() {
        let members = [member(1), member(2), member(3), member(4)];
        let heard = [
            Heard { member: member(2), held: Ranges::range(1, 10), read: Ranges::range(1, 4), at: 0 },
            Heard { member: member(3), held: Ranges::range(1, 10), read: Ranges::range(1, 2), at: 0 },
        ];
        let messages = [chat(2, 11, Ranges::range(1, 6)), chat(4, 12, Ranges::range(1, 3))];
        let got = receipts(&members, &Bytes(vec![1]), &heard, &[member(3)], &messages);
        let got: Vec<(u8, Ranges, Ranges)> = got.into_iter().map(|r| (r.member.key.0[0], r.held, r.read)).collect();
        assert_eq!(
            got,
            [
                (2, Ranges::range(1, 10), Ranges::range(1, 6)),
                (3, Ranges::range(1, 2), Ranges::range(1, 2)),
                (4, Ranges::range(1, 3), Ranges::range(1, 3)),
            ]
        );
    }
}
