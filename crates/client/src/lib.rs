//! The client core: what one member does on top of its lmk-node session, alike in every client. It answers requests,
//! turns the node's events into `ClientEvent`s with members described as this client knows them, introduces joiners and
//! records the contact an invite was made for, records groups' openings in the devices groups, has its device certify
//! it for the identities it speaks as, and hosts kinds' plugins. A shell gives it storage (the node's provider), a network, the device's node, the plugins'
//! transport, and shows or prints what it tells.

mod describe;
mod request;

pub use describe::{AddedBy, Described, Describer, Introduced, Introduction, Known, Standing, answers};
pub use n0_future::boxed::BoxFuture;
pub use request::{ContactsOp, IdentityOp, Request};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lmk_core::contacts::{self, Contact};
use lmk_core::device::Device;
use lmk_core::provider::Provider;
use lmk_node::devices::Devices;
use lmk_node::{Event, Heard, INVITE_VALID, Item, Member, Message, Node};
use lmk_proto::Bytes;
use lmk_proto::ranges::Ranges;
use lmk_proto::group::{Attachment, CHAT, Certificate, ChatMessage, Control, DEVICES, How, IdentityRef, Named, Opening, PROTOCOL, Service, Settings, UPDATE};
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
/// The node's record of the introductions not accepted yet.
const INTRODUCTIONS: &str = "client/introductions";

pub fn fp(key: &[u8]) -> String {
    hex::encode(&Sha256::digest(key)[..8])
}

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

/// A membership service from its address: `letmeknow.dev`, `<iroh key, hex>@<relay URL>`, or a folder's absolute path.
pub fn service(address: &str) -> Result<Service> {
    if address == "letmeknow.dev" {
        return Ok(letmeknow_dev());
    }
    if let Some((key, relay)) = address.split_once("@https://") {
        let key = Bytes(hex::decode(key).context("a service key is hex")?);
        return Ok(Service::Serve { key, relay: format!("https://{relay}"), addrs: Vec::new(), rest: Default::default() });
    }
    ensure!(is_folder(address), "a membership service is letmeknow.dev, <key>@<relay URL>, or a folder");
    Ok(Service::Folder(address.into()))
}

/// A membership address names a folder when it is a path, not a service at a relay.
pub fn is_folder(address: &str) -> bool {
    !address.contains("@https://") && (address.contains(['/', '\\']) || address.starts_with('.'))
}

pub struct Config {
    /// This session's name, fixed when it is created.
    pub name: String,
    pub device: Device,
    /// For the groups and identities it creates.
    pub membership: Service,
}

/// The device's node, which keeps its identities, contacts and openings, and certifies its sessions.
pub enum Access<P> {
    /// It runs here: the devices kind on it.
    Here(Devices<P>),
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
    /// The device's name; none as 0.12.1 published it.
    #[serde(default)]
    pub device: Option<String>,
    pub identities: Vec<(IdentityRef, String)>,
    /// This device's key on each identity, by identity id.
    pub keys: Vec<(Bytes, Bytes)>,
    pub contacts: Vec<(Bytes, Contact)>,
    pub openings: Vec<Opening>,
}

impl DeviceState {
    pub fn of<P: Provider + Send + 'static>(devices: &Devices<P>) -> Self {
        DeviceState {
            device: devices.name(),
            identities: devices.identities(),
            keys: devices.identities().into_iter().filter_map(|(identity, _)| Some((identity.id.clone(), devices.key(&identity.id.0).ok()?))).collect(),
            contacts: devices.contacts(),
            openings: devices.openings(),
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
    Introduced { group: Bytes, by: Described, identity: Named, how: How },
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
    /// The devices of one of this device's identities changed.
    Devices { identity: Bytes },
    Warning { group: Option<Bytes>, text: String },
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
    /// The kinds whose groups carry chat too, as their plugins said when they started.
    chat_kinds: HashSet<String>,
    /// The last position of each group's log handed to its plugin, once the plugin follows the log.
    handed: HashMap<Bytes, u64>,
    /// The groups whose `leave` was answered pending, until another member's summary holds it.
    leaving: HashSet<Bytes>,
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

    fn access(&self) -> Access<P> {
        self.inner.access.lock().unwrap().clone()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap()
    }

    fn emit(&self, event: ClientEvent) {
        self.inner.events.send(event).ok();
    }

    pub fn warn(&self, group: Option<&Bytes>, text: String) {
        self.emit(ClientEvent::Warning { group: group.cloned(), text });
    }

    /// Tells the plugins of its groups' kinds of the groups, as when the client starts.
    pub async fn start(&self) {
        for gid in self.inner.node.groups() {
            if self.inner.node.settings(&gid.0).is_ok_and(|s| s.kind != CHAT && s.kind != DEVICES)
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

    /// The devices kind, where the device's node runs here.
    fn devices(&self) -> Result<Devices<P>> {
        match self.access() {
            Access::Here(devices) => Ok(devices),
            Access::Elsewhere(_) => bail!("the device's node runs elsewhere"),
        }
    }

    /// This client: its name and fingerprint, its device, and the device's identities, each with the device's key on it.
    pub fn me(&self) -> Result<Value> {
        let device = &self.inner.config.device;
        let state = self.device_state()?;
        let key = |id: &Bytes| state.keys.iter().find(|(of, _)| of == id).map(|(_, key)| key.clone());
        let identities: Vec<Value> =
            state.identities.iter().map(|(identity, name)| json!({ "id": identity.id, "name": name, "device": key(&identity.id) })).collect();
        let fp = fp(&self.inner.node.key().0);
        let name = state.device.clone().unwrap_or_else(|| device.name.clone());
        Ok(json!({ "name": self.inner.config.name, "fp": fp, "device": { "name": name }, "identities": identities }))
    }

    /// Answers a request; one only the device's node answers goes to it where it runs elsewhere.
    pub async fn request(&self, request: Request) -> Result<Value> {
        if request.for_device()
            && let Access::Elsewhere(remote) = self.access()
        {
            return remote.request(request).await;
        }
        match request {
            Request::Invite { group, kind, name, args, cwd, carry, membership, as_, for_, to, qr: _, identity } => {
                self.invite(group, kind, name, (args, cwd), carry, membership, as_, for_, to, identity).await
            }
            Request::Join { target, args, cwd, as_ } => self.join(target, (args, cwd), as_).await,
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
            Request::Leave { group } => self.leave(&self.resolve(group)?).await,
            Request::Name { group, name } => {
                let gid = self.resolve(group)?;
                let settings = self.inner.node.change_settings(&gid.0, |settings| Settings { name: name.clone(), ..settings }).await?;
                Ok(json!({ "group": b64(&gid.0), "settings": settings }))
            }
            Request::Open { group, close, identity } => {
                let gid = self.resolve(group)?;
                let (id, name) = self.identity_named(&identity)?;
                let settings = self
                    .inner
                    .node
                    .change_settings(&gid.0, |mut settings| {
                        if !close && settings.open.iter().any(|o| o.id == id && o.name == name) {
                            return settings;
                        }
                        settings.open.retain(|o| o.id != id);
                        if !close {
                            settings.open.push(Named { id: id.clone(), name: name.clone(), rest: Default::default() });
                        }
                        settings
                    })
                    .await?;
                self.refresh_opening(&gid).await?;
                Ok(json!({ "group": b64(&gid.0), "settings": settings }))
            }
            Request::Status => self.status(),
            Request::Identity { op: IdentityOp::Leave { identity } } => self.leave_identity(&identity).await,
            Request::Identity { op } => self.identity(op).await,
            Request::Contacts { op: None } => self.contacts(),
            Request::Contacts { op: Some(ContactsOp::Accept { identity, name }) } => self.accept(&identity, name).await,
            Request::Introduce { group, member, to } => self.introduce(group, &member, &to).await,
            Request::SetContact { identity, contact } => {
                self.set_contact(&identity, contact).await?;
                Ok(json!({}))
            }
            Request::SetOpening { identity, opening } => {
                self.devices()?.set_opening(&identity.0, opening).await?;
                Ok(json!({}))
            }
            Request::Certify { identity, key } => Ok(json!(self.devices()?.certify(&identity.0, &key.0)?)),
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
        as_: Option<String>,
        for_: Option<String>,
        to: Option<String>,
        identity: Option<String>,
    ) -> Result<Value> {
        let to = to.map(|to| self.contact(&to)).transpose()?;
        ensure!(
            for_.is_none() || !self.device_state()?.identities.is_empty(),
            "contacts belong to an identity: create one with `identity create`"
        );
        let mut answer = json!({ "expires_in": INVITE_VALID / 1000 });
        let link = match identity {
            Some(identity) => {
                let (identity, name) = self.own_identity(&identity)?;
                answer["identity"] = json!({ "id": identity.id, "name": name });
                self.devices()?.invite(&identity.id.0).await?
            }
            None => {
                let gid = match group {
                    Some(group) => self.resolve(Some(group))?,
                    None => {
                        let membership = membership.map(|m| service(&m)).transpose()?.unwrap_or(self.inner.config.membership.clone());
                        let settings =
                            Settings { protocol: PROTOCOL, kind, name: name.unwrap_or_default(), open: Vec::new(), carry, update: UPDATE, membership, rest: Default::default() };
                        let (gid, opened) = self.create(settings, as_, args).await?;
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
                self.inner.node.invite(&gid.0, for_.clone(), to.clone()).await?.link()
            }
        };
        if let Some(for_) = &for_ {
            answer["for"] = json!(for_);
        }
        if let Some(to) = &to {
            answer["to"] = json!(to);
        }
        answer["link"] = json!(link);
        Ok(answer)
    }

    /// Makes a group, speaking as `as_` or else the device's first identity, and tells its kind's plugin, with the
    /// arguments `invite` has for the kind and the directory they are relative to; returns its id and what the plugin
    /// answered.
    pub async fn create(&self, settings: Settings, as_: Option<String>, (args, cwd): (Vec<String>, String)) -> Result<(Bytes, Value)> {
        let kind = settings.kind.clone();
        ensure!(
            kind == CHAT || self.inner.plugins.kinds().contains(&kind),
            "this session has no plugin for {kind} groups (letmeknow-kind-{kind})"
        );
        ensure!(args.is_empty() || kind != CHAT, "a chat takes no arguments");
        let as_ = self.speaking_as(as_).await?;
        let gid = self.inner.node.create(settings, as_)?;
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

    async fn join(&self, target: String, (args, cwd): (Vec<String>, String), as_: Option<String>) -> Result<Value> {
        if let Ok(invite) = Invite::parse(target.trim())
            && invite.device
        {
            self.devices()?.join(&invite).await?;
            return Ok(json!({ "device": "this device joined the identity" }));
        }
        let as_ = self.speaking_as(as_).await?;
        let node = &self.inner.node;
        let gid = if target.contains('#') {
            node.join(&Invite::parse(target.trim())?, as_).await?.0
        } else {
            let opening = self.device_state()?.openings.into_iter().find(|o| b64(&o.group.0) == target || o.name == target);
            let opening = opening.context("expected an invite link, or the id or name of a group open to your identity")?;
            let identity = as_.context("joining a group open to your identity needs one: this device is on none")?;
            node.join_open(&opening, identity).await?
        };
        let settings = node.settings(&gid.0)?;
        let mut answer = json!({ "group": b64(&gid.0), "kind": settings.kind, "name": settings.name, "members": self.described_members(&gid)? });
        if settings.kind != CHAT {
            match self.open_kind(&gid, Some(("join", args, cwd))).await {
                Ok(opened) => merge(&mut answer, opened),
                Err(error) => {
                    node.leave(&gid.0).await?;
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
            st.handed.remove(gid);
            st.leaving.remove(gid);
            st.kind_of.remove(gid)
        };
        if let Some(kind) = kind {
            // Answered once the plugin let go of the group, so that a doc file it made is gone when `leave` returns.
            self.ask(&kind, json!({ "type": "gone", "group": b64(&gid.0) })).await?;
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
            if !settings.open.is_empty() {
                group["open"] = json!(settings.open);
            }
            if let Some(info) = self.state().infos.get(&gid) {
                merge(&mut group, info.clone());
            }
            groups.push(group);
        }
        let joined = node.groups();
        for opening in self.device_state()?.openings {
            if !joined.contains(&opening.group) && node.kinds().contains(&opening.kind) {
                groups.push(json!({ "group": b64(&opening.group.0), "kind": opening.kind, "name": opening.name, "joined": false }));
            }
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
            let mut group = json!({ "group": b64(&gid.0), "online": online, "away": away, "only_here": only_here });
            if let Some(name) = Some(node.settings(&gid.0)?.name).filter(|n| !n.is_empty()) {
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

    /// Whether a group carries chat: a chat, or a group of a kind whose plugin says its groups do.
    pub fn chats(&self, gid: &Bytes) -> bool {
        self.inner.node.settings(&gid.0).is_ok_and(|s| s.kind == CHAT || self.state().chat_kinds.contains(&s.kind))
    }

    /// The group carrying chat a request acts on: the one it names, or else the client's one such group.
    pub fn chat(&self, group: Option<String>) -> Result<Bytes> {
        if group.is_some() {
            let gid = self.resolve(group)?;
            ensure!(self.chats(&gid), "{} carries no chat", b64(&gid.0));
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
                answer["attachment"] = json!({ "pending": true, "warning": "no other member holds the file yet; it is available only while this session runs" });
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
                    return self.emit(changed);
                }
                event
            }
            Access::Elsewhere(_) => event,
        };
        let group = event.group().filter(|_| !matches!(event, Event::Warning { .. })).cloned();
        if let Err(error) = self.on(event).await {
            self.warn(group.as_ref(), format!("{error:#}"));
        }
    }

    /// Takes an event of the device's node, where it is not this client's node: the devices kind takes its groups'
    /// events, and of the rest only warnings concern the user.
    pub fn device_event(&self, devices: &Devices<P>, event: Event) {
        let Some(event) = devices.on(event) else { return };
        if let Some(changed) = Self::devices_changed(devices, &event) {
            self.emit(changed);
        } else if let Event::Warning { text, .. } = event {
            self.warn(None, format!("this device: {text}"));
        }
    }

    /// A device joined or left one of this device's identities.
    fn devices_changed(devices: &Devices<P>, event: &Event) -> Option<ClientEvent> {
        let (Event::Joined { group, .. } | Event::Left { group, .. }) = event else { return None };
        Some(ClientEvent::Devices { identity: devices.identity(&group.0)?.id })
    }

    async fn on(&self, event: Event) -> Result<()> {
        let node = &self.inner.node;
        match event {
            Event::Joined { group, member, by, how, introduces, label } => {
                let describer = self.describer(&group)?;
                let (member_described, by) = (describer.describe(&member), describer.describe(&by));
                self.emit(ClientEvent::Joined { group: group.clone(), member: member_described, by, how: how.clone() });
                if introduces {
                    self.introduce_joiner(&group, &member, how, label).await?;
                }
                self.refresh_opening(&group).await?;
            }
            Event::Left { group, member, by } => {
                let describer = self.describer(&group)?;
                self.emit(ClientEvent::Left { group: group.clone(), member: describer.describe(&member), by: describer.describe(&by) });
                self.refresh_opening(&group).await?;
            }
            Event::Revoked { group, removed, added } => {
                let describer = self.describer(&group)?;
                let (removed, added) = (removed.iter().map(|m| describer.describe(m)).collect(), added.iter().map(|m| describer.describe(m)).collect());
                self.emit(ClientEvent::Revoked { group, removed, added });
            }
            Event::Keys { .. } | Event::Duties { .. } => {}
            Event::Removed { group, by } => {
                let by = by.map(|by| self.describe(&group, &by)).transpose()?;
                self.drop_group(&group).await?;
                self.emit(ClientEvent::Removed { group, by });
            }
            Event::Settings { group, settings, by } => {
                let by = self.describe(&group, &by)?;
                self.emit(ClientEvent::Settings { group: group.clone(), settings, by });
                self.refresh_opening(&group).await?;
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
            Event::Message(message) => {
                let from = self.describe(&message.group, &message.sender)?;
                let item = json!({ "type": "message", "id": hex::encode(&message.id.0), "position": message.position, "from": from, "payload": message.payload, "held": true });
                self.tell_plugin(&message.group, item)?;
            }
            Event::Live { group, sender, payload } => {
                let item = json!({ "type": "message", "from": self.describe(&group, &sender)?, "payload": payload, "held": false });
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
            Event::Logged { group } => self.hand_entries(&group)?,
            Event::Snapshot { group, reply } => {
                let kind = self.state().kind_of.get(&group).cloned();
                if let Some(kind) = kind {
                    let id = self.wait_for(&kind, Waiter::Snapshot(reply));
                    self.inner.plugins.send(&kind, &json!({ "type": "snapshot", "id": id, "group": b64(&group.0) }))?;
                }
            }
            Event::Introduced { group, by, identity, name, how } => self.introduced(&group, &by, identity, name, how)?,
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

    // Members, identities and contacts.

    /// What describes a group's members, gathered once for many.
    pub fn describer(&self, gid: &Bytes) -> Result<Describer> {
        let DeviceState { identities, contacts, .. } = self.device_state()?;
        Ok(Describer {
            me: self.inner.node.key(),
            name: self.inner.config.name.clone(),
            identities,
            contacts,
            introductions: self.introductions()?,
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

    fn introductions(&self) -> Result<Vec<Introduction>> {
        let record = self.inner.node.record(INTRODUCTIONS)?;
        Ok(record.map(|record| serde_json::from_slice(&record)).transpose()?.unwrap_or_default())
    }

    /// Changes the introductions not accepted yet.
    fn change_introductions(&self, change: impl FnOnce(&mut Vec<Introduction>)) -> Result<()> {
        let _st = self.state();
        let mut introductions = self.introductions()?;
        change(&mut introductions);
        self.inner.node.put_record(INTRODUCTIONS, &serde_json::to_vec(&introductions)?)
    }

    /// Records an introduction, in place of the introducer's earlier one of the same identity.
    pub fn add_introduction(&self, introduction: Introduction) -> Result<()> {
        self.change_introductions(|introductions| {
            introductions.retain(|i| i.identity != introduction.identity || i.by.fp != introduction.by.fp);
            introductions.push(introduction);
        })
    }

    fn introduced(&self, gid: &Bytes, by: &Member, identity: IdentityRef, name: String, how: How) -> Result<()> {
        let sender = self.describe(gid, by)?;
        let state = self.device_state()?;
        let own = state.identities.iter().any(|(own, _)| own.id == identity.id);
        let contact = state.contacts.iter().any(|(id, _)| *id == identity.id);
        if !own && !contact {
            let by_id = by.identity.as_ref().map_or_else(|| by.key.clone(), |claim| claim.identity.id.clone());
            self.add_introduction(Introduction { identity: identity.id.clone(), name: name.clone(), by: sender.clone(), by_id })?;
        }
        self.emit(ClientEvent::Introduced { group: gid.clone(), by: sender, identity: Named { id: identity.id, name, rest: Default::default() }, how });
        Ok(())
    }

    /// A member came in by this client's invite, or was admitted by it to an open group: it tells the group who the
    /// member is to it, and the member of an invite meant for someone becomes that contact.
    async fn introduce_joiner(&self, gid: &Bytes, member: &Member, how: How, label: Option<String>) -> Result<()> {
        let Some(claim) = member.identity.clone().filter(|claim| claim.error.is_none()) else { return Ok(()) };
        if let Some(label) = &label {
            let contact = Contact { name: label.clone(), how: contacts::How::Verified, by: None, at: lmk_node::now(), rest: Default::default() };
            self.set_contact(&claim.identity.id, contact).await?;
        }
        let name = match label {
            Some(label) => label,
            None => self.describer(gid)?.display_name(&claim),
        };
        let introduce = Control::Introduce { identity: claim.identity, name, how, to: Vec::new() };
        self.inner.node.send(&gid.0, &serde_json::to_value(introduce)?).await?;
        Ok(())
    }

    /// Records, in the devices group of each of this device's identities the group is open to, the group's opening.
    async fn refresh_opening(&self, gid: &Bytes) -> Result<()> {
        let Ok(settings) = self.inner.node.settings(&gid.0) else { return Ok(()) };
        for (identity, _) in self.device_state()?.identities {
            if settings.open.iter().any(|named| named.id == identity.id) {
                let opening = self.inner.node.opening(&gid.0)?;
                match self.access() {
                    Access::Here(devices) => devices.set_opening(&identity.id.0, opening).await?,
                    Access::Elsewhere(remote) => drop(remote.request(Request::SetOpening { identity: identity.id, opening }).await?),
                }
            }
        }
        Ok(())
    }

    async fn set_contact(&self, identity: &Bytes, contact: Contact) -> Result<()> {
        match self.access() {
            Access::Here(devices) => devices.set_contact(&identity.0, contact).await,
            Access::Elsewhere(remote) => remote.request(Request::SetContact { identity: identity.clone(), contact }).await.map(drop),
        }
    }

    /// Leaves the groups it speaks as an identity in that its device is no longer on. Returns what failed.
    pub async fn leave_identities_left(&self) -> Vec<anyhow::Error> {
        let Ok(state) = self.device_state() else { return Vec::new() };
        let mut failed = Vec::new();
        for identity in self.inner.node.spoken() {
            // A state that names the device was published by a device's node; none is published before one first runs.
            if state.device.is_some()
                && !state.identities.iter().any(|(own, _)| own.id == identity.id)
                && let Err(error) = self.leave_as(&identity.id).await
            {
                failed.push(error);
            }
        }
        failed
    }

    /// Takes this device off an identity, once this client left the groups it speaks as it in, as the device's node
    /// leaves those of its own client.
    async fn leave_identity(&self, identity: &str) -> Result<Value> {
        let (identity, _) = self.own_identity(identity)?;
        let left = self.leave_as(&identity.id).await?;
        let ended = match self.access() {
            Access::Here(devices) => devices.leave(&identity.id.0).await?,
            Access::Elsewhere(remote) => {
                let request = Request::Identity { op: IdentityOp::Leave { identity: b64(&identity.id.0) } };
                remote.request(request).await?["ended"] == true
            }
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

    /// The identity a new membership speaks as, the one named or else the device's first, with the device's certificate
    /// of this client.
    async fn speaking_as(&self, as_: Option<String>) -> Result<Option<Certificate>> {
        let identity = match as_ {
            Some(as_) => Some(self.own_identity(&as_)?.0),
            None => self.device_state()?.identities.into_iter().next().map(|(identity, _)| identity),
        };
        let Some(identity) = identity else { return Ok(None) };
        let key = self.inner.node.key();
        Ok(Some(match self.access() {
            Access::Here(devices) => devices.certify(&identity.id.0, &key.0)?,
            Access::Elsewhere(remote) => serde_json::from_value(remote.request(Request::Certify { identity: identity.id, key }).await?)?,
        }))
    }

    /// An identity this device is on, by id or name.
    fn own_identity(&self, name: &str) -> Result<(IdentityRef, String)> {
        let identities = self.device_state()?.identities;
        identities
            .into_iter()
            .find(|(identity, own)| b64(&identity.id.0) == name || own == name)
            .with_context(|| format!("this device is on no identity {name}"))
    }

    /// An identity named by id or name: one of this device's own, or a contact.
    fn identity_named(&self, name: &str) -> Result<(Bytes, String)> {
        if let Ok((identity, own)) = self.own_identity(name) {
            return Ok((identity.id, own));
        }
        let id = self.contact(name)?;
        let (_, contact) = self.device_state()?.contacts.into_iter().find(|(cid, _)| *cid == id).expect("found by contact");
        Ok((id, contact.name))
    }

    fn contact(&self, name: &str) -> Result<Bytes> {
        let contacts = self.device_state()?.contacts;
        let contact = contacts.iter().find(|(id, c)| b64(&id.0) == name || c.name.eq_ignore_ascii_case(name));
        Ok(contact.with_context(|| format!("no contact {name}; `contacts` lists them"))?.0.clone())
    }

    async fn identity(&self, op: IdentityOp) -> Result<Value> {
        let devices = self.devices()?;
        match op {
            IdentityOp::Create { name, membership } => {
                let membership = membership.map(|m| service(&m)).transpose()?.unwrap_or(self.inner.config.membership.clone());
                let identity = devices.create(&name, membership).await?;
                Ok(json!({ "identity": identity.id, "name": name }))
            }
            IdentityOp::List => {
                let mut identities = Vec::new();
                for (identity, name) in devices.identities() {
                    let me = devices.key(&identity.id.0)?;
                    let listed = devices.devices(&identity.id.0)?;
                    let listed: Vec<Value> = listed.iter().map(|(key, name)| json!({ "key": key, "name": name, "you": *key == me })).collect();
                    identities.push(json!({ "identity": identity.id, "name": name, "devices": listed }));
                }
                Ok(json!({ "identities": identities }))
            }
            IdentityOp::Rename { name } => {
                devices.rename(&name).await?;
                Ok(json!({ "device": { "name": name } }))
            }
            IdentityOp::Leave { .. } => unreachable!("a client leaves an identity itself"),
            IdentityOp::Remove { identity, device: removed } => {
                let identities = devices.identities();
                let identity = match (identity, &identities[..]) {
                    (Some(identity), _) => self.own_identity(&identity)?.0,
                    (None, [(only, _)]) => only.clone(),
                    (None, _) => bail!("pass --identity: this device is on {} identities", identities.len()),
                };
                let listed = devices.devices(&identity.id.0)?;
                let (key, _) = listed.iter().find(|(key, name)| b64(&key.0) == removed || *name == removed).context("no such device")?;
                devices.remove(&identity.id.0, &key.0).await?;
                // This client's groups lose the device's sessions too, once it shows them the new key.
                self.inner.node.read_key_log(&identity).await?;
                Ok(json!({ "identity": identity.id, "removed": key }))
            }
        }
    }

    fn contacts(&self) -> Result<Value> {
        let contacts = self.device_state()?.contacts;
        let listed: Vec<Value> = contacts
            .iter()
            .map(|(id, c)| {
                let mut contact = json!({ "identity": id, "name": c.name, "how": c.how });
                if let Some(by) = &c.by {
                    contact["by"] = json!(contacts.iter().find(|(i, _)| i == by).map_or_else(|| b64(&by.0), |(_, i)| i.name.clone()));
                }
                contact
            })
            .collect();
        let introductions: Vec<Value> =
            self.introductions()?.into_iter().map(|i| json!({ "identity": i.identity, "name": i.name, "by": i.by })).collect();
        Ok(json!({ "contacts": listed, "introductions": introductions }))
    }

    async fn accept(&self, identity: &str, name: Option<String>) -> Result<Value> {
        let id = Bytes(URL_SAFE_NO_PAD.decode(identity).context("expected an identity id")?);
        let introduction = self.introductions()?.into_iter().find(|i| i.identity == id).context("no introduction of that identity")?;
        let contact = Contact { name: name.unwrap_or(introduction.name), how: contacts::How::Introduced, by: Some(introduction.by_id), at: lmk_node::now(), rest: Default::default() };
        self.set_contact(&id, contact.clone()).await?;
        self.change_introductions(|introductions| introductions.retain(|i| i.identity != id))?;
        Ok(json!({ "identity": id, "name": contact.name, "how": contact.how }))
    }

    async fn introduce(&self, group: Option<String>, member: &str, to: &str) -> Result<Value> {
        let gid = self.resolve(group)?;
        let introduced = self.member(&gid, member)?;
        let to = self.member(&gid, to)?;
        let described = self.describe(&gid, &introduced)?;
        let (Some(claim), Some(known)) = (introduced.identity.filter(|c| c.error.is_none()), described.identity) else {
            bail!("that member speaks as no verified identity")
        };
        ensure!(known.how != Standing::Unknown, "you can introduce only your contacts and your own identities");
        let to_fp = Bytes(Sha256::digest(&to.key.0)[..8].to_vec());
        let payload = Control::Introduce { identity: claim.identity.clone(), name: known.name.clone(), how: How::Introduce, to: vec![to_fp] };
        let sent = self.inner.node.send(&gid.0, &serde_json::to_value(payload)?).await?;
        Ok(json!({ "id": hex::encode(&sent.id.0), "group": b64(&gid.0), "identity": { "id": claim.identity.id, "name": known.name }, "to": self.describe(&gid, &to)? }))
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
        self.state().kind_of.insert(gid.clone(), kind.clone());
        let me = self.describe_key(gid, &self.inner.node.key())?;
        let mut message = json!({ "type": "group", "group": b64(&gid.0), "settings": settings, "me": me });
        let Some((command, args, cwd)) = args else {
            self.inner.plugins.send(&kind, &message)?;
            return Ok(json!({}));
        };
        message["command"] = json!(command);
        message["args"] = json!(args);
        message["cwd"] = json!(cwd);
        self.ask(&kind, message).await
    }

    /// Starts a kind's plugin, which answers `start` with what its groups carry besides its own content.
    async fn start_plugin(&self, kind: &str) -> Result<()> {
        let mut start = self.inner.plugins.start(kind)?;
        start["type"] = json!("start");
        start["kind"] = json!(kind);
        if self.ask(kind, start).await?["chat"] == true {
            self.state().chat_kinds.insert(kind.to_owned());
        }
        Ok(())
    }

    /// Hands a group's plugin its held messages and the losses, in log order, that it has not had.
    fn hand_entries(&self, gid: &Bytes) -> Result<()> {
        let mut st = self.state();
        let (Some(&after), Some(kind)) = (st.handed.get(gid), st.kind_of.get(gid).cloned()) else { return Ok(()) };
        let entries = self.inner.node.entries(&gid.0, after)?;
        if entries.is_empty() {
            return Ok(());
        }
        let describer = self.describer(gid)?;
        for item in entries {
            let position = item.position();
            let item = match item {
                Item::Entry(entry) => {
                    json!({ "type": "entry", "group": b64(&gid.0), "position": position, "id": hex::encode(&entry.id.0), "from": describer.describe(&entry.from), "payload": entry.payload })
                }
                Item::Lost(lost) => {
                    let ids: Vec<String> = lost.ids.iter().map(|id| hex::encode(&id.0)).collect();
                    json!({ "type": "lost", "group": b64(&gid.0), "position": position, "member": describer.describe(&lost.member), "positions": lost.positions, "ids": ids })
                }
            };
            self.inner.plugins.send(&kind, &item)?;
            st.handed.insert(gid.clone(), position);
        }
        Ok(())
    }

    /// Passes a command to a kind's plugin: `letmeknow <kind> <args>...`, run in `cwd`. The plugin's answer comes on
    /// the receiver, or an error once the plugin stops.
    pub async fn command(&self, kind: &str, args: Vec<String>, cwd: String) -> Result<oneshot::Receiver<Result<Value>>> {
        if !self.inner.plugins.running().iter().any(|running| running == kind) {
            self.start_plugin(kind).await?;
        }
        let (answer, answered) = oneshot::channel();
        let id = self.wait_for(kind, Waiter::Answer(answer));
        self.inner.plugins.send(kind, &json!({ "type": "command", "id": id, "args": args, "cwd": cwd }))?;
        Ok(answered)
    }

    /// Sends a plugin a message about one of its groups, if it has the group.
    fn tell_plugin(&self, gid: &Bytes, mut message: Value) -> Result<()> {
        let Some(kind) = self.state().kind_of.get(gid).cloned() else { return Ok(()) };
        message["group"] = json!(b64(&gid.0));
        self.inner.plugins.send(&kind, &message)
    }

    fn wait_for(&self, kind: &str, waiter: Waiter) -> u64 {
        let mut st = self.state();
        st.asked += 1;
        let id = st.asked;
        st.waiting.insert((kind.to_owned(), id), waiter);
        id
    }

    /// Asks a plugin, and takes in what plugins write meanwhile, until it answers.
    async fn ask(&self, kind: &str, mut message: Value) -> Result<Value> {
        let (answer, mut answered) = oneshot::channel();
        let id = self.wait_for(kind, Waiter::Answer(answer));
        message["id"] = json!(id);
        self.inner.plugins.send(kind, &message)?;
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
                    self.open_kind(&gid, None).await?;
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
            // The core orders a held send, and answers with its position once it counts, the plugin handed its
            // messages up to there: this takes a while, answered without holding up the client.
            "send" if message["held"] == true => {
                let (client, gid, kind, payload) = (self.clone(), group()?, kind.to_owned(), message["payload"].clone());
                n0_future::task::spawn(async move {
                    let sent = async {
                        let sent = client.inner.node.send(&gid.0, &payload).await?;
                        client.hand_entries(&gid)?;
                        Ok(sent_answer(&sent))
                    };
                    let sent = sent.await;
                    match sent {
                        Ok(sent) if !id.is_null() => client.answer(&kind, id, Ok(sent)),
                        Err(error) if !id.is_null() => client.answer(&kind, id, Err(error)),
                        Err(error) => client.warn(Some(&gid), format!("the {kind} plugin's send: {error:#}")),
                        Ok(_) => {}
                    }
                });
            }
            "send" => node.send_live(&group()?.0, &message["payload"], to)?,
            "log" => {
                let gid = group()?;
                let after = message["after"].as_u64();
                node.follow_log(&gid.0, after)?;
                if let Some(after) = after {
                    self.state().handed.insert(gid.clone(), after);
                    self.hand_entries(&gid)?;
                }
            }
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
        let payload = serde_json::to_value(ChatMessage { content: String::new(), read, to: Vec::new(), reply_to: None, urgent: false, attachment: None });
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
