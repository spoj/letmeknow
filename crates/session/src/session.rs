//! The session process: it runs this session's node (and, holding the device's lock, the device's), hosts the plugins
//! of its groups' kinds, and prints what concerns the agent. Chat is its built-in kind. The session process that holds
//! the lock publishes the device's identities, contacts and openings to `device-state.json`, and answers the requests
//! only the device's node can on the command channel `device-endpoint`, both in `LETMEKNOW_HOME`; the device's other
//! session processes read the one and send such requests to the other.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD};
use lmk_core::contacts::{self, Contact};
use lmk_core::invite::Target;
use lmk_core::provider::SqliteProvider;
use lmk_node::{Claim, Event, Member, Node};
use lmk_proto::Bytes;
use lmk_proto::group::{Attachment, CHAT, ChatMessage, Control, How, IdentityRef, Named, Opening, PROTOCOL, Service, Settings};
use lmk_proto::links::{FileLink, Invite};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::cli::{ContactsOp, IdentityOp, Request, private_file};
use crate::Network;
use crate::kinds::Plugins;
use crate::policy::{Outbox, mentions, wakes};

/// How long a message waits for those it comes after.
pub const CAUSAL_WAIT: Duration = Duration::from_secs(300);
/// How long after starting what arrives counts as catching up.
const CATCH_UP_WINDOW: Duration = Duration::from_secs(3);
const FETCH_WAIT: Duration = Duration::from_secs(60);
const INVITE_TTL: u64 = 600;
/// How long the session waits for a plugin's answer.
const ASK_WAIT: Duration = Duration::from_secs(60);
/// How long a plugin's `spread` waits for a member online to hold its file.
const SPREAD_WAIT: Duration = Duration::from_secs(30);
/// How often a session process that does not act for the device tries its lock.
const DEVICE_RETRY: Duration = Duration::from_secs(10);

pub type SessionNode = Node<SqliteProvider>;

pub struct Config {
    pub handle: String,
    pub dir: PathBuf,
    pub name: String,
    pub hold: Duration,
    /// How long a message waits for those it comes after: `CAUSAL_WAIT`, but in tests.
    pub causal_wait: Duration,
    /// How long it keeps ended epochs' keys: `Window::default()`, but in tests.
    pub window: lmk_core::group::Window,
    pub keep_log: bool,
    /// For groups and identities this session creates.
    pub membership: Service,
    /// Where it looks for kinds' plugins, in order.
    pub plugins: Vec<PathBuf>,
}

/// What reaches the session process besides its nodes' events.
pub enum Inbound {
    Request(Box<Request>, oneshot::Sender<Value>),
    /// A warning of the device's node: of its events, only these concern the agent.
    DeviceWarning(String),
    /// A plugin's request that the session carried out in the background, to answer now.
    Done { kind: String, group: Bytes, id: Value, done: Result<Done> },
}

/// What a plugin's request carried out in the background came to.
pub enum Done {
    Appended(u64),
    Holders(Vec<Member>),
}

/// What the session process acting for the device publishes of it.
#[derive(Default, Serialize, Deserialize)]
struct DeviceState {
    identities: Vec<(IdentityRef, String)>,
    contacts: Vec<(Bytes, Contact)>,
    openings: Vec<Opening>,
}

impl DeviceState {
    fn of(device: &SessionNode) -> Result<Self> {
        Ok(DeviceState { identities: device.identities(), contacts: device.contacts()?, openings: device.openings() })
    }
}

/// A message waiting for the messages it comes after.
struct Waiting {
    deadline: Instant,
    gid: Bytes,
    id: [u8; 32],
    sender: Value,
    payload: Value,
}

/// A `fetch` waiting for its file.
struct Fetch {
    hash: [u8; 32],
    gid: Bytes,
    link: FileLink,
    name: Option<String>,
    deadline: Instant,
    reply: oneshot::Sender<Value>,
}

/// A plugin's `fetch` waiting for its file.
struct KindFetch {
    kind: String,
    id: Value,
    link: FileLink,
    deadline: Instant,
}

pub struct Session {
    db: Connection,
    node: SessionNode,
    /// The device's node, when this process holds the device's lock.
    device: Option<SessionNode>,
    lock: std::fs::File,
    device_retry: Instant,
    /// The device's state as last published.
    published: String,
    home: PathBuf,
    network: Network,
    config: Config,
    outbox: Outbox,
    waiting: Vec<Waiting>,
    fetches: Vec<Fetch>,
    catching_up: Option<Instant>,
    inbound: mpsc::UnboundedSender<Inbound>,
    plugins: Plugins,
    plugin_lines: mpsc::UnboundedReceiver<(String, Option<Value>)>,
    /// The kind of each group a plugin was told of.
    kind_of: HashMap<Bytes, String>,
    /// The last id this session gave a request to a plugin.
    asked: u64,
    /// Inviters' requests for a kind's state, by plugin and request id.
    snapshots: HashMap<(String, u64), oneshot::Sender<Option<Vec<u8>>>>,
    /// Commands a plugin is carrying out, by plugin and request id.
    commands: HashMap<(String, u64), oneshot::Sender<Value>>,
    kind_fetches: Vec<KindFetch>,
    /// What plugins show of their groups in `groups`.
    infos: HashMap<Bytes, Value>,
    /// The kinds whose groups carry chat too, as their plugins said when they started.
    chat_kinds: HashSet<String>,
    /// The last position of each group's kind log handed to its plugin, once the plugin follows the log.
    handed: HashMap<Bytes, u64>,
}

pub fn fp(key: &[u8]) -> String {
    hex::encode(&Sha256::digest(key)[..8])
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Adds an object's fields to another.
fn merge(into: &mut Value, from: Value) {
    if let (Some(into), Value::Object(from)) = (into.as_object_mut(), from) {
        into.extend(from);
    }
}

fn message_id(hex_id: &str) -> Result<[u8; 32]> {
    hex::decode(hex_id).ok().and_then(|id| id.try_into().ok()).with_context(|| format!("{hex_id} is not a message id"))
}

/// The file extension of an image the browser shows inline, by its first bytes: PNG, JPEG, GIF or WebP.
fn image_type(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0x89, b'P', b'N', b'G', ..] => Some("png"),
        [0xff, 0xd8, 0xff, ..] => Some("jpeg"),
        [b'G', b'I', b'F', b'8', ..] => Some("gif"),
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("webp"),
        _ => None,
    }
}

impl Session {
    pub async fn open(
        config: Config,
        node: SessionNode,
        home: &Path,
        network: Network,
        inbound: mpsc::UnboundedSender<Inbound>,
    ) -> Result<Self> {
        let db = crate::store::open(&config.dir.join("session.db"))?;
        let stored: Option<String> = db.query_row("SELECT name FROM session", [], |r| r.get(0)).optional()?;
        match stored {
            Some(stored) if stored != config.name => {
                bail!("this session is named {stored:?}; names are fixed when a session is created")
            }
            Some(_) => {}
            None => _ = db.execute("INSERT INTO session (name) VALUES (?)", [&config.name])?,
        }
        let (plugins, plugin_lines) = Plugins::new(crate::kinds::discover(&config.plugins));
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(home.join("device.lock"))?;
        let mut session = Self {
            db,
            node,
            device: None,
            lock,
            device_retry: Instant::now(),
            published: String::new(),
            home: home.to_path_buf(),
            network,
            config,
            outbox: Outbox::default(),
            waiting: Vec::new(),
            fetches: Vec::new(),
            catching_up: Some(Instant::now() + CATCH_UP_WINDOW),
            inbound,
            plugins,
            plugin_lines,
            kind_of: HashMap::new(),
            asked: 0,
            snapshots: HashMap::new(),
            commands: HashMap::new(),
            kind_fetches: Vec::new(),
            infos: HashMap::new(),
            chat_kinds: HashSet::new(),
            handed: HashMap::new(),
        };
        session.take_device().await?;
        for gid in session.node.groups() {
            session.outbox.catch_up(&b64(&gid.0));
            if session.node.settings(&gid.0)?.kind != CHAT
                && let Err(error) = session.open_kind(&gid, None).await
            {
                session.warn(Some(&gid), format!("{error:#}"));
            }
            if !session.chats(&gid) {
                continue;
            }
            // Messages that arrived but were never taken in, as when the session stopped while they waited.
            for message in session.node.messages(&gid.0)? {
                if message.payload["type"] == "message" && !session.taken(&message.id.0)? && message.sender.key != session.node.key() {
                    session.received(message).await?;
                }
            }
        }
        // Once every doc 0.10 kept is the doc plugin's, the tables it kept them in go.
        if session.legacy("bindings")? && session.db.query_row("SELECT count(*) FROM bindings", [], |r| r.get::<_, i64>(0))? == 0 {
            session.db.execute_batch("DROP TABLE bindings; DROP TABLE IF EXISTS carrying;")?;
        }
        Ok(session)
    }

    /// This session as the agent sees it in `ready`.
    pub fn me(&self) -> Result<Value> {
        let device = self.node.device();
        let identities: Vec<Value> =
            self.identities()?.into_iter().map(|(identity, name)| json!({ "id": identity.id, "name": name })).collect();
        Ok(json!({ "name": self.config.name, "fp": fp(&self.node.key().0), "device": { "key": Bytes(device.public().to_vec()), "name": device.name }, "identities": identities }))
    }

    /// Acts for the device if no other session process does: runs its node and answers its command channel.
    async fn take_device(&mut self) -> Result<()> {
        self.device_retry = Instant::now() + DEVICE_RETRY;
        match self.lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(()),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        // Another session process may have acted for the device before, and changed it.
        let device = lmk_core::device::Device::load(&self.device_file())?;
        let provider = SqliteProvider::open(&self.home.join("device.db"))?;
        let kinds = self.node.kinds().to_vec();
        let config = crate::node_config(&self.network, &self.home, &device.name, true, self.home.join("device-files"), kinds);
        let (node, mut events) = Node::start(provider, device.clone(), config).await?;
        if node.device().identities != device.identities {
            node.device().save(&self.device_file())?;
        }
        let inbound = self.inbound.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if let Event::Warning { text, .. } = event {
                    let _ = inbound.send(Inbound::DeviceWarning(text));
                }
            }
        });
        crate::cli::open_channel(&self.home.join("device-endpoint"), self.inbound.clone()).await?;
        self.device = Some(node);
        Ok(())
    }

    /// Writes the device's state where its other session processes read it, if this process acts for the device and
    /// the state changed.
    fn publish(&mut self) {
        let Some(device) = &self.device else { return };
        let published = DeviceState::of(device).map(|state| serde_json::to_string(&state).expect("JSON"));
        let written = published.and_then(|state| {
            if state != self.published {
                let path = self.home.join("device-state.json");
                let new = path.with_extension("new");
                private_file(&new, state.as_bytes())?;
                std::fs::rename(&new, &path)?;
                self.published = state;
            }
            Ok(())
        });
        if let Err(error) = written {
            self.warn(None, format!("publishing this device's state: {error:#}"));
        }
    }

    /// The device's state: from its node if this process acts for the device, else as published.
    fn device_state(&self) -> Result<DeviceState> {
        if let Some(device) = &self.device {
            return DeviceState::of(device);
        }
        match std::fs::read(self.home.join("device-state.json")) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DeviceState::default()),
            Err(error) => Err(error.into()),
        }
    }

    /// When something is next due without anything arriving.
    pub fn next_due(&self) -> Instant {
        let held = self.outbox.deadline(self.config.hold);
        let waiting = self.waiting.iter().map(|w| w.deadline);
        let fetches = self.fetches.iter().map(|f| f.deadline).chain(self.kind_fetches.iter().map(|f| f.deadline));
        let device = self.device.is_none().then_some(self.device_retry);
        let later = Instant::now() + Duration::from_secs(3600);
        let due = held.into_iter().chain(waiting).chain(fetches).chain(device);
        due.chain(self.catching_up).fold(later, Instant::min)
    }

    pub async fn tick(&mut self) {
        let now = Instant::now();
        if self.device.is_none()
            && self.device_retry <= now
            && let Err(error) = self.take_device().await
        {
            self.warn(None, format!("acting for this device: {error:#}"));
        }
        if self.outbox.deadline(self.config.hold).is_some_and(|at| at <= now) {
            self.outbox.flush_held();
        }
        if self.catching_up.is_some_and(|at| at <= now) {
            self.catching_up = None;
            self.outbox.caught_up();
        }
        let (late, waiting) = std::mem::take(&mut self.waiting).into_iter().partition(|w| w.deadline <= now);
        self.waiting = waiting;
        for w in late {
            if let Err(error) = self.take_message(&w.gid, w.id, w.sender, w.payload).await {
                self.warn(Some(&w.gid), format!("{error:#}"));
            }
        }
        let (late, fetches): (Vec<Fetch>, _) = std::mem::take(&mut self.fetches).into_iter().partition(|f| f.deadline <= now);
        self.fetches = fetches;
        for fetch in late {
            let _ = fetch.reply.send(json!({ "error": "no member online holds that file; try again when one is" }));
        }
        let (late, fetches): (Vec<KindFetch>, _) = std::mem::take(&mut self.kind_fetches).into_iter().partition(|f| f.deadline <= now);
        self.kind_fetches = fetches;
        for fetch in late {
            let answer = json!({ "type": "answer", "id": fetch.id, "error": "no member online holds that file" });
            let _ = self.plugins.send(&fetch.kind, &answer).await;
        }
    }

    /// Prints what is waiting, once the plugins are in step (a doc's file with its doc): whatever wakes the agent, it
    /// acts on current state.
    pub async fn emit(&mut self, print: &mut impl FnMut(String)) {
        if self.outbox.is_empty() {
            return;
        }
        self.sync_kinds().await;
        for mut item in self.outbox.take() {
            if item["type"] == "message"
                && let Some(id) = item["id"].as_str().and_then(|id| message_id(id).ok())
            {
                let _ = self.mark_seen(&id);
            }
            let printed = item.as_object_mut().and_then(|item| item.remove("printed"));
            print(item.to_string());
            if let Some(printed) = printed {
                let told = json!({ "type": "printed", "group": item["group"], "key": printed["key"] });
                let _ = self.plugins.send(printed["kind"].as_str().unwrap_or_default(), &told).await;
            }
        }
    }

    pub async fn handle(&mut self, inbound: Inbound) {
        match inbound {
            Inbound::Request(request, reply) => {
                let request = *request;
                // The agent may have just changed a file.
                self.sync_kinds().await;
                if let Request::Fetch { link } = request {
                    if let Err(error) = self.fetch(link, reply).await {
                        self.warn(None, format!("{error:#}"));
                    }
                } else if let Request::Kind { kind, args, cwd } = request {
                    // A plugin's command may take a while, and may need this session meanwhile: it is answered when the
                    // plugin answers.
                    if let Err(error) = self.command(kind, args, cwd, reply).await {
                        self.warn(None, format!("{error:#}"));
                    }
                } else {
                    let result = self.request(request).await;
                    // Before the answer, so that the device's other session processes read what the request changed.
                    self.publish();
                    let _ = reply.send(result.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
                }
                self.outbox.flush_held();
            }
            Inbound::DeviceWarning(text) => self.warn(None, format!("this device: {text}")),
            Inbound::Done { kind, group, id, done } => {
                let answer = match done {
                    Ok(Done::Appended(position)) => self.hand_entries(&group).await.map(|()| json!({ "position": position })),
                    Ok(Done::Holders(holders)) => {
                        holders.iter().map(|m| self.describe(&group, m)).collect::<Result<Vec<_>>>().map(|held_by| json!({ "held_by": held_by }))
                    }
                    Err(error) => Err(error),
                };
                let answer = match answer {
                    Ok(answer) => json!({ "type": "answer", "id": id, "answer": answer }),
                    Err(error) => json!({ "type": "answer", "id": id, "error": format!("{error:#}") }),
                };
                if let Err(error) = self.plugins.send(&kind, &answer).await {
                    self.warn(Some(&group), format!("{error:#}"));
                }
            }
        }
    }

    /// What this session's node tells.
    pub async fn event(&mut self, event: Event) {
        let group = match &event {
            Event::Joined { group, .. }
            | Event::Left { group, .. }
            | Event::Removed { group, .. }
            | Event::Settings { group, .. }
            | Event::Live { group, .. }
            | Event::Frame { group, .. }
            | Event::Synced { group }
            | Event::InStep { group, .. }
            | Event::State { group, .. }
            | Event::Logged { group }
            | Event::Snapshot { group, .. }
            | Event::Introduced { group, .. }
            | Event::Held { group, .. }
            | Event::Refused { group, .. }
            | Event::Unread { group, .. } => Some(group.clone()),
            Event::Message(message) => Some(message.group.clone()),
            Event::File(_) | Event::Warning { .. } => None,
        };
        if let Err(error) = self.on(event).await {
            self.warn(group.as_ref(), format!("{error:#}"));
        }
    }

    async fn on(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Joined { group, member, by, how, label } => {
                let item = json!({ "type": "joined", "group": b64(&group.0), "member": self.describe(&group, &member)?, "by": self.describe(&group, &by)?, "how": how });
                self.outbox.deliver(item, true);
                if by.key == self.node.key() {
                    self.admitted(&group, &member, how, label).await?;
                }
                self.refresh_opening(&group).await?;
            }
            Event::Left { group, member, by } => {
                let item = json!({ "type": "left", "group": b64(&group.0), "member": self.describe(&group, &member)?, "by": self.describe(&group, &by)? });
                self.outbox.deliver(item, true);
                self.refresh_opening(&group).await?;
            }
            Event::Removed { group, by } => {
                let by = by.map(|by| self.describe(&group, &by)).transpose()?;
                self.drop_group(&group).await?;
                self.outbox.deliver(json!({ "type": "removed", "group": b64(&group.0), "by": by }), true);
            }
            Event::Settings { group, settings, by } => {
                let item = json!({ "type": "settings", "group": b64(&group.0), "settings": settings, "by": self.describe(&group, &by)? });
                self.outbox.deliver(item, true);
                self.refresh_opening(&group).await?;
            }
            Event::Message(message) if message.payload["type"] == "message" && self.chats(&message.group) => self.received(message).await?,
            Event::Message(message) => {
                let from = self.describe(&message.group, &message.sender)?;
                let item = json!({ "type": "message", "id": hex::encode(&message.id.0), "from": from, "payload": message.payload, "held": true });
                self.tell_plugin(&message.group, item).await?;
            }
            Event::Live { group, sender, payload } => {
                let item = json!({ "type": "message", "from": self.describe(&group, &sender)?, "payload": payload, "held": false });
                self.tell_plugin(&group, item).await?;
            }
            Event::Frame { group, from, frame } => {
                let item = json!({ "type": "frame", "from": self.describe(&group, &from)?, "frame": frame });
                self.tell_plugin(&group, item).await?;
            }
            // What a sync did not bring will not come from that member: a message waiting only for such shows the gap.
            Event::Synced { group } => loop {
                let waiting: Vec<[u8; 32]> = self.waiting.iter().map(|w| w.id).collect();
                let unblocked = |w: &Waiting| self.missing(&w.payload).is_ok_and(|missing| missing.iter().all(|id| !waiting.contains(id)));
                let Some(i) = self.waiting.iter().position(|w| w.gid == group && unblocked(w)) else { break };
                let w = self.waiting.remove(i);
                self.take_message(&w.gid, w.id, w.sender, w.payload).await?;
            },
            Event::InStep { group, member } => {
                let item = json!({ "type": "synced", "member": self.describe(&group, &member)? });
                self.tell_plugin(&group, item).await?;
            }
            Event::State { group, from, data } => {
                let item = json!({ "type": "state", "from": self.describe(&group, &from)?, "data": Bytes(data) });
                self.tell_plugin(&group, item).await?;
            }
            Event::Logged { group } => self.hand_entries(&group).await?,
            Event::Snapshot { group, reply } => {
                if let Some(kind) = self.kind_of.get(&group).cloned() {
                    self.asked += 1;
                    self.snapshots.insert((kind.clone(), self.asked), reply);
                    let asked = json!({ "type": "snapshot", "id": self.asked, "group": b64(&group.0) });
                    self.plugins.send(&kind, &asked).await?;
                }
            }
            Event::Introduced { group, by, identity, name, how } => self.introduced(&group, &by, identity, name, how)?,
            Event::Held { .. } => {}
            Event::Refused { group, id, by, reason } => {
                let item = json!({ "type": "refused", "group": b64(&group.0), "id": hex::encode(&id.0), "member": self.describe(&group, &by)?, "reason": reason });
                self.outbox.deliver(item, true);
            }
            Event::Unread { group, by, ids } => self.unread(&group, &by, &ids).await?,
            Event::File(hash) => self.arrived(hash).await?,
            Event::Warning { group, text } => self.warn(group.as_ref(), text),
        }
        Ok(())
    }

    /// A member reports messages it could not read: those of this session's chat messages print, with their text and a
    /// copy of their attachment while this session holds them, so that the agent can send them again.
    async fn unread(&mut self, gid: &Bytes, by: &Member, ids: &[Bytes]) -> Result<()> {
        let mut messages = Vec::new();
        for id in ids {
            let Some(message) = self.node.message(&id.0)? else { continue };
            if message.sender.key != self.node.key() || message.payload["type"] != "message" {
                continue;
            }
            let chat: ChatMessage = serde_json::from_value(message.payload)?;
            let mut item = json!({ "id": hex::encode(&id.0), "content": chat.content });
            if !chat.to.is_empty() {
                item["to"] = json!(chat.to.iter().map(|fp| hex::encode(&fp.0)).collect::<Vec<_>>());
            }
            if chat.urgent {
                item["urgent"] = json!(true);
            }
            if let Some(attachment) = chat.attachment {
                let link = FileLink::parse(&attachment.link)?;
                item["attachment"] = json!(attachment);
                if let Some(bytes) = self.node.file(&link).await? {
                    item["attachment"]["path"] = json!(self.save(gid, &link, Some(&attachment.name), &bytes)?);
                }
            }
            messages.push(item);
        }
        if !messages.is_empty() {
            let item = json!({ "type": "unread", "group": b64(&gid.0), "member": self.describe(gid, by)?, "messages": messages });
            self.outbox.deliver(item, true);
        }
        Ok(())
    }

    /// This session admitted a member: it tells the group who the member is to it, and the member of an invite meant
    /// for someone becomes that contact.
    async fn admitted(&mut self, gid: &Bytes, member: &Member, how: How, label: Option<String>) -> Result<()> {
        let Some(claim) = member.identity.clone().filter(|claim| claim.error.is_none()) else { return Ok(()) };
        if let Some(label) = &label {
            let contact = Contact { name: label.clone(), how: contacts::How::Verified, by: None, at: lmk_node::now() };
            Box::pin(self.request(Request::SetContact { identity: claim.identity.id.clone(), contact })).await?;
        }
        let name = match label {
            Some(label) => label,
            None => self.display_name(&claim)?,
        };
        let introduce = Control::Introduce { identity: claim.identity, name, how, to: Vec::new() };
        self.node.send(&gid.0, &serde_json::to_value(introduce)?, false).await?;
        Ok(())
    }

    /// Records, in the devices group of each of this device's identities the group is open to, the group's opening.
    async fn refresh_opening(&mut self, gid: &Bytes) -> Result<()> {
        let Ok(settings) = self.node.settings(&gid.0) else { return Ok(()) };
        for (identity, _) in self.identities()? {
            if settings.open.iter().any(|named| named.id == identity.id) {
                let opening = self.node.opening(&gid.0)?;
                Box::pin(self.request(Request::SetOpening { identity: identity.id, opening })).await?;
            }
        }
        Ok(())
    }

    async fn request(&mut self, request: Request) -> Result<Value> {
        let for_device = match &request {
            Request::Identity { .. } | Request::SetContact { .. } | Request::SetOpening { .. } => true,
            Request::Invite { identity, .. } => identity.is_some(),
            Request::Join { target, .. } => Invite::parse(target.trim()).is_ok_and(|invite| invite.device),
            _ => false,
        };
        if for_device && self.device.is_none() {
            let channel = crate::cli::connect(&self.home.join("device-endpoint")).await;
            return crate::cli::exchange(channel.context("no session process acts for this device")?, request).await;
        }
        match request {
            Request::Invite { group, kind, name, args, cwd, keep, membership, as_, for_, to, qr: _, identity } => {
                self.invite(group, kind, name, (args, cwd), keep, membership, as_, for_, to, identity).await
            }
            Request::Join { target, args, cwd, as_ } => self.join(target, (args, cwd), as_).await,
            Request::Send { group, to, reply_to, urgent, attach, attach_name, text } => {
                self.send(group, to, reply_to, urgent, attach.map(|data| (data, attach_name)), text).await
            }
            Request::Read { id, ancestors } => self.read(&id, ancestors),
            Request::Members { group } => {
                let gid = self.resolve(group)?;
                Ok(json!({ "group": b64(&gid.0), "kind": self.node.settings(&gid.0)?.kind, "members": self.described_members(&gid)? }))
            }
            Request::Kind { .. } => unreachable!("answered by command"),
            Request::Groups => self.groups(),
            Request::Remove { group, member } => {
                let gid = self.resolve(group)?;
                let member = self.member(&gid, &member)?;
                ensure!(member.key != self.node.key(), "to leave a group, use `leave`");
                self.node.remove(&gid.0, &member.key.0).await?;
                Ok(json!({ "group": b64(&gid.0), "members": self.described_members(&gid)? }))
            }
            Request::Leave { group } => self.leave(group).await,
            Request::Name { group, name } => {
                let gid = self.resolve(group)?;
                let settings = self.node.change_settings(&gid.0, |settings| Settings { name: name.clone(), ..settings }).await?;
                Ok(json!({ "group": b64(&gid.0), "settings": settings }))
            }
            Request::Open { group, close, identity } => {
                let gid = self.resolve(group)?;
                let (id, name) = self.identity_named(&identity)?;
                let settings = self
                    .node
                    .change_settings(&gid.0, |mut settings| {
                        settings.open.retain(|o| o.id != id);
                        if !close {
                            settings.open.push(Named { id: id.clone(), name: name.clone() });
                        }
                        settings
                    })
                    .await?;
                self.refresh_opening(&gid).await?;
                Ok(json!({ "group": b64(&gid.0), "settings": settings }))
            }
            Request::Fetch { .. } => unreachable!("answered by fetch"),
            Request::Status => self.status(),
            Request::Identity { op } => self.identity(op).await,
            Request::Contacts { op: None } => self.contacts(),
            Request::Contacts { op: Some(ContactsOp::Accept { identity, name }) } => self.accept(&identity, name).await,
            Request::Introduce { group, member, to } => self.introduce(group, &member, &to).await,
            Request::SetContact { identity, contact } => {
                self.device()?.set_contact(&identity.0, &contact).await?;
                Ok(json!({}))
            }
            Request::SetOpening { identity, opening } => {
                self.device()?.set_opening(&identity.0, opening).await?;
                Ok(json!({}))
            }
        }
    }

    // Groups.

    #[allow(clippy::too_many_arguments)]
    async fn invite(
        &mut self,
        group: Option<String>,
        kind: String,
        name: Option<String>,
        (args, cwd): (Vec<String>, String),
        keep: u32,
        membership: Option<String>,
        as_: Option<String>,
        for_: Option<String>,
        to: Option<String>,
        identity: Option<String>,
    ) -> Result<Value> {
        ensure!(kind == CHAT || self.plugins.found.contains_key(&kind), "this session has no plugin for {kind} groups (letmeknow-kind-{kind})");
        ensure!(args.is_empty() || kind != CHAT, "a chat takes no arguments");
        let to = to.map(|to| self.contact(&to)).transpose()?;
        ensure!(
            for_.is_none() || !self.identities()?.is_empty(),
            "contacts belong to an identity: create one with `identity create`"
        );
        let mut answer = json!({ "expires_in": INVITE_TTL });
        let link = match identity {
            Some(identity) => {
                let (identity, name) = self.own_identity(&identity)?;
                answer["identity"] = json!({ "id": identity.id, "name": name });
                self.device()?.invite(Target::Device(identity.id.0), None, None)?
            }
            None => {
                let gid = match group {
                    Some(group) => self.resolve(Some(group))?,
                    None => {
                        let membership = membership.map(|m| crate::service(&m)).transpose()?.unwrap_or(self.config.membership.clone());
                        let as_ = self.speaking_as(as_)?;
                        let settings = Settings {
                            protocol: PROTOCOL,
                            kind: kind.clone(),
                            name: name.unwrap_or_default(),
                            open: Vec::new(),
                            keep,
                            membership,
                            devices_of: None,
                            openings: Vec::new(),
                            log: None,
                        };
                        let gid = self.node.create(settings, as_)?;
                        if kind != CHAT {
                            match self.open_kind(&gid, Some(("invite", args, cwd))).await {
                                Ok(opened) => merge(&mut answer, opened),
                                Err(error) => {
                                    self.node.leave(&gid.0).await?;
                                    self.drop_group(&gid).await?;
                                    return Err(error);
                                }
                            }
                        }
                        gid
                    }
                };
                let settings = self.node.settings(&gid.0)?;
                answer["group"] = json!(b64(&gid.0));
                answer["kind"] = json!(settings.kind);
                if !settings.name.is_empty() {
                    answer["name"] = json!(settings.name);
                }
                self.node.invite(Target::Group(gid.0), for_.clone(), to.as_ref().map(|to| to.0.clone()))?
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

    async fn leave(&mut self, group: Option<String>) -> Result<Value> {
        let gid = self.resolve(group)?;
        let Some(delivery) = self.node.leave(&gid.0).await? else {
            self.drop_group(&gid).await?;
            return Ok(json!({ "group": b64(&gid.0), "left": true }));
        };
        let mut answer = json!({ "group": b64(&gid.0), "left": true, "status": "another member commits the removal" });
        if delivery.held.is_empty() {
            answer["pending"] = json!(true);
        }
        Ok(answer)
    }

    /// Clears what the session kept of a group the node has left, and tells its kind's plugin.
    async fn drop_group(&mut self, gid: &Bytes) -> Result<()> {
        self.infos.remove(gid);
        if let Some(kind) = self.kind_of.remove(gid) {
            self.plugins.send(&kind, &json!({ "type": "gone", "group": b64(&gid.0) })).await?;
        }
        for table in ["taken", "attachments"] {
            self.db.execute(&format!("DELETE FROM {table} WHERE gid = ?"), [&gid.0])?;
        }
        let attachments = self.attachments_dir(gid);
        if attachments.exists() {
            std::fs::remove_dir_all(attachments)?;
        }
        self.node.scrub()
    }

    fn groups(&self) -> Result<Value> {
        let mut groups = Vec::new();
        for gid in self.node.groups() {
            let settings = self.node.settings(&gid.0)?;
            let mut group = json!({
                "group": b64(&gid.0), "kind": settings.kind, "members": self.node.members(&gid.0)?.len(), "keep": settings.keep,
                "membership": settings.membership, "epoch": self.node.epoch(&gid.0)?,
            });
            if !settings.name.is_empty() {
                group["name"] = json!(settings.name);
            }
            if !settings.open.is_empty() {
                group["open"] = json!(settings.open);
            }
            if let Some(info) = self.infos.get(&gid) {
                merge(&mut group, info.clone());
            }
            groups.push(group);
        }
        let joined = self.node.groups();
        for opening in self.device_state()?.openings {
            if !joined.contains(&opening.group) && self.node.kinds().contains(&opening.kind) {
                groups.push(json!({ "group": b64(&opening.group.0), "kind": opening.kind, "name": opening.name, "joined": false }));
            }
        }
        Ok(Value::Array(groups))
    }

    fn status(&self) -> Result<Value> {
        let mut groups = Vec::new();
        let mut only_here_count = 0;
        for gid in self.node.groups() {
            let online: Vec<Value> = self.node.online(&gid.0)?.iter().map(|m| self.describe(&gid, m)).collect::<Result<_>>()?;
            let only_here: Vec<Value> =
                self.node.only_here(&gid.0)?.iter().map(|p| json!({ "id": hex::encode(&p.id.0), "what": p.what })).collect();
            only_here_count += only_here.len();
            let mut group = json!({ "group": b64(&gid.0), "online": online, "only_here": only_here });
            if let Some(name) = Some(self.node.settings(&gid.0)?.name).filter(|n| !n.is_empty()) {
                group["name"] = json!(name);
            }
            groups.push(group);
        }
        let mut status = json!({ "groups": groups });
        if only_here_count > 0 {
            status["warning"] =
                json!(format!("{only_here_count} sends are held only by this session; keep it running until a member is online"));
        }
        Ok(status)
    }

    /// The group a command acts on: the one --group names (by id or name), or else the session's one group.
    fn resolve(&self, group: Option<String>) -> Result<Bytes> {
        let gids = self.node.groups();
        match group {
            Some(group) => {
                let named: Vec<&Bytes> = gids
                    .iter()
                    .filter(|gid| b64(&gid.0) == group || self.node.settings(&gid.0).is_ok_and(|s| s.name == group))
                    .collect();
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
    fn chats(&self, gid: &Bytes) -> bool {
        self.node.settings(&gid.0).is_ok_and(|s| s.kind == CHAT || self.chat_kinds.contains(&s.kind))
    }

    /// The group carrying chat a command acts on: the one --group names, or else the session's one such group.
    fn chat(&self, group: Option<String>) -> Result<Bytes> {
        if group.is_some() {
            let gid = self.resolve(group)?;
            ensure!(self.chats(&gid), "{} carries no chat", b64(&gid.0));
            return Ok(gid);
        }
        let found: Vec<Bytes> = self.node.groups().into_iter().filter(|gid| self.chats(gid)).collect();
        match &found[..] {
            [gid] => Ok(gid.clone()),
            [] => bail!("this session is in no chat; create one with `invite`, or join one with `join`"),
            _ => bail!("this session is in several chats; pass --group"),
        }
    }

    // Joins.

    async fn join(&mut self, target: String, (args, cwd): (Vec<String>, String), as_: Option<String>) -> Result<Value> {
        let as_ = self.speaking_as(as_)?;
        let gid = if target.contains('#') {
            let invite = Invite::parse(target.trim())?;
            if invite.device {
                let device = self.device()?;
                device.join(&invite, None).await?;
                device.device().save(&self.device_file())?;
                return Ok(json!({ "device": "added to the identity's device list" }));
            }
            self.node.join(&invite, as_).await?
        } else {
            let opening = self.device_state()?.openings.into_iter().find(|o| b64(&o.group.0) == target || o.name == target);
            let opening = opening.context("expected an invite link, or the id or name of a group open to your identity")?;
            let identity = as_.context("joining a group open to your identity needs one: this device is on none")?;
            self.node.join_open(&opening, identity).await?
        };
        let settings = self.node.settings(&gid.0)?;
        let mut answer = json!({ "group": b64(&gid.0), "kind": settings.kind, "name": settings.name, "members": self.described_members(&gid)? });
        if settings.kind != CHAT {
            match self.open_kind(&gid, Some(("join", args, cwd))).await {
                Ok(opened) => merge(&mut answer, opened),
                Err(error) => {
                    self.node.leave(&gid.0).await?;
                    return Err(error);
                }
            }
        }
        Ok(answer)
    }

    // Messages.

    async fn send(
        &mut self,
        group: Option<String>,
        to: Vec<String>,
        reply_to: Option<String>,
        urgent: bool,
        attach: Option<(String, String)>,
        text: String,
    ) -> Result<Value> {
        let gid = self.chat(group)?;
        let mut addressed: Vec<Member> = Vec::new();
        for to in to {
            for member in self.addressed(&gid, &to)? {
                if !addressed.contains(&member) {
                    addressed.push(member);
                }
            }
        }
        let reply_to = reply_to.map(|id| message_id(&id)).transpose()?;
        if let Some(id) = &reply_to {
            ensure!(self.node.message(id)?.is_some(), "unknown message {}", hex::encode(id));
            self.mark_seen(id)?;
        }
        let attachment = match attach {
            Some((data, name)) => {
                let bytes = B64.decode(data)?;
                let media_type = image_type(&bytes).map(|t| format!("image/{t}")).unwrap_or_default();
                let size = bytes.len() as u64;
                let link = self.node.add_file(&gid.0, bytes).await?;
                Some((link.clone(), Attachment { link: link.link(), name, size, media_type }))
            }
            None => None,
        };
        let payload = ChatMessage {
            content: text,
            after: self.tips(&gid)?.into_iter().map(|id| Bytes(id.to_vec())).collect(),
            to: addressed.iter().map(|m| Bytes(Sha256::digest(&m.key.0)[..8].to_vec())).collect(),
            reply_to: reply_to.map(|id| Bytes(id.to_vec())),
            urgent,
            attachment: attachment.as_ref().map(|(_, a)| a.clone()),
        };
        let (id, delivery) = self.node.send(&gid.0, &serde_json::to_value(payload)?, true).await?;
        self.db.execute("INSERT OR IGNORE INTO taken (id, gid, seen) VALUES (?, ?, 1)", params![id.0, gid.0])?;
        let mut answer = json!({ "id": hex::encode(&id.0) });
        if !addressed.is_empty() {
            answer["to"] = json!(addressed.iter().map(|m| fp(&m.key.0)).collect::<Vec<_>>());
        }
        if delivery.held.is_empty() {
            answer["pending"] = json!(true);
        } else {
            answer["held_by"] = json!(delivery.held.iter().map(|m| self.describe(&gid, m)).collect::<Result<Vec<_>>>()?);
        }
        if !delivery.refused.is_empty() {
            let refused: Vec<Value> = delivery
                .refused
                .iter()
                .map(|(member, reason)| Ok(json!({ "member": self.describe(&gid, member)?, "reason": reason })))
                .collect::<Result<_>>()?;
            answer["refused"] = json!(refused);
        }
        if let Some((link, _)) = attachment {
            let holders = self.node.spread(&gid.0, &link).await;
            if holders.is_empty() {
                answer["attachment"] = json!({ "pending": true, "warning": "no other member holds the file yet; it is available only while this session runs" });
            } else {
                answer["attachment"] = json!({ "held_by": holders.iter().map(|m| self.describe(&gid, m)).collect::<Result<Vec<_>>>()? });
            }
        }
        Ok(answer)
    }

    /// The members `to` addresses: a fingerprint, or a name they answer to, as long as they speak for one identity.
    fn addressed(&self, gid: &Bytes, to: &str) -> Result<Vec<Member>> {
        let members = self.node.members(&gid.0)?;
        if let Some(member) = members.iter().find(|m| fp(&m.key.0) == to) {
            return Ok(vec![member.clone()]);
        }
        let mut named = Vec::new();
        for member in members {
            let described = self.describe(gid, &member)?;
            if described["you"] != true && crate::policy::answers(&described, to) {
                named.push((member, described));
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

    /// A chat message the node took in: the file it attaches is held, and it waits for those it comes after.
    async fn received(&mut self, message: lmk_node::Message) -> Result<()> {
        let id: [u8; 32] = message.id.0.as_slice().try_into()?;
        if self.taken(&id)? || self.waiting.iter().any(|w| w.id == id) {
            return Ok(());
        }
        let sender = self.describe(&message.group, &message.sender)?;
        let payload = message.payload;
        if let Some(link) = payload["attachment"]["link"].as_str() {
            self.node.hold(&message.group.0, &[link.to_owned()])?;
        }
        // A message waits for those it comes after, unless this session gave them up: then it shows the gap.
        if self.missing(&payload)?.iter().all(|missing| self.node.given_up(&message.group.0, missing)) {
            self.take_message(&message.group, id, sender, payload).await
        } else {
            self.waiting.push(Waiting { deadline: Instant::now() + self.config.causal_wait, gid: message.group, id, sender, payload });
            Ok(())
        }
    }

    fn taken(&self, id: &[u8]) -> Result<bool> {
        Ok(self.db.query_row("SELECT 1 FROM taken WHERE id = ?", [id], |_| Ok(())).optional()?.is_some())
    }

    /// The messages a message comes after that this session has not taken in.
    fn missing(&self, payload: &Value) -> Result<Vec<[u8; 32]>> {
        let after: Vec<Bytes> = serde_json::from_value(payload["after"].clone())?;
        let mut missing = Vec::new();
        for id in after {
            if !self.taken(&id.0)? {
                missing.push(id.0.try_into().ok().context("a message id is 32 bytes")?);
            }
        }
        Ok(missing)
    }

    /// Takes in a chat message, then those that waited for it.
    async fn take_message(&mut self, gid: &Bytes, id: [u8; 32], sender: Value, payload: Value) -> Result<()> {
        let missing = self.missing(&payload)?;
        self.db.execute("INSERT OR IGNORE INTO taken (id, gid) VALUES (?, ?)", params![id, gid.0])?;
        let mut item = self.message_json(gid, id, sender, &payload, true)?;
        if !missing.is_empty() {
            item["missing"] = json!(missing.iter().map(hex::encode).collect::<Vec<_>>());
        }
        let wakes = wakes(&item, |id| self.mine(id));
        if let Some(attachment) = payload.get("attachment").filter(|a| a.is_object()) {
            let link = FileLink::parse(attachment["link"].as_str().context("an attachment has a link")?)?;
            let name = attachment["name"].as_str().unwrap_or_default().to_owned();
            self.db.execute(
                "INSERT OR IGNORE INTO attachments (hash, gid, message, link, name, wakes) VALUES (?, ?, ?, ?, ?, ?)",
                params![link.hash, gid.0, id, link.link(), name, wakes],
            )?;
            match self.node.file(&link).await? {
                Some(bytes) => {
                    let path = self.save(gid, &link, Some(&name), &bytes)?;
                    self.db.execute("UPDATE attachments SET path = ? WHERE hash = ? AND message = ?", params![path.to_str(), link.hash, id])?;
                    item["attachment"]["path"] = json!(path);
                }
                None => item["attachment"]["pending"] = json!(true),
            }
        }
        self.outbox.deliver(item, wakes);
        let ready: Vec<usize> = (0..self.waiting.len())
            .filter(|&i| self.waiting[i].gid == *gid && self.missing(&self.waiting[i].payload).is_ok_and(|m| m.is_empty()))
            .collect();
        for i in ready.into_iter().rev() {
            let w = self.waiting.remove(i);
            Box::pin(self.take_message(&w.gid, w.id, w.sender, w.payload)).await?;
        }
        Ok(())
    }

    fn mine(&self, id: &str) -> bool {
        message_id(id).is_ok_and(|id| self.node.message(&id).ok().flatten().is_some_and(|m| m.sender.key == self.node.key()))
    }

    fn message_json(&self, gid: &Bytes, id: [u8; 32], from: Value, payload: &Value, fresh: bool) -> Result<Value> {
        let me = self.describe_key(gid, &self.node.key());
        let to: Vec<Bytes> = serde_json::from_value(payload.get("to").cloned().unwrap_or(json!([])))?;
        let to: Vec<String> = to.iter().map(|fp| hex::encode(&fp.0)).collect();
        let forgotten = !fresh && !self.config.keep_log && self.seen(&id)?;
        let content = if forgotten { Value::Null } else { payload.get("content").cloned().unwrap_or(Value::Null) };
        let direct = to.iter().any(|fp| me["fp"] == fp.as_str()) || content.as_str().is_some_and(|text| mentions(text, &me));
        let mut item = json!({ "type": "message", "group": b64(&gid.0), "id": hex::encode(id), "from": from, "direct": direct, "content": content });
        if !to.is_empty() {
            item["to"] = json!(to);
        }
        if let Some(reply_to) = payload.get("reply_to") {
            item["reply_to"] = json!(hex::encode(serde_json::from_value::<Bytes>(reply_to.clone())?.0));
        }
        if payload["urgent"] == true {
            item["urgent"] = json!(true);
        }
        if let Some(attachment) = payload.get("attachment") {
            item["attachment"] = attachment.clone();
        }
        Ok(item)
    }

    fn seen(&self, id: &[u8]) -> Result<bool> {
        Ok(self.db.query_row("SELECT seen FROM taken WHERE id = ?", [id], |r| r.get(0)).optional()?.unwrap_or(false))
    }

    /// Read-frontier tips: seen messages that no other seen message lists in `after`.
    fn tips(&self, gid: &Bytes) -> Result<Vec<[u8; 32]>> {
        let seen: Vec<lmk_node::Message> =
            self.node.messages(&gid.0)?.into_iter().filter(|m| self.seen(&m.id.0).unwrap_or(false)).collect();
        let mut covered = HashSet::new();
        for message in &seen {
            if let Ok(chat) = serde_json::from_value::<ChatMessage>(message.payload.clone()) {
                covered.extend(chat.after.into_iter().map(|id| id.0));
            }
        }
        Ok(seen.into_iter().filter(|m| !covered.contains(&m.id.0)).filter_map(|m| m.id.0.try_into().ok()).collect())
    }

    /// Records that a message entered the agent's context. Its text is then deleted, unless `listen --keep-log` or it
    /// is this session's own, which it keeps to send again.
    fn mark_seen(&self, id: &[u8; 32]) -> Result<()> {
        let Some(message) = self.node.message(id)? else { return Ok(()) };
        self.db.execute("INSERT OR IGNORE INTO taken (id, gid) VALUES (?, ?)", params![id, message.group.0])?;
        self.db.execute("UPDATE taken SET seen = 1 WHERE id = ?", [id])?;
        if !self.config.keep_log && message.payload["type"] == "message" && message.sender.key != self.node.key() {
            let mut payload = message.payload;
            payload["content"] = json!("");
            self.node.redact(id, payload)?;
        }
        Ok(())
    }

    fn read(&mut self, id: &str, ancestors: usize) -> Result<Value> {
        let mut found = Vec::new();
        let mut visited = HashSet::new();
        let mut level = vec![message_id(id)?];
        for depth in 0..=ancestors {
            let mut next = Vec::new();
            for id in level {
                if !visited.insert(id) {
                    continue;
                }
                let Some(message) = self.node.message(&id)? else {
                    ensure!(depth > 0, "unknown message {}", hex::encode(id));
                    continue;
                };
                let Ok(chat) = serde_json::from_value::<ChatMessage>(message.payload.clone()) else { continue };
                let from = self.describe(&message.group, &message.sender)?;
                found.push(self.message_json(&message.group, id, from, &message.payload, false)?);
                self.mark_seen(&id)?;
                for after in chat.after {
                    next.push(after.0.as_slice().try_into().ok().context("a message id is 32 bytes")?);
                }
            }
            level = next;
        }
        found.reverse();
        Ok(Value::Array(found))
    }

    // Files.

    fn attachments_dir(&self, gid: &Bytes) -> PathBuf {
        self.config.dir.join("attachments").join(hex::encode(&gid.0))
    }

    /// Writes a file into a file only this user can read; returns its path.
    fn save(&self, gid: &Bytes, link: &FileLink, name: Option<&str>, bytes: &[u8]) -> Result<PathBuf> {
        let dir = self.attachments_dir(gid);
        std::fs::create_dir_all(&dir)?;
        let hash = &hex::encode(link.hash)[..16];
        let file = match (name, image_type(bytes)) {
            (Some(name), _) => format!("{hash}-{}", name.replace(|c: char| !c.is_ascii_alphanumeric() && !"._-".contains(c), "-")),
            (None, Some(extension)) => format!("{hash}.{extension}"),
            (None, None) => hash.to_owned(),
        };
        let path = dir.join(file);
        private_file(&path, bytes)?;
        Ok(path)
    }

    /// A file arrived: for the attachments and fetches waiting for it.
    #[allow(clippy::type_complexity)]
    async fn arrived(&mut self, hash: [u8; 32]) -> Result<()> {
        let waiting: Vec<(Vec<u8>, Vec<u8>, String, String, bool)> = self
            .db
            .prepare("SELECT gid, message, link, name, wakes FROM attachments WHERE hash = ? AND path IS NULL")?
            .query_map([hash], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<Result<_, _>>()?;
        for (gid, message, link, name, wakes) in waiting {
            let (gid, link) = (Bytes(gid), FileLink::parse(&link)?);
            let bytes = self.node.file(&link).await?.context("an arrived file is held")?;
            let path = self.save(&gid, &link, Some(&name), &bytes)?;
            self.db.execute("UPDATE attachments SET path = ? WHERE hash = ? AND message = ?", params![path.to_str(), hash, message])?;
            let item = json!({ "type": "attachment", "group": b64(&gid.0), "message": hex::encode(&message), "name": name, "path": path });
            self.outbox.deliver(item, wakes);
        }
        let (done, fetches): (Vec<KindFetch>, _) = std::mem::take(&mut self.kind_fetches).into_iter().partition(|f| f.link.hash == hash);
        self.kind_fetches = fetches;
        for fetch in done {
            let data = self.node.file(&fetch.link).await?.context("an arrived file is held")?;
            self.plugins.send(&fetch.kind, &json!({ "type": "answer", "id": fetch.id, "answer": { "data": Bytes(data) } })).await?;
        }
        let (done, fetches): (Vec<Fetch>, _) = std::mem::take(&mut self.fetches).into_iter().partition(|f| f.hash == hash);
        self.fetches = fetches;
        for fetch in done {
            let bytes = self.node.file(&fetch.link).await?.context("an arrived file is held")?;
            let path = self.save(&fetch.gid, &fetch.link, fetch.name.as_deref(), &bytes)?;
            let _ = fetch.reply.send(json!({ "path": path, "bytes": bytes.len() }));
        }
        Ok(())
    }

    /// The file a message's attachment or a doc's text links, decrypted into a file only this user can read. The answer
    /// waits for the file if no copy is here yet.
    async fn fetch(&mut self, link: String, reply: oneshot::Sender<Value>) -> Result<()> {
        let found = (|| -> Result<_> {
            let parsed = FileLink::parse(link.trim())?;
            let (gid, name) = self.linking(&parsed.link())?.context("no message or doc here links that")?;
            Ok((parsed, gid, name))
        })();
        let (link, gid, name) = match found {
            Ok(found) => found,
            Err(error) => {
                let _ = reply.send(json!({ "error": format!("{error:#}") }));
                return Ok(());
            }
        };
        match self.node.file(&link).await? {
            Some(bytes) => {
                let path = self.save(&gid, &link, name.as_deref(), &bytes)?;
                let _ = reply.send(json!({ "path": path, "bytes": bytes.len() }));
            }
            None => {
                self.node.fetch(&gid.0, link.clone());
                self.fetches.push(Fetch { hash: link.hash, gid, link, name, deadline: Instant::now() + FETCH_WAIT, reply });
            }
        }
        Ok(())
    }

    /// The group whose chat messages or kind link `link`, and the file's name if a message attached it.
    fn linking(&self, link: &str) -> Result<Option<(Bytes, Option<String>)>> {
        for gid in self.node.groups() {
            for message in self.node.messages(&gid.0)? {
                if message.payload["attachment"]["link"] == link {
                    return Ok(Some((gid, message.payload["attachment"]["name"].as_str().map(str::to_owned))));
                }
            }
            if self.node.linked(&gid.0).iter().any(|linked| linked.link() == link) {
                return Ok(Some((gid, None)));
            }
        }
        Ok(None)
    }

    // Kinds' plugins.

    /// Where a kind's plugin keeps its state.
    fn kind_dir(&self, kind: &str) -> PathBuf {
        self.config.dir.join("kinds").join(kind)
    }

    /// Tells a group's kind's plugin of the group, starting the plugin if need be: with `args` from `invite` or `join`,
    /// or with a doc 0.10 kept. Returns the plugin's answer, when it is asked one.
    async fn open_kind(&mut self, gid: &Bytes, args: Option<(&str, Vec<String>, String)>) -> Result<Value> {
        let settings = self.node.settings(&gid.0)?;
        let kind = settings.kind.clone();
        if !self.plugins.is_running(&kind) {
            self.start_plugin(&kind).await?;
        }
        self.kind_of.insert(gid.clone(), kind.clone());
        let me = self.describe_key(gid, &self.node.key());
        let mut message = json!({ "type": "group", "group": b64(&gid.0), "settings": settings, "me": me });
        let legacy = self.legacy_doc(gid)?;
        if let Some(import) = &legacy {
            message["import"] = import.clone();
        }
        let asked = args.is_some() || legacy.is_some();
        if let Some((command, args, cwd)) = args {
            message["command"] = json!(command);
            message["args"] = json!(args);
            message["cwd"] = json!(cwd);
        }
        if !asked {
            self.plugins.send(&kind, &message).await?;
            return Ok(json!({}));
        }
        let answer = self.ask(&kind, message).await?;
        if legacy.is_some() {
            self.forget_legacy(gid)?;
        }
        Ok(answer)
    }

    /// Starts a kind's plugin, which answers `start` with what its groups carry besides its own content.
    async fn start_plugin(&mut self, kind: &str) -> Result<()> {
        self.plugins.start(kind).await?;
        let started = self.ask(kind, json!({ "type": "start", "kind": kind, "dir": self.kind_dir(kind) })).await?;
        if started["chat"] == true {
            self.chat_kinds.insert(kind.to_owned());
        }
        Ok(())
    }

    /// Hands a group's plugin the entries of its kind's log it has not had.
    async fn hand_entries(&mut self, gid: &Bytes) -> Result<()> {
        let Some(&after) = self.handed.get(gid) else { return Ok(()) };
        for entry in self.node.entries(&gid.0, after)? {
            let item = json!({ "type": "entry", "position": entry.position, "epoch": entry.epoch, "from": self.describe(gid, &entry.from)?, "payload": entry.payload });
            self.tell_plugin(gid, item).await?;
            self.handed.insert(gid.clone(), entry.position);
        }
        Ok(())
    }

    /// Passes `letmeknow <kind> <args>...` to the kind's plugin; `reply` gets its answer.
    async fn command(&mut self, kind: String, args: Vec<String>, cwd: String, reply: oneshot::Sender<Value>) -> Result<()> {
        let started = match self.plugins.is_running(&kind) {
            true => Ok(()),
            false => self.start_plugin(&kind).await,
        };
        if let Err(error) = started {
            let _ = reply.send(json!({ "error": format!("{error:#}") }));
            return Ok(());
        }
        self.asked += 1;
        self.commands.insert((kind.clone(), self.asked), reply);
        self.plugins.send(&kind, &json!({ "type": "command", "id": self.asked, "args": args, "cwd": cwd })).await
    }

    /// Whether a table 0.10 kept docs in is still here: `bindings`, or `carrying`, which 0.10.0 lacks.
    fn legacy(&self, table: &str) -> Result<bool> {
        Ok(self.db.query_row("SELECT count(*) FROM sqlite_master WHERE name = ?", [table], |r| r.get::<_, i64>(0))? > 0)
    }

    /// A doc as 0.10 kept it, before the doc plugin did: its state, and its file's binding, which the plugin imports.
    fn legacy_doc(&self, gid: &Bytes) -> Result<Option<Value>> {
        if self.node.settings(&gid.0)?.kind != "doc" {
            return Ok(None);
        }
        let state = self.node.legacy_doc(&gid.0)?;
        let binding: Option<(String, String)> = match self.legacy("bindings")? {
            true => self.db.query_row("SELECT path, base FROM bindings WHERE gid = ?", [&gid.0], |r| Ok((r.get(0)?, r.get(1)?))).optional()?,
            false => None,
        };
        if state.is_none() && binding.is_none() {
            return Ok(None);
        }
        let mut import = json!({});
        if let Some(state) = state {
            import["state"] = json!(Bytes(state));
        }
        if let Some((path, base)) = binding {
            let carrying: Option<(String, Vec<u8>)> = match self.legacy("carrying")? {
                true => self.db.query_row("SELECT file, edit FROM carrying WHERE gid = ?", [&gid.0], |r| Ok((r.get(0)?, r.get(1)?))).optional()?,
                false => None,
            };
            let made = Path::new(&path).starts_with(self.config.dir.join("docs"));
            let carrying = carrying.map(|(file, edit)| json!({ "file": file, "edit": Bytes(edit) }));
            import = json!({ "state": import["state"], "path": path, "base": base, "made": made, "carrying": carrying });
        }
        Ok(Some(import))
    }

    fn forget_legacy(&self, gid: &Bytes) -> Result<()> {
        self.node.forget_legacy_doc(&gid.0)?;
        for table in ["bindings", "carrying"] {
            if self.legacy(table)? {
                self.db.execute(&format!("DELETE FROM {table} WHERE gid = ?"), [&gid.0])?;
            }
        }
        Ok(())
    }

    /// Sends a plugin a message about one of its groups, if it runs.
    async fn tell_plugin(&mut self, gid: &Bytes, mut message: Value) -> Result<()> {
        let Some(kind) = self.kind_of.get(gid).cloned() else { return Ok(()) };
        message["group"] = json!(b64(&gid.0));
        self.plugins.send(&kind, &message).await
    }

    /// Asks a plugin, and takes in what it and the others send meanwhile, until it answers.
    async fn ask(&mut self, kind: &str, mut message: Value) -> Result<Value> {
        self.asked += 1;
        let id = self.asked;
        message["id"] = json!(id);
        self.plugins.send(kind, &message).await?;
        let deadline = Instant::now() + ASK_WAIT;
        loop {
            let next = tokio::time::timeout_at(deadline, self.plugin_lines.recv()).await;
            let (from, line) = next.ok().flatten().with_context(|| format!("the {kind} plugin did not answer"))?;
            match &line {
                Some(line) if from == kind && line["type"] == "answer" && line["id"] == id => {
                    return match &line["error"] {
                        Value::Null => Ok(line["answer"].clone()),
                        error => bail!("{}", error.as_str().unwrap_or_default()),
                    };
                }
                None if from == kind => {
                    Box::pin(self.plugin_line(from, line)).await;
                    bail!("the {kind} plugin stopped");
                }
                _ => Box::pin(self.plugin_line(from, line)).await,
            }
        }
    }

    /// Brings every plugin into step, as before the session prints or runs a command.
    async fn sync_kinds(&mut self) {
        for kind in self.plugins.running() {
            if let Err(error) = self.ask(&kind, json!({ "type": "sync" })).await {
                self.warn(None, format!("{error:#}"));
            }
        }
    }

    /// A line a plugin wrote, or `None` once it stopped, when it is started again.
    pub async fn plugin_line(&mut self, kind: String, line: Option<Value>) {
        let Some(message) = line else {
            // Its commands' callers hear that the session could not answer.
            self.commands.retain(|(of, _), _| *of != kind);
            if !self.plugins.stopped(&kind) {
                self.warn(None, format!("the {kind} plugin stopped; it runs again once this session restarts"));
                return;
            }
            self.warn(None, format!("the {kind} plugin stopped; starting it again"));
            let restarted = async {
                self.start_plugin(&kind).await?;
                let gids: Vec<Bytes> = self.kind_of.iter().filter(|(_, k)| **k == kind).map(|(gid, _)| gid.clone()).collect();
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
                Some(id) if message["type"] != "answer" => {
                    let _ = self.plugins.send(&kind, &json!({ "type": "answer", "id": id, "error": format!("{error:#}") })).await;
                }
                _ => {
                    let gid = message["group"].as_str().and_then(|g| URL_SAFE_NO_PAD.decode(g).ok()).map(Bytes);
                    self.warn(gid.as_ref(), format!("the {kind} plugin: {error:#}"));
                }
            }
        }
    }

    /// Carries out what a plugin asks, through its groups' channels.
    async fn carry_out(&mut self, kind: &str, message: &Value) -> Result<()> {
        let group = || -> Result<Bytes> {
            let gid = Bytes(URL_SAFE_NO_PAD.decode(message["group"].as_str().context("no group")?)?);
            ensure!(self.kind_of.get(&gid).is_some_and(|k| k == kind), "not a {kind} group of this session");
            Ok(gid)
        };
        let to = message["to"].as_str();
        let reply = |answer: Value| json!({ "type": "answer", "id": message["id"], "answer": answer });
        match message["type"].as_str().unwrap_or_default() {
            "send" if message["held"] == true => {
                let gid = group()?;
                let (id, delivery) = self.node.send(&gid.0, &message["payload"], true).await?;
                if message.get("id").is_some() {
                    let held_by: Vec<Value> = delivery.held.iter().map(|m| self.describe(&gid, m)).collect::<Result<_>>()?;
                    let refused: Vec<Value> = delivery
                        .refused
                        .iter()
                        .map(|(member, reason)| Ok(json!({ "member": self.describe(&gid, member)?, "reason": reason })))
                        .collect::<Result<_>>()?;
                    let answer = json!({ "id": hex::encode(&id.0), "held_by": held_by, "refused": refused, "pending": delivery.held.is_empty() });
                    self.plugins.send(kind, &reply(answer)).await?;
                }
            }
            "send" => self.node.send_live(&group()?.0, &message["payload"], to)?,
            "log" => {
                let gid = group()?;
                let from = message["after"].as_u64().map(|after| (after, message["epoch"].as_u64().unwrap_or_default()));
                self.node.follow_log(&gid.0, from)?;
                if let Some((after, _)) = from {
                    self.handed.insert(gid.clone(), after);
                    self.hand_entries(&gid).await?;
                }
            }
            "append" => {
                let (node, group, payload) = (self.node.clone(), group()?, message["payload"].clone());
                self.background(kind, group.clone(), message["id"].clone(), async move { Ok(Done::Appended(node.append(&group.0, &payload).await?)) });
            }
            "spread" => {
                let (node, gid) = (self.node.clone(), group()?);
                let link = FileLink::parse(message["link"].as_str().context("no link")?)?;
                let holders = async move { Ok(Done::Holders(node.holders(&gid.0, &link, SPREAD_WAIT).await)) };
                self.background(kind, group()?, message["id"].clone(), holders);
            }
            "frame" => self.node.frame(&group()?.0, to.context("a frame goes to a member")?, message["frame"].clone())?,
            "add" => {
                let data = serde_json::from_value::<Bytes>(message["data"].clone())?.0;
                let link = self.node.add_file(&group()?.0, data).await?;
                self.plugins.send(kind, &reply(json!({ "link": link.link() }))).await?;
            }
            "hold" => self.node.hold(&group()?.0, &serde_json::from_value::<Vec<String>>(message["links"].clone())?)?,
            "links" => self.node.set_links(&group()?.0, serde_json::from_value(message["links"].clone())?)?,
            "fetch" => {
                let gid = group()?;
                let link = FileLink::parse(message["link"].as_str().context("no link")?)?;
                ensure!(self.node.linked(&gid.0).contains(&link), "the group does not link that file");
                match self.node.file(&link).await? {
                    Some(data) => self.plugins.send(kind, &reply(json!({ "data": Bytes(data) }))).await?,
                    None => {
                        self.node.fetch(&gid.0, link.clone());
                        let deadline = Instant::now() + FETCH_WAIT;
                        self.kind_fetches.push(KindFetch { kind: kind.to_owned(), id: message["id"].clone(), link, deadline });
                    }
                }
            }
            "state" => {
                let data = serde_json::from_value::<Bytes>(message["data"].clone())?.0;
                self.node.hand_state(&group()?.0, to.context("a state goes to a member")?, data).await?;
            }
            "event" => {
                let gid = group()?;
                let event = message["event"].as_object().context("no event")?;
                if event.get("type") == Some(&json!("warning")) {
                    self.warn(Some(&gid), event.get("text").and_then(Value::as_str).unwrap_or_default().to_owned());
                    return Ok(());
                }
                let mut item = json!({ "group": b64(&gid.0) });
                merge(&mut item, Value::Object(event.clone()));
                if let Some(key) = message["key"].as_str() {
                    item["printed"] = json!({ "kind": kind, "key": key });
                    self.outbox.take_keyed(&item["group"], &item["printed"]);
                }
                self.outbox.deliver(item, message["wake"] == true);
            }
            "info" => _ = self.infos.insert(group()?, message["info"].clone()),
            "answer" => {
                let id = message["id"].as_u64().unwrap_or_default();
                if let Some(reply) = self.commands.remove(&(kind.to_owned(), id)) {
                    let _ = reply.send(match &message["error"] {
                        Value::Null => message["answer"].clone(),
                        error => json!({ "error": error }),
                    });
                }
                if let Some(reply) = self.snapshots.remove(&(kind.to_owned(), id)) {
                    let data = message["answer"]["data"].as_str().and_then(|data| URL_SAFE_NO_PAD.decode(data).ok());
                    let _ = reply.send(data);
                }
            }
            other => bail!("unknown message {other:?}"),
        }
        Ok(())
    }

    /// Carries out a plugin's request without holding up the session; its answer follows as `Inbound::Done`.
    fn background(&self, kind: &str, group: Bytes, id: Value, done: impl Future<Output = Result<Done>> + Send + 'static) {
        let (inbound, kind) = (self.inbound.clone(), kind.to_owned());
        tokio::spawn(async move {
            let _ = inbound.send(Inbound::Done { kind, group, id, done: done.await });
        });
    }

    // Members, identities and contacts.

    fn described_members(&self, gid: &Bytes) -> Result<Vec<Value>> {
        self.node.members(&gid.0)?.iter().map(|m| self.describe(gid, m)).collect()
    }

    fn describe_key(&self, gid: &Bytes, key: &Bytes) -> Value {
        let member = self.node.members(&gid.0).ok().and_then(|members| members.into_iter().find(|m| &m.key == key));
        match member {
            Some(member) => self.describe(gid, &member).unwrap_or_else(|_| json!({ "fp": fp(&key.0) })),
            None if *key == self.node.key() => json!({ "name": self.config.name, "fp": fp(&key.0), "you": true }),
            None => json!({ "fp": fp(&key.0) }),
        }
    }

    /// A member as events show it: its name, its identity as this session knows it, and who added it.
    fn describe(&self, gid: &Bytes, member: &Member) -> Result<Value> {
        if member.key.0.is_empty() {
            return Ok(json!({ "iroh": member.iroh }));
        }
        let mut described = json!({ "name": member.name, "fp": fp(&member.key.0), "device": member.device_name });
        if member.key == self.node.key() {
            described["you"] = json!(true);
        }
        if let Some(claim) = &member.identity {
            described["identity"] = self.known(gid, claim)?;
        }
        if let Some((by, how)) = &member.added {
            let adder = self.node.members(&gid.0).ok().and_then(|members| members.into_iter().find(|m| &m.key == by));
            let mut added = json!({ "fp": fp(&by.0), "how": how });
            if let Some(adder) = adder {
                added["name"] = json!(adder.name);
            }
            described["added_by"] = added;
        }
        Ok(described)
    }

    /// An identity as this one knows it: its own, a contact (verified or introduced), or unknown: only its own claim,
    /// with the introductions others made of it.
    fn known(&self, gid: &Bytes, claim: &Claim) -> Result<Value> {
        let id = &claim.identity.id;
        let mut known = json!({ "id": id });
        let DeviceState { identities, contacts, .. } = self.device_state()?;
        let own = identities.into_iter().find(|(identity, _)| &identity.id == id);
        let present = |by: &[u8]| {
            self.node.members(&gid.0).is_ok_and(|members| members.iter().any(|m| m.identity.as_ref().is_some_and(|c| c.identity.id.0 == by)))
        };
        if let Some((_, name)) = &own {
            known["name"] = json!(name);
            known["how"] = json!("self");
        } else if let Some((_, contact)) = contacts.iter().find(|(cid, _)| cid == id) {
            known["name"] = json!(contact.name);
            known["how"] = json!(contact.how);
            if let Some(by) = &contact.by {
                let name = contacts.iter().find(|(cid, _)| cid == by).map_or_else(|| b64(&by.0), |(_, c)| c.name.clone());
                known["by"] = json!(name);
                if !present(&by.0) {
                    known["introducer_absent"] = json!(true);
                }
            }
        } else {
            known["name"] = json!(claim.name);
            known["claim"] = json!(true);
            known["how"] = json!("unknown");
            if contacts.iter().any(|(_, c)| c.name.eq_ignore_ascii_case(&claim.name)) {
                known["warning"] = json!(format!("not your {}", claim.name));
            }
            let introductions: Vec<Value> = self
                .db
                .prepare("SELECT by, name FROM introductions WHERE identity = ?")?
                .query_map([&id.0], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .map(|row| row.map(|(by, name)| json!({ "by": serde_json::from_str::<Value>(&by).unwrap_or(Value::Null), "name": name })))
                .collect::<Result<_, _>>()?;
            if !introductions.is_empty() {
                known["introduced"] = json!(introductions);
            }
        }
        if let Some(error) = &claim.error {
            known["error"] = json!(error);
        }
        if let (Some(device), None) = (&claim.added_by_device, &own) {
            known["new_device"] = json!(format!("added by {device}"));
        }
        Ok(known)
    }

    /// The name this identity gives another: its contact name, else the other's own claim.
    fn display_name(&self, claim: &Claim) -> Result<String> {
        let contact = self.device_state()?.contacts.into_iter().find(|(id, _)| *id == claim.identity.id);
        Ok(contact.map_or_else(|| claim.name.clone(), |(_, c)| c.name))
    }

    fn introduced(&mut self, gid: &Bytes, by: &Member, identity: IdentityRef, name: String, how: How) -> Result<()> {
        let sender = self.describe(gid, by)?;
        let state = self.device_state()?;
        let own = state.identities.iter().any(|(own, _)| own.id == identity.id);
        let contact = state.contacts.iter().any(|(id, _)| *id == identity.id);
        if !own && !contact {
            let by_id = by.identity.as_ref().map_or_else(|| by.key.clone(), |claim| claim.identity.id.clone());
            self.db.execute(
                "INSERT OR REPLACE INTO introductions (identity, by, name, ref) VALUES (?, ?, ?, ?)",
                params![identity.id.0, sender.to_string(), name, json!({ "by": by_id, "identity": identity }).to_string()],
            )?;
        }
        let item = json!({ "type": "introduced", "group": b64(&gid.0), "by": sender, "identity": { "id": identity.id, "name": name }, "how": how });
        self.outbox.deliver(item, false);
        Ok(())
    }

    async fn introduce(&mut self, group: Option<String>, member: &str, to: &str) -> Result<Value> {
        let gid = self.resolve(group)?;
        let introduced = self.member(&gid, member)?;
        let to = self.member(&gid, to)?;
        let claim = introduced.identity.filter(|c| c.error.is_none()).context("that member speaks as no verified identity")?;
        let known = self.known(&gid, &claim)?;
        ensure!(known["how"] != "unknown", "you can introduce only your contacts and your own identities");
        let name = known["name"].as_str().unwrap_or_default().to_owned();
        let to_fp = Bytes(Sha256::digest(&to.key.0)[..8].to_vec());
        let payload = Control::Introduce { identity: claim.identity.clone(), name: name.clone(), how: How::Introduce, to: vec![to_fp] };
        let (id, _) = self.node.send(&gid.0, &serde_json::to_value(payload)?, false).await?;
        Ok(json!({ "id": hex::encode(&id.0), "group": b64(&gid.0), "identity": { "id": claim.identity.id, "name": name }, "to": self.describe(&gid, &to)? }))
    }

    /// The device's node, which this process runs when it holds the device's lock.
    fn device(&self) -> Result<&SessionNode> {
        self.device.as_ref().context("this session process does not act for the device")
    }

    fn device_file(&self) -> PathBuf {
        self.home.join("device.json")
    }

    /// This device's identities, with their names.
    fn identities(&self) -> Result<Vec<(IdentityRef, String)>> {
        Ok(self.device_state()?.identities)
    }

    fn contact_list(&self) -> Result<Vec<(Bytes, Contact)>> {
        Ok(self.device_state()?.contacts)
    }

    /// The identity a new membership speaks as: the one named, or else the device's first.
    fn speaking_as(&self, as_: Option<String>) -> Result<Option<IdentityRef>> {
        match as_ {
            Some(as_) => Ok(Some(self.own_identity(&as_)?.0)),
            None => Ok(self.identities()?.into_iter().next().map(|(identity, _)| identity)),
        }
    }

    /// An identity this device is on, by id or name.
    fn own_identity(&self, name: &str) -> Result<(IdentityRef, String)> {
        let identities = self.identities()?;
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
        let (_, contact) = self.contact_list()?.into_iter().find(|(cid, _)| *cid == id).expect("found by contact");
        Ok((id, contact.name))
    }

    fn contact(&self, name: &str) -> Result<Bytes> {
        let contacts = self.contact_list()?;
        let contact = contacts.iter().find(|(id, c)| b64(&id.0) == name || c.name.eq_ignore_ascii_case(name));
        Ok(contact.with_context(|| format!("no contact {name}; `contacts` lists them"))?.0.clone())
    }

    async fn identity(&mut self, op: IdentityOp) -> Result<Value> {
        let device = self.device()?.clone();
        match op {
            IdentityOp::Create { name, membership } => {
                let membership = membership.map(|m| crate::service(&m)).transpose()?.unwrap_or(self.config.membership.clone());
                let identity = device.identity_create(&name, membership).await?;
                device.device().save(&self.device_file())?;
                Ok(json!({ "identity": identity.id, "name": name }))
            }
            IdentityOp::List => {
                let mut identities = Vec::new();
                let me = device.device().public();
                for (identity, _) in device.identities() {
                    let list = device.device_list(&identity).await?;
                    let devices: Vec<Value> =
                        list.devices.iter().map(|d| json!({ "key": d.key, "name": d.name, "you": d.key.0 == me })).collect();
                    identities.push(json!({ "identity": identity.id, "name": list.name, "devices": devices }));
                }
                Ok(json!({ "identities": identities }))
            }
            IdentityOp::Remove { identity, device: removed } => {
                let identities = device.identities();
                let identity = match (identity, &identities[..]) {
                    (Some(identity), _) => self.own_identity(&identity)?.0,
                    (None, [(only, _)]) => only.clone(),
                    (None, _) => bail!("pass --identity: this device is on {} identities", identities.len()),
                };
                let list = device.device_list(&identity).await?;
                let listed = list.devices.iter().find(|d| b64(&d.key.0) == removed || d.name == removed).context("no such device")?;
                device.remove_device(&identity, &listed.key.0).await?;
                // This session's groups lose the device's sessions too.
                self.node.device_list(&identity).await?;
                Ok(json!({ "identity": identity.id, "removed": listed.key }))
            }
        }
    }

    fn contacts(&self) -> Result<Value> {
        let contacts = self.contact_list()?;
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
        let introductions: Vec<Value> = self
            .db
            .prepare("SELECT identity, by, name FROM introductions")?
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
            .map(|row| row.map(|(id, by, name)| json!({ "identity": b64(&id), "name": name, "by": serde_json::from_str::<Value>(&by).unwrap_or(Value::Null) })))
            .collect::<Result<_, _>>()?;
        Ok(json!({ "contacts": listed, "introductions": introductions }))
    }

    async fn accept(&mut self, identity: &str, name: Option<String>) -> Result<Value> {
        let id = URL_SAFE_NO_PAD.decode(identity).context("expected an identity id")?;
        let introduction: (String, String) = self
            .db
            .query_row("SELECT name, ref FROM introductions WHERE identity = ?", [&id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
            .context("no introduction of that identity")?;
        let by: Bytes = serde_json::from_value(serde_json::from_str::<Value>(&introduction.1)?["by"].clone())?;
        let contact = Contact { name: name.unwrap_or(introduction.0), how: contacts::How::Introduced, by: Some(by), at: lmk_node::now() };
        Box::pin(self.request(Request::SetContact { identity: Bytes(id.clone()), contact: contact.clone() })).await?;
        self.db.execute("DELETE FROM introductions WHERE identity = ?", [&id])?;
        Ok(json!({ "identity": Bytes(id), "name": contact.name, "how": contact.how }))
    }

    fn warn(&mut self, gid: Option<&Bytes>, text: String) {
        self.outbox.print(json!({ "type": "warning", "group": gid.map(|g| b64(&g.0)), "text": text }));
    }

    pub async fn shutdown(&self) {
        // Plugins stop with the session: their stdin closes when it ends.
        let _ = self.node.shutdown().await;
        if let Some(device) = &self.device {
            let _ = device.shutdown().await;
            let _ = std::fs::remove_file(self.home.join("device-endpoint"));
        }
        let _ = std::fs::remove_file(self.config.dir.join("endpoint"));
    }
}

/// Runs a session until `shutdown`: prints `ready`, then handles what arrives and prints what concerns the agent, one
/// JSON object per line.
pub async fn run(
    mut session: Session,
    mut inbound: mpsc::UnboundedReceiver<Inbound>,
    mut events: mpsc::UnboundedReceiver<Event>,
    mut print: impl FnMut(String),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let ready = json!({ "type": "ready", "session": session.config.handle, "member": session.me()?, "state": session.config.dir });
    print(ready.to_string());
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        session.publish();
        session.emit(&mut print).await;
        let due = session.next_due();
        tokio::select! {
            Some(item) = inbound.recv() => session.handle(item).await,
            Some(event) = events.recv() => session.event(event).await,
            Some((kind, line)) = session.plugin_lines.recv() => session.plugin_line(kind, line).await,
            _ = tokio::time::sleep_until(due) => session.tick().await,
            _ = &mut shutdown => break,
        }
    }
    session.shutdown().await;
    Ok(())
}
