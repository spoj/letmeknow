//! The session process: the client core on this session's node, and, holding the device's lock, the device's node with
//! the devices kind; the plugins of its groups' kinds as executables; and what concerns the agent, printed. Chat is its
//! built-in kind. The session process that holds the lock publishes the device's identities, its key on each,
//! contacts and openings to `device-state.json`, and answers the requests only the device's node can on the command
//! channel `device-endpoint`, both in `LETMEKNOW_HOME`; the device's other session processes read the one and send such
//! requests to the other, among them for the certificates their credentials carry.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use lmk_client::{Access, BoxFuture, Chat, Client, ClientEvent, DeviceState, File, Introduction, Remote, message_id};
use lmk_core::device::Device;
use lmk_core::provider::SqliteProvider;
use lmk_node::devices::Devices;
use lmk_node::{Event, Node};
use lmk_proto::Bytes;
use lmk_proto::group::{ChatMessage, DEVICES, Service};
use lmk_proto::links::FileLink;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::Network;
use crate::cli::{Request, private_file};
use crate::kinds::Plugins;
use crate::policy::{Outbox, mentions, wakes};

/// How long after starting what arrives counts as catching up.
const CATCH_UP_WINDOW: Duration = Duration::from_secs(3);
/// How often a session process that does not act for the device tries its lock.
const DEVICE_RETRY: Duration = Duration::from_secs(10);
/// How often a session checks that its device is still on the identities it speaks as.
const IDENTITIES_CHECK: Duration = Duration::from_secs(10);

pub type SessionNode = Node<SqliteProvider>;

pub struct Config {
    pub handle: String,
    pub dir: PathBuf,
    pub name: String,
    pub hold: Duration,
    pub keep_log: bool,
    /// For groups and identities this session creates.
    pub membership: Service,
    /// Where it looks for kinds' plugins, in order.
    pub plugins: Vec<PathBuf>,
}

/// A request on a command channel, and where its answer goes.
pub type Inbound = (Request, oneshot::Sender<Value>);

/// The device's node, as another session process runs it: its state as published in `LETMEKNOW_HOME`, and its command
/// channel.
struct Published(PathBuf);

impl Remote for Published {
    fn state(&self) -> Result<DeviceState> {
        match std::fs::read(self.0.join("device-state.json")) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DeviceState::default()),
            Err(error) => Err(error.into()),
        }
    }

    fn request(&self, request: lmk_client::Request) -> BoxFuture<Result<Value>> {
        let endpoint = self.0.join("device-endpoint");
        Box::pin(async move {
            let channel = crate::cli::connect(&endpoint).await.context("no session process acts for this device")?;
            crate::cli::exchange(channel, Request::Client(request)).await
        })
    }
}

pub struct Session {
    db: Connection,
    client: Client<SqliteProvider>,
    /// What the client tells.
    told: mpsc::UnboundedReceiver<ClientEvent>,
    /// The device's node, when this process holds the device's lock.
    device: Option<SessionNode>,
    lock: std::fs::File,
    device_retry: Instant,
    /// When this session next checks its device's identities.
    identities_at: Instant,
    /// The device's state as last published.
    published: String,
    home: PathBuf,
    network: Network,
    config: Config,
    outbox: Outbox,
    catching_up: Option<Instant>,
    inbound: mpsc::UnboundedSender<Inbound>,
}

fn b64(bytes: &[u8]) -> String {
    serde_json::to_value(Bytes(bytes.to_vec())).expect("JSON").as_str().expect("a string").to_owned()
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

/// Writes a file into `dir`, in a file only this user can read; returns its path.
fn save(dir: &Path, link: &FileLink, name: Option<&str>, bytes: &[u8]) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
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
        let (plugins, lines) = Plugins::new(crate::kinds::discover(&config.plugins), config.dir.join("kinds"));
        let device = Device::load(&home.join("device.json"))?;
        let client_config = lmk_client::Config { name: config.name.clone(), device, membership: config.membership.clone() };
        let access = Access::Elsewhere(Arc::new(Published(home.to_path_buf())));
        let (client, told) = Client::new(node, client_config, access, Arc::new(plugins), lines);
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(home.join("device.lock"))?;
        let mut session = Self {
            db,
            client,
            told,
            device: None,
            lock,
            device_retry: Instant::now(),
            identities_at: Instant::now(),
            published: String::new(),
            home: home.to_path_buf(),
            network,
            config,
            outbox: Outbox::default(),
            catching_up: Some(Instant::now() + CATCH_UP_WINDOW),
            inbound,
        };
        session.take_introductions()?;
        session.take_device().await?;
        let groups = session.client.node().groups();
        for gid in &groups {
            session.outbox.catch_up(&b64(&gid.0));
        }
        session.client.start().await;
        for gid in groups {
            if !session.client.chats(&gid) {
                continue;
            }
            // Messages that arrived but were never taken in, as when the session stopped while they waited.
            for message in session.client.node().messages(&gid.0)? {
                if message.payload["type"] == "message" && !session.taken(&message.id.0)? && message.sender.key != session.client.node().key() {
                    let sender = serde_json::to_value(session.client.describe(&gid, &message.sender)?)?;
                    let id = message.id.0.as_slice().try_into()?;
                    session.received(gid.clone(), id, sender, message.payload).await?;
                }
            }
        }
        Ok(session)
    }

    /// Hands the client the introductions that letmeknow 0.12 kept in this session's own table.
    fn take_introductions(&self) -> Result<()> {
        let kept = self.db.query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'introductions'", [], |_| Ok(()));
        if kept.optional()?.is_none() {
            return Ok(());
        }
        let rows: Vec<(Vec<u8>, String, String, String)> = self
            .db
            .prepare("SELECT identity, by, name, ref FROM introductions")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        for (identity, by, name, reference) in rows {
            let by_id = serde_json::from_value(serde_json::from_str::<Value>(&reference)?["by"].clone())?;
            self.client.add_introduction(Introduction { identity: Bytes(identity), name, by: serde_json::from_str(&by)?, by_id })?;
        }
        self.db.execute("DROP TABLE introductions", [])?;
        Ok(())
    }

    /// This session as the agent sees it in `ready`.
    pub fn me(&self) -> Result<Value> {
        self.client.me()
    }

    /// Acts for the device if no other session process does: runs its node and answers its command channel.
    async fn take_device(&mut self) -> Result<()> {
        self.device_retry = Instant::now() + DEVICE_RETRY;
        match self.lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(()),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        let device = Device::load(&self.home.join("device.json"))?;
        let provider = SqliteProvider::open(&self.home.join("device.db"))?;
        let kinds = vec![lmk_proto::group::CHAT.into(), DEVICES.into()];
        let config = crate::node_config(&self.network, &self.home, &device.name, Some(device.clone()), self.home.join("device-files"), kinds);
        let (node, mut events) = Node::start(provider, config).await?;
        let path = self.home.join("device.json");
        let devices = Devices::new(node.clone(), device, Arc::new(move |device: &Device| device.save(&path)));
        let (client, taking) = (self.client.clone(), devices.clone());
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                client.device_event(&taking, event);
            }
        });
        crate::cli::open_channel(&self.home.join("device-endpoint"), self.inbound.clone()).await?;
        self.client.set_access(Access::Here(devices));
        self.device = Some(node);
        Ok(())
    }

    /// Writes the device's state where its other session processes read it, if this process acts for the device and
    /// the state changed.
    fn publish(&mut self) {
        if self.device.is_none() {
            return;
        }
        let written = (|| {
            let state = serde_json::to_string(&self.client.device_state()?)?;
            if state != self.published {
                let path = self.home.join("device-state.json");
                let new = path.with_extension("new");
                private_file(&new, state.as_bytes())?;
                std::fs::rename(&new, &path)?;
                self.published = state;
            }
            anyhow::Ok(())
        })();
        if let Err(error) = written {
            self.warn(None, format!("publishing this device's state: {error:#}"));
        }
    }

    /// When something is next due without anything arriving.
    pub fn next_due(&self) -> Instant {
        let held = self.outbox.deadline(self.config.hold);
        let device = self.device.is_none().then_some(self.device_retry);
        let later = Instant::now() + Duration::from_secs(3600);
        let due = held.into_iter().chain(device).chain([self.identities_at]);
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
        if self.identities_at <= now {
            self.identities_at = now + IDENTITIES_CHECK;
            for error in self.client.leave_identities_left().await {
                eprintln!("letmeknow: leaving the groups of an identity this device left: {error:#}");
            }
        }
        if self.outbox.deadline(self.config.hold).is_some_and(|at| at <= now) {
            self.outbox.flush_held();
        }
        if self.catching_up.is_some_and(|at| at <= now) {
            self.catching_up = None;
            self.outbox.caught_up();
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
                let (kind, key) = (printed["kind"].as_str().unwrap_or_default(), printed["key"].as_str().unwrap_or_default());
                self.client.printed(kind, item["group"].as_str().unwrap_or_default(), key);
            }
        }
    }

    /// Brings the plugins into step, and takes in what they told meanwhile.
    async fn sync_kinds(&mut self) {
        self.client.sync_kinds().await;
        while let Ok(event) = self.told.try_recv() {
            self.client_event(event).await;
        }
    }

    pub async fn handle(&mut self, (request, reply): Inbound) {
        // The agent may have just changed a file.
        self.sync_kinds().await;
        let answer = match request {
            Request::Fetch { link } => return self.fetch(link, reply),
            // A plugin's command may take a while, and may need this session meanwhile: it is answered when the plugin
            // answers.
            Request::Kind { kind, args, cwd } => return self.command(kind, args, cwd, reply).await,
            Request::Send { group, to, reply_to, urgent, attach, attach_name, text } => {
                self.send(group, to, reply_to, urgent, attach.map(|data| (data, attach_name)), text).await
            }
            Request::Read { id, ancestors } => self.read(&id, ancestors),
            Request::Client(request) => self.client.request(request).await,
        };
        // Before the answer, so that the device's other session processes read what the request changed.
        self.publish();
        let _ = reply.send(answer.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
        self.outbox.flush_held();
    }

    /// Passes `letmeknow <kind> <args>...` to the kind's plugin; `reply` gets its answer.
    async fn command(&mut self, kind: String, args: Vec<String>, cwd: String, reply: oneshot::Sender<Value>) {
        match self.client.command(&kind, args, cwd).await {
            Ok(answered) => {
                tokio::spawn(async move {
                    let answer = answered.await.unwrap_or_else(|_| Err(anyhow::anyhow!("the {kind} plugin stopped")));
                    let _ = reply.send(answer.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
                });
            }
            Err(error) => _ = reply.send(json!({ "error": format!("{error:#}") })),
        }
        self.outbox.flush_held();
    }

    /// What the client tells.
    pub async fn client_event(&mut self, event: ClientEvent) {
        if let Err(error) = self.on(event).await {
            self.warn(None, format!("{error:#}"));
        }
    }

    async fn on(&mut self, event: ClientEvent) -> Result<()> {
        let wake = match &event {
            ClientEvent::Joined { .. }
            | ClientEvent::Left { .. }
            | ClientEvent::Revoked { .. }
            | ClientEvent::Removed { .. }
            | ClientEvent::Settings { .. } => Some(true),
            ClientEvent::Introduced { .. } => Some(false),
            _ => None,
        };
        if let Some(wake) = wake {
            self.outbox.deliver(serde_json::to_value(&event)?, wake);
            return Ok(());
        }
        match event {
            ClientEvent::Warning { .. } => self.outbox.print(serde_json::to_value(&event)?),
            ClientEvent::Gone { group } => self.forget(&group)?,
            ClientEvent::Message { group, id, from, payload } => self.received(group, message_id(&id)?, serde_json::to_value(from)?, payload).await?,
            ClientEvent::Sent { .. } => self.outbox.deliver(serde_json::to_value(&event)?, false),
            ClientEvent::File { hash } => self.arrived(hex::decode(hash)?.try_into().ok().context("a hash is 32 bytes")?).await?,
            ClientEvent::Plugin { group, kind, event, wake, key } => {
                let mut item = json!({ "group": group });
                item.as_object_mut().expect("an object").extend(event);
                if let Some(key) = key {
                    item["printed"] = json!({ "kind": kind, "key": key });
                    self.outbox.take_keyed(&item["group"], &item["printed"]);
                }
                self.outbox.deliver(item, wake);
            }
            _ => {}
        }
        Ok(())
    }

    /// Clears what the session kept of a group the client let go of.
    fn forget(&mut self, gid: &Bytes) -> Result<()> {
        for table in ["taken", "attachments"] {
            self.db.execute(&format!("DELETE FROM {table} WHERE gid = ?"), [&gid.0])?;
        }
        let attachments = self.attachments_dir(gid);
        if attachments.exists() {
            std::fs::remove_dir_all(attachments)?;
        }
        self.client.node().scrub()
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
        let gid = self.client.chat(group)?;
        let reply_to = reply_to.map(|id| message_id(&id)).transpose()?;
        if let Some(id) = &reply_to {
            self.mark_seen(id)?;
        }
        let attachment = match attach {
            Some((data, name)) => {
                let data = B64.decode(data)?;
                let media_type = image_type(&data).map(|t| format!("image/{t}")).unwrap_or_default();
                Some(File { name, media_type, data })
            }
            None => None,
        };
        let after = self.client.tips(&gid, |id| self.seen(id).unwrap_or(false))?;
        let (id, answer) = self.client.send(&gid, Chat { text, to, reply_to, urgent, attachment }, after).await?;
        self.db.execute("INSERT OR IGNORE INTO taken (id, gid, seen) VALUES (?, ?, 1)", params![id.0, gid.0])?;
        Ok(answer)
    }

    /// A chat message the client took in, in log order but past the gaps the node no longer fetches: those it comes
    /// after that this session has not taken in show as missing.
    async fn received(&mut self, gid: Bytes, id: [u8; 32], sender: Value, payload: Value) -> Result<()> {
        if self.taken(&id)? {
            return Ok(());
        }
        self.take_message(&gid, id, sender, payload).await
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

    /// Takes in a chat message.
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
            match self.client.node().file(&link).await? {
                Some(bytes) => {
                    let path = save(&self.attachments_dir(gid), &link, Some(&name), &bytes)?;
                    self.db.execute("UPDATE attachments SET path = ? WHERE hash = ? AND message = ?", params![path.to_str(), link.hash, id])?;
                    item["attachment"]["path"] = json!(path);
                }
                None => item["attachment"]["pending"] = json!(true),
            }
        }
        self.outbox.deliver(item, wakes);
        Ok(())
    }

    fn mine(&self, id: &str) -> bool {
        let node = self.client.node();
        message_id(id).is_ok_and(|id| node.message(&id).ok().flatten().is_some_and(|m| m.sender.key == node.key()))
    }

    fn message_json(&self, gid: &Bytes, id: [u8; 32], from: Value, payload: &Value, fresh: bool) -> Result<Value> {
        let me = serde_json::to_value(self.client.describe_key(gid, &self.client.node().key())?)?;
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

    /// Records that a message entered the agent's context. Its text is then deleted, unless `listen --keep-log` or it
    /// is this session's own, which it keeps to send again.
    fn mark_seen(&self, id: &[u8; 32]) -> Result<()> {
        let node = self.client.node();
        let Some(message) = node.message(id)? else { return Ok(()) };
        self.db.execute("INSERT OR IGNORE INTO taken (id, gid) VALUES (?, ?)", params![id, message.group.0])?;
        self.db.execute("UPDATE taken SET seen = 1 WHERE id = ?", [id])?;
        if !self.config.keep_log && message.payload["type"] == "message" && message.sender.key != node.key() {
            let mut payload = message.payload;
            payload["content"] = json!("");
            node.redact(id, payload)?;
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
                let Some(message) = self.client.node().message(&id)? else {
                    ensure!(depth > 0, "unknown message {}", hex::encode(id));
                    continue;
                };
                let Ok(chat) = serde_json::from_value::<ChatMessage>(message.payload.clone()) else { continue };
                let from = serde_json::to_value(self.client.describe(&message.group, &message.sender)?)?;
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

    /// A file arrived: for the attachments waiting for it.
    #[allow(clippy::type_complexity)]
    async fn arrived(&mut self, hash: [u8; 32]) -> Result<()> {
        let waiting: Vec<(Vec<u8>, Vec<u8>, String, String, bool)> = self
            .db
            .prepare("SELECT gid, message, link, name, wakes FROM attachments WHERE hash = ? AND path IS NULL")?
            .query_map([hash], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<Result<_, _>>()?;
        for (gid, message, link, name, wakes) in waiting {
            let (gid, link) = (Bytes(gid), FileLink::parse(&link)?);
            let bytes = self.client.node().file(&link).await?.context("an arrived file is held")?;
            let path = save(&self.attachments_dir(&gid), &link, Some(&name), &bytes)?;
            self.db.execute("UPDATE attachments SET path = ? WHERE hash = ? AND message = ?", params![path.to_str(), hash, message])?;
            let item = json!({ "type": "attachment", "group": b64(&gid.0), "message": hex::encode(&message), "name": name, "path": path });
            self.outbox.deliver(item, wakes);
        }
        Ok(())
    }

    /// The file a message's attachment or a doc's text links, decrypted into a file only this user can read. The answer
    /// waits for the file if no copy is here yet.
    fn fetch(&mut self, link: String, reply: oneshot::Sender<Value>) {
        let found = (|| -> Result<_> {
            let parsed = FileLink::parse(link.trim())?;
            let (gid, name) = self.linking(&parsed.link())?.context("no message or doc here links that")?;
            Ok((parsed, gid, name))
        })();
        let (link, gid, name) = match found {
            Ok(found) => found,
            Err(error) => {
                let _ = reply.send(json!({ "error": format!("{error:#}") }));
                return;
            }
        };
        let (client, dir) = (self.client.clone(), self.attachments_dir(&gid));
        tokio::spawn(async move {
            let fetched = async {
                let bytes = client.fetched(&gid, &link).await?;
                anyhow::Ok(json!({ "path": save(&dir, &link, name.as_deref(), &bytes)?, "bytes": bytes.len() }))
            };
            let _ = reply.send(fetched.await.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
        });
        self.outbox.flush_held();
    }

    /// The group whose chat messages or kind link `link`, and the file's name if a message attached it.
    fn linking(&self, link: &str) -> Result<Option<(Bytes, Option<String>)>> {
        let node = self.client.node();
        for gid in node.groups() {
            for message in node.messages(&gid.0)? {
                if message.payload["attachment"]["link"] == link {
                    return Ok(Some((gid, message.payload["attachment"]["name"].as_str().map(str::to_owned))));
                }
            }
            if node.linked(&gid.0).iter().any(|linked| linked.link() == link) {
                return Ok(Some((gid, None)));
            }
        }
        Ok(None)
    }

    fn warn(&mut self, gid: Option<&Bytes>, text: String) {
        self.outbox.print(json!({ "type": "warning", "group": gid.map(|g| b64(&g.0)), "text": text }));
    }

    pub async fn shutdown(&self) {
        // Plugins stop with the session: their stdin closes when it ends.
        let _ = self.client.node().shutdown().await;
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
    let client = session.client.clone();
    loop {
        session.publish();
        session.emit(&mut print).await;
        let due = session.next_due();
        tokio::select! {
            Some(item) = inbound.recv() => session.handle(item).await,
            Some(event) = events.recv() => client.event(event).await,
            Some(event) = session.told.recv() => session.client_event(event).await,
            (kind, line) = client.next_line() => client.plugin_line(kind, line).await,
            _ = tokio::time::sleep_until(due) => session.tick().await,
            _ = &mut shutdown => break,
        }
    }
    session.shutdown().await;
    Ok(())
}
