//! The session process: the client core on this session's node, and, holding the device's lock, the device's node with
//! the identity kind; the plugins of its groups' kinds as executables; and what concerns the agent, printed. Chat is its
//! built-in kind. The session process that holds the lock publishes the device's identity and its key on it to
//! `device-state.json`, and answers the requests only the device's node can on the command channel `device-endpoint`,
//! both in `LETMEKNOW_HOME`; the device's other session processes read the one and send such
//! requests to the other, among them for the certificates their credentials carry. It also finds which of the device's
//! sessions run, for the identity's other devices to hear, and hands each the adds for it.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use lmk_client::{Access, BoxFuture, Chat, Client, ClientEvent, DeviceState, File, Missing, Remote, message_id};
use lmk_core::device::Device;
use lmk_core::provider::SqliteProvider;
use lmk_node::identity::{Identity, Pending, Presence, SessionGroup};
use lmk_node::{Event, Message, Node};
use lmk_proto::Bytes;
use lmk_proto::group::{IDENTITY, Service};
use lmk_proto::links::FileLink;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::Network;
use crate::cli::{Request, private_file};
use crate::kinds::Plugins;
use crate::policy::{Outbox, mentions, wakes};
use crate::short;

/// How long after starting what arrives counts as catching up.
const CATCH_UP_WINDOW: Duration = Duration::from_secs(3);
/// How often a session process that does not act for the device tries its lock.
const DEVICE_RETRY: Duration = Duration::from_secs(10);
/// How often a session checks that its device is still on the identity it speaks as.
const IDENTITY_CHECK: Duration = Duration::from_secs(10);
/// How often the session acting for the device finds which of the device's sessions run.
const PRESENCE: Duration = Duration::from_secs(2);

pub type SessionNode = Node<SqliteProvider>;

pub struct Config {
    pub handle: String,
    pub dir: PathBuf,
    pub hold: Duration,
    pub keep_log: bool,
    /// The domain of the membership service for groups and identities this session creates.
    pub membership: String,
    /// Where it looks for kinds' plugins, in order.
    pub plugins: Vec<PathBuf>,
    /// Where it looks for a newer release.
    pub registry: String,
}

/// A request on a command channel, and where its answer goes.
pub type Inbound = (Request, oneshot::Sender<Value>);

/// Work the session loop started, finished.
pub enum Done {
    /// A request's answer, and where it goes.
    Answered(Result<Value>, oneshot::Sender<Value>),
    /// What failed of leaving the groups of identities this device left.
    IdentityRefreshed(Vec<anyhow::Error>),
    /// The handles of the device's sessions that run.
    Found(Vec<String>),
    /// How handing a session the add with this id went.
    Handed(Bytes, u64, Result<Value>),
}

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
            let channel = crate::cli::connect(&endpoint)
                .await
                .context("no session process acts for this device just now; another is taking over: retry in a moment")?;
            crate::cli::exchange(channel, Request::Client(request)).await
        })
    }
}

pub struct Session {
    db: Connection,
    client: Client<SqliteProvider>,
    plugins: Arc<Plugins>,
    /// What the client tells.
    told: mpsc::UnboundedReceiver<ClientEvent>,
    /// The session's lock, held while this process runs it.
    _held: std::fs::File,
    /// The device's node, when this process holds the device's lock.
    device: Option<SessionNode>,
    device_lock: std::fs::File,
    device_retry: Instant,
    /// When this session next checks its device's identity.
    identity_at: Instant,
    /// When the session acting for the device next finds which of the device's sessions run, and hands them their adds.
    presence_at: Instant,
    /// The adds handed to a session, by id, while it runs: one that failed goes again once the session starts again.
    handed: HashMap<Bytes, String>,
    /// The device's state as last published.
    published: String,
    /// The groups as last written to `groups.json`.
    groups: String,
    /// How each group this session has been in shows to the agent: by its name where none of its other groups has that
    /// name, or else by its id. Kept once the session leaves a group, for the events that tell of that.
    names: HashMap<String, String>,
    home: PathBuf,
    network: Network,
    config: Config,
    outbox: Outbox,
    catching_up: Option<Instant>,
    inbound: mpsc::UnboundedSender<Inbound>,
    /// Work in flight: the loop takes each as it finishes, and never waits on one.
    running: JoinSet<Done>,
}

fn b64(bytes: &[u8]) -> String {
    serde_json::to_value(Bytes(bytes.to_vec())).expect("JSON").as_str().expect("a string").to_owned()
}

/// The file extension of an image, by its first bytes: PNG, JPEG, GIF or WebP.
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
    #[allow(clippy::too_many_arguments)]
    pub async fn open(
        config: Config,
        db: Connection,
        node: SessionNode,
        home: &Path,
        network: Network,
        inbound: mpsc::UnboundedSender<Inbound>,
        held: std::fs::File,
        membership: Service,
    ) -> Result<Self> {
        let (plugins, lines) = Plugins::new(crate::kinds::discover(&config.plugins), config.dir.join("kinds"));
        let device = Device::load(&home.join("device.json"))?;
        let client_config = lmk_client::Config { device, membership };
        let access = Access::Elsewhere(Arc::new(Published(home.to_path_buf())));
        let plugins = Arc::new(plugins);
        let (client, told) = Client::new(node, client_config, access, plugins.clone(), lines);
        let device_lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(home.join("device.lock"))?;
        let mut session = Self {
            db,
            client,
            plugins,
            told,
            _held: held,
            device: None,
            device_lock,
            device_retry: Instant::now(),
            identity_at: Instant::now(),
            presence_at: Instant::now(),
            handed: HashMap::new(),
            published: String::new(),
            groups: String::new(),
            names: HashMap::new(),
            home: home.to_path_buf(),
            network,
            config,
            outbox: Outbox::default(),
            catching_up: Some(Instant::now() + CATCH_UP_WINDOW),
            inbound,
            running: JoinSet::new(),
        };
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
            // What was delivered after the last message shown, as when the session stopped before printing it.
            let (node, me) = (session.client.node(), session.client.node().key());
            let mut unshown = Vec::new();
            for message in node.messages(&gid.0)?.into_iter().rev() {
                if node.shown(&gid.0, &message.id.0)? {
                    break;
                }
                if message.payload["type"] == "message" && message.sender.key != me {
                    unshown.push(message);
                }
            }
            for message in unshown.iter().rev() {
                let event = session.message_event(message)?;
                session.received(event).await?;
            }
        }
        Ok(session)
    }

    /// Acts for the device if no other session process does: runs its node and answers its command channel.
    async fn take_device(&mut self) -> Result<()> {
        self.device_retry = Instant::now() + DEVICE_RETRY;
        match self.device_lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(()),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        let device = Device::load(&self.home.join("device.json"))?;
        let provider = SqliteProvider::open(&self.home.join("device.db"))?;
        let kinds = vec![lmk_proto::group::CHAT.into(), IDENTITY.into()];
        let config = crate::node_config(&self.network, &self.home, "", Some(device.clone()), self.home.join("device-files"), kinds);
        let (node, mut events) = Node::start(provider, config).await?;
        let path = self.home.join("device.json");
        let devices = Identity::new(node.clone(), device, Arc::new(move |device: &Device| device.save(&path)));
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

    /// Writes what changed of what other processes read: this session's groups to `groups.json` in its directory, for
    /// `sessions` and the session acting for the device; and, if this process acts for it, the device's state where its
    /// other session processes read it.
    fn publish(&mut self) {
        let replace = |path: PathBuf, text: &str| {
            let new = path.with_extension("new");
            private_file(&new, text.as_bytes())?;
            anyhow::Ok(std::fs::rename(&new, &path)?)
        };
        let written = (|| {
            let named = self.client.session_groups()?;
            let groups = serde_json::to_string(&named)?;
            if groups != self.groups {
                for group in &named {
                    let unique = !group.name.is_empty() && named.iter().filter(|other| other.name == group.name).count() == 1;
                    let id = b64(&group.group.0);
                    self.names.insert(id.clone(), if unique { group.name.clone() } else { id });
                }
                replace(self.config.dir.join("groups.json"), &groups)?;
                self.groups = groups;
            }
            if self.device.is_some() {
                let state = serde_json::to_string(&self.client.device_state()?)?;
                if state != self.published {
                    replace(self.home.join("device-state.json"), &state)?;
                    self.published = state;
                }
            }
            anyhow::Ok(())
        })();
        if let Err(error) = written {
            self.warn(format!("publishing this session's state: {error:#}"));
        }
    }

    /// When something is next due without anything arriving.
    pub fn next_due(&self) -> Instant {
        let held = self.outbox.deadline(self.config.hold);
        let device = self.device.is_none().then_some(self.device_retry);
        let presence = self.device.is_some().then_some(self.presence_at);
        let later = Instant::now() + Duration::from_secs(3600);
        let due = held.into_iter().chain(device).chain(presence).chain([self.identity_at]);
        due.chain(self.catching_up).fold(later, Instant::min)
    }

    pub async fn tick(&mut self) {
        let now = Instant::now();
        if self.device.is_none()
            && self.device_retry <= now
            && let Err(error) = self.take_device().await
        {
            self.warn(format!("acting for this device: {error:#}"));
        }
        if self.device.is_some() && self.presence_at <= now {
            // Not due again until this pass finishes.
            self.presence_at = now + Duration::from_secs(3600);
            let home = self.home.clone();
            self.running.spawn_local(async move { Done::Found(crate::cli::running(&home).await) });
        }
        if self.identity_at <= now {
            // Not due again until this check finishes.
            self.identity_at = now + Duration::from_secs(3600);
            let client = self.client.clone();
            self.running.spawn_local(async move { Done::IdentityRefreshed(client.refresh_identity().await) });
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
    /// acts on current state. A message is seen once its line is written.
    pub async fn emit(&mut self, print: &mut impl FnMut(String) -> std::io::Result<()>) -> Result<()> {
        if self.outbox.is_empty() {
            return Ok(());
        }
        self.sync_kinds().await;
        for mut item in self.outbox.take() {
            let printed = item.as_object_mut().and_then(|item| item.remove("printed"));
            print(short::line(&self.compact(item.clone())))?;
            if item["type"] == "message" {
                let shown = || -> Result<()> {
                    let gid: Bytes = serde_json::from_value(item["group"].clone())?;
                    self.show(&gid, &message_id(item["id"].as_str().context("a message has an id")?)?)
                };
                // Only a line that cannot be written stops the session.
                if let Err(error) = shown() {
                    self.warn(format!("marking a message shown: {error:#}"));
                }
            }
            if let Some(printed) = printed {
                let (kind, key) = (printed["kind"].as_str().unwrap_or_default(), printed["key"].as_str().unwrap_or_default());
                self.client.printed(kind, item["group"].as_str().unwrap_or_default(), key);
            }
        }
        Ok(())
    }

    /// An item as the agent reads it: made short, with its group by name where that name is its alone.
    fn compact(&self, mut item: Value) -> Value {
        if let Some(name) = item["group"].as_str().and_then(|group| self.names.get(group)) {
            item["group"] = json!(name);
        }
        short::compact(&mut item);
        item
    }

    /// Brings the plugins into step, and takes in what they told meanwhile.
    async fn sync_kinds(&mut self) {
        self.client.sync_kinds().await;
        while let Ok(event) = self.told.try_recv() {
            self.client_event(event).await;
        }
    }

    /// Takes a request: what may wait on the network goes on in `running`, and is answered once done.
    pub async fn handle(&mut self, (request, reply): Inbound) {
        if self.device.is_none()
            && let Err(error) = self.take_device().await
        {
            self.warn(format!("acting for this device: {error:#}"));
        }
        // The agent may have just changed a file.
        self.sync_kinds().await;
        let client = self.client.clone();
        match request {
            Request::Read { id, ancestors } => {
                let answer = self.read(&id, ancestors);
                self.answer(answer, reply);
            }
            Request::Send { group, to, reply_to, urgent, attach, attach_name, text } => {
                match self.message(group, to, reply_to, urgent, attach.map(|data| (data, attach_name)), text) {
                    Ok((gid, chat)) => _ = self.running.spawn_local(async move {
                        let sent = client.send(&gid, chat).await.map(|(_, answer)| answer);
                        Done::Answered(sent, reply)
                    }),
                    Err(error) => self.answer(Err(error), reply),
                }
            }
            Request::Fetch { link } => match self.fetching(&link) {
                Ok((link, gid, name)) => {
                    let dir = self.attachments_dir(&gid);
                    self.running.spawn_local(async move {
                        let fetched = async {
                            let bytes = client.fetched(&gid, &link).await?;
                            anyhow::Ok(json!({ "path": save(&dir, &link, name.as_deref(), &bytes)?, "bytes": bytes.len() }))
                        };
                        Done::Answered(fetched.await, reply)
                    });
                }
                Err(error) => self.answer(Err(error), reply),
            },
            // A plugin's command may take a while, and may need this session meanwhile.
            Request::Kind { kind, args, cwd } => {
                self.running.spawn_local(async move {
                    let answered = async {
                        let answer = client.command(&kind, args, cwd).await?;
                        answer.await.unwrap_or_else(|_| Err(anyhow::anyhow!("the {kind} plugin stopped")))
                    };
                    Done::Answered(answered.await, reply)
                });
            }
            Request::Client(request) => _ = self.running.spawn_local(async move { Done::Answered(client.request(request).await, reply) }),
            Request::IdentityJoin { .. } | Request::Status { .. } => unreachable!("the CLI sends these as the client's requests"),
            Request::Stop => unreachable!("`run` stops on it"),
            Request::Added { link, group, device } => {
                _ = self.running.spawn_local(async move { Done::Answered(client.added(&link, &group, &device).await, reply) })
            }
        }
    }

    /// Takes work in `running` that finished.
    pub fn done(&mut self, done: Done) {
        match done {
            Done::Answered(answer, reply) => self.answer(answer, reply),
            Done::IdentityRefreshed(failed) => {
                self.identity_at = Instant::now() + IDENTITY_CHECK;
                for error in failed {
                    self.warn(format!("refreshing identity claims: {error:#}"));
                }
            }
            Done::Found(running) => {
                self.presence_at = Instant::now() + PRESENCE;
                if let Err(error) = self.hand_adds(running) {
                    self.warn(format!("handing this device's sessions their adds: {error:#}"));
                }
            }
            Done::Handed(id, expires, handed) => {
                let Access::Here(devices) = self.client.access() else { return };
                if let Err(error) = handed.and_then(|_| devices.take(&id, expires)) {
                    self.warn(format!("handing a session of this device an add: {error:#}"));
                }
            }
        }
    }

    /// Tells the identity's other devices which of this device's sessions run, with the groups each last wrote, and hands
    /// each running session the adds for it it was not handed while it runs; an add for no session in particular goes to
    /// this one.
    fn hand_adds(&mut self, running: Vec<String>) -> Result<()> {
        let Access::Here(devices) = self.client.access() else { return Ok(()) };
        let mut groups = Vec::new();
        for session in &running {
            // None before the session first wrote its groups.
            let Ok(written) = std::fs::read(crate::cli::session_dir(&self.home, session)?.join("groups.json")) else { continue };
            let written: Vec<SessionGroup> = serde_json::from_slice(&written)?;
            groups.extend(written.into_iter().map(|group| SessionGroup { session: Some(session.clone()), ..group }));
        }
        devices.set_presence(Presence { sessions: running.clone(), groups });
        self.handed.retain(|_, session| running.contains(session));
        for Pending { id, by, add } in devices.adds()? {
            let session = if add.session.is_empty() { self.config.handle.clone() } else { add.session };
            if !running.contains(&session) || self.handed.contains_key(&id) {
                continue;
            }
            self.handed.insert(id.clone(), session.clone());
            let home = self.home.clone();
            self.running.spawn_local(async move {
                let request = Request::Added { link: add.link, group: add.group, device: by };
                Done::Handed(id, add.expires, crate::cli::call(&home, &session, request).await)
            });
        }
        Ok(())
    }

    fn answer(&mut self, answer: Result<Value>, reply: oneshot::Sender<Value>) {
        // Before the answer, so that the device's other session processes read what the request changed.
        self.publish();
        let _ = reply.send(answer.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
        self.outbox.flush_held();
    }

    /// What the client tells.
    pub async fn client_event(&mut self, event: ClientEvent) {
        if let Err(error) = self.on(event).await {
            self.warn(format!("{error:#}"));
        }
    }

    async fn on(&mut self, event: ClientEvent) -> Result<()> {
        if let ClientEvent::Joined { .. }
        | ClientEvent::Left { .. }
        | ClientEvent::Revoked { .. }
        | ClientEvent::Removed { .. }
        | ClientEvent::Settings { .. }
        | ClientEvent::Lost { .. } = &event
        {
            let mut item = serde_json::to_value(&event)?;
            if let ClientEvent::Lost { member, messages, .. } = &event
                && !member.you
            {
                let count: usize = messages.iter().map(|lost| lost.seqs.len()).sum();
                item["text"] = json!(format!(
                    "{} could not read {count} of your messages; send again, with --reply-to <id>, any that still matters",
                    lmk_client::shown(&item["member"]),
                ));
            }
            let wake = wakes(&item, |id| self.mine(id));
            self.outbox.deliver(item, wake);
            return Ok(());
        }
        if let ClientEvent::Message { id, .. } = &event {
            let id = message_id(id)?;
            if !self.taken(&id)? {
                self.received(event).await?;
            }
            return Ok(());
        }
        match event {
            ClientEvent::Warning { .. } => self.outbox.print(serde_json::to_value(&event)?),
            ClientEvent::Gone { group } => self.forget(&group)?,
            ClientEvent::Added { device, mut joined } => {
                joined["type"] = json!("joined");
                joined["how"] = json!("add");
                joined["device"] = json!(device);
                let wake = wakes(&joined, |id| self.mine(id));
                self.outbox.deliver(joined, wake);
            }
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

    /// A chat message to send, and the group it goes to.
    fn message(
        &mut self,
        group: Option<String>,
        to: Vec<String>,
        reply_to: Option<String>,
        urgent: bool,
        attach: Option<(String, String)>,
        text: String,
    ) -> Result<(Bytes, Chat)> {
        let gid = self.client.chat(group)?;
        let reply_to: Option<[u8; 32]> = match reply_to {
            Some(id) => {
                let target = self.find(&id)?;
                self.show(&target.group, &target.id.0)?;
                Some(target.id.0.as_slice().try_into()?)
            }
            None => None,
        };
        let attachment = match attach {
            Some((data, name)) => {
                let data = B64.decode(data)?;
                let media_type = image_type(&data).map(|t| format!("image/{t}")).unwrap_or_default();
                Some(File { name, media_type, data })
            }
            None => None,
        };
        Ok((gid, Chat { text, to, reply_to, urgent, attachment }))
    }

    /// Takes in a chat message, in delivery order: printed, with its attachment's file once it is held.
    async fn received(&mut self, event: ClientEvent) -> Result<()> {
        let mut item = self.message_item(event)?;
        let gid: Bytes = serde_json::from_value(item["group"].clone())?;
        let id = message_id(item["id"].as_str().context("a message has an id")?)?;
        self.db.execute("INSERT OR IGNORE INTO taken (id, gid) VALUES (?, ?)", params![id, gid.0])?;
        let wakes = wakes(&item, |id| self.mine(id));
        if item["attachment"].is_object() {
            let link = FileLink::parse(item["attachment"]["link"].as_str().context("an attachment has a link")?)?;
            let name = item["attachment"]["name"].as_str().unwrap_or_default().to_owned();
            self.db.execute(
                "INSERT OR IGNORE INTO attachments (hash, gid, message, link, name, wakes) VALUES (?, ?, ?, ?, ?, ?)",
                params![link.hash, gid.0, id, link.link(), name, wakes],
            )?;
            match self.client.node().file(&link).await? {
                Some(bytes) => {
                    let path = save(&self.attachments_dir(&gid), &link, Some(&name), &bytes)?;
                    self.db.execute("UPDATE attachments SET path = ? WHERE hash = ? AND message = ?", params![path.to_str(), link.hash, id])?;
                    item["attachment"]["path"] = json!(path);
                }
                None => item["attachment"]["pending"] = json!(true),
            }
        }
        self.outbox.deliver(item, wakes);
        Ok(())
    }

    fn taken(&self, id: &[u8]) -> Result<bool> {
        Ok(self.db.query_row("SELECT 1 FROM taken WHERE id = ?", [id], |_| Ok(())).optional()?.is_some())
    }

    /// Whether a message of this session's, in any of its groups, has this id.
    fn mine(&self, id: &str) -> bool {
        let node = self.client.node();
        message_id(id).is_ok_and(|id| node.groups().iter().any(|gid| node.message(&gid.0, &id).ok().flatten().is_some_and(|m| m.sender.key == node.key())))
    }

    /// A delivered chat message, as the client tells of it.
    fn message_event(&self, message: &Message) -> Result<ClientEvent> {
        let describer = self.client.describer(&message.group)?;
        Ok(ClientEvent::Message {
            group: message.group.clone(),
            id: hex::encode(&message.id.0),
            from: describer.describe(&message.sender),
            seq: message.seq,
            missing: message.missing.iter().map(|seqs| Missing { from: describer.describe_key(&seqs.key), seqs: seqs.seqs.iter().collect() }).collect(),
            late: message.late,
            reply_outside: message.reply_outside,
            reply_to: message.reply_to.as_ref().map(|id| hex::encode(&id.0)),
            payload: message.payload.clone(),
        })
    }

    /// A chat message as the agent reads it: its text is left out once shown, unless `listen --keep-log`.
    fn message_item(&self, event: ClientEvent) -> Result<Value> {
        let mut item = serde_json::to_value(&event)?;
        let payload = item["payload"].take();
        let gid: Bytes = serde_json::from_value(item["group"].clone())?;
        let id = message_id(item["id"].as_str().context("a message has an id")?)?;
        let me = serde_json::to_value(self.client.describe_key(&gid, &self.client.node().key())?)?;
        let to: Vec<Bytes> = serde_json::from_value(payload.get("to").cloned().unwrap_or(json!([])))?;
        let to: Vec<String> = to.iter().map(|fp| hex::encode(&fp.0)).collect();
        let forgotten = !self.config.keep_log && self.client.node().shown(&gid.0, &id)?;
        let content = if forgotten { Value::Null } else { payload.get("content").cloned().unwrap_or(Value::Null) };
        let direct = to.iter().any(|fp| me["fp"] == fp.as_str()) || content.as_str().is_some_and(|text| mentions(text, &me));
        item["content"] = content;
        item["direct"] = json!(direct);
        if !to.is_empty() {
            let members = self.client.described_members(&gid)?;
            item["to"] = to.iter().map(|fp| members.iter().find(|m| m.fp.as_ref() == Some(fp)).map_or_else(|| json!(fp), |m| json!(m))).collect();
        }
        if payload["urgent"] == true {
            item["urgent"] = json!(true);
        }
        for field in ["attachment", "sent_at"] {
            if let Some(value) = payload.get(field) {
                item[field] = value.clone();
            }
        }
        Ok(item)
    }

    /// Marks a delivered message shown, as printed or replied to. Its text is then deleted, unless `listen --keep-log` or
    /// it is this session's own, which it keeps to send again.
    fn show(&self, gid: &Bytes, id: &[u8]) -> Result<()> {
        let node = self.client.node();
        // Gone when the session left the group meanwhile, with what was waiting to print.
        let Some(message) = node.message(&gid.0, id)? else { return Ok(()) };
        self.client.mark_shown(gid, &[Bytes(id.to_vec())])?;
        if !self.config.keep_log && message.payload["type"] == "message" && message.sender.key != node.key() {
            let mut payload = message.payload;
            payload["content"] = json!("");
            node.redact(&gid.0, id, payload)?;
        }
        Ok(())
    }

    /// A chat message, after the latest `ancestors` chat messages in its causal past that this session delivered; this
    /// session's own say who holds and who was shown them.
    fn read(&self, id: &str, ancestors: usize) -> Result<Value> {
        let message = self.find(id)?;
        let node = self.client.node();
        let (gid, me) = (message.group.clone(), node.key());
        let mut shown = node.ancestors(&gid.0, &message.id.0, ancestors)?;
        shown.push(message);
        let receipts = self.client.receipts(&gid)?;
        let describer = self.client.describer(&gid)?;
        let mut found = Vec::new();
        for m in shown {
            let mut item = self.message_item(self.message_event(&m)?)?;
            if m.sender.key == me {
                item["held_by"] = json!(receipts.iter().filter(|r| r.holds(&m)).map(|r| describer.describe(&r.member)).collect::<Vec<_>>());
                item["read_by"] = json!(receipts.iter().filter(|r| r.showed(&m)).map(|r| describer.describe(&r.member)).collect::<Vec<_>>());
            }
            self.show(&gid, &m.id.0)?;
            found.push(self.compact(item));
        }
        Ok(Value::Array(found))
    }

    /// The message of this session's groups whose id begins with `id`.
    fn find(&self, id: &str) -> Result<Message> {
        let node = self.client.node();
        let mut found = Vec::new();
        for gid in node.groups() {
            found.extend(node.messages(&gid.0)?.into_iter().filter(|m| hex::encode(&m.id.0).starts_with(id)));
        }
        match found.len() {
            1 => Ok(found.remove(0)),
            0 => bail!("no message has an id that begins {id}"),
            _ => bail!("several messages have ids that begin {id}; give more of it"),
        }
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

    /// The file a message's attachment or a doc's text links, the group that links it, and the file's name if a message
    /// attached it.
    fn fetching(&self, link: &str) -> Result<(FileLink, Bytes, Option<String>)> {
        let parsed = FileLink::parse(link.trim())?;
        let (gid, name) = self.linking(&parsed.link())?.context("no message or doc here links that")?;
        Ok((parsed, gid, name))
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

    fn warn(&mut self, text: String) {
        self.outbox.print(json!({ "type": "warning", "text": text }));
    }

    pub async fn shutdown(&self) {
        self.plugins.stop_all().await;
        let _ = std::fs::remove_file(self.config.dir.join("endpoint"));
        if self.device.is_some() {
            let _ = std::fs::remove_file(self.home.join("device-endpoint"));
        }
        let device = async {
            if let Some(device) = &self.device {
                let _ = device.shutdown().await;
            }
        };
        let _ = tokio::join!(self.client.node().shutdown(), device);
    }
}

/// Runs a session until `shutdown`, a `stop` request, which it answers once it stopped, or a line it prints that cannot
/// be written: prints `ready`, then handles what arrives and prints what concerns the agent, one JSON object per line.
pub async fn run(
    mut session: Session,
    mut inbound: mpsc::UnboundedReceiver<Inbound>,
    mut events: mpsc::UnboundedReceiver<Event>,
    mut print: impl FnMut(String) -> std::io::Result<()>,
    shutdown: impl std::future::Future<Output = ()>,
    newer: Option<String>,
) -> Result<()> {
    let me = session.client.me()?;
    // Termux may run a program through Android's linker, which /proc/self/exe then names; it names the program in
    // TERMUX_EXEC__PROC_SELF_EXE.
    let bin = std::env::var_os("TERMUX_EXEC__PROC_SELF_EXE").map_or_else(std::env::current_exe, |exe| Ok(exe.into()))?;
    let mut ready = json!({ "type": "ready", "session": session.config.handle, "name": me["device"]["name"], "fp": me["fp"], "bin": bin });
    ready["membership"] = json!(session.config.membership);
    if let Some(identity) = me["identity"]["name"].as_str() {
        ready["identity"] = json!(identity);
    }
    if let Some(version) = newer {
        let minor = version.split('.').take(2).collect::<Vec<_>>().join(".");
        let home = if session.home == crate::cli::home_dir(None)? { String::new() } else { format!("LETMEKNOW_HOME={} ", session.home.display()) };
        ready["newer"] = json!(version);
        ready["update"] = json!(format!("{home}npx -y @letmeknow/cli@{minor} --session {} listen", session.config.handle));
    }
    let mut shutdown = std::pin::pin!(shutdown);
    let client = session.client.clone();
    let mut stopped = None;
    if print(short::line(&ready)).is_ok() {
        loop {
            session.publish();
            if session.emit(&mut print).await.is_err() {
                break;
            }
            let due = session.next_due();
            tokio::select! {
                Some(item) = inbound.recv() => match item {
                    (Request::Stop, reply) => {
                        stopped = Some(reply);
                        break;
                    }
                    item => session.handle(item).await,
                },
                Some(done) = session.running.join_next() => session.done(done.expect("work in flight runs until shutdown")),
                Some(event) = events.recv() => client.event(event).await,
                Some(event) = session.told.recv() => session.client_event(event).await,
                (kind, line) = client.next_line() => client.plugin_line(kind, line).await,
                _ = tokio::time::sleep_until(due) => session.tick().await,
                _ = &mut shutdown => break,
            }
        }
    }
    session.running.shutdown().await;
    session.shutdown().await;
    // Its locks go before the answer: `sessions remove` runs the session as soon as it has it.
    drop(session);
    if let Some(reply) = stopped {
        reply.send(json!({ "stopped": true })).ok();
    }
    Ok(())
}
