//! The session process: the client core on this session's node, and what concerns the agent, printed.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crate::client::{Chat, Client, ClientEvent, Missing, message_id};
use lmk_node::{Event, Message, Node};
use lmk_proto::Bytes;
use lmk_proto::group::{Attachment, Service};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::cli::{Request, private_file};
use crate::policy::{Outbox, wakes};
use crate::short;

/// How long after starting what arrives counts as catching up.
const CATCH_UP_WINDOW: Duration = Duration::from_secs(3);
/// How often a session forgets the messages it took in more than H ago.
const FORGET: Duration = Duration::from_secs(3600);

pub struct Config {
    pub handle: String,
    pub dir: PathBuf,
    pub hold: Duration,
    pub keep_log: bool,
    /// The domain of the membership service for groups this session creates.
    pub membership: String,
    /// Where it looks for a newer release.
    pub registry: String,
}

/// A request on a command channel, and where its answer goes.
pub type Inbound = (Request, oneshot::Sender<Value>);

/// A request's answer that work the session loop started gave, and where it goes.
pub struct Answered(Result<Value>, oneshot::Sender<Value>);

pub struct Session {
    db: Connection,
    client: Client,
    /// What the client tells.
    told: mpsc::UnboundedReceiver<ClientEvent>,
    /// The session's lock, held while this process runs it.
    _held: std::fs::File,
    /// When the session next forgets the messages it took in more than H ago.
    forget_at: Instant,
    /// The groups as last written to `groups.json`.
    groups: String,
    home: PathBuf,
    config: Config,
    outbox: Outbox,
    catching_up: Option<Instant>,
    /// Work in flight: the loop takes each as it finishes, and never waits on one.
    running: JoinSet<Answered>,
}

fn b64(bytes: &[u8]) -> String {
    serde_json::to_value(Bytes(bytes.to_vec())).expect("JSON").as_str().expect("a string").to_owned()
}

impl Session {
    pub async fn open(config: Config, db: Connection, node: Node, home: &Path, held: std::fs::File, membership: Service) -> Result<Self> {
        let (client, told) = Client::new(node, membership);
        let mut session = Self {
            db,
            client,
            told,
            _held: held,
            forget_at: Instant::now() + FORGET,
            groups: String::new(),
            home: home.to_path_buf(),
            config,
            outbox: Outbox::default(),
            catching_up: Some(Instant::now() + CATCH_UP_WINDOW),
            running: JoinSet::new(),
        };
        session.forget_old()?;
        let groups = session.client.node().groups();
        for gid in &groups {
            session.outbox.catch_up(&b64(&gid.0));
        }
        for gid in groups {
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
                session.received(event)?;
            }
        }
        Ok(session)
    }

    /// Writes this session's groups, by id, to `groups.json` in its directory, for `sessions`, when they changed.
    fn publish(&mut self) {
        let groups: Vec<String> = self.client.node().groups().iter().map(|gid| b64(&gid.0)).collect();
        let groups = serde_json::to_string(&groups).expect("JSON");
        if groups == self.groups {
            return;
        }
        let path = self.config.dir.join("groups.json");
        let new = path.with_extension("new");
        match private_file(&new, groups.as_bytes()).and_then(|()| Ok(std::fs::rename(&new, &path)?)) {
            Ok(()) => self.groups = groups,
            Err(error) => self.warn(format!("writing this session's groups: {error:#}")),
        }
    }

    /// When something is next due without anything arriving.
    pub fn next_due(&self) -> Instant {
        let held = self.outbox.deadline(self.config.hold);
        let later = Instant::now() + Duration::from_secs(3600);
        held.into_iter().chain([self.forget_at]).chain(self.catching_up).fold(later, Instant::min)
    }

    pub async fn tick(&mut self) {
        let now = Instant::now();
        if self.forget_at <= now {
            self.forget_at = now + FORGET;
            if let Err(error) = self.forget_old() {
                self.warn(format!("forgetting old messages: {error:#}"));
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

    /// Prints what is waiting. A message is seen once its line is written.
    pub fn emit(&mut self, print: &mut impl FnMut(String) -> std::io::Result<()>) -> Result<()> {
        for item in self.outbox.take() {
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
        }
        Ok(())
    }

    /// An item as the agent reads it: made short.
    fn compact(&self, mut item: Value) -> Value {
        short::compact(&mut item);
        item
    }

    /// Takes a request: what may wait on the network goes on in `running`, and is answered once done.
    pub fn handle(&mut self, (request, reply): Inbound) {
        let client = self.client.clone();
        match request {
            Request::Read { id } => {
                let answer = self.read(&id);
                self.answer(answer, reply);
            }
            Request::Send { group, to, reply_to, urgent, attach, attach_name, text } => {
                match self.message(group, to, reply_to, urgent, attach.map(|data| (data, attach_name)), text) {
                    Ok((gid, chat)) => _ = self.running.spawn_local(async move {
                        let sent = client.send(&gid, chat).await.map(|(_, answer)| answer);
                        Answered(sent, reply)
                    }),
                    Err(error) => self.answer(Err(error), reply),
                }
            }
            Request::Client(request) => _ = self.running.spawn_local(async move { Answered(client.request(request).await, reply) }),
            Request::Status { .. } => unreachable!("the CLI sends it as the client's request"),
        }
    }

    fn answer(&mut self, answer: Result<Value>, reply: oneshot::Sender<Value>) {
        // Before the answer, so that `sessions` shows what the request changed.
        self.publish();
        let _ = reply.send(answer.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
        self.outbox.flush_held();
    }

    /// What the client tells.
    pub fn client_event(&mut self, event: ClientEvent) {
        if let Err(error) = self.on(event) {
            self.warn(format!("{error:#}"));
        }
    }

    fn on(&mut self, event: ClientEvent) -> Result<()> {
        if let ClientEvent::Joined { .. } | ClientEvent::Left { .. } | ClientEvent::Removed { .. } | ClientEvent::Lost { .. } = &event
        {
            let mut item = serde_json::to_value(&event)?;
            if let ClientEvent::Lost { member, messages, .. } = &event
                && !member.you
            {
                let count: usize = messages.iter().map(|lost| lost.seqs.len()).sum();
                item["text"] = json!(format!(
                    "{} could not read {count} of your messages; send again, with --reply-to <id>, any that still matters",
                    crate::client::shown(&item["member"]),
                ));
            }
            let wake = wakes(&item, |id| self.mine(id));
            self.outbox.deliver(item, wake);
            return Ok(());
        }
        if let ClientEvent::Message { id, .. } = &event {
            let id = message_id(id)?;
            if !self.taken(&id)? {
                self.received(event)?;
            }
            return Ok(());
        }
        match event {
            ClientEvent::Warning { .. } => self.outbox.print(serde_json::to_value(&event)?),
            ClientEvent::Gone { group } => self.forget(&group)?,
            _ => {}
        }
        Ok(())
    }

    /// Clears what the session kept of a group the client let go of.
    fn forget(&mut self, gid: &Bytes) -> Result<()> {
        self.db.execute("DELETE FROM taken WHERE gid = ?", [&gid.0])?;
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
        let gid = self.client.resolve(group)?;
        let reply_to: Option<[u8; 32]> = match reply_to {
            Some(id) => {
                let target = self.find(&id)?;
                self.show(&target.group, &target.id.0)?;
                Some(target.id.0.as_slice().try_into()?)
            }
            None => None,
        };
        let attachment = match attach {
            Some((data, name)) => Some(Attachment { name, data: Bytes(B64.decode(data)?) }),
            None => None,
        };
        Ok((gid, Chat { text, to, reply_to, urgent, attachment }))
    }

    /// Takes in a chat message, in delivery order: printed, with its attachment saved into a file only this user can read.
    fn received(&mut self, event: ClientEvent) -> Result<()> {
        let ClientEvent::Message { payload, .. } = &event else { bail!("not a chat message") };
        let attachment: Option<Attachment> = payload.get("attachment").map(|a| serde_json::from_value(a.clone())).transpose()?;
        let item = self.message_item(event)?;
        let gid: Bytes = serde_json::from_value(item["group"].clone())?;
        let id = message_id(item["id"].as_str().context("a message has an id")?)?;
        let path = item["attachment"]["path"].as_str();
        self.db.execute("INSERT OR IGNORE INTO taken (id, gid, at, attachment) VALUES (?, ?, ?, ?)", params![id, gid.0, lmk_proto::clock::now(), path])?;
        if let (Some(attachment), Some(path)) = (attachment, path) {
            std::fs::create_dir_all(self.attachments_dir(&gid))?;
            private_file(Path::new(path), &attachment.data.0)?;
        }
        let wakes = wakes(&item, |id| self.mine(id));
        self.outbox.deliver(item, wakes);
        Ok(())
    }

    /// Forgets the messages taken in more than the group's H ago, with the copies of their attachments: no member can
    /// send them again by then.
    fn forget_old(&self) -> Result<()> {
        let node = self.client.node();
        for gid in node.groups() {
            let before = lmk_proto::clock::now().saturating_sub(node.settings(&gid.0)?.carry as u64 * 24 * 3600 * 1000);
            let old = "SELECT attachment FROM taken WHERE gid = ?1 AND at < ?2 AND attachment IS NOT NULL";
            let paths: Vec<String> = self.db.prepare(old)?.query_map(params![gid.0, before], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
            for path in paths {
                match std::fs::remove_file(&path) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
                    _ => {}
                }
            }
            self.db.execute("DELETE FROM taken WHERE gid = ?1 AND at < ?2", params![gid.0, before])?;
        }
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
        let direct = to.iter().any(|fp| me["fp"] == fp.as_str());
        item["content"] = content;
        item["direct"] = json!(direct);
        if !to.is_empty() {
            let members = self.client.described_members(&gid)?;
            item["to"] = to.iter().map(|fp| members.iter().find(|m| m.fp.as_ref() == Some(fp)).map_or_else(|| json!(fp), |m| json!(m))).collect();
        }
        if payload["urgent"] == true {
            item["urgent"] = json!(true);
        }
        if let Some(sent_at) = payload.get("sent_at") {
            item["sent_at"] = sent_at.clone();
        }
        // An attachment shows as the file another member's attached is saved in.
        if let Some(name) = payload["attachment"]["name"].as_str() {
            item["attachment"] = json!({ "name": name });
            if item["from"]["you"] != true {
                let file = format!("{}-{}", &hex::encode(id)[..16], name.replace(|c: char| !c.is_ascii_alphanumeric() && !"._-".contains(c), "-"));
                item["attachment"]["path"] = json!(self.attachments_dir(&gid).join(file));
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

    /// A chat message.
    fn read(&self, id: &str) -> Result<Value> {
        let message = self.find(id)?;
        let item = self.message_item(self.message_event(&message)?)?;
        self.show(&message.group, &message.id.0)?;
        Ok(self.compact(item))
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

    fn warn(&mut self, text: String) {
        self.outbox.print(json!({ "type": "warning", "text": text }));
    }

    pub async fn shutdown(&self) {
        let _ = std::fs::remove_file(self.config.dir.join("endpoint"));
        let _ = self.client.node().shutdown().await;
    }
}

/// Runs a session until `shutdown` or a line it prints that cannot be written: prints `ready`, then handles what arrives and prints what concerns the agent, one JSON object per line.
pub async fn run(
    mut session: Session,
    mut inbound: mpsc::UnboundedReceiver<Inbound>,
    mut events: mpsc::UnboundedReceiver<Event>,
    mut print: impl FnMut(String) -> std::io::Result<()>,
    shutdown: impl std::future::Future<Output = ()>,
    newer: Option<String>,
) -> Result<()> {
    let fp = crate::client::fp(&session.client.node().key().0);
    // Termux may run a program through Android's linker, which /proc/self/exe then names; it names the program in
    // TERMUX_EXEC__PROC_SELF_EXE.
    let bin = std::env::var_os("TERMUX_EXEC__PROC_SELF_EXE").map_or_else(std::env::current_exe, |exe| Ok(exe.into()))?;
    let mut ready = json!({ "type": "ready", "session": session.config.handle, "fp": fp, "bin": bin, "membership": session.config.membership });
    if let Some(version) = newer {
        let minor = version.split('.').take(2).collect::<Vec<_>>().join(".");
        let home = if session.home == crate::cli::home_dir(None)? { String::new() } else { format!("LETMEKNOW_HOME={} ", session.home.display()) };
        ready["newer"] = json!(version);
        ready["update"] = json!(format!("{home}npx -y @letmeknow/cli@{minor} --session {} listen", session.config.handle));
    }
    let mut shutdown = std::pin::pin!(shutdown);
    let client = session.client.clone();
    if print(short::line(&ready)).is_ok() {
        loop {
            session.publish();
            if session.emit(&mut print).is_err() {
                break;
            }
            let due = session.next_due();
            tokio::select! {
                Some(item) = inbound.recv() => session.handle(item),
                Some(done) = session.running.join_next() => {
                    let Answered(answer, reply) = done.expect("work in flight runs until shutdown");
                    session.answer(answer, reply);
                }
                Some(event) = events.recv() => client.event(event),
                Some(event) = session.told.recv() => session.client_event(event),
                _ = tokio::time::sleep_until(due) => session.tick().await,
                _ = &mut shutdown => break,
            }
        }
    }
    session.running.shutdown().await;
    session.shutdown().await;
    Ok(())
}
