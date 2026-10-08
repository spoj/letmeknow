//! The session process: it runs this session's node (and, holding the device's lock, the device's), keeps docs in step
//! with their files, and prints what concerns the agent.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD};
use lmk_core::contacts::{self, Contact};
use lmk_core::invite::Target;
use lmk_core::provider::SqliteProvider;
use lmk_node::{Claim, Event, Member, Node, doc as ydoc};
use lmk_proto::Bytes;
use lmk_proto::group::{Attachment, How, IdentityRef, Kind, Named, PROTOCOL, Payload, Service, Settings};
use lmk_proto::links::{FileLink, Invite};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::cli::{ContactsOp, IdentityOp, Request, private_file};
use crate::doc::{self, Quiet};
use crate::policy::{Outbox, mentions, wakes};

/// How long a message waits for those it comes after.
const CAUSAL_WAIT: Duration = Duration::from_secs(300);
/// How long after starting what arrives counts as catching up.
const CATCH_UP_WINDOW: Duration = Duration::from_secs(3);
const FETCH_WAIT: Duration = Duration::from_secs(60);
const INVITE_TTL: u64 = 600;

pub type SessionNode = Node<SqliteProvider>;

pub struct Config {
    pub handle: String,
    pub dir: PathBuf,
    pub name: String,
    pub hold: Duration,
    pub keep_log: bool,
    /// For groups and identities this session creates.
    pub membership: Service,
}

/// What reaches the session process besides its nodes' events.
pub enum Inbound {
    Request(Box<Request>, oneshot::Sender<Value>),
    /// A doc's file changed.
    FileChanged(Bytes),
}

/// A doc group's file, which the session keeps in step with the doc. Its base, the text both last had, is in the store.
struct Binding {
    path: PathBuf,
    /// Watches the file's directory, as editors often replace a file rather than write into it.
    _watcher: Option<RecommendedWatcher>,
    quiet: Quiet,
    /// The members whose changes came in since the doc was last brought into step.
    editors: Vec<Value>,
    /// The text the agent was last told of, while an `edited` event waits to be printed.
    since: String,
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

pub struct Session {
    db: Connection,
    node: SessionNode,
    /// The device's node, when this process holds the device's lock.
    device: Option<SessionNode>,
    config: Config,
    outbox: Outbox,
    bindings: HashMap<Bytes, Binding>,
    waiting: Vec<Waiting>,
    fetches: Vec<Fetch>,
    catching_up: Option<Instant>,
    inbound: mpsc::UnboundedSender<Inbound>,
}

pub fn fp(key: &[u8]) -> String {
    hex::encode(&Sha256::digest(key)[..8])
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
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
        device: Option<SessionNode>,
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
        let mut session = Self {
            db,
            node,
            device,
            config,
            outbox: Outbox::default(),
            bindings: HashMap::new(),
            waiting: Vec::new(),
            fetches: Vec::new(),
            catching_up: Some(Instant::now() + CATCH_UP_WINDOW),
            inbound,
        };
        for gid in session.node.groups() {
            session.outbox.catch_up(&b64(&gid.0));
            // Messages that arrived but were never taken in, as when the session stopped while they waited.
            for message in session.node.messages(&gid.0)? {
                if !session.taken(&message.id.0)? && message.sender.key != session.node.key() {
                    session.received(message).await?;
                }
            }
            if session.node.settings(&gid.0)?.kind != Kind::Doc {
                continue;
            }
            let path: Option<String> =
                session.db.query_row("SELECT path FROM bindings WHERE gid = ?", [&gid.0], |r| r.get(0)).optional()?;
            let text = ydoc::text(&session.node.doc(&gid.0)?)?;
            match path {
                Some(path) => {
                    // A session stopped after writing the file but before storing its base: the file holds the doc's text.
                    if std::fs::read_to_string(&path).is_ok_and(|file| file.replace("\r\n", "\n") == text) {
                        session.db.execute("UPDATE bindings SET base = ? WHERE gid = ?", params![text, gid.0])?;
                    }
                    session.follow(&gid, PathBuf::from(path));
                }
                None => _ = session.bind(&gid, None, &text)?,
            }
        }
        Ok(session)
    }

    /// This session as the agent sees it in `ready`.
    pub fn me(&self) -> Value {
        let device = self.node.device();
        let identities: Vec<Value> =
            self.identities().into_iter().map(|(identity, name)| json!({ "id": identity.id, "name": name })).collect();
        json!({ "name": self.config.name, "fp": fp(&self.node.key().0), "device": { "key": Bytes(device.public().to_vec()), "name": device.name }, "identities": identities })
    }

    /// When something is next due without anything arriving.
    pub fn next_due(&self) -> Instant {
        let held = self.outbox.deadline(self.config.hold);
        let docs = self.bindings.values().filter_map(|b| b.quiet.due());
        let waiting = self.waiting.iter().map(|w| w.deadline);
        let fetches = self.fetches.iter().map(|f| f.deadline);
        let later = Instant::now() + Duration::from_secs(3600);
        held.into_iter().chain(docs).chain(waiting).chain(fetches).chain(self.catching_up).fold(later, Instant::min)
    }

    pub async fn tick(&mut self) {
        let now = Instant::now();
        if self.outbox.deadline(self.config.hold).is_some_and(|at| at <= now) {
            self.outbox.flush_held();
        }
        if self.catching_up.is_some_and(|at| at <= now) {
            self.catching_up = None;
            self.outbox.caught_up();
        }
        let due: Vec<Bytes> =
            self.bindings.iter().filter(|(_, b)| b.quiet.due().is_some_and(|at| at <= now)).map(|(gid, _)| gid.clone()).collect();
        for gid in due {
            if let Err(error) = self.sync(&gid).await {
                self.warn(Some(&gid), format!("{error:#}"));
            }
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
    }

    /// Prints what is waiting, once the docs' files are in step: whatever wakes the agent, it reads current files.
    pub async fn emit(&mut self, print: &mut impl FnMut(String)) {
        if self.outbox.is_empty() {
            return;
        }
        self.sync_all().await;
        for item in self.outbox.take() {
            if item["type"] == "message"
                && let Some(id) = item["id"].as_str().and_then(|id| message_id(id).ok())
            {
                let _ = self.mark_seen(&id);
            }
            print(item.to_string());
        }
    }

    pub async fn handle(&mut self, inbound: Inbound) {
        match inbound {
            Inbound::Request(request, reply) => {
                let request = *request;
                // The agent may have just changed a file.
                self.sync_all().await;
                if let Request::Fetch { link } = request {
                    if let Err(error) = self.fetch(link, reply).await {
                        self.warn(None, format!("{error:#}"));
                    }
                } else {
                    let result = self.request(request).await;
                    let _ = reply.send(result.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
                }
                self.outbox.flush_held();
            }
            Inbound::FileChanged(gid) => {
                if let Some(binding) = self.bindings.get_mut(&gid) {
                    binding.quiet.file_changed(Instant::now());
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
            | Event::Edited { group, .. }
            | Event::Introduced { group, .. }
            | Event::Held { group, .. }
            | Event::Refused { group, .. } => Some(group.clone()),
            Event::Message(message) => Some(message.group.clone()),
            Event::File(_) | Event::Warning { .. } => None,
        };
        if let Err(error) = self.on(event).await {
            self.warn(group.as_ref(), format!("{error:#}"));
        }
    }

    /// What the device's node tells: only its warnings concern the agent.
    pub fn device_event(&mut self, event: Event) {
        if let Event::Warning { text, .. } = event {
            self.warn(None, format!("this device: {text}"));
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
                self.drop_group(&group)?;
                self.outbox.deliver(json!({ "type": "removed", "group": b64(&group.0), "by": by }), true);
            }
            Event::Settings { group, settings, by } => {
                let item = json!({ "type": "settings", "group": b64(&group.0), "settings": settings, "by": self.describe(&group, &by)? });
                self.outbox.deliver(item, true);
                self.refresh_opening(&group).await?;
            }
            Event::Message(message) => self.received(message).await?,
            Event::Edited { group, by } => {
                let by = self.describe(&group, &by)?;
                if let Some(binding) = self.bindings.get_mut(&group) {
                    binding.quiet.doc_changed(Instant::now());
                    if !binding.editors.iter().any(|e| e["fp"] == by["fp"]) {
                        binding.editors.push(by);
                    }
                }
            }
            Event::Introduced { group, by, identity, name, how } => self.introduced(&group, &by, identity, name, how)?,
            Event::Held { .. } => {}
            Event::Refused { group, id, by, reason } => {
                let item = json!({ "type": "refused", "group": b64(&group.0), "id": hex::encode(&id.0), "member": self.describe(&group, &by)?, "reason": reason });
                self.outbox.deliver(item, true);
            }
            Event::File(hash) => self.arrived(hash).await?,
            Event::Warning { group, text } => self.warn(group.as_ref(), text),
        }
        Ok(())
    }

    /// This session admitted a member: it tells the group who the member is to it, and the member of an invite meant
    /// for someone becomes that contact.
    async fn admitted(&mut self, gid: &Bytes, member: &Member, how: How, label: Option<String>) -> Result<()> {
        let Some(claim) = member.identity.clone().filter(|claim| claim.error.is_none()) else { return Ok(()) };
        if let Some(label) = &label {
            let contact = Contact { name: label.clone(), how: contacts::How::Verified, by: None, at: lmk_node::now() };
            self.device()?.set_contact(&claim.identity.id.0, &contact).await?;
        }
        let name = label.unwrap_or_else(|| self.display_name(&claim));
        self.node.send(&gid.0, &Payload::Introduce { identity: claim.identity, name, how }).await?;
        Ok(())
    }

    /// Records, in the devices group of each of this device's identities the group is open to, the group's opening.
    async fn refresh_opening(&mut self, gid: &Bytes) -> Result<()> {
        let Some(device) = &self.device else { return Ok(()) };
        let Ok(settings) = self.node.settings(&gid.0) else { return Ok(()) };
        for (identity, _) in device.identities() {
            if settings.open.iter().any(|named| named.id == identity.id) {
                device.set_opening(&identity.id.0, self.node.opening(&gid.0)?).await?;
            }
        }
        Ok(())
    }

    async fn request(&mut self, request: Request) -> Result<Value> {
        match request {
            Request::Invite { group, kind, name, file, keep, membership, as_, for_, to, qr: _, identity } => {
                self.invite(group, kind, name, file, keep, membership, as_, for_, to, identity).await
            }
            Request::Join { target, file, as_ } => self.join(target, file, as_).await,
            Request::Send { group, to, reply_to, urgent, attach, attach_name, text } => {
                self.send(group, to, reply_to, urgent, attach.map(|data| (data, attach_name)), text).await
            }
            Request::Read { id, ancestors } => self.read(&id, ancestors),
            Request::Members { group } => {
                let gid = self.resolve(group)?;
                Ok(json!({ "group": b64(&gid.0), "kind": self.node.settings(&gid.0)?.kind, "members": self.described_members(&gid)? }))
            }
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
            Request::Attach { group, path } => {
                let gid = self.of_kind(group, Kind::Doc)?;
                let bytes = std::fs::read(&path).with_context(|| format!("cannot read {path}"))?;
                let name = Path::new(&path).file_name().map_or_else(String::new, |n| n.to_string_lossy().replace(['[', ']'], ""));
                let image = image_type(&bytes).is_some();
                let link = self.node.add_file(&gid.0, bytes).await?.link();
                let markdown = format!("{}[{name}]({link})", if image { "!" } else { "" });
                Ok(json!({ "link": link, "markdown": markdown }))
            }
            Request::Fetch { .. } => unreachable!("answered by fetch"),
            Request::Status => self.status(),
            Request::Identity { op } => self.identity(op).await,
            Request::Contacts { op: None } => self.contacts(),
            Request::Contacts { op: Some(ContactsOp::Accept { identity, name }) } => self.accept(&identity, name).await,
            Request::Introduce { group, member, to } => self.introduce(group, &member, &to).await,
        }
    }

    // Groups.

    #[allow(clippy::too_many_arguments)]
    async fn invite(
        &mut self,
        group: Option<String>,
        kind: String,
        name: Option<String>,
        file: Option<String>,
        keep: u32,
        membership: Option<String>,
        as_: Option<String>,
        for_: Option<String>,
        to: Option<String>,
        identity: Option<String>,
    ) -> Result<Value> {
        let kind = if kind == "doc" { Kind::Doc } else { Kind::Chat };
        ensure!(file.is_none() || kind == Kind::Doc, "only a doc has a file: invite --kind doc <file>");
        // Two docs in one file would pass each one's text to the other's members.
        if let Some(file) = &file
            && self.bindings.values().any(|b| b.path == Path::new(file))
        {
            bail!("{file} already holds another doc");
        }
        let to = to.map(|to| self.contact(&to)).transpose()?;
        ensure!(
            for_.is_none() || !self.identities().is_empty(),
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
                            kind,
                            name: name.unwrap_or_default(),
                            open: Vec::new(),
                            keep,
                            membership,
                            devices_of: None,
                            openings: Vec::new(),
                        };
                        self.create(settings, as_, file).await?
                    }
                };
                let settings = self.node.settings(&gid.0)?;
                answer["group"] = json!(b64(&gid.0));
                answer["kind"] = json!(settings.kind);
                if !settings.name.is_empty() {
                    answer["name"] = json!(settings.name);
                }
                if let Some(binding) = self.bindings.get(&gid) {
                    answer["file"] = json!(binding.path);
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

    async fn create(&mut self, settings: Settings, as_: Option<IdentityRef>, file: Option<String>) -> Result<Bytes> {
        let doc = settings.kind == Kind::Doc;
        let gid = self.node.create(settings, as_)?;
        if doc {
            self.bind(&gid, file, "")?;
            self.sync(&gid).await?;
        }
        Ok(gid)
    }

    async fn leave(&mut self, group: Option<String>) -> Result<Value> {
        let gid = self.resolve(group)?;
        let Some(delivery) = self.node.leave(&gid.0).await? else {
            self.drop_group(&gid)?;
            return Ok(json!({ "group": b64(&gid.0), "left": true }));
        };
        let mut answer = json!({ "group": b64(&gid.0), "left": true, "status": "another member commits the removal" });
        if delivery.held.is_empty() {
            answer["pending"] = json!(true);
        }
        Ok(answer)
    }

    /// Clears what the session kept of a group the node has left.
    fn drop_group(&mut self, gid: &Bytes) -> Result<()> {
        // A file the agent named stays; one in the session's state goes with the group.
        if let Some(binding) = self.bindings.remove(gid)
            && binding.path.starts_with(self.config.dir.join("docs"))
            && binding.path.exists()
        {
            std::fs::remove_file(&binding.path)?;
        }
        for table in ["taken", "bindings", "attachments"] {
            self.db.execute(&format!("DELETE FROM {table} WHERE gid = ?"), [&gid.0])?;
        }
        let attachments = self.attachments_dir(gid);
        if attachments.exists() {
            std::fs::remove_dir_all(attachments)?;
        }
        Ok(())
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
            if let Some(binding) = self.bindings.get(&gid) {
                group["file"] = json!(binding.path);
            }
            groups.push(group);
        }
        let joined = self.node.groups();
        for opening in self.openings() {
            if !joined.contains(&opening.group) {
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

    /// The group a chat or doc command acts on: the one --group names, which must be of `kind`, or else the session's
    /// one group of that kind.
    fn of_kind(&self, group: Option<String>, kind: Kind) -> Result<Bytes> {
        let name = if kind == Kind::Doc { "doc" } else { "chat" };
        if group.is_some() {
            let gid = self.resolve(group)?;
            ensure!(self.node.settings(&gid.0)?.kind == kind, "{} is not a {name}", b64(&gid.0));
            return Ok(gid);
        }
        let found: Vec<Bytes> =
            self.node.groups().into_iter().filter(|gid| self.node.settings(&gid.0).is_ok_and(|s| s.kind == kind)).collect();
        match &found[..] {
            [gid] => Ok(gid.clone()),
            [] => bail!("this session is in no {name}; create one with `invite --kind {name}`, or join one with `join`"),
            _ => bail!("this session is in several {name}s; pass --group"),
        }
    }

    // Joins.

    async fn join(&mut self, target: String, file: Option<String>, as_: Option<String>) -> Result<Value> {
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
            let opening = self.openings().into_iter().find(|o| b64(&o.group.0) == target || o.name == target);
            let opening = opening.context("expected an invite link, or the id or name of a group open to your identity")?;
            let identity = as_.context("joining a group open to your identity needs one: this device is on none")?;
            self.node.join_open(&opening, identity).await?
        };
        let settings = self.node.settings(&gid.0)?;
        let mut answer = json!({ "group": b64(&gid.0), "kind": settings.kind, "name": settings.name, "members": self.described_members(&gid)? });
        if settings.kind == Kind::Doc {
            let text = ydoc::text(&self.node.doc(&gid.0)?)?;
            answer["file"] = json!(self.bind(&gid, file, &text)?);
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
        let gid = self.of_kind(group, Kind::Chat)?;
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
        let payload = Payload::Message {
            content: text,
            after: self.tips(&gid)?.into_iter().map(|id| Bytes(id.to_vec())).collect(),
            to: addressed.iter().map(|m| Bytes(Sha256::digest(&m.key.0)[..8].to_vec())).collect(),
            reply_to: reply_to.map(|id| Bytes(id.to_vec())),
            urgent,
            attachment: attachment.as_ref().map(|(_, a)| a.clone()),
        };
        let (id, delivery) = self.node.send(&gid.0, &payload).await?;
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

    /// A chat message the node took in: it waits for those it comes after.
    async fn received(&mut self, message: lmk_node::Message) -> Result<()> {
        let id: [u8; 32] = message.id.0.as_slice().try_into()?;
        if self.taken(&id)? || self.waiting.iter().any(|w| w.id == id) {
            return Ok(());
        }
        let sender = self.describe(&message.group, &message.sender)?;
        let payload = serde_json::to_value(&message.payload)?;
        // A message waits for those it comes after, unless this session gave them up: then it shows the gap.
        if self.missing(&payload)?.iter().all(|missing| self.node.given_up(&message.group.0, missing)) {
            self.take_message(&message.group, id, sender, payload).await
        } else {
            self.waiting.push(Waiting { deadline: Instant::now() + CAUSAL_WAIT, gid: message.group, id, sender, payload });
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
            if let Payload::Message { after, .. } = &message.payload {
                covered.extend(after.iter().map(|id| id.0.clone()));
            }
        }
        Ok(seen.into_iter().filter(|m| !covered.contains(&m.id.0)).filter_map(|m| m.id.0.try_into().ok()).collect())
    }

    /// Records that a message entered the agent's context. Its text is then deleted, unless `listen --keep-log`.
    fn mark_seen(&self, id: &[u8; 32]) -> Result<()> {
        let Some(message) = self.node.message(id)? else { return Ok(()) };
        self.db.execute("INSERT OR IGNORE INTO taken (id, gid) VALUES (?, ?)", params![id, message.group.0])?;
        self.db.execute("UPDATE taken SET seen = 1 WHERE id = ?", [id])?;
        if !self.config.keep_log {
            self.node.redact(id)?;
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
                let payload = serde_json::to_value(&message.payload)?;
                let from = self.describe(&message.group, &message.sender)?;
                found.push(self.message_json(&message.group, id, from, &payload, false)?);
                self.mark_seen(&id)?;
                if let Payload::Message { after, .. } = &message.payload {
                    for after in after {
                        next.push(after.0.as_slice().try_into().ok().context("a message id is 32 bytes")?);
                    }
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

    /// The group whose messages or doc link `link`, and the file's name if a message attached it.
    fn linking(&self, link: &str) -> Result<Option<(Bytes, Option<String>)>> {
        for gid in self.node.groups() {
            for message in self.node.messages(&gid.0)? {
                if let Payload::Message { attachment: Some(attachment), .. } = &message.payload
                    && attachment.link == link
                {
                    return Ok(Some((gid, Some(attachment.name.clone()))));
                }
            }
            if self.node.settings(&gid.0)?.kind == Kind::Doc && ydoc::text(&self.node.doc(&gid.0)?)?.contains(link) {
                return Ok(Some((gid, None)));
            }
        }
        Ok(None)
    }

    // Docs.

    /// Keeps `file` (or a new one in the session's state) in step with the doc `gid`, from `base`, the text both have
    /// now. The file is created holding it unless it exists; one that exists brings its text in at the next sync.
    fn bind(&mut self, gid: &Bytes, file: Option<String>, base: &str) -> Result<PathBuf> {
        let path = match file {
            Some(file) => PathBuf::from(file),
            None => {
                let name: String =
                    self.node.settings(&gid.0)?.name.chars().map(|c| if c.is_alphanumeric() { c } else { '-' }).collect();
                let name = Some(name.trim_matches('-')).filter(|name| !name.is_empty()).unwrap_or("doc");
                self.config.dir.join("docs").join(format!("{name}-{}.md", &hex::encode(&gid.0)[..8]))
            }
        };
        if !path.exists() {
            doc::write_file(&path, base)?;
        }
        self.db.execute(
            "INSERT INTO bindings (gid, path, base) VALUES (?, ?, ?)",
            params![gid.0, path.to_str().context("path is not UTF-8")?, base],
        )?;
        self.follow(gid, path.clone());
        Ok(path)
    }

    /// Watches a doc's file, which is brought into step once it has been quiet for a moment.
    fn follow(&mut self, gid: &Bytes, path: PathBuf) {
        let (inbound, changed, name) = (self.inbound.clone(), gid.clone(), path.file_name().map(OsStr::to_owned));
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            if let Ok(event) = event
                && !event.kind.is_access()
                && event.paths.iter().any(|p| p.file_name() == name.as_deref())
            {
                let _ = inbound.send(Inbound::FileChanged(changed.clone()));
            }
        })
        .and_then(|mut watcher| watcher.watch(path.parent().expect("a file is in a directory"), RecursiveMode::NonRecursive).map(|()| watcher));
        if let Err(error) = &watcher {
            self.warn(Some(gid), format!("cannot watch {}: {error}; what you write there is taken at your next command", path.display()));
        }
        let binding = Binding { path, _watcher: watcher.ok(), quiet: Quiet::default(), editors: Vec::new(), since: String::new() };
        self.bindings.insert(gid.clone(), binding);
    }

    /// Brings a doc and its file into step. What changed in the file since they last were (its base) is carried line by
    /// line onto the doc as it is now and sent; the file then gets the doc's text. A line both changed keeps the doc's
    /// version, with a warning. What others changed in the doc meanwhile is told as `edited`.
    async fn sync(&mut self, gid: &Bytes) -> Result<()> {
        let binding = self.bindings.get_mut(gid).expect("a doc is bound");
        binding.quiet = Quiet::default();
        let editors = std::mem::take(&mut binding.editors);
        let path = binding.path.clone();
        let base: String = self.db.query_row("SELECT base FROM bindings WHERE gid = ?", [&gid.0], |r| r.get(0))?;
        let file = match std::fs::read_to_string(&path) {
            Ok(text) => text.replace("\r\n", "\n"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => base.clone(),
            Err(error) => return Err(error).with_context(|| format!("cannot read {}", path.display())),
        };
        let state = self.node.doc(&gid.0)?;
        let current = ydoc::text(&state)?;
        let (text, lost) = if file == base { (current.clone(), Vec::new()) } else { doc::rebase(&base, &file, &current) };
        if text != current {
            self.node.edit(&gid.0, ydoc::edit(&state, &text)?).await?;
        }
        if text != file {
            doc::write_file(&path, &text)?;
        }
        self.db.execute("UPDATE bindings SET base = ? WHERE gid = ?", params![text, gid.0])?;
        if !lost.is_empty() {
            let text = format!("others changed these lines of {} meanwhile, so your changes to them were not kept: {}", path.display(), lost.join(" | "));
            self.warn(Some(gid), text);
        }
        if current != base {
            // One `edited` event per doc waits, telling of every change since the agent was last told.
            let group = b64(&gid.0);
            let mut by = editors;
            match self.outbox.take_edited(&group) {
                Some(waited) => {
                    for editor in waited["by"].as_array().expect("edited lists its editors") {
                        if !by.iter().any(|e| e["fp"] == editor["fp"]) {
                            by.push(editor.clone());
                        }
                    }
                }
                None => self.bindings.get_mut(gid).expect("a doc is bound").since = base.clone(),
            }
            let me = self.describe_key(gid, &self.node.key());
            let lines = doc::changed(&self.bindings[gid].since, &current).0;
            let direct = doc::changed(&base, &current).1.iter().any(|line| mentions(line, &me));
            let item = json!({ "type": "edited", "group": group, "file": path, "by": by, "lines": lines, "direct": direct });
            let wakes = wakes(&item, |_| false);
            self.outbox.deliver(item, wakes);
        }
        Ok(())
    }

    async fn sync_all(&mut self) {
        let gids: Vec<Bytes> = self.bindings.keys().cloned().collect();
        for gid in gids {
            if let Err(error) = self.sync(&gid).await {
                self.warn(Some(&gid), format!("{error:#}"));
            }
        }
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
        let own = self.identities().into_iter().find(|(identity, _)| &identity.id == id);
        let contacts = self.contact_list();
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
    fn display_name(&self, claim: &Claim) -> String {
        let contact = self.contact_list().into_iter().find(|(id, _)| *id == claim.identity.id);
        contact.map_or_else(|| claim.name.clone(), |(_, c)| c.name)
    }

    fn introduced(&mut self, gid: &Bytes, by: &Member, identity: IdentityRef, name: String, how: How) -> Result<()> {
        let sender = self.describe(gid, by)?;
        let own = self.identities().iter().any(|(own, _)| own.id == identity.id);
        let contact = self.contact_list().iter().any(|(id, _)| *id == identity.id);
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
        let payload = Payload::Introduce { identity: claim.identity.clone(), name: name.clone(), how: How::Introduce };
        let (id, _) = self.node.send(&gid.0, &payload).await?;
        Ok(json!({ "id": hex::encode(&id.0), "group": b64(&gid.0), "identity": { "id": claim.identity.id, "name": name }, "to": self.describe(&gid, &to)? }))
    }

    /// The device's node, which this process runs when it holds the device's lock.
    fn device(&self) -> Result<&SessionNode> {
        self.device.as_ref().context("another session process acts for this device; run identity and contact commands there")
    }

    fn device_file(&self) -> PathBuf {
        self.config.dir.parent().and_then(Path::parent).expect("a session lives in <home>/sessions").join("device.json")
    }

    /// This device's identities, with their names where the device's node is here to tell them.
    fn identities(&self) -> Vec<(IdentityRef, String)> {
        match &self.device {
            Some(device) => device.identities(),
            None => self.node.device().identities.into_iter().map(|identity| (identity, String::new())).collect(),
        }
    }

    fn contact_list(&self) -> Vec<(Bytes, Contact)> {
        self.device.as_ref().and_then(|device| device.contacts().ok()).unwrap_or_default()
    }

    fn openings(&self) -> Vec<lmk_proto::group::Opening> {
        self.device.as_ref().map(|device| device.openings()).unwrap_or_default()
    }

    /// The identity a new membership speaks as: the one named, or else the device's first.
    fn speaking_as(&self, as_: Option<String>) -> Result<Option<IdentityRef>> {
        match as_ {
            Some(as_) => Ok(Some(self.own_identity(&as_)?.0)),
            None => Ok(self.identities().into_iter().next().map(|(identity, _)| identity)),
        }
    }

    /// An identity this device is on, by id or name.
    fn own_identity(&self, name: &str) -> Result<(IdentityRef, String)> {
        let identities = self.identities();
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
        let (_, contact) = self.contact_list().into_iter().find(|(cid, _)| *cid == id).expect("found by contact");
        Ok((id, contact.name))
    }

    fn contact(&self, name: &str) -> Result<Bytes> {
        let contacts = self.contact_list();
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
                Ok(json!({ "identity": identity.id, "removed": listed.key }))
            }
        }
    }

    fn contacts(&self) -> Result<Value> {
        let contacts = self.contact_list();
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
        self.device()?.set_contact(&id, &contact).await?;
        self.db.execute("DELETE FROM introductions WHERE identity = ?", [&id])?;
        Ok(json!({ "identity": Bytes(id), "name": contact.name, "how": contact.how }))
    }

    fn warn(&mut self, gid: Option<&Bytes>, text: String) {
        self.outbox.print(json!({ "type": "warning", "group": gid.map(|g| b64(&g.0)), "text": text }));
    }

    pub async fn shutdown(&self) {
        let _ = self.node.shutdown().await;
        if let Some(device) = &self.device {
            let _ = device.shutdown().await;
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
    mut device_events: mpsc::UnboundedReceiver<Event>,
    mut print: impl FnMut(String),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let ready = json!({ "type": "ready", "session": session.config.handle, "member": session.me(), "state": session.config.dir });
    print(ready.to_string());
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        session.emit(&mut print).await;
        tokio::select! {
            Some(item) = inbound.recv() => session.handle(item).await,
            Some(event) = events.recv() => session.event(event).await,
            Some(event) = device_events.recv() => session.device_event(event),
            _ = tokio::time::sleep_until(session.next_due()) => session.tick().await,
            _ = &mut shutdown => break,
        }
    }
    session.shutdown().await;
    Ok(())
}
