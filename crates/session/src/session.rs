//! The session process: it drives the group logic, the peers and the membership service, keeps docs in step with
//! their files, and prints what concerns the agent.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD};
use lmk_proto::group::{Attachment, How, IdentityRef, Kind, Named, PROTOCOL, Payload, Service, Settings};
use lmk_proto::links::{FileLink, Invite};
use lmk_proto::peer::{Admitted, InviteRequest, Joiner};
use lmk_proto::{Answer, Bytes};
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
use crate::node::{Applied, Change, Claim, Commit, Contact, Core, Inbound, Known, Log, Member, Op, Peers, device_log};
use crate::policy::{Outbox, mentions, wakes};

const INVITE_TTL: Duration = Duration::from_secs(600);
/// How long a message waits for those it comes after.
const CAUSAL_WAIT: Duration = Duration::from_secs(300);
/// How long after starting what arrives counts as catching up.
const CATCH_UP_WINDOW: Duration = Duration::from_secs(3);
const KEY_UPDATE: Duration = Duration::from_secs(24 * 60 * 60);
const FETCH_WAIT: Duration = Duration::from_secs(60);

pub struct Config {
    pub handle: String,
    pub dir: PathBuf,
    pub name: String,
    pub hold: Duration,
    pub keep_log: bool,
    /// For groups and identities this session creates.
    pub membership: Service,
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

enum Into {
    Group(Bytes),
    Device(IdentityRef),
}

struct PendingInvite {
    into: Into,
    for_: Option<String>,
    to: Option<Bytes>,
    expires: Instant,
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

pub struct Session<C, P, L> {
    db: Connection,
    core: C,
    peers: P,
    log: L,
    config: Config,
    outbox: Outbox,
    bindings: HashMap<Bytes, Binding>,
    invites: HashMap<[u8; 16], PendingInvite>,
    waiting: Vec<Waiting>,
    fetches: Vec<Fetch>,
    /// Docs whose state, linked in a Welcome, has not arrived yet: by the file's hash.
    doc_states: HashMap<[u8; 32], (Bytes, FileLink)>,
    catching_up: Option<Instant>,
    next_update: Instant,
    inbound: mpsc::UnboundedSender<Inbound>,
}

pub fn fp(key: &[u8]) -> String {
    hex::encode(&Sha256::digest(key)[..8])
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn id_of(ciphertext: &[u8]) -> [u8; 32] {
    Sha256::digest(ciphertext).into()
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

impl<C: Core, P: Peers, L: Log> Session<C, P, L> {
    pub fn open(config: Config, core: C, peers: P, log: L, inbound: mpsc::UnboundedSender<Inbound>) -> Result<Self> {
        let db = crate::store::open(&config.dir.join("session.db"))?;
        let stored: Option<String> = db.query_row("SELECT name FROM session", [], |r| r.get(0)).optional()?;
        match stored {
            Some(stored) if stored != config.name => {
                bail!("this session is named {stored:?}; names are fixed when a session is created")
            }
            Some(_) => {}
            None => _ = db.execute("INSERT INTO session (name) VALUES (?)", [&config.name])?,
        }
        if !config.keep_log {
            db.execute("UPDATE messages SET payload = json_remove(payload, '$.content') WHERE seen = 1", [])?;
        }
        let mut session = Self {
            db,
            core,
            peers,
            log,
            config,
            outbox: Outbox::default(),
            bindings: HashMap::new(),
            invites: HashMap::new(),
            waiting: Vec::new(),
            fetches: Vec::new(),
            doc_states: HashMap::new(),
            catching_up: Some(Instant::now() + CATCH_UP_WINDOW),
            next_update: Instant::now() + KEY_UPDATE,
            inbound,
        };
        for gid in session.core.groups() {
            session.outbox.catch_up(&b64(&gid.0));
            session.log.follow(&session.core.settings(&gid.0)?.membership, &gid.0);
            if session.core.settings(&gid.0)?.kind != Kind::Doc {
                continue;
            }
            let path: Option<String> =
                session.db.query_row("SELECT path FROM bindings WHERE gid = ?", [&gid.0], |r| r.get(0)).optional()?;
            let text = doc::text(&session.doc_state(&gid)?)?;
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
    pub fn me(&self) -> Result<Value> {
        let (device, device_name) = self.core.device();
        let identities: Vec<Value> =
            self.core.identities()?.into_iter().map(|(identity, name)| json!({ "id": identity.id, "name": name })).collect();
        Ok(json!({ "name": self.config.name, "fp": fp(&self.core.key().0), "device": { "key": device, "name": device_name }, "identities": identities }))
    }

    /// Catches up on every group's log, then replaces this session's keys in each.
    pub async fn resume(&mut self) {
        for gid in self.core.groups() {
            if let Err(error) = self.catch_up(&gid).await {
                self.warn(Some(&gid), format!("catching up: {error:#}"));
            }
        }
        self.update_keys().await;
    }

    async fn update_keys(&mut self) {
        for gid in self.core.groups() {
            if let Err(error) = self.commit(&gid, Op::Update).await {
                self.warn(Some(&gid), format!("key update: {error:#}"));
            }
        }
        self.next_update = Instant::now() + KEY_UPDATE;
    }

    /// When something is next due without anything arriving.
    pub fn next_due(&self) -> Instant {
        let held = self.outbox.deadline(self.config.hold);
        let docs = self.bindings.values().filter_map(|b| b.quiet.due());
        let waiting = self.waiting.iter().map(|w| w.deadline);
        let fetches = self.fetches.iter().map(|f| f.deadline);
        held.into_iter().chain(docs).chain(waiting).chain(fetches).chain(self.catching_up).fold(self.next_update, Instant::min)
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
            if let Err(error) = self.take_message(&w.gid, w.id, w.sender, w.payload) {
                self.warn(Some(&w.gid), format!("{error:#}"));
            }
        }
        let (late, fetches): (Vec<Fetch>, _) = std::mem::take(&mut self.fetches).into_iter().partition(|f| f.deadline <= now);
        self.fetches = fetches;
        for fetch in late {
            let _ = fetch.reply.send(json!({ "error": "no member online holds that file; try again when one is" }));
        }
        if self.next_update <= now {
            self.update_keys().await;
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

    pub async fn handle(&mut self, event: Inbound) {
        match event {
            Inbound::Request(request, reply) => {
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
            Inbound::Entry { log, position, entry } => {
                if self.core.groups().contains(&log)
                    && let Err(error) = self.entry(&log, position, &entry).await
                {
                    self.warn(Some(&log), format!("{error:#}"));
                }
            }
            Inbound::Message { group, ciphertext } => {
                if let Err(error) = self.receive(&group, &ciphertext).await {
                    self.warn(Some(&group), format!("{error:#}"));
                }
            }
            Inbound::Held { id, .. } => _ = self.db.execute("DELETE FROM pending WHERE id = ?", [id]),
            Inbound::Refused { group, id, by, reason } => {
                let member = self.describe_iroh(&group, &by);
                let item = json!({ "type": "refused", "group": b64(&group.0), "id": hex::encode(id), "member": member, "reason": reason });
                self.outbox.deliver(item, true);
            }
            Inbound::File { hash } => {
                if let Err(error) = self.arrived(hash) {
                    self.warn(None, format!("{error:#}"));
                }
            }
            Inbound::Invite { request, reply } => {
                let answer = self.redeemed(request).await;
                let _ = reply.send(self.answered(None, answer));
            }
            Inbound::Join { group, key_package, reply } => {
                let answer = self.join_open(&group, key_package).await;
                let _ = reply.send(self.answered(Some(&group), answer));
            }
            Inbound::DocSv { group, sv } => {
                if let Err(error) = self.answer_sv(&group, &sv).await {
                    self.warn(Some(&group), format!("{error:#}"));
                }
            }
            Inbound::Snapshot { group, reply } => {
                if let Ok(snapshot) = self.doc_state(&group).and_then(|state| doc::snapshot(&state)) {
                    let _ = reply.send(snapshot);
                }
            }
            Inbound::FileChanged(gid) => {
                if let Some(binding) = self.bindings.get_mut(&gid) {
                    binding.quiet.file_changed(Instant::now());
                }
            }
        }
    }

    fn answered(&mut self, gid: Option<&Bytes>, answer: Result<Admitted>) -> Answer<Admitted> {
        match answer {
            Ok(admitted) => Answer::Ok(admitted),
            Err(error) => {
                self.warn(gid, format!("refused a join: {error:#}"));
                Answer::Refused { refused: format!("{error:#}") }
            }
        }
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
                Ok(json!({ "group": b64(&gid.0), "kind": self.core.settings(&gid.0)?.kind, "members": self.described_members(&gid)? }))
            }
            Request::Groups => self.groups(),
            Request::Remove { group, member } => {
                let gid = self.resolve(group)?;
                let member = self.member(&gid, &member)?;
                ensure!(member.key != self.core.key(), "to leave a group, use `leave`");
                self.commit(&gid, Op::Remove(member.key)).await?;
                Ok(json!({ "group": b64(&gid.0), "members": self.described_members(&gid)? }))
            }
            Request::Leave { group } => self.leave(group).await,
            Request::Name { group, name } => {
                let gid = self.resolve(group)?;
                let settings = Settings { name, ..self.core.settings(&gid.0)? };
                self.commit(&gid, Op::Settings(settings.clone())).await?;
                Ok(json!({ "group": b64(&gid.0), "settings": settings }))
            }
            Request::Open { group, close, identity } => {
                let gid = self.resolve(group)?;
                let (id, name) = self.identity_named(&identity)?;
                let mut settings = self.core.settings(&gid.0)?;
                settings.open.retain(|o| o.id != id);
                if !close {
                    settings.open.push(Named { id, name });
                }
                self.commit(&gid, Op::Settings(settings.clone())).await?;
                Ok(json!({ "group": b64(&gid.0), "settings": settings }))
            }
            Request::Attach { group, path } => {
                let gid = self.of_kind(group, Kind::Doc)?;
                let bytes = std::fs::read(&path).with_context(|| format!("cannot read {path}"))?;
                let name = Path::new(&path).file_name().map_or_else(String::new, |n| n.to_string_lossy().replace(['[', ']'], ""));
                let link = self.peers.add_file(&gid.0, &bytes)?.link();
                let markdown = format!("{}[{name}]({link})", if image_type(&bytes).is_some() { "!" } else { "" });
                Ok(json!({ "link": link, "markdown": markdown }))
            }
            Request::Fetch { .. } => unreachable!("answered by fetch"),
            Request::Status => self.status(),
            Request::Identity { op } => self.identity(op).await,
            Request::Contacts { op: None } => self.contacts(),
            Request::Contacts { op: Some(ContactsOp::Accept { identity, name }) } => self.accept(&identity, name),
            Request::Introduce { group, member, to } => self.introduce(group, &member, &to).await,
        }
    }

    // Groups and their logs.

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
        let mut answer = json!({ "expires_in": INVITE_TTL.as_secs() });
        let into = match identity {
            Some(identity) => {
                let (identity, name) = self.own_identity(&identity)?;
                answer["identity"] = json!({ "id": identity.id, "name": name });
                Into::Device(identity)
            }
            None => {
                let gid = match group {
                    Some(group) => self.resolve(Some(group))?,
                    None => {
                        let membership = membership.map(|m| crate::service(&m)).transpose()?.unwrap_or(self.config.membership.clone());
                        let as_ = as_.map(|as_| self.own_identity(&as_).map(|(identity, _)| identity.id)).transpose()?;
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
                let settings = self.core.settings(&gid.0)?;
                answer["group"] = json!(b64(&gid.0));
                answer["kind"] = json!(settings.kind);
                if !settings.name.is_empty() {
                    answer["name"] = json!(settings.name);
                }
                if let Some(binding) = self.bindings.get(&gid) {
                    answer["file"] = json!(binding.path);
                }
                Into::Group(gid)
            }
        };
        if let Some(for_) = &for_ {
            answer["for"] = json!(for_);
        }
        if let Some(to) = &to {
            answer["to"] = json!(to);
        }
        let secret: [u8; 16] = rand::random();
        let device = matches!(into, Into::Device(_));
        self.invites.insert(secret, PendingInvite { into, for_, to, expires: Instant::now() + INVITE_TTL });
        let (key, relay) = self.peers.address();
        let key = key.0.try_into().ok().context("an iroh key is 32 bytes")?;
        let relay = (relay != crate::RELAY).then_some(relay);
        answer["link"] = json!(Invite { device, key, secret, relay }.link());
        Ok(answer)
    }

    async fn create(&mut self, settings: Settings, as_: Option<Bytes>, file: Option<String>) -> Result<Bytes> {
        let doc = settings.kind == Kind::Doc;
        let gid = self.core.create(settings, as_.as_ref())?;
        self.add_group(&gid, 0)?;
        if doc {
            self.store_doc(&gid, &doc::new(""))?;
            self.bind(&gid, file, "")?;
            self.sync(&gid).await?;
        }
        Ok(gid)
    }

    fn add_group(&mut self, gid: &Bytes, position: u64) -> Result<()> {
        self.db.execute("INSERT INTO groups (gid, position) VALUES (?, ?)", params![gid.0, position])?;
        self.log.follow(&self.core.settings(&gid.0)?.membership, &gid.0);
        Ok(())
    }

    fn position(&self, gid: &Bytes) -> Result<u64> {
        Ok(self.db.query_row("SELECT position FROM groups WHERE gid = ?", [&gid.0], |r| r.get(0))?)
    }

    async fn entry(&mut self, gid: &Bytes, position: u64, entry: &[u8]) -> Result<()> {
        let at = self.position(gid)?;
        match position {
            p if p <= at => Ok(()),
            p if p == at + 1 => self.apply(gid, p, entry).map(drop),
            _ => self.catch_up(gid).await,
        }
    }

    async fn catch_up(&mut self, gid: &Bytes) -> Result<()> {
        let at = self.position(gid)?;
        let entries = self.log.read(&self.core.settings(&gid.0)?.membership, &gid.0, at).await?;
        for (position, entry) in (at + 1..).zip(entries) {
            if let Applied::Commit(changes) | Applied::Own(changes) = self.apply(gid, position, &entry)?
                && changes.iter().any(|c| matches!(c, Change::Removed { .. }))
            {
                break;
            }
        }
        Ok(())
    }

    fn apply(&mut self, gid: &Bytes, position: u64, entry: &[u8]) -> Result<Applied> {
        let applied = self.core.apply(&gid.0, entry)?;
        self.db.execute("UPDATE groups SET position = ? WHERE gid = ?", params![position, gid.0])?;
        if let Applied::Commit(changes) | Applied::Own(changes) = &applied {
            for change in changes.clone() {
                self.change(gid, change)?;
            }
        }
        Ok(applied)
    }

    fn change(&mut self, gid: &Bytes, change: Change) -> Result<()> {
        let group = b64(&gid.0);
        let item = match change {
            Change::Joined { member, by, how } => {
                json!({ "type": "joined", "group": group, "member": self.describe(gid, &member)?, "by": self.describe_key(gid, &by), "how": how })
            }
            Change::Left { member, by } => {
                json!({ "type": "left", "group": group, "member": self.describe(gid, &member)?, "by": self.describe_key(gid, &by) })
            }
            Change::Removed { by } => {
                let by = self.describe_key(gid, &by);
                self.drop_group(gid)?;
                json!({ "type": "removed", "group": group, "by": by })
            }
            Change::Settings { settings, by } => {
                self.log.follow(&settings.membership, &gid.0);
                json!({ "type": "settings", "group": group, "settings": settings, "by": self.describe_key(gid, &by) })
            }
            Change::KeyUpdate => return Ok(()),
        };
        self.outbox.deliver(item, true);
        Ok(())
    }

    /// Commits `op` on the group's current epoch: the commit counts once the log has it as the first valid commit for
    /// that epoch; if another commit came first, it is built again on the new epoch.
    async fn commit(&mut self, gid: &Bytes, op: Op) -> Result<(Commit, u64)> {
        for _ in 0..3 {
            self.catch_up(gid).await?;
            if let Op::Remove(key) = &op {
                ensure!(self.core.members(&gid.0)?.iter().any(|m| &m.key == key), "{} is not a member", fp(&key.0));
            }
            let commit = self.core.commit(&gid.0, op.clone())?;
            let service = self.core.settings(&gid.0)?.membership;
            let position = self.log.append(&service, &gid.0, &commit.entry).await?;
            let at = self.position(gid)?;
            let entries = self.log.read(&service, &gid.0, at).await?;
            for (n, entry) in (at + 1..=position).zip(entries) {
                if matches!(self.apply(gid, n, &entry)?, Applied::Own(_)) {
                    self.peers.commit(&gid.0, &commit.entry);
                    return Ok((commit, position));
                }
            }
        }
        bail!("the group kept changing; try again")
    }

    async fn leave(&mut self, group: Option<String>) -> Result<Value> {
        let gid = self.resolve(group)?;
        if self.core.members(&gid.0)?.len() == 1 {
            self.drop_group(&gid)?;
            return Ok(json!({ "group": b64(&gid.0), "left": true }));
        }
        let (_, delivery) = self.post(&gid, &Payload::Leave).await?;
        let mut answer = json!({ "group": b64(&gid.0), "left": true, "status": "another member commits the removal" });
        if delivery.held.is_empty() {
            answer["pending"] = json!(true);
        }
        Ok(answer)
    }

    fn drop_group(&mut self, gid: &Bytes) -> Result<()> {
        self.core.forget(&gid.0)?;
        // A file the agent named stays; one in the session's state goes with the group.
        if let Some(binding) = self.bindings.remove(gid)
            && binding.path.starts_with(self.config.dir.join("docs"))
            && binding.path.exists()
        {
            std::fs::remove_file(&binding.path)?;
        }
        for table in ["groups", "messages", "pending", "docs", "bindings", "attachments"] {
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
        for gid in self.core.groups() {
            let settings = self.core.settings(&gid.0)?;
            let mut group = json!({
                "group": b64(&gid.0), "kind": settings.kind, "members": self.core.members(&gid.0)?.len(), "keep": settings.keep,
                "membership": settings.membership,
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
        let joined = self.core.groups();
        for opening in self.core.openings()? {
            if !joined.contains(&opening.group) {
                groups.push(json!({ "group": opening.group, "kind": opening.kind, "name": opening.name, "joined": false }));
            }
        }
        Ok(Value::Array(groups))
    }

    fn status(&self) -> Result<Value> {
        let mut groups = Vec::new();
        for gid in self.core.groups() {
            let online = self.peers.online(&gid.0);
            let mut members = Vec::new();
            for member in self.core.members(&gid.0)? {
                if online.contains(&member.iroh) {
                    members.push(self.describe(&gid, &member)?);
                }
            }
            let only_here: Vec<Value> = self
                .db
                .prepare("SELECT id, what FROM pending WHERE gid = ?")?
                .query_map([&gid.0], |r| Ok(json!({ "id": hex::encode(r.get::<_, Vec<u8>>(0)?), "what": r.get::<_, String>(1)? })))?
                .collect::<Result<_, _>>()?;
            let mut group = json!({ "group": b64(&gid.0), "online": members, "only_here": only_here });
            if let Some(name) = Some(self.core.settings(&gid.0)?.name).filter(|n| !n.is_empty()) {
                group["name"] = json!(name);
            }
            groups.push(group);
        }
        let only_here = self.db.query_row("SELECT count(*) FROM pending", [], |r| r.get::<_, u64>(0))?;
        let mut status = json!({ "groups": groups });
        if only_here > 0 {
            status["warning"] = json!(format!("{only_here} sends are held only by this session; keep it running until a member is online"));
        }
        Ok(status)
    }

    /// The group a command acts on: the one --group names (by id or name), or else the session's one group.
    fn resolve(&self, group: Option<String>) -> Result<Bytes> {
        let gids = self.core.groups();
        match group {
            Some(group) => {
                let named: Vec<&Bytes> = gids
                    .iter()
                    .filter(|gid| b64(&gid.0) == group || self.core.settings(&gid.0).is_ok_and(|s| s.name == group))
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
            ensure!(self.core.settings(&gid.0)?.kind == kind, "{} is not a {name}", b64(&gid.0));
            return Ok(gid);
        }
        let found: Vec<Bytes> = self.core.groups().into_iter().filter(|gid| self.core.settings(&gid.0).is_ok_and(|s| s.kind == kind)).collect();
        match &found[..] {
            [gid] => Ok(gid.clone()),
            [] => bail!("this session is in no {name}; create one with `invite --kind {name}`, or join one with `join`"),
            _ => bail!("this session is in several {name}s; pass --group"),
        }
    }

    // Invites and joins.

    /// Answers a joiner that presented an invite's secret.
    async fn redeemed(&mut self, request: InviteRequest) -> Result<Admitted> {
        let secret: [u8; 16] = request.secret.0.as_slice().try_into().ok().context("a secret is 16 bytes")?;
        let invite = self.invites.remove(&secret).filter(|i| i.expires > Instant::now()).context("unknown, used or expired invite")?;
        match (invite.into, request.joiner) {
            (Into::Group(gid), Joiner::Member { key_package }) => {
                let joiner = self.core.inspect(&key_package.0)?;
                let claim = joiner.identity.filter(|claim| claim.error.is_none());
                if let Some(to) = &invite.to {
                    ensure!(claim.as_ref().is_some_and(|c| &c.identity.id == to), "this link is for another identity");
                }
                let admitted = self.admit(&gid, key_package).await?;
                if let Some(claim) = claim {
                    if let Some(name) = &invite.for_ {
                        let contact = Contact { id: claim.identity.id.clone(), name: name.clone(), how: Known::Verified, by: None };
                        self.core.set_contact(contact)?;
                    }
                    let name = invite.for_.unwrap_or_else(|| self.display_name(&claim));
                    self.post(&gid, &Payload::Introduce { identity: claim.identity, name, how: How::Invite }).await?;
                }
                Ok(admitted)
            }
            (Into::Device(identity), Joiner::Device { device, device_name }) => {
                let log = device_log(&identity.id.0);
                let entries = self.log.read(&identity.membership, &log.0, 0).await?;
                let entry = self.core.identity_entry(&identity.id.0, Some(&device_name), &device.0, &entries)?;
                self.log.append(&identity.membership, &log.0, &entry).await?;
                Ok(Admitted { welcome: Bytes::default(), position: 0, doc: None })
            }
            (Into::Group(_), _) => bail!("this link invites a session into a group, not a device"),
            (Into::Device(_), _) => bail!("this link adds a device to an identity, not a session"),
        }
    }

    /// Admits a session that asked to join a group open to its identity.
    async fn join_open(&mut self, gid: &Bytes, key_package: Bytes) -> Result<Admitted> {
        let open = self.core.settings(&gid.0)?.open;
        let joiner = self.core.inspect(&key_package.0)?;
        let claim = joiner.identity.filter(|c| c.error.is_none() && open.iter().any(|o| o.id == c.identity.id));
        let claim = claim.context("it speaks as no identity the group is open to")?;
        let admitted = self.admit(gid, key_package).await?;
        let name = self.display_name(&claim);
        self.post(gid, &Payload::Introduce { identity: claim.identity, name, how: How::Open }).await?;
        Ok(admitted)
    }

    async fn admit(&mut self, gid: &Bytes, key_package: Bytes) -> Result<Admitted> {
        let (commit, position) = self.commit(gid, Op::Add(key_package)).await?;
        let doc = match self.core.settings(&gid.0)?.kind {
            Kind::Doc => Some(self.peers.add_file(&gid.0, &self.doc_state(gid)?)?.link()),
            Kind::Chat => None,
        };
        Ok(Admitted { welcome: Bytes(commit.welcome.context("an add makes a welcome")?), position, doc })
    }

    async fn join(&mut self, target: String, file: Option<String>, as_: Option<String>) -> Result<Value> {
        let as_ = as_.map(|as_| self.own_identity(&as_).map(|(identity, _)| identity.id)).transpose()?;
        let answer = if target.contains('#') {
            let invite = Invite::parse(target.trim())?;
            let joiner = match invite.device {
                true => {
                    let (device, device_name) = self.core.device();
                    Joiner::Device { device, device_name }
                }
                false => Joiner::Member { key_package: self.core.key_package(as_.as_ref())? },
            };
            self.peers.redeem(&invite, &InviteRequest { secret: Bytes(invite.secret.to_vec()), joiner }).await?
        } else {
            let opening = self.core.openings()?.into_iter().find(|o| b64(&o.group.0) == target || o.name == target);
            let opening = opening.context("expected an invite link, or the id or name of a group open to your identity")?;
            let key_package = self.core.key_package(as_.as_ref())?;
            self.peers.ask_to_join(&opening, &key_package.0).await?
        };
        let admitted = match answer {
            Answer::Ok(admitted) => admitted,
            Answer::Refused { refused } => bail!("refused: {refused}"),
        };
        if admitted.welcome.0.is_empty() {
            return Ok(json!({ "device": "added to the identity's device list" }));
        }
        let gid = self.core.join(&admitted.welcome.0)?;
        self.add_group(&gid, admitted.position)?;
        self.catch_up(&gid).await?;
        let settings = self.core.settings(&gid.0)?;
        let mut answer = json!({ "group": b64(&gid.0), "kind": settings.kind, "name": settings.name, "members": self.described_members(&gid)? });
        if settings.kind == Kind::Doc {
            let mut state = doc::new("");
            if let Some(link) = &admitted.doc {
                let link = FileLink::parse(link)?;
                match self.peers.file(&link)? {
                    Some(held) => state = held,
                    None => {
                        self.peers.want(&gid.0, &link);
                        self.doc_states.insert(link.hash, (gid.clone(), link));
                    }
                }
            }
            self.store_doc(&gid, &state)?;
            answer["file"] = json!(self.bind(&gid, file, &doc::text(&state)?)?);
        }
        Ok(answer)
    }

    // Messages.

    /// Seals a payload and sends it to the members online.
    async fn post(&mut self, gid: &Bytes, payload: &Payload) -> Result<([u8; 32], crate::node::Delivery)> {
        let ciphertext = self.core.seal(&gid.0, payload)?;
        Ok((id_of(&ciphertext), self.peers.send(&gid.0, &ciphertext).await))
    }

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
            ensure!(self.mark_seen(id)?, "unknown message {}", hex::encode(id));
        }
        let attachment = match attach {
            Some((data, name)) => {
                let bytes = B64.decode(data)?;
                let link = self.peers.add_file(&gid.0, &bytes)?;
                let media_type = image_type(&bytes).map(|t| format!("image/{t}")).unwrap_or_default();
                Some((link.clone(), Attachment { link: link.link(), name, size: bytes.len() as u64, media_type }))
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
        let ciphertext = self.core.seal(&gid.0, &payload)?;
        let id = id_of(&ciphertext);
        let me = self.describe_key(&gid, &self.core.key());
        self.db.execute(
            "INSERT INTO messages (id, gid, sender, payload, seen, mine) VALUES (?, ?, ?, ?, 1, 1)",
            params![id, gid.0, me.to_string(), serde_json::to_string(&payload)?],
        )?;
        let delivery = self.peers.send(&gid.0, &ciphertext).await;
        let mut answer = json!({ "id": hex::encode(id) });
        if !addressed.is_empty() {
            answer["to"] = json!(addressed.iter().map(|m| fp(&m.key.0)).collect::<Vec<_>>());
        }
        let held: Vec<Value> = delivery.held.iter().map(|key| self.describe_iroh(&gid, key)).collect();
        if held.is_empty() {
            self.db.execute("INSERT INTO pending (id, gid, what) VALUES (?, ?, 'message')", params![id, gid.0])?;
            answer["pending"] = json!(true);
        } else {
            answer["held_by"] = json!(held);
        }
        if !delivery.refused.is_empty() {
            let refused: Vec<Value> = delivery
                .refused
                .iter()
                .map(|(key, reason)| json!({ "member": self.describe_iroh(&gid, key), "reason": reason }))
                .collect();
            answer["refused"] = json!(refused);
        }
        if let Some((link, _)) = attachment {
            let holders = self.peers.spread(&gid.0, &link).await;
            if holders.is_empty() {
                self.db.execute("INSERT OR IGNORE INTO pending (id, gid, what) VALUES (?, ?, 'file')", params![link.hash, gid.0])?;
                answer["attachment"] = json!({ "pending": true, "warning": "no other member holds the file yet; it is available only while this session runs" });
            } else {
                answer["attachment"] = json!({ "held_by": holders.iter().map(|key| self.describe_iroh(&gid, key)).collect::<Vec<_>>() });
            }
        }
        Ok(answer)
    }

    /// The members `to` addresses: a fingerprint, or a name they answer to, as long as they speak for one identity.
    fn addressed(&self, gid: &Bytes, to: &str) -> Result<Vec<Member>> {
        let members = self.core.members(&gid.0)?;
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

    async fn receive(&mut self, gid: &Bytes, ciphertext: &[u8]) -> Result<()> {
        let id = id_of(ciphertext);
        let known = self.db.query_row("SELECT 1 FROM messages WHERE id = ?", [id], |_| Ok(())).optional()?.is_some();
        if known || self.waiting.iter().any(|w| w.id == id) || !self.core.groups().contains(gid) {
            return Ok(());
        }
        let opened = self.core.open(&gid.0, ciphertext)?;
        let sender = self.describe_key(gid, &opened.sender);
        match opened.payload {
            payload @ Payload::Message { .. } => {
                let payload = serde_json::to_value(&payload)?;
                let missing = self.missing(&payload)?;
                if missing.is_empty() {
                    self.take_message(gid, id, sender, payload)?;
                } else {
                    self.waiting.push(Waiting { deadline: Instant::now() + CAUSAL_WAIT, gid: gid.clone(), id, sender, payload });
                }
            }
            Payload::Edit { update } | Payload::Diff { update } => {
                ensure!(self.core.settings(&gid.0)?.kind == Kind::Doc, "an edit in a chat");
                let state = doc::apply(&self.doc_state(gid)?, &update.0)?;
                self.store_doc(gid, &state)?;
                let binding = self.bindings.get_mut(gid).expect("a doc is bound");
                binding.quiet.doc_changed(Instant::now());
                if !binding.editors.iter().any(|e| e["fp"] == sender["fp"]) {
                    binding.editors.push(sender);
                }
            }
            Payload::Leave => {
                if self.core.members(&gid.0)?.iter().any(|m| m.key == opened.sender) {
                    // The first member to see it commits the removal; one that lost the race finds it gone.
                    if let Err(error) = self.commit(gid, Op::Remove(opened.sender.clone())).await
                        && self.core.members(&gid.0)?.iter().any(|m| m.key == opened.sender)
                    {
                        return Err(error);
                    }
                }
            }
            Payload::Introduce { identity, name, how } => self.introduced(gid, &opened.sender, sender, identity, name, how)?,
        }
        Ok(())
    }

    /// The messages a message comes after that this session has not taken in.
    fn missing(&self, payload: &Value) -> Result<Vec<[u8; 32]>> {
        let after: Vec<Bytes> = serde_json::from_value(payload["after"].clone())?;
        let mut missing = Vec::new();
        for id in after {
            let id: [u8; 32] = id.0.try_into().ok().context("a message id is 32 bytes")?;
            if self.db.query_row("SELECT 1 FROM messages WHERE id = ?", [id], |_| Ok(())).optional()?.is_none() {
                missing.push(id);
            }
        }
        Ok(missing)
    }

    /// Takes in a chat message, then those that waited for it.
    fn take_message(&mut self, gid: &Bytes, id: [u8; 32], sender: Value, payload: Value) -> Result<()> {
        let missing = self.missing(&payload)?;
        self.db.execute(
            "INSERT OR IGNORE INTO messages (id, gid, sender, payload) VALUES (?, ?, ?, ?)",
            params![id, gid.0, sender.to_string(), payload.to_string()],
        )?;
        let mut item = self.message_json(gid, id, sender, &payload)?;
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
            match self.peers.file(&link)? {
                Some(bytes) => item["attachment"]["path"] = json!(self.save(gid, &link, Some(&name), &bytes)?),
                None => {
                    self.peers.want(&gid.0, &link);
                    item["attachment"]["pending"] = json!(true);
                }
            }
        }
        self.outbox.deliver(item, wakes);
        let ready: Vec<usize> = (0..self.waiting.len())
            .filter(|&i| self.waiting[i].gid == *gid && self.missing(&self.waiting[i].payload).is_ok_and(|m| m.is_empty()))
            .collect();
        for i in ready.into_iter().rev() {
            let w = self.waiting.remove(i);
            self.take_message(&w.gid, w.id, w.sender, w.payload)?;
        }
        Ok(())
    }

    fn mine(&self, id: &str) -> bool {
        message_id(id).is_ok_and(|id| {
            self.db.query_row("SELECT mine FROM messages WHERE id = ?", [id], |r| r.get::<_, bool>(0)).unwrap_or(false)
        })
    }

    fn message_json(&self, gid: &Bytes, id: [u8; 32], from: Value, payload: &Value) -> Result<Value> {
        let me = self.describe_key(gid, &self.core.key());
        let to: Vec<Bytes> = serde_json::from_value(payload.get("to").cloned().unwrap_or(json!([])))?;
        let to: Vec<String> = to.iter().map(|fp| hex::encode(&fp.0)).collect();
        let content = payload.get("content").cloned().unwrap_or(Value::Null);
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

    /// Read-frontier tips: seen messages that no other seen message lists in `after`.
    fn tips(&self, gid: &Bytes) -> Result<Vec<[u8; 32]>> {
        let seen: Vec<([u8; 32], String)> = self
            .db
            .prepare("SELECT id, payload FROM messages WHERE gid = ? AND seen = 1")?
            .query_map([&gid.0], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut covered = HashSet::new();
        for (_, payload) in &seen {
            let payload: Value = serde_json::from_str(payload)?;
            covered.extend(serde_json::from_value::<Vec<Bytes>>(payload["after"].clone())?.into_iter().map(|id| id.0));
        }
        Ok(seen.into_iter().map(|(id, _)| id).filter(|id| !covered.contains(id.as_slice())).collect())
    }

    /// Records that a message entered the agent's context. Its text is then deleted, unless `listen --keep-log`.
    fn mark_seen(&self, id: &[u8; 32]) -> Result<bool> {
        let forget = if self.config.keep_log { "" } else { ", payload = json_remove(payload, '$.content')" };
        Ok(self.db.execute(&format!("UPDATE messages SET seen = 1{forget} WHERE id = ?"), [id])? > 0)
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
                let row: Option<(Vec<u8>, String, String)> = self
                    .db
                    .query_row("SELECT gid, sender, payload FROM messages WHERE id = ?", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                    .optional()?;
                let Some((gid, sender, payload)) = row else {
                    ensure!(depth > 0, "unknown message {}", hex::encode(id));
                    continue;
                };
                let payload: Value = serde_json::from_str(&payload)?;
                found.push(self.message_json(&Bytes(gid), id, serde_json::from_str(&sender)?, &payload)?);
                self.mark_seen(&id)?;
                for after in serde_json::from_value::<Vec<Bytes>>(payload["after"].clone())? {
                    next.push(after.0.try_into().ok().context("a message id is 32 bytes")?);
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

    /// A file arrived: for the attachments and fetches waiting for it, and a joined doc's state.
    fn arrived(&mut self, hash: [u8; 32]) -> Result<()> {
        self.db.execute("DELETE FROM pending WHERE id = ?", [hash])?;
        let waiting: Vec<(Vec<u8>, Vec<u8>, String, String, bool)> = self
            .db
            .prepare("SELECT gid, message, link, name, wakes FROM attachments WHERE hash = ? AND path IS NULL")?
            .query_map([hash], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<Result<_, _>>()?;
        for (gid, message, link, name, wakes) in waiting {
            let (gid, link) = (Bytes(gid), FileLink::parse(&link)?);
            let bytes = self.peers.file(&link)?.context("an arrived file is held")?;
            let path = self.save(&gid, &link, Some(&name), &bytes)?;
            self.db.execute("UPDATE attachments SET path = ? WHERE hash = ? AND message = ?", params![path.to_str(), hash, message])?;
            let item = json!({ "type": "attachment", "group": b64(&gid.0), "message": hex::encode(&message), "name": name, "path": path });
            self.outbox.deliver(item, wakes);
        }
        let (done, fetches): (Vec<Fetch>, _) = std::mem::take(&mut self.fetches).into_iter().partition(|f| f.hash == hash);
        self.fetches = fetches;
        for fetch in done {
            let bytes = self.peers.file(&fetch.link)?.context("an arrived file is held")?;
            let path = self.save(&fetch.gid, &fetch.link, fetch.name.as_deref(), &bytes)?;
            let _ = fetch.reply.send(json!({ "path": path, "bytes": bytes.len() }));
        }
        if let Some((gid, link)) = self.doc_states.remove(&hash) {
            let state = self.peers.file(&link)?.context("an arrived file is held")?;
            self.merge_doc(&gid, &state)?;
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
        match self.peers.file(&link)? {
            Some(bytes) => {
                let path = self.save(&gid, &link, name.as_deref(), &bytes)?;
                let _ = reply.send(json!({ "path": path, "bytes": bytes.len() }));
            }
            None => {
                self.peers.want(&gid.0, &link);
                self.fetches.push(Fetch { hash: link.hash, gid, link, name, deadline: Instant::now() + FETCH_WAIT, reply });
            }
        }
        Ok(())
    }

    /// The group whose messages or doc link `link`, and the file's name if a message attached it.
    fn linking(&self, link: &str) -> Result<Option<(Bytes, Option<String>)>> {
        let attached: Option<(Vec<u8>, String)> = self
            .db
            .query_row("SELECT gid, name FROM attachments WHERE link = ?", [link], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        if let Some((gid, name)) = attached {
            return Ok(Some((Bytes(gid), Some(name))));
        }
        let mine: Option<(Vec<u8>,)> = self
            .db
            .query_row("SELECT gid FROM messages WHERE json_extract(payload, '$.attachment.link') = ?", [link], |r| Ok((r.get(0)?,)))
            .optional()?;
        if let Some((gid,)) = mine {
            return Ok(Some((Bytes(gid), None)));
        }
        let docs: Vec<(Vec<u8>, Vec<u8>)> =
            self.db.prepare("SELECT gid, state FROM docs")?.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
        for (gid, state) in docs {
            if doc::text(&state)?.contains(link) {
                return Ok(Some((Bytes(gid), None)));
            }
        }
        Ok(None)
    }

    // Docs.

    fn doc_state(&self, gid: &Bytes) -> Result<Vec<u8>> {
        let state: Option<Vec<u8>> = self.db.query_row("SELECT state FROM docs WHERE gid = ?", [&gid.0], |r| r.get(0)).optional()?;
        Ok(state.unwrap_or_else(|| doc::new("")))
    }

    fn store_doc(&self, gid: &Bytes, state: &[u8]) -> Result<()> {
        self.db.execute(
            "INSERT INTO docs (gid, state) VALUES (?, ?) ON CONFLICT (gid) DO UPDATE SET state = excluded.state",
            params![gid.0, state],
        )?;
        Ok(())
    }

    fn merge_doc(&mut self, gid: &Bytes, update: &[u8]) -> Result<()> {
        let state = doc::apply(&self.doc_state(gid)?, update)?;
        self.store_doc(gid, &state)?;
        if let Some(binding) = self.bindings.get_mut(gid) {
            binding.quiet.doc_changed(Instant::now());
        }
        Ok(())
    }

    async fn answer_sv(&mut self, gid: &Bytes, sv: &[u8]) -> Result<()> {
        let update = doc::diff(&self.doc_state(gid)?, sv)?;
        self.post(gid, &Payload::Diff { update: Bytes(update) }).await?;
        Ok(())
    }

    /// Keeps `file` (or a new one in the session's state) in step with the doc `gid`, from `base`, the text both have
    /// now. The file is created holding it unless it exists; one that exists brings its text in at the next sync.
    fn bind(&mut self, gid: &Bytes, file: Option<String>, base: &str) -> Result<PathBuf> {
        let path = match file {
            Some(file) => PathBuf::from(file),
            None => {
                let name: String = self.core.settings(&gid.0)?.name.chars().map(|c| if c.is_alphanumeric() { c } else { '-' }).collect();
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
        let state = self.doc_state(gid)?;
        let current = doc::text(&state)?;
        let (text, lost) = if file == base { (current.clone(), Vec::new()) } else { doc::rebase(&base, &file, &current) };
        if text != current {
            let update = doc::edit(&state, &text)?;
            self.store_doc(gid, &doc::apply(&state, &update)?)?;
            self.post(gid, &Payload::Edit { update: Bytes(update) }).await?;
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
            let me = self.describe_key(gid, &self.core.key());
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
        self.core.members(&gid.0)?.iter().map(|m| self.describe(gid, m)).collect()
    }

    fn describe_key(&self, gid: &Bytes, key: &Bytes) -> Value {
        let member = self.core.members(&gid.0).ok().and_then(|members| members.into_iter().find(|m| &m.key == key));
        match member {
            Some(member) => self.describe(gid, &member).unwrap_or_else(|_| json!({ "fp": fp(&key.0) })),
            None if *key == self.core.key() => json!({ "name": self.config.name, "fp": fp(&key.0), "you": true }),
            None => json!({ "fp": fp(&key.0) }),
        }
    }

    fn describe_iroh(&self, gid: &Bytes, iroh: &Bytes) -> Value {
        let member = self.core.members(&gid.0).ok().and_then(|members| members.into_iter().find(|m| &m.iroh == iroh));
        match member {
            Some(member) => self.describe(gid, &member).unwrap_or_else(|_| json!({ "iroh": iroh })),
            None => json!({ "iroh": iroh }),
        }
    }

    /// A member as events show it: its name, its identity as this session knows it, and who added it.
    fn describe(&self, gid: &Bytes, member: &Member) -> Result<Value> {
        let mut described = json!({ "name": member.name, "fp": fp(&member.key.0), "device": member.device_name });
        if member.key == self.core.key() {
            described["you"] = json!(true);
        }
        if let Some(claim) = &member.identity {
            described["identity"] = self.known(gid, claim)?;
        }
        if let Some((by, how)) = &member.added {
            let adder = self.core.members(&gid.0)?.into_iter().find(|m| &m.key == by);
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
        let own = self.core.identities()?.into_iter().find(|(identity, _)| &identity.id == id);
        let contacts = self.core.contacts()?;
        let present = |by: &[u8]| {
            self.core.members(&gid.0).is_ok_and(|members| members.iter().any(|m| m.identity.as_ref().is_some_and(|c| c.identity.id.0 == by)))
        };
        if let Some((_, name)) = &own {
            known["name"] = json!(name);
            known["how"] = json!("self");
        } else if let Some(contact) = contacts.iter().find(|c| &c.id == id) {
            known["name"] = json!(contact.name);
            known["how"] = json!(contact.how);
            if let Some(by) = &contact.by {
                let name = contacts.iter().find(|c| &c.id == by).map_or_else(|| b64(&by.0), |c| c.name.clone());
                known["by"] = json!(name);
                if !present(&by.0) {
                    known["introducer_absent"] = json!(true);
                }
            }
        } else {
            known["name"] = json!(claim.name);
            known["claim"] = json!(true);
            known["how"] = json!("unknown");
            if contacts.iter().any(|c| c.name.eq_ignore_ascii_case(&claim.name)) {
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
        let contact = self.core.contacts().ok().and_then(|c| c.into_iter().find(|c| c.id == claim.identity.id));
        contact.map_or_else(|| claim.name.clone(), |c| c.name)
    }

    fn introduced(&mut self, gid: &Bytes, sender_key: &Bytes, sender: Value, identity: IdentityRef, name: String, how: How) -> Result<()> {
        let own = self.core.identities()?.iter().any(|(own, _)| own.id == identity.id);
        let contact = self.core.contacts()?.iter().any(|c| c.id == identity.id);
        if !own && !contact {
            let by_id = sender["identity"]["id"].as_str().map_or_else(|| sender_key.0.clone(), |id| URL_SAFE_NO_PAD.decode(id).unwrap_or_default());
            self.db.execute(
                "INSERT OR REPLACE INTO introductions (identity, by, name, ref) VALUES (?, ?, ?, ?)",
                params![identity.id.0, sender.to_string(), name, json!({ "by": Bytes(by_id), "identity": identity }).to_string()],
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
        let (id, _) = self.post(&gid, &Payload::Introduce { identity: claim.identity.clone(), name: name.clone(), how: How::Introduce }).await?;
        Ok(json!({ "id": hex::encode(id), "group": b64(&gid.0), "identity": { "id": claim.identity.id, "name": name }, "to": self.describe(&gid, &to)? }))
    }

    /// An identity this device is on, by id or name.
    fn own_identity(&self, name: &str) -> Result<(IdentityRef, String)> {
        let identities = self.core.identities()?;
        identities.into_iter().find(|(identity, own)| b64(&identity.id.0) == name || own == name).with_context(|| format!("this device is on no identity {name}"))
    }

    /// An identity named by id or name: one of this device's own, or a contact.
    fn identity_named(&self, name: &str) -> Result<(Bytes, String)> {
        if let Ok((identity, own)) = self.own_identity(name) {
            return Ok((identity.id, own));
        }
        let id = self.contact(name)?;
        let contact = self.core.contacts()?.into_iter().find(|c| c.id == id).expect("found by contact");
        Ok((contact.id, contact.name))
    }

    fn contact(&self, name: &str) -> Result<Bytes> {
        let contacts = self.core.contacts()?;
        let contact = contacts.iter().find(|c| b64(&c.id.0) == name || c.name.eq_ignore_ascii_case(name));
        Ok(contact.with_context(|| format!("no contact {name}; `contacts` lists them"))?.id.clone())
    }

    async fn identity(&mut self, op: IdentityOp) -> Result<Value> {
        match op {
            IdentityOp::Create { name, membership } => {
                let membership = membership.map(|m| crate::service(&m)).transpose()?.unwrap_or(self.config.membership.clone());
                let (identity, entry) = self.core.identity_create(&name, membership)?;
                self.log.append(&identity.membership, &device_log(&identity.id.0).0, &entry).await?;
                Ok(json!({ "identity": identity.id, "name": name }))
            }
            IdentityOp::List => {
                let mut identities = Vec::new();
                let (me, _) = self.core.device();
                for (identity, _) in self.core.identities()? {
                    let entries = self.log.read(&identity.membership, &device_log(&identity.id.0).0, 0).await?;
                    let list = self.core.device_list(&identity.id.0, &entries)?;
                    let devices: Vec<Value> =
                        list.devices.iter().map(|(key, name)| json!({ "key": key, "name": name, "you": *key == me })).collect();
                    identities.push(json!({ "identity": identity.id, "name": list.name, "devices": devices }));
                }
                Ok(json!({ "identities": identities }))
            }
            IdentityOp::Remove { identity, device } => {
                let identities = self.core.identities()?;
                let identity = match (identity, &identities[..]) {
                    (Some(identity), _) => self.own_identity(&identity)?.0,
                    (None, [(only, _)]) => only.clone(),
                    (None, _) => bail!("pass --identity: this device is on {} identities", identities.len()),
                };
                let log = device_log(&identity.id.0);
                let entries = self.log.read(&identity.membership, &log.0, 0).await?;
                let list = self.core.device_list(&identity.id.0, &entries)?;
                let (key, _) = list.devices.iter().find(|(key, name)| b64(&key.0) == device || *name == device).context("no such device")?;
                let entry = self.core.identity_entry(&identity.id.0, None, &key.0, &entries)?;
                self.log.append(&identity.membership, &log.0, &entry).await?;
                Ok(json!({ "identity": identity.id, "removed": key }))
            }
        }
    }

    fn contacts(&self) -> Result<Value> {
        let contacts = self.core.contacts()?;
        let listed: Vec<Value> = contacts
            .iter()
            .map(|c| {
                let mut contact = json!({ "identity": c.id, "name": c.name, "how": c.how });
                if let Some(by) = &c.by {
                    contact["by"] = json!(contacts.iter().find(|i| &i.id == by).map_or_else(|| b64(&by.0), |i| i.name.clone()));
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

    fn accept(&mut self, identity: &str, name: Option<String>) -> Result<Value> {
        let id = URL_SAFE_NO_PAD.decode(identity).context("expected an identity id")?;
        let introduction: (String, String) = self
            .db
            .query_row("SELECT name, ref FROM introductions WHERE identity = ?", [&id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
            .context("no introduction of that identity")?;
        let by: Bytes = serde_json::from_value(serde_json::from_str::<Value>(&introduction.1)?["by"].clone())?;
        let contact = Contact { id: Bytes(id.clone()), name: name.unwrap_or(introduction.0), how: Known::Introduced, by: Some(by) };
        self.core.set_contact(contact.clone())?;
        self.db.execute("DELETE FROM introductions WHERE identity = ?", [&id])?;
        Ok(json!({ "identity": contact.id, "name": contact.name, "how": contact.how }))
    }

    fn warn(&mut self, gid: Option<&Bytes>, text: String) {
        self.outbox.print(json!({ "type": "warning", "group": gid.map(|g| b64(&g.0)), "text": text }));
    }
}

/// Runs a session until `shutdown`: prints `ready`, catches up, then handles what arrives and prints what concerns the
/// agent, one JSON object per line.
pub async fn run<C: Core, P: Peers, L: Log>(
    mut session: Session<C, P, L>,
    mut inbound: mpsc::UnboundedReceiver<Inbound>,
    mut print: impl FnMut(String),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let ready = json!({ "type": "ready", "session": session.config.handle, "member": session.me()?, "state": session.config.dir });
    print(ready.to_string());
    session.resume().await;
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        session.emit(&mut print).await;
        tokio::select! {
            Some(event) = inbound.recv() => session.handle(event).await,
            _ = tokio::time::sleep_until(session.next_due()) => session.tick().await,
            _ = &mut shutdown => break,
        }
    }
    let _ = std::fs::remove_file(session.config.dir.join("endpoint"));
    Ok(())
}
