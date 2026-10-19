//! The session process: this session's node, the requests it answers, and what concerns the agent, printed.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use lmk_node::{Event, INVITE_VALID, Member, Message, Node, fp};
use lmk_proto::Bytes;
use lmk_proto::group::{Attachment, ChatMessage, PROTOCOL, Service, Settings, UPDATE};
use lmk_proto::links::Invite;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::cli::{Request, private_file};
use crate::policy::{Outbox, wakes};
use crate::{message_id, shown, short};

/// How long after starting what arrives counts as catching up.
const CATCH_UP_WINDOW: Duration = Duration::from_secs(3);
/// How often a session forgets the messages it took in more than H ago.
const FORGET: Duration = Duration::from_secs(3600);

pub struct Config {
    pub handle: String,
    pub dir: PathBuf,
    pub hold: Duration,
    /// The domain of the membership service for groups this session creates.
    pub membership: String,
}

/// A request on a command channel, and where its answer goes.
pub type Inbound = (Request, oneshot::Sender<Value>);

/// What work the session loop started gave: a request's answer, and where it goes; or, with no request, warnings to
/// print.
pub struct Answered(Result<Value>, Option<oneshot::Sender<Value>>);

pub struct Session {
    db: Connection,
    node: Node,
    /// The membership service of the groups it creates.
    membership: Service,
    /// The invite secrets it is joining by.
    joining: Rc<RefCell<HashSet<Vec<u8>>>>,
    /// The session's lock, held while this process runs it.
    _held: std::fs::File,
    /// When the session next forgets the messages it took in more than H ago.
    forget_at: Instant,
    /// The groups as last written to `groups.json`.
    groups: Vec<Bytes>,
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
    pub async fn open(config: Config, db: Connection, node: Node, held: std::fs::File, membership: Service) -> Result<Self> {
        let mut session = Self {
            db,
            groups: node.groups(),
            node,
            membership,
            joining: Rc::default(),
            _held: held,
            forget_at: Instant::now() + FORGET,
            config,
            outbox: Outbox::default(),
            catching_up: Some(Instant::now() + CATCH_UP_WINDOW),
            running: JoinSet::new(),
        };
        session.forget_old()?;
        session.write_groups();
        let groups = session.node.groups();
        for gid in &groups {
            session.outbox.catch_up(&b64(&gid.0));
        }
        for gid in groups {
            // What was delivered after the last message shown, as when the session stopped before printing it.
            let (node, me) = (&session.node, session.node.key());
            let mut unshown = Vec::new();
            for message in node.messages(&gid.0)?.into_iter().rev() {
                if node.shown(&gid.0, &message.id.0)? {
                    break;
                }
                if message.payload["type"] == "message" && message.sender.key != me {
                    unshown.push(message);
                }
            }
            for message in &unshown.into_iter().rev().collect::<Vec<_>>() {
                session.received(message)?;
            }
        }
        Ok(session)
    }

    /// Lets go of the groups this session is no longer in, removed or left, and writes its groups, by id, to
    /// `groups.json` in its directory, for `sessions`, when they changed.
    fn publish(&mut self) {
        let groups = self.node.groups();
        if groups == self.groups {
            return;
        }
        let gone: Vec<Bytes> = std::mem::replace(&mut self.groups, groups).into_iter().filter(|gid| !self.groups.contains(gid)).collect();
        for gid in gone {
            if let Err(error) = self.forget(&gid) {
                self.warn(format!("letting go of a group: {error:#}"));
            }
        }
        self.write_groups();
    }

    fn write_groups(&mut self) {
        let groups: Vec<String> = self.groups.iter().map(|gid| b64(&gid.0)).collect();
        let path = self.config.dir.join("groups.json");
        let new = path.with_extension("new");
        if let Err(error) = private_file(&new, serde_json::to_string(&groups).expect("JSON").as_bytes()).and_then(|()| Ok(std::fs::rename(&new, &path)?)) {
            self.warn(format!("writing this session's groups: {error:#}"));
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
        let node = self.node.clone();
        let answer = match request {
            Request::Read { id } => self.read(&id),
            Request::Members { group } => self.resolve(group).and_then(|gid| Ok(json!({ "group": b64(&gid.0), "members": described_members(&node, &gid)? }))),
            Request::Groups => self.list_groups(),
            Request::Status { group } => self.status(group),
            Request::Send { group, to, reply_to, urgent, attach, attach_name, text } => {
                match self.message(group, to, reply_to, urgent, attach.map(|data| (data, attach_name)), text) {
                    Ok((gid, payload, reply_to)) => {
                        _ = self.running.spawn_local(async move { Answered(send(&node, &gid, payload, reply_to).await, Some(reply)) });
                        return;
                    }
                    Err(error) => Err(error),
                }
            }
            Request::Invite { group, carry } => {
                let gid = match group {
                    Some(group) => self.resolve(Some(group)),
                    None => node.create(Settings { protocol: PROTOCOL, carry, update: UPDATE, membership: self.membership.clone() }),
                };
                let invite = async move {
                    let gid = gid?;
                    let link = node.invite(&gid.0, INVITE_VALID).await?.link();
                    Ok(json!({ "group": b64(&gid.0), "link": link, "expires_in": INVITE_VALID / 1000 }))
                };
                _ = self.running.spawn_local(async move { Answered(invite.await, Some(reply)) });
                return;
            }
            Request::Join { target } => {
                let joining = self.joining.clone();
                _ = self.running.spawn_local(async move { Answered(join(&node, &joining, &target).await, Some(reply)) });
                return;
            }
            Request::Remove { group, member } => {
                let found = self.resolve(group).and_then(|gid| Ok((member_by_fp(&node, &gid, &member)?, gid)));
                let remove = async move {
                    let (member, gid) = found?;
                    ensure!(member.key != node.key(), "to leave a group, use `leave`");
                    node.remove(&gid.0, &member.key.0).await?;
                    Ok(json!({ "group": b64(&gid.0), "members": described_members(&node, &gid)? }))
                };
                _ = self.running.spawn_local(async move { Answered(remove.await, Some(reply)) });
                return;
            }
            Request::Leave { group, end } => {
                let gid = self.resolve(group);
                let leave = async move {
                    let gid = gid?;
                    if end {
                        node.remove_others(&gid.0).await?;
                    }
                    let mut answer = match node.leave(&gid.0)? {
                        None => json!({ "group": b64(&gid.0), "left": true }),
                        Some(_) => json!({ "group": b64(&gid.0), "left": true, "pending": true, "status": "a member removes this session once a cut keeps its leave" }),
                    };
                    if end {
                        answer["ended"] = json!(true);
                    }
                    Ok(answer)
                };
                _ = self.running.spawn_local(async move { Answered(leave.await, Some(reply)) });
                return;
            }
        };
        self.answer(answer, reply);
    }

    fn list_groups(&self) -> Result<Value> {
        let mut groups = Vec::new();
        for gid in self.node.groups() {
            let settings = self.node.settings(&gid.0)?;
            groups.push(json!({
                "group": b64(&gid.0), "members": self.node.members(&gid.0)?.len(), "carry": settings.carry,
                "membership": settings.membership, "epoch": self.node.epoch(&gid.0)?,
            }));
        }
        Ok(Value::Array(groups))
    }

    /// The members online in each of its groups, or only `group`, and its chat messages no other member holds yet.
    fn status(&self, group: Option<String>) -> Result<Value> {
        let gids = match group {
            Some(group) => vec![self.resolve(Some(group))?],
            None => self.node.groups(),
        };
        let me = self.node.key();
        let mut groups = Vec::new();
        let mut only_here_count = 0;
        for gid in gids {
            let online: Vec<Value> = self.node.online(&gid.0)?.iter().map(|m| describe(&me, m)).collect();
            let only_here: Vec<Value> =
                self.node.only_here(&gid.0)?.iter().map(|(id, payload)| json!({ "what": payload["type"], "id": hex::encode(&id.0) })).collect();
            only_here_count += only_here.len();
            groups.push(json!({ "group": b64(&gid.0), "online": online, "only_here": only_here }));
        }
        let mut status = json!({ "groups": groups });
        if only_here_count > 0 {
            status["warning"] = json!(format!("{only_here_count} sends are held by no other member yet; keep this session running until they are"));
        }
        Ok(status)
    }

    /// The group a request acts on: the one it names by id, or else the session's one group.
    fn resolve(&self, group: Option<String>) -> Result<Bytes> {
        let gids = self.node.groups();
        match group {
            Some(group) => gids.into_iter().find(|gid| b64(&gid.0) == group).with_context(|| format!("unknown group {group}")),
            None => match &gids[..] {
                [gid] => Ok(gid.clone()),
                [] => bail!("this session is in no group; create one with `invite`, or join one with `join`"),
                _ => bail!("this session is in several groups; pass --group"),
            },
        }
    }

    fn answer(&mut self, answer: Result<Value>, reply: oneshot::Sender<Value>) {
        // Before the answer, so that `sessions` shows what the request changed.
        self.publish();
        let _ = reply.send(answer.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
        self.outbox.flush_held();
    }

    /// Runs work of the session's own, as requests run: what it warns of prints.
    pub fn start(&mut self, work: impl Future<Output = Result<Vec<String>>> + 'static) {
        self.running.spawn_local(async move { Answered(work.await.map(|warnings| json!(warnings)), None) });
    }

    /// Takes an event of the node.
    pub fn event(&mut self, event: Event) {
        let group = event.group().cloned();
        if let Err(error) = self.on(event) {
            self.outbox.print(json!({ "type": "warning", "group": group, "text": format!("{error:#}") }));
        }
    }

    fn on(&mut self, event: Event) -> Result<()> {
        let me = self.node.key();
        let item = match event {
            Event::Joined { group, member, by } => json!({ "type": "joined", "group": group, "member": describe(&me, &member), "by": describe(&me, &by) }),
            Event::Left { group, member, by } => json!({ "type": "left", "group": group, "member": describe(&me, &member), "by": describe(&me, &by) }),
            Event::Removed { group, by, not_kept } => {
                let not_kept: Vec<String> = not_kept.iter().map(|id| hex::encode(&id.0)).collect();
                json!({ "type": "removed", "group": group, "by": by.map(|by| describe(&me, &by)), "not_kept": not_kept })
            }
            Event::Message(message) if message.payload["type"] == "message" => {
                if !self.taken(&message.id.0)? {
                    self.received(&message)?;
                }
                return Ok(());
            }
            // The others are the node's: invites and leaves.
            Event::Message(_) => return Ok(()),
            Event::Lost(lost) => {
                let members = self.node.members(&lost.group.0).unwrap_or_default();
                let messages: Vec<Value> = lost.messages.iter().map(|of| json!({
                    "from": describe(&me, &of.from), "seqs": of.seqs, "ids": of.ids.iter().map(|id| hex::encode(&id.0)).collect::<Vec<_>>(),
                })).collect();
                let member = describe_key(&me, &members, &lost.member.key);
                let mut item = json!({ "type": "lost", "group": lost.group, "member": member, "messages": messages });
                if member["you"] != true {
                    let count: usize = lost.messages.iter().map(|lost| lost.seqs.len()).sum();
                    item["text"] = json!(format!("{} could not read {count} of your messages; send again, with --reply-to <id>, any that still matters", shown(&member)));
                }
                item
            }
            Event::Warning { group, text } => {
                self.outbox.print(json!({ "type": "warning", "group": group, "text": text }));
                return Ok(());
            }
        };
        let wake = wakes(&item, |id| self.mine(id));
        self.outbox.deliver(item, wake);
        Ok(())
    }

    /// Clears what the session kept of a group it is no longer in.
    fn forget(&mut self, gid: &Bytes) -> Result<()> {
        self.db.execute("DELETE FROM taken WHERE gid = ?", [&gid.0])?;
        let attachments = self.attachments_dir(gid);
        if attachments.exists() {
            std::fs::remove_dir_all(attachments)?;
        }
        self.node.scrub()
    }

    // Messages.

    /// A chat message to send, the group it goes to, and the message it answers.
    fn message(
        &mut self,
        group: Option<String>,
        to: Vec<String>,
        reply_to: Option<String>,
        urgent: bool,
        attach: Option<(String, String)>,
        text: String,
    ) -> Result<(Bytes, ChatMessage, Option<Bytes>)> {
        let gid = self.resolve(group)?;
        let reply_to = match reply_to {
            Some(id) => {
                let target = self.find(&id)?;
                ensure!(target.group == gid, "{id} is a message of another group");
                self.show(&target.group, &target.id.0)?;
                Some(target.id)
            }
            None => None,
        };
        let attachment = match attach {
            Some((data, name)) => Some(Attachment { name, data: Bytes(B64.decode(data)?) }),
            None => None,
        };
        let mut addressed: Vec<Member> = Vec::new();
        for to in &to {
            let member = member_by_fp(&self.node, &gid, to)?;
            if !addressed.contains(&member) {
                addressed.push(member);
            }
        }
        let to = addressed.iter().map(|m| Bytes(Sha256::digest(&m.key.0)[..8].to_vec())).collect();
        Ok((gid, ChatMessage { content: text, to, urgent, attachment, sent_at: None }, reply_to))
    }

    /// Takes in a chat message, in delivery order: printed, with its attachment saved into a file only this user can read.
    fn received(&mut self, message: &Message) -> Result<()> {
        let attachment: Option<Attachment> = message.payload.get("attachment").map(|a| serde_json::from_value(a.clone())).transpose()?;
        let item = self.message_item(message)?;
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
        let node = &self.node;
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
        let node = &self.node;
        message_id(id).is_ok_and(|id| node.groups().iter().any(|gid| node.message(&gid.0, &id).ok().flatten().is_some_and(|m| m.sender.key == node.key())))
    }

    /// A chat message as the agent reads it: in delivery order, with what it needed and this session gave up on
    /// (`missing`), and whether messages that needed those were delivered without them (`late`). Its text is left out
    /// once shown.
    fn message_item(&self, message: &Message) -> Result<Value> {
        let (gid, payload, me) = (&message.group, &message.payload, self.node.key());
        let members = self.node.members(&gid.0).unwrap_or_default();
        let missing: Vec<Value> = message.missing.iter().map(|seqs| json!({ "from": describe_key(&me, &members, &seqs.key), "seqs": seqs.seqs.iter().collect::<Vec<_>>() })).collect();
        let id = hex::encode(&message.id.0);
        let mut item = json!({ "type": "message", "group": gid, "id": id, "from": describe(&me, &message.sender), "seq": message.seq });
        if !missing.is_empty() {
            item["missing"] = json!(missing);
        }
        if message.late {
            item["late"] = json!(true);
        }
        if let Some(reply_to) = &message.reply_to {
            item["reply_to"] = json!(hex::encode(&reply_to.0));
        }
        let to: Vec<Bytes> = serde_json::from_value(payload.get("to").cloned().unwrap_or(json!([])))?;
        let to: Vec<String> = to.iter().map(|fp| hex::encode(&fp.0)).collect();
        let forgotten = self.node.shown(&gid.0, &message.id.0)?;
        item["content"] = if forgotten { Value::Null } else { payload.get("content").cloned().unwrap_or(Value::Null) };
        item["direct"] = json!(to.iter().any(|to| *to == fp(&me.0)));
        if !to.is_empty() {
            let described: Vec<Value> = members.iter().map(|m| describe(&me, m)).collect();
            item["to"] = to.iter().map(|fp| described.iter().find(|m| m["fp"] == fp.as_str()).cloned().unwrap_or_else(|| json!(fp))).collect();
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
                let file = format!("{}-{}", &id[..16], name.replace(|c: char| !c.is_ascii_alphanumeric() && !"._-".contains(c), "-"));
                item["attachment"]["path"] = json!(self.attachments_dir(gid).join(file));
            }
        }
        Ok(item)
    }

    /// Marks a delivered message shown, as printed or replied to. Its text is then deleted, unless it is this session's
    /// own, which it keeps to send again.
    fn show(&self, gid: &Bytes, id: &[u8]) -> Result<()> {
        let node = &self.node;
        // Gone when the session left the group meanwhile, with what was waiting to print.
        let Some(message) = node.message(&gid.0, id)? else { return Ok(()) };
        node.mark_shown(&gid.0, &[Bytes(id.to_vec())])?;
        if message.payload["type"] == "message" && message.sender.key != node.key() {
            let mut payload = message.payload;
            payload["content"] = json!("");
            node.redact(&gid.0, id, payload)?;
        }
        Ok(())
    }

    /// A chat message.
    fn read(&self, id: &str) -> Result<Value> {
        let message = self.find(id)?;
        let item = self.message_item(&message)?;
        self.show(&message.group, &message.id.0)?;
        Ok(self.compact(item))
    }

    /// The message of this session's groups whose id begins with `id`.
    fn find(&self, id: &str) -> Result<Message> {
        let node = &self.node;
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
        let _ = self.node.shutdown().await;
    }
}

/// Joins a group through an invite link, unless a join by the same link is under way: the node shares one KeyPackage
/// per invite.
async fn join(node: &Node, joining: &RefCell<HashSet<Vec<u8>>>, link: &str) -> Result<Value> {
    let invite = Invite::parse(link.trim())?;
    let key = invite.secret.to_vec();
    ensure!(joining.borrow_mut().insert(key.clone()), "this session is joining that already: wait for that join to end");
    let joined = node.join(&invite).await;
    joining.borrow_mut().remove(&key);
    let gid = joined?.0;
    Ok(json!({ "group": b64(&gid.0), "members": described_members(node, &gid)? }))
}

/// Sends a chat message, a reply to `reply_to` if given, stamped with the time it is sent.
async fn send(node: &Node, gid: &Bytes, mut payload: ChatMessage, reply_to: Option<Bytes>) -> Result<Value> {
    payload.sent_at = Some(lmk_proto::clock::corrected());
    let to: Vec<String> = payload.to.iter().map(|to| hex::encode(&to.0)).collect();
    let id = node.send(&gid.0, &serde_json::to_value(payload)?, reply_to.as_ref().map(|id| &id.0[..])).await?;
    let mut answer = json!({ "id": hex::encode(&id.0) });
    if !to.is_empty() {
        answer["to"] = json!(to);
    }
    Ok(answer)
}

/// The member of a group with the fingerprint `fp`.
fn member_by_fp(node: &Node, gid: &Bytes, fp: &str) -> Result<Member> {
    let members = node.members(&gid.0)?;
    members.into_iter().find(|m| lmk_node::fp(&m.key.0) == fp).with_context(|| format!("no member of {} has the fingerprint {fp}", b64(&gid.0)))
}

/// A member as the agent sees it: by its fingerprint, and whether it is this session; a peer that is no member, by its
/// iroh key.
fn describe(me: &Bytes, member: &Member) -> Value {
    if member.key.0.is_empty() {
        return json!({ "iroh": member.iroh });
    }
    describe_key(me, &[], &member.key)
}

/// The member with this key, or else its fingerprint: a former member's, or this session's before it is one.
fn describe_key(me: &Bytes, members: &[Member], key: &Bytes) -> Value {
    match members.iter().find(|m| &m.key == key) {
        Some(member) => describe(me, member),
        None if key == me => json!({ "fp": fp(&key.0), "you": true }),
        None => json!({ "fp": fp(&key.0) }),
    }
}

fn described_members(node: &Node, gid: &Bytes) -> Result<Vec<Value>> {
    let me = node.key();
    Ok(node.members(&gid.0)?.iter().map(|m| describe(&me, m)).collect())
}

/// Runs a session until `shutdown` or a line it prints that cannot be written: prints `ready`, then handles what arrives and prints what concerns the agent, one JSON object per line.
pub async fn run(
    mut session: Session,
    mut inbound: mpsc::UnboundedReceiver<Inbound>,
    mut events: mpsc::UnboundedReceiver<Event>,
    mut print: impl FnMut(String) -> std::io::Result<()>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let fp = fp(&session.node.key().0);
    // Termux may run a program through Android's linker, which /proc/self/exe then names; it names the program in
    // TERMUX_EXEC__PROC_SELF_EXE.
    let bin = std::env::var_os("TERMUX_EXEC__PROC_SELF_EXE").map_or_else(std::env::current_exe, |exe| Ok(exe.into()))?;
    let ready = json!({ "type": "ready", "session": session.config.handle, "fp": fp, "bin": bin, "membership": session.config.membership });
    let mut shutdown = std::pin::pin!(shutdown);
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
                    match done.expect("work in flight runs until shutdown") {
                        Answered(answer, Some(reply)) => session.answer(answer, reply),
                        Answered(warnings, None) => {
                            session.publish();
                            match warnings {
                                Ok(Value::Array(warnings)) => warnings.into_iter().for_each(|text| session.outbox.print(json!({ "type": "warning", "text": text }))),
                                Ok(_) => {}
                                Err(error) => session.warn(format!("{error:#}")),
                            }
                        }
                    }
                }
                Some(event) = events.recv() => session.event(event),
                _ = tokio::time::sleep_until(due) => session.tick().await,
                _ = &mut shutdown => break,
            }
        }
    }
    session.running.shutdown().await;
    session.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_shows_by_its_fingerprint() {
        let member = |key: u8| Member { key: Bytes(vec![key]), iroh: Bytes(vec![key]), revision: 1 };
        let me = Bytes(vec![1]);
        assert_eq!(describe(&me, &member(1)), json!({ "fp": fp(&[1]), "you": true }));
        assert_eq!(describe(&me, &member(2)), json!({ "fp": fp(&[2]) }));
        assert_eq!(shown(&describe(&me, &member(1))), "you");
        assert_eq!(shown(&describe(&me, &member(2))), fp(&[2]));
        assert_eq!(describe(&me, &Member { key: Bytes::default(), ..member(9) }), json!({ "iroh": "CQ" }));
        assert_eq!(describe_key(&me, &[], &Bytes(vec![3])), json!({ "fp": fp(&[3]) }), "a former member");
    }
}
