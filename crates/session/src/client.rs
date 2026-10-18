//! The client core: what one member does on top of its lmk-node session. It answers requests, and turns the node's
//! events into `ClientEvent`s with members described. A shell gives it storage (the node's provider) and a network, and
//! prints what it tells.

mod describe;
mod request;

pub use describe::{Described, Describer, shown};
pub use request::Request;

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lmk_node::{Event, INVITE_VALID, Member, Node};
use lmk_proto::Bytes;
use lmk_proto::group::{Attachment, ChatMessage, PROTOCOL, Service, Settings, UPDATE};
use lmk_proto::links::Invite;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

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
    Joined { group: Bytes, member: Described, by: Described },
    Left { group: Bytes, member: Described, by: Described },
    /// This client was removed from a group; `not_kept`: its messages no cut kept, by id.
    Removed { group: Bytes, by: Option<Described>, not_kept: Vec<String> },
    /// The client let go of a group, removed or leaving: the shell drops what it keeps of it.
    Gone { group: Bytes },
    /// A chat message, in delivery order. `missing`: what it needed and this client gave up on; `late`: messages that
    /// needed those were delivered without them.
    Message {
        group: Bytes,
        id: String,
        from: Described,
        seq: u64,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        missing: Vec<Missing>,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        late: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        reply_to: Option<String>,
        payload: Value,
    },
    /// Held messages lost, as `member` tells: this client's own, or as another member's summary tells, each seq once.
    Lost { group: Bytes, member: Described, messages: Vec<LostMessages> },
    Warning { group: Option<Bytes>, text: String },
}

/// A chat message to send.
pub struct Chat {
    pub text: String,
    /// Fingerprints.
    pub to: Vec<String>,
    pub reply_to: Option<[u8; 32]>,
    pub urgent: bool,
    pub attachment: Option<Attachment>,
}

#[derive(Default)]
struct State {
    /// The invite secrets this session is joining by.
    joining: HashSet<Vec<u8>>,
}

struct Inner {
    node: Node,
    /// The membership service of the groups it creates.
    membership: Service,
    state: Mutex<State>,
    events: mpsc::UnboundedSender<ClientEvent>,
}

/// One member's client, on its node. Its methods may run at once.
pub struct Client {
    inner: Arc<Inner>,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Client { inner: self.inner.clone() }
    }
}

impl Client {
    pub fn new(node: Node, membership: Service) -> (Self, mpsc::UnboundedReceiver<ClientEvent>) {
        let (events, told) = mpsc::unbounded_channel();
        let inner = Inner { node, membership, state: Mutex::default(), events };
        (Client { inner: Arc::new(inner) }, told)
    }

    pub fn node(&self) -> &Node {
        &self.inner.node
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

    pub async fn request(&self, request: Request) -> Result<Value> {
        match request {
            Request::Invite { group, carry } => self.invite(group, carry).await,
            Request::Join { target } => self.join(target).await,
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
            Request::Status => self.status(),
        }
    }

    // Groups.

    async fn invite(&self, group: Option<String>, carry: u32) -> Result<Value> {
        let gid = match group {
            Some(group) => self.resolve(Some(group))?,
            None => {
                let settings = Settings { protocol: PROTOCOL, carry, update: UPDATE, membership: self.inner.membership.clone() };
                self.inner.node.create(settings)?
            }
        };
        let link = self.inner.node.invite(&gid.0, INVITE_VALID).await?.link();
        Ok(json!({ "group": b64(&gid.0), "link": link, "expires_in": INVITE_VALID / 1000 }))
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
        let gid = self.inner.node.join(&invite).await?.0;
        Ok(json!({ "group": b64(&gid.0), "members": self.described_members(&gid)? }))
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
            groups.push(json!({
                "group": b64(&gid.0), "members": node.members(&gid.0)?.len(), "carry": settings.carry,
                "membership": settings.membership, "epoch": node.epoch(&gid.0)?,
            }));
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
            let only_here: Vec<Value> =
                node.only_here(&gid.0)?.iter().map(|(id, payload)| json!({ "what": payload["type"], "id": hex::encode(&id.0) })).collect();
            only_here_count += only_here.len();
            groups.push(json!({ "group": b64(&gid.0), "online": online, "only_here": only_here }));
        }
        let mut status = json!({ "groups": groups });
        if only_here_count > 0 {
            status["warning"] = json!(format!("{only_here_count} sends are held by no other member yet; keep this session running until they are"));
        }
        Ok(status)
    }

    /// The group a request acts on: the one it names by id, or else the client's one group.
    pub fn resolve(&self, group: Option<String>) -> Result<Bytes> {
        let gids = self.inner.node.groups();
        match group {
            Some(group) => gids.into_iter().find(|gid| b64(&gid.0) == group).with_context(|| format!("unknown group {group}")),
            None => match &gids[..] {
                [gid] => Ok(gid.clone()),
                [] => bail!("this session is in no group; create one with `invite`, or join one with `join`"),
                _ => bail!("this session is in several groups; pass --group"),
            },
        }
    }

    // Messages.

    /// Sends a chat message, a reply to `reply_to` if given; returns its id and the answer to `send`.
    pub async fn send(&self, gid: &Bytes, chat: Chat) -> Result<(Bytes, Value)> {
        let node = &self.inner.node;
        let mut addressed: Vec<Member> = Vec::new();
        for to in &chat.to {
            let member = self.member(gid, to)?;
            if !addressed.contains(&member) {
                addressed.push(member);
            }
        }
        if let Some(id) = &chat.reply_to {
            ensure!(node.message(&gid.0, id)?.is_some(), "unknown message {}", hex::encode(id));
        }
        let payload = ChatMessage {
            content: chat.text,
            to: addressed.iter().map(|m| Bytes(Sha256::digest(&m.key.0)[..8].to_vec())).collect(),
            urgent: chat.urgent,
            attachment: chat.attachment,
            sent_at: Some(lmk_proto::clock::corrected()),
        };
        let id = node.send(&gid.0, &serde_json::to_value(payload)?, chat.reply_to.as_ref().map(|id| &id[..])).await?;
        let mut answer = json!({ "id": hex::encode(&id.0) });
        if !addressed.is_empty() {
            answer["to"] = json!(addressed.iter().map(|m| fp(&m.key.0)).collect::<Vec<_>>());
        }
        Ok((id, answer))
    }

    /// Marks held messages of a group shown, as this client showed or printed them.
    pub fn mark_shown(&self, gid: &Bytes, ids: &[Bytes]) -> Result<()> {
        self.inner.node.mark_shown(&gid.0, ids)
    }

    /// The member of a group with the fingerprint `fp`.
    fn member(&self, gid: &Bytes, fp: &str) -> Result<Member> {
        let members = self.inner.node.members(&gid.0)?;
        members.into_iter().find(|m| self::fp(&m.key.0) == fp).with_context(|| format!("no member of {} has the fingerprint {fp}", b64(&gid.0)))
    }

    // Events.

    /// Takes an event of this client's node.
    pub fn event(&self, event: Event) {
        let group = event.group().cloned();
        if let Err(error) = self.on(event) {
            self.warn(group.as_ref(), format!("{error:#}"));
        }
    }

    fn on(&self, event: Event) -> Result<()> {
        match event {
            Event::Joined { group, member, by } => {
                let describer = self.describer(&group)?;
                self.emit(ClientEvent::Joined { group, member: describer.describe(&member), by: describer.describe(&by) });
            }
            Event::Left { group, member, by } => {
                let describer = self.describer(&group)?;
                self.emit(ClientEvent::Left { group, member: describer.describe(&member), by: describer.describe(&by) });
            }
            Event::Removed { group, by, not_kept } => {
                let by = by.map(|by| self.describe(&group, &by)).transpose()?;
                let not_kept = not_kept.iter().map(|id| hex::encode(&id.0)).collect();
                self.drop_group(&group)?;
                self.emit(ClientEvent::Removed { group, by, not_kept });
            }
            Event::Message(message) if message.payload["type"] == "message" => {
                let describer = self.describer(&message.group)?;
                let from = describer.describe(&message.sender);
                let missing: Vec<Missing> = message.missing.iter().map(|seqs| Missing { from: describer.describe_key(&seqs.key), seqs: seqs.seqs.iter().collect() }).collect();
                let id = hex::encode(&message.id.0);
                let reply_to = message.reply_to.as_ref().map(|id| hex::encode(&id.0));
                let (seq, late) = (message.seq, message.late);
                self.emit(ClientEvent::Message { group: message.group, id, from, seq, missing, late, reply_to, payload: message.payload });
            }
            // The others are the node's: invites and leaves.
            Event::Message(_) => {}
            Event::Lost(lost) => {
                let describer = self.describer(&lost.group)?;
                let member = describer.describe(&lost.member);
                let messages = lost.messages.iter().map(|of| LostMessages { from: describer.describe(&of.from), seqs: of.seqs.clone(), ids: of.ids.iter().map(|id| hex::encode(&id.0)).collect() });
                self.emit(ClientEvent::Lost { group: lost.group, member, messages: messages.collect() });
            }
            Event::Warning { group, text } => self.warn(group.as_ref(), text),
        }
        Ok(())
    }

    // Members.

    /// What describes a group's members, gathered once for many.
    pub fn describer(&self, gid: &Bytes) -> Result<Describer> {
        Ok(Describer { me: self.inner.node.key(), members: self.inner.node.members(&gid.0).unwrap_or_default() })
    }

    /// A member as this client shows it: by its fingerprint.
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
}
