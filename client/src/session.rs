use crate::device::{Device, Membership};
use crate::files;
use crate::relay::{Notice, Relay, transient};
use crate::store::{Provider, SCHEMA};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::Subcommand;
use letmeknow::proto::{
    CIPHERSUITE, FileUpdate, INVITE_SLOTS, INVITE_TTL_S, Opened, PAKE_ID, Payload, Settings, create_config, digest, fingerprint, invite_key, invite_words, join_config,
    membership_changes, open, person, random_below, seal,
};
use letmeknow::entity::{self, JoinRequest, List, Member, Opening, place};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self as std_mpsc, RecvTimeoutError};
use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use reqwest_websocket::{Message, WebSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

const POLL_WAIT_S: u64 = 25;
const RETRY_S: u64 = 3;
const POLL_S: u64 = 15;
const PING_S: u64 = 30;
/// How often a request box is checked while its socket is down, and how soon a request that failed is tried again.
const REQUESTS_POLL_S: u64 = 60;
const REQUESTS_RETRY_S: u64 = 15;
const CATCH_UP: usize = 20;
const LIST_TTL: Duration = Duration::from_secs(60);

/// Requests an agent sends to its session process.
#[derive(Subcommand, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Create a one-time invite code and link: into a group (a new one unless --group is given), or with --entity, for another device to join an entity
    Invite {
        #[arg(long)]
        group: Option<String>,
        /// What this session speaks as in a new group: one of its device's entities, "device" or "self" [default: the device's first entity]
        #[arg(long = "as", value_name = "ENTITY")]
        #[serde(rename = "as")]
        as_: Option<String>,
        /// Invite another device (a machine or a browser) into this entity, instead of a session into a group
        #[arg(long, conflicts_with_all = ["group", "as_"])]
        entity: Option<String>,
    },
    /// Join a group through an invite code or link, or a shared folder (a path with a slash, or an existing directory); a device link adds this device to an entity
    Join {
        target: String,
        /// What this session speaks as in the group: one of its device's entities, "device" or "self" [default: the device's first entity]
        #[arg(long = "as", value_name = "ENTITY")]
        #[serde(rename = "as")]
        as_: Option<String>,
    },
    /// Send a message ("-" reads the text from stdin)
    Send {
        #[arg(long)]
        group: Option<String>,
        /// Fingerprint of a member this message is addressed to; repeat for several
        #[arg(long)]
        to: Vec<String>,
        /// Id of the message this answers
        #[arg(long)]
        reply_to: Option<String>,
        /// Deliver at once to every member, not only those addressed
        #[arg(long)]
        urgent: bool,
        /// File to attach ("-" reads stdin); recipients get the path of a private copy, not the content
        #[arg(long, value_name = "FILE")]
        attach: Option<String>,
        text: String,
    },
    /// Show a message and its causal history
    Read {
        id: String,
        #[arg(long, default_value_t = 0)]
        ancestors: usize,
    },
    /// List members of a group
    Members {
        #[arg(long)]
        group: Option<String>,
    },
    /// List this session's groups
    Groups,
    /// Remove a member (by fingerprint) from a group
    Remove {
        #[arg(long)]
        group: Option<String>,
        member: String,
    },
    /// Leave a group
    Leave {
        #[arg(long)]
        group: Option<String>,
    },
    /// Let sessions of an entity this device is in join the group without an invite (they run `join <group>`), or with --close, no longer
    Open {
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        close: bool,
        entity: String,
    },
    /// Name the group, for everyone in it
    Name {
        #[arg(long)]
        group: Option<String>,
        name: String,
    },
    /// The group's files: text documents every member can edit at once
    File {
        #[command(subcommand)]
        op: FileOp,
    },
    /// Entities this device is in: create one, list them, or take a member off one
    Entity {
        #[command(subcommand)]
        op: EntityOp,
    },
}

#[derive(Subcommand, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOp {
    /// The group's files
    Ls {
        #[arg(long)]
        group: Option<String>,
    },
    /// A file's text, and its version for `file edit --base`
    Show {
        #[arg(long)]
        group: Option<String>,
        file: String,
    },
    /// Make the file's text that of PATH ("-" reads stdin), read at version --base: lines you changed are changed where they are now, so what others changed since stays
    Edit {
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        base: String,
        file: String,
        #[arg(value_name = "PATH")]
        text: String,
    },
    /// Create a file holding the text of PATH ("-" reads stdin)
    Create {
        #[arg(long)]
        group: Option<String>,
        name: String,
        #[arg(value_name = "PATH")]
        text: String,
    },
}

#[derive(Subcommand, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityOp {
    /// Start an entity with this device as its first member
    Create { name: String },
    /// The entities this device is in, and who is on their lists
    List,
    /// Take a member, by id, off an entity's list
    Remove {
        #[arg(long)]
        entity: Option<String>,
        member: String,
    },
}

pub enum Event {
    Request(Request, oneshot::Sender<Value>),
    Batch { gid: String, messages: Vec<(u64, Vec<u8>)>, synced: bool },
    Files { gid: String, records: Vec<(String, Record)>, ignored: Vec<String> },
    JoinRequest { invite: Box<Invite>, spake: Spake2<Ed25519Group>, data: String },
    Welcome { relay: String, key: [u8; 32], data: String, reply: oneshot::Sender<Value> },
    /// The requests box of this open group has new entries, or may have.
    Requests(String),
}

pub struct Invite {
    relay: String,
    id: String,
    owner: String,
    into: Into,
}

/// What an invite admits: a session into a group, or a device into an entity.
enum Into {
    Group(String),
    Entity(Membership),
}

/// A folder group message: the file `<id>.json`, whose id is the SHA-256 of the file. It holds the payload plus the `from` that MLS supplies on the relay.
#[derive(Serialize, Deserialize)]
pub struct Record {
    from: Person,
    #[serde(flatten)]
    payload: Payload,
}

#[derive(Serialize, Deserialize)]
struct Person {
    name: String,
    fp: String,
}

struct Group {
    mls: MlsGroup,
    relay: String,
    cursor: u64,
    poller: JoinHandle<()>,
    /// The requests box this group is open on, and the task following it.
    requests: Option<(String, JoinHandle<()>)>,
}

impl Drop for Group {
    fn drop(&mut self) {
        self.poller.abort();
        if let Some((_, task)) = &self.requests {
            task.abort();
        }
    }
}

/// Keeps a folder's scanning thread alive; dropping it closes the wake channel, which stops the thread.
struct Folder {
    _watcher: Option<RecommendedWatcher>,
    _wake: std_mpsc::Sender<()>,
}

pub struct Session {
    db: Connection,
    provider: Provider,
    signer: SignatureKeyPair,
    name: String,
    person: Value,
    fp: String,
    relay: Relay,
    default_relay: String,
    groups: HashMap<String, Group>,
    folders: HashMap<String, Folder>,
    backlog: HashMap<String, Vec<Value>>,
    held: Vec<Value>,
    held_since: Option<Instant>,
    keep_log: bool,
    attachments: PathBuf,
    events: mpsc::UnboundedSender<Event>,
    /// The letmeknow home, which holds the device.
    home: PathBuf,
    /// Entity lists fetched lately, by entity id.
    lists: HashMap<String, (Instant, List)>,
    /// Welcomes for admitted join requests not yet written to their reply box, by its address.
    replies: HashMap<String, String>,
}

impl Session {
    pub fn open(
        home: &Path,
        dir: &Path,
        name: String,
        rename: bool,
        default_relay: String,
        keep_log: bool,
        events: mpsc::UnboundedSender<Event>,
    ) -> Result<Self> {
        let provider = Provider::open(&dir.join("mls.db"))?;
        let db = Connection::open(dir.join("session.db"))?;
        db.execute_batch(SCHEMA)?;
        if !keep_log {
            db.execute("UPDATE messages SET payload = json_remove(payload, '$.content') WHERE seen = 1", [])?;
        }
        let stored: Option<(String, Vec<u8>)> =
            db.query_row("SELECT name, public FROM identity", [], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let (name, signer) = match stored {
            Some((stored, public)) => {
                if rename && stored != name {
                    bail!("this session is already named {stored:?}; names are fixed when a session is created");
                }
                let signer = SignatureKeyPair::read(provider.storage(), &public, SignatureScheme::ED25519).context("missing signing key")?;
                (stored, signer)
            }
            None => {
                let signer = SignatureKeyPair::new(SignatureScheme::ED25519)?;
                signer.store(provider.storage())?;
                db.execute("INSERT INTO identity (name, public) VALUES (?, ?)", params![name, signer.public()])?;
                (name, signer)
            }
        };
        let fp = fingerprint(signer.public());
        let mut session = Self {
            db,
            provider,
            signer,
            person: json!({ "name": name, "fp": fp }),
            name,
            fp,
            relay: Relay::new()?,
            default_relay,
            groups: HashMap::new(),
            folders: HashMap::new(),
            backlog: HashMap::new(),
            held: Vec::new(),
            held_since: None,
            keep_log,
            attachments: dir.join("attachments"),
            events,
            home: home.to_owned(),
            lists: HashMap::new(),
            replies: HashMap::new(),
        };
        let rows: Vec<(String, String, u64)> = session
            .db
            .prepare("SELECT gid, relay, cursor FROM groups")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        for (gid, relay, cursor) in rows {
            let mls = MlsGroup::load(session.provider.storage(), &GroupId::from_slice(gid.as_bytes()))?.context("missing MLS state")?;
            session.backlog.insert(gid.clone(), Vec::new());
            session.track(gid.clone(), relay, cursor, mls);
            session.follow_requests(&gid)?;
        }
        let folders: Vec<String> = session.db.prepare("SELECT gid FROM folders")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
        for gid in folders {
            session.backlog.insert(gid.clone(), Vec::new());
            session.watch(gid);
        }
        Ok(session)
    }

    pub fn person(&self) -> &Value {
        &self.person
    }

    pub async fn handle(&mut self, event: Event) {
        match event {
            Event::Request(Request::Join { target, as_ }, reply) if !Path::new(&target).is_absolute() => {
                let joined = if target.len() == 32 && target.chars().all(|c| c.is_ascii_hexdigit()) {
                    self.join_open(target, as_, reply).await
                } else {
                    self.join(target, as_, reply).await
                };
                if let Err(error) = joined {
                    self.warn(None, format!("join: {error:#}"));
                }
                self.flush_held();
            }
            Event::Request(request, reply) => {
                let result = self.request(request).await;
                let _ = reply.send(result.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
                self.flush_held();
            }
            Event::Batch { gid, messages, synced } => {
                for (seq, data) in messages {
                    if let Err(error) = self.receive(&gid, seq, &data).await {
                        self.warn(Some(&gid), format!("{error:#}"));
                    }
                }
                if synced && self.backlog.contains_key(&gid) {
                    self.flush(&gid);
                    self.update_key(&gid).await;
                }
            }
            Event::Files { gid, records, ignored } => {
                if !self.folders.contains_key(&gid) {
                    return;
                }
                if !ignored.is_empty() {
                    self.warn(Some(&gid), format!("ignored files not named by the SHA-256 of their content: {}", ignored.join(", ")));
                }
                for (id, record) in records {
                    if let Err(error) = self.ingest(&gid, &id, json!(record.from), record.payload) {
                        self.warn(Some(&gid), format!("{error:#}"));
                    }
                }
                self.flush(&gid);
            }
            Event::JoinRequest { invite, spake, data } => {
                if let Err(error) = self.admit(&invite, spake, &data).await {
                    let gid = match &invite.into {
                        Into::Group(gid) => Some(gid.as_str()),
                        Into::Entity(_) => None,
                    };
                    self.warn(gid, format!("invite {}: {error:#}", invite.id));
                }
            }
            Event::Welcome { relay, key, data, reply } => {
                let result = self.welcome(&relay, &key, &data).await;
                let _ = reply.send(result.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
            }
            Event::Requests(gid) => {
                if let Err(error) = self.admit_open(&gid).await {
                    self.warn(Some(&gid), format!("join requests: {error:#}"));
                    let events = self.events.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(REQUESTS_RETRY_S)).await;
                        let _ = events.send(Event::Requests(gid));
                    });
                }
            }
        }
    }

    async fn request(&mut self, request: Request) -> Result<Value> {
        match request {
            Request::Invite { group, as_, entity } => self.invite(group, as_, entity).await,
            Request::Join { target, .. } => self.join_folder(target).await,
            Request::Send { group, to, reply_to, urgent, attach, text } => self.send(group, to, reply_to, urgent, attach, text).await,
            Request::Read { id, ancestors } => self.read(&id, ancestors),
            Request::Members { group } => {
                let gid = self.resolve(group)?;
                Ok(json!({ "group": gid, "members": self.described_members(&gid).await? }))
            }
            Request::Groups => {
                let mut groups = Vec::new();
                for (gid, g) in &self.groups {
                    let mut group = json!({ "group": gid, "members": g.mls.members().count(), "relay": g.relay, "epoch": g.mls.epoch().as_u64() });
                    let settings = self.settings(gid)?;
                    if !settings.name.is_empty() {
                        group["name"] = json!(settings.name);
                    }
                    if !settings.open.is_empty() {
                        group["open"] = json!(settings.open);
                    }
                    groups.push(group);
                }
                for gid in self.folders.keys() {
                    groups.push(json!({ "group": gid, "members": self.members(gid)?.len(), "folder": gid }));
                }
                for (opening, membership) in self.openings().await? {
                    if !self.groups.contains_key(&opening.group) {
                        groups.push(json!({ "group": opening.group, "name": opening.name, "open_to": membership.name, "joined": false }));
                    }
                }
                Ok(Value::Array(groups))
            }
            Request::Remove { group, member } => self.remove(group, &member).await,
            Request::Leave { group } => self.leave(group).await,
            Request::Open { group, close, entity } => self.open_to(group, entity, close).await,
            Request::Name { group, name } => {
                let gid = self.resolve(group)?;
                let settings = Settings { name, ..self.settings(&gid)? };
                self.set(&gid, settings).await
            }
            Request::File { op } => self.file(op).await,
            Request::Entity { op: EntityOp::Create { name } } => self.entity_create(name).await,
            Request::Entity { op: EntityOp::List } => self.entities().await,
            Request::Entity { op: EntityOp::Remove { entity, member } } => self.entity_remove(entity, member).await,
        }
    }

    async fn invite(&mut self, group: Option<String>, as_: Option<String>, entity: Option<String>) -> Result<Value> {
        // A device link announces itself in the pake message, so the joiner knows to send its device, not a key package.
        let (into, relay, kind) = match entity {
            Some(entity) => {
                let membership = Device::load(&self.home)?.entity(&entity)?.clone();
                let relay = membership.relay.clone();
                (Into::Entity(membership), relay, "entity ")
            }
            None => {
                let gid = match group {
                    Some(_) => self.resolve(group)?,
                    None => self.create_group(as_.as_deref())?,
                };
                let relay = self.groups.get(&gid).context("folder groups need no invite; share the folder path")?.relay.clone();
                (Into::Group(gid), relay, "")
            }
        };
        let words = invite_words(self.provider.rand())?;
        let (spake, pake) = Spake2::<Ed25519Group>::start_symmetric(&Password::new(&words), &Identity::new(PAKE_ID));
        let owner = hex::encode(self.provider.rand().random_array::<32>()?);
        let mut slot = None;
        for _ in 0..10 {
            let id = (random_below(self.provider.rand(), INVITE_SLOTS)? + 1).to_string();
            if self.relay.create_invite(&relay, &id, INVITE_TTL_S, &owner, &format!("{kind}{}", B64.encode(&pake))).await? {
                slot = Some(id);
                break;
            }
        }
        let id = slot.context("no free invite slot on the relay; try again")?;
        let target = match &into {
            Into::Group(gid) => json!({ "group": gid }),
            Into::Entity(membership) => json!({ "entity": membership.id, "name": membership.name }),
        };
        let invite = Box::new(Invite { relay: relay.clone(), id: id.clone(), owner, into });

        let (http, events) = (self.relay.clone(), self.events.clone());
        tokio::spawn(async move {
            if let Ok(data) = wait(|| http.invite_get(&invite.relay, &invite.id, "join", POLL_WAIT_S), "nobody used the invite").await {
                let _ = events.send(Event::JoinRequest { invite, spake, data });
            }
        });
        let mut answer = json!({ "code": format!("{id}-{words}"), "link": format!("{relay}/i/{id}#{words}"), "expires_in": INVITE_TTL_S });
        answer.as_object_mut().expect("object").extend(target.as_object().expect("object").clone());
        Ok(answer)
    }

    async fn admit(&mut self, invite: &Invite, spake: Spake2<Ed25519Group>, data: &str) -> Result<()> {
        let join: Value = serde_json::from_str(data)?;
        let pake = B64.decode(join["pake"].as_str().context("join request lacks pake")?)?;
        let key = invite_key(&spake.finish(&pake)?, &invite.id);
        let admitted = self.admitted(invite, &key, &join).await;
        // Sealed under our key: a joiner with a wrong code cannot open it either, and stops waiting.
        let envelope = admitted.as_ref().map(Value::clone).unwrap_or_else(|error| json!({ "error": format!("{error:#}") }));
        let sealed = seal(self.provider.rand(), &key, b"welcome", &serde_json::to_vec(&envelope)?)?;
        self.relay.invite_post(&invite.relay, &invite.id, "welcome", &sealed, Some(&invite.owner)).await?;
        admitted?;
        if let Into::Group(gid) = &invite.into {
            self.post_state(gid).await?;
        }
        Ok(())
    }

    /// Adds whoever redeemed an invite, as `join` describes it; returns the envelope that lets it join.
    async fn admitted(&mut self, invite: &Invite, key: &[u8; 32], join: &Value) -> Result<Value> {
        let field = match invite.into {
            Into::Group(_) => "key_package",
            Into::Entity(_) => "device",
        };
        let bytes = open(key, b"join", join[field].as_str().with_context(|| format!("join request lacks {field}"))?)?;
        match &invite.into {
            Into::Group(gid) => {
                let key_package = self.key_package(&bytes)?;
                self.add(gid, key_package).await
            }
            Into::Entity(membership) => {
                let member: Member = serde_json::from_slice(&bytes)?;
                let device = Device::load(&self.home)?;
                let by = device.id();
                self.append(&membership.relay, &membership.id, |list| list.add(device.signer(), &by, member.clone()), |list| {
                    list.get(&member.id).is_some()
                })
                .await?;
                Ok(json!({ "entity": membership }))
            }
        }
    }

    fn key_package(&self, bytes: &[u8]) -> Result<KeyPackage> {
        let MlsMessageBodyIn::KeyPackage(key_package) = MlsMessageIn::tls_deserialize_exact_bytes(bytes)?.extract() else {
            bail!("join request is not a key package");
        };
        Ok(key_package.validate(self.provider.crypto(), ProtocolVersion::Mls10)?)
    }

    /// Adds the session with `key_package` to a group; returns the welcome envelope that lets it join.
    async fn add(&mut self, gid: &str, key_package: KeyPackage) -> Result<Value> {
        let mut welcome = None;
        let (_, seq) = self
            .post_retrying(gid, |mls, provider, signer| {
                let (commit, message, _) = mls.add_members(provider, signer, std::slice::from_ref(&key_package))?;
                welcome = Some(message);
                Ok(commit)
            })
            .await?;
        let welcome = welcome.context("no welcome")?.to_bytes()?;
        Ok(json!({ "group": gid, "seq": seq, "welcome": B64.encode(welcome) }))
    }

    /// A folder has no membership record, so joining posts a message: senders are members, and this makes the new one visible and addressable before it speaks.
    async fn join_folder(&mut self, gid: String) -> Result<Value> {
        if !self.folders.contains_key(&gid) {
            std::fs::create_dir_all(&gid)?;
            self.db.execute("INSERT INTO folders (gid) VALUES (?)", [&gid])?;
            self.backlog.insert(gid.clone(), Vec::new());
            self.watch(gid.clone());
            self.print(json!({ "type": "joined", "group": gid, "member": self.person }));
            self.send(Some(gid.clone()), Vec::new(), None, false, None, "joined".into()).await?;
        }
        Ok(json!({ "group": gid, "members": self.members(&gid)? }))
    }

    async fn join(&mut self, code: String, as_: Option<String>, reply: oneshot::Sender<Value>) -> Result<()> {
        let prepared = async {
            let (target, words) = code
                .trim()
                .split_once('#')
                .or_else(|| code.trim().split_once('-'))
                .context("expected an invite code like 417-acid-zebra, its link, or a folder path like ./chat")?;
            let (relay, id) = target.rsplit_once("/i/").unwrap_or((self.default_relay.as_str(), target));
            let pake = self.relay.invite_get(relay, id, "pake", 0).await?.context("invite lacks the inviter's pake message")?;
            let (device_link, pake) = match pake.strip_prefix("entity ") {
                Some(pake) => (true, pake.to_owned()),
                None => (false, pake),
            };
            let (spake, message) = Spake2::<Ed25519Group>::start_symmetric(&Password::new(words.to_lowercase()), &Identity::new(PAKE_ID));
            let key = invite_key(&spake.finish(&B64.decode(pake)?)?, id);
            let (field, bytes) = if device_link {
                let device = Device::load(&self.home)?;
                let member = Member { id: device.id(), key: Some(hex::encode(device.key())), name: device.name.clone() };
                ("device", serde_json::to_vec(&member)?)
            } else {
                let bundle = KeyPackage::builder().build(CIPHERSUITE, &self.provider, &self.signer, self.credential(as_.as_deref())?)?;
                ("key_package", MlsMessageOut::from(bundle.key_package().clone()).to_bytes()?)
            };
            let mut join = json!({ "pake": B64.encode(message) });
            join[field] = json!(seal(self.provider.rand(), &key, b"join", &bytes)?);
            self.relay.invite_post(relay, id, "join", &join.to_string(), None).await?;
            anyhow::Ok((relay.to_owned(), id.to_owned(), key))
        };
        let (relay, id, key) = match prepared.await {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = reply.send(json!({ "error": format!("{error:#}") }));
                return Ok(());
            }
        };
        let (http, events) = (self.relay.clone(), self.events.clone());
        tokio::spawn(async move {
            match wait(|| http.invite_get(&relay, &id, "welcome", POLL_WAIT_S), "the inviter did not answer within 10 minutes").await {
                Ok(data) => drop(events.send(Event::Welcome { relay, key, data, reply })),
                Err(error) => drop(reply.send(json!({ "error": format!("waiting for welcome: {error:#}") }))),
            }
        });
        Ok(())
    }

    async fn welcome(&mut self, relay: &str, key: &[u8; 32], data: &str) -> Result<Value> {
        let envelope: Value = serde_json::from_slice(&open(key, b"welcome", data)?)?;
        if let Some(error) = envelope.get("error").and_then(Value::as_str) {
            bail!("the inviter could not admit this session: {error}");
        }
        if let Some(entity) = envelope.get("entity") {
            let membership: Membership = serde_json::from_value(entity.clone())?;
            let mut device = Device::load(&self.home)?;
            device.entities.retain(|e| e.id != membership.id);
            device.entities.push(membership.clone());
            device.save(&self.home)?;
            return Ok(json!({ "entity": membership.id, "name": membership.name }));
        }
        let gid = envelope["group"].as_str().context("welcome lacks group")?.to_owned();
        let seq = envelope["seq"].as_u64().context("welcome lacks seq")?;
        let bytes = B64.decode(envelope["welcome"].as_str().context("welcome lacks message")?)?;
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact_bytes(&bytes)?.extract() else {
            bail!("not a welcome message");
        };
        let mls = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)?.into_group(&self.provider)?;
        if mls.group_id().as_slice() != gid.as_bytes() {
            bail!("welcome is for a different group");
        }
        self.add_group(&gid, relay, seq, mls)?;
        self.print(json!({ "type": "joined", "group": gid, "member": self.person }));
        Ok(json!({ "group": gid, "members": self.described_members(&gid).await? }))
    }

    async fn send(
        &mut self,
        group: Option<String>,
        to: Vec<String>,
        reply_to: Option<String>,
        urgent: bool,
        attachment: Option<String>,
        text: String,
    ) -> Result<Value> {
        let gid = self.resolve(group)?;
        let members = self.members(&gid)?;
        if let Some(to) = to.iter().find(|to| !members.iter().any(|m| m["fp"] == to.as_str())) {
            bail!("{to} is not a member of {gid}");
        }
        if let Some(reply_to) = &reply_to
            && !self.mark_seen(&gid, reply_to)?
        {
            bail!("unknown message {reply_to}");
        }
        let mut payload = Payload { to, reply_to, urgent, attachment, after: self.tips(&gid)?, content: Some(text), ..Payload::default() };
        let id = self.post_payload(&gid, &payload).await?;
        payload.attachment = None;
        self.db.execute(
            "INSERT INTO messages (id, gid, sender, payload) VALUES (?, ?, ?, ?)",
            params![id, gid, self.person.to_string(), serde_json::to_string(&payload)?],
        )?;
        self.mark_seen(&gid, &id)?;
        Ok(json!({ "id": id }))
    }

    /// Posts a message to the relay or writes it to the folder; returns its id.
    async fn post_payload(&mut self, gid: &str, payload: &Payload) -> Result<String> {
        if self.groups.contains_key(gid) {
            let bytes = serde_json::to_vec(payload)?;
            return Ok(self.post_retrying(gid, |mls, provider, signer| Ok(mls.create_message(provider, signer, &bytes)?)).await?.0);
        }
        let bytes = serde_json::to_vec(&Record { from: serde_json::from_value(self.person.clone())?, payload: payload.clone() })?;
        let (dir, id) = (Path::new(gid), digest(&bytes));
        let temp = dir.join(format!(".{id}.tmp"));
        std::fs::write(&temp, bytes)?;
        std::fs::rename(&temp, dir.join(format!("{id}.json")))?;
        // Taken in already, so the folder scan does not apply it again.
        self.db.execute("INSERT INTO applied (id, gid) VALUES (?, ?)", params![id, gid])?;
        Ok(id)
    }

    fn settings(&self, gid: &str) -> Result<Settings> {
        let stored: Option<String> = self.db.query_row("SELECT settings FROM settings WHERE gid = ?", [gid], |r| r.get(0)).optional()?;
        Ok(stored.map(|s| serde_json::from_str(&s)).transpose()?.unwrap_or_default())
    }

    fn store_settings(&mut self, gid: &str, settings: &Settings) -> Result<()> {
        self.db.execute(
            "INSERT INTO settings (gid, settings) VALUES (?, ?) ON CONFLICT (gid) DO UPDATE SET settings = excluded.settings",
            params![gid, serde_json::to_string(settings)?],
        )?;
        self.follow_requests(gid)
    }

    /// Follows the requests box of a group open to an entity: its socket announces each join request, and while it has
    /// none the box is checked every REQUESTS_POLL_S seconds.
    fn follow_requests(&mut self, gid: &str) -> Result<()> {
        let settings = self.settings(gid)?;
        let Some(group) = self.groups.get_mut(gid) else { return Ok(()) };
        let address = match settings.open.is_empty() {
            true => None,
            false => Some(place("requests", &hex::decode(&settings.requests)?).0),
        };
        if group.requests.as_ref().map(|(followed, _)| followed) == address.as_ref() {
            return Ok(());
        }
        if let Some((_, task)) = group.requests.take() {
            task.abort();
        }
        let Some(address) = address else { return Ok(()) };
        let (http, events, relay, gid, path) = (self.relay.clone(), self.events.clone(), group.relay.clone(), gid.to_owned(), format!("b/{address}"));
        let task = tokio::spawn(async move {
            loop {
                let socket = http.subscribe(&relay, &path).await.ok();
                let _ = events.send(Event::Requests(gid.clone()));
                if let Some(mut ws) = socket {
                    while notified(&mut ws).await.is_some() {
                        let _ = events.send(Event::Requests(gid.clone()));
                    }
                }
                tokio::time::sleep(Duration::from_secs(REQUESTS_POLL_S)).await;
            }
        });
        group.requests = Some((address, task));
        Ok(())
    }

    /// Changes the group's settings for everyone in it.
    async fn set(&mut self, gid: &str, settings: Settings) -> Result<Value> {
        self.post_payload(gid, &Payload { settings: Some(settings.clone()), ..Payload::default() }).await?;
        self.store_settings(gid, &settings)?;
        Ok(json!({ "group": gid, "settings": settings }))
    }

    /// What a member who was just added needs from the others, who keep it: the settings, and a snapshot of every file.
    /// It cannot read anything sent before it joined.
    async fn post_state(&mut self, gid: &str) -> Result<()> {
        let settings = self.settings(gid)?;
        if settings != Settings::default() {
            self.post_payload(gid, &Payload { settings: Some(settings), ..Payload::default() }).await?;
        }
        for (id, name, state) in self.files(gid)? {
            self.post_file(gid, &id, &name, &state).await?;
        }
        Ok(())
    }

    fn files(&self, gid: &str) -> Result<Vec<(String, String, Vec<u8>)>> {
        Ok(self
            .db
            .prepare("SELECT id, name, state FROM files WHERE gid = ? ORDER BY rowid")?
            .query_map([gid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?)
    }

    /// A file by id, or by name if only one file has it.
    fn find_file(&self, gid: &str, file: &str) -> Result<(String, String, Vec<u8>)> {
        let mut found: Vec<_> = self.files(gid)?.into_iter().filter(|(id, name, _)| id == file || name == file).collect();
        match found.len() {
            1 => Ok(found.remove(0)),
            0 => bail!("no file {file} in {gid}"),
            n => bail!("{n} files are named {file}; use the id from `file ls`"),
        }
    }

    fn store_file(&self, gid: &str, id: &str, name: &str, state: &[u8]) -> Result<()> {
        self.db.execute(
            "INSERT INTO files (gid, id, name, state) VALUES (?, ?, ?, ?)
             ON CONFLICT (gid, id) DO UPDATE SET state = excluded.state, name = CASE WHEN excluded.name = '' THEN name ELSE excluded.name END",
            params![gid, id, name, state],
        )?;
        Ok(())
    }

    /// Records a version shown to the agent, which a later `file edit --base` may build on.
    fn keep_version(&self, gid: &str, id: &str, state: &[u8]) -> Result<String> {
        let version = files::version(state);
        self.db.execute("INSERT OR IGNORE INTO versions (gid, file, version, state) VALUES (?, ?, ?, ?)", params![gid, id, version, state])?;
        Ok(version)
    }

    async fn post_file(&mut self, gid: &str, id: &str, name: &str, update: &[u8]) -> Result<()> {
        let file = FileUpdate { id: id.to_owned(), name: name.to_owned(), update: B64.encode(update) };
        self.post_payload(gid, &Payload { file: Some(file), ..Payload::default() }).await?;
        Ok(())
    }

    async fn file(&mut self, op: FileOp) -> Result<Value> {
        match op {
            FileOp::Ls { group } => {
                let gid = self.resolve(group)?;
                self.catch_up_now(&gid).await?;
                let mut listed = Vec::new();
                for (id, name, state) in self.files(&gid)? {
                    listed.push(json!({ "file": id, "name": name, "version": files::version(&state), "lines": files::text(&state)?.lines().count() }));
                }
                Ok(Value::Array(listed))
            }
            FileOp::Show { group, file } => {
                let gid = self.resolve(group)?;
                self.catch_up_now(&gid).await?;
                let (id, name, state) = self.find_file(&gid, &file)?;
                let version = self.keep_version(&gid, &id, &state)?;
                Ok(json!({ "file": id, "name": name, "version": version, "text": files::text(&state)? }))
            }
            FileOp::Edit { group, base, file, text } => {
                let gid = self.resolve(group)?;
                self.catch_up_now(&gid).await?;
                let (id, name, state) = self.find_file(&gid, &file)?;
                let base_state: Vec<u8> = self
                    .db
                    .query_row("SELECT state FROM versions WHERE gid = ? AND file = ? AND version = ?", params![gid, id, base], |r| r.get(0))
                    .optional()?
                    .with_context(|| format!("unknown version {base} of {name}; run `file show` for the current one"))?;
                let (target, lost) = files::rebase(&files::text(&base_state)?, &text, &files::text(&state)?);
                let update = files::edit(&state, &target)?;
                let merged = files::apply(Some(&state), &update)?;
                self.post_file(&gid, &id, "", &update).await?;
                self.store_file(&gid, &id, &name, &merged)?;
                let version = self.keep_version(&gid, &id, &merged)?;
                Ok(json!({ "file": id, "version": version, "merged": base != files::version(&state), "lost": lost, "text": files::text(&merged)? }))
            }
            FileOp::Create { group, name, text } => {
                let gid = self.resolve(group)?;
                let id = hex::encode(self.provider.rand().random_array::<8>()?);
                let state = files::new(&text);
                self.post_file(&gid, &id, &name, &state).await?;
                self.store_file(&gid, &id, &name, &state)?;
                Ok(json!({ "file": id, "name": name, "version": self.keep_version(&gid, &id, &state)? }))
            }
        }
    }

    /// Takes in what the relay has for a group now, so a file is read, or a message built, from where the group stands.
    async fn catch_up_now(&mut self, gid: &str) -> Result<()> {
        let Some(group) = self.groups.get(gid) else { return Ok(()) };
        let (relay, cursor) = (group.relay.clone(), group.cursor);
        for (seq, data) in self.relay.fetch(&relay, gid, cursor).await? {
            if let Err(error) = self.receive(gid, seq, &data).await {
                self.warn(Some(gid), format!("{error:#}"));
            }
        }
        Ok(())
    }


    /// Opens the group to an entity: records it in the settings, and tells the entity's devices through its inbox.
    async fn open_to(&mut self, group: Option<String>, entity: String, close: bool) -> Result<Value> {
        let gid = self.resolve(group)?;
        let relay = self.groups.get(&gid).context("only relay groups can be opened; anyone who can write a folder is in it")?.relay.clone();
        let membership = Device::load(&self.home)?.entity(&entity)?.clone();
        let mut settings = self.settings(&gid)?;
        settings.open.retain(|o| o.id != membership.id);
        if !close {
            settings.open.push(Opened { id: membership.id.clone(), name: membership.name.clone() });
        }
        if settings.requests.is_empty() {
            settings.requests = hex::encode(self.provider.rand().random_array::<32>()?);
        }
        let opening = Opening { group: gid.clone(), relay, name: settings.name.clone(), requests: settings.requests.clone(), closed: close };
        let (address, key) = place("inbox", &hex::decode(&membership.secret)?);
        let sealed = seal(self.provider.rand(), &key, b"inbox", &serde_json::to_vec(&opening)?)?;
        self.relay.append(&membership.relay, &address, &sealed).await?;
        self.set(&gid, settings).await
    }

    /// Groups open to this device's entities, from their inboxes: the latest entry for each group, unless it closed it.
    async fn openings(&self) -> Result<Vec<(Opening, Membership)>> {
        let mut openings: Vec<(Opening, Membership)> = Vec::new();
        for membership in Device::load(&self.home)?.entities {
            let (address, key) = place("inbox", &hex::decode(&membership.secret)?);
            for entry in self.read_box(&membership.relay, &address).await? {
                let Ok(opening) = open(&key, b"inbox", &entry).and_then(|bytes| Ok(serde_json::from_slice::<Opening>(&bytes)?)) else {
                    continue;
                };
                openings.retain(|(o, m)| o.group != opening.group || m.id != membership.id);
                if !opening.closed {
                    openings.push((opening, membership.clone()));
                }
            }
        }
        Ok(openings)
    }

    /// Asks to join a group open to one of this device's entities; whichever member is online checks the request and
    /// adds this session.
    async fn join_open(&mut self, gid: String, as_: Option<String>, reply: oneshot::Sender<Value>) -> Result<()> {
        let prepared = async {
            let (opening, membership) =
                self.openings().await?.into_iter().find(|(o, _)| o.group == gid).context("that group is not open to any entity of this device")?;
            let as_ = as_.unwrap_or(membership.id);
            let bundle = KeyPackage::builder().build(CIPHERSUITE, &self.provider, &self.signer, self.credential(Some(&as_))?)?;
            let key_package = B64.encode(MlsMessageOut::from(bundle.key_package().clone()).to_bytes()?);
            let reply_secret: [u8; 32] = self.provider.rand().random_array()?;
            let request = JoinRequest { key_package, reply: hex::encode(reply_secret) };
            let (address, key) = place("requests", &hex::decode(&opening.requests)?);
            let sealed = seal(self.provider.rand(), &key, b"request", &serde_json::to_vec(&request)?)?;
            self.relay.append(&opening.relay, &address, &sealed).await?;
            anyhow::Ok((opening.relay, place("reply", &reply_secret)))
        };
        let (relay, (address, key)) = match prepared.await {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = reply.send(json!({ "error": format!("{error:#}") }));
                return Ok(());
            }
        };
        let (http, events) = (self.relay.clone(), self.events.clone());
        tokio::spawn(async move {
            let entry = wait(|| async { Ok(http.entries(&relay, &address, 0, POLL_WAIT_S).await?.into_iter().next().map(|(_, _, data)| data)) }, "no member admitted the request; one must be online").await;
            match entry {
                Ok(data) => drop(events.send(Event::Welcome { relay, key, data, reply })),
                Err(error) => drop(reply.send(json!({ "error": format!("waiting to be admitted: {error:#}") }))),
            }
        });
        Ok(())
    }

    /// Admits the join requests in an open group's requests box from sessions that speak as an entity the group is open
    /// to, unless another member admitted them first. The cursor moves past a request once it is handled, so one that
    /// failed is tried again.
    async fn admit_open(&mut self, gid: &str) -> Result<()> {
        let Some(group) = self.groups.get(gid) else { return Ok(()) };
        let relay = group.relay.clone();
        let (settings, cursor): (String, u64) = self.db.query_row("SELECT settings, cursor FROM settings WHERE gid = ?", [gid], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let settings: Settings = serde_json::from_str(&settings)?;
        if settings.open.is_empty() {
            return Ok(());
        }
        let (address, key) = place("requests", &hex::decode(&settings.requests)?);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64;
        for (seq, at, data) in self.relay.entries(&relay, &address, cursor, 0).await? {
            // Expired requests are skipped, so an old one posted again cannot bring back a session that left.
            if at + INVITE_TTL_S * 1000 >= now {
                self.admit_request(gid, &relay, &settings, &key, &data).await?;
            }
            self.db.execute("UPDATE settings SET cursor = ? WHERE gid = ?", params![seq, gid])?;
        }
        Ok(())
    }

    /// Admits one join request. A request that cannot be admitted is refused with a warning; an error means it may be
    /// admitted on a later try.
    async fn admit_request(&mut self, gid: &str, relay: &str, settings: &Settings, key: &[u8; 32], data: &str) -> Result<()> {
        let read = || -> Result<(KeyPackage, (String, [u8; 32]))> {
            let request: JoinRequest = serde_json::from_slice(&open(key, b"request", data)?)?;
            Ok((self.key_package(&B64.decode(&request.key_package)?)?, place("reply", &hex::decode(&request.reply)?)))
        };
        let (key_package, (reply_address, reply_key)) = match read() {
            Ok(read) => read,
            Err(error) => {
                self.warn(Some(gid), format!("ignored a join request that does not read: {error:#}"));
                return Ok(());
            }
        };
        if !self.replies.contains_key(&reply_address) {
            let leaf = key_package.leaf_node();
            let joiner = person(leaf.credential(), leaf.signature_key().as_slice());
            let present = |session: &Self| session.members(gid).map(|members| members.iter().any(|m| m["fp"] == joiner["fp"]));
            if present(self)? {
                return Ok(());
            }
            // Fetched first, so a list the relay failed to give fails this try instead of refusing the request.
            for id in joiner["as"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                let list = self.fetch_list(relay, id).await?;
                self.lists.insert(id.to_owned(), (Instant::now(), list));
            }
            let described = self.describe(gid, joiner.clone(), false).await?;
            let entity = described["entity"]["id"].as_str().filter(|_| described["entity"].get("error").is_none());
            if !entity.is_some_and(|id| settings.open.iter().any(|o| o.id == id)) {
                self.warn(Some(gid), format!("refused a join request from {described}: it speaks as no entity the group is open to"));
                return Ok(());
            }
            let envelope = match self.add(gid, key_package).await {
                Ok(envelope) => envelope,
                Err(_) if present(self)? => return Ok(()), // another member was first
                Err(error) => return Err(error),
            };
            self.replies.insert(reply_address.clone(), seal(self.provider.rand(), &reply_key, b"welcome", &serde_json::to_vec(&envelope)?)?);
        }
        self.relay.append(relay, &reply_address, &self.replies[&reply_address]).await?;
        self.replies.remove(&reply_address);
        if let Err(error) = self.post_state(gid).await {
            self.warn(Some(gid), format!("posting the group's state for its new member: {error:#}"));
        }
        Ok(())
    }

    fn read(&mut self, id: &str, ancestors: usize) -> Result<Value> {
        let mut found = Vec::new();
        let mut visited = HashSet::new();
        let mut level = vec![id.to_owned()];
        for depth in 0..=ancestors {
            let mut next = Vec::new();
            for id in level {
                if !visited.insert(id.clone()) {
                    continue;
                }
                let Some((gid, sender, payload)) = self.message(&id)? else {
                    if depth == 0 {
                        bail!("unknown message {id}");
                    }
                    continue;
                };
                self.mark_seen(&gid, &id)?;
                next.extend(payload.after.iter().cloned());
                found.push(self.message_json(&gid, &id, sender, &payload));
            }
            level = next;
        }
        found.reverse();
        Ok(Value::Array(found))
    }

    async fn remove(&mut self, group: Option<String>, member: &str) -> Result<Value> {
        let gid = self.resolve(group)?;
        let group = self.groups.get(&gid).context("folder groups have no removal; whoever can write the folder is a member")?;
        let target = group
            .mls
            .members()
            .find(|m| fingerprint(&m.signature_key) == member && m.index != group.mls.own_leaf_index())
            .context("no such member")?;
        self.post_retrying(&gid, |mls, provider, signer| Ok(mls.remove_members(provider, signer, &[target.index])?.0))
            .await?;
        Ok(json!({ "group": gid, "members": self.members(&gid)? }))
    }

    async fn leave(&mut self, group: Option<String>) -> Result<Value> {
        let gid = self.resolve(group)?;
        if self.groups.get(&gid).is_none_or(|g| g.mls.members().count() == 1) {
            self.drop_group(&gid)?;
            return Ok(json!({ "group": gid, "left": true }));
        }
        self.post_retrying(&gid, |mls, provider, signer| Ok(mls.leave_group(provider, signer)?)).await?;
        Ok(json!({ "group": gid, "left": false, "status": "waiting for another member to commit the removal" }))
    }

    async fn receive(&mut self, gid: &str, seq: u64, data: &[u8]) -> Result<()> {
        let Some(group) = self.groups.get_mut(gid) else { return Ok(()) };
        if seq <= group.cursor {
            return Ok(());
        }
        group.cursor = seq;
        self.db.execute("UPDATE groups SET cursor = ? WHERE gid = ?", params![seq, gid])?;
        let id = digest(data);
        let pending: Option<String> = self.db.query_row("SELECT id FROM pending WHERE gid = ?", [gid], |r| r.get(0)).optional()?;
        if pending.as_ref() == Some(&id) {
            // This session's commit, which the relay took though its answer never came.
            return self.merge_pending(gid).await;
        }
        let posted: Option<String> = self.db.query_row("SELECT id FROM posted WHERE id = ?", [&id], |r| r.get(0)).optional()?;
        if posted.is_some() {
            return Ok(());
        }
        self.process(gid, &id, data).await.with_context(|| format!("message {id}"))
    }

    async fn process(&mut self, gid: &str, id: &str, data: &[u8]) -> Result<()> {
        let message = MlsMessageIn::tls_deserialize_exact_bytes(data)?.try_into_protocol_message()?;
        let group = self.groups.get_mut(gid).expect("checked by receive");
        let processed = group.mls.process_message(&self.provider, message)?;
        let sender = match processed.sender() {
            Sender::Member(leaf) => group.mls.member_at(*leaf).map(|m| person(&m.credential, &m.signature_key)),
            _ => None,
        }
        .context("message from a non-member")?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                let payload: Payload = serde_json::from_slice(&message.into_bytes())?;
                // A file update is never shown, so it does not meet the sender's entity.
                let sender = self.describe(gid, sender, payload.file.is_none()).await?;
                self.ingest(gid, id, sender, payload)?;
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                if !matches!(proposal.proposal(), Proposal::Remove(_)) {
                    bail!("unsupported proposal");
                }
                group.mls.store_pending_proposal(self.provider.storage(), *proposal)?;
                self.post(gid, |mls, provider, signer| Ok(mls.commit_to_pending_proposals(provider, signer)?.0)).await?;
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let changes = membership_changes(&group.mls, &staged, &sender);
                let self_removed = staged.self_removed();
                // Merging drops any commit of this session's own for the same epoch: the relay took this one instead.
                group.mls.merge_staged_commit(&self.provider, *staged)?;
                self.db.execute("DELETE FROM pending WHERE gid = ?", [gid])?;
                if self_removed {
                    self.drop_group(gid)?;
                    let by = self.describe(gid, sender, true).await?;
                    self.print(json!({ "type": "removed", "group": gid, "by": by }));
                    return Ok(());
                }
                for change in changes {
                    self.deliver_change(gid, change).await?;
                }
            }
            _ => bail!("unsupported message"),
        }
        Ok(())
    }

    /// Posts the message `build` makes from the current epoch, and merges it if it is a commit. Returns its id and relay
    /// sequence number, or `None` if the relay has seen a commit this session has not: it only takes messages for its epoch.
    /// A commit whose answer never came stays pending, recorded in `pending`: the relay may have taken it, and catching up
    /// tells.
    async fn post(
        &mut self,
        gid: &str,
        build: impl FnOnce(&mut MlsGroup, &Provider, &SignatureKeyPair) -> Result<MlsMessageOut>,
    ) -> Result<Option<(String, u64)>> {
        let group = self.groups.get_mut(gid).context("unknown group")?;
        let bytes = build(&mut group.mls, &self.provider, &self.signer)?.to_bytes()?;
        let (id, relay) = (digest(&bytes), group.relay.clone());
        self.db.execute("INSERT INTO posted (id) VALUES (?)", [&id])?;
        if group.mls.pending_commit().is_some() {
            self.db.execute("INSERT OR REPLACE INTO pending (gid, id) VALUES (?, ?)", [gid, &id])?;
        }
        let Some(seq) = self.relay.post(&relay, gid, &bytes).await? else {
            self.groups.get_mut(gid).expect("still tracked").mls.clear_pending_commit(self.provider.storage())?;
            self.db.execute("DELETE FROM pending WHERE gid = ?", [gid])?;
            return Ok(None);
        };
        self.merge_pending(gid).await?;
        Ok(Some((id, seq)))
    }

    /// Merges this session's commit once the relay took it, and delivers the membership changes it makes.
    async fn merge_pending(&mut self, gid: &str) -> Result<()> {
        self.db.execute("DELETE FROM pending WHERE gid = ?", [gid])?;
        let mls = &mut self.groups.get_mut(gid).context("unknown group")?.mls;
        let Some(staged) = mls.pending_commit() else { return Ok(()) };
        let changes = membership_changes(mls, staged, &self.person);
        mls.merge_pending_commit(&self.provider)?;
        for change in changes {
            self.deliver_change(gid, change).await?;
        }
        Ok(())
    }

    /// Like `post`, but on `None` catches up and builds the message again.
    async fn post_retrying(
        &mut self,
        gid: &str,
        mut build: impl FnMut(&mut MlsGroup, &Provider, &SignatureKeyPair) -> Result<MlsMessageOut>,
    ) -> Result<(String, u64)> {
        if self.groups.get(gid).context("unknown group")?.mls.pending_commit().is_some() {
            // A commit whose answer never came: if the relay has it, catching up merges it; if not, it never arrived.
            self.catch_up_now(gid).await?;
            if self.groups[gid].mls.pending_commit().is_some() {
                self.groups.get_mut(gid).expect("checked").mls.clear_pending_commit(self.provider.storage())?;
                self.db.execute("DELETE FROM pending WHERE gid = ?", [gid])?;
            }
        }
        for _ in 0..3 {
            if let Some(posted) = self.post(gid, &mut build).await? {
                return Ok(posted);
            }
            self.catch_up_now(gid).await?;
        }
        bail!("the group kept changing; try again")
    }

    /// Replaces this member's keys with an empty commit, so whoever copied the old ones cannot follow the group past it.
    async fn update_key(&mut self, gid: &str) {
        // Not from the proposal store: after `leave` it holds this member's own removal, which only another member may commit.
        let updated = self
            .post_retrying(gid, |mls, provider, signer| {
                Ok(mls
                    .commit_builder()
                    .consume_proposal_store(false)
                    .force_self_update(true)
                    .load_psks(provider.storage())?
                    .build(provider.rand(), provider.crypto(), signer, |_| true)?
                    .stage_commit(provider)?
                    .into_commit())
            })
            .await;
        if let Err(error) = updated {
            self.warn(Some(gid), format!("key update: {error:#}"));
        }
    }

    /// Run periodically by `listen`; a resumed group also updates once caught up.
    pub async fn update_keys(&mut self) {
        for gid in self.groups.keys().cloned().collect::<Vec<_>>() {
            self.update_key(&gid).await;
        }
    }

    fn create_group(&mut self, as_: Option<&str>) -> Result<String> {
        let gid = hex::encode(self.provider.rand().random_array::<16>()?);
        let me = self.credential(as_)?;
        let mls = MlsGroup::new_with_group_id(&self.provider, &self.signer, &create_config(), GroupId::from_slice(gid.as_bytes()), me)?;
        let relay = self.default_relay.clone();
        self.add_group(&gid, &relay, 0, mls)?;
        Ok(gid)
    }

    fn add_group(&mut self, gid: &str, relay: &str, cursor: u64, mls: MlsGroup) -> Result<()> {
        self.db.execute("INSERT INTO groups (gid, relay, cursor) VALUES (?, ?, ?)", params![gid, relay, cursor])?;
        self.track(gid.to_owned(), relay.to_owned(), cursor, mls);
        Ok(())
    }

    fn track(&mut self, gid: String, relay: String, cursor: u64, mls: MlsGroup) {
        let (http, events, poll_gid, poll_relay) = (self.relay.clone(), self.events.clone(), gid.clone(), relay.clone());
        // Fetches on connecting, then takes messages from the socket's notices, fetching only after a gap or for a large
        // message; polls only while it has no socket.
        let poller = tokio::spawn(async move {
            let (mut after, mut synced) = (cursor, false);
            loop {
                let mut socket = http.subscribe(&poll_relay, &format!("g/{poll_gid}")).await.ok();
                'fetch: while catch_up(&http, &events, &poll_relay, &poll_gid, &mut after, &mut synced).await.is_ok() {
                    let Some(ws) = &mut socket else { break };
                    loop {
                        match notified(ws).await {
                            None => break 'fetch,
                            Some(Notice { seq, .. }) if seq <= after => {}
                            Some(Notice { seq, data: Some(data) }) if seq == after + 1 => {
                                let Ok(data) = B64.decode(data) else { continue 'fetch };
                                after = seq;
                                let _ = events.send(Event::Batch { gid: poll_gid.clone(), messages: vec![(seq, data)], synced: true });
                            }
                            Some(_) => continue 'fetch,
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(POLL_S)).await;
            }
        });
        self.groups.insert(gid, Group { mls, relay, cursor, poller, requests: None });
    }

    fn drop_group(&mut self, gid: &str) -> Result<()> {
        if let Some(mut group) = self.groups.remove(gid) {
            group.mls.delete(self.provider.storage())?;
        }
        self.folders.remove(gid);
        self.backlog.remove(gid);
        for table in ["groups", "folders", "messages", "settings", "applied", "files", "versions", "pending"] {
            self.db.execute(&format!("DELETE FROM {table} WHERE gid = ?"), [gid])?;
        }
        let attachments = self.attachments.join(&digest(gid.as_bytes())[..16]);
        if attachments.exists() {
            std::fs::remove_dir_all(attachments)?;
        }
        Ok(())
    }

    fn resolve(&self, group: Option<String>) -> Result<String> {
        let mut gids = self.groups.keys().chain(self.folders.keys());
        match group {
            Some(gid) if self.groups.contains_key(&gid) || self.folders.contains_key(&gid) => Ok(gid),
            Some(gid) => bail!("unknown group {gid}"),
            None => match (gids.next(), gids.next()) {
                (Some(gid), None) => Ok(gid.clone()),
                (None, _) => bail!("this session is in no group; create one with `invite`, or join one with `join`"),
                _ => bail!("this session is in several groups; pass --group"),
            },
        }
    }

    async fn described_members(&mut self, gid: &str) -> Result<Vec<Value>> {
        let mut members = Vec::new();
        for member in self.members(gid)? {
            members.push(self.describe(gid, member, true).await?);
        }
        Ok(members)
    }

    /// Delivers a "joined" or "left" line once the member's entity is checked.
    async fn deliver_change(&mut self, gid: &str, mut change: Value) -> Result<()> {
        change["member"] = self.describe(gid, change["member"].take(), true).await?;
        change["by"] = self.describe(gid, change["by"].take(), true).await?;
        self.deliver(gid, change);
        Ok(())
    }

    /// This session's credential for a group: its name, its device's note, and the entity it speaks as.
    fn credential(&self, as_: Option<&str>) -> Result<CredentialWithKey> {
        let device = Device::load(&self.home)?;
        let mut identity = entity::Identity { name: self.name.clone(), ..Default::default() };
        if as_ != Some("self") {
            identity.device = Some(entity::note(device.signer(), device.key(), self.signer.public())?);
            identity.path = match as_ {
                Some("device") => Vec::new(),
                Some(name) => vec![device.entity(name)?.id.clone()],
                None => device.entities.first().map(|e| e.id.clone()).into_iter().collect(),
            };
        }
        Ok(CredentialWithKey { credential: BasicCredential::new(identity.to_bytes()).into(), signature_key: self.signer.public().into() })
    }

    /// Checks the entities a member says it speaks as against their lists: the first must list its device (or the
    /// member itself), each later one the one before. An entity is `new` until this session meets it: until it shows the
    /// agent something from or about it (`meet`), which an admission check or a file update does not.
    async fn describe(&mut self, gid: &str, mut person: Value, meet: bool) -> Result<Value> {
        let Some(path) = person.as_object_mut().and_then(|p| p.remove("as")) else { return Ok(person) };
        let path: Vec<String> = serde_json::from_value(path)?;
        let relay = self.groups.get(gid).map_or_else(|| self.default_relay.clone(), |g| g.relay.clone());
        let mut holder = person.get("device").or(person.get("fp")).and_then(Value::as_str).unwrap_or_default().to_owned();
        let mut name = String::new();
        for id in path {
            let error = match self.list(&relay, &id, &holder).await {
                Ok(list) if list.get(&holder).is_some() => {
                    name = list.name;
                    holder = id;
                    continue;
                }
                Ok(list) => format!("not on {}'s list", list.name),
                Err(error) => format!("{error:#}"),
            };
            person["entity"] = json!({ "id": id, "error": error });
            return Ok(person);
        }
        let new = match meet {
            true => self.db.execute("INSERT OR IGNORE INTO seen (id, name, gid) VALUES (?, ?, ?)", params![holder, name, gid])? > 0,
            false => self.db.query_row("SELECT 1 FROM seen WHERE id = ?", [&holder], |_| Ok(())).optional()?.is_none(),
        };
        let yours = Device::load(&self.home)?.entities.iter().any(|e| e.id == holder);
        person["entity"] = json!({ "id": holder, "name": name, "new": new && !yours, "yours": yours });
        Ok(person)
    }

    /// An entity's list as the relay has it. A list fetched in the last minute answers for those on it; anyone else is
    /// checked with the relay, so a device added a moment ago counts at once.
    async fn list(&mut self, relay: &str, id: &str, member: &str) -> Result<List> {
        if let Some((at, list)) = self.lists.get(id)
            && at.elapsed() < LIST_TTL
            && list.get(member).is_some()
        {
            return Ok(list.clone());
        }
        let list = self.fetch_list(relay, id).await?;
        self.lists.insert(id.to_owned(), (Instant::now(), list.clone()));
        Ok(list)
    }

    async fn fetch_list(&self, relay: &str, id: &str) -> Result<List> {
        let (address, key) = place("list", id.as_bytes());
        let entries: Vec<Vec<u8>> = self.read_box(relay, &address).await?.iter().filter_map(|e| open(&key, b"list", e).ok()).collect();
        List::replay(id, &entries)
    }

    /// Every entry in a box on the relay, in the order it took them.
    async fn read_box(&self, relay: &str, address: &str) -> Result<Vec<String>> {
        let (mut entries, mut after) = (Vec::new(), 0);
        loop {
            let page = self.relay.entries(relay, address, after, 0).await?;
            let Some(last) = page.last() else { return Ok(entries) };
            after = last.0;
            entries.extend(page.into_iter().map(|(_, _, data)| data));
        }
    }

    /// Appends the entry `build` makes to an entity's list, then checks with `done` that it took effect. An entry posted
    /// by someone else in between makes ours invalid (it no longer follows the last one), so it is built again.
    async fn append(&mut self, relay: &str, id: &str, build: impl Fn(&List) -> Result<Vec<u8>>, done: impl Fn(&List) -> bool) -> Result<List> {
        let (address, key) = place("list", id.as_bytes());
        for _ in 0..3 {
            let entry = build(&self.fetch_list(relay, id).await?)?;
            self.relay.append(relay, &address, &seal(self.provider.rand(), &key, b"list", &entry)?).await?;
            let list = self.fetch_list(relay, id).await?;
            if done(&list) {
                self.lists.insert(id.to_owned(), (Instant::now(), list.clone()));
                return Ok(list);
            }
        }
        bail!("the entity's list kept changing; try again")
    }

    async fn entity_create(&mut self, name: String) -> Result<Value> {
        let mut device = Device::load(&self.home)?;
        let member = Member { id: device.id(), key: Some(hex::encode(device.key())), name: device.name.clone() };
        let (id, entry) = entity::create(device.signer(), member, &name, &self.provider.rand().random_array::<16>()?)?;
        let relay = self.default_relay.clone();
        let (address, key) = place("list", id.as_bytes());
        self.relay.append(&relay, &address, &seal(self.provider.rand(), &key, b"list", &entry)?).await?;
        let secret = hex::encode(self.provider.rand().random_array::<32>()?);
        device.entities.push(Membership { id: id.clone(), name: name.clone(), secret, relay });
        device.save(&self.home)?;
        Ok(json!({ "entity": id, "name": name }))
    }

    async fn entities(&mut self) -> Result<Value> {
        let device = Device::load(&self.home)?;
        let mut entities = Vec::new();
        for membership in &device.entities {
            let list = self.fetch_list(&membership.relay, &membership.id).await?;
            let members: Vec<Value> = list.members.iter().map(|m| json!({ "id": m.id, "name": m.name, "you": m.id == device.id() })).collect();
            entities.push(json!({ "entity": list.id, "name": list.name, "members": members }));
        }
        Ok(json!({ "device": { "id": device.id(), "name": device.name }, "entities": entities }))
    }

    async fn entity_remove(&mut self, entity: Option<String>, member: String) -> Result<Value> {
        let mut device = Device::load(&self.home)?;
        let membership = match (entity, device.entities.as_slice()) {
            (Some(entity), _) => device.entity(&entity)?.clone(),
            (None, [only]) => only.clone(),
            (None, _) => bail!("pass --entity: this device is in {} entities", device.entities.len()),
        };
        let by = device.id();
        let list = self
            .append(&membership.relay, &membership.id, |list| list.remove(device.signer(), &by, &member), |list| list.get(&member).is_none())
            .await?;
        if member == by {
            device.entities.retain(|e| e.id != membership.id);
            device.save(&self.home)?;
        }
        let members: Vec<Value> = list.members.iter().map(|m| json!({ "id": m.id, "name": m.name })).collect();
        Ok(json!({ "entity": list.id, "name": list.name, "members": members }))
    }

    /// Relay groups: the MLS members. Folder groups: this session and every sender seen in the folder.
    fn members(&self, gid: &str) -> Result<Vec<Value>> {
        let Some(group) = self.groups.get(gid) else {
            let senders: Vec<String> = self
                .db
                .prepare("SELECT sender FROM messages WHERE gid = ? GROUP BY sender ORDER BY MIN(rowid)")?
                .query_map([gid], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let mut members = vec![self.person.clone()];
            for sender in senders {
                let sender: Value = serde_json::from_str(&sender)?;
                if !members.iter().any(|m| m["fp"] == sender["fp"]) {
                    members.push(sender);
                }
            }
            for member in &mut members {
                member["you"] = json!(member["fp"] == self.fp.as_str());
            }
            return Ok(members);
        };
        let mls = &group.mls;
        Ok(mls
            .members()
            .map(|m| {
                let mut entry = person(&m.credential, &m.signature_key);
                entry["you"] = json!(m.index == mls.own_leaf_index());
                entry
            })
            .collect())
    }

    /// Scans the folder on each OS file notification, and every POLL_S seconds for filesystems that send none.
    fn watch(&mut self, gid: String) {
        let dir = PathBuf::from(&gid);
        let (wake, woken) = std_mpsc::channel();
        let notifier = wake.clone();
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            if !matches!(event, Ok(e) if e.kind.is_access()) {
                let _ = notifier.send(());
            }
        })
        .and_then(|mut watcher| watcher.watch(&dir, RecursiveMode::NonRecursive).map(|()| watcher))
        .ok();
        let (events, scan_gid) = (self.events.clone(), gid.clone());
        std::thread::spawn(move || {
            let mut seen = HashSet::new();
            loop {
                while woken.try_recv().is_ok() {}
                let (records, ignored) = scan(&dir, &mut seen);
                let _ = events.send(Event::Files { gid: scan_gid.clone(), records, ignored });
                if let Err(RecvTimeoutError::Disconnected) = woken.recv_timeout(Duration::from_secs(POLL_S)) {
                    return;
                }
            }
        });
        self.folders.insert(gid, Folder { _watcher: watcher, _wake: wake });
    }

    /// Logs a received message and delivers it, with its attachment written to a file only this user can read.
    fn ingest(&mut self, gid: &str, id: &str, sender: Value, mut payload: Payload) -> Result<()> {
        if (payload.settings.is_some() || payload.file.is_some())
            && self.db.execute("INSERT OR IGNORE INTO applied (id, gid) VALUES (?, ?)", params![id, gid])? == 0
        {
            return Ok(());
        }
        // A file update changes the file and nothing else: it never wakes the agent.
        if let Some(file) = payload.file.take() {
            let state: Option<Vec<u8>> =
                self.db.query_row("SELECT state FROM files WHERE gid = ? AND id = ?", params![gid, file.id], |r| r.get(0)).optional()?;
            let state = files::apply(state.as_deref(), &B64.decode(&file.update)?)?;
            return self.store_file(gid, &file.id, &file.name, &state);
        }
        if let Some(settings) = payload.settings.take() {
            if settings != self.settings(gid)? {
                self.store_settings(gid, &settings)?;
                self.deliver(gid, json!({ "type": "settings", "group": gid, "settings": settings, "by": sender }));
            }
            return Ok(());
        }
        let attachment = payload.attachment.take().map(|data| B64.decode(data)).transpose()?;
        let inserted = self.db.execute(
            "INSERT OR IGNORE INTO messages (id, gid, sender, payload) VALUES (?, ?, ?, ?)",
            params![id, gid, sender.to_string(), serde_json::to_string(&payload)?],
        )?;
        if inserted == 0 {
            return Ok(());
        }
        let mut item = self.message_json(gid, id, sender, &payload);
        if let Some(bytes) = attachment {
            let dir = self.attachments.join(&digest(gid.as_bytes())[..16]);
            std::fs::create_dir_all(&dir)?;
            crate::private_file(&dir.join(id), &bytes)?;
            item["attachment"] = json!(dir.join(id));
        }
        self.deliver(gid, item);
        Ok(())
    }

    /// Prints what arrived while catching up: the last CATCH_UP items, after an `omitted` count.
    fn flush(&mut self, gid: &str) {
        if let Some(items) = self.backlog.remove(gid) {
            let omitted = items.len().saturating_sub(CATCH_UP);
            if omitted > 0 {
                self.print(json!({ "type": "omitted", "group": gid, "count": omitted }));
            }
            for item in items.into_iter().skip(omitted) {
                self.print(item);
            }
        }
    }

    /// Read-frontier tips: seen messages that no other seen message lists in `after`.
    fn tips(&self, gid: &str) -> Result<Vec<String>> {
        let seen: Vec<(String, String)> = self
            .db
            .prepare("SELECT id, payload FROM messages WHERE gid = ? AND seen = 1")?
            .query_map([gid], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut covered = HashSet::new();
        for (_, payload) in &seen {
            covered.extend(serde_json::from_str::<Payload>(payload)?.after);
        }
        Ok(seen.into_iter().map(|(id, _)| id).filter(|id| !covered.contains(id)).collect())
    }

    fn message(&self, id: &str) -> Result<Option<(String, Value, Payload)>> {
        let row: Option<(String, String, String)> = self
            .db
            .query_row("SELECT gid, sender, payload FROM messages WHERE id = ?", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .optional()?;
        row.map(|(gid, sender, payload)| Ok((gid, serde_json::from_str(&sender)?, serde_json::from_str(&payload)?))).transpose()
    }

    fn message_json(&self, gid: &str, id: &str, from: Value, payload: &Payload) -> Value {
        let mut item = json!({
            "type": "message",
            "group": gid,
            "id": id,
            "from": from,
            "direct": payload.to.contains(&self.fp),
            "content": payload.content,
        });
        if !payload.to.is_empty() {
            item["to"] = json!(payload.to);
        }
        if let Some(reply_to) = &payload.reply_to {
            item["reply_to"] = json!(reply_to);
        }
        if payload.urgent {
            item["urgent"] = json!(true);
        }
        item
    }

    /// Printing wakes the agent, so only what concerns this session is printed at once, after anything held.
    /// Other messages are held until then, until the agent's next command, or until `listen --hold` runs out.
    fn deliver(&mut self, gid: &str, item: Value) {
        if let Some(backlog) = self.backlog.get_mut(gid) {
            backlog.push(item);
        } else if self.wakes(&item) {
            self.flush_held();
            self.print(item);
        } else {
            self.held_since.get_or_insert_with(Instant::now);
            self.held.push(item);
        }
    }

    /// Membership changes, and messages addressed to this session, answering one of its messages, or urgent.
    fn wakes(&self, item: &Value) -> bool {
        item["type"] != "message"
            || item["direct"] == true
            || item["urgent"] == true
            || item["reply_to"]
                .as_str()
                .is_some_and(|id| matches!(self.message(id), Ok(Some((_, from, _))) if from["fp"] == self.fp.as_str()))
    }

    pub fn held_since(&self) -> Option<Instant> {
        self.held_since
    }

    pub fn flush_held(&mut self) {
        self.held_since = None;
        for item in std::mem::take(&mut self.held) {
            self.print(item);
        }
    }

    fn print(&self, item: Value) {
        if item["type"] == "message"
            && let (Some(gid), Some(id)) = (item["group"].as_str(), item["id"].as_str())
        {
            let _ = self.mark_seen(gid, id);
        }
        println!("{item}");
    }

    /// Records that a message entered the agent's context. Its text is then deleted, unless `listen --keep-log`.
    fn mark_seen(&self, gid: &str, id: &str) -> Result<bool> {
        let forget = if self.keep_log { "" } else { ", payload = json_remove(payload, '$.content')" };
        Ok(self.db.execute(&format!("UPDATE messages SET seen = 1{forget} WHERE id = ? AND gid = ?"), [id, gid])? > 0)
    }

    fn warn(&self, gid: Option<&str>, text: String) {
        println!("{}", json!({ "type": "warning", "group": gid, "text": text }));
    }

}

/// Long-polls with `poll` until it yields something, for as long as an invite or join request lives. A poll that failed
/// on the way is tried again a few seconds later: a dropped connection says nothing about the invite.
async fn wait<T, F: std::future::Future<Output = Result<Option<T>>>>(mut poll: impl FnMut() -> F, expired: &str) -> Result<T> {
    let deadline = Instant::now() + Duration::from_secs(INVITE_TTL_S);
    while Instant::now() < deadline {
        match poll().await {
            Ok(Some(found)) => return Ok(found),
            Ok(None) => {}
            Err(error) if transient(&error) => tokio::time::sleep(Duration::from_secs(RETRY_S)).await,
            Err(error) => return Err(error),
        }
    }
    bail!("{expired}")
}

async fn catch_up(
    http: &Relay,
    events: &mpsc::UnboundedSender<Event>,
    relay: &str,
    gid: &str,
    after: &mut u64,
    synced: &mut bool,
) -> Result<()> {
    loop {
        let messages = http.fetch(relay, gid, *after).await?;
        let was_synced = std::mem::replace(synced, messages.is_empty());
        if let Some((seq, _)) = messages.last() {
            *after = *seq;
        }
        if !messages.is_empty() || !was_synced {
            let _ = events.send(Event::Batch { gid: gid.to_owned(), messages, synced: *synced });
        }
        if *synced {
            return Ok(());
        }
    }
}

/// Waits for the relay to announce something new; `None` once the socket is gone, or when a ping goes unanswered.
/// A notice that does not parse counts as one without data, so the caller fetches.
async fn notified(ws: &mut WebSocket) -> Option<Notice> {
    let mut unanswered = false;
    loop {
        match tokio::time::timeout(Duration::from_secs(PING_S), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) if text == "pong" => unanswered = false,
            Ok(Some(Ok(Message::Text(text)))) => return Some(serde_json::from_str(&text).unwrap_or(Notice { seq: u64::MAX, data: None })),
            Ok(Some(Ok(_))) => {}
            Ok(_) => return None,
            Err(_) if unanswered => return None,
            Err(_) => {
                unanswered = true;
                ws.send(Message::Text("ping".into())).await.ok()?;
            }
        }
    }
}

/// Messages in `dir` not yet in `seen`, in causal order, and the names of files not named by their content's hash.
/// Temp files are skipped; files that fail to parse are retried next scan.
fn scan(dir: &Path, seen: &mut HashSet<OsString>) -> (Vec<(String, Record)>, Vec<String>) {
    let (mut found, mut ignored) = (Vec::new(), Vec::new());
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let (name, path) = (entry.file_name(), entry.path());
        if path.extension() != Some(OsStr::new("json")) || seen.contains(&name) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let Ok(record) = serde_json::from_slice::<Record>(&bytes) else { continue };
        seen.insert(name.clone());
        let id = digest(&bytes);
        if path.file_stem() != Some(OsStr::new(&id)) {
            ignored.push(name.to_string_lossy().into_owned());
            continue;
        }
        found.push((entry.metadata().and_then(|m| m.modified()).ok(), id, record));
    }
    found.sort_by_key(|(modified, ..)| *modified);
    let mut records: Vec<(String, Record)> = found.into_iter().map(|(_, id, record)| (id, record)).collect();
    let mut pending: HashSet<String> = records.iter().map(|(id, _)| id.clone()).collect();
    let mut ordered = Vec::with_capacity(records.len());
    while !records.is_empty() {
        let next = records.iter().position(|(_, r)| r.payload.after.iter().all(|a| !pending.contains(a))).unwrap_or(0);
        let (id, record) = records.remove(next);
        pending.remove(&id);
        ordered.push((id, record));
    }
    (ordered, ignored)
}
