use crate::relay::Relay;
use crate::store::{Provider, SCHEMA};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, Payload as Aad}};
use clap::Subcommand;
use hkdf::Hkdf;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const MAX_PAST_EPOCHS: usize = 5;
const INVITE_TTL_S: u64 = 600;
const POLL_WAIT_S: u64 = 25;
const PAGE: usize = 500;
const CATCH_UP: usize = 20;

/// Requests an agent sends to its session process.
#[derive(Subcommand, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Create an invite link; creates a new group unless --group is given
    Invite {
        #[arg(long)]
        group: Option<String>,
    },
    /// Join a group through an invite link
    Join { link: String },
    /// Send a message ("-" reads the text from stdin)
    Send {
        #[arg(long)]
        group: Option<String>,
        /// Fingerprint of the member this message is addressed to
        #[arg(long)]
        to: Option<String>,
        /// Id of the message this answers
        #[arg(long)]
        reply_to: Option<String>,
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
}

pub enum Event {
    Request(Request, oneshot::Sender<Value>),
    Batch { gid: String, messages: Vec<(u64, Vec<u8>)>, synced: bool },
    JoinRequest { invite: Invite, data: String },
    Welcome { invite: Invite, data: String, reply: oneshot::Sender<Value> },
}

#[derive(Clone)]
pub struct Invite {
    relay: String,
    id: String,
    key: [u8; 32],
    owner: String,
    gid: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Payload {
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<String>,
    after: Vec<String>,
    epoch_auth: String,
    content: String,
}

struct Group {
    mls: MlsGroup,
    relay: String,
    cursor: u64,
    poller: JoinHandle<()>,
}

impl Drop for Group {
    fn drop(&mut self) {
        self.poller.abort();
    }
}

pub struct Session {
    db: Connection,
    provider: Provider,
    signer: SignatureKeyPair,
    me: CredentialWithKey,
    person: Value,
    fp: String,
    relay: Relay,
    default_relay: String,
    groups: HashMap<String, Group>,
    backlog: HashMap<String, Vec<Value>>,
    events: mpsc::UnboundedSender<Event>,
}

impl Session {
    pub fn open(dir: &Path, name: String, rename: bool, default_relay: String, events: mpsc::UnboundedSender<Event>) -> Result<Self> {
        let provider = Provider::open(&dir.join("mls.db"))?;
        let db = Connection::open(dir.join("session.db"))?;
        db.execute_batch(SCHEMA)?;
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
        let me = CredentialWithKey { credential: BasicCredential::new(name.clone().into_bytes()).into(), signature_key: signer.public().into() };
        let mut session = Self {
            db,
            provider,
            signer,
            me,
            person: json!({ "name": name, "fp": fp }),
            fp,
            relay: Relay::new()?,
            default_relay,
            groups: HashMap::new(),
            backlog: HashMap::new(),
            events,
        };
        let rows: Vec<(String, String, u64)> = session
            .db
            .prepare("SELECT gid, relay, cursor FROM groups")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        for (gid, relay, cursor) in rows {
            let mls = MlsGroup::load(session.provider.storage(), &GroupId::from_slice(gid.as_bytes()))?.context("missing MLS state")?;
            session.backlog.insert(gid.clone(), Vec::new());
            session.track(gid, relay, cursor, mls);
        }
        Ok(session)
    }

    pub fn person(&self) -> &Value {
        &self.person
    }

    pub async fn handle(&mut self, event: Event) {
        match event {
            Event::Request(Request::Join { link }, reply) => {
                if let Err(error) = self.join(link, reply).await {
                    self.warn(None, format!("join: {error:#}"));
                }
            }
            Event::Request(request, reply) => {
                let result = self.request(request).await;
                let _ = reply.send(result.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
            }
            Event::Batch { gid, messages, synced } => {
                for (seq, data) in messages {
                    if let Err(error) = self.receive(&gid, seq, &data).await {
                        self.warn(Some(&gid), format!("{error:#}"));
                    }
                }
                if synced && let Some(items) = self.backlog.remove(&gid) {
                    let omitted = items.len().saturating_sub(CATCH_UP);
                    if omitted > 0 {
                        self.print(json!({ "type": "omitted", "group": gid, "count": omitted }));
                    }
                    for item in items.into_iter().skip(omitted) {
                        self.print(item);
                    }
                }
            }
            Event::JoinRequest { invite, data } => {
                if let Err(error) = self.admit(&invite, &data).await {
                    self.warn(Some(&invite.gid), format!("invite {}: {error:#}", invite.id));
                }
            }
            Event::Welcome { invite, data, reply } => {
                let result = self.welcome(invite, &data);
                let _ = reply.send(result.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
            }
        }
    }

    async fn request(&mut self, request: Request) -> Result<Value> {
        match request {
            Request::Invite { group } => self.invite(group).await,
            Request::Join { .. } => unreachable!("handled with its reply channel"),
            Request::Send { group, to, reply_to, text } => self.send(group, to, reply_to, text).await,
            Request::Read { id, ancestors } => self.read(&id, ancestors),
            Request::Members { group } => {
                let gid = self.resolve(group)?;
                Ok(json!({ "group": gid, "members": self.members(&gid) }))
            }
            Request::Groups => Ok(Value::Array(
                self.groups
                    .iter()
                    .map(|(gid, g)| json!({ "group": gid, "members": g.mls.members().count(), "relay": g.relay }))
                    .collect(),
            )),
            Request::Remove { group, member } => self.remove(group, &member).await,
            Request::Leave { group } => self.leave(group).await,
        }
    }

    async fn invite(&mut self, group: Option<String>) -> Result<Value> {
        let gid = match group {
            Some(_) => self.resolve(group)?,
            None => self.create_group()?,
        };
        let relay = self.groups[&gid].relay.clone();
        let id = hex::encode(self.provider.rand().random_array::<16>()?);
        let secret: [u8; 32] = self.provider.rand().random_array()?;
        let owner = hex::encode(self.provider.rand().random_array::<32>()?);
        self.relay.create_invite(&relay, &id, INVITE_TTL_S, &owner).await?;
        let invite = Invite { relay: relay.clone(), id: id.clone(), key: invite_key(&secret, &id), owner, gid: gid.clone() };

        let (http, events) = (self.relay.clone(), self.events.clone());
        tokio::spawn(async move {
            loop {
                match http.invite_get(&invite.relay, &invite.id, "join", POLL_WAIT_S).await {
                    Ok(Some(data)) => return drop(events.send(Event::JoinRequest { invite, data })),
                    Ok(None) => {}
                    Err(_) => return,
                }
            }
        });
        Ok(json!({ "group": gid, "link": format!("{relay}/i/{id}#{}", hex::encode(secret)), "expires_in": INVITE_TTL_S }))
    }

    async fn admit(&mut self, invite: &Invite, data: &str) -> Result<()> {
        let bytes = open(&invite.key, b"join", data)?;
        let MlsMessageBodyIn::KeyPackage(key_package) = MlsMessageIn::tls_deserialize_exact_bytes(&bytes)?.extract() else {
            bail!("join request is not a key package");
        };
        let key_package = key_package.validate(self.provider.crypto(), ProtocolVersion::Mls10)?;

        let mut welcome = None;
        let seq = self
            .commit_retrying(&invite.gid, |mls, provider, signer| {
                let (commit, message, _) = mls.add_members(provider, signer, std::slice::from_ref(&key_package))?;
                welcome = Some(message);
                Ok(commit)
            })
            .await?;
        let welcome = welcome.context("no welcome")?.to_bytes()?;
        let envelope = json!({ "group": invite.gid, "seq": seq, "welcome": B64.encode(welcome) });
        let sealed = self.seal(&invite.key, b"welcome", &serde_json::to_vec(&envelope)?)?;
        self.relay.invite_post(&invite.relay, &invite.id, "welcome", &sealed, Some(&invite.owner)).await?;
        Ok(())
    }

    async fn join(&mut self, link: String, reply: oneshot::Sender<Value>) -> Result<()> {
        let prepared = async {
            let (relay, fragment) = link.split_once('#').context("link lacks the secret after '#'")?;
            let (relay, id) = relay.rsplit_once("/i/").context("not an invite link")?;
            let secret = hex::decode(fragment).context("bad invite secret")?;
            let key = invite_key(&secret, id);
            let bundle = KeyPackage::builder().build(CIPHERSUITE, &self.provider, &self.signer, self.me.clone())?;
            let bytes = MlsMessageOut::from(bundle.key_package().clone()).to_bytes()?;
            self.relay.invite_post(relay, id, "join", &self.seal(&key, b"join", &bytes)?, None).await?;
            anyhow::Ok(Invite { relay: relay.to_owned(), id: id.to_owned(), key, owner: String::new(), gid: String::new() })
        };
        let invite = match prepared.await {
            Ok(invite) => invite,
            Err(error) => {
                let _ = reply.send(json!({ "error": format!("{error:#}") }));
                return Ok(());
            }
        };
        let (http, events) = (self.relay.clone(), self.events.clone());
        tokio::spawn(async move {
            loop {
                match http.invite_get(&invite.relay, &invite.id, "welcome", POLL_WAIT_S).await {
                    Ok(Some(data)) => return drop(events.send(Event::Welcome { invite, data, reply })),
                    Ok(None) => {}
                    Err(error) => return drop(reply.send(json!({ "error": format!("waiting for welcome: {error:#}") }))),
                }
            }
        });
        Ok(())
    }

    fn welcome(&mut self, invite: Invite, data: &str) -> Result<Value> {
        let envelope: Value = serde_json::from_slice(&open(&invite.key, b"welcome", data)?)?;
        let gid = envelope["group"].as_str().context("welcome lacks group")?.to_owned();
        let seq = envelope["seq"].as_u64().context("welcome lacks seq")?;
        let bytes = B64.decode(envelope["welcome"].as_str().context("welcome lacks message")?)?;
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact_bytes(&bytes)?.extract() else {
            bail!("not a welcome message");
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build();
        let mls = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)?.into_group(&self.provider)?;
        if mls.group_id().as_slice() != gid.as_bytes() {
            bail!("welcome is for a different group");
        }
        self.add_group(&gid, &invite.relay, seq, mls)?;
        self.print(json!({ "type": "joined", "group": gid, "member": self.person }));
        Ok(json!({ "group": gid, "members": self.members(&gid) }))
    }

    async fn send(&mut self, group: Option<String>, to: Option<String>, reply_to: Option<String>, text: String) -> Result<Value> {
        let gid = self.resolve(group)?;
        if let Some(to) = &to
            && !self.members(&gid).iter().any(|m| m["fp"] == *to)
        {
            bail!("{to} is not a member of {gid}");
        }
        if let Some(reply_to) = &reply_to
            && self.db.execute("UPDATE messages SET seen = 1 WHERE id = ? AND gid = ?", params![reply_to, gid])? == 0
        {
            bail!("unknown message {reply_to}");
        }
        let group = &self.groups[&gid];
        let payload = Payload {
            to,
            reply_to,
            after: self.tips(&gid)?,
            epoch_auth: hex::encode(group.mls.epoch_authenticator().as_slice()),
            content: text,
        };
        let relay = group.relay.clone();
        let json = serde_json::to_string(&payload)?;
        let group = self.groups.get_mut(&gid).expect("resolved");
        let bytes = group.mls.create_message(&self.provider, &self.signer, json.as_bytes())?.to_bytes()?;
        let id = digest(&bytes);
        self.db.execute("INSERT INTO posted (id) VALUES (?)", [&id])?;
        self.db.execute(
            "INSERT INTO messages (id, gid, sender, payload, seen) VALUES (?, ?, ?, ?, 1)",
            params![id, gid, self.person.to_string(), json],
        )?;
        self.relay.post(&relay, &gid, &bytes).await?;
        Ok(json!({ "id": id }))
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
                self.db.execute("UPDATE messages SET seen = 1 WHERE id = ?", [&id])?;
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
        let target = self.groups[&gid]
            .mls
            .members()
            .find(|m| fingerprint(&m.signature_key) == member && m.index != self.groups[&gid].mls.own_leaf_index())
            .context("no such member")?;
        self.commit_retrying(&gid, |mls, provider, signer| Ok(mls.remove_members(provider, signer, &[target.index])?.0))
            .await?;
        Ok(json!({ "group": gid, "members": self.members(&gid) }))
    }

    async fn leave(&mut self, group: Option<String>) -> Result<Value> {
        let gid = self.resolve(group)?;
        if self.groups[&gid].mls.members().count() == 1 {
            self.drop_group(&gid)?;
            return Ok(json!({ "group": gid, "left": true }));
        }
        let group = self.groups.get_mut(&gid).expect("resolved");
        let bytes = group.mls.leave_group(&self.provider, &self.signer)?.to_bytes()?;
        let relay = group.relay.clone();
        self.db.execute("INSERT INTO posted (id) VALUES (?)", [digest(&bytes)])?;
        self.relay.post(&relay, &gid, &bytes).await?;
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
        let epoch = processed.epoch().as_u64();
        let sender = match processed.sender() {
            Sender::Member(leaf) => group.mls.member_at(*leaf).map(|m| person(&m.credential, &m.signature_key)),
            _ => None,
        }
        .context("message from a non-member")?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                let payload: Payload = serde_json::from_slice(&message.into_bytes())?;
                let auth: Option<String> = self
                    .db
                    .query_row("SELECT auth FROM epochs WHERE gid = ? AND epoch = ?", params![gid, epoch], |r| r.get(0))
                    .optional()?;
                if auth.as_deref() != Some(payload.epoch_auth.as_str()) {
                    self.warn(Some(gid), format!("message {id} was sent from a different view of epoch {epoch}; the relay may be splitting the group"));
                }
                self.db.execute(
                    "INSERT OR IGNORE INTO messages (id, gid, sender, payload) VALUES (?, ?, ?, ?)",
                    params![id, gid, sender.to_string(), serde_json::to_string(&payload)?],
                )?;
                let item = self.message_json(gid, id, sender, &payload);
                self.deliver(gid, item);
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                if !matches!(proposal.proposal(), Proposal::Remove(_)) {
                    bail!("unsupported proposal");
                }
                group.mls.store_pending_proposal(self.provider.storage(), *proposal)?;
                self.commit(gid, |mls, provider, signer| Ok(mls.commit_to_pending_proposals(provider, signer)?.0)).await?;
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let changes = membership_changes(&group.mls, &staged, &sender);
                let self_removed = staged.self_removed();
                group.mls.merge_staged_commit(&self.provider, *staged)?;
                if self_removed {
                    self.drop_group(gid)?;
                    self.print(json!({ "type": "removed", "group": gid, "by": sender }));
                    return Ok(());
                }
                self.record_epoch(gid)?;
                for change in changes {
                    self.deliver(gid, change);
                }
            }
            _ => bail!("unsupported message"),
        }
        Ok(())
    }

    /// Posts a commit built by `build`. Returns the relay sequence number, or `None` if another commit won the epoch.
    async fn commit(
        &mut self,
        gid: &str,
        build: impl FnOnce(&mut MlsGroup, &Provider, &SignatureKeyPair) -> Result<MlsMessageOut>,
    ) -> Result<Option<u64>> {
        let group = self.groups.get_mut(gid).context("unknown group")?;
        let bytes = build(&mut group.mls, &self.provider, &self.signer)?.to_bytes()?;
        let relay = group.relay.clone();
        let posted = self.relay.post(&relay, gid, &bytes).await;
        let group = self.groups.get_mut(gid).expect("still tracked");
        match posted {
            Ok(Some(seq)) => {
                self.db.execute("INSERT INTO posted (id) VALUES (?)", [digest(&bytes)])?;
                let staged = group.mls.pending_commit().context("no pending commit")?;
                let changes = membership_changes(&group.mls, staged, &self.person);
                group.mls.merge_pending_commit(&self.provider)?;
                self.record_epoch(gid)?;
                for change in changes {
                    self.deliver(gid, change);
                }
                Ok(Some(seq))
            }
            other => {
                group.mls.clear_pending_commit(self.provider.storage())?;
                other
            }
        }
    }

    async fn commit_retrying(
        &mut self,
        gid: &str,
        mut build: impl FnMut(&mut MlsGroup, &Provider, &SignatureKeyPair) -> Result<MlsMessageOut>,
    ) -> Result<u64> {
        for _ in 0..3 {
            if let Some(seq) = self.commit(gid, &mut build).await? {
                return Ok(seq);
            }
            let group = &self.groups[gid];
            let (relay, cursor) = (group.relay.clone(), group.cursor);
            for (seq, data) in self.relay.fetch(&relay, gid, cursor, 0).await? {
                if let Err(error) = self.receive(gid, seq, &data).await {
                    self.warn(Some(gid), format!("{error:#}"));
                }
            }
        }
        bail!("the group kept changing; try again")
    }

    fn create_group(&mut self) -> Result<String> {
        let gid = hex::encode(self.provider.rand().random_array::<16>()?);
        let mls = MlsGroup::builder()
            .with_group_id(GroupId::from_slice(gid.as_bytes()))
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build(&self.provider, &self.signer, self.me.clone())?;
        let relay = self.default_relay.clone();
        self.add_group(&gid, &relay, 0, mls)?;
        Ok(gid)
    }

    fn add_group(&mut self, gid: &str, relay: &str, cursor: u64, mls: MlsGroup) -> Result<()> {
        self.db.execute("INSERT INTO groups (gid, relay, cursor) VALUES (?, ?, ?)", params![gid, relay, cursor])?;
        self.track(gid.to_owned(), relay.to_owned(), cursor, mls);
        self.record_epoch(gid)
    }

    fn track(&mut self, gid: String, relay: String, cursor: u64, mls: MlsGroup) {
        let (http, events, poll_gid, poll_relay) = (self.relay.clone(), self.events.clone(), gid.clone(), relay.clone());
        let poller = tokio::spawn(async move {
            let (mut after, mut wait) = (cursor, 0);
            loop {
                match http.fetch(&poll_relay, &poll_gid, after, wait).await {
                    Ok(messages) => {
                        let synced = messages.len() < PAGE;
                        if let Some((seq, _)) = messages.last() {
                            after = *seq;
                        }
                        if (!messages.is_empty() || wait == 0)
                            && events.send(Event::Batch { gid: poll_gid.clone(), messages, synced }).is_err()
                        {
                            return;
                        }
                        wait = if synced { POLL_WAIT_S } else { 0 };
                    }
                    Err(_) => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
                }
            }
        });
        self.groups.insert(gid, Group { mls, relay, cursor, poller });
    }

    fn drop_group(&mut self, gid: &str) -> Result<()> {
        if let Some(mut group) = self.groups.remove(gid) {
            group.mls.delete(self.provider.storage())?;
        }
        self.backlog.remove(gid);
        for table in ["groups", "epochs", "messages"] {
            self.db.execute(&format!("DELETE FROM {table} WHERE gid = ?"), [gid])?;
        }
        Ok(())
    }

    fn record_epoch(&self, gid: &str) -> Result<()> {
        let mls = &self.groups[gid].mls;
        self.db.execute(
            "INSERT OR REPLACE INTO epochs (gid, epoch, auth) VALUES (?, ?, ?)",
            params![gid, mls.epoch().as_u64(), hex::encode(mls.epoch_authenticator().as_slice())],
        )?;
        Ok(())
    }

    fn resolve(&self, group: Option<String>) -> Result<String> {
        match group {
            Some(gid) if self.groups.contains_key(&gid) => Ok(gid),
            Some(gid) => bail!("unknown group {gid}"),
            None if self.groups.len() == 1 => Ok(self.groups.keys().next().expect("one").clone()),
            None if self.groups.is_empty() => bail!("this session is in no group; create one with `invite` or join one with `join`"),
            None => bail!("this session is in several groups; pass --group"),
        }
    }

    fn members(&self, gid: &str) -> Vec<Value> {
        let mls = &self.groups[gid].mls;
        mls.members()
            .map(|m| {
                let mut entry = person(&m.credential, &m.signature_key);
                entry["you"] = json!(m.index == mls.own_leaf_index());
                entry
            })
            .collect()
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
            "direct": payload.to.as_deref() == Some(self.fp.as_str()),
            "content": payload.content,
        });
        if let Some(to) = &payload.to {
            item["to"] = json!(to);
        }
        if let Some(reply_to) = &payload.reply_to {
            item["reply_to"] = json!(reply_to);
        }
        item
    }

    fn deliver(&mut self, gid: &str, item: Value) {
        match self.backlog.get_mut(gid) {
            Some(backlog) => backlog.push(item),
            None => self.print(item),
        }
    }

    fn print(&self, item: Value) {
        if item["type"] == "message"
            && let Some(id) = item["id"].as_str()
        {
            let _ = self.db.execute("UPDATE messages SET seen = 1 WHERE id = ?", [id]);
        }
        println!("{item}");
    }

    fn warn(&self, gid: Option<&str>, text: String) {
        println!("{}", json!({ "type": "warning", "group": gid, "text": text }));
    }

    fn seal(&self, key: &[u8; 32], label: &[u8], plaintext: &[u8]) -> Result<String> {
        let nonce: [u8; 12] = self.provider.rand().random_array()?;
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
        let sealed = cipher
            .encrypt(&nonce.into(), Aad { msg: plaintext, aad: label })
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        Ok(B64.encode([nonce.as_slice(), &sealed].concat()))
    }
}

fn open(key: &[u8; 32], label: &[u8], data: &str) -> Result<Vec<u8>> {
    let bytes = B64.decode(data)?;
    if bytes.len() < 12 {
        bail!("sealed data too short");
    }
    let (nonce, sealed) = bytes.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().expect("12 bytes");
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(&nonce.into(), Aad { msg: sealed, aad: label })
        .map_err(|_| anyhow::anyhow!("cannot decrypt: wrong invite secret or tampered data"))
}

fn invite_key(secret: &[u8], id: &str) -> [u8; 32] {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(format!("letmeknow invite v1 {id}").as_bytes(), &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

/// "joined"/"left" lines for a commit, computed before it is merged.
fn membership_changes(mls: &MlsGroup, staged: &StagedCommit, by: &Value) -> Vec<Value> {
    let gid = String::from_utf8_lossy(mls.group_id().as_slice());
    let added = staged.add_proposals().map(|p| {
        let leaf = p.add_proposal().key_package().leaf_node();
        json!({ "type": "joined", "group": gid, "member": person(leaf.credential(), leaf.signature_key().as_slice()), "by": by })
    });
    let removed = staged.remove_proposals().filter_map(|p| mls.member_at(p.remove_proposal().removed())).map(|m| {
        json!({ "type": "left", "group": gid, "member": person(&m.credential, &m.signature_key), "by": by })
    });
    added.chain(removed).collect()
}

fn person(credential: &Credential, signature_key: &[u8]) -> Value {
    let name = BasicCredential::try_from(credential.clone())
        .map(|c| String::from_utf8_lossy(c.identity()).into_owned())
        .unwrap_or_else(|_| "?".into());
    json!({ "name": name, "fp": fingerprint(signature_key) })
}

fn fingerprint(signature_key: &[u8]) -> String {
    hex::encode(&Sha256::digest(signature_key)[..8])
}

fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
