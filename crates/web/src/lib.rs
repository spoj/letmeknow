//! The browser client: one lmk-node session whose MLS key is the browser's device key, reaching its peers only through
//! the relay. The page persists the session's records in IndexedDB, one record per key, and the ciphertext of the files
//! it holds. Results that are not bytes are JSON strings; message ids and fingerprints are hex, other bytes base64url.
#![cfg(target_arch = "wasm32")]

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::hash::Hasher;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{Context, Result};
use js_sys::{Array, Function, Uint8Array};
use lmk_node::lmk_core::contacts::{self, Contact};
use lmk_node::lmk_core::device::Device;
use lmk_node::lmk_core::group::Window;
use lmk_node::lmk_core::invite::Target;
use lmk_node::lmk_core::provider::{MemoryProvider, Provider};
use lmk_node::{Claim, Event, Member, Node, doc, now};
use lmk_proto::Bytes;
use lmk_proto::group::{Attachment, How, IdentityRef, Kind, Named, PROTOCOL, Payload, Service, Settings};
use lmk_proto::links::{FileLink, Invite, MEMBERSHIP_KEY, RELAY};
use n0_future::time::{Duration, sleep};
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

type R<T> = Result<T, JsError>;

fn js(error: anyhow::Error) -> JsError {
    JsError::new(&format!("{error:#}"))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn error(text: &str);
}

/// The session's provider, shared with `App::flush`, which persists it.
#[derive(Clone, Default)]
struct Store(Arc<MemoryProvider>);

impl OpenMlsProvider for Store {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        self.0.storage()
    }

    fn crypto(&self) -> &RustCrypto {
        self.0.crypto()
    }

    fn rand(&self) -> &RustCrypto {
        self.0.rand()
    }
}

impl Provider for Store {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.0.get(key)
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.0.put(key, value)
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.0.delete(key)
    }
}

fn get<T: for<'de> Deserialize<'de>>(store: &Store, key: &[u8]) -> Result<Option<T>> {
    Ok(store.get(key)?.map(|bytes| serde_json::from_slice(&bytes)).transpose()?)
}

fn put<T: Serialize>(store: &Store, key: &[u8], value: &T) -> Result<()> {
    store.put(key, &serde_json::to_vec(value)?)
}

fn key(kind: &str, gid: &[u8]) -> Vec<u8> {
    [format!("web/{kind}/").as_bytes(), gid].concat()
}

fn fp(key: &[u8]) -> String {
    hex::encode(&Sha256::digest(key)[..8])
}

fn b64(bytes: &[u8]) -> String {
    serde_json::to_value(Bytes(bytes.to_vec())).unwrap().as_str().unwrap().to_owned()
}

fn unb64(text: &str) -> Result<Vec<u8>> {
    Ok(serde_json::from_value::<Bytes>(json!(text))?.0)
}

fn digest(value: &[u8]) -> u64 {
    let mut hasher = rustc_hash::FxHasher::default();
    hasher.write(value);
    hasher.write_usize(value.len());
    hasher.finish()
}

/// A membership service: `letmeknow.dev`, or `<iroh key, hex>@<relay URL>`.
fn service(address: &str) -> Result<Service> {
    let (key, relay) = match address {
        "letmeknow.dev" => (MEMBERSHIP_KEY, RELAY),
        _ => address.split_once('@').context("a membership service is letmeknow.dev or <key>@<relay URL>")?,
    };
    Ok(Service::Serve { key: Bytes(hex::decode(key)?), relay: relay.into(), addrs: Vec::new() })
}

#[derive(Deserialize)]
struct Config {
    /// The person's name and this device's: used only when the browser has no session yet.
    name: String,
    device: String,
    relay: Option<String>,
    membership: Option<String>,
}

/// An introduction of an identity that is neither this one nor a contact: someone's word, until accepted.
#[derive(Clone, Serialize, Deserialize)]
struct Introduction {
    name: String,
    /// The introducer, as this session showed it.
    by: String,
    by_id: Bytes,
}

/// What describing members needs, gathered once per call.
struct Known {
    me: Bytes,
    identities: Vec<(IdentityRef, String)>,
    contacts: Vec<(Bytes, Contact)>,
    introductions: HashMap<String, Introduction>,
    members: Vec<Member>,
}

struct App {
    node: Node<Store>,
    store: Store,
    membership: Service,
    /// A digest of each record as last persisted.
    shadow: RefCell<HashMap<Vec<u8>, u64>>,
    save: Function,
    save_file: Function,
    on_event: Function,
}

/// The browser's session.
#[wasm_bindgen]
pub struct Lmk {
    app: Rc<App>,
}

/// Opens the session from its records (`[key, value]` pairs) and the ciphertexts of its files, creating it if there
/// are none. `save(puts, deletes)` persists records, `save_file(hash, ciphertext)` a file, and `on_event(json)`
/// hears what happens.
#[wasm_bindgen]
pub async fn start(records: Array, files: Array, config: String, save: Function, save_file: Function, on_event: Function) -> R<Lmk> {
    std::panic::set_hook(Box::new(|info| error(&info.to_string())));
    let app = App::start(records, files, &config, save, save_file, on_event).await.map_err(js)?;
    Ok(Lmk { app })
}

/// What an invite link is: `group` or `device`.
#[wasm_bindgen]
pub fn invite_kind(link: &str) -> R<String> {
    Ok(if Invite::parse(link).map_err(js)?.device { "device" } else { "group" }.into())
}

impl App {
    async fn start(records: Array, files: Array, config: &str, save: Function, save_file: Function, on_event: Function) -> Result<Rc<Self>> {
        let config: Config = serde_json::from_str(config)?;
        let store = Store::default();
        let mut shadow = HashMap::new();
        {
            let mut values = store.0.storage.values.write().unwrap();
            for record in records.iter() {
                let record = Array::from(&record);
                let value = Uint8Array::from(record.get(1)).to_vec();
                let key = Uint8Array::from(record.get(0)).to_vec();
                shadow.insert(key.clone(), digest(&value));
                values.insert(key, value);
            }
        }
        if store.get(b"web/name")?.is_none() {
            put(&store, b"web/name", &config.name)?;
        }
        let device = get(&store, b"web/device")?.unwrap_or_else(|| Device::new(&config.device));
        let node_config = lmk_node::Config {
            name: get(&store, b"web/name")?.context("no name")?,
            device_key: true,
            relay: config.relay.as_deref().unwrap_or(RELAY).parse()?,
            ca: Default::default(),
            home: None,
            files: None,
            file_limit: 25 << 20,
            window: Window::default(),
        };
        let (node, mut events) = Node::start(store.clone(), device, node_config).await?;
        for file in files.iter() {
            node.hold(Uint8Array::from(file).to_vec()).await?;
        }
        let membership = service(config.membership.as_deref().unwrap_or("letmeknow.dev"))?;
        let app = Rc::new(App { node, store, membership, shadow: RefCell::new(shadow), save, save_file, on_event });
        app.flush();
        let events_app = app.clone();
        spawn_local(async move {
            while let Some(event) = events.recv().await {
                if let Err(e) = events_app.on(event).await {
                    events_app.emit(json!({ "type": "warning", "text": format!("{e:#}") }));
                }
                events_app.flush();
            }
        });
        let flushing = Rc::downgrade(&app);
        spawn_local(async move {
            while let Some(app) = flushing.upgrade() {
                app.flush();
                drop(app);
                sleep(Duration::from_secs(1)).await;
            }
        });
        Ok(app)
    }

    /// Hands the records that changed since the last flush to the page.
    fn flush(&self) {
        put(&self.store, b"web/device", &self.node.device()).unwrap();
        let values = self.store.0.storage.values.read().unwrap();
        let mut shadow = self.shadow.borrow_mut();
        let puts = Array::new();
        for (key, value) in values.iter() {
            let digest = digest(value);
            match shadow.get_mut(key) {
                Some(known) if *known == digest => continue,
                Some(known) => *known = digest,
                None => drop(shadow.insert(key.clone(), digest)),
            }
            puts.push(&Array::of2(&Uint8Array::from(&key[..]), &Uint8Array::from(&value[..])));
        }
        let deletes = Array::new();
        shadow.retain(|key, _| {
            let kept = values.contains_key(key);
            if !kept {
                deletes.push(&Uint8Array::from(&key[..]));
            }
            kept
        });
        if puts.length() > 0 || deletes.length() > 0 {
            self.save.call2(&JsValue::NULL, &puts, &deletes).ok();
        }
    }

    fn emit(&self, event: Value) {
        self.on_event.call1(&JsValue::NULL, &JsValue::from_str(&event.to_string())).ok();
    }

    async fn keep_file(&self, hash: [u8; 32]) -> Result<()> {
        let ciphertext = self.node.ciphertext(hash).await?;
        self.save_file.call2(&JsValue::NULL, &JsValue::from_str(&hex::encode(hash)), &Uint8Array::from(&ciphertext[..])).ok();
        Ok(())
    }

    async fn on(self: &Rc<Self>, event: Event) -> Result<()> {
        match event {
            Event::Joined { group, member, by, how, label } => {
                let known = self.known(&group.0)?;
                let item = json!({ "type": "joined", "at": now(), "member": self.describe(&known, &member), "by": self.describe(&known, &by), "how": how });
                self.remember(&group.0, &item)?;
                self.emit(json!({ "type": "joined", "group": group }));
                if by.key == self.node.key() {
                    self.admitted(&group.0, &member, how, label).await?;
                }
                self.refresh_opening(&group.0).await?;
            }
            Event::Left { group, member, by } => {
                let known = self.known(&group.0)?;
                let item = json!({ "type": "left", "at": now(), "member": self.describe(&known, &member), "by": self.describe(&known, &by) });
                self.remember(&group.0, &item)?;
                self.emit(json!({ "type": "left", "group": group }));
                self.refresh_opening(&group.0).await?;
            }
            Event::Removed { group, by } => {
                let by = by.map(|by| by.name);
                for kind in ["timeline", "settings", "refused"] {
                    self.store.delete(&key(kind, &group.0))?;
                }
                self.emit(json!({ "type": "removed", "group": group, "by": by }));
            }
            Event::Settings { group, settings, by } => {
                let known = self.known(&group.0)?;
                let before: Option<Settings> = get(&self.store, &key("settings", &group.0))?;
                put(&self.store, &key("settings", &group.0), &settings)?;
                let item = json!({ "type": "settings", "at": now(), "by": self.describe(&known, &by), "before": before, "settings": settings });
                self.remember(&group.0, &item)?;
                self.emit(json!({ "type": "settings", "group": group }));
                self.refresh_opening(&group.0).await?;
            }
            Event::Message(message) => {
                self.emit(json!({ "type": "message", "group": message.group, "id": hex::encode(&message.id.0) }));
            }
            Event::Edited { group, by } => self.emit(json!({ "type": "edited", "group": group, "by": by.name })),
            Event::Introduced { group, by, identity, name, how } => {
                let known = self.known(&group.0)?;
                let described = self.describe(&known, &by);
                let own = known.identities.iter().any(|(own, _)| own.id == identity.id);
                if !own && !known.contacts.iter().any(|(id, _)| *id == identity.id) {
                    let mut introductions = known.introductions;
                    let by_id = by.identity.as_ref().map_or_else(|| by.key.clone(), |claim| claim.identity.id.clone());
                    let introduction = Introduction { name: name.clone(), by: label(&described), by_id };
                    introductions.insert(b64(&identity.id.0), introduction);
                    put(&self.store, b"web/introductions", &introductions)?;
                }
                let item = json!({ "type": "introduced", "at": now(), "by": described, "identity": { "id": identity.id, "name": name }, "how": how });
                self.remember(&group.0, &item)?;
                self.emit(json!({ "type": "introduced", "group": group }));
            }
            Event::Held { group, id, .. } => self.emit(json!({ "type": "held", "group": group, "id": hex::encode(&id.0) })),
            Event::Refused { group, id, by, reason } => {
                self.refused(&group.0, &id.0, &by, &reason)?;
                self.emit(json!({ "type": "refused", "group": group, "id": hex::encode(&id.0) }));
            }
            Event::File(hash) => {
                self.keep_file(hash).await?;
                self.emit(json!({ "type": "file", "hash": hex::encode(hash) }));
            }
            Event::Warning { group, text } => self.emit(json!({ "type": "warning", "group": group, "text": text })),
        }
        Ok(())
    }

    /// Adds an item to a group's timeline, beside its messages.
    fn remember(&self, gid: &[u8], item: &Value) -> Result<()> {
        let mut timeline: Vec<Value> = get(&self.store, &key("timeline", gid))?.unwrap_or_default();
        timeline.push(item.clone());
        put(&self.store, &key("timeline", gid), &timeline)
    }

    fn refused(&self, gid: &[u8], id: &[u8], by: &Member, reason: &str) -> Result<()> {
        let mut refused: HashMap<String, Vec<Value>> = get(&self.store, &key("refused", gid))?.unwrap_or_default();
        refused.entry(hex::encode(id)).or_default().push(json!({ "name": by.name, "reason": reason }));
        put(&self.store, &key("refused", gid), &refused)
    }

    /// This session admitted a member: it tells the group who the member is to it, and the member of an invite meant
    /// for someone becomes that contact.
    async fn admitted(&self, gid: &[u8], member: &Member, how: How, label: Option<String>) -> Result<()> {
        let Some(claim) = member.identity.clone().filter(|claim| claim.error.is_none()) else { return Ok(()) };
        if let Some(label) = &label {
            let contact = Contact { name: label.clone(), how: contacts::How::Verified, by: None, at: now() };
            self.node.set_contact(&claim.identity.id.0, &contact).await?;
        }
        let contact = self.node.contacts()?.into_iter().find(|(id, _)| *id == claim.identity.id);
        let name = label.or(contact.map(|(_, c)| c.name)).unwrap_or(claim.name);
        self.node.send(gid, &Payload::Introduce { identity: claim.identity, name, how, to: Vec::new() }).await?;
        Ok(())
    }

    /// Records, in the devices group of each of this device's identities the group is open to, the group's opening.
    async fn refresh_opening(&self, gid: &[u8]) -> Result<()> {
        let Ok(settings) = self.node.settings(gid) else { return Ok(()) };
        for (identity, _) in self.node.identities() {
            if settings.open.iter().any(|named| named.id == identity.id) {
                self.node.set_opening(&identity.id.0, self.node.opening(gid)?).await?;
            }
        }
        Ok(())
    }

    fn remember_settings(&self, gid: &[u8]) -> Result<()> {
        put(&self.store, &key("settings", gid), &self.node.settings(gid)?)
    }

    fn known(&self, gid: &[u8]) -> Result<Known> {
        Ok(Known {
            me: self.node.key(),
            identities: self.node.identities(),
            contacts: self.node.contacts()?,
            introductions: get(&self.store, b"web/introductions")?.unwrap_or_default(),
            members: self.node.members(gid).unwrap_or_default(),
        })
    }

    /// A member as the page shows it: its names, its identity as this one knows it, and who added it.
    fn describe(&self, known: &Known, member: &Member) -> Value {
        if member.key.0.is_empty() {
            return json!({ "name": "", "iroh": member.iroh });
        }
        let mut described = json!({ "key": member.key, "fp": fp(&member.key.0), "name": member.name, "device": member.device_name });
        if member.key == known.me {
            described["you"] = json!(true);
        }
        if let Some(claim) = &member.identity {
            described["identity"] = self.identity(known, claim);
        }
        if let Some((by, how)) = &member.added {
            let adder = known.members.iter().find(|m| &m.key == by);
            described["added_by"] = json!({ "name": adder.map(|a| a.name.clone()), "how": how });
        }
        described
    }

    /// An identity as this one knows it: its own (`self`), a contact (`verified` or `introduced`), or `unknown`: only
    /// its own claim, with the introductions others made of it.
    fn identity(&self, known: &Known, claim: &Claim) -> Value {
        let id = &claim.identity.id;
        let mut identity = json!({ "id": id });
        if let Some((_, name)) = known.identities.iter().find(|(own, _)| &own.id == id) {
            identity["name"] = json!(name);
            identity["how"] = json!("self");
        } else if let Some((_, contact)) = known.contacts.iter().find(|(cid, _)| cid == id) {
            identity["name"] = json!(contact.name);
            identity["how"] = json!(contact.how);
            if let Some(by) = &contact.by {
                let name = known.contacts.iter().find(|(cid, _)| cid == by).map_or_else(|| b64(&by.0), |(_, c)| c.name.clone());
                identity["by"] = json!(name);
            }
        } else {
            identity["name"] = json!(claim.name);
            identity["how"] = json!("unknown");
            if known.contacts.iter().any(|(_, c)| c.name.eq_ignore_ascii_case(&claim.name)) {
                identity["warning"] = json!(format!("not your {}", claim.name));
            }
            if let Some(introduction) = known.introductions.get(&b64(&id.0)) {
                identity["introduced"] = json!({ "by": introduction.by, "name": introduction.name });
            }
        }
        if let Some(error) = &claim.error {
            identity["error"] = json!(error);
        }
        if let Some(device) = &claim.added_by_device
            && identity["how"] != "self"
        {
            identity["new_device"] = json!(format!("added by {device}"));
        }
        identity
    }

    fn own_identity(&self, id: &str) -> Result<IdentityRef> {
        let id = unb64(id)?;
        let identities = self.node.identities();
        Ok(identities.into_iter().find(|(identity, _)| identity.id.0 == id).context("this browser is on no such identity")?.0)
    }

    fn groups(&self) -> Result<Value> {
        let mut groups = Vec::new();
        for gid in self.node.groups() {
            let known = self.known(&gid.0)?;
            let settings = self.node.settings(&gid.0)?;
            let members: Vec<Value> = known.members.iter().map(|m| self.describe(&known, m)).collect();
            groups.push(json!({ "group": gid, "settings": settings, "members": members, "joined": true }));
        }
        let joined = self.node.groups();
        for opening in self.node.openings() {
            if !joined.contains(&opening.group) && !groups.iter().any(|g| g["group"] == json!(opening.group)) {
                groups.push(json!({ "group": opening.group, "settings": { "kind": opening.kind, "name": opening.name }, "joined": false }));
            }
        }
        Ok(Value::Array(groups))
    }

    /// A group's timeline: its held messages, and the changes this session saw, oldest first.
    fn items(&self, gid: &[u8]) -> Result<Value> {
        let known = self.known(gid)?;
        let mut items: Vec<Value> = get(&self.store, &key("timeline", gid))?.unwrap_or_default();
        let pending: HashSet<Vec<u8>> = self.node.only_here(gid)?.into_iter().map(|p| p.id.0).collect();
        let refused: HashMap<String, Value> = get(&self.store, &key("refused", gid))?.unwrap_or_default();
        for message in self.node.messages(gid)? {
            let from = self.describe(&known, &message.sender);
            let id = hex::encode(&message.id.0);
            let Payload::Message { content, to, reply_to, urgent, attachment, .. } = message.payload else {
                items.push(json!({ "type": "leave", "id": id, "at": message.at, "from": from }));
                continue;
            };
            let mut item = json!({ "type": "message", "id": id, "at": message.at, "from": from, "content": content });
            if !to.is_empty() {
                item["to"] = json!(to.iter().map(|fp| hex::encode(&fp.0)).collect::<Vec<_>>());
            }
            if let Some(reply_to) = reply_to {
                item["reply_to"] = json!(hex::encode(&reply_to.0));
            }
            if urgent {
                item["urgent"] = json!(true);
            }
            if let Some(attachment) = attachment {
                item["attachment"] = json!(attachment);
            }
            if pending.contains(&message.id.0) {
                item["pending"] = json!(true);
            }
            if let Some(refused) = refused.get(&id) {
                item["refused"] = refused.clone();
            }
            items.push(item);
        }
        items.sort_by_key(|item| item["at"].as_u64());
        Ok(Value::Array(items))
    }

    /// The messages no other held message comes after: what a new message names in `after`.
    fn tips(&self, gid: &[u8]) -> Result<Vec<Bytes>> {
        let messages = self.node.messages(gid)?;
        let covered: HashSet<&Bytes> = messages
            .iter()
            .flat_map(|m| match &m.payload {
                Payload::Message { after, .. } => after.iter().collect(),
                _ => Vec::new(),
            })
            .collect();
        Ok(messages.iter().filter(|m| matches!(m.payload, Payload::Message { .. }) && !covered.contains(&m.id)).map(|m| m.id.clone()).collect())
    }

    #[allow(clippy::too_many_arguments)]
    async fn send(&self, gid: &[u8], content: String, reply_to: Option<String>, to: Vec<String>, urgent: bool, file: Option<(String, String, Vec<u8>)>) -> Result<Value> {
        let attachment = match file {
            Some((name, media_type, bytes)) => {
                let size = bytes.len() as u64;
                let link = self.node.add_file(gid, bytes).await?;
                self.keep_file(link.hash).await?;
                Some((link.clone(), Attachment { link: link.link(), name, size, media_type }))
            }
            None => None,
        };
        let payload = Payload::Message {
            content,
            after: self.tips(gid)?,
            to: to.iter().map(|fp| Ok(Bytes(hex::decode(fp)?))).collect::<Result<_>>()?,
            reply_to: reply_to.map(|id| Ok::<_, anyhow::Error>(Bytes(hex::decode(id)?))).transpose()?,
            urgent,
            attachment: attachment.as_ref().map(|(_, a)| a.clone()),
        };
        let (id, delivery) = self.node.send(gid, &payload).await?;
        for (member, reason) in &delivery.refused {
            self.refused(gid, &id.0, member, reason)?;
        }
        let mut answer = json!({ "id": hex::encode(&id.0), "held_by": delivery.held.iter().map(|m| &m.name).collect::<Vec<_>>() });
        if let Some((link, _)) = attachment {
            let holders = self.node.spread(gid, &link).await;
            answer["attachment"] = json!({ "held_by": holders.iter().map(|m| &m.name).collect::<Vec<_>>() });
        }
        Ok(answer)
    }

    async fn join(&self, link: &str) -> Result<Value> {
        let invite = Invite::parse(link.trim())?;
        if invite.device {
            self.node.join(&invite, None).await?;
            return Ok(json!({ "device": true }));
        }
        let identity = self.node.identities().into_iter().next().map(|(identity, _)| identity);
        let gid = self.node.join(&invite, identity).await?;
        self.remember_settings(&gid.0)?;
        Ok(json!({ "group": gid }))
    }

    async fn join_open(&self, gid: &str) -> Result<Value> {
        let gid = unb64(gid)?;
        let opening = self.node.openings().into_iter().find(|o| o.group.0 == gid).context("no such open group")?;
        let identity = self.node.identities().into_iter().next().context("this browser is on no identity")?.0;
        let gid = self.node.join_open(&opening, identity).await?;
        self.remember_settings(&gid.0)?;
        Ok(json!({ "group": gid }))
    }

    async fn devices(&self, id: &str) -> Result<Value> {
        let identity = self.own_identity(id)?;
        let list = self.node.device_list(&identity).await?;
        let me = self.node.device().public();
        let devices: Vec<Value> = list.devices.iter().map(|d| json!({ "key": d.key, "name": d.name, "you": d.key.0 == me })).collect();
        Ok(json!({ "id": identity.id, "name": list.name, "devices": devices }))
    }

    fn contacts(&self) -> Result<Value> {
        let contacts = self.node.contacts()?;
        let introductions: HashMap<String, Introduction> = get(&self.store, b"web/introductions")?.unwrap_or_default();
        let listed: Vec<Value> = contacts
            .iter()
            .map(|(id, c)| {
                let by = c.by.as_ref().map(|by| contacts.iter().find(|(i, _)| i == by).map_or_else(|| b64(&by.0), |(_, i)| i.name.clone()));
                json!({ "id": id, "name": c.name, "how": c.how, "by": by })
            })
            .collect();
        let introduced: Vec<Value> = introductions.iter().map(|(id, i)| json!({ "id": id, "name": i.name, "by": i.by })).collect();
        Ok(json!({ "contacts": listed, "introductions": introduced }))
    }

    async fn accept(&self, id: &str, name: Option<String>) -> Result<()> {
        let mut introductions: HashMap<String, Introduction> = get(&self.store, b"web/introductions")?.unwrap_or_default();
        let introduction = introductions.remove(id).context("no introduction of that identity")?;
        let contact = Contact { name: name.unwrap_or(introduction.name), how: contacts::How::Introduced, by: Some(introduction.by_id), at: now() };
        self.node.set_contact(&unb64(id)?, &contact).await?;
        put(&self.store, b"web/introductions", &introductions)
    }

    async fn set_open(&self, gid: &[u8], id: &str, name: &str, open: bool) -> Result<()> {
        let id = Bytes(unb64(id)?);
        self.node
            .change_settings(gid, |mut settings| {
                settings.open.retain(|named| named.id != id);
                if open {
                    settings.open.push(Named { id: id.clone(), name: name.into() });
                }
                settings
            })
            .await?;
        self.refresh_opening(gid).await
    }
}

/// A member's label: the name its identity goes by here, and its device; else its own name.
fn label(described: &Value) -> String {
    match described["identity"]["name"].as_str() {
        Some(name) if described["identity"]["error"].is_null() => format!("{name} · {}", described["device"].as_str().unwrap_or_default()),
        _ => described["name"].as_str().unwrap_or_default().to_owned(),
    }
}

#[wasm_bindgen]
impl Lmk {
    /// Persists what changed now, as when the page is hidden.
    pub fn flush(&self) {
        self.app.flush();
    }

    /// This browser: `{"key", "fp", "name", "device": {"key", "name"}, "identities": [{"id", "name"}]}`.
    pub fn me(&self) -> R<String> {
        let app = &self.app;
        let device = app.node.device();
        let name: String = get(&app.store, b"web/name").map_err(js)?.unwrap_or_default();
        let identities: Vec<Value> = app.node.identities().into_iter().map(|(i, name)| json!({ "id": i.id, "name": name })).collect();
        let key = app.node.key();
        Ok(json!({ "key": key, "fp": fp(&key.0), "name": name, "device": { "key": Bytes(device.public().to_vec()), "name": device.name }, "identities": identities }).to_string())
    }

    /// Every group this browser is in, with its settings and members, then the open groups it could join.
    pub fn groups(&self) -> R<String> {
        Ok(self.app.groups().map_err(js)?.to_string())
    }

    pub fn members(&self, gid: &str) -> R<String> {
        let gid = unb64(gid).map_err(js)?;
        let known = self.app.known(&gid).map_err(js)?;
        Ok(Value::Array(known.members.iter().map(|m| self.app.describe(&known, m)).collect()).to_string())
    }

    pub fn items(&self, gid: &str) -> R<String> {
        Ok(self.app.items(&unb64(gid).map_err(js)?).map_err(js)?.to_string())
    }

    /// The members online now, and what only this browser holds.
    pub fn status(&self, gid: &str) -> R<String> {
        let gid = unb64(gid).map_err(js)?;
        let online: Vec<String> = self.app.node.online(&gid).map_err(js)?.into_iter().map(|m| m.name).collect();
        let only_here = self.app.node.only_here(&gid).map_err(js)?;
        Ok(json!({ "online": online, "only_here": only_here.len() }).to_string())
    }

    /// A new chat or doc, speaking as this browser's first identity; returns its id.
    pub fn create(&self, kind: &str, name: &str) -> R<String> {
        let app = &self.app;
        let kind = if kind == "doc" { Kind::Doc } else { Kind::Chat };
        let settings = Settings {
            protocol: PROTOCOL,
            kind,
            name: name.into(),
            open: Vec::new(),
            keep: 90,
            membership: app.membership.clone(),
            devices_of: None,
            openings: Vec::new(),
        };
        let identity = app.node.identities().into_iter().next().map(|(identity, _)| identity);
        let gid = app.node.create(settings, identity).map_err(js)?;
        app.remember_settings(&gid.0).map_err(js)?;
        app.flush();
        Ok(b64(&gid.0))
    }

    /// An invite link into a group, labelled with whom it is for.
    pub fn invite(&self, gid: &str, label: Option<String>) -> R<String> {
        let gid = unb64(gid).map_err(js)?;
        self.app.node.invite(Target::Group(gid), label.filter(|l| !l.is_empty()), None).map_err(js)
    }

    /// A device link: whoever opens it becomes a device of this identity.
    pub fn invite_device(&self, id: &str) -> R<String> {
        let identity = self.app.own_identity(id).map_err(js)?;
        self.app.node.invite(Target::Device(identity.id.0), None, None).map_err(js)
    }

    /// Joins through an invite link: `{"group"}`, or `{"device": true}` for a device link.
    pub async fn join(&self, link: String) -> R<String> {
        let joined = self.app.join(&link).await.map_err(js)?;
        self.app.flush();
        Ok(joined.to_string())
    }

    /// Joins a group open to this browser's identity.
    pub async fn join_open(&self, gid: String) -> R<String> {
        let joined = self.app.join_open(&gid).await.map_err(js)?;
        self.app.flush();
        Ok(joined.to_string())
    }

    /// Sends a chat message, with an optional file: `{"id", "held_by", "attachment": {"held_by"}}`.
    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &self,
        gid: String,
        content: String,
        reply_to: Option<String>,
        to: Vec<String>,
        urgent: bool,
        file_name: Option<String>,
        file_type: Option<String>,
        file: Option<Vec<u8>>,
    ) -> R<String> {
        let gid = unb64(&gid).map_err(js)?;
        let file = file.map(|bytes| (file_name.unwrap_or_default(), file_type.unwrap_or_default(), bytes));
        let sent = self.app.send(&gid, content, reply_to, to, urgent, file).await.map_err(js)?;
        self.app.flush();
        Ok(sent.to_string())
    }

    pub async fn remove(&self, gid: String, key: String) -> R<()> {
        self.app.node.remove(&unb64(&gid).map_err(js)?, &unb64(&key).map_err(js)?).await.map_err(js)?;
        self.app.flush();
        Ok(())
    }

    /// Leaves a group: true once gone, false while another member is to commit the removal.
    pub async fn leave(&self, gid: String) -> R<bool> {
        let gone = self.app.node.leave(&unb64(&gid).map_err(js)?).await.map_err(js)?.is_none();
        self.app.flush();
        Ok(gone)
    }

    pub async fn rename(&self, gid: String, name: String) -> R<()> {
        let gid = unb64(&gid).map_err(js)?;
        self.app.node.change_settings(&gid, |settings| Settings { name: name.clone(), ..settings }).await.map_err(js)?;
        self.app.flush();
        Ok(())
    }

    /// Opens a group to an identity's devices, or closes it.
    pub async fn set_open(&self, gid: String, id: String, name: String, open: bool) -> R<()> {
        self.app.set_open(&unb64(&gid).map_err(js)?, &id, &name, open).await.map_err(js)?;
        self.app.flush();
        Ok(())
    }

    /// A doc's Yjs state.
    pub fn doc(&self, gid: &str) -> R<Vec<u8>> {
        self.app.node.doc(&unb64(gid).map_err(js)?).map_err(js)
    }

    /// What a Yjs doc with state vector `sv` lacks of a doc.
    pub fn doc_diff(&self, gid: &str, sv: &[u8]) -> R<Vec<u8>> {
        let state = self.app.node.doc(&unb64(gid).map_err(js)?).map_err(js)?;
        doc::diff(&state, sv).map_err(js)
    }

    /// Applies a Yjs update made here to a doc and sends it to the members online.
    pub async fn edit(&self, gid: String, update: Vec<u8>) -> R<()> {
        self.app.node.edit(&unb64(&gid).map_err(js)?, update).await.map_err(js)?;
        self.app.flush();
        Ok(())
    }

    /// Seals a file for a group and holds it; returns its link.
    pub async fn add_file(&self, gid: String, bytes: Vec<u8>) -> R<String> {
        let link = self.app.node.add_file(&unb64(&gid).map_err(js)?, bytes).await.map_err(js)?;
        self.app.keep_file(link.hash).await.map_err(js)?;
        self.app.flush();
        Ok(link.link())
    }

    /// A file's plaintext, if it is held.
    pub async fn file(&self, link: String) -> R<Option<Vec<u8>>> {
        self.app.node.file(&FileLink::parse(&link).map_err(js)?).await.map_err(js)
    }

    /// Fetches a file a group links, whatever its size; a `file` event follows.
    pub fn fetch(&self, gid: &str, link: &str) -> R<()> {
        self.app.node.fetch(&unb64(gid).map_err(js)?, FileLink::parse(link).map_err(js)?);
        Ok(())
    }

    /// Starts an identity with this browser its first device.
    pub async fn identity_create(&self, name: String) -> R<String> {
        let identity = self.app.node.identity_create(&name, self.app.membership.clone()).await.map_err(js)?;
        self.app.flush();
        Ok(b64(&identity.id.0))
    }

    /// An identity's device list: `{"id", "name", "devices": [{"key", "name", "you"}]}`.
    pub async fn devices(&self, id: String) -> R<String> {
        Ok(self.app.devices(&id).await.map_err(js)?.to_string())
    }

    pub async fn remove_device(&self, id: String, device: String) -> R<()> {
        let identity = self.app.own_identity(&id).map_err(js)?;
        self.app.node.remove_device(&identity, &unb64(&device).map_err(js)?).await.map_err(js)?;
        self.app.flush();
        Ok(())
    }

    /// `{"contacts": [{"id", "name", "how", "by"}], "introductions": [{"id", "name", "by"}]}`.
    pub fn contacts(&self) -> R<String> {
        Ok(self.app.contacts().map_err(js)?.to_string())
    }

    /// Makes an introduced identity a contact.
    pub async fn accept(&self, id: String, name: Option<String>) -> R<()> {
        self.app.accept(&id, name).await.map_err(js)?;
        self.app.flush();
        Ok(())
    }
}
