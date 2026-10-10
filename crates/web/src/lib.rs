//! The browser client: the client core on one lmk-node session, which is the browser's device too, with a device key of
//! its own in each identity's devices group, reaching its peers only through the relay, with the devices kind on the
//! same node. Chat is built in; the doc kind
//! (`lmk_kind_doc::Page`) and the git kind, display-only (`lmk_kind_git::Page`), are in-page plugins, whose messages go
//! to and from the core as calls. The page persists the session's records in IndexedDB, one record per key, each step's
//! before what the step produced leaves the session, and the ciphertext of the files it holds, which the session loads
//! when it needs one. Results that are not bytes are JSON
//! strings; message ids and fingerprints are hex, other bytes base64url.
#![cfg(target_arch = "wasm32")]

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use js_sys::{Array, Function, Promise, Uint8Array};
use lmk_client::{Access, Chat, Client, ClientEvent, Described, File, Introduction, Request, fp, message_id, service};
use lmk_node::devices::Devices;
use lmk_node::lmk_core::crypto::{Crypto, Rand};
use lmk_node::lmk_core::device::Device;
use lmk_node::lmk_core::provider::{MemoryProvider, Provider};
use lmk_node::{Disk, Node, now};
use lmk_proto::Bytes;
use lmk_proto::group::{CHAT, DEVICES, PROTOCOL, Settings};
use lmk_proto::links::{FileLink, Invite};
use n0_future::boxed::BoxFuture;
use n0_future::time::{Duration, sleep};
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};

/// Others' files larger than this are fetched only when asked, and kept only in memory, until the page closes.
const FILE_LIMIT: u64 = 25 << 20;
/// The kinds the browser supports: chat, and those of its in-page plugins.
const DOC: &str = "doc";
const GIT: &str = "git";
/// How often the files no group links any longer are deleted.
const COLLECT: Duration = Duration::from_secs(60 * 60);

type R<T> = Result<T, JsError>;

fn js(error: anyhow::Error) -> JsError {
    JsError::new(&format!("{error:#}"))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn error(text: &str);

    /// The page's IndexedDB.
    pub type Idb;
    /// Persists records: `[key, value]` pairs, and keys to delete; resolves once they are durable.
    #[wasm_bindgen(method)]
    fn save(this: &Idb, puts: Array, deletes: Array) -> Promise;
    #[wasm_bindgen(method, js_name = saveFile)]
    fn save_file(this: &Idb, hash: &str, ciphertext: Vec<u8>);
    /// Resolves to a kept file's ciphertext.
    #[wasm_bindgen(method, js_name = loadFile)]
    fn load_file(this: &Idb, hash: &str) -> Promise;
    #[wasm_bindgen(method, js_name = deleteFile)]
    fn delete_file(this: &Idb, hash: &str);
}

/// The files kept in IndexedDB, which the session loads and saves through the page.
struct Kept {
    hashes: Mutex<HashSet<[u8; 32]>>,
    io: mpsc::UnboundedSender<Io>,
}

enum Io {
    Load([u8; 32], oneshot::Sender<Result<Vec<u8>>>),
    Save([u8; 32], Vec<u8>),
}

impl Disk for Kept {
    fn has(&self, hash: &[u8; 32]) -> bool {
        self.hashes.lock().unwrap().contains(hash)
    }

    fn load(&self, hash: [u8; 32]) -> BoxFuture<Result<Vec<u8>>> {
        let (reply, answer) = oneshot::channel();
        self.io.send(Io::Load(hash, reply)).ok();
        Box::pin(async move { answer.await? })
    }

    fn save(&self, hash: [u8; 32], ciphertext: Vec<u8>) {
        self.hashes.lock().unwrap().insert(hash);
        self.io.send(Io::Save(hash, ciphertext)).ok();
    }
}

/// The session's provider, shared with `flush`, which persists it.
#[derive(Clone, Default)]
struct Store(Arc<MemoryProvider>);

impl OpenMlsProvider for Store {
    type CryptoProvider = Crypto;
    type RandProvider = Rand;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        self.0.storage()
    }

    fn crypto(&self) -> &Crypto {
        self.0.crypto()
    }

    fn rand(&self) -> &Rand {
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

    fn begin(&self) -> Result<()> {
        self.0.begin()
    }

    fn commit(&self) -> Result<()> {
        self.0.commit()
    }

    fn savepoint(&self) -> Result<()> {
        self.0.savepoint()
    }

    fn rollback_to(&self) -> Result<()> {
        self.0.rollback_to()
    }

    fn release(&self) -> Result<()> {
        self.0.release()
    }
}

/// Hands the records that changed since the last flush to the page; resolves once they are durable.
fn flush(store: &Store, idb: &Idb) -> Promise {
    let (puts, deletes) = (Array::new(), Array::new());
    for (key, value) in store.0.changes() {
        match value {
            Some(value) => drop(puts.push(&Array::of2(&Uint8Array::from(&key[..]), &Uint8Array::from(&value[..])))),
            None => drop(deletes.push(&Uint8Array::from(&key[..]))),
        }
    }
    idb.save(puts, deletes)
}

/// The in-page plugins' records, among the session's.
struct PageStore(Store);

impl lmk_kind_doc::Store for PageStore {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.0.get(key.as_bytes()).ok().flatten()
    }

    fn put(&self, key: &str, value: &[u8]) {
        self.0.put(key.as_bytes(), value).ok();
    }

    fn delete(&self, key: &str) {
        self.0.delete(key.as_bytes()).ok();
    }
}

impl lmk_kind_git::Store for PageStore {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        lmk_kind_doc::Store::get(self, key)
    }

    fn put(&self, key: &str, value: &[u8]) {
        lmk_kind_doc::Store::put(self, key, value)
    }

    fn delete(&self, key: &str) {
        lmk_kind_doc::Store::delete(self, key)
    }
}

/// The in-page plugins: what they send in answer to a message goes to the client as their lines.
struct InPage {
    docs: Mutex<lmk_kind_doc::Page<PageStore>>,
    git: Mutex<lmk_kind_git::Page<PageStore>>,
    started: Mutex<HashSet<String>>,
    lines: mpsc::UnboundedSender<(String, Option<Value>)>,
}

impl lmk_client::Plugins for InPage {
    fn kinds(&self) -> Vec<String> {
        vec![DOC.into(), GIT.into()]
    }

    fn start(&self, kind: &str) -> Result<Value> {
        anyhow::ensure!([DOC, GIT].contains(&kind), "this browser has no plugin for {kind} groups");
        self.started.lock().unwrap().insert(kind.to_owned());
        Ok(json!({}))
    }

    fn running(&self) -> Vec<String> {
        self.started.lock().unwrap().iter().cloned().collect()
    }

    fn send(&self, kind: &str, message: &Value) -> Result<()> {
        let out = match kind {
            DOC => self.docs.lock().unwrap().input(message),
            _ => self.git.lock().unwrap().input(message),
        };
        for line in out {
            self.lines.send((kind.to_owned(), Some(line))).ok();
        }
        Ok(())
    }

    fn stopped(&self, _: &str) -> bool {
        unreachable!("an in-page plugin does not stop")
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

fn unb64(text: &str) -> Result<Vec<u8>> {
    Ok(serde_json::from_value::<Bytes>(json!(text))?.0)
}

#[derive(Deserialize)]
struct Config {
    /// The person's name and this device's: used only when the browser has no session yet.
    name: String,
    device: String,
    relay: String,
    membership: String,
}

/// An introduction as letmeknow 0.12 kept it, in the record `web/introductions`, by identity id.
#[derive(Deserialize)]
struct Kept012 {
    name: String,
    /// The introducer's label.
    by: String,
    by_id: Bytes,
}

struct App {
    client: Client<Store>,
    store: Store,
    membership: lmk_proto::group::Service,
    idb: Idb,
    kept: Arc<Kept>,
    on_event: Function,
    /// Open groups this session tried to join by itself, and those it failed to join.
    tried: RefCell<HashSet<Bytes>>,
    failed: RefCell<HashSet<Bytes>>,
}

/// The browser's session.
#[wasm_bindgen]
pub struct Lmk {
    app: Rc<App>,
}

/// Opens the session from its records (`[key, value]` pairs) and the hashes (hex) of the files kept in IndexedDB,
/// creating it if there are none. `on_event(json)` hears what happens.
#[wasm_bindgen]
pub async fn start(records: Array, kept: Vec<String>, config: String, idb: Idb, on_event: Function) -> R<Lmk> {
    std::panic::set_hook(Box::new(|info| error(&info.to_string())));
    let app = App::start(records, kept, &config, idb, on_event).await.map_err(js)?;
    Ok(Lmk { app })
}

/// What an invite link is: `group` or `device`.
#[wasm_bindgen]
pub fn invite_kind(link: &str) -> R<String> {
    Ok(if Invite::parse(link).map_err(js)?.device { "device" } else { "group" }.into())
}

impl App {
    async fn start(records: Array, kept: Vec<String>, config: &str, idb: Idb, on_event: Function) -> Result<Rc<Self>> {
        let config: Config = serde_json::from_str(config)?;
        let records = records.iter().map(|record| {
            let record = Array::from(&record);
            (Uint8Array::from(record.get(0)).to_vec(), Uint8Array::from(record.get(1)).to_vec())
        });
        let store = Store(Arc::new(MemoryProvider::load(records.collect::<Vec<_>>())));
        // Each step's records are durable before what it produced leaves the session.
        let (durable_tx, mut durable_rx) = mpsc::unbounded_channel::<oneshot::Sender<Result<()>>>();
        let (saving, saving_idb): (_, Idb) = (store.clone(), idb.clone().unchecked_into());
        spawn_local(async move {
            while let Some(reply) = durable_rx.recv().await {
                let saved = JsFuture::from(flush(&saving, &saving_idb)).await;
                reply.send(saved.map(drop).map_err(|e| anyhow!("saving to IndexedDB: {e:?}"))).ok();
            }
        });
        let durable: lmk_node::Durable = Arc::new(move || {
            let (reply, saved) = oneshot::channel();
            let asked = durable_tx.send(reply);
            Box::pin(async move {
                asked.map_err(|_| anyhow!("the page stopped saving"))?;
                saved.await?
            })
        });
        if store.get(b"web/name")?.is_none() {
            put(&store, b"web/name", &config.name)?;
        }
        let device: Device = get(&store, b"web/device")?.unwrap_or_else(|| Device::new(&config.device));
        put(&store, b"web/device", &device)?;
        let hashes = kept.iter().map(|hash| hex::decode(hash)?.try_into().map_err(|_| anyhow!("a hash is 32 bytes"))).collect::<Result<_>>()?;
        let (io, mut io_rx) = mpsc::unbounded_channel();
        let kept = Arc::new(Kept { hashes: Mutex::new(hashes), io });
        let name: String = get(&store, b"web/name")?.context("no name")?;
        let node_config = lmk_node::Config {
            name: name.clone(),
            device: Some(device.clone()),
            relay: config.relay.parse()?,
            ca: Default::default(),
            home: None,
            files: None,
            disk: Some(kept.clone()),
            file_limit: FILE_LIMIT,
            kinds: vec![CHAT.into(), DOC.into(), GIT.into(), DEVICES.into()],
            durable: Some(durable),
            observe: None,
        };
        let (node, mut events) = Node::start(store.clone(), node_config).await?;
        let saved = store.clone();
        let devices = Devices::new(node.clone(), device.clone(), Arc::new(move |device: &Device| put(&saved, b"web/device", device)));
        let membership = service(&config.membership)?;
        let (lines, written) = mpsc::unbounded_channel();
        let plugins = InPage {
            docs: Mutex::new(lmk_kind_doc::Page::new(PageStore(store.clone()))),
            git: Mutex::new(lmk_kind_git::Page::new(PageStore(store.clone()))),
            started: Mutex::default(),
            lines,
        };
        let client_config = lmk_client::Config { name, device, membership: membership.clone() };
        let (client, mut told) = Client::new(node, client_config, Access::Here(devices), Arc::new(plugins), written);
        let (tried, failed) = Default::default();
        let app = Rc::new(App { client, store, membership, idb, kept, on_event, tried, failed });
        app.take_introductions()?;
        let told_app = app.clone();
        spawn_local(async move {
            while let Some(event) = told.recv().await {
                if let Err(e) = told_app.on(event) {
                    told_app.emit(json!({ "type": "warning", "text": format!("{e:#}") }));
                }
                told_app.flush();
            }
        });
        let client = app.client.clone();
        spawn_local(async move {
            loop {
                let (kind, line) = client.next_line().await;
                client.plugin_line(kind, line).await;
            }
        });
        app.client.start().await;
        app.flush();
        app.join_openings();
        let io_app = app.clone();
        spawn_local(async move {
            while let Some(io) = io_rx.recv().await {
                match io {
                    Io::Save(hash, ciphertext) => io_app.idb.save_file(&hex::encode(hash), ciphertext),
                    Io::Load(hash, reply) => {
                        let loaded = JsFuture::from(io_app.idb.load_file(&hex::encode(hash))).await;
                        reply.send(loaded.map(|bytes| Uint8Array::new(&bytes).to_vec()).map_err(|e| anyhow!("loading a file: {e:?}"))).ok();
                    }
                }
            }
        });
        let events_app = app.clone();
        spawn_local(async move {
            while let Some(event) = events.recv().await {
                events_app.client.event(event).await;
                events_app.flush();
                events_app.join_openings();
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
        let collecting = Rc::downgrade(&app);
        spawn_local(async move {
            while let Some(app) = collecting.upgrade() {
                app.collect();
                drop(app);
                sleep(COLLECT).await;
            }
        });
        Ok(app)
    }

    /// Hands the client the introductions that letmeknow 0.12 kept in this browser's own record.
    fn take_introductions(&self) -> Result<()> {
        let Some(kept) = get::<HashMap<String, Kept012>>(&self.store, b"web/introductions")? else { return Ok(()) };
        for (id, introduction) in kept {
            let by = Described { name: Some(introduction.by), ..Described::default() };
            self.client.add_introduction(Introduction { identity: Bytes(unb64(&id)?), name: introduction.name, by, by_id: introduction.by_id })?;
        }
        self.store.delete(b"web/introductions")
    }

    /// Joins, once each, the groups open to this browser's identities; one that fails waits for a click.
    fn join_openings(self: &Rc<Self>) {
        let joined = self.client.node().groups();
        let Ok(state) = self.client.device_state() else { return };
        for opening in state.openings {
            if joined.contains(&opening.group) || !self.tried.borrow_mut().insert(opening.group.clone()) {
                continue;
            }
            let app = self.clone();
            spawn_local(async move {
                if app.request(join(&opening.group)).await.is_err() {
                    app.failed.borrow_mut().insert(opening.group.clone());
                }
                app.flush();
                app.emit(json!({ "type": "opening", "group": opening.group }));
            });
        }
    }

    /// Deletes the kept files no group links any longer, by the rule lmk-node holds files by.
    fn collect(&self) {
        let linked: HashSet<[u8; 32]> = self.client.node().files().iter().map(|link| link.hash).collect();
        self.kept.hashes.lock().unwrap().retain(|hash| {
            let keep = linked.contains(hash);
            if !keep {
                self.idb.delete_file(&hex::encode(hash));
            }
            keep
        });
    }

    /// Hands the records that changed since the last flush to the page.
    fn flush(&self) {
        drop(flush(&self.store, &self.idb));
    }

    fn emit(&self, event: Value) {
        self.on_event.call1(&JsValue::NULL, &JsValue::from_str(&event.to_string())).ok();
    }

    /// A request of the client core; a group joined has its settings remembered, for the changes to them.
    async fn request(&self, request: Request) -> Result<Value> {
        let joining = matches!(request, Request::Join { .. });
        let answer = self.client.request(request).await?;
        if joining && let Some(gid) = answer["group"].as_str() {
            self.remember_settings(&unb64(gid)?)?;
        }
        Ok(answer)
    }

    /// What the client tells: kept in its group's timeline and told the page.
    fn on(&self, event: ClientEvent) -> Result<()> {
        match event {
            ClientEvent::Joined { group, member, by, how } => {
                self.remember(&group.0, &json!({ "type": "joined", "at": now(), "member": member, "by": by, "how": how }))?;
                self.emit(json!({ "type": "joined", "group": group }));
            }
            ClientEvent::Left { group, member, by } => {
                self.remember(&group.0, &json!({ "type": "left", "at": now(), "member": member, "by": by }))?;
                self.emit(json!({ "type": "left", "group": group }));
            }
            ClientEvent::Revoked { group, removed, added } => {
                self.remember(&group.0, &json!({ "type": "revoked", "at": now(), "removed": removed, "added": added }))?;
                self.emit(json!({ "type": "revoked", "group": group }));
            }
            ClientEvent::Removed { group, by } => self.emit(json!({ "type": "removed", "group": group, "by": by.and_then(|by| by.name) })),
            ClientEvent::Gone { group } => {
                for kind in ["timeline", "settings"] {
                    self.store.delete(&key(kind, &group.0))?;
                }
            }
            ClientEvent::Settings { group, settings, by } => {
                let before: Option<Settings> = get(&self.store, &key("settings", &group.0))?;
                put(&self.store, &key("settings", &group.0), &settings)?;
                let item = json!({ "type": "settings", "at": now(), "by": by, "before": before, "settings": settings });
                self.remember(&group.0, &item)?;
                self.emit(json!({ "type": "settings", "group": group }));
            }
            ClientEvent::Introduced { group, by, identity, how } => {
                self.remember(&group.0, &json!({ "type": "introduced", "at": now(), "by": by, "identity": identity, "how": how }))?;
                self.emit(json!({ "type": "introduced", "group": group }));
            }
            ClientEvent::Message { group, id, missing, .. } => {
                if !missing.is_empty() {
                    self.remember(&group.0, &json!({ "type": "missing", "at": now(), "positions": missing }))?;
                }
                self.emit(json!({ "type": "message", "group": group, "id": id }));
            }
            ClientEvent::Lost { group, member, positions, ids } => {
                self.remember(&group.0, &json!({ "type": "lost", "at": now(), "member": member, "positions": positions, "ids": ids }))?;
                self.emit(json!({ "type": "lost", "group": group }));
            }
            ClientEvent::Sent { group, id, .. } => self.emit(json!({ "type": "sent", "group": group, "id": id })),
            ClientEvent::Heard { group } => self.emit(json!({ "type": "heard", "group": group })),
            ClientEvent::File { hash } => self.emit(json!({ "type": "file", "hash": hash })),
            ClientEvent::Plugin { group, kind, mut event, .. } => {
                if event.get("type") == Some(&json!("pushed")) {
                    let item = json!({ "type": "pushed", "at": now(), "by": event["by"], "ref": event["ref"], "subjects": event["subjects"] });
                    self.remember(&group.0, &item)?;
                }
                event.insert("group".into(), json!(group));
                event.insert("kind".into(), json!(kind));
                self.emit(Value::Object(event));
            }
            ClientEvent::Devices { identity } => self.emit(json!({ "type": "devices", "identity": identity })),
            ClientEvent::Warning { group, text } => self.emit(json!({ "type": "warning", "group": group, "text": text })),
            // The page shows messages as they come, waiting for none; a held leave shows as its tick.
            ClientEvent::Synced { .. } | ClientEvent::LeaveHeld { .. } => {}
        }
        Ok(())
    }

    /// Adds an item to a group's timeline, beside its messages.
    fn remember(&self, gid: &[u8], item: &Value) -> Result<()> {
        let mut timeline: Vec<Value> = get(&self.store, &key("timeline", gid))?.unwrap_or_default();
        timeline.push(item.clone());
        put(&self.store, &key("timeline", gid), &timeline)
    }

    fn remember_settings(&self, gid: &[u8]) -> Result<()> {
        put(&self.store, &key("settings", gid), &self.client.node().settings(gid)?)
    }

    fn groups(&self) -> Result<Value> {
        let node = self.client.node();
        let mut groups = Vec::new();
        for gid in node.groups() {
            let settings = node.settings(&gid.0)?;
            if settings.kind == DEVICES {
                continue;
            }
            let away: Vec<String> = node.away(&gid.0)?.iter().map(|m| fp(&m.key.0)).collect();
            let mut members = serde_json::to_value(self.client.described_members(&gid)?)?;
            for member in members.as_array_mut().expect("a list") {
                if member["fp"].as_str().is_some_and(|fp| away.iter().any(|away| away == fp)) {
                    member["away"] = json!(true);
                }
            }
            groups.push(json!({ "group": gid, "settings": settings, "members": members, "joined": true }));
        }
        let joined = node.groups();
        for opening in self.client.device_state()?.openings {
            if !joined.contains(&opening.group) && !groups.iter().any(|g| g["group"] == json!(opening.group)) {
                let failed = self.failed.borrow().contains(&opening.group);
                groups.push(json!({ "group": opening.group, "settings": { "kind": opening.kind, "name": opening.name }, "joined": false, "failed": failed }));
            }
        }
        Ok(Value::Array(groups))
    }

    /// A group's timeline: its held messages, the changes and losses this session saw, oldest first; then its sends
    /// pending. Its own messages say which other members hold them (`held_by`), read them (`read_by`) or lost them
    /// (`lost_by`), and whether no other member's summary shows them held (`only_here`). `shown`: the page shows them,
    /// so they are read.
    fn items(&self, gid: &Bytes, shown: bool) -> Result<Value> {
        let node = self.client.node();
        let describer = self.client.describer(gid)?;
        let (receipts, only_here) = (self.client.receipts(gid)?, node.only_here(&gid.0)?);
        let mut read = Vec::new();
        let mut items: Vec<Value> = get(&self.store, &key("timeline", &gid.0))?.unwrap_or_default();
        let losses: Vec<Value> = items.iter().filter(|item| item["type"] == "lost" && item["member"]["you"] != true).cloned().collect();
        items.retain(|item| item["type"] != "lost" || item["member"]["you"] == true);
        let held = node.messages(&gid.0)?.into_iter().map(|message| (message.id, message.at, Some(message.position), message.sender, message.payload));
        let me = node.members(&gid.0)?.into_iter().find(|m| m.key == node.key());
        let pending = node.sending(&gid.0)?.into_iter().filter_map(|(id, payload)| Some((id, now(), None, me.clone()?, payload)));
        for (id, at, position, sender, payload) in held.chain(pending) {
            let from = describer.describe(&sender);
            let id = hex::encode(&id.0);
            let mine = sender.key == node.key();
            if payload["type"] == "leave" {
                let only_here = mine && position.is_some_and(|position| only_here.contains(position));
                items.push(json!({ "type": "leave", "id": id, "at": at, "from": from, "only_here": only_here }));
            }
            let Ok(lmk_proto::group::ChatMessage { content, to, reply_to, urgent, attachment, .. }) = serde_json::from_value(payload) else {
                continue;
            };
            let mut item = json!({ "type": "message", "id": id, "at": at, "from": from, "content": content });
            match position {
                Some(position) if mine => {
                    let by = |of: &dyn Fn(&lmk_client::Receipt) -> bool| -> Vec<Described> {
                        receipts.iter().filter(|r| of(r)).map(|r| describer.describe(&r.member)).collect()
                    };
                    item["position"] = json!(position);
                    item["only_here"] = json!(only_here.contains(position));
                    item["held_by"] = json!(by(&|r| r.held.contains(position)));
                    item["read_by"] = json!(by(&|r| r.read.contains(position)));
                    read.push(position);
                }
                Some(position) => {
                    item["position"] = json!(position);
                    read.push(position);
                }
                None => item["pending"] = json!(true),
            }
            let lost_by: Vec<&Value> = losses.iter().filter(|lost| lost["ids"].as_array().is_some_and(|ids| ids.contains(&json!(id)))).map(|lost| &lost["member"]).collect();
            if !lost_by.is_empty() {
                item["lost_by"] = json!(lost_by);
            }
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
                let kept = self.kept.has(&FileLink::parse(&attachment.link)?.hash);
                item["attachment"] = json!(attachment);
                item["attachment"]["kept"] = json!(kept);
            }
            items.push(item);
        }
        items.sort_by_key(|item| item["at"].as_u64());
        if shown {
            self.client.mark_read(gid, &read.into_iter().collect())?;
        }
        Ok(Value::Array(items))
    }

    /// How many of this session's sends no other member's summary shows held, in its groups but devices groups, its
    /// pending sends among them.
    fn only_here(&self) -> Result<u32> {
        let node = self.client.node();
        let mut count = 0;
        for gid in node.groups() {
            if node.settings(&gid.0)?.kind != DEVICES {
                count += node.only_here(&gid.0)?.len() as u32 + node.sending(&gid.0)?.len() as u32;
            }
        }
        Ok(count)
    }
}

/// A request to join a group open to this browser's identity.
fn join(gid: &Bytes) -> Request {
    let target = json!(gid).as_str().expect("base64url").to_owned();
    Request::Join { target, args: Vec::new(), cwd: String::new(), as_: None }
}

#[wasm_bindgen]
impl Lmk {
    /// Persists what changed now, as when the page is hidden.
    pub fn flush(&self) {
        self.app.flush();
    }

    /// This browser: `{"name", "fp", "device": {"name"}, "identities": [{"id", "name", "device"}]}`, `device` its key on
    /// the identity.
    pub fn me(&self) -> R<String> {
        Ok(self.app.client.me().map_err(js)?.to_string())
    }

    /// A request of the client core, as `letmeknow`'s command channel takes it (`{"cmd", ...}`); answers as it does.
    pub async fn request(&self, request: String) -> R<String> {
        let request: Request = serde_json::from_str(&request).map_err(|e| js(e.into()))?;
        let answer = self.app.request(request).await.map_err(js)?;
        self.app.flush();
        Ok(answer.to_string())
    }

    /// Every group this browser is in, with its settings and members, then the open groups it could join.
    pub fn groups(&self) -> R<String> {
        Ok(self.app.groups().map_err(js)?.to_string())
    }

    /// A group's timeline; `shown`: the page shows it, so its messages are read.
    pub fn items(&self, gid: &str, shown: bool) -> R<String> {
        Ok(self.app.items(&Bytes(unb64(gid).map_err(js)?), shown).map_err(js)?.to_string())
    }

    /// How many of this browser's sends no other member holds yet: closing it while any is loses them.
    pub fn only_here(&self) -> R<u32> {
        self.app.only_here().map_err(js)
    }

    /// A new chat, doc or git repository, speaking as this browser's first identity; returns its id.
    pub async fn create(&self, kind: String, name: String) -> R<String> {
        let app = &self.app;
        let settings = Settings { protocol: PROTOCOL, kind, name, open: Vec::new(), carry: 7, update: lmk_proto::group::UPDATE, membership: app.membership.clone(), rest: Default::default() };
        let (gid, _) = app.client.create(settings, None, (Vec::new(), String::new())).await.map_err(js)?;
        app.remember_settings(&gid.0).map_err(js)?;
        app.flush();
        Ok(json!(gid).as_str().expect("base64url").to_owned())
    }

    /// Sends a chat message, with an optional file, as `letmeknow send` does: `{"id", "position" | "pending",
    /// "attachment": {"held_by"} | {"pending"}}`.
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
        let gid = Bytes(unb64(&gid).map_err(js)?);
        let attachment = file.map(|data| File { name: file_name.unwrap_or_default(), media_type: file_type.unwrap_or_default(), data });
        let reply_to = reply_to.map(|id| message_id(&id)).transpose().map_err(js)?;
        let (_, sent) = self.app.client.send(&gid, Chat { text: content, to, reply_to, urgent, attachment }).await.map_err(js)?;
        self.app.flush();
        Ok(sent.to_string())
    }

    /// A command of a kind's in-page plugin, `args` a JSON array; answers its answer, as JSON. The doc kind's bind an
    /// editor to a doc: `["state", group]`, `["diff", group, state vector]` and `["edit", group, update]`.
    pub async fn command(&self, kind: String, args: String) -> R<String> {
        let args: Vec<String> = serde_json::from_str(&args).map_err(|e| js(e.into()))?;
        let answered = self.app.client.command(&kind, args, String::new()).await.map_err(js)?;
        let answer = answered.await.map_err(|_| JsError::new("the plugin stopped"))?.map_err(js)?;
        self.app.flush();
        Ok(answer.to_string())
    }

    /// Seals a file for a group and holds it; returns its link.
    pub async fn add_file(&self, gid: String, bytes: Vec<u8>) -> R<String> {
        let link = self.app.client.node().add_file(&unb64(&gid).map_err(js)?, bytes).await.map_err(js)?;
        self.app.flush();
        Ok(link.link())
    }

    /// A file's plaintext, if it is held.
    pub async fn file(&self, link: String) -> R<Option<Vec<u8>>> {
        self.app.client.node().file(&FileLink::parse(&link).map_err(js)?).await.map_err(js)
    }

    /// Fetches a file a group links, whatever its size; a `file` event follows.
    pub fn fetch(&self, gid: &str, link: &str) -> R<()> {
        self.app.client.node().fetch(&unb64(gid).map_err(js)?, FileLink::parse(link).map_err(js)?);
        Ok(())
    }
}
