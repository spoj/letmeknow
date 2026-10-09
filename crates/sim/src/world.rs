//! The world: members on the client core with the devices kind on their own node, as a browser runs it, one in-memory
//! membership service, the simulated network between them, and the properties checked as they act.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use iroh::EndpointId;
use lmk_client::{Access, Chat, Client, ClientEvent, Plugins, Request, fp};
use lmk_membership::service::{Policy, Service};
use lmk_net::{Fetch, Network};
use lmk_node::devices::Devices;
use lmk_node::lmk_core::crypto::{Crypto, Rand};
use lmk_node::lmk_core::device::Device;
use lmk_node::lmk_core::group::Window;
use lmk_node::lmk_core::provider::{MemoryProvider, Provider};
use lmk_node::{Event, Node};
use lmk_proto::Bytes;
use lmk_proto::group::{CHAT, DEVICES, Service as Membership};
use lmk_proto::peer::Frame;
use n0_future::boxed::BoxFuture;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

use crate::net::Net;
use crate::{Act, Action, Options, Outcome, clock};

const RELAY: &str = "https://relay.sim.invalid";
/// When simulated time starts: 2026-01-01, in milliseconds since the Unix epoch.
const BASE: u64 = 1_767_225_600_000;
/// How long members stay connected and undisturbed before they must agree: well under the 5-minute resync.
const CONVERGE: Duration = Duration::from_secs(90);
/// How long a live message may take to arrive.
const LIVE_WAIT: Duration = Duration::from_secs(10);
/// How long an action may take.
const ACTION_WAIT: Duration = Duration::from_secs(300);
/// How long after a device is taken off every member holding its sessions' certificates has read the key log entry
/// that names it: a copy of a key log is fresh for 10 minutes.
const KEYS_READ: u64 = 11 * 60 * 1000;
/// A removed member's messages are taken for 5 minutes after its removal is applied.
const REMOVED_GRACE: u64 = 5 * 60 * 1000;

thread_local! {
    static START: Cell<Option<Instant>> = const { Cell::new(None) };
    static PANICS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn now() -> u64 {
    BASE + START.get().expect("a simulation runs").elapsed().as_millis() as u64
}

fn elapsed() -> u64 {
    now() - BASE
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A property a run broke, and when.
#[derive(Clone, Debug)]
pub struct Failure {
    pub kind: &'static str,
    pub at: u64,
    pub text: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} at {}: {}", self.kind, clock(self.at), self.text)
    }
}

/// Members of a group, with their nodes.
type Holders = Vec<(usize, Node<Store>)>;

/// A member's storage, which outlives its crashes: a browser's records.
#[derive(Clone, Default)]
struct Store(Arc<MemoryProvider>);

impl Store {
    /// A copy, as storage stands when a session crashes, for the next one to start from.
    fn snapshot(&self) -> Store {
        let provider = MemoryProvider::default();
        *provider.storage.values.write().unwrap() = self.0.storage.values.read().unwrap().clone();
        Store(Arc::new(provider))
    }
}

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
}

/// Chat only: the simulated members load no plugins.
struct NoPlugins;

impl Plugins for NoPlugins {
    fn kinds(&self) -> Vec<String> {
        Vec::new()
    }

    fn start(&self, kind: &str) -> Result<Value> {
        bail!("no plugin for {kind}")
    }

    fn running(&self) -> Vec<String> {
        Vec::new()
    }

    fn send(&self, _: &str, _: &Value) -> Result<()> {
        Ok(())
    }

    fn stopped(&self, _: &str) -> bool {
        false
    }
}

struct Member {
    device: Device,
    store: Store,
    iroh: EndpointId,
    client: Option<Client<Store>>,
    tasks: Vec<JoinHandle<()>>,
}

/// A held chat message an action sent.
struct Sent {
    by: usize,
    group: Bytes,
    id: Bytes,
    epoch: u64,
}

/// What the properties keep track of, and the trace.
#[derive(Default)]
struct Book {
    groups: Vec<Bytes>,
    trace: Sha256,
    log: Vec<String>,
    failure: Option<Failure>,
    /// The held chat messages each member was told of.
    seen: BTreeMap<usize, BTreeSet<String>>,
    /// When each member was told a member left a group: by member, group and fingerprint.
    left: BTreeMap<(usize, Bytes, String), u64>,
    sent: Vec<Sent>,
    /// Refusals senders were told of: sender, message id (hex), and the fingerprint of the member that refused it.
    refusals: BTreeSet<(usize, String, String)>,
    /// Live messages each member took: by member and nonce.
    live: BTreeSet<(usize, String)>,
    /// Actions that may keep a live message from its receiver, so far.
    disruptions: u64,
    /// Members each member saw join with a valid certificate: by member, group and the joiner's fingerprint.
    vouched: BTreeSet<(usize, Bytes, String)>,
    /// Introductions each member was told of: by member, group, and the introducer's fingerprint.
    introduced: BTreeSet<(usize, Bytes, String)>,
    /// Devices taken off identities: the identity, the member whose device it was, and when.
    revoked: Vec<(Bytes, usize, u64)>,
}

struct World {
    net: Net,
    membership: Membership,
    members: Mutex<Vec<Member>>,
    /// Each member's peers, to which another member's fetch of a file goes.
    peers: Mutex<BTreeMap<EndpointId, lmk_net::Net>>,
    book: Mutex<Book>,
    /// Actions under way.
    running: Mutex<Vec<JoinHandle<()>>>,
}

pub(crate) fn run(seed: u64, actions: &[Action], options: Options) -> Outcome {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        // openmls encrypts path secrets on rayon's threads: on one, they draw randomness in order.
        rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICS.with_borrow_mut(|panics| panics.push(info.to_string()));
            default(info);
        }));
    });
    PANICS.with_borrow_mut(Vec::clear);
    lmk_proto::random::seed(seed);
    lmk_proto::clock::set(now);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().unwrap();
    let outcome = runtime.block_on(async {
        START.set(Some(Instant::now()));
        let world = World::new(seed, options);
        world.drive(actions).await;
        let book = std::mem::take(&mut *world.book.lock().unwrap());
        let mut trace = book.trace;
        trace.update(world.net.trace());
        Outcome { trace: trace.finalize().into(), failure: book.failure, log: book.log }
    });
    drop(runtime);
    outcome
}

impl World {
    fn new(seed: u64, options: Options) -> Arc<Self> {
        let net = Net::new(seed);
        let secret = iroh::SecretKey::from_bytes(&lmk_proto::random::random());
        let store = lmk_membership::store::Store::open(std::path::Path::new(":memory:"), ed25519_dalek::SigningKey::from_bytes(&secret.to_bytes())).unwrap();
        let service = Service::new(store, Policy::default());
        let membership = Membership::Serve { key: Bytes(secret.public().as_bytes().to_vec()), relay: RELAY.into(), addrs: Vec::new(), rest: Default::default() };
        drop(net.bind(secret.public()));
        net.listen(
            secret.public(),
            Arc::new(move |conn| {
                let service = service.clone();
                tokio::spawn(async move { service.accept(conn).await });
            }),
        );
        let members = (0..options.members)
            .map(|i| {
                let device = Device::new(&format!("device{i}"));
                let store = Store::default();
                let iroh = lmk_node::iroh_key(&store).unwrap().public();
                Member { device, store, iroh, client: None, tasks: Vec::new() }
            })
            .collect();
        let world = Arc::new(World { net, membership, members: Mutex::new(members), peers: Mutex::default(), book: Mutex::default(), running: Mutex::default() });
        let inspecting = Arc::downgrade(&world);
        world.net.inspect(Arc::new(move |from, to, frame| {
            if let Some(world) = inspecting.upgrade() {
                world.inspect(from, to, frame);
            }
        }));
        world
    }

    async fn drive(self: &Arc<Self>, actions: &[Action]) {
        for i in 0..self.size() {
            if let Err(error) = self.start(i).await {
                self.fail("start", format!("m{i} did not start: {error:#}"));
            }
        }
        let mut last = 0;
        for (i, action) in actions.iter().enumerate() {
            sleep(Duration::from_millis(action.at - last)).await;
            last = action.at;
            if self.book.lock().unwrap().failure.is_some() {
                break;
            }
            self.note(format!("#{i} {:?}", action.act));
            if !matches!(action.act, Act::Send { .. } | Act::Live { .. } | Act::Rename { .. } | Act::Online { .. } | Act::Quiesce) {
                self.book.lock().unwrap().disruptions += 1;
            }
            match &action.act {
                Act::Quiesce => self.quiesce().await,
                Act::Offline { m } => self.online(*m, false),
                Act::Online { m } => self.online(*m, true),
                Act::Restart { m } => self.restart(*m).await,
                Act::Partition { mask } => self.partition(*mask),
                Act::Heal => self.partition(0),
                Act::Sleep { ms } => {
                    for i in 0..self.size() {
                        self.crash(i).await;
                    }
                    sleep(Duration::from_millis(*ms)).await;
                    for i in 0..self.size() {
                        self.start_again(i).await;
                    }
                }
                Act::Drop { m, n } => {
                    let members = self.members.lock().unwrap();
                    let (a, b) = (members[m % members.len()].iroh, members[n % members.len()].iroh);
                    self.net.drop_connection(a, b);
                }
                act => {
                    let (world, act) = (self.clone(), act.clone());
                    let task = tokio::spawn(async move {
                        let done = match timeout(ACTION_WAIT, world.act(&act)).await {
                            Ok(Ok(done)) => format!("ok {done}"),
                            Ok(Err(error)) => format!("failed: {error:#}"),
                            Err(_) => "timed out".into(),
                        };
                        world.note(format!("#{i} {done}"));
                    });
                    self.running.lock().unwrap().push(task);
                }
            }
        }
        if self.book.lock().unwrap().failure.is_none() {
            self.note("end".into());
            self.quiesce().await;
        }
        for i in 0..self.size() {
            self.stop(i).await;
        }
    }

    fn note(&self, text: String) {
        let line = format!("{} {text}", clock(elapsed()));
        if std::env::var_os("LMK_SIM_LOG").is_some() {
            eprintln!("{line}");
        }
        let mut book = self.book.lock().unwrap();
        book.trace.update(line.as_bytes());
        book.log.push(line);
    }

    fn fail(&self, kind: &'static str, text: String) {
        let mut book = self.book.lock().unwrap();
        if book.failure.is_none() {
            let failure = Failure { kind, at: elapsed(), text };
            book.log.push(format!("{} FAILED {failure}", clock(elapsed())));
            book.failure = Some(failure);
        }
    }

    fn client(&self, m: usize) -> Result<Client<Store>> {
        let members = self.members.lock().unwrap();
        members[m % members.len()].client.clone().context("down")
    }

    fn clients(&self) -> Vec<(usize, Client<Store>)> {
        let members = self.members.lock().unwrap();
        members.iter().enumerate().filter_map(|(i, m)| Some((i, m.client.clone()?))).collect()
    }

    fn size(&self) -> usize {
        self.members.lock().unwrap().len()
    }

    fn index(&self, m: usize) -> usize {
        m % self.size()
    }

    // Members' lives.

    async fn start(self: &Arc<Self>, i: usize) -> Result<()> {
        let (store, device, id) = {
            let members = self.members.lock().unwrap();
            (members[i].store.clone(), members[i].device.clone(), members[i].iroh)
        };
        let transport = self.net.bind(id);
        let fetch = Arc::new(Fetcher { world: Arc::downgrade(self), me: id });
        let network = Network::Other { transport: Arc::new(transport), fetch };
        let name = format!("m{i}");
        let config = lmk_node::Config {
            name: name.clone(),
            device: Some(device.clone()),
            relay: RELAY.parse()?,
            ca: Default::default(),
            home: None,
            files: None,
            disk: None,
            file_limit: 25 << 20,
            window: Window::default(),
            kinds: vec![CHAT.into(), DEVICES.into()],
        };
        let (node, mut events) = Node::start_on(store, config, network).await?;
        let peers = node.net().clone();
        self.peers.lock().unwrap().insert(id, peers.clone());
        self.net.listen(
            id,
            Arc::new(move |conn| {
                let peers = peers.clone();
                tokio::spawn(async move { peers.accept(conn).await });
            }),
        );
        let devices = Devices::new(node.clone(), device.clone());
        let (_, lines) = mpsc::unbounded_channel();
        let config = lmk_client::Config { name, device, membership: self.membership.clone() };
        let (client, mut told) = Client::new(node, config, Access::Here(devices), Arc::new(NoPlugins), lines);
        client.start().await;
        let (world, taking) = (Arc::downgrade(self), client.clone());
        let events = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if let (Event::Live { payload, .. }, Some(world)) = (&event, world.upgrade())
                    && let Some(nonce) = payload["nonce"].as_str()
                {
                    world.book.lock().unwrap().live.insert((i, nonce.to_owned()));
                }
                taking.event(event).await;
            }
        });
        let world = Arc::downgrade(self);
        let told = tokio::spawn(async move {
            while let Some(event) = told.recv().await {
                let Some(world) = world.upgrade() else { return };
                world.told(i, event);
            }
        });
        let renewing = client.clone();
        let renew = tokio::spawn(async move {
            loop {
                renewing.renew().await;
                sleep(Duration::from_secs(10)).await;
            }
        });
        self.note(format!("m{i} up as {}", id.fmt_short()));
        let mut members = self.members.lock().unwrap();
        members[i].client = Some(client);
        members[i].tasks = vec![events, told, renew];
        Ok(())
    }

    async fn stop(&self, i: usize) {
        let (client, tasks) = {
            let mut members = self.members.lock().unwrap();
            (members[i].client.take(), std::mem::take(&mut members[i].tasks))
        };
        for task in tasks {
            task.abort();
        }
        if let Some(client) = client {
            client.node().shutdown().await.ok();
        }
    }

    /// Stops a member as a crash does, leaving its storage as it stood.
    async fn crash(&self, i: usize) {
        self.stop(i).await;
        let id = {
            let mut members = self.members.lock().unwrap();
            members[i].store = members[i].store.snapshot();
            members[i].iroh
        };
        self.net.kill(id);
        self.peers.lock().unwrap().remove(&id);
    }

    async fn start_again(self: &Arc<Self>, i: usize) {
        if let Err(error) = self.start(i).await {
            self.fail("start", format!("m{i} did not start again: {error:#}"));
        }
    }

    async fn restart(self: &Arc<Self>, m: usize) {
        let i = self.index(m);
        self.crash(i).await;
        self.start_again(i).await;
    }

    fn online(&self, m: usize, online: bool) {
        let i = self.index(m);
        let id = self.members.lock().unwrap()[i].iroh;
        self.net.set_online(id, online);
    }

    fn partition(&self, mask: u32) {
        let members = self.members.lock().unwrap();
        let mut sides: BTreeMap<EndpointId, u8> = members.iter().enumerate().map(|(i, m)| (m.iroh, (mask >> i & 1) as u8)).collect();
        if let Membership::Serve { key, .. } = &self.membership {
            sides.insert(EndpointId::from_bytes(key.0.as_slice().try_into().unwrap()).unwrap(), (mask >> 31) as u8);
        }
        self.net.partition(&sides);
    }

    // Actions.

    async fn request(&self, m: usize, request: Value) -> Result<Value> {
        let request: Request = serde_json::from_value(request)?;
        self.client(m)?.request(request).await
    }

    fn group(&self, g: usize) -> Result<Bytes> {
        let book = self.book.lock().unwrap();
        ensure!(!book.groups.is_empty(), "no group yet");
        Ok(book.groups[g % book.groups.len()].clone())
    }

    fn identity(&self, m: usize) -> Result<Bytes> {
        Ok(self.client(m)?.device_state()?.identities.first().context("on no identity")?.0.id.clone())
    }

    fn device(&self, m: usize) -> Device {
        let i = self.index(m);
        self.members.lock().unwrap()[i].device.clone()
    }

    /// Of the members running and in a group, the one `m` picks.
    fn holder(&self, gid: &Bytes, m: usize) -> Result<usize> {
        let holders: Vec<usize> = self.clients().into_iter().filter(|(_, c)| c.node().groups().contains(gid)).map(|(i, _)| i).collect();
        ensure!(!holders.is_empty(), "no one running holds the group");
        Ok(holders[m % holders.len()])
    }

    async fn act(self: &Arc<Self>, act: &Act) -> Result<String> {
        match *act {
            Act::CreateIdentity { m } => {
                ensure!(self.identity(m).is_err(), "on an identity already");
                Ok(self.request(m, json!({ "cmd": "identity", "op": { "create": { "name": format!("id{}", self.index(m)) } } })).await?.to_string())
            }
            Act::LinkDevice { m, n } => {
                ensure!(self.index(m) != self.index(n) && self.identity(n).is_err(), "not a new device");
                let identity = self.identity(m)?;
                let link = self.request(m, json!({ "cmd": "invite", "identity": b64(&identity.0) })).await?;
                let link = link["link"].as_str().context("no link")?;
                Ok(self.request(n, json!({ "cmd": "join", "target": link })).await?.to_string())
            }
            Act::Invite { m, group, n, label, to } => {
                let mut invite = json!({ "cmd": "invite" });
                let m = match group {
                    Some(g) => {
                        let gid = self.group(g)?;
                        invite["group"] = json!(b64(&gid.0));
                        self.holder(&gid, m)?
                    }
                    None => {
                        invite["name"] = json!(format!("g{}", self.book.lock().unwrap().groups.len()));
                        m
                    }
                };
                if label {
                    invite["for"] = json!(format!("friend{}", self.index(n)));
                }
                if to {
                    invite["to"] = json!(b64(&self.identity(n)?.0));
                }
                let answer = self.request(m, invite).await?;
                let gid = Bytes(URL_SAFE_NO_PAD.decode(answer["group"].as_str().context("no group")?)?);
                {
                    let mut book = self.book.lock().unwrap();
                    if !book.groups.contains(&gid) {
                        book.groups.push(gid.clone());
                    }
                }
                let link = answer["link"].as_str().context("no link")?;
                let disruptions = self.book.lock().unwrap().disruptions;
                let joined = self.request(n, json!({ "cmd": "join", "target": link })).await?;
                self.introduces(m, n, gid, disruptions).await;
                Ok(joined["group"].to_string())
            }
            Act::JoinOpen { n, group } => {
                let gid = self.group(group)?;
                Ok(self.request(n, json!({ "cmd": "join", "target": b64(&gid.0) })).await?["group"].to_string())
            }
            Act::Send { m, group } => {
                let gid = self.group(group)?;
                let m = self.holder(&gid, m)?;
                let client = self.client(m)?;
                let after = client.tips(&gid, |_| true)?;
                let chat = Chat { text: format!("from m{m} at {}", elapsed()), to: Vec::new(), reply_to: None, urgent: false, attachment: None };
                let (id, answer) = client.send(&gid, chat, after).await?;
                let epoch = client.node().message(&id.0)?.context("a sent message is held")?.epoch;
                self.book.lock().unwrap().sent.push(Sent { by: m, group: gid, id, epoch });
                Ok(answer.to_string())
            }
            Act::Live { m, group } => {
                let gid = self.group(group)?;
                let m = self.holder(&gid, m)?;
                self.client(m)?.node().send_live(&gid.0, &json!({ "type": "sim", "from": m }), None)?;
                Ok(String::new())
            }
            Act::Rename { m, group } => {
                let gid = self.group(group)?;
                let m = self.holder(&gid, m)?;
                Ok(self.request(m, json!({ "cmd": "name", "group": b64(&gid.0), "name": format!("named at {}", elapsed()) })).await?.to_string())
            }
            Act::Open { m, group, n, close } => {
                let gid = self.group(group)?;
                let m = self.holder(&gid, m)?;
                let identity = self.identity(n)?;
                Ok(self.request(m, json!({ "cmd": "open", "group": b64(&gid.0), "identity": b64(&identity.0), "close": close })).await?.to_string())
            }
            Act::Leave { m, group } => {
                let gid = self.group(group)?;
                let m = self.holder(&gid, m)?;
                Ok(self.request(m, json!({ "cmd": "leave", "group": b64(&gid.0) })).await?.to_string())
            }
            Act::Remove { m, group, n } => {
                let gid = self.group(group)?;
                let m = self.holder(&gid, m)?;
                let me = self.client(m)?.node().key();
                let others: Vec<Bytes> = self.client(m)?.node().members(&gid.0)?.into_iter().map(|member| member.key).filter(|key| *key != me).collect();
                ensure!(!others.is_empty(), "alone in the group");
                let member = fp(&others[n % others.len()].0);
                Ok(self.request(m, json!({ "cmd": "remove", "group": b64(&gid.0), "member": member })).await?.to_string())
            }
            Act::TakeOff { m, n } => {
                let identity = self.identity(m)?;
                let m = self.index(m);
                let others: Vec<usize> = (0..self.size()).filter(|j| *j != m && self.identity(*j).is_ok_and(|id| id == identity)).collect();
                ensure!(!others.is_empty(), "the only device of its identity");
                let n = others[n % others.len()];
                let device = b64(&self.device(n).public());
                let answer = self.request(m, json!({ "cmd": "identity", "op": { "remove": { "identity": b64(&identity.0), "device": device } } })).await?;
                self.book.lock().unwrap().revoked.push((identity, n, elapsed()));
                Ok(answer.to_string())
            }
            _ => unreachable!("the world's own"),
        }
    }

    // Properties.

    /// A member that joins by an invite, as an identity its inviter holds a valid certificate of as it sees it join, is
    /// introduced to the group by its inviter, in a live message, unless an action in the meantime may have kept it away.
    async fn introduces(&self, m: usize, n: usize, gid: Bytes, disruptions: u64) {
        sleep(LIVE_WAIT).await;
        let (Ok(inviter), Ok(joiner)) = (self.client(m), self.client(n)) else { return };
        let (inviter, joiner) = (fp(&inviter.node().key().0), fp(&joiner.node().key().0));
        let book = self.book.lock().unwrap();
        if book.disruptions != disruptions
            || !book.vouched.contains(&(m, gid.clone(), joiner))
            || book.introduced.contains(&(self.index(n), gid.clone(), inviter))
        {
            return;
        }
        drop(book);
        self.fail("introduce", format!("m{} was not introduced to {} by m{m}, who invited it", self.index(n), b64(&gid.0)));
    }

    /// What a member was told; with what changes a group, members at one epoch are checked to agree.
    fn told(&self, i: usize, event: ClientEvent) {
        let text = serde_json::to_string(&event).unwrap();
        self.note(format!("m{i} {text}"));
        if !matches!(event, ClientEvent::Synced { .. }) {
            self.agreement();
        }
        match event {
            ClientEvent::Message { group, id, from, .. } => {
                let from = from.fp.unwrap_or_default();
                let left = self.book.lock().unwrap().left.get(&(i, group.clone(), from.clone())).copied();
                if let Some(left) = left
                    && elapsed() > left + REMOVED_GRACE
                {
                    self.fail("late", format!("m{i} took {id} from {from}, who left {} at {}", b64(&group.0), clock(left)));
                }
                if !self.book.lock().unwrap().seen.entry(i).or_default().insert(id.clone()) {
                    self.fail("duplicate", format!("m{i} was told of {id} twice"));
                }
            }
            ClientEvent::Left { group, member, .. } => {
                self.book.lock().unwrap().left.insert((i, group, member.fp.unwrap_or_default()), elapsed());
            }
            ClientEvent::Joined { group, member, .. } => {
                let mut book = self.book.lock().unwrap();
                let fp = member.fp.unwrap_or_default();
                if member.identity.is_some_and(|known| known.error.is_none()) {
                    book.vouched.insert((i, group.clone(), fp.clone()));
                }
                book.left.remove(&(i, group, fp));
            }
            ClientEvent::Introduced { group, by, .. } => {
                self.book.lock().unwrap().introduced.insert((i, group, by.fp.unwrap_or_default()));
            }
            ClientEvent::Refused { member, messages, .. } => {
                let mut book = self.book.lock().unwrap();
                for refusal in messages {
                    book.refusals.insert((i, hex::encode(&refusal.id.0), member.fp.clone().unwrap_or_default()));
                }
            }
            _ => {}
        }
    }

    /// Checks a frame on a `peer` stream against the serving rules, as its sender sees them as it sends it.
    fn inspect(&self, from: EndpointId, to: EndpointId, bytes: &[u8]) {
        let Ok(frame) = serde_json::from_slice::<Frame>(bytes) else { return };
        let sender = {
            let members = self.members.lock().unwrap();
            members.iter().position(|m| m.iroh == from).and_then(|i| Some((i, members[i].client.clone()?)))
        };
        let Some((i, client)) = sender else { return };
        let name = |id: EndpointId| self.members.lock().unwrap().iter().position(|m| m.iroh == id).map_or_else(|| id.fmt_short().to_string(), |j| format!("m{j}"));
        if std::env::var_os("LMK_SIM_FRAMES").is_some() {
            let text: String = String::from_utf8_lossy(bytes).chars().take(300).collect();
            self.book.lock().unwrap().log.push(format!("{} m{i} -> {} {text}", clock(elapsed()), name(to)));
        }
        let node = client.node();
        let groups: Vec<(&str, Bytes)> = match &frame {
            Frame::Hello { groups, .. } => groups.iter().map(|hello| ("hello", hello.group.clone())).collect(),
            Frame::Entries { log, .. } if node.groups().contains(log) => vec![("entries", log.clone())],
            Frame::Reconcile { group, .. } => vec![("reconcile", group.clone())],
            Frame::Messages { group, .. } => vec![("messages", group.clone())],
            Frame::Receipt { group, .. } => vec![("receipt", group.clone())],
            Frame::State { group, .. } => vec![("state", group.clone())],
            Frame::Want { group, .. } => vec![("want", group.clone())],
            Frame::Have { group, files } if !files.is_empty() => vec![("have", group.clone())],
            _ => Vec::new(),
        };
        for (what, gid) in groups {
            if !node.serves(&gid.0, &to) {
                self.fail("served", format!("m{i} sent {} {what} of {}, which it does not serve it", name(to), b64(&gid.0)));
            }
        }
    }

    /// Members at one epoch of a group agree on its members and settings.
    fn agreement(&self) {
        let mut seen: BTreeMap<(Bytes, u64), (usize, Vec<Bytes>, String)> = BTreeMap::new();
        for (i, client) in self.clients() {
            let node = client.node();
            for gid in node.groups() {
                let (Ok(epoch), Ok(members), Ok(settings)) = (node.epoch(&gid.0), node.members(&gid.0), node.settings(&gid.0)) else { continue };
                let mut keys: Vec<Bytes> = members.into_iter().map(|m| m.key).collect();
                keys.sort();
                let settings = serde_json::to_string(&settings).unwrap();
                match seen.get(&(gid.clone(), epoch)) {
                    Some((j, theirs, their_settings)) if *theirs != keys || *their_settings != settings => {
                        self.fail("agreement", format!("m{i} and m{j} disagree on {} at epoch {epoch}", b64(&gid.0)));
                    }
                    Some(_) => {}
                    None => drop(seen.insert((gid, epoch), (i, keys, settings))),
                }
            }
        }
    }

    /// Every member online and reachable, then after a while: members of a group agree on it, hold the same messages,
    /// and get each other's live messages; senders are told of refusals; devices taken off have left.
    async fn quiesce(self: &Arc<Self>) {
        let running = std::mem::take(&mut *self.running.lock().unwrap());
        for task in running {
            task.await.ok();
        }
        let start = elapsed();
        self.partition(0);
        for m in 0..self.size() {
            self.online(m, true);
        }
        sleep(CONVERGE).await;
        self.agreement();
        let groups = self.converged();
        self.revoked(start);
        self.live(&groups).await;
        if let Some(panic) = PANICS.with_borrow(|panics| panics.first().cloned()) {
            self.fail("panic", panic);
        }
    }

    /// Each group's members, as its latest epoch shows them, checked to have converged; with each one's node.
    fn converged(&self) -> Vec<(Bytes, Holders)> {
        let clients = self.clients();
        let gids: BTreeSet<Bytes> = clients.iter().flat_map(|(_, c)| c.node().groups()).collect();
        let mut groups = Vec::new();
        for gid in gids {
            let holders: Vec<(usize, Node<Store>)> = clients.iter().filter(|(_, c)| c.node().groups().contains(&gid)).map(|(i, c)| (*i, c.node().clone())).collect();
            let Some((latest, keys)) = holders
                .iter()
                .filter_map(|(_, node)| Some((node.epoch(&gid.0).ok()?, node.members(&gid.0).ok()?.into_iter().map(|m| m.key).collect::<Vec<_>>())))
                .max_by_key(|(epoch, _)| *epoch)
            else {
                continue;
            };
            let group = b64(&gid.0);
            let (inside, stale): (Vec<_>, Vec<_>) = holders.into_iter().partition(|(_, node)| keys.contains(&node.key()));
            for (i, _) in &stale {
                self.fail("convergence", format!("m{i} still holds {group}, whose epoch {latest} it is not in"));
            }
            for (i, node) in &inside {
                if node.epoch(&gid.0).ok() != Some(latest) {
                    self.fail("convergence", format!("m{i} is at epoch {:?} of {group}, not {latest}", node.epoch(&gid.0).ok()));
                }
            }
            for (a, x) in &inside {
                for (b, y) in &inside {
                    if a == b || !x.serves(&gid.0, &y.net().id()) || !y.serves(&gid.0, &x.net().id()) {
                        continue;
                    }
                    let floor = x.joined(&gid.0).unwrap_or(0).max(y.joined(&gid.0).unwrap_or(0));
                    for message in x.messages(&gid.0).unwrap_or_default().into_iter().filter(|m| m.epoch >= floor) {
                        if y.message(&message.id.0).ok().flatten().is_none() && !y.given_up(&gid.0, &message.id.0) {
                            self.fail("convergence", format!("m{b} lacks {} of {group}, which m{a} holds", hex::encode(&message.id.0)));
                        }
                    }
                }
            }
            self.delivered(&gid, &inside);
            groups.push((gid, inside));
        }
        groups
    }

    /// A member that gave up a message an action sent told its sender, if the sender is still in the group.
    fn delivered(&self, gid: &Bytes, inside: &[(usize, Node<Store>)]) {
        let book = self.book.lock().unwrap();
        let sent: Vec<&Sent> = book.sent.iter().filter(|s| s.group == *gid && inside.iter().any(|(i, _)| *i == s.by)).collect();
        let mut missing = Vec::new();
        for s in sent {
            for (r, node) in inside.iter().filter(|(r, _)| *r != s.by) {
                if node.joined(&gid.0).is_ok_and(|joined| joined <= s.epoch) && node.given_up(&gid.0, &s.id.0) {
                    let refuser = fp(&node.key().0);
                    if !book.refusals.contains(&(s.by, hex::encode(&s.id.0), refuser)) {
                        missing.push(format!("m{} was not told that m{r} refused {}", s.by, hex::encode(&s.id.0)));
                    }
                }
            }
        }
        drop(book);
        for text in missing {
            self.fail("delivery", text);
        }
    }

    /// A device taken off its identity long enough ago that every member holding its sessions' certificates has read
    /// the key log entry naming it: its sessions are in no group with such a member.
    fn revoked(&self, start: u64) {
        let revoked: Vec<(Bytes, usize, u64)> = self.book.lock().unwrap().revoked.clone();
        let clients = self.clients();
        for (identity, n, at) in revoked.into_iter().filter(|(_, _, at)| at + KEYS_READ <= start) {
            let key = Bytes(self.device(n).public().to_vec());
            for (i, client) in &clients {
                let node = client.node();
                for gid in node.groups() {
                    let members = node.members(&gid.0).unwrap_or_default();
                    let held = members.iter().find(|m| m.key == key).and_then(|m| m.identity.as_ref()).filter(|claim| {
                        claim.identity.id == identity
                            && !matches!(claim.error.as_deref(), Some("it has shown no certificate of its identity" | "its identity's key could not be read yet"))
                    });
                    if held.is_some() && *i != n {
                        self.fail("revocation", format!("m{n}, taken off {} at {}, is still in {} as m{i} sees it", b64(&identity.0), clock(at), b64(&gid.0)));
                    }
                }
            }
        }
    }

    /// Each member of a group sends a live message; every other that both sides hold valid certificates of takes it.
    async fn live(&self, groups: &[(Bytes, Holders)]) {
        let mut expected = Vec::new();
        for (gid, inside) in groups {
            for (s, sender) in inside {
                let nonce = format!("{}-m{s}-{}", elapsed(), b64(&gid.0));
                if sender.send_live(&gid.0, &json!({ "type": "sim", "nonce": nonce }), None).is_err() {
                    continue;
                }
                for (r, receiver) in inside {
                    if r != s && sender.serves(&gid.0, &receiver.net().id()) && receiver.serves(&gid.0, &sender.net().id()) {
                        let connected = sender.net().connected().contains(&receiver.net().id());
                        expected.push((*s, *r, nonce.clone(), connected));
                    }
                }
            }
        }
        sleep(LIVE_WAIT).await;
        let book = self.book.lock().unwrap();
        let lost: Vec<String> = expected
            .into_iter()
            .filter(|(_, r, nonce, _)| !book.live.contains(&(*r, nonce.clone())))
            .map(|(s, r, nonce, connected)| format!("m{r} did not take m{s}'s live message {nonce}, sent {}connected", if connected { "" } else { "not " }))
            .collect();
        drop(book);
        for text in lost {
            self.fail("live", text);
        }
    }
}

/// Files over the simulated network: whole, from a holder reachable now, by its rules.
struct Fetcher {
    world: Weak<World>,
    me: EndpointId,
}

impl Fetch for Fetcher {
    fn fetch(&self, holder: EndpointId, hash: [u8; 32]) -> BoxFuture<Result<Vec<u8>>> {
        let (world, me) = (self.world.clone(), self.me);
        Box::pin(async move {
            sleep(Duration::from_millis(200)).await;
            let world = world.upgrade().context("the world ended")?;
            ensure!(world.net.path(me, holder), "{} is unreachable", holder.fmt_short());
            let peers = world.peers.lock().unwrap().get(&holder).cloned().context("not running")?;
            peers.upload(me, hash).await
        })
    }
}
