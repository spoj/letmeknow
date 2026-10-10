//! The world: members on the client core with the devices kind on their own node, as a browser runs it, one in-memory
//! membership service, the simulated network between them, and the record of what they do (`trace`), which the
//! properties check at the end of each quiet period.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
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
use lmk_node::lmk_core::provider::{MemoryProvider, Provider};
use lmk_node::{Event, Judgement, Node, Observation};
use lmk_proto::Bytes;
use lmk_proto::entry::{Entry, signed};
use lmk_proto::group::{CHAT, DEVICES, Service as Membership};
use n0_future::boxed::BoxFuture;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

use crate::net::{Change, Net, Wire};
use crate::props::{self, CONVERGE};
use crate::trace::{Answer, Dropped, Frame, Leaf, Obs, Saved, Trace, Verdict, View, What};
use crate::{Act, Action, Forgery, Options, Outcome, Output, clock};

const RELAY: &str = "https://relay.sim.invalid";
/// When simulated time starts: 2026-01-01, in milliseconds since the Unix epoch.
const BASE: u64 = 1_767_225_600_000;
/// How long an action may take.
const ACTION_WAIT: Duration = Duration::from_secs(300);

thread_local! {
    static START: Cell<Option<Instant>> = const { Cell::new(None) };
    static PANICS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// The simulated clock, in milliseconds since the Unix epoch, in a run.
pub(crate) fn now() -> Option<u64> {
    START.get().map(|start| BASE + start.elapsed().as_millis() as u64)
}

fn elapsed() -> u64 {
    now().expect("a simulation runs") - BASE
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
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

/// A member's storage, which outlives its crashes: a browser's records; and whether a step is under way on it.
#[derive(Clone, Default)]
struct Store(Arc<MemoryProvider>, Arc<AtomicBool>);

impl Store {
    /// A copy, as storage stands when a session crashes, for the next one to start from: as of its last committed step,
    /// which a crash never interrupts, as steps hold the node's lock and do not wait.
    fn snapshot(&self) -> Store {
        assert!(!self.1.load(Ordering::Relaxed), "a snapshot of storage within a step");
        Store(Arc::new(MemoryProvider::load(self.0.records())), Arc::default())
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

    fn begin(&self) -> Result<()> {
        self.1.store(true, Ordering::Relaxed);
        self.0.begin()
    }

    fn commit(&self) -> Result<()> {
        self.1.store(false, Ordering::Relaxed);
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
    /// Its storage as it stood when it crashed, if it crashed before it stopped.
    frozen: Option<Store>,
    /// How many times it started.
    starts: u64,
}

/// What the world keeps of a run: the groups made, the trace, the log and its hash, and the first failure.
#[derive(Default)]
struct Book {
    groups: Vec<Bytes>,
    hash: Sha256,
    log: Vec<String>,
    failure: Option<Failure>,
    trace: Trace,
    /// Each member's roster of each group as last recorded.
    rosters: BTreeMap<(usize, Bytes), (u64, Vec<Leaf>, String)>,
    /// Members to crash after they next write this.
    crash: BTreeMap<usize, Output>,
    /// The positions of forged messages the world pushed.
    forged: BTreeSet<(Bytes, u64)>,
}

struct World {
    net: Net,
    membership: Membership,
    service: EndpointId,
    /// The service's store, as an attacker writing to it directly.
    outsider: lmk_membership::store::Store,
    members: Mutex<Vec<Member>>,
    /// Each member's peers, to which another member's fetch of a file goes.
    peers: Mutex<BTreeMap<EndpointId, lmk_net::Net>>,
    book: Mutex<Book>,
    /// Actions under way.
    running: Mutex<Vec<JoinHandle<()>>>,
    /// Restarts and crashes to come, of members down or woken.
    later: Mutex<Vec<JoinHandle<()>>>,
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
    lmk_proto::clock::set(|| now().expect("a simulation runs"));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().unwrap();
    let outcome = runtime.block_on(async {
        START.set(Some(Instant::now()));
        let world = World::new(seed, options);
        world.drive(actions).await;
        let book = std::mem::take(&mut *world.book.lock().unwrap());
        let mut hash = book.hash;
        hash.update(world.net.trace());
        Outcome { trace: hash.finalize().into(), failure: book.failure, log: book.log }
    });
    drop(runtime);
    START.set(None);
    outcome
}

impl World {
    fn new(seed: u64, options: Options) -> Arc<Self> {
        static RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let net = Net::new(seed);
        let secret = iroh::SecretKey::from_bytes(&lmk_proto::random::random());
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret.to_bytes());
        let path = format!("file:lmk-sim-{}-{}?mode=memory&cache=shared", std::process::id(), RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        let store = lmk_membership::store::Store::open(std::path::Path::new(&path), signing.clone()).unwrap();
        let outsider = lmk_membership::store::Store::open(std::path::Path::new(&path), signing).unwrap();
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
                Member { device, store, iroh, client: None, tasks: Vec::new(), frozen: None, starts: 0 }
            })
            .collect();
        let world = Arc::new(World {
            net,
            membership,
            service: secret.public(),
            outsider,
            members: Mutex::new(members),
            peers: Mutex::default(),
            book: Mutex::default(),
            running: Mutex::default(),
            later: Mutex::default(),
        });
        let inspecting = Arc::downgrade(&world);
        world.net.inspect(Arc::new(move |wire, frame| {
            if let Some(world) = inspecting.upgrade() {
                world.inspect(wire, frame);
            }
        }));
        world
    }

    async fn drive(self: &Arc<Self>, actions: &[Action]) {
        for i in 0..self.size() {
            self.start_again(i).await;
        }
        let mut last = 0;
        for (i, action) in actions.iter().enumerate() {
            sleep(Duration::from_millis(action.at - last)).await;
            last = action.at;
            if self.book.lock().unwrap().failure.is_some() {
                break;
            }
            self.note(format!("#{i} {:?}", action.act));
            match action.act {
                Act::Quiesce => self.quiesce().await,
                Act::Settle { ms } => sleep(Duration::from_millis(ms)).await,
                Act::Offline { m } => {
                    self.disrupt(&[m]);
                    self.online(m, false);
                }
                Act::Online { m } => {
                    self.online(m, true);
                    self.reconnected(self.index(m));
                }
                Act::Restart { m } => {
                    let i = self.index(m);
                    self.crash(i).await;
                    self.start_again(i).await;
                }
                Act::Down { m, ms } => self.down(self.index(m), ms).await,
                Act::Wake { m, ms } => self.wake(self.index(m), ms).await,
                Act::Partition { mask } => {
                    self.disrupt(&(0..self.size()).collect::<Vec<_>>());
                    self.partition(mask);
                }
                Act::Heal => self.heal(),
                Act::Drop { m, n } => {
                    self.disrupt(&[m, n]);
                    let (a, b) = (self.iroh(m), self.iroh(n));
                    self.net.drop_connection(a, b);
                }
                Act::LoseAnswer { m } => {
                    self.disrupt(&[m]);
                    self.net.lose_answer(self.service, self.iroh(m));
                }
                Act::CrashAfter { m, what } => drop(self.book.lock().unwrap().crash.insert(self.index(m), what)),
                Act::Sleep { ms } => {
                    for i in 0..self.size() {
                        self.crash(i).await;
                    }
                    sleep(Duration::from_millis(ms)).await;
                    for i in 0..self.size() {
                        if self.members.lock().unwrap()[i].client.is_none() {
                            self.start_again(i).await;
                        }
                    }
                }
                Act::Forge { m, group, what } => {
                    let done = self.forge(m, group, what).map_or_else(|error| format!("failed: {error:#}"), |done| format!("ok {done}"));
                    self.note(format!("#{i} {done}"));
                }
                ref act => {
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
        for task in std::mem::take(&mut *self.later.lock().unwrap()) {
            task.abort();
        }
        if self.book.lock().unwrap().failure.is_none() {
            self.note("end".into());
            for i in 0..self.size() {
                if self.members.lock().unwrap()[i].client.is_none() {
                    self.start_again(i).await;
                }
            }
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
        book.hash.update(line.as_bytes());
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

    fn observe(&self, what: What) {
        self.observe_at(elapsed(), what);
    }

    fn observe_at(&self, at: u64, what: What) {
        self.book.lock().unwrap().trace.0.push(Obs { at, what });
    }

    fn disrupt(&self, members: &[usize]) {
        for m in members {
            self.observe(What::Disrupted { m: self.index(*m) });
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

    /// How many times a member started, if it runs: a session that stops answers nothing more.
    fn starts(&self, m: usize) -> Option<u64> {
        let members = self.members.lock().unwrap();
        let member = &members[m % members.len()];
        member.client.is_some().then_some(member.starts)
    }

    fn size(&self) -> usize {
        self.members.lock().unwrap().len()
    }

    fn index(&self, m: usize) -> usize {
        m % self.size()
    }

    fn iroh(&self, m: usize) -> EndpointId {
        let members = self.members.lock().unwrap();
        members[m % members.len()].iroh
    }

    fn member_at(&self, id: EndpointId) -> Option<usize> {
        self.members.lock().unwrap().iter().position(|m| m.iroh == id)
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
        let observing = Arc::downgrade(self);
        let observe: lmk_node::Observe = Arc::new(move |observation| {
            if let Some(world) = observing.upgrade() {
                world.observe(observed(i, observation));
            }
        });
        let config = lmk_node::Config {
            name: name.clone(),
            device: Some(device.clone()),
            relay: RELAY.parse()?,
            ca: Default::default(),
            home: None,
            files: None,
            disk: None,
            file_limit: 25 << 20,
            kinds: vec![CHAT.into(), DEVICES.into()],
            durable: None,
            observe: Some(observe),
        };
        self.observe(What::Up { m: i });
        let held: Vec<Bytes> = self.book.lock().unwrap().rosters.keys().filter(|(m, _)| *m == i).map(|(_, gid)| gid.clone()).collect();
        for gid in held {
            if let Some(saved) = lmk_node::saved(&store, &gid.0)? {
                self.observe(What::Restored { m: i, group: gid, saved: restored(saved) });
            }
        }
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
        let saved = Arc::downgrade(self);
        let save = Arc::new(move |device: &Device| {
            if let Some(world) = saved.upgrade() {
                world.members.lock().unwrap()[i].device = device.clone();
            }
            Ok(())
        });
        let devices = Devices::new(node.clone(), device.clone(), save);
        let (_, lines) = mpsc::unbounded_channel();
        let config = lmk_client::Config { name, device, membership: self.membership.clone() };
        let (client, mut told) = Client::new(node, config, Access::Here(devices), Arc::new(NoPlugins), lines);
        client.start().await;
        let (world, taking) = (Arc::downgrade(self), client.clone());
        let events = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if let Some(world) = world.upgrade() {
                    world.event(i, taking.node(), &event);
                }
                taking.event(event).await;
            }
        });
        let (world, telling) = (Arc::downgrade(self), client.clone());
        let told = tokio::spawn(async move {
            while let Some(event) = told.recv().await {
                let Some(world) = world.upgrade() else { return };
                world.told(i, telling.node(), event);
            }
        });
        self.note(format!("m{i} up as {}", id.fmt_short()));
        let mut members = self.members.lock().unwrap();
        members[i].client = Some(client);
        members[i].tasks = vec![events, told];
        members[i].starts += 1;
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

    /// Stops a member as a crash does, leaving its storage as it stood, or as it stood when it was frozen.
    async fn crash(&self, i: usize) {
        if self.members.lock().unwrap()[i].client.is_none() {
            return;
        }
        self.stop(i).await;
        let id = {
            let mut members = self.members.lock().unwrap();
            let member = &mut members[i];
            member.store = member.frozen.take().unwrap_or_else(|| member.store.snapshot());
            member.iroh
        };
        self.net.kill(id);
        self.peers.lock().unwrap().remove(&id);
        self.observe(What::Down { m: i });
    }

    async fn start_again(self: &Arc<Self>, i: usize) {
        if let Err(error) = self.start(i).await {
            self.fail("start", format!("m{i} did not start: {error:#}"));
        }
    }

    /// Crashes a member now, and starts it again later if it is down then.
    async fn down(self: &Arc<Self>, i: usize, ms: u64) {
        self.crash(i).await;
        let world = self.clone();
        let task = tokio::spawn(async move {
            sleep(Duration::from_millis(ms)).await;
            if world.members.lock().unwrap()[i].client.is_none() {
                world.start_again(i).await;
            }
        });
        self.later.lock().unwrap().push(task);
    }

    /// Starts a member that is down, and crashes it again later unless it started since.
    async fn wake(self: &Arc<Self>, i: usize, ms: u64) {
        if self.members.lock().unwrap()[i].client.is_some() {
            return;
        }
        self.start_again(i).await;
        let starts = self.members.lock().unwrap()[i].starts;
        let world = self.clone();
        let task = tokio::spawn(async move {
            sleep(Duration::from_millis(ms)).await;
            if world.members.lock().unwrap()[i].starts == starts {
                world.crash(i).await;
            }
        });
        self.later.lock().unwrap().push(task);
    }

    fn online(&self, m: usize, online: bool) {
        self.net.set_online(self.iroh(m), online);
    }

    fn heal(&self) {
        self.partition(0);
        for m in 0..self.size() {
            self.reconnected(m);
        }
    }

    /// Records that a member's paths are whole, if it reaches the service now.
    fn reconnected(&self, m: usize) {
        if self.net.path(self.iroh(m), self.service) {
            self.observe(What::Reconnected { m });
        }
    }

    fn partition(&self, mask: u32) {
        let members = self.members.lock().unwrap();
        let mut sides: BTreeMap<EndpointId, u8> = members.iter().enumerate().map(|(i, m)| (m.iroh, (mask >> i & 1) as u8)).collect();
        sides.insert(self.service, (mask >> 31) as u8);
        self.net.partition(&sides);
    }

    // Observations.

    /// Records a member's roster of a group if it changed since it was last recorded.
    fn sample(&self, i: usize, node: &Node<Store>, gid: &Bytes) {
        let (Ok(epoch), Ok(members), Ok(settings)) = (node.epoch(&gid.0), node.members(&gid.0), node.settings(&gid.0)) else { return };
        let mut leaves: Vec<Leaf> = members
            .into_iter()
            .map(|member| {
                // In a devices group, a member's key is its device's; a claim counts as shown once its key log is read.
                let shown = member.identity.as_ref().filter(|claim| claim.error.as_deref() != Some("its identity's key log could not be read yet"));
                let identity = shown.map(|claim| claim.identity.id.clone());
                let device = shown.map(|_| member.key.clone());
                Leaf { key: member.key, iroh: member.iroh, identity, device }
            })
            .collect();
        leaves.sort();
        let settings = serde_json::to_string(&settings).unwrap();
        let mut book = self.book.lock().unwrap();
        let state = (epoch, leaves, settings);
        if book.rosters.get(&(i, gid.clone())) == Some(&state) {
            return;
        }
        book.rosters.insert((i, gid.clone()), state.clone());
        let (epoch, leaves, settings) = state;
        book.trace.0.push(Obs { at: elapsed(), what: What::Roster { m: i, key: node.key_in(&gid.0), group: gid.clone(), epoch, leaves, settings } });
    }

    fn event(&self, i: usize, node: &Node<Store>, event: &Event) {
        if let Some(gid) = event.group() {
            self.sample(i, node, gid);
        }
    }

    fn told(&self, i: usize, node: &Node<Store>, event: ClientEvent) {
        self.note(format!("m{i} {}", serde_json::to_string(&event).unwrap()));
        match &event {
            ClientEvent::Message { group, position, missing, .. } => {
                self.observe(What::Shown { m: i, group: group.clone(), position: *position, missing: missing.iter().copied().collect() })
            }
            ClientEvent::Sent { group, id, position } => {
                self.observe(What::Sent { m: i, group: group.clone(), id: Bytes(hex::decode(id).unwrap()), position: *position })
            }
            _ => {}
        }
        for gid in node.groups() {
            self.sample(i, node, &gid);
        }
    }

    /// Every frame written: what it says of a group, from whom to whom; and a member to crash after it.
    fn inspect(self: &Arc<Self>, wire: &Wire, bytes: &[u8]) {
        let name = |id: EndpointId| self.member_at(id).map_or_else(|| "service".into(), |j| format!("m{j}"));
        if std::env::var_os("LMK_SIM_FRAMES").is_some() {
            let text: String = String::from_utf8_lossy(bytes).chars().take(300).collect();
            self.book.lock().unwrap().log.push(format!("{} {} -> {} {text}", clock(elapsed()), name(wire.from), name(wire.to)));
        }
        let Some(i) = self.member_at(wire.from) else { return };
        let Some(client) = self.members.lock().unwrap()[i].client.clone() else { return };
        let node = client.node();
        let mut output = None;
        if wire.to == self.service {
            if let Ok(lmk_proto::membership::Request::Append { log, entries }) = serde_json::from_slice(bytes) {
                self.observe(What::Out { m: i, to: None, group: log, frame: Frame::Append { entries: entries.iter().map(|entry| sha(&entry.0)).collect() } });
                output = Some(Output::Append);
            }
        } else if wire.peer
            && let Ok(frame) = serde_json::from_slice::<lmk_proto::peer::Frame>(bytes)
        {
            let to = self.member_at(wire.to);
            for (gid, frame) in frames(node, &frame) {
                if let Frame::Messages { positions } = &frame
                    && positions.iter().all(|p| self.book.lock().unwrap().forged.contains(&(gid.clone(), *p)))
                {
                    continue;
                }
                self.sample(i, node, &gid);
                self.observe(What::Out { m: i, to: Some(Bytes(wire.to.as_bytes().to_vec())), group: gid.clone(), frame: frame.clone() });
                if let Some(to) = to {
                    self.observe_at(elapsed() + wire.delay.as_millis() as u64, What::In { m: to, from: i, conn: wire.conn, group: gid, frame });
                }
                output = Some(Output::Frame);
            }
        } else if let Ok(admitted) = serde_json::from_slice::<lmk_proto::peer::Admitted>(bytes) {
            let adds = |gid: &Bytes| {
                let page = self.outsider.read(&gid.0, admitted.position - 1, 1).ok().flatten();
                let entry = page.and_then(|page| page.entries.into_iter().next());
                entry.is_some_and(|entry| matches!(Entry::parse(&entry.0), Ok(Entry::Commit { welcome: Some(welcome), .. }) if welcome == admitted.welcome.0))
            };
            if let Some(gid) = node.groups().into_iter().find(adds) {
                self.observe(What::Out { m: i, to: Some(Bytes(wire.to.as_bytes().to_vec())), group: gid, frame: Frame::Admitted { position: admitted.position } });
            }
            output = Some(Output::Admitted);
        }
        let armed = self.book.lock().unwrap().crash.get(&i).copied();
        if let (Some(what), Some(wrote)) = (armed, output)
            && std::mem::discriminant(&what) == std::mem::discriminant(&wrote)
        {
            self.book.lock().unwrap().crash.remove(&i);
            self.freeze(i);
        }
    }

    /// Crashes a member now, as it writes: its storage as it stands and its endpoint dead; it stops and starts again
    /// after.
    fn freeze(self: &Arc<Self>, i: usize) {
        let id = {
            let mut members = self.members.lock().unwrap();
            let member = &mut members[i];
            member.frozen = Some(member.store.snapshot());
            member.iroh
        };
        self.net.kill(id);
        self.note(format!("m{i} crashes as it writes"));
        let world = self.clone();
        tokio::spawn(async move {
            world.crash(i).await;
            world.start_again(i).await;
        });
    }

    /// The connections' changes so far, into the trace.
    fn connections(&self) {
        let now = Instant::now();
        for (at, conn, [a, b], change) in self.net.changes() {
            let at = elapsed() - (now - at).as_millis() as u64;
            let what = match change {
                Change::Opened => {
                    let (Some(a), Some(b)) = (self.member_at(a), self.member_at(b)) else { continue };
                    What::Connected { conn, a, b }
                }
                Change::Cut => What::Cut { conn },
                Change::Closed => What::Closed { conn },
            };
            self.observe_at(at, what);
        }
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

    /// `m` if it runs and holds the group, else the running member that holds it that `m` picks.
    fn holder(&self, gid: &Bytes, m: usize) -> Result<usize> {
        let holders: Vec<usize> = self.clients().into_iter().filter(|(_, c)| c.node().groups().contains(gid)).map(|(i, _)| i).collect();
        ensure!(!holders.is_empty(), "no one running holds the group");
        let m = self.index(m);
        Ok(if holders.contains(&m) { m } else { holders[m % holders.len()] })
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
                let joined = self.request(n, json!({ "cmd": "join", "target": link })).await?;
                let keys = self.client(n)?.device_state()?.keys;
                let device = keys.into_iter().find(|(id, _)| *id == identity).context("no key on the identity")?.1;
                self.observe(What::Device { identity, device, listed: true });
                Ok(joined.to_string())
            }
            Act::Invite { m, group, n, label, to, wait, race } => {
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
                if let Some(to) = to {
                    invite["to"] = json!(b64(&self.identity(to)?.0));
                }
                let answer = self.request(m, invite).await?;
                let gid = Bytes(URL_SAFE_NO_PAD.decode(answer["group"].as_str().context("no group")?)?);
                {
                    let mut book = self.book.lock().unwrap();
                    if !book.groups.contains(&gid) {
                        book.groups.push(gid.clone());
                    }
                }
                let link = answer["link"].as_str().context("no link")?.to_owned();
                sleep(Duration::from_millis(wait)).await;
                let racing = race.map(|r| {
                    let (world, link) = (self.clone(), link.clone());
                    tokio::spawn(async move { world.join(r, &link).await })
                });
                let joined = self.join(n, &link).await;
                if let (Some(racing), Some(r)) = (racing, race) {
                    let raced = racing.await?;
                    self.note(format!("m{} raced: {}", self.index(r), raced.as_ref().map_or_else(|e| format!("{e:#}"), Value::to_string)));
                }
                Ok(joined?["group"].to_string())
            }
            Act::JoinOpen { n, group } => {
                let gid = self.group(group)?;
                Ok(self.join(n, &b64(&gid.0)).await?["group"].to_string())
            }
            Act::Send { m, group } => {
                let gid = self.group(group)?;
                let m = self.holder(&gid, m)?;
                let client = self.client(m)?;
                let after = client.tips(&gid, |_| true)?;
                let chat = Chat { text: format!("from m{m} at {}", elapsed()), to: Vec::new(), reply_to: None, urgent: false, attachment: None };
                let starts = self.starts(m);
                let sent = client.send(&gid, chat, after).await;
                ensure!(self.starts(m) == starts, "m{m} stopped before it answered");
                let (id, answer) = match &sent {
                    Ok((_, answer)) => {
                        let id = Bytes(hex::decode(answer["id"].as_str().context("no id")?)?);
                        (id, answer["position"].as_u64().map_or(Answer::Pending, Answer::Position))
                    }
                    Err(error) => (Bytes::default(), Answer::Failed(format!("{error:#}"))),
                };
                self.observe(What::Send { m, group: gid, id, answer });
                Ok(sent?.1.to_string())
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
                let answer = self.request(m, json!({ "cmd": "leave", "group": b64(&gid.0) })).await?;
                self.observe(What::Leaving { m, group: gid });
                Ok(answer.to_string())
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
                let keys = self.client(n)?.device_state()?.keys;
                let device = keys.into_iter().find(|(id, _)| *id == identity).context("no key on the identity")?.1;
                let answer = self.request(m, json!({ "cmd": "identity", "op": { "remove": { "identity": b64(&identity.0), "device": b64(&device.0) } } })).await?;
                self.observe(What::Device { identity, device, listed: false });
                Ok(answer.to_string())
            }
            Act::PushState { m, group } => {
                let gid = self.group(group)?;
                let clients = self.clients();
                let current: Vec<Bytes> = clients.iter().filter_map(|(_, c)| c.node().members(&gid.0).ok()).max_by_key(Vec::len).unwrap_or_default().into_iter().map(|member| member.key).collect();
                let removed: Vec<&(usize, Client<Store>)> = clients.iter().filter(|(_, c)| c.node().groups().contains(&gid) && !current.contains(&c.node().key())).collect();
                ensure!(!removed.is_empty(), "no member removed holds the group");
                let (j, client) = removed[m % removed.len()];
                for key in &current {
                    client.node().hand_state(&gid.0, &fp(&key.0), b"pushed by a removed member".to_vec()).await.ok();
                }
                Ok(format!("by m{j}"))
            }
            _ => unreachable!("the world's own"),
        }
    }

    /// `m` joins by a link or an opening, answered with the group, where it starts.
    async fn join(&self, m: usize, target: &str) -> Result<Value> {
        let starts = self.starts(m);
        let joined = self.request(m, json!({ "cmd": "join", "target": target })).await?;
        ensure!(self.starts(m) == starts, "m{m} stopped before it answered");
        let gid = Bytes(URL_SAFE_NO_PAD.decode(joined["group"].as_str().context("no group")?)?);
        let node = self.client(m)?.node().clone();
        let start = node.positions(&gid.0)?.start;
        self.observe(What::Join { m: self.index(m), key: node.key_in(&gid.0), group: gid, answer: Answer::Position(start) });
        Ok(joined)
    }

    /// An attacker's entry in a group's log, by the service's store directly; a forged message's ciphertext pushed to
    /// the members, as the member whose state it copied would.
    fn forge(&self, m: usize, g: usize, what: Forgery) -> Result<String> {
        let gid = self.group(g)?;
        let (entry, push) = match what {
            Forgery::Junk => (lmk_proto::random::random::<64>().to_vec(), None),
            Forgery::Replay => {
                let page = self.outsider.read(&gid.0, 0, usize::MAX)?.context("no log")?;
                (page.entries.get(m % page.entries.len().max(1)).context("an empty log")?.0.clone(), None)
            }
            Forgery::Foreign => {
                let groups = self.book.lock().unwrap().groups.clone();
                let other = groups.iter().find(|other| **other != gid).context("one group")?;
                let page = self.outsider.read(&other.0, 0, usize::MAX)?.context("no log")?;
                (page.entries.last().context("an empty log")?.0.clone(), None)
            }
            Forgery::Message { .. } | Forgery::Commit | Forgery::Copy => {
                let m = self.holder(&gid, m)?;
                let copy = self.members.lock().unwrap()[m].store.snapshot();
                if matches!(what, Forgery::Copy) {
                    self.observe(What::Copied { m, group: gid.clone() });
                }
                let (entry, ciphertext) = forged(&copy, &gid, what)?;
                (entry, ciphertext.map(|ciphertext| (m, ciphertext)))
            }
        };
        let position = self.outsider.append(&gid.0, &[Bytes(entry)])?.position;
        if !matches!(what, Forgery::Copy) {
            let mac = matches!(what, Forgery::Message { mac: true });
            self.observe(What::Forged { group: gid.clone(), position, mac });
        }
        if let Some((m, ciphertext)) = push {
            self.book.lock().unwrap().forged.insert((gid.clone(), position));
            let net = self.peers.lock().unwrap().get(&self.iroh(m)).cloned();
            let item = lmk_proto::peer::Item { position, ciphertext: Bytes(ciphertext) };
            for j in (0..self.size()).filter(|j| *j != m) {
                let frame = lmk_proto::peer::Frame::Messages { group: gid.clone(), items: vec![item.clone()], answers: None };
                net.as_ref().map(|net| net.frame(self.iroh(j), frame));
            }
        }
        Ok(format!("at {position}"))
    }

    /// Every member online and reachable, then after a while the properties are checked.
    async fn quiesce(self: &Arc<Self>) {
        let running = std::mem::take(&mut *self.running.lock().unwrap());
        for task in running {
            task.await.ok();
        }
        for m in 0..self.size() {
            self.online(m, true);
        }
        self.heal();
        sleep(Duration::from_millis(CONVERGE)).await;
        self.observe(What::Quiet { views: self.views() });
        self.connections();
        let failure = props::check(&self.book.lock().unwrap().trace);
        if let Some((name, text)) = failure {
            self.fail(name, text);
        }
        if let Some(panic) = PANICS.with_borrow(|panics| panics.first().cloned()) {
            self.fail("panic", panic);
        }
    }

    /// Each running member's view of each group it holds.
    fn views(&self) -> Vec<View> {
        let mut views = Vec::new();
        for (m, client) in self.clients() {
            let node = client.node();
            for gid in node.groups() {
                self.sample(m, node, &gid);
                let book = self.book.lock().unwrap();
                let Some((epoch, leaves, _)) = book.rosters.get(&(m, gid.clone())).cloned() else { continue };
                drop(book);
                let Ok(p) = node.positions(&gid.0) else { continue };
                let set = |ranges: lmk_proto::ranges::Ranges| ranges.iter().collect();
                views.push(View { m, key: node.key_in(&gid.0), group: gid, epoch, leaves, start: p.start, head: p.head, held: set(p.held), opened: set(p.opened), lost: set(p.lost) });
            }
        }
        views
    }
}

/// A node's observation, as the trace records it.
fn observed(m: usize, observation: Observation) -> What {
    match observation {
        Observation::Read { group, position, entry, epoch, verdict } => {
            let verdict = match verdict {
                Judgement::Commit { committer, added, removed } => Verdict::Commit { committer, added, removed },
                Judgement::Counted { id } => Verdict::Counted { id },
                Judgement::Skipped => Verdict::Skipped,
            };
            What::Read { m, group, position, entry, epoch, verdict }
        }
        Observation::Joined { group, key, start } => What::Joined { m, key, group, start },
        Observation::Head { group, head } => What::Head { m, group, head },
        Observation::Opened { group, position, kind, sender, plaintext } => What::Opened { m, group, position, kind, sender, plaintext },
        Observation::Lost { group, position } => What::Lost { m, group, positions: [position].into() },
        Observation::Announced { group, position, positions } => What::Announced { m, group, position, positions: positions.into_iter().collect() },
        Observation::Handed { group, kind, position } => What::Handed { m, group, kind, position },
        Observation::Live { group, sender, epoch } => What::Live { m, group, sender, epoch },
        Observation::State { group, from } => What::StateTaken { m, group, from },
        Observation::Dropped { group, reason } => {
            let reason = match reason {
                lmk_node::Dropped::Retention => Dropped::Retention,
                lmk_node::Dropped::Copied => Dropped::Copied,
                lmk_node::Dropped::Forgotten => Dropped::Forgotten,
            };
            What::Dropped { m, group, reason }
        }
    }
}

fn restored(saved: lmk_node::Saved) -> Saved {
    Saved {
        epoch: saved.epoch,
        start: saved.start,
        expired: saved.expired,
        head: saved.head,
        logged: saved.logged,
        judged: saved.judged.into_iter().collect(),
        commits: saved.commits,
        held: saved.held.iter().collect(),
        entries: saved.entries,
        sends: saved.sends,
        summaries: saved.summaries,
        roster: saved.roster,
    }
}

/// What a peer frame says of each group, as the properties look; `entries` only of a group's own log.
fn frames(node: &Node<Store>, frame: &lmk_proto::peer::Frame) -> Vec<(Bytes, Frame)> {
    use lmk_proto::peer::Frame as F;
    match frame {
        F::Hello { groups, .. } => groups
            .iter()
            .map(|summary| (summary.group.clone(), Frame::Hello { head: summary.head.length, held: summary.held.iter().collect(), fetching: summary.fetching.iter().collect() }))
            .collect(),
        F::Entries { log, .. } if node.groups().contains(log) => vec![(log.clone(), Frame::Entries)],
        // A `want` from a peer the gate does not admit is answered, with nothing.
        F::Messages { group, items, .. } if !items.is_empty() => vec![(group.clone(), Frame::Messages { positions: items.iter().map(|item| item.position).collect() })],
        F::Want { group, positions } => vec![(group.clone(), Frame::Want { positions: positions.iter().collect() })],
        F::State { group, .. } => vec![(group.clone(), Frame::State)],
        F::Live { group, .. } => vec![(group.clone(), Frame::Live)],
        F::WantFiles { group, .. } => vec![(group.clone(), Frame::Files)],
        F::Have { group, files } if !files.is_empty() => vec![(group.clone(), Frame::Files)],
        _ => Vec::new(),
    }
}

/// From a copy of a member's state, in 0.13's entries: a message with a valid AEAD signed by another key, with its
/// ciphertext, under a MAC that verifies or not; a commit signed by another key; or a commit as the member signs it.
fn forged(copy: &Store, gid: &Bytes, what: Forgery) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    use lmk_node::lmk_core::group::{Change, Group, Session};
    use openmls::prelude::{GroupId, LeafNodeParameters, MlsGroup};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::signatures::Signer;
    use openmls_traits::types::SignatureScheme;
    if matches!(what, Forgery::Copy) {
        let session = Session::load(copy)?;
        let mut group = Group::load(copy, &gid.0)?;
        return Ok((group.commit(copy, &session, Change::default())?.entry, None));
    }
    let key = ed25519_dalek::SigningKey::from_bytes(&lmk_proto::random::random());
    let stranger = SignatureKeyPair::from_raw(SignatureScheme::ED25519, key.to_bytes().to_vec(), key.verifying_key().to_bytes().to_vec());
    let mut mls = MlsGroup::load(copy.storage(), &GroupId::from_slice(&gid.0))?.context("no such group")?;
    if let Forgery::Message { mac } = what {
        let payload = serde_json::to_vec(&json!({ "type": "message", "content": "forged" }))?;
        let ciphertext = mls.create_message(copy, &stranger, &payload)?.to_bytes()?;
        let id = sha(&ciphertext);
        let entry = match mac {
            true => Group::load(copy, &gid.0)?.entry(copy, &id)?,
            false => Entry::Message { id, mac: lmk_proto::random::random() }.encode(),
        };
        return Ok((entry, Some(ciphertext)));
    }
    let commit = mls.self_update(copy, &stranger, LeafNodeParameters::default())?.into_commit().to_bytes()?;
    let sig = stranger.sign(&signed(&commit, None)).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    Ok((Entry::Commit { commit, welcome: None, sig }.encode(), None))
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
