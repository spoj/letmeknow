//! Starting a session and its background tasks: what steps produced goes out once durable (`send_out`), the work the
//! group logic hands on runs one item at a time (`drive`), the duties run at start and every while (`resume`), and
//! files are fetched.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use iroh::{EndpointId, RelayMap};
use lmk_core::group::{Group, Session};
use lmk_core::provider::Provider;
use lmk_net::peers::Peers;
use lmk_net::{Net, Network};
use lmk_proto::group::{Leaf, REVISION};
use lmk_proto::links::FileLink;
use lmk_proto::Bytes;
use n0_future::task::spawn;
use n0_future::time::sleep;
use tokio::sync::mpsc;

use crate::{COLLECT, Config, Event, G, Inner, MEMBER_WAIT, Node, Out, Rec, State, Work, admission, device_key_key, duties, endpoint_id, get, hex, iroh_key, logs, now, peering, rec_key};

/// How long a fetch keeps looking for a member that holds the file.
const FETCH_TRIES: u32 = 12;

impl<P: Provider + Send + 'static> Node<P> {
    /// Opens the session in `provider`, creating it on first use, and starts its peers.
    pub async fn start(provider: P, mut config: Config) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
        let relays = RelayMap::from(iroh::RelayConfig::new(config.relay.clone(), Some(Default::default())));
        let ca = std::mem::take(&mut config.ca);
        let endpoint = lmk_net::builder(relays).secret_key(iroh_key(&provider)?).ca_tls_config(ca).bind().await?;
        Self::start_on(provider, config, Network::Iroh(endpoint)).await
    }

    /// Opens the session on a network of the caller's, whose key is `iroh_key`'s.
    pub async fn start_on(provider: P, config: Config, network: Network) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
        let transport = network.transport();
        let leaf = Leaf { key: Bytes(transport.id().as_bytes().to_vec()), relay: config.relay.to_string(), kinds: config.kinds.clone(), revision: REVISION };
        let clients = logs::Clients::new(transport);
        let state = State::open(provider, &config, leaf, &clients)?;
        let (events, events_rx) = mpsc::unbounded_channel();
        let (work, work_rx) = mpsc::unbounded_channel();
        let (outbox, outbox_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            net: OnceLock::new(),
            clients,
            follows: Mutex::default(),
            relay: config.relay.clone(),
            file_limit: config.file_limit,
            kinds: config.kinds,
            events,
            work,
            outbox,
            durable: config.durable,
            observe: config.observe,
            committing: tokio::sync::Mutex::new(()),
            advanced: tokio::sync::Notify::new(),
            heard: tokio::sync::Notify::new(),
            reading: Mutex::default(),
            sending: Mutex::default(),
            passing: Mutex::default(),
            timers: Mutex::default(),
            tasks: Mutex::default(),
            contradictions: Mutex::default(),
        });
        let net_config = lmk_net::Config { home: config.home, files: config.files, disk: config.disk, file_limit: config.file_limit, collect: COLLECT };
        let (net, net_events) = Net::spawn(network, net_config, inner.clone(), Arc::new(admission::Admitter(inner.clone()))).await?;
        inner.net.set(net).ok();
        inner.run(net_events, work_rx, outbox_rx);
        Ok((Node { inner }, events_rx))
    }
}

impl<P: Provider> State<P> {
    /// The session in `provider`, created on first use, with its leaf as `leaf`; its logs, groups and device keys.
    fn open(provider: P, config: &Config, leaf: Leaf, clients: &logs::Clients) -> Result<Self> {
        let mut session = match provider.get(b"session")? {
            Some(_) => Session::load(&provider)?,
            None => Session::create(&provider, &config.name, leaf.clone())?,
        };
        if session.leaf != leaf {
            session.set_leaf(&provider, leaf)?;
        }
        let logs = State::load_logs(&provider)?;
        for log in logs.values() {
            if let Some(chain) = &log.chain {
                clients.client(&log.service)?.set_chain(chain.clone());
            }
        }
        let mut groups = BTreeMap::new();
        for gid in get::<Vec<Bytes>>(&provider, b"node/groups")?.unwrap_or_default() {
            let mls = Group::load(&provider, &gid.0)?;
            let rec: Rec = get(&provider, &rec_key(&gid.0))?.context("a group without its record")?;
            let heard = peering::load_heard(&provider, &gid.0)?;
            groups.insert(gid.0, G::new(mls, rec, heard));
        }
        let mut state = State {
            provider,
            out: Vec::new(),
            scrub: false,
            observed: Vec::new(),
            observing: config.observe.is_some(),
            events: Vec::new(),
            device: config.device.as_ref().map(|device| device.name.clone()),
            session,
            groups,
            logs,
            keys: BTreeMap::new(),
            unlisted: HashSet::new(),
            device_keys: BTreeMap::new(),
            waiters: HashMap::new(),
            peers: Peers::new(now()),
            served: BTreeMap::new(),
            gate: true,
            time: now(),
        };
        for gid in state.groups.keys().cloned().collect::<Vec<_>>() {
            if let Some(seed) = get::<Bytes>(&state.provider, &device_key_key(&gid))? {
                let seed: [u8; 32] = seed.0.as_slice().try_into().context("a device key is 32 bytes")?;
                let session = state.keyed(seed)?;
                state.device_keys.insert(gid.clone(), (seed, session));
            }
            state.refresh(&gid);
        }
        Ok(state)
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Starts the tasks, follows the logs, and picks up where the session stopped: its key logs replayed, its groups
    /// it was removed from told, its pending sends appended.
    fn run(
        self: &Arc<Self>,
        mut net_events: mpsc::UnboundedReceiver<lmk_net::Event>,
        work: mpsc::UnboundedReceiver<Work>,
        outbox: mpsc::UnboundedReceiver<Vec<Out>>,
    ) {
        let peering = self.clone();
        self.spawn(async move {
            while let Some(event) = net_events.recv().await {
                match event {
                    lmk_net::Event::Fetched(hash) => peering.fetched_file(hash),
                    event => peering.peer_event(event),
                }
            }
        });
        self.spawn(self.clone().drive(work));
        self.spawn(self.clone().send_out(outbox));
        let followed: Vec<Vec<u8>> = self.lock().logs.keys().cloned().collect();
        for log in &followed {
            self.follow(log);
        }
        let mut st = self.lock();
        let identities: Vec<Bytes> = st.logs.values().filter_map(|log| match &log.of {
            logs::Of::Identity(id) => Some(id.clone()),
            _ => None,
        }).collect();
        for id in identities {
            if let Err(error) = self.keyed(&mut st, &id.0) {
                self.warn(None, format!("the key log of {}: {error:#}", hex(&id.0)));
            }
        }
        // A session removed by a commit it applied before it stopped is told so now; its sends go on. A group its log's
        // reading dropped meanwhile is gone already.
        for (gid, g) in &st.groups {
            if !g.mls.active() {
                self.work.send(Work::Gone(gid.clone())).ok();
            } else if !g.rec.sends.is_empty() {
                self.work.send(Work::Send(gid.clone())).ok();
            }
        }
        drop(st);
        self.spawn(self.clone().resume());
        self.spawn(self.clone().polling());
    }

    /// Sends what steps produced, in order, once it is durable.
    async fn send_out(self: Arc<Self>, mut outbox: mpsc::UnboundedReceiver<Vec<Out>>) {
        while let Some(out) = outbox.recv().await {
            if let Err(error) = self.durable().await {
                self.warn(None, format!("saving this session's state: {error:#}"));
            }
            for out in out {
                match (out, self.net.get()) {
                    (Out::Outcome { waiters, outcome }, _) => waiters.into_iter().for_each(|waiter| drop(waiter.send(outcome.clone()))),
                    (Out::Frame { peer, frame }, Some(net)) => drop(net.frame(peer, frame)),
                    (Out::WantFiles { peer, group }, Some(net)) => net.want_files(peer, &group),
                    _ => {}
                }
            }
        }
    }

    /// Catches up as this session starts: the key logs it lacks, then the entries it stored and had not applied, as
    /// while waiting before a commit. Then runs every group's duties, now and every `duties::TIMER`, and scrubs.
    async fn resume(self: Arc<Self>) {
        self.refresh_all().await;
        let gids: Vec<Vec<u8>> = self.lock().groups.keys().cloned().collect();
        for gid in &gids {
            if let Err(error) = self.advance(&mut self.lock(), gid) {
                tracing::debug!("applying the stored log of {}: {error:#}", hex(gid));
            }
        }
        loop {
            for gid in self.lock().groups.keys() {
                self.work.send(Work::Duties(gid.clone())).ok();
            }
            sleep(duties::TIMER).await;
            self.lock().scrub = true;
        }
    }

    /// Dials every member of every group that is not connected.
    pub(crate) fn dial_all(self: &Arc<Self>) {
        let connected = self.net().connected();
        let me = self.net().id();
        let leaves: BTreeSet<(EndpointId, String)> = {
            let st = self.lock();
            st.groups
                .values()
                .flat_map(|g| g.mls.members())
                .filter_map(|m| Some((endpoint_id(&m.leaf.as_ref()?.key.0)?, m.leaf?.relay)))
                .filter(|(peer, _)| *peer != me && !connected.contains(peer))
                .collect()
        };
        for (peer, relay) in leaves {
            let Ok(relay) = relay.parse() else { continue };
            let net = self.net().clone();
            spawn(async move {
                if let Err(error) = net.dial(peer, relay).await {
                    tracing::debug!("dialing {}: {error:#}", peer.fmt_short());
                }
            });
        }
    }

    /// Fetches, in the background, the files linked anew that are within this session's limit.
    pub(crate) fn fetch_within_limit(&self, gid: &[u8], links: Vec<FileLink>) {
        for link in links.into_iter().filter(|link| link.size <= self.file_limit) {
            self.work.send(Work::Fetch { group: gid.to_vec(), link }).ok();
        }
    }

    /// Fetches a file from the members online, trying for a while.
    pub(crate) async fn fetched(&self, gid: &[u8], link: &FileLink) -> Result<()> {
        let mut last = anyhow::anyhow!("no member online holds the file");
        for _ in 0..FETCH_TRIES {
            match self.net().fetch(gid, link).await {
                Ok(()) => return Ok(()),
                Err(error) => last = error,
            }
            sleep(MEMBER_WAIT).await;
        }
        Err(last)
    }

    /// Handles what the group logic and the peers hand on, one at a time.
    async fn drive(self: Arc<Self>, mut work: mpsc::UnboundedReceiver<Work>) {
        while let Some(item) = work.recv().await {
            match item {
                Work::Applied { group, by, added, how, invite, removed, settings, gone } => {
                    self.applied(&group, by, added, how, invite, removed, settings, gone).await
                }
                Work::Read(log) => {
                    if self.reading.lock().unwrap().insert(log.clone()) {
                        let inner = self.clone();
                        self.spawn(async move {
                            if let Err(error) = inner.read(&log).await {
                                tracing::debug!("reading {}: {error:#}", hex(&log));
                            }
                            inner.reading.lock().unwrap().remove(&log);
                        });
                    }
                }
                Work::Duties(gid) => self.duties(&gid),
                Work::Gone(group) => self.gone(&group, None),
                Work::Fetch { group, link } => {
                    if self.net().has(link.hash).await.unwrap_or(false) {
                        self.events.send(Event::File(link.hash)).ok();
                        continue;
                    }
                    let inner = self.clone();
                    self.spawn(async move {
                        if let Err(error) = inner.fetched(&group, &link).await {
                            tracing::debug!("fetching {}: {error:#}", link.link());
                        }
                    });
                }
                Work::Send(gid) => {
                    if self.sending.lock().unwrap().insert(gid.clone()) {
                        let inner = self.clone();
                        self.spawn(async move {
                            inner.sends(&gid).await;
                            inner.sending.lock().unwrap().remove(&gid);
                        });
                    }
                }
            }
        }
    }

    /// A file is held whole: it is no longer held only here.
    fn fetched_file(&self, hash: [u8; 32]) {
        let mut st = self.lock();
        let gids: Vec<Vec<u8>> = st.groups.keys().cloned().collect();
        for gid in gids {
            let g = st.groups.get_mut(&gid).unwrap();
            let before = g.rec.pending.len();
            g.rec.pending.retain(|pending| *pending != hash);
            if g.rec.pending.len() != before {
                st.save(&gid).ok();
            }
        }
        st.events.push(Event::File(hash));
    }
}
