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
use n0_future::time::{Duration, sleep};
use tokio::sync::mpsc;

use crate::{Config, Event, G, Inner, MEMBER_WAIT, Node, Out, Rec, State, Work, admission, device_key_key, duties, endpoint_id, get, hex, iroh_key, logs, now, peering, rec_key};

/// How often files no group holds any longer are deleted.
const COLLECT: Duration = Duration::from_secs(60 * 60);
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
        let mut session = match provider.get(b"session")? {
            Some(_) => Session::load(&provider)?,
            None => Session::create(&provider, &config.name, leaf.clone())?,
        };
        if session.leaf != leaf {
            session.set_leaf(&provider, leaf)?;
        }
        let clients = logs::Clients::new(transport);
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
        let (events, events_rx) = mpsc::unbounded_channel();
        let (work, work_rx) = mpsc::unbounded_channel();
        let (outbox, outbox_rx) = mpsc::unbounded_channel();
        let mut state = State {
            provider,
            out: Vec::new(),
            scrub: false,
            observed: Vec::new(),
            observing: config.observe.is_some(),
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
        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            net: OnceLock::new(),
            clients,
            follows: Mutex::default(),
            relay: config.relay.clone(),
            file_limit: config.file_limit,
            kinds: config.kinds,
            events,
            work: work.clone(),
            outbox,
            durable: config.durable,
            observe: config.observe,
            committing: tokio::sync::Mutex::new(()),
            advanced: tokio::sync::Notify::new(),
            reading: Mutex::default(),
            sending: Mutex::default(),
            passing: Mutex::default(),
            timers: Mutex::default(),
            tasks: Mutex::default(),
            contradictions: Mutex::default(),
        });
        let net_config = lmk_net::Config {
            home: config.home,
            files: config.files,
            disk: config.disk,
            file_limit: config.file_limit,
            collect: COLLECT,
        };
        let (net, mut net_events) =
            Net::spawn(network, net_config, inner.clone(), Arc::new(admission::Admitter(inner.clone()))).await?;
        inner.net.set(net).ok();
        let peering = inner.clone();
        inner.spawn(async move {
            while let Some(event) = net_events.recv().await {
                match event {
                    lmk_net::Event::Fetched(hash) => peering.fetched_file(hash),
                    event => peering.peer_event(event),
                }
            }
        });
        inner.spawn(inner.clone().drive(work_rx));
        inner.spawn(inner.clone().send_out(outbox_rx));
        let followed: Vec<Vec<u8>> = inner.lock().logs.keys().cloned().collect();
        for log in &followed {
            inner.follow(log);
        }
        {
            let mut st = inner.lock();
            let identities: Vec<Bytes> = st.logs.values().filter_map(|log| match &log.of {
                logs::Of::Identity(id) => Some(id.clone()),
                _ => None,
            }).collect();
            for id in identities {
                if let Err(error) = inner.keyed(&mut st, &id.0) {
                    inner.warn(None, format!("the key log of {}: {error:#}", hex(&id.0)));
                }
            }
        }
        {
            // A session removed by a commit it applied before it stopped is told so now; its sends go on. A group its
            // log's reading dropped meanwhile is gone already.
            let st = inner.lock();
            for (gid, g) in &st.groups {
                if !g.mls.active() {
                    inner.work.send(Work::Gone(gid.clone())).ok();
                    continue;
                }
                if !g.rec.sends.is_empty() {
                    inner.work.send(Work::Send(gid.clone())).ok();
                }
            }
        }
        inner.spawn(inner.clone().resume());
        inner.spawn(inner.clone().polling());
        Ok((Node { inner }, events_rx))
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
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
        self.events.send(Event::File(hash)).ok();
    }
}
