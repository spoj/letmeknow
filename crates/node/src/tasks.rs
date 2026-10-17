//! Starting a session and its background tasks: what steps produced goes out in order (`send_out`), the work the
//! group logic hands on runs one item at a time (`drive`), the duties run at start and every while (`resume`), and
//! files are fetched.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use iroh::{EndpointId, RelayUrl};
use lmk_core::group::{Group, Session};
use lmk_core::provider::Provider;
use lmk_net::peers::Peers;
use lmk_net::Net;
use lmk_proto::group::{Leaf, REVISION};
use lmk_proto::links::FileLink;
use lmk_proto::Bytes;
use n0_future::{join_all, task::spawn};
use n0_future::time::{Duration, sleep};
use tokio::sync::mpsc;

use crate::{COLLECT, Config, Event, G, Inner, MEMBER_WAIT, Node, Out, Rec, State, Work, admission, device_key_key, duties, endpoint_id, get, hex, iroh_key, logs, now, peering, rec_key};

/// How long a fetch keeps looking for a member that holds the file.
const FETCH_TRIES: u32 = 12;
/// How often identities whose public logs could not be read are read again, as their directories may answer by then.
const READ_RETRY: Duration = Duration::from_secs(30);

impl<P: Provider + Send + 'static> Node<P> {
    /// Opens the session in `provider`, creating it on first use, and starts its peers.
    pub async fn start(provider: P, mut config: Config) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
        let ca = std::mem::take(&mut config.ca);
        let home = if config.chosen.is_empty() { config.relays.clone() } else { config.chosen.clone() };
        let endpoint = lmk_net::builder(home).secret_key(iroh_key(&provider)?).ca_tls_config(ca).bind().await?;
        let leaf = Leaf { key: Bytes(endpoint.id().as_bytes().to_vec()), revision: REVISION };
        let clients = logs::Clients::new(config.post.clone());
        let state = State::open(provider, &config, leaf)?;
        let (events, events_rx) = mpsc::unbounded_channel();
        let (work, work_rx) = mpsc::unbounded_channel();
        let (outbox, outbox_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            net: OnceLock::new(),
            clients,
            relays: config.relays.clone(),
            chosen: config.chosen.clone(),
            resolve: config.resolve.clone(),
            file_limit: config.file_limit,
            events,
            work,
            outbox,
            committing: tokio::sync::Mutex::new(()),
            advanced: tokio::sync::Notify::new(),
            heard: tokio::sync::Notify::new(),
            passing: Mutex::default(),
            timers: Mutex::default(),
            tasks: Mutex::default(),
            contradictions: Mutex::default(),
            warned: Mutex::default(),
        });
        let net_config = lmk_net::Config { home: config.home, files: config.files, file_limit: config.file_limit, collect: COLLECT };
        let (net, net_events) = Net::spawn(endpoint, net_config, inner.clone(), Arc::new(admission::Admitter(inner.clone()))).await?;
        inner.net.set(net).ok();
        inner.run(net_events, work_rx, outbox_rx);
        Ok((Node { inner }, events_rx))
    }
}

impl<P: Provider> State<P> {
    /// The session in `provider`, created on first use, with its leaf as `leaf`; its logs, groups and device keys.
    fn open(provider: P, config: &Config, leaf: Leaf) -> Result<Self> {
        let mut session = match provider.get(b"session")? {
            Some(_) => Session::load(&provider)?,
            None => Session::create(&provider, &config.handle, leaf.clone())?,
        };
        if session.leaf != leaf {
            session.set_leaf(&provider, leaf)?;
        }
        let logs = State::load_logs(&provider)?;
        let mut groups = BTreeMap::new();
        for gid in get::<Vec<Bytes>>(&provider, b"node/groups")?.unwrap_or_default() {
            let mls = Group::load(&provider, &gid.0)?;
            let rec: Rec = get(&provider, &rec_key(&gid.0))?.context("a group without its record")?;
            groups.insert(gid.0, G::new(mls, rec));
        }
        let bindings = get(&provider, b"node/identity-bindings")?.unwrap_or_default();
        let mut hints = BTreeMap::new();
        for g in groups.values() {
            for leaf in g.mls.members().iter().filter_map(|member| member.leaf.as_ref()) {
                if let Some(hint) = get::<peering::Hint>(&provider, &peering::hint_key(&leaf.key.0))? {
                    hints.insert(leaf.key.clone(), hint);
                }
            }
        }
        let peers = Peers::new(now(), u64::from_be_bytes(lmk_core::random()), *iroh_key(&provider)?.public().as_bytes());
        let mut state = State {
            bindings,
            notified: BTreeSet::new(),
            provider,
            out: Vec::new(),
            scrub: false,
            events: Vec::new(),
            device: config.device.as_ref().map(|device| device.name.clone()),
            session,
            groups,
            logs,
            public: BTreeMap::new(),
            unlisted: HashSet::new(),
            device_keys: BTreeMap::new(),
            peers,
            served: BTreeMap::new(),
            gate: true,
            home: None,
            hints,
            time: now(),
        };
        for gid in state.groups.keys().cloned().collect::<Vec<_>>() {
            if let Some(seed) = get::<Bytes>(&state.provider, &device_key_key(&gid))? {
                let seed: [u8; 32] = seed.0.as_slice().try_into().context("a device key is 32 bytes")?;
                let session = state.keyed(seed)?;
                state.device_keys.insert(gid.clone(), (seed, session));
            }
            state.refresh(&gid);
            state.load_heard(&gid)?;
        }
        Ok(state)
    }
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Starts the tasks, polls the logs, and picks up where the session stopped: its public logs replayed, and its
    /// groups it was removed from told.
    fn run(
        self: &Arc<Self>,
        mut net_events: mpsc::UnboundedReceiver<lmk_net::Event>,
        work: mpsc::UnboundedReceiver<Work>,
        outbox: mpsc::UnboundedReceiver<(Vec<Out>, Vec<Event>)>,
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
        self.spawn(self.clone().ask_heads_forever());
        self.spawn(self.clone().ask_members_forever());
        let mut st = self.lock();
        let public: Vec<Bytes> = st.logs.values().filter_map(|log| match &log.of {
            logs::Of::Public(id) => Some(id.clone()),
            _ => None,
        }).collect();
        for id in public {
            if let Err(error) = self.replayed(&mut st, &id.0) {
                self.warn(None, format!("the public log {}: {error:#}", hex(&id.0)));
            }
        }
        // A session removed by a commit it applied before it stopped is told so now. A group its log's reading dropped
        // meanwhile is gone already.
        for (gid, g) in &st.groups {
            if !g.mls.active() {
                self.work.send(Work::Gone(gid.clone())).ok();
            }
        }
        drop(st);
        self.spawn(self.clone().resume());
        self.spawn(self.clone().reread_identities());
        self.spawn(self.clone().polling());
    }

    /// Sends what steps produced, in order.
    async fn send_out(self: Arc<Self>, mut outbox: mpsc::UnboundedReceiver<(Vec<Out>, Vec<Event>)>) {
        while let Some((out, events)) = outbox.recv().await {
            for event in events {
                self.events.send(event).ok();
            }
            for out in out {
                let Some(net) = self.net.get() else { continue };
                match out {
                    Out::Frame { peer, frame } => drop(net.frame(peer, frame)),
                    Out::WantFiles { peer, group } => net.want_files(peer, &group),
                    Out::Dial(peer) => self.dial(peer),
                    Out::Close(peer) => net.close(peer),
                }
            }
        }
    }

    /// Catches up as this session starts: the public logs it lacks, then the entries it stored and had not applied, as
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

    /// Dials a member, at the relay it last said it was on, then its fallback, and tells `Peers` how it went.
    fn dial(self: &Arc<Self>, peer: EndpointId) {
        let hint: Vec<RelayUrl> = self.lock().hint_of(&peer).into_iter().chain(self.chosen.clone()).collect();
        let inner = self.clone();
        spawn(async move {
            let dialed = inner.net().dial(peer, hint, Box::pin(inner.clone().fallback(peer))).await;
            if let Err(error) = &dialed {
                tracing::debug!("dialing {}: {error:#}", peer.fmt_short());
            }
            let mut st = inner.lock();
            let now = st.tick();
            st.peers.dialed(peer.as_bytes(), dialed.is_ok(), now);
        });
    }

    /// The relays a member may be reached at: this session's own, the relay of the service of each group the member is
    /// in, and the relays of the identity it speaks as. The directories resolve together; one that does not adds none.
    async fn fallback(self: Arc<Self>, peer: EndpointId) -> Vec<RelayUrl> {
        let (groups, identities) = {
            let st = self.lock();
            let (mut groups, mut identities) = (Vec::new(), Vec::new());
            for g in st.groups.values() {
                let members = g.mls.members();
                let Some(member) = members.iter().find(|m| m.leaf.as_ref().and_then(|leaf| endpoint_id(&leaf.key.0)) == Some(peer)) else { continue };
                let service = g.mls.settings().membership;
                if !groups.contains(&service) {
                    groups.push(service);
                }
                if let Some(identity) = member.credential.as_ref().and_then(|credential| credential.identity())
                    && let Some(log) = st.public.get(&identity.id.0)
                    && !identities.contains(&log.membership)
                {
                    identities.push(log.membership.clone());
                }
            }
            (groups, identities)
        };
        let resolve = &self.resolve;
        let services = groups.iter().map(|service| (service, false)).chain(identities.iter().map(|service| (service, true)));
        let found = join_all(services.map(|(service, identity)| async move {
            let found = lmk_membership::client::directory(resolve, service).await;
            found.map(|found| if identity { found.relays } else { vec![found.relay] }).unwrap_or_default()
        }))
        .await;
        let mut relays = self.relays.clone();
        relays.extend(found.iter().flatten().filter_map(|relay| relay.parse().ok()));
        relays
    }

    async fn reread_identities(self: Arc<Self>) {
        loop {
            sleep(READ_RETRY).await;
            self.refresh_all().await;
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
                Work::Applied { group, by, added, how, removed, settings, gone } => self.applied(&group, by, added, how, removed, settings, gone).await,
                Work::Read(log) => {
                    let node = self.clone();
                    self.spawn(async move {
                        if let Err(error) = node.read(&log).await {
                            tracing::debug!("reading log {}: {error:#}", hex(&log));
                        }
                    });
                }
                Work::Duties(gid) => self.duties(&gid),
                Work::Gone(group) => self.gone(&group, None),
                Work::Fetch { group, link } => {
                    if self.net().has(link.hash).await.unwrap_or(false) {
                        self.lock().events.push(Event::File(link.hash));
                        continue;
                    }
                    let inner = self.clone();
                    self.spawn(async move {
                        if let Err(error) = inner.fetched(&group, &link).await {
                            tracing::debug!("fetching {}: {error:#}", link.link());
                        }
                    });
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

