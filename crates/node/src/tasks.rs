//! Starting a session and its background tasks: what steps produced goes out in order (`send_out`), the work the
//! group logic hands on runs one item at a time (`drive`), and the session catches up as it starts (`resume`) and runs
//! each group's duties.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use iroh::{EndpointId, RelayUrl};
use lmk_core::group::{Group, Session};
use lmk_core::provider::SqliteProvider;
use lmk_net::peers::{Peers, WAIT};
use lmk_net::Net;
use lmk_proto::group::{Leaf, REVISION};
use lmk_proto::Bytes;
use n0_future::time::{Duration, sleep};
use n0_future::{join_all, task::spawn};
use tokio::sync::mpsc;

use crate::{Config, Event, G, Inner, Node, Out, Rec, State, Work, admission, endpoint_id, get, hex, iroh_key, logs, now, peering, rec_key};

impl Node {
    /// Opens the session in `provider`, creating it on first use, and starts its peers.
    pub async fn start(provider: SqliteProvider, mut config: Config) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
        let ca = std::mem::take(&mut config.ca);
        let home = if config.chosen.is_empty() { config.relays.clone() } else { config.chosen.clone() };
        let endpoint = lmk_net::builder(home).secret_key(iroh_key(&provider)?).ca_tls_config(ca).bind().await?;
        let leaf = Leaf { key: Bytes(endpoint.id().as_bytes().to_vec()), revision: REVISION };
        let clients = logs::Clients::new(config.post.clone());
        let state = State::open(provider, leaf)?;
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
            events,
            work,
            outbox,
            committing: Mutex::default(),
            advanced: tokio::sync::Notify::new(),
            heard: tokio::sync::Notify::new(),
            passing: Mutex::default(),
            timers: Mutex::default(),
            tasks: Mutex::default(),
            contradictions: Mutex::default(),
            warned: Mutex::default(),
        });
        let (net, net_events) = Net::spawn(endpoint, inner.clone(), Arc::new(admission::Admitter(inner.clone()))).await?;
        inner.net.set(net).ok();
        inner.run(net_events, work_rx, outbox_rx);
        Ok((Node { inner }, events_rx))
    }
}

impl State {
    /// The session in `provider`, created on first use, with its leaf as `leaf`; its logs and groups.
    fn open(provider: SqliteProvider, leaf: Leaf) -> Result<Self> {
        let mut session = match provider.get(b"session")? {
            Some(_) => Session::load(&provider)?,
            None => Session::create(&provider, leaf.clone())?,
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
            provider,
            out: Vec::new(),
            scrub: false,
            events: Vec::new(),
            session,
            groups,
            logs,
            peers,
            gate: true,
            home: None,
            hints,
            time: now(),
        };
        for gid in state.groups.keys().cloned().collect::<Vec<_>>() {
            state.refresh(&gid);
            state.load_heard(&gid)?;
        }
        Ok(state)
    }
}

impl Inner {
    /// Starts the tasks, opens the logs, and picks up where the session stopped: its groups it was removed from told.
    fn run(
        self: &Arc<Self>,
        mut net_events: mpsc::UnboundedReceiver<lmk_net::Event>,
        work: mpsc::UnboundedReceiver<Work>,
        outbox: mpsc::UnboundedReceiver<(Vec<Out>, Vec<Event>)>,
    ) {
        let peering = self.clone();
        self.spawn(async move {
            while let Some(event) = net_events.recv().await {
                peering.peer_event(event);
            }
        });
        self.spawn(self.clone().drive(work));
        self.spawn(self.clone().send_out(outbox));
        let st = self.lock();
        // A session removed by a commit it applied before it stopped is told so now. A group its log's reading dropped
        // meanwhile is gone already.
        for (gid, g) in &st.groups {
            let work = if g.mls.active() { Work::Duties(gid.clone()) } else { Work::Gone(gid.clone()) };
            self.work.send(work).ok();
        }
        drop(st);
        self.spawn(self.clone().resume());
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
                    Out::Dial(peer) => self.dial(peer),
                    Out::Close(peer) => net.close(peer),
                }
            }
        }
    }

    /// Catches up as this session starts: the entries it stored and had not applied, as while waiting before a commit.
    async fn resume(self: Arc<Self>) {
        let gids: Vec<Vec<u8>> = self.lock().groups.keys().cloned().collect();
        for gid in &gids {
            if let Err(error) = self.advance(&mut self.lock(), gid) {
                tracing::debug!("applying the stored log of {}: {error:#}", hex(gid));
            }
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

    /// The relays a member may be reached at: this session's own, and the relay of the service of each group the member
    /// is in. The directories resolve together; one that does not adds none.
    async fn fallback(self: Arc<Self>, peer: EndpointId) -> Vec<RelayUrl> {
        let services = {
            let st = self.lock();
            let mut services = Vec::new();
            for g in st.groups.values() {
                let in_group = g.mls.members().iter().any(|m| m.leaf.as_ref().and_then(|leaf| endpoint_id(&leaf.key.0)) == Some(peer));
                let service = g.mls.settings().membership;
                if in_group && !services.contains(&service) {
                    services.push(service);
                }
            }
            services
        };
        let resolve = &self.resolve;
        let found = join_all(services.iter().map(|service| async move {
            lmk_membership::client::directory(resolve, service).await.map(|found| vec![found.relay]).unwrap_or_default()
        }))
        .await;
        let mut relays = self.relays.clone();
        relays.extend(found.iter().flatten().filter_map(|relay| relay.parse().ok()));
        relays
    }

    /// Handles what the group logic and the peers hand on, one at a time.
    async fn drive(self: Arc<Self>, mut work: mpsc::UnboundedReceiver<Work>) {
        while let Some(item) = work.recv().await {
            match item {
                Work::Applied { group, by, added, removed, gone } => self.applied(&group, by, added, removed, gone).await,
                Work::Duties(gid) => self.duties(&gid),
                Work::Lapsed(log) => {
                    let node = self.clone();
                    self.spawn(async move {
                        sleep(Duration::from_millis(WAIT)).await;
                        if let Err(error) = node.read(&log).await {
                            tracing::debug!("reading the lapsed log {}: {error:#}", hex(&log));
                        }
                    });
                }
                Work::Gone(group) => self.gone(&group, None),
            }
        }
    }
}

