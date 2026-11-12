//! Starting a session and its background tasks: what steps produced goes out in order (`send_out`), the work the
//! group logic hands on runs one item at a time (`drive`), and the session catches up as it starts (`resume`) and runs
//! each group's duties.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use iroh::{EndpointId, RelayUrl};
use lmk_core::group::{Group, Session};
use lmk_core::provider::SqliteProvider;
use lmk_net::peers::Peers;
use lmk_net::Net;
use lmk_proto::directory::relay_url;
use lmk_proto::group::{Device, LEAF, Leaf};
use lmk_proto::Bytes;
use n0_future::task::spawn;
use tokio::sync::mpsc;

use crate::{Config, Event, G, Inner, Leave, Node, Out, Rec, State, Work, admission, get, hex, iroh_key, logs, now, rec_key};

impl Node {
    /// Opens the session in `provider`, creating it on first use, and starts its peers.
    pub async fn start(provider: SqliteProvider, mut config: Config) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
        let ca = std::mem::take(&mut config.ca);
        let relay: RelayUrl = relay_url(&config.home).parse()?;
        let endpoint = lmk_net::builder([relay]).secret_key(iroh_key(&provider)?).ca_tls_config(ca).bind().await?;
        let clients = logs::Clients::new(config.post.clone(), config.home.clone());
        let state = State::open(provider, &config.home, &config.device)?;
        let (events, events_rx) = mpsc::unbounded_channel();
        let (work, work_rx) = mpsc::unbounded_channel();
        let (outbox, outbox_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            net: OnceLock::new(),
            clients,
            home: config.home.clone(),
            events,
            work,
            outbox,
            committing: Mutex::default(),
            advanced: tokio::sync::Notify::new(),
            heard: tokio::sync::Notify::new(),
            poke: tokio::sync::Notify::new(),
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

/// Makes a new session in `provider`, living on the relay of `home`, which `Node::start` opens: answers its key. Its leaf
/// names its iroh key, which signs the session's key.
pub fn create(provider: &SqliteProvider, home: &str) -> Result<Bytes> {
    let iroh = iroh_key(provider)?;
    let leaf = |session: &[u8]| Leaf {
        key: Bytes(iroh.public().as_bytes().to_vec()),
        proof: Bytes(iroh.sign(&[LEAF, session].concat()).to_bytes().to_vec()),
        home: home.into(),
        device: None,
    };
    Ok(Bytes(Session::create(provider, leaf)?.key().to_vec()))
}

/// The groups the session in `provider` is in, as its node saved them.
pub fn groups(provider: &SqliteProvider) -> Result<Vec<Bytes>> {
    Ok(get::<Vec<Bytes>>(provider, b"node/groups")?.unwrap_or_default())
}

/// The leaves of the session in `provider` of the groups it is a member of (`Group::leave`), as it goes for good.
pub fn leaves(provider: &SqliteProvider) -> Result<Vec<Leave>> {
    let mut leaves = Vec::new();
    for gid in groups(provider)? {
        let (session, mls) = (Session::load(provider)?, Group::load(provider, &gid.0)?);
        // None once a commit it applied removed it.
        let Some(joined) = mls.joined(session.key()) else { continue };
        leaves.push(Leave { key: Bytes(session.key().to_vec()), joined, sig: mls.leave(&session)?, group: gid });
    }
    Ok(leaves)
}

impl State {
    /// The session in `provider`, created on first use, with its leaf at `home`, certified by `device`; its logs and
    /// groups.
    fn open(provider: SqliteProvider, home: &str, device: &ed25519_dalek::SigningKey) -> Result<Self> {
        if provider.get(b"session")?.is_none() {
            create(&provider, home)?;
        }
        let mut session = Session::load(&provider)?;
        let leaf = Leaf { home: home.into(), device: Some(Device::sign(device, session.key())), ..session.leaf.clone() };
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
        let peers = Peers::new(*iroh_key(&provider)?.public().as_bytes());
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
            quiet: false,
            early_hellos: Vec::new(),
            joins: Vec::new(),
            early_entries: Vec::new(),
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
        mut net_events: mpsc::Receiver<lmk_net::Event>,
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
        // A session removed by a commit it applied but could not forget the group at is told so now. A group its log's
        // reading dropped meanwhile is gone already.
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


    /// Dials a member at the relay its leaves name, and tells `Peers` if that failed: a connection made goes to it as its
    /// `Connected`, which ends the dial there.
    fn dial(self: &Arc<Self>, peer: EndpointId) {
        let relays = self.lock().relays_of(&peer);
        let inner = self.clone();
        spawn(async move {
            if let Err(error) = inner.net().dial(peer, relays).await {
                tracing::debug!("dialing {}: {error:#}", peer.fmt_short());
                let mut st = inner.lock();
                let now = st.tick();
                st.peers.failed(peer.as_bytes(), now);
            }
        });
    }

    /// Handles what the group logic and the peers hand on, one at a time.
    async fn drive(self: Arc<Self>, mut work: mpsc::UnboundedReceiver<Work>) {
        while let Some(item) = work.recv().await {
            match item {
                Work::Duties(gid) => self.duties(&gid),
                Work::Gone(group) => self.gone(&mut self.lock(), &group, None),
            }
        }
    }
}

