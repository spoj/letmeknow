//! Starting a session and its background tasks: what steps produced goes out once durable (`send_out`), the work the
//! group logic hands on runs one item at a time (`drive`), the duties run at start and every while (`resume`), and
//! files are fetched.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use iroh::EndpointId;
use lmk_core::group::{Group, Session};
use lmk_core::provider::Provider;
use lmk_net::peers::Peers;
use lmk_net::Net;
use lmk_proto::group::{Leaf, REVISION};
use lmk_proto::links::FileLink;
use lmk_proto::Bytes;
use n0_future::task::spawn;
use n0_future::time::sleep;
use tokio::sync::mpsc;

use crate::{COLLECT, Config, Event, G, Inner, MEMBER_WAIT, Node, Out, Rec, State, Work, admission, device_key_key, duties, endpoint_id, get, hex, iroh_key, logs, now, rec_key};

/// How long a fetch keeps looking for a member that holds the file.
const FETCH_TRIES: u32 = 12;

impl<P: Provider + Send + 'static> Node<P> {
    /// Opens the session in `provider`, creating it on first use, and starts its peers.
    pub async fn start(provider: P, mut config: Config) -> Result<(Self, mpsc::UnboundedReceiver<Event>)> {
        let ca = std::mem::take(&mut config.ca);
        let endpoint = lmk_net::builder([config.relay.clone()]).secret_key(iroh_key(&provider)?).ca_tls_config(ca).bind().await?;
        let leaf = Leaf { key: Bytes(endpoint.id().as_bytes().to_vec()), relay: config.relay.to_string(), kinds: config.kinds.clone(), revision: REVISION };
        let clients = logs::Clients::new(endpoint.clone());
        let state = State::open(provider, &config, leaf)?;
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
            persistence_error: Mutex::default(),
            committing: tokio::sync::Mutex::new(()),
            advanced: tokio::sync::Notify::new(),
            heard: tokio::sync::Notify::new(),
            passing: Mutex::default(),
            timers: Mutex::default(),
            tasks: Mutex::default(),
            contradictions: Mutex::default(),
        });
        let net_config = lmk_net::Config { home: config.home, files: config.files, disk: config.disk, file_limit: config.file_limit, collect: COLLECT };
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
    /// Starts the tasks, follows the logs, and picks up where the session stopped: its public logs replayed, and its
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
        let mut st = self.lock();
        let followed: Vec<Vec<u8>> = st.logs.keys().filter(|log| st.capability(log).is_ok()).cloned().collect();
        for log in &followed {
            self.follow(log);
        }
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
        self.spawn(self.clone().polling());
    }

    /// Sends what steps produced, in order, once it is durable.
    async fn send_out(self: Arc<Self>, mut outbox: mpsc::UnboundedReceiver<(Vec<Out>, Vec<Event>)>) {
        while let Some((out, events)) = outbox.recv().await {
            if let Err(error) = self.durable().await {
                self.warn(None, format!("{error:#}"));
                return;
            }
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

    /// Dials a member, at the relay its leaf names and then this session's, and tells `Peers` how it went.
    fn dial(self: &Arc<Self>, peer: EndpointId) {
        let relay = {
            let mut st = self.lock();
            let leaves = st.groups.values().flat_map(|g| g.mls.members()).filter_map(|m| m.leaf);
            let relay = leaves.into_iter().find(|leaf| endpoint_id(&leaf.key.0) == Some(peer)).and_then(|leaf| leaf.relay.parse().ok());
            if relay.is_none() {
                let now = st.tick();
                st.peers.dialed(peer.as_bytes(), false, now);
            }
            relay
        };
        let Some(relay) = relay else { return };
        let inner = self.clone();
        spawn(async move {
            let dialed = inner.net().dial(peer, vec![relay], vec![inner.relay.clone()]).await;
            if let Err(error) = &dialed {
                tracing::debug!("dialing {}: {error:#}", peer.fmt_short());
            }
            let mut st = inner.lock();
            let now = st.tick();
            st.peers.dialed(peer.as_bytes(), dialed.is_ok(), now);
        });
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
                Work::Follow { log, old } => {
                    self.unfollow(&old);
                    self.follow(&log);
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

#[cfg(test)]
mod tests {
    use super::*;
    use lmk_core::provider::MemoryProvider;
    use lmk_proto::peer::Frame;

    #[tokio::test]
    async fn cached_file_work_requires_durability() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let relay = lmk_testing::relay().await;
        for failed in [false, true] {
            let fail = Arc::new(AtomicBool::new(false));
            let failing = fail.clone();
            let config = Config {
                handle: "Alice".into(), device: None, relay: relay.url.clone(), ca: relay.ca(),
                home: None, files: None, disk: None, file_limit: 0, kinds: vec![],
                durable: Some(Arc::new(move || {
                    let fail = failing.load(Ordering::SeqCst);
                    Box::pin(async move {
                        anyhow::ensure!(!fail, "injected persistence failure");
                        Ok(())
                    })
                })),
            };
            let (node, mut events) = Node::start(MemoryProvider::default(), config).await.unwrap();
            let link = node.net().add_file(std::io::Cursor::new(b"cached file")).await.unwrap();
            assert!(node.net().has(link.hash).await.unwrap());
            if failed {
                fail.store(true, Ordering::SeqCst);
                assert!(node.inner.durable().await.is_err());
                fail.store(false, Ordering::SeqCst);
            }
            node.fetch(&[], link.clone());
            if failed {
                let event = tokio::time::timeout(std::time::Duration::from_secs(10), events.recv()).await.unwrap().unwrap();
                assert!(matches!(event, Event::Warning { text, .. } if text.contains("injected persistence failure")), "cached file escaped the failed barrier");
                assert!(node.inner.outbox.is_closed());
                while let Ok(event) = events.try_recv() {
                    assert!(!matches!(event, Event::File(_)), "cached file escaped the failed barrier");
                }
            } else {
                let event = tokio::time::timeout(std::time::Duration::from_secs(10), events.recv()).await.unwrap().unwrap();
                assert!(matches!(event, Event::File(hash) if hash == link.hash));
            }
            node.shutdown().await.unwrap();
        }
    }

    struct GatedDisk {
        file: Mutex<Option<([u8; 32], Vec<u8>)>>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    impl lmk_net::Disk for GatedDisk {
        fn has(&self, hash: &[u8; 32]) -> bool {
            self.file.lock().unwrap().as_ref().is_some_and(|(held, _)| held == hash)
        }

        fn load(&self, hash: [u8; 32]) -> n0_future::boxed::BoxFuture<Result<Vec<u8>>> {
            let (held, bytes) = self.file.lock().unwrap().clone().unwrap();
            assert_eq!(held, hash);
            let (entered, release) = (self.entered.clone(), self.release.clone());
            Box::pin(async move {
                entered.notify_one();
                release.notified().await;
                Ok(bytes)
            })
        }

        fn save(&self, hash: [u8; 32], ciphertext: Vec<u8>) -> n0_future::boxed::BoxFuture<Result<()>> {
            *self.file.lock().unwrap() = Some((hash, ciphertext));
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn state_file_completion_requires_durability() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use lmk_proto::group::{PROTOCOL, Settings};
        let relay = lmk_testing::relay().await;
        let disk = Arc::new(GatedDisk {
            file: Mutex::new(None),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        });
        let config = Config {
            handle: "Writer".into(), device: None, relay: relay.url.clone(), ca: relay.ca(),
            home: None, files: None, disk: Some(disk.clone()), file_limit: 0, kinds: vec![], durable: None,
        };
        let (writer, _) = Node::start(MemoryProvider::default(), config).await.unwrap();
        let data = b"the complete state";
        let link = writer.net().add_file(std::io::Cursor::new(data)).await.unwrap();
        writer.shutdown().await.unwrap();
        for failed in [false, true] {
            let fail = Arc::new(AtomicBool::new(false));
            let failing = fail.clone();
            let config = Config {
                handle: "Reader".into(), device: None, relay: relay.url.clone(), ca: relay.ca(),
                home: None, files: None, disk: Some(disk.clone()), file_limit: 0, kinds: vec!["test".into()],
                durable: Some(Arc::new(move || {
                    let fail = failing.load(Ordering::SeqCst);
                    Box::pin(async move {
                        anyhow::ensure!(!fail, "injected persistence failure");
                        Ok(())
                    })
                })),
            };
            let (node, mut events) = Node::start(MemoryProvider::default(), config).await.unwrap();
            let gid = node.create(Settings {
                protocol: PROTOCOL, kind: "test".into(), name: "Plan".into(), carry: 7,
                update: lmk_proto::group::UPDATE, membership: relay.service.clone(), public: None, rest: Default::default(),
            }, None).unwrap();
            assert_eq!(node.net().held(link.hash).await.unwrap(), 0);
            node.inner.state_from(&gid.0, link.link(), node.net().id());
            // On this single-thread runtime, state_from just registered the last task, before it could be polled.
            let completion = node.inner.tasks.lock().unwrap().pop().unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(10), disk.entered.notified()).await.unwrap();
            assert!(!completion.is_finished());
            assert!(node.files().iter().any(|file| file.hash == link.hash));
            if failed {
                fail.store(true, Ordering::SeqCst);
                assert!(node.inner.durable().await.is_err());
                fail.store(false, Ordering::SeqCst);
            }
            disk.release.notify_one();
            tokio::time::timeout(std::time::Duration::from_secs(10), completion).await.unwrap().unwrap();
            assert!(node.net().held(link.hash).await.unwrap() > 0, "the file completed after the barrier");
            if failed {
                while let Ok(event) = events.try_recv() {
                    assert!(!matches!(event, Event::State { .. }), "state escaped the failed barrier");
                    if let Event::Warning { text, .. } = event {
                        assert!(!text.contains("state did not arrive"), "{text}");
                    }
                }
            } else {
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        match events.recv().await.unwrap() {
                            Event::State { group, data: received, .. } => {
                                assert_eq!(group, gid);
                                assert_eq!(received, data);
                                break;
                            }
                            Event::Warning { text, .. } => panic!("{text}"),
                            _ => {}
                        }
                    }
                }).await.unwrap();
            }
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_durability_closes_peer_outbox_and_withholds_client_effects() {
        let relay = lmk_testing::relay().await;
        let config = Config {
            handle: "Alice".into(), device: None, relay: relay.url.clone(), ca: relay.ca(),
            home: None, files: None, disk: None, file_limit: 0, kinds: vec![],
            durable: Some(Arc::new(|| Box::pin(async { anyhow::bail!("injected persistence failure") }))),
        };
        let (node, mut events) = Node::start(MemoryProvider::default(), config).await.unwrap();
        let peer = node.net().id();
        let out = vec![Out::Frame { peer, frame: Frame::Hello { groups: vec![], heads: vec![] } }, Out::WantFiles { peer, group: vec![1] }];
        assert!(node.inner.outbox.send((out, vec![Event::Heard { group: Bytes(vec![1]) }])).is_ok());
        let event = tokio::time::timeout(std::time::Duration::from_secs(10), events.recv()).await.unwrap().unwrap();
        assert!(matches!(event, Event::Warning { text, .. } if text.contains("injected persistence failure")));
        assert!(events.try_recv().is_err(), "a failed barrier releases none of the batch's events");
        assert!(node.inner.outbox.is_closed(), "no later peer batch can bypass the failure");
        assert!(node.inner.durable().await.is_err(), "failure stays latched until restart");
        tokio::time::timeout(std::time::Duration::from_secs(10), node.shutdown()).await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn output_waits_for_success_and_shutdown_cancels_an_in_flight_barrier() {
        let relay = lmk_testing::relay().await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let saving = entered.clone();
        let release = Arc::new(tokio::sync::Notify::new());
        let saved = release.clone();
        let config = Config {
            handle: "Alice".into(), device: None, relay: relay.url.clone(), ca: relay.ca(),
            home: None, files: None, disk: None, file_limit: 0, kinds: vec![],
            durable: Some(Arc::new(move || {
                saving.notify_one();
                let saved = saved.clone();
                Box::pin(async move { saved.notified().await; Ok(()) })
            })),
        };
        let (node, mut events) = Node::start(MemoryProvider::default(), config).await.unwrap();
        assert!(node.inner.outbox.send((vec![], vec![Event::Heard { group: Bytes(vec![1]) }])).is_ok());
        tokio::time::timeout(std::time::Duration::from_secs(10), entered.notified()).await.unwrap();
        assert!(events.try_recv().is_err());
        release.notify_one();
        assert!(matches!(events.recv().await, Some(Event::Heard { .. })));

        assert!(node.inner.outbox.send((vec![], vec![Event::Heard { group: Bytes(vec![2]) }])).is_ok());
        tokio::time::timeout(std::time::Duration::from_secs(10), entered.notified()).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), node.shutdown()).await.unwrap().unwrap();
        assert!(!matches!(events.try_recv(), Ok(Event::Heard { .. })), "shutdown cancels the barrier in flight");
    }
}
