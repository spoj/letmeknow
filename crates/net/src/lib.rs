//! Everything a session says to its peers over iroh: one `letmeknow/2` connection per pair of sessions, its `peer`
//! stream of frames, an `admission` stream per joiner's request, and files over iroh-blobs. What the frames mean is the
//! node's (see [`peers`]): this crate moves them, answers the files' `want_files`, and holds no keys. A simulator runs
//! it over its own transport instead.

mod files;
mod peer;
pub mod peers;
mod seal;

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl,
    endpoint::{Builder, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use lmk_proto::{
    Answer,
    frame::{self, ALPN, Open, Stream},
    links::FileLink,
    peer::{Admitted, Frame, Join},
};
use lmk_transport::{Conn, IrohConnection, Iroh, RecvStream, SendStream, Transport};
use n0_future::{boxed::BoxFuture, join_all, task::spawn, time::timeout};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

use crate::{
    files::{Blobs, Files},
    peer::Input,
};

/// How long to wait for a peer's `have`.
const ANSWER_WAIT: Duration = Duration::from_secs(5);

/// What this crate needs from the group logic to serve files and gate frames. Calls are quick and local.
pub trait Groups: Send + Sync + 'static {
    /// The groups this session is in.
    fn groups(&self) -> Vec<Vec<u8>>;
    /// Whether this session serves `peer` the group: it is in a leaf and, speaking as an identity, its device is on the
    /// identity's list.
    fn is_member(&self, group: &[u8], peer: &EndpointId) -> bool;
    /// The files the group links now.
    fn files(&self, group: &[u8]) -> Vec<FileLink>;
    /// What of a frame goes to `peer` as it is written, by the gate as it is then: none if nothing.
    fn admit(&self, peer: &EndpointId, frame: Frame) -> Option<Frame>;
}

/// A browser's own storage of the files it holds, since iroh-blobs keeps only memory there. With one, a session keeps
/// there the files it adds and those it fetches up to its limit, holds and serves only those, and loads each into
/// memory when it is needed.
pub trait Disk: Send + Sync + 'static {
    fn has(&self, hash: &[u8; 32]) -> bool;
    /// A kept file's ciphertext.
    fn load(&self, hash: [u8; 32]) -> BoxFuture<Result<Vec<u8>>>;
    fn save(&self, hash: [u8; 32], ciphertext: Vec<u8>);
}

/// How a session reaches its peers: iroh, or another transport, such as a simulator's, over which files move whole.
pub enum Network {
    Iroh(Endpoint),
    Other { transport: Arc<dyn Transport>, fetch: Arc<dyn Fetch> },
}

impl Network {
    pub fn transport(&self) -> Arc<dyn Transport> {
        match self {
            Network::Iroh(endpoint) => Arc::new(Iroh(endpoint.clone())),
            Network::Other { transport, .. } => transport.clone(),
        }
    }
}

/// Fetches a file whole from a peer that holds it, over a transport other than iroh: the peer answers by
/// [`Net::upload`].
pub trait Fetch: Send + Sync + 'static {
    fn fetch(&self, holder: EndpointId, hash: [u8; 32]) -> BoxFuture<Result<Vec<u8>>>;
}

/// A member's decision on a joiner's request; it may commit an Add before it answers.
pub trait Admit: Send + Sync + 'static {
    fn join(&self, peer: EndpointId, join: Join) -> BoxFuture<Answer<Admitted>>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A `peer` stream with the peer started, replacing any other.
    Connected(EndpointId),
    Disconnected(EndpointId),
    /// A frame on the peer's stream, but files' `want_files` and `have`, which this crate answers.
    Frame(EndpointId, Frame),
    /// A file is now held whole.
    Fetched([u8; 32]),
}

pub struct Config {
    /// `LETMEKNOW_HOME`, where sessions of one device publish their addresses to each other.
    pub home: Option<PathBuf>,
    /// Where files are kept; in memory if none.
    pub files: Option<PathBuf>,
    pub disk: Option<Arc<dyn Disk>>,
    /// The largest file fetched without being asked.
    pub file_limit: u64,
    /// How often the files no group links any longer are deleted.
    pub collect: Duration,
}

/// An endpoint with our relays and no address lookup; relay connections honour the proxy
/// environment variables.
pub fn builder(relays: RelayMap) -> Builder {
    Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(relays)).proxy_from_env()
}

#[derive(Clone)]
pub struct Net {
    inner: Arc<Inner>,
    router: Option<Router>,
}

pub(crate) struct Inner {
    transport: Arc<dyn Transport>,
    config: Config,
    groups: Arc<dyn Groups>,
    admit: Arc<dyn Admit>,
    files: Arc<Files>,
    links: Mutex<BTreeMap<EndpointId, Link>>,
    events: mpsc::UnboundedSender<Event>,
}

struct Link {
    conn: Conn,
    dialer: EndpointId,
    input: mpsc::UnboundedSender<Input>,
}

impl Net {
    pub async fn spawn(
        network: Network,
        config: Config,
        groups: Arc<dyn Groups>,
        admit: Arc<dyn Admit>,
    ) -> Result<(Net, mpsc::UnboundedReceiver<Event>)> {
        let (transport, blobs) = match &network {
            Network::Iroh(endpoint) => (network.transport(), Blobs::Iroh(endpoint.clone())),
            Network::Other { transport, fetch } => (transport.clone(), Blobs::Fetch(fetch.clone())),
        };
        let files = Arc::new(Files::new(blobs, config.files.clone(), config.disk.clone(), groups.clone(), config.collect).await?);
        #[cfg(not(target_family = "wasm"))]
        if let (Network::Iroh(endpoint), Some(home)) = (&network, &config.home) {
            addresses::publish(endpoint, home)?;
        }
        let (events, rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner { transport, config, groups, admit, files, links: Mutex::default(), events });
        let router = match network {
            Network::Iroh(endpoint) => {
                let blobs = inner.files.protocol(inner.groups.clone());
                Some(Router::builder(endpoint).accept(ALPN, Handler(inner.clone())).accept(iroh_blobs::ALPN, blobs).spawn())
            }
            Network::Other { .. } => None,
        };
        Ok((Net { inner, router }, rx))
    }

    pub fn id(&self) -> EndpointId {
        self.inner.transport.id()
    }

    /// Serves a connection a peer opened, until it closes.
    pub async fn accept(&self, conn: Conn) {
        self.inner.clone().accept(conn).await;
    }

    /// A file's ciphertext for a peer that fetches it whole (see [`Fetch`]), by the rules iroh-blobs serves files by.
    pub async fn upload(&self, peer: EndpointId, hash: [u8; 32]) -> Result<Vec<u8>> {
        let groups = &self.inner.groups;
        let linked = groups.groups().iter().any(|g| groups.is_member(g, &peer) && groups.files(g).iter().any(|file| file.hash == hash));
        ensure!(linked && self.inner.files.serve(&hash).await?, "not served");
        self.inner.files.ciphertext(&hash).await
    }

    /// Connects to a member by the key and relay in its leaf, unless already connected.
    pub async fn dial(&self, key: EndpointId, relay: RelayUrl) -> Result<()> {
        self.inner.connection(key, relay).await?;
        Ok(())
    }

    pub fn connected(&self) -> Vec<EndpointId> {
        self.inner.links.lock().unwrap().keys().copied().collect()
    }

    /// Sends a frame to a peer, if it is connected.
    pub fn frame(&self, peer: EndpointId, frame: Frame) -> bool {
        self.inner.input(&peer).is_some_and(|input| input.send(Input::Send(frame)).is_ok())
    }

    /// Asks a peer for the files the group links that this session lacks, within its limit, and fetches those it has.
    pub fn want_files(&self, peer: EndpointId, group: &[u8]) {
        let (inner, group) = (self.inner.clone(), group.to_vec());
        spawn(async move {
            let mut files = Vec::new();
            for link in inner.groups.files(&group) {
                if link.size <= inner.config.file_limit && !inner.files.has(&link.hash).await.unwrap_or(true) {
                    files.push(link.hash);
                }
            }
            if let (false, Some(input)) = (files.is_empty(), inner.input(&peer)) {
                input.send(Input::Want { group: lmk_proto::Bytes(group), files, reply: None }).ok();
            }
        });
    }

    /// Asks a member to admit this session, on an `admission` stream of its own.
    pub async fn join(&self, peer: EndpointId, relay: RelayUrl, join: Join) -> Result<Answer<Admitted>> {
        let conn = self.inner.connection(peer, relay).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        frame::write(&mut send, &Open { stream: Stream::Admission }).await?;
        frame::write(&mut send, &join).await?;
        frame::read(&mut recv).await
    }

    /// Seals a file under a new key and holds it.
    pub async fn add_file(&self, plain: impl AsyncRead + Unpin + Send + Sync + 'static) -> Result<FileLink> {
        self.inner.files.add(plain).await
    }

    /// The members online that hold a file whole.
    pub async fn holders(&self, group: &[u8], hash: [u8; 32]) -> Vec<EndpointId> {
        let asked = self.inner.members(group).into_iter().filter_map(|(peer, input)| {
            let (reply, answer) = oneshot::channel();
            input.send(Input::Want { group: group.into(), files: vec![hash], reply: Some(reply) }).ok()?;
            Some(async move { timeout(ANSWER_WAIT, answer).await.ok()?.ok()?.contains(&hash).then_some(peer) })
        });
        join_all(asked).await.into_iter().flatten().collect()
    }

    /// Fetches a file from every member online that holds it, whatever its size.
    pub async fn fetch(&self, group: &[u8], link: &FileLink) -> Result<()> {
        if self.inner.files.has(&link.hash).await? {
            return Ok(());
        }
        let holders = self.holders(group, link.hash).await;
        if holders.is_empty() {
            bail!("no member online holds {}", link.link());
        }
        for holder in holders {
            self.inner.offer(link, holder);
        }
        if !self.inner.files.wait(&link.hash).await? {
            bail!("could not fetch {}", link.link());
        }
        Ok(())
    }

    /// Whether a file is held whole.
    pub async fn has(&self, hash: [u8; 32]) -> Result<bool> {
        self.inner.files.has(&hash).await
    }

    /// Verified ciphertext bytes held of a file.
    pub async fn held(&self, hash: [u8; 32]) -> Result<u64> {
        self.inner.files.held(&hash).await
    }

    /// Decrypts a held file into `out`.
    pub async fn read_file(&self, link: &FileLink, out: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
        self.inner.files.read(link, out).await
    }

    pub async fn shutdown(&self) -> Result<()> {
        if let Some(router) = &self.router {
            router.shutdown().await?;
        }
        #[cfg(not(target_family = "wasm"))]
        if let Some(home) = &self.inner.config.home {
            std::fs::remove_file(addresses::path(home, &self.id()))?;
        }
        Ok(())
    }
}

impl Inner {
    async fn connection(self: &Arc<Self>, key: EndpointId, relay: RelayUrl) -> Result<Conn> {
        if let Some(conn) = self.live(&key) {
            return Ok(conn);
        }
        #[allow(unused_mut)]
        let mut addr = EndpointAddr::new(key).with_relay_url(relay);
        #[cfg(not(target_family = "wasm"))]
        if let Some(home) = &self.config.home {
            addr = addresses::read(home, &key).into_iter().fold(addr, EndpointAddr::with_ip_addr);
        }
        let conn = self.transport.connect(addr).await?;
        match self.register(&conn, true) {
            Some((input, rx)) => {
                spawn(self.clone().serve(conn.clone(), true, input, rx));
                Ok(conn)
            }
            None => self.live(&key).context("the connection closed"),
        }
    }

    fn live(&self, key: &EndpointId) -> Option<Conn> {
        let links = self.links.lock().unwrap();
        links.get(key).map(|link| link.conn.clone()).filter(|conn| !conn.closed())
    }

    fn input(&self, peer: &EndpointId) -> Option<mpsc::UnboundedSender<Input>> {
        self.links.lock().unwrap().get(peer).map(|link| link.input.clone())
    }

    async fn accept(self: Arc<Self>, conn: Conn) {
        if let Some((input, rx)) = self.register(&conn, false) {
            self.serve(conn, false, input, rx).await;
        }
    }

    /// Keeps one connection per peer: of two live ones, the one dialed by the smaller key, which
    /// both sides pick alike; a redial replaces the old one.
    fn register(&self, conn: &Conn, dialed: bool) -> Option<(mpsc::UnboundedSender<Input>, mpsc::UnboundedReceiver<Input>)> {
        let (me, peer) = (self.transport.id(), conn.remote_id());
        let dialer = if dialed { me } else { peer };
        let mut links = self.links.lock().unwrap();
        match links.get(&peer).filter(|old| !old.conn.closed()) {
            Some(old) if old.dialer != dialer && old.dialer == me.min(peer) => {
                conn.close(b"duplicate");
                return None;
            }
            Some(old) => old.conn.close(b"duplicate"),
            None => {}
        }
        let (input, rx) = mpsc::unbounded_channel();
        links.insert(peer, Link { conn: conn.clone(), dialer, input: input.clone() });
        Some((input, rx))
    }

    fn unregister(&self, conn: &Conn) {
        let peer = conn.remote_id();
        let mut links = self.links.lock().unwrap();
        if links.get(&peer).is_some_and(|link| link.conn.stable_id() == conn.stable_id()) {
            links.remove(&peer);
            self.events.send(Event::Disconnected(peer)).ok();
        }
    }

    /// Runs a connection's streams until it closes. The dialer opens the one `peer` stream.
    async fn serve(self: Arc<Self>, conn: Conn, dialed: bool, input: mpsc::UnboundedSender<Input>, rx: mpsc::UnboundedReceiver<Input>) {
        let peer = conn.remote_id();
        let mut rx = Some(rx);
        if dialed {
            match open_peer(&conn).await {
                Ok((send, recv)) => {
                    spawn(peer::run(self.clone(), conn.clone(), send, recv, input.clone(), rx.take().unwrap()));
                }
                Err(e) => tracing::debug!("no peer stream to {}: {e:#}", peer.fmt_short()),
            }
        }
        while let Ok((send, mut recv)) = conn.accept_bi().await {
            let Ok(open) = frame::read::<Open, _>(&mut recv).await else { continue };
            match open.stream {
                Stream::Peer => {
                    if let Some(rx) = rx.take() {
                        spawn(peer::run(self.clone(), conn.clone(), send, recv, input.clone(), rx));
                    }
                }
                Stream::Admission => {
                    spawn(self.clone().admit(peer, send, recv));
                }
                Stream::Membership => {}
            }
        }
        self.unregister(&conn);
    }

    /// Answers a joiner's request to be admitted.
    async fn admit(self: Arc<Self>, peer: EndpointId, mut send: SendStream, mut recv: RecvStream) {
        let answered = async {
            let join: Join = frame::read(&mut recv).await?;
            let answer = self.admit.join(peer, join).await;
            frame::write(&mut send, &answer).await
        };
        if let Err(e) = answered.await {
            tracing::debug!("admitting {}: {e:#}", peer.fmt_short());
        }
    }

    /// The peers online that are members of a group, by this session's view.
    fn members(&self, group: &[u8]) -> Vec<(EndpointId, mpsc::UnboundedSender<Input>)> {
        let links: Vec<_> = self.links.lock().unwrap().iter().map(|(peer, link)| (*peer, link.input.clone())).collect();
        links.into_iter().filter(|(peer, _)| self.groups.is_member(group, peer)).collect()
    }

    fn offer(self: &Arc<Self>, link: &FileLink, holder: EndpointId) {
        let (events, hash) = (self.events.clone(), link.hash);
        self.files.offer(link, holder, link.size <= self.config.file_limit, move |ok| {
            if ok {
                events.send(Event::Fetched(hash)).ok();
            }
        });
    }
}

async fn open_peer(conn: &Conn) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = conn.open_bi().await?;
    frame::write(&mut send, &Open { stream: Stream::Peer }).await?;
    Ok((send, recv))
}

#[derive(Debug, Clone)]
struct Handler(Arc<Inner>);

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner").field("id", &self.transport.id()).finish()
    }
}

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        self.0.clone().accept(Arc::new(IrohConnection(conn))).await;
        Ok(())
    }
}

/// Sessions of one device find each other through `LETMEKNOW_HOME/addresses/<iroh key>.json`,
/// which holds `{"addrs": ["<ip:port>", ...]}`.
#[cfg(not(target_family = "wasm"))]
mod addresses {
    use std::{
        net::SocketAddr,
        path::{Path, PathBuf},
    };

    use iroh::{Endpoint, EndpointId, Watcher};
    use n0_future::StreamExt;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Addresses {
        addrs: Vec<SocketAddr>,
    }

    pub fn path(home: &Path, key: &EndpointId) -> PathBuf {
        home.join("addresses").join(format!("{key}.json"))
    }

    pub fn publish(endpoint: &Endpoint, home: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(home.join("addresses"))?;
        let path = path(home, &endpoint.id());
        let mut updates = endpoint.watch_addr().stream();
        n0_future::task::spawn(async move {
            while let Some(addr) = updates.next().await {
                let addrs = Addresses { addrs: addr.ip_addrs().copied().collect() };
                let temp = path.with_extension("tmp");
                let written = std::fs::write(&temp, serde_json::to_vec(&addrs).unwrap()).and_then(|()| std::fs::rename(&temp, &path));
                if let Err(e) = written {
                    tracing::warn!("cannot publish addresses at {}: {e}", path.display());
                }
            }
        });
        Ok(())
    }

    pub fn read(home: &Path, key: &EndpointId) -> Vec<SocketAddr> {
        std::fs::read(path(home, key))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Addresses>(&bytes).ok())
            .map_or_else(Vec::new, |addresses| addresses.addrs)
    }
}
