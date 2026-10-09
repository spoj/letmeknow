//! Everything a session says to its peers over iroh: one `letmeknow/1` connection per pair of
//! sessions, its `peer` and `invite` streams, and files over iroh-blobs. MLS stays outside, behind
//! [`Groups`]: this crate moves ciphertexts and holds no keys.

mod files;
mod peer;
mod seal;
mod sync;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl,
    endpoint::{Builder, Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use lmk_proto::{
    Answer, Bytes,
    frame::{self, ALPN, Open, Stream},
    head::Head,
    identity::Envelope,
    links::{FileLink, Invite},
    peer::{Admitted, Frame, Hello, InviteRequest, Keys, KindFrame},
};
use n0_future::{boxed::BoxFuture, join_all, task::spawn, time::timeout};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

use crate::{files::Files, peer::Input};

/// How long to wait for a peer's `have`.
const ANSWER_WAIT: Duration = Duration::from_secs(5);

/// What this crate needs from the group logic, which holds the MLS state, the logs and the
/// messages. Calls are quick and local.
pub trait Groups: Send + Sync + 'static {
    /// The groups this session is in.
    fn groups(&self) -> Vec<Vec<u8>>;
    /// Whether `peer` is in a leaf of the group's current epoch.
    fn is_member(&self, group: &[u8], peer: &EndpointId) -> bool;
    /// This session's state of the group, as `hello` carries it.
    fn hello(&self, group: &[u8]) -> Hello;
    /// Whether the group's membership service signed `head`; a folder's heads are unsigned.
    fn verify_head(&self, group: &[u8], head: &Head) -> bool;
    /// This session's chain hash after `position` entries, if it knows it.
    fn chain(&self, group: &[u8], position: u64) -> Option<[u8; 32]>;
    /// This session's log entries after `position`.
    fn entries(&self, group: &[u8], after: u64) -> Vec<Bytes>;
    /// Applies entries that directly follow this session's log and end at `head`, already
    /// checked against its chain.
    fn apply(&self, group: &[u8], entries: Vec<Bytes>, head: Head) -> Result<()>;
    /// (epoch, message id) of every message held or given up on, from epoch `from`, in the order this session took them.
    fn items(&self, group: &[u8], from: u64) -> Vec<(u64, [u8; 32])>;
    /// A held message's MLS ciphertext.
    fn message(&self, group: &[u8], id: &[u8; 32]) -> Option<Vec<u8>>;
    /// An MLS ciphertext from a peer: decrypt, verify, and hold or apply it, or give it up.
    fn receive(&self, group: &[u8], ciphertext: &[u8]) -> Taken;
    /// A frame of the group's kind from `peer`, a member.
    fn frame(&self, peer: EndpointId, frame: KindFrame);
    /// A link to the state of the group's kind, which `peer`, a member, hands this session; without one, `peer` asks
    /// for the kind's state.
    fn state(&self, group: &[u8], peer: EndpointId, link: Option<String>);
    /// The newest signed head `peer`, a member, holds of the group's kind log.
    fn log_head(&self, peer: EndpointId, group: &[u8], head: Head);
    /// The files the group links now.
    fn files(&self, group: &[u8]) -> Vec<FileLink>;
    /// The key logs this session holds, with signed heads, of the identities in these groups.
    fn keys(&self, groups: &[Vec<u8>]) -> Vec<Keys>;
    /// A key log `peer` presented.
    fn key_log(&self, peer: EndpointId, keys: Keys);
    /// The certificates this session holds of these groups' members.
    fn certificates(&self, groups: &[Vec<u8>]) -> Vec<Envelope>;
    /// A certificate `peer` presented.
    fn certificate(&self, peer: EndpointId, certificate: Envelope);
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

/// What became of a ciphertext a peer sent; the peer hears which unless it waits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Taken {
    Held,
    Refused(String),
    /// Kept until a commit it follows is applied.
    Waiting,
}

/// The inviter's decisions; each may commit an Add before it answers.
pub trait Admit: Send + Sync + 'static {
    fn invite(&self, peer: EndpointId, request: InviteRequest) -> BoxFuture<Answer<Admitted>>;
    /// A `join` request for an open group.
    fn join(&self, peer: EndpointId, group: Vec<u8>, key_package: Vec<u8>, certificate: Envelope) -> BoxFuture<Answer<Admitted>>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Connected(EndpointId),
    Disconnected(EndpointId),
    /// Two incompatible signed heads: the membership service showed members different logs.
    Contradiction { group: Vec<u8>, peer: EndpointId, ours: Head, theirs: Head },
    /// What `peer` did with messages this session sent it.
    Receipt { group: Vec<u8>, peer: EndpointId, held: Vec<[u8; 32]>, refused: Vec<([u8; 32], String)> },
    /// This session and `peer` hold the same log of the group: a time to compare the state of its kind.
    InStep { group: Vec<u8>, peer: EndpointId },
    /// Message sync with `peer` finished.
    Synced { group: Vec<u8>, peer: EndpointId },
    /// A file is now held whole.
    Fetched([u8; 32]),
}

pub struct Config {
    /// The relay for an invite link that names none.
    pub relay: RelayUrl,
    /// `LETMEKNOW_HOME`, where sessions of one device publish their addresses to each other.
    pub home: Option<PathBuf>,
    /// Where files are kept; in memory if none.
    pub files: Option<PathBuf>,
    pub disk: Option<Arc<dyn Disk>>,
    /// The largest file fetched without being asked.
    pub file_limit: u64,
    /// How often two connected sessions swap heads and sync their groups again.
    pub resync: Duration,
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
    router: Router,
}

pub(crate) struct Inner {
    endpoint: Endpoint,
    config: Config,
    groups: Arc<dyn Groups>,
    admit: Arc<dyn Admit>,
    files: Arc<Files>,
    links: Mutex<HashMap<EndpointId, Link>>,
    events: mpsc::UnboundedSender<Event>,
}

struct Link {
    conn: Connection,
    dialer: EndpointId,
    input: mpsc::UnboundedSender<Input>,
}

impl Net {
    pub async fn spawn(
        endpoint: Endpoint,
        config: Config,
        groups: Arc<dyn Groups>,
        admit: Arc<dyn Admit>,
    ) -> Result<(Net, mpsc::UnboundedReceiver<Event>)> {
        let files = Arc::new(Files::new(endpoint.clone(), config.files.clone(), config.disk.clone(), groups.clone(), config.collect).await?);
        #[cfg(not(target_family = "wasm"))]
        if let Some(home) = &config.home {
            addresses::publish(&endpoint, home)?;
        }
        let (events, rx) = mpsc::unbounded_channel();
        let blobs = files.protocol(groups.clone());
        let inner = Arc::new(Inner { endpoint: endpoint.clone(), config, groups, admit, files, links: Mutex::default(), events });
        let router = Router::builder(endpoint).accept(ALPN, Handler(inner.clone())).accept(iroh_blobs::ALPN, blobs).spawn();
        Ok((Net { inner, router }, rx))
    }

    pub fn id(&self) -> EndpointId {
        self.inner.endpoint.id()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.inner.endpoint
    }

    /// Connects to a member by the key and relay in its leaf, unless already connected.
    pub async fn dial(&self, key: EndpointId, relay: RelayUrl) -> Result<()> {
        self.inner.connection(key, relay).await?;
        Ok(())
    }

    pub fn connected(&self) -> Vec<EndpointId> {
        self.inner.links.lock().unwrap().keys().copied().collect()
    }

    /// Sends a new MLS message to the members online; returns whom it went to.
    pub fn send(&self, group: &[u8], ciphertext: Vec<u8>) -> Vec<EndpointId> {
        let frame = Frame::Messages { group: group.into(), items: vec![Bytes(ciphertext)] };
        self.inner.members(group).into_iter().filter(|(_, input)| input.send(Input::Send(frame.clone())).is_ok()).map(|(peer, _)| peer).collect()
    }

    /// Sends a new MLS message to one member online, if it is connected.
    pub fn send_to(&self, peer: EndpointId, group: &[u8], ciphertext: Vec<u8>) -> bool {
        self.frame(peer, Frame::Messages { group: group.into(), items: vec![Bytes(ciphertext)] })
    }

    /// Sends a frame to one member online, if it is connected.
    pub fn frame(&self, peer: EndpointId, frame: Frame) -> bool {
        let input = self.inner.links.lock().unwrap().get(&peer).map(|link| link.input.clone());
        input.is_some_and(|input| input.send(Input::Send(frame)).is_ok())
    }

    /// Tells peers this session's state of a group changed (a commit applied, a member added):
    /// each gets a new `hello`, and the entries it lacks.
    pub fn changed(&self, group: &[u8]) {
        self.inner.changed(group);
    }

    /// Redeems an invite link on an `invite` stream to the inviter.
    pub async fn redeem(&self, invite: &Invite, key_package: Vec<u8>, certificate: Option<Envelope>) -> Result<Answer<Admitted>> {
        let key = EndpointId::from_bytes(&invite.key)?;
        let relay = match &invite.relay {
            Some(relay) => relay.parse()?,
            None => self.inner.config.relay.clone(),
        };
        let conn = self.inner.connection(key, relay).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        frame::write(&mut send, &Open { stream: Stream::Invite }).await?;
        frame::write(&mut send, &InviteRequest { secret: invite.secret.into(), key_package: Bytes(key_package), certificate }).await?;
        send.finish()?;
        frame::read(&mut recv).await
    }

    /// Asks a member of an open group to admit this session, which shows its certificate.
    pub async fn join(&self, peer: EndpointId, relay: RelayUrl, group: &[u8], key_package: Vec<u8>, certificate: Envelope) -> Result<Answer<Admitted>> {
        self.inner.connection(peer, relay).await?;
        let (reply, answer) = oneshot::channel();
        let input = self.inner.links.lock().unwrap().get(&peer).map(|link| link.input.clone()).context("not connected")?;
        input.send(Input::Join { group: group.into(), key_package: Bytes(key_package), certificate, reply })?;
        Ok(answer.await?)
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
        self.router.shutdown().await?;
        #[cfg(not(target_family = "wasm"))]
        if let Some(home) = &self.inner.config.home {
            std::fs::remove_file(addresses::path(home, &self.id()))?;
        }
        Ok(())
    }
}

impl Inner {
    async fn connection(self: &Arc<Self>, key: EndpointId, relay: RelayUrl) -> Result<Connection> {
        if let Some(conn) = self.live(&key) {
            return Ok(conn);
        }
        #[allow(unused_mut)]
        let mut addr = EndpointAddr::new(key).with_relay_url(relay);
        #[cfg(not(target_family = "wasm"))]
        if let Some(home) = &self.config.home {
            addr = addresses::read(home, &key).into_iter().fold(addr, EndpointAddr::with_ip_addr);
        }
        let conn = self.endpoint.connect(addr, ALPN).await?;
        match self.register(&conn, true) {
            Some((input, rx)) => {
                spawn(self.clone().serve(conn.clone(), true, input, rx));
                Ok(conn)
            }
            None => self.live(&key).context("the connection closed"),
        }
    }

    fn live(&self, key: &EndpointId) -> Option<Connection> {
        let links = self.links.lock().unwrap();
        links.get(key).map(|link| link.conn.clone()).filter(|conn| conn.close_reason().is_none())
    }

    /// Keeps one connection per peer: of two live ones, the one dialed by the smaller key, which
    /// both sides pick alike; a redial replaces the old one.
    fn register(&self, conn: &Connection, dialed: bool) -> Option<(mpsc::UnboundedSender<Input>, mpsc::UnboundedReceiver<Input>)> {
        let (me, peer) = (self.endpoint.id(), conn.remote_id());
        let dialer = if dialed { me } else { peer };
        let mut links = self.links.lock().unwrap();
        match links.get(&peer).filter(|old| old.conn.close_reason().is_none()) {
            Some(old) if old.dialer != dialer && old.dialer == me.min(peer) => {
                conn.close(0u32.into(), b"duplicate");
                return None;
            }
            Some(old) => old.conn.close(0u32.into(), b"duplicate"),
            None => {
                self.events.send(Event::Connected(peer)).ok();
            }
        }
        let (input, rx) = mpsc::unbounded_channel();
        links.insert(peer, Link { conn: conn.clone(), dialer, input: input.clone() });
        Some((input, rx))
    }

    fn unregister(&self, conn: &Connection) {
        let peer = conn.remote_id();
        let mut links = self.links.lock().unwrap();
        if links.get(&peer).is_some_and(|link| link.conn.stable_id() == conn.stable_id()) {
            links.remove(&peer);
            self.events.send(Event::Disconnected(peer)).ok();
        }
    }

    /// Runs a connection's streams until it closes. The dialer opens the one `peer` stream.
    async fn serve(self: Arc<Self>, conn: Connection, dialed: bool, input: mpsc::UnboundedSender<Input>, rx: mpsc::UnboundedReceiver<Input>) {
        let peer = conn.remote_id();
        let mut rx = Some(rx);
        if dialed {
            match open_peer(&conn).await {
                Ok((send, recv)) => {
                    spawn(peer::run(self.clone(), conn.clone(), true, send, recv, input.clone(), rx.take().unwrap()));
                }
                Err(e) => tracing::debug!("no peer stream to {}: {e:#}", peer.fmt_short()),
            }
        }
        while let Ok((send, mut recv)) = conn.accept_bi().await {
            let Ok(open) = frame::read::<Open, _>(&mut recv).await else { continue };
            match open.stream {
                Stream::Peer => {
                    if let Some(rx) = rx.take() {
                        spawn(peer::run(self.clone(), conn.clone(), false, send, recv, input.clone(), rx));
                    }
                }
                Stream::Invite => {
                    let inner = self.clone();
                    spawn(async move {
                        if let Err(e) = inner.answer_invite(peer, send, recv).await {
                            tracing::debug!("invite stream from {}: {e:#}", peer.fmt_short());
                        }
                    });
                }
                Stream::Membership => {}
            }
        }
        self.unregister(&conn);
    }

    async fn answer_invite(&self, peer: EndpointId, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
        let request = frame::read(&mut recv).await?;
        let answer = self.admit.invite(peer, request).await;
        frame::write(&mut send, &answer).await?;
        send.finish()?;
        Ok(())
    }

    /// The peers online that are members of a group, by this session's view.
    fn members(&self, group: &[u8]) -> Vec<(EndpointId, mpsc::UnboundedSender<Input>)> {
        let links: Vec<_> = self.links.lock().unwrap().iter().map(|(peer, link)| (*peer, link.input.clone())).collect();
        links.into_iter().filter(|(peer, _)| self.groups.is_member(group, peer)).collect()
    }

    fn changed(&self, group: &[u8]) {
        for link in self.links.lock().unwrap().values() {
            link.input.send(Input::Changed(group.into())).ok();
        }
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

async fn open_peer(conn: &Connection) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = conn.open_bi().await?;
    frame::write(&mut send, &Open { stream: Stream::Peer }).await?;
    Ok((send, recv))
}

#[derive(Debug, Clone)]
struct Handler(Arc<Inner>);

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner").field("id", &self.endpoint.id()).finish()
    }
}

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        if let Some((input, rx)) = self.0.register(&conn, false) {
            self.0.clone().serve(conn, false, input, rx).await;
        }
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
