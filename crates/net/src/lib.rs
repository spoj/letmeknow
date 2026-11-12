//! Everything a session says to its peers over iroh: one `letmeknow/11` connection per pair of sessions, its `peer`
//! stream of frames, and an `admission` stream per joiner's request. What the frames mean is the node's (see [`peers`]):
//! this crate moves them, and holds no keys.

mod peer;
pub mod peers;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl,
    endpoint::{Builder, Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use lmk_proto::{
    Answer,
    frame::{self, ALPN, MAX_ASK, Open, Stream},
    peer::{Admitted, Frame, Join},
};
use n0_future::{
    boxed::BoxFuture,
    task::spawn,
    time::{Duration, timeout},
};
use tokio::sync::mpsc;

/// How many events wait for the node: past that, the peers that send them wait.
const EVENTS: usize = 64;
/// How long a connection has to open its `peer` stream, and a stream to send its opening frame or a joiner's request.
const ASK: Duration = Duration::from_secs(30);

/// What this crate needs from the group logic to gate frames. Calls are quick and local.
pub trait Groups: Send + Sync + 'static {
    /// What of a frame goes to `peer` as it is written, by the gate as it is then: none if nothing.
    fn admit(&self, peer: &EndpointId, frame: Frame) -> Option<Frame>;
}

/// A member's decision on a joiner's request; it may commit an Add before it answers.
pub trait Admit: Send + Sync + 'static {
    fn join(&self, peer: EndpointId, join: Join) -> BoxFuture<Answer<Admitted>>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A connection to the peer registered, replacing any other; true when this side dialed it.
    Connected(EndpointId, bool),
    Disconnected(EndpointId),
    /// A frame on the peer's stream.
    Frame(EndpointId, Frame),
}

/// An endpoint with these relays and no address lookup; relay connections honour the proxy
/// environment variables.
pub fn builder(relays: impl IntoIterator<Item = RelayUrl>) -> Builder {
    let builder = Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(relays.into_iter().collect())).proxy_from_env();
    // iroh's default resolver reads Android's DNS configuration through a JVM, which a Termux process has not: it
    // panics there, catches that, and goes on with its public nameservers, which this one starts with.
    #[cfg(target_os = "android")]
    let builder = builder.dns_resolver(iroh::dns::DnsResolver::builder().build());
    builder
}

#[derive(Clone)]
pub struct Net {
    inner: Arc<Inner>,
    router: Router,
}

pub(crate) struct Inner {
    endpoint: Endpoint,
    groups: Arc<dyn Groups>,
    admit: Arc<dyn Admit>,
    links: Mutex<BTreeMap<EndpointId, Link>>,
    events: mpsc::Sender<Event>,
}

struct Link {
    conn: Connection,
    dialer: EndpointId,
    /// The frames to write to the peer.
    out: mpsc::UnboundedSender<Frame>,
}

impl Net {
    pub async fn spawn(
        endpoint: Endpoint,
        groups: Arc<dyn Groups>,
        admit: Arc<dyn Admit>,
    ) -> Result<(Net, mpsc::Receiver<Event>)> {
        let (events, rx) = mpsc::channel(EVENTS);
        let inner = Arc::new(Inner {
            endpoint: endpoint.clone(),
            groups,
            admit,
            links: Mutex::default(),
            events,
        });
        let router = Router::builder(endpoint).accept(ALPN, Handler(inner.clone())).spawn();
        Ok((Net { inner, router }, rx))
    }

    pub fn id(&self) -> EndpointId {
        self.inner.endpoint.id()
    }

    /// Connects to a member at `relays`, unless already connected, giving up when iroh's handshake does, after 30 s.
    pub async fn dial(&self, key: EndpointId, relays: Vec<RelayUrl>) -> Result<()> {
        self.inner.connection(key, relays).await?;
        Ok(())
    }

    pub fn connected(&self) -> Vec<EndpointId> {
        self.inner.links.lock().unwrap().keys().copied().collect()
    }

    /// Closes the link to the peer, if there is one.
    pub fn close(&self, peer: EndpointId) {
        if let Some(conn) = self.inner.live(&peer) {
            conn.close(0u32.into(), b"idle");
        }
    }

    /// Sends a frame to a peer, if it is connected.
    pub fn frame(&self, peer: EndpointId, frame: Frame) -> bool {
        self.inner.links.lock().unwrap().get(&peer).is_some_and(|link| link.out.send(frame).is_ok())
    }

    /// Asks a member, at `relays`, to admit this session, on an `admission` stream of its own.
    pub async fn join(&self, peer: EndpointId, relays: Vec<RelayUrl>, join: Join) -> Result<Answer<Admitted>> {
        let conn = self.inner.connection(peer, relays).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        frame::write(&mut send, &Open { stream: Stream::Admission }).await?;
        frame::write(&mut send, &join).await?;
        frame::read(&mut recv).await
    }

    /// Closes the connections and the endpoint, in full.
    pub async fn shutdown(&self) -> Result<()> {
        self.router.shutdown().await?;
        Ok(())
    }
}

impl Inner {
    async fn connection(self: &Arc<Self>, key: EndpointId, relays: Vec<RelayUrl>) -> Result<Connection> {
        if let Some(conn) = self.live(&key) {
            return Ok(conn);
        }
        let conn = self.endpoint.connect(addr(key, relays), ALPN).await?;
        match self.register(&conn, true) {
            Some(out) => {
                spawn(self.clone().serve(conn.clone(), true, out));
                Ok(conn)
            }
            None => self.live(&key).context("the connection closed"),
        }
    }

    fn live(&self, key: &EndpointId) -> Option<Connection> {
        let links = self.links.lock().unwrap();
        links.get(key).map(|link| link.conn.clone()).filter(|conn| conn.close_reason().is_none())
    }

    async fn accept(self: Arc<Self>, conn: Connection) {
        if let Some(out) = self.register(&conn, false) {
            self.serve(conn, false, out).await;
        }
    }

    /// Keeps one connection per peer: of two live ones, the one dialed by the smaller key, which
    /// both sides pick alike; a redial replaces the old one.
    fn register(&self, conn: &Connection, dialed: bool) -> Option<mpsc::UnboundedReceiver<Frame>> {
        let (me, peer) = (self.endpoint.id(), conn.remote_id());
        let dialer = if dialed { me } else { peer };
        let mut links = self.links.lock().unwrap();
        match links.get(&peer).filter(|old| old.conn.close_reason().is_none()) {
            Some(old) if old.dialer != dialer && old.dialer == me.min(peer) => {
                conn.close(0u32.into(), b"duplicate");
                return None;
            }
            Some(old) => old.conn.close(0u32.into(), b"duplicate"),
            None => {}
        }
        let (out, rx) = mpsc::unbounded_channel();
        links.insert(peer, Link { conn: conn.clone(), dialer, out });
        Some(rx)
    }

    /// Whether the connection was the peer's link, which it no longer is.
    fn unregister(&self, conn: &Connection) -> bool {
        let peer = conn.remote_id();
        let mut links = self.links.lock().unwrap();
        let linked = links.get(&peer).is_some_and(|link| link.conn.stable_id() == conn.stable_id());
        if linked {
            links.remove(&peer);
        }
        linked
    }

    /// Runs a connection's streams until it closes. The dialer opens the one `peer` stream, within `ASK`; it tells of the
    /// connection before the stream's frames, and of its end after.
    async fn serve(self: Arc<Self>, conn: Connection, dialed: bool, out: mpsc::UnboundedReceiver<Frame>) {
        let peer = conn.remote_id();
        self.events.send(Event::Connected(peer, dialed)).await.ok();
        let opened = timeout(ASK, async {
            if dialed {
                return open_peer(&conn).await.inspect_err(|e| tracing::debug!("no peer stream to {}: {e:#}", peer.fmt_short())).ok();
            }
            while let Ok((send, mut recv)) = conn.accept_bi().await {
                let Ok(open) = frame::read_within::<Open, _>(&mut recv, MAX_ASK).await else { continue };
                match open.stream {
                    Stream::Peer => return Some((send, recv)),
                    Stream::Admission => {
                        spawn(self.clone().admit(peer, send, recv));
                    }
                }
            }
            None
        })
        .await;
        if let Ok(Some((send, recv))) = opened {
            spawn(peer::run(self.clone(), conn.clone(), send, recv, out));
            while let Ok((send, mut recv)) = conn.accept_bi().await {
                if let Ok(Ok(Open { stream: Stream::Admission })) = timeout(ASK, frame::read_within(&mut recv, MAX_ASK)).await {
                    spawn(self.clone().admit(peer, send, recv));
                }
            }
        } else {
            conn.close(0u32.into(), b"no peer stream");
        }
        if self.unregister(&conn) {
            self.events.send(Event::Disconnected(peer)).await.ok();
        }
    }

    /// Answers a joiner's request to be admitted, which it sends within `ASK`.
    async fn admit(self: Arc<Self>, peer: EndpointId, mut send: SendStream, mut recv: RecvStream) {
        let answered = async {
            let join: Join = timeout(ASK, frame::read_within(&mut recv, MAX_ASK)).await??;
            let answer = self.admit.join(peer, join).await;
            frame::write(&mut send, &answer).await
        };
        if let Err(e) = answered.await {
            tracing::debug!("admitting {}: {e:#}", peer.fmt_short());
        }
    }
}

fn addr(key: EndpointId, relays: impl IntoIterator<Item = RelayUrl>) -> EndpointAddr {
    relays.into_iter().fold(EndpointAddr::new(key), EndpointAddr::with_relay_url)
}

async fn open_peer(conn: &Connection) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = conn.open_bi().await?;
    frame::write(&mut send, &Open { stream: Stream::Peer }).await?;
    Ok((send, recv))
}

#[derive(Debug)]
struct Handler(Arc<Inner>);

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner").field("id", &self.endpoint.id()).finish()
    }
}

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.0.clone().accept(conn).await;
        Ok(())
    }
}
