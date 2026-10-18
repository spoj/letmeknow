//! Everything a session says to its peers over iroh: one `letmeknow/6` connection per pair of sessions, its `peer`
//! stream of frames, and an `admission` stream per joiner's request. What the frames mean is the node's (see [`peers`]):
//! this crate moves them, and holds no keys.

mod peer;
pub mod peers;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, Watcher,
    endpoint::{Builder, Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use lmk_proto::{
    Answer,
    frame::{self, ALPN, Open, Stream},
    peer::{Admitted, Frame, Join},
};
use n0_future::{StreamExt, boxed::BoxFuture, task::spawn, time::timeout};
use tokio::sync::mpsc;

use crate::peer::Input;

/// How long a dial at the hint's relays may take before it is dropped for a dial at all relays.
const HINT_WAIT: Duration = Duration::from_secs(2);

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
    /// A `peer` stream with the peer started, replacing any other; true when this side dialed it.
    Connected(EndpointId, bool),
    Disconnected(EndpointId),
    /// A frame on the peer's stream.
    Frame(EndpointId, Frame),
    /// The endpoint's home relay is now this one.
    Home(RelayUrl),
}

/// An endpoint with these relays and no address lookup; relay connections honour the proxy
/// environment variables.
pub fn builder(relays: impl IntoIterator<Item = RelayUrl>) -> Builder {
    Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(relays.into_iter().collect())).proxy_from_env()
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
        groups: Arc<dyn Groups>,
        admit: Arc<dyn Admit>,
    ) -> Result<(Net, mpsc::UnboundedReceiver<Event>)> {
        let (events, rx) = mpsc::unbounded_channel();
        let mut homes = endpoint.watch_addr().stream();
        let reporting = events.clone();
        spawn(endpoint.closed().run_until(async move {
            let mut last = None;
            while let Some(addr) = homes.next().await {
                if let Some(home) = addr.relay_urls().next()
                    && last.as_ref() != Some(home)
                {
                    last = Some(home.clone());
                    reporting.send(Event::Home(home.clone())).ok();
                }
            }
        }));
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

    /// Connects to a member, unless already connected: at the `hint` relays, or if that takes over 2 s, at those and the
    /// `fallback` relays, giving up 5 s later. The fallback is resolved from the start, and awaited once the 2 s are up.
    pub async fn dial(&self, key: EndpointId, hint: Vec<RelayUrl>, fallback: BoxFuture<Vec<RelayUrl>>) -> Result<()> {
        self.inner.connection(key, hint, fallback).await?;
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
        self.inner.input(&peer).is_some_and(|input| input.send(Input::Send(frame)).is_ok())
    }

    /// Asks a member to admit this session, on an `admission` stream of its own.
    pub async fn join(&self, peer: EndpointId, hint: Vec<RelayUrl>, fallback: BoxFuture<Vec<RelayUrl>>, join: Join) -> Result<Answer<Admitted>> {
        let conn = self.inner.connection(peer, hint, fallback).await?;
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
    async fn connection(self: &Arc<Self>, key: EndpointId, hint: Vec<RelayUrl>, fallback: BoxFuture<Vec<RelayUrl>>) -> Result<Connection> {
        if let Some(conn) = self.live(&key) {
            return Ok(conn);
        }
        let fallback = spawn(fallback);
        let hinted = if hint.is_empty() {
            None
        } else {
            timeout(HINT_WAIT, self.endpoint.connect(addr(key, hint.clone()), ALPN)).await.ok().and_then(Result::ok)
        };
        let conn = match hinted {
            Some(conn) => {
                fallback.abort();
                conn
            }
            None => {
                let relays = fallback.await?;
                self.endpoint.connect(addr(key, hint.into_iter().chain(relays)), ALPN).await?
            }
        };
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

    fn input(&self, peer: &EndpointId) -> Option<mpsc::UnboundedSender<Input>> {
        self.links.lock().unwrap().get(peer).map(|link| link.input.clone())
    }

    async fn accept(self: Arc<Self>, conn: Connection) {
        if let Some((input, rx)) = self.register(&conn, false) {
            self.serve(conn, false, input, rx).await;
        }
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
            None => {}
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
                    spawn(peer::run(self.clone(), conn.clone(), send, recv, input.clone(), rx.take().unwrap(), dialed));
                }
                Err(e) => tracing::debug!("no peer stream to {}: {e:#}", peer.fmt_short()),
            }
        }
        while let Ok((send, mut recv)) = conn.accept_bi().await {
            let Ok(open) = frame::read::<Open, _>(&mut recv).await else { continue };
            match open.stream {
                Stream::Peer => {
                    if let Some(rx) = rx.take() {
                        spawn(peer::run(self.clone(), conn.clone(), send, recv, input.clone(), rx, dialed));
                    }
                }
                Stream::Admission => {
                    spawn(self.clone().admit(peer, send, recv));
                }
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
