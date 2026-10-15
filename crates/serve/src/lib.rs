//! `letmeknow serve`: the membership service and an embedded iroh relay.

use std::{
    convert::Infallible,
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{Context, Result};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    service::{Service as HyperService, service_fn},
};
use hyper_util::rt::{TokioIo, TokioTimer};
use iroh_relay::{
    KeyCache,
    server::{
        AllowAll, ClientRateLimit, Handlers, Metrics, QuicConfig, RelayService, Server, ServerConfig,
        http_server::{BytesBody, HyperError, RelayServiceWithNotify},
        streams::MaybeTlsStream,
    },
};
use lmk_membership::{
    service::{Admission, Policy, Route, Service},
    store::Store,
};
use lmk_proto::{directory::{self, Directory}, group, membership::MAX_BODY};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use socket2::{Domain, Socket, Type};
use tokio::{
    net::TcpListener,
    sync::{Notify, watch},
    time::{Instant, sleep_until, timeout},
};
use tokio_rustls_acme::{AcmeConfig, caches::DirCache};
use tokio_stream::StreamExt;

/// The app's origin: its pages may append to the membership service, as may those `--origin` adds.
const APP: &str = "https://letmeknow.dev";
const HANDSHAKE: Duration = Duration::from_secs(10);
const HEADERS: Duration = Duration::from_secs(10);
const BODY: Duration = Duration::from_secs(15);
/// How long a membership answer may take to drain before its connection is closed.
const DRAIN: Duration = Duration::from_secs(30);
/// Hyper takes an answer's next chunk once it has room to write it.
const CHUNK: usize = 64 << 10;

pub enum Certificate {
    /// From Let's Encrypt, by TLS-ALPN-01 on the HTTPS port; cached in the state directory.
    Acme { contact: Option<String> },
    /// PEM files: a certificate chain and its key.
    Files { chain: PathBuf, key: PathBuf },
}

pub struct ServeConfig {
    pub domain: String,
    pub https_port: u16,
    /// For `/generate_204` and redirects to HTTPS; `None` leaves it closed.
    pub http_port: Option<u16>,
    /// QUIC address discovery. Clients given only the relay's URL assume 7842.
    pub qad_port: u16,
    /// The relays the directory names, which members live on; empty names this service's own `relay_url()`.
    pub relays: Vec<String>,
    /// Holds the service's key, its database and the ACME cache.
    pub state: PathBuf,
    pub certificate: Certificate,
    /// Bytes a second that the relay reads from each connection.
    pub relay_rate_limit: NonZeroU32,
    pub policy: Policy,
    /// Origins besides the app's whose pages may append to the membership service.
    pub origins: Vec<String>,
}

impl ServeConfig {
    pub fn new(domain: impl Into<String>, state: impl Into<PathBuf>) -> Self {
        ServeConfig {
            domain: domain.into(),
            https_port: 443,
            http_port: Some(80),
            qad_port: 7842,
            relays: vec![],
            state: state.into(),
            certificate: Certificate::Acme { contact: None },
            relay_rate_limit: NonZeroU32::new(1 << 20).unwrap(),
            policy: Policy::default(),
            origins: vec![],
        }
    }

    /// Where the service's directory is published: `host`, or `host:port` off the default port.
    pub fn domain(&self) -> String {
        match self.https_port {
            443 => self.domain.clone(),
            port => format!("{}:{port}", self.domain),
        }
    }

    pub fn relay_url(&self) -> String {
        format!("https://{}", self.domain())
    }

    /// The address members put in their settings: the service's key and domain.
    pub fn service(&self) -> Result<group::Service> {
        let store = Store::open(&self.state)
            .with_context(|| format!("opening the service's state in {}; make a new one with `serve --initialize`", self.state.display()))?;
        let key = store.key().verifying_key();
        directory::check_domain(&self.domain())?;
        Ok(group::Service::Serve { key: (*key.as_bytes()).into(), domain: self.domain(), rest: Default::default() })
    }

    pub fn initialize(&self) -> Result<group::Service> {
        drop(Store::initialize(&self.state)?);
        self.service()
    }
}

enum Tls {
    Acme(tokio_rustls_acme::AcmeAcceptor, Arc<rustls::ServerConfig>),
    Files(tokio_rustls::TlsAcceptor),
}

fn rustls_builder() -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert> {
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default versions")
        .with_no_client_auth()
}

/// Runs until the HTTPS listener fails.
pub async fn serve(config: ServeConfig) -> Result<()> {
    let store = Store::open(&config.state)?;
    let (tls, server_config) = match &config.certificate {
        Certificate::Acme { contact } => {
            let mut state = AcmeConfig::new([&config.domain])
                .contact(contact.iter().map(|c| format!("mailto:{c}")))
                .directory_lets_encrypt(true)
                .cache(DirCache::new(config.state.join("acme")))
                .state();
            let server_config = Arc::new(rustls_builder().with_cert_resolver(state.resolver()));
            let acceptor = state.acceptor();
            tokio::spawn(async move {
                while let Some(event) = state.next().await {
                    match event {
                        Ok(ok) => tracing::info!("acme: {ok:?}"),
                        Err(err) => tracing::warn!("acme: {err:?}"),
                    }
                }
            });
            (Tls::Acme(acceptor, server_config.clone()), server_config)
        }
        Certificate::Files { chain, key } => {
            let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(chain)?
                .collect::<Result<_, _>>()
                .context("reading the certificate")?;
            let key = PrivateKeyDer::from_pem_file(key).context("reading the key")?;
            let server_config = Arc::new(rustls_builder().with_single_cert(chain, key)?);
            (
                Tls::Files(tokio_rustls::TlsAcceptor::from(server_config.clone())),
                server_config,
            )
        }
    };

    let mut qad = QuicConfig::new((Ipv6Addr::UNSPECIFIED, config.qad_port));
    qad.server_config = Some((*server_config).clone());
    let mut qad_config = ServerConfig::default();
    qad_config.quic = Some(qad);
    let _qad = Server::spawn(qad_config).await?;

    let relay = RelayService::new(
        Handlers::default(),
        http::HeaderMap::new(),
        Some(ClientRateLimit::new(config.relay_rate_limit)),
        KeyCache::new(1024),
        Arc::new(AllowAll),
        Arc::new(Metrics::default()),
    );
    let https = listen_all(config.https_port)?;
    if let Some(port) = config.http_port {
        let http = listen_all(port)?;
        tokio::spawn(redirect(http, config.relay_url()));
    }

    let directory = Directory {
        key: *store.key().verifying_key().as_bytes(),
        relay: config.relay_url(),
        relays: if config.relays.is_empty() { vec![config.relay_url()] } else { config.relays.clone() },
    };
    directory.check()?;
    let directory = Bytes::from(serde_json::to_vec(&directory)?);
    let health = Bytes::from(format!(
        r#"{{"version":"{}","membership":"{}"}}"#,
        env!("CARGO_PKG_VERSION"),
        hex::encode(store.key().verifying_key().as_bytes())
    ));
    let membership = Service::new(store, config.policy);

    let tls = Arc::new(tls);
    let origins = Arc::new(std::iter::once(APP.to_owned()).chain(config.origins.iter().cloned()).collect::<Vec<_>>());
    loop {
        let (tcp, peer) = https.accept().await?;
        let (tls, relay, health, directory, membership, origins) =
            (tls.clone(), relay.clone(), health.clone(), directory.clone(), membership.clone(), origins.clone());
        tokio::spawn(async move {
            let stream = timeout(HANDSHAKE, async move {
                match &*tls {
                    Tls::Files(acceptor) => acceptor.accept(tcp).await.ok(),
                    Tls::Acme(acceptor, server_config) => match acceptor.accept(tcp).await {
                        Ok(Some(start)) => start.into_stream(server_config.clone()).await.ok(),
                        _ => None,
                    },
                }
            }).await.ok().flatten();
            let Some(stream) = stream else { return };
            let (drain, mut draining) = watch::channel(None);
            let site = Site {
                relay: RelayServiceWithNotify::new(relay, Arc::new(Notify::new())),
                health,
                directory,
                membership,
                peer: peer.ip(),
                origins,
                drain,
            };
            let connection = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADERS)
                .serve_connection(TokioIo::new(MaybeTlsStream::Tls(stream)), site)
                .with_upgrades();
            tokio::pin!(connection);
            loop {
                let deadline = *draining.borrow_and_update();
                let drained = async {
                    match deadline {
                        Some(deadline) => sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    biased;
                    _ = &mut connection => return,
                    _ = drained => return,
                    _ = draining.changed() => {}
                }
            }
        });
    }
}

/// A TCP listener on every address, IPv4 and IPv6: a bare `[::]` takes IPv4 too on Linux, but not on Windows.
fn listen_all(port: u16) -> Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(false)?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(TcpListener::from_std(socket.into())?)
}

fn respond(status: StatusCode) -> http::response::Builder {
    Response::builder().status(status)
}

fn body(bytes: impl Into<Bytes>) -> BytesBody {
    Box::new(Full::new(bytes.into()))
}

fn json(bytes: impl Into<Bytes>) -> http::Result<Response<BytesBody>> {
    respond(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(body(bytes))
}

/// Port 80: the captive-portal check iroh clients make, and redirects to HTTPS.
async fn redirect(listener: TcpListener, base: String) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let base = base.clone();
        let service = service_fn(move |req: Request<Incoming>| {
            let res = if req.uri().path() == "/generate_204" {
                let mut res = respond(StatusCode::NO_CONTENT);
                if let Some(challenge) = req.headers().get("x-iroh-challenge").and_then(|c| c.to_str().ok()) {
                    res = res.header("x-iroh-response", format!("response {challenge}"));
                }
                res.body(body(""))
            } else {
                let path = req.uri().path_and_query().map_or("/", |p| p.as_str());
                respond(StatusCode::MOVED_PERMANENTLY)
                    .header(header::LOCATION, format!("{base}{path}"))
                    .body(body(""))
            };
            std::future::ready(res)
        });
        tokio::spawn(hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), service));
    }
}

/// WebSocket upgrades at /relay are cross-origin and cookie-free; iroh authenticates the peers.
struct Site {
    relay: RelayServiceWithNotify,
    /// This release's version and the service's public key, which rollouts compare with the release they install.
    health: Bytes,
    /// The directory at `/.well-known/letmeknow.json`.
    directory: Bytes,
    membership: Service,
    /// The address membership budgets count the request against.
    peer: IpAddr,
    origins: Arc<Vec<String>>,
    /// When the last membership answer must have drained, unless another request follows it.
    drain: watch::Sender<Option<Instant>>,
}

/// An answer, which holds its admission until it is written or dropped.
struct Held { answer: Bytes, _admission: Admission }

impl Body for Held {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let chunk = self.answer.len().min(CHUNK);
        Poll::Ready((chunk > 0).then(|| Ok(Frame::data(self.answer.split_to(chunk)))))
    }

    fn is_end_stream(&self) -> bool { self.answer.is_empty() }

    fn size_hint(&self) -> SizeHint { SizeHint::with_exact(self.answer.len() as u64) }
}

/// Membership requests. Only the app's origins, and those `--origin` adds, may send them: another page could otherwise
/// make its visitors append. A path with no route is a 404 those origins can read, so a page learns the service runs
/// another minor.
async fn answer_membership(route: Option<Route>, service: Service, peer: IpAddr, origins: Arc<Vec<String>>, drain: watch::Sender<Option<Instant>>, req: Request<Incoming>) -> http::Result<Response<BytesBody>> {
    let origin = req.headers().get(header::ORIGIN).cloned();
    if !origin.as_ref().is_none_or(|o| o.to_str().is_ok_and(|o| origins.iter().any(|allowed| allowed == o))) {
        return respond(StatusCode::FORBIDDEN).body(body(""));
    }
    let allow = |res: http::response::Builder| match &origin {
        Some(o) => res.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, o),
        None => res,
    };
    match (req.method(), route) {
        (&Method::OPTIONS, _) => allow(respond(StatusCode::NO_CONTENT))
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "POST")
            .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type")
            .header(header::ACCESS_CONTROL_MAX_AGE, "600")
            .body(body("")),
        (_, None) => allow(respond(StatusCode::NOT_FOUND)).body(body("not found")),
        (&Method::POST, Some(route)) => {
            let size = req.body().size_hint().upper().map_or(MAX_BODY, |upper| MAX_BODY.min(upper as usize));
            let Some(mut admission) = service.admit(peer, route, size) else {
                return respond(StatusCode::SERVICE_UNAVAILABLE).body(body(""));
            };
            let Ok(Ok(collected)) = timeout(BODY, Limited::new(req.into_body(), MAX_BODY).collect()).await else {
                return respond(StatusCode::BAD_REQUEST).body(body(""));
            };
            match service.post(route, &admission, &collected.to_bytes()).await {
                Ok(answer) => {
                    admission.keep(answer.len());
                    drain.send_replace(Some(Instant::now() + DRAIN));
                    allow(respond(StatusCode::OK))
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::CACHE_CONTROL, "no-store")
                        .body(Box::new(Held { answer: answer.into(), _admission: admission }))
                }
                Err(_) => respond(StatusCode::INTERNAL_SERVER_ERROR).body(body("")),
            }
        }
        _ => respond(StatusCode::METHOD_NOT_ALLOWED).header(header::ALLOW, "POST, OPTIONS").body(body("")),
    }
}

type Answer = Pin<Box<dyn Future<Output = Result<Response<BytesBody>, HyperError>> + Send>>;

impl HyperService<Request<Incoming>> for Site {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = Answer;

    fn call(&self, req: Request<Incoming>) -> Answer {
        self.drain.send_replace(None);
        if req.uri().path().starts_with("/membership/") {
            let route = Route::parse(req.uri().path());
            let (service, peer, origins, drain) = (self.membership.clone(), self.peer, self.origins.clone(), self.drain.clone());
            return Box::pin(async move { answer_membership(route, service, peer, origins, drain, req).await.map_err(Into::into) });
        }
        match req.uri().path() {
            "/relay" => return Box::pin(self.relay.call(req)),
            "/ping" => {
                let res = respond(StatusCode::OK)
                    .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                    .body(body(""));
                return Box::pin(std::future::ready(res.map_err(Into::into)));
            }
            "/.well-known/letmeknow.json" => return Box::pin(std::future::ready(json(self.directory.clone()).map_err(Into::into))),
            "/health" => return Box::pin(std::future::ready(json(self.health.clone()).map_err(Into::into))),
            // What the service took in each of the last completed days, which it keeps nothing private of.
            "/stats" => {
                let membership = self.membership.clone();
                return Box::pin(async move {
                    let res = match membership.stats().await {
                        Ok(stats) => json(serde_json::to_vec(&stats).unwrap()),
                        Err(_) => respond(StatusCode::SERVICE_UNAVAILABLE).body(body("busy")),
                    };
                    res.map_err(Into::into)
                });
            }
            _ => {}
        }
        Box::pin(std::future::ready(
            respond(StatusCode::NOT_FOUND).body(body("not found")).map_err(Into::into),
        ))
    }
}
