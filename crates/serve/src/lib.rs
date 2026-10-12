//! `letmeknow serve`: the membership service and an embedded iroh relay.

use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
};

use anyhow::{Context, Result};
use http::{Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    service::{Service as HyperService, service_fn},
};
use hyper_util::rt::TokioIo;
use iroh::{
    Endpoint, RelayConfig, RelayMap, RelayMode, SecretKey, endpoint::presets, protocol::Router, tls::CaTlsConfig,
};
use iroh_relay::{
    KeyCache, RelayQuicConfig,
    server::{
        AllowAll, ClientRateLimit, Handlers, Metrics, QuicConfig, RelayService, Server, ServerConfig,
        http_server::{BytesBody, HyperError, RelayServiceWithNotify},
        streams::MaybeTlsStream,
    },
};
use lmk_membership::{
    service::{Policy, Service},
    store::Store,
};
use lmk_proto::{frame::ALPN, group};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use socket2::{Domain, Socket, Type};
use tokio::{net::TcpListener, sync::Notify};
use tokio_rustls_acme::{AcmeConfig, caches::DirCache};
use tokio_stream::StreamExt;

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
    /// The membership service's iroh endpoint.
    pub membership_port: u16,
    /// Holds the service's key, its database and the ACME cache.
    pub state: PathBuf,
    pub certificate: Certificate,
    /// Bytes a second that the relay reads from each connection.
    pub relay_rate_limit: NonZeroU32,
    pub policy: Policy,
}

impl ServeConfig {
    pub fn new(domain: impl Into<String>, state: impl Into<PathBuf>) -> Self {
        ServeConfig {
            domain: domain.into(),
            https_port: 443,
            http_port: Some(80),
            qad_port: 7842,
            membership_port: 7843,
            state: state.into(),
            certificate: Certificate::Acme { contact: None },
            relay_rate_limit: NonZeroU32::new(1 << 20).unwrap(),
            policy: Policy::default(),
        }
    }

    pub fn relay_url(&self) -> String {
        match self.https_port {
            443 => format!("https://{}", self.domain),
            port => format!("https://{}:{port}", self.domain),
        }
    }

    /// The address members put in their settings: the service's key and relay.
    pub fn service(&self) -> Result<group::Service> {
        let store = Store::open(&self.state)
            .with_context(|| format!("opening the service's state in {}; make a new one with `serve --initialize`", self.state.display()))?;
        let key = store.key().verifying_key();
        Ok(group::Service::Serve {
            key: (*key.as_bytes()).into(),
            relay: self.relay_url(),
            addrs: vec![],
            rest: Default::default(),
        })
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
    let secret = SecretKey::from_bytes(&store.key().to_bytes());
    let mut roots = Vec::new();
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
            roots = chain.clone();
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

    let relay_config = RelayConfig::new(config.relay_url().parse()?, Some(RelayQuicConfig::new(config.qad_port)));
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .relay_mode(RelayMode::Custom(RelayMap::from_iter([relay_config])))
        .ca_tls_config(CaTlsConfig::embedded().with_extra_roots(roots))
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::UNSPECIFIED, config.membership_port))?
        .bind_addr((Ipv6Addr::UNSPECIFIED, config.membership_port))?
        .bind()
        .await?;
    let health = Bytes::from(format!(
        r#"{{"version":"{}","membership":"{}"}}"#,
        env!("CARGO_PKG_VERSION"),
        hex::encode(store.key().verifying_key().as_bytes())
    ));
    let _router = Router::builder(endpoint)
        .accept(ALPN, Service::new(store, config.policy))
        .spawn();

    let tls = Arc::new(tls);
    loop {
        let (tcp, _) = https.accept().await?;
        let (tls, relay, health) = (tls.clone(), relay.clone(), health.clone());
        tokio::spawn(async move {
            let stream = match &*tls {
                Tls::Files(acceptor) => acceptor.accept(tcp).await.ok(),
                Tls::Acme(acceptor, server_config) => match acceptor.accept(tcp).await {
                    Ok(Some(start)) => start.into_stream(server_config.clone()).await.ok(),
                    _ => None,
                },
            };
            let Some(stream) = stream else { return };
            let site = Site {
                relay: RelayServiceWithNotify::new(relay, Arc::new(Notify::new())),
                health,
            };
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(MaybeTlsStream::Tls(stream)), site)
                .with_upgrades()
                .await;
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
}

type Answer = Pin<Box<dyn Future<Output = Result<Response<BytesBody>, HyperError>> + Send>>;

impl HyperService<Request<Incoming>> for Site {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = Answer;

    fn call(&self, req: Request<Incoming>) -> Answer {
        match req.uri().path() {
            "/relay" => return Box::pin(self.relay.call(req)),
            "/ping" => {
                let res = respond(StatusCode::OK)
                    .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                    .body(body(""));
                return Box::pin(std::future::ready(res.map_err(Into::into)));
            }
            "/health" => {
                let res = respond(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CACHE_CONTROL, "no-store")
                    .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                    .body(body(self.health.clone()));
                return Box::pin(std::future::ready(res.map_err(Into::into)));
            }
            _ => {}
        }
        Box::pin(std::future::ready(
            respond(StatusCode::NOT_FOUND).body(body("not found")).map_err(Into::into),
        ))
    }
}
