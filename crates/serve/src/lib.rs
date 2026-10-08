//! `letmeknow serve`: the membership service, an embedded iroh relay, and the web client, on one TLS listener.

use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
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
    /// The web client's static files; `None` serves only the relay.
    pub web: Option<PathBuf>,
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
            web: None,
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
        let key = membership_key(&self.state)?.public();
        Ok(group::Service::Serve {
            key: (*key.as_bytes()).into(),
            relay: self.relay_url(),
            addrs: vec![],
        })
    }
}

/// The membership service's iroh key, which also signs its heads; made on first use.
fn membership_key(state: &Path) -> Result<SecretKey> {
    let path = state.join("membership.key");
    if let Ok(bytes) = std::fs::read(&path) {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} is not a key", path.display()))?;
        return Ok(SecretKey::from_bytes(&bytes));
    }
    std::fs::create_dir_all(state)?;
    let key = SecretKey::generate();
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(&path)?, &key.to_bytes())?;
    Ok(key)
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
    std::fs::create_dir_all(&config.state)?;
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
    let https = TcpListener::bind((Ipv6Addr::UNSPECIFIED, config.https_port)).await?;
    if let Some(port) = config.http_port {
        let http = TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)).await?;
        tokio::spawn(redirect(http, config.relay_url()));
    }

    let relay_config = RelayConfig::new(config.relay_url().parse()?, Some(RelayQuicConfig::new(config.qad_port)));
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(membership_key(&config.state)?)
        .relay_mode(RelayMode::Custom(RelayMap::from_iter([relay_config])))
        .ca_tls_config(CaTlsConfig::embedded().with_extra_roots(roots))
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::UNSPECIFIED, config.membership_port))?
        .bind_addr((Ipv6Addr::UNSPECIFIED, config.membership_port))?
        .bind()
        .await?;
    let key = SigningKey::from_bytes(&endpoint.secret_key().to_bytes());
    let store = Store::open(&config.state.join("membership.db"), key)?;
    let _router = Router::builder(endpoint)
        .accept(ALPN, Service::new(store, config.policy))
        .spawn();

    let tls = Arc::new(tls);
    let web = config.web.map(Arc::new);
    loop {
        let (tcp, _) = https.accept().await?;
        let (tls, relay, web) = (tls.clone(), relay.clone(), web.clone());
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
                web,
            };
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(MaybeTlsStream::Tls(stream)), site)
                .with_upgrades()
                .await;
        });
    }
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

/// The HTTPS listener's routes: the relay's, and the web client's files for everything else.
struct Site {
    relay: RelayServiceWithNotify,
    web: Option<Arc<PathBuf>>,
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
            _ => {}
        }
        let web = self.web.clone();
        let path = req.uri().path().to_owned();
        let accept = req.headers().get(header::ACCEPT_ENCODING).and_then(|a| a.to_str().ok()).unwrap_or_default().to_owned();
        Box::pin(async move { Ok(file(web.as_deref(), &path, &accept).await?) })
    }
}

/// A file of the web client, or its `.br` or `.gz` beside it when the client takes that encoding.
async fn file(web: Option<&PathBuf>, path: &str, accept: &str) -> http::Result<Response<BytesBody>> {
    let not_found = || respond(StatusCode::NOT_FOUND).body(body("not found"));
    let Some(web) = web else { return not_found() };
    let name = path.trim_start_matches('/');
    if name.split('/').any(|part| part == ".." || part.starts_with('.')) {
        return not_found();
    }
    let last = name.rsplit('/').next().unwrap_or_default();
    let name = if last.contains('.') { name } else { "index.html" };
    let ext = name.rsplit('.').next().unwrap_or_default();
    let res = respond(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type(ext))
        .header(header::VARY, "accept-encoding");
    for (encoding, suffix) in [("br", "br"), ("gzip", "gz")] {
        if accept.split(',').any(|a| a.split(';').next().map(str::trim) == Some(encoding))
            && let Ok(bytes) = tokio::fs::read(web.join(format!("{name}.{suffix}"))).await
        {
            return res.header(header::CONTENT_ENCODING, encoding).body(body(bytes));
        }
    }
    let Ok(bytes) = tokio::fs::read(web.join(name)).await else {
        return not_found();
    };
    res.body(body(bytes))
}

fn content_type(ext: &str) -> &'static str {
    match ext {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "wasm" => "application/wasm",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
