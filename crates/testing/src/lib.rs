//! What `letmeknow serve` runs, in a test's process: membership services with self-signed certificates, each with its relay
//! beside it, on a local port of its own that is its domain.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes as Body, Incoming};
use hyper::service::Service as HyperService;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use iroh::endpoint::presets;
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_relay::KeyCache;
use iroh_relay::server::http_server::{BytesBody, HyperError, RelayServiceWithNotify};
use iroh_relay::server::streams::MaybeTlsStream;
use iroh_relay::server::{AllowAll, Handlers, Metrics, RelayService};
use lmk_membership::client::{Post, Resolve, ServeClient, https};
use lmk_membership::service::{Policy, Route, Service as Membership};
use lmk_membership::store::Store;
use lmk_proto::Bytes;
use lmk_proto::directory::{Directory, relay_url};
use lmk_proto::head::Head;
use lmk_proto::membership::Known;
use lmk_proto::group::Service;
use lmk_proto::membership::MAX_BODY;
use n0_future::boxed::BoxFuture;
use n0_future::task::AbortOnDropHandle;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

/// The certificates of the services made here, each of which `post` trusts.
static CERTS: Mutex<Vec<CertificateDer<'static>>> = Mutex::new(Vec::new());

/// The directories the test services' domains publish, as a shell's fetches would answer.
static DIRECTORIES: Mutex<BTreeMap<String, Directory>> = Mutex::new(BTreeMap::new());

/// Publishes the directory a domain answers with.
pub fn publish(domain: &str, directory: Directory) {
    DIRECTORIES.lock().unwrap().insert(domain.into(), directory);
}

/// Makes a domain answer with no directory, as one that is down.
pub fn withdraw(domain: &str) {
    DIRECTORIES.lock().unwrap().remove(domain);
}

/// Resolves domains to the directories published here.
pub fn resolve() -> Resolve {
    Arc::new(|domain: String| -> BoxFuture<anyhow::Result<Directory>> {
        let found = DIRECTORIES.lock().unwrap().get(&domain).cloned();
        Box::pin(async move { found.ok_or_else(|| anyhow::anyhow!("no directory for {domain}")) })
    })
}

/// A membership service, for the groups and identities a test makes, and the relay it runs beside it.
pub struct Relay {
    pub url: RelayUrl,
    /// The service's domain, `localhost:<port>`.
    pub domain: String,
    pub cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    pub service: Service,
    /// The membership service of `service`, to expire its history.
    pub membership: Membership,
    _task: AbortOnDropHandle<()>,
    _state: tempfile::TempDir,
}

impl Relay {
    pub fn ca(&self) -> CaTlsConfig {
        CaTlsConfig::custom_roots([self.cert.clone()])
    }

    /// Posts to the membership services made here, over https as a shell does.
    pub fn post(&self) -> Post {
        let roots = CERTS.lock().unwrap().clone();
        let tls = CaTlsConfig::custom_roots(roots).client_config(Arc::new(rustls::crypto::ring::default_provider())).unwrap();
        https(reqwest::Client::builder().tls_backend_preconfigured(tls).no_proxy().build().unwrap())
    }

    /// An endpoint that reaches others through this relay.
    pub async fn endpoint(&self, secret: SecretKey) -> Endpoint {
        endpoint(&self.url, &self.cert, secret).await
    }

    /// Another membership service with its relay, its store at `db`, with this one's certificate, so that whoever trusts
    /// one trusts both; it runs while the guard lives.
    pub async fn serve(&self, db: &Path) -> (Service, AbortOnDropHandle<()>) {
        let (service, _, task) = serve(&self.cert, &self.key, db).await;
        (service, task)
    }
}

/// A service with a self-signed certificate of its own, named apart from the others' (which `post` trusts too): a client
/// checks a certificate against the roots of its issuer's name, and gives up past 100 checks.
pub async fn relay() -> Relay {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, format!("relay {}", CERTS.lock().unwrap().len()));
    let signing_key = rcgen::KeyPair::generate().unwrap();
    let cert = CertificateDer::from(params.self_signed(&signing_key).unwrap().der().to_vec());
    let key = PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap();
    CERTS.lock().unwrap().push(cert.clone());
    let state = tempfile::tempdir().unwrap();
    let (service, membership, task) = serve(&cert, &key, &state.path().join("membership")).await;
    let Service::Serve { domain, .. } = &service else { unreachable!() };
    let (url, domain) = (relay_url(domain).parse().unwrap(), domain.clone());
    Relay { url, domain, cert, key, service, membership, _task: task, _state: state }
}

fn server_config(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> rustls::ServerConfig {
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap()
}

async fn endpoint(url: &RelayUrl, cert: &CertificateDer<'static>, secret: SecretKey) -> Endpoint {
    let relays = RelayMap::from(iroh::RelayConfig::new(url.clone(), Some(Default::default())));
    let ca = CaTlsConfig::custom_roots([cert.clone()]);
    Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(relays)).ca_tls_config(ca).secret_key(secret).bind().await.unwrap()
}

/// Serves a membership service from `db`, and a relay, over https on a port of its own, which is its domain. The service
/// limits nothing.
async fn serve(cert: &CertificateDer<'static>, key: &PrivateKeyDer<'static>, db: &Path) -> (Service, Membership, AbortOnDropHandle<()>) {
    let store = Store::initialize(db).unwrap();
    let public = store.key().verifying_key().to_bytes();
    let membership = Membership::new(store, unlimited());
    let handle = membership.clone();
    let relay = RelayService::new(Handlers::default(), HeaderMap::new(), None, KeyCache::new(1024), Arc::new(AllowAll), Arc::new(Metrics::default()));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert.clone(), key.clone_key())));
    let task = AbortOnDropHandle::new(n0_future::task::spawn(async move {
        loop {
            let Ok((tcp, peer)) = listener.accept().await else { return };
            let (acceptor, membership, relay) = (acceptor.clone(), membership.clone(), relay.clone());
            n0_future::task::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let site = Site { relay: RelayServiceWithNotify::new(relay, Arc::new(Notify::new())), membership, peer: peer.ip() };
                _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(MaybeTlsStream::Tls(tls)), site).with_upgrades().await;
            });
        }
    }));
    let domain = format!("localhost:{port}");
    publish(&domain, Directory { key: public });
    (Service::Serve { key: Bytes(public.to_vec()), domain, rest: Default::default() }, handle, task)
}

struct Site {
    relay: RelayServiceWithNotify,
    membership: Membership,
    peer: IpAddr,
}

impl HyperService<Request<Incoming>> for Site {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = BoxFuture<Result<Response<BytesBody>, HyperError>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        match req.uri().path() {
            "/relay" => Box::pin(self.relay.call(req)),
            "/ping" => Box::pin(std::future::ready(Ok(Response::new(Box::new(Full::new(Body::new())) as BytesBody)))),
            _ => Box::pin(answer(self.membership.clone(), self.peer, req)),
        }
    }
}

/// The membership routes, as `letmeknow serve` answers them: the service's answer as its body, or 404 and 503 alone.
async fn answer(membership: Membership, peer: IpAddr, req: Request<Incoming>) -> Result<Response<BytesBody>, HyperError> {
    let (status, body) = match Route::parse(req.uri().path()) {
        Some(route) if req.method() == Method::POST => match membership.admit(peer, route, MAX_BODY) {
            None => (StatusCode::SERVICE_UNAVAILABLE, Vec::new()),
            Some(admission) => match Limited::new(req.into_body(), MAX_BODY).collect().await {
                Ok(collected) => match membership.post(route, &admission, &collected.to_bytes()).await {
                    Ok(answer) => (StatusCode::OK, answer),
                    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Vec::new()),
                },
                Err(_) => (StatusCode::BAD_REQUEST, Vec::new()),
            },
        },
        _ => (StatusCode::NOT_FOUND, b"not found".to_vec()),
    };
    Ok(Response::builder().status(status).body(Box::new(Full::new(Body::from(body))) as BytesBody).unwrap())
}

/// The head of a log, which a heads request answers whatever length it names, as no log has `u64::MAX` entries.
pub async fn head(client: &ServeClient, capability: &[u8; 32]) -> Head {
    client.heads(&[Known(*capability, u64::MAX)]).await.unwrap().remove(0).unwrap()
}

/// Limits no test's traffic: no test counts its appends.
fn unlimited() -> Policy {
    let big = 1 << 40;
    Policy {
        appends_per_minute: u32::MAX, append_bytes_per_day: big, reads_per_minute: u32::MAX, read_bytes_per_minute: big,
        new_logs_per_day: big,
        requests_at_once: 1 << 20, bytes_at_once: big, bytes_at_once_in_all: big, ..Policy::default()
    }
}
