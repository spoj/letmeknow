//! What `letmeknow serve` runs, in a test's process: a relay with a self-signed certificate on local ports, and membership
//! services on ports of their own, reached over https with that certificate.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes as Body, Incoming};
use hyper::{Method, Request, Response, StatusCode, service::service_fn};
use hyper_util::rt::TokioIo;
use iroh::endpoint::presets;
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use lmk_membership::client::{Post, Resolve, ServeClient, https};
use lmk_membership::service::{Policy, Route, Service as Membership};
use lmk_membership::store::Store;
use lmk_proto::Bytes;
use lmk_proto::directory::Directory;
use lmk_proto::head::Head;
use lmk_proto::membership::Known;
use lmk_proto::group::Service;
use lmk_proto::membership::MAX_BODY;
use n0_future::boxed::BoxFuture;
use n0_future::task::AbortOnDropHandle;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The certificates of the relays made here, which the membership services of all of them are served with.
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

pub struct Relay {
    pub url: RelayUrl,
    pub cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    /// A membership service in memory, for the groups and identities a test makes, at the domain its relay's port names.
    pub service: Service,
    _server: Server,
    _membership: AbortOnDropHandle<()>,
    _state: tempfile::TempDir,
}

impl Relay {
    pub fn ca(&self) -> CaTlsConfig {
        CaTlsConfig::custom_roots([self.cert.clone()])
    }

    /// Posts to the membership services of the relays made here, over https as a shell does.
    pub fn post(&self) -> Post {
        let roots = CERTS.lock().unwrap().clone();
        let tls = CaTlsConfig::custom_roots(roots).client_config(Arc::new(rustls::crypto::ring::default_provider())).unwrap();
        https(reqwest::Client::builder().tls_backend_preconfigured(tls).no_proxy().build().unwrap())
    }

    /// An endpoint that reaches others through this relay.
    pub async fn endpoint(&self, secret: SecretKey) -> Endpoint {
        endpoint(&self.url, &self.cert, secret).await
    }

    /// Another membership service, its store at `db`, served over https at a port of its own; it runs while the guard
    /// lives. The service limits nothing.
    pub async fn serve(&self, db: &Path) -> (Service, AbortOnDropHandle<()>) {
        membership(&self.url, &self.cert, &self.key, db).await
    }
}

pub async fn relay() -> Relay {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    serve(cert, key).await
}

/// Another relay, with the certificate of `first`, so that whoever trusts one trusts both.
pub async fn relay_beside(first: &Relay) -> Relay {
    serve(first.cert.clone(), first.key.clone_key()).await
}

async fn serve(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Relay {
    CERTS.lock().unwrap().push(cert.clone());
    let tls = server_config(cert.clone(), key.clone_key());
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.tls = Some(TlsConfig::new((Ipv6Addr::UNSPECIFIED, 0), CertConfig::Manual { server_config: tls.clone() }));
    let mut quic = QuicConfig::new((Ipv6Addr::UNSPECIFIED, 0));
    quic.server_config = Some(tls);
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    config.quic = Some(quic);
    let server = Server::spawn(config).await.unwrap();
    let url = format!("https://localhost:{}", server.https_addr().unwrap().port()).parse().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (service, membership) = membership(&url, &cert, &key, &state.path().join("membership")).await;
    Relay { url, cert, key, service, _server: server, _membership: membership, _state: state }
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

/// Serves a membership service from `db` over https on a port of its own, which is its domain.
async fn membership(url: &RelayUrl, cert: &CertificateDer<'static>, key: &PrivateKeyDer<'static>, db: &Path) -> (Service, AbortOnDropHandle<()>) {
    let store = Store::initialize(db).unwrap();
    let public = store.key().verifying_key().to_bytes();
    let membership = Membership::new(store, unlimited());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert.clone(), key.clone_key())));
    let task = AbortOnDropHandle::new(n0_future::task::spawn(async move {
        loop {
            let Ok((tcp, peer)) = listener.accept().await else { return };
            let (acceptor, membership) = (acceptor.clone(), membership.clone());
            n0_future::task::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let answer = service_fn(move |req| answer(membership.clone(), peer.ip(), req));
                _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), answer).await;
            });
        }
    }));
    let domain = format!("localhost:{port}");
    publish(&domain, Directory { key: public, relay: url.to_string(), relays: vec![url.to_string()] });
    (Service::Serve { key: Bytes(public.to_vec()), domain, rest: Default::default() }, task)
}

/// The membership routes, as `letmeknow serve` answers them: the service's answer as its body, or 404 and 503 alone.
async fn answer(membership: Membership, peer: IpAddr, req: Request<Incoming>) -> Result<Response<Full<Body>>, Infallible> {
    let (status, body) = match Route::parse(req.uri().path()) {
        Some(route) if req.method() == Method::POST => match membership.admit(peer) {
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
    Ok(Response::builder().status(status).body(Full::new(Body::from(body))).unwrap())
}

/// The head of a log, which a heads request answers whatever length it names, as no log has `u64::MAX` entries.
pub async fn head(client: &ServeClient, capability: &[u8; 32]) -> Head {
    client.heads(&[Known(*capability, u64::MAX)]).await.unwrap().remove(0)
}

/// Limits no test's traffic: no test counts its appends.
fn unlimited() -> Policy {
    let big = 1 << 40;
    Policy {
        appends_per_minute: u32::MAX, append_bytes_per_day: big, reads_per_minute: u32::MAX, read_bytes_per_minute: big,
        new_logs_per_day: big, new_public_logs_per_day: big, public_appends_per_day: big, new_logs_per_day_in_all: big,
        requests_at_once: 1 << 20, ..Policy::default()
    }
}
