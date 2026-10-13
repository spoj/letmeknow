//! What `letmeknow serve` runs, in a test's process: a relay with a self-signed certificate on local ports, and
//! membership services reached through it.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use iroh::endpoint::presets;
use iroh::protocol::{ProtocolHandler, Router};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use lmk_membership::client::Resolve;
use lmk_membership::service::{Policy, Service as Membership};
use lmk_membership::store::Store;
use lmk_proto::Bytes;
use lmk_proto::directory::Directory;
use lmk_proto::frame::ALPN;
use lmk_proto::group::Service;
use n0_future::boxed::BoxFuture;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// The directories the test services' domains publish, as a shell's fetches would answer.
static DIRECTORIES: Mutex<BTreeMap<String, Directory>> = Mutex::new(BTreeMap::new());
static SERVICES: AtomicU32 = AtomicU32::new(0);

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
        Box::pin(async move { found.with_context(|| format!("no directory for {domain}")) })
    })
}

pub struct Relay {
    pub url: RelayUrl,
    pub cert: CertificateDer<'static>,
    /// A membership service in memory, for the groups and identities a test makes, at the domain its relay's port names.
    pub service: Service,
    _server: Server,
    _router: Router,
    _state: tempfile::TempDir,
}

impl Relay {
    pub fn ca(&self) -> CaTlsConfig {
        CaTlsConfig::custom_roots([self.cert.clone()])
    }

    /// An endpoint that reaches others through this relay.
    pub async fn endpoint(&self, secret: SecretKey) -> Endpoint {
        endpoint(&self.url, &self.cert, secret).await
    }

    /// Another membership service, its store at `db`, served through `serve` at a domain of its own; it runs while the
    /// router lives. Neither service limits the rate of appends.
    pub async fn serve<H: ProtocolHandler>(&self, db: &Path, serve: impl FnOnce(Membership) -> H) -> (Service, Router) {
        let number = SERVICES.fetch_add(1, Ordering::Relaxed);
        membership(&self.url, &self.cert, &format!("s{number}.{}", domain(&self.url)), db, serve).await
    }
}

pub async fn relay() -> Relay {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
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
    let (service, router) = membership(&url, &cert, &domain(&url), &state.path().join("membership"), |service| service).await;
    Relay { url, cert, service, _server: server, _router: router, _state: state }
}

async fn endpoint(url: &RelayUrl, cert: &CertificateDer<'static>, secret: SecretKey) -> Endpoint {
    let relays = RelayMap::from(iroh::RelayConfig::new(url.clone(), Some(Default::default())));
    let ca = CaTlsConfig::custom_roots([cert.clone()]);
    Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(relays)).ca_tls_config(ca).secret_key(secret).bind().await.unwrap()
}

/// The `host:port` of a relay's URL, the domain its own service has.
fn domain(url: &RelayUrl) -> String {
    format!("{}:{}", url.host_str().unwrap(), url.port().unwrap())
}

async fn membership<H: ProtocolHandler>(url: &RelayUrl, cert: &CertificateDer<'static>, domain: &str, db: &Path, serve: impl FnOnce(Membership) -> H) -> (Service, Router) {
    let store = Store::initialize(db).unwrap();
    let secret = SecretKey::from_bytes(&store.key().to_bytes());
    let endpoint = endpoint(url, cert, secret).await;
    let router = Router::builder(endpoint.clone()).accept(ALPN, serve(Membership::new(store, Policy { appends_per_minute: u32::MAX, ..Policy::default() }))).spawn();
    let key = Bytes(endpoint.id().as_bytes().to_vec());
    publish(domain, Directory { key: *endpoint.id().as_bytes(), addrs: vec![], relay: url.to_string(), relays: vec![url.to_string()] });
    (Service::Serve { key, domain: domain.into(), rest: Default::default() }, router)
}
