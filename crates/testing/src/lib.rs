//! What `letmeknow serve` runs, in a test's process: a relay with a self-signed certificate on local ports, and
//! membership services reached through it.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

use iroh::endpoint::presets;
use iroh::protocol::{ProtocolHandler, Router};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use lmk_membership::service::{Policy, Service as Membership};
use lmk_membership::store::Store;
use lmk_proto::Bytes;
use lmk_proto::frame::ALPN;
use lmk_proto::group::Service;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub struct Relay {
    pub url: RelayUrl,
    pub cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    /// A membership service in memory, for the groups and identities a test makes.
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

    /// Another membership service, its store at `db`, served through `serve`; it runs while the router lives. Neither
    /// service limits the rate of appends.
    pub async fn serve<H: ProtocolHandler>(&self, db: &Path, serve: impl FnOnce(Membership) -> H) -> (Service, Router) {
        membership(&self.url, &self.cert, db, serve).await
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
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.clone_key())
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
    let (service, router) = membership(&url, &cert, &state.path().join("membership"), |service| service).await;
    Relay { url, cert, key, service, _server: server, _router: router, _state: state }
}

async fn endpoint(url: &RelayUrl, cert: &CertificateDer<'static>, secret: SecretKey) -> Endpoint {
    let relays = RelayMap::from(iroh::RelayConfig::new(url.clone(), Some(Default::default())));
    let ca = CaTlsConfig::custom_roots([cert.clone()]);
    Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(relays)).ca_tls_config(ca).secret_key(secret).bind().await.unwrap()
}

async fn membership<H: ProtocolHandler>(url: &RelayUrl, cert: &CertificateDer<'static>, db: &Path, serve: impl FnOnce(Membership) -> H) -> (Service, Router) {
    let store = Store::initialize(db).unwrap();
    let secret = SecretKey::from_bytes(&store.key().to_bytes());
    let endpoint = endpoint(url, cert, secret).await;
    let router = Router::builder(endpoint.clone()).accept(ALPN, serve(Membership::new(store, Policy { appends_per_minute: u32::MAX, ..Policy::default() }))).spawn();
    let service = Service::Serve { key: Bytes(endpoint.id().as_bytes().to_vec()), relay: url.to_string(), addrs: vec![], rest: Default::default() };
    (service, router)
}
