//! A local relay with a self-signed certificate, and a fake of the group logic, which lets every frame go.

#![allow(dead_code)]

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use iroh::{EndpointId, RelayUrl, SecretKey, tls::CaTlsConfig};
use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use lmk_net::{Admit, Event, Groups, Net};
use lmk_proto::{
    Answer, Bytes,
    peer::{Admitted, Frame, Join},
};
use n0_future::boxed::BoxFuture;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;

pub const WAIT: Duration = Duration::from_secs(30);

pub struct Relay {
    pub server: Server,
    pub url: RelayUrl,
    pub cert: CertificateDer<'static>,
}

pub async fn relay() -> Relay {
    relays(1).await.remove(0)
}

/// Relays that share one certificate, so one CA trusts them all.
pub async fn relays(n: usize) -> Vec<Relay> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let mut relays = Vec::new();
    for _ in 0..n {
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
        let url: RelayUrl = format!("https://localhost:{}", server.https_addr().unwrap().port()).parse().unwrap();
        relays.push(Relay { server, url, cert: cert.clone() });
    }
    relays
}

pub struct Node {
    pub net: Net,
    pub events: mpsc::UnboundedReceiver<Event>,
}

/// A node on `relay`; with `relay_only`, reached only through it.
pub async fn node(relay: &Relay, key: SecretKey, relay_only: bool) -> Node {
    let mut builder = lmk_net::builder([relay.url.clone()]).secret_key(key).ca_tls_config(CaTlsConfig::custom_roots([relay.cert.clone()]));
    if relay_only {
        builder = builder.clear_ip_transports();
    }
    let endpoint = builder.bind().await.unwrap();
    tokio::time::timeout(WAIT, endpoint.online()).await.expect("online");
    let (net, events) = Net::spawn(endpoint, Arc::new(Fake), Arc::new(Inviter)).await.unwrap();
    Node { net, events }
}

impl Node {
    pub async fn until(&mut self, wanted: impl Fn(&Event) -> bool) -> Event {
        tokio::time::timeout(WAIT, async {
            loop {
                let event = self.events.recv().await.unwrap();
                if wanted(&event) {
                    return event;
                }
            }
        })
        .await
        .expect("the event came")
    }
}

pub async fn eventually(what: &str, check: impl Fn() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

pub fn keys(n: usize) -> Vec<SecretKey> {
    (0..n).map(|_| SecretKey::generate()).collect()
}

pub const SECRET: [u8; 16] = [5; 16];

/// Admits whoever brings `SECRET`.
pub struct Inviter;

impl Admit for Inviter {
    fn join(&self, _: EndpointId, join: Join) -> BoxFuture<Answer<Admitted>> {
        Box::pin(async move {
            if join.secret.0 == SECRET {
                Answer::Ok(Admitted { commit: Bytes(b"invited".to_vec()), welcome: Bytes(vec![]), sig: Bytes(vec![]) })
            } else {
                Answer::Refused { refused: "unknown secret".into() }
            }
        })
    }
}

pub struct Fake;

impl Groups for Fake {
    fn admit(&self, _: &EndpointId, frame: Frame) -> Option<Frame> {
        Some(frame)
    }
}
