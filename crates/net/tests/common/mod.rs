//! A local relay with a self-signed certificate, and a fake of the group logic: who is in which group, and the files
//! each links.

#![allow(dead_code)]

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use iroh::{EndpointId, RelayMap, RelayUrl, SecretKey, tls::CaTlsConfig};
use iroh_relay::{
    RelayQuicConfig,
    server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig},
};
use lmk_net::{Admit, Config, Disk, Event, Groups, Net};
use lmk_proto::{
    Answer, Bytes,
    links::FileLink,
    peer::{Admitted, Join},
};
use n0_future::boxed::BoxFuture;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;

pub const WAIT: Duration = Duration::from_secs(30);

pub struct Relay {
    pub server: Server,
    pub url: RelayUrl,
    pub map: RelayMap,
    pub cert: CertificateDer<'static>,
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
    let url: RelayUrl = format!("https://localhost:{}", server.https_addr().unwrap().port()).parse().unwrap();
    let quic = RelayQuicConfig::new(server.quic_addr().unwrap().port());
    let map = RelayMap::from(iroh::RelayConfig::new(url.clone(), Some(quic)));
    Relay { server, url, map, cert }
}

pub struct Node {
    pub net: Net,
    pub events: mpsc::UnboundedReceiver<Event>,
    pub fake: Arc<Fake>,
}

pub struct Options {
    pub relay_only: bool,
    pub disk: Option<Arc<dyn Disk>>,
    pub home: Option<PathBuf>,
    pub file_limit: u64,
    pub collect: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options { relay_only: false, disk: None, home: None, file_limit: 100 << 20, collect: Duration::from_secs(3600) }
    }
}

pub async fn node(relay: &Relay, key: SecretKey, fake: Arc<Fake>, options: Options) -> Node {
    let mut builder = lmk_net::builder(relay.map.clone()).secret_key(key).ca_tls_config(CaTlsConfig::custom_roots([relay.cert.clone()]));
    if options.relay_only {
        builder = builder.clear_ip_transports();
    }
    let endpoint = builder.bind().await.unwrap();
    tokio::time::timeout(WAIT, endpoint.online()).await.expect("online");
    let config = Config { home: options.home, files: None, disk: options.disk, file_limit: options.file_limit, collect: options.collect };
    let (net, events) = Net::spawn(lmk_net::Network::Iroh(endpoint), config, fake.clone(), Arc::new(Inviter)).await.unwrap();
    Node { net, events, fake }
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

/// Admits whoever brings `SECRET`, and every request for a group, with a Welcome that is the group's id.
pub struct Inviter;

impl Admit for Inviter {
    fn join(&self, _: EndpointId, join: Join) -> BoxFuture<Answer<Admitted>> {
        let admitted = |welcome: &[u8]| Answer::Ok(Admitted { welcome: Bytes(welcome.to_vec()), position: 1, doc: None });
        Box::pin(async move {
            match (join.secret, join.group) {
                (Some(secret), _) if secret.0 == SECRET => admitted(b"invited"),
                (None, Some(group)) => admitted(&group.0),
                _ => Answer::Refused { refused: "unknown secret".into() },
            }
        })
    }
}

#[derive(Default)]
pub struct Group {
    pub members: Vec<EndpointId>,
    pub files: Vec<FileLink>,
}

/// A browser's storage of files.
#[derive(Default)]
pub struct FakeDisk(pub Mutex<HashMap<[u8; 32], Vec<u8>>>);

impl Disk for FakeDisk {
    fn has(&self, hash: &[u8; 32]) -> bool {
        self.0.lock().unwrap().contains_key(hash)
    }

    fn load(&self, hash: [u8; 32]) -> BoxFuture<Result<Vec<u8>>> {
        let ciphertext = self.0.lock().unwrap()[&hash].clone();
        Box::pin(async move { Ok(ciphertext) })
    }

    fn save(&self, hash: [u8; 32], ciphertext: Vec<u8>) {
        self.0.lock().unwrap().insert(hash, ciphertext);
    }
}

pub struct Fake {
    pub groups: Mutex<HashMap<Vec<u8>, Group>>,
    /// After this many more membership checks, the peer is no longer a member.
    pub cut: Mutex<Option<(EndpointId, usize)>>,
}

impl Fake {
    pub fn new() -> Arc<Fake> {
        Arc::new(Fake { groups: Mutex::default(), cut: Mutex::default() })
    }

    pub fn with(self: &Arc<Self>, group: &[u8], g: Group) -> Arc<Self> {
        self.groups.lock().unwrap().insert(group.to_vec(), g);
        self.clone()
    }
}

impl Groups for Fake {
    fn groups(&self) -> Vec<Vec<u8>> {
        self.groups.lock().unwrap().keys().cloned().collect()
    }

    fn is_member(&self, group: &[u8], peer: &EndpointId) -> bool {
        let mut cut = self.cut.lock().unwrap();
        if let Some((who, left)) = cut.as_mut()
            && who == peer
        {
            if *left == 0 {
                return false;
            }
            *left -= 1;
        }
        self.groups.lock().unwrap().get(group).is_some_and(|g| g.members.contains(peer))
    }

    fn files(&self, group: &[u8]) -> Vec<FileLink> {
        self.groups.lock().unwrap()[group].files.clone()
    }
}
