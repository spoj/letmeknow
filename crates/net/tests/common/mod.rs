//! A local relay with a self-signed certificate, and a fake of the group logic: epochs are log
//! lengths, and a "ciphertext" is `epoch ‖ kind ‖ body`, kind 0 a held message, kind 1 a live one.

#![allow(dead_code)]

use std::{
    collections::{BTreeMap, HashMap},
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use ed25519_dalek::SigningKey;
use iroh::{EndpointId, RelayMap, RelayUrl, SecretKey, tls::CaTlsConfig};
use iroh_relay::{
    RelayQuicConfig,
    server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig},
};
use lmk_net::{Admit, Config, Disk, Event, Groups, Net, Taken};
use lmk_proto::{
    Answer, Bytes,
    head::{self, Head},
    identity::Envelope,
    links::FileLink,
    peer::{Admitted, Hello, Join},
};
use n0_future::boxed::BoxFuture;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
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
    pub resync: Duration,
    pub collect: Duration,
}

impl Default for Options {
    fn default() -> Self {
        let (resync, collect) = (Duration::from_secs(300), Duration::from_secs(3600));
        Options { relay_only: false, disk: None, home: None, file_limit: 100 << 20, resync, collect }
    }
}

pub async fn node(relay: &Relay, key: SecretKey, fake: Arc<Fake>, options: Options) -> Node {
    let mut builder = lmk_net::builder(relay.map.clone()).secret_key(key).ca_tls_config(CaTlsConfig::custom_roots([relay.cert.clone()]));
    if options.relay_only {
        builder = builder.clear_ip_transports();
    }
    let endpoint = builder.bind().await.unwrap();
    tokio::time::timeout(WAIT, endpoint.online()).await.expect("online");
    let config = Config { home: options.home, files: None, disk: options.disk, file_limit: options.file_limit, resync: options.resync, collect: options.collect };
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

    pub async fn synced(&mut self, group: &[u8], peer: EndpointId) {
        self.until(|e| *e == Event::Synced { group: group.to_vec(), peer }).await;
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

pub fn message(epoch: u64, text: &str) -> Vec<u8> {
    [&epoch.to_be_bytes()[..], &[0], text.as_bytes()].concat()
}

pub fn id(ciphertext: &[u8]) -> [u8; 32] {
    Sha256::digest(ciphertext).into()
}

pub const SECRET: [u8; 16] = [5; 16];

/// Admits whoever brings `SECRET`, and every request for a group, with a Welcome that is the group's id.
pub struct Inviter;

impl Admit for Inviter {
    fn join(&self, _: EndpointId, join: Join) -> BoxFuture<Answer<Admitted>> {
        let admitted = |welcome: &[u8]| Answer::Ok(Admitted { welcome: Bytes(welcome.to_vec()), position: 1, doc: None, before: Vec::new(), certificates: Vec::new(), logs: Vec::new() });
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
    pub log: Vec<Vec<u8>>,
    pub floor: u64,
    pub joined: u64,
    pub held: BTreeMap<[u8; 32], (u64, Vec<u8>)>,
    pub given_up: BTreeMap<[u8; 32], u64>,
    pub live: Vec<Vec<u8>>,
    pub files: Vec<FileLink>,
    /// Takes no entries from peers, as when they reach it only from the service; counts those offered.
    pub frozen: bool,
    pub offered: usize,
    /// Other logs it follows for the group, such as its kind's, by id.
    pub others: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
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
    service: SigningKey,
    pub groups: Mutex<HashMap<Vec<u8>, Group>>,
    /// After this many more membership checks, the peer is no longer a member.
    pub cut: Mutex<Option<(EndpointId, usize)>>,
    /// Members in a leaf it does not serve, for want of a valid certificate.
    pub uncertified: Mutex<Vec<EndpointId>>,
    /// The certificates it presents, and those peers presented to it.
    pub certificates: Mutex<Vec<Envelope>>,
    pub certified: Mutex<Vec<Envelope>>,
    /// State links from peers.
    pub states: Mutex<Vec<StateLink>>,
}

/// A group, the peer, and the link it handed, or none when it asked for a state.
pub type StateLink = (Vec<u8>, EndpointId, Option<String>);

impl Fake {
    pub fn new(service: &SigningKey) -> Arc<Fake> {
        Arc::new(Fake {
            service: service.clone(),
            groups: Mutex::default(),
            cut: Mutex::default(),
            uncertified: Mutex::default(),
            certificates: Mutex::default(),
            certified: Mutex::default(),
            states: Mutex::default(),
        })
    }

    pub fn with(self: &Arc<Self>, group: &[u8], g: Group) -> Arc<Self> {
        self.groups.lock().unwrap().insert(group.to_vec(), g);
        self.clone()
    }

    pub fn hold(&self, group: &[u8], ciphertext: Vec<u8>) {
        let epoch = u64::from_be_bytes(ciphertext[..8].try_into().unwrap());
        self.groups.lock().unwrap().get_mut(group).unwrap().held.insert(id(&ciphertext), (epoch, ciphertext));
    }

    pub fn holds(&self, group: &[u8], ciphertext: &[u8]) -> bool {
        self.groups.lock().unwrap()[group].held.contains_key(&id(ciphertext))
    }

    /// The entries of a log: a group's own, or another it follows.
    pub fn log(&self, log: &[u8]) -> Vec<Vec<u8>> {
        let groups = self.groups.lock().unwrap();
        match groups.get(log) {
            Some(g) => g.log.clone(),
            None => groups.values().find_map(|g| g.others.get(log)).cloned().unwrap_or_default(),
        }
    }

    fn chain_of(entries: &[Vec<u8>], log: &[u8], n: usize) -> [u8; 32] {
        entries[..n].iter().fold(head::start(log), |hash, entry| head::next(&hash, entry))
    }
}

impl Groups for Fake {
    fn groups(&self) -> Vec<Vec<u8>> {
        self.groups.lock().unwrap().keys().cloned().collect()
    }

    fn in_leaf(&self, group: &[u8], peer: &EndpointId) -> bool {
        self.groups.lock().unwrap().get(group).is_some_and(|g| g.members.contains(peer))
    }

    fn is_member(&self, group: &[u8], peer: &EndpointId) -> bool {
        if self.uncertified.lock().unwrap().contains(peer) {
            return false;
        }
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

    fn revision(&self, _: &[u8], _: &EndpointId) -> u32 {
        lmk_proto::group::REVISION
    }

    fn hello(&self, group: &[u8]) -> Hello {
        let groups = self.groups.lock().unwrap();
        let g = &groups[group];
        Hello { group: group.into(), epoch: g.log.len() as u64, floor: g.floor, joined: g.joined, anew: false }
    }

    fn logs(&self, group: &[u8]) -> Vec<Vec<u8>> {
        let groups = self.groups.lock().unwrap();
        [group.to_vec()].into_iter().chain(groups[group].others.keys().cloned()).collect()
    }

    fn head(&self, log: &[u8]) -> Head {
        let entries = self.log(log);
        Head::sign(&self.service, log, entries.len() as u64, Self::chain_of(&entries, log, entries.len()), 0)
    }

    fn verify_head(&self, _: &[u8], head: &Head) -> bool {
        head.verify(&self.service.verifying_key())
    }

    fn chain(&self, log: &[u8], position: u64) -> Option<[u8; 32]> {
        let entries = self.log(log);
        (position as usize <= entries.len()).then(|| Self::chain_of(&entries, log, position as usize))
    }

    fn entries(&self, log: &[u8], after: u64) -> Vec<Bytes> {
        self.log(log)[after as usize..].iter().map(|e| Bytes(e.clone())).collect()
    }

    fn apply(&self, log: &[u8], entries: Vec<Bytes>, _: Head) -> Result<()> {
        let mut groups = self.groups.lock().unwrap();
        let entries = entries.into_iter().map(|e| e.0);
        if let Some(g) = groups.get_mut(log) {
            if g.frozen {
                g.offered += entries.len();
                anyhow::bail!("frozen");
            }
            g.log.extend(entries);
            return Ok(());
        }
        let other = groups.values_mut().find_map(|g| g.others.get_mut(log)).unwrap();
        other.extend(entries);
        Ok(())
    }

    fn items(&self, group: &[u8], from: u64) -> Vec<(u64, [u8; 32])> {
        let groups = self.groups.lock().unwrap();
        let g = &groups[group];
        let held = g.held.iter().map(|(id, (epoch, _))| (*epoch, *id));
        held.chain(g.given_up.iter().map(|(id, epoch)| (*epoch, *id))).filter(|(epoch, _)| *epoch >= from).collect()
    }

    fn message(&self, group: &[u8], id: &[u8; 32]) -> Option<Vec<u8>> {
        self.groups.lock().unwrap()[group].held.get(id).map(|(_, ciphertext)| ciphertext.clone())
    }

    fn receive(&self, group: &[u8], ciphertext: &[u8]) -> Taken {
        let epoch = u64::from_be_bytes(ciphertext[..8].try_into().unwrap());
        let mut groups = self.groups.lock().unwrap();
        let g = groups.get_mut(group).unwrap();
        if epoch < g.floor {
            g.given_up.insert(id(ciphertext), epoch);
            return Taken::Refused;
        }
        if epoch > g.log.len() as u64 {
            return Taken::Waiting;
        }
        match ciphertext[8] {
            0 => {
                g.held.insert(id(ciphertext), (epoch, ciphertext.to_vec()));
            }
            _ => g.live.push(ciphertext.to_vec()),
        }
        Taken::Held
    }

    fn below(&self, group: &[u8], items: Vec<(u64, [u8; 32])>) {
        let mut groups = self.groups.lock().unwrap();
        let g = groups.get_mut(group).unwrap();
        g.given_up.extend(items.into_iter().map(|(epoch, id)| (id, epoch)));
    }

    fn state(&self, group: &[u8], peer: EndpointId, link: Option<String>) {
        self.states.lock().unwrap().push((group.to_vec(), peer, link));
    }

    fn files(&self, group: &[u8]) -> Vec<FileLink> {
        self.groups.lock().unwrap()[group].files.clone()
    }

    fn certificates(&self, _: &[Vec<u8>]) -> Vec<Envelope> {
        self.certificates.lock().unwrap().clone()
    }

    fn certificate(&self, _: EndpointId, certificate: Envelope) {
        self.certified.lock().unwrap().push(certificate);
    }
}
