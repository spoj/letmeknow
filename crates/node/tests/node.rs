//! Sessions over a local relay with a self-signed certificate, their logs in a folder.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use iroh::RelayUrl;
use iroh::tls::CaTlsConfig;
use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use lmk_core::device::Device;
use lmk_core::provider::{MemoryProvider, Provider, SqliteProvider};
use lmk_membership::service::{Policy, Service as Membership};
use lmk_membership::store::Store;
use lmk_node::devices::Devices;
use lmk_node::{Config, Event, Node};
use lmk_proto::group::{CHAT, Certificate, ChatMessage, DEVICES, IdentityRef, Named, PROTOCOL, Service, Settings};
use lmk_proto::identity::Listed;
use lmk_proto::Bytes;
use lmk_proto::frame::{self, ALPN};
use lmk_proto::head::Head;
use lmk_proto::peer::{Frame, Item, Summary};
use lmk_proto::ranges::Ranges;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::UnboundedReceiver;

/// Generous, for slow CI runners with tests running side by side.
const WAIT: Duration = Duration::from_secs(60);

struct Relay {
    _server: Server,
    url: RelayUrl,
    cert: CertificateDer<'static>,
}

async fn relay() -> Relay {
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
    Relay { _server: server, url, cert }
}

struct Session<P = MemoryProvider> {
    node: Node<P>,
    events: UnboundedReceiver<Event>,
}

/// The kinds the sessions here support, besides chat.
const KIND: &str = "test";

async fn session(relay: &Relay, name: &str) -> Session {
    node(relay, name, &[CHAT, KIND]).await
}

async fn node(relay: &Relay, name: &str, kinds: &[&str]) -> Session {
    let (node, events) = Node::start(MemoryProvider::default(), config(relay, name, None, kinds)).await.unwrap();
    Session { node, events }
}

/// A device's own node, whose key is the device key, as a browser's is: a device and a session at once.
async fn device(relay: &Relay, name: &str) -> (Session, Devices<MemoryProvider>) {
    let device = Device::new(name);
    let (node, events) = Node::start(MemoryProvider::default(), config(relay, name, Some(device.clone()), &[CHAT, DEVICES])).await.unwrap();
    (Session { node: node.clone(), events }, Devices::new(node, device, Arc::new(|_: &Device| Ok(()))))
}

fn config(relay: &Relay, name: &str, device: Option<Device>, kinds: &[&str]) -> Config {
    Config {
        name: name.into(),
        device,
        relay: relay.url.clone(),
        ca: CaTlsConfig::custom_roots([relay.cert.clone()]),
        home: None,
        files: None,
        disk: None,
        file_limit: 100 << 20,
        kinds: kinds.iter().map(|kind| kind.to_string()).collect(),
        durable: None,
        observe: None,
    }
}

impl<P: Provider + Send + 'static> Session<P> {
    async fn until<T>(&mut self, mut wanted: impl FnMut(Event) -> Option<T>) -> T {
        tokio::time::timeout(WAIT, async {
            loop {
                let event = self.events.recv().await.unwrap();
                if let Event::Warning { text, .. } = &event {
                    eprintln!("warning: {text}");
                }
                if let Some(found) = wanted(event) {
                    return found;
                }
            }
        })
        .await
        .expect("the event came")
    }
}

/// A test's folder, deleted when the test ends.
struct Folder(PathBuf);

impl std::ops::Deref for Folder {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Folder {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn folder(test: &str) -> Folder {
    let dir = std::env::temp_dir().join(format!("lmk-node-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Folder(dir)
}

fn settings(kind: &str, folder: &Path) -> Settings {
    Settings {
        protocol: PROTOCOL,
        kind: kind.into(),
        name: "Plan".into(),
        open: vec![],
        carry: 7,
        update: lmk_proto::group::UPDATE,
        membership: Service::Folder(folder.to_str().unwrap().into()),
        rest: Default::default(),
    }
}

fn message(text: &str) -> Value {
    serde_json::to_value(ChatMessage { content: text.into(), read: Default::default(), to: vec![], reply_to: None, urgent: false, attachment: None }).unwrap()
}

/// A new identity, its key log on `membership`, with a first device called laptop: the identity, its key, and the
/// laptop's key on it.
async fn identity<P: Provider + Send + 'static>(node: &Node<P>, name: &str, membership: Service) -> (IdentityRef, [u8; 32], [u8; 32]) {
    let (key, device): ([u8; 32], [u8; 32]) = (lmk_core::random(), lmk_core::random());
    let (id, first) = lmk_core::identity::create(&key, name, membership.clone(), listed(&device, "laptop"));
    let identity = IdentityRef { id: id.into(), membership };
    node.append_identity(&identity, &first).await.unwrap();
    (identity, key, device)
}

fn listed(device: &[u8; 32], name: &str) -> Listed {
    Listed { key: lmk_core::identity::public(device).into(), name: name.into() }
}

/// That the session with key `session` speaks as `identity`, by the device key `device`.
fn certificate(identity: &IdentityRef, device: &[u8; 32], session: &Bytes) -> Certificate {
    let sig = lmk_core::identity::sign(device, &lmk_proto::identity::certified(&session.0, &identity.id.0));
    Certificate { identity: identity.clone(), device: lmk_core::identity::public(device).into(), sig: Bytes(sig) }
}

fn fp(key: &Bytes) -> String {
    Sha256::digest(&key.0)[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn chat_and_removal() {
    let relay = relay().await;
    let dir = folder("chat");
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &dir), None).unwrap();
    let link = alice.node.invite(&gid.0, Some("Bob (Acme)".into()), None).await.unwrap();
    let (joined, _) = bob.node.join(&link, None).await.unwrap();
    assert_eq!(joined, gid);
    let (member, label, introduces) = alice.until(|e| match e {
        Event::Joined { member, label, introduces, .. } => Some((member, label, introduces)),
        _ => None,
    }).await;
    assert_eq!((member.name.as_str(), label.as_deref(), introduces), ("Bob", Some("Bob (Acme)"), true));
    assert_eq!(bob.node.members(&gid.0).unwrap().len(), 2);

    let sent = bob.node.send(&gid.0, &message("hello")).await.unwrap();
    let got = alice.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((got.id, got.position, got.sender.name.as_str()), (sent.id, sent.position.unwrap(), "Bob"));
    let big = message(&"x".repeat(1 << 20));
    let refused = bob.node.send(&gid.0, &big).await.unwrap_err();
    assert!(matches!(refused.downcast_ref(), Some(lmk_node::SendError::Size(_))), "{refused:#}");

    alice.node.change_settings(&gid.0, |s| Settings { name: "Release".into(), ..s }).await.unwrap();
    let renamed = bob.until(|e| match e {
        Event::Settings { settings, .. } => Some(settings),
        _ => None,
    }).await;
    assert_eq!(renamed.name, "Release");

    let bob_key = bob.node.key();
    alice.node.remove(&gid.0, &bob_key.0).await.unwrap();
    bob.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
    eventually("Bob forgot the group", || bob.node.groups().is_empty()).await;
}

/// An invite is a rule every member holds: any of them admits its joiner, once, within its 10 minutes.
#[tokio::test(flavor = "multi_thread")]
async fn any_member_admits_an_invite_once() {
    use lmk_proto::links::Invite;
    let relay = relay().await;
    let dir = folder("invite");
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &dir), None).unwrap();
    // A member named first that cannot be reached holds up nothing while another can.
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    let dead = lmk_proto::links::Address { key: *iroh::SecretKey::from_bytes(&lmk_core::random()).public().as_bytes(), relay: Some(relay.url.to_string()) };
    let started = std::time::Instant::now();
    bob.node.join(&Invite { members: vec![dead, link.members[0].clone()], ..link }, None).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;

    // Two joiners race with one secret, each asking another member: one gets in, and the other is refused.
    let link = alice.node.invite(&gid.0, Some("Carol".into()), None).await.unwrap();
    assert_eq!(link.members.len(), 2, "the link names the inviter and the member that took the invite");
    let only = |n: usize| Invite { members: vec![link.members[n].clone()], ..link.clone() };
    let (carol, dave) = (session(&relay, "Carol").await, session(&relay, "Dave").await);
    let (to_alice, to_bob) = (only(0), only(1));
    let (by_alice, by_bob) = tokio::join!(carol.node.join(&to_alice, None), dave.node.join(&to_bob, None));
    assert!(by_alice.is_ok() != by_bob.is_ok(), "{by_alice:?} {by_bob:?}");
    let refused = format!("{:#}", by_alice.err().or(by_bob.err()).unwrap());
    assert!(refused.contains("unknown, used or expired"), "{refused}");
    let erin = session(&relay, "Erin").await;
    let used = erin.node.join(&link, None).await.unwrap_err();
    assert!(format!("{used:#}").contains("unknown, used or expired"), "a used secret is refused");

    // A member that redeems a link is refused, and the link stays unused.
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    let member = bob.node.join(&link, None).await.unwrap_err();
    assert!(format!("{member:#}").contains("a member already"), "{member:#}");

    // An expired one too.
    let secret = [7u8; 16];
    let expired = json!({ "type": "invite", "hash": Bytes(Sha256::digest(secret).to_vec()), "expires": lmk_node::now() - 1 });
    bob.node.send(&gid.0, &expired).await.unwrap();
    eventually("Alice holds the expired invite", || alice.node.messages(&gid.0).unwrap().iter().any(|m| m.payload["type"] == "invite")).await;
    let expired = Invite { secret, members: vec![link.members[0].clone()], ..link.clone() };
    assert!(format!("{:#}", erin.node.join(&expired, None).await.unwrap_err()).contains("unknown, used or expired"));

    // With the inviter offline, another member it named admits the joiner; the inviter, not it, introduces them.
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let (joined, by) = erin.node.join(&link, None).await.unwrap();
    assert_eq!(joined, gid);
    assert!(link.members[1..].iter().any(|m| m.key == by), "another member admits");
    let (member, how, introduces) = bob.until(|e| match e {
        Event::Joined { member, how, introduces, .. } if member.name == "Erin" => Some((member, how, introduces)),
        _ => None,
    }).await;
    assert_eq!((member.name.as_str(), how, introduces), ("Erin", lmk_proto::group::How::Invite, false));
}

/// A member reached first that never answers keeps the joiner from no other member it dials meanwhile.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_member_reached_first_holds_up_no_other() {
    use lmk_proto::links::{Address, Invite};
    let relay = relay().await;
    let dir = folder("silent");
    let alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &dir), None).unwrap();
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    let key = iroh::SecretKey::from_bytes(&lmk_core::random());
    let silent = Address { key: *key.public().as_bytes(), relay: Some(relay.url.to_string()) };
    let _silent = hand(&relay, key.clone(), &bob.node).await;
    eventually("the silent member is connected", || bob.node.net().connected().contains(&key.public())).await;
    let (joined, by) = bob.node.join(&Invite { members: vec![link.members[0].clone(), silent], ..link.clone() }, None).await.unwrap();
    assert_eq!((joined, by), (gid, link.members[0].key));
    alice.node.shutdown().await.unwrap();
}

/// An invite dies when its inviter leaves the group, removed or by `leave`.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_dies_when_its_inviter_leaves() {
    use lmk_proto::links::Invite;
    let relay = relay().await;
    let dir = folder("inviter-left");
    let mut alice = session(&relay, "Alice").await;
    let (bob, carol) = (session(&relay, "Bob").await, session(&relay, "Carol").await);
    let gid = alice.node.create(settings(CHAT, &dir), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    let (by_bob, by_carol) = (bob.node.invite(&gid.0, None, None).await.unwrap(), carol.node.invite(&gid.0, None, None).await.unwrap());
    let invites = || alice.node.messages(&gid.0).unwrap().iter().filter(|m| m.payload["type"] == "invite").count();
    eventually("Alice holds both invites", || invites() == 4).await;

    alice.node.remove(&gid.0, &bob.node.key().0).await.unwrap();
    carol.node.leave(&gid.0).await.unwrap();
    eventually("Bob and Carol are out", || alice.node.members(&gid.0).unwrap().len() == 1).await;
    let dave = session(&relay, "Dave").await;
    let at_alice = lmk_proto::links::Address { key: alice.node.address().0, relay: Some(relay.url.to_string()) };
    let ask_alice = |link: &Invite| Invite { members: vec![at_alice.clone()], ..link.clone() };
    for link in [&by_bob, &by_carol] {
        let refused = dave.node.join(&ask_alice(link), None).await.unwrap_err();
        assert!(format!("{refused:#}").contains("its inviter left the group"), "{refused:#}");
    }
    while let Ok(event) = alice.events.try_recv() {
        assert!(!matches!(&event, Event::Warning { text, .. } if text.contains("refused a join")), "a routine refusal is no warning: {event:?}");
    }
    alice.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kind_gets_its_state_to_a_joiner_and_its_payloads_and_files_through() {
    let relay = relay().await;
    let dir = folder("kind");
    let mut alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let carol = node(&relay, "Carol", &[CHAT]).await;
    let gid = alice.node.create(settings(KIND, &dir), None).unwrap();
    assert!(carol.node.create(settings(KIND, &dir), None).is_err(), "a session makes no group of a kind it lacks");
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    let refused = carol.node.join(&link, None).await.unwrap_err();
    assert!(format!("{refused:#}").contains("does not support test groups"), "{refused:#}");

    // The inviter's kind hands the joiner its state.
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    let joining = tokio::spawn(async move { bob.node.join(&link, None).await.map(|_| bob) });
    let reply = alice.until(|e| match e {
        Event::Snapshot { reply, .. } => Some(reply),
        _ => None,
    }).await;
    reply.send(Some(b"the state".to_vec())).unwrap();
    let mut bob = joining.await.unwrap().unwrap();
    let (data, from) = bob.until(|e| match e {
        Event::State { data, from, .. } => Some((data, from)),
        _ => None,
    }).await;
    assert_eq!((data.as_slice(), from.name.as_str()), (&b"the state"[..], "Alice"));

    // Held and live payloads; a live payload to one member.
    let push = json!({ "type": "push", "n": 1 });
    let sent = alice.node.send(&gid.0, &push).await.unwrap();
    let held = bob.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((held.id, held.payload), (sent.id, push));
    alice.node.send_live(&gid.0, &json!({ "type": "edit", "n": 2 }), Some(&fp(&bob.node.key()))).unwrap();
    let live = bob.until(|e| match e {
        Event::Live { payload, sender, .. } => Some((payload, sender.name)),
        _ => None,
    }).await;
    assert_eq!(live, (json!({ "type": "edit", "n": 2 }), "Alice".to_owned()));
    assert!(bob.node.messages(&gid.0).unwrap().iter().all(|m| m.payload["type"] == "push"), "a live payload is not held");

    // A file the kind links now is fetched and held; one it hands as state reaches the member it names.
    let file = alice.node.add_file(&gid.0, b"linked".to_vec()).await.unwrap();
    bob.node.set_links(&gid.0, vec![file.link()]).unwrap();
    let hash = bob.until(|e| match e {
        Event::File(hash) => Some(hash),
        _ => None,
    }).await;
    assert_eq!((hash, bob.node.linked(&gid.0).contains(&file)), (file.hash, true));
    alice.node.hand_state(&gid.0, &fp(&bob.node.key()), b"newer".to_vec()).await.unwrap();
    let data = bob.until(|e| match e {
        Event::State { data, .. } => Some(data),
        _ => None,
    }).await;
    assert_eq!(data, b"newer");
}

/// A membership service like `letmeknow serve`'s, which signs its heads.
async fn signing_service(relay: &Relay, dir: &Path) -> (Service, iroh::protocol::Router) {
    served(relay, dir, |service| service).await
}

/// A signing membership service, served through `serve`.
async fn served<H: iroh::protocol::ProtocolHandler>(relay: &Relay, dir: &Path, serve: impl FnOnce(Membership) -> H) -> (Service, iroh::protocol::Router) {
    let secret = iroh::SecretKey::from_bytes(&lmk_core::random());
    let relays = iroh::RelayMap::from(iroh::RelayConfig::new(relay.url.clone(), Some(Default::default())));
    let roots = CaTlsConfig::custom_roots([relay.cert.clone()]);
    let endpoint = lmk_net::builder(relays).secret_key(secret.clone()).ca_tls_config(roots).bind().await.unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let store = Store::open(&dir.join("membership.db"), ed25519_dalek::SigningKey::from_bytes(&secret.to_bytes())).unwrap();
    let router = iroh::protocol::Router::builder(endpoint.clone()).accept(ALPN, serve(Membership::new(store, Policy::default()))).spawn();
    let service = Service::Serve { key: Bytes(endpoint.id().as_bytes().to_vec()), relay: relay.url.to_string(), addrs: vec![], rest: Default::default() };
    (service, router)
}

/// A membership service's gate: closing it ends the service's connections, and those opened while it is closed wait
/// until it opens, each told by `reached` with the key of the endpoint that opened it.
#[derive(Debug)]
struct Gate {
    open: tokio::sync::watch::Sender<bool>,
    /// The endpoints let through while it is shut.
    spared: std::sync::Mutex<Vec<[u8; 32]>>,
    conns: std::sync::Mutex<Vec<iroh::endpoint::Connection>>,
    reached: tokio::sync::mpsc::UnboundedSender<Bytes>,
}

impl Gate {
    fn new() -> (Arc<Gate>, UnboundedReceiver<Bytes>) {
        let (reached, reaching) = tokio::sync::mpsc::unbounded_channel();
        (Arc::new(Gate { open: tokio::sync::watch::Sender::new(true), spared: Default::default(), conns: Default::default(), reached }), reaching)
    }

    fn set(&self, open: bool) {
        let mut conns = self.conns.lock().unwrap();
        self.open.send_replace(open);
        if !open {
            for conn in conns.drain(..) {
                conn.close(0u32.into(), b"closed");
            }
        }
    }
}

#[derive(Debug)]
struct Gated {
    service: Membership,
    gate: Arc<Gate>,
}

impl iroh::protocol::ProtocolHandler for Gated {
    async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), iroh::protocol::AcceptError> {
        if self.gate.spared.lock().unwrap().contains(connection.remote_id().as_bytes()) {
            return iroh::protocol::ProtocolHandler::accept(&self.service, connection).await;
        }
        let mut open = self.gate.open.subscribe();
        {
            let mut conns = self.gate.conns.lock().unwrap();
            conns.push(connection.clone());
            if !*open.borrow() {
                self.gate.reached.send(Bytes(connection.remote_id().as_bytes().to_vec())).ok();
            }
        }
        open.wait_for(|open| *open).await.ok();
        iroh::protocol::ProtocolHandler::accept(&self.service, connection).await
    }
}

/// The rule a joiner comes by is checked again as the Add is built: an invite that expired, or an opening closed, while
/// the admitter read the joiner's key log admits no one.
#[tokio::test(flavor = "multi_thread")]
async fn a_rule_is_checked_again_as_the_add_is_built() {
    use lmk_proto::links::Invite;
    let relay = relay().await;
    let dir = folder("rebuild");
    let alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &dir), None).unwrap();
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    bob.node.join(&link, None).await.unwrap();
    let alice_only = vec![link.members[0].clone()];
    let alice_iroh = alice.node.members(&gid.0).unwrap().into_iter().find(|m| m.name == "Alice").unwrap().iroh;
    // On a slow machine an invite may expire before Alice reads the key log: then once more, valid twice as long.
    let mut valid = 3000;
    for closed in [false, true] {
        loop {
            let (gate, mut reaching) = Gate::new();
            let (membership, _service) = served(&relay, &dir.join(format!("{closed}-{valid}")), |service| Gated { service, gate: gate.clone() }).await;
            let joiner = session(&relay, "Carol").await;
            let (carol, _, device) = identity(&joiner.node, "Carol", membership).await;
            let certificate = certificate(&carol, &device, &joiner.node.key());
            gate.set(false);
            let expires = lmk_node::now() + valid;
            let mut joining = if closed {
                alice.node.change_settings(&gid.0, |mut s| {
                    s.open.push(Named { id: carol.id.clone(), name: "Carol".into(), rest: Default::default() });
                    s
                }).await.unwrap();
                let opening = lmk_proto::group::Opening { members: vec![alice_iroh.clone()], ..alice.node.opening(&gid.0).unwrap() };
                tokio::spawn(async move { joiner.node.join_open(&opening, certificate).await })
            } else {
                let secret: [u8; 16] = lmk_core::random();
                let hash = Bytes(Sha256::digest(secret).to_vec());
                let rule = json!({ "type": "invite", "hash": hash, "expires": expires, "to": carol.id });
                bob.node.send(&gid.0, &rule).await.unwrap();
                eventually("Alice holds the invite", || alice.node.messages(&gid.0).unwrap().iter().any(|m| m.payload["hash"] == rule["hash"])).await;
                let link = Invite { device: false, secret, members: alice_only.clone() };
                tokio::spawn(async move { joiner.node.join(&link, Some(certificate)).await.map(|(gid, _)| gid) })
            };
            // Alice reads the key log once the rule admits Carol.
            let alice_reads = async { while reaching.recv().await.unwrap() != alice_iroh {} };
            let reached = tokio::time::timeout(WAIT, async {
                tokio::select! {
                    _ = alice_reads => true,
                    refused = &mut joining => {
                        assert!(!closed && format!("{refused:?}").contains("unknown, used or expired"), "{refused:?}");
                        false
                    }
                }
            }).await.expect("Alice reads Carol's key log");
            if !reached {
                assert!(valid < WAIT.as_millis() as u64, "the invite expired before Alice read the key log");
                valid *= 2;
                continue;
            }
            if closed {
                bob.node.change_settings(&gid.0, |s| Settings { open: vec![], ..s }).await.unwrap();
                eventually("Alice sees the group closed", || alice.node.settings(&gid.0).unwrap().open.is_empty()).await;
            } else {
                tokio::time::sleep(Duration::from_millis(expires + 200 - lmk_node::now())).await;
            }
            gate.set(true);
            let refused = format!("{:#}", joining.await.unwrap().unwrap_err());
            let reason = if closed { "no identity the group is open to" } else { "unknown, used or expired" };
            assert!(refused.contains(reason), "{refused}");
            assert_eq!(alice.node.members(&gid.0).unwrap().len(), 2);
            break;
        }
    }
}

/// A service that shows a session another version of a log than the session read is reported once, however often the
/// session reads it again.
#[tokio::test(flavor = "multi_thread")]
async fn a_contradiction_is_reported_once() {
    let relay = relay().await;
    let dir = folder("contradiction");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let mut alice = session(&relay, "Alice").await;
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &dir) }, None).unwrap();
    let rename = |name: &'static str| move |s: Settings| Settings { name: name.into(), ..s };
    alice.node.change_settings(&gid.0, rename("Release")).await.unwrap();
    let db = rusqlite::Connection::open(dir.join("membership.db")).unwrap();
    db.execute("UPDATE logs SET hash = zeroblob(32) WHERE id = ?", [&gid.0]).unwrap();
    for name in ["Again", "And again"] {
        assert!(alice.node.change_settings(&gid.0, rename(name)).await.is_err());
    }
    let mut warnings = 0;
    while let Ok(event) = alice.events.try_recv() {
        warnings += matches!(event, Event::Warning { text, .. } if text.contains("another version")) as usize;
    }
    assert_eq!(warnings, 1);
}

/// The kind's held messages taken after position `after`.
fn entries<P: Provider + Send + 'static>(node: &Node<P>, gid: &Bytes, after: u64) -> Vec<lmk_node::Entry> {
    let items = node.entries(&gid.0, after).unwrap().into_iter();
    items.filter_map(|item| match item {
        lmk_node::Item::Entry(entry) => Some(entry),
        lmk_node::Item::Lost(_) => None,
    }).collect()
}

impl Session {
    /// Waits for the kind's held messages after position `after`; returns them.
    async fn logged(&mut self, gid: &Bytes, after: u64) -> Vec<lmk_node::Entry> {
        loop {
            let entries = entries(&self.node, gid, after);
            if !entries.is_empty() {
                return entries;
            }
            self.until(|e| matches!(e, Event::Logged { .. }).then_some(())).await;
        }
    }

    /// Answers the next request for the kind's state.
    async fn snapshot(&mut self, state: Option<&[u8]>) {
        let reply = self.until(|e| match e {
            Event::Snapshot { reply, .. } => Some(reply),
            _ => None,
        }).await;
        reply.send(state.map(<[u8]>::to_vec)).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kind_takes_held_messages_in_log_order_and_a_member_without_state_asks_for_one() {
    let relay = relay().await;
    let dir = folder("log");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let mut alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(Settings { membership, ..settings(KIND, &dir) }, None).unwrap();
    alice.node.follow_log(&gid.0, Some(0)).unwrap();
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    let joining = tokio::spawn(async move { bob.node.join(&link, None).await.map(|_| bob) });
    alice.snapshot(Some(b"empty")).await;
    let mut bob = joining.await.unwrap().unwrap();
    bob.until(|e| matches!(e, Event::State { .. }).then_some(())).await;
    bob.node.follow_log(&gid.0, Some(0)).unwrap();

    // A held send answers its entry's position, and every member takes the messages in one order.
    let one = alice.node.send(&gid.0, &json!({ "type": "push", "n": 1 })).await.unwrap();
    let p = one.position.unwrap();
    let first = bob.logged(&gid, 0).await;
    assert_eq!((first[0].position, first[0].from.name.as_str(), &first[0].payload), (p, "Alice", &json!({ "type": "push", "n": 1 })));
    assert_eq!(first[0].id, one.id);
    let (two, three) = (json!({ "type": "push", "n": 2 }), json!({ "type": "push", "n": 3 }));
    let (a, b) = tokio::join!(alice.node.send(&gid.0, &two), bob.node.send(&gid.0, &three));
    let mut positions = [a.unwrap().position.unwrap(), b.unwrap().position.unwrap()];
    positions.sort();
    assert_eq!(positions, [p + 1, p + 2]);
    let order = |entries: Vec<lmk_node::Entry>| entries.iter().map(|e| (e.position, e.payload["n"].as_u64().unwrap())).collect::<Vec<_>>();
    let seen = order(alice.logged(&gid, p + 1).await);
    let seen = if seen.len() == 2 { seen } else { order(entries(&alice.node, &gid, p)) };
    assert_eq!(seen.len(), 2);
    assert_eq!(order(bob.logged(&gid, p + 1).await), seen[1..]);
    bob.node.follow_log(&gid.0, Some(p + 1)).unwrap();
    assert_eq!(bob.node.entries(&gid.0, 0).unwrap().len(), 1, "messages the kind read past go");

    // Carol joins with no state, admitted by whichever member she reaches first: she asks every member online for the
    // kind's state, gets none from Bob, as a browser gives none for git, and Alice's, and follows from her start.
    let carol = session(&relay, "Carol").await;
    let link = bob.node.invite(&gid.0, None, None).await.unwrap();
    let joining = tokio::spawn(async move { carol.node.join(&link, None).await.map(|_| carol) });
    tokio::select! {
        _ = alice.snapshot(None) => {}
        _ = bob.snapshot(None) => {}
    }
    let mut carol = joining.await.unwrap().unwrap();
    let mut synced = std::collections::BTreeSet::new();
    carol.until(|e| match e {
        Event::Synced { member, .. } => (synced.insert(member.name) && synced.len() == 2).then_some(()),
        _ => None,
    }).await;
    carol.node.follow_log(&gid.0, None).unwrap();
    tokio::join!(alice.snapshot(Some(b"through 3")), bob.snapshot(None));
    let data = carol.until(|e| match e {
        Event::State { data, .. } => Some(data),
        _ => None,
    }).await;
    assert_eq!(data, b"through 3");
    carol.node.follow_log(&gid.0, Some(p + 2)).unwrap();
    let four = carol.node.send(&gid.0, &json!({ "type": "push", "n": 4 })).await.unwrap();
    let after = alice.logged(&gid, p + 2).await;
    assert_eq!((after[0].position, after[0].from.name.as_str()), (four.position.unwrap(), "Carol"));
    assert_eq!(carol.logged(&gid, 0).await[0].from.name, "Carol");
}

/// A member whose kind has no state asks the members online for one as they connect, as after a restart.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_without_state_asks_for_one_once_members_are_online() {
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder("state-ask");
    let (membership, _service) = signing_service(&relay, &dir).await;
    std::fs::create_dir_all(&dir).unwrap();
    let mut alice = session(&relay, "Alice").await;
    let gid = alice.node.create(Settings { membership, ..settings(KIND, &dir) }, None).unwrap();
    alice.node.follow_log(&gid.0, Some(0)).unwrap();
    let start = || {
        let (relay, db) = (&relay, dir.join("carol.db"));
        async move {
            let (node, events) = Node::start(SqliteProvider::open(&db).unwrap(), config(relay, "Carol", None, &[CHAT, KIND])).await.unwrap();
            Session { node, events }
        }
    };
    let carol = start().await;
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    let joining = tokio::spawn(async move { carol.node.join(&link, None).await.map(|_| carol) });
    alice.snapshot(None).await;
    let carol = joining.await.unwrap().unwrap();
    carol.node.follow_log(&gid.0, None).unwrap();
    alice.snapshot(None).await;
    carol.node.shutdown().await.unwrap();
    drop(carol);

    let mut carol = start().await;
    alice.snapshot(Some(b"state")).await;
    let data = carol.until(|e| match e {
        Event::State { data, .. } => Some(data),
        _ => None,
    }).await;
    assert_eq!(data, b"state");
    alice.node.shutdown().await.unwrap();
}

impl<P: Provider + Send + 'static> Session<P> {
    /// Waits until a member's identity checks out, or not.
    async fn checked(&self, gid: &Bytes, name: &str, valid: bool) -> lmk_node::Member {
        tokio::time::timeout(WAIT, async {
            loop {
                let members = self.node.members(&gid.0).unwrap();
                if let Some(member) = members.into_iter().find(|m| m.name == name && m.identity.as_ref().is_some_and(|c| c.error.is_none() == valid)) {
                    return member;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("the check came out as expected")
    }
}

/// Has the devices kind take a device's events first, as a client does.
fn routed<P: Provider + Send + 'static>(session: &mut Session<P>, devices: Devices<P>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mut events = std::mem::replace(&mut session.events, rx);
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if let Some(event) = devices.on(event) {
                tx.send(event).ok();
            }
        }
    });
}

/// Waits until a device has its identity's state.
async fn identified<P: Provider + Send + 'static>(devices: &Devices<P>) {
    tokio::time::timeout(WAIT, async {
        while devices.identities().is_empty() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the identity's state came");
}

/// A device's own node on SQLite at `db`, which survives a restart, with the devices kind taking its events first.
async fn stored_device(relay: &Relay, name: &str, db: &Path) -> (Session<SqliteProvider>, Devices<SqliteProvider>) {
    let device = Device::new(name);
    let (node, events) = Node::start(SqliteProvider::open(db).unwrap(), config(relay, name, Some(device.clone()), &[CHAT, DEVICES])).await.unwrap();
    let devices = Devices::new(node.clone(), device, Arc::new(|_: &Device| Ok(())));
    let mut session = Session { node, events };
    routed(&mut session, devices.clone());
    (session, devices)
}

/// Waits until an identity's key log lists these devices, by name.
async fn lists<P: Provider + Send + 'static>(node: &Node<P>, identity: &IdentityRef, names: &[&str]) -> lmk_core::identity::KeyLog {
    tokio::time::timeout(WAIT, async {
        loop {
            let log = node.read_key_log(identity).await.unwrap();
            let mut listed: Vec<&str> = log.devices.iter().map(|device| device.name.as_str()).collect();
            listed.sort();
            if listed == names {
                return log;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the key log lists the devices")
}

/// The devices group of a device's only identity.
fn devices_group<P: Provider + Send + 'static>(node: &Node<P>) -> Bytes {
    node.groups().into_iter().find(|gid| node.settings(&gid.0).unwrap().kind == DEVICES).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_share_an_identity_list_their_devices_and_certify_their_sessions() {
    let relay = relay().await;
    let dir = folder("identity");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let mut alice = session(&relay, "Alice").await;
    let (mut laptop, laptop_devices) = device(&relay, "laptop").await;
    let (mut tablet, tablet_devices) = device(&relay, "tablet").await;
    routed(&mut laptop, laptop_devices.clone());
    routed(&mut tablet, tablet_devices.clone());
    let bob = laptop_devices.create("Bob", membership.clone()).await.unwrap();
    let first = *lists(&laptop.node, &bob, &["laptop"]).await.current();
    laptop_devices.set_contact(&[9; 32], lmk_core::contacts::Contact { name: "Carol".into(), how: lmk_core::contacts::How::Verified, by: None, at: 1, rest: Default::default() }).await.unwrap();

    // A device link: the tablet gets the identity's state, its key and contacts among it, and joins with a key of its
    // own, which the key log lists once a device restates the list.
    let link = lmk_proto::links::Invite::parse(&laptop_devices.invite(&bob.id.0).await.unwrap()).unwrap();
    tablet_devices.join(&link).await.unwrap();
    identified(&tablet_devices).await;
    assert_eq!(tablet_devices.identities(), [(bob.clone(), "Bob".to_owned())]);
    assert_eq!(tablet_devices.contacts()[0].1.name, "Carol");
    let (laptop_key, tablet_key) = (laptop_devices.key(&bob.id.0).unwrap(), tablet_devices.key(&bob.id.0).unwrap());
    assert!(laptop_key != tablet_key && laptop_key != laptop.node.key() && tablet_key != tablet.node.key(), "a device key per identity");
    let log = lists(&laptop.node, &bob, &["laptop", "tablet"]).await;
    assert_eq!(log.current(), &first, "a link keeps the key");

    // Each certifies its session; alice opens a chat to Bob, which the tablet joins without an invite, and invites the
    // laptop.
    let chat = alice.node.create(Settings { membership: membership.clone(), ..settings(CHAT, &dir) }, None).unwrap();
    alice.node.change_settings(&chat.0, |mut s| {
        s.open.push(Named { id: bob.id.clone(), name: "Bob".into(), rest: Default::default() });
        s
    }).await.unwrap();
    let opening = alice.node.opening(&chat.0).unwrap();
    tablet_devices.set_opening(&bob.id.0, opening.clone()).await.unwrap();
    tokio::time::timeout(WAIT, async {
        while laptop_devices.openings().is_empty() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.expect("an opening reaches every device");
    tablet.node.join_open(&opening, tablet_devices.certify(&bob.id.0, &tablet.node.key().0).unwrap()).await.unwrap();
    let link = alice.node.invite(&chat.0, None, None).await.unwrap();
    laptop.node.join(&link, Some(laptop_devices.certify(&bob.id.0, &laptop.node.key().0).unwrap())).await.unwrap();
    let seen = alice.checked(&chat, "tablet", true).await;
    assert_eq!((seen.device_name.as_str(), seen.identity.unwrap().added), ("tablet", true));
    let seen = alice.checked(&chat, "laptop", true).await;
    assert_eq!((seen.device_name.as_str(), seen.identity.unwrap().added), ("laptop", false));

    // The tablet stops, and the laptop takes it off Bob: a new key, and a list without it. Alice removes its session
    // from the chat without its coming back; the laptop's certificate still checks out, and alice serves it.
    tablet.node.shutdown().await.unwrap();
    laptop_devices.remove(&bob.id.0, &tablet_key.0).await.unwrap();
    let log = lists(&laptop.node, &bob, &["laptop"]).await;
    assert!(log.current() != &first && log.dropped(&tablet_key.0));
    alice.until(|e| matches!(e, Event::Left { member, .. } if member.name == "tablet").then_some(())).await;
    alice.checked(&chat, "laptop", true).await;
    let id = alice.node.send(&chat.0, &message("after the tablet left")).await.unwrap().id;
    let got = laptop.until(|e| match e {
        Event::Message(message) if message.id == id => Some(message.id),
        _ => None,
    }).await;
    assert_eq!(got, id);
}

/// Once an identity's key log drops a device, its sessions leave every group, each by one commit, whose committer
/// reports the members they added; a list that grows removes no one.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_devices_sessions_are_removed_once_and_reported() {
    use lmk_core::identity::public;
    let relay = relay().await;
    let dir = folder("revoke");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let alice = session(&relay, "Alice").await;
    let (carol, key, laptop) = identity(&alice.node, "Carol", membership.clone()).await;
    let tablet_key: [u8; 32] = lmk_core::random();
    let log = alice.node.read_key_log(&carol).await.unwrap();
    alice.node.append_identity(&carol, &log.next(&key, &public(&key), vec![listed(&laptop, "laptop"), listed(&tablet_key, "tablet")])).await.unwrap();
    let groups = [(); 2].map(|_| alice.node.create(Settings { membership: membership.clone(), ..settings(CHAT, &dir) }, None).unwrap());
    let (tablet, desk, dave, eve) = (session(&relay, "tablet").await, session(&relay, "desk").await, session(&relay, "Dave").await, session(&relay, "Eve").await);
    let alice_only = vec![alice.node.invite(&groups[0].0, None, None).await.unwrap().members[0].clone()];
    for gid in &groups {
        for (joiner, device) in [(&tablet, &tablet_key), (&desk, &laptop)] {
            // Alice admits each: a link that named the tablet too could have the tablet add the desk.
            let link = alice.node.invite(&gid.0, None, None).await.unwrap();
            let link = lmk_proto::links::Invite { members: link.members[..1].to_vec(), ..link };
            joiner.node.join(&link, Some(certificate(&carol, device, &joiner.node.key()))).await.unwrap();
            alice.checked(gid, &joiner.node.members(&gid.0).unwrap().iter().find(|m| m.key == joiner.node.key()).unwrap().name, true).await;
        }
    }
    // The tablet's session adds Dave to the first group, and invites Eve, whom alice admits.
    let link = tablet.node.invite(&groups[0].0, None, None).await.unwrap();
    dave.node.join(&link, None).await.unwrap();
    let link = tablet.node.invite(&groups[0].0, None, None).await.unwrap();
    assert!(link.members.contains(&alice_only[0]), "the link names Alice, who holds the invite");
    eve.node.join(&lmk_proto::links::Invite { members: alice_only, ..link }, None).await.unwrap();
    tokio::time::timeout(WAIT, async {
        while alice.node.members(&groups[0].0).unwrap().len() < 5 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.expect("Dave and Eve join");
    // A member reports only the Adds it applied, so Dave and Eve, who did not apply their own, stop too.
    for session in [&tablet, &dave, &eve] {
        session.node.shutdown().await.unwrap();
    }

    let (all, mut told) = tokio::sync::mpsc::unbounded_channel();
    for (name, mut session) in [("alice", alice.events), ("desk", desk.events)] {
        let all = all.clone();
        tokio::spawn(async move {
            while let Some(event) = session.recv().await {
                all.send((name, event)).ok();
            }
        });
    }
    let log = alice.node.read_key_log(&carol).await.unwrap();
    alice.node.append_identity(&carol, &log.next(&key, &public(&lmk_core::random()), vec![listed(&laptop, "laptop")])).await.unwrap();
    let (mut left, mut revoked) = (Vec::new(), Vec::new());
    tokio::time::timeout(WAIT, async {
        while left.len() < 4 || revoked.len() < 2 {
            match told.recv().await.unwrap() {
                (name, Event::Left { group, member, .. }) if member.name == "tablet" => left.push((name, group)),
                (_, Event::Revoked { group, removed, added }) => revoked.push((group, removed, added)),
                _ => {}
            }
        }
    }).await.expect("every member applies the removals, and the committers report them");
    left.sort();
    let mut expected = vec![("alice", groups[0].clone()), ("alice", groups[1].clone()), ("desk", groups[0].clone()), ("desk", groups[1].clone())];
    expected.sort();
    assert_eq!(left, expected, "one removal of the tablet's session per group");
    revoked.sort_by_key(|(group, ..)| groups.iter().position(|gid| gid == group));
    let names = |members: &[lmk_node::Member]| members.iter().map(|m| m.name.clone()).collect::<Vec<_>>();
    assert_eq!(revoked.iter().map(|(group, removed, added)| (group.clone(), names(removed), names(added))).collect::<Vec<_>>(), [
        (groups[0].clone(), vec!["tablet".to_owned()], vec!["Dave".to_owned(), "Eve".to_owned()]),
        (groups[1].clone(), vec!["tablet".to_owned()], vec![]),
    ]);
    assert_eq!(names(&alice.node.members(&groups[0].0).unwrap()), ["Alice", "desk", "Dave", "Eve"], "the desk's device is still listed");
}

/// A device that read the key log entry listing a device just linked, before the Add of it, reads the devices group's
/// log before it compares, and so does not drop the new device.
#[tokio::test(flavor = "multi_thread")]
async fn the_list_does_not_drop_a_device_just_linked() {
    let relay = relay().await;
    let dir = folder("link-race");
    std::fs::create_dir_all(&dir).unwrap();
    let membership = Service::Folder(dir.join("logs").to_str().unwrap().into());
    let (laptop, laptop_devices) = stored_device(&relay, "laptop", &dir.join("laptop.db")).await;
    let (_phone, phone_devices) = stored_device(&relay, "phone", &dir.join("phone.db")).await;
    let (_tablet, tablet_devices) = stored_device(&relay, "tablet", &dir.join("tablet.db")).await;
    let bob = laptop_devices.create("Bob", membership).await.unwrap();
    let link = lmk_proto::links::Invite::parse(&laptop_devices.invite(&bob.id.0).await.unwrap()).unwrap();
    phone_devices.join(&link).await.unwrap();
    identified(&phone_devices).await;
    lists(&laptop.node, &bob, &["laptop", "phone"]).await;
    // While the laptop is stopped, the phone links the tablet.
    laptop.node.shutdown().await.unwrap();
    drop((laptop, laptop_devices));
    let link = lmk_proto::links::Invite::parse(&phone_devices.invite(&bob.id.0).await.unwrap()).unwrap();
    tablet_devices.join(&link).await.unwrap();
    identified(&tablet_devices).await;
    let tablet_key = tablet_devices.key(&bob.id.0).unwrap();

    // The laptop starts with its devices group as it stopped, and the key log as it is now.
    let (laptop, laptop_devices) = stored_device(&relay, "laptop", &dir.join("laptop.db")).await;
    let gid = devices_group(&laptop.node);
    laptop_devices.duties(&gid.0).await.unwrap();
    let log = lists(&laptop.node, &bob, &["laptop", "phone", "tablet"]).await;
    assert!(!log.dropped(&tablet_key.0));
    assert_eq!(laptop.node.members(&gid.0).unwrap().len(), 3);
}

/// A new key reaches the key log only once another device's summary holds its key message.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_key_is_named_once_another_device_holds_it() {
    let relay = relay().await;
    let dir = folder("key-held");
    std::fs::create_dir_all(&dir).unwrap();
    let membership = Service::Folder(dir.join("logs").to_str().unwrap().into());
    let (laptop, laptop_devices) = stored_device(&relay, "laptop", &dir.join("laptop.db")).await;
    let (phone, phone_devices) = stored_device(&relay, "phone", &dir.join("phone.db")).await;
    let (tablet, tablet_devices) = stored_device(&relay, "tablet", &dir.join("tablet.db")).await;
    let bob = laptop_devices.create("Bob", membership).await.unwrap();
    for devices in [&phone_devices, &tablet_devices] {
        let link = lmk_proto::links::Invite::parse(&laptop_devices.invite(&bob.id.0).await.unwrap()).unwrap();
        devices.join(&link).await.unwrap();
        identified(devices).await;
    }
    let first = *lists(&laptop.node, &bob, &["laptop", "phone", "tablet"]).await.current();
    let tablet_key = tablet_devices.key(&bob.id.0).unwrap();
    tablet.node.shutdown().await.unwrap();
    phone.node.shutdown().await.unwrap();
    drop((phone, phone_devices));

    laptop_devices.remove(&bob.id.0, &tablet_key.0).await.unwrap();
    let log = laptop.node.read_key_log(&bob).await.unwrap();
    assert!(log.current() == &first && !log.dropped(&tablet_key.0), "no other device holds the new key yet");

    let (_phone, _phone_devices) = stored_device(&relay, "phone", &dir.join("phone.db")).await;
    let log = lists(&laptop.node, &bob, &["laptop", "phone"]).await;
    assert!(log.current() != &first && log.dropped(&tablet_key.0));
}

/// A device that missed the key message of the identity's current key reports the key lost while no device online has
/// it, and gets it once one that has it is online.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_missing_the_current_key_asks_for_it_and_reports_it_lost() {
    let relay = relay().await;
    let dir = folder("missing-key");
    std::fs::create_dir_all(&dir).unwrap();
    let membership = Service::Folder(dir.join("logs").to_str().unwrap().into());
    let (laptop, laptop_devices) = stored_device(&relay, "laptop", &dir.join("laptop.db")).await;
    let (phone, phone_devices) = stored_device(&relay, "phone", &dir.join("phone.db")).await;
    let (tablet, tablet_devices) = stored_device(&relay, "tablet", &dir.join("tablet.db")).await;
    let (desk, desk_devices) = stored_device(&relay, "desk", &dir.join("desk.db")).await;
    let bob = laptop_devices.create("Bob", membership).await.unwrap();
    for devices in [&phone_devices, &tablet_devices, &desk_devices] {
        let link = lmk_proto::links::Invite::parse(&laptop_devices.invite(&bob.id.0).await.unwrap()).unwrap();
        devices.join(&link).await.unwrap();
        identified(devices).await;
    }
    let first = *lists(&laptop.node, &bob, &["desk", "laptop", "phone", "tablet"]).await.current();
    let tablet_key = tablet_devices.key(&bob.id.0).unwrap();
    tablet.node.shutdown().await.unwrap();
    desk.node.shutdown().await.unwrap();
    drop((desk, desk_devices));

    // Only the laptop and the phone hold the key message of the key that replaces the tablet's, then stop.
    laptop_devices.remove(&bob.id.0, &tablet_key.0).await.unwrap();
    assert!(lists(&laptop.node, &bob, &["desk", "laptop", "phone"]).await.current() != &first);
    for node in [&laptop.node, &phone.node] {
        node.shutdown().await.unwrap();
    }
    drop((laptop, laptop_devices, phone, phone_devices));

    let (mut desk, desk_devices) = stored_device(&relay, "desk", &dir.join("desk.db")).await;
    let gid = devices_group(&desk.node);
    desk_devices.duties(&gid.0).await.unwrap();
    desk_devices.duties(&gid.0).await.unwrap();
    desk.until(|e| matches!(e, Event::Warning { text, .. } if text.contains("does not hold its identity's current key")).then_some(())).await;

    // The laptop comes back: the desk asks it, holds the key, and so restates the list with its new name.
    let (_laptop, _laptop_devices) = stored_device(&relay, "laptop", &dir.join("laptop.db")).await;
    desk_devices.rename("study").await.unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            desk_devices.duties(&gid.0).await.unwrap();
            let log = desk.node.read_key_log(&bob).await.unwrap();
            if log.devices.iter().any(|device| device.name == "study") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }).await.expect("the desk takes the key and lists itself anew");
}

/// A session whose leaf names an older revision writes its own as it starts.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_updates_an_older_leaf_as_it_starts() {
    use lmk_core::group::{Change, Group, Session as Mls};
    use lmk_core::provider::SqliteProvider;
    use lmk_membership::Membership;
    let relay = relay().await;
    let dir = folder("revision");
    std::fs::create_dir_all(&dir).unwrap();
    let (logs, bob_db) = (dir.join("logs"), dir.join("bob.db"));
    let start = || async { Node::start(SqliteProvider::open(&bob_db).unwrap(), config(&relay, "Bob", None, &[CHAT])).await.unwrap().0 };
    let alice = session(&relay, "Alice").await;
    let gid = alice.node.create(settings(CHAT, &logs), None).unwrap();
    let bob = start().await;
    bob.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    let revision = |wanted: u32| {
        let (node, gid) = (&alice.node, &gid);
        tokio::time::timeout(WAIT, async move {
            while !node.members(&gid.0).unwrap().iter().any(|m| m.name == "Bob" && m.revision == wanted) {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
    };
    revision(lmk_proto::group::REVISION).await.expect("a joiner's leaf names this revision");
    bob.shutdown().await.unwrap();
    drop(bob);

    // Bob's leaf goes back to revision 0 while he is stopped.
    let provider = SqliteProvider::open(&bob_db).unwrap();
    let mls = Mls::load(&provider).unwrap();
    let old = lmk_proto::group::Leaf { revision: 0, ..mls.leaf.clone() };
    let commit = Group::load(&provider, &gid.0).unwrap().commit(&provider, &mls, Change { leaf: Some(old), ..Change::default() }).unwrap();
    lmk_membership::folder::FolderClient::new(logs.to_str().unwrap()).append(&gid.0, &[commit.entry]).await.unwrap();
    drop(provider);
    revision(0).await.expect("Alice sees Bob's leaf of revision 0");

    let bob = start().await;
    revision(lmk_proto::group::REVISION).await.expect("Bob's leaf names this revision once he starts");
    bob.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_keeps_its_identities_across_restarts() {
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder("restart");
    std::fs::create_dir_all(&dir).unwrap();
    let membership = Service::Folder(dir.join("logs").to_str().unwrap().into());
    let device = Device::new("laptop");
    let start = || async {
        let (node, _events) =
            Node::start(SqliteProvider::open(&dir.join("device.db")).unwrap(), config(&relay, "laptop", Some(device.clone()), &[CHAT, DEVICES])).await.unwrap();
        (node.clone(), Devices::new(node, device.clone(), Arc::new(|_: &Device| Ok(()))))
    };
    let (node, devices) = start().await;
    let bob = devices.create("Bob", membership).await.unwrap();
    node.shutdown().await.unwrap();
    drop((node, devices));
    let (node, devices) = start().await;
    assert_eq!(devices.identities(), [(bob, "Bob".to_owned())]);
    node.shutdown().await.unwrap();
}

/// A member catching up from a holder gets a sender's messages about as they were sent, so more than the 1000 that MLS
/// opens out of order all arrive.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_catching_up_takes_more_than_a_thousand_messages_of_one_sender() {
    use lmk_core::provider::SqliteProvider;
    const MESSAGES: usize = 1100;
    let relay = relay().await;
    let dir = folder("thousand");
    std::fs::create_dir_all(&dir).unwrap();
    let carol_config = || config(&relay, "Carol", None, &[CHAT]);
    let carol_db = dir.join("carol.db");
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let (carol, _events) = Node::start(SqliteProvider::open(&carol_db).unwrap(), carol_config()).await.unwrap();
    let gid = alice.node.create(settings(CHAT, &dir.join("logs")), None).unwrap();
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    bob.node.join(&link, None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    carol.join(&link, None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    bob.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    carol.shutdown().await.unwrap();
    drop(carol);
    for n in 0..MESSAGES {
        alice.node.send(&gid.0, &message(&n.to_string())).await.unwrap();
    }
    for _ in 0..MESSAGES {
        bob.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    }
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let (carol, mut events) = Node::start(SqliteProvider::open(&carol_db).unwrap(), carol_config()).await.unwrap();
    let mut taken = 0;
    let all = async {
        while taken < MESSAGES {
            if let Event::Message(_) = events.recv().await.unwrap() {
                taken += 1;
            }
        }
    };
    tokio::time::timeout(3 * WAIT, all).await.expect("Carol took every message");
    carol.shutdown().await.unwrap();
}

/// Waits until `done` holds, polling.
async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

/// A `leave` sent while the group's log is unreachable is pending: the leaver appends it once the log is reachable,
/// after a restart with `restart_leaver`, and the other member then removes it.
async fn held_leave(test: &str, restart_leaver: bool) {
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder(test);
    let (gate, _reaching) = Gate::new();
    let (membership, _service) = served(&relay, &dir, |service| Gated { service, gate: gate.clone() }).await;
    let start = |name: &'static str| {
        let (relay, db) = (&relay, dir.join(format!("{name}.db")));
        async move {
            let (node, events) = Node::start(SqliteProvider::open(&db).unwrap(), config(relay, name, None, &[CHAT])).await.unwrap();
            Session { node, events }
        }
    };
    let mut alice = start("Alice").await;
    let bob = start("Bob").await;
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &dir) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;

    gate.set(false);
    let mut bob = bob;
    let sent = bob.node.leave(&gid.0).await.unwrap().unwrap();
    assert_eq!(sent.position, None, "the leave is pending");
    if restart_leaver {
        bob.node.shutdown().await.unwrap();
        drop(bob);
        gate.set(true);
        bob = start("Bob").await;
    } else {
        gate.set(true);
    }
    let answered = bob.until(|e| match e {
        Event::Sent { answered, .. } => Some(answered),
        _ => None,
    }).await;
    assert_eq!(answered, sent.id, "Sent names the send as `leave` answered it");
    alice.until(|e| matches!(e, Event::Left { member, .. } if member.name == "Bob").then_some(())).await;
    assert_eq!(alice.node.members(&gid.0).unwrap().len(), 1);
    alice.node.shutdown().await.unwrap();
}

/// A `leave` sealed before its sender was removed and added again removes it no more.
#[tokio::test(flavor = "multi_thread")]
async fn an_old_leave_does_not_remove_a_member_added_again() {
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder("leave-again");
    std::fs::create_dir_all(&dir).unwrap();
    let alice_db = dir.join("alice.db");
    let start = || async {
        let (node, events) = Node::start(SqliteProvider::open(&alice_db).unwrap(), config(&relay, "Alice", None, &[CHAT])).await.unwrap();
        Session { node, events }
    };
    let mut alice = start().await;
    let mut bob = session(&relay, "Bob").await;
    let carol = session(&relay, "Carol").await;
    let gid = alice.node.create(settings(CHAT, &dir.join("logs")), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Carol has both Adds", || carol.node.members(&gid.0).unwrap().len() == 3).await;
    alice.node.shutdown().await.unwrap();
    drop(alice);

    bob.node.leave(&gid.0).await.unwrap();
    bob.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
    bob.node.join(&carol.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    // Only Carol holds the leave: were Bob online, Alice's wait could end at her connection to him before Carol's lands.
    bob.node.shutdown().await.unwrap();
    let alice = start().await;
    let leaves = || alice.node.messages(&gid.0).unwrap().iter().filter(|m| m.payload["type"] == "leave").count();
    eventually("Alice holds Bob's old leave", || leaves() == 1).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(alice.node.members(&gid.0).unwrap().len(), 3, "Bob is still in");
    assert_eq!(carol.node.members(&gid.0).unwrap().len(), 3, "Bob is still in");
    alice.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pending_leave_is_finished_after_a_restart() {
    held_leave("leave-restart", true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pending_leave_is_finished_once_the_log_is_reachable() {
    held_leave("leave-reachable", false).await;
}

/// A pending send sealed again after a commit is reported sent by the id its members know it by.
#[tokio::test(flavor = "multi_thread")]
async fn a_pending_send_sealed_again_is_reported_by_its_final_id() {
    let relay = relay().await;
    let dir = folder("sealed-again");
    let (gate, _reaching) = Gate::new();
    let (membership, _service) = served(&relay, &dir, |service| Gated { service, gate: gate.clone() }).await;
    let (mut alice, mut bob) = (session(&relay, "Alice").await, session(&relay, "Bob").await);
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &dir) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;

    // Only Bob is kept from the log: his send is pending while Alice renames the group.
    gate.spared.lock().unwrap().push(alice.node.address().0);
    gate.set(false);
    let sent = bob.node.send(&gid.0, &message("before the rename")).await.unwrap();
    assert_eq!(sent.position, None, "the send is pending");
    alice.node.change_settings(&gid.0, |s| Settings { name: "Release".into(), ..s }).await.unwrap();
    gate.set(true);
    let (id, answered) = bob.until(|e| match e {
        Event::Sent { id, answered, .. } => Some((id, answered)),
        _ => None,
    }).await;
    assert!(answered == sent.id && id != sent.id, "sealed again after the rename");
    let got = alice.until(|e| match e {
        Event::Message(message) => Some(message.id),
        _ => None,
    }).await;
    assert_eq!(got, id);
}

/// Two members that leave at once: one's removal of the other wins, and the one left alone forgets the group.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaver_left_alone_forgets_the_group() {
    let relay = relay().await;
    let dir = folder("alone");
    let mut alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &dir), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let (a, b) = tokio::join!(alice.node.leave(&gid.0), bob.node.leave(&gid.0));
    a.unwrap();
    b.unwrap();
    eventually("both forgot the group", || alice.node.groups().is_empty() && bob.node.groups().is_empty()).await;
}

/// Changes that another member's commit already made answer ok and commit nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_made_moot_commits_nothing() {
    let relay = relay().await;
    let dir = folder("moot");
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let carol = session(&relay, "Carol").await;
    let gid = alice.node.create(settings(CHAT, &dir), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Bob has both Adds", || bob.node.members(&gid.0).unwrap().len() == 3).await;
    let epoch = alice.node.epoch(&gid.0).unwrap();

    let rename = |s: Settings| Settings { name: "Same".into(), ..s };
    let (a, b) = tokio::join!(alice.node.change_settings(&gid.0, rename), bob.node.change_settings(&gid.0, rename));
    a.unwrap();
    b.unwrap();
    let epochs = (alice.node.epoch(&gid.0).unwrap(), bob.node.epoch(&gid.0).unwrap());
    assert!(epochs.0.max(epochs.1) == epoch + 1, "one rename committed: {epochs:?} after {epoch}");
    eventually("Bob is at the rename", || bob.node.epoch(&gid.0).unwrap() == epoch + 1).await;

    let carol_key = carol.node.key();
    let remove = |node: &Node<MemoryProvider>| {
        let (node, gid, key) = (node.clone(), gid.clone(), carol_key.clone());
        tokio::spawn(async move { node.remove(&gid.0, &key.0).await })
    };
    // One commits the removal; the other finds it moot, or, if it starts once the removal applied, not a member.
    let (a, b) = (remove(&alice.node), remove(&bob.node));
    let mut answers = [a.await.unwrap(), b.await.unwrap()].map(|answer| answer.map_err(|error| format!("{error:#}")));
    answers.sort();
    assert!(matches!(&answers, [Ok(false), Ok(true)] | [Ok(true), Err(_)]), "{answers:?}");
    if let Err(error) = &answers[1] {
        assert!(error.contains("not a member"), "{error}");
    }
    let epochs = (alice.node.epoch(&gid.0).unwrap(), bob.node.epoch(&gid.0).unwrap());
    assert!(epochs.0.max(epochs.1) == epoch + 2, "one removal committed: {epochs:?} after {}", epoch + 1);
    bob.until(|e| matches!(e, Event::Left { .. }).then_some(())).await;
    let again = alice.node.remove(&gid.0, &carol_key.0).await.unwrap_err();
    assert!(format!("{again:#}").contains("not a member"), "removing a non-member fails at once: {again:#}");
}

/// A member away past its log's retention can apply none of the commits it missed: it is told it was removed, and
/// forgets the group.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_away_past_the_retention_drops_the_group() {
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder("retention");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let bob_db = dir.join("bob.db");
    let start = || async {
        let (node, events) = Node::start(SqliteProvider::open(&bob_db).unwrap(), config(&relay, "Bob", None, &[CHAT])).await.unwrap();
        Session { node, events }
    };
    let mut alice = session(&relay, "Alice").await;
    let bob = start().await;
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &dir) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    alice.node.change_settings(&gid.0, |s| Settings { name: "Later".into(), ..s }).await.unwrap();
    alice.node.shutdown().await.unwrap();
    let store = Store::open(&dir.join("membership.db"), ed25519_dalek::SigningKey::from_bytes(&[0; 32])).unwrap();
    store.expire(lmk_node::now() + 1).unwrap();

    let mut bob = start().await;
    bob.until(|e| matches!(e, Event::Removed { by: None, .. }).then_some(())).await;
    eventually("Bob forgot the group", || bob.node.groups().is_empty()).await;
    bob.node.shutdown().await.unwrap();
}

/// A session on SQLite at `db`, which survives a restart.
async fn stored(relay: &Relay, name: &str, db: &Path) -> Session<SqliteProvider> {
    let (node, events) = Node::start(SqliteProvider::open(db).unwrap(), config(relay, name, None, &[CHAT])).await.unwrap();
    Session { node, events }
}

/// A member that applies the commit deleting an epoch's keys while no member online holds a message of it loses that
/// message, and announces it: every member gets the announcement, and the sender is told its message was lost.
#[tokio::test(flavor = "multi_thread")]
async fn an_announced_loss_reaches_every_member() {
    let relay = relay().await;
    let dir = folder("lost");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, "Alice", &db("alice")).await;
    let bob = stored(&relay, "Bob", &db("bob")).await;
    let carol = stored(&relay, "Carol", &db("carol")).await;
    let gid = alice.node.create(settings(CHAT, &dir.join("logs")), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Carol has both Adds", || carol.node.members(&gid.0).unwrap().len() == 3).await;
    for session in [&alice, &carol] {
        session.node.shutdown().await.unwrap();
    }
    drop((alice, carol));

    // Only Bob holds his message; Alice, back while he is away, commits twice, and so loses it.
    let sent = bob.node.send(&gid.0, &message("only Bob holds this")).await.unwrap();
    let position = sent.position.unwrap();
    bob.node.shutdown().await.unwrap();
    drop(bob);
    let mut alice = stored(&relay, "Alice", &db("alice")).await;
    for name in ["One", "Two"] {
        alice.node.change_settings(&gid.0, |s| Settings { name: name.into(), ..s }).await.unwrap();
    }
    let lost = alice.until(|e| match e {
        Event::Lost(lost) => Some(lost),
        _ => None,
    }).await;
    assert_eq!((lost.member.name.as_str(), lost.positions.clone(), lost.ids.clone()), ("Alice", vec![position], vec![sent.id.clone()]));
    let announced = lost.position;

    // Bob hears that Alice lost his message; Carol, who gets it from Bob, holds the announcement too.
    let mut bob = stored(&relay, "Bob", &db("bob")).await;
    let told = bob.until(|e| match e {
        Event::Lost(lost) => Some(lost),
        _ => None,
    }).await;
    assert_eq!((told.member.name.as_str(), told.positions, told.ids, told.position), ("Alice", vec![position], vec![sent.id.clone()], announced));
    let carol = stored(&relay, "Carol", &db("carol")).await;
    let alices = |node: &Node<SqliteProvider>| node.losses(&gid.0).unwrap().iter().any(|l| l.member.name == "Alice" && l.positions == [position]);
    eventually("Carol holds Alice's announcement", || alices(&carol.node)).await;
    assert!(alices(&bob.node) && alices(&alice.node));
    assert!(carol.node.message(&sent.id.0).unwrap().is_some(), "Carol got the message from Bob");
    for session in [&alice, &bob, &carol] {
        session.node.shutdown().await.unwrap();
    }
}

/// A device that loses a message of its devices group stops there, and takes the state of a device that has it.
#[tokio::test(flavor = "multi_thread")]
async fn devices_stop_at_a_loss_and_resume_from_a_state_past_it() {
    let relay = relay().await;
    let dir = folder("devices-lost");
    std::fs::create_dir_all(&dir).unwrap();
    let membership = Service::Folder(dir.join("logs").to_str().unwrap().into());
    let (laptop, laptop_devices) = stored_device(&relay, "laptop", &dir.join("laptop.db")).await;
    let (tablet, tablet_devices) = stored_device(&relay, "tablet", &dir.join("tablet.db")).await;
    let bob = laptop_devices.create("Bob", membership).await.unwrap();
    let link = lmk_proto::links::Invite::parse(&laptop_devices.invite(&bob.id.0).await.unwrap()).unwrap();
    tablet_devices.join(&link).await.unwrap();
    identified(&tablet_devices).await;
    tablet.node.shutdown().await.unwrap();
    drop((tablet, tablet_devices));
    let carol = lmk_core::contacts::Contact { name: "Carol".into(), how: lmk_core::contacts::How::Verified, by: None, at: 1, rest: Default::default() };
    laptop_devices.set_contact(&[9; 32], carol).await.unwrap();
    laptop.node.shutdown().await.unwrap();
    drop((laptop, laptop_devices));

    // The tablet, alone, commits twice and so loses the contact: it stops.
    let (mut tablet, tablet_devices) = stored_device(&relay, "tablet", &dir.join("tablet.db")).await;
    for name in ["tab", "slate"] {
        tablet_devices.rename(name).await.unwrap();
    }
    tablet.until(|e| matches!(e, Event::Warning { text, .. } if text.contains("waits for a device's state")).then_some(())).await;
    assert!(tablet_devices.contacts().is_empty());

    // The laptop comes back and hands it the state, past the loss.
    let (_laptop, _laptop_devices) = stored_device(&relay, "laptop", &dir.join("laptop.db")).await;
    eventually("the tablet takes the laptop's state", || tablet_devices.contacts().iter().any(|(_, c)| c.name == "Carol")).await;
}

/// The members a key log entry drops are removed by one commit.
#[tokio::test(flavor = "multi_thread")]
async fn a_pass_removes_every_member_due_in_one_commit() {
    use lmk_core::identity::public;
    let relay = relay().await;
    let dir = folder("one-commit");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let mut alice = session(&relay, "Alice").await;
    let (carol, key, laptop) = identity(&alice.node, "Carol", membership.clone()).await;
    let (tablet_key, phone_key): ([u8; 32], [u8; 32]) = (lmk_core::random(), lmk_core::random());
    let log = alice.node.read_key_log(&carol).await.unwrap();
    let all = vec![listed(&laptop, "laptop"), listed(&tablet_key, "tablet"), listed(&phone_key, "phone")];
    alice.node.append_identity(&carol, &log.next(&key, &public(&key), all)).await.unwrap();
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &dir) }, None).unwrap();
    let (tablet, phone) = (session(&relay, "tablet").await, session(&relay, "phone").await);
    for (joiner, device, name) in [(&tablet, &tablet_key, "tablet"), (&phone, &phone_key, "phone")] {
        let link = alice.node.invite(&gid.0, None, None).await.unwrap();
        joiner.node.join(&link, Some(certificate(&carol, device, &joiner.node.key()))).await.unwrap();
        alice.checked(&gid, name, true).await;
    }
    for session in [&tablet, &phone] {
        session.node.shutdown().await.unwrap();
    }
    let epoch = alice.node.epoch(&gid.0).unwrap();
    let log = alice.node.read_key_log(&carol).await.unwrap();
    alice.node.append_identity(&carol, &log.next(&key, &public(&lmk_core::random()), vec![listed(&laptop, "laptop")])).await.unwrap();
    let mut removed = alice.until(|e| match e {
        Event::Revoked { removed, .. } => Some(removed.into_iter().map(|m| m.name).collect::<Vec<_>>()),
        _ => None,
    }).await;
    removed.sort();
    assert_eq!(removed, ["phone", "tablet"]);
    assert_eq!((alice.node.epoch(&gid.0).unwrap(), alice.node.members(&gid.0).unwrap().len()), (epoch + 1, 1));
}

/// Members update their leaves every T. One that leaves asks again once its `leave` is older than the prior epoch,
/// and is removed once a member that can is back.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaver_asks_again_while_it_updates_every_t() {
    let relay = relay().await;
    let dir = folder("leave-again-t");
    std::fs::create_dir_all(&dir).unwrap();
    let alice_db = dir.join("alice.db");
    let alice = stored(&relay, "Alice", &alice_db).await;
    let mut bob = session(&relay, "Bob").await;
    let gid = alice.node.create(Settings { update: 2, ..settings(CHAT, &dir.join("logs")) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    alice.node.shutdown().await.unwrap();
    drop(alice);

    let epoch = bob.node.epoch(&gid.0).unwrap();
    bob.node.leave(&gid.0).await.unwrap().unwrap();
    let leaves = || bob.node.messages(&gid.0).unwrap().iter().filter(|m| m.payload["type"] == "leave").count();
    eventually("Bob asks again", || leaves() >= 2).await;
    assert!(bob.node.epoch(&gid.0).unwrap() >= epoch + 2, "Bob updated his leaf meanwhile");

    let alice = stored(&relay, "Alice", &alice_db).await;
    bob.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
    eventually("Alice is alone", || alice.node.members(&gid.0).unwrap().len() == 1).await;
    alice.node.shutdown().await.unwrap();
}

/// What a stopped session at `db` held: its iroh key, its head of the group's log, and its ciphertexts at `positions`.
fn holdings(db: &Path, gid: &Bytes, positions: &[u64]) -> (iroh::SecretKey, Head, Vec<Bytes>) {
    let provider = SqliteProvider::open(db).unwrap();
    let key = lmk_node::iroh_key(&provider).unwrap();
    let log: Value = serde_json::from_slice(&provider.get(&[b"node/log/".as_slice(), &gid.0].concat()).unwrap().unwrap()).unwrap();
    let head = serde_json::from_value(log["chain"]["head"].clone()).unwrap();
    let ciphertext = |p: &u64| Bytes(provider.get(&[b"node/ciphertext/".as_slice(), &gid.0, b"/", &p.to_be_bytes()].concat()).unwrap().unwrap());
    (key, head, positions.iter().map(ciphertext).collect())
}

/// A peer speaking the peer protocol by hand, on a connection it opens to a node.
struct Hand {
    _endpoint: iroh::Endpoint,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

async fn hand<P: Provider + Send + 'static>(relay: &Relay, key: iroh::SecretKey, to: &Node<P>) -> Hand {
    let relays = iroh::RelayMap::from(iroh::RelayConfig::new(relay.url.clone(), Some(Default::default())));
    let endpoint = lmk_net::builder(relays).secret_key(key).ca_tls_config(CaTlsConfig::custom_roots([relay.cert.clone()])).bind().await.unwrap();
    let (id, relay) = to.address();
    let addr = iroh::EndpointAddr::new(iroh::EndpointId::from_bytes(&id).unwrap()).with_relay_url(relay);
    let conn = endpoint.connect(addr, ALPN).await.unwrap();
    let (mut send, recv) = conn.open_bi().await.unwrap();
    frame::write(&mut send, &frame::Open { stream: frame::Stream::Peer }).await.unwrap();
    Hand { _endpoint: endpoint, send, recv }
}

impl Hand {
    async fn send(&mut self, frame: &Frame) {
        frame::write(&mut self.send, frame).await.unwrap();
    }

    /// Reads frames until one `pick` takes.
    async fn until<T>(&mut self, mut pick: impl FnMut(Frame) -> Option<T>) -> T {
        tokio::time::timeout(WAIT, async {
            loop {
                if let Some(found) = pick(frame::read_known(&mut self.recv).await.unwrap()) {
                    return found;
                }
            }
        })
        .await
        .expect("the frame came")
    }

    /// The positions the node asks for next.
    async fn wanted(&mut self) -> Ranges {
        self.until(|f| match f {
            Frame::Want { positions, .. } => Some(positions),
            _ => None,
        })
        .await
    }

    /// Asks the node for a position and waits for its answer: it has handled every frame sent before. Returns what it
    /// gave.
    async fn settle(&mut self, gid: &Bytes) -> Vec<Item> {
        self.send(&Frame::Want { group: gid.clone(), positions: Ranges::range(1, 1) }).await;
        self.until(|f| match f {
            Frame::Messages { items, answers: Some(_), .. } => Some(items),
            _ => None,
        })
        .await
    }
}

/// A `hello` showing a group's log at `head`, with `held` held.
fn summary(gid: &Bytes, head: &Head, held: Ranges) -> Frame {
    let summary = Summary { group: gid.clone(), head: head.clone(), held: held.clone(), read: held, fetching: Ranges::default() };
    Frame::Hello { groups: vec![summary], heads: vec![] }
}

fn one(position: u64) -> Ranges {
    Ranges::range(position, position)
}

/// The answer to a `want` of `asked`, carrying a ciphertext at a position, or none.
fn answer(gid: &Bytes, asked: u64, item: Option<(u64, &Bytes)>) -> Frame {
    let items = item.map(|(position, ciphertext)| Item { position, ciphertext: ciphertext.clone() }).into_iter().collect();
    Frame::Messages { group: gid.clone(), items, answers: Some(one(asked)) }
}

/// Each peer's latest summary of a group is saved over the last, survives a restart, shows what it held and read, and
/// goes when its Remove applies; `synced` fires on a `hello` at this session's head; `only_here` and Away follow.
#[tokio::test(flavor = "multi_thread")]
async fn summaries_are_kept_shown_and_dropped_with_their_member() {
    let relay = relay().await;
    let dir = folder("summaries");
    std::fs::create_dir_all(&dir).unwrap();
    let alice_db = dir.join("alice.db");
    let mut alice = stored(&relay, "Alice", &alice_db).await;
    let bob = session(&relay, "Bob").await;
    let carol = session(&relay, "Carol").await;
    let gid = alice.node.create(settings(CHAT, &dir.join("logs")), None).unwrap();
    let first = alice.node.send(&gid.0, &message("before anyone")).await.unwrap().position.unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    assert!(!alice.node.only_here(&gid.0).unwrap().contains(first), "before every other member's start, whether or not heard yet");
    let p = alice.node.send(&gid.0, &message("hello")).await.unwrap().position.unwrap();
    eventually("both hold Alice's message", || !alice.node.only_here(&gid.0).unwrap().contains(p)).await;
    bob.node.mark_read(&gid.0, &one(p)).unwrap();
    eventually("Bob's summary shows it read", || {
        alice.node.heard(&gid.0).unwrap().iter().any(|h| h.member.name == "Bob" && h.held.contains(p) && h.read.contains(p))
    })
    .await;
    alice.until(|e| matches!(e, Event::Synced { member, .. } if member.name == "Bob").then_some(())).await;
    assert!(alice.node.away(&gid.0).unwrap().is_empty());

    alice.node.shutdown().await.unwrap();
    drop(alice);
    let alice = stored(&relay, "Alice", &alice_db).await;
    let mut names: Vec<String> = alice.node.heard(&gid.0).unwrap().into_iter().map(|h| h.member.name).collect();
    names.sort();
    assert_eq!(names, ["Bob", "Carol"], "saved across the restart");
    alice.node.remove(&gid.0, &carol.node.key().0).await.unwrap();
    assert!(alice.node.heard(&gid.0).unwrap().iter().all(|h| h.member.name != "Carol"), "gone with its member");
    bob.node.shutdown().await.unwrap();
    let q = alice.node.send(&gid.0, &message("alone")).await.unwrap().position.unwrap();
    let only_here = alice.node.only_here(&gid.0).unwrap();
    assert!(only_here.contains(q) && !only_here.contains(p) && !only_here.contains(first), "Bob's saved summary holds the first, not the second");
    alice.node.shutdown().await.unwrap();
}

/// A missing position holds up the later ones of its epoch while it is being fetched; once no summary shows it, they open
/// past it; it opens still if it comes while its epoch's keys are kept; and one still missing as a commit deletes them is
/// lost.
#[tokio::test(flavor = "multi_thread")]
async fn a_gap_holds_up_its_epoch_while_fetched_then_is_passed_and_opens_late_or_is_lost() {
    let relay = relay().await;
    let dir = folder("gap");
    std::fs::create_dir_all(&dir).unwrap();
    let (sam_db, bob_db) = (dir.join("sam.db"), dir.join("bob.db"));
    let sam = stored(&relay, "Sam", &sam_db).await;
    let bob = stored(&relay, "Bob", &bob_db).await;
    let gid = sam.node.create(settings(CHAT, &dir.join("logs")), None).unwrap();
    bob.node.join(&sam.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    eventually("Bob is in", || sam.node.members(&gid.0).unwrap().len() == 2).await;
    bob.node.shutdown().await.unwrap();
    drop(bob);
    let mut sent = Vec::new();
    for text in ["one", "two", "three"] {
        sent.push(sam.node.send(&gid.0, &message(text)).await.unwrap());
    }
    sam.node.shutdown().await.unwrap();
    drop(sam);
    let p: Vec<u64> = sent.iter().map(|s| s.position.unwrap()).collect();
    let (key, head, ciphertexts) = holdings(&sam_db, &gid, &p);

    // Bob comes back. Sam, by hand, holds the first two: Bob asks for them, and gets the second only.
    let mut bob = stored(&relay, "Bob", &bob_db).await;
    let mut sam = hand(&relay, key, &bob.node).await;
    let held = Ranges::range(1, head.length).difference(&one(p[2]));
    sam.send(&summary(&gid, &head, held.clone())).await;
    assert_eq!(sam.wanted().await, Ranges::range(p[0], p[1]));
    sam.send(&answer(&gid, p[1], Some((p[1], &ciphertexts[1])))).await;
    // The first is being fetched still: the second waits for it.
    assert_eq!(sam.wanted().await, one(p[0]));
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(bob.node.messages(&gid.0).unwrap().is_empty(), "the second waits while the first is fetched");
    // Sam has not got the first after all: no summary shows it, and the second opens past it.
    sam.send(&answer(&gid, p[0], None)).await;
    let got = bob.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!(got.id, sent[1].id);
    // Sam's next summary shows it again: it opens late.
    sam.send(&summary(&gid, &head, held)).await;
    assert_eq!(sam.wanted().await, one(p[0]));
    sam.send(&answer(&gid, p[0], Some((p[0], &ciphertexts[0])))).await;
    let got = bob.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((got.id, got.position), (sent[0].id.clone(), p[0]));

    // No member holds the third: once its epoch's keys go, two commits on, it is lost.
    for name in ["Later", "Later still"] {
        bob.node.change_settings(&gid.0, |s| Settings { name: name.into(), ..s }).await.unwrap();
    }
    assert!(bob.node.lost(&gid.0, &sent[2].id.0));
    assert!(!bob.node.lost(&gid.0, &sent[0].id.0));
    bob.node.shutdown().await.unwrap();
}

/// The line S–Q–R (G3): R, which reaches only Q, waits before the commit that deletes the keys of a message it lacks
/// while Q fetches the message from S, then gets it from Q. Behind its log's head, Q takes no `state`.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_waits_while_the_member_between_it_and_the_holder_fetches() {
    let relay = relay().await;
    let dir = folder("line");
    std::fs::create_dir_all(&dir).unwrap();
    let dbs = ["sam", "quinn", "rita"].map(|name| dir.join(format!("{name}.db")));
    let sam = stored(&relay, "Sam", &dbs[0]).await;
    let gid = sam.node.create(settings(CHAT, &dir.join("logs")), None).unwrap();
    let links = [sam.node.invite(&gid.0, None, None).await.unwrap(), sam.node.invite(&gid.0, None, None).await.unwrap()];
    for ((name, db), link) in [("Quinn", &dbs[1]), ("Rita", &dbs[2])].into_iter().zip(links) {
        let joiner = stored(&relay, name, db).await;
        joiner.node.join(&link, None).await.unwrap();
        eventually("the joiner has its Add", || joiner.node.members(&gid.0).unwrap().iter().any(|m| m.name == name)).await;
        joiner.node.shutdown().await.unwrap();
    }
    let sent = sam.node.send(&gid.0, &message("p")).await.unwrap();
    let epoch = sam.node.epoch(&gid.0).unwrap();
    for name in ["One", "Two"] {
        sam.node.change_settings(&gid.0, |s| Settings { name: name.into(), ..s }).await.unwrap();
    }
    sam.node.shutdown().await.unwrap();
    drop(sam);
    let p = sent.position.unwrap();
    let (key, head, ciphertexts) = holdings(&dbs[0], &gid, &[p]);

    // Q comes back, reads to the second rename, which deletes p's keys, and fetches p from S.
    let quinn = stored(&relay, "Quinn", &dbs[1]).await;
    let mut sam = hand(&relay, key, &quinn.node).await;
    sam.send(&summary(&gid, &head, Ranges::range(1, head.length))).await;
    assert_eq!(sam.wanted().await, one(p));
    let file = lmk_proto::links::FileLink { hash: [7; 32], size: 1, key: [0; 32] };
    sam.send(&Frame::State { group: gid.clone(), link: Some(file.link()) }).await;
    sam.settle(&gid).await;
    assert!(!quinn.node.linked(&gid.0).contains(&file), "no state while behind");

    // R comes back too, reaching only Q, whose summary shows p fetching: R waits past the 3 seconds after it came online
    // (its first connection), and within the 10 without progress. S keeps Q's request alive.
    let mut rita = stored(&relay, "Rita", &dbs[2]).await;
    eventually("R reaches Q", || rita.node.online(&gid.0).unwrap().iter().any(|m| m.name == "Quinn")).await;
    let online = std::time::Instant::now();
    eventually("R reached the second rename", || rita.node.epoch(&gid.0).unwrap() == epoch + 1).await;
    while online.elapsed() < Duration::from_secs(4) {
        tokio::time::sleep(Duration::from_millis(500)).await;
        sam.send(&summary(&gid, &head, Ranges::range(1, head.length))).await;
    }
    assert_eq!(rita.node.epoch(&gid.0).unwrap(), epoch + 1, "R waits past the 3 seconds after it came online");
    sam.send(&answer(&gid, p, Some((p, &ciphertexts[0])))).await;
    let got = rita.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((got.id, got.position), (sent.id.clone(), p));
    eventually("R applied the second rename", || rita.node.epoch(&gid.0).unwrap() >= epoch + 2).await;
    assert!(!rita.node.lost(&gid.0, &sent.id.0));
    sam.send(&Frame::State { group: gid.clone(), link: Some(file.link()) }).await;
    eventually("at its head, Q takes a state", || quinn.node.linked(&gid.0).contains(&file)).await;
    quinn.node.shutdown().await.unwrap();
    rita.node.shutdown().await.unwrap();
}

/// Every row of every table in a session's database.
fn dump(db: &Path) -> Vec<String> {
    let db = rusqlite::Connection::open(db).unwrap();
    let mut tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").unwrap();
    let tables: Vec<String> = tables.query_map([], |row| row.get(0)).unwrap().map(Result::unwrap).collect();
    let mut rows = Vec::new();
    for table in tables {
        let mut select = db.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
        let columns = select.column_count();
        let mut query = select.query([]).unwrap();
        while let Some(row) = query.next().unwrap() {
            let values: Vec<rusqlite::types::Value> = (0..columns).map(|i| row.get(i).unwrap()).collect();
            rows.push(format!("{table} {values:?}"));
        }
    }
    rows.sort();
    rows
}

/// What a peer the gate does not admit sends changes nothing: a forged ciphertext, entries under a head the service did
/// not sign, a `state`, live payloads; and its `want` gets nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_not_admitted_changes_nothing() {
    let relay = relay().await;
    let dir = folder("forged");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let alice_db = dir.join("alice.db");
    let mut alice = stored(&relay, "Alice", &alice_db).await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &dir) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    let sent = bob.node.send(&gid.0, &message("real")).await.unwrap();
    alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    bob.node.shutdown().await.unwrap();
    eventually("Bob is gone", || alice.node.online(&gid.0).unwrap().is_empty()).await;
    let before = dump(&alice_db);

    let mut mallory = hand(&relay, iroh::SecretKey::from_bytes(&lmk_core::random()), &alice.node).await;
    let p = sent.position.unwrap();
    let real = Bytes(rusqlite::Connection::open(&alice_db).unwrap().query_row(
        "SELECT value FROM lmk WHERE key = ?",
        [[b"node/ciphertext/".as_slice(), &gid.0, b"/", &p.to_be_bytes()].concat()],
        |row| row.get(0),
    ).unwrap());
    let forged = |n: u8| {
        let mut forged = real.clone();
        *forged.0.last_mut().unwrap() ^= n;
        forged
    };
    let items = vec![Item { position: p, ciphertext: forged(1) }, Item { position: p + 1, ciphertext: forged(2) }];
    mallory.send(&Frame::Messages { group: gid.clone(), items, answers: None }).await;
    let head = Head { log: gid.clone(), length: p + 1, hash: Bytes(vec![9; 32]), time: lmk_node::now(), sig: Bytes(vec![0; 64]) };
    mallory.send(&Frame::Entries { log: gid.clone(), entries: vec![Bytes(b"junk".to_vec())], head }).await;
    let file = lmk_proto::links::FileLink { hash: [7; 32], size: 1, key: [0; 32] };
    mallory.send(&Frame::State { group: gid.clone(), link: Some(file.link()) }).await;
    mallory.send(&Frame::Live { group: gid.clone(), items: vec![forged(3)] }).await;
    assert!(mallory.settle(&gid).await.is_empty(), "a want the gate does not take gets nothing");
    assert_eq!(dump(&alice_db), before);
    assert!(!alice.node.linked(&gid.0).contains(&file));
    while let Ok(event) = alice.events.try_recv() {
        assert!(!matches!(event, Event::Message(_) | Event::Live { .. } | Event::State { .. }), "{event:?}");
    }
    alice.node.shutdown().await.unwrap();
}

/// A joiner whose `admitted` was lost asks again with the KeyPackage it kept: the member answers with the Welcome its log
/// holds, and adds it no second time.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_whose_answer_was_lost_is_admitted_by_the_logged_welcome() {
    let relay = relay().await;
    let dir = folder("lost-answer");
    let mut alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(KIND, &dir), None).unwrap();
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    let (node, first) = (bob.node.clone(), link.clone());
    let joining = tokio::spawn(async move { node.join(&first, None).await });
    // The Add is in: its answer waits for the kind's state, and the joiner stops waiting for it.
    let reply = alice.until(|e| match e {
        Event::Snapshot { reply, .. } => Some(reply),
        _ => None,
    }).await;
    let epoch = alice.node.epoch(&gid.0).unwrap();
    joining.abort();
    assert!(joining.await.is_err());
    drop(reply);

    let node = bob.node.clone();
    let again = tokio::spawn(async move { node.join(&link, None).await });
    alice.snapshot(Some(b"state")).await;
    let (joined, _) = again.await.unwrap().unwrap();
    assert_eq!(joined, gid);
    assert_eq!(alice.node.epoch(&gid.0).unwrap(), epoch, "no second Add");
    assert_eq!(bob.node.members(&gid.0).unwrap().len(), 2);
}

/// A link's kind is not authenticated: a device link altered to read as a group's admits to nothing, nor does a group's
/// link altered to read as a device link.
#[tokio::test(flavor = "multi_thread")]
async fn a_link_altered_to_another_kind_admits_to_nothing() {
    use lmk_proto::links::Invite;
    let relay = relay().await;
    let dir = folder("altered");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let (mut laptop, laptop_devices) = device(&relay, "laptop").await;
    routed(&mut laptop, laptop_devices.clone());
    let bob = laptop_devices.create("Bob", membership.clone()).await.unwrap();
    let mallory = node(&relay, "Mallory", &[CHAT, DEVICES]).await;
    let link = Invite::parse(&laptop_devices.invite(&bob.id.0).await.unwrap()).unwrap();
    // Nor does a device-link attempt left waiting make the same secret, read as a group link, join with a device key.
    let dead = lmk_proto::links::Address { key: *iroh::SecretKey::from_bytes(&lmk_core::random()).public().as_bytes(), relay: Some(relay.url.to_string()) };
    mallory.node.join(&Invite { members: vec![dead], ..link.clone() }, None).await.unwrap_err();
    let refused = mallory.node.join(&Invite { device: false, ..link }, None).await.unwrap_err();
    assert!(format!("{refused:#}").contains("altered"), "{refused:#}");
    assert!(mallory.node.groups().is_empty());

    let gid = laptop.node.create(settings(CHAT, &dir), None).unwrap();
    let link = laptop.node.invite(&gid.0, None, None).await.unwrap();
    let refused = mallory.node.join(&Invite { device: true, ..link }, None).await.unwrap_err();
    assert!(format!("{refused:#}").contains("altered"), "{refused:#}");
    assert!(mallory.node.groups().is_empty());
    laptop.node.shutdown().await.unwrap();
}

/// A member online is not away, though not heard from yet; a file spreads once one member takes it, though another never
/// answers; a member's adder keeps its key once gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_online_is_not_away_and_a_file_spreads_on_its_first_holder() {
    let relay = relay().await;
    let dir = folder("spread");
    std::fs::create_dir_all(&dir).unwrap();
    let (alice_db, carol_db) = (dir.join("alice.db"), dir.join("carol.db"));
    let alice = stored(&relay, "Alice", &alice_db).await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &dir.join("logs")), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    eventually("Alice has Bob's Add", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let carol = stored(&relay, "Carol", &carol_db).await;
    carol.node.join(&bob.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    carol.node.shutdown().await.unwrap();
    drop(carol);

    // Alice comes back; Carol, by hand, connects and says nothing.
    let alice = stored(&relay, "Alice", &alice_db).await;
    eventually("Alice has Carol's Add", || alice.node.members(&gid.0).unwrap().len() == 3).await;
    assert!(alice.node.away(&gid.0).unwrap().iter().any(|m| m.name == "Carol"), "never heard from");
    let key = lmk_node::iroh_key(&SqliteProvider::open(&carol_db).unwrap()).unwrap();
    let _carol = hand(&relay, key, &alice.node).await;
    eventually("Carol is online", || alice.node.online(&gid.0).unwrap().iter().any(|m| m.name == "Carol")).await;
    assert!(alice.node.away(&gid.0).unwrap().is_empty(), "online, though not heard from");

    // Bob takes the file a second into the wait.
    let file = alice.node.add_file(&gid.0, b"attached".to_vec()).await.unwrap();
    let started = std::time::Instant::now();
    let (holders, _) = tokio::join!(alice.node.spread(&gid.0, &file), async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        bob.node.hold(&gid.0, &[file.link()]).unwrap();
    });
    assert_eq!(holders.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(), ["Bob"]);
    assert!(started.elapsed() < Duration::from_secs(4), "no wait for Carol's answer: {:?}", started.elapsed());

    alice.node.remove(&gid.0, &bob.node.key().0).await.unwrap();
    let carol = alice.node.members(&gid.0).unwrap().into_iter().find(|m| m.name == "Carol").unwrap();
    assert_eq!(carol.added.unwrap().0, bob.node.key());
    alice.node.shutdown().await.unwrap();
}
