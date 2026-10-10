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
use lmk_proto::frame::ALPN;
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

fn folder(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lmk-node-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn settings(kind: &str, folder: &Path) -> Settings {
    Settings {
        protocol: PROTOCOL,
        kind: kind.into(),
        name: "Plan".into(),
        open: vec![],
        carry: 7,
        membership: Service::Folder(folder.to_str().unwrap().into()),
        rest: Default::default(),
    }
}

fn message(text: &str) -> Value {
    serde_json::to_value(ChatMessage { content: text.into(), after: vec![], to: vec![], reply_to: None, urgent: false, attachment: None }).unwrap()
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
    bob.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
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

    // With the inviter offline, the other member it named admits the joiner; the inviter, not it, introduces them.
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let (joined, by) = erin.node.join(&link, None).await.unwrap();
    assert_eq!((joined, by), (gid.clone(), link.members[1].key));
    let (member, how, introduces) = bob.until(|e| match e {
        Event::Joined { member, how, introduces, .. } if member.name == "Erin" => Some((member, how, introduces)),
        _ => None,
    }).await;
    assert_eq!((member.name.as_str(), how, introduces), ("Erin", lmk_proto::group::How::Invite, false));
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

/// A membership service whose connections opened while `open` is false wait until it is true, each told by `reached`.
#[derive(Debug)]
struct Gated {
    service: Membership,
    open: tokio::sync::watch::Receiver<bool>,
    reached: tokio::sync::mpsc::UnboundedSender<()>,
}

impl iroh::protocol::ProtocolHandler for Gated {
    async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), iroh::protocol::AcceptError> {
        if !*self.open.borrow() {
            self.reached.send(()).ok();
        }
        self.open.clone().wait_for(|open| *open).await.ok();
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
    for closed in [false, true] {
        let (open, gate) = tokio::sync::watch::channel(true);
        let (reached, mut reaching) = tokio::sync::mpsc::unbounded_channel();
        let (membership, _service) = served(&relay, &dir.join(format!("{closed}")), |service| Gated { service, open: gate, reached }).await;
        let joiner = session(&relay, "Carol").await;
        let (carol, _, device) = identity(&joiner.node, "Carol", membership).await;
        let certificate = certificate(&carol, &device, &joiner.node.key());
        open.send(false).unwrap();
        let expires = lmk_node::now() + 3000;
        let joining = if closed {
            alice.node.change_settings(&gid.0, |mut s| {
                s.open.push(Named { id: carol.id.clone(), name: "Carol".into(), rest: Default::default() });
                s
            }).await.unwrap();
            let opening = lmk_proto::group::Opening { members: vec![alice_iroh.clone()], ..alice.node.opening(&gid.0).unwrap() };
            tokio::spawn(async move { joiner.node.join_open(&opening, certificate).await })
        } else {
            let secret = [8u8; 16];
            let rule = json!({ "type": "invite", "hash": Bytes(Sha256::digest(secret).to_vec()), "expires": expires, "to": carol.id });
            bob.node.send(&gid.0, &rule).await.unwrap();
            eventually("Alice holds the invite", || alice.node.messages(&gid.0).unwrap().iter().any(|m| m.payload["type"] == "invite")).await;
            let link = Invite { device: false, secret, members: alice_only.clone() };
            tokio::spawn(async move { joiner.node.join(&link, Some(certificate)).await.map(|(gid, _)| gid) })
        };
        tokio::time::timeout(WAIT, reaching.recv()).await.unwrap();
        if closed {
            bob.node.change_settings(&gid.0, |s| Settings { open: vec![], ..s }).await.unwrap();
            tokio::time::timeout(WAIT, async {
                while !alice.node.settings(&gid.0).unwrap().open.is_empty() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }).await.unwrap();
        } else {
            assert!(lmk_node::now() < expires, "the invite was ahead when the request came");
            tokio::time::sleep(Duration::from_millis(expires + 200 - lmk_node::now())).await;
        }
        open.send(true).unwrap();
        let refused = format!("{:#}", joining.await.unwrap().unwrap_err());
        let reason = if closed { "no identity the group is open to" } else { "unknown, used or expired" };
        assert!(refused.contains(reason), "{refused}");
        assert_eq!(alice.node.members(&gid.0).unwrap().len(), 2);
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

impl Session {
    /// Waits for the kind's held messages after position `after`; returns them.
    async fn logged(&mut self, gid: &Bytes, after: u64) -> Vec<lmk_node::Entry> {
        loop {
            let entries = self.node.entries(&gid.0, after).unwrap();
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
    let seen = if seen.len() == 2 { seen } else { order(alice.node.entries(&gid.0, p).unwrap()) };
    assert_eq!(seen.len(), 2);
    assert_eq!(order(bob.logged(&gid, p + 1).await), seen[1..]);
    bob.node.follow_log(&gid.0, Some(p + 1)).unwrap();
    assert_eq!(bob.node.entries(&gid.0, 0).unwrap().len(), 1, "messages the kind read past go");

    // Carol joins with no state: she asks a member for the kind's state, and follows from her start.
    let carol = session(&relay, "Carol").await;
    let link = bob.node.invite(&gid.0, None, None).await.unwrap();
    let joining = tokio::spawn(async move { carol.node.join(&link, None).await.map(|_| carol) });
    bob.snapshot(None).await;
    let mut carol = joining.await.unwrap().unwrap();
    carol.node.follow_log(&gid.0, None).unwrap();
    tokio::select! {
        _ = alice.snapshot(Some(b"through 3")) => {}
        _ = bob.snapshot(Some(b"through 3")) => {}
    }
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
            let link = alice.node.invite(&gid.0, None, None).await.unwrap();
            joiner.node.join(&link, Some(certificate(&carol, device, &joiner.node.key()))).await.unwrap();
            alice.checked(gid, &joiner.node.members(&gid.0).unwrap().iter().find(|m| m.key == joiner.node.key()).unwrap().name, true).await;
        }
    }
    // The tablet's session adds Dave to the first group, and invites Eve, whom alice admits.
    let link = tablet.node.invite(&groups[0].0, None, None).await.unwrap();
    dave.node.join(&link, None).await.unwrap();
    let link = lmk_proto::links::Invite { members: alice_only, ..tablet.node.invite(&groups[0].0, None, None).await.unwrap() };
    eve.node.join(&link, None).await.unwrap();
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

    // Only the laptop sees the key message of the key that replaces the tablet's, then stops.
    laptop_devices.remove(&bob.id.0, &tablet_key.0).await.unwrap();
    assert!(lists(&laptop.node, &bob, &["laptop", "phone"]).await.current() != &first);
    laptop.node.shutdown().await.unwrap();
    drop((laptop, laptop_devices));

    let (mut phone, phone_devices) = stored_device(&relay, "phone", &dir.join("phone.db")).await;
    let gid = devices_group(&phone.node);
    phone_devices.duties(&gid.0).await.unwrap();
    phone_devices.duties(&gid.0).await.unwrap();
    phone.until(|e| matches!(e, Event::Warning { text, .. } if text.contains("does not hold its identity's current key")).then_some(())).await;

    // The laptop comes back: the phone asks it, holds the key, and so restates the list with its new name.
    let (_laptop, _laptop_devices) = stored_device(&relay, "laptop", &dir.join("laptop.db")).await;
    phone_devices.rename("desk").await.unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            phone_devices.duties(&gid.0).await.unwrap();
            let log = phone.node.read_key_log(&bob).await.unwrap();
            if log.devices.iter().any(|device| device.name == "desk") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }).await.expect("the phone takes the key and lists itself anew");
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

fn log_dir(logs: &Path, gid: &Bytes) -> PathBuf {
    logs.join(gid.0.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Makes a folder's log unreachable, even to root, by a file in its place; or reachable again.
fn reachable(dir: &Path, reachable: bool) {
    let aside = dir.with_extension("aside");
    if reachable {
        std::fs::remove_file(dir).unwrap();
        std::fs::rename(&aside, dir).unwrap();
    } else {
        std::fs::rename(dir, &aside).unwrap();
        std::fs::write(dir, b"").unwrap();
    }
}

/// A `leave` sent while the group's log is unreachable is pending: the leaver appends it once the log is reachable,
/// after a restart with `restart_leaver`, and the other member then removes it.
async fn held_leave(test: &str, restart_leaver: bool) {
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder(test);
    std::fs::create_dir_all(&dir).unwrap();
    let logs = dir.join("logs");
    let start = |name: &'static str| {
        let (relay, db) = (&relay, dir.join(format!("{name}.db")));
        async move {
            let (node, events) = Node::start(SqliteProvider::open(&db).unwrap(), config(relay, name, None, &[CHAT])).await.unwrap();
            Session { node, events }
        }
    };
    let mut alice = start("Alice").await;
    let bob = start("Bob").await;
    let gid = alice.node.create(settings(CHAT, &logs), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, None).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;

    reachable(&log_dir(&logs, &gid), false);
    let mut bob = bob;
    let sent = bob.node.leave(&gid.0).await.unwrap().unwrap();
    assert_eq!(sent.position, None, "the leave is pending");
    if restart_leaver {
        bob.node.shutdown().await.unwrap();
        drop(bob);
        reachable(&log_dir(&logs, &gid), true);
        bob = start("Bob").await;
    } else {
        reachable(&log_dir(&logs, &gid), true);
    }
    let counted = bob.until(|e| match e {
        Event::Sent { id, position, .. } => Some((id, position)),
        _ => None,
    }).await;
    assert_eq!(counted.0, sent.id, "Sent names the send as `leave` answered it");
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
    a.unwrap().unwrap();
    b.unwrap().unwrap();
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
        tokio::spawn(async move { node.remove(&gid.0, &key.0).await.unwrap() })
    };
    let (a, b) = (remove(&alice.node), remove(&bob.node));
    assert!(a.await.unwrap() != b.await.unwrap(), "one of them committed the removal");
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
