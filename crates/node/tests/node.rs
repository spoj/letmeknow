//! Sessions over a local relay with a self-signed certificate, their logs in a folder.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use iroh::RelayUrl;
use iroh::tls::CaTlsConfig;
use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use lmk_core::device::Device;
use lmk_core::group::Window;
use lmk_core::invite::Target;
use lmk_core::provider::MemoryProvider;
use lmk_membership::service::{Policy, Service as Membership};
use lmk_membership::store::Store;
use lmk_node::{Config, Event, Node};
use lmk_proto::group::{CHAT, ChatMessage, PROTOCOL, Service, Settings};
use lmk_proto::Bytes;
use lmk_proto::frame::ALPN;
use lmk_proto::links::Invite;
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

struct Session {
    node: Node<MemoryProvider>,
    events: UnboundedReceiver<Event>,
}

/// The kinds the sessions here support, besides chat.
const KIND: &str = "test";

async fn session(relay: &Relay, name: &str) -> Session {
    node(relay, name, false, &[CHAT, KIND]).await
}

/// A device's own node: its key is the device key.
async fn device(relay: &Relay, name: &str) -> Session {
    node(relay, name, true, &[CHAT, KIND]).await
}

async fn node(relay: &Relay, name: &str, device_key: bool, kinds: &[&str]) -> Session {
    let config = Config {
        name: name.into(),
        device_key,
        relay: relay.url.clone(),
        ca: CaTlsConfig::custom_roots([relay.cert.clone()]),
        home: None,
        files: None,
        disk: None,
        file_limit: 100 << 20,
        window: Window::default(),
        kinds: kinds.iter().map(|kind| kind.to_string()).collect(),
    };
    let (node, events) = Node::start(MemoryProvider::default(), Device::new(&format!("{name}'s laptop")), config).await.unwrap();
    Session { node, events }
}

impl Session {
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
        keep: 90,
        membership: Service::Folder(folder.to_str().unwrap().into()),
        devices_of: None,
        openings: vec![],
        log: None,
    }
}

fn message(text: &str) -> Value {
    serde_json::to_value(ChatMessage { content: text.into(), after: vec![], to: vec![], reply_to: None, urgent: false, attachment: None }).unwrap()
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
    let link = alice.node.invite(Target::Group(gid.0.clone()), Some("Bob (Acme)".into()), None).unwrap();
    let joined = bob.node.join(&Invite::parse(&link).unwrap(), None).await.unwrap();
    assert_eq!(joined, gid);
    let (member, label) = alice.until(|e| match e {
        Event::Joined { member, label, .. } => Some((member, label)),
        _ => None,
    }).await;
    assert_eq!((member.name.as_str(), label.as_deref()), ("Bob", Some("Bob (Acme)")));
    assert_eq!(bob.node.members(&gid.0).unwrap().len(), 2);

    let (id, delivery) = bob.node.send(&gid.0, &message("hello"), false).await.unwrap();
    assert_eq!(delivery.held[0].name, "Alice");
    let got = alice.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((got.id, got.sender.name.as_str()), (id, "Bob"));
    assert!(bob.node.only_here(&gid.0).unwrap().is_empty());

    alice.node.change_settings(&gid.0, |s| Settings { name: "Release".into(), ..s }).await.unwrap();
    let renamed = bob.until(|e| match e {
        Event::Settings { settings, .. } => Some(settings),
        _ => None,
    }).await;
    assert_eq!(renamed.name, "Release");

    let bob_key = bob.node.key();
    alice.node.remove(&gid.0, &bob_key.0).await.unwrap();
    bob.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
    assert!(bob.node.groups().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kind_gets_its_state_to_a_joiner_and_its_payloads_frames_and_files_through() {
    let relay = relay().await;
    let dir = folder("kind");
    let mut alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let carol = node(&relay, "Carol", false, &[CHAT]).await;
    let gid = alice.node.create(settings(KIND, &dir), None).unwrap();
    assert!(carol.node.create(settings(KIND, &dir), None).is_err(), "a session makes no group of a kind it lacks");
    let link = alice.node.invite(Target::Group(gid.0.clone()), None, None).unwrap();
    let refused = carol.node.join(&Invite::parse(&link).unwrap(), None).await.unwrap_err();
    assert!(format!("{refused:#}").contains("does not support test groups"), "{refused:#}");

    // The inviter's kind hands the joiner its state.
    let link = alice.node.invite(Target::Group(gid.0.clone()), None, None).unwrap();
    let joining = tokio::spawn(async move { bob.node.join(&Invite::parse(&link).unwrap(), None).await.map(|_| bob) });
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

    // Held and live payloads; a frame and a live payload to one member.
    let push = json!({ "type": "push", "n": 1 });
    let (id, delivery) = alice.node.send(&gid.0, &push, true).await.unwrap();
    assert_eq!(delivery.held[0].name, "Bob");
    let held = bob.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((held.id, held.payload), (id, push));
    alice.node.send_live(&gid.0, &json!({ "type": "edit", "n": 2 }), Some(&fp(&bob.node.key()))).unwrap();
    let live = bob.until(|e| match e {
        Event::Live { payload, sender, .. } => Some((payload, sender.name)),
        _ => None,
    }).await;
    assert_eq!(live, (json!({ "type": "edit", "n": 2 }), "Alice".to_owned()));
    assert!(bob.node.messages(&gid.0).unwrap().iter().all(|m| m.payload["type"] == "push"), "a live payload is not held");
    alice.node.frame(&gid.0, &fp(&bob.node.key()), json!({ "doc": { "snapshot": "AA" } })).unwrap();
    let frame = bob.until(|e| match e {
        Event::Frame { frame, from, .. } => Some((frame, from.name)),
        _ => None,
    }).await;
    assert_eq!(frame, (json!({ "doc": { "snapshot": "AA" } }), "Alice".to_owned()));

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

#[tokio::test(flavor = "multi_thread")]
async fn a_removed_device_leaves_every_group() {
    let relay = relay().await;
    let dir = folder("revoke");
    let membership = Service::Folder(dir.join("identities").to_str().unwrap().into());
    let mut alice = session(&relay, "Alice").await;
    let mut laptop = device(&relay, "laptop").await;
    let mut tablet = device(&relay, "tablet").await;
    let bob = laptop.node.identity_create("Bob", membership).await.unwrap();
    let link = laptop.node.invite(Target::Device(bob.id.0.clone()), None, None).unwrap();
    let devices = tablet.node.join(&Invite::parse(&link).unwrap(), None).await.unwrap();
    laptop.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let chat = alice.node.create(settings(CHAT, &dir), None).unwrap();
    let link = alice.node.invite(Target::Group(chat.0.clone()), None, None).unwrap();
    tablet.node.join(&Invite::parse(&link).unwrap(), Some(bob.clone())).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;

    laptop.node.remove_device(&bob, &tablet.node.device().public()).await.unwrap();
    // The laptop notices in the devices group; alice, once she reads the list.
    laptop.until(|e| matches!(e, Event::Left { .. }).then_some(())).await;
    alice.node.device_list(&bob).await.unwrap();
    let left = alice.until(|e| match e {
        Event::Left { member, .. } => Some(member),
        _ => None,
    }).await;
    assert_eq!(left.device.0, tablet.node.device().public());
    let mut gone = Vec::new();
    while gone.len() < 2 {
        gone.push(tablet.until(|e| match e {
            Event::Removed { group, .. } => Some(group),
            _ => None,
        }).await);
    }
    gone.sort();
    let mut expected = vec![devices, chat];
    expected.sort();
    assert_eq!(gone, expected);
}

/// A membership service like `letmeknow serve`'s, which signs its heads.
async fn signing_service(relay: &Relay, dir: &Path) -> (Service, iroh::protocol::Router) {
    let secret = iroh::SecretKey::from_bytes(&lmk_core::random());
    let relays = iroh::RelayMap::from(iroh::RelayConfig::new(relay.url.clone(), Some(Default::default())));
    let roots = CaTlsConfig::custom_roots([relay.cert.clone()]);
    let endpoint = lmk_net::builder(relays).secret_key(secret.clone()).ca_tls_config(roots).bind().await.unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let store = Store::open(&dir.join("membership.db"), ed25519_dalek::SigningKey::from_bytes(&secret.to_bytes())).unwrap();
    let router = iroh::protocol::Router::builder(endpoint.clone()).accept(ALPN, Membership::new(store, Policy::default())).spawn();
    let service = Service::Serve { key: Bytes(endpoint.id().as_bytes().to_vec()), relay: relay.url.to_string(), addrs: vec![] };
    (service, router)
}

impl Session {
    /// Waits for entries of the kind's log after `after`; returns them.
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
async fn a_kinds_log_orders_appends_and_a_member_behind_it_takes_a_state() {
    let relay = relay().await;
    let dir = folder("log");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let mut alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(Settings { membership, ..settings(KIND, &dir) }, None).unwrap();
    assert!(alice.node.settings(&gid.0).unwrap().log.is_some(), "a group of a plugin's kind has a log");
    alice.node.follow_log(&gid.0, Some((0, 0))).unwrap();
    let link = alice.node.invite(Target::Group(gid.0.clone()), None, None).unwrap();
    let joining = tokio::spawn(async move { bob.node.join(&Invite::parse(&link).unwrap(), None).await.map(|_| bob) });
    alice.snapshot(Some(b"empty")).await;
    let mut bob = joining.await.unwrap().unwrap();
    bob.until(|e| matches!(e, Event::State { .. }).then_some(())).await;
    bob.node.follow_log(&gid.0, Some((0, 0))).unwrap();

    // Each append learns its position, with every entry before it opened; every member opens them in one order.
    assert_eq!(alice.node.append(&gid.0, &json!({ "type": "push", "n": 1 })).await.unwrap(), 1);
    let first = bob.logged(&gid, 0).await;
    assert_eq!((first[0].position, first[0].from.name.as_str(), &first[0].payload), (1, "Alice", &json!({ "type": "push", "n": 1 })));
    let (two, three) = (json!({ "type": "push", "n": 2 }), json!({ "type": "push", "n": 3 }));
    let (a, b) = tokio::join!(alice.node.append(&gid.0, &two), bob.node.append(&gid.0, &three));
    let mut positions = [a.unwrap(), b.unwrap()];
    positions.sort();
    assert_eq!(positions, [2, 3]);
    let order = |entries: Vec<lmk_node::Entry>| entries.iter().map(|e| (e.position, e.payload["n"].as_u64().unwrap())).collect::<Vec<_>>();
    let seen = order(alice.node.entries(&gid.0, 1).unwrap());
    assert_eq!(seen.len(), 2);
    assert_eq!(order(bob.node.entries(&gid.0, 1).unwrap()), seen);
    bob.node.follow_log(&gid.0, Some((2, 0))).unwrap();
    assert_eq!(bob.node.entries(&gid.0, 0).unwrap().len(), 1, "entries the kind read past go");

    // Carol joins with no state and reads from the start: she holds no keys of the entries' epochs, so she asks a member
    // for the kind's state, and follows from where it leaves off.
    let carol = session(&relay, "Carol").await;
    let link = bob.node.invite(Target::Group(gid.0.clone()), None, None).unwrap();
    let joining = tokio::spawn(async move { carol.node.join(&Invite::parse(&link).unwrap(), None).await.map(|_| carol) });
    bob.snapshot(None).await;
    let mut carol = joining.await.unwrap().unwrap();
    carol.node.follow_log(&gid.0, Some((0, 0))).unwrap();
    tokio::select! {
        _ = alice.snapshot(Some(b"through 3")) => {}
        _ = bob.snapshot(Some(b"through 3")) => {}
    }
    let data = carol.until(|e| match e {
        Event::State { data, .. } => Some(data),
        _ => None,
    }).await;
    assert_eq!(data, b"through 3");
    assert!(carol.node.append(&gid.0, &json!({ "type": "push" })).await.is_err(), "a member behind the log does not append");
    let epoch = alice.node.entries(&gid.0, 2).unwrap()[0].epoch;
    carol.node.follow_log(&gid.0, Some((3, epoch))).unwrap();
    assert_eq!(carol.node.append(&gid.0, &json!({ "type": "push", "n": 4 })).await.unwrap(), 4);
    assert_eq!(alice.logged(&gid, 3).await[0].from.name, "Carol");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removal_spreads_through_peers() {
    let relay = relay().await;
    let dir = folder("spread");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let mut alice = session(&relay, "Alice").await;
    let mut laptop = device(&relay, "laptop").await;
    let tablet = device(&relay, "tablet").await;
    let bob = laptop.node.identity_create("Bob", membership.clone()).await.unwrap();
    let link = laptop.node.invite(Target::Device(bob.id.0.clone()), None, None).unwrap();
    tablet.node.join(&Invite::parse(&link).unwrap(), None).await.unwrap();
    laptop.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    // Alice shares one chat with the tablet and another with the laptop; she reads Bob's list as each joins.
    for member in [&tablet, &laptop] {
        let chat = alice.node.create(Settings { membership: membership.clone(), ..settings(CHAT, &dir) }, None).unwrap();
        let link = alice.node.invite(Target::Group(chat.0.clone()), None, None).unwrap();
        member.node.join(&Invite::parse(&link).unwrap(), Some(bob.clone())).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    // Her copy is fresh for 10 minutes, so she learns of the removal only from the laptop, which shows her the list.
    laptop.node.remove_device(&bob, &tablet.node.device().public()).await.unwrap();
    let left = alice.until(|e| match e {
        Event::Left { member, .. } => Some(member),
        _ => None,
    }).await;
    assert_eq!(left.device.0, tablet.node.device().public());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_stopped_before_it_was_saved_is_still_on_its_identity() {
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder("unsaved");
    std::fs::create_dir_all(&dir).unwrap();
    let membership = Service::Folder(dir.join("logs").to_str().unwrap().into());
    let config = || Config {
        name: "laptop".into(),
        device_key: true,
        relay: relay.url.clone(),
        ca: CaTlsConfig::custom_roots([relay.cert.clone()]),
        home: None,
        files: None,
        disk: None,
        file_limit: 100 << 20,
        window: Window::default(),
        kinds: vec![CHAT.into()],
    };
    let saved = Device::new("laptop");
    let (node, _events) = Node::start(SqliteProvider::open(&dir.join("device.db")).unwrap(), saved.clone(), config()).await.unwrap();
    let bob = node.identity_create("Bob", membership).await.unwrap();
    node.shutdown().await.unwrap();
    drop(node);
    let (node, _events) = Node::start(SqliteProvider::open(&dir.join("device.db")).unwrap(), saved, config()).await.unwrap();
    assert_eq!(node.device().identities, std::slice::from_ref(&bob));
    assert_eq!(node.identities(), [(bob, "Bob".to_owned())]);
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
    let carol_config = || Config {
        name: "Carol".into(),
        device_key: false,
        relay: relay.url.clone(),
        ca: CaTlsConfig::custom_roots([relay.cert.clone()]),
        home: None,
        files: None,
        disk: None,
        file_limit: 100 << 20,
        window: Window::default(),
        kinds: vec![CHAT.into()],
    };
    let carol_device = Device::new("Carol's laptop");
    let carol_db = dir.join("carol.db");
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let (carol, _events) = Node::start(SqliteProvider::open(&carol_db).unwrap(), carol_device.clone(), carol_config()).await.unwrap();
    let gid = alice.node.create(settings(CHAT, &dir.join("logs")), None).unwrap();
    let link = alice.node.invite(Target::Group(gid.0.clone()), None, None).unwrap();
    bob.node.join(&Invite::parse(&link).unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let link = alice.node.invite(Target::Group(gid.0.clone()), None, None).unwrap();
    carol.join(&Invite::parse(&link).unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    bob.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    carol.shutdown().await.unwrap();
    drop(carol);
    for n in 0..MESSAGES {
        alice.node.send(&gid.0, &message(&n.to_string()), false).await.unwrap();
    }
    for _ in 0..MESSAGES {
        bob.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    }
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let (carol, mut events) = Node::start(SqliteProvider::open(&carol_db).unwrap(), carol_device, carol_config()).await.unwrap();
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
