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
use lmk_core::provider::MemoryProvider;
use lmk_membership::service::{Policy, Service as Membership};
use lmk_membership::store::Store;
use lmk_node::devices::Devices;
use lmk_node::{Config, Event, Node};
use lmk_proto::group::{CHAT, ChatMessage, DEVICES, Named, PROTOCOL, Service, Settings};
use lmk_proto::Bytes;
use lmk_proto::frame::ALPN;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::UnboundedReceiver;

const WAIT: Duration = Duration::from_secs(30);

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
    (Session { node: node.clone(), events }, Devices::new(node, device))
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
        window: Window::default(),
        kinds: kinds.iter().map(|kind| kind.to_string()).collect(),
    }
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
    let link = alice.node.invite(&gid.0, Some("Bob (Acme)".into()), None).unwrap();
    let joined = bob.node.join(&link, None).await.unwrap();
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
    let carol = node(&relay, "Carol", &[CHAT]).await;
    let gid = alice.node.create(settings(KIND, &dir), None).unwrap();
    assert!(carol.node.create(settings(KIND, &dir), None).is_err(), "a session makes no group of a kind it lacks");
    let link = alice.node.invite(&gid.0, None, None).unwrap();
    let refused = carol.node.join(&link, None).await.unwrap_err();
    assert!(format!("{refused:#}").contains("does not support test groups"), "{refused:#}");

    // The inviter's kind hands the joiner its state.
    let link = alice.node.invite(&gid.0, None, None).unwrap();
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
    let link = alice.node.invite(&gid.0, None, None).unwrap();
    let joining = tokio::spawn(async move { bob.node.join(&link, None).await.map(|_| bob) });
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
    let link = bob.node.invite(&gid.0, None, None).unwrap();
    let joining = tokio::spawn(async move { carol.node.join(&link, None).await.map(|_| carol) });
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

impl Session {
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
fn routed(session: &mut Session, devices: Devices<MemoryProvider>) {
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
async fn identified(devices: &Devices<MemoryProvider>) {
    tokio::time::timeout(WAIT, async {
        while devices.identities().is_empty() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the identity's state came");
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_share_an_identity_and_certify_their_sessions_with_its_key() {
    let relay = relay().await;
    let dir = folder("identity");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let alice = session(&relay, "Alice").await;
    let (mut laptop, laptop_devices) = device(&relay, "laptop").await;
    let (mut tablet, tablet_devices) = device(&relay, "tablet").await;
    routed(&mut laptop, laptop_devices.clone());
    routed(&mut tablet, tablet_devices.clone());
    let bob = laptop_devices.create("Bob", membership.clone()).await.unwrap();
    laptop_devices.set_contact(&[9; 32], lmk_core::contacts::Contact { name: "Carol".into(), how: lmk_core::contacts::How::Verified, by: None, at: 1 }).await.unwrap();

    // A device link: the tablet gets the identity's state, its key and contacts among it.
    let link = lmk_proto::links::Invite::parse(&laptop_devices.invite(&bob.id.0).unwrap()).unwrap();
    tablet_devices.join(&link).await.unwrap();
    identified(&tablet_devices).await;
    assert_eq!(tablet_devices.identities(), [(bob.clone(), "Bob".to_owned())]);
    assert_eq!(tablet_devices.contacts()[0].1.name, "Carol");
    let names: Vec<String> = laptop_devices.devices(&bob.id.0).unwrap().into_iter().map(|(_, name)| name).collect();
    assert_eq!(names.len(), 2);

    // Each certifies itself; alice opens a chat to Bob, which the tablet joins without an invite, and invites the laptop.
    for (session, devices, name) in [(&laptop, &laptop_devices, "laptop"), (&tablet, &tablet_devices, "tablet")] {
        let certificate = devices.certify(&bob.id.0, session.node.key(), name.into()).await.unwrap();
        session.node.set_certificate(certificate).unwrap();
    }
    let chat = alice.node.create(Settings { membership: membership.clone(), ..settings(CHAT, &dir) }, None).unwrap();
    alice.node.change_settings(&chat.0, |mut s| {
        s.open.push(Named { id: bob.id.clone(), name: "Bob".into() });
        s
    }).await.unwrap();
    let opening = alice.node.opening(&chat.0).unwrap();
    tablet_devices.set_opening(&bob.id.0, opening.clone()).await.unwrap();
    tokio::time::timeout(WAIT, async {
        while laptop_devices.openings().is_empty() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.expect("an opening reaches every device");
    tablet.node.join_open(&opening, bob.clone()).await.unwrap();
    let link = alice.node.invite(&chat.0, None, None).unwrap();
    laptop.node.join(&link, Some(bob.clone())).await.unwrap();
    let seen = alice.checked(&chat, "tablet", true).await;
    assert_eq!((seen.device_name.as_str(), seen.identity.unwrap().added_by_device.as_deref()), ("tablet", Some("laptop")));
    alice.checked(&chat, "laptop", true).await;

    // The laptop takes the tablet off Bob: the key is replaced, which alice learns from the laptop, so the tablet's
    // certificate no longer checks out, and the laptop's renewed one does.
    laptop_devices.remove(&bob.id.0, &tablet.node.key().0).await.unwrap();
    tokio::time::timeout(WAIT, async {
        while !tablet_devices.identities().is_empty() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.expect("the tablet is off the identity");
    let keys = tokio::time::timeout(WAIT, async {
        loop {
            let log = laptop.node.read_key_log(&bob).await.unwrap();
            if log.keys.len() == 2 {
                return log;
            }
        }
    }).await.unwrap();
    assert_eq!(laptop_devices.keys(), [(bob.id.clone(), Bytes(keys.current().to_vec()))]);
    let certificate = laptop_devices.certify(&bob.id.0, laptop.node.key(), "laptop".into()).await.unwrap();
    laptop.node.set_certificate(certificate).unwrap();
    let tablet_seen = alice.checked(&chat, "tablet", false).await;
    assert_eq!(tablet_seen.identity.unwrap().error.as_deref(), Some("its certificate is not by its identity's current key"));
    alice.checked(&chat, "laptop", true).await;
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
        (node.clone(), Devices::new(node, device.clone()))
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
    let link = alice.node.invite(&gid.0, None, None).unwrap();
    bob.node.join(&link, None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let link = alice.node.invite(&gid.0, None, None).unwrap();
    carol.join(&link, None).await.unwrap();
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
    let (carol, mut events) = Node::start(SqliteProvider::open(&carol_db).unwrap(), carol_config()).await.unwrap();
    let mut taken = 0;
    let all = async {
        while taken < MESSAGES {
            if let Event::Message(_) = events.recv().await.unwrap() {
                taken += 1;
            }
        }
    };
    tokio::time::timeout(WAIT, all).await.expect("Carol took every message");
    carol.shutdown().await.unwrap();
}
