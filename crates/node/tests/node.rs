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
use lmk_core::provider::{MemoryProvider, Provider};
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
        window: Window::default(),
        kinds: kinds.iter().map(|kind| kind.to_string()).collect(),
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
        keep: 90,
        membership: Service::Folder(folder.to_str().unwrap().into()),
        rest: Default::default(),
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
    let link = alice.node.invite(&gid.0, Some("Bob (Acme)".into()), None).await.unwrap();
    let (joined, _) = bob.node.join(&link, None).await.unwrap();
    assert_eq!(joined, gid);
    let (member, label, introduces) = alice.until(|e| match e {
        Event::Joined { member, label, introduces, .. } => Some((member, label, introduces)),
        _ => None,
    }).await;
    assert_eq!((member.name.as_str(), label.as_deref(), introduces), ("Bob", Some("Bob (Acme)"), true));
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

    // An expired one too.
    let secret = [7u8; 16];
    let expired = json!({ "type": "invite", "hash": Bytes(Sha256::digest(secret).to_vec()), "expires": lmk_node::now() - 1 });
    let (_, delivery) = bob.node.send(&gid.0, &expired, true).await.unwrap();
    assert!(delivery.held.iter().any(|m| m.name == "Alice"));
    let expired = Invite { secret, members: vec![link.members[0].clone()], ..link.clone() };
    assert!(format!("{:#}", erin.node.join(&expired, None).await.unwrap_err()).contains("unknown, used or expired"));

    // With the inviter offline, the other member it named admits the joiner; the inviter, not it, introduces them.
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
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
    let service = Service::Serve { key: Bytes(endpoint.id().as_bytes().to_vec()), relay: relay.url.to_string(), addrs: vec![], rest: Default::default() };
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
    alice.node.follow_log(&gid.0, Some(0)).unwrap();
    let link = alice.node.invite(&gid.0, None, None).await.unwrap();
    let joining = tokio::spawn(async move { bob.node.join(&link, None).await.map(|_| bob) });
    alice.snapshot(Some(b"empty")).await;
    let mut bob = joining.await.unwrap().unwrap();
    bob.until(|e| matches!(e, Event::State { .. }).then_some(())).await;
    bob.node.follow_log(&gid.0, Some(0)).unwrap();

    // An entry names a held message; each append learns its position, with every entry before it taken, and every
    // member takes them in one order.
    assert!(alice.node.append(&gid.0, &[9; 32]).await.is_err(), "only a message the group holds is appended");
    let (one, _) = alice.node.send(&gid.0, &json!({ "type": "push", "n": 1 }), true).await.unwrap();
    assert_eq!(alice.node.append(&gid.0, &one.0).await.unwrap(), 1);
    let first = bob.logged(&gid, 0).await;
    assert_eq!((first[0].position, first[0].from.name.as_str(), &first[0].payload), (1, "Alice", &json!({ "type": "push", "n": 1 })));
    assert_eq!(first[0].id, one);
    let (two, _) = alice.node.send(&gid.0, &json!({ "type": "push", "n": 2 }), true).await.unwrap();
    let (three, _) = bob.node.send(&gid.0, &json!({ "type": "push", "n": 3 }), true).await.unwrap();
    let (a, b) = tokio::join!(alice.node.append(&gid.0, &two.0), bob.node.append(&gid.0, &three.0));
    let mut positions = [a.unwrap(), b.unwrap()];
    positions.sort();
    assert_eq!(positions, [2, 3]);
    let order = |entries: Vec<lmk_node::Entry>| entries.iter().map(|e| (e.position, e.payload["n"].as_u64().unwrap())).collect::<Vec<_>>();
    let seen = order(alice.node.entries(&gid.0, 1).unwrap());
    assert_eq!(seen.len(), 2);
    assert_eq!(order(bob.logged(&gid, 2).await), seen[1..]);
    bob.node.follow_log(&gid.0, Some(2)).unwrap();
    assert_eq!(bob.node.entries(&gid.0, 0).unwrap().len(), 1, "entries the kind read past go");

    // Carol joins with no state and reads from the start: the messages the entries name are from before she joined,
    // so she asks a member for the kind's state, and follows from where it leaves off.
    let carol = session(&relay, "Carol").await;
    let link = bob.node.invite(&gid.0, None, None).await.unwrap();
    let joining = tokio::spawn(async move { carol.node.join(&link, None).await.map(|_| carol) });
    bob.snapshot(None).await;
    let mut carol = joining.await.unwrap().unwrap();
    carol.node.follow_log(&gid.0, Some(0)).unwrap();
    tokio::select! {
        _ = alice.snapshot(Some(b"through 3")) => {}
        _ = bob.snapshot(Some(b"through 3")) => {}
    }
    let data = carol.until(|e| match e {
        Event::State { data, .. } => Some(data),
        _ => None,
    }).await;
    assert_eq!(data, b"through 3");
    let (four, _) = carol.node.send(&gid.0, &json!({ "type": "push", "n": 4 }), true).await.unwrap();
    assert!(carol.node.append(&gid.0, &four.0).await.is_err(), "a member behind the log does not append");
    carol.node.follow_log(&gid.0, Some(3)).unwrap();
    assert_eq!(carol.node.append(&gid.0, &four.0).await.unwrap(), 4);
    assert_eq!(alice.logged(&gid, 3).await[0].from.name, "Carol");
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
    let mut alice = session(&relay, "Alice").await;
    let (mut laptop, laptop_devices) = device(&relay, "laptop").await;
    let (mut tablet, tablet_devices) = device(&relay, "tablet").await;
    routed(&mut laptop, laptop_devices.clone());
    routed(&mut tablet, tablet_devices.clone());
    let bob = laptop_devices.create("Bob", membership.clone()).await.unwrap();
    laptop_devices.set_contact(&[9; 32], lmk_core::contacts::Contact { name: "Carol".into(), how: lmk_core::contacts::How::Verified, by: None, at: 1, rest: Default::default() }).await.unwrap();

    // A device link: the tablet gets the identity's state, its key and contacts among it.
    let link = lmk_proto::links::Invite::parse(&laptop_devices.invite(&bob.id.0).await.unwrap()).unwrap();
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
    tablet.node.join_open(&opening, bob.clone()).await.unwrap();
    let link = alice.node.invite(&chat.0, None, None).await.unwrap();
    laptop.node.join(&link, Some(bob.clone())).await.unwrap();
    let seen = alice.checked(&chat, "tablet", true).await;
    assert_eq!((seen.device_name.as_str(), seen.identity.unwrap().added_by_device.as_deref()), ("tablet", Some("laptop")));
    alice.checked(&chat, "laptop", true).await;

    // The tablet stops, and the laptop takes it off Bob: the key log entry that replaces the key names it, so alice
    // removes its session from the chat without its coming back. The laptop's certificate no longer checks out, and
    // alice serves it nothing until it renews it.
    tablet.node.shutdown().await.unwrap();
    laptop_devices.remove(&bob.id.0, &tablet.node.key().0).await.unwrap();
    alice.until(|e| matches!(e, Event::Left { member, .. } if member.name == "tablet").then_some(())).await;
    let keys = laptop.node.read_key_log(&bob).await.unwrap();
    assert_eq!(keys.keys.len(), 2);
    assert_eq!(laptop_devices.keys(), [(bob.id.clone(), Bytes(keys.current().to_vec()))]);
    let laptop_seen = alice.checked(&chat, "laptop", false).await;
    assert_eq!(laptop_seen.identity.unwrap().error.as_deref(), Some("its certificate is not by its identity's current key"));
    let (before, delivery) = alice.node.send(&chat.0, &message("before the laptop renews"), true).await.unwrap();
    assert!(delivery.held.is_empty(), "the laptop's session is not served");
    let certificate = laptop_devices.certify(&bob.id.0, laptop.node.key(), "laptop".into()).await.unwrap();
    laptop.node.set_certificate(certificate).unwrap();
    alice.checked(&chat, "laptop", true).await;
    // Alice asks the laptop to sync anew once she serves it again, so what it missed comes at once, not at the next
    // resync.
    laptop.until(|e| matches!(e, Event::Message(message) if message.id == before).then_some(())).await;
    let (id, delivery) = alice.node.send(&chat.0, &message("after it renews"), true).await.unwrap();
    assert_eq!(delivery.held.iter().map(|m| m.device_name.as_str()).collect::<Vec<_>>(), ["laptop"]);
    let got = laptop.until(|e| match e {
        Event::Message(message) if message.id == id => Some(message.id),
        _ => None,
    }).await;
    assert_eq!(got, id);
}

/// A member holds the certificates of its groups' members across restarts, so it removes the sessions of a device taken
/// off their identity while they are offline; a key replaced for no device removes no one.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_taken_off_its_identity_leaves_while_its_sessions_are_offline() {
    use lmk_core::identity::{DAY, certify, create, public};
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder("revoke");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let alice_db = dir.join("alice.db");
    let start = || async {
        let (node, events) = Node::start(SqliteProvider::open(&alice_db).unwrap(), config(&relay, "Alice", None, &[CHAT])).await.unwrap();
        Session { node, events }
    };
    let alice = start().await;
    let keys: [[u8; 32]; 3] = [lmk_core::random(), lmk_core::random(), lmk_core::random()];
    let (id, first) = create(&keys[0], "Carol", membership.clone());
    let carol = lmk_proto::group::IdentityRef { id: id.into(), membership: membership.clone() };
    alice.node.append_identity(&carol, &first).await.unwrap();
    let chat = alice.node.create(Settings { membership, ..settings(CHAT, &dir) }, None).unwrap();
    for (name, device) in [("phone", 1), ("tablet", 2)] {
        let session = session(&relay, name).await;
        let certified = lmk_proto::identity::Certified {
            identity: carol.id.clone(),
            key: session.node.key(),
            name: name.into(),
            device: name.into(),
            device_key: Some(Bytes(vec![device; 32])),
            added_by: None,
            expires: lmk_node::now() + DAY,
        };
        session.node.set_certificate(certify(&keys[0], &certified)).unwrap();
        let link = alice.node.invite(&chat.0, None, None).await.unwrap();
        session.node.join(&link, Some(carol.clone())).await.unwrap();
        alice.checked(&chat, name, true).await;
        session.node.shutdown().await.unwrap();
    }
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let mut alice = start().await;

    let log = alice.node.read_key_log(&carol).await.unwrap();
    alice.node.append_identity(&carol, &log.rotate(&keys[0], &public(&keys[1]), None)).await.unwrap();
    let log = alice.node.read_key_log(&carol).await.unwrap();
    alice.node.append_identity(&carol, &log.rotate(&keys[1], &public(&keys[2]), Some(Bytes(vec![2; 32])))).await.unwrap();
    alice.until(|e| matches!(e, Event::Left { member, .. } if member.name == "tablet").then_some(())).await;
    let members: Vec<String> = alice.node.members(&chat.0).unwrap().into_iter().map(|m| m.name).collect();
    assert_eq!(members, ["Alice", "phone"]);
    alice.node.shutdown().await.unwrap();
}

/// A session whose leaf names an older revision, as 0.12.1's does, writes its own as it starts.
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
    lmk_membership::folder::FolderClient::new(logs.to_str().unwrap()).append(&gid.0, &commit.commit).await.unwrap();
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

/// A member holding a `leave` whose removal it could not commit as it took it commits it once it starts again, with the
/// leaver offline, or, with `restart_holder` false, once it syncs with the leaver.
async fn held_leave(test: &str, restart_holder: bool) {
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
    let delivery = bob.node.leave(&gid.0).await.unwrap().unwrap();
    assert_eq!(delivery.held.len(), 1, "Alice holds the leave");
    alice.until(|e| matches!(e, Event::Warning { text, .. } if text.contains("removing a member")).then_some(())).await;
    bob.node.shutdown().await.unwrap();
    drop(bob);
    if restart_holder {
        alice.node.shutdown().await.unwrap();
        drop(alice);
        reachable(&log_dir(&logs, &gid), true);
        alice = start("Alice").await;
    } else {
        reachable(&log_dir(&logs, &gid), true);
        start("Bob").await;
    }
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
async fn a_held_leave_is_committed_on_start() {
    held_leave("leave-start", true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_leave_is_committed_after_a_sync() {
    held_leave("leave-sync", false).await;
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
