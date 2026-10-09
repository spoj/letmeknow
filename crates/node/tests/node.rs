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
use lmk_node::{Config, Event, Node};
use lmk_proto::group::{Kind, PROTOCOL, Payload, Service, Settings};
use lmk_proto::links::Invite;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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

async fn session(relay: &Relay, name: &str) -> Session {
    node(relay, name, false).await
}

/// A device's own node: its key is the device key.
async fn device(relay: &Relay, name: &str) -> Session {
    node(relay, name, true).await
}

async fn node(relay: &Relay, name: &str, device_key: bool) -> Session {
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

fn settings(kind: Kind, folder: &Path) -> Settings {
    Settings {
        protocol: PROTOCOL,
        kind,
        name: "Plan".into(),
        open: vec![],
        keep: 90,
        membership: Service::Folder(folder.to_str().unwrap().into()),
        devices_of: None,
        openings: vec![],
    }
}

fn message(text: &str) -> Payload {
    Payload::Message { content: text.into(), after: vec![], to: vec![], reply_to: None, urgent: false, attachment: None }
}

#[tokio::test(flavor = "multi_thread")]
async fn chat_doc_and_removal() {
    let relay = relay().await;
    let dir = folder("chat");
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(Kind::Chat, &dir), None).unwrap();
    let link = alice.node.invite(Target::Group(gid.0.clone()), Some("Bob (Acme)".into()), None).unwrap();
    let joined = bob.node.join(&Invite::parse(&link).unwrap(), None).await.unwrap();
    assert_eq!(joined, gid);
    let (member, label) = alice.until(|e| match e {
        Event::Joined { member, label, .. } => Some((member, label)),
        _ => None,
    }).await;
    assert_eq!((member.name.as_str(), label.as_deref()), ("Bob", Some("Bob (Acme)")));
    assert_eq!(bob.node.members(&gid.0).unwrap().len(), 2);

    let (id, delivery) = bob.node.send(&gid.0, &message("hello")).await.unwrap();
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
async fn a_doc_reaches_a_joiner_and_edits_go_live() {
    let relay = relay().await;
    let dir = folder("doc");
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(Kind::Doc, &dir), None).unwrap();
    let update = lmk_node::doc::edit(&alice.node.doc(&gid.0).unwrap(), "first line\n").unwrap();
    alice.node.edit(&gid.0, update).await.unwrap();
    let link = alice.node.invite(Target::Group(gid.0.clone()), None, None).unwrap();
    bob.node.join(&Invite::parse(&link).unwrap(), None).await.unwrap();
    bob.until(|e| matches!(e, Event::Edited { .. }).then_some(())).await;
    assert_eq!(lmk_node::doc::text(&bob.node.doc(&gid.0).unwrap()).unwrap(), "first line\n");
    let update = lmk_node::doc::edit(&bob.node.doc(&gid.0).unwrap(), "first line\nsecond\n").unwrap();
    alice.node.doc_edits(&gid.0).unwrap();
    bob.node.edit(&gid.0, update).await.unwrap();
    // Whoever reads the doc before the event is handled still learns who changed it.
    let editors = tokio::time::timeout(WAIT, async {
        loop {
            let (state, editors) = alice.node.doc_edits(&gid.0).unwrap();
            if lmk_node::doc::text(&state).unwrap() == "first line\nsecond\n" {
                return editors;
            }
            assert!(editors.is_empty());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(editors.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["Bob"]);
    let by = alice.until(|e| match e {
        Event::Edited { by, .. } => Some(by),
        _ => None,
    }).await;
    assert_eq!(by.name, "Bob");
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
    let chat = alice.node.create(settings(Kind::Chat, &dir), None).unwrap();
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
