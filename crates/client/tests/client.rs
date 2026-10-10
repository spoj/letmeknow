//! The client core as every shell runs it: on a node that is its device's too, as a browser's is, with plugins that
//! answer in the call, as in-page plugins do, and requests as JSON, as the page and the command line send them.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::tls::CaTlsConfig;
use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use lmk_client::{Access, Client, ClientEvent, Config, Plugins, Request, Standing};
use lmk_core::device::Device;
use lmk_core::provider::MemoryProvider;
use lmk_node::{Event, Node};
use lmk_node::devices::Devices;
use lmk_proto::group::{CHAT, DEVICES, Service};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc};

const WAIT: Duration = Duration::from_secs(60);
const KIND: &str = "test";
/// "state", in base64url.
const STATE: &str = "c3RhdGU";

/// A plugin of the kind `test` that answers every request at once, but `start` while a gate is set, and keeps what it
/// was sent. Its groups' state is "state".
struct Recorder {
    started: Mutex<Vec<String>>,
    sent: Mutex<Vec<Value>>,
    lines: mpsc::UnboundedSender<(String, Option<Value>)>,
    /// Opened once to let `start` be answered.
    gate: Mutex<Option<Arc<Notify>>>,
}

impl Plugins for Recorder {
    fn kinds(&self) -> Vec<String> {
        vec![KIND.into()]
    }

    fn start(&self, kind: &str) -> anyhow::Result<Value> {
        self.started.lock().unwrap().push(kind.into());
        Ok(json!({}))
    }

    fn running(&self) -> Vec<String> {
        self.started.lock().unwrap().clone()
    }

    fn send(&self, kind: &str, message: &Value) -> anyhow::Result<()> {
        self.sent.lock().unwrap().push(message.clone());
        if let Some(id) = message.get("id") {
            let answer = match message["type"].as_str() {
                Some("snapshot") => json!({ "data": STATE }),
                told => json!({ "told": told }),
            };
            let (lines, line) = (self.lines.clone(), (kind.to_owned(), Some(json!({ "type": "answer", "id": id, "answer": answer }))));
            let gate = self.gate.lock().unwrap().clone().filter(|_| message["type"] == "start");
            tokio::spawn(async move {
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                lines.send(line).unwrap();
            });
        }
        Ok(())
    }

    fn stopped(&self, _: &str) -> bool {
        false
    }
}

struct Member {
    client: Client<MemoryProvider>,
    told: mpsc::UnboundedReceiver<ClientEvent>,
    plugin: Arc<Recorder>,
    /// Told whenever the client took a state handed to it.
    stated: Arc<Notify>,
}

impl Member {
    async fn start(relay: &(Server, CertificateDer<'static>), logs: &std::path::Path, name: &str) -> Member {
        let device = Device::new(name);
        let config = lmk_node::Config {
            name: name.into(),
            device: Some(device.clone()),
            relay: format!("https://localhost:{}", relay.0.https_addr().unwrap().port()).parse().unwrap(),
            ca: CaTlsConfig::custom_roots([relay.1.clone()]),
            home: None,
            files: None,
            disk: None,
            file_limit: 100 << 20,
            durable: None,
            observe: None,
            kinds: vec![CHAT.into(), DEVICES.into(), KIND.into()],
        };
        let (node, mut events) = Node::start(MemoryProvider::default(), config).await.unwrap();
        let devices = Devices::new(node.clone(), device.clone(), Arc::new(|_: &Device| Ok(())));
        let (lines, written) = mpsc::unbounded_channel();
        let plugin = Arc::new(Recorder { started: Mutex::default(), sent: Mutex::default(), lines, gate: Mutex::default() });
        let membership = Service::Folder(logs.to_str().unwrap().into());
        let config = Config { name: name.into(), device, membership };
        let (client, told) = Client::new(node, config, Access::Here(devices), plugin.clone(), written);
        let (taking, pumping, stated) = (client.clone(), client.clone(), Arc::new(Notify::new()));
        let state = stated.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let handed = matches!(event, Event::State { .. });
                taking.event(event).await;
                if handed {
                    state.notify_one();
                }
            }
        });
        tokio::spawn(async move {
            loop {
                let (kind, line) = pumping.next_line().await;
                pumping.plugin_line(kind, line).await;
            }
        });
        Member { client, told, plugin, stated }
    }

    async fn request(&self, request: Value) -> Value {
        let request: Request = serde_json::from_value(request).unwrap();
        self.client.request(request).await.unwrap()
    }

    async fn until(&mut self, mut wanted: impl FnMut(&ClientEvent) -> bool) -> ClientEvent {
        tokio::time::timeout(WAIT, async {
            loop {
                let event = self.told.recv().await.unwrap();
                if wanted(&event) {
                    return event;
                }
            }
        })
        .await
        .expect("the event came")
    }
}

async fn relay() -> (Server, CertificateDer<'static>) {
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
    (Server::spawn(config).await.unwrap(), cert)
}

/// A test's folder, deleted when the test ends.
struct Folder(std::path::PathBuf);

impl std::ops::Deref for Folder {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn logs(test: &str) -> Folder {
    let dir = std::env::temp_dir().join(format!("lmk-client-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Folder(dir)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invite_made_for_someone_makes_its_joiner_that_contact_and_describes_them_so() {
    let (relay, logs) = (relay().await, logs("invite"));
    let mut alice = Member::start(&relay, &logs, "Alice's laptop").await;
    let mut bob = Member::start(&relay, &logs, "Bob's laptop").await;
    alice.request(json!({ "cmd": "identity", "op": { "create": { "name": "Alice" } } })).await;
    bob.request(json!({ "cmd": "identity", "op": { "create": { "name": "Robert" } } })).await;
    let invite = alice.request(json!({ "cmd": "invite", "for": "Bob (Acme)" })).await;
    assert_eq!((invite["kind"].as_str(), invite["for"].as_str()), (Some(CHAT), Some("Bob (Acme)")));
    bob.request(json!({ "cmd": "join", "target": invite["link"] })).await;
    let ClientEvent::Joined { member, .. } = alice.until(|e| matches!(e, ClientEvent::Joined { .. })).await else { unreachable!() };
    let known = member.identity.unwrap();
    assert_eq!((known.name.as_str(), known.how), ("Bob (Acme)", Standing::Verified), "whom the invite was for, at once");
    // Whom the invite was for becomes a contact, and the group is told who they are. Every leaf names revision 1, so
    // the introduce is held, by its sender and by those it reaches.
    let holds_introduce = |m: &Member| {
        let node = m.client.node();
        node.groups().iter().any(|g| node.messages(&g.0).unwrap().iter().any(|message| message.payload["type"] == "introduce"))
    };
    // A shutdown lets the work the join caused end.
    alice.client.shutdown().await;
    assert!(holds_introduce(&alice));
    tokio::time::timeout(WAIT, async {
        while !holds_introduce(&bob) {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("the introduce is held");
    // Bob is not told who he is himself.
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(event) = bob.told.try_recv() {
        assert!(!matches!(event, ClientEvent::Introduced { .. }), "{event:?}");
    }
    let me = alice.client.me().unwrap()["fp"].as_str().unwrap().to_owned();
    let introduced = alice.client.request(serde_json::from_value(json!({ "cmd": "introduce", "group": invite["group"], "member": me, "to": "Bob" })).unwrap()).await;
    assert_eq!(introduced.unwrap_err().to_string(), "you can introduce only your contacts");
    // The contact is the identity's once its devices group's log takes it.
    let mut contacts = alice.request(json!({ "cmd": "contacts" })).await;
    for _ in 0..200 {
        if contacts["contacts"][0].is_object() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        contacts = alice.request(json!({ "cmd": "contacts" })).await;
    }
    assert_eq!((contacts["contacts"][0]["name"].as_str(), contacts["contacts"][0]["how"].as_str()), (Some("Bob (Acme)"), Some("verified")));
    let gid = invite["group"].as_str().unwrap();
    let members = alice.request(json!({ "cmd": "members", "group": gid })).await;
    let seen: Vec<lmk_client::Described> = serde_json::from_value(members["members"].clone()).unwrap();
    let robert = seen.iter().find(|m| !m.you).unwrap().identity.clone().unwrap();
    assert_eq!((robert.name.as_str(), robert.how), ("Bob (Acme)", Standing::Verified));
    let me = seen.iter().find(|m| m.you).unwrap().identity.clone().unwrap();
    assert_eq!((me.name.as_str(), me.how), ("Alice", Standing::Own));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kinds_plugin_hears_of_its_groups_and_lets_go_of_one_left() {
    let (relay, logs) = (relay().await, logs("kind"));
    let mut alice = Member::start(&relay, &logs, "Alice").await;
    let invite = alice.request(json!({ "cmd": "invite", "kind": KIND, "name": "Plan", "args": ["plan.md"], "cwd": "/tmp" })).await;
    assert_eq!(invite["told"], "group", "the plugin's answer to the group it was told of joins the answer");
    let sent = alice.plugin.sent.lock().unwrap().clone();
    assert_eq!(sent[0]["type"], "start");
    let group = &sent[1];
    assert_eq!((group["type"].as_str(), group["command"].as_str(), group["args"][0].as_str()), (Some("group"), Some("invite"), Some("plan.md")));
    assert_eq!((group["me"]["name"].as_str(), group["me"]["you"].as_bool()), (Some("Alice"), Some(true)));
    let left = alice.request(json!({ "cmd": "leave", "group": invite["group"] })).await;
    assert_eq!(left["left"], true);
    assert_eq!(alice.plugin.sent.lock().unwrap().last().unwrap()["type"], "gone");
    alice.until(|e| matches!(e, ClientEvent::Gone { .. })).await;
}

/// A link to a new group of the kind `test`, which the second member is joining, its plugin starting until the gate opens.
async fn joining(alice: &Member, bob: &Member) -> (Value, Arc<Notify>, tokio::task::JoinHandle<anyhow::Result<Value>>) {
    let invite = alice.request(json!({ "cmd": "invite", "kind": KIND })).await;
    let gate = Arc::new(Notify::new());
    *bob.plugin.gate.lock().unwrap() = Some(gate.clone());
    let (client, join) = (bob.client.clone(), serde_json::from_value(json!({ "cmd": "join", "target": invite["link"] })).unwrap());
    (invite, gate, tokio::spawn(async move { client.request(join).await }))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_keeps_the_state_handed_before_its_kind_opened_and_joins_once() {
    let (relay, logs) = (relay().await, logs("state"));
    let alice = Member::start(&relay, &logs, "Alice").await;
    let bob = Member::start(&relay, &logs, "Bob").await;
    let (invite, gate, joined) = joining(&alice, &bob).await;
    tokio::time::timeout(WAIT, bob.stated.notified()).await.expect("the state came with the Welcome");
    let again = invite["link"].as_str().unwrap().replace("https://letmeknow.dev/i", "https://example.com/x");
    let refused = bob.client.request(serde_json::from_value(json!({ "cmd": "join", "target": again })).unwrap()).await;
    assert_eq!(refused.unwrap_err().to_string(), "this session is joining that already: wait for that join to end");
    gate.notify_one();
    joined.await.unwrap().unwrap();
    let sent = bob.plugin.sent.lock().unwrap().clone();
    let told = sent.iter().position(|m| m["type"] == "group").unwrap();
    let state = sent.iter().position(|m| m["type"] == "state").expect("the plugin is handed the state");
    assert!(told < state, "after the group");
    assert_eq!((sent[state]["group"].clone(), sent[state]["data"].as_str()), (invite["group"].clone(), Some(STATE)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_group_left_while_its_kind_starts_is_never_told_of() {
    let (relay, logs) = (relay().await, logs("gone"));
    let alice = Member::start(&relay, &logs, "Alice").await;
    let mut bob = Member::start(&relay, &logs, "Bob").await;
    let (invite, gate, joined) = joining(&alice, &bob).await;
    tokio::time::timeout(WAIT, bob.stated.notified()).await.expect("bob is in the group");
    bob.request(json!({ "cmd": "leave", "group": invite["group"] })).await;
    bob.until(|e| matches!(e, ClientEvent::Gone { .. })).await;
    gate.notify_one();
    let error = joined.await.unwrap().unwrap_err().to_string();
    assert_eq!(error, format!("{} is gone", invite["group"].as_str().unwrap()));
    let sent = bob.plugin.sent.lock().unwrap().clone();
    assert!(sent.iter().all(|m| m["type"] == "start"), "{sent:?}");
    assert!(bob.client.node().groups().is_empty());
}

/// Asks a member again until its answer is as wanted.
async fn polled(member: &Member, request: Value, wanted: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(WAIT, async {
        loop {
            let answer = member.request(request.clone()).await;
            if wanted(&answer) {
                return answer;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("the answer came")
}

/// A device link from the first member's identity, `Bob`, which the second joins.
async fn devices_of_bob(laptop: &Member, tablet: &Member) {
    laptop.request(json!({ "cmd": "identity", "op": { "create": { "name": "Bob" } } })).await;
    let link = laptop.request(json!({ "cmd": "invite", "identity": "Bob" })).await;
    tablet.request(json!({ "cmd": "join", "target": link["link"] })).await;
    polled(tablet, json!({ "cmd": "identity", "op": "list" }), |listed| listed["identities"][0]["name"] == "Bob").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_renamed_device_shows_its_new_name_to_its_other_devices_and_its_groups() {
    let (relay, logs) = (relay().await, logs("rename"));
    let alice = Member::start(&relay, &logs, "Alice").await;
    let laptop = Member::start(&relay, &logs, "laptop").await;
    let tablet = Member::start(&relay, &logs, "tablet").await;
    devices_of_bob(&laptop, &tablet).await;
    let chat = alice.request(json!({ "cmd": "invite" })).await;
    laptop.request(json!({ "cmd": "join", "target": chat["link"] })).await;
    let device = |m: &Value| m["members"].as_array().unwrap().iter().any(|m| m["device"] == "desk");
    let renamed = laptop.request(json!({ "cmd": "identity", "op": { "rename": { "name": "desk" } } })).await;
    assert_eq!(renamed["device"]["name"], "desk");
    assert_eq!(laptop.client.me().unwrap()["device"]["name"], "desk");
    let names = |listed: &Value| -> Vec<String> {
        listed["identities"][0]["devices"].as_array().unwrap().iter().map(|d| d["name"].as_str().unwrap().to_owned()).collect()
    };
    let listed = polled(&tablet, json!({ "cmd": "identity", "op": "list" }), |listed| names(listed).contains(&"desk".to_owned())).await;
    assert_eq!(names(&listed).len(), 2, "the tablet lists the laptop by its new name");
    polled(&alice, json!({ "cmd": "members", "group": chat["group"] }), device).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_leaves_its_identity_with_other_devices_left_and_as_its_only_device() {
    let (relay, logs) = (relay().await, logs("leave"));
    let alice = Member::start(&relay, &logs, "Alice").await;
    let laptop = Member::start(&relay, &logs, "laptop").await;
    let tablet = Member::start(&relay, &logs, "tablet").await;
    devices_of_bob(&laptop, &tablet).await;
    let chat = alice.request(json!({ "cmd": "invite" })).await;
    tablet.request(json!({ "cmd": "join", "target": chat["link"] })).await;
    let bob = laptop.client.device_state().unwrap().identities[0].0.clone();
    let before = *laptop.client.node().read_key_log(&bob).await.unwrap().current();

    // The tablet leaves Bob: its session leaves the chat first, and the laptop, which removes it, replaces Bob's key.
    let left = tablet.request(json!({ "cmd": "identity", "op": { "leave": { "identity": "Bob" } } })).await;
    assert_eq!((left["left"][0].clone(), left["ended"].clone()), (chat["group"].clone(), json!(false)));
    assert_eq!(tablet.client.me().unwrap()["identities"], json!([]));
    polled(&alice, json!({ "cmd": "members", "group": chat["group"] }), |m| m["members"].as_array().unwrap().len() == 1).await;
    polled(&laptop, json!({ "cmd": "identity", "op": "list" }), |listed| listed["identities"][0]["devices"].as_array().unwrap().len() == 1).await;
    tokio::time::timeout(WAIT, async {
        while *laptop.client.node().read_key_log(&bob).await.unwrap().current() == before {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("the laptop replaces Bob's key");

    // Bob's only device leaves him, and he ends.
    let left = laptop.request(json!({ "cmd": "identity", "op": { "leave": { "identity": "Bob" } } })).await;
    assert_eq!((left["left"].clone(), left["ended"].clone()), (json!([]), json!(true)));
    assert_eq!(laptop.client.me().unwrap()["identities"], json!([]));
    assert!(laptop.client.node().groups().is_empty(), "its devices group is gone");
}
