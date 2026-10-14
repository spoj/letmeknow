//! The client core as every shell runs it: on a node that is its device's too, as a browser's is, with plugins that
//! answer in the call, as in-page plugins do, and requests as JSON, as the page and the command line send them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lmk_client::{Access, Chat, Client, ClientEvent, Config, Plugins, Receipt, Request, Standing};
use lmk_core::device::Device;
use lmk_core::provider::MemoryProvider;
use lmk_node::{Event, Message, Node};
use lmk_node::identity::Identity;
use lmk_proto::group::{CHAT, IDENTITY};
use lmk_testing::{Relay, relay};
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
    async fn start(relay: &Relay, name: &str) -> Member {
        let device = Device::new(name);
        let config = lmk_node::Config {
            handle: String::new(),
            device: Some(device.clone()),
            relays: vec![relay.url.clone()],
            chosen: vec![],
            resolve: lmk_testing::resolve(),
            ca: relay.ca(),
            home: None,
            files: None,
            disk: None,
            file_limit: 100 << 20,
            durable: None,
            kinds: vec![CHAT.into(), IDENTITY.into(), KIND.into()],
        };
        let (node, mut events) = Node::start(MemoryProvider::default(), config).await.unwrap();
        let devices = Identity::new(node.clone(), device.clone(), Arc::new(|_: &Device| Ok(())));
        let (lines, written) = mpsc::unbounded_channel();
        let plugin = Arc::new(Recorder { started: Mutex::default(), sent: Mutex::default(), lines, gate: Mutex::default() });
        let config = Config { device, membership: relay.service.clone() };
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

/// Another identity's members show its own claim; this device's own identity is `self`. A link `--to` an identity
/// admits only that one.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_shows_its_identitys_claim_and_a_link_to_an_identity_admits_only_it() {
    let relay = relay().await;
    let mut alice = Member::start(&relay, "Alice's laptop").await;
    let bob = Member::start(&relay, "Bob's laptop").await;
    let carol = Member::start(&relay, "Carol's laptop").await;
    for (member, name) in [(&alice, "Alice"), (&bob, "Robert"), (&carol, "Carol")] {
        member.request(json!({ "cmd": "identity", "op": { "create": { "name": name } } })).await;
    }
    let robert = bob.client.me().unwrap()["identity"]["id"].clone();
    let refused = alice.client.request(serde_json::from_value(json!({ "cmd": "invite", "to": "Robert" })).unwrap()).await;
    assert_eq!(refused.unwrap_err().to_string(), "--to takes an identity's id, as `members` shows it");
    let invite = alice.request(json!({ "cmd": "invite", "to": robert })).await;
    assert_eq!((invite["kind"].as_str(), &invite["to"]), (Some(CHAT), &robert));
    let other = carol.client.request(serde_json::from_value(json!({ "cmd": "join", "target": invite["link"] })).unwrap()).await;
    assert!(other.unwrap_err().to_string().contains("another identity"));
    bob.request(json!({ "cmd": "join", "target": invite["link"] })).await;
    let ClientEvent::Joined { member, .. } = alice.until(|e| matches!(e, ClientEvent::Joined { .. })).await else { unreachable!() };
    let known = member.identity.unwrap();
    assert_eq!((known.id, known.name.as_str(), known.how), (serde_json::from_value(robert).unwrap(), "Robert", Standing::Observed));
    let members = alice.request(json!({ "cmd": "members", "group": invite["group"] })).await;
    let seen: Vec<lmk_client::Described> = serde_json::from_value(members["members"].clone()).unwrap();
    let me = seen.iter().find(|m| m.you).unwrap().identity.clone().unwrap();
    assert_eq!((me.name.as_str(), me.how), ("Alice", Standing::Own));
}

#[tokio::test(flavor = "multi_thread")]
async fn late_identity_creation_keeps_anonymous_leaves_and_certifies_future_memberships() {
    let relay = relay().await;
    let alice = Member::start(&relay, "Alice").await;
    let old = alice.request(json!({ "cmd": "invite", "name": "anonymous" })).await;
    let gid: lmk_proto::Bytes = serde_json::from_value(old["group"].clone()).unwrap();
    let before = alice.client.node().members(&gid.0).unwrap();
    assert!(before[0].identity.is_none());
    let epoch = alice.client.node().epoch(&gid.0).unwrap();
    alice.request(json!({ "cmd": "identity", "op": { "create": { "name": "Ann" } } })).await;
    for _ in 0..3 {
        assert!(alice.client.refresh_identity().await.is_empty(), "anonymous memberships must not cause a refresh error loop");
    }
    let after = alice.client.node().members(&gid.0).unwrap();
    assert!(after[0].identity.is_none());
    assert_eq!(after[0].key, before[0].key);
    assert_eq!(alice.client.node().epoch(&gid.0).unwrap(), epoch);
    let new = alice.request(json!({ "cmd": "invite", "name": "certified" })).await;
    let spoken = alice.client.node().spoken();
    assert_eq!(spoken.len(), 1, "the new installed leaf carries the identity certificate");
    alice.client.node().read_public(&spoken[0]).await.unwrap();
    let members = alice.request(json!({ "cmd": "members", "group": new["group"] })).await;
    let claim = &members["members"][0]["identity"];
    assert_eq!(claim["name"], "Ann");
    assert!(claim["error"].is_null());
    assert_eq!(claim["how"], "self");
    let old_members = alice.request(json!({ "cmd": "members", "group": old["group"] })).await;
    assert!(old_members["members"][0]["identity"].is_null());
    alice.client.node().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kinds_plugin_hears_of_its_groups_and_lets_go_of_one_left() {
    let relay = relay().await;
    let mut alice = Member::start(&relay, "Alice").await;
    let invite = alice.request(json!({ "cmd": "invite", "kind": KIND, "name": "Plan", "args": ["plan.md"], "cwd": "/tmp" })).await;
    assert_eq!(invite["told"], "group", "the plugin's answer to the group it was told of joins the answer");
    let sent = alice.plugin.sent.lock().unwrap().clone();
    assert_eq!(sent[0]["type"], "start");
    let group = &sent[1];
    assert_eq!((group["type"].as_str(), group["command"].as_str(), group["args"][0].as_str()), (Some("group"), Some("invite"), Some("plan.md")));
    assert_eq!((&group["me"]["fp"], group["me"]["you"].as_bool()), (&alice.client.me().unwrap()["fp"], Some(true)));
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
    let relay = relay().await;
    let alice = Member::start(&relay, "Alice").await;
    let bob = Member::start(&relay, "Bob").await;
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
    let relay = relay().await;
    let alice = Member::start(&relay, "Alice").await;
    let mut bob = Member::start(&relay, "Bob").await;
    let (invite, gate, joined) = joining(&alice, &bob).await;
    tokio::time::timeout(WAIT, bob.stated.notified()).await.expect("bob is in the group");
    bob.request(json!({ "cmd": "leave", "group": invite["group"], "end": true })).await;
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
    let link = laptop.request(json!({ "cmd": "identity", "op": { "invite": {} } })).await;
    tablet.request(json!({ "cmd": "join", "target": link["link"] })).await;
    polled(tablet, json!({ "cmd": "identity", "op": "list" }), |listed| listed["name"] == "Bob").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_renamed_device_shows_its_new_name_to_its_other_devices_and_its_groups() {
    let relay = relay().await;
    let alice = Member::start(&relay, "Alice").await;
    let laptop = Member::start(&relay, "laptop").await;
    let tablet = Member::start(&relay, "tablet").await;
    devices_of_bob(&laptop, &tablet).await;
    let chat = alice.request(json!({ "cmd": "invite" })).await;
    laptop.request(json!({ "cmd": "join", "target": chat["link"] })).await;
    let device = |m: &Value| m["members"].as_array().unwrap().iter().any(|m| m["device"] == "desk");
    let renamed = laptop.request(json!({ "cmd": "identity", "op": { "rename": { "name": "desk", "device": true } } })).await;
    assert_eq!(renamed["device"]["name"], "desk");
    assert_eq!(laptop.client.me().unwrap()["device"]["name"], "desk");
    let names = |listed: &Value| -> Vec<String> {
        listed["devices"].as_array().unwrap().iter().map(|d| d["name"].as_str().unwrap().to_owned()).collect()
    };
    let listed = polled(&tablet, json!({ "cmd": "identity", "op": "list" }), |listed| names(listed).contains(&"desk".to_owned())).await;
    assert_eq!(names(&listed).len(), 2, "the tablet lists the laptop by its new name");
    polled(&alice, json!({ "cmd": "members", "group": chat["group"] }), device).await;
    // Renamed, the identity shows so to its devices and to the members of its sessions' groups.
    assert_eq!(laptop.request(json!({ "cmd": "identity", "op": { "rename": { "name": "Robert" } } })).await["name"], "Robert");
    polled(&tablet, json!({ "cmd": "identity", "op": "list" }), |listed| listed["name"] == "Robert").await;
    polled(&alice, json!({ "cmd": "members", "group": chat["group"] }), |m| m["members"].as_array().unwrap().iter().any(|m| m["identity"]["name"] == "Robert")).await;
}

/// A browser joins at once a group that another of its identity's devices adds it to.
#[tokio::test(flavor = "multi_thread")]
async fn a_browser_joins_a_group_another_of_its_devices_adds_it_to() {
    let relay = relay().await;
    let laptop = Member::start(&relay, "laptop").await;
    let tablet = Member::start(&relay, "tablet").await;
    devices_of_bob(&laptop, &tablet).await;
    let chat = laptop.request(json!({ "cmd": "invite" })).await;
    let added = laptop.request(json!({ "cmd": "add", "target": "tablet", "group": chat["group"] })).await;
    assert_eq!((added["device"].as_str(), added["session"].as_str()), (Some("tablet"), Some("")));
    let group = chat["group"].as_str().unwrap();
    polled(&tablet, json!({ "cmd": "groups" }), |groups| groups.to_string().contains(group)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_welcome_observes_two_colliding_identities_without_merging_their_names() {
    let relay = relay().await;
    let host = Member::start(&relay, "host").await;
    let ann = Member::start(&relay, "phone").await;
    let other = Member::start(&relay, "desk").await;
    let reader = Member::start(&relay, "reader").await;
    for (member, name) in [(&ann, "Ann"), (&other, "ann")] {
        member.request(json!({ "cmd": "identity", "op": { "create": { "name": name } } })).await;
    }
    let invite = host.request(json!({ "cmd": "invite" })).await;
    ann.request(json!({ "cmd": "join", "target": invite["link"] })).await;
    let link = host.request(json!({ "cmd": "invite", "group": invite["group"] })).await;
    other.request(json!({ "cmd": "join", "target": link["link"] })).await;
    for peer in [&ann, &other] {
        reader.client.node().read_public(&peer.client.device_state().unwrap().identity.unwrap().0).await.unwrap();
    }
    let link = host.request(json!({ "cmd": "invite", "group": invite["group"] })).await;
    reader.request(json!({ "cmd": "join", "target": link["link"] })).await;
    let members = reader.request(json!({ "cmd": "members", "group": invite["group"] })).await;
    let claims: Vec<_> = members["members"].as_array().unwrap().iter().filter(|m| m["identity"].is_object()).collect();
    assert_eq!(claims.len(), 2);
    for claim in &claims {
        assert_eq!(claim["identity"]["how"], "observed");
        assert_eq!(claim["identity"]["observed"]["names"], json!([claim["identity"]["name"]]));
        let other = claims.iter().find(|other| other["identity"]["id"] != claim["identity"]["id"]).unwrap();
        assert_eq!(claim["identity"]["observed"]["other_ids"], json!([other["identity"]["id"]]));
        assert!(claim["name"].as_str().unwrap().contains('['));
    }
    let gid = serde_json::from_value(invite["group"].clone()).unwrap();
    assert!(reader.client.addressed(&gid, "Ann").unwrap_err().to_string().contains("could be any"));
    let status = reader.request(json!({ "cmd": "status" })).await.to_string();
    for claim in claims {
        assert!(status.contains(claim["identity"]["id"].as_str().unwrap()));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unavailable_group_does_not_starve_other_private_claim_refreshes() {
    let relay = relay().await;
    let observer = Member::start(&relay, "observer").await;
    let mut member = Member::start(&relay, "phone").await;
    member.request(json!({ "cmd": "identity", "op": { "create": { "name": "Ann" } } })).await;
    let invite = observer.request(json!({ "cmd": "invite" })).await;
    member.request(json!({ "cmd": "join", "target": invite["link"] })).await;
    let gid: lmk_proto::Bytes = serde_json::from_value(invite["group"].clone()).unwrap();
    let mut settings = member.client.node().settings(&gid.0).unwrap();
    let lmk_proto::group::Service::Serve { key, .. } = &mut settings.membership else { unreachable!() };
    *key = lmk_core::device::public(&lmk_core::random()).into();
    let Access::Here(devices) = member.client.access() else { unreachable!() };
    let certificate = devices.certify(&member.client.node().key().0).unwrap();
    member.client.node().create(settings, Some(certificate)).unwrap();
    member.request(json!({ "cmd": "identity", "op": { "rename": { "name": "Ann Lee" } } })).await;
    polled(&observer, json!({ "cmd": "members", "group": invite["group"] }), |m| m["members"].as_array().unwrap().iter().any(|m| m["identity"]["name"] == "Ann Lee")).await;
    member.until(|e| matches!(e, ClientEvent::Warning { text, .. } if text.contains("refreshing identity claims") && text.contains("group"))).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_leaves_its_identity_with_other_devices_left_and_as_its_only_device() {
    let relay = relay().await;
    let alice = Member::start(&relay, "Alice").await;
    let laptop = Member::start(&relay, "laptop").await;
    let tablet = Member::start(&relay, "tablet").await;
    devices_of_bob(&laptop, &tablet).await;
    let chat = alice.request(json!({ "cmd": "invite" })).await;
    tablet.request(json!({ "cmd": "join", "target": chat["link"] })).await;
    let bob = laptop.client.device_state().unwrap().identity.unwrap().0;

    // The tablet leaves Bob: its session leaves the chat first, and Bob's public log lists the laptop alone.
    let left = tablet.request(json!({ "cmd": "identity", "op": "leave" })).await;
    assert_eq!((left["left"][0].clone(), left["ended"].clone()), (chat["group"].clone(), json!(false)));
    assert_eq!(tablet.client.me().unwrap()["identity"], json!(null));
    polled(&alice, json!({ "cmd": "members", "group": chat["group"] }), |m| m["members"].as_array().unwrap().len() == 1).await;
    polled(&laptop, json!({ "cmd": "identity", "op": "list" }), |listed| listed["devices"].as_array().unwrap().len() == 1).await;
    // Listed when it left, the tablet lists the laptop alone; not yet listed, it leaves that to the laptop's duties.
    let alone = async {
        while alice.client.node().read_public(&bob).await.unwrap().writers != [laptop.client.device_state().unwrap().key.unwrap()] {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    tokio::time::timeout(WAIT, alone).await.expect("Bob's public log lists the laptop alone");

    // Bob's only device leaves him: it closes his public log, and he ends.
    let left = laptop.request(json!({ "cmd": "identity", "op": "leave" })).await;
    assert_eq!((left["left"].clone(), left["ended"].clone()), (json!([]), json!(true)));
    assert_eq!(laptop.client.me().unwrap()["identity"], json!(null));
    assert!(laptop.client.node().groups().is_empty(), "its identity group is gone");
    assert!(alice.client.node().read_public(&bob).await.unwrap().closed(), "no session speaks for Bob any more");
}

fn is_message(event: &ClientEvent) -> bool {
    matches!(event, ClientEvent::Message { .. })
}

/// Sends `text` in a chat, a reply to `reply_to` if given; returns the message as its sender holds it.
async fn say(member: &Member, gid: &lmk_proto::Bytes, text: &str, reply_to: Option<&lmk_proto::Bytes>) -> Message {
    let reply_to: Option<[u8; 32]> = reply_to.map(|id| id.0.clone().try_into().unwrap());
    let chat = Chat { text: text.into(), to: Vec::new(), reply_to, urgent: false, attachment: None };
    let (id, _) = member.client.send(gid, chat).await.unwrap();
    member.client.node().message(&gid.0, &id.0).unwrap().unwrap()
}

/// Waits until a member's receipts of the group say what `wanted` asks, as its summaries come.
async fn receipts_say(member: &mut Member, gid: &lmk_proto::Bytes, wanted: impl Fn(&Receipt) -> bool) {
    tokio::time::timeout(WAIT, async {
        loop {
            member.until(|e| matches!(e, ClientEvent::Heard { .. })).await;
            if member.client.receipts(gid).unwrap().iter().any(&wanted) {
                return;
            }
        }
    })
    .await
    .expect("the receipts said so")
}

/// Alice's chat, which Bob joins once Alice has seen him join.
async fn chat_with_bob(alice: &mut Member, bob: &Member) -> lmk_proto::Bytes {
    let invite = alice.request(json!({ "cmd": "invite" })).await;
    bob.request(json!({ "cmd": "join", "target": invite["link"] })).await;
    alice.until(|e| matches!(e, ClientEvent::Joined { .. })).await;
    serde_json::from_value(invite["group"].clone()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chat_message_comes_with_its_seq_and_a_reply_names_the_message_it_answers() {
    let relay = relay().await;
    let mut alice = Member::start(&relay, "Alice").await;
    let mut bob = Member::start(&relay, "Bob").await;
    let gid = chat_with_bob(&mut alice, &bob).await;
    // Bob's seqs count from his membership, so his first two messages are 1 and 2; Alice's invite is her seq 1.
    let first = say(&bob, &gid, "one", None).await;
    let second = say(&bob, &gid, "two", None).await;
    let ClientEvent::Message { id, seq: 1, .. } = alice.until(is_message).await else { panic!("the first message is seq 1") };
    assert_eq!(id, hex::encode(&first.id.0));
    let ClientEvent::Message { id, seq: 2, .. } = alice.until(is_message).await else { panic!("the second message is seq 2") };
    assert_eq!(id, hex::encode(&second.id.0));
    // A reply's causal past holds the message it answers once Alice showed it, so it is not outside.
    alice.client.mark_shown(&gid, &[first.id.clone(), second.id.clone()]).unwrap();
    let reply = say(&alice, &gid, "three", Some(&second.id)).await;
    let ClientEvent::Message { id, reply_to, reply_outside, .. } = bob.until(is_message).await else { panic!("the reply came") };
    assert_eq!((id, reply_to, reply_outside), (hex::encode(&reply.id.0), Some(hex::encode(&second.id.0)), false));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_members_receipts_show_a_message_held_and_then_shown_as_its_summaries_say() {
    let relay = relay().await;
    let mut alice = Member::start(&relay, "Alice").await;
    let mut bob = Member::start(&relay, "Bob").await;
    let gid = chat_with_bob(&mut alice, &bob).await;
    let message = say(&alice, &gid, "hello", None).await;
    bob.until(is_message).await;
    receipts_say(&mut alice, &gid, |receipt| receipt.holds(&message) && !receipt.showed(&message)).await;
    bob.client.node().mark_shown(&gid.0, std::slice::from_ref(&message.id)).unwrap();
    receipts_say(&mut alice, &gid, |receipt| receipt.showed(&message)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sent_message_is_only_here_until_a_commit_keeps_it() {
    let relay = relay().await;
    let mut alice = Member::start(&relay, "Alice").await;
    let mut bob = Member::start(&relay, "Bob").await;
    let gid = chat_with_bob(&mut alice, &bob).await;
    let message = say(&alice, &gid, "hello", None).await;
    bob.until(is_message).await;
    // Bob holds it, so the commit that the rename makes keeps it.
    receipts_say(&mut alice, &gid, |receipt| receipt.holds(&message) && !receipt.showed(&message)).await;
    let status = alice.request(json!({ "cmd": "status" })).await;
    assert!(status["groups"][0]["only_here"].as_array().unwrap().contains(&json!({ "what": "message", "id": hex::encode(&message.id.0) })));
    assert!(status["warning"].is_string());
    alice.request(json!({ "cmd": "name", "name": "Plan" })).await;
    polled(&alice, json!({ "cmd": "status" }), |status| status["groups"][0]["only_here"] == json!([]) && status["warning"].is_null()).await;
}
