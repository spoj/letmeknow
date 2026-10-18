//! Sessions over a local relay with a self-signed certificate, their logs on a membership service served through it.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use iroh::tls::CaTlsConfig;
use n0_future::boxed::BoxFuture;
use n0_future::task::AbortOnDropHandle;
use lmk_core::device::Device;
use lmk_core::group::Session as Mls;
use lmk_core::provider::{MemoryProvider, Provider, SqliteProvider};
use lmk_membership::client::{Post, ServeClient};
use lmk_membership::store::Store;
use lmk_testing::{Relay, relay, relay_beside};
use lmk_node::identity::Identity;
use lmk_node::{Config, Event, INVITE_VALID, Node};
use lmk_proto::directory::Directory;
use lmk_proto::group::{CHAT, Certificate, ChatMessage, IDENTITY, IdentityRef, PROTOCOL, Service, Settings};
use lmk_proto::Bytes;
use lmk_proto::frame::{self, ALPN};
use lmk_proto::head::Head;
use lmk_proto::membership::{Answer, Page};
use lmk_proto::peer::{Frame, SUMMARY, Seqs, Signed, Summary};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::UnboundedReceiver;

#[path = "identity/claims.rs"]
mod private_identity;
use private_identity::binding_record;

/// Generous, for slow CI runners with tests running side by side.
const WAIT: Duration = Duration::from_secs(60);

struct Session<P = MemoryProvider> {
    node: Node<P>,
    events: UnboundedReceiver<Event>,
}

async fn session(relay: &Relay, name: &str) -> Session {
    let (node, events) = Node::start(MemoryProvider::default(), config(relay, name, None)).await.unwrap();
    Session { node, events }
}

/// A session that posts to membership services through `post`.
async fn session_with(relay: &Relay, name: &str, post: Post) -> Session {
    let (node, events) = Node::start(MemoryProvider::default(), Config { post, ..config(relay, name, None) }).await.unwrap();
    Session { node, events }
}

/// A session that trusts the certificates of several relays, for peers and services on any of them.
async fn session_trusting(relays: [&Relay; 2], name: &str) -> Session {
    let ca = CaTlsConfig::custom_roots([relays[0].cert.clone(), relays[1].cert.clone()]);
    let (node, events) = Node::start(MemoryProvider::default(), Config { ca, ..config(relays[0], name, None) }).await.unwrap();
    Session { node, events }
}

/// A device's own node, whose key is the device key, as a session too.
async fn device(relay: &Relay, name: &str) -> (Session, Identity<MemoryProvider>) {
    let device = Device::new(name);
    let (node, events) = Node::start(MemoryProvider::default(), config(relay, name, Some(device.clone()))).await.unwrap();
    (Session { node: node.clone(), events }, Identity::new(node, device, Arc::new(|_: &Device| Ok(()))))
}

fn config(relay: &Relay, name: &str, device: Option<Device>) -> Config {
    Config {
        handle: name.into(),
        device,
        relays: vec![relay.url.clone()],
        chosen: vec![],
        resolve: lmk_testing::resolve(),
        post: relay.post(),
        ca: relay.ca(),
        home: None,
        files: None,
        file_limit: 100 << 20,
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
struct Folder(tempfile::TempDir);

impl std::ops::Deref for Folder {
    type Target = Path;
    fn deref(&self) -> &Path {
        self.0.path()
    }
}

impl AsRef<Path> for Folder {
    fn as_ref(&self) -> &Path {
        self.0.path()
    }
}

fn folder(test: &str) -> Folder {
    Folder(tempfile::Builder::new().prefix(&format!("lmk-node-{test}-")).tempdir().unwrap())
}

fn settings(kind: &str, relay: &Relay) -> Settings {
    Settings {
        protocol: PROTOCOL,
        kind: kind.into(),
        name: "Plan".into(),
        carry: 7,
        update: lmk_proto::group::UPDATE,
        membership: relay.service.clone(),
        public: None,
        rest: Default::default(),
    }
}

fn message(text: &str) -> Value {
    serde_json::to_value(ChatMessage { content: text.into(), to: vec![], urgent: false, attachment: None, sent_at: None }).unwrap()
}

/// A new identity, its public log on `membership`, whose first writer is a device called laptop, read by `node`: the
/// identity, and the laptop's key on it.
async fn identity<P: Provider + Send + 'static>(relay: &Relay, node: &Node<P>, membership: Service) -> (IdentityRef, [u8; 32]) {
    let laptop: [u8; 32] = lmk_core::random();
    let (id, first) = lmk_core::public::create(&laptop, membership.clone());
    let identity = IdentityRef { id: id.into(), membership };
    publish(relay, node, &identity, first).await;
    (identity, laptop)
}

/// Appends a sealed entry to an identity's public log, as a device of it would, and has `node` read the log.
async fn publish<P: Provider + Send + 'static>(relay: &Relay, node: &Node<P>, identity: &IdentityRef, entry: Vec<u8>) {
    let log = lmk_proto::public::address(&identity.id.0);
    ServeClient::for_service(relay.post(), &identity.membership).unwrap().append(&log, &[entry], true).await.unwrap();
    node.read_public(identity).await.unwrap();
}

/// That the session with key `session` speaks as `identity`, by the device key `device`.
fn certificate(identity: &IdentityRef, device: &[u8; 32], session: &Bytes, name: &str, device_name: &str) -> Certificate {
    let key = lmk_core::device::public(device);
    let sig = lmk_core::device::sign(device, &lmk_proto::public::certified(session.0.as_slice().try_into().unwrap(), identity.id.0.as_slice().try_into().unwrap(), &key, name, device_name));
    Certificate { identity: identity.clone(), device: key.into(), name: name.into(), device_name: device_name.into(), sig: Bytes(sig) }
}

/// A mirror of an identity's public log is only a hint: a reader takes the log from the service the identity names, and a
/// stale copy installs no claim.
#[tokio::test(flavor = "multi_thread")]
async fn an_identity_mirror_is_only_a_hint_to_its_authoritative_service() {
    use lmk_core::public::{PublicLog, Verdict};
    use lmk_membership::client::ServeClient;
    use lmk_proto::group::Credential;

    let relay = relay().await;
    let dir = folder("identity-mirror");
    let (mirror, mirror_service) = signing_service(&relay, &dir).await;
    let authority = ServeClient::for_service(relay.post(), &relay.service).unwrap();
    let mirror_client = ServeClient::for_service(relay.post(), &mirror).unwrap();
    let (laptop, tablet) = (lmk_core::random(), lmk_core::random());
    let (id, first) = lmk_core::public::create(&laptop, relay.service.clone());
    let address = lmk_proto::public::address(&id);
    let mut public = PublicLog::replay(&id, [first.as_slice()]).unwrap();
    let added = public.next(&laptop, vec![lmk_core::device::public(&laptop).into(), lmk_core::device::public(&tablet).into()]);
    assert!(public.apply(&added));
    let revoked = public.next(&laptop, vec![lmk_core::device::public(&laptop).into()]);
    authority.append(&address, &[first.clone(), added.clone(), revoked], true).await.unwrap();
    mirror_client.append(&address, &[first, added], true).await.unwrap();

    let db = dir.join("reader.db");
    let reader = stored(&relay, "Reader", &db).await;
    let claim = IdentityRef { id: id.into(), membership: mirror };
    let credential = |device| Credential {
        name: "claimant".into(),
        key: reader.node.key(),
        certificate: Some(certificate(&claim, device, &reader.node.key(), "Carol", "device").into()),
    };
    let gid = reader.node.create(settings(CHAT, &relay), Some(*credential(&tablet).certificate.unwrap())).unwrap();
    assert_eq!(public.verify(&credential(&tablet)), Verdict::Authorized, "the genuine prefix still lists the revoked device");
    let latest = reader.node.read_public(&claim).await.unwrap();
    assert_eq!(latest.membership, relay.service);
    assert_eq!(latest.verify(&credential(&tablet)), Verdict::Dropped);
    assert_eq!(latest.verify(&credential(&laptop)), Verdict::Authorized, "a claimant's service is not its authority");
    assert!(reader.node.members(&gid.0).unwrap()[0].identity.as_ref().unwrap().observed.is_none());
    assert!(binding_record(&db).is_none(), "a genuine stale hint must not pin an installed revoked claim");

    let fork = public.next(&tablet, vec![lmk_core::device::public(&tablet).into()]);
    mirror_client.append(&address, &[fork], true).await.unwrap();
    assert_eq!(reader.node.read_public(&claim).await.unwrap().writers, [lmk_core::device::public(&laptop).into()]);
    reader.node.shutdown().await.unwrap();
    drop(reader);
    drop(mirror_service);
    let reader = stored(&relay, "Reader", &db).await;
    assert_eq!(reader.node.read_public(&claim).await.unwrap().writers, [lmk_core::device::public(&laptop).into()], "the persisted service is the authority, not the mirror");
    reader.node.shutdown().await.unwrap();
}

/// A first lookup of an identity that fails persists no service for it; the genuine genesis, once served, does.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_first_identity_lookup_does_not_persist_a_service() {
    use lmk_membership::client::ServeClient;

    let relay = relay().await;
    let dir = folder("identity-failed-service");
    let (mirror, _mirror_service) = signing_service(&relay, &dir).await;
    let authority = ServeClient::for_service(relay.post(), &relay.service).unwrap();
    let mirror_client = ServeClient::for_service(relay.post(), &mirror).unwrap();
    let laptop = lmk_core::random();
    let (id, first) = lmk_core::public::create(&laptop, relay.service.clone());
    let address = lmk_proto::public::address(&id);
    let claim = IdentityRef { id: id.into(), membership: mirror };
    mirror_client.append(&address, &[b"not a genesis".to_vec()], true).await.unwrap();

    let db = dir.join("reader.db");
    let mut reader = stored(&relay, "Reader", &db).await;
    let gid = reader.node.create(settings(CHAT, &relay), Some(certificate(&claim, &laptop, &reader.node.key(), "Carol", "laptop"))).unwrap();
    assert!(reader.node.read_public(&claim).await.is_err());
    mirror_client.append(&address, std::slice::from_ref(&first), true).await.unwrap();
    assert!(reader.node.read_public(&claim).await.is_err(), "a genuine genesis alone is not authoritative history");
    while let Ok(event) = reader.events.try_recv() {
        assert!(!matches!(event, Event::Public { .. }), "no identity state from either failed lookup");
    }
    reader.node.shutdown().await.unwrap();
    drop(reader);
    let mut provider = SqliteProvider::open(&db).unwrap();
    assert!(provider.get(b"node/identity-bindings").unwrap().is_none());
    assert!(provider.get(&[b"node/log/".as_slice(), &address].concat()).unwrap().is_none());
    assert!(provider.get(&[b"node/entry/".as_slice(), &address, b"/", &1u64.to_be_bytes()].concat()).unwrap().is_none());
    provider.close().unwrap();

    authority.append(&address, &[first], true).await.unwrap();
    let reader = stored(&relay, "Reader", &db).await;
    let legitimate = IdentityRef { membership: relay.service.clone(), ..claim };
    let public = reader.node.read_public(&legitimate).await.unwrap();
    assert_eq!(reader.node.members(&gid.0).unwrap()[0].identity.as_ref().unwrap().observed.as_ref().unwrap().names, ["Carol"]);
    assert_eq!(serde_json::from_slice::<Value>(&binding_record(&db).unwrap()).unwrap(), json!([[legitimate.id, "Carol"]]));
    assert_eq!(public.membership, relay.service);
    assert_eq!(public.writers, [lmk_core::device::public(&laptop).into()]);
    reader.node.shutdown().await.unwrap();
}

/// A group's service and a member's identity's service are two services, each found by its own domain.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_whose_identity_is_on_another_service_speaks_in_a_group() {
    let (group_relay, identity_relay) = (relay().await, relay().await);
    let alice = session_trusting([&group_relay, &identity_relay], "Alice").await;
    let mut bob = session_trusting([&group_relay, &identity_relay], "Bob").await;
    let (claim, laptop) = identity(&identity_relay, &bob.node, identity_relay.service.clone()).await;
    let gid = bob.node.create(settings(CHAT, &group_relay), Some(certificate(&claim, &laptop, &bob.node.key(), "Bob", "laptop"))).unwrap();
    alice.node.join(&bob.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    bob.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    eventually("Alice verifies Bob's identity, on the other service", || {
        alice.node.members(&gid.0).unwrap().iter().any(|m| m.key == bob.node.key() && m.identity.as_ref().is_some_and(|c| c.name == "Bob" && c.error.is_none()))
    })
    .await;
    let sent = alice.node.send(&gid.0, &message("across services"), None).await.unwrap();
    let got = bob.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    })
    .await;
    assert_eq!(got.id, sent);
}

/// A member whose own relay is down is reached through the relay of its group's service, which its node holds too.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_is_reached_through_its_groups_service_when_its_own_relay_is_down() {
    let (service, own) = (relay().await, relay().await);
    let mut carol = session(&service, "Carol").await;
    let gid = carol.node.create(settings(CHAT, &service), None).unwrap();
    // Bob's own relay is down, and Alice lives on another: Bob is reached through the relay of its group's service.
    let alice = session_trusting([&own, &service], "Alice").await;
    alice.node.join(&carol.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let dead: iroh::RelayUrl = "https://127.0.0.1:1".parse().unwrap();
    let (node, events) = Node::start(MemoryProvider::default(), Config { relays: vec![dead, service.url.clone()], ..config(&service, "Bob", None) }).await.unwrap();
    let mut bob = Session { node, events };
    bob.node.join(&carol.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    carol.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    eventually("Alice holds Bob", || alice.node.members(&gid.0).unwrap().len() == 3).await;
    carol.node.shutdown().await.unwrap();
    let sent = alice.node.send(&gid.0, &message("through the service"), None).await.unwrap();
    let got = bob.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    })
    .await;
    assert_eq!(got.id, sent);
}

/// A join reaches an inviter whose home relay is not its group's service's, through the service's relay alone, where
/// the inviter is reached as a backup.
#[tokio::test(flavor = "multi_thread")]
async fn a_join_reaches_an_inviter_on_another_relay_than_the_services() {
    let (service, own) = (relay().await, relay().await);
    let mut carol = session(&service, "Carol").await;
    let gid = carol.node.create(settings(CHAT, &service), None).unwrap();
    // Bob's home is his first relay, which is not the service's.
    let (node, events) = Node::start(MemoryProvider::default(), Config { relays: vec![own.url.clone(), service.url.clone()], ca: CaTlsConfig::custom_roots([own.cert.clone(), service.cert.clone()]), ..config(&service, "Bob", None) }).await.unwrap();
    let mut bob = Session { node, events };
    bob.node.join(&carol.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    carol.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let link = bob.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    let dan = session(&service, "Dan").await;
    dan.node.join(&link, None).await.unwrap();
    bob.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
}

/// An identity whose directory is down when a member joins is unverified until the directory answers, and is then read
/// again, without a restart.
#[tokio::test(flavor = "multi_thread")]
async fn an_identity_whose_directory_is_down_at_join_is_read_again() {
    let (group_relay, identity_relay) = (relay().await, relay().await);
    let (gate, _reaching) = Gate::new(Some(&identity_relay.service));
    let ca = CaTlsConfig::custom_roots([group_relay.cert.clone(), identity_relay.cert.clone()]);
    let (node, events) = Node::start(MemoryProvider::default(), Config { ca, post: gate.post("Alice", identity_relay.post()), ..config(&group_relay, "Alice", None) }).await.unwrap();
    let alice = Session { node, events };
    let bob = session_trusting([&group_relay, &identity_relay], "Bob").await;
    let (claim, laptop) = identity(&identity_relay, &bob.node, identity_relay.service.clone()).await;
    let gid = bob.node.create(settings(CHAT, &group_relay), Some(certificate(&claim, &laptop, &bob.node.key(), "Bob", "laptop"))).unwrap();
    gate.set(false);
    alice.node.join(&bob.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let unread = |node: &Node<MemoryProvider>| node.members(&gid.0).unwrap().iter().any(|m| m.key == bob.node.key() && m.identity.as_ref().is_some_and(|c| c.error.is_some()));
    eventually("Alice cannot verify Bob's identity yet", || unread(&alice.node)).await;
    gate.set(true);
    eventually("Alice verifies Bob's identity once its directory answers", || {
        alice.node.members(&gid.0).unwrap().iter().any(|m| m.key == bob.node.key() && m.identity.as_ref().is_some_and(|c| c.name == "Bob" && c.error.is_none()))
    })
    .await;
}

/// A link whose domain does not resolve still admits its joiner: the members it names are dialed at their own relays.
#[tokio::test(flavor = "multi_thread")]
async fn a_join_survives_an_unresolved_link_domain() {
    let relay = relay().await;
    let mut alice = session(&relay, "Alice").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    // Only Bob's node fails to resolve the link's domain: Alice's commits still need the service's directory.
    let unresolved: lmk_membership::client::Resolve = Arc::new(|domain: String| -> BoxFuture<anyhow::Result<Directory>> {
        Box::pin(async move { anyhow::bail!("no directory for {domain}") })
    });
    let (node, events) = Node::start(MemoryProvider::default(), Config { resolve: unresolved, ..config(&relay, "Bob", None) }).await.unwrap();
    let bob = Session { node, events };
    bob.node.join(&link, None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
}

/// Posts through `post`, except the next append of entries once `late` is set, which opens of logs do not take: it
/// lands, is told on the channel, and is answered `after` later.
fn late_append(post: Post, after: Duration) -> (Arc<std::sync::atomic::AtomicBool>, UnboundedReceiver<()>, Post) {
    let late = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (landed, landing) = tokio::sync::mpsc::unbounded_channel();
    let armed = late.clone();
    let post: Post = Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| {
        let entries = serde_json::from_slice::<Value>(&body).is_ok_and(|append| append["entries"].as_array().is_some_and(|entries| !entries.is_empty()));
        let late = route.ends_with("/append") && entries && armed.swap(false, std::sync::atomic::Ordering::SeqCst);
        let (post, landed) = (post.clone(), landed.clone());
        Box::pin(async move {
            let answer = post(domain, route, body).await;
            if late {
                landed.send(()).ok();
                tokio::time::sleep(after).await;
            }
            answer
        })
    });
    (late, landing, post)
}

/// A committer stopped once its Add is logged, before it hears so: restarted, it answers the joiner's retry with that
/// Add, not another.
#[tokio::test(flavor = "multi_thread")]
async fn a_committer_stopped_once_its_add_is_logged_answers_the_retry_with_it() {
    let relay = relay().await;
    let dir = folder("logged-add");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("alice.db");
    let (late, mut landing, post) = late_append(relay.post(), Duration::from_secs(3600));
    let alice = stored_with(&relay, "Alice", &path, post).await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    let epoch = alice.node.epoch(&gid.0).unwrap();
    late.store(true, std::sync::atomic::Ordering::SeqCst);
    let joining = {
        let (node, link) = (bob.node.clone(), link.clone());
        tokio::spawn(async move { node.join(&link, None).await })
    };
    tokio::time::timeout(WAIT, landing.recv()).await.unwrap().unwrap();
    alice.node.shutdown().await.unwrap();
    drop(alice);
    joining.abort();
    assert!(bob.node.groups().is_empty());

    let alice = stored(&relay, "Alice", &path).await;
    let joining = {
        let node = bob.node.clone();
        tokio::spawn(async move { node.join(&link, None).await })
    };
    assert_eq!(tokio::time::timeout(WAIT, joining).await.unwrap().unwrap().unwrap().0, gid);
    assert_eq!(alice.node.epoch(&gid.0).unwrap(), epoch + 1, "the retry got the logged Add, not another");
    alice.node.shutdown().await.unwrap();
    bob.node.shutdown().await.unwrap();
}

/// A chat of two: a message arrives with its sender, a settings change reaches the other member, and a removal ends its
/// group for the removed member.
#[tokio::test(flavor = "multi_thread")]
async fn chat_and_removal() {
    let relay = relay().await;
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    let (joined, _) = bob.node.join(&link, None).await.unwrap();
    assert_eq!(joined, gid);
    let member = alice.until(|e| match e {
        Event::Joined { member, .. } => Some(member),
        _ => None,
    }).await;
    assert_eq!(member.name, "Bob");
    assert_eq!(bob.node.members(&gid.0).unwrap().len(), 2);

    let sent = bob.node.send(&gid.0, &message("hello"), None).await.unwrap();
    let got = alice.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((got.id, got.seq, got.sender.name.as_str()), (sent, 1, "Bob"));
    let big = message(&"x".repeat(1 << 20));
    let refused = bob.node.send(&gid.0, &big, None).await.unwrap_err();
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
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    // A member named first that cannot be reached holds up nothing while another can.
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    let dead = *iroh::SecretKey::from_bytes(&lmk_core::random()).public().as_bytes();
    let started = std::time::Instant::now();
    bob.node.join(&Invite { members: vec![dead, link.members[0]], ..link }, None).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;

    // Two joiners race with one secret, each asking another member: one gets in, and the other is refused.
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    assert_eq!(link.members.len(), 2, "the link names the inviter and the member that took the invite");
    let only = |n: usize| Invite { members: vec![link.members[n]], ..link.clone() };
    let (carol, dave) = (session(&relay, "Carol").await, session(&relay, "Dave").await);
    let (to_alice, to_bob) = (only(0), only(1));
    let (by_alice, by_bob) = tokio::join!(carol.node.join(&to_alice, None), dave.node.join(&to_bob, None));
    assert!(by_alice.is_ok() != by_bob.is_ok(), "{by_alice:?} {by_bob:?}");
    let refused = format!("{:#}", by_alice.err().or(by_bob.err()).unwrap());
    assert!(refused.contains("unknown, used or expired"), "{refused}");
    let erin = session(&relay, "Erin").await;
    let used = erin.node.join(&link, None).await.unwrap_err();
    assert!(format!("{used:#}").contains("unknown, used or expired"), "a used secret is refused");

    // A member that redeems a link is refused, routinely, and the link stays unused.
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    let member = bob.node.join(&link, None).await.unwrap_err();
    assert!(format!("{member:#}").contains("a member already"), "{member:#}");
    while let Ok(event) = alice.events.try_recv().or_else(|_| bob.events.try_recv()) {
        assert!(!matches!(&event, Event::Warning { text, .. } if text.contains("refused a join")), "a routine refusal is no warning: {event:?}");
    }

    // An expired one too.
    let secret = [7u8; 16];
    let expired = json!({ "type": "invite", "hash": Bytes(Sha256::digest(secret).to_vec()), "expires": lmk_node::now() - 1 });
    bob.node.send(&gid.0, &expired, None).await.unwrap();
    eventually("Alice holds the expired invite", || alice.node.messages(&gid.0).unwrap().iter().any(|m| m.payload["type"] == "invite")).await;
    let expired = Invite { secret, members: vec![link.members[0]], ..link.clone() };
    assert!(format!("{:#}", erin.node.join(&expired, None).await.unwrap_err()).contains("unknown, used or expired"));

    // With the inviter offline, another member it named admits the joiner.
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let (joined, by) = erin.node.join(&link, None).await.unwrap();
    assert_eq!(joined, gid);
    assert!(link.members[1..].contains(&by), "another member admits");
    let how = bob.until(|e| match e {
        Event::Joined { member, how, .. } if member.name == "Erin" => Some(how),
        _ => None,
    }).await;
    assert_eq!(how, lmk_proto::group::How::Invite);
}

/// A member reached first that never answers keeps the joiner from no other member it dials meanwhile.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_member_reached_first_holds_up_no_other() {
    use lmk_proto::links::Invite;
    let relay = relay().await;
    let alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    let key = iroh::SecretKey::from_bytes(&lmk_core::random());
    let silent = *key.public().as_bytes();
    let _silent = hand(&relay, key.clone(), &bob.node).await;
    eventually("the silent member is connected", || bob.node.net().connected().contains(&key.public())).await;
    let (joined, by) = bob.node.join(&Invite { members: vec![silent, link.members[0]], ..link.clone() }, None).await.unwrap();
    assert_eq!((joined, by), (gid, link.members[0]));
    alice.node.shutdown().await.unwrap();
}

/// An invite dies when its inviter leaves the group, removed or by `leave`.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_dies_when_its_inviter_leaves() {
    use lmk_proto::links::Invite;
    let relay = relay().await;
    let mut alice = session(&relay, "Alice").await;
    let (bob, carol) = (session(&relay, "Bob").await, session(&relay, "Carol").await);
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    let (by_bob, by_carol) = (bob.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), carol.node.invite(&gid.0, None, INVITE_VALID).await.unwrap());
    let invites = || alice.node.messages(&gid.0).unwrap().iter().filter(|m| m.payload["type"] == "invite").count();
    eventually("Alice holds both invites", || invites() == 4).await;

    alice.node.remove(&gid.0, &bob.node.key().0).await.unwrap();
    carol.node.leave(&gid.0).unwrap();
    eventually("Bob and Carol are out", || alice.node.members(&gid.0).unwrap().len() == 1).await;
    let dave = session(&relay, "Dave").await;
    let at_alice = alice.node.address().0;
    let ask_alice = |link: &Invite| Invite { members: vec![at_alice], ..link.clone() };
    for link in [&by_bob, &by_carol] {
        let refused = dave.node.join(&ask_alice(link), None).await.unwrap_err();
        assert!(format!("{refused:#}").contains("its inviter left the group"), "{refused:#}");
    }
    while let Ok(event) = alice.events.try_recv() {
        assert!(!matches!(&event, Event::Warning { text, .. } if text.contains("refused a join")), "a routine refusal is no warning: {event:?}");
    }
    alice.node.shutdown().await.unwrap();
}

/// A membership service like `letmeknow serve`'s, which signs its heads.
async fn signing_service(relay: &Relay, dir: &Path) -> (Service, AbortOnDropHandle<()>) {
    served(relay, dir).await
}

/// A signing membership service, its store in `dir`, served over https.
async fn served(relay: &Relay, dir: &Path) -> (Service, AbortOnDropHandle<()>) {
    std::fs::create_dir_all(dir).unwrap();
    relay.serve(&dir.join("membership")).await
}

/// A membership service's gate: while it is shut, the posts a node makes to its domain wait until it opens, and each
/// node whose post waits is told by `reaching`, by its name.
struct Gate {
    /// The domain whose posts wait; all domains' if none.
    domain: Option<String>,
    open: tokio::sync::watch::Sender<bool>,
    reached: tokio::sync::mpsc::UnboundedSender<String>,
}

impl Gate {
    fn new(service: Option<&Service>) -> (Arc<Gate>, UnboundedReceiver<String>) {
        let domain = service.map(|service| { let Service::Serve { domain, .. } = service else { unreachable!() }; domain.clone() });
        let (reached, reaching) = tokio::sync::mpsc::unbounded_channel();
        (Arc::new(Gate { domain, open: tokio::sync::watch::Sender::new(true), reached }), reaching)
    }

    fn set(&self, open: bool) {
        self.open.send_replace(open);
    }

    /// The posts of the node `who` through the gate: its domain's wait while the gate is shut, and the others pass.
    fn post(self: &Arc<Self>, who: &str, post: Post) -> Post {
        let (gate, who) = (self.clone(), who.to_owned());
        Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| {
            let (gate, who, post) = (gate.clone(), who.clone(), post.clone());
            Box::pin(async move {
                if gate.domain.as_ref().is_none_or(|waits| *waits == domain) {
                    let mut open = gate.open.subscribe();
                    if !*open.borrow() {
                        gate.reached.send(who).ok();
                    }
                    open.wait_for(|open| *open).await.ok();
                }
                post(domain, route, body).await
            })
        })
    }
}

/// The rule a joiner comes by is checked again as the Add is built: an invite that expired while the admitter read the
/// joiner's public log admits no one.
#[tokio::test(flavor = "multi_thread")]
async fn a_rule_is_checked_again_as_the_add_is_built() {
    use lmk_proto::links::Invite;
    let relay = relay().await;
    let dir = folder("rebuild");
    let (gate, mut reaching) = Gate::new(None);
    let alice = session_with(&relay, "Alice", gate.post("Alice", relay.post())).await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    bob.node.join(&link, None).await.unwrap();
    let alice_only = vec![link.members[0]];
    // On a slow machine an invite may expire before Alice reads the public log: then once more, valid twice as long.
    let mut valid = 3000;
    loop {
        let (membership, _service) = served(&relay, &dir.join(valid.to_string())).await;
        let joiner = session(&relay, "Carol").await;
        let (carol, device) = identity(&relay, &joiner.node, membership).await;
        let certificate = certificate(&carol, &device, &joiner.node.key(), "Carol", "laptop");
        gate.set(false);
        let expires = lmk_node::now() + valid;
        let secret: [u8; 16] = lmk_core::random();
        let hash = Bytes(Sha256::digest(secret).to_vec());
        let rule = json!({ "type": "invite", "hash": hash, "expires": expires, "to": carol.id });
        bob.node.send(&gid.0, &rule, None).await.unwrap();
        eventually("Alice holds the invite", || alice.node.messages(&gid.0).unwrap().iter().any(|m| m.payload["hash"] == rule["hash"])).await;
        let link = Invite { device: false, secret, domain: link.domain.clone(), members: alice_only.clone() };
        let mut joining = tokio::spawn(async move { joiner.node.join(&link, Some(certificate)).await.map(|(gid, _)| gid) });
        // Alice reads the public log once the rule admits Carol.
        let alice_reads = async { while reaching.recv().await.unwrap() != "Alice" {} };
        let reached = tokio::time::timeout(WAIT, async {
            tokio::select! {
                _ = alice_reads => true,
                refused = &mut joining => {
                    assert!(format!("{refused:?}").contains("unknown, used or expired"), "{refused:?}");
                    false
                }
            }
        }).await.expect("Alice reads Carol's public log");
        if !reached {
            assert!(valid < WAIT.as_millis() as u64, "the invite expired before Alice read the public log");
            valid *= 2;
            continue;
        }
        tokio::time::sleep(Duration::from_millis(expires + 200 - lmk_node::now())).await;
        gate.set(true);
        let refused = format!("{:#}", joining.await.unwrap().unwrap_err());
        assert!(refused.contains("unknown, used or expired"), "{refused}");
        assert_eq!(alice.node.members(&gid.0).unwrap().len(), 2);
        break;
    }
}

/// A service that shows a session another version of a log than the session read is reported once, however often the
/// session reads it again.
#[tokio::test(flavor = "multi_thread")]
async fn a_contradiction_is_reported_once() {
    let relay = relay().await;
    let dir = folder("contradiction");
    let (membership, _service) = signing_service(&relay, &dir).await;
    // The service's key signs the forged head, as an operator's own fork would be signed.
    let key = Store::open(&dir.join("membership")).unwrap().key().clone();
    let forging = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let post: Post = {
        let (forging, base) = (forging.clone(), relay.post());
        Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| {
            let (forging, base, key) = (forging.clone(), base.clone(), key.clone());
            Box::pin(async move {
                let answer = base(domain, route, body).await?;
                if route != "/membership/2/read" || !forging.load(std::sync::atomic::Ordering::Relaxed) { return Ok(answer) }
                let Answer::<Page>::Ok(mut page) = serde_json::from_slice(&answer)? else { return Ok(answer) };
                page.head = Head::sign(&key, &page.head.log_ref, page.head.length, [0; 32], page.head.time);
                Ok(serde_json::to_vec(&Answer::Ok(page))?)
            })
        })
    };
    let mut alice = session_with(&relay, "Alice", post).await;
    let (identity, _laptop) = identity(&relay, &alice.node, membership).await;
    alice.node.read_public(&identity).await.unwrap();
    forging.store(true, std::sync::atomic::Ordering::Relaxed);
    for _ in 0..2 {
        assert!(alice.node.read_public(&identity).await.is_err());
    }
    let mut warnings = 0;
    while let Ok(event) = alice.events.try_recv() {
        warnings += matches!(event, Event::Warning { text, .. } if text.contains("another version")) as usize;
    }
    assert_eq!(warnings, 1);
}

/// A membership service whose answers name another key than its directory's is reported once, however often sends ask
/// it about the directory of an identity a member speaks as.
#[test]
fn a_directory_naming_another_key_is_reported_once() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("misdirected");
        let (membership, _service) = signing_service(&relay, &dir.join("first")).await;
        let (other, _other_service) = signing_service(&relay, &dir.join("other")).await;
        let Service::Serve { domain: elsewhere, .. } = other else { unreachable!() };
        let switched = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (base, flag) = (relay.post(), switched.clone());
        let post: Post = Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| {
            let domain = if flag.load(std::sync::atomic::Ordering::SeqCst) { elsewhere.clone() } else { domain };
            base(domain, route, body)
        });
        let mut alice = session_with(&relay, "Alice", post).await;
        let (carol, laptop) = identity(&relay, &alice.node, membership).await;
        let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
        let tablet = session(&relay, "tablet").await;
        let certified = certificate(&carol, &laptop, &tablet.node.key(), "Carol", "laptop");
        tablet.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), Some(certified)).await.unwrap();
        eventually("Alice holds Carol's session", || alice.node.members(&gid.0).unwrap().len() == 2).await;
        switched.store(true, std::sync::atomic::Ordering::SeqCst);
        for _ in 0..2 {
            SHIFT.fetch_add(FRESH_MS, std::sync::atomic::Ordering::Relaxed);
            alice.node.send(&gid.0, &message("asks"), None).await.unwrap();
        }
        let mut warnings = 0;
        while let Ok(event) = alice.events.try_recv() {
            warnings += matches!(&event, Event::Warning { group, text } if group.is_none() && text.contains("names another key")) as usize;
        }
        assert_eq!(warnings, 1);
        alice.node.shutdown().await.unwrap();
        tablet.node.shutdown().await.unwrap();
    });
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

/// Has the identity kind take a device's events first, as a client does.
fn routed<P: Provider + Send + 'static>(session: &mut Session<P>, devices: Identity<P>) {
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

/// A device's own node on SQLite at `db`, which survives a restart, with the identity kind taking its events first.
async fn stored_device(relay: &Relay, name: &str, db: &Path) -> (Session<SqliteProvider>, Identity<SqliteProvider>) {
    let device = Device::new(name);
    let (node, events) = Node::start(SqliteProvider::open(db).unwrap(), config(relay, name, Some(device.clone()))).await.unwrap();
    let devices = Identity::new(node.clone(), device, Arc::new(|_: &Device| Ok(())));
    let mut session = Session { node, events };
    routed(&mut session, devices.clone());
    (session, devices)
}

/// Waits until the keys-only directory lists exactly these devices.
async fn lists<P: Provider + Send + 'static>(node: &Node<P>, identity: &IdentityRef, keys: &[Bytes]) -> lmk_core::public::PublicLog {
    tokio::time::timeout(WAIT, async {
        loop {
            let log = node.read_public(identity).await.unwrap();
            let mut keys = keys.to_vec();
            keys.sort();
            if log.writers == keys {
                return log;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the public log lists the devices")
}

/// The identity group of a device's only identity.
fn devices_group<P: Provider + Send + 'static>(node: &Node<P>) -> Bytes {
    node.groups().into_iter().find(|gid| node.settings(&gid.0).unwrap().kind == IDENTITY).unwrap()
}

/// Devices share an identity's list; each certifies its session, and a device dropped from the list takes its session out
/// of chats.
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
    lists(&laptop.node, &bob, &[laptop_devices.key().unwrap()]).await;

    // A device link: the tablet joins with a key of its own, which the public log lists once the laptop publishes the
    // list.
    let link = lmk_proto::links::Invite::parse(&laptop_devices.invite().await.unwrap()).unwrap();
    tablet_devices.join(&link).await.unwrap();
    assert_eq!(tablet_devices.identity(), Some((bob.clone(), "Bob".to_owned())));
    let (laptop_key, tablet_key) = (laptop_devices.key().unwrap(), tablet_devices.key().unwrap());
    assert!(laptop_key != tablet_key && laptop_key != laptop.node.key() && tablet_key != tablet.node.key(), "a device key per identity");
    lists(&laptop.node, &bob, &[laptop_devices.key().unwrap(), tablet_devices.key().unwrap()]).await;

    // Each certifies its session, which joins a chat of Alice's by an invite.
    let chat = alice.node.create(Settings { membership: membership.clone(), ..settings(CHAT, &relay) }, None).unwrap();
    for (node, devices) in [(&tablet.node, &tablet_devices), (&laptop.node, &laptop_devices)] {
        let link = alice.node.invite(&chat.0, None, INVITE_VALID).await.unwrap();
        node.join(&link, Some(devices.certify(&node.key().0).unwrap())).await.unwrap();
    }
    assert_eq!(alice.checked(&chat, "tablet", true).await.device_name, "tablet");
    assert_eq!(alice.checked(&chat, "laptop", true).await.device_name, "laptop");

    // The tablet stops, and the laptop takes it off Bob: a list without it. Alice removes its session from the chat
    // without its coming back; the laptop's certificate still checks out, and alice serves it.
    tablet.node.shutdown().await.unwrap();
    laptop_devices.remove(&tablet_key.0).await.unwrap();
    lists(&laptop.node, &bob, &[laptop_devices.key().unwrap()]).await;
    alice.until(|e| matches!(e, Event::Left { member, .. } if member.name == "tablet").then_some(())).await;
    alice.checked(&chat, "laptop", true).await;
    let id = alice.node.send(&chat.0, &message("after the tablet left"), None).await.unwrap();
    let got = laptop.until(|e| match e {
        Event::Message(message) if message.id == id => Some(message.id),
        _ => None,
    }).await;
    assert_eq!(got, id);
}

/// An identity's public log follows its group's keys, not its names. The last device to leave
/// closes it, and from then on no session speaks for the identity.
#[tokio::test(flavor = "multi_thread")]
async fn an_identitys_public_log_follows_its_group_until_its_last_device_closes_it() {
    let relay = relay().await;
    let mut alice = session(&relay, "Alice").await;
    let (mut laptop, laptop_devices) = device(&relay, "laptop").await;
    routed(&mut laptop, laptop_devices.clone());
    let bob = laptop_devices.create("Bob", relay.service.clone()).await.unwrap();
    laptop_devices.rename("Robert").await.unwrap();
    laptop_devices.rename_device("desk").await.unwrap();
    lists(&laptop.node, &bob, &[laptop_devices.key().unwrap()]).await;
    assert_eq!(laptop_devices.certify(&alice.node.key().0).unwrap().name, "Robert");

    let chat = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let agent = session(&relay, "agent").await;
    let certificate = laptop_devices.certify(&agent.node.key().0).unwrap();
    agent.node.join(&alice.node.invite(&chat.0, None, INVITE_VALID).await.unwrap(), Some(certificate)).await.unwrap();
    assert_eq!(alice.checked(&chat, "agent", true).await.device_name, "desk");
    assert!(laptop_devices.leave().await.unwrap(), "the only device ends the identity");
    assert!(alice.node.read_public(&bob).await.unwrap().closed());
    alice.until(|e| matches!(e, Event::Left { member, .. } if member.name == "agent").then_some(())).await;
}

/// Once an identity's public log drops a device, its sessions leave every group, each by one commit, whose committer
/// reports the members they added; a list that grows removes no one.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_devices_sessions_are_removed_once_and_reported() {
    let relay = relay().await;
    let dir = folder("revoke");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let alice = session(&relay, "Alice").await;
    let (carol, laptop) = identity(&relay, &alice.node, membership.clone()).await;
    let tablet_key: [u8; 32] = lmk_core::random();
    let log = alice.node.read_public(&carol).await.unwrap();
    let both = vec![lmk_core::device::public(&laptop).into(), lmk_core::device::public(&tablet_key).into()];
    publish(&relay, &alice.node, &carol, log.next(&laptop, both)).await;
    let groups = [(); 2].map(|_| alice.node.create(Settings { membership: membership.clone(), ..settings(CHAT, &relay) }, None).unwrap());
    let (tablet, desk, dave, eve) = (session(&relay, "tablet").await, session(&relay, "desk").await, session(&relay, "Dave").await, session(&relay, "Eve").await);
    let alice_only = vec![alice.node.invite(&groups[0].0, None, INVITE_VALID).await.unwrap().members[0]];
    for gid in &groups {
        for (joiner, device) in [(&tablet, &tablet_key), (&desk, &laptop)] {
            // Alice admits each: a link that named the tablet too could have the tablet add the desk.
            let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
            let link = lmk_proto::links::Invite { members: link.members[..1].to_vec(), ..link };
            joiner.node.join(&link, Some(certificate(&carol, device, &joiner.node.key(), "Carol", "device"))).await.unwrap();
            alice.checked(gid, &joiner.node.members(&gid.0).unwrap().iter().find(|m| m.key == joiner.node.key()).unwrap().name, true).await;
        }
    }
    // The tablet's session adds Dave to the first group, and invites Eve, whom alice admits.
    let link = tablet.node.invite(&groups[0].0, None, INVITE_VALID).await.unwrap();
    dave.node.join(&link, None).await.unwrap();
    let link = tablet.node.invite(&groups[0].0, None, INVITE_VALID).await.unwrap();
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
    let log = alice.node.read_public(&carol).await.unwrap();
    publish(&relay, &alice.node, &carol, log.next(&laptop, vec![lmk_core::device::public(&laptop).into()])).await;
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

/// A device that read the public log entry listing a device just linked, before the Add of it, reads the devices
/// group's log before it compares, and so does not drop the new device.
#[tokio::test(flavor = "multi_thread")]
async fn the_list_does_not_drop_a_device_just_linked() {
    let relay = relay().await;
    let dir = folder("link-race");
    std::fs::create_dir_all(&dir).unwrap();
    let membership = relay.service.clone();
    let (laptop, laptop_devices) = stored_device(&relay, "laptop", &dir.join("laptop.db")).await;
    let (_phone, phone_devices) = stored_device(&relay, "phone", &dir.join("phone.db")).await;
    let (_tablet, tablet_devices) = stored_device(&relay, "tablet", &dir.join("tablet.db")).await;
    let bob = laptop_devices.create("Bob", membership).await.unwrap();
    let link = lmk_proto::links::Invite::parse(&laptop_devices.invite().await.unwrap()).unwrap();
    phone_devices.join(&link).await.unwrap();
    lists(&laptop.node, &bob, &[laptop_devices.key().unwrap(), phone_devices.key().unwrap()]).await;
    // While the laptop is stopped, the phone links the tablet.
    laptop.node.shutdown().await.unwrap();
    drop((laptop, laptop_devices));
    let link = lmk_proto::links::Invite::parse(&phone_devices.invite().await.unwrap()).unwrap();
    tablet_devices.join(&link).await.unwrap();

    // The laptop starts with its identity group as it stopped, and the public log as it is now.
    let (laptop, laptop_devices) = stored_device(&relay, "laptop", &dir.join("laptop.db")).await;
    let gid = devices_group(&laptop.node);
    laptop_devices.duties(&gid.0).await.unwrap();
    lists(&laptop.node, &bob, &[laptop_devices.key().unwrap(), phone_devices.key().unwrap(), tablet_devices.key().unwrap()]).await;
    assert_eq!(laptop.node.members(&gid.0).unwrap().len(), 3);
}

/// A session whose leaf names an older revision writes its own as it starts.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_updates_an_older_leaf_as_it_starts() {
    use lmk_core::group::{Change, Group, Session as Mls};
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder("revision");
    std::fs::create_dir_all(&dir).unwrap();
    let bob_db = dir.join("bob.db");
    let start = || async { Node::start(SqliteProvider::open(&bob_db).unwrap(), config(&relay, "Bob", None)).await.unwrap().0 };
    let alice = session(&relay, "Alice").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let bob = start().await;
    bob.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
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
    let mut group = Group::load(&provider, &gid.0).unwrap();
    let capability = group.capability(&provider).unwrap();
    let cut = group.cut().to_vec();
    let commit = group.commit(&provider, &mls, Change { leaf: Some(old), cut, ..Change::default() }).unwrap();
    ServeClient::for_service(relay.post(), &relay.service).unwrap().append(&capability, &[commit.entry], false).await.unwrap();
    drop(provider);
    revision(0).await.expect("Alice sees Bob's leaf of revision 0");

    let bob = start().await;
    revision(lmk_proto::group::REVISION).await.expect("Bob's leaf names this revision once he starts");
    bob.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();
}

/// A device keeps its identity across restarts, from its database.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_keeps_its_identity_across_restarts() {
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder("restart");
    std::fs::create_dir_all(&dir).unwrap();
    let membership = relay.service.clone();
    let device = Device::new("laptop");
    let start = || async {
        let (node, _events) =
            Node::start(SqliteProvider::open(&dir.join("device.db")).unwrap(), config(&relay, "laptop", Some(device.clone()))).await.unwrap();
        (node.clone(), Identity::new(node, device.clone(), Arc::new(|_: &Device| Ok(()))))
    };
    let (node, devices) = start().await;
    let bob = devices.create("Bob", membership).await.unwrap();
    node.shutdown().await.unwrap();
    drop((node, devices));
    let (node, devices) = start().await;
    assert_eq!(devices.identity(), Some((bob, "Bob".to_owned())));
    node.shutdown().await.unwrap();
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

/// A `leave` sent while the membership service is unreachable reaches the other member, which removes the leaver once the
/// service is back: the leaver is restarted meanwhile with `restart_leaver`.
async fn held_leave(test: &str, restart_leaver: bool) {
    use lmk_core::provider::SqliteProvider;
    let relay = relay().await;
    let dir = folder(test);
    let (membership, _service) = served(&relay, &dir).await;
    let (gate, _reaching) = Gate::new(Some(&membership));
    let start = |name: &'static str| {
        let (relay, db, gate) = (&relay, dir.join(format!("{name}.db")), gate.clone());
        async move {
            let (node, events) = Node::start(SqliteProvider::open(&db).unwrap(), Config { post: gate.post(name, relay.post()), ..config(relay, name, None) }).await.unwrap();
            Session { node, events }
        }
    };
    let mut alice = start("Alice").await;
    let bob = start("Bob").await;
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &relay) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;

    gate.set(false);
    bob.node.leave(&gid.0).unwrap().unwrap();
    if restart_leaver {
        bob.node.shutdown().await.unwrap();
        drop(bob);
        gate.set(true);
        let _bob = start("Bob").await;
    } else {
        gate.set(true);
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
        let (node, events) = Node::start(SqliteProvider::open(&alice_db).unwrap(), config(&relay, "Alice", None)).await.unwrap();
        Session { node, events }
    };
    let mut alice = start().await;
    let mut bob = session(&relay, "Bob").await;
    let carol = session(&relay, "Carol").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Bob and Carol have both Adds", || [&bob, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 3)).await;
    alice.node.shutdown().await.unwrap();
    drop(alice);

    bob.node.leave(&gid.0).unwrap();
    bob.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
    bob.node.join(&carol.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    // Only Carol holds the leave: were Bob online, Alice's wait could end at her connection to him before Carol's lands.
    bob.node.shutdown().await.unwrap();
    let mut alice = start().await;
    let leaves = || alice.node.messages(&gid.0).unwrap().iter().filter(|m| m.payload["type"] == "leave").count();
    // Alice applies the removal before it reaches Carol, which holds the leave: it is told the leave lost, or holds it.
    let mut lost = false;
    eventually("Alice settles the old leave", || {
        while let Ok(event) = alice.events.try_recv() {
            lost |= matches!(event, Event::Lost(_));
        }
        lost || leaves() == 1
    })
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(alice.node.members(&gid.0).unwrap().len(), 3, "Bob is still in");
    assert_eq!(carol.node.members(&gid.0).unwrap().len(), 3, "Bob is still in");
    alice.node.shutdown().await.unwrap();
}

/// A `leave` sent while the membership service is unreachable is finished by the other member, the leaver restarted.
#[tokio::test(flavor = "multi_thread")]
async fn a_pending_leave_is_finished_after_a_restart() {
    held_leave("leave-restart", true).await;
}

/// A `leave` sent while the membership service is unreachable is finished by the other member once the service is back.
#[tokio::test(flavor = "multi_thread")]
async fn a_pending_leave_is_finished_once_the_log_is_reachable() {
    held_leave("leave-reachable", false).await;
}

/// A commit reaches a member that no peer brings it to as the member starts: it opens its group's log, and reads it, as
/// it moved.
#[tokio::test(flavor = "multi_thread")]
async fn a_commit_reaches_a_member_with_no_peer_online_as_it_starts() {
    let relay = relay().await;
    let dir = folder("opened");
    std::fs::create_dir_all(&dir).unwrap();
    let mut alice = stored(&relay, "Alice", &dir.join("alice.db")).await;
    let bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    bob.node.shutdown().await.unwrap();
    drop(bob);
    alice.node.change_settings(&gid.0, |s| Settings { name: "Moved".into(), ..s }).await.unwrap();
    alice.node.shutdown().await.unwrap();

    let bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
    eventually("Bob reads the commit", || bob.node.settings(&gid.0).unwrap().name == "Moved").await;
    bob.node.shutdown().await.unwrap();
}

/// Each commit moves a group to its new epoch's log, at a reference only the epoch's members can derive: a joiner reads
/// from the log its Add moved the group to, and a removed member is left behind on the last one it could name.
#[tokio::test(flavor = "multi_thread")]
async fn each_commit_moves_the_group_to_its_new_epochs_log() {
    let relay = relay().await;
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let mut carol = session(&relay, "Carol").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let mut logs = vec![alice.node.log(&gid.0).unwrap()];
    alice.node.send(&gid.0, &message("before anyone"), None).await.unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        let log = joiner.node.log(&gid.0).unwrap();
        assert!(!logs.contains(&log), "the Add moved the group to a new log");
        assert_eq!(alice.node.log(&gid.0).unwrap(), log, "the joiner reads from the log its Add moved the group to");
        logs.push(log);
    }
    alice.node.remove(&gid.0, &carol.node.key_in(&gid.0).0).await.unwrap();
    carol.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
    assert!(!logs.contains(&alice.node.log(&gid.0).unwrap()), "the Remove moved the group to a log Carol cannot name");
    let after = alice.node.send(&gid.0, &message("after Carol"), None).await.unwrap();
    let got = bob.until(|e| match e {
        Event::Message(m) if m.payload == message("after Carol") => Some(m.id),
        _ => None,
    }).await;
    assert_eq!(got, after);
    for session in [&alice, &bob, &carol] {
        session.node.shutdown().await.unwrap();
    }
}

/// A message sent while an Add is in flight, which its author seals again in the joiner's epoch, never reaches the
/// joiner; the author's next message reaches it at once, missing nothing: what was sent before a member joined is not
/// its to have.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_sent_while_an_add_is_in_flight_never_reaches_the_joiner() {
    let relay = relay().await;
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let mut carol = session(&relay, "Carol").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    alice.node.send(&gid.0, &message("before Carol"), None).await.unwrap();
    carol.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let after = alice.node.send(&gid.0, &message("after Carol"), None).await.unwrap();
    let got = carol.until(|e| match e {
        Event::Message(m) if m.id == after => Some(m),
        _ => None,
    }).await;
    assert!(got.missing.is_empty(), "{got:?}");
    let held: Vec<Value> = carol.node.messages(&gid.0).unwrap().into_iter().map(|m| m.payload).collect();
    assert_eq!(held, [message("after Carol")]);
    for text in ["before Carol", "after Carol"] {
        bob.until(|e| matches!(e, Event::Message(m) if m.payload == message(text)).then_some(())).await;
    }
    for session in [&alice, &bob, &carol] {
        session.node.shutdown().await.unwrap();
    }
}

/// Two members that leave at once: one's removal of the other wins, and the one left alone forgets the group.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaver_left_alone_forgets_the_group() {
    let relay = relay().await;
    let mut alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    alice.node.leave(&gid.0).unwrap();
    bob.node.leave(&gid.0).unwrap();
    eventually("both forgot the group", || alice.node.groups().is_empty() && bob.node.groups().is_empty()).await;
}

/// Changes that another member's commit already made answer ok and commit nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_made_moot_commits_nothing() {
    let relay = relay().await;
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let carol = session(&relay, "Carol").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
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

/// A log its service let go is no removal while a peer brings the commits the member missed, within `WAIT`: the member keeps
/// its state and catches up from the peer, across the two logs the group moved through meanwhile.
#[tokio::test(flavor = "multi_thread")]
async fn a_log_let_go_is_no_removal_while_a_peer_brings_the_commits() {
    let relay = relay().await;
    let dir = folder("let-go-catch-up");
    let (membership, _service) = served(&relay, &dir).await;
    let (gate, _reaching) = Gate::new(Some(&membership));
    let start = |name: &'static str| {
        let (relay, dir, gate) = (&relay, &dir, gate.clone());
        async move {
            let mut config = config(relay, name, None);
            config.post = gate.post(name, relay.post());
            config.files = Some(dir.join(format!("{name}-files")));
            let (node, events) = Node::start(SqliteProvider::open(&dir.join(format!("{name}.db"))).unwrap(), config).await.unwrap();
            Session { node, events }
        }
    };
    let mut alice = start("Alice").await;
    let bob = start("Bob").await;
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &relay) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let held = bob.node.send(&gid.0, &message("held before refusal"), None).await.unwrap();
    let file = bob.node.add_file(&gid.0, b"held file".to_vec()).await.unwrap();
    let members = bob.node.members(&gid.0).unwrap();
    let epoch = bob.node.epoch(&gid.0).unwrap();
    let key = bob.node.key_in(&gid.0);
    let log_ref: [u8; 32] = bob.node.log(&gid.0).unwrap().0.try_into().unwrap();
    bob.node.shutdown().await.unwrap();
    drop(bob);

    for name in ["Sooner", "Later"] {
        alice.node.change_settings(&gid.0, |s| Settings { name: name.into(), ..s }).await.unwrap();
    }
    let missed = alice.node.send(&gid.0, &message("recover from the peer"), None).await.unwrap();
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let store = Store::open(&dir.join("membership")).unwrap();
    store.expire(lmk_node::now() / lmk_membership::store::DAY_MS + 1).unwrap();
    let expired: bool = rusqlite::Connection::open(dir.join("membership").join("membership.db")).unwrap()
        .query_row("SELECT EXISTS(SELECT 1 FROM expired WHERE reference=?)", [log_ref], |r| r.get(0)).unwrap();
    assert!(expired);
    let mut bob = start("Bob").await;
    let error = bob.node.read_group(&gid.0).await.unwrap_err();
    assert!(error.is::<lmk_membership::Expired>(), "{error:#}");
    // Settings runs through the same FIFO work driver as a removal would, so seeing this later commit's event shows
    // that no removal was queued before it.
    let barrier = bob.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.change_settings(&barrier.0, |s| Settings { name: "barrier".into(), ..s }).await.unwrap();
    bob.until(|e| {
        assert!(!matches!(&e, Event::Removed { group, .. } if group == &gid), "refusal removed the group");
        matches!(e, Event::Settings { group, .. } if group == barrier).then_some(())
    }).await;
    assert!(bob.node.groups().contains(&gid));
    assert_eq!(bob.node.members(&gid.0).unwrap(), members);
    assert_eq!(bob.node.epoch(&gid.0).unwrap(), epoch);
    assert_eq!(bob.node.key_in(&gid.0), key);
    assert_eq!(bob.node.message(&gid.0, &held.0).unwrap().unwrap().payload, message("held before refusal"));
    assert_eq!(bob.node.file(&file).await.unwrap().unwrap(), b"held file");
    bob.node.shutdown().await.unwrap();

    gate.set(false);
    let mut bob = start("Bob").await;
    assert_eq!(bob.node.members(&gid.0).unwrap(), members);
    let alice = start("Alice").await;
    bob.until(|e| {
        assert!(!matches!(&e, Event::Removed { group, .. } if group == &gid));
        matches!(e, Event::Settings { group, settings, .. } if group == gid && settings.name == "Later").then_some(())
    }).await;
    eventually("Bob takes the message beyond the expired history", || bob.node.message(&gid.0, &missed.0).unwrap().is_some()).await;
    assert_eq!(bob.node.message(&gid.0, &missed.0).unwrap().unwrap().payload, message("recover from the peer"));
    assert_eq!(bob.node.key_in(&gid.0), key);
    assert_eq!(bob.node.members(&gid.0).unwrap(), members);
    assert!(bob.node.epoch(&gid.0).unwrap() > epoch);
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();
}

/// An identity whose directory its service let go ends on the devices that followed it: each forgets its identity group,
/// which reports its removal, and the identity is no more.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_directory_ends_its_identity_on_its_devices() {
    let relay = relay().await;
    let dir = folder("expired-directory");
    let (membership, _service) = served(&relay, &dir).await;
    let start = |name: &'static str| {
        let (relay, dir) = (&relay, &dir);
        async move {
            let device = Device::new(name);
            let config = config(relay, name, Some(device.clone()));
            let (node, events) = Node::start(SqliteProvider::open(&dir.join(format!("{name}.db"))).unwrap(), config).await.unwrap();
            let devices = Identity::new(node.clone(), device, Arc::new(|_: &Device| Ok(())));
            (Session { node, events }, devices)
        }
    };
    let (mut alice, alice_devices) = start("Alice").await;
    let (bob, bob_devices) = start("Bob").await;
    alice_devices.create("Plan", membership).await.unwrap();
    let link = lmk_proto::links::Invite::parse(&alice_devices.invite().await.unwrap()).unwrap();
    bob_devices.join(&link).await.unwrap();
    let gid = devices_group(&bob.node);
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    // The duties read the directory, which this device follows from then on.
    bob_devices.duties(&gid.0).await.unwrap();
    bob.node.shutdown().await.unwrap();
    drop((bob, bob_devices));
    alice.node.shutdown().await.unwrap();
    drop((alice, alice_devices));
    let store = Store::open(&dir.join("membership")).unwrap();
    store.expire(lmk_node::now() / lmk_membership::store::DAY_MS + 1).unwrap();

    let (mut bob, bob_devices) = start("Bob").await;
    bob.node.open_logs().await;
    bob.until(|e| matches!(&e, Event::Removed { group, kind, .. } if *group == gid && kind == IDENTITY).then_some(())).await;
    let text = bob.until(|e| match e {
        Event::Warning { group, text } if group == Some(gid.clone()) => Some(text),
        _ => None,
    }).await;
    assert!(text.contains("identity join"), "{text}");
    assert!(!bob.node.groups().contains(&gid));
    assert!(bob_devices.identity().is_none());
    bob.node.shutdown().await.unwrap();
}

/// Runs `test` on a runtime whose every thread reads the system's clock as `clock` does: the nodes, relay and service
/// of one test share the time it moves to, and no other test's threads do.
fn on_clock(clock: fn() -> u64, test: impl std::future::Future<Output = ()>) {
    let runtime = tokio::runtime::Builder::new_multi_thread().on_thread_start(move || lmk_proto::clock::set(clock)).enable_all().build().unwrap();
    runtime.block_on(async {
        lmk_proto::clock::set(clock);
        test.await
    });
}

const DAY_MS: u64 = 24 * 3600 * 1000;
const HOUR_MS: u64 = 3600 * 1000;

/// The records of who added whom keep the group's members, the joins of the last H and those whose invites still admit:
/// a member removed longer than H ago leaves none.
#[test]
fn a_group_forgets_who_added_its_members_once_they_are_gone_past_h() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("forgotten-adds");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("alice.db");
        let alice = stored(&relay, "Alice", &db).await;
        let gid = alice.node.create(Settings { carry: 2, ..settings(CHAT, &relay) }, None).unwrap();
        let mut keys = Vec::new();
        for (name, valid) in [("Bob", INVITE_VALID), ("Carol", INVITE_VALID), ("Dave", 7 * DAY_MS)] {
            let joiner = session(&relay, name).await;
            joiner.node.join(&alice.node.invite(&gid.0, None, valid).await.unwrap(), None).await.unwrap();
            keys.push(joiner.node.key());
            joiner.node.shutdown().await.unwrap();
        }
        for key in [&keys[0], &keys[2]] {
            assert!(alice.node.remove(&gid.0, &key.0).await.unwrap());
        }
        alice.node.shutdown().await.unwrap();
        drop(alice);
        let state = || {
            let mut provider = SqliteProvider::open(&db).unwrap();
            let state = String::from_utf8(provider.get(&[b"group/".as_slice(), &gid.0].concat()).unwrap().unwrap()).unwrap();
            provider.close().unwrap();
            state
        };
        assert!(["Bob", "Carol", "Dave"].iter().all(|name| state().contains(&format!("\"name\":\"{name}\""))));

        SHIFT.store(3 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        let alice = stored(&relay, "Alice", &db).await;
        eventually("Bob's record is forgotten", || !state().contains("\"name\":\"Bob\"")).await;
        assert!(state().contains("\"name\":\"Carol\""), "a member's record stays");
        assert!(state().contains("\"name\":\"Dave\""), "a record stays while its invite admits");
        alice.node.shutdown().await.unwrap();
    });
}

/// A member whose epoch's log its service let go is removed by the others, which hold the commits it missed: the hourly
/// check finds the log gone, and their next pass removes the member.
#[test]
fn a_member_in_an_epoch_the_service_let_go_is_removed_by_the_others() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let mut alice = session(&relay, "Alice").await;
        let bob = session(&relay, "Bob").await;
        let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        bob.node.shutdown().await.unwrap();
        alice.node.change_settings(&gid.0, |s| Settings { name: "Later".into(), ..s }).await.unwrap();
        alice.node.sync_members().await.unwrap();
        assert_eq!(alice.node.members(&gid.0).unwrap().len(), 2, "the log Bob is in is not gone yet");

        SHIFT.store(8 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        alice.node.open_logs().await;
        while relay.membership.expire().await {}
        alice.node.sync_members().await.unwrap();
        alice.until(|e| matches!(e, Event::Left { member, .. } if member.name == "Bob").then_some(())).await;
        assert_eq!(alice.node.members(&gid.0).unwrap().len(), 1);
        alice.node.shutdown().await.unwrap();
    });
}

/// A member away six days resumes: the service keeps the log of the commit it missed for a week.
#[test]
fn a_member_away_six_days_resumes() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("six-days");
        std::fs::create_dir_all(&dir).unwrap();
        let mut alice = session(&relay, "Alice").await;
        let bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
        let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        bob.node.shutdown().await.unwrap();
        drop(bob);
        alice.node.change_settings(&gid.0, |s| Settings { name: "Later".into(), ..s }).await.unwrap();

        SHIFT.store(6 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        let mut bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
        eventually("Bob applied the rename", || bob.node.settings(&gid.0).is_ok_and(|s| s.name == "Later")).await;
        alice.node.send(&gid.0, &message("welcome back"), None).await.unwrap();
        bob.until(|e| matches!(e, Event::Message(m) if m.payload == message("welcome back")).then_some(())).await;
        alice.node.shutdown().await.unwrap();
        bob.node.shutdown().await.unwrap();
    });
}

/// A member whose service let its log go, and which no peer brings the commits of within `WAIT`, leaves the group, and is
/// told it did, with nothing kept: the commit that moved the group on is in that log, which no member can read now.
#[test]
fn a_member_whose_log_the_service_let_go_leaves_when_no_peer_brings_it_within_wait() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("let-go-leaver");
        let mut alice = session(&relay, "Alice").await;
        let bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
        let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        bob.node.shutdown().await.unwrap();
        alice.node.change_settings(&gid.0, |s| Settings { name: "Later".into(), ..s }).await.unwrap();
        alice.node.shutdown().await.unwrap();

        SHIFT.store(8 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        let mut bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
        bob.node.open_logs().await;
        assert!(bob.node.groups().contains(&gid), "a log let go is left only after WAIT with no entry of it brought");
        SHIFT.fetch_add(lmk_net::peers::WAIT + 60_000, std::sync::atomic::Ordering::Relaxed);
        bob.node.open_logs().await;
        let (by, not_kept) = bob.until(|e| match e {
            Event::Removed { group, by, not_kept, .. } if group == gid => Some((by, not_kept)),
            _ => None,
        }).await;
        assert!(by.is_none() && not_kept.is_empty(), "no commit removed it: its own log did");
        assert!(!bob.node.groups().contains(&gid));
        bob.node.shutdown().await.unwrap();
    });
}

/// A group nobody is online in for longer than the retention ends for each member as it comes back: its current log,
/// which they opened last as they went, is gone.
#[test]
fn a_group_nobody_is_online_in_past_the_retention_ends() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("quiet-group");
        std::fs::create_dir_all(&dir).unwrap();
        let db = |name: &str| dir.join(format!("{name}.db"));
        let mut alice = stored(&relay, "Alice", &db("alice")).await;
        let bob = stored(&relay, "Bob", &db("bob")).await;
        let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        for session in [alice, bob] {
            session.node.open_logs().await;
            session.node.shutdown().await.unwrap();
        }

        SHIFT.store(8 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        for name in ["alice", "bob"] {
            let mut member = stored(&relay, name, &db(name)).await;
            member.node.open_logs().await;
            SHIFT.fetch_add(lmk_net::peers::WAIT + 60_000, std::sync::atomic::Ordering::Relaxed);
            member.node.open_logs().await;
            member.until(|e| matches!(&e, Event::Removed { group, by: None, .. } if *group == gid).then_some(())).await;
            assert!(member.node.groups().is_empty());
            member.node.shutdown().await.unwrap();
        }
    });
}

/// The last member to go offline, 23 hours after its group's last commit, comes back to the group six and a half days
/// later: it opened the group's log every hour while it was online.
#[test]
fn a_group_whose_last_member_went_a_day_after_its_last_commit_lives_six_and_a_half_days() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("last-member");
        std::fs::create_dir_all(&dir).unwrap();
        let db = |name: &str| dir.join(format!("{name}.db"));
        let mut alice = stored(&relay, "Alice", &db("alice")).await;
        let bob = stored(&relay, "Bob", &db("bob")).await;
        let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        bob.node.shutdown().await.unwrap();
        drop(bob);
        SHIFT.store(23 * HOUR_MS, std::sync::atomic::Ordering::Relaxed);
        alice.node.open_logs().await;
        alice.node.shutdown().await.unwrap();
        drop(alice);

        SHIFT.store(23 * HOUR_MS + 13 * DAY_MS / 2, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        let alice = stored(&relay, "Alice", &db("alice")).await;
        let mut bob = stored(&relay, "Bob", &db("bob")).await;
        alice.node.open_logs().await;
        SHIFT.fetch_add(lmk_net::peers::WAIT + 60_000, std::sync::atomic::Ordering::Relaxed);
        alice.node.open_logs().await;
        alice.node.send(&gid.0, &message("still here"), None).await.unwrap();
        bob.until(|e| matches!(e, Event::Message(m) if m.payload == message("still here")).then_some(())).await;
        alice.node.shutdown().await.unwrap();
        bob.node.shutdown().await.unwrap();
    });
}

/// A device that missed its identity's commits past the retention is revoked: the identity's other device removes it from
/// the identity group, which drops it from the directory, so its sessions leave the chats they are in, and it is told. The
/// device in use carries on, its identity's directory kept by its touches.
#[test]
fn a_device_missing_its_identitys_commits_past_the_retention_is_revoked_and_told() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("device-behind");
        let start = |name: &'static str| {
            let (relay, dir) = (&relay, &dir);
            async move {
                let device = Device::new(name);
                let config = config(relay, name, Some(device.clone()));
                let (node, events) = Node::start(SqliteProvider::open(&dir.join(format!("{name}.db"))).unwrap(), config).await.unwrap();
                let devices = Identity::new(node.clone(), device, Arc::new(|_: &Device| Ok(())));
                (Session { node, events }, devices)
            }
        };
        let (mut laptop, laptop_devices) = start("laptop").await;
        routed(&mut laptop, laptop_devices.clone());
        let identity = laptop_devices.create("Plan", relay.service.clone()).await.unwrap();
        let link = lmk_proto::links::Invite::parse(&laptop_devices.invite().await.unwrap()).unwrap();
        let (phone, phone_devices) = start("phone").await;
        phone_devices.join(&link).await.unwrap();
        let gid = devices_group(&laptop.node);
        laptop.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        // The chat is between the devices' sessions, which their devices certify.
        let mut agent = session(&relay, "laptop").await;
        let phone_agent = session(&relay, "phone").await;
        let chat = agent.node.create(settings(CHAT, &relay), None).unwrap();
        let invite = agent.node.invite(&chat.0, None, INVITE_VALID).await.unwrap();
        phone_agent.node.join(&invite, Some(phone_devices.certify(&phone_agent.node.key().0).unwrap())).await.unwrap();
        agent.until(|e| matches!(&e, Event::Joined { group, member, .. } if *group == chat && member.name == "phone").then_some(())).await;
        // The duties read the directory, which the phone follows from then on. The phone is away before the commit that
        // moves the group on, so that it never reaches the epoch the laptop's later commits are in.
        phone_devices.duties(&gid.0).await.unwrap();
        phone.node.shutdown().await.unwrap();
        phone_agent.node.shutdown().await.unwrap();
        drop((phone, phone_devices, phone_agent));
        laptop_devices.rename("Renamed").await.unwrap();

        SHIFT.store(5 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        laptop_devices.rename("Again").await.unwrap();
        SHIFT.store(9 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        laptop.node.open_logs().await;
        agent.node.open_logs().await;
        while relay.membership.expire().await {}
        laptop.node.sync_members().await.unwrap();
        laptop.until(|e| matches!(e, Event::Left { member, .. } if member.name == "phone").then_some(())).await;
        assert_eq!(laptop.node.members(&gid.0).unwrap().len(), 1);
        lists(&laptop.node, &identity, &[laptop_devices.key().unwrap()]).await;
        agent.node.send(&chat.0, &message("after the phone"), None).await.unwrap();
        agent.until(|e| matches!(&e, Event::Revoked { group, removed, .. } if *group == chat && removed.iter().any(|m| m.name == "phone")).then_some(())).await;
        assert_eq!(agent.node.members(&chat.0).unwrap().len(), 1, "the phone's session left the chat");
        assert!(laptop_devices.identity().is_some(), "the device in use keeps its identity");

        let (mut phone, phone_devices) = start("phone").await;
        phone.node.open_logs().await;
        SHIFT.fetch_add(lmk_net::peers::WAIT + 60_000, std::sync::atomic::Ordering::Relaxed);
        phone.node.open_logs().await;
        phone.until(|e| matches!(&e, Event::Removed { group, kind, .. } if *group == gid && kind == IDENTITY).then_some(())).await;
        let text = phone.until(|e| match e {
            Event::Warning { group, text } if group == Some(gid.clone()) => Some(text),
            _ => None,
        }).await;
        assert!(text.contains("identity join"), "{text}");
        assert!(phone_devices.identity().is_none());
        phone.node.shutdown().await.unwrap();
        laptop.node.shutdown().await.unwrap();
        agent.node.shutdown().await.unwrap();
    });
}

/// A member that left behind, by its log let go, comes back by invite with the key it had: that key is still in the tree
/// until a commit of its own removes it, which comes before the Add that lets it in again.
#[test]
fn a_joiner_whose_key_is_in_the_tree_of_a_lapsed_member_is_removed_before_its_add() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("lapsed-rejoin");
        let mut alice = stored(&relay, "Alice", &dir.join("alice.db")).await;
        let bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
        let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        bob.node.shutdown().await.unwrap();
        alice.node.change_settings(&gid.0, |s| Settings { name: "Later".into(), ..s }).await.unwrap();

        SHIFT.store(8 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        alice.node.open_logs().await;
        while relay.membership.expire().await {}
        let mut bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
        bob.node.open_logs().await;
        SHIFT.fetch_add(lmk_net::peers::WAIT + 60_000, std::sync::atomic::Ordering::Relaxed);
        bob.node.open_logs().await;
        bob.until(|e| matches!(&e, Event::Removed { group, .. } if *group == gid).then_some(())).await;
        bob.node.shutdown().await.unwrap();

        let bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
        bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(&e, Event::Left { member, .. } if member.name == "Bob").then_some(())).await;
        alice.until(|e| matches!(&e, Event::Joined { member, .. } if member.name == "Bob").then_some(())).await;
        assert_eq!(alice.node.members(&gid.0).unwrap().len(), 2);
        alice.node.shutdown().await.unwrap();
        bob.node.shutdown().await.unwrap();
    });
}

/// An identity whose directory no device touched in the retention ends for the chats its sessions are in: the members drop
/// its session as a dropped device's, and remove it, and its device forgets the identity, telling so.
#[test]
fn an_untouched_directory_ends_its_identity_for_the_chats_its_sessions_are_in() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let (mut laptop, laptop_devices) = device(&relay, "laptop").await;
        routed(&mut laptop, laptop_devices.clone());
        let bob = laptop_devices.create("Bob", relay.service.clone()).await.unwrap();
        lists(&laptop.node, &bob, &[laptop_devices.key().unwrap()]).await;
        let mut alice = session(&relay, "Alice").await;
        let chat = alice.node.create(settings(CHAT, &relay), None).unwrap();
        let link = alice.node.invite(&chat.0, None, INVITE_VALID).await.unwrap();
        let agent = session(&relay, "laptop").await;
        agent.node.join(&link, Some(laptop_devices.certify(&agent.node.key().0).unwrap())).await.unwrap();
        alice.checked(&chat, "laptop", true).await;

        SHIFT.store(8 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        alice.node.open_logs().await;
        while relay.membership.expire().await {}
        alice.node.send(&chat.0, &message("after the laptop"), None).await.unwrap();
        alice.until(|e| matches!(&e, Event::Left { member, .. } if member.name == "laptop").then_some(())).await;
        alice.until(|e| matches!(&e, Event::Revoked { removed, .. } if removed.iter().any(|m| m.name == "laptop")).then_some(())).await;
        assert_eq!(alice.node.members(&chat.0).unwrap().len(), 1);

        laptop.node.open_logs().await;
        laptop.until(|e| matches!(&e, Event::Warning { text, .. } if text.contains("identity join")).then_some(())).await;
        assert!(laptop_devices.identity().is_none());
        for node in [&laptop.node, &agent.node, &alice.node] {
            node.shutdown().await.unwrap();
        }
    });
}

/// A device that asks its identity to leave, with another device staying, is removed by that device and is not warned:
/// only a removal it did not ask for is.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_leaves_its_identity_is_removed_without_a_warning() {
    let relay = relay().await;
    let (mut laptop, laptop_devices) = device(&relay, "laptop").await;
    routed(&mut laptop, laptop_devices.clone());
    let identity = laptop_devices.create("Bob", relay.service.clone()).await.unwrap();
    let (mut phone, phone_devices) = device(&relay, "phone").await;
    phone_devices.join(&lmk_proto::links::Invite::parse(&laptop_devices.invite().await.unwrap()).unwrap()).await.unwrap();
    let gid = devices_group(&laptop.node);
    lists(&laptop.node, &identity, &[laptop_devices.key().unwrap(), phone_devices.key().unwrap()]).await;

    assert!(!phone_devices.leave().await.unwrap(), "the laptop stays in the identity");
    lists(&laptop.node, &identity, &[laptop_devices.key().unwrap()]).await;
    laptop_devices.duties(&gid.0).await.unwrap();
    laptop.until(|e| matches!(&e, Event::Left { member, .. } if member.name == "phone").then_some(())).await;
    phone.until(|e| matches!(&e, Event::Removed { group, kind, .. } if *group == gid && kind == IDENTITY).then_some(())).await;
    phone.node.shutdown().await.unwrap();
    // The warning, were there one, is sent with the removal: it would be read by now.
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(event) = phone.events.try_recv() {
        assert!(!matches!(&event, Event::Warning { text, .. } if text.contains("identity join")), "a device that left is not warned");
    }
    laptop.node.shutdown().await.unwrap();
}

/// A device last online 23 hours after its identity's last commit keeps its identity six and a half days later: it
/// touched its directory, and opened its identity group's log, every hour.
#[test]
fn a_device_last_online_a_day_after_its_identitys_last_commit_keeps_it_six_and_a_half_days() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let (mut laptop, laptop_devices) = device(&relay, "laptop").await;
        routed(&mut laptop, laptop_devices.clone());
        let bob = laptop_devices.create("Bob", relay.service.clone()).await.unwrap();
        lists(&laptop.node, &bob, &[laptop_devices.key().unwrap()]).await;
        SHIFT.store(23 * HOUR_MS, std::sync::atomic::Ordering::Relaxed);
        laptop.node.open_logs().await;
        SHIFT.store(23 * HOUR_MS + 13 * DAY_MS / 2, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        laptop.node.open_logs().await;
        SHIFT.fetch_add(lmk_net::peers::WAIT + 60_000, std::sync::atomic::Ordering::Relaxed);
        laptop.node.open_logs().await;
        laptop.node.sync_members().await.unwrap();
        assert_eq!(laptop_devices.identity().map(|(_, name)| name), Some("Bob".into()));
        laptop.node.shutdown().await.unwrap();
    });
}

/// A session on SQLite at `db`, which survives a restart.
async fn stored(relay: &Relay, name: &str, db: &Path) -> Session<SqliteProvider> {
    stored_with(relay, name, db, relay.post()).await
}

/// A session on SQLite at `db` that posts to membership services through `post`.
async fn stored_with(relay: &Relay, name: &str, db: &Path, post: Post) -> Session<SqliteProvider> {
    let (node, events) = Node::start(SqliteProvider::open(db).unwrap(), Config { post, ..config(relay, name, None) }).await.unwrap();
    Session { node, events }
}

/// A commit keeps the messages its committer holds, and a member that comes back with none of them loses those no
/// online member holds: the commit after the one that kept them cannot wait for them, and tells the member `Lost` with
/// their author's seqs.
#[tokio::test(flavor = "multi_thread")]
async fn an_announced_loss_reaches_every_member() {
    let relay = relay().await;
    let dir = folder("lost");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, "Alice", &db("alice")).await;
    let bob = stored(&relay, "Bob", &db("bob")).await;
    let carol = stored(&relay, "Carol", &db("carol")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Bob and Carol have both Adds", || [&bob, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 3)).await;
    carol.node.shutdown().await.unwrap();
    drop(carol);

    // Alice holds Bob's message and keeps it in a commit; then Alice and Bob stop, and Carol, back, has no holder.
    let sent = bob.node.send(&gid.0, &message("only Alice and Bob hold this"), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    for name in ["One", "Two"] {
        alice.node.change_settings(&gid.0, |s| Settings { name: name.into(), ..s }).await.unwrap();
    }
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();

    let mut carol = stored(&relay, "Carol", &db("carol")).await;
    carol.node.open_logs().await;
    let lost = carol.until(|e| match e {
        Event::Lost(lost) => Some(lost),
        _ => None,
    }).await;
    assert_eq!(lost.member.name, "Carol");
    assert_eq!((lost.messages[0].from.name.as_str(), lost.messages[0].seqs.clone()), ("Bob", vec![1]));
    assert!(carol.node.message(&gid.0, &sent.0).unwrap().is_none(), "Carol never took the message");
    carol.node.shutdown().await.unwrap();
}

static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The system's clock, moved on by `SHIFT`.
fn shifted() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
}

/// A member catching up does not wait for what a commit made more than H ago kept: Carol, back 8 days later with no
/// holder of Bob's kept message online, is told it lost at once rather than after `HEAR`. Every thread of the runtime,
/// the service's included, reads the shifted clock.
#[test]
fn catching_up_waits_for_nothing_a_commit_older_than_h_kept() {
    let runtime = tokio::runtime::Builder::new_multi_thread().on_thread_start(|| lmk_proto::clock::set(shifted)).enable_all().build().unwrap();
    runtime.block_on(catching_up());
}

async fn catching_up() {
    let relay = relay().await;
    let dir = folder("lost-old");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, "Alice", &db("alice")).await;
    let bob = stored(&relay, "Bob", &db("bob")).await;
    let carol = stored(&relay, "Carol", &db("carol")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Bob and Carol have both Adds", || [&bob, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 3)).await;
    carol.node.shutdown().await.unwrap();
    drop(carol);

    bob.node.send(&gid.0, &message("only Alice and Bob hold this"), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    for name in ["One", "Two"] {
        alice.node.change_settings(&gid.0, |s| Settings { name: name.into(), ..s }).await.unwrap();
    }
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();

    SHIFT.store(8 * 24 * 3600 * 1000, std::sync::atomic::Ordering::Relaxed);
    let started = std::time::Instant::now();
    let mut carol = stored(&relay, "Carol", &db("carol")).await;
    carol.node.open_logs().await;
    let lost = carol.until(|e| match e {
        Event::Lost(lost) => Some(lost),
        _ => None,
    }).await;
    assert!(started.elapsed() < Duration::from_millis(lmk_net::peers::HEAR), "took {:?}", started.elapsed());
    assert_eq!((lost.messages[0].from.name.as_str(), lost.messages[0].seqs.clone()), ("Bob", vec![1]));
    carol.node.shutdown().await.unwrap();
}

/// The members a public log entry drops are removed by one commit.
#[tokio::test(flavor = "multi_thread")]
async fn a_pass_removes_every_member_due_in_one_commit() {
    let relay = relay().await;
    let dir = folder("one-commit");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let mut alice = session(&relay, "Alice").await;
    let (carol, laptop) = identity(&relay, &alice.node, membership.clone()).await;
    let (tablet_key, phone_key): ([u8; 32], [u8; 32]) = (lmk_core::random(), lmk_core::random());
    let log = alice.node.read_public(&carol).await.unwrap();
    let all = vec![lmk_core::device::public(&laptop).into(), lmk_core::device::public(&tablet_key).into(), lmk_core::device::public(&phone_key).into()];
    publish(&relay, &alice.node, &carol, log.next(&laptop, all)).await;
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &relay) }, None).unwrap();
    let (tablet, phone) = (session(&relay, "tablet").await, session(&relay, "phone").await);
    for (joiner, device, name) in [(&tablet, &tablet_key, "tablet"), (&phone, &phone_key, "phone")] {
        let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
        joiner.node.join(&link, Some(certificate(&carol, device, &joiner.node.key(), "Carol", "device"))).await.unwrap();
        alice.checked(&gid, name, true).await;
    }
    for session in [&tablet, &phone] {
        session.node.shutdown().await.unwrap();
    }
    let epoch = alice.node.epoch(&gid.0).unwrap();
    let log = alice.node.read_public(&carol).await.unwrap();
    publish(&relay, &alice.node, &carol, log.next(&laptop, vec![lmk_core::device::public(&laptop).into()])).await;
    let mut removed = alice.until(|e| match e {
        Event::Revoked { removed, .. } => Some(removed.into_iter().map(|m| m.name).collect::<Vec<_>>()),
        _ => None,
    }).await;
    removed.sort();
    assert_eq!(removed, ["phone", "tablet"]);
    assert_eq!((alice.node.epoch(&gid.0).unwrap(), alice.node.members(&gid.0).unwrap().len()), (epoch + 1, 1));
}

/// Members update their leaves every T. A leaver that updates while the others are away reseals its `leave` in each
/// epoch it moves to, and is removed once a member that holds it is back.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaver_asks_again_while_it_updates_every_t() {
    let relay = relay().await;
    let dir = folder("leave-again-t");
    std::fs::create_dir_all(&dir).unwrap();
    let alice_db = dir.join("alice.db");
    let alice = stored(&relay, "Alice", &alice_db).await;
    let mut bob = session(&relay, "Bob").await;
    let gid = alice.node.create(Settings { update: 2, ..settings(CHAT, &relay) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.node.shutdown().await.unwrap();
    drop(alice);

    let epoch = bob.node.epoch(&gid.0).unwrap();
    bob.node.leave(&gid.0).unwrap().unwrap();
    eventually("Bob updates its leaf", || bob.node.epoch(&gid.0).unwrap() >= epoch + 2).await;

    let alice = stored(&relay, "Alice", &alice_db).await;
    bob.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
    eventually("Alice is alone", || alice.node.members(&gid.0).unwrap().len() == 1).await;
    alice.node.shutdown().await.unwrap();
}

/// A stopped stored member's record of a message of `gid`, as its database keeps it.
fn record(db: &Path, gid: &Bytes, id: &Bytes) -> Value {
    let provider = SqliteProvider::open(db).unwrap();
    let key = [b"node/message/".as_slice(), &gid.0, b"/", &id.0].concat();
    serde_json::from_slice(&provider.get(&key).unwrap().unwrap()).unwrap()
}

/// The sealing a stopped stored member holds of a message of `gid`: its epoch, and its ciphertext.
fn sealed(db: &Path, gid: &Bytes, id: &Bytes) -> (u64, Bytes) {
    serde_json::from_value(record(db, gid, id)["sealing"].clone()).unwrap()
}

/// A stopped stored member's iroh key, and its MLS session, which a hand stands in for it with.
fn member_of(db: &Path) -> (iroh::SecretKey, Mls) {
    let provider = SqliteProvider::open(db).unwrap();
    (lmk_node::iroh_key(&provider).unwrap(), Mls::load(&provider).unwrap())
}

/// The newest head of a log a session holds.
fn held_head(provider: &SqliteProvider, log: &Bytes) -> Option<Head> {
    let record: Value = serde_json::from_slice(&provider.get(&[b"node/log/".as_slice(), &log.0].concat()).unwrap().unwrap()).unwrap();
    serde_json::from_value(record["head"].clone()).unwrap()
}

/// A peer speaking the peer protocol by hand, on a connection it opens to a node.
struct Hand {
    _endpoint: iroh::Endpoint,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

async fn hand<P: Provider + Send + 'static>(relay: &Relay, key: iroh::SecretKey, to: &Node<P>) -> Hand {
    let endpoint = lmk_net::builder([relay.url.clone()]).secret_key(key).ca_tls_config(CaTlsConfig::custom_roots([relay.cert.clone()])).bind().await.unwrap();
    let (id, relays) = to.address();
    let addr = relays.into_iter().fold(iroh::EndpointAddr::new(iroh::EndpointId::from_bytes(&id).unwrap()), iroh::EndpointAddr::with_relay_url);
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

    /// Asks the node for nothing, and waits for its answer, which carries what it gave: it has handled every frame sent
    /// before.
    async fn settle(&mut self, gid: &Bytes) -> Vec<Bytes> {
        self.send(&Frame::Want { group: gid.clone(), epoch: 0, wants: Vec::new(), ids: Vec::new() }).await;
        self.until(|f| match f {
            Frame::Held { items, answers: Some(_), .. } => Some(items),
            _ => None,
        })
        .await
    }
}

/// The seqs of one membership, as a `Seqs`.
fn seqs(key: &Bytes, joined: u64, seqs: &[u64]) -> Seqs {
    Seqs { key: key.clone(), joined, seqs: seqs.iter().copied().collect() }
}

/// Hands `hand` a summary of `mls`'s membership, signed as its member, which holds and seals `listed` in `epoch`.
async fn list(hand: &mut Hand, mls: &Mls, gid: &Bytes, joined: u64, epoch: u64, version: u64, listed: Vec<Seqs>) {
    let summary = Summary {
        group: gid.clone(),
        member: Bytes(mls.key().to_vec()),
        joined,
        version,
        time: lmk_node::now(),
        epoch,
        relay: None,
        held: listed.clone(),
        sealed: listed,
        shown: Vec::new(),
        lost: Vec::new(),
    };
    let body = serde_json::to_vec(&summary).unwrap();
    let sig = mls.sign(&[SUMMARY, &body].concat());
    hand.send(&Frame::Summaries { group: gid.clone(), items: vec![Signed { body: Bytes(body), sig: Bytes(sig) }] }).await;
}

/// A member that reaches only one holder of a message a commit kept waits for it before applying the next commit, which
/// deletes the keys it needs, and takes the message from that holder. Quinn holds Sam's message, which Sam's first
/// rename keeps; Rita, online, hears Quinn hold it, and so waits for it from Quinn alone while Sam's second rename
/// waits. Sam stops after that.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_waits_for_the_kept_message_its_only_holder_gives() {
    let relay = relay().await;
    let dir = folder("line");
    std::fs::create_dir_all(&dir).unwrap();
    let dbs = ["sam", "quinn", "rita"].map(|name| dir.join(format!("{name}.db")));
    let sam = stored(&relay, "Sam", &dbs[0]).await;
    let gid = sam.node.create(settings(CHAT, &relay), None).unwrap();
    let links = [sam.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), sam.node.invite(&gid.0, None, INVITE_VALID).await.unwrap()];
    let mut quinn = stored(&relay, "Quinn", &dbs[1]).await;
    quinn.node.join(&links[0], None).await.unwrap();
    let rita = stored(&relay, "Rita", &dbs[2]).await;
    rita.node.join(&links[1], None).await.unwrap();
    rita.node.shutdown().await.unwrap();
    drop(rita);

    // Quinn is online for the message and holds it; Sam's first rename keeps it, as Quinn's summary shows it held.
    let sent = sam.node.send(&gid.0, &message("p"), None).await.unwrap();
    let got = quinn.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!(got.id, sent);
    let sam_key = sam.node.key();
    let held = |node: &Node<SqliteProvider>| node.heard(&gid.0).unwrap().iter().any(|h| h.held.iter().any(|s| s.key == sam_key && s.seqs.contains(got.seq)));
    eventually("Sam hears that Quinn holds it", || held(&sam.node)).await;
    sam.node.change_settings(&gid.0, |s| Settings { name: "One".into(), ..s }).await.unwrap();

    // Rita comes back online and hears that Quinn holds the message before Sam's second rename needs it.
    let mut rita = stored(&relay, "Rita", &dbs[2]).await;
    eventually("Rita hears that Quinn holds it", || held(&rita.node)).await;
    sam.node.change_settings(&gid.0, |s| Settings { name: "Two".into(), ..s }).await.unwrap();
    let epoch = sam.node.epoch(&gid.0).unwrap();
    let got_by_rita = rita.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!(got_by_rita.id, sent);
    eventually("Rita applied the second rename", || rita.node.epoch(&gid.0).unwrap() == epoch).await;
    sam.node.shutdown().await.unwrap();
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
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &relay) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let sent = bob.node.send(&gid.0, &message("real"), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    bob.node.shutdown().await.unwrap();
    eventually("Bob is gone", || alice.node.online(&gid.0).unwrap().is_empty()).await;
    // Alice signs her summary a moment after what she holds changes: her state is taken once it stays still.
    let mut before = dump(&alice_db);
    loop {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let now = dump(&alice_db);
        if now == before {
            break;
        }
        before = now;
    }

    let mut mallory = hand(&relay, iroh::SecretKey::from_bytes(&lmk_core::random()), &alice.node).await;
    let real = sealed(&alice_db, &gid, &sent).1;
    let forged = |n: u8| {
        let mut forged = real.clone();
        *forged.0.last_mut().unwrap() ^= n;
        forged
    };
    mallory.send(&Frame::Held { group: gid.clone(), items: vec![forged(1), forged(2)], answers: None }).await;
    let log = alice.node.log(&gid.0).unwrap();
    let head = Head { log_ref: log.0.as_slice().try_into().unwrap(), length: 2, hash: [9; 32], time: lmk_node::now(), sig: Bytes(vec![0; 64]) };
    mallory.send(&Frame::Entries { log, entries: vec![Bytes(b"junk".to_vec())], head }).await;
    mallory.send(&Frame::Live { group: gid.clone(), hops: 0, item: forged(3) }).await;
    assert!(mallory.settle(&gid).await.is_empty(), "a want the gate does not take gets nothing");
    assert_eq!(dump(&alice_db), before);
    while let Ok(event) = alice.events.try_recv() {
        assert!(!matches!(event, Event::Message(_) | Event::Live { .. }), "{event:?}");
    }
    alice.node.shutdown().await.unwrap();
}

/// A peer's entries under a genuine head for another log or service change nothing; under the right head, they are taken.
#[tokio::test(flavor = "multi_thread")]
async fn peer_entries_are_bound_to_the_destination_log_and_service() {
    let relay = relay().await;
    let dir = folder("wrong-log-head");
    let (service_a, _membership_a) = served(&relay, &dir.join("a")).await;
    let (service_b, _membership_b) = served(&relay, &dir.join("b")).await;
    let (gate_a, _reaching_a) = Gate::new(Some(&service_a));
    let (gate_b, _reaching_b) = Gate::new(Some(&service_b));
    let key_of = |name: &str| ed25519_dalek::SigningKey::from_bytes(&Store::open(&dir.join(name).join("membership")).unwrap().key().to_bytes());
    let (key_a, key_b) = (key_of("a"), key_of("b"));
    let db = dir.join("reader.db");
    let reader = stored_with(&relay, "Reader", &db, gate_b.post("Reader", gate_a.post("Reader", relay.post()))).await;
    let gid = reader.node.create(settings(CHAT, &relay), None).unwrap();
    let (identity_a, _) = identity(&relay, &reader.node, service_a).await;
    let (identity_b, writer_b) = identity(&relay, &reader.node, service_b).await;
    let public = reader.node.read_public(&identity_b).await.unwrap();
    let entry = Bytes(public.next(&writer_b, public.writers.clone()));
    reader.node.shutdown().await.unwrap();
    drop(reader);
    gate_a.set(false);
    gate_b.set(false);

    let reference = |key: &ed25519_dalek::SigningKey, identity: &IdentityRef| {
        lmk_proto::head::reference(key.verifying_key().as_bytes(), &lmk_proto::public::address(&identity.id.0))
    };
    let (log_a, log_b) = (reference(&key_a, &identity_a), reference(&key_b, &identity_b));
    let mut provider = SqliteProvider::open(&db).unwrap();
    let before = held_head(&provider, &Bytes(log_b.to_vec())).unwrap();
    assert_eq!(before.length, 1);
    let hash = lmk_proto::head::next(&before.hash, &entry.0);
    let wrong_log = Head::sign(&key_a, &log_a, 2, hash, lmk_node::now());
    assert!(wrong_log.verify(&key_a.verifying_key()), "a genuine signature by A beyond its known head, over B's extended hash");
    let record_key = [b"node/log/".as_slice(), &log_b].concat();
    let record = provider.get(&record_key).unwrap();
    provider.close().unwrap();

    let mut reader = stored_with(&relay, "Reader", &db, gate_b.post("Reader", gate_a.post("Reader", relay.post()))).await;
    let mut peer = hand(&relay, iroh::SecretKey::from_bytes(&lmk_core::random()), &reader.node).await;
    let log = Bytes(log_b.to_vec());
    peer.send(&Frame::Entries { log: log.clone(), entries: vec![entry.clone()], head: wrong_log }).await;
    peer.settle(&gid).await;
    let wrong_service = Head::sign(&key_a, &log_b, 2, hash, lmk_node::now());
    assert!(wrong_service.verify(&key_a.verifying_key()));
    peer.send(&Frame::Entries { log: log.clone(), entries: vec![entry.clone()], head: wrong_service }).await;
    peer.settle(&gid).await;
    let mut provider = SqliteProvider::open(&db).unwrap();
    assert_eq!(provider.get(&record_key).unwrap(), record, "neither attack changes the destination's head, length or timestamp");
    assert!(provider.get(&[b"node/entry/".as_slice(), &log_b, b"/", &2u64.to_be_bytes()].concat()).unwrap().is_none());
    provider.close().unwrap();

    let right = Head::sign(&key_b, &log_b, 2, hash, lmk_node::now());
    peer.send(&Frame::Entries { log: log.clone(), entries: vec![entry], head: right.clone() }).await;
    peer.settle(&gid).await;
    reader.until(|event| matches!(event, Event::Public { identity } if identity == identity_b.id).then_some(())).await;
    reader.node.shutdown().await.unwrap();
    let provider = SqliteProvider::open(&db).unwrap();
    assert_eq!(held_head(&provider, &log), Some(right), "same-log catch-up works while the authority is unreachable");
}

/// A joiner whose `admitted` was lost asks again with the KeyPackage it kept: the committer answers with the Add's answer it
/// kept, and adds it no second time.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_whose_answer_was_lost_is_admitted_by_the_committers_answer() {
    let relay = relay().await;
    let (late, mut landing, post) = late_append(relay.post(), Duration::from_secs(5));
    let alice = session_with(&relay, "Alice", post).await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    let epoch = alice.node.epoch(&gid.0).unwrap();
    late.store(true, std::sync::atomic::Ordering::SeqCst);
    let (node, first) = (bob.node.clone(), link.clone());
    let joining = tokio::spawn(async move { node.join(&first, None).await });
    // The Add is in, and its answer is late: the joiner stops waiting for it.
    tokio::time::timeout(WAIT, landing.recv()).await.unwrap().unwrap();
    joining.abort();
    assert!(joining.await.is_err());

    let (joined, _) = tokio::time::timeout(WAIT, bob.node.join(&link, None)).await.unwrap().unwrap();
    assert_eq!(joined, gid);
    assert_eq!(alice.node.epoch(&gid.0).unwrap(), epoch + 1, "no second Add");
    assert_eq!(bob.node.members(&gid.0).unwrap().len(), 2);
}

/// While a commit in one group waits to read its log, a commit in another group completes, and so does a joiner's ask
/// again in the first, whose Add this session applied and whose answer was lost.
#[tokio::test(flavor = "multi_thread")]
async fn a_commit_waiting_in_one_group_holds_up_no_other() {
    let relay = relay().await;
    let dir = folder("commit-locks");
    let (slow, _service) = served(&relay, &dir).await;
    let (gate, mut reaching) = Gate::new(Some(&slow));
    let (late, mut landing, post) = late_append(gate.post("Alice", relay.post()), Duration::from_secs(5));
    let alice = session_with(&relay, "Alice", post).await;
    let bob = session(&relay, "Bob").await;
    let a = alice.node.create(Settings { membership: slow, ..settings(CHAT, &relay) }, None).unwrap();
    let b = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let link = alice.node.invite(&a.0, None, INVITE_VALID).await.unwrap();
    late.store(true, std::sync::atomic::Ordering::SeqCst);
    let (node, first) = (bob.node.clone(), link.clone());
    let joining = tokio::spawn(async move { node.join(&first, None).await });
    tokio::time::timeout(WAIT, landing.recv()).await.unwrap().unwrap();
    joining.abort();
    eventually("Alice applied the Add", || alice.node.members(&a.0).unwrap().len() == 2).await;

    gate.set(false);
    let (node, waits) = (alice.node.clone(), a.clone());
    let rename = |name: &str| { let name = name.to_owned(); move |s: Settings| Settings { name: name.clone(), ..s } };
    let waiting = tokio::spawn(async move { node.change_settings(&waits.0, rename("Waiting")).await });
    assert_eq!(tokio::time::timeout(WAIT, reaching.recv()).await.unwrap().unwrap(), "Alice");
    tokio::time::timeout(Duration::from_secs(20), alice.node.change_settings(&b.0, rename("Free"))).await.expect("B commits").unwrap();
    let (joined, _) = tokio::time::timeout(Duration::from_secs(20), bob.node.join(&link, None)).await.expect("the ask again is answered").unwrap();
    assert_eq!(joined, a);
    assert!(!waiting.is_finished());
    gate.set(true);
    tokio::time::timeout(WAIT, waiting).await.unwrap().unwrap().unwrap();
}

/// A joiner's first ask outlasts its wait, while the committer is busy answering: the joiner asks again, and the committer
/// answers with the Add it kept, adding the joiner once.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_asks_again_once_the_committers_answer_is_late() {
    let relay = relay().await;
    let (late, _landing, post) = late_append(relay.post(), Duration::from_secs(35));
    let (node, events) = Node::start(MemoryProvider::default(), Config { post, ..config(&relay, "Alice", None) }).await.unwrap();
    let alice = Session { node, events };
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    let epoch = alice.node.epoch(&gid.0).unwrap();
    late.store(true, std::sync::atomic::Ordering::SeqCst);
    let (joined, _) = tokio::time::timeout(Duration::from_secs(120), bob.node.join(&link, None)).await.unwrap().unwrap();
    assert_eq!(joined, gid);
    assert_eq!(alice.node.epoch(&gid.0).unwrap(), epoch + 1, "one Add");
    assert_eq!(bob.node.members(&gid.0).unwrap().len(), 2);
}

/// A joiner's committer is busy past its wait, and a second member it names gives no answer: the joiner asks the committer
/// again once the second member's wait is up, and the committer answers with the Add it kept.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_asks_its_committer_again_past_a_silent_member() {
    use lmk_proto::links::Invite;
    let relay = relay().await;
    let (late, _landing, post) = late_append(relay.post(), Duration::from_secs(35));
    let (node, events) = Node::start(MemoryProvider::default(), Config { post, ..config(&relay, "Alice", None) }).await.unwrap();
    let alice = Session { node, events };
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    let key = iroh::SecretKey::from_bytes(&lmk_core::random());
    let silent = *key.public().as_bytes();
    let _silent = hand(&relay, key.clone(), &bob.node).await;
    eventually("the silent member is connected", || bob.node.net().connected().contains(&key.public())).await;
    let link = Invite { members: vec![link.members[0], silent], ..link };
    let epoch = alice.node.epoch(&gid.0).unwrap();
    late.store(true, std::sync::atomic::Ordering::SeqCst);
    let (joined, _) = tokio::time::timeout(Duration::from_secs(120), bob.node.join(&link, None)).await.unwrap().unwrap();
    assert_eq!(joined, gid);
    assert_eq!(alice.node.epoch(&gid.0).unwrap(), epoch + 1, "one Add");
}

/// Two asks with one KeyPackage at once, as a joiner's again after one failed in transit: the member adds it once and
/// answers both with its Welcome, refusing neither.
#[tokio::test(flavor = "multi_thread")]
async fn two_asks_with_one_key_package_add_it_once() {
    let relay = relay().await;
    let alice = session(&relay, "Alice").await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    let epoch = alice.node.epoch(&gid.0).unwrap();
    let (one, two) = tokio::join!(bob.node.join(&link, None), bob.node.join(&link, None));
    // The joiner applies one Welcome; the other answer finds its KeyPackage spent.
    let (joined, other) = match (one, two) {
        (Ok((joined, _)), Err(other)) | (Err(other), Ok((joined, _))) => (joined, other),
        answers => panic!("{answers:?}"),
    };
    assert_eq!(joined, gid);
    assert!(!format!("{other:#}").contains("refused"), "{other:#}");
    assert_eq!(alice.node.epoch(&gid.0).unwrap(), epoch + 1, "one Add");
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
    laptop_devices.create("Bob", membership.clone()).await.unwrap();
    let mallory = session(&relay, "Mallory").await;
    let link = Invite::parse(&laptop_devices.invite().await.unwrap()).unwrap();
    // Nor does a device-link attempt left waiting make the same secret, read as a group link, join with a device key.
    let dead = *iroh::SecretKey::from_bytes(&lmk_core::random()).public().as_bytes();
    mallory.node.join(&Invite { members: vec![dead], ..link.clone() }, None).await.unwrap_err();
    let refused = mallory.node.join(&Invite { device: false, ..link }, None).await.unwrap_err();
    assert!(format!("{refused:#}").contains("altered"), "{refused:#}");
    assert!(mallory.node.groups().is_empty());

    let gid = laptop.node.create(settings(CHAT, &relay), None).unwrap();
    let link = laptop.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
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
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    eventually("Alice has Bob's Add", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let carol = stored(&relay, "Carol", &carol_db).await;
    carol.node.join(&bob.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    carol.node.shutdown().await.unwrap();
    drop(carol);

    // Alice comes back; Carol, by hand, connects and says nothing.
    let alice = stored(&relay, "Alice", &alice_db).await;
    eventually("Alice has Carol's Add", || alice.node.members(&gid.0).unwrap().len() == 3).await;
    assert!(alice.node.away(&gid.0).unwrap().iter().any(|m| m.name == "Carol"), "never heard from");
    let key = lmk_node::iroh_key(&SqliteProvider::open(&carol_db).unwrap()).unwrap();
    let _carol = hand(&relay, key, &alice.node).await;
    eventually("Carol is online", || alice.node.online(&gid.0).unwrap().iter().any(|m| m.name == "Carol")).await;
    assert!(!alice.node.away(&gid.0).unwrap().iter().any(|m| m.name == "Carol"), "online, though not heard from");

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

/// The deps a stored member keeps for a message of `gid`.
fn deps_of(db: &Path, gid: &Bytes, id: &Bytes) -> Vec<lmk_proto::held::Ref> {
    let header = &record(db, gid, id)["header"];
    serde_json::from_value(header.get("deps").cloned().unwrap_or(json!([]))).unwrap()
}

/// Three members chat in causal order. Each sender's messages come with seqs 1, 2, 3, in order. A reply's deps are the
/// messages its sender marked shown: Bob's replies depend on Alice's first message, which it showed, and not on her
/// second, which it received but did not show.
#[tokio::test(flavor = "multi_thread")]
async fn three_members_chat_in_causal_order() {
    let relay = relay().await;
    let dir = folder("chat");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, "Alice", &db("alice")).await;
    let bob = stored(&relay, "Bob", &db("bob")).await;
    let carol = stored(&relay, "Carol", &db("carol")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("everyone has three members", || [&alice, &bob, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 3)).await;
    let mut bob = bob;
    let mut carol = carol;

    let a1 = alice.node.send(&gid.0, &message("a1"), None).await.unwrap();
    let first = bob.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((first.id.clone(), first.sender.name.as_str()), (a1.clone(), "Alice"));
    bob.node.mark_shown(&gid.0, std::slice::from_ref(&a1)).unwrap();
    assert!(bob.node.shown(&gid.0, &a1.0).unwrap());
    let b1 = bob.node.send(&gid.0, &message("b1 replies to a1"), None).await.unwrap();
    let a2 = alice.node.send(&gid.0, &message("a2"), None).await.unwrap();
    let a3 = alice.node.send(&gid.0, &message("a3"), None).await.unwrap();
    let b2 = bob.node.send(&gid.0, &message("b2 is sent after a2 arrived, unshown"), None).await.unwrap();
    assert!(!bob.node.shown(&gid.0, &a2.0).unwrap());

    // Carol takes all five, each of Alice's in its seq order, and Bob's replies after the message they depend on.
    let mut taken = Vec::new();
    while taken.len() < 5 {
        taken.push(carol.until(|e| match e {
            Event::Message(message) => Some(message),
            _ => None,
        }).await);
    }
    let index = |id: &Bytes| taken.iter().find(|m| m.id == *id).unwrap().index;
    let seq = |id: &Bytes| taken.iter().find(|m| m.id == *id).unwrap().seq;
    assert_eq!([seq(&a1), seq(&a2), seq(&a3)], [3, 4, 5], "the two invites took seqs 1 and 2");
    assert!(index(&a1) < index(&b1) && index(&a2) < index(&a3), "causal order: {taken:?}");
    assert!(taken.iter().all(|m| m.index >= 1 && m.missing.is_empty() && !m.late));

    // Heard, Alice sees what Bob holds and showed.
    let alice_key = alice.node.key();
    eventually("Alice hears that Bob showed a1", || {
        alice.node.heard(&gid.0).unwrap().iter().any(|h| h.member.name == "Bob" && h.shown.iter().any(|s| s.key == alice_key && s.seqs.contains(first.seq)))
    })
    .await;
    bob.node.shutdown().await.unwrap();
    let sent = record(&db("bob"), &gid, &a1)["header"]["epoch"].as_u64().unwrap();
    assert_eq!(deps_of(&db("bob"), &gid, &b1), [lmk_proto::held::Ref { key: alice.node.key(), joined: 0, seq: 3, id: a1.clone(), epoch: sent }]);
    assert_eq!(deps_of(&db("bob"), &gid, &b2), deps_of(&db("bob"), &gid, &b1), "b2 depends on a1 still: a2 was not shown");
    carol.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();
}

/// A message whose dep is withheld waits for it, then is delivered with the dep named in `missing`, and the withheld
/// message comes `late` once its holder is back. Sam's first message is held by Bob alone, and Sam's reply depends on
/// it; Sam is then a hand that pushes the reply to Carol, and answers nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_whose_dep_is_withheld_is_delivered_with_missing_and_the_dep_comes_late() {
    let relay = relay().await;
    let dir = folder("withheld");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut bob = stored(&relay, "Bob", &db("bob")).await;
    let sam = stored(&relay, "Sam", &db("sam")).await;
    let carol = stored(&relay, "Carol", &db("carol")).await;
    let gid = bob.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&sam, &carol] {
        joiner.node.join(&bob.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        bob.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("everyone has three members", || [&bob, &sam, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 3)).await;
    carol.node.shutdown().await.unwrap();
    drop(carol);

    // Bob's m1 reaches Sam, who shows it and replies. Bob's rename keeps m1, since Sam's summary shows it held: Carol
    // then knows m1 was sent. Then Bob and Sam stop.
    let bob_key = bob.node.key();
    let m1 = bob.node.send(&gid.0, &message("m1"), None).await.unwrap();
    let mut sam = sam;
    let m1_seq = sam.until(|e| match e {
        Event::Message(message) => Some(message.seq),
        _ => None,
    }).await;
    sam.node.mark_shown(&gid.0, std::slice::from_ref(&m1)).unwrap();
    eventually("Bob hears that Sam holds m1", || bob.node.heard(&gid.0).unwrap().iter().any(|h| h.member.name == "Sam" && h.held.iter().any(|s| s.key == bob_key && s.seqs.contains(m1_seq)))).await;
    bob.node.change_settings(&gid.0, |s| Settings { name: "Kept".into(), ..s }).await.unwrap();
    let m2 = sam.node.send(&gid.0, &message("m2 replies to m1"), None).await.unwrap();
    bob.node.shutdown().await.unwrap();
    sam.node.shutdown().await.unwrap();

    // Carol comes back and takes m2 from Sam's hand, which never answers a `want`: m1 is withheld, so Carol waits for
    // it, gives it up after the hold-off, and delivers m2 with m1 in `missing`.
    let mut carol = stored(&relay, "Carol", &db("carol")).await;
    let (sam_key, _) = member_of(&db("sam"));
    let mut hand = hand(&relay, sam_key, &carol.node).await;
    let started = std::time::Instant::now();
    hand.send(&Frame::Held { group: gid.clone(), items: vec![sealed(&db("sam"), &gid, &m2).1], answers: None }).await;
    let reply = carol.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!(reply.id, m2);
    assert!(started.elapsed() >= Duration::from_secs(2), "m2 waited for m1: {:?}", started.elapsed());
    assert_eq!((reply.missing.clone(), reply.late), (vec![seqs(&bob_key, 0, &[m1_seq])], false));

    // Bob is back: Carol takes m1 from him, late, after m2.
    let bob = stored(&relay, "Bob", &db("bob")).await;
    let late = carol.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((late.id, late.seq, late.late, late.index > reply.index), (m1, m1_seq, true, true));
    bob.node.shutdown().await.unwrap();
    carol.node.shutdown().await.unwrap();
}

/// A sender alone online sends while the membership service is unreachable: its sends answer and deliver to it, and a
/// member that comes online later takes both messages, in order, from the sender.
#[tokio::test(flavor = "multi_thread")]
async fn chat_works_while_the_service_is_down() {
    let relay = relay().await;
    let dir = folder("service-down");
    let (membership, service) = signing_service(&relay, &dir).await;
    let mut alice = stored(&relay, "Alice", &dir.join("alice.db")).await;
    let bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &relay) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    drop(service);
    let one = alice.node.send(&gid.0, &message("one"), None).await.unwrap();
    let two = alice.node.send(&gid.0, &message("two"), None).await.unwrap();
    let mut bob = stored(&relay, "Bob", &dir.join("bob.db")).await;
    for (id, seq) in [(one, 2), (two, 3)] {
        let got = bob.until(|e| match e {
            Event::Message(message) => Some(message),
            _ => None,
        }).await;
        assert_eq!((got.id, got.seq, got.sender.name.as_str()), (id, seq, "Alice"));
    }
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();
}

/// A commit keeps what an online member holds: Bob holds Alice's two messages while Alice removes Dave, so `only_here`
/// empties and the commit keeps both, which reach Carol after Bob is gone, in causal order.
#[tokio::test(flavor = "multi_thread")]
async fn a_commit_keeps_what_an_online_member_holds() {
    let relay = relay().await;
    let dir = folder("keeps");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, "Alice", &db("alice")).await;
    let bob = stored(&relay, "Bob", &db("bob")).await;
    let carol = stored(&relay, "Carol", &db("carol")).await;
    let dave = stored(&relay, "Dave", &db("dave")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&bob, &carol, &dave] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Alice has four members", || alice.node.members(&gid.0).unwrap().len() == 4).await;
    carol.node.shutdown().await.unwrap();
    drop(carol);
    let (bob_key, dave_key) = (bob.node.key(), dave.node.key());

    let alice_key = alice.node.key();
    let m1 = alice.node.send(&gid.0, &message("one"), None).await.unwrap();
    let mut bob = bob;
    let seq = bob.until(|e| match e {
        Event::Message(message) => Some(message.seq),
        _ => None,
    }).await;
    // Her seq 1, Bob's invite, was sent before he joined: it is not his to have.
    eventually("Alice hears that Bob holds her messages up to one", || alice.node.heard(&gid.0).unwrap().iter().any(|h| h.member.key == bob_key && (2..=seq).all(|q| h.held.iter().any(|s| s.key == alice_key && s.seqs.contains(q))))).await;
    dave.node.shutdown().await.unwrap();
    let m2 = alice.node.send(&gid.0, &message("two"), None).await.unwrap();
    bob.until(|e| matches!(e, Event::Message(message) if message.id == m2).then_some(())).await;
    let held = |node: &Node<SqliteProvider>| node.only_here(&gid.0).unwrap().into_iter().map(|(id, _)| id).collect::<Vec<_>>();
    eventually("Alice hears that Bob holds both", || held(&alice.node).is_empty()).await;

    assert!(alice.node.remove(&gid.0, &dave_key.0).await.unwrap());
    assert!(held(&alice.node).is_empty(), "the commit kept both, which Bob held");

    bob.node.shutdown().await.unwrap();
    let mut carol = stored(&relay, "Carol", &db("carol")).await;
    let mut taken = Vec::new();
    while taken.len() < 2 {
        taken.push(carol.until(|e| match e {
            Event::Message(message) => Some(message.id),
            _ => None,
        }).await);
    }
    assert_eq!(taken, [m1, m2], "in causal order");
    alice.node.shutdown().await.unwrap();
    carol.node.shutdown().await.unwrap();
}

/// A message Bob holds sealed in an epoch that Alice's commit ended is only here until Bob holds it sealed in the new
/// epoch. Bob is away across the commit, and then connected as a stand-in that takes no reseal: it lists the message
/// held sealed in the ended epoch, which does not count, and then sealed in the new one, which Alice's reseal would have
/// given it.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_held_in_an_ended_epoch_is_only_here_until_its_holder_takes_the_new_sealing() {
    let relay = relay().await;
    let dir = folder("ended-epoch");
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("bob.db");
    let alice = session(&relay, "Alice").await;
    let mut bob = stored(&relay, "Bob", &db).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    eventually("Alice has Bob", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    let m = alice.node.send(&gid.0, &message("held"), None).await.unwrap();
    let seq = bob.until(|e| match e {
        Event::Message(message) => Some(message.seq),
        _ => None,
    }).await;
    eventually("Alice hears that Bob holds it", || alice.node.only_here(&gid.0).unwrap().is_empty()).await;
    let (bob_key, alice_key) = (bob.node.key(), alice.node.key());
    let bob_joined = alice.node.heard(&gid.0).unwrap().iter().find(|h| h.member.key == bob_key).unwrap().joined;
    let alice_joined = alice.node.heard(&gid.0).unwrap().iter().find(|h| h.member.key == bob_key).unwrap().held.iter().find(|s| s.key == alice_key).unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    alice.node.change_settings(&gid.0, |s| Settings { name: "Moved".into(), ..s }).await.unwrap();
    assert!(alice.node.only_here(&gid.0).unwrap().iter().any(|(id, _)| *id == m), "the commit kept nothing: Bob was away");

    let (iroh, mls) = member_of(&db);
    let mut bob_hand = hand(&relay, iroh, &alice.node).await;
    eventually("Bob is back, and still holds the message sealed in the ended epoch", || alice.node.online(&gid.0).unwrap().iter().any(|m| m.key == bob_key)).await;
    assert!(alice.node.only_here(&gid.0).unwrap().iter().any(|(id, _)| *id == m), "a summary of an ended epoch does not count");

    let epoch = alice.node.epoch(&gid.0).unwrap();
    list(&mut bob_hand, &mls, &gid, bob_joined, epoch, lmk_node::now() + 3_600_000, vec![seqs(&alice_key, alice_joined, &(1..=seq).collect::<Vec<_>>())]).await;
    eventually("Alice hears that Bob holds it sealed in the new epoch", || alice.node.only_here(&gid.0).unwrap().is_empty()).await;
    alice.node.shutdown().await.unwrap();
}

/// A message an online member holds is kept by the next commit: Bob holds Alice's message, and the next commit that Alice
/// makes keeps it, so it is no longer only here once Bob goes away.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_an_online_member_holds_is_kept_by_the_next_commit() {
    let relay = relay().await;
    let alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let gid = alice.node.create(Settings { update: 2, ..settings(CHAT, &relay) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    eventually("Alice has Bob", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    alice.node.send(&gid.0, &message("kept"), None).await.unwrap();
    bob.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    eventually("Alice hears that Bob holds it", || alice.node.only_here(&gid.0).unwrap().is_empty()).await;
    let epoch = alice.node.epoch(&gid.0).unwrap();
    eventually("Alice commits its update", || alice.node.epoch(&gid.0).unwrap() > epoch).await;
    bob.node.shutdown().await.unwrap();
    eventually("Alice sees Bob go", || alice.node.online(&gid.0).unwrap().is_empty()).await;
    assert!(alice.node.only_here(&gid.0).unwrap().is_empty(), "the commit kept it");
    alice.node.shutdown().await.unwrap();
}

/// An update waiting for what connected members list commits once HEAR is up, not later: Bob's stand-in lists seqs that
/// Alice never got, and nothing sends them.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_waits_for_what_connected_members_list_for_at_most_hear() {
    let relay = relay().await;
    let dir = folder("fetch-hear");
    std::fs::create_dir_all(&dir).unwrap();
    let bob_db = dir.join("bob.db");
    let alice = session(&relay, "Alice").await;
    let bob = stored(&relay, "Bob", &bob_db).await;
    let gid = alice.node.create(Settings { update: 2, ..settings(CHAT, &relay) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    eventually("Alice hears Bob", || alice.node.heard(&gid.0).unwrap().iter().any(|heard| heard.member.name == "Bob")).await;
    let joined = alice.node.heard(&gid.0).unwrap().iter().find(|heard| heard.member.name == "Bob").unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    let (iroh, mls) = member_of(&bob_db);
    let mut bob_hand = hand(&relay, iroh, &alice.node).await;
    let epoch = alice.node.epoch(&gid.0).unwrap();
    let listed_at = std::time::Instant::now();
    list(&mut bob_hand, &mls, &gid, joined, epoch, lmk_node::now() + 3_600_000, vec![seqs(&Bytes(mls.key().to_vec()), joined, &[1, 2, 3])]).await;
    tokio::time::timeout(Duration::from_millis(lmk_net::peers::HEAR + 5_000), async {
        while alice.node.epoch(&gid.0).unwrap() == epoch {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("Alice's update waited past HEAR");
    assert!(listed_at.elapsed() >= Duration::from_millis(lmk_net::peers::HEAR), "Alice's update did not wait for what was listed");
    alice.node.shutdown().await.unwrap();
}

/// A pass that removes, and an Add, do not wait for holders: while Bob, connected, lists messages Alice lacks and never
/// gives them, Alice's updates wait, but she removes the device Carol's identity dropped, and admits Dave, at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_removing_pass_and_an_add_do_not_wait_for_holders() {
    let relay = relay().await;
    let dir = folder("no-wait");
    std::fs::create_dir_all(&dir).unwrap();
    let (membership, _service) = signing_service(&relay, &dir).await;
    let bob_db = dir.join("bob.db");
    let alice = session(&relay, "Alice").await;
    let (carol, laptop) = identity(&relay, &alice.node, membership.clone()).await;
    let tablet_key: [u8; 32] = lmk_core::random();
    let log = alice.node.read_public(&carol).await.unwrap();
    let both = vec![lmk_core::device::public(&laptop).into(), lmk_core::device::public(&tablet_key).into()];
    publish(&relay, &alice.node, &carol, log.next(&laptop, both)).await;
    let gid = alice.node.create(Settings { update: 2, membership, ..settings(CHAT, &relay) }, None).unwrap();
    let bob = stored(&relay, "Bob", &bob_db).await;
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let tablet = session(&relay, "tablet").await;
    let link = alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap();
    tablet.node.join(&link, Some(certificate(&carol, &tablet_key, &tablet.node.key(), "Carol", "tablet"))).await.unwrap();
    eventually("Alice hears Bob", || alice.node.heard(&gid.0).unwrap().iter().any(|heard| heard.member.name == "Bob")).await;
    let joined = alice.node.heard(&gid.0).unwrap().iter().find(|heard| heard.member.name == "Bob").unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);
    tablet.node.shutdown().await.unwrap();

    // Bob's stopped session, standing in for itself, lists seqs of its own that it never sent, sealed in Alice's epoch.
    let (iroh, mls) = member_of(&bob_db);
    let mut bob_hand = hand(&relay, iroh, &alice.node).await;
    let mut version = lmk_node::now() + 3_600_000;
    // Lists them in Alice's epoch until her updates, due every 2 s, wait on them; answers when it listed.
    let mut block = async || {
        for _ in 0..3 {
            let epoch = alice.node.epoch(&gid.0).unwrap();
            version += 1;
            list(&mut bob_hand, &mls, &gid, joined, epoch, version, vec![seqs(&Bytes(mls.key().to_vec()), joined, &[1, 2, 3])]).await;
            let listed_at = std::time::Instant::now();
            tokio::time::sleep(Duration::from_secs(5)).await;
            if alice.node.epoch(&gid.0).unwrap() == epoch {
                return listed_at;
            }
        }
        panic!("Alice's updates never waited");
    };

    let listed_at = block().await;
    let log = alice.node.read_public(&carol).await.unwrap();
    publish(&relay, &alice.node, &carol, log.next(&laptop, vec![lmk_core::device::public(&laptop).into()])).await;
    eventually("Alice removes the tablet", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    assert!(listed_at.elapsed() < Duration::from_millis(lmk_net::peers::HEAR), "the removal waited");

    let listed_at = block().await;
    let dave = session(&relay, "Dave").await;
    dave.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    assert!(listed_at.elapsed() < Duration::from_millis(lmk_net::peers::HEAR), "the Add waited");
    alice.node.shutdown().await.unwrap();
    dave.node.shutdown().await.unwrap();
}

/// A chat commits only for its members' updates and changes: messages both members hold, and sends of either, move no
/// epoch, even at the passes their sessions run when they start 21 minutes later. Its T is so long that no update falls
/// due.
#[test]
fn a_chat_of_held_messages_commits_only_for_an_update_or_change() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("held-chat");
        std::fs::create_dir_all(&dir).unwrap();
        let db = |name: &str| dir.join(format!("{name}.db"));
        let mut alice = stored(&relay, "Alice", &db("alice")).await;
        let mut bob = stored(&relay, "Bob", &db("bob")).await;
        let gid = alice.node.create(Settings { update: u32::MAX, ..settings(CHAT, &relay) }, None).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        eventually("Alice has Bob's Add", || alice.node.members(&gid.0).unwrap().len() == 2).await;
        let epoch = alice.node.epoch(&gid.0).unwrap();
        alice.node.send(&gid.0, &message("one"), None).await.unwrap();
        bob.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
        bob.node.send(&gid.0, &message("two"), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
        alice.node.shutdown().await.unwrap();
        bob.node.shutdown().await.unwrap();
        drop((alice, bob));
        SHIFT.store(21 * 60 * 1000, std::sync::atomic::Ordering::Relaxed);
        let alice = stored(&relay, "Alice", &db("alice")).await;
        let bob = stored(&relay, "Bob", &db("bob")).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!((alice.node.epoch(&gid.0).unwrap(), bob.node.epoch(&gid.0).unwrap()), (epoch, epoch));
        alice.node.shutdown().await.unwrap();
        bob.node.shutdown().await.unwrap();
    });
}

/// A removed member's sends while it is offline are told to it as not kept: `Removed` names the ids of its messages no
/// cut kept, and it keeps none of them once it comes back.
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_member_is_told_which_of_its_messages_no_cut_kept() {
    let relay = relay().await;
    let dir = folder("not-kept");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let alice = stored(&relay, "Alice", &db("alice")).await;
    let dave = stored(&relay, "Dave", &db("dave")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    dave.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    eventually("Alice has Dave's Add", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    let dave_key = dave.node.key();
    alice.node.shutdown().await.unwrap();
    drop(alice);

    // Alice is away, so Dave's messages are held by Dave alone; then Dave stops too.
    let one = dave.node.send(&gid.0, &message("one"), None).await.unwrap();
    let two = dave.node.send(&gid.0, &message("two"), None).await.unwrap();
    dave.node.shutdown().await.unwrap();
    drop(dave);

    let alice = stored(&relay, "Alice", &db("alice")).await;
    assert!(alice.node.remove(&gid.0, &dave_key.0).await.unwrap());
    alice.node.shutdown().await.unwrap();
    let mut dave = stored(&relay, "Dave", &db("dave")).await;
    let (not_kept, by) = dave.until(|e| match e {
        Event::Removed { not_kept, by, .. } => Some((not_kept, by)),
        _ => None,
    }).await;
    assert_eq!(not_kept, [one, two]);
    assert_eq!(by.map(|m| m.name), Some("Alice".to_owned()));
    dave.node.shutdown().await.unwrap();
}

/// A member that delivered a removed member's last kept message still has it after the removal.
#[tokio::test(flavor = "multi_thread")]
async fn a_holder_keeps_the_removed_members_last_kept_message() {
    let relay = relay().await;
    let dir = folder("holder");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, "Alice", &db("alice")).await;
    let bob = stored(&relay, "Bob", &db("bob")).await;
    let dave = stored(&relay, "Dave", &db("dave")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&bob, &dave] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Alice has three members", || alice.node.members(&gid.0).unwrap().len() == 3).await;
    let (bob_key, dave_key) = (bob.node.key(), dave.node.key());
    let mut bob = bob;
    let last = dave.node.send(&gid.0, &message("Dave's last"), None).await.unwrap();
    bob.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    eventually("Alice hears that Bob holds it", || alice.node.heard(&gid.0).unwrap().iter().any(|h| h.member.key == bob_key && h.held.iter().any(|s| s.key == dave_key && s.seqs.contains(1)))).await;
    dave.node.shutdown().await.unwrap();

    assert!(alice.node.remove(&gid.0, &dave_key.0).await.unwrap());
    assert!(alice.node.message(&gid.0, &last.0).unwrap().is_some(), "Alice kept it");
    bob.until(|e| matches!(e, Event::Left { member, .. } if member.name == "Dave").then_some(())).await;
    assert!(bob.node.message(&gid.0, &last.0).unwrap().is_some(), "Bob keeps it");
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();
}

/// What a member sends while alone in its group is no one else's: it needs no holder, and a joiner takes only what is
/// sent after it joined, past the next commit too.
#[tokio::test(flavor = "multi_thread")]
async fn what_a_member_sends_alone_needs_no_holder_and_reaches_no_joiner() {
    let relay = relay().await;
    let mut alice = session(&relay, "Alice").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    alice.node.send(&gid.0, &message("before Bob"), None).await.unwrap();
    assert!(alice.node.only_here(&gid.0).unwrap().is_empty());
    let mut bob = session(&relay, "Bob").await;
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let after = alice.node.send(&gid.0, &message("after Bob"), None).await.unwrap();
    // Alice's invite took seq 2: before is seq 1, after seq 3.
    let got = bob.until(|e| match e {
        Event::Message(m) => Some(m),
        _ => None,
    }).await;
    assert_eq!((got.id, got.seq, got.missing.is_empty()), (after, 3, true));
    alice.node.change_settings(&gid.0, |s| Settings { name: "Kept".into(), ..s }).await.unwrap();
    assert!(bob.node.messages(&gid.0).unwrap().iter().all(|m| m.payload != message("before Bob")));
    alice.node.shutdown().await.unwrap();
    bob.node.shutdown().await.unwrap();
}

/// Carol misses two commits that keep Alice's two messages, which Bob holds; it comes back to them: the messages it
/// took, and those it was told lost, by seq. Each is one or the other, once.
async fn missed_commits(test: &str) -> (Vec<u64>, Vec<u64>) {
    let relay = relay().await;
    let dir = folder(test);
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, "Alice", &db("alice")).await;
    let mut bob = stored(&relay, "Bob", &db("bob")).await;
    let carol = stored(&relay, "Carol", &db("carol")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Alice has three members", || alice.node.members(&gid.0).unwrap().len() == 3).await;
    carol.node.shutdown().await.unwrap();
    drop(carol);
    let alice_key = alice.node.key();

    // The two invites took seqs 1 and 2; Alice's messages are 3 and 4, each held by Bob before the rename that keeps it.
    // Seq 1, Bob's invite, was sent before he joined: it is not his to have.
    let mut sent = Vec::new();
    for text in ["a1", "a2"] {
        alice.node.send(&gid.0, &message(text), None).await.unwrap();
        let seq = bob.until(|e| match e {
            Event::Message(message) => Some(message.seq),
            _ => None,
        }).await;
        sent.push(seq);
        eventually("Alice hears that Bob holds her messages up to it", || alice.node.heard(&gid.0).unwrap().iter().any(|h| h.member.name == "Bob" && (2..=seq).all(|q| h.held.iter().any(|s| s.key == alice_key && s.seqs.contains(q))))).await;
        alice.node.change_settings(&gid.0, |s| Settings { name: text.into(), ..s }).await.unwrap();
    }
    alice.node.change_settings(&gid.0, |s| Settings { name: "last".into(), ..s }).await.unwrap();
    let epoch = alice.node.epoch(&gid.0).unwrap();
    assert_eq!(sent, [3, 4]);

    let mut carol = stored(&relay, "Carol", &db("carol")).await;
    let (mut delivered, mut lost) = (Vec::new(), Vec::new());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match carol.events.recv().await {
                Some(Event::Message(message)) => delivered.push(message.seq),
                Some(Event::Lost(lost_now)) => lost.extend(lost_now.messages.iter().flat_map(|of| of.seqs.clone())),
                _ => {}
            }
        }
    })
    .await
    .unwrap_err();
    eventually("Carol applied every commit", || carol.node.epoch(&gid.0).unwrap() == epoch).await;
    for session in [&alice, &bob, &carol] {
        session.node.shutdown().await.unwrap();
    }
    (delivered, lost)
}

/// A member offline across several commits accounts for each message they kept once: it takes it, or is told it lost,
/// and never both or twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_back_after_several_commits_takes_or_is_told_each_kept_message_once() {
    let (delivered, lost) = missed_commits("several").await;
    let mut accounted: Vec<u64> = delivered.into_iter().chain(lost).collect();
    accounted.sort();
    assert_eq!(accounted, [3, 4]);
}

/// A member offline across several commits takes each message they kept, once, when it comes back: the wait before
/// each commit holds until it heard the summaries that show who holds them.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_back_after_several_commits_takes_each_kept_message() {
    let (delivered, lost) = missed_commits("several-taken").await;
    assert_eq!((delivered, lost), (vec![3, 4], Vec::<u64>::new()));
}

/// A removed member that has not read the commit removing it still sends: what it sends past its final cut reaches no
/// member that read the removal. Alice and Bob read the commit; Dave, away as it lands and back behind the gate, cannot:
/// no peer brings a commit to a member it removed that was not connected.
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_members_send_past_its_final_cut_reaches_no_one() {
    let relay = relay().await;
    let dir = folder("sealed-on");
    std::fs::create_dir_all(&dir).unwrap();
    let (membership, _service) = served(&relay, &dir).await;
    let (gate, _reaching) = Gate::new(Some(&membership));
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let dave = stored_with(&relay, "Dave", &dir.join("dave.db"), gate.post("Dave", relay.post())).await;
    let gid = alice.node.create(Settings { membership, ..settings(CHAT, &relay) }, None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    dave.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    eventually("Bob has three members", || bob.node.members(&gid.0).unwrap().len() == 3).await;
    let dave_key = dave.node.key();
    dave.node.shutdown().await.unwrap();
    drop(dave);
    gate.set(false);

    assert!(alice.node.remove(&gid.0, &dave_key.0).await.unwrap());
    let epoch = alice.node.epoch(&gid.0).unwrap();
    eventually("Bob applies the removal", || bob.node.epoch(&gid.0).unwrap() == epoch).await;
    let dave = stored_with(&relay, "Dave", &dir.join("dave.db"), gate.post("Dave", relay.post())).await;
    eventually("Dave reaches Alice", || dave.node.online(&gid.0).unwrap().iter().any(|m| m.name == "Alice")).await;
    let sealed_on = dave.node.send(&gid.0, &message("sealed on after the removal"), None).await.unwrap();
    let quiet = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            alice.until(|e| matches!(e, Event::Message(m) if m.id == sealed_on).then_some(())),
            bob.until(|e| matches!(e, Event::Message(m) if m.id == sealed_on).then_some(())),
        )
    })
    .await;
    assert!(quiet.is_err(), "neither member delivers it");
    assert!(alice.node.message(&gid.0, &sealed_on.0).unwrap().is_none());
    assert!(bob.node.message(&gid.0, &sealed_on.0).unwrap().is_none());
    for session in [&alice, &bob] {
        session.node.shutdown().await.unwrap();
    }
    dave.node.shutdown().await.unwrap();
}

/// A member's summary tells what another holds and showed, and survives a restart. A loss a member reports is told to
/// the author once, and not again after it restarts.
#[tokio::test(flavor = "multi_thread")]
async fn lost_seqs_are_told_once_across_restarts() {
    let relay = relay().await;
    let dir = folder("told");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, "Alice", &db("alice")).await;
    let bob = stored(&relay, "Bob", &db("bob")).await;
    let carol = stored(&relay, "Carol", &db("carol")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Bob and Carol have both Adds", || [&bob, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 3)).await;
    carol.node.shutdown().await.unwrap();
    drop(carol);
    let bob_key = bob.node.key();
    let sent = bob.node.send(&gid.0, &message("only Alice and Bob hold this"), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    eventually("Alice hears that Bob holds it", || alice.node.heard(&gid.0).unwrap().iter().any(|h| h.member.key == bob_key && h.held.iter().any(|s| s.key == bob_key && s.seqs.contains(1)))).await;
    for name in ["One", "Two"] {
        alice.node.change_settings(&gid.0, |s| Settings { name: name.into(), ..s }).await.unwrap();
    }
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();

    // Carol, back with no holder online, loses Bob's message and says so in its summary.
    let mut carol = stored(&relay, "Carol", &db("carol")).await;
    carol.node.open_logs().await;
    let lost = carol.until(|e| match e {
        Event::Lost(lost) => Some(lost),
        _ => None,
    }).await;
    assert_eq!((lost.messages[0].from.key.clone(), lost.messages[0].seqs.clone()), (bob_key.clone(), vec![1]));

    // Bob comes back and hears Carol's summary: he is told once, as its author. Carol's summary survives his restart.
    let mut bob = stored(&relay, "Bob", &db("bob")).await;
    let told = bob.until(|e| match e {
        Event::Lost(lost) => Some(lost),
        _ => None,
    }).await;
    let of = &told.messages[0];
    assert_eq!((told.member.name.as_str(), &of.from.key, of.seqs.clone(), of.ids.clone()), ("Carol", &bob_key, vec![1], vec![sent.clone()]));
    bob.node.shutdown().await.unwrap();
    let mut bob = stored(&relay, "Bob", &db("bob")).await;
    assert!(bob.node.heard(&gid.0).unwrap().iter().any(|h| h.member.name == "Carol"), "Carol's summary survives the restart");
    let again = tokio::time::timeout(Duration::from_secs(3), bob.until(|e| matches!(e, Event::Lost(_)).then_some(()))).await;
    assert!(again.is_err(), "told once");
    assert!(carol.node.message(&gid.0, &sent.0).unwrap().is_none());
    for session in [&bob, &carol] {
        session.node.shutdown().await.unwrap();
    }
}

/// Live payloads reach each member online once. One sent before a commit moved the group on is not delivered after it,
/// to a member that comes back: it takes what is sent after, once it is connected.
#[tokio::test(flavor = "multi_thread")]
async fn live_payloads_reach_each_member_once_and_not_across_a_commit() {
    let relay = relay().await;
    let dir = folder("live");
    std::fs::create_dir_all(&dir).unwrap();
    let mut alice = session(&relay, "Alice").await;
    let mut bob = session(&relay, "Bob").await;
    let carol = stored(&relay, "Carol", &dir.join("carol.db")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    carol.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    eventually("Bob and Carol have both Adds", || bob.node.members(&gid.0).unwrap().len() == 3 && carol.node.members(&gid.0).unwrap().len() == 3).await;
    let live = |n: u64| json!({ "type": "edit", "n": n });
    alice.node.send_live(&gid.0, &live(1), None).unwrap();
    let first = bob.until(|e| match e {
        Event::Live { payload, .. } => Some(payload),
        _ => None,
    }).await;
    assert_eq!(first, live(1));
    carol.node.shutdown().await.unwrap();
    alice.node.send_live(&gid.0, &live(2), None).unwrap();
    bob.until(|e| matches!(e, Event::Live { payload, .. } if payload == live(2)).then_some(())).await;
    alice.node.change_settings(&gid.0, |s| Settings { name: "Release".into(), ..s }).await.unwrap();

    let mut carol = stored(&relay, "Carol", &dir.join("carol.db")).await;
    eventually("Alice is online to Carol", || alice.node.online(&gid.0).unwrap().iter().any(|m| m.name == "Carol")).await;
    eventually("Bob and Carol have the commit", || [bob.node.settings(&gid.0), carol.node.settings(&gid.0)].iter().all(|s| s.as_ref().unwrap().name == "Release")).await;
    alice.node.send_live(&gid.0, &live(3), None).unwrap();
    let got = carol.until(|e| match e {
        Event::Live { payload, .. } => Some(payload),
        _ => None,
    }).await;
    assert_eq!(got, live(3), "what came before the commit is not resent");
    assert_eq!(bob.until(|e| match e {
        Event::Live { payload, .. } => Some(payload),
        _ => None,
    }).await, live(3));
    let extra = tokio::time::timeout(Duration::from_secs(2), bob.until(|e| matches!(e, Event::Live { .. }).then_some(()))).await;
    assert!(extra.is_err(), "Bob takes each payload once");
    alice.node.shutdown().await.unwrap();
    bob.node.shutdown().await.unwrap();
    carol.node.shutdown().await.unwrap();
}

/// One sender with more than a thousand messages in an epoch, while a member is offline: the member, back, takes all of
/// them, in order. Alice's messages are sealed here from her stored state, as her node would seal them, since her own
/// sends are limited to a hundred and then one a second; a receiver's flood bucket, twice that, admits about two a
/// second after its first 200, so this takes some minutes.
#[ignore = "about eight minutes: a receiver's flood bucket admits 2 messages a second after its first 200"]
#[tokio::test(flavor = "multi_thread")]
async fn a_member_back_takes_more_than_a_thousand_messages_of_one_sender() {
    const MESSAGES: u64 = 1100;
    let relay = relay().await;
    let dir = folder("thousand");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, "Alice", &db("alice")).await;
    let bob = stored(&relay, "Bob", &db("bob")).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    bob.node.shutdown().await.unwrap();
    drop(bob);
    alice.node.shutdown().await.unwrap();
    drop(alice);

    // Alice's invite for Bob is her seq 1, so her messages run from 2.
    let provider = SqliteProvider::open(&db("alice")).unwrap();
    let (iroh, session) = member_of(&db("alice"));
    let author = Bytes(session.key().to_vec());
    let invite = provider.get(&[b"node/seq/".as_slice(), &gid.0, b"/", &author.0, b"/", &0u64.to_be_bytes(), &1u64.to_be_bytes()].concat()).unwrap().unwrap();
    let mut prev: Bytes = serde_json::from_slice(&invite).unwrap();
    let mut group = lmk_core::group::Group::load(&provider, &gid.0).unwrap();
    let invite_plaintext: Bytes = serde_json::from_value(record(&db("alice"), &gid, &prev)["plaintext"].clone()).unwrap();
    let mut sent = record(&db("alice"), &gid, &prev)["header"]["epoch"].as_u64().unwrap();
    let mut ciphertexts = vec![Bytes(group.seal(&provider, &session, &invite_plaintext.0).unwrap())];
    let mut ids = Vec::new();
    for seq in 2..=MESSAGES + 1 {
        let header = lmk_proto::held::Header {
            group: gid.clone(),
            author: author.clone(),
            joined: 0,
            seq,
            epoch: group.epoch(),
            prev: Some((prev.clone(), sent)),
            deps: Vec::new(),
            reply_to: None,
            payload: message(&seq.to_string()),
        };
        let plaintext = header.encode();
        ciphertexts.push(Bytes(group.seal(&provider, &session, &plaintext).unwrap()));
        (prev, sent) = (Bytes(lmk_proto::held::id(&plaintext).to_vec()), group.epoch());
        ids.push(prev.clone());
    }
    drop(group);
    drop(provider);

    // Bob, back, takes them from Alice's hand, the invite first: all of them, once each, in seq order.
    let mut bob = stored(&relay, "Bob", &db("bob")).await;
    let mut hand = hand(&relay, iroh, &bob.node).await;
    hand.send(&Frame::Held { group: gid.clone(), items: ciphertexts, answers: None }).await;
    let mut taken = Vec::new();
    while taken.len() < MESSAGES as usize {
        taken.push(bob.until(|e| match e {
            Event::Message(message) => Some(message.id),
            _ => None,
        }).await);
    }
    assert_eq!(taken, ids);
    bob.node.shutdown().await.unwrap();
}

/// Members learn each other's home relays as they connect.
#[tokio::test(flavor = "multi_thread")]
async fn members_learn_each_others_relays() {
    let relay = relay().await;
    let dir = folder("relays-learn");
    let alice = stored(&relay, "Alice", &dir.join("alice.db")).await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let (alice_key, bob_key, url) = (alice.node.address().0, bob.node.address().0, relay.url.to_string());
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_key) == Some(url.clone())).await;
    eventually("Bob holds Alice's relay", || bob.node.hint(&alice_key) == Some(url.clone())).await;
}

/// Chosen relays are where a session lives, whatever its directory names: its members hold them as its relays.
#[tokio::test(flavor = "multi_thread")]
async fn chosen_relays_replace_the_directorys() {
    let relay = relay().await;
    let dead = "https://127.0.0.1:1".parse().unwrap();
    let (node, events) = Node::start(MemoryProvider::default(), Config { relays: vec![dead], chosen: vec![relay.url.clone()], ..config(&relay, "Alice", None) })
        .await
        .unwrap();
    let alice = Session { node, events };
    let bob = session(&relay, "Bob").await;
    assert_eq!(alice.node.address().1, vec![relay.url.clone()]);
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let (alice_key, url) = (alice.node.address().0, relay.url.to_string());
    eventually("Bob holds Alice's chosen relay", || bob.node.hint(&alice_key) == Some(url.clone())).await;
}

/// A member whose home relay moves tells its online co-member, which holds the new relay within seconds.
#[tokio::test(flavor = "multi_thread")]
async fn a_home_relay_change_reaches_an_online_co_member() {
    let relay = relay().await;
    let moved = relay_beside(&relay).await;
    let dir = folder("relays-move");
    let alice_db = dir.join("alice.db");
    let alice = stored(&relay, "Alice", &alice_db).await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let alice_key = alice.node.address().0;
    eventually("Bob holds Alice's relay", || bob.node.hint(&alice_key) == Some(relay.url.to_string())).await;

    alice.node.shutdown().await.unwrap();
    drop(alice);
    let _alice = stored(&moved, "Alice", &alice_db).await;
    eventually("Bob holds Alice's new relay", || bob.node.hint(&alice_key) == Some(moved.url.to_string())).await;
}

/// In a group over seven, where members do not all connect, a member's new home relay reaches every co-member, though
/// most of them never connect to it.
#[tokio::test(flavor = "multi_thread")]
async fn a_home_relay_reaches_every_member_of_a_group_over_seven() {
    let relay = relay().await;
    let moved = relay_beside(&relay).await;
    let dir = folder("relays-seven");
    let bob_db = dir.join("bob.db");
    let mut sessions = vec![session(&relay, "Alice").await];
    let gid = sessions[0].node.create(settings(CHAT, &relay), None).unwrap();
    let bob = stored(&relay, "Bob", &bob_db).await;
    bob.node.join(&sessions[0].node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    for name in ["Carol", "Dave", "Erin", "Frank", "Grace", "Heidi"] {
        let joiner = session(&relay, name).await;
        joiner.node.join(&sessions[0].node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        sessions.push(joiner);
    }
    eventually("Alice has eight members", || sessions[0].node.members(&gid.0).unwrap().len() == 8).await;

    let bob_key = bob.node.address().0;
    bob.node.shutdown().await.unwrap();
    drop(bob);
    let _bob = stored(&moved, "Bob", &bob_db).await;
    eventually("every member holds Bob's new relay", || sessions.iter().all(|s| s.node.hint(&bob_key) == Some(moved.url.to_string()))).await;
}

/// A summary without a relay leaves the hint saved before it.
#[tokio::test(flavor = "multi_thread")]
async fn a_summary_without_relay_keeps_the_hint() {
    let relay = relay().await;
    let dir = folder("relays-keep");
    let (alice_db, bob_db) = (dir.join("alice.db"), dir.join("bob.db"));
    let alice = stored(&relay, "Alice", &alice_db).await;
    let bob = stored(&relay, "Bob", &bob_db).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let (bob_iroh, url) = (bob.node.address().0, relay.url.to_string());
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh) == Some(url.clone())).await;
    let joined = alice.node.heard(&gid.0).unwrap().iter().find(|heard| heard.member.name == "Bob").unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    // Bob's stopped session, standing in for itself, signs a newer summary that names no relay.
    let (iroh, mls) = member_of(&bob_db);
    let shown = seqs(&Bytes(mls.key().to_vec()), joined, &[1]);
    let summary = Summary {
        group: gid.clone(),
        member: Bytes(mls.key().to_vec()),
        joined,
        version: lmk_node::now() + 3_600_000,
        time: lmk_node::now(),
        epoch: alice.node.epoch(&gid.0).unwrap(),
        relay: None,
        held: Vec::new(),
        sealed: Vec::new(),
        shown: vec![shown.clone()],
        lost: Vec::new(),
    };
    let body = serde_json::to_vec(&summary).unwrap();
    let sig = mls.sign(&[SUMMARY, &body].concat());
    let mut bob_hand = hand(&relay, iroh, &alice.node).await;
    bob_hand.send(&Frame::Summaries { group: gid.clone(), items: vec![Signed { body: Bytes(body), sig: Bytes(sig) }] }).await;
    eventually("Alice takes the summary", || alice.node.heard(&gid.0).unwrap().iter().any(|heard| heard.shown == [shown.clone()])).await;
    assert_eq!(alice.node.hint(&bob_iroh), Some(url));
}

/// A summary names a relay only if it is an https one: a member's other relay is taken from no summary.
#[tokio::test(flavor = "multi_thread")]
async fn a_summary_relay_must_be_https() {
    let relay = relay().await;
    let dir = folder("relays-https");
    let (alice_db, bob_db) = (dir.join("alice.db"), dir.join("bob.db"));
    let alice = stored(&relay, "Alice", &alice_db).await;
    let bob = stored(&relay, "Bob", &bob_db).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let (bob_iroh, url) = (bob.node.address().0, relay.url.to_string());
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh) == Some(url.clone())).await;
    let joined = alice.node.heard(&gid.0).unwrap().iter().find(|heard| heard.member.name == "Bob").unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    let (iroh, mls) = member_of(&bob_db);
    let shown = seqs(&Bytes(mls.key().to_vec()), joined, &[1]);
    let summary = Summary {
        group: gid.clone(),
        member: Bytes(mls.key().to_vec()),
        joined,
        version: lmk_node::now() + 3_600_000,
        time: lmk_node::now(),
        epoch: alice.node.epoch(&gid.0).unwrap(),
        relay: Some("http://127.0.0.1:1".into()),
        held: Vec::new(),
        sealed: Vec::new(),
        shown: vec![shown.clone()],
        lost: Vec::new(),
    };
    let body = serde_json::to_vec(&summary).unwrap();
    let sig = mls.sign(&[SUMMARY, &body].concat());
    let mut bob_hand = hand(&relay, iroh, &alice.node).await;
    bob_hand.send(&Frame::Summaries { group: gid.clone(), items: vec![Signed { body: Bytes(body), sig: Bytes(sig) }] }).await;
    eventually("Alice takes the summary", || alice.node.heard(&gid.0).unwrap().iter().any(|heard| heard.shown == [shown.clone()])).await;
    assert_eq!(alice.node.hint(&bob_iroh), Some(url));
}

/// A member's hint is one record, saved when its relay changes: a newer summary that names the same relay saves nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_hint_is_saved_when_the_relay_changes() {
    let relay = relay().await;
    let dir = folder("relays-saved");
    let (alice_db, bob_db) = (dir.join("alice.db"), dir.join("bob.db"));
    let alice = stored(&relay, "Alice", &alice_db).await;
    let bob = stored(&relay, "Bob", &bob_db).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let (bob_iroh, url) = (bob.node.address().0, relay.url.to_string());
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh) == Some(url.clone())).await;
    let saved = hint_records(&alice_db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].0, [b"node/hint/".as_slice(), &bob_iroh].concat());
    let joined = alice.node.heard(&gid.0).unwrap().iter().find(|heard| heard.member.name == "Bob").unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    let (iroh, mls) = member_of(&bob_db);
    let shown = seqs(&Bytes(mls.key().to_vec()), joined, &[1]);
    let summary = Summary {
        group: gid.clone(),
        member: Bytes(mls.key().to_vec()),
        joined,
        version: lmk_node::now() + 3_600_000,
        time: lmk_node::now(),
        epoch: alice.node.epoch(&gid.0).unwrap(),
        relay: Some(url.clone()),
        held: Vec::new(),
        sealed: Vec::new(),
        shown: vec![shown.clone()],
        lost: Vec::new(),
    };
    let body = serde_json::to_vec(&summary).unwrap();
    let sig = mls.sign(&[SUMMARY, &body].concat());
    let mut bob_hand = hand(&relay, iroh, &alice.node).await;
    bob_hand.send(&Frame::Summaries { group: gid.clone(), items: vec![Signed { body: Bytes(body), sig: Bytes(sig) }] }).await;
    eventually("Alice takes the summary", || alice.node.heard(&gid.0).unwrap().iter().any(|heard| heard.shown == [shown.clone()])).await;
    assert_eq!(hint_records(&alice_db), saved);
}

/// A member removed from its last group loses its hint, saved or held.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_in_no_group_has_no_hint() {
    let relay = relay().await;
    let dir = folder("relays-removed");
    let alice_db = dir.join("alice.db");
    let alice = stored(&relay, "Alice", &alice_db).await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let bob_iroh = bob.node.address().0;
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh).is_some()).await;
    let bob_key = alice.node.members(&gid.0).unwrap().into_iter().find(|m| m.name == "Bob").unwrap().key;
    assert!(alice.node.remove(&gid.0, &bob_key.0).await.unwrap());
    assert_eq!(alice.node.hint(&bob_iroh), None);
    assert!(hint_records(&alice_db).is_empty());
}

/// A session removed from its only group drops the hints of the members it shared it with.
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_session_drops_its_groups_hints() {
    let relay = relay().await;
    let dir = folder("relays-forgotten");
    let alice_db = dir.join("alice.db");
    let mut alice = stored(&relay, "Alice", &alice_db).await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let bob_iroh = bob.node.address().0;
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh).is_some()).await;
    let alice_key = bob.node.members(&gid.0).unwrap().into_iter().find(|m| m.name == "Alice").unwrap().key;
    assert!(bob.node.remove(&gid.0, &alice_key.0).await.unwrap());
    alice.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
    assert_eq!(alice.node.hint(&bob_iroh), None);
    assert!(hint_records(&alice_db).is_empty());
}

/// The hint records of a session's database.
fn hint_records(db: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    let db = rusqlite::Connection::open(db).unwrap();
    let mut select = db.prepare("SELECT key, value FROM lmk").unwrap();
    let rows = select.query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))).unwrap();
    rows.map(Result::unwrap).filter(|(key, _)| key.starts_with(b"node/hint/")).collect()
}

/// Hints are saved with the session: a member restarted with its co-members away still holds what they said.
#[tokio::test(flavor = "multi_thread")]
async fn hints_survive_a_restart() {
    let relay = relay().await;
    let dir = folder("relays-restart");
    let alice_db = dir.join("alice.db");
    let alice = stored(&relay, "Alice", &alice_db).await;
    let bob = session(&relay, "Bob").await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    let (bob_iroh, url) = (bob.node.address().0, relay.url.to_string());
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh) == Some(url.clone())).await;
    bob.node.shutdown().await.unwrap();
    drop(bob);
    alice.node.shutdown().await.unwrap();
    drop(alice);

    let alice = stored(&relay, "Alice", &alice_db).await;
    assert_eq!(alice.node.hint(&bob_iroh), Some(url));
}

/// A post that counts the requests for heads it passes on.
fn counting(post: Post) -> (Arc<std::sync::atomic::AtomicUsize>, Post) {
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = asked.clone();
    let post: Post = Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| {
        if route == "/membership/2/heads" {
            counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        post(domain, route, body)
    });
    (asked, post)
}

/// The domain and route of each request a post passed on.
type Requests = Arc<std::sync::Mutex<Vec<(String, &'static str)>>>;

/// A post that records the requests it passes on.
fn recording(post: Post) -> (Requests, Post) {
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let post: Post = Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| {
        recorded.lock().unwrap().push((domain.clone(), route));
        post(domain, route, body)
    });
    (requests, post)
}

/// Waits until a recording has taken no request for a second: what was under way ended.
async fn quiet(requests: &Requests) {
    let mut seen = usize::MAX;
    while requests.lock().unwrap().len() != seen {
        seen = requests.lock().unwrap().len();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// A device's passes ask the service nothing while the directory it holds lists its identity group's devices.
#[tokio::test(flavor = "multi_thread")]
async fn a_devices_pass_with_nothing_to_publish_asks_nothing() {
    let relay = relay().await;
    let (requests, post) = recording(relay.post());
    let device = Device::new("laptop");
    let (node, _events) = Node::start(MemoryProvider::default(), Config { post, ..config(&relay, "laptop", Some(device.clone())) }).await.unwrap();
    let devices = Identity::new(node.clone(), device, Arc::new(|_: &Device| Ok(())));
    devices.create("Carol", relay.service.clone()).await.unwrap();
    let gid = devices_group(&node);
    devices.duties(&gid.0).await.unwrap();
    quiet(&requests).await;
    let before = requests.lock().unwrap().len();
    for _ in 0..3 {
        assert!(devices.on(Event::Duties { group: gid.clone() }).is_none());
    }
    quiet(&requests).await;
    assert_eq!(requests.lock().unwrap().len(), before, "the passes asked nothing");
    devices.duties(&gid.0).await.unwrap();
    assert!(requests.lock().unwrap().len() > before, "duties asked for read the directory");
    node.shutdown().await.unwrap();
}

/// A member entering an epoch a peer brought it into asks the service once: it opens the epoch's log.
#[tokio::test(flavor = "multi_thread")]
async fn entering_an_epoch_takes_one_request() {
    let relay = relay().await;
    let alice = session(&relay, "Alice").await;
    let (requests, post) = recording(relay.post());
    let bob = session_with(&relay, "Bob", post).await;
    let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
    eventually("Alice has Bob", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    quiet(&requests).await;
    let before = requests.lock().unwrap().len();
    alice.node.change_settings(&gid.0, |s| Settings { name: "Moved".into(), ..s }).await.unwrap();
    eventually("Bob applied the commit", || bob.node.settings(&gid.0).unwrap().name == "Moved").await;
    quiet(&requests).await;
    let routes: Vec<&str> = requests.lock().unwrap()[before..].iter().map(|(_, route)| *route).collect();
    assert_eq!(routes, ["/membership/2/append"]);
    alice.node.shutdown().await.unwrap();
    bob.node.shutdown().await.unwrap();
}

/// How long a read of a group's logs stands for a send.
const FRESH_MS: u64 = 2 * 60 * 1000;

/// A send asks each service about its group's logs in one request: the group's, and that of the identity a member speaks
/// as, which lives on another.
#[test]
fn a_send_asks_each_service_once() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("heads");
        let (other, _service) = served(&relay, &dir).await;
        let (requests, post) = recording(relay.post());
        let alice = session_with(&relay, "Alice", post).await;
        let (carol, laptop) = identity(&relay, &alice.node, other.clone()).await;
        let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
        let tablet = session(&relay, "tablet").await;
        let certified = certificate(&carol, &laptop, &tablet.node.key(), "Carol", "laptop");
        tablet.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), Some(certified)).await.unwrap();
        eventually("Alice holds Carol's session", || alice.node.members(&gid.0).unwrap().len() == 2).await;
        quiet(&requests).await;
        SHIFT.fetch_add(FRESH_MS, std::sync::atomic::Ordering::Relaxed);
        let before = requests.lock().unwrap().len();
        alice.node.send(&gid.0, &message("asks"), None).await.unwrap();
        let mut asked: Vec<String> = requests.lock().unwrap()[before..].iter().filter(|(_, route)| *route == "/membership/2/heads").map(|(domain, _)| domain.clone()).collect();
        asked.sort();
        let domain = |service: &Service| match service {
            Service::Serve { domain, .. } => domain.clone(),
            _ => unreachable!(),
        };
        let mut expected = vec![domain(&relay.service), domain(&other)];
        expected.sort();
        assert_eq!(asked, expected);
        alice.node.shutdown().await.unwrap();
        tablet.node.shutdown().await.unwrap();
    });
}

/// A send asks the service about its group's logs when this session has not read them within 2 minutes, and then only,
/// and reads on through each epoch a commit moves the group to: a member that the second of two commits no peer pushed
/// removed gets nothing sealed after the send reads them.
#[test]
fn a_send_reads_the_group_first_when_its_copy_is_older_than_2_minutes() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        // Alice reaches peers through one relay only, Carol through another, and Bob through either: Alice and Carol meet
        // only through Bob.
        let (relay, other) = (relay().await, relay().await);
        let alice = session(&relay, "Alice").await;
        let bob = session_trusting([&other, &relay], "Bob").await;
        let (asked, post) = counting(other.post());
        let mut carol = session_with(&other, "Carol", post).await;
        let gid = alice.node.create(settings(CHAT, &relay), None).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        carol.node.join(&bob.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), None).await.unwrap();
        eventually("Carol holds the three members", || carol.node.members(&gid.0).unwrap().len() == 3).await;

        bob.node.shutdown().await.unwrap();
        alice.node.change_settings(&gid.0, |s| Settings { name: "Moved".into(), ..s }).await.unwrap();
        alice.node.remove(&gid.0, &bob.node.key().0).await.unwrap();
        SHIFT.fetch_add(FRESH_MS, std::sync::atomic::Ordering::Relaxed);
        let before = asked.load(std::sync::atomic::Ordering::Relaxed);
        carol.node.send(&gid.0, &message("after"), None).await.unwrap();
        assert_eq!(asked.load(std::sync::atomic::Ordering::Relaxed), before + 1, "the send asked about the group's log");
        assert_eq!(carol.node.members(&gid.0).unwrap().len(), 2, "the message was sealed to Alice and Carol alone");
        carol.until(|e| matches!(&e, Event::Left { member, .. } if member.name == "Bob").then_some(())).await;
        let read = asked.load(std::sync::atomic::Ordering::Relaxed);
        carol.node.send(&gid.0, &message("again"), None).await.unwrap();
        assert_eq!(asked.load(std::sync::atomic::Ordering::Relaxed), read, "a send within 2 minutes of a read asks nothing");
        alice.node.shutdown().await.unwrap();
        carol.node.shutdown().await.unwrap();
    });
}

/// A send removes the session of a device its identity's directory dropped, which the send read, before it seals: what it
/// sends never reaches the device.
#[test]
fn a_send_removes_a_revoked_devices_session_before_sealing() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("revoked-on-send");
        let (membership, _service) = signing_service(&relay, &dir).await;
        let alice = session(&relay, "Alice").await;
        let (carol, laptop) = identity(&relay, &alice.node, membership.clone()).await;
        let tablet_key: [u8; 32] = lmk_core::random();
        let log = alice.node.read_public(&carol).await.unwrap();
        let both = vec![lmk_core::device::public(&laptop).into(), lmk_core::device::public(&tablet_key).into()];
        publish(&relay, &alice.node, &carol, log.next(&laptop, both)).await;
        let gid = alice.node.create(Settings { membership: membership.clone(), ..settings(CHAT, &relay) }, None).unwrap();
        let tablet = session(&relay, "tablet").await;
        let certified = certificate(&carol, &tablet_key, &tablet.node.key(), "Carol", "tablet");
        tablet.node.join(&alice.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), Some(certified)).await.unwrap();
        eventually("Alice holds the tablet's session", || alice.node.members(&gid.0).unwrap().len() == 2).await;

        // The laptop drops the tablet from Carol's directory, which no one tells Alice.
        let log = alice.node.read_public(&carol).await.unwrap();
        let entry = log.next(&laptop, vec![lmk_core::device::public(&laptop).into()]);
        ServeClient::for_service(relay.post(), &carol.membership).unwrap().append(&lmk_proto::public::address(&carol.id.0), &[entry], true).await.unwrap();
        SHIFT.fetch_add(FRESH_MS, std::sync::atomic::Ordering::Relaxed);
        alice.node.send(&gid.0, &message("after"), None).await.unwrap();
        assert_eq!(alice.node.members(&gid.0).unwrap().len(), 1, "the tablet's session was removed before the message was sealed");
        alice.node.shutdown().await.unwrap();
        tablet.node.shutdown().await.unwrap();
    });
}
