//! Sessions over a local relay with a self-signed certificate, their logs on a membership service served through it.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use iroh::tls::CaTlsConfig;
use n0_future::boxed::BoxFuture;
use n0_future::task::AbortOnDropHandle;
use lmk_core::group::Session as Mls;
use lmk_core::provider::SqliteProvider;
use lmk_membership::client::{Post, ServeClient};
use lmk_membership::store::Store;
use lmk_testing::{Relay, relay, relay_beside};
use lmk_node::{Config, Event, INVITE_VALID, Node, SendError};
use lmk_proto::directory::Directory;
use lmk_proto::group::{ChatMessage, PROTOCOL, Service, Settings};
use lmk_proto::Bytes;
use lmk_proto::frame::{self, ALPN};
use lmk_proto::head::Head;
use lmk_proto::peer::{Frame, SUMMARY, Seqs, Signed, Summary};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::UnboundedReceiver;

/// Generous, for slow CI runners with tests running side by side.
const WAIT: Duration = Duration::from_secs(60);

struct Session {
    node: Node,
    events: UnboundedReceiver<Event>,
}

async fn session(relay: &Relay) -> Session {
    let (node, events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(relay)).await.unwrap();
    Session { node, events }
}

/// A session that posts to membership services through `post`.
async fn session_with(relay: &Relay, post: Post) -> Session {
    let (node, events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), Config { post, ..config(relay) }).await.unwrap();
    Session { node, events }
}

/// A session that trusts the certificates of several relays, for peers and services on any of them.
async fn session_trusting(relays: [&Relay; 2]) -> Session {
    let ca = CaTlsConfig::custom_roots([relays[0].cert.clone(), relays[1].cert.clone()]);
    let (node, events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), Config { ca, ..config(relays[0]) }).await.unwrap();
    Session { node, events }
}

fn config(relay: &Relay) -> Config {
    Config {
        relays: vec![relay.url.clone()],
        chosen: vec![],
        resolve: lmk_testing::resolve(),
        post: relay.post(),
        ca: relay.ca(),
    }
}

impl Session {
    /// Waits for the event `wanted` takes. Past `WAIT`, fails naming where it was awaited, and each group's epoch and
    /// members online.
    #[track_caller]
    fn until<T>(&mut self, mut wanted: impl FnMut(Event) -> Option<T>) -> impl Future<Output = T> {
        let at = std::panic::Location::caller();
        async move {
            let waited = tokio::time::timeout(WAIT, async {
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
            .await;
            waited.unwrap_or_else(|_| {
                let groups: Vec<_> = self.node.groups().into_iter().map(|gid| {
                    let online: Vec<Bytes> = self.node.online(&gid.0).unwrap_or_default().into_iter().map(|m| m.key).collect();
                    (self.node.epoch(&gid.0).ok(), online)
                }).collect();
                panic!("the event awaited at {at} did not come; each group's epoch and members online: {groups:?}")
            })
        }
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

fn settings(relay: &Relay) -> Settings {
    Settings {
        protocol: PROTOCOL,
        carry: 7,
        update: lmk_proto::group::UPDATE,
        membership: relay.service.clone(),
    }
}

fn message(text: &str) -> Value {
    serde_json::to_value(ChatMessage { content: text.into(), to: vec![], urgent: false, attachment: None, sent_at: None }).unwrap()
}

/// Admits `n` strangers to the group of `member`, each of which stops once admitted: a commit removing one moves the group
/// on without a message.
async fn strangers(member: &mut Session, gid: &Bytes, relay: &Relay, n: usize) -> Vec<Bytes> {
    let mut keys = Vec::new();
    for _ in 0..n {
        let joiner = session(relay).await;
        keys.push(joiner.node.key());
        joiner.node.join(&member.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        member.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        joiner.node.shutdown().await.unwrap();
    }
    keys
}

/// A member whose own relay is down is reached through the relay of its group's service, which its node holds too.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_is_reached_through_its_groups_service_when_its_own_relay_is_down() {
    let (service, own) = (relay().await, relay().await);
    let mut carol = session(&service).await;
    let gid = carol.node.create(settings(&service)).unwrap();
    // Bob's own relay is down, and Alice lives on another: Bob is reached through the relay of its group's service.
    let alice = session_trusting([&own, &service]).await;
    alice.node.join(&carol.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let dead: iroh::RelayUrl = "https://127.0.0.1:1".parse().unwrap();
    let (node, events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), Config { relays: vec![dead, service.url.clone()], ..config(&service) }).await.unwrap();
    let mut bob = Session { node, events };
    bob.node.join(&carol.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
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
    let mut carol = session(&service).await;
    let gid = carol.node.create(settings(&service)).unwrap();
    // Bob's home is his first relay, which is not the service's.
    let (node, events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), Config { relays: vec![own.url.clone(), service.url.clone()], ca: CaTlsConfig::custom_roots([own.cert.clone(), service.cert.clone()]), ..config(&service) }).await.unwrap();
    let mut bob = Session { node, events };
    bob.node.join(&carol.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    carol.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let link = bob.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    let dan = session(&service).await;
    dan.node.join(&link).await.unwrap();
    bob.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
}

/// A link whose domain does not resolve still admits its joiner: the members it names are dialed at their own relays.
#[tokio::test(flavor = "multi_thread")]
async fn a_join_survives_an_unresolved_link_domain() {
    let relay = relay().await;
    let mut alice = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    // Only Bob's node fails to resolve the link's domain: Alice's commits still need the service's directory.
    let unresolved: lmk_membership::client::Resolve = Arc::new(|domain: String| -> BoxFuture<anyhow::Result<Directory>> {
        Box::pin(async move { anyhow::bail!("no directory for {domain}") })
    });
    let (node, events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), Config { resolve: unresolved, ..config(&relay) }).await.unwrap();
    let bob = Session { node, events };
    bob.node.join(&link).await.unwrap();
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
    let alice = stored_with(&relay, &path, post).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    let epoch = alice.node.epoch(&gid.0).unwrap();
    late.store(true, std::sync::atomic::Ordering::SeqCst);
    let joining = {
        let (node, link) = (bob.node.clone(), link.clone());
        tokio::spawn(async move { node.join(&link).await })
    };
    tokio::time::timeout(WAIT, landing.recv()).await.unwrap().unwrap();
    alice.node.shutdown().await.unwrap();
    drop(alice);
    joining.abort();
    assert!(bob.node.groups().is_empty());

    let alice = stored(&relay, &path).await;
    let joining = {
        let node = bob.node.clone();
        tokio::spawn(async move { node.join(&link).await })
    };
    assert_eq!(tokio::time::timeout(WAIT, joining).await.unwrap().unwrap().unwrap().0, gid);
    assert_eq!(alice.node.epoch(&gid.0).unwrap(), epoch + 1, "the retry got the logged Add, not another");
    alice.node.shutdown().await.unwrap();
    bob.node.shutdown().await.unwrap();
}

/// A chat of two: a message arrives with its sender, one of 8 MiB too, and a removal ends its group for the removed
/// member.
#[tokio::test(flavor = "multi_thread")]
async fn chat_and_removal() {
    let relay = relay().await;
    let mut alice = session(&relay).await;
    let mut bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    let (joined, _) = bob.node.join(&link).await.unwrap();
    assert_eq!(joined, gid);
    let member = alice.until(|e| match e {
        Event::Joined { member, .. } => Some(member),
        _ => None,
    }).await;
    assert_eq!(member.key, bob.node.key());
    assert_eq!(bob.node.members(&gid.0).unwrap().len(), 2);

    let sent = bob.node.send(&gid.0, &message("hello"), None).await.unwrap();
    let got = alice.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((got.id, got.seq, got.sender.key), (sent, 1, bob.node.key()));
    let large = message(&"y".repeat(8 << 20));
    let sent = bob.node.send(&gid.0, &large, None).await.unwrap();
    let got = alice.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!((got.id, got.payload), (sent, large));
    let big = message(&"x".repeat(16 << 20));
    let refused = bob.node.send(&gid.0, &big, None).await.unwrap_err();
    assert!(matches!(refused.downcast_ref(), Some(lmk_node::SendError::Size(_))), "{refused:#}");

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
    let mut alice = session(&relay).await;
    let mut bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    // A member named first that cannot be reached holds up nothing while another can.
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    let dead = *iroh::SecretKey::from_bytes(&lmk_core::random()).public().as_bytes();
    let started = std::time::Instant::now();
    bob.node.join(&Invite { members: vec![dead, link.members[0]], ..link }).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;

    // Two joiners race with one secret, each asking another member: one gets in, and the other is refused.
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    assert_eq!(link.members.len(), 2, "the link names the inviter and the member that took the invite");
    let only = |n: usize| Invite { members: vec![link.members[n]], ..link.clone() };
    let (carol, dave) = (session(&relay).await, session(&relay).await);
    let (to_alice, to_bob) = (only(0), only(1));
    let (by_alice, by_bob) = tokio::join!(carol.node.join(&to_alice), dave.node.join(&to_bob));
    assert!(by_alice.is_ok() != by_bob.is_ok(), "{by_alice:?} {by_bob:?}");
    let refused = format!("{:#}", by_alice.err().or(by_bob.err()).unwrap());
    assert!(refused.contains("unknown, used or expired"), "{refused}");
    let erin = session(&relay).await;
    let erin_key = erin.node.key();
    let used = erin.node.join(&link).await.unwrap_err();
    assert!(format!("{used:#}").contains("unknown, used or expired"), "a used secret is refused");

    // A member that redeems a link is refused, routinely, and the link stays unused.
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    let member = bob.node.join(&link).await.unwrap_err();
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
    assert!(format!("{:#}", erin.node.join(&expired).await.unwrap_err()).contains("unknown, used or expired"));

    // With the inviter offline, another member it named admits the joiner.
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let (joined, by) = erin.node.join(&link).await.unwrap();
    assert_eq!(joined, gid);
    assert!(link.members[1..].contains(&by), "another member admits");
    bob.until(|e| matches!(e, Event::Joined { member, .. } if member.key == erin_key).then_some(())).await;
}

/// A member reached first that never answers keeps the joiner from no other member it dials meanwhile.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_member_reached_first_holds_up_no_other() {
    use lmk_proto::links::Invite;
    let relay = relay().await;
    let alice = session(&relay).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    let key = iroh::SecretKey::from_bytes(&lmk_core::random());
    let silent = *key.public().as_bytes();
    let _silent = hand(&relay, key.clone(), &bob.node).await;
    eventually("the silent member is connected", || bob.node.net().connected().contains(&key.public())).await;
    let (joined, by) = bob.node.join(&Invite { members: vec![silent, link.members[0]], ..link.clone() }).await.unwrap();
    assert_eq!((joined, by), (gid, link.members[0]));
    alice.node.shutdown().await.unwrap();
}

/// An invite dies when its inviter leaves the group, removed or by `leave`.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_dies_when_its_inviter_leaves() {
    use lmk_proto::links::Invite;
    let relay = relay().await;
    let mut alice = session(&relay).await;
    let (bob, carol) = (session(&relay).await, session(&relay).await);
    let gid = alice.node.create(settings(&relay)).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    let (by_bob, by_carol) = (bob.node.invite(&gid.0, INVITE_VALID, None).await.unwrap(), carol.node.invite(&gid.0, INVITE_VALID, None).await.unwrap());
    let invites = || alice.node.messages(&gid.0).unwrap().iter().filter(|m| m.payload["type"] == "invite").count();
    eventually("Alice holds both invites", || invites() == 4).await;

    alice.node.remove(&gid.0, &bob.node.key().0).await.unwrap();
    carol.node.leave(&gid.0).unwrap();
    eventually("Bob and Carol are out", || alice.node.members(&gid.0).unwrap().len() == 1).await;
    let dave = session(&relay).await;
    let at_alice = alice.node.address().0;
    let ask_alice = |link: &Invite| Invite { members: vec![at_alice], ..link.clone() };
    for link in [&by_bob, &by_carol] {
        let refused = dave.node.join(&ask_alice(link)).await.unwrap_err();
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

/// A session whose leaf names an older revision writes its own as it starts.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_updates_an_older_leaf_as_it_starts() {
    use lmk_core::group::{Change, Group, Session as Mls};
    let relay = relay().await;
    let dir = folder("revision");
    std::fs::create_dir_all(&dir).unwrap();
    let bob_db = dir.join("bob.db");
    let start = || async { Node::start(SqliteProvider::open(&bob_db).unwrap(), config(&relay)).await.unwrap().0 };
    let alice = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let bob = start().await;
    let bob_key = bob.key();
    bob.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let revision = |wanted: u32| {
        let (node, gid, bob_key) = (&alice.node, &gid, &bob_key);
        tokio::time::timeout(WAIT, async move {
            while !node.members(&gid.0).unwrap().iter().any(|m| m.key == *bob_key && m.revision == wanted) {
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
    ServeClient::for_service(relay.post(), &relay.service).unwrap().append(&capability, &[commit.entry]).await.unwrap();
    drop(provider);
    revision(0).await.expect("Alice sees Bob's leaf of revision 0");

    let bob = start().await;
    revision(lmk_proto::group::REVISION).await.expect("Bob's leaf names this revision once he starts");
    bob.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();
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
    let relay = relay().await;
    let dir = folder(test);
    let (membership, _service) = served(&relay, &dir).await;
    let (gate, _reaching) = Gate::new(Some(&membership));
    let start = |name: &'static str| {
        let (relay, db, gate) = (&relay, dir.join(format!("{name}.db")), gate.clone());
        async move {
            let (node, events) = Node::start(SqliteProvider::open(&db).unwrap(), Config { post: gate.post(name, relay.post()), ..config(relay) }).await.unwrap();
            Session { node, events }
        }
    };
    let mut alice = start("Alice").await;
    let bob = start("Bob").await;
    let gid = alice.node.create(Settings { membership, ..settings(&relay) }).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;

    gate.set(false);
    bob.node.leave(&gid.0).unwrap().unwrap();
    let bob_key = bob.node.key();
    if restart_leaver {
        bob.node.shutdown().await.unwrap();
        drop(bob);
        gate.set(true);
        let _bob = start("Bob").await;
    } else {
        gate.set(true);
    }
    alice.until(|e| matches!(e, Event::Left { member, .. } if member.key == bob_key).then_some(())).await;
    assert_eq!(alice.node.members(&gid.0).unwrap().len(), 1);
    alice.node.shutdown().await.unwrap();
}

/// A `leave` sealed before its sender was removed and added again removes it no more.
#[tokio::test(flavor = "multi_thread")]
async fn an_old_leave_does_not_remove_a_member_added_again() {
    let relay = relay().await;
    let dir = folder("leave-again");
    std::fs::create_dir_all(&dir).unwrap();
    let alice_db = dir.join("alice.db");
    let start = || async {
        let (node, events) = Node::start(SqliteProvider::open(&alice_db).unwrap(), config(&relay)).await.unwrap();
        Session { node, events }
    };
    let mut alice = start().await;
    let mut bob = session(&relay).await;
    let carol = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Bob and Carol have both Adds", || [&bob, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 3)).await;
    alice.node.shutdown().await.unwrap();
    drop(alice);

    bob.node.leave(&gid.0).unwrap();
    bob.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
    bob.node.join(&carol.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
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

/// A member of a group that delivered nothing and changed nothing since its last update reads and commits nothing, days
/// later: the commit it missed reaches it at its next send, which stirs its update.
#[test]
fn an_idle_member_commits_nothing_until_it_sends() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("updated");
        std::fs::create_dir_all(&dir).unwrap();
        let mut alice = stored(&relay, &dir.join("alice.db")).await;
        let bob = stored(&relay, &dir.join("bob.db")).await;
        let gid = alice.node.create(settings(&relay)).unwrap();
        let spares = strangers(&mut alice, &gid, &relay, 1).await;
        bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        bob.node.shutdown().await.unwrap();
        drop(bob);
        alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
        let epoch = alice.node.epoch(&gid.0).unwrap();
        alice.node.shutdown().await.unwrap();

        let bob = stored(&relay, &dir.join("bob.db")).await;
        assert!(bob.node.epoch(&gid.0).unwrap() < epoch, "starting reads nothing");
        bob.node.shutdown().await.unwrap();
        drop(bob);
        SHIFT.store(2 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        let bob = stored(&relay, &dir.join("bob.db")).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(bob.node.epoch(&gid.0).unwrap() < epoch, "an idle member reads and commits nothing");
        bob.node.send(&gid.0, &message("back"), None).await.unwrap();
        assert!(bob.node.epoch(&gid.0).unwrap() >= epoch, "the send read the commit first");
        eventually("Bob's send stirs his update", || bob.node.epoch(&gid.0).unwrap() == epoch + 1).await;
        bob.node.shutdown().await.unwrap();
    });
}

/// Each commit moves a group to its new epoch's log, at a reference only the epoch's members can derive: a joiner reads
/// from the log its own update past its Add moved the group to, and a removed member is left behind on the last one it
/// could name.
#[tokio::test(flavor = "multi_thread")]
async fn each_commit_moves_the_group_to_its_new_epochs_log() {
    let relay = relay().await;
    let mut alice = session(&relay).await;
    let mut bob = session(&relay).await;
    let mut carol = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let mut logs = vec![alice.node.log(&gid.0).unwrap()];
    alice.node.send(&gid.0, &message("before anyone"), None).await.unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        let log = joiner.node.log(&gid.0).unwrap();
        assert!(!logs.contains(&log), "the Add, and the joiner's update past it, moved the group to a new log");
        eventually("Alice reads the joiner's update", || alice.node.log(&gid.0).unwrap() == log).await;
        logs.push(log);
    }
    alice.node.remove(&gid.0, &carol.node.key().0).await.unwrap();
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
    let mut alice = session(&relay).await;
    let mut bob = session(&relay).await;
    let mut carol = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    alice.node.send(&gid.0, &message("before Carol"), None).await.unwrap();
    carol.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
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
    let mut alice = session(&relay).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    alice.node.leave(&gid.0).unwrap();
    bob.node.leave(&gid.0).unwrap();
    eventually("both forgot the group", || alice.node.groups().is_empty() && bob.node.groups().is_empty()).await;
}

/// A removal that another member's commit already made answers ok and commits nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_removal_made_moot_commits_nothing() {
    let relay = relay().await;
    let mut alice = session(&relay).await;
    let mut bob = session(&relay).await;
    let carol = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    let epoch = carol.node.epoch(&gid.0).unwrap();
    eventually("Alice and Bob have both Adds, and Carol's update", || [&alice, &bob].iter().all(|s| s.node.epoch(&gid.0).unwrap() == epoch)).await;

    let carol_key = carol.node.key();
    let remove = |node: &Node| {
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
    assert!(epochs.0.max(epochs.1) == epoch + 1, "one removal committed: {epochs:?} after {epoch}");
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
            let mut config = config(relay);
            config.post = gate.post(name, relay.post());
            let (node, events) = Node::start(SqliteProvider::open(&dir.join(format!("{name}.db"))).unwrap(), config).await.unwrap();
            Session { node, events }
        }
    };
    let mut alice = start("Alice").await;
    let bob = start("Bob").await;
    let gid = alice.node.create(Settings { membership, ..settings(&relay) }).unwrap();
    let spares = strangers(&mut alice, &gid, &relay, 2).await;
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    // A joiner's update that its join could not land lands meanwhile: a send then asks to be sent again.
    let held = loop {
        match bob.node.send(&gid.0, &message("held before refusal"), None).await {
            Err(error) if matches!(error.downcast_ref::<SendError>(), Some(SendError::Behind)) => continue,
            sent => break sent.unwrap(),
        }
    };
    let members = bob.node.members(&gid.0).unwrap();
    let epoch = bob.node.epoch(&gid.0).unwrap();
    let log_ref: [u8; 32] = bob.node.log(&gid.0).unwrap().0.try_into().unwrap();
    bob.node.shutdown().await.unwrap();
    drop(bob);

    for spare in &spares {
        alice.node.remove(&gid.0, &spare.0).await.unwrap();
    }
    let missed = alice.node.send(&gid.0, &message("recover from the peer"), None).await.unwrap();
    let moved = alice.node.epoch(&gid.0).unwrap();
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
    // The barrier's commit is made through the same work a removal would be, so its event comes after any removal of the
    // group that was queued before it.
    let barrier = bob.node.create(settings(&relay)).unwrap();
    let barrier_spare = strangers(&mut bob, &barrier, &relay, 1).await;
    bob.node.remove(&barrier.0, &barrier_spare[0].0).await.unwrap();
    bob.until(|e| {
        assert!(!matches!(&e, Event::Removed { group, .. } if group == &gid), "refusal removed the group");
        matches!(e, Event::Left { group, .. } if group == barrier).then_some(())
    }).await;
    assert!(bob.node.groups().contains(&gid));
    assert_eq!(bob.node.members(&gid.0).unwrap(), members);
    assert_eq!(bob.node.epoch(&gid.0).unwrap(), epoch);
    assert_eq!(bob.node.message(&gid.0, &held.0).unwrap().unwrap().payload, message("held before refusal"));
    bob.node.shutdown().await.unwrap();

    gate.set(false);
    let mut bob = start("Bob").await;
    assert_eq!(bob.node.members(&gid.0).unwrap(), members);
    let alice = start("Alice").await;
    eventually("Bob takes the commits its peer brings", || bob.node.epoch(&gid.0).unwrap() == moved).await;
    while let Ok(event) = bob.events.try_recv() {
        assert!(!matches!(&event, Event::Removed { group, .. } if group == &gid), "{event:?}");
    }
    eventually("Bob takes the message beyond the expired history", || bob.node.message(&gid.0, &missed.0).unwrap().is_some()).await;
    assert_eq!(bob.node.message(&gid.0, &missed.0).unwrap().unwrap().payload, message("recover from the peer"));
    assert_eq!(bob.node.members(&gid.0).unwrap().len(), members.len() - 2, "the two commits removed their spares");
    assert!(bob.node.epoch(&gid.0).unwrap() > epoch);
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();
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

/// The records of Adds keep the group's members, the joins of the last H and those whose invites still admit: a member
/// removed longer than H ago leaves none.
#[test]
fn a_group_forgets_the_adds_of_members_gone_past_h() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("forgotten-adds");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("alice.db");
        let alice = stored(&relay, &db).await;
        let gid = alice.node.create(Settings { carry: 2, ..settings(&relay) }).unwrap();
        let mut keys = Vec::new();
        for valid in [INVITE_VALID, INVITE_VALID, 7 * DAY_MS] {
            let joiner = session(&relay).await;
            joiner.node.join(&alice.node.invite(&gid.0, valid, None).await.unwrap()).await.unwrap();
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
        assert!(keys.iter().all(|key| state().contains(&serde_json::to_string(key).unwrap())));

        SHIFT.store(3 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        let alice = stored(&relay, &db).await;
        eventually("Bob's record is forgotten", || !state().contains(&serde_json::to_string(&keys[0]).unwrap())).await;
        assert!(state().contains(&serde_json::to_string(&keys[1]).unwrap()), "a member's record stays");
        assert!(state().contains(&serde_json::to_string(&keys[2]).unwrap()), "a record stays while its invite admits");
        alice.node.shutdown().await.unwrap();
    });
}

/// A member whose epoch's log its service let go is removed by the others, which hold the commits it missed: the next
/// commit a member builds, its update once its message stirs it, asks the service about the logs members are behind in
/// first.
#[test]
fn a_member_in_an_epoch_the_service_let_go_is_removed_by_the_others() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("let-go-removed");
        let mut alice = stored(&relay, &dir.join("alice.db")).await;
        let bob = session(&relay).await;
        let bob_key = bob.node.key();
        let gid = alice.node.create(settings(&relay)).unwrap();
        let spares = strangers(&mut alice, &gid, &relay, 1).await;
        bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        bob.node.shutdown().await.unwrap();
        alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
        alice.node.ask_behind(&gid.0).await.unwrap();
        assert_eq!(alice.node.members(&gid.0).unwrap().len(), 2, "the log Bob is in is not gone yet");
        alice.node.shutdown().await.unwrap();
        drop(alice);

        SHIFT.store(8 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        let mut alice = stored(&relay, &dir.join("alice.db")).await;
        alice.node.send(&gid.0, &message("back"), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Left { member, .. } if member.key == bob_key).then_some(())).await;
        assert_eq!(alice.node.members(&gid.0).unwrap().len(), 1);
        alice.node.shutdown().await.unwrap();
    });
}

/// The types of the payloads of a group's messages a stopped stored member holds, by its author's key.
fn payload_types(db: &Path, gid: &Bytes) -> Vec<(Bytes, String)> {
    let db = rusqlite::Connection::open(db).unwrap();
    let mut select = db.prepare("SELECT value FROM lmk WHERE key >= ?1 AND key < ?2").unwrap();
    let prefix = [b"node/message/".as_slice(), &gid.0, b"/"].concat();
    let end = [b"node/message/".as_slice(), &gid.0, b"0"].concat();
    let values: Vec<Vec<u8>> = select.query_map([prefix, end], |row| row.get(0)).unwrap().map(Result::unwrap).collect();
    values.iter().map(|value| serde_json::from_slice::<Value>(value).unwrap()).map(|record| {
        let author = serde_json::from_value(record["header"]["author"].clone()).unwrap();
        (author, record["header"]["payload"]["type"].as_str().unwrap().to_string())
    }).collect()
}

/// A member that showed itself in no epoch since the group moved past the last one it did sends a `present` two days
/// later, while online: the others see it in the current epoch, so their evictions spare it once the log of that last
/// one is let go.
#[test]
fn an_idle_member_shows_itself_present_before_its_epochs_log_goes() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("present");
        std::fs::create_dir_all(&dir).unwrap();
        let (alice_db, bob_db) = (dir.join("alice.db"), dir.join("bob.db"));
        let mut alice = stored(&relay, &alice_db).await;
        let bob = stored(&relay, &bob_db).await;
        let gid = alice.node.create(settings(&relay)).unwrap();
        let spares = strangers(&mut alice, &gid, &relay, 1).await;
        bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        let epoch = bob.node.epoch(&gid.0).unwrap();
        eventually("Alice has Bob's update", || alice.node.epoch(&gid.0).unwrap() == epoch).await;
        alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
        eventually("Bob has the removal", || bob.node.epoch(&gid.0).unwrap() == epoch + 1).await;
        let bob_key = bob.node.key();
        for session in [alice, bob] {
            session.node.shutdown().await.unwrap();
        }
        assert!(!payload_types(&bob_db, &gid).contains(&(bob_key.clone(), "present".into())));

        SHIFT.store(3 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        let bob = stored(&relay, &bob_db).await;
        let alice = stored(&relay, &alice_db).await;
        let present = (bob_key.clone(), "present".to_string());
        eventually("Bob sends a present, and Alice holds it", || payload_types(&alice_db, &gid).contains(&present)).await;
        for session in [bob, alice] {
            session.node.shutdown().await.unwrap();
        }

        SHIFT.store(9 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        let alice = stored(&relay, &alice_db).await;
        alice.node.send(&gid.0, &message("stir"), None).await.unwrap();
        eventually("Alice updates", || alice.node.epoch(&gid.0).unwrap() == epoch + 2).await;
        assert_eq!(alice.node.members(&gid.0).unwrap().len(), 2, "Bob is spared");
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
        let mut alice = session(&relay).await;
        let bob = stored(&relay, &dir.join("bob.db")).await;
        let gid = alice.node.create(settings(&relay)).unwrap();
        let spares = strangers(&mut alice, &gid, &relay, 1).await;
        bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        bob.node.shutdown().await.unwrap();
        drop(bob);
        alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
        let alice_epoch = alice.node.epoch(&gid.0).unwrap();

        SHIFT.store(6 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        let mut bob = stored(&relay, &dir.join("bob.db")).await;
        eventually("Bob applied the commit", || bob.node.epoch(&gid.0).unwrap() >= alice_epoch).await;
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
        let mut alice = session(&relay).await;
        let bob = stored(&relay, &dir.join("bob.db")).await;
        let gid = alice.node.create(settings(&relay)).unwrap();
        let spares = strangers(&mut alice, &gid, &relay, 1).await;
        bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        bob.node.shutdown().await.unwrap();
        alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
        alice.node.shutdown().await.unwrap();

        SHIFT.store(8 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        let mut bob = stored(&relay, &dir.join("bob.db")).await;
        let refused = bob.node.send(&gid.0, &message("hello"), None).await.unwrap_err();
        assert!(matches!(refused.downcast_ref::<SendError>(), Some(SendError::LetGo)), "{refused:#}");
        assert!(bob.node.groups().contains(&gid), "a log let go is left only after WAIT with no entry of it brought");
        SHIFT.fetch_add(lmk_net::peers::WAIT + 60_000, std::sync::atomic::Ordering::Relaxed);
        bob.node.read_group(&gid.0).await.unwrap_err();
        let (by, not_kept) = bob.until(|e| match e {
            Event::Removed { group, by, not_kept, .. } if group == gid => Some((by, not_kept)),
            _ => None,
        }).await;
        assert!(by.is_none() && not_kept.is_empty(), "no commit removed it: its own log did");
        assert!(!bob.node.groups().contains(&gid));
        bob.node.shutdown().await.unwrap();
    });
}

/// A group nobody is online in for longer than `STALE` ends for each member as it comes back: it takes the group's log as
/// let go, as the service may have forgotten that it let it go.
#[test]
fn a_group_nobody_is_online_in_past_stale_ends() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("quiet-group");
        std::fs::create_dir_all(&dir).unwrap();
        let db = |name: &str| dir.join(format!("{name}.db"));
        let mut alice = stored(&relay, &db("alice")).await;
        let bob = stored(&relay, &db("bob")).await;
        let gid = alice.node.create(settings(&relay)).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        for session in [alice, bob] {
            session.node.shutdown().await.unwrap();
        }

        SHIFT.store(lmk_proto::membership::STALE + 60_000, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        for name in ["alice", "bob"] {
            let mut member = stored(&relay, &db(name)).await;
            member.node.read_group(&gid.0).await.unwrap_err();
            SHIFT.fetch_add(lmk_net::peers::WAIT + 60_000, std::sync::atomic::Ordering::Relaxed);
            member.node.read_group(&gid.0).await.unwrap_err();
            member.until(|e| matches!(&e, Event::Removed { group, by: None, .. } if *group == gid).then_some(())).await;
            assert!(member.node.groups().is_empty());
            member.node.shutdown().await.unwrap();
        }
    });
}

/// A group nobody is online in lives past the retention: its current log holds no entry, so the service keeps nothing
/// of it to let go, and its members, back within `STALE`, chat on.
#[test]
fn a_group_nobody_is_online_in_lives_until_stale() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("last-member");
        std::fs::create_dir_all(&dir).unwrap();
        let db = |name: &str| dir.join(format!("{name}.db"));
        let mut alice = stored(&relay, &db("alice")).await;
        let bob = stored(&relay, &db("bob")).await;
        let gid = alice.node.create(settings(&relay)).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        let epoch = bob.node.epoch(&gid.0).unwrap();
        eventually("Alice reads Bob's update", || alice.node.epoch(&gid.0).unwrap() == epoch).await;
        bob.node.shutdown().await.unwrap();
        drop(bob);
        alice.node.shutdown().await.unwrap();
        drop(alice);

        SHIFT.store(lmk_proto::membership::STALE - DAY_MS, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        let alice = stored(&relay, &db("alice")).await;
        let mut bob = stored(&relay, &db("bob")).await;
        alice.node.send(&gid.0, &message("still here"), None).await.unwrap();
        bob.until(|e| matches!(e, Event::Message(m) if m.payload == message("still here")).then_some(())).await;
        alice.node.shutdown().await.unwrap();
        bob.node.shutdown().await.unwrap();
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
        let mut alice = stored(&relay, &dir.join("alice.db")).await;
        let bob = stored(&relay, &dir.join("bob.db")).await;
        let bob_key = bob.node.key();
        let gid = alice.node.create(settings(&relay)).unwrap();
        let spares = strangers(&mut alice, &gid, &relay, 1).await;
        bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        bob.node.shutdown().await.unwrap();
        alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
        alice.node.shutdown().await.unwrap();
        drop(alice);

        // Alice is away, so that no peer brings Bob the commits.
        SHIFT.store(8 * DAY_MS, std::sync::atomic::Ordering::Relaxed);
        while relay.membership.expire().await {}
        let mut bob = stored(&relay, &dir.join("bob.db")).await;
        bob.node.read_group(&gid.0).await.unwrap_err();
        SHIFT.fetch_add(lmk_net::peers::WAIT + 60_000, std::sync::atomic::Ordering::Relaxed);
        bob.node.read_group(&gid.0).await.unwrap_err();
        bob.until(|e| matches!(&e, Event::Removed { group, .. } if *group == gid).then_some(())).await;
        bob.node.shutdown().await.unwrap();

        let mut alice = stored(&relay, &dir.join("alice.db")).await;
        let bob = stored(&relay, &dir.join("bob.db")).await;
        bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(&e, Event::Left { member, .. } if member.key == bob_key).then_some(())).await;
        alice.until(|e| matches!(&e, Event::Joined { member, .. } if member.key == bob_key).then_some(())).await;
        assert_eq!(alice.node.members(&gid.0).unwrap().len(), 2);
        alice.node.shutdown().await.unwrap();
        bob.node.shutdown().await.unwrap();
    });
}

/// A session that has not seen its group's log alive for `STALE` takes the log as let go, as its service may have
/// forgotten that it let it go, and asks the service nothing of it: it leaves the group once no peer brought the commits
/// within `WAIT`.
#[test]
fn a_log_not_seen_alive_for_stale_is_let_go_without_asking() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let (requests, post) = recording(relay.post());
        let mut alice = session_with(&relay, post).await;
        let gid = alice.node.create(settings(&relay)).unwrap();
        alice.node.read_group(&gid.0).await.unwrap();
        quiet(&requests).await;
        let asked = requests.lock().unwrap().len();
        SHIFT.store(lmk_proto::membership::STALE + 60_000, std::sync::atomic::Ordering::Relaxed);
        alice.node.read_group(&gid.0).await.unwrap_err();
        SHIFT.fetch_add(lmk_net::peers::WAIT + 60_000, std::sync::atomic::Ordering::Relaxed);
        alice.node.read_group(&gid.0).await.unwrap_err();
        alice.until(|e| matches!(&e, Event::Removed { group, .. } if *group == gid).then_some(())).await;
        assert_eq!(requests.lock().unwrap().len(), asked, "nothing asked of the service");
        alice.node.shutdown().await.unwrap();
    });
}

/// A session on SQLite at `db`, which survives a restart.
async fn stored(relay: &Relay, db: &Path) -> Session {
    stored_with(relay, db, relay.post()).await
}

/// A session on SQLite at `db` that posts to membership services through `post`.
async fn stored_with(relay: &Relay, db: &Path, post: Post) -> Session {
    let (node, events) = Node::start(SqliteProvider::open(db).unwrap(), Config { post, ..config(relay) }).await.unwrap();
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
    let mut alice = stored(&relay, &db("alice")).await;
    let bob = stored(&relay, &db("bob")).await;
    let carol = stored(&relay, &db("carol")).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let spares = strangers(&mut alice, &gid, &relay, 2).await;
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Bob and Carol have both Adds", || [&bob, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 5)).await;
    let (bob_key, carol_key) = (bob.node.key(), carol.node.key());
    carol.node.shutdown().await.unwrap();
    drop(carol);

    // Alice holds Bob's message and keeps it in a commit; then Alice and Bob stop, and Carol, back, has no holder.
    let sent = bob.node.send(&gid.0, &message("only Alice and Bob hold this"), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    for spare in &spares {
        alice.node.remove(&gid.0, &spare.0).await.unwrap();
    }
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();

    let mut carol = stored(&relay, &db("carol")).await;
    carol.node.read_group(&gid.0).await.unwrap();
    let lost = carol.until(|e| match e {
        Event::Lost(lost) => Some(lost),
        _ => None,
    }).await;
    assert_eq!(lost.member.key, carol_key);
    assert_eq!((lost.messages[0].from.key.clone(), lost.messages[0].seqs.clone()), (bob_key, vec![1]));
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
    let mut alice = stored(&relay, &db("alice")).await;
    let bob = stored(&relay, &db("bob")).await;
    let carol = stored(&relay, &db("carol")).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let spares = strangers(&mut alice, &gid, &relay, 2).await;
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Bob and Carol have both Adds", || [&bob, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 5)).await;
    let bob_key = bob.node.key();
    carol.node.shutdown().await.unwrap();
    drop(carol);

    bob.node.send(&gid.0, &message("only Alice and Bob hold this"), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    for spare in &spares {
        alice.node.remove(&gid.0, &spare.0).await.unwrap();
    }
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();

    SHIFT.store(8 * 24 * 3600 * 1000, std::sync::atomic::Ordering::Relaxed);
    let started = std::time::Instant::now();
    let mut carol = stored(&relay, &db("carol")).await;
    carol.node.read_group(&gid.0).await.unwrap();
    let lost = carol.until(|e| match e {
        Event::Lost(lost) => Some(lost),
        _ => None,
    }).await;
    assert!(started.elapsed() < Duration::from_millis(lmk_net::peers::HEAR), "took {:?}", started.elapsed());
    assert_eq!((lost.messages[0].from.key.clone(), lost.messages[0].seqs.clone()), (bob_key, vec![1]));
    carol.node.shutdown().await.unwrap();
}

/// `remove_others` removes every other member in one commit: the group is then its committer's alone.
#[tokio::test(flavor = "multi_thread")]
async fn remove_others_removes_every_other_member_in_one_commit() {
    let relay = relay().await;
    let mut alice = session(&relay).await;
    let mut bob = session(&relay).await;
    let mut carol = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
        let epoch = joiner.node.epoch(&gid.0).unwrap();
        eventually("Alice reads the joiner's update", || alice.node.epoch(&gid.0).unwrap() == epoch).await;
    }
    eventually("Bob has three members", || bob.node.members(&gid.0).unwrap().len() == 3).await;
    let epoch = alice.node.epoch(&gid.0).unwrap();
    alice.node.remove_others(&gid.0).await.unwrap();
    assert_eq!((alice.node.epoch(&gid.0).unwrap(), alice.node.members(&gid.0).unwrap().len()), (epoch + 1, 1));
    bob.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
    carol.until(|e| matches!(e, Event::Removed { .. }).then_some(())).await;
}

/// A `leave` stirs its sender's update. A leaver that updates while the others are away reseals its `leave` in the epoch
/// it moves to, and is removed once a member that holds it is back.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaver_asks_again_past_its_update() {
    let relay = relay().await;
    let dir = folder("leave-again-t");
    std::fs::create_dir_all(&dir).unwrap();
    let alice_db = dir.join("alice.db");
    let alice = stored(&relay, &alice_db).await;
    let mut bob = session(&relay).await;
    let gid = alice.node.create(Settings { update: 2, ..settings(&relay) }).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    alice.node.shutdown().await.unwrap();
    drop(alice);

    let epoch = bob.node.epoch(&gid.0).unwrap();
    bob.node.leave(&gid.0).unwrap().unwrap();
    eventually("Bob updates its leaf", || bob.node.epoch(&gid.0).unwrap() > epoch).await;

    let alice = stored(&relay, &alice_db).await;
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

/// A peer speaking the peer protocol by hand, on a connection it opens to a node.
struct Hand {
    _endpoint: iroh::Endpoint,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

async fn hand(relay: &Relay, key: iroh::SecretKey, to: &Node) -> Hand {
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
        self.send(&Frame::Want { group: gid.clone(), epoch: 0, wants: Vec::new() }).await;
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
    };
    let body = serde_json::to_vec(&summary).unwrap();
    let sig = mls.sign(&[SUMMARY, &body].concat());
    hand.send(&Frame::Summary { group: gid.clone(), summary: Signed { body: Bytes(body), sig: Bytes(sig) } }).await;
}

/// A member that reaches only one holder of a message a commit kept waits for it before applying the next commit, which
/// deletes the keys it needs, and takes the message from that holder. Quinn holds Sam's message, which Sam's first
/// commit keeps; Rita, online, hears Quinn hold it, and so waits for it from Quinn alone while Sam's second commit
/// waits. Sam stops after that.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_waits_for_the_kept_message_its_only_holder_gives() {
    let relay = relay().await;
    let dir = folder("line");
    std::fs::create_dir_all(&dir).unwrap();
    let dbs = ["sam", "quinn", "rita"].map(|name| dir.join(format!("{name}.db")));
    let mut sam = stored(&relay, &dbs[0]).await;
    let gid = sam.node.create(settings(&relay)).unwrap();
    let spares = strangers(&mut sam, &gid, &relay, 2).await;
    let links = [sam.node.invite(&gid.0, INVITE_VALID, None).await.unwrap(), sam.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()];
    let mut quinn = stored(&relay, &dbs[1]).await;
    quinn.node.join(&links[0]).await.unwrap();
    let rita = stored(&relay, &dbs[2]).await;
    rita.node.join(&links[1]).await.unwrap();
    rita.node.shutdown().await.unwrap();
    drop(rita);

    // Quinn is online for the message and holds it; Sam's first commit keeps it, as Quinn's summary shows it held.
    let sent = sam.node.send(&gid.0, &message("p"), None).await.unwrap();
    let got = quinn.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!(got.id, sent);
    let sam_key = sam.node.key();
    let held = |node: &Node| node.heard(&gid.0).unwrap().iter().any(|h| h.held.iter().any(|s| s.key == sam_key && s.seqs.contains(got.seq)));
    eventually("Sam hears that Quinn holds it", || held(&sam.node)).await;
    sam.node.remove(&gid.0, &spares[0].0).await.unwrap();

    // Rita comes back online and hears that Quinn holds the message before Sam's second commit needs it.
    let mut rita = stored(&relay, &dbs[2]).await;
    eventually("Rita hears that Quinn holds it", || held(&rita.node)).await;
    sam.node.remove(&gid.0, &spares[1].0).await.unwrap();
    let epoch = sam.node.epoch(&gid.0).unwrap();
    let got_by_rita = rita.until(|e| match e {
        Event::Message(message) => Some(message),
        _ => None,
    }).await;
    assert_eq!(got_by_rita.id, sent);
    eventually("Rita applied the second commit", || rita.node.epoch(&gid.0).unwrap() == epoch).await;
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
/// not sign; and its `want` gets nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_not_admitted_changes_nothing() {
    let relay = relay().await;
    let dir = folder("forged");
    let (membership, _service) = signing_service(&relay, &dir).await;
    let alice_db = dir.join("alice.db");
    let mut alice = stored(&relay, &alice_db).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(Settings { membership, ..settings(&relay) }).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
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
    assert!(mallory.settle(&gid).await.is_empty(), "a want the gate does not take gets nothing");
    assert_eq!(dump(&alice_db), before);
    while let Ok(event) = alice.events.try_recv() {
        assert!(!matches!(event, Event::Message(_)), "{event:?}");
    }
    alice.node.shutdown().await.unwrap();
}

/// A joiner whose `admitted` was lost asks again with the KeyPackage it kept: the committer answers with the Add's answer it
/// kept, and adds it no second time.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_whose_answer_was_lost_is_admitted_by_the_committers_answer() {
    let relay = relay().await;
    let (late, mut landing, post) = late_append(relay.post(), Duration::from_secs(5));
    let alice = session_with(&relay, post).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    let epoch = alice.node.epoch(&gid.0).unwrap();
    late.store(true, std::sync::atomic::Ordering::SeqCst);
    let (node, first) = (bob.node.clone(), link.clone());
    let joining = tokio::spawn(async move { node.join(&first).await });
    // The Add is in, and its answer is late: the joiner stops waiting for it.
    tokio::time::timeout(WAIT, landing.recv()).await.unwrap().unwrap();
    joining.abort();
    assert!(joining.await.is_err());

    let (joined, _) = tokio::time::timeout(WAIT, bob.node.join(&link)).await.unwrap().unwrap();
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
    let mut alice = session_with(&relay, post).await;
    let bob = session(&relay).await;
    let a = alice.node.create(Settings { membership: slow, ..settings(&relay) }).unwrap();
    let b = alice.node.create(settings(&relay)).unwrap();
    let spare_a = strangers(&mut alice, &a, &relay, 1).await;
    let spare_b = strangers(&mut alice, &b, &relay, 1).await;
    let link = alice.node.invite(&a.0, INVITE_VALID, None).await.unwrap();
    late.store(true, std::sync::atomic::Ordering::SeqCst);
    let (node, first) = (bob.node.clone(), link.clone());
    let joining = tokio::spawn(async move { node.join(&first).await });
    tokio::time::timeout(WAIT, landing.recv()).await.unwrap().unwrap();
    joining.abort();
    eventually("Alice applied the Add", || alice.node.members(&a.0).unwrap().len() == 3).await;

    // A removal in `a` waits for its log, which the gate holds shut.
    gate.set(false);
    let (node, group, spare) = (alice.node.clone(), a.clone(), spare_a[0].clone());
    let waiting = tokio::spawn(async move { node.remove(&group.0, &spare.0).await });
    assert_eq!(tokio::time::timeout(WAIT, reaching.recv()).await.unwrap().unwrap(), "Alice");
    tokio::time::timeout(Duration::from_secs(20), alice.node.remove(&b.0, &spare_b[0].0)).await.expect("B commits").unwrap();
    let (joined, _) = tokio::time::timeout(Duration::from_secs(20), bob.node.join(&link)).await.expect("the ask again is answered").unwrap();
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
    let (node, events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), Config { post, ..config(&relay) }).await.unwrap();
    let alice = Session { node, events };
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    let epoch = alice.node.epoch(&gid.0).unwrap();
    late.store(true, std::sync::atomic::Ordering::SeqCst);
    let (joined, _) = tokio::time::timeout(Duration::from_secs(120), bob.node.join(&link)).await.unwrap().unwrap();
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
    let (node, events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), Config { post, ..config(&relay) }).await.unwrap();
    let alice = Session { node, events };
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    let key = iroh::SecretKey::from_bytes(&lmk_core::random());
    let silent = *key.public().as_bytes();
    let _silent = hand(&relay, key.clone(), &bob.node).await;
    eventually("the silent member is connected", || bob.node.net().connected().contains(&key.public())).await;
    let link = Invite { members: vec![link.members[0], silent], ..link };
    let epoch = alice.node.epoch(&gid.0).unwrap();
    late.store(true, std::sync::atomic::Ordering::SeqCst);
    let (joined, _) = tokio::time::timeout(Duration::from_secs(120), bob.node.join(&link)).await.unwrap().unwrap();
    assert_eq!(joined, gid);
    assert_eq!(alice.node.epoch(&gid.0).unwrap(), epoch + 1, "one Add");
}

/// Two asks with one KeyPackage at once, as a joiner's again after one failed in transit: the member adds it once, and
/// answers the other with its Welcome too unless the joiner's update past its Add came first.
#[tokio::test(flavor = "multi_thread")]
async fn two_asks_with_one_key_package_add_it_once() {
    let relay = relay().await;
    let mut alice = session(&relay).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let link = alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap();
    let (one, two) = tokio::join!(bob.node.join(&link), bob.node.join(&link));
    // The joiner applies one Welcome; the other answer finds its KeyPackage spent, or the invite used.
    let joined = match (one, two) {
        (Ok((joined, _)), Err(_)) | (Err(_), Ok((joined, _))) => joined,
        answers => panic!("{answers:?}"),
    };
    assert_eq!(joined, gid);
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let epoch = bob.node.epoch(&gid.0).unwrap();
    eventually("Alice reads Bob's update", || alice.node.epoch(&gid.0).unwrap() == epoch).await;
    assert_eq!(alice.node.members(&gid.0).unwrap().len(), 2, "one Add");
}

/// A member connected is online, though not heard from yet.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_connected_is_online() {
    let relay = relay().await;
    let dir = folder("online");
    std::fs::create_dir_all(&dir).unwrap();
    let (alice_db, carol_db) = (dir.join("alice.db"), dir.join("carol.db"));
    let alice = stored(&relay, &alice_db).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    eventually("Alice has Bob's Add", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    alice.node.shutdown().await.unwrap();
    drop(alice);
    let carol = stored(&relay, &carol_db).await;
    let carol_key = carol.node.key();
    carol.node.join(&bob.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    carol.node.shutdown().await.unwrap();
    drop(carol);

    // Alice comes back; Carol, by hand, connects and says nothing.
    let alice = stored(&relay, &alice_db).await;
    eventually("Alice has Carol's Add", || alice.node.members(&gid.0).unwrap().len() == 3).await;
    let key = lmk_node::iroh_key(&SqliteProvider::open(&carol_db).unwrap()).unwrap();
    let _carol = hand(&relay, key, &alice.node).await;
    eventually("Carol is online", || alice.node.online(&gid.0).unwrap().iter().any(|m| m.key == carol_key)).await;
    alice.node.shutdown().await.unwrap();
}

/// The deps a stored member keeps for a message of `gid`.
fn deps_of(db: &Path, gid: &Bytes, id: &Bytes) -> Vec<lmk_proto::held::Ref> {
    let header = &record(db, gid, id)["header"];
    serde_json::from_value(header.get("deps").cloned().unwrap_or(json!([]))).unwrap()
}

/// Three members chat in causal order. Each sender's messages come with seqs 1, 2, 3, in order. A message's deps are the
/// frontier of what its sender marked shown since its last: Bob's first depends on Alice's first message, which he
/// showed; his second on nothing, as its prev covers that and he received her second but did not show it. Answering a
/// message shows it, so the answer's deps cover it.
#[tokio::test(flavor = "multi_thread")]
async fn three_members_chat_in_causal_order() {
    let relay = relay().await;
    let dir = folder("chat");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, &db("alice")).await;
    let bob = stored(&relay, &db("bob")).await;
    let carol = stored(&relay, &db("carol")).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
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
    assert_eq!((first.id.clone(), first.sender.key), (a1.clone(), alice.node.key()));
    bob.node.mark_shown(&gid.0, std::slice::from_ref(&a1)).unwrap();
    assert!(bob.node.shown(&gid.0, &a1.0).unwrap());
    let b1 = bob.node.send(&gid.0, &message("b1 replies to a1"), None).await.unwrap();
    let a2 = alice.node.send(&gid.0, &message("a2"), None).await.unwrap();
    let a3 = alice.node.send(&gid.0, &message("a3"), None).await.unwrap();
    let b2 = bob.node.send(&gid.0, &message("b2 is sent after a2 arrived, unshown"), None).await.unwrap();
    assert!(!bob.node.shown(&gid.0, &a2.0).unwrap());
    eventually("Bob holds a3", || bob.node.message(&gid.0, &a3.0).unwrap().is_some()).await;
    let b3 = bob.node.send(&gid.0, &message("b3 answers a3"), Some(&a3.0)).await.unwrap();
    assert!(bob.node.shown(&gid.0, &a3.0).unwrap());

    // Carol takes all six, each of Alice's in its seq order, and Bob's replies after the message they depend on.
    let mut taken = Vec::new();
    while taken.len() < 6 {
        taken.push(carol.until(|e| match e {
            Event::Message(message) => Some(message),
            _ => None,
        }).await);
    }
    let index = |id: &Bytes| taken.iter().find(|m| m.id == *id).unwrap().index;
    let seq = |id: &Bytes| taken.iter().find(|m| m.id == *id).unwrap().seq;
    assert_eq!([seq(&a1), seq(&a2), seq(&a3)], [3, 4, 5], "the two invites took seqs 1 and 2");
    assert!(index(&a1) < index(&b1) && index(&a2) < index(&a3) && index(&a3) < index(&b3), "causal order: {taken:?}");
    assert_eq!(taken.iter().find(|m| m.id == b3).unwrap().reply_to, Some(a3.clone()));
    assert!(taken.iter().all(|m| m.index >= 1 && m.missing.is_empty() && !m.late));
    // Carol shows all six: b3 depends on a3, which follows a1 and a2, and b1 and b2 precede it.
    carol.node.mark_shown(&gid.0, &taken.iter().map(|m| m.id.clone()).collect::<Vec<_>>()).unwrap();
    let c1 = carol.node.send(&gid.0, &message("c1"), None).await.unwrap();

    // Heard, Alice sees what Bob holds.
    let alice_key = alice.node.key();
    eventually("Alice hears that Bob holds a1", || {
        alice.node.heard(&gid.0).unwrap().iter().any(|h| h.member.key == bob.node.key() && h.held.iter().any(|s| s.key == alice_key && s.seqs.contains(first.seq)))
    })
    .await;
    bob.node.shutdown().await.unwrap();
    let sent = record(&db("bob"), &gid, &a1)["header"]["epoch"].as_u64().unwrap();
    assert_eq!(deps_of(&db("bob"), &gid, &b1), [lmk_proto::held::Ref { key: alice.node.key(), joined: 0, seq: 3, id: a1.clone(), epoch: sent }]);
    assert_eq!(deps_of(&db("bob"), &gid, &b2), [], "b1 covers a1, and a2 was not shown");
    assert_eq!(deps_of(&db("bob"), &gid, &b3), [lmk_proto::held::Ref { key: alice.node.key(), joined: 0, seq: 5, id: a3.clone(), epoch: sent }]);
    carol.node.shutdown().await.unwrap();
    assert_eq!(deps_of(&db("carol"), &gid, &c1).iter().map(|r| r.id.clone()).collect::<Vec<_>>(), [b3], "c1 names only b3");
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
    let mut bob = stored(&relay, &db("bob")).await;
    let sam = stored(&relay, &db("sam")).await;
    let carol = stored(&relay, &db("carol")).await;
    let gid = bob.node.create(settings(&relay)).unwrap();
    for joiner in [&sam, &carol] {
        joiner.node.join(&bob.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        bob.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("everyone has three members", || [&bob, &sam, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 3)).await;
    let spares = strangers(&mut bob, &gid, &relay, 1).await;
    carol.node.shutdown().await.unwrap();
    drop(carol);

    // Bob's m1 reaches Sam, who shows it and replies. Bob's commit keeps m1, since Sam's summary shows it held: Carol
    // then knows m1 was sent. Then Bob and Sam stop.
    let bob_key = bob.node.key();
    let m1 = bob.node.send(&gid.0, &message("m1"), None).await.unwrap();
    let mut sam = sam;
    let m1_seq = sam.until(|e| match e {
        Event::Message(message) => Some(message.seq),
        _ => None,
    }).await;
    sam.node.mark_shown(&gid.0, std::slice::from_ref(&m1)).unwrap();
    eventually("Bob hears that Sam holds m1", || bob.node.heard(&gid.0).unwrap().iter().any(|h| h.member.key == sam.node.key() && h.held.iter().any(|s| s.key == bob_key && s.seqs.contains(m1_seq)))).await;
    bob.node.remove(&gid.0, &spares[0].0).await.unwrap();
    let m2 = sam.node.send(&gid.0, &message("m2 replies to m1"), None).await.unwrap();
    bob.node.shutdown().await.unwrap();
    sam.node.shutdown().await.unwrap();

    // Carol comes back, reads Bob's commit, and takes m2 from Sam's hand, which never answers a `want`: m1 is withheld,
    // so Carol waits for it, gives it up after the hold-off, and delivers m2 with m1 in `missing`.
    let mut carol = stored(&relay, &db("carol")).await;
    carol.node.read_group(&gid.0).await.unwrap();
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
    let bob = stored(&relay, &db("bob")).await;
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
    let mut alice = stored(&relay, &dir.join("alice.db")).await;
    let bob = stored(&relay, &dir.join("bob.db")).await;
    let gid = alice.node.create(Settings { membership, ..settings(&relay) }).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    drop(service);
    let one = alice.node.send(&gid.0, &message("one"), None).await.unwrap();
    let two = alice.node.send(&gid.0, &message("two"), None).await.unwrap();
    let mut bob = stored(&relay, &dir.join("bob.db")).await;
    for (id, seq) in [(one, 2), (two, 3)] {
        let got = bob.until(|e| match e {
            Event::Message(message) => Some(message),
            _ => None,
        }).await;
        assert_eq!((got.id, got.seq, got.sender.key), (id, seq, alice.node.key()));
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
    let mut alice = stored(&relay, &db("alice")).await;
    let bob = stored(&relay, &db("bob")).await;
    let carol = stored(&relay, &db("carol")).await;
    let dave = stored(&relay, &db("dave")).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    for joiner in [&bob, &carol, &dave] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
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
    let held = |node: &Node| node.only_here(&gid.0).unwrap().into_iter().map(|(id, _)| id).collect::<Vec<_>>();
    eventually("Alice hears that Bob holds both", || held(&alice.node).is_empty()).await;

    assert!(alice.node.remove(&gid.0, &dave_key.0).await.unwrap());
    assert!(held(&alice.node).is_empty(), "the commit kept both, which Bob held");

    bob.node.shutdown().await.unwrap();
    let mut carol = stored(&relay, &db("carol")).await;
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
    let mut alice = session(&relay).await;
    let mut bob = stored(&relay, &db).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    eventually("Alice has Bob", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    let spares = strangers(&mut alice, &gid, &relay, 1).await;
    let m = alice.node.send(&gid.0, &message("held"), None).await.unwrap();
    let seq = bob.until(|e| match e {
        Event::Message(message) => Some(message.seq),
        _ => None,
    }).await;
    let (bob_key, alice_key) = (bob.node.key(), alice.node.key());
    eventually("Alice hears that Bob holds it", || alice.node.heard(&gid.0).unwrap().iter().any(|h| h.member.key == bob_key && h.held.iter().any(|s| s.key == alice_key && s.seqs.contains(seq)))).await;
    let bob_joined = alice.node.heard(&gid.0).unwrap().iter().find(|h| h.member.key == bob_key).unwrap().joined;
    let alice_joined = alice.node.heard(&gid.0).unwrap().iter().find(|h| h.member.key == bob_key).unwrap().held.iter().find(|s| s.key == alice_key).unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
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
    let mut alice = session(&relay).await;
    let mut bob = session(&relay).await;
    // No update comes due in the test: one already on its way as Alice hears Bob would not keep the message.
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    eventually("Alice has Bob", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    alice.node.send(&gid.0, &message("kept"), None).await.unwrap();
    bob.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    eventually("Alice hears that Bob holds it", || alice.node.only_here(&gid.0).unwrap().is_empty()).await;
    // The commit is a removal of a stranger admitted now, while Bob is online to hold its invite.
    let spares = strangers(&mut alice, &gid, &relay, 1).await;
    alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
    bob.node.shutdown().await.unwrap();
    eventually("Alice sees Bob go", || alice.node.online(&gid.0).unwrap().is_empty()).await;
    assert!(alice.node.only_here(&gid.0).unwrap().is_empty(), "the commit kept it");
    alice.node.shutdown().await.unwrap();
}

/// An update waiting for what connected members list commits once HEAR is up, not later: Bob's stand-in lists seqs that
/// Alice never got, and nothing sends them. It lists right after an update Alice's message stirred; her next message
/// stirs the next update, due within T, which waits in the epoch it lists for.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_waits_for_what_connected_members_list_for_at_most_hear() {
    const T: u32 = 10;
    let relay = relay().await;
    let dir = folder("fetch-hear");
    std::fs::create_dir_all(&dir).unwrap();
    let bob_db = dir.join("bob.db");
    let alice = session(&relay).await;
    let bob = stored(&relay, &bob_db).await;
    let bob_key = bob.node.key();
    let gid = alice.node.create(Settings { update: T, ..settings(&relay) }).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    eventually("Alice hears Bob", || alice.node.heard(&gid.0).unwrap().iter().any(|heard| heard.member.key == bob_key)).await;
    let joined = alice.node.heard(&gid.0).unwrap().iter().find(|heard| heard.member.key == bob_key).unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    let (iroh, mls) = member_of(&bob_db);
    let mut bob_hand = hand(&relay, iroh, &alice.node).await;
    let before = alice.node.epoch(&gid.0).unwrap();
    alice.node.send(&gid.0, &message("stir"), None).await.unwrap();
    eventually("Alice updates", || alice.node.epoch(&gid.0).unwrap() > before).await;
    let epoch = alice.node.epoch(&gid.0).unwrap();
    let listed_at = std::time::Instant::now();
    list(&mut bob_hand, &mls, &gid, joined, epoch, lmk_node::now() + 3_600_000, vec![seqs(&Bytes(mls.key().to_vec()), joined, &[1, 2, 3])]).await;
    alice.node.send(&gid.0, &message("stir"), None).await.unwrap();
    tokio::time::timeout(Duration::from_millis(T as u64 * 1000 + lmk_net::peers::HEAR + 5_000), async {
        while alice.node.epoch(&gid.0).unwrap() == epoch {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("Alice's update waited past HEAR");
    assert!(listed_at.elapsed() >= Duration::from_millis(lmk_net::peers::HEAR), "Alice's update did not wait for what was listed");
    alice.node.shutdown().await.unwrap();
}

/// A removal and an Add do not wait for holders: while Bob, connected, lists messages Alice lacks and never gives them,
/// Alice's updates wait, but she removes a member and admits Dave at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_removal_and_an_add_do_not_wait_for_holders() {
    let relay = relay().await;
    let dir = folder("no-wait");
    std::fs::create_dir_all(&dir).unwrap();
    let bob_db = dir.join("bob.db");
    let alice = session(&relay).await;
    let gid = alice.node.create(Settings { update: 2, ..settings(&relay) }).unwrap();
    let bob = stored(&relay, &bob_db).await;
    let bob_key = bob.node.key();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let tablet = session(&relay).await;
    let tablet_key = tablet.node.key();
    tablet.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    eventually("Alice hears Bob", || alice.node.heard(&gid.0).unwrap().iter().any(|heard| heard.member.key == bob_key)).await;
    let joined = alice.node.heard(&gid.0).unwrap().iter().find(|heard| heard.member.key == bob_key).unwrap().joined;
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
    alice.node.remove(&gid.0, &tablet_key.0).await.unwrap();
    assert!(listed_at.elapsed() < Duration::from_millis(lmk_net::peers::HEAR), "the removal waited");

    let listed_at = block().await;
    let dave = session(&relay).await;
    dave.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    assert!(listed_at.elapsed() < Duration::from_millis(lmk_net::peers::HEAR), "the Add waited");
    alice.node.shutdown().await.unwrap();
    dave.node.shutdown().await.unwrap();
}

/// A chat with no update due commits nothing: messages both members hold, and sends of either, move no epoch, even at the
/// passes their sessions run when they start 21 minutes later. Its T is so long that no update falls due but the
/// joiner's first.
#[test]
fn a_chat_of_held_messages_commits_nothing() {
    static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn shifted() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
    }
    on_clock(shifted, async {
        let relay = relay().await;
        let dir = folder("held-chat");
        std::fs::create_dir_all(&dir).unwrap();
        let db = |name: &str| dir.join(format!("{name}.db"));
        let mut alice = stored(&relay, &db("alice")).await;
        let mut bob = stored(&relay, &db("bob")).await;
        let gid = alice.node.create(Settings { update: u32::MAX, ..settings(&relay) }).unwrap();
        let created = alice.node.epoch(&gid.0).unwrap();
        bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        let epoch = bob.node.epoch(&gid.0).unwrap();
        assert_eq!(epoch, created + 2, "a joiner updates at once past its Add, whatever T");
        eventually("Alice has Bob's Add, and his update", || alice.node.epoch(&gid.0).unwrap() == epoch).await;
        alice.node.send(&gid.0, &message("one"), None).await.unwrap();
        bob.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
        bob.node.send(&gid.0, &message("two"), None).await.unwrap();
        alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
        alice.node.shutdown().await.unwrap();
        bob.node.shutdown().await.unwrap();
        drop((alice, bob));
        SHIFT.store(21 * 60 * 1000, std::sync::atomic::Ordering::Relaxed);
        let alice = stored(&relay, &db("alice")).await;
        let bob = stored(&relay, &db("bob")).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!((alice.node.epoch(&gid.0).unwrap(), bob.node.epoch(&gid.0).unwrap()), (epoch, epoch));
        alice.node.shutdown().await.unwrap();
        bob.node.shutdown().await.unwrap();
    });
}

/// A removed member's sends while it is offline are told to it as not kept: `Removed`, which it finds at its next send,
/// names the ids of its messages no cut kept, and it keeps none of them.
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_member_is_told_which_of_its_messages_no_cut_kept() {
    let relay = relay().await;
    let dir = folder("not-kept");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let alice = stored(&relay, &db("alice")).await;
    let dave = stored(&relay, &db("dave")).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    dave.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    eventually("Alice has Dave's Add", || alice.node.members(&gid.0).unwrap().len() == 2).await;
    let (alice_key, dave_key) = (alice.node.key(), dave.node.key());
    alice.node.shutdown().await.unwrap();
    drop(alice);

    // Alice is away, so Dave's messages are held by Dave alone; then Dave stops too.
    let one = dave.node.send(&gid.0, &message("one"), None).await.unwrap();
    let two = dave.node.send(&gid.0, &message("two"), None).await.unwrap();
    dave.node.shutdown().await.unwrap();
    drop(dave);

    let alice = stored(&relay, &db("alice")).await;
    assert!(alice.node.remove(&gid.0, &dave_key.0).await.unwrap());
    alice.node.shutdown().await.unwrap();
    let mut dave = stored(&relay, &db("dave")).await;
    dave.node.send(&gid.0, &message("three"), None).await.unwrap_err();
    let (not_kept, by) = dave.until(|e| match e {
        Event::Removed { not_kept, by, .. } => Some((not_kept, by)),
        _ => None,
    }).await;
    assert_eq!(not_kept, [one, two]);
    assert_eq!(by.map(|m| m.key), Some(alice_key));
    dave.node.shutdown().await.unwrap();
}

/// A member that delivered a removed member's last kept message still has it after the removal.
#[tokio::test(flavor = "multi_thread")]
async fn a_holder_keeps_the_removed_members_last_kept_message() {
    let relay = relay().await;
    let dir = folder("holder");
    std::fs::create_dir_all(&dir).unwrap();
    let db = |name: &str| dir.join(format!("{name}.db"));
    let mut alice = stored(&relay, &db("alice")).await;
    let bob = stored(&relay, &db("bob")).await;
    let dave = stored(&relay, &db("dave")).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    for joiner in [&bob, &dave] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
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
    bob.until(|e| matches!(e, Event::Left { member, .. } if member.key == dave_key).then_some(())).await;
    assert!(bob.node.message(&gid.0, &last.0).unwrap().is_some(), "Bob keeps it");
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();
}

/// What a member sends while alone in its group is no one else's: it needs no holder, and a joiner takes only what is
/// sent after it joined, past the next commit too.
#[tokio::test(flavor = "multi_thread")]
async fn what_a_member_sends_alone_needs_no_holder_and_reaches_no_joiner() {
    let relay = relay().await;
    let mut alice = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    alice.node.send(&gid.0, &message("before Bob"), None).await.unwrap();
    assert!(alice.node.only_here(&gid.0).unwrap().is_empty());
    let spares = strangers(&mut alice, &gid, &relay, 1).await;
    let mut bob = session(&relay).await;
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    let after = alice.node.send(&gid.0, &message("after Bob"), None).await.unwrap();
    // Alice's invites took seqs 2 and 3: before is seq 1, after seq 4.
    let got = bob.until(|e| match e {
        Event::Message(m) => Some(m),
        _ => None,
    }).await;
    assert_eq!((got.id, got.seq, got.missing.is_empty()), (after, 4, true));
    alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
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
    let mut alice = stored(&relay, &db("alice")).await;
    let mut bob = stored(&relay, &db("bob")).await;
    let carol = stored(&relay, &db("carol")).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let spares = strangers(&mut alice, &gid, &relay, 3).await;
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Alice has six members", || alice.node.members(&gid.0).unwrap().len() == 6).await;
    carol.node.shutdown().await.unwrap();
    drop(carol);
    let alice_key = alice.node.key();

    // The strangers' invites and Bob's and Carol's took seqs 1 to 5: those before Bob joined are not his to have.
    // Alice's messages are 6 and 7, each held by Bob before the commit that keeps it.
    let mut sent = Vec::new();
    for (text, spare) in ["a1", "a2"].into_iter().zip(&spares) {
        alice.node.send(&gid.0, &message(text), None).await.unwrap();
        let seq = bob.until(|e| match e {
            Event::Message(message) => Some(message.seq),
            _ => None,
        }).await;
        sent.push(seq);
        eventually("Alice hears that Bob holds her messages up to it", || alice.node.heard(&gid.0).unwrap().iter().any(|h| h.member.key == bob.node.key() && (5..=seq).all(|q| h.held.iter().any(|s| s.key == alice_key && s.seqs.contains(q))))).await;
        alice.node.remove(&gid.0, &spare.0).await.unwrap();
    }
    alice.node.remove(&gid.0, &spares[2].0).await.unwrap();
    let epoch = alice.node.epoch(&gid.0).unwrap();
    assert_eq!(sent, [6, 7]);

    let mut carol = stored(&relay, &db("carol")).await;
    let (mut delivered, mut lost) = (Vec::new(), Vec::new());
    // Carol's events until she accounted for both messages, and for 2 seconds more, in which a second account shows.
    let mut end = tokio::time::Instant::now() + WAIT;
    while let Ok(Some(event)) = tokio::time::timeout_at(end, carol.events.recv()).await {
        match event {
            Event::Message(message) => delivered.push(message.seq),
            Event::Lost(lost_now) => lost.extend(lost_now.messages.iter().flat_map(|of| of.seqs.clone())),
            _ => {}
        }
        if delivered.len() + lost.len() >= sent.len() {
            end = end.min(tokio::time::Instant::now() + Duration::from_secs(2));
        }
    }
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
    assert_eq!(accounted, [6, 7]);
}

/// A member offline across several commits takes each message they kept, once, when it comes back: the wait before
/// each commit holds until it heard the summaries that show who holds them.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_back_after_several_commits_takes_each_kept_message() {
    let (delivered, lost) = missed_commits("several-taken").await;
    assert_eq!((delivered, lost), (vec![6, 7], Vec::<u64>::new()));
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
    let mut alice = session(&relay).await;
    let mut bob = session(&relay).await;
    let dave = stored_with(&relay, &dir.join("dave.db"), gate.post("Dave", relay.post())).await;
    let gid = alice.node.create(Settings { membership, ..settings(&relay) }).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    dave.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    eventually("Bob has three members", || bob.node.members(&gid.0).unwrap().len() == 3).await;
    let dave_key = dave.node.key();
    dave.node.shutdown().await.unwrap();
    drop(dave);
    gate.set(false);

    assert!(alice.node.remove(&gid.0, &dave_key.0).await.unwrap());
    let epoch = alice.node.epoch(&gid.0).unwrap();
    eventually("Bob applies the removal", || bob.node.epoch(&gid.0).unwrap() == epoch).await;
    let dave = stored_with(&relay, &dir.join("dave.db"), gate.post("Dave", relay.post())).await;
    eventually("Dave reaches Alice", || dave.node.online(&gid.0).unwrap().iter().any(|m| m.key == alice.node.key())).await;
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
    let mut alice = stored(&relay, &db("alice")).await;
    let bob = stored(&relay, &db("bob")).await;
    let carol = stored(&relay, &db("carol")).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let spares = strangers(&mut alice, &gid, &relay, 2).await;
    for joiner in [&bob, &carol] {
        joiner.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    }
    eventually("Bob and Carol have both Adds", || [&bob, &carol].iter().all(|s| s.node.members(&gid.0).unwrap().len() == 5)).await;
    let (bob_key, carol_key) = (bob.node.key(), carol.node.key());
    carol.node.shutdown().await.unwrap();
    drop(carol);
    let sent = bob.node.send(&gid.0, &message("only Alice and Bob hold this"), None).await.unwrap();
    alice.until(|e| matches!(e, Event::Message(_)).then_some(())).await;
    eventually("Alice hears that Bob holds it", || alice.node.heard(&gid.0).unwrap().iter().any(|h| h.member.key == bob_key && h.held.iter().any(|s| s.key == bob_key && s.seqs.contains(1)))).await;
    for spare in &spares {
        alice.node.remove(&gid.0, &spare.0).await.unwrap();
    }
    bob.node.shutdown().await.unwrap();
    alice.node.shutdown().await.unwrap();

    // Carol, back with no holder online, loses Bob's message and says so in its summary.
    let mut carol = stored(&relay, &db("carol")).await;
    carol.node.read_group(&gid.0).await.unwrap();
    let lost = carol.until(|e| match e {
        Event::Lost(lost) => Some(lost),
        _ => None,
    }).await;
    assert_eq!((lost.messages[0].from.key.clone(), lost.messages[0].seqs.clone()), (bob_key.clone(), vec![1]));

    // Bob comes back and hears Carol's summary: he is told once, as its author. Carol's summary survives his restart.
    let mut bob = stored(&relay, &db("bob")).await;
    let told = bob.until(|e| match e {
        Event::Lost(lost) => Some(lost),
        _ => None,
    }).await;
    let of = &told.messages[0];
    assert_eq!((told.member.key.clone(), &of.from.key, of.seqs.clone(), of.ids.clone()), (carol_key.clone(), &bob_key, vec![1], vec![sent.clone()]));
    bob.node.shutdown().await.unwrap();
    let mut bob = stored(&relay, &db("bob")).await;
    assert!(bob.node.heard(&gid.0).unwrap().iter().any(|h| h.member.key == carol_key), "Carol's summary survives the restart");
    let again = tokio::time::timeout(Duration::from_secs(3), bob.until(|e| matches!(e, Event::Lost(_)).then_some(()))).await;
    assert!(again.is_err(), "told once");
    assert!(carol.node.message(&gid.0, &sent.0).unwrap().is_none());
    for session in [&bob, &carol] {
        session.node.shutdown().await.unwrap();
    }
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
    let mut alice = stored(&relay, &db("alice")).await;
    let bob = stored(&relay, &db("bob")).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
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
    let mut bob = stored(&relay, &db("bob")).await;
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
    let alice = stored(&relay, &dir.join("alice.db")).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let (alice_key, bob_key, url) = (alice.node.address().0, bob.node.address().0, relay.url.to_string());
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_key) == Some(url.clone())).await;
    eventually("Bob holds Alice's relay", || bob.node.hint(&alice_key) == Some(url.clone())).await;
}

/// Chosen relays are where a session lives, whatever its directory names: its members hold them as its relays.
#[tokio::test(flavor = "multi_thread")]
async fn chosen_relays_replace_the_directorys() {
    let relay = relay().await;
    let dead = "https://127.0.0.1:1".parse().unwrap();
    let (node, events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), Config { relays: vec![dead], chosen: vec![relay.url.clone()], ..config(&relay) })
        .await
        .unwrap();
    let alice = Session { node, events };
    let bob = session(&relay).await;
    assert_eq!(alice.node.address().1, vec![relay.url.clone()]);
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
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
    let alice = stored(&relay, &alice_db).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let alice_key = alice.node.address().0;
    eventually("Bob holds Alice's relay", || bob.node.hint(&alice_key) == Some(relay.url.to_string())).await;

    alice.node.shutdown().await.unwrap();
    drop(alice);
    let _alice = stored(&moved, &alice_db).await;
    eventually("Bob holds Alice's new relay", || bob.node.hint(&alice_key) == Some(moved.url.to_string())).await;
}

/// In a group over seven, where members do not all connect, a member's new home relay reaches the members it connects
/// to: summaries go no further than neighbours.
#[tokio::test(flavor = "multi_thread")]
async fn a_home_relay_reaches_the_neighbours_in_a_group_over_seven() {
    let relay = relay().await;
    let moved = relay_beside(&relay).await;
    let dir = folder("relays-seven");
    let bob_db = dir.join("bob.db");
    let mut sessions = vec![session(&relay).await];
    let gid = sessions[0].node.create(settings(&relay)).unwrap();
    let bob = stored(&relay, &bob_db).await;
    bob.node.join(&sessions[0].node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    for _ in 0..6 {
        let joiner = session(&relay).await;
        joiner.node.join(&sessions[0].node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
        sessions.push(joiner);
    }
    eventually("Alice has eight members", || sessions[0].node.members(&gid.0).unwrap().len() == 8).await;

    let (bob_iroh, bob_key) = (bob.node.address().0, bob.node.key());
    bob.node.shutdown().await.unwrap();
    drop(bob);
    let _bob = stored(&moved, &bob_db).await;
    let neighbour = |s: &Session| s.node.online(&gid.0).unwrap().iter().any(|m| m.key == bob_key);
    eventually("Bob has neighbours", || sessions.iter().any(neighbour)).await;
    eventually("each neighbour holds Bob's new relay", || sessions.iter().filter(|s| neighbour(s)).all(|s| s.node.hint(&bob_iroh) == Some(moved.url.to_string()))).await;
}

/// A summary without a relay leaves the hint saved before it.
#[tokio::test(flavor = "multi_thread")]
async fn a_summary_without_relay_keeps_the_hint() {
    let relay = relay().await;
    let dir = folder("relays-keep");
    let (alice_db, bob_db) = (dir.join("alice.db"), dir.join("bob.db"));
    let alice = stored(&relay, &alice_db).await;
    let bob = stored(&relay, &bob_db).await;
    let bob_key = bob.node.key();
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let (bob_iroh, url) = (bob.node.address().0, relay.url.to_string());
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh) == Some(url.clone())).await;
    let joined = alice.node.heard(&gid.0).unwrap().iter().find(|heard| heard.member.key == bob_key).unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    // Bob's stopped session, standing in for itself, signs a newer summary that names no relay.
    let (iroh, mls) = member_of(&bob_db);
    let held = seqs(&Bytes(mls.key().to_vec()), joined, &[1]);
    let summary = Summary {
        group: gid.clone(),
        member: Bytes(mls.key().to_vec()),
        joined,
        version: lmk_node::now() + 3_600_000,
        time: lmk_node::now(),
        epoch: alice.node.epoch(&gid.0).unwrap(),
        relay: None,
        held: vec![held.clone()],
        sealed: Vec::new(),
    };
    let body = serde_json::to_vec(&summary).unwrap();
    let sig = mls.sign(&[SUMMARY, &body].concat());
    let mut bob_hand = hand(&relay, iroh, &alice.node).await;
    bob_hand.send(&Frame::Summary { group: gid.clone(), summary: Signed { body: Bytes(body), sig: Bytes(sig) } }).await;
    eventually("Alice takes the summary", || alice.node.heard(&gid.0).unwrap().iter().any(|heard| heard.held == [held.clone()])).await;
    assert_eq!(alice.node.hint(&bob_iroh), Some(url));
}

/// A summary names a relay only if it is an https one: a member's other relay is taken from no summary.
#[tokio::test(flavor = "multi_thread")]
async fn a_summary_relay_must_be_https() {
    let relay = relay().await;
    let dir = folder("relays-https");
    let (alice_db, bob_db) = (dir.join("alice.db"), dir.join("bob.db"));
    let alice = stored(&relay, &alice_db).await;
    let bob = stored(&relay, &bob_db).await;
    let bob_key = bob.node.key();
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let (bob_iroh, url) = (bob.node.address().0, relay.url.to_string());
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh) == Some(url.clone())).await;
    let joined = alice.node.heard(&gid.0).unwrap().iter().find(|heard| heard.member.key == bob_key).unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    let (iroh, mls) = member_of(&bob_db);
    let held = seqs(&Bytes(mls.key().to_vec()), joined, &[1]);
    let summary = Summary {
        group: gid.clone(),
        member: Bytes(mls.key().to_vec()),
        joined,
        version: lmk_node::now() + 3_600_000,
        time: lmk_node::now(),
        epoch: alice.node.epoch(&gid.0).unwrap(),
        relay: Some("http://127.0.0.1:1".into()),
        held: vec![held.clone()],
        sealed: Vec::new(),
    };
    let body = serde_json::to_vec(&summary).unwrap();
    let sig = mls.sign(&[SUMMARY, &body].concat());
    let mut bob_hand = hand(&relay, iroh, &alice.node).await;
    bob_hand.send(&Frame::Summary { group: gid.clone(), summary: Signed { body: Bytes(body), sig: Bytes(sig) } }).await;
    eventually("Alice takes the summary", || alice.node.heard(&gid.0).unwrap().iter().any(|heard| heard.held == [held.clone()])).await;
    assert_eq!(alice.node.hint(&bob_iroh), Some(url));
}

/// A member's hint is one record, saved when its relay changes: a newer summary that names the same relay saves nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_hint_is_saved_when_the_relay_changes() {
    let relay = relay().await;
    let dir = folder("relays-saved");
    let (alice_db, bob_db) = (dir.join("alice.db"), dir.join("bob.db"));
    let alice = stored(&relay, &alice_db).await;
    let bob = stored(&relay, &bob_db).await;
    let bob_key = bob.node.key();
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let (bob_iroh, url) = (bob.node.address().0, relay.url.to_string());
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh) == Some(url.clone())).await;
    let saved = hint_records(&alice_db);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].0, [b"node/hint/".as_slice(), &bob_iroh].concat());
    let joined = alice.node.heard(&gid.0).unwrap().iter().find(|heard| heard.member.key == bob_key).unwrap().joined;
    bob.node.shutdown().await.unwrap();
    drop(bob);

    let (iroh, mls) = member_of(&bob_db);
    let held = seqs(&Bytes(mls.key().to_vec()), joined, &[1]);
    let summary = Summary {
        group: gid.clone(),
        member: Bytes(mls.key().to_vec()),
        joined,
        version: lmk_node::now() + 3_600_000,
        time: lmk_node::now(),
        epoch: alice.node.epoch(&gid.0).unwrap(),
        relay: Some(url.clone()),
        held: vec![held.clone()],
        sealed: Vec::new(),
    };
    let body = serde_json::to_vec(&summary).unwrap();
    let sig = mls.sign(&[SUMMARY, &body].concat());
    let mut bob_hand = hand(&relay, iroh, &alice.node).await;
    bob_hand.send(&Frame::Summary { group: gid.clone(), summary: Signed { body: Bytes(body), sig: Bytes(sig) } }).await;
    eventually("Alice takes the summary", || alice.node.heard(&gid.0).unwrap().iter().any(|heard| heard.held == [held.clone()])).await;
    assert_eq!(hint_records(&alice_db), saved);
}

/// A member removed from its last group loses its hint, saved or held.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_in_no_group_has_no_hint() {
    let relay = relay().await;
    let dir = folder("relays-removed");
    let alice_db = dir.join("alice.db");
    let alice = stored(&relay, &alice_db).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let bob_iroh = bob.node.address().0;
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh).is_some()).await;
    let bob_key = bob.node.key();
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
    let mut alice = stored(&relay, &alice_db).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let bob_iroh = bob.node.address().0;
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh).is_some()).await;
    let alice_key = alice.node.key();
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
    let alice = stored(&relay, &alice_db).await;
    let bob = session(&relay).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let (bob_iroh, url) = (bob.node.address().0, relay.url.to_string());
    eventually("Alice holds Bob's relay", || alice.node.hint(&bob_iroh) == Some(url.clone())).await;
    bob.node.shutdown().await.unwrap();
    drop(bob);
    alice.node.shutdown().await.unwrap();
    drop(alice);

    let alice = stored(&relay, &alice_db).await;
    assert_eq!(alice.node.hint(&bob_iroh), Some(url));
}

/// A post that counts the requests for heads it passes on.
fn counting(post: Post) -> (Arc<std::sync::atomic::AtomicUsize>, Post) {
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = asked.clone();
    let post: Post = Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| {
        if route == "/membership/4/heads" {
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

/// A member entering an epoch a peer brought it into asks the service nothing.
#[tokio::test(flavor = "multi_thread")]
async fn entering_an_epoch_asks_the_service_nothing() {
    let relay = relay().await;
    let mut alice = session(&relay).await;
    let (requests, post) = recording(relay.post());
    let bob = session_with(&relay, post).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let spares = strangers(&mut alice, &gid, &relay, 1).await;
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    eventually("Alice has Bob", || alice.node.members(&gid.0).unwrap().len() == 3).await;
    quiet(&requests).await;
    let before = requests.lock().unwrap().len();
    alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
    let epoch = alice.node.epoch(&gid.0).unwrap();
    eventually("Bob applied the commit", || bob.node.epoch(&gid.0).unwrap() == epoch).await;
    quiet(&requests).await;
    assert_eq!(requests.lock().unwrap().len(), before);
    alice.node.shutdown().await.unwrap();
    bob.node.shutdown().await.unwrap();
}

/// A send whose service answers that its group's log moved is refused as behind when the session does not catch up
/// within `SEND_WAIT`: nothing is sealed in an epoch the service shows over.
#[tokio::test(flavor = "multi_thread")]
async fn a_send_that_does_not_catch_up_with_its_moved_log_is_refused() {
    let relay = relay().await;
    let dir = folder("behind");
    std::fs::create_dir_all(&dir).unwrap();
    let mut alice = session(&relay).await;
    let bob = stored(&relay, &dir.join("bob.db")).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let spares = strangers(&mut alice, &gid, &relay, 1).await;
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    alice.until(|e| matches!(e, Event::Joined { .. }).then_some(())).await;
    bob.node.shutdown().await.unwrap();
    drop(bob);
    alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
    alice.node.shutdown().await.unwrap();

    let inner = relay.post();
    let slow: Post = Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| {
        let answer = inner(domain, route, body);
        Box::pin(async move {
            if route == "/membership/4/read" {
                tokio::time::sleep(Duration::from_secs(6)).await;
            }
            answer.await
        })
    });
    let bob = stored_with(&relay, &dir.join("bob.db"), slow).await;
    let epoch = bob.node.epoch(&gid.0).unwrap();
    let refused = bob.node.send(&gid.0, &message("hello"), None).await.unwrap_err();
    assert!(matches!(refused.downcast_ref::<SendError>(), Some(SendError::Behind)), "{refused:#}");
    assert!(bob.node.messages(&gid.0).unwrap().iter().all(|m| m.payload != message("hello")));
    eventually("Bob catches up", || bob.node.epoch(&gid.0).unwrap() > epoch).await;
    bob.node.send(&gid.0, &message("hello"), None).await.unwrap();
    bob.node.shutdown().await.unwrap();
}

/// Each send asks the service about its group's log, and reads on through each epoch a commit moves the group to: a
/// member that the second of two commits no peer pushed removed gets nothing sealed after the send reads them.
#[tokio::test(flavor = "multi_thread")]
async fn each_send_reads_the_group_first() {
    // Alice reaches peers through one relay only, Carol through another, and Bob through either: Alice and Carol meet
    // only through Bob.
    let (relay, other) = (relay().await, relay().await);
    let mut alice = session(&relay).await;
    let bob = session_trusting([&other, &relay]).await;
    let bob_key = bob.node.key();
    let (asked, post) = counting(other.post());
    let mut carol = session_with(&other, post).await;
    let gid = alice.node.create(settings(&relay)).unwrap();
    let spares = strangers(&mut alice, &gid, &relay, 1).await;
    bob.node.join(&alice.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    carol.node.join(&bob.node.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    eventually("Carol holds the four members", || carol.node.members(&gid.0).unwrap().len() == 4).await;

    bob.node.shutdown().await.unwrap();
    alice.node.remove(&gid.0, &spares[0].0).await.unwrap();
    alice.node.remove(&gid.0, &bob.node.key().0).await.unwrap();
    let before = asked.load(std::sync::atomic::Ordering::Relaxed);
    carol.node.send(&gid.0, &message("after"), None).await.unwrap();
    assert_eq!(asked.load(std::sync::atomic::Ordering::Relaxed), before + 1, "the send asked about the group's log");
    assert_eq!(carol.node.members(&gid.0).unwrap().len(), 2, "the message was sealed without Bob");
    carol.until(|e| matches!(&e, Event::Left { member, .. } if member.key == bob_key).then_some(())).await;
    let read = asked.load(std::sync::atomic::Ordering::Relaxed);
    carol.node.send(&gid.0, &message("again"), None).await.unwrap();
    assert_eq!(asked.load(std::sync::atomic::Ordering::Relaxed), read + 1, "the next send asks again");
    alice.node.shutdown().await.unwrap();
    carol.node.shutdown().await.unwrap();
}
