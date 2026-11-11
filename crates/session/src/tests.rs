//! Session processes in one test process, each in a home of its own (sessions may share one), living on the relay of a
//! local membership service with a self-signed certificate, which keeps their logs. The CLI talks to them over their
//! command channels.

use anyhow::Result;
use lmk_proto::directory::Directory;
use lmk_serve::{Certificate, ServeConfig};
use lmk_testing::free_port;
use n0_future::boxed::BoxFuture;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, oneshot};

use crate::cli::{Command, Request, session_dir};
use crate::session::Config;

/// How long a test waits for what a session prints: sessions start slowly on CI's Windows runners.
const WAIT: Duration = Duration::from_secs(60);

struct World {
    network: crate::Network,
    root: tempfile::TempDir,
    /// The membership service its own `serve` runs at: its domain, and its key in hex.
    domain: String,
    key: String,
}

async fn world(test: &str) -> World {
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_test_writer().try_init();
    let root = tempfile::Builder::new().prefix(&format!("lmk-session-{test}-")).tempdir().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(root.path().join("cert.pem"), certified.cert.pem()).unwrap();
    std::fs::write(root.path().join("key.pem"), certified.signing_key.serialize_pem()).unwrap();
    let (domain, key) = service(root.path(), "service", &tokio::runtime::Handle::current()).await;
    let ca = iroh::tls::CaTlsConfig::custom_roots([certified.cert.der().clone()]);
    let network = crate::Network::new(root.path(), ca).unwrap();
    World { network, root, domain, key }
}

/// A membership service run by `serve` on `runtime`, its state in `root`'s directory `name`, at a localhost domain of its
/// own with `root`'s certificate: its domain and its key in hex.
async fn service(root: &Path, name: &str, runtime: &tokio::runtime::Handle) -> (String, String) {
    let mut config = ServeConfig::new("localhost", root.join(name));
    (config.https_port, config.qad_port) = (free_port(), free_port());
    config.http_port = Some(free_port());
    config.policy.appends_per_minute = u32::MAX;
    let lmk_proto::group::Service::Serve { key, .. } = config.initialize().unwrap() else { unreachable!() };
    config.certificate = Certificate::Files { chain: root.join("cert.pem"), key: root.join("key.pem") };
    let (domain, https) = (config.domain(), config.https_port);
    let mut serving = runtime.spawn(lmk_serve::serve(config));
    let listening = async {
        while std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, https)).is_err() {
            if serving.is_finished() {
                (&mut serving).await.unwrap().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::time::timeout(WAIT, listening).await.expect("the service listens");
    (domain, hex::encode(key.0))
}

struct Agent {
    /// Its directory's name, which `--session` takes.
    name: String,
    home: PathBuf,
    fp: String,
    events: mpsc::UnboundedReceiver<String>,
    stop: Option<oneshot::Sender<()>>,
    done: Option<tokio::task::JoinHandle<()>>,
    ready: Value,
    /// The log's lines `told` returned.
    told: BTreeSet<String>,
}

impl World {
    /// A session process in a home of its own.
    async fn start(&self, name: &str) -> Agent {
        self.start_in(name, name).await
    }

    /// A session process in the home `home`.
    async fn start_in(&self, home: &str, name: &str) -> Agent {
        self.launch(self.config(home, name), usize::MAX).await
    }

    /// A new session process in the home `home`, in a directory named by its fingerprint, as `listen` makes one.
    async fn start_new(&self, home: &str) -> Agent {
        let dir = crate::new_session(&self.root.path().join(home), &self.domain).unwrap();
        self.start_in(home, &dir.file_name().unwrap().to_string_lossy()).await
    }

    /// The device of the home `home`, as `members` shows it.
    fn device(&self, home: &str) -> Value {
        let key = crate::device(&self.root.path().join(home)).unwrap();
        json!({ "fp": lmk_node::fp(key.verifying_key().as_bytes()) })
    }

    /// A session's configuration, in the home `home`, which is a device of its own.
    fn config(&self, home: &str, name: &str) -> Config {
        Config {
            dir: session_dir(&self.root.path().join(home), name).unwrap(),
            device: self.root.path().join(home),
            membership: self.domain.clone(),
            detached: false,
        }
    }

    async fn open_session(&self, config: Config) -> (crate::session::Session, mpsc::UnboundedReceiver<lmk_node::Event>) {
        let db = crate::store::open(&config.dir.join("session.db")).unwrap();
        let provider = lmk_core::provider::SqliteProvider::open(&config.dir.join("session.db")).unwrap();
        let node_config = lmk_node::Config {
            home: config.membership.clone(),
            post: self.network.post.clone(),
            ca: self.network.ca.clone(),
            device: crate::device(&config.device).unwrap(),
        };
        let (node, events) = lmk_node::Node::start(provider, node_config).await.unwrap();
        let held = std::fs::OpenOptions::new().write(true).open(config.dir.join("session.lock")).unwrap();
        let membership = lmk_proto::group::Service::Serve { key: lmk_proto::Bytes(hex::decode(&self.key).unwrap()), domain: self.domain.clone(), rest: Default::default() };
        (crate::session::Session::open(config, db, node, held, membership).await.unwrap(), events)
    }

    /// A session process; writing the message after its first `messages` fails, as when its reader is gone.
    async fn launch(&self, config: Config, messages: usize) -> Agent {
        let home = config.dir.parent().unwrap().parent().unwrap().to_path_buf();
        let name = config.dir.file_name().unwrap().to_string_lossy().into_owned();
        let (out, events) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel::<()>();
        let (network, at) = (self.network.clone(), home.clone());
        let done = tokio::task::spawn_local(async move {
            let mut written = 0;
            let print = move |line: String| {
                if serde_json::from_str::<Value>(&line).unwrap()["type"] == "message" {
                    written += 1;
                    if written > messages {
                        return Err(std::io::ErrorKind::BrokenPipe.into());
                    }
                }
                drop(out.send(line));
                Ok(())
            };
            crate::listen(config, &at, network, print, async { drop(stopped.await) }).await.unwrap();
        });
        let mut agent = Agent { name, home, fp: String::new(), events, stop: Some(stop), done: Some(done), ready: Value::Null, told: BTreeSet::new() };
        let ready = agent.expect("ready").await;
        assert!(keys(&ready).is_superset(&keys(&json!({ "type": 0, "fp": 0, "bin": 0, "membership": 0 }))), "{ready}");
        agent.fp = ready["fp"].as_str().unwrap().into();
        agent.ready = ready;
        agent
    }
}

impl Agent {
    async fn cmd(&self, args: &[&str]) -> Result<Value> {
        let home = self.home.to_str().unwrap();
        let base = ["letmeknow", "--home", home, "--session", self.name.as_str()];
        let cli = crate::cli::parse(base.iter().chain(args))?;
        let Command::Request(request) = cli.command else { panic!("not a request") };
        crate::cli::call(&self.home, &self.name, request).await
    }

    /// The next event of `kind`, skipping others.
    async fn expect(&mut self, kind: &str) -> Value {
        self.expect_any(&[kind]).await
    }

    /// The session's log, line by line.
    fn log(&self) -> Vec<String> {
        let log = std::fs::read_to_string(session_dir(&self.home, &self.name).unwrap().join("log.jsonl")).unwrap_or_default();
        log.lines().map(str::to_owned).collect()
    }

    /// The first event of any of `kinds` in the log that it did not return before, as it waits for one.
    async fn told(&mut self, kinds: &[&str]) -> Value {
        let start = std::time::Instant::now();
        loop {
            for line in self.log() {
                let event: Value = serde_json::from_str(&line).unwrap();
                if kinds.iter().any(|kind| event["type"] == *kind) && self.told.insert(line) {
                    return event;
                }
            }
            assert!(start.elapsed() < WAIT, "{}: no {kinds:?} event", self.name);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The next event of any of `kinds`, skipping others.
    async fn expect_any(&mut self, kinds: &[&str]) -> Value {
        loop {
            let Ok(line) = tokio::time::timeout(WAIT, self.events.recv()).await else {
                panic!("{}: no {kinds:?} event; status: {:?}", self.name, self.cmd(&["groups"]).await);
            };
            let line = line.unwrap();
            let event: Value = serde_json::from_str(&line).unwrap();
            if kinds.iter().any(|kind| event["type"] == *kind) {
                return event;
            }
            eprintln!("{}: {event}", self.name);
        }
    }

    /// What was printed, after a moment for what is on its way.
    async fn printed(&mut self) -> Vec<Value> {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut printed = Vec::new();
        while let Ok(line) = self.events.try_recv() {
            printed.push(serde_json::from_str(&line).unwrap());
        }
        printed
    }

    async fn stop(&mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.done.take().unwrap().await.unwrap();
    }
}

fn keys(value: &Value) -> BTreeSet<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

fn local<F: std::future::Future>(test: F) -> F::Output {
    // As main runs them: the sessions' own work on this thread, the rest on others.
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&runtime, test)
}

/// Alice makes a group and invites Bob.
async fn pair(world: &World) -> (Agent, Agent, String) {
    let mut alice = world.start("alice").await;
    let bob = world.start("bob").await;
    let invite = alice.cmd(&["invite"]).await.unwrap();
    assert_eq!(keys(&invite), keys(&json!({ "link": 0, "group": 0, "expires": 0, "via": 0 })));
    assert_eq!(invite["via"], json!(["you"]));
    let link = invite["link"].as_str().unwrap();
    assert!(link.starts_with("https://letmeknow.dev/i#14."));
    let joined = bob.cmd(&["join", link]).await.unwrap();
    assert_eq!(joined["group"], invite["group"]);
    assert_eq!(joined["members"].as_array().unwrap().len() + joined["offline"].as_u64().unwrap_or(0) as usize, 2);
    let event = alice.told(&["joined"]).await;
    assert_eq!((&event["member"], &event["by"]), (&json!(bob.fp), &json!("you")));
    (alice, bob, invite["group"].as_str().unwrap().to_owned())
}

#[test]
fn messages_that_do_not_concern_a_session_wait_for_one_that_does() {
    local(async {
        let world = world("steer").await;
        let (mut alice, mut bob, group) = pair(&world).await;
        let sent = bob.cmd(&["send", "the build is green"]).await.unwrap();
        assert!(sent["id"].is_string() && sent.get("pos").is_none(), "{sent}");
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message"));
        let first = alice.told(&["message"]).await;
        assert_eq!((first["content"].as_str(), first.get("to")), (Some("the build is green"), None));
        bob.cmd(&["send", "--to", &alice.fp, "can you deploy?"]).await.unwrap();
        let second = alice.expect("message").await;
        assert_eq!((second["content"].as_str(), &second["to"]), (Some("can you deploy?"), &json!(["you"])));
        assert_eq!(keys(&second), keys(&json!({ "type": 0, "group": 0, "id": 0, "seq": 0, "from": 0, "to": 0, "content": 0, "sent_at": 0, "at": 0 })));
        assert_eq!(alice.told(&["message"]).await, second, "the log holds what prints");
        assert_eq!(second["seq"].as_u64(), first["seq"].as_u64().map(|s| s + 1), "in order");
        assert_eq!((second["group"].as_str(), second["id"].as_str().unwrap().len()), (Some(group.as_str()), crate::short::ID));
        assert_eq!(second["from"], bob.fp);
        // A reply to Bob wakes him.
        let id = second["id"].as_str().unwrap();
        alice.cmd(&["send", "--reply-to", id, "on it"]).await.unwrap();
        let reply = bob.expect("message").await;
        assert_eq!(reply["reply_to"], id);
        // Its own messages wake no one, urgent or not.
        alice.cmd(&["send", "--urgent", "deploying"]).await.unwrap();
        assert_eq!(bob.expect("message").await["content"], "deploying");
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message"));
    });
}

#[test]
fn send_answers_its_id_and_refuses_a_message_too_large() {
    local(async {
        let world = world("pending").await;
        let (alice, mut bob, _) = pair(&world).await;
        let big = "x".repeat(16 << 20);
        let refused = alice.cmd(&["send", "--to", &bob.fp, &big]).await.unwrap_err().to_string();
        assert!(refused.contains("members take"), "{refused}");
        let bob_fp = bob.fp.clone();
        let last_seen = |members: &Value| members["members"].as_array().unwrap().iter().find(|m| m["fp"] == bob_fp).unwrap()["last_seen"].clone();
        assert_eq!(last_seen(&alice.cmd(&["members"]).await.unwrap()), "now");
        bob.stop().await;
        let before = lmk_node::now();
        let sent = alice.cmd(&["send", "--urgent", "anyone?"]).await.unwrap();
        assert!(sent["id"].is_string() && sent.get("pos").is_none(), "{sent}");
        // Alice finds out that Bob's connection closed once his close reaches her: he was seen until then, and is listed
        // for two hours.
        let members = until(|| async { alice.cmd(&["members"]).await.unwrap() }, |members| last_seen(members) == "0m").await;
        assert_eq!((last_seen(&members), members.get("offline")), (json!("0m"), None), "{members}");
        // Once Bob is back, he takes it.
        let mut bob = world.start("bob").await;
        let message = bob.expect("message").await;
        assert_eq!((message["id"].as_str(), message["content"].as_str()), (sent["id"].as_str(), Some("anyone?")));
        let sent_at = message["sent_at"].as_str().unwrap();
        let (sent, now) = (crate::short::iso(before), crate::short::iso(lmk_node::now()));
        assert!(sent.as_str() <= sent_at && sent_at <= now.as_str(), "it tells when it was sent, not when it arrived");
    });
}

#[test]
fn an_attachment_arrives_as_a_private_file() {
    local(async {
        let world = world("attach").await;
        let (mut alice, bob, _) = pair(&world).await;
        let file = world.root.path().join("token.txt");
        std::fs::write(&file, "s3cret").unwrap();
        let sent = bob.cmd(&["send", "--to", &alice.fp, "--attach", file.to_str().unwrap(), "the token"]).await.unwrap();
        let message = alice.expect("message").await;
        assert_eq!(keys(&message["attachment"]), keys(&json!({ "name": 0, "path": 0 })));
        assert_eq!(message["attachment"]["name"], "token.txt");
        let path = message["attachment"]["path"].as_str().unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "s3cret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(message["id"], sent["id"]);
    });
}

#[test]
fn membership_changes_are_told_and_a_removed_session_learns_it() {
    local(async {
        let world = world("remove").await;
        let (mut alice, mut bob, group) = pair(&world).await;
        let members = bob.cmd(&["members", "--all", "--group", &group[..6]]).await.unwrap();
        assert_eq!((&members["members"][0]["fp"], &members["members"][0]["last_seen"]), (&json!(alice.fp), &json!("now")));
        assert_eq!(members["members"][1], json!({ "fp": bob.fp, "you": true, "device": world.device("bob") }));
        let other = alice.cmd(&["invite"]).await.unwrap()["group"].as_str().unwrap().to_owned();
        assert_eq!(alice.cmd(&["groups"]).await.unwrap()["groups"].as_array().unwrap().len(), 2);
        let status = alice.cmd(&["groups", &format!("--group={}", &group[..8])]).await.unwrap();
        assert_eq!(status["groups"].as_array().unwrap().iter().map(|g| &g["group"]).collect::<Vec<_>>(), [group.as_str()]);
        assert!(alice.cmd(&["groups", "--group", "nope"]).await.unwrap_err().to_string().contains("unknown group nope"));
        alice.cmd(&["leave", &format!("--group={}", &other[..8])]).await.unwrap();
        assert!(alice.cmd(&["remove", "Carol"]).await.is_err());
        assert_eq!(alice.cmd(&["remove", &bob.fp[..8]]).await.unwrap()["removed"], json!([bob.fp]));
        assert_eq!(alice.told(&["left"]).await["member"], bob.fp);
        let removed = bob.told(&["removed"]).await;
        assert_eq!((&removed["group"], &removed["by"]), (&json!(group), &json!(alice.fp)));
        assert_eq!(bob.cmd(&["groups"]).await.unwrap(), json!({}), "no groups");
    });
}

/// The files of a session's database, and its log, that hold `secret`. The `-shm` file holds only the WAL's index, and
/// Windows locks parts of it.
fn holding(dir: &Path, secret: &str) -> Vec<PathBuf> {
    let files = ["session.db", "session.db-wal", "log.jsonl"].map(|name| dir.join(name));
    files.into_iter().filter(|path| std::fs::read(path).unwrap_or_default().windows(secret.len()).any(|w| w == secret.as_bytes())).collect()
}

#[test]
fn text_logged_stays_only_in_the_log_until_the_group_is_left() {
    local(async {
        let world = world("scrub").await;
        let (mut alice, mut bob, _) = pair(&world).await;
        let secret = "the vault code is 7-tangerine-42";
        bob.cmd(&["send", "--to", &alice.fp, secret]).await.unwrap();
        assert_eq!(alice.expect("message").await["content"].as_str().unwrap(), secret);
        alice.cmd(&["groups"]).await.unwrap();
        let dir = session_dir(&alice.home, "alice").unwrap();
        assert_eq!(holding(&dir, secret), vec![dir.join("log.jsonl")]);
        alice.cmd(&["remove", &bob.fp]).await.unwrap();
        bob.told(&["removed"]).await;
        assert_eq!(holding(&session_dir(&bob.home, "bob").unwrap(), secret), Vec::<PathBuf>::new());
    });
}

#[test]
fn a_shown_messages_attachment_stays_only_in_its_file() {
    local(async {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let world = world("scrub-attach").await;
        let (mut alice, mut bob, _) = pair(&world).await;
        let secret = "the vault key is 9-apricot-71";
        let encoded = URL_SAFE_NO_PAD.encode(secret);
        let file = world.root.path().join("cred.key");
        std::fs::write(&file, secret).unwrap();
        bob.cmd(&["send", "--to", &alice.fp, "--attach", file.to_str().unwrap(), "the key"]).await.unwrap();
        let message = alice.expect("message").await;
        assert_eq!(std::fs::read_to_string(message["attachment"]["path"].as_str().unwrap()).unwrap(), secret);
        alice.cmd(&["send", "--reply-to", message["id"].as_str().unwrap(), "got it"]).await.unwrap();
        assert_eq!(bob.expect("message").await["content"], "got it");
        let dir = session_dir(&alice.home, "alice").unwrap();
        assert_eq!(holding(&dir, &encoded), Vec::<PathBuf>::new());
        assert_eq!(holding(&dir, secret), Vec::<PathBuf>::new());
        assert!(!holding(&session_dir(&bob.home, "bob").unwrap(), &encoded).is_empty(), "its sender's own stays whole");
    });
}

#[test]
fn a_leaving_member_is_removed_by_another() {
    local(async {
        let world = world("leave").await;
        let (mut alice, mut bob, _) = pair(&world).await;
        let left = bob.cmd(&["leave"]).await.unwrap();
        assert_eq!(left["pending"], true);
        assert_eq!(alice.told(&["left"]).await["member"], bob.fp);
        bob.told(&["removed"]).await;
    });
}

/// Asks again, a quarter of a second apart, until `accept` takes what `ask` answers or 30 seconds pass; returns the last
/// answer.
async fn until(ask: impl AsyncFn() -> Value, accept: impl Fn(&Value) -> bool) -> Value {
    let end = std::time::Instant::now() + WAIT;
    loop {
        let answer = ask().await;
        if accept(&answer) || std::time::Instant::now() > end {
            return answer;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// A message taken in leaves nothing in the session's tables once H has passed, and its attachment's copy goes with it.
#[test]
fn a_message_taken_in_is_forgotten_after_h_with_its_attachments_copy() {
    static LATER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn later() -> u64 {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64 + LATER.load(Ordering::Relaxed)
    }
    local(async {
        lmk_proto::clock::set(later);
        let world = world("forgotten").await;
        let (mut alice, bob, _) = pair(&world).await;
        let file = world.root.path().join("token.txt");
        std::fs::write(&file, "s3cret").unwrap();
        bob.cmd(&["send", "--to", &alice.fp, "--attach", file.to_str().unwrap(), "the token"]).await.unwrap();
        let message = alice.expect("message").await;
        let path = message["attachment"]["path"].as_str().unwrap();
        assert!(Path::new(path).exists());
        let db = session_dir(&alice.home, "alice").unwrap().join("session.db");
        let taken = || rusqlite::Connection::open(&db).unwrap().query_row("SELECT count(*) FROM taken", [], |row| row.get::<_, i64>(0)).unwrap();
        assert_eq!(taken(), 1);
        alice.stop().await;
        LATER.store(8 * 24 * 3600 * 1000, Ordering::Relaxed);
        let alice = world.start("alice").await;
        alice.cmd(&["groups"]).await.unwrap();
        assert_eq!(taken(), 0);
        assert!(!Path::new(path).exists());
    });
}

/// `status` lists this session's sends that no other member holds yet, with a warning, until a member connected to it holds
/// them.
#[test]
fn status_lists_sends_held_only_here() {
    local(async {
        let world = world("only-here").await;
        let (mut alice, mut bob, group) = pair(&world).await;
        alice.cmd(&["send", "hello"]).await.unwrap();
        // Bob takes it, and the invite before it: once his summary tells Alice, her next commit keeps both.
        bob.told(&["message"]).await;
        until(|| async { alice.cmd(&["groups"]).await.unwrap() }, |status| status["groups"][0]["only_here"].is_null()).await;
        add_and_remove(&world, &mut alice, &group).await;
        bob.stop().await;
        let sent = alice.cmd(&["send", "anyone?"]).await.unwrap();
        let status = alice.cmd(&["groups"]).await.unwrap();
        assert_eq!(status["groups"][0]["only_here"], json!([{ "what": "message", "id": sent["id"] }]));
        let _bob = world.start("bob").await;
        let status = until(|| async { alice.cmd(&["groups"]).await.unwrap() }, |status| status["groups"][0]["only_here"].is_null()).await;
        assert!(status["groups"][0]["only_here"].is_null(), "Bob holds it: {status}");
    });
}

#[test]
fn a_leave_is_pending_until_another_member_removes_the_session() {
    local(async {
        let world = world("leave-pending").await;
        let (mut alice, mut bob, _) = pair(&world).await;
        alice.stop().await;
        let left = bob.cmd(&["leave"]).await.unwrap();
        assert_eq!(left, json!({ "group": left["group"], "pending": true }));
        let _alice = world.start("alice").await;
        assert_eq!(bob.told(&["removed"]).await["type"], "removed");
    });
}

/// Alice adds a session to the group and removes it again: two commits, after which the members are as they were.
async fn add_and_remove(world: &World, alice: &mut Agent, group: &str) {
    let mut carol = world.start("carol").await;
    let link = alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap();
    carol.cmd(&["join", link["link"].as_str().unwrap()]).await.unwrap();
    alice.told(&["joined"]).await;
    alice.cmd(&["remove", &carol.fp]).await.unwrap();
    carol.told(&["removed"]).await;
    carol.stop().await;
}

/// A message no other member holds is not told lost: Bob is away while Alice sends and commits twice, and gets the
/// message once Alice is back, as she still holds it.
#[test]
fn a_message_no_other_member_holds_is_not_lost() {
    local(async {
        let world = world("unkept").await;
        let (mut alice, mut bob, group) = pair(&world).await;
        bob.stop().await;
        alice.cmd(&["send", "while you were out"]).await.unwrap();
        add_and_remove(&world, &mut alice, &group).await;
        alice.stop().await;
        let mut bob = world.start("bob").await;
        let _alice = world.start("alice").await;
        // Unless it comes while Bob catches up, the message, which does not wake him, waits for his next command.
        assert_eq!(bob.told(&["message"]).await["content"], "while you were out");
        assert!(bob.printed().await.iter().all(|e| e["type"] != "lost"));
    });
}

#[test]
fn the_command_channel_needs_its_token_and_a_running_session() {
    local(async {
        let world = world("channel").await;
        let alice = world.start("alice").await;
        let endpoint: Value =
            serde_json::from_slice(&std::fs::read(session_dir(&alice.home, "alice").unwrap().join("endpoint")).unwrap()).unwrap();
        let port = endpoint["port"].as_u64().unwrap() as u16;
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (read, mut write) = stream.into_split();
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        write.write_all(b"{\"token\":\"nope\",\"request\":{\"cmd\":\"groups\"}}\n").await.unwrap();
        let mut line = String::new();
        tokio::io::BufReader::new(read).read_line(&mut line).await.unwrap();
        assert!(line.contains("bad token"));
        // Sessions killed long ago left their endpoints; on Windows each refused connection takes seconds.
        for i in 0..5 {
            let dir = session_dir(&alice.home, &format!("fake{i}")).unwrap();
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("endpoint"), r#"{"port":1,"token":"x"}"#).unwrap();
        }
        let finding = std::time::Instant::now();
        assert_eq!(crate::cli::running_session(&alice.home).await.unwrap(), "alice");
        assert!(finding.elapsed() < Duration::from_secs(1), "{:?}", finding.elapsed());
        let missing = Agent { name: "nobody".into(), home: alice.home.clone(), fp: String::new(), events: mpsc::unbounded_channel().1, stop: None, done: None, ready: Value::Null, told: BTreeSet::new() };
        let error = missing.cmd(&["groups"]).await.unwrap_err().to_string();
        assert!(error.contains("not running"), "{error}");
    });
}

#[test]
fn the_command_channel_drops_an_oversized_call_without_a_newline() {
    local(async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let home = tempfile::tempdir().unwrap();
        let held = std::fs::File::create(home.path().join("session.lock")).unwrap();
        held.try_lock().unwrap();
        let endpoint = home.path().join("endpoint");
        let (inbound, mut requests) = mpsc::unbounded_channel();
        crate::cli::open_channel(&endpoint, inbound).await.unwrap();
        let (mut stream, token) = crate::cli::connect(&endpoint).await.unwrap();
        let mut call = serde_json::to_vec(&json!({ "token": token, "request": { "cmd": "groups" } })).unwrap();
        call.resize(crate::cli::MAX_CALL as usize + 1, b' ');
        stream.write_all(&call).await.unwrap();
        let mut byte = [0];
        let read = tokio::time::timeout(WAIT, stream.read(&mut byte)).await.expect("an oversized call closes without a newline");
        assert_eq!(read.unwrap(), 0, "an oversized call gets no response");
        assert!(requests.try_recv().is_err(), "even a valid prefix is not dispatched");
    });
}

#[test]
fn a_stale_endpoint_on_a_live_port_does_not_make_a_session_running() {
    local(async {
        let world = world("stale-running").await;
        let alice = world.start("alice").await;
        let dir = session_dir(&alice.home, "stopped").unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(world.config("alice", "alice").dir.join("endpoint"), dir.join("endpoint")).unwrap();
        let held = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("session.lock")).unwrap();
        assert_eq!(crate::cli::running(&alice.home).await, ["alice"]);
        assert_eq!(crate::cli::running_session(&alice.home).await.unwrap(), "alice");
        held.try_lock().unwrap();
        assert_eq!(crate::cli::running(&alice.home).await, ["alice", "stopped"]);
        drop(held);
        assert_eq!(crate::cli::running(&alice.home).await, ["alice"]);
    });
}

#[test]
fn the_command_channel_takes_a_twelve_mib_attachment_and_no_larger_call() {
    local(async {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        let home = tempfile::tempdir().unwrap();
        let held = std::fs::File::create(home.path().join("session.lock")).unwrap();
        held.try_lock().unwrap();
        let endpoint = home.path().join("endpoint");
        let (inbound, mut requests) = mpsc::unbounded_channel();
        crate::cli::open_channel(&endpoint, inbound).await.unwrap();
        let channel = crate::cli::connect(&endpoint).await.unwrap();
        let attach = B64.encode(vec![0; 12 << 20]);
        let request = Request::Send {
            group: None, to: vec![], reply_to: None, urgent: false, attach: Some(attach.clone()), attach_name: "large.bin".into(), text: "a large file".into(),
        };
        let calling = tokio::spawn(crate::cli::exchange(channel, request));
        let request = tokio::time::timeout(WAIT, requests.recv()).await.unwrap().unwrap();
        let crate::session::Inbound::Request(Request::Send { attach: received, .. }, reply) = request else { panic!("not a send") };
        assert_eq!(received.as_deref(), Some(attach.as_str()));
        reply.send(json!({ "id": "sent" })).unwrap();
        assert_eq!(calling.await.unwrap().unwrap(), json!({ "id": "sent" }));
        let channel = crate::cli::connect(&endpoint).await.unwrap();
        let request = Request::Send {
            group: None, to: vec![], reply_to: None, urgent: false, attach: Some(B64.encode(vec![0; 13 << 20])), attach_name: "larger.bin".into(), text: String::new(),
        };
        let refused = crate::cli::exchange(channel, request).await.unwrap_err();
        assert!(refused.to_string().starts_with("size: "), "{refused:#}");
    });
}

#[test]
fn a_session_starts_with_a_stale_endpoint_on_a_live_port() {
    local(async {
        let world = world("stale-channel").await;
        let alice = world.start("alice").await;
        let dir = session_dir(&alice.home, "bob").unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(world.config("alice", "alice").dir.join("endpoint"), dir.join("endpoint")).unwrap();
        let bob = world.start_in("alice", "bob").await;
        assert_eq!(bob.cmd(&["groups"]).await.unwrap(), json!({}));
        assert_eq!(alice.cmd(&["groups"]).await.unwrap(), json!({}));
    });
}

#[test]
fn a_stale_endpoint_on_a_live_port_is_not_connected_to() {
    local(async {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let world = world("stale-connect").await;
        let (mut alice, _bob, _) = pair(&world).await;
        let detached = || Config { detached: true, ..world.config("alice", "alice") };
        alice.stop().await;
        let mut alice = world.launch(detached(), usize::MAX).await;
        let (mut printed, reading) = attached(&alice);
        assert_eq!(read(&mut printed).await["type"], "ready");

        alice.stop().await;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        std::fs::write(detached().dir.join("endpoint"), serde_json::to_vec(&json!({ "port": port, "token": "other" })).unwrap()).unwrap();
        let (taken_tx, mut taken) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let taken_tx = taken_tx.clone();
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut line = String::new();
                    let _ = tokio::io::BufReader::new(r).read_line(&mut line).await;
                    let _ = taken_tx.send(line);
                    let _ = w.write_all(b"{\"error\":\"bad token\"}\n").await;
                });
            }
        });

        let secret = world.root.path().join("secret.txt");
        std::fs::write(&secret, "secret-attachment").unwrap();
        let error = alice.cmd(&["send", "--attach", secret.to_str().unwrap(), "secret-text"]).await.unwrap_err().to_string();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(taken.try_recv().is_err() && error.contains("not running") && !reading.is_finished(), "{error}");

        let _alice = world.launch(detached(), usize::MAX).await;
        assert_eq!(read(&mut printed).await["type"], "ready");
    });
}

#[test]
fn a_restarted_session_takes_in_what_it_missed_in_delivery_order() {
    local(async {
        let world = world("causal").await;
        let (mut alice, bob, group) = pair(&world).await;
        alice.stop().await;
        let first = bob.cmd(&["send", "--urgent", "first"]).await.unwrap();
        assert!(first["id"].is_string(), "{first}");
        let second = bob.cmd(&["send", "--urgent", "second"]).await.unwrap();
        let mut alice = world.start("alice").await;
        let mut got = Vec::new();
        while got.len() < 2 {
            let message = alice.expect("message").await;
            assert!(message.get("missing").is_none());
            got.push(message["id"].clone());
        }
        assert_eq!(got, [first["id"].clone(), second["id"].clone()]);
        let groups = alice.cmd(&["groups"]).await.unwrap();
        assert_eq!(groups["groups"][0]["group"], group);
    });
}

/// A member ends a group for everyone: the others are removed, and it leaves.
#[test]
fn a_group_ended_for_everyone_keeps_no_member() {
    local(async {
        let world = world("end").await;
        let (alice, mut bob, _) = pair(&world).await;
        let ended = alice.cmd(&["leave", "--end"]).await.unwrap();
        assert_eq!((ended["ended"].as_bool(), ended.get("pending")), (Some(true), None), "{ended}");
        assert_eq!(bob.told(&["removed"]).await["by"], alice.fp);
        assert_eq!(alice.cmd(&["groups"]).await.unwrap(), json!({}), "no groups");
        assert_eq!(bob.cmd(&["groups"]).await.unwrap(), json!({}), "no groups");
    });
}

/// A message whose holders are all away does not hold up a later one that does not depend on it: that one comes as soon as
/// its author is online, and says nothing missing.
#[test]
fn a_message_no_member_online_holds_does_not_hold_up_others() {
    local(async {
        let world = world("gap").await;
        let (mut alice, mut bob, group) = pair(&world).await;
        let mut carol = world.start("carol").await;
        carol.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        bob.told(&["joined"]).await;
        alice.stop().await;
        carol.stop().await;
        bob.cmd(&["send", "while they are away"]).await.unwrap();
        bob.stop().await;
        let alice = world.start("alice").await;
        let mut carol = world.start("carol").await;
        alice.cmd(&["send", "--to", &carol.fp, "after the gap"]).await.unwrap();
        let got = carol.expect("message").await;
        assert_eq!(got["content"], "after the gap");
        assert!(got.get("missing").is_none(), "{got}");
    });
}

/// A session whose reader is gone stops at the first line it cannot write. What it logged is delivered: started again, it
/// prints none of it again, and its log holds each message once.
#[test]
fn a_session_stops_once_it_cannot_print_and_logged_each_message_once() {
    local(async {
        let world = world("output").await;
        let (mut alice, bob, _) = pair(&world).await;
        alice.stop().await;
        let mut sent = Vec::new();
        for i in 0..10 {
            sent.push(bob.cmd(&["send", "--urgent", &format!("m{i}")]).await.unwrap()["id"].clone());
        }
        let mut alice = world.launch(world.config("alice", "alice"), 1).await;
        alice.expect("message").await;
        tokio::time::timeout(Duration::from_secs(30), alice.done.take().unwrap()).await.unwrap().unwrap();
        let ids = |agent: &Agent| -> Vec<Value> {
            let logged = agent.log().into_iter().map(|line| serde_json::from_str::<Value>(&line).unwrap()).filter(|e| e["type"] == "message");
            logged.map(|e| e["id"].clone()).collect()
        };
        let before = ids(&alice);
        let mut alice = world.start("alice").await;
        let logged = until(|| async { json!(ids(&alice)) }, |logged| logged.as_array().unwrap().len() >= sent.len()).await;
        assert_eq!(logged, json!(sent));
        assert!(alice.printed().await.iter().all(|e| !before.contains(&e["id"])), "what was logged prints not again");
    });
}

/// A message whose attachment could not be saved warns and stays unshown while later messages are shown; started again,
/// the session takes it in, without taking in what was shown again.
#[test]
fn a_message_whose_file_could_not_be_saved_is_taken_in_as_the_session_next_starts() {
    local(async {
        let world = world("retaken").await;
        let (mut alice, bob, _) = pair(&world).await;
        let blocked = session_dir(&alice.home, "alice").unwrap().join("attachments");
        std::fs::write(&blocked, "").unwrap();
        let file = world.root.path().join("token.txt");
        std::fs::write(&file, "s3cret").unwrap();
        bob.cmd(&["send", "--to", &alice.fp, "--attach", file.to_str().unwrap(), "first"]).await.unwrap();
        alice.expect("warning").await;

        std::fs::remove_file(&blocked).unwrap();
        bob.cmd(&["send", "--to", &alice.fp, "second"]).await.unwrap();
        assert_eq!(alice.expect("message").await["content"], "second");

        alice.stop().await;
        let mut alice = world.start("alice").await;
        alice.cmd(&["groups"]).await.unwrap();
        let logged: Vec<Value> = alice
            .log()
            .into_iter()
            .map(|line| serde_json::from_str::<Value>(&line).unwrap())
            .filter(|e| e["type"] == "message")
            .map(|e| e["content"].clone())
            .collect();
        assert_eq!(logged, ["second", "first"]);
        let first = alice.expect("message").await;
        assert_eq!(first["content"], "first");
        assert_eq!(std::fs::read_to_string(first["attachment"]["path"].as_str().unwrap()).unwrap(), "s3cret");
    });
}

/// `sessions` lists this machine's sessions, each with its fingerprint, its group ids and whether it runs. One that
/// stopped in no group is gone.
#[test]
fn sessions_lists_this_machines_sessions_running_or_stopped() {
    local(async {
        let world = world("sessions").await;
        let alice = world.start("alice").await;
        let mut bob = world.start_new("bob").await;
        let invite = alice.cmd(&["invite"]).await.unwrap();
        let group = invite["group"].as_str().unwrap().to_owned();
        bob.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        world.start_new("bob").await.stop().await;
        let mut desk = world.start_new("bob").await;
        let invite = alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap();
        desk.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        let desk_fp = desk.fp.clone();
        let listed = |desk: bool| {
            let mut sessions = vec![
                json!({ "fp": bob.fp, "running": true, "groups": [group] }),
                json!({ "fp": desk_fp, "groups": [group] }),
            ];
            if desk {
                sessions[1]["running"] = json!(true);
            }
            sessions.sort_by(|a, b| a["fp"].as_str().cmp(&b["fp"].as_str()));
            json!({ "sessions": sessions })
        };
        // Each with when it last ran, which is about now.
        let sessions = || async {
            let mut listed = crate::sessions(&bob.home).await.unwrap();
            for session in listed["sessions"].as_array_mut().unwrap() {
                let at = session.as_object_mut().unwrap().remove("last_ran").unwrap();
                assert!(at.as_str().unwrap().starts_with(&crate::short::iso(lmk_proto::clock::now())[..13]), "{at}");
            }
            listed
        };
        let running = until(sessions, |running| *running == listed(true)).await;
        assert_eq!(running, listed(true));
        desk.stop().await;
        assert_eq!(sessions().await, listed(false));
        bob.stop().await;
    });
}

/// One process runs a session: another `listen` of it fails, also one that does not find its command channel, as when
/// both start at once.
#[test]
fn a_session_runs_in_one_process() {
    local(async {
        let world = world("one-process").await;
        let alice = world.start("alice").await;
        std::fs::remove_file(world.config("alice", "alice").dir.join("endpoint")).unwrap();
        let again = crate::listen(world.config("alice", "alice"), &alice.home, world.network.clone(), |_| Ok(()), std::future::pending());
        let error = tokio::time::timeout(Duration::from_secs(10), again).await.expect("it fails at once").unwrap_err();
        assert_eq!(error.to_string(), "this session is already running");
    });
}

/// A join that waits on a member who never answers holds up none of the session's other work.
#[test]
fn a_session_goes_on_while_a_join_waits() {
    local(async {
        let world = world("busy").await;
        let (alice, mut bob, group) = pair(&world).await;
        let link = alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap().to_owned();
        let mut invite = lmk_proto::links::Invite::parse(&link).unwrap();
        invite.members[0].0 = *iroh::SecretKey::generate().public().as_bytes();
        let (home, name) = (bob.home.clone(), bob.name.clone());
        let join = Request::Join { link: invite.link() };
        let joining = tokio::task::spawn_local(async move { crate::cli::call(&home, &name, join).await });
        tokio::time::sleep(Duration::from_millis(500)).await;
        let started = std::time::Instant::now();
        bob.cmd(&["groups"]).await.unwrap();
        alice.cmd(&["send", "--to", &bob.fp, "still there?"]).await.unwrap();
        assert_eq!(bob.expect("message").await["content"], "still there?");
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(!joining.is_finished(), "the join still waits");
    });
}

/// A restarted session prints what was delivered after the last message it showed, and not what came before it.
#[test]
fn messages_not_for_a_session_are_logged_in_order_and_print_not() {
    local(async {
        let world = world("logged").await;
        let (mut alice, bob, group) = pair(&world).await;
        bob.cmd(&["send", "before"]).await.unwrap();
        bob.cmd(&["send", "--to", &alice.fp, "to alice"]).await.unwrap();
        assert_eq!(alice.expect("message").await["content"], "to alice");
        bob.cmd(&["send", "after"]).await.unwrap();
        let contents: Vec<Value> = [alice.told(&["message"]).await, alice.told(&["message"]).await, alice.told(&["message"]).await].iter().map(|e| e["content"].clone()).collect();
        assert_eq!(contents, ["before", "to alice", "after"]);
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message"));
        assert!(alice.ready["log"].as_str().unwrap().ends_with("log.jsonl"));
        // Leaving takes its lines out of the log, but for the `removed`.
        alice.cmd(&["leave", "--end"]).await.unwrap();
        let log = until(|| async { json!(alice.log()) }, |log| log.as_array().unwrap().iter().all(|line| !line.as_str().unwrap().contains(r#""type":"message""#))).await;
        assert!(log.as_array().unwrap().iter().all(|line| !line.as_str().unwrap().contains(&group) || line.as_str().unwrap().contains(r#""type":"removed""#)), "{log}");
    });
}

/// A home another release wrote is refused and left as it is.
#[test]
fn a_home_of_another_format_is_refused() {
    local(async {
        let world = world("format").await;
        for (format, names) in [("13", "an earlier letmeknow"), ("15", "a newer letmeknow")] {
            let home = world.root.path().join(format!("format-{format}"));
            std::fs::create_dir_all(&home).unwrap();
            std::fs::write(home.join("format"), format!("{format}\n")).unwrap();
            let config = Config { dir: session_dir(&home, "alice").unwrap(), ..world.config("alice", "alice") };
            let error = crate::listen(config, &home, world.network.clone(), |_| Ok(()), std::future::pending()).await.unwrap_err().to_string();
            assert!(error.contains(names), "{error}");
            assert_eq!(std::fs::read_to_string(home.join("format")).unwrap(), format!("{format}\n"));
            assert!(!home.join("sessions").exists());
        }
    });
}

/// A session refuses a membership service that is not a domain, names one its home has pinned another key for, or has
/// no directory, and the refusals name what they concern.
#[test]
fn a_membership_domain_is_checked_pinned_and_fetched() {
    local(async {
        let world = world("membership").await;
        let network = world.network.clone();
        let listen = |config: Config, home: PathBuf| {
            let network = network.clone();
            async move { crate::listen(config, &home, network, |_| Ok(()), std::future::pending()).await.unwrap_err().to_string() }
        };
        for address in ["Relay.example.com", "a1b2@https://relay.example.com"] {
            let config = Config { membership: address.into(), ..world.config("alice", "alice") };
            let error = listen(config, world.root.path().join("alice")).await;
            assert!(error.contains("canonical host"), "{error}");
        }
        let unreachable = free_port();
        let config = Config { membership: format!("localhost:{unreachable}"), ..world.config("bob", "bob") };
        let error = listen(config, world.root.path().join("bob")).await;
        assert!(error.contains(&format!("localhost:{unreachable}")), "{error}");

        let home = world.root.path().join("carol");
        std::fs::create_dir_all(&home).unwrap();
        let other = hex::encode([7u8; 32]);
        std::fs::write(home.join("membership.json"), json!({ &world.domain: other }).to_string()).unwrap();
        let config = world.config("carol", "carol");
        let error = listen(config, home.clone()).await;
        assert!(error.contains(&other) && error.contains(&world.key), "{error}");
    });
}

/// Sessions starting at once in one home find neither `format`, written once, nor `membership.json` half written.
#[test]
fn sessions_starting_at_once_in_one_home_read_whole_files() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let network = crate::Network {
        ca: iroh::tls::CaTlsConfig::embedded(),
        resolve: Arc::new(|_| Box::pin(async { Ok(Directory { key: [1; 32] }) })),
        post: Arc::new(|_, _, _| Box::pin(async { unreachable!() })),
    };
    std::thread::scope(|scope| {
        for worker in 0..4 {
            let (root, home, network) = (dir.path(), &home, &network);
            scope.spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                for round in 0..200 {
                    crate::own_format(&root.join(format!("fresh-{round}"))).unwrap();
                    crate::own_format(home).unwrap();
                    let domain = if worker == 0 { format!("d{round}.example") } else { "pinned.example".into() };
                    rt.block_on(crate::own_directory(home, network, &domain)).unwrap();
                }
            });
        }
    });
    let earlier = SystemTime::now() - Duration::from_secs(60);
    std::fs::File::options().write(true).open(home.join("format")).unwrap().set_modified(earlier).unwrap();
    crate::own_format(&home).unwrap();
    assert_eq!(std::fs::metadata(home.join("format")).unwrap().modified().unwrap(), earlier);
}

/// A session's directory is fetched, and a copy of it answers while it is fresh, and where a fetch fails.
#[tokio::test]
async fn a_directory_is_cached_and_the_built_in_one_answers_for_letmeknow_dev() {
    let dir = tempfile::tempdir().unwrap();
    let served = Directory { key: [1; 32] };
    let calls = Arc::new(AtomicU32::new(0));
    let fetch: lmk_membership::client::Resolve = {
        let (served, calls) = (served.clone(), calls.clone());
        Arc::new(move |domain: String| -> BoxFuture<anyhow::Result<Directory>> {
            let (served, calls) = (served.clone(), calls.clone());
            Box::pin(async move {
                if calls.fetch_add(1, Ordering::Relaxed) == 0 { Ok(served) } else { anyhow::bail!("{domain} is down") }
            })
        })
    };
    let cache = dir.path().join("directories");
    let resolve = crate::cached(cache.clone(), fetch);
    assert_eq!(resolve("localhost:8443".into()).await.unwrap(), served);
    assert_eq!(resolve("localhost:8443".into()).await.unwrap(), served);
    assert_eq!(calls.load(Ordering::Relaxed), 1, "a fresh copy answers without a fetch");
    let file = std::fs::File::options().write(true).open(cache.join("localhost_8443.json")).unwrap();
    file.set_modified(SystemTime::now() - Duration::from_secs(3600)).unwrap();
    assert_eq!(resolve("localhost:8443".into()).await.unwrap(), served, "a failed fetch answers the copy");
    assert!(resolve("localhost:9443".into()).await.unwrap_err().to_string().contains("is down"));
    let fetches = calls.load(Ordering::Relaxed);
    assert!(resolve("localhost:9443".into()).await.is_err());
    assert_eq!(calls.load(Ordering::Relaxed), fetches, "a failed fetch is not repeated for a minute");
    assert_eq!(calls.load(Ordering::Relaxed), 3);
    let down: lmk_membership::client::Resolve = Arc::new(|domain: String| -> BoxFuture<anyhow::Result<Directory>> {
        Box::pin(async move { anyhow::bail!("{domain} is down") })
    });
    let resolve = crate::cached(dir.path().join("empty"), down);
    assert_eq!(resolve(lmk_proto::links::DOMAIN.into()).await.unwrap(), Directory::builtin());
    assert!(resolve("localhost:9443".into()).await.is_err());
}

/// Lookups that arrive during a fetch do not start another: the first answers its failure, the others answer that they
/// started too recently.
#[tokio::test]
async fn lookups_during_a_fetch_do_not_start_another() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicU32::new(0));
    let fetch: lmk_membership::client::Resolve = {
        let calls = calls.clone();
        Arc::new(move |domain: String| -> BoxFuture<anyhow::Result<Directory>> {
            let calls = calls.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(50)).await;
                anyhow::bail!("{domain} is down")
            })
        })
    };
    let resolve = crate::cached(dir.path().join("directories"), fetch);
    let (a, b, c) = tokio::join!(resolve("localhost:8443".into()), resolve("localhost:8443".into()), resolve("localhost:8443".into()));
    assert!(a.unwrap_err().to_string().contains("is down"));
    for answer in [b, c] {
        assert!(answer.unwrap_err().to_string().contains("started less than a minute ago"));
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

/// As a session starts, the stopped sessions that have not run for 28 days go, whatever their groups, by the last change
/// of any of their files; and so do those in no group.
#[tokio::test]
async fn stopped_sessions_that_have_not_run_for_28_days_are_deleted() {
    let home = tempfile::tempdir().unwrap();
    let ago = |days: u64| SystemTime::now() - Duration::from_secs(days * 24 * 3600);
    for (name, days, log_days, groups) in [("old", 28, 28, r#"["group"]"#), ("recent", 27, 27, r#"["group"]"#), ("logged", 40, 1, r#"["group"]"#), ("running", 29, 29, r#"["group"]"#), ("empty", 0, 0, "[]")] {
        let dir = session_dir(home.path(), name).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        for (file, days) in [("groups.json", days), ("session.db", days), ("session.lock", days), ("log.jsonl", log_days)] {
            std::fs::write(dir.join(file), if file == "groups.json" { groups } else { "" }).unwrap();
            std::fs::File::options().write(true).open(dir.join(file)).unwrap().set_modified(ago(days)).unwrap();
        }
    }
    let held = std::fs::File::options().write(true).open(session_dir(home.path(), "running").unwrap().join("session.lock")).unwrap();
    held.try_lock().unwrap();
    assert!(crate::delete_stopped(home.path().to_owned()).await.unwrap().is_empty());
    for (name, kept) in [("old", false), ("recent", true), ("logged", true), ("running", true), ("empty", false)] {
        assert_eq!(session_dir(home.path(), name).unwrap().exists(), kept, "{name}");
    }
}

/// A stopped session that the group moved past while it was stopped, started again, catches up with the group before it
/// invites, however long its reading takes: as a harness starts one again to bring a new session of its home into the
/// group. A stopped session in no group that was not deleted as it stopped goes as the next one starts.
#[test]
fn a_stopped_session_started_again_catches_up_before_it_invites() {
    local(async {
        let mut world = world("revive").await;
        let home = world.root.path().join("h");
        let mut alice = world.start_in("h", "alice").await;
        let invite = alice.cmd(&["invite"]).await.unwrap();
        let group = invite["group"].as_str().unwrap().to_owned();
        // On Alice's device, an admin, as she is.
        let bob = world.start_in("h", "bob").await;
        bob.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        let mut carol = world.start("carol").await;
        carol.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        alice.stop().await;
        bob.cmd(&["remove", &carol.fp]).await.unwrap();
        carol.stop().await;

        let fast = world.network.post.clone();
        world.network.post = Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| -> BoxFuture<Result<Vec<u8>>> {
            let answer = fast(domain, route, body);
            Box::pin(async move {
                if route == "/membership/6/read" {
                    tokio::time::sleep(Duration::from_secs(6)).await;
                }
                answer.await
            })
        });
        let mut stale = world.start_in("h", "stale").await;
        stale.stop().await;
        crate::cli::private_dir(&session_dir(&home, "stale").unwrap()).unwrap();
        std::fs::write(session_dir(&home, "stale").unwrap().join("groups.json"), "[]").unwrap();
        let alice = world.start_in("h", "alice").await;
        let link = alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap().to_owned();
        let dave = world.start_in("h", "dave").await;
        dave.cmd(&["join", &link]).await.unwrap();
        assert_eq!(dave.cmd(&["members", "--all"]).await.unwrap()["members"].as_array().unwrap().len(), 3);
        // Windows refuses to delete a file still open, as one of this process's other sessions may hold one of theirs.
        if !cfg!(windows) {
            let gone = || !session_dir(&home, "stale").unwrap().exists();
            until(|| async { json!(gone()) }, |gone| *gone == true).await;
            assert!(gone(), "the stopped session in no group is deleted as the next session starts");
        }
    });
}

/// A member's intro reaches the group by its neighbours, with no commit: every member sees it in `members`, a joiner
/// too, until the member clears it.
#[test]
fn an_intro_shows_in_every_members_list() {
    local(async {
        let world = world("intro").await;
        let (alice, bob, group) = pair(&world).await;
        let intro = |members: &Value, fp: &str| members["members"].as_array().unwrap().iter().find(|m| m["fp"] == fp).unwrap()["intro"].clone();
        assert!(alice.cmd(&["intro", &"x".repeat(281)]).await.unwrap_err().to_string().contains("at most 280 bytes"));
        assert_eq!(alice.cmd(&["intro", "budget agent, LF laptop"]).await.unwrap()["intro"], "budget agent, LF laptop");
        let seen = until(|| async { bob.cmd(&["members"]).await.unwrap() }, |members| intro(members, &alice.fp) == "budget agent, LF laptop").await;
        assert_eq!(intro(&seen, &alice.fp), "budget agent, LF laptop");
        let carol = world.start("carol").await;
        carol.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        let joined = until(|| async { carol.cmd(&["members"]).await.unwrap() }, |members| intro(members, &alice.fp) == "budget agent, LF laptop").await;
        assert_eq!(intro(&joined, &alice.fp), "budget agent, LF laptop", "a joiner sees it in the group it joins");
        alice.cmd(&["intro"]).await.unwrap();
        let seen = until(|| async { bob.cmd(&["members"]).await.unwrap() }, |members| intro(members, &alice.fp).is_null()).await;
        assert!(intro(&seen, &alice.fp).is_null(), "{seen}");
    });
}

/// Each home here is a device: `members` shows the device each member runs on, by the fingerprint `device` gives, and
/// `remove --device` removes every other member on a device in one commit, never the caller.
#[test]
fn members_show_their_devices_and_remove_device_removes_a_devices_members() {
    local(async {
        let world = world("device").await;
        let (alice, mut bob, group) = pair(&world).await;
        let mut desk = world.start_in("bob", "desk").await;
        desk.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        let (alices, bobs) = (world.device("alice"), world.device("bob"));
        assert_ne!(alices["fp"], bobs["fp"]);
        let shown = |members: &Value| members["members"].as_array().unwrap().iter().filter(|m| m.get("device").is_some()).count();
        let listed = until(|| async { alice.cmd(&["members"]).await.unwrap() }, |members| shown(members) == 3).await;
        for member in listed["members"].as_array().unwrap() {
            assert_eq!(member["device"], if member["you"] == true { alices.clone() } else { bobs.clone() }, "{listed}");
        }
        let refused = alice.cmd(&["remove", "--device", alices["fp"].as_str().unwrap()]).await.unwrap_err().to_string();
        assert!(refused.contains("no other member"), "{refused}");
        let removed = alice.cmd(&["remove", "--device", &bobs["fp"].as_str().unwrap()[..8]]).await.unwrap();
        let removed: BTreeSet<&str> = removed["removed"].as_array().unwrap().iter().map(|fp| fp.as_str().unwrap()).collect();
        assert_eq!(removed, BTreeSet::from([bob.fp.as_str(), desk.fp.as_str()]));
        assert_eq!(bob.told(&["removed"]).await["by"], alice.fp);
        assert_eq!(desk.told(&["removed"]).await["by"], alice.fp);
    });
}

/// An admin's session that was stopped while sessions joined catches up before `remove` names its members, by device or
/// by fingerprint.
#[test]
fn a_stopped_admin_catches_up_before_remove_names_members() {
    local(async {
        let world = world("remove-caught-up").await;
        let (mut alice, mut bob, group) = pair(&world).await;
        let mut other = world.start_in("alice", "other").await;
        other.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        let bobs = world.device("bob")["fp"].as_str().unwrap().to_owned();
        let carols = hex::encode(crate::device(&world.root.path().join("carol")).unwrap().verifying_key().to_bytes());
        alice.cmd(&["admitted", "add", &bobs[..8], &carols]).await.unwrap();
        until(|| async { bob.cmd(&["admins"]).await.unwrap() }, |listed| listed["admitted"].as_array().unwrap().len() == 2).await;
        until(|| async { other.cmd(&["admins"]).await.unwrap() }, |listed| listed["admitted"].as_array().unwrap().len() == 2).await;
        let link1 = bob.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap().to_owned();
        let link2 = bob.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap().to_owned();
        alice.stop().await;
        other.stop().await;

        let (mut desk, mut carol) = (world.start_in("bob", "desk").await, world.start("carol").await);
        let (join1, join2) = (["join", link1.as_str()], ["join", link2.as_str()]);
        let (joined1, joined2) = tokio::join!(desk.cmd(&join1), carol.cmd(&join2));
        joined1.unwrap();
        joined2.unwrap();
        bob.stop().await;
        desk.stop().await;
        carol.stop().await;

        let mut alice = world.start("alice").await;
        let removed = alice.cmd(&["remove", "--device", &bobs[..8]]).await.unwrap();
        let removed: BTreeSet<&str> = removed["removed"].as_array().unwrap().iter().map(|fp| fp.as_str().unwrap()).collect();
        assert_eq!(removed, BTreeSet::from([bob.fp.as_str(), desk.fp.as_str()]));
        alice.stop().await;

        let mut other = world.start_in("alice", "other").await;
        assert_eq!(other.cmd(&["remove", &carol.fp[..8]]).await.unwrap()["removed"], json!([carol.fp]));
        let members = other.cmd(&["members", "--all"]).await.unwrap();
        let left: BTreeSet<&str> = members["members"].as_array().unwrap().iter().map(|m| m["fp"].as_str().unwrap()).collect();
        assert_eq!(left, BTreeSet::from([alice.fp.as_str(), other.fp.as_str()]));
        other.stop().await;
    });
}

/// A group's founder and its device are its admins: `members` marks them, and `admins` and `groups` list them, with the
/// admitted devices. A member that is no admin is told so as it removes, ends or changes them; it admits a session of an
/// admitted device, not of another; an admin makes it an admin, and the group keeps one.
#[test]
fn admins_and_admitted_devices_decide_who_adds_and_removes() {
    local(async {
        let world = world("admins").await;
        let (mut alice, mut bob, group) = pair(&world).await;
        let (alices, bobs) = (world.device("alice"), world.device("bob"));
        let listed = alice.cmd(&["admins"]).await.unwrap();
        assert_eq!(listed, json!({ "group": group, "admins": [{ "fp": alice.fp, "you": true }, alices], "admitted": [] }));
        let members = bob.cmd(&["members"]).await.unwrap();
        let marked: Vec<&Value> = members["members"].as_array().unwrap().iter().filter(|m| m["admin"] == true).map(|m| &m["fp"]).collect();
        assert_eq!(marked, [&json!(alice.fp)]);
        assert_eq!(bob.cmd(&["groups"]).await.unwrap()["groups"][0]["admins"], json!([alice.fp, alices["fp"]]));
        let bobs_fp = &bobs["fp"].as_str().unwrap()[..8];
        for refused in [bob.cmd(&["remove", &alice.fp]).await, bob.cmd(&["leave", "--end"]).await, bob.cmd(&["admitted", "add", bobs_fp]).await] {
            let refused = refused.unwrap_err().to_string();
            assert!(refused.contains("no admin"), "{refused}");
        }

        assert_eq!(alice.cmd(&["admitted", "add", bobs_fp]).await.unwrap()["admitted"], json!([bobs]));
        until(|| async { bob.cmd(&["admins"]).await.unwrap() }, |listed| listed["admitted"] == json!([bobs])).await;
        alice.stop().await;
        let invite = bob.cmd(&["invite", &format!("--group={group}"), "--valid", "60"]).await.unwrap();
        assert!(invite["expires"].as_str().unwrap() > crate::short::iso(lmk_proto::clock::now() + 50 * 60_000).as_str(), "{invite}");
        let link = invite["link"].as_str().unwrap();
        let refused = world.start("carol").await.cmd(&["join", link]).await.unwrap_err().to_string();
        assert!(refused.contains("neither admitted nor an admin"), "{refused}");
        let desk = world.start_in("bob", "desk").await;
        desk.cmd(&["join", link]).await.unwrap();
        assert_eq!(bob.told(&["joined"]).await["by"], "you");

        let mut alice = world.start("alice").await;
        let made = alice.cmd(&["admins", "add", &bob.fp[..8]]).await.unwrap();
        assert_eq!(made["admins"], json!([{ "fp": alice.fp, "you": true }, alices, { "fp": bob.fp }]));
        until(|| async { bob.cmd(&["admins"]).await.unwrap() }, |listed| listed["admins"].as_array().unwrap().contains(&json!({ "fp": bob.fp, "you": true }))).await;
        bob.cmd(&["remove", &desk.fp]).await.unwrap();
        let emptied = bob.cmd(&["admins", "remove", &alice.fp, alices["fp"].as_str().unwrap(), &bob.fp]).await.unwrap_err().to_string();
        assert!(emptied.contains("no admin"), "{emptied}");
        let unknown = alice.cmd(&["admitted", "remove", "ffff"]).await.unwrap_err().to_string();
        assert!(unknown.contains("no key this can take"), "{unknown}");
        alice.stop().await;
    });
}

/// An invite made with --for admits only that known member: another member of the shared group is refused without
/// warning the inviter, and the link stays usable for the member it names.
#[test]
fn an_invite_for_a_member_admits_only_that_member() {
    local(async {
        let world = world("for").await;
        let (mut alice, bob, group) = pair(&world).await;
        let carol = world.start("carol").await;
        carol.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        alice.told(&["joined"]).await;

        assert!(alice.cmd(&["invite", "--for", "nope"]).await.unwrap_err().to_string().contains("no known member"));
        assert!(alice.cmd(&["invite", "--group", &group, "--for", &bob.fp[..8]]).await.unwrap_err().to_string().contains("is a member of"));
        assert_eq!(alice.cmd(&["groups"]).await.unwrap()["groups"].as_array().unwrap().len(), 1, "a failed invite creates no group");

        let breakout = alice.cmd(&["invite", "--for", &bob.fp[..8]]).await.unwrap();
        assert_eq!(breakout["for"], bob.fp);
        let link = breakout["link"].as_str().unwrap();
        let refused = carol.cmd(&["join", link]).await.unwrap_err().to_string();
        assert!(refused.contains("for another member"), "{refused}");
        assert!(alice.printed().await.iter().all(|e| e["type"] != "warning"));

        let joined = bob.cmd(&["join", link]).await.unwrap();
        assert_eq!(joined["group"], breakout["group"]);
        assert_eq!(alice.told(&["joined"]).await["member"], bob.fp);
    });
}


/// A reader `attach` makes of the session `agent`: what it prints, and its task.
fn attached(agent: &Agent) -> (mpsc::UnboundedReceiver<Value>, tokio::task::JoinHandle<Result<()>>) {
    let (out, printed) = mpsc::unbounded_channel();
    let (home, name) = (agent.home.clone(), agent.name.clone());
    let reading = tokio::task::spawn_local(async move {
        crate::cli::attach(&home, &name, |line| {
            drop(out.send(serde_json::from_str(&line).unwrap()));
            Ok(())
        })
        .await
    });
    (printed, reading)
}

async fn read(printed: &mut mpsc::UnboundedReceiver<Value>) -> Value {
    tokio::time::timeout(WAIT, printed.recv()).await.expect("a line").expect("the reader runs")
}

/// A detached session prints only `ready`, and holds what concerns it for the reader that attaches, one at a time: the
/// reader gets `ready`, what waited, and what comes, and follows the session as it runs again. What is held goes as its
/// line in the log goes.
#[test]
fn a_detached_session_holds_what_concerns_it_for_one_reader_at_a_time() {
    local(async {
        let world = world("detached").await;
        let (mut alice, bob, _) = pair(&world).await;
        let detached = || Config { detached: true, ..world.config("alice", "alice") };
        alice.stop().await;
        let mut alice = world.launch(detached(), usize::MAX).await;
        bob.cmd(&["send", "--to", &alice.fp, "one"]).await.unwrap();
        assert_eq!(alice.told(&["message"]).await["content"], "one");
        assert!(alice.printed().await.is_empty(), "only `ready` prints");
        let refused = crate::cli::attach(&bob.home, &bob.name, |_| Ok(())).await.unwrap_err().to_string();
        assert!(refused.contains("prints to the program that started it"), "{refused}");

        let (mut printed, reading) = attached(&alice);
        let ready = read(&mut printed).await;
        assert_eq!((ready["type"].as_str(), ready["fp"].as_str()), (Some("ready"), Some(alice.fp.as_str())));
        assert_eq!(read(&mut printed).await["content"], "one", "what waited for a reader");
        let refused = crate::cli::attach(&alice.home, &alice.name, |_| Ok(())).await.unwrap_err().to_string();
        assert!(refused.contains("has a reader attached already"), "{refused}");
        bob.cmd(&["send", "--to", &alice.fp, "two"]).await.unwrap();
        assert_eq!(read(&mut printed).await["content"], "two");

        alice.stop().await;
        let mut alice = world.launch(detached(), usize::MAX).await;
        assert_eq!(read(&mut printed).await["type"], "ready", "the reader follows the session as it runs again");
        bob.cmd(&["send", "--to", &alice.fp, "three"]).await.unwrap();
        assert_eq!(read(&mut printed).await["content"], "three");

        // With no reader, a line is held; the lines of a group the session is no longer in go, but its `removed`.
        reading.abort();
        alice.stop().await;
        let mut alice = world.launch(detached(), usize::MAX).await;
        bob.cmd(&["send", "--to", &alice.fp, "four"]).await.unwrap();
        until(|| async { json!(alice.log().iter().any(|line| line.contains("four"))) }, |logged| *logged == json!(true)).await;
        // Bob, no admin, removes Alice by the leave her `leave` carries.
        alice.cmd(&["leave"]).await.unwrap();
        alice.told(&["removed"]).await;
        let (mut printed, _reading) = attached(&alice);
        assert_eq!(read(&mut printed).await["type"], "ready");
        assert_eq!(read(&mut printed).await["type"], "removed");
    });
}

#[test]
fn a_detached_message_is_not_shown_before_its_wakeup_is_held() {
    local(async {
        let world = world("hold-before-shown").await;
        let (mut alice, bob, _) = pair(&world).await;
        alice.stop().await;
        let detached = || Config { detached: true, ..world.config("alice", "alice") };
        let db = crate::store::open(&detached().dir.join("session.db")).unwrap();
        let (mut session, mut events) = world.open_session(detached()).await;
        db.execute_batch("CREATE TRIGGER no_hold BEFORE INSERT ON held BEGIN SELECT RAISE(FAIL, 'holding failed'); END").unwrap();
        bob.cmd(&["send", "--to", &alice.fp, "wake me"]).await.unwrap();
        loop {
            let event = tokio::time::timeout(WAIT, events.recv()).await.unwrap().unwrap();
            let message = matches!(&event, lmk_node::Event::Message(_));
            session.event(event);
            if message {
                break;
            }
        }
        assert!(session.emit(&mut |_| Ok(())).is_err());
        session.shutdown().await;
        drop(session);
        db.execute_batch("DROP TRIGGER no_hold").unwrap();

        let (mut session, _events) = world.open_session(detached()).await;
        session.emit(&mut |_| Ok(())).unwrap();
        let held: Vec<String> = db.prepare("SELECT line FROM held").unwrap().query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert!(held.iter().any(|line| serde_json::from_str::<Value>(line).unwrap()["content"] == "wake me"), "the unshown message is held after restarting: {held:?}");
        session.shutdown().await;
    });
}

#[test]
fn a_detached_session_keeps_lines_queued_for_a_reader_that_goes_away() {
    local(async {
        let world = world("queued-reader").await;
        let (mut alice, bob, _) = pair(&world).await;
        alice.stop().await;
        let config = Config { detached: true, ..world.config("alice", "alice") };
        let mut alice = world.launch(config, usize::MAX).await;
        bob.cmd(&["send", "--to", &alice.fp, "wake me"]).await.unwrap();
        alice.told(&["message"]).await;
        alice.stop().await;
        let (mut session, _events) = world.open_session(Config { detached: true, ..world.config("alice", "alice") }).await;
        let db = crate::store::open(&world.config("alice", "alice").dir.join("session.db")).unwrap();
        let (reader, queued) = mpsc::unbounded_channel();
        session.handle(crate::session::Inbound::Attach(reader));
        drop(queued);
        assert_eq!(db.query_row("SELECT count(*) FROM held", [], |row| row.get::<_, i64>(0)).unwrap(), 1, "queuing is not writing");
        let (reader, mut queued) = mpsc::unbounded_channel();
        session.handle(crate::session::Inbound::Attach(reader));
        assert!(queued.try_recv().is_ok(), "ready");
        let (seq, line) = queued.try_recv().expect("the next reader gets the unwritten line");
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["content"], "wake me");
        session.handle(crate::session::Inbound::Written(seq.unwrap()));
        assert_eq!(db.query_row("SELECT count(*) FROM held", [], |row| row.get::<_, i64>(0)).unwrap(), 0, "writing releases the line");
        session.shutdown().await;
    });
}

#[test]
fn a_detached_readers_late_acknowledgment_does_not_release_a_newer_line() {
    local(async {
        let world = world("late-reader-ack").await;
        let (mut alice, bob, _) = pair(&world).await;
        alice.stop().await;
        let config = Config { detached: true, ..world.config("alice", "alice") };
        let (mut session, mut events) = world.open_session(config).await;
        let db = crate::store::open(&world.config("alice", "alice").dir.join("session.db")).unwrap();
        let (reader, mut queued) = mpsc::unbounded_channel();
        session.handle(crate::session::Inbound::Attach(reader));
        assert_eq!(queued.try_recv().unwrap().0, None, "ready has no held line");
        let mut seqs = Vec::new();
        for text in ["old", "new"] {
            bob.cmd(&["send", "--to", &alice.fp, text]).await.unwrap();
            loop {
                let event = tokio::time::timeout(WAIT, events.recv()).await.unwrap().unwrap();
                let message = matches!(&event, lmk_node::Event::Message(_));
                session.event(event);
                if message {
                    break;
                }
            }
            session.emit(&mut |_| Ok(())).unwrap();
            let (seq, line) = queued.try_recv().unwrap();
            assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["content"], text);
            seqs.push(seq.unwrap());
            assert_eq!(db.query_row("SELECT count(*) FROM held", [], |row| row.get::<_, i64>(0)).unwrap(), 1, "live lines are held until written too");
            if text == "old" {
                db.execute("DELETE FROM held", []).unwrap();
            }
        }
        session.handle(crate::session::Inbound::Written(seqs[0]));
        assert_eq!(db.query_row("SELECT count(*) FROM held", [], |row| row.get::<_, i64>(0)).unwrap(), 1, "a pruned line's acknowledgment cannot release its successor");
        session.handle(crate::session::Inbound::Written(seqs[1]));
        assert_eq!(db.query_row("SELECT count(*) FROM held", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        session.shutdown().await;
    });
}

/// A log whose last line was cut short, as when the disk filled while it was written, loses that line as the session next
/// starts, and no other.
#[test]
fn a_log_cut_short_loses_its_last_line_as_the_session_starts() {
    local(async {
        let world = world("cut").await;
        let (mut alice, _bob, _) = pair(&world).await;
        alice.stop().await;
        let whole = alice.log();
        let log = session_dir(&alice.home, &alice.name).unwrap().join("log.jsonl");
        std::io::Write::write_all(&mut std::fs::OpenOptions::new().append(true).open(log).unwrap(), br#"{"type":"message","con"#).unwrap();
        let alice = world.start("alice").await;
        assert_eq!(alice.log(), whole);
    });
}

/// An attachment whose name is as long as a file's may be is saved under the end of its name.
#[test]
fn an_attachment_with_a_long_name_is_saved_under_the_end_of_it() {
    local(async {
        let world = world("name").await;
        let (mut alice, bob, _) = pair(&world).await;
        let name = format!("{}.txt", "a".repeat(250));
        let file = world.root.path().join(&name);
        std::fs::write(&file, "s3cret").unwrap();
        bob.cmd(&["send", "--to", &alice.fp, "--attach", file.to_str().unwrap(), "the token"]).await.unwrap();
        let message = alice.expect("message").await;
        assert_eq!(message["attachment"]["name"], name);
        let path = Path::new(message["attachment"]["path"].as_str().unwrap());
        assert!(path.to_str().unwrap().ends_with("aaa.txt"), "{path:?}");
        assert_eq!(std::fs::read_to_string(path).unwrap(), "s3cret");
    });
}

/// A payload is its sender's: of a chat message whose `to` and `attachment` are shaped as none are, the session shows
/// the rest, and starts again.
#[test]
fn a_chat_message_with_a_malformed_to_and_attachment_shows_without_them() {
    local(async {
        let world = world("shape").await;
        let mut alice = world.start("alice").await;
        let invite = alice.cmd(&["invite"]).await.unwrap();
        let device = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let config = lmk_node::Config { home: world.domain.clone(), post: world.network.post.clone(), ca: world.network.ca.clone(), device };
        let (mallory, _events) = lmk_node::Node::start(lmk_core::provider::SqliteProvider::open(":memory:".as_ref()).unwrap(), config).await.unwrap();
        let (gid, _) = mallory.join(&lmk_proto::links::Invite::parse(invite["link"].as_str().unwrap()).unwrap()).await.unwrap();
        mallory.send(&gid.0, &json!({ "type": "message", "content": "hi", "to": "all", "attachment": { "name": 7 } }), None).await.unwrap();
        let message = alice.told(&["message"]).await;
        assert_eq!((message["content"].as_str(), message.get("to"), message.get("attachment")), (Some("hi"), None, None));
        alice.stop().await;
        world.start("alice").await;
        mallory.shutdown().await.unwrap();
    });
}

/// A long message prints with the beginning of its content, marked `truncated`; its line in the log is whole.
#[test]
fn a_long_message_prints_cut_and_is_logged_whole() {
    local(async {
        let world = world("long").await;
        let (mut alice, bob, _) = pair(&world).await;
        let text = "中".repeat(crate::short::CONTENT);
        bob.cmd(&["send", "--to", &alice.fp, &text]).await.unwrap();
        let printed = alice.expect("message").await;
        assert_eq!((printed["content"].as_str().unwrap(), &printed["truncated"]), (&text[..text.floor_char_boundary(crate::short::CONTENT)], &json!(true)));
        let logged = alice.told(&["message"]).await;
        assert_eq!((logged["content"].as_str(), logged.get("truncated")), (Some(text.as_str()), None));
    });
}
