//! Session processes in one test process, each in a home of its own (sessions may share one), living on the relay of a
//! local membership service with a self-signed certificate, which keeps their logs. The CLI talks to them over their
//! command channels.

use anyhow::Result;
use lmk_proto::directory::Directory;
use lmk_serve::{Certificate, ServeConfig};
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

const HOUR: Duration = Duration::from_secs(3600);
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

/// A port free for TCP and UDP, below the ephemeral range: a port `bind(0)` returned could be taken by another test's relay
/// or endpoint before the service binds it. No two tests of this process get the same one, though both could find it free.
fn free_port() -> u16 {
    static TAKEN: std::sync::Mutex<BTreeSet<u16>> = std::sync::Mutex::new(BTreeSet::new());
    loop {
        let port = rand::random_range(1024..32768);
        if TAKEN.lock().unwrap().insert(port) && std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() && std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
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
    handle: String,
    home: PathBuf,
    fp: String,
    events: mpsc::UnboundedReceiver<String>,
    stop: Option<oneshot::Sender<()>>,
    done: Option<tokio::task::JoinHandle<()>>,
    ready: Value,
}

impl World {
    /// A session process in a home of its own.
    async fn start(&self, handle: &str, hold: Duration) -> Agent {
        self.start_in(handle, handle, hold).await
    }

    /// A session process in the home `home`.
    async fn start_in(&self, home: &str, handle: &str, hold: Duration) -> Agent {
        self.launch(Config { hold, ..self.config(home, handle) }, usize::MAX).await
    }

    /// A session's configuration, in the home `home`.
    fn config(&self, home: &str, handle: &str) -> Config {
        Config {
            handle: handle.into(),
            dir: session_dir(&self.root.path().join(home), handle).unwrap(),
            hold: HOUR,
            membership: self.domain.clone(),
        }
    }

    /// A session process; writing the message after its first `messages` fails, as when its reader is gone.
    async fn launch(&self, config: Config, messages: usize) -> Agent {
        let home = config.dir.parent().unwrap().parent().unwrap().to_path_buf();
        let handle = config.handle.clone();
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
        let mut agent = Agent { handle, home, fp: String::new(), events, stop: Some(stop), done: Some(done), ready: Value::Null };
        let ready = agent.expect("ready").await;
        assert!(keys(&ready).is_superset(&keys(&json!({ "type": 0, "handle": 0, "fp": 0, "bin": 0, "membership": 0 }))), "{ready}");
        agent.fp = ready["fp"].as_str().unwrap().into();
        agent.ready = ready;
        agent
    }
}

impl Agent {
    async fn cmd(&self, args: &[&str]) -> Result<Value> {
        let home = self.home.to_str().unwrap();
        let base = ["letmeknow", "--home", home, "--session", self.handle.as_str()];
        let cli = crate::cli::parse(base.iter().chain(args))?;
        let Command::Request(request) = cli.command else { panic!("not a request") };
        crate::cli::call(&self.home, &self.handle, request).await
    }

    /// The next event of `kind`, skipping others.
    async fn expect(&mut self, kind: &str) -> Value {
        self.expect_any(&[kind]).await
    }

    /// The next event of any of `kinds`, which wait, as membership changes do, until the agent's next command: it runs
    /// `status` until one prints, skipping other events.
    async fn told(&mut self, kinds: &[&str]) -> Value {
        let start = std::time::Instant::now();
        loop {
            // Once removed from its last group, the session has no status to give, but still prints what it was told.
            let _ = self.cmd(&["status"]).await;
            while let Ok(line) = tokio::time::timeout(Duration::from_millis(200), self.events.recv()).await {
                let event: Value = serde_json::from_str(&line.unwrap()).unwrap();
                if kinds.iter().any(|kind| event["type"] == *kind) {
                    return event;
                }
            }
            assert!(start.elapsed() < WAIT, "{}: no {kinds:?} event", self.handle);
        }
    }

    /// The next event of any of `kinds`, skipping others.
    async fn expect_any(&mut self, kinds: &[&str]) -> Value {
        loop {
            let Ok(line) = tokio::time::timeout(WAIT, self.events.recv()).await else {
                panic!("{}: no {kinds:?} event; status: {:?}", self.handle, self.cmd(&["status"]).await);
            };
            let line = line.unwrap();
            let event: Value = serde_json::from_str(&line).unwrap();
            if kinds.iter().any(|kind| event["type"] == *kind) {
                return event;
            }
            eprintln!("{}: {event}", self.handle);
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
async fn pair(world: &World, hold: Duration) -> (Agent, Agent, String) {
    let mut alice = world.start("alice", hold).await;
    let bob = world.start("bob", hold).await;
    let invite = alice.cmd(&["invite"]).await.unwrap();
    assert_eq!(keys(&invite), keys(&json!({ "link": 0, "group": 0, "expires": 0, "via": 0 })));
    assert_eq!(invite["via"], json!(["you"]));
    let link = invite["link"].as_str().unwrap();
    assert!(link.starts_with("https://letmeknow.dev/i#12."));
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
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        let sent = bob.cmd(&["send", "the build is green"]).await.unwrap();
        assert!(sent["id"].is_string() && sent.get("pos").is_none(), "{sent}");
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message"));
        bob.cmd(&["send", "--to", &alice.fp, "can you deploy?"]).await.unwrap();
        let first = alice.expect("message").await;
        let second = alice.expect("message").await;
        assert_eq!((first["content"].as_str(), first.get("to")), (Some("the build is green"), None));
        assert_eq!((second["content"].as_str(), &second["to"]), (Some("can you deploy?"), &json!(["you"])));
        assert_eq!(keys(&second), keys(&json!({ "type": 0, "group": 0, "id": 0, "seq": 0, "from": 0, "to": 0, "content": 0, "sent_at": 0 })));
        assert_eq!(second["seq"].as_u64(), first["seq"].as_u64().map(|s| s + 1), "in order");
        assert_eq!((second["group"].as_str(), second["id"].as_str().unwrap().len()), (Some(group.as_str()), crate::short::ID));
        assert_eq!(second["from"], bob.fp);
        // A reply to Bob wakes him.
        let id = second["id"].as_str().unwrap();
        alice.cmd(&["send", "--reply-to", id, "on it"]).await.unwrap();
        let reply = bob.expect("message").await;
        assert_eq!(reply["reply_to"], id);
        // Shown text is forgotten.
        let read = alice.cmd(&["read", id]).await.unwrap();
        assert_eq!((&read["content"], &read["shown"]), (&Value::Null, &json!(true)));
    });
}

#[test]
fn held_messages_print_once_the_hold_runs_out() {
    local(async {
        let world = world("hold").await;
        let hold = Duration::from_secs(2);
        let (mut alice, bob, _) = pair(&world, hold).await;
        // A command of Alice's prints what she holds, so that her hold starts at Bob's message.
        alice.cmd(&["status"]).await.unwrap();
        let sending = std::time::Instant::now();
        bob.cmd(&["send", "fyi"]).await.unwrap();
        assert_eq!(alice.expect("message").await["content"], "fyi");
        assert!(sending.elapsed() >= hold, "printed after {:?}", sending.elapsed());
    });
}

#[test]
fn send_answers_its_id_and_refuses_a_message_too_large() {
    local(async {
        let world = world("pending").await;
        let (alice, mut bob, _) = pair(&world, HOUR).await;
        let big = "x".repeat(16 << 20);
        let refused = alice.cmd(&["send", "--to", &bob.fp, &big]).await.unwrap_err().to_string();
        assert!(refused.contains("members take"), "{refused}");
        let stopping = lmk_node::now();
        bob.stop().await;
        let before = lmk_node::now();
        let sent = alice.cmd(&["send", "--urgent", "anyone?"]).await.unwrap();
        assert!(sent["id"].is_string() && sent.get("pos").is_none(), "{sent}");
        // Alice finds out that Bob's connection closed once his close reaches her: he was online until then.
        let offline = |members: &Value| members["offline"] == 1;
        let members = until(|| async { alice.cmd(&["members"]).await.unwrap() }, offline).await;
        assert!(offline(&members), "{members}");
        let all = alice.cmd(&["members", "--all"]).await.unwrap();
        let last_seen = all["members"].as_array().unwrap().iter().find(|m| m["fp"] == bob.fp).unwrap()["last_seen"].clone();
        assert!(last_seen.as_str().is_some_and(|at| crate::short::iso(stopping).as_str() <= at), "{all}");
        // Once Bob is back, he takes it.
        let mut bob = world.start("bob", HOUR).await;
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
        let (mut alice, bob, _) = pair(&world, HOUR).await;
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
        let id = sent["id"].as_str().unwrap();
        assert_eq!(alice.cmd(&["read", id]).await.unwrap()["attachment"], message["attachment"]);
        assert_eq!(bob.cmd(&["read", id]).await.unwrap()["attachment"], json!({ "name": "token.txt" }), "the sender's own is not saved");
    });
}

#[test]
fn membership_changes_are_told_and_a_removed_session_learns_it() {
    local(async {
        let world = world("remove").await;
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        let members = bob.cmd(&["members", "--all", "--group", &group[..6]]).await.unwrap();
        assert_eq!(members["members"][0]["fp"], alice.fp);
        assert_eq!(members["members"][1], json!({ "fp": bob.fp, "you": true }));
        let other = alice.cmd(&["invite"]).await.unwrap()["group"].as_str().unwrap().to_owned();
        assert_eq!(alice.cmd(&["status"]).await.unwrap()["groups"].as_array().unwrap().len(), 2);
        let status = alice.cmd(&["status", &format!("--group={}", &group[..8])]).await.unwrap();
        assert_eq!(status["groups"].as_array().unwrap().iter().map(|g| &g["group"]).collect::<Vec<_>>(), [group.as_str()]);
        assert!(alice.cmd(&["status", "--group", "nope"]).await.unwrap_err().to_string().contains("unknown group nope"));
        alice.cmd(&["leave", &format!("--group={}", &other[..8])]).await.unwrap();
        assert!(alice.cmd(&["remove", "Carol"]).await.is_err());
        alice.cmd(&["remove", &bob.fp[..8]]).await.unwrap();
        assert_eq!(alice.told(&["left"]).await["member"], bob.fp);
        let removed = bob.told(&["removed"]).await;
        assert_eq!((&removed["group"], &removed["by"]), (&json!(group), &json!(alice.fp)));
        assert_eq!(bob.cmd(&["groups"]).await.unwrap(), json!({}), "no groups");
    });
}

/// The files of a session's database that hold `secret`. The `-shm` file holds only the WAL's index, and Windows locks
/// parts of it.
fn holding(dir: &Path, secret: &str) -> Vec<PathBuf> {
    let files = ["session.db", "session.db-wal"].map(|name| dir.join(name));
    files.into_iter().filter(|path| std::fs::read(path).unwrap_or_default().windows(secret.len()).any(|w| w == secret.as_bytes())).collect()
}

#[test]
fn text_shown_or_left_behind_stays_in_no_file() {
    local(async {
        let world = world("scrub").await;
        let (mut alice, mut bob, _) = pair(&world, HOUR).await;
        let secret = "the vault code is 7-tangerine-42";
        bob.cmd(&["send", "--to", &alice.fp, secret]).await.unwrap();
        assert_eq!(alice.expect("message").await["content"].as_str().unwrap(), secret);
        alice.cmd(&["status"]).await.unwrap();
        assert_eq!(holding(&session_dir(&alice.home, "alice").unwrap(), secret), Vec::<PathBuf>::new());
        alice.cmd(&["remove", &bob.fp]).await.unwrap();
        bob.told(&["removed"]).await;
        assert_eq!(holding(&session_dir(&bob.home, "bob").unwrap(), secret), Vec::<PathBuf>::new());
    });
}

#[test]
fn a_leaving_member_is_removed_by_another() {
    local(async {
        let world = world("leave").await;
        let (mut alice, mut bob, _) = pair(&world, HOUR).await;
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
        let (mut alice, bob, _) = pair(&world, HOUR).await;
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
        let alice = world.start("alice", HOUR).await;
        alice.cmd(&["status"]).await.unwrap();
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
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        alice.cmd(&["send", "hello"]).await.unwrap();
        // Bob takes it, and the invite before it: once his summary tells Alice, her next commit keeps both.
        bob.told(&["message"]).await;
        until(|| async { alice.cmd(&["status"]).await.unwrap() }, |status| status["groups"][0]["only_here"].is_null()).await;
        add_and_remove(&world, &mut alice, &group).await;
        bob.stop().await;
        let sent = alice.cmd(&["send", "anyone?"]).await.unwrap();
        let status = alice.cmd(&["status"]).await.unwrap();
        assert_eq!(status["groups"][0]["only_here"], json!([{ "what": "message", "id": sent["id"] }]));
        let _bob = world.start("bob", HOUR).await;
        let status = until(|| async { alice.cmd(&["status"]).await.unwrap() }, |status| status["groups"][0]["only_here"].is_null()).await;
        assert!(status["groups"][0]["only_here"].is_null(), "Bob holds it: {status}");
    });
}

#[test]
fn a_leave_is_pending_until_another_member_removes_the_session() {
    local(async {
        let world = world("leave-pending").await;
        let (mut alice, mut bob, _) = pair(&world, HOUR).await;
        alice.stop().await;
        let left = bob.cmd(&["leave"]).await.unwrap();
        assert_eq!(left, json!({ "group": left["group"], "pending": true }));
        let _alice = world.start("alice", HOUR).await;
        assert_eq!(bob.told(&["removed"]).await["type"], "removed");
    });
}

/// Alice adds a session to the group and removes it again: two commits, after which the members are as they were.
async fn add_and_remove(world: &World, alice: &mut Agent, group: &str) {
    let mut carol = world.start("carol", HOUR).await;
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
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        bob.stop().await;
        alice.cmd(&["send", "while you were out"]).await.unwrap();
        add_and_remove(&world, &mut alice, &group).await;
        alice.stop().await;
        let mut bob = world.start("bob", HOUR).await;
        let _alice = world.start("alice", HOUR).await;
        // Unless it comes while Bob catches up, the message, which does not wake him, waits for his next command.
        assert_eq!(bob.told(&["message"]).await["content"], "while you were out");
        assert!(bob.printed().await.iter().all(|e| e["type"] != "lost"));
    });
}

#[test]
fn the_command_channel_needs_its_token_and_a_running_session() {
    local(async {
        let world = world("channel").await;
        let alice = world.start("alice", HOUR).await;
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
        let missing = Agent { handle: "nobody".into(), home: alice.home.clone(), fp: String::new(), events: mpsc::unbounded_channel().1, stop: None, done: None, ready: Value::Null };
        let error = missing.cmd(&["groups"]).await.unwrap_err().to_string();
        assert!(error.contains("not running"), "{error}");
    });
}

#[test]
fn a_restarted_session_takes_in_what_it_missed_in_delivery_order() {
    local(async {
        let world = world("causal").await;
        let (mut alice, bob, group) = pair(&world, HOUR).await;
        alice.stop().await;
        let first = bob.cmd(&["send", "--urgent", "first"]).await.unwrap();
        assert!(first["id"].is_string(), "{first}");
        let second = bob.cmd(&["send", "--urgent", "second"]).await.unwrap();
        let mut alice = world.start("alice", HOUR).await;
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
        let (alice, mut bob, _) = pair(&world, HOUR).await;
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
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        let mut carol = world.start("carol", HOUR).await;
        carol.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        bob.told(&["joined"]).await;
        alice.stop().await;
        carol.stop().await;
        bob.cmd(&["send", "while they are away"]).await.unwrap();
        bob.stop().await;
        let alice = world.start("alice", HOUR).await;
        let mut carol = world.start("carol", HOUR).await;
        alice.cmd(&["send", "--to", &carol.fp, "after the gap"]).await.unwrap();
        let got = carol.expect("message").await;
        assert_eq!(got["content"], "after the gap");
        assert!(got.get("missing").is_none(), "{got}");
    });
}

/// A session whose reader is gone stops at the first line it cannot write; started again, it prints the messages after
/// the last it printed, once.
#[test]
fn a_session_stops_once_it_cannot_print_and_prints_the_rest_when_started_again() {
    local(async {
        let world = world("output").await;
        let (mut alice, bob, _) = pair(&world, HOUR).await;
        alice.stop().await;
        let mut sent = Vec::new();
        // Fewer than catching up prints, so none is omitted, however long catching up takes.
        for i in 0..10 {
            sent.push(bob.cmd(&["send", "--urgent", &format!("m{i}")]).await.unwrap()["id"].clone());
        }
        let mut alice = world.launch(world.config("alice", "alice"), 1).await;
        assert_eq!(alice.expect("message").await["id"], sent[0]);
        tokio::time::timeout(Duration::from_secs(30), alice.done.take().unwrap()).await.unwrap().unwrap();
        let mut alice = world.start("alice", HOUR).await;
        for id in &sent[1..] {
            assert_eq!(alice.expect("message").await["id"], *id);
        }
        alice.stop().await;
        let mut alice = world.start("alice", HOUR).await;
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message" && e["type"] != "omitted"));
    });
}

/// `sessions` lists this machine's sessions, each with its fingerprint, its group ids and whether it runs. One that
/// stopped in no group is gone.
#[test]
fn sessions_lists_this_machines_sessions_running_or_stopped() {
    local(async {
        let world = world("sessions").await;
        let (alice, mut bob, group) = pair(&world, HOUR).await;
        world.start_in("bob", "lone", HOUR).await.stop().await;
        let mut desk = world.start_in("bob", "desk", HOUR).await;
        let invite = alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap();
        desk.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        let desk_fp = desk.fp.clone();
        let listed = |desk: bool| {
            let mut listed = json!({ "sessions": [
                { "handle": "bob", "fp": bob.fp, "running": true, "groups": [group] },
                { "handle": "desk", "fp": desk_fp, "groups": [group] },
            ] });
            if desk {
                listed["sessions"][1]["running"] = json!(true);
            }
            listed
        };
        let running = until(|| async { crate::sessions(&bob.home).await.unwrap() }, |running| *running == listed(true)).await;
        assert_eq!(running, listed(true));
        desk.stop().await;
        assert_eq!(crate::sessions(&bob.home).await.unwrap(), listed(false));
        bob.stop().await;
    });
}

/// One process runs a session: another `listen` of it fails, also one that does not find its command channel, as when
/// both start at once.
#[test]
fn a_session_runs_in_one_process() {
    local(async {
        let world = world("one-process").await;
        let alice = world.start("alice", HOUR).await;
        std::fs::remove_file(world.config("alice", "alice").dir.join("endpoint")).unwrap();
        let again = crate::listen(world.config("alice", "alice"), &alice.home, world.network.clone(), |_| Ok(()), std::future::pending());
        let error = tokio::time::timeout(Duration::from_secs(10), again).await.expect("it fails at once").unwrap_err();
        assert_eq!(error.to_string(), "session alice is already running");
    });
}

/// A join that waits on a member who never answers holds up none of the session's other work.
#[test]
fn a_session_goes_on_while_a_join_waits() {
    local(async {
        let world = world("busy").await;
        let (alice, mut bob, group) = pair(&world, HOUR).await;
        let link = alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap().to_owned();
        let mut invite = lmk_proto::links::Invite::parse(&link).unwrap();
        invite.members[0].0 = *iroh::SecretKey::generate().public().as_bytes();
        let (home, handle) = (bob.home.clone(), bob.handle.clone());
        let join = Request::Join { target: invite.link() };
        let joining = tokio::task::spawn_local(async move { crate::cli::call(&home, &handle, join).await });
        tokio::time::sleep(Duration::from_millis(500)).await;
        let started = std::time::Instant::now();
        bob.cmd(&["status"]).await.unwrap();
        alice.cmd(&["send", "--to", &bob.fp, "still there?"]).await.unwrap();
        assert_eq!(bob.expect("message").await["content"], "still there?");
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(!joining.is_finished(), "the join still waits");
    });
}

/// A restarted session prints what was delivered after the last message it showed, and not what came before it.
#[test]
fn a_restarted_session_prints_what_came_after_the_last_it_showed() {
    local(async {
        let world = world("reprint").await;
        let (mut alice, bob, _) = pair(&world, HOUR).await;
        bob.cmd(&["send", "before"]).await.unwrap();
        bob.cmd(&["send", "--to", &alice.fp, "to alice"]).await.unwrap();
        assert_eq!(alice.expect("message").await["content"], "before");
        assert_eq!(alice.expect("message").await["content"], "to alice");
        bob.cmd(&["send", "after one"]).await.unwrap();
        bob.cmd(&["send", "after two"]).await.unwrap();
        // Alice holds both, as Bob's status shows, and, unaddressed, prints neither.
        let status = until(|| async { bob.cmd(&["status"]).await.unwrap() }, |status| status["groups"][0]["only_here"].is_null()).await;
        assert!(status["groups"][0]["only_here"].is_null(), "{status}");
        alice.stop().await;
        let mut alice = world.start("alice", HOUR).await;
        assert_eq!(alice.expect("message").await["content"], "after one");
        assert_eq!(alice.expect("message").await["content"], "after two");
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message"));
    });
}

/// A home another release wrote is refused and left as it is.
#[test]
fn a_home_of_another_format_is_refused() {
    local(async {
        let world = world("format").await;
        for (format, names) in [("11", "an earlier letmeknow"), ("13", "a newer letmeknow")] {
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

/// A group on a home's auto list is joined by each new session of the home as it starts: through a running session of
/// the home in it, or else through a stopped one, whose node alone runs meanwhile, past one the group removed while it
/// was stopped. A group no session of the home is in leaves the list, and the home's stopped sessions in no group go.
#[test]
fn a_new_session_joins_the_auto_groups_of_its_home() {
    local(async {
        let world = world("auto").await;
        let home = world.root.path().join("h");
        let mut alice = world.start_in("h", "alice", HOUR).await;
        let group = alice.cmd(&["invite"]).await.unwrap()["group"].as_str().unwrap().to_owned();
        let added = crate::change_auto(&home, false, Some(crate::cli::Auto::Add { group: group[..6].into() })).unwrap();
        assert_eq!(added, json!({ "auto": [group] }));
        assert!(crate::change_auto(&home, false, Some(crate::cli::Auto::Add { group: "nope".into() })).unwrap_err().to_string().contains("no session of this home is in nope"));

        let bob = world.start_in("h", "bob", HOUR).await;
        let joined = alice.told(&["joined"]).await;
        assert_eq!(joined["member"], json!(bob.fp));
        assert_eq!(bob.cmd(&["groups"]).await.unwrap()["groups"][0]["group"], json!(group));

        let mut bob = bob;
        alice.stop().await;
        bob.cmd(&["remove", &alice.fp]).await.unwrap();
        bob.stop().await;
        let carol = world.start_in("h", "carol", HOUR).await;
        let members = async {
            loop {
                if let Ok(members) = carol.cmd(&["members", "--all"]).await {
                    return members;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        let members = tokio::time::timeout(WAIT, members).await.expect("Carol joins through a stopped session");
        assert_eq!(members["members"].as_array().unwrap().len(), 2);

        // Once no session of the home is in it, the next session drops it from the list.
        let mut carol = carol;
        carol.cmd(&["leave", "--end"]).await.unwrap();
        carol.stop().await;
        for gone in ["alice", "bob"] {
            std::fs::write(session_dir(&home, gone).unwrap().join("groups.json"), "[]").unwrap();
        }
        let mut dave = world.start_in("h", "dave", HOUR).await;
        let warning = dave.expect("warning").await;
        assert!(warning["text"].as_str().unwrap().contains("leaves the list"), "{warning}");
        for gone in ["alice", "bob"] {
            assert!(!session_dir(&home, gone).unwrap().exists(), "{gone}, stopped in no group, is deleted as Dave starts");
        }
        assert_eq!(crate::change_auto(&home, false, None).unwrap(), json!({ "auto": [] }));
    });
}

/// A stopped session of the home that the group moved past while it was stopped catches up with the group before it
/// invites a new session, however longer than a send waits its reading takes.
#[test]
fn a_new_session_joins_an_auto_group_through_a_stopped_one_the_group_moved_past() {
    local(async {
        let mut world = world("auto-behind").await;
        let home = world.root.path().join("h");
        let mut alice = world.start_in("h", "alice", HOUR).await;
        let invite = alice.cmd(&["invite"]).await.unwrap();
        let group = invite["group"].as_str().unwrap().to_owned();
        crate::change_auto(&home, false, Some(crate::cli::Auto::Add { group: group.clone() })).unwrap();
        let bob = world.start("bob", HOUR).await;
        bob.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        let mut carol = world.start("carol", HOUR).await;
        carol.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        alice.stop().await;
        bob.cmd(&["remove", &carol.fp]).await.unwrap();
        carol.stop().await;

        let fast = world.network.post.clone();
        world.network.post = Arc::new(move |domain: String, route: &'static str, body: Vec<u8>| -> BoxFuture<Result<Vec<u8>>> {
            let answer = fast(domain, route, body);
            Box::pin(async move {
                if route == "/membership/5/read" {
                    tokio::time::sleep(Duration::from_secs(6)).await;
                }
                answer.await
            })
        });
        let dave = world.start_in("h", "dave", HOUR).await;
        let members = async {
            loop {
                if let Ok(members) = dave.cmd(&["members", "--all"]).await {
                    return members;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        let members = tokio::time::timeout(2 * WAIT, members).await.expect("Dave joins through Alice, stopped");
        assert_eq!(members["members"].as_array().unwrap().len(), 3);
    });
}

/// One session of a home at a time represents it in a group of its autorep list: the first to start, and as that one
/// stops, one of those running then. It joins the group through a session of the home in it, and removes the home's
/// stopped sessions from it. A group added to one list leaves the other.
#[test]
fn one_session_of_a_home_at_a_time_represents_it_in_an_autorep_group() {
    local(async {
        let world = world("autorep").await;
        let home = world.root.path().join("h");
        let mut alice = world.start_in("h", "alice", HOUR).await;
        let invite = alice.cmd(&["invite"]).await.unwrap();
        let group = invite["group"].as_str().unwrap().to_owned();
        let mut dave = world.start("dave", HOUR).await;
        dave.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        crate::change_auto(&home, false, Some(crate::cli::Auto::Add { group: group.clone() })).unwrap();
        let added = crate::change_auto(&home, true, Some(crate::cli::Auto::Add { group: group.clone() })).unwrap();
        assert_eq!(added, json!({ "autorep": [group] }));
        assert_eq!(crate::change_auto(&home, false, None).unwrap(), json!({ "auto": [] }), "a group added to one list leaves the other");

        // Bob, the first to start since, joins through Alice, who started before.
        let mut bob = world.start_in("h", "bob", HOUR).await;
        let joined = dave.told(&["joined"]).await;
        assert_eq!((&joined["member"], &joined["by"]), (&json!(bob.fp), &json!(alice.fp)));
        alice.stop().await;
        // Carol, running as Bob stops, takes over: through a stopped session, Alice's, not Bob's while he ran.
        let carol = world.start_in("h", "carol", HOUR).await;
        // Long past her start, which would have joined through Bob.
        tokio::time::sleep(Duration::from_secs(1)).await;
        bob.stop().await;
        let joined = dave.told(&["joined"]).await;
        assert_eq!((&joined["member"], &joined["by"]), (&json!(carol.fp), &json!(alice.fp)));
        for removed in [&alice.fp, &bob.fp] {
            let left = dave.told(&["left"]).await;
            assert_eq!((&left["member"], &left["by"]), (&json!(removed), &json!(carol.fp)));
        }
        let members = dave.cmd(&["members", "--all"]).await.unwrap();
        let fps: Vec<&Value> = members["members"].as_array().unwrap().iter().map(|m| &m["fp"]).collect();
        assert_eq!(fps, [&json!(dave.fp), &json!(carol.fp)]);
        let out = |sessions: &Value| sessions["sessions"].as_array().unwrap().iter().all(|s| s["handle"] == "carol" || s["groups"].is_null());
        let sessions = until(|| async { crate::sessions(&home).await.unwrap() }, out).await;
        assert!(out(&sessions), "Alice's and Bob's groups no longer name the group: {sessions}");
    });
}

/// An invite made with --for admits only that known member: another member of the shared group is refused without
/// warning the inviter, and the link stays usable for the member it names.
#[test]
fn an_invite_for_a_member_admits_only_that_member() {
    local(async {
        let world = world("for").await;
        let (mut alice, bob, group) = pair(&world, HOUR).await;
        let carol = world.start("carol", HOUR).await;
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

