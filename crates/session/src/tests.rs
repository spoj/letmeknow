//! Session processes in one test process, each its own device, talking over a local relay with a self-signed
//! certificate, their logs on a membership service served through it. The CLI talks to them over their command
//! channels.

use anyhow::Result;
use lmk_proto::directory::Directory;
use lmk_serve::{Certificate, ServeConfig};
use lmk_testing::{Relay, relay};
use n0_future::boxed::BoxFuture;
use rustls_pki_types::CertificateDer;
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

#[path = "identity_tests.rs"]
mod private_identity;

const HOUR: Duration = Duration::from_secs(3600);
/// How long a test waits for what a session prints: sessions start slowly on CI's Windows runners.
const WAIT: Duration = Duration::from_secs(60);

struct World {
    /// Keeps the relay running.
    _relay: Relay,
    network: crate::Network,
    root: tempfile::TempDir,
    plugins: Vec<PathBuf>,
    /// The membership service its own `serve` runs at: its domain, and its key in hex.
    domain: String,
    key: String,
}

/// Where cargo builds the workspace's binaries, the kinds' plugins among them: beside this test's own directory.
fn built() -> PathBuf {
    let dir = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf();
    for kind in ["doc", "table"] {
        let plugin = dir.join(format!("letmeknow-kind-{kind}{}", std::env::consts::EXE_SUFFIX));
        assert!(plugin.exists(), "build the plugins first: cargo build -p lmk-kinds");
    }
    dir
}

async fn world(test: &str) -> World {
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_test_writer().try_init();
    let relay = relay().await;
    let root = tempfile::Builder::new().prefix(&format!("lmk-session-{test}-")).tempdir().unwrap();
    let (domain, key, cert) = service(&root.path().join("service")).await;
    let ca = iroh::tls::CaTlsConfig::custom_roots([relay.cert.clone(), cert]);
    let network = crate::Network::new(root.path(), &[relay.url.to_string()], ca).unwrap();
    World { _relay: relay, network, root, plugins: vec![built()], domain, key }
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

/// A membership service run by `serve` in `state`, at a localhost domain of its own with a certificate of its own: its
/// domain, its key in hex, and its certificate.
async fn service(state: &Path) -> (String, String, CertificateDer<'static>) {
    let mut config = ServeConfig::new("localhost", state);
    (config.https_port, config.qad_port, config.membership_port) = (free_port(), free_port(), free_port());
    config.http_port = Some(free_port());
    config.policy.appends_per_minute = u32::MAX;
    let lmk_proto::group::Service::Serve { key, .. } = config.initialize().unwrap() else { unreachable!() };
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(state.join("cert.pem"), certified.cert.pem()).unwrap();
    std::fs::write(state.join("key.pem"), certified.signing_key.serialize_pem()).unwrap();
    config.certificate = Certificate::Files { chain: state.join("cert.pem"), key: state.join("key.pem") };
    let (domain, https) = (config.domain(), config.https_port);
    let mut serving = tokio::spawn(lmk_serve::serve(config));
    let listening = async {
        while std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, https)).is_err() {
            if serving.is_finished() {
                (&mut serving).await.unwrap().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::time::timeout(WAIT, listening).await.expect("the service listens");
    (domain, hex::encode(key.0), certified.cert.der().clone())
}

struct Agent {
    handle: String,
    home: PathBuf,
    fp: String,
    /// Its device's name.
    device: String,
    events: mpsc::UnboundedReceiver<String>,
    stop: Option<oneshot::Sender<()>>,
    done: Option<tokio::task::JoinHandle<()>>,
    ready: Value,
}

impl World {
    /// A session process in its own home: its own device.
    async fn start(&self, handle: &str, hold: Duration) -> Agent {
        self.start_in(handle, handle, hold).await
    }

    /// A session process in the home `device`.
    async fn start_in(&self, device: &str, handle: &str, hold: Duration) -> Agent {
        self.launch(Config { hold, ..self.config(device, handle) }, usize::MAX).await
    }

    /// A session's configuration, in the home `device`.
    fn config(&self, device: &str, handle: &str) -> Config {
        Config {
            handle: handle.into(),
            dir: session_dir(&self.root.path().join(device), handle).unwrap(),
            hold: HOUR,
            keep_log: false,
            membership: self.domain.clone(),
            plugins: self.plugins.clone(),
            registry: "http://127.0.0.1:1".into(),
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
        let mut agent = Agent { handle, home, fp: String::new(), device: String::new(), events, stop: Some(stop), done: Some(done), ready: Value::Null };
        let ready = agent.expect("ready").await;
        assert!(keys(&ready).is_superset(&keys(&json!({ "type": 0, "session": 0, "name": 0, "fp": 0, "bin": 0, "membership": 0 }))), "{ready}");
        agent.fp = ready["fp"].as_str().unwrap().into();
        agent.device = ready["name"].as_str().unwrap().into();
        agent.ready = ready;
        agent
    }
}

impl Agent {
    async fn cmd(&self, args: &[&str]) -> Result<Value> {
        let home = self.home.to_str().unwrap();
        let base = ["letmeknow", "--home", home, "--session", self.handle.as_str()];
        let cli = crate::cli::parse(base.iter().chain(args))?;
        let request = match cli.command {
            Command::Request(request) => request,
            Command::Kind(mut args) => Request::Kind { kind: args.remove(0), args, cwd: String::new() },
            _ => panic!("not a request"),
        };
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
            if event["type"] == "warning" {
                let text = event["text"].as_str().unwrap();
                assert!(text.starts_with("First locally observed identity claim:") || text.starts_with("Previously observed identity-name change or shared name:"), "{event}");
                assert!(text.contains("not been independently verified"), "{event}");
            }
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

/// Alice makes a group and invites Bob, who speaks as his identity "Robert".
async fn pair(world: &World, hold: Duration) -> (Agent, Agent, String) {
    let mut alice = world.start("alice", hold).await;
    let bob = world.start("bob", hold).await;
    alice.cmd(&["identity", "create", "Alice"]).await.unwrap();
    bob.cmd(&["identity", "create", "Robert"]).await.unwrap();
    let invite = alice.cmd(&["invite"]).await.unwrap();
    assert_eq!(keys(&invite), keys(&json!({ "link": 0, "group": 0, "kind": 0, "expires_in": 0 })));
    let link = invite["link"].as_str().unwrap();
    assert!(link.starts_with("https://letmeknow.dev/i#7.g."));
    let joined = bob.cmd(&["join", link]).await.unwrap();
    assert_eq!(joined["group"], invite["group"]);
    assert_eq!(joined["members"].as_array().unwrap().len(), 2);
    let event = alice.told(&["joined"]).await;
    assert_eq!((&event["member"], &event["by"], &event["how"]), (&json!(format!("Robert · {}", bob.device)), &json!("you"), &json!("invite")));
    (alice, bob, invite["group"].as_str().unwrap().to_owned())
}

/// The id of an agent's identity.
async fn identity_of(agent: &Agent) -> String {
    agent.cmd(&["identity", "list"]).await.unwrap()["identity"].as_str().unwrap().to_owned()
}

#[test]
fn messages_that_do_not_concern_a_session_wait_for_one_that_does() {
    local(async {
        let world = world("steer").await;
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        let sent = bob.cmd(&["send", "the build is green"]).await.unwrap();
        assert!(sent["id"].is_string() && sent.get("pos").is_none(), "{sent}");
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message"));
        bob.cmd(&["send", "@alice can you deploy?"]).await.unwrap();
        let first = alice.expect("message").await;
        let second = alice.expect("message").await;
        assert_eq!((first["content"].as_str(), first.get("direct")), (Some("the build is green"), None));
        assert_eq!((second["content"].as_str(), second["direct"].as_bool()), (Some("@alice can you deploy?"), Some(true)));
        assert_eq!(keys(&second), keys(&json!({ "type": 0, "group": 0, "id": 0, "seq": 0, "from": 0, "direct": 0, "content": 0, "sent_at": 0 })));
        assert_eq!(second["seq"].as_u64(), first["seq"].as_u64().map(|s| s + 1), "in order");
        assert_eq!((second["group"].as_str(), second["id"].as_str().unwrap().len()), (Some(group.as_str()), crate::short::ID));
        // Bob's identity is known only by its own claim; `members` tells more of him.
        assert_eq!(second["from"], format!("Robert · {}", bob.device));
        let members = alice.cmd(&["members"]).await.unwrap();
        let robert = members["members"].as_array().unwrap().iter().find(|m| m["handle"] == "bob").unwrap();
        assert_eq!((&robert["identity"]["how"], &robert["added_by"]), (&json!("observed"), &json!({ "fp": alice.fp, "how": "invite" })));
        // The read frontier: Alice's answer comes after what she was shown, and a reply to Bob wakes him.
        let id = second["id"].as_str().unwrap();
        let answer = alice.cmd(&["send", "--reply-to", id, "on it"]).await.unwrap();
        let read = alice.cmd(&["read", answer["id"].as_str().unwrap(), "--ancestors", "2"]).await.unwrap();
        let read: Vec<&str> = read.as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
        assert_eq!(read.len(), 3);
        assert_eq!(read[2], answer["id"].as_str().unwrap());
        let reply = bob.expect("message").await;
        assert_eq!(reply["reply_to"], id);
        // Shown text is forgotten.
        let read = alice.cmd(&["read", id]).await.unwrap();
        assert!(read[0]["content"].is_null());
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
        let big = "x".repeat(1 << 20);
        let refused = alice.cmd(&["send", "--to", "Bob", &big]).await.unwrap_err().to_string();
        assert!(refused.contains("members take"), "{refused}");
        bob.stop().await;
        let before = lmk_node::now();
        let sent = alice.cmd(&["send", "--urgent", "anyone?"]).await.unwrap();
        assert!(sent["id"].is_string() && sent.get("pos").is_none(), "{sent}");
        // Alice finds out that Bob's connection closed once his close reaches her.
        let status = until(|| async { alice.cmd(&["status"]).await.unwrap() }, |status| status["groups"][0]["online"].is_null()).await;
        assert!(status["groups"][0]["online"].is_null(), "{status}");
        // Once Bob is back, he takes it.
        let mut bob = world.start("bob", HOUR).await;
        let message = bob.expect("message").await;
        assert_eq!((message["id"].as_str(), message["content"].as_str()), (sent["id"].as_str(), Some("anyone?")));
        let sent_at = message["sent_at"].as_u64().unwrap();
        assert!(before <= sent_at && sent_at < lmk_node::now(), "it tells when it was sent, not when it arrived");
    });
}

#[test]
fn an_attachment_arrives_as_a_private_file() {
    local(async {
        let world = world("attach").await;
        let (mut alice, bob, _) = pair(&world, HOUR).await;
        let file = world.root.path().join("token.txt");
        std::fs::write(&file, "s3cret").unwrap();
        let sent = bob.cmd(&["send", "--to", "Alice", "--attach", file.to_str().unwrap(), "the token"]).await.unwrap();
        assert_eq!(sent["attachment"]["held_by"], json!([format!("Alice · {}", alice.device)]));
        let message = alice.expect("message").await;
        assert_eq!(message["attachment"]["name"], "token.txt");
        assert!(message["attachment"]["link"].as_str().unwrap().starts_with("lmk:"));
        let path = match message["attachment"]["path"].as_str() {
            Some(path) => path.to_owned(),
            None => {
                assert_eq!(message["attachment"]["pending"], true);
                let arrived = alice.expect("attachment").await;
                assert_eq!(keys(&arrived), keys(&json!({ "type": 0, "group": 0, "message": 0, "name": 0, "path": 0 })));
                assert_eq!(arrived["message"], message["id"]);
                arrived["path"].as_str().unwrap().to_owned()
            }
        };
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "s3cret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let fetched = alice.cmd(&["fetch", message["attachment"]["link"].as_str().unwrap()]).await.unwrap();
        assert_eq!(fetched["bytes"], 6);
    });
}

#[test]
fn a_doc_is_a_file_that_others_edit_too() {
    local(async {
        let world = world("doc").await;
        let mut alice = world.start("alice", HOUR).await;
        let mut bob = world.start("bob", HOUR).await;
        let plan = world.root.path().join("plan.md");
        std::fs::write(&plan, "- [ ] alpha\n- [ ] beta\n").unwrap();
        let invite = alice.cmd(&["invite", "--kind", "doc", "--name", "Plan", plan.to_str().unwrap()]).await.unwrap();
        assert_eq!(invite["file"], plan.to_str().unwrap());
        let theirs = world.root.path().join("bob-plan.md");
        let joined = bob.cmd(&["join", invite["link"].as_str().unwrap(), theirs.to_str().unwrap()]).await.unwrap();
        assert_eq!(joined["kind"], "doc");
        alice.told(&["joined"]).await;
        // The doc's text arrives a moment later, from whoever admitted Bob; a command prints what waits.
        for _ in 0..40 {
            bob.cmd(&["groups"]).await.unwrap();
            if std::fs::read_to_string(&theirs).unwrap().contains("alpha") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let edited = bob.expect("edited").await;
        assert_eq!(edited["by"], json!([alice.fp]), "of no identity, so by fingerprint");
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "- [ ] alpha\n- [ ] beta\n");
        // Bob ticks a line and adds one that mentions Alice; Alice meanwhile changes another.
        std::fs::write(&theirs, "- [x] alpha\n- [ ] beta\n- [ ] gamma @alice\n").unwrap();
        std::fs::write(&plan, "- [ ] alpha\n- [ ] beta (Tuesday)\n").unwrap();
        let edited = alice.expect("edited").await;
        assert_eq!(keys(&edited), keys(&json!({ "type": 0, "group": 0, "file": 0, "by": 0, "lines": 0, "direct": 0 })));
        assert_eq!(edited["by"], json!([bob.fp]));
        assert_eq!(edited["direct"], true);
        assert_eq!(std::fs::read_to_string(&plan).unwrap(), "- [x] alpha\n- [ ] beta (Tuesday)\n- [ ] gamma @alice\n");
        // Bob's edit to a line was not to the line Alice changed, so nothing is lost; his file gets her change.
        for _ in 0..40 {
            bob.cmd(&["groups"]).await.unwrap();
            if std::fs::read_to_string(&theirs).unwrap().contains("Tuesday") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "- [x] alpha\n- [ ] beta (Tuesday)\n- [ ] gamma @alice\n");
        assert!(bob.printed().await.iter().all(|e| e["type"] != "warning"));
        let attached = world.root.path().join("chart.png");
        std::fs::write(&attached, b"\x89PNG....").unwrap();
        let link = alice.cmd(&["doc", "attach", attached.to_str().unwrap()]).await.unwrap();
        assert!(link["markdown"].as_str().unwrap().starts_with("![chart.png](lmk:"));
    });
}

#[test]
fn a_table_is_a_csv_file_whose_cells_others_edit_too() {
    local(async {
        let world = world("table").await;
        let mut alice = world.start("alice", HOUR).await;
        let bob = world.start("bob", HOUR).await;
        let tasks = world.root.path().join("tasks.csv");
        std::fs::write(&tasks, "Task,Owner,Done\nwrite,,false\nship,,false\n").unwrap();
        let invite = alice.cmd(&["invite", "--kind", "table", "--name", "Tasks", tasks.to_str().unwrap()]).await.unwrap();
        assert_eq!(invite["file"], tasks.to_str().unwrap());
        let ours = std::fs::read_to_string(&tasks).unwrap();
        assert!(ours.starts_with("id,Task,Owner,Done\n"), "the rows get ids: {ours}");
        let theirs = world.root.path().join("bob-tasks.csv");
        let joined = bob.cmd(&["join", invite["link"].as_str().unwrap(), theirs.to_str().unwrap()]).await.unwrap();
        assert_eq!(joined["kind"], "table");
        alice.told(&["joined"]).await;
        assert_eq!(until_file(&bob, &theirs, |text| text == ours).await, ours);
        // Bob takes the first task while Alice ticks the second: both stand.
        let (first, second) = (ours.lines().nth(1).unwrap(), ours.lines().nth(2).unwrap());
        std::fs::write(&theirs, ours.replace(first, &first.replace(",write,,", ",write,bob,"))).unwrap();
        std::fs::write(&tasks, ours.replace(second, &second.replace(",false", ",true"))).unwrap();
        let both = |text: &str| text.contains(",write,bob,false\n") && text.contains(",ship,,true\n");
        assert!(both(&until_file(&alice, &tasks, both).await));
        assert!(both(&until_file(&bob, &theirs, both).await));
        assert_eq!(alice.expect("edited").await["by"], json!([bob.fp]));
    });
}

#[test]
fn membership_and_settings_changes_are_told_and_a_removed_session_learns_it() {
    local(async {
        let world = world("remove").await;
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        let named = alice.cmd(&["name", "Release"]).await.unwrap();
        assert_eq!(named["settings"]["name"], "Release");
        let settings = bob.told(&["settings"]).await;
        let alice_shown = json!(format!("Alice · {}", alice.device));
        assert_eq!((&settings["group"], &settings["settings"]["name"], &settings["by"]), (&json!("Release"), &json!("Release"), &alice_shown));
        let members = bob.cmd(&["members", "--group", "Release"]).await.unwrap();
        let handles: Vec<&str> = members["members"].as_array().unwrap().iter().map(|m| m["handle"].as_str().unwrap()).collect();
        assert_eq!(handles, ["alice", "bob"], "`members` tells all of each");
        assert_eq!(members["members"][1]["you"], true);
        let other = alice.cmd(&["invite"]).await.unwrap()["group"].as_str().unwrap().to_owned();
        assert_eq!(alice.cmd(&["status"]).await.unwrap()["groups"].as_array().unwrap().len(), 2);
        for named in ["Release", group.as_str()] {
            let status = alice.cmd(&["status", &format!("--group={named}")]).await.unwrap();
            assert_eq!(status["groups"].as_array().unwrap().iter().map(|g| &g["group"]).collect::<Vec<_>>(), [group.as_str()]);
        }
        assert!(alice.cmd(&["status", "--group", "nope"]).await.unwrap_err().to_string().contains("unknown group nope"));
        alice.cmd(&["leave", &format!("--group={other}")]).await.unwrap();
        assert!(alice.cmd(&["remove", "Carol"]).await.is_err());
        alice.cmd(&["remove", "Bob"]).await.unwrap();
        assert_eq!(alice.told(&["left"]).await["member"], format!("Robert · {}", bob.device));
        let removed = bob.told(&["removed"]).await;
        assert_eq!((&removed["group"], &removed["by"]), (&json!("Release"), &alice_shown), "by the name it had");
        assert_eq!(bob.cmd(&["groups"]).await.unwrap(), json!([]));
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
        bob.cmd(&["send", &format!("@alice {secret}")]).await.unwrap();
        assert_eq!(alice.expect("message").await["content"].as_str().unwrap(), format!("@alice {secret}"));
        alice.cmd(&["status"]).await.unwrap();
        assert_eq!(holding(&session_dir(&alice.home, "alice").unwrap(), secret), Vec::<PathBuf>::new());
        alice.cmd(&["remove", "Bob"]).await.unwrap();
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
        assert_eq!(left["left"], true);
        assert_eq!(alice.told(&["left"]).await["member"], format!("Robert · {}", bob.device));
        bob.told(&["removed"]).await;
    });
}

/// Asks again, a quarter of a second apart, until `accept` takes what `ask` answers or 30 seconds pass; returns the last
/// answer.
async fn until(ask: impl AsyncFn() -> Value, accept: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..120 {
        let answer = ask().await;
        if accept(&answer) {
            return answer;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    ask().await
}

#[test]
fn a_message_printed_is_read_and_one_waiting_only_held() {
    local(async {
        let world = world("read").await;
        let (mut alice, bob, _) = pair(&world, HOUR).await;
        let quiet = bob.cmd(&["send", "fyi"]).await.unwrap();
        let id = quiet["id"].as_str().unwrap();
        let alice_shown = json!([format!("Alice · {}", alice.device)]);
        let read = until(|| async { bob.cmd(&["read", id]).await.unwrap() }, |read| read[0]["held_by"] == alice_shown).await;
        assert_eq!((&read[0]["held_by"], &read[0]["read_by"]), (&alice_shown, &Value::Null), "Alice holds it, unprinted");
        let look = bob.cmd(&["send", "@alice look"]).await.unwrap();
        assert_eq!(alice.expect("message").await["id"], id);
        alice.expect("message").await;
        let read = until(|| async { bob.cmd(&["read", id]).await.unwrap() }, |read| read[0]["read_by"] == alice_shown).await;
        assert_eq!(read[0]["read_by"], alice_shown, "printed, so read");
        // Alice's next message carries what she read.
        let answer = alice.cmd(&["send", "seen both"]).await.unwrap();
        // Unknown to Bob until her message reaches him.
        let ask = || async { bob.cmd(&["read", answer["id"].as_str().unwrap(), "--ancestors", "5"]).await.unwrap_or_default() };
        let shown = until(ask, |shown| shown.as_array().is_some_and(|shown| shown.len() == 3)).await;
        let shown: Vec<&Value> = shown.as_array().expect("Bob knows Alice's message by the id send answered").iter().map(|m| &m["id"]).collect();
        assert_eq!(shown, [&quiet["id"], &look["id"], &answer["id"]]);
    });
}

/// Waits until the member named `by` holds a message of `alice`'s, as her `read` shows.
async fn held(alice: &Agent, sent: &Value, by: &str) {
    let read = until(|| async { alice.cmd(&["read", sent["id"].as_str().unwrap()]).await.unwrap() }, |read| read[0]["held_by"] == json!([by])).await;
    assert_eq!(read[0]["held_by"], json!([by]), "{read}");
}

static SHIFT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The system's clock, moved on by `SHIFT`.
fn shifted() -> u64 {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    now + SHIFT.load(std::sync::atomic::Ordering::Relaxed)
}

#[test]
fn status_lists_sends_held_only_here_and_members_away() {
    local(async {
        lmk_proto::clock::set(shifted);
        let world = world("only-here").await;
        let (alice, mut bob, _) = pair(&world, HOUR).await;
        let robert = format!("Robert · {}", bob.device);
        let hello = alice.cmd(&["send", "hello"]).await.unwrap();
        // Bob was shown it, so his summary that says so shows that he holds it and the invite before it: Alice's next
        // commit keeps both.
        bob.told(&["message"]).await;
        let read = until(|| async { alice.cmd(&["read", hello["id"].as_str().unwrap()]).await.unwrap() }, |read| read[0]["read_by"] == json!([robert])).await;
        assert_eq!(read[0]["read_by"], json!([robert]), "{read}");
        alice.cmd(&["name", "Kept"]).await.unwrap();
        let status = until(|| async { alice.cmd(&["status"]).await.unwrap() }, |status| status["groups"][0]["only_here"].is_null()).await;
        assert!(status["groups"][0]["only_here"].is_null(), "{status}");
        bob.stop().await;
        let sent = alice.cmd(&["send", "anyone?"]).await.unwrap();
        let status = alice.cmd(&["status"]).await.unwrap();
        assert_eq!(status["groups"][0]["only_here"], json!([{ "what": "message", "id": sent["id"] }]));
        assert!(status["warning"].is_string());
        assert!(status["groups"][0]["away"].is_null(), "Bob was heard from just now");
        let mut bob = world.start("bob", HOUR).await;
        held(&alice, &sent, &robert).await;
        alice.cmd(&["name", "Again"]).await.unwrap();
        let status = until(|| async { alice.cmd(&["status"]).await.unwrap() }, |status| status["groups"][0]["only_here"].is_null()).await;
        assert!(status["groups"][0]["only_here"].is_null(), "Bob holds it, and a commit kept it");
        assert!(status.get("warning").is_none());
        bob.stop().await;
        SHIFT.store(8 * 24 * 3600 * 1000, std::sync::atomic::Ordering::Relaxed);
        // Once Bob's close reaches Alice.
        let status = until(|| async { alice.cmd(&["status"]).await.unwrap() }, |status| status["groups"][0]["away"][0] == robert.as_str()).await;
        assert_eq!(status["groups"][0]["away"][0], robert.as_str(), "not heard from for longer than members carry messages");
        assert_eq!(alice.cmd(&["members"]).await.unwrap()["members"].as_array().unwrap().len(), 2, "away, not removed");
    });
}

#[test]
fn a_leave_is_pending_until_another_member_removes_the_session() {
    local(async {
        let world = world("leave-pending").await;
        let (mut alice, mut bob, _) = pair(&world, HOUR).await;
        alice.stop().await;
        let left = bob.cmd(&["leave"]).await.unwrap();
        assert_eq!((&left["left"], &left["pending"]), (&json!(true), &json!(true)), "{left}");
        let _alice = world.start("alice", HOUR).await;
        assert_eq!(bob.told(&["removed"]).await["type"], "removed");
    });
}

/// A message no commit kept is not told lost: Bob is away while Alice sends and commits twice, and gets the message once
/// Alice is back, as she still holds it.
#[test]
fn a_message_no_commit_kept_is_not_lost() {
    local(async {
        let world = world("unkept").await;
        let (mut alice, mut bob, _) = pair(&world, HOUR).await;
        bob.stop().await;
        alice.cmd(&["send", "while you were out"]).await.unwrap();
        alice.cmd(&["name", "Once"]).await.unwrap();
        alice.cmd(&["name", "Twice"]).await.unwrap();
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
        let missing = Agent { handle: "nobody".into(), home: alice.home.clone(), fp: String::new(), device: String::new(), events: mpsc::unbounded_channel().1, stop: None, done: None, ready: Value::Null };
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
        let bob_renamed = bob.cmd(&["name", "Later"]).await.unwrap();
        assert_eq!(bob_renamed["settings"]["name"], "Later");
        let mut alice = world.start("alice", HOUR).await;
        let mut got = Vec::new();
        while got.len() < 2 {
            let message = alice.expect("message").await;
            assert!(message.get("missing").is_none());
            got.push(message["id"].clone());
        }
        assert_eq!(got, [first["id"].clone(), second["id"].clone()]);
        let groups = alice.cmd(&["groups"]).await.unwrap();
        assert_eq!((groups[0]["group"].as_str(), groups[0]["name"].as_str()), (Some(group.as_str()), Some("Later")));
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
        assert_eq!(bob.told(&["removed"]).await["by"], format!("Alice · {}", alice.device));
        assert_eq!(alice.cmd(&["groups"]).await.unwrap(), json!([]));
        assert_eq!(bob.cmd(&["groups"]).await.unwrap(), json!([]));
    });
}

#[test]
fn a_link_for_one_identity_admits_no_other() {
    local(async {
        let world = world("to").await;
        let (alice, bob, _) = pair(&world, HOUR).await;
        let invite = alice.cmd(&["invite", "--to", &identity_of(&bob).await]).await.unwrap();
        let carol = world.start("carol", HOUR).await;
        carol.cmd(&["identity", "create", "Carol"]).await.unwrap();
        let link = invite["link"].as_str().unwrap();
        let refused = carol.cmd(&["join", link]).await.unwrap_err().to_string();
        assert!(refused.contains("another identity"), "{refused}");
        // A refused try does not use the link up: Bob still can.
        assert_eq!(bob.cmd(&["join", link]).await.unwrap()["group"], invite["group"]);
    });
}

#[test]
fn a_device_is_on_one_identity_which_lists_and_loses_devices() {
    local(async {
        let world = world("identity").await;
        let alice = world.start("alice", HOUR).await;
        let created = alice.cmd(&["identity", "create", "Alice Smith"]).await.unwrap();
        assert_eq!(created["name"], "Alice Smith");
        let listed = alice.cmd(&["identity", "list"]).await.unwrap();
        assert_eq!(listed["devices"][0]["you"], true);
        assert_eq!(listed["name"], "Alice Smith");
        let invite = alice.cmd(&["identity", "invite"]).await.unwrap();
        assert!(invite["link"].as_str().unwrap().contains("#7.d."));
        let phone = world.start("phone", HOUR).await;
        let refused = phone.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap_err().to_string();
        assert!(refused.contains("letmeknow identity join <link>"), "{refused}");
        let group = alice.cmd(&["invite"]).await.unwrap();
        let refused = phone.cmd(&["identity", "join", group["link"].as_str().unwrap()]).await.unwrap_err().to_string();
        assert!(refused.contains("not a device link"), "{refused}");
        let joined = phone.cmd(&["identity", "join", invite["link"].as_str().unwrap()]).await.unwrap();
        assert!(joined["device"].is_string());
        assert_eq!(phone.cmd(&["identity", "list"]).await.unwrap()["name"], "Alice Smith");
        let refused = phone.cmd(&["identity", "create", "Phone"]).await.unwrap_err().to_string();
        assert!(refused.contains("on an identity already"), "{refused}");
        let again = alice.cmd(&["identity", "invite"]).await.unwrap();
        let refused = phone.cmd(&["identity", "join", again["link"].as_str().unwrap()]).await.unwrap_err().to_string();
        assert!(refused.contains("on an identity already"), "{refused}");
        let listed = alice.cmd(&["identity", "list"]).await.unwrap();
        let devices = listed["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 2);
        let phone_key = devices.iter().find(|d| d["you"] != true).unwrap()["key"].as_str().unwrap().to_owned();
        alice.cmd(&["identity", "remove", "--", &phone_key]).await.unwrap();
        let listed = alice.cmd(&["identity", "list"]).await.unwrap();
        assert_eq!(listed["devices"].as_array().unwrap().len(), 1);
    });
}

/// A member shows as its identity and its device, with its handle where another session of its device is in the group,
/// and answers to any of them: another person's identity's name too.
#[test]
fn a_member_shows_as_its_identity_and_device_and_answers_to_them() {
    local(async {
        let world = world("shown").await;
        let (alice, mut bob, group) = pair(&world, HOUR).await;
        let mut desk = world.start_in("bob", "desk", HOUR).await;
        let invite = alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap();
        desk.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        let device = lmk_core::device::Device::load(&bob.home.join("device.json")).unwrap().name;
        let shown = |members: &Value| {
            let mut names: Vec<String> = members["members"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap().to_owned()).collect();
            names.sort();
            names
        };
        let expected = [format!("Alice · {device}"), format!("Robert · {device} (bob)"), format!("Robert · {device} (desk)")];
        let members = until(|| async { alice.cmd(&["members"]).await.unwrap() }, |members| shown(members) == expected).await;
        assert_eq!(shown(&members), expected);
        alice.cmd(&["send", "@robert, a word"]).await.unwrap();
        for robert in [&mut bob, &mut desk] {
            let message = robert.expect("message").await;
            assert_eq!((&message["direct"], &message["from"]), (&json!(true), &json!(format!("Alice · {device}"))));
        }
        // To Bob, another session of his own identity shows as its device, with its handle, as the device has two here.
        desk.cmd(&["send", "--to", "bob", "from the desk"]).await.unwrap();
        let message = bob.expect("message").await;
        assert_eq!((&message["from"], &message["to"]), (&json!(format!("{device} (desk)")), &json!(["you"])));
    });
}

/// A session that does not act for its device renames the device and takes it off its identity, through the session
/// that does: both sessions refresh their private signed credentials, and the identity, whose only device it was, ends.
#[test]
fn a_device_is_renamed_and_leaves_its_identity_from_another_of_its_sessions() {
    local(async {
        let world = world("rename").await;
        let alice = world.start("alice", HOUR).await;
        let desk = world.start_in("alice", "desk", HOUR).await;
        let mut carol = world.start("carol", HOUR).await;
        alice.cmd(&["identity", "create", "Alice"]).await.unwrap();
        let invite = carol.cmd(&["invite"]).await.unwrap();
        desk.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        carol.told(&["joined"]).await;

        assert_eq!(desk.cmd(&["identity", "rename", "--device", "studio"]).await.unwrap()["device"]["name"], "studio");
        let listed = alice.cmd(&["identity", "list"]).await.unwrap();
        assert_eq!(listed["devices"][0]["name"], "studio");
        assert_eq!(lmk_core::device::Device::load(&alice.home.join("device.json")).unwrap().name, "studio");
        let device = || async { carol.cmd(&["members"]).await.unwrap()["members"].as_array().unwrap().iter().any(|m| m["device"] == "studio") };
        for _ in 0..120 {
            if device().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(device().await, "carol sees the device's new name in its refreshed signed leaf");

        let left = desk.cmd(&["identity", "leave"]).await.unwrap();
        assert_eq!((&left["left"][0], &left["ended"]), (&invite["group"], &json!(true)));
        assert_eq!(alice.cmd(&["identity", "list"]).await.unwrap()["identity"], json!(null));
        // Carol may hear that the device left its identity before she commits its leave, and then it shows by fingerprint.
        let left = carol.told(&["left"]).await;
        assert!(left["member"] == desk.fp.as_str() || left["member"] == "Alice · studio", "{left}");
    });
}

/// Waits, running commands so that what waits prints, until `file` reads as `check` wants.
async fn until_file(agent: &Agent, file: &Path, check: impl Fn(&str) -> bool) -> String {
    for _ in 0..80 {
        agent.cmd(&["groups"]).await.unwrap();
        let text = std::fs::read_to_string(file).unwrap_or_default();
        if check(&text) {
            return text;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    std::fs::read_to_string(file).unwrap()
}

#[test]
fn docs_that_drift_apart_meet_again() {
    local(async {
        let world = world("frames").await;
        let mut alice = world.start("alice", HOUR).await;
        let mut bob = world.start("bob", HOUR).await;
        let (plan, theirs) = (world.root.path().join("plan.md"), world.root.path().join("bob-plan.md"));
        std::fs::write(&plan, "- [ ] alpha\n").unwrap();
        let invite = alice.cmd(&["invite", "--kind", "doc", plan.to_str().unwrap()]).await.unwrap();
        bob.cmd(&["join", invite["link"].as_str().unwrap(), theirs.to_str().unwrap()]).await.unwrap();
        alice.told(&["joined"]).await;
        assert_eq!(until_file(&bob, &theirs, |t| t.contains("alpha")).await, "- [ ] alpha\n");
        // Bob is away while Alice edits: her live edit never reaches him, but the docs compare once he is back.
        bob.stop().await;
        std::fs::write(&plan, "- [x] alpha\n").unwrap();
        alice.cmd(&["status"]).await.unwrap();
        let bob = world.start("bob", HOUR).await;
        assert_eq!(until_file(&bob, &theirs, |t| t.contains("[x]")).await, "- [x] alpha\n");
        alice.stop().await;
    });
}

#[test]
fn a_kinds_commands_pass_through_and_a_session_without_its_plugin_is_refused() {
    local(async {
        let mut world = world("plugins").await;
        let alice = world.start("alice", HOUR).await;
        world.plugins = Vec::new();
        let bob = world.start("bob", HOUR).await;
        // Both find the doc plugin stopped; it starts once.
        let (invite, other) = tokio::join!(alice.cmd(&["invite", "--kind", "doc"]), alice.cmd(&["invite", "--kind", "doc"]));
        let (invite, other) = (invite.unwrap(), other.unwrap());
        alice.cmd(&["leave", &format!("--group={}", other["group"].as_str().unwrap())]).await.unwrap();
        let error = bob.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap_err();
        assert!(format!("{error:#}").contains("does not support doc groups"), "{error:#}");
        let error = bob.cmd(&["invite", "--kind", "doc"]).await.unwrap_err();
        assert!(format!("{error:#}").contains("no plugin for doc groups"), "{error:#}");
        let error = bob.cmd(&["doc", "attach", "x"]).await.unwrap_err();
        assert!(format!("{error:#}").contains("no plugin for doc groups"), "{error:#}");
        // Alice's plugin answers her doc's commands, and refuses those it does not know.
        let error = alice.cmd(&["doc", "frobnicate"]).await.unwrap_err();
        assert!(format!("{error:#}").contains("usage: letmeknow doc attach"), "{error:#}");
        let readme = world.root.path().join("readme.txt");
        std::fs::write(&readme, "read me").unwrap();
        let attached = alice.cmd(&["doc", "attach", readme.to_str().unwrap()]).await.unwrap();
        assert!(attached["markdown"].as_str().unwrap().starts_with("[readme.txt](lmk:"));
        let fetched = alice.cmd(&["fetch", attached["link"].as_str().unwrap()]).await.unwrap();
        assert_eq!(fetched["bytes"], 7);
    });
}

#[test]
fn a_restarted_session_resumes_its_groups_and_docs() {
    local(async {
        let world = world("restart").await;
        let mut alice = world.start("alice", HOUR).await;
        let invite = alice.cmd(&["invite", "--kind", "doc", "--name", "Notes"]).await.unwrap();
        let file = invite["file"].as_str().unwrap().to_owned();
        assert!(std::path::Path::new(&file).parent().unwrap().ends_with("docs"));
        alice.stop().await;
        std::fs::write(&file, "written while stopped\n").unwrap();
        let alice = world.start("alice", HOUR).await;
        let groups = alice.cmd(&["groups"]).await.unwrap();
        assert_eq!((groups[0]["name"].as_str(), groups[0]["file"].as_str()), (Some("Notes"), Some(file.as_str())));
        alice.cmd(&["leave"]).await.unwrap();
        assert!(!Path::new(&file).exists());
    });
}

#[test]
fn a_session_that_stopped_while_carrying_a_file_onto_its_doc_does_not_carry_it_twice() {
    local(async {
        use lmk_kinds::ydoc;
        let world = world("carrying").await;
        let mut alice = world.start("alice", HOUR).await;
        let invite = alice.cmd(&["invite", "--kind", "doc", "--name", "Notes"]).await.unwrap();
        let gid = invite["group"].as_str().unwrap().to_owned();
        let file = invite["file"].as_str().unwrap().to_owned();
        std::fs::write(&file, "one\n").unwrap();
        alice.cmd(&["status"]).await.unwrap();
        alice.stop().await;
        let dir = session_dir(&alice.home, "alice").unwrap();
        let (state_file, saved_file) = (dir.join(format!("kinds/doc/{gid}.yjs")), dir.join(format!("kinds/doc/{gid}.json")));
        // Another member's line came in; then the plugin stopped after recording that it carried its own new line onto
        // the doc, with the doc changed (`applied`) or not, before the file was rewritten and the base stored.
        for (i, applied) in [true, false].into_iter().enumerate() {
            let base = std::fs::read_to_string(&file).unwrap();
            let carried = format!("{base}mine {i}\n");
            let expected = format!("others {i}\n{carried}");
            std::fs::write(&file, &carried).unwrap();
            let state = std::fs::read(&state_file).unwrap();
            let theirs = ydoc::apply(&state, &ydoc::edit(&state, &format!("others {i}\n{base}")).unwrap()).unwrap();
            let edit = ydoc::edit(&theirs, &expected).unwrap();
            let state = if applied { ydoc::apply(&theirs, &edit).unwrap() } else { theirs };
            let carrying = json!({ "file": carried, "edit": lmk_proto::Bytes(edit.clone()) });
            std::fs::write(&state_file, &state).unwrap();
            std::fs::write(&saved_file, json!({ "path": file, "base": base, "made": true, "carrying": carrying }).to_string()).unwrap();
            alice = world.start("alice", HOUR).await;
            alice.cmd(&["status"]).await.unwrap();
            assert_eq!(std::fs::read_to_string(&file).unwrap(), expected);
            alice.stop().await;
        }
    });
}

#[test]
fn every_session_of_a_device_sees_its_state_and_changes_it() {
    local(async {
        let world = world("device").await;
        let mut first = world.start("alice", HOUR).await;
        let mut second = world.start_in("alice", "second", HOUR).await;
        // The second session process acts through the first, which holds the device's lock.
        second.cmd(&["identity", "create", "Alice"]).await.unwrap();
        assert_eq!(first.cmd(&["identity", "list"]).await.unwrap()["name"], "Alice");
        let bob = world.start("bob", HOUR).await;
        bob.cmd(&["identity", "create", "Robert"]).await.unwrap();
        let invite = second.cmd(&["invite"]).await.unwrap();
        bob.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        second.told(&["joined"]).await;
        let members = second.cmd(&["members"]).await.unwrap();
        let alice_seen = members["members"].as_array().unwrap().iter().find(|m| m["you"] == true).unwrap().clone();
        assert_eq!((alice_seen["identity"]["name"].as_str(), alice_seen["identity"]["how"].as_str()), (Some("Alice"), Some("self")));
        // Once the first stops, the second acts for the device, from its next command on.
        first.stop().await;
        assert_eq!(second.cmd(&["identity", "list"]).await.unwrap()["name"], "Alice");
        // Work the second sent the first in the background may fail as the first stops; taking over may not.
        let warnings: Vec<Value> = second.printed().await.into_iter().filter(|e| e["type"] == "warning").collect();
        assert!(warnings.iter().all(|w| !w["text"].as_str().unwrap_or_default().contains("acting for this device")), "{warnings:?}");
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
        alice.cmd(&["send", "@carol after the gap"]).await.unwrap();
        let got = carol.expect("message").await;
        assert_eq!(got["content"], "@carol after the gap");
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

/// `sessions` lists this machine's sessions, each with its groups, and their other members as they show to it, and
/// whether it runs. `sessions remove` stops one that runs, or runs one that does not, until another member holds its
/// leave of each group, and deletes it.
#[test]
fn a_session_is_listed_and_removed_running_or_stopped() {
    local(async {
        let world = world("sessions").await;
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        let desk = world.start_in("bob", "desk", HOUR).await;
        let invite = alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap();
        desk.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        let groups = |other: &str| json!([{ "group": group, "name": "", "kind": "chat", "members": [format!("Alice · {}", alice.device), format!("{} ({other})", bob.device)] }]);
        let both = json!({ "sessions": [
            { "handle": "bob", "running": true, "groups": groups("desk") },
            { "handle": "desk", "running": true, "groups": groups("bob") },
        ] });
        let listed = until(|| async { crate::sessions(&bob.home).await.unwrap() }, |listed| *listed == both).await;
        assert_eq!(listed, both);

        let removed = crate::remove(world.config("bob", "desk"), &bob.home, world.network.clone()).await.unwrap();
        assert_eq!(removed, json!({ "removed": "desk", "left": [group] }));
        assert_eq!(alice.told(&["left"]).await["member"], format!("Robert · {} (desk)", bob.device), "Bob's device has two sessions here");
        drop(desk);
        bob.stop().await;
        crate::remove(world.config("bob", "bob"), &bob.home, world.network.clone()).await.unwrap();
        assert_eq!(alice.told(&["left"]).await["member"], format!("Robert · {}", bob.device));
        assert_eq!(crate::sessions(&bob.home).await.unwrap(), json!({ "sessions": [] }));
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

/// `add` brings a session of another of your devices into a group: `identity list` shows the sessions each device runs,
/// and their groups, and the session the add names joins once it runs, by an invite that admits only a session of its
/// device, once.
#[test]
fn an_add_brings_a_session_of_another_device_into_a_group_once() {
    local(async {
        let world = world("add").await;
        let (alice, bob, group) = pair(&world, HOUR).await;
        let mut desk = world.start("desk", HOUR).await;
        let invite = bob.cmd(&["identity", "invite"]).await.unwrap();
        desk.cmd(&["identity", "join", invite["link"].as_str().unwrap()]).await.unwrap();
        let runs = |listed: &Value, you: bool| listed["devices"].as_array().unwrap().iter().find(|d| (d["you"] == true) == you).unwrap().clone();
        let listed = until(|| async { bob.cmd(&["identity", "list"]).await.unwrap() }, |listed| runs(listed, false)["sessions"] == json!(["desk"])).await;
        assert_eq!(runs(&listed, false)["sessions"], json!(["desk"]), "the laptop hears which sessions the desk runs");
        assert_eq!(runs(&listed, true)["sessions"], json!(["bob"]));

        // Added while it is stopped, the desk's session joins once it runs again.
        desk.stop().await;
        let added = bob.cmd(&["add", "desk", &format!("--group={group}")]).await.unwrap();
        assert_eq!((added["group"].as_str(), added["session"].as_str()), (Some(group.as_str()), Some("desk")));
        let link = added["link"].as_str().unwrap();
        let laptop = world.start_in("bob", "laptop", HOUR).await;
        let refused = laptop.cmd(&["join", link]).await.unwrap_err().to_string();
        assert!(refused.contains("another device"), "{refused}");
        let mut desk = world.start("desk", HOUR).await;
        let joined = desk.told(&["joined"]).await;
        assert_eq!((joined["how"].as_str(), joined["group"].as_str()), (Some("add"), Some(group.as_str())));
        assert_eq!(joined["device"], runs(&listed, true)["name"]);
        // Both devices are named after this machine, so the laptop's session shows with its handle.
        let members = [format!("Alice · {}", alice.device), format!("{} (bob)", bob.device)];
        let shown = json!([{ "session": "desk", "group": group, "kind": "chat", "members": members }]);
        let heard = until(|| async { bob.cmd(&["identity", "list"]).await.unwrap() }, |listed| runs(listed, false)["groups"] == shown).await;
        assert_eq!(runs(&heard, false)["groups"], shown, "the laptop hears which groups the desk's sessions are in, with whom");
        let other = world.start_in("desk", "other", HOUR).await;
        let refused = other.cmd(&["join", link]).await.unwrap_err().to_string();
        assert!(refused.contains("used"), "{refused}");

        // In the group, it is refused another add, and an add it is handed anyway, made before it joined, is done.
        let again = bob.cmd(&["add", "desk", &format!("--group={group}")]).await.unwrap_err().to_string();
        assert!(again.contains("desk is in this group already"), "{again}");
        let stale = Request::Added { link: link.to_owned(), group: serde_json::from_value(json!(group)).unwrap(), device: "laptop".into() };
        assert_eq!(crate::cli::call(&desk.home, &desk.handle, stale).await.unwrap(), Value::Null);

        // Two devices run a session "other": an add names one as members show it.
        desk.cmd(&["identity", "rename", "--device", "desk"]).await.unwrap();
        let _mine = world.start_in("bob", "other", HOUR).await;
        let heard = |listed: &Value| {
            let devices = listed["devices"].as_array().unwrap();
            let other = |d: &Value| d["sessions"].as_array().is_some_and(|sessions| sessions.contains(&json!("other")));
            devices.iter().all(other) && devices.iter().any(|d| d["name"] == "desk")
        };
        until(|| async { bob.cmd(&["identity", "list"]).await.unwrap() }, heard).await;
        let several = bob.cmd(&["add", "other", &format!("--group={group}")]).await.unwrap_err().to_string();
        assert!(several.contains("several of your devices run a session other"), "{several}");
        let added = bob.cmd(&["add", "desk (other)", &format!("--group={group}")]).await.unwrap();
        assert_eq!((added["device"].as_str(), added["session"].as_str()), (Some("desk"), Some("other")));
    });
}

/// An added session tells of its own join before any other event of the group, though the group changes as it joins.
#[test]
fn an_added_session_tells_of_its_join_first() {
    local(async {
        let world = world("add-first").await;
        let (alice, bob, group) = pair(&world, HOUR).await;
        let mut desk = world.start("desk", HOUR).await;
        let invite = bob.cmd(&["identity", "invite"]).await.unwrap();
        desk.cmd(&["identity", "join", invite["link"].as_str().unwrap()]).await.unwrap();
        let runs_desk = |listed: &Value| listed["devices"].as_array().unwrap().iter().any(|d| d["sessions"] == json!(["desk"]));
        until(|| async { bob.cmd(&["identity", "list"]).await.unwrap() }, runs_desk).await;
        let at = format!("--group={group}");
        let renames = tokio::task::spawn_local(async move {
            for round in 0..1000 {
                alice.cmd(&["name", &format!("round {round}"), &at]).await.ok();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        bob.cmd(&["add", "desk", &format!("--group={group}")]).await.unwrap();
        let first = desk.told(&["joined", "settings"]).await;
        renames.abort();
        assert_eq!((first["type"].as_str(), first["how"].as_str()), (Some("joined"), Some("add")), "{first}");
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
        invite.members[0] = *iroh::SecretKey::generate().public().as_bytes();
        let (home, handle) = (bob.home.clone(), bob.handle.clone());
        let join = lmk_client::Request::Join { target: invite.link(), args: Vec::new(), cwd: String::new() };
        let joining = tokio::task::spawn_local(async move { crate::cli::call(&home, &handle, Request::Client(join)).await });
        tokio::time::sleep(Duration::from_millis(500)).await;
        let started = std::time::Instant::now();
        bob.cmd(&["status"]).await.unwrap();
        alice.cmd(&["send", "@bob still there?"]).await.unwrap();
        assert_eq!(bob.expect("message").await["content"], "@bob still there?");
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
        bob.cmd(&["send", "@alice shown"]).await.unwrap();
        assert_eq!(alice.expect("message").await["content"], "before");
        assert_eq!(alice.expect("message").await["content"], "@alice shown");
        bob.cmd(&["send", "after one"]).await.unwrap();
        let last = bob.cmd(&["send", "after two"]).await.unwrap();
        // Alice holds both and, unaddressed, prints neither.
        let alice_shown = json!([format!("Alice \u{b7} {}", alice.device)]);
        let read = until(|| async { bob.cmd(&["read", last["id"].as_str().unwrap()]).await.unwrap() }, |read| read[0]["held_by"] == alice_shown).await;
        assert_eq!(read[0]["held_by"], alice_shown);
        alice.stop().await;
        let mut alice = world.start("alice", HOUR).await;
        assert_eq!(alice.expect("message").await["content"], "after one");
        assert_eq!(alice.expect("message").await["content"], "after two");
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message"));
    });
}

/// `read --ancestors` shows the latest chat messages in a message's causal past that the session delivered, before it.
#[test]
fn read_shows_the_latest_messages_in_its_causal_past() {
    local(async {
        let world = world("ancestors").await;
        let (alice, bob, _) = pair(&world, HOUR).await;
        let mut sent = Vec::new();
        for text in ["one", "two", "three"] {
            sent.push(bob.cmd(&["send", text]).await.unwrap()["id"].as_str().unwrap().to_owned());
        }
        // Alice replies to the last once she holds it: the reply's causal past is all three.
        let reply = until(|| async { alice.cmd(&["send", "--reply-to", sent[2].as_str(), "four"]).await.unwrap_or_default() }, |reply| reply["id"].is_string()).await;
        let reply = reply["id"].as_str().unwrap().to_owned();
        let ids = |read: &Value| read.as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap().to_owned()).collect::<Vec<_>>();
        let cases = [
            ("0", vec![reply.clone()]),
            ("1", vec![sent[2].clone(), reply.clone()]),
            ("5", vec![sent[0].clone(), sent[1].clone(), sent[2].clone(), reply.clone()]),
        ];
        for (n, expected) in cases {
            let read = alice.cmd(&["read", &reply, "--ancestors", n]).await.unwrap();
            assert_eq!(ids(&read), expected, "--ancestors {n}");
        }
    });
}

/// `leave` is pending until another member removes the session, and `sessions remove` finishes on that removal.
#[test]
fn a_leave_then_a_removal_finishes_on_the_removal() {
    local(async {
        let world = world("leave-remove").await;
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        alice.stop().await;
        let left = bob.cmd(&["leave"]).await.unwrap();
        assert_eq!((&left["left"], &left["pending"]), (&json!(true), &json!(true)), "{left}");
        bob.stop().await;
        let (home, config, network) = (bob.home.clone(), world.config("bob", "bob"), world.network.clone());
        let removing = tokio::task::spawn_local(async move { crate::remove(config, &home, network).await });
        // Bob's removal waits for Alice, who comes back only once the session it runs answers, and so waits for her.
        until(|| async { json!(bob.cmd(&["status"]).await.is_ok()) }, |running| *running == json!(true)).await;
        assert!(!removing.is_finished());
        let _alice = world.start("alice", HOUR).await;
        assert_eq!(removing.await.unwrap().unwrap(), json!({ "removed": "bob", "left": [group] }));
        assert_eq!(crate::sessions(&bob.home).await.unwrap(), json!({ "sessions": [] }));
    });
}

/// A home another release wrote is refused and left as it is, and the refusal names the release that wrote it.
#[test]
fn a_home_of_another_format_is_refused_and_names_its_release() {
    local(async {
        let world = world("format").await;
        for (format, names, run) in [
            ("5", "letmeknow 0.16", "@letmeknow/cli@0.16"),
            ("6", "letmeknow 0.17", "@letmeknow/cli@0.17"),
            ("8", "a newer letmeknow", "@letmeknow/cli@latest"),
        ] {
            let home = world.root.path().join(format!("format-{format}"));
            std::fs::create_dir_all(&home).unwrap();
            std::fs::write(home.join("format"), format!("{format}\n")).unwrap();
            let config = Config { dir: session_dir(&home, "alice").unwrap(), ..world.config("alice", "alice") };
            let error = crate::listen(config, &home, world.network.clone(), |_| Ok(()), std::future::pending()).await.unwrap_err().to_string();
            assert!(error.contains(names) && error.contains(run), "{error}");
            assert_eq!(std::fs::read_to_string(home.join("format")).unwrap(), format!("{format}\n"));
            assert!(!home.join("sessions").exists());
        }
    });
}

/// `ready` names a newer minor version the registry has, and the command to run it; the same minor is no news.
#[test]
fn ready_names_a_newer_minor_version_and_the_command_to_run_it() {
    local(async {
        let world = world("newer").await;
        let newer = registry(r#"{"dist-tags":{"latest":"0.19.0"}}"#, Duration::ZERO).await;
        let alice = world.launch(Config { registry: newer, ..world.config("alice", "alice") }, usize::MAX).await;
        let home = world.root.path().join("alice");
        assert_eq!(alice.ready["newer"], "0.19.0");
        assert_eq!(alice.ready["update"], format!("LETMEKNOW_HOME={} npx -y @letmeknow/cli@0.19 --session alice listen", home.display()));
        let same = registry(r#"{"dist-tags":{"latest":"0.17.4"}}"#, Duration::ZERO).await;
        let bob = world.launch(Config { registry: same, ..world.config("bob", "bob") }, usize::MAX).await;
        assert!(bob.ready.get("newer").is_none(), "{}", bob.ready);
    });
}

/// A registry that does not answer within the lookup's bound leaves `ready` without a notice, and `ready` comes once
/// the bound passes.
#[test]
fn a_slow_registry_leaves_ready_without_a_notice() {
    local(async {
        let world = world("slow").await;
        let slow = registry(r#"{"dist-tags":{"latest":"0.19.0"}}"#, Duration::from_secs(10)).await;
        let started = std::time::Instant::now();
        let alice = world.launch(Config { registry: slow, ..world.config("alice", "alice") }, usize::MAX).await;
        assert!(alice.ready.get("newer").is_none(), "{}", alice.ready);
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    });
}

/// A registry answering each request with `body` after `delay`; returns its address.
async fn registry(body: &'static str, delay: Duration) -> String {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                {
                    let mut lines = BufReader::new(&mut stream).lines();
                    while let Some(line) = lines.next_line().await.unwrap() {
                        if line.is_empty() {
                            break;
                        }
                    }
                }
                tokio::time::sleep(delay).await;
                let answer = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(answer.as_bytes()).await.unwrap();
            });
        }
    });
    address
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
        for address in ["letmeknow.dev", "a1b2@https://relay.example.com"] {
            let config = Config { membership: address.into(), ..world.config("alice", "alice") };
            let error = listen(config, world.root.path().join("alice")).await;
            assert!(error.contains("--membership <domain>"), "{error}");
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
    let served = Directory { key: [1; 32], addrs: vec![], relay: "https://relay.example".into(), relays: vec!["https://relay.example".into()] };
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
