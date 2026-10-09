//! Session processes in one test process, each its own device, talking over a local relay with a self-signed
//! certificate; their logs are in a folder. The CLI talks to them over their command channels.

use anyhow::Result;
use clap::Parser;
use iroh::tls::CaTlsConfig;
use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use lmk_core::group::Window;
use lmk_proto::group::Service;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use crate::cli::{Cli, Command, Request, session_dir};
use crate::session::Config;

const HOUR: Duration = Duration::from_secs(3600);

struct World {
    _relay: Server,
    network: crate::Network,
    root: PathBuf,
    /// For the sessions started from now on.
    causal_wait: Duration,
    window: Window,
    plugins: Vec<PathBuf>,
}

/// Where cargo builds the workspace's binaries, the doc and git plugins among them: beside this test's own directory.
fn built() -> PathBuf {
    let dir = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf();
    for kind in ["doc", "git"] {
        let plugin = dir.join(format!("letmeknow-kind-{kind}{}", std::env::consts::EXE_SUFFIX));
        assert!(plugin.exists(), "build the plugins first: cargo build -p letmeknow-kind-{kind}");
    }
    dir
}

async fn world(test: &str) -> World {
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_test_writer().try_init();
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
    let relay = format!("https://localhost:{}", server.https_addr().unwrap().port()).parse().unwrap();
    let root = std::env::temp_dir().join(format!("lmk-session-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let network = crate::Network { relay, ca: CaTlsConfig::custom_roots([cert]) };
    World { _relay: server, network, root, causal_wait: crate::session::CAUSAL_WAIT, window: Window::default(), plugins: vec![built()] }
}

struct Agent {
    handle: String,
    home: PathBuf,
    events: mpsc::UnboundedReceiver<String>,
    stop: Option<oneshot::Sender<()>>,
    done: Option<tokio::task::JoinHandle<()>>,
}

impl World {
    fn membership(&self) -> Service {
        Service::Folder(self.root.join("logs").to_str().unwrap().into())
    }

    /// A session process in its own home: its own device.
    async fn start(&self, handle: &str, hold: Duration) -> Agent {
        self.start_in(handle, handle, hold).await
    }

    /// A session process in the home `device`.
    async fn start_in(&self, device: &str, handle: &str, hold: Duration) -> Agent {
        let home = self.root.join(device);
        let config = Config {
            handle: handle.into(),
            dir: session_dir(&home, handle).unwrap(),
            name: handle[..1].to_uppercase() + &handle[1..],
            hold,
            causal_wait: self.causal_wait,
            window: self.window,
            keep_log: false,
            membership: self.membership(),
            plugins: self.plugins.clone(),
        };
        let (out, events) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel::<()>();
        let (network, at) = (self.network.clone(), home.clone());
        let done = tokio::task::spawn_local(async move {
            let print = move |line: String| drop(out.send(line));
            crate::listen(config, &at, network, print, async { drop(stopped.await) }).await.unwrap();
        });
        let mut agent = Agent { handle: handle.into(), home, events, stop: Some(stop), done: Some(done) };
        let ready = agent.expect("ready").await;
        assert_eq!(keys(&ready), keys(&json!({ "type": 0, "session": 0, "member": 0, "state": 0 })));
        agent
    }
}

impl Agent {
    async fn cmd(&self, args: &[&str]) -> Result<Value> {
        let home = self.home.to_str().unwrap();
        let base = ["letmeknow", "--home", home, "--session", self.handle.as_str()];
        let cli = Cli::try_parse_from(base.iter().chain(args))?;
        let request = match cli.command {
            Command::Request(request) => request,
            Command::Kind(mut args) => Request::Kind { kind: args.remove(0), args, cwd: String::new() },
            _ => panic!("not a request"),
        };
        crate::cli::call(&self.home, &self.handle, request).await
    }

    /// The next event of `kind`, skipping others.
    async fn expect(&mut self, kind: &str) -> Value {
        loop {
            let line = tokio::time::timeout(Duration::from_secs(30), self.events.recv())
                .await
                .unwrap_or_else(|_| panic!("{}: no {kind} event", self.handle))
                .unwrap();
            let event: Value = serde_json::from_str(&line).unwrap();
            if event["type"] == kind {
                return event;
            }
            eprintln!("{}: {event}", self.handle);
            assert_ne!(event["type"], "warning", "{event}");
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
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&runtime, test)
}

/// Alice makes a group and invites Bob, who speaks as his identity "Robert", for whom the link is meant.
async fn pair(world: &World, hold: Duration) -> (Agent, Agent, String) {
    let mut alice = world.start("alice", hold).await;
    let bob = world.start("bob", hold).await;
    alice.cmd(&["identity", "create", "Alice"]).await.unwrap();
    bob.cmd(&["identity", "create", "Robert"]).await.unwrap();
    let invite = alice.cmd(&["invite", "--for", "Bob (Acme)"]).await.unwrap();
    assert_eq!(keys(&invite), keys(&json!({ "link": 0, "group": 0, "kind": 0, "expires_in": 0, "for": 0 })));
    let link = invite["link"].as_str().unwrap();
    assert!(link.starts_with("https://letmeknow.dev/i#2.g."));
    let joined = bob.cmd(&["join", link]).await.unwrap();
    assert_eq!(joined["group"], invite["group"]);
    assert_eq!(joined["members"].as_array().unwrap().len(), 2);
    let event = alice.expect("joined").await;
    assert_eq!(event["member"]["name"], "Bob");
    assert_eq!(event["by"]["name"], "Alice");
    assert_eq!(event["how"], "invite");
    (alice, bob, invite["group"].as_str().unwrap().to_owned())
}

#[test]
fn messages_that_do_not_concern_a_session_wait_for_one_that_does() {
    local(async {
        let world = world("steer").await;
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        let sent = bob.cmd(&["send", "the build is green"]).await.unwrap();
        assert_eq!(sent["held_by"][0]["name"], "Alice");
        assert!(sent.get("pending").is_none());
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message"));
        bob.cmd(&["send", "@alice can you deploy?"]).await.unwrap();
        let first = alice.expect("message").await;
        let second = alice.expect("message").await;
        assert_eq!((first["content"].as_str(), first["direct"].as_bool()), (Some("the build is green"), Some(false)));
        assert_eq!((second["content"].as_str(), second["direct"].as_bool()), (Some("@alice can you deploy?"), Some(true)));
        assert_eq!(keys(&second), keys(&json!({ "type": 0, "group": 0, "id": 0, "from": 0, "direct": 0, "content": 0 })));
        assert_eq!(second["group"], group.as_str());
        // Bob is Alice's contact under the name the link was for, verified; his own name for himself is only a claim.
        assert_eq!(second["from"]["identity"]["name"], "Bob (Acme)");
        assert_eq!(second["from"]["identity"]["how"], "verified");
        assert_eq!(second["from"]["added_by"]["name"], "Alice");
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
        let (mut alice, bob, _) = pair(&world, Duration::from_secs(2)).await;
        bob.cmd(&["send", "fyi"]).await.unwrap();
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message"));
        assert_eq!(alice.expect("message").await["content"], "fyi");
    });
}

#[test]
fn send_reports_who_holds_a_message_or_that_it_is_pending_or_refused() {
    local(async {
        let world = world("pending").await;
        let (mut alice, mut bob, _) = pair(&world, HOUR).await;
        let big = "x".repeat(1 << 20);
        let refused = alice.cmd(&["send", "--to", "Bob", &big]).await.unwrap();
        assert_eq!(refused["refused"][0]["reason"], "size", "{refused}");
        assert_eq!(refused["refused"][0]["member"]["name"], "Bob");
        assert_eq!(refused["to"].as_array().unwrap().len(), 1);
        bob.stop().await;
        let sent = alice.cmd(&["send", "--urgent", "anyone?"]).await.unwrap();
        assert_eq!(sent["pending"], true);
        let status = alice.cmd(&["status"]).await.unwrap();
        assert_eq!(status["groups"][0]["online"], json!([]));
        assert!(status["groups"][0]["only_here"].as_array().unwrap().iter().any(|p| p["id"] == sent["id"]));
        assert!(status["warning"].is_string());
        // Once Bob is back, he takes it, and it is held here no more; what he refused still is.
        let mut bob = world.start("bob", HOUR).await;
        let message = bob.expect("message").await;
        assert_eq!(message["content"], "anyone?");
        // It comes after the message Bob refused, which shows as a known gap rather than keeping it waiting.
        assert_eq!(message["missing"], json!([refused["id"]]));
        let only_here = || async { alice.cmd(&["status"]).await.unwrap()["groups"][0]["only_here"].clone() };
        for _ in 0..20 {
            if only_here().await.as_array().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert_eq!(only_here().await[0]["id"], refused["id"]);
        assert!(alice.printed().await.iter().all(|e| e["type"] != "warning" && e["type"] != "refused"), "send told of the refusal");
    });
}

#[test]
fn an_attachment_arrives_as_a_private_file() {
    local(async {
        let world = world("attach").await;
        let (mut alice, bob, _) = pair(&world, HOUR).await;
        let file = world.root.join("token.txt");
        std::fs::write(&file, "s3cret").unwrap();
        let sent = bob.cmd(&["send", "--to", "Alice", "--attach", file.to_str().unwrap(), "the token"]).await.unwrap();
        assert_eq!(sent["attachment"]["held_by"][0]["name"], "Alice");
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
        std::fs::create_dir_all(&world.root).unwrap();
        let plan = world.root.join("plan.md");
        std::fs::write(&plan, "- [ ] alpha\n- [ ] beta\n").unwrap();
        let invite = alice.cmd(&["invite", "--kind", "doc", "--name", "Plan", plan.to_str().unwrap()]).await.unwrap();
        assert_eq!(invite["file"], plan.to_str().unwrap());
        let theirs = world.root.join("bob-plan.md");
        let joined = bob.cmd(&["join", invite["link"].as_str().unwrap(), theirs.to_str().unwrap()]).await.unwrap();
        assert_eq!(joined["kind"], "doc");
        alice.expect("joined").await;
        // The doc's text arrives a moment later, from whoever admitted Bob; a command prints what waits.
        for _ in 0..40 {
            bob.cmd(&["groups"]).await.unwrap();
            if std::fs::read_to_string(&theirs).unwrap().contains("alpha") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let edited = bob.expect("edited").await;
        assert_eq!(edited["by"][0]["name"], "Alice");
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "- [ ] alpha\n- [ ] beta\n");
        // Bob ticks a line and adds one that mentions Alice; Alice meanwhile changes another.
        std::fs::write(&theirs, "- [x] alpha\n- [ ] beta\n- [ ] gamma @alice\n").unwrap();
        std::fs::write(&plan, "- [ ] alpha\n- [ ] beta (Tuesday)\n").unwrap();
        let edited = alice.expect("edited").await;
        assert_eq!(keys(&edited), keys(&json!({ "type": 0, "group": 0, "file": 0, "by": 0, "lines": 0, "direct": 0 })));
        assert_eq!(edited["by"][0]["name"], "Bob");
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
        let attached = world.root.join("chart.png");
        std::fs::write(&attached, b"\x89PNG....").unwrap();
        let link = alice.cmd(&["doc", "attach", attached.to_str().unwrap()]).await.unwrap();
        assert!(link["markdown"].as_str().unwrap().starts_with("![chart.png](lmk:"));
    });
}

#[test]
fn membership_changes_wake_and_a_removed_session_is_told() {
    local(async {
        let world = world("remove").await;
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        let named = alice.cmd(&["name", "Release"]).await.unwrap();
        assert_eq!(named["settings"]["name"], "Release");
        let settings = bob.expect("settings").await;
        assert_eq!((settings["settings"]["name"].as_str(), settings["by"]["name"].as_str()), (Some("Release"), Some("Alice")));
        let members = bob.cmd(&["members", "--group", "Release"]).await.unwrap();
        let names: Vec<&str> = members["members"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["Alice", "Bob"]);
        assert_eq!(members["members"][1]["you"], true);
        assert!(alice.cmd(&["remove", "Carol"]).await.is_err());
        alice.cmd(&["remove", "Bob"]).await.unwrap();
        let left = alice.expect("left").await;
        assert_eq!(left["member"]["name"], "Bob");
        let removed = bob.expect("removed").await;
        assert_eq!((removed["group"].as_str(), removed["by"]["name"].as_str()), (Some(group.as_str()), Some("Alice")));
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
        bob.expect("removed").await;
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
        assert_eq!(alice.expect("left").await["member"]["name"], "Bob");
        bob.expect("removed").await;
    });
}

#[test]
fn introductions_are_shown_until_accepted() {
    local(async {
        let world = world("introduce").await;
        let (alice, _bob, group) = pair(&world, HOUR).await;
        let mut carol = world.start("carol", HOUR).await;
        carol.cmd(&["identity", "create", "Carol"]).await.unwrap();
        assert!(alice.cmd(&["invite", "--group", "x"]).await.is_err());
        let mut dave = world.start("dave", HOUR).await;
        dave.cmd(&["identity", "create", "Dave"]).await.unwrap();
        for joiner in [&carol, &dave] {
            let invite = alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap();
            joiner.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        }
        let introduced = alice.cmd(&["introduce", "Bob", "--to", "Carol"]).await.unwrap();
        assert_eq!(introduced["identity"]["name"], "Bob (Acme)");
        let bob_seen = || async {
            let members = carol.cmd(&["members"]).await.unwrap();
            members["members"].as_array().unwrap().iter().find(|m| m["name"] == "Bob").unwrap().clone()
        };
        for _ in 0..40 {
            if bob_seen().await["identity"]["introduced"].is_array() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let bob_seen = bob_seen().await;
        let mut event = carol.expect("introduced").await;
        while event["how"] != "introduce" {
            event = carol.expect("introduced").await;
        }
        assert_eq!((event["by"]["name"].as_str(), event["how"].as_str()), (Some("Alice"), Some("introduce")));
        assert_eq!(bob_seen["identity"]["how"], "unknown");
        assert_eq!(bob_seen["identity"]["name"], "Robert");
        assert_eq!(bob_seen["identity"]["claim"], true);
        assert_eq!(bob_seen["identity"]["introduced"][0]["by"]["name"], "Alice");
        assert_eq!(bob_seen["identity"]["introduced"][0]["name"], "Bob (Acme)");
        // Dave, to whom Alice did not introduce Bob, ignores it.
        assert_eq!(dave.cmd(&["contacts"]).await.unwrap()["introductions"], json!([]));
        assert!(dave.printed().await.iter().all(|e| e["type"] != "introduced" || e["how"] != "introduce"));
        let contacts = carol.cmd(&["contacts"]).await.unwrap();
        let introductions = contacts["introductions"].as_array().unwrap();
        let id = introductions.iter().find(|i| i["name"] == "Bob (Acme)").unwrap()["identity"].as_str().unwrap().to_owned();
        carol.cmd(&["contacts", "accept", "--", &id]).await.unwrap();
        let members = carol.cmd(&["members"]).await.unwrap();
        let bob_seen = members["members"].as_array().unwrap().iter().find(|m| m["name"] == "Bob").unwrap().clone();
        assert_eq!((bob_seen["identity"]["how"].as_str(), bob_seen["identity"]["name"].as_str()), (Some("introduced"), Some("Bob (Acme)")));
        assert!(carol.cmd(&["send", "--to", "Bob (Acme)", "hi"]).await.is_ok());
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
        assert_eq!(crate::cli::running_session(&alice.home).await.unwrap(), "alice");
        let missing = Agent { handle: "nobody".into(), home: alice.home.clone(), events: mpsc::unbounded_channel().1, stop: None, done: None };
        let error = missing.cmd(&["groups"]).await.unwrap_err().to_string();
        assert!(error.contains("not running"), "{error}");
    });
}

#[test]
fn a_restarted_session_takes_in_what_it_missed_in_causal_order() {
    local(async {
        let world = world("causal").await;
        let (mut alice, bob, group) = pair(&world, HOUR).await;
        alice.stop().await;
        let first = bob.cmd(&["send", "--urgent", "first"]).await.unwrap();
        assert_eq!(first["pending"], true);
        let second = bob.cmd(&["send", "--urgent", "second"]).await.unwrap();
        let bob_renamed = bob.cmd(&["name", "Later"]).await.unwrap();
        assert_eq!(bob_renamed["settings"]["name"], "Later");
        let mut alice = world.start("alice", HOUR).await;
        let mut got = Vec::new();
        while got.len() < 2 {
            let message = alice.expect("message").await;
            assert!(message.get("missing").is_none());
            got.push(message["id"].as_str().unwrap().to_owned());
        }
        assert_eq!(got, [first["id"].as_str().unwrap(), second["id"].as_str().unwrap()]);
        let groups = alice.cmd(&["groups"]).await.unwrap();
        assert_eq!((groups[0]["group"].as_str(), groups[0]["name"].as_str()), (Some(group.as_str()), Some("Later")));
    });
}

#[test]
fn a_member_back_past_its_key_window_reports_what_it_missed_and_the_sender_resends_it() {
    local(async {
        let mut world = world("old").await;
        let (mut alice, mut bob, _) = pair(&world, HOUR).await;
        bob.stop().await;
        let file = world.root.join("notes.txt");
        std::fs::write(&file, "the notes").unwrap();
        let sent = alice.cmd(&["send", "--attach", file.to_str().unwrap(), "while you were away"]).await.unwrap();
        assert_eq!(sent["pending"], true);
        for name in ["one", "two", "three"] {
            alice.cmd(&["name", name]).await.unwrap();
        }
        // Bob keeps the keys of one ended epoch: Alice's message is below his floor when he is back.
        world.window = Window { epochs: 1, ..Window::default() };
        let mut bob = world.start("bob", HOUR).await;
        let refused = alice.expect("refused").await;
        assert_eq!(refused["member"]["name"], "Bob");
        let id = sent["id"].as_str().unwrap();
        let message = &refused["messages"][0];
        assert_eq!((message["id"].as_str(), message["reason"].as_str(), message["content"].as_str()), (Some(id), Some("old"), Some("while you were away")));
        let path = message["attachment"]["path"].as_str().unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "the notes");
        let resent = alice.cmd(&["send", "--reply-to", id, "--attach", path, "while you were away"]).await.unwrap();
        assert_eq!(resent["held_by"][0]["name"], "Bob");
        let message = bob.expect("message").await;
        assert_eq!((message["reply_to"].as_str(), message["content"].as_str()), (Some(id), Some("while you were away")));
        assert_eq!(message["missing"], json!([id]), "a known gap, not a wait");
    });
}

#[test]
fn a_session_of_an_identity_joins_a_group_open_to_it() {
    local(async {
        let world = world("open").await;
        let (mut alice, bob, group) = pair(&world, HOUR).await;
        let tablet = world.start("tablet", HOUR).await;
        let link = bob.cmd(&["invite", "--identity", "Robert"]).await.unwrap();
        assert!(link["link"].as_str().unwrap().contains("#2.d."));
        assert!(tablet.cmd(&["join", link["link"].as_str().unwrap()]).await.unwrap()["device"].is_string());
        let opened = alice.cmd(&["open", "Bob (Acme)"]).await.unwrap();
        assert_eq!(opened["settings"]["open"][0]["name"], "Bob (Acme)");
        let mut groups = tablet.cmd(&["groups"]).await.unwrap();
        for _ in 0..40 {
            if groups.as_array().unwrap().iter().any(|g| g["group"] == group.as_str()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            groups = tablet.cmd(&["groups"]).await.unwrap();
        }
        assert_eq!(groups[0]["joined"], false, "{groups}");
        let joined = tablet.cmd(&["join", "--", &group]).await.unwrap();
        assert_eq!(joined["members"].as_array().unwrap().len(), 3);
        let event = alice.expect("joined").await;
        assert_eq!((event["member"]["identity"]["name"].as_str(), event["how"].as_str()), (Some("Bob (Acme)"), Some("open")));
        assert!(event["member"]["identity"]["new_device"].as_str().unwrap().starts_with("added by "));
        // A session of another identity cannot see the group, so it cannot join it.
        let carol = world.start("carol", HOUR).await;
        let refused = carol.cmd(&["join", "--", &group]).await.unwrap_err().to_string();
        assert!(refused.contains("open to your identity"), "{refused}");
    });
}

#[test]
fn a_link_for_one_identity_admits_no_other() {
    local(async {
        let world = world("to").await;
        let (alice, bob, _) = pair(&world, HOUR).await;
        let invite = alice.cmd(&["invite", "--to", "Bob (Acme)"]).await.unwrap();
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
fn identities_are_created_listed_and_lose_devices() {
    local(async {
        let world = world("identity").await;
        let alice = world.start("alice", HOUR).await;
        let created = alice.cmd(&["identity", "create", "Alice Smith"]).await.unwrap();
        assert_eq!(created["name"], "Alice Smith");
        let listed = alice.cmd(&["identity", "list"]).await.unwrap();
        assert_eq!(listed["identities"][0]["devices"][0]["you"], true);
        assert_eq!(listed["identities"][0]["name"], "Alice Smith");
        let invite = alice.cmd(&["invite", "--identity", "Alice Smith"]).await.unwrap();
        assert!(invite["link"].as_str().unwrap().contains("#2.d."));
        let phone = world.start("phone", HOUR).await;
        let joined = phone.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        assert!(joined["device"].is_string());
        assert_eq!(phone.cmd(&["identity", "list"]).await.unwrap()["identities"][0]["name"], "Alice Smith");
        let listed = alice.cmd(&["identity", "list"]).await.unwrap();
        let devices = listed["identities"][0]["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 2);
        let phone_key = devices.iter().find(|d| d["you"] == false).unwrap()["key"].as_str().unwrap().to_owned();
        alice.cmd(&["identity", "remove", "--", &phone_key]).await.unwrap();
        let listed = alice.cmd(&["identity", "list"]).await.unwrap();
        assert_eq!(listed["identities"][0]["devices"].as_array().unwrap().len(), 1);
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
        std::fs::create_dir_all(&world.root).unwrap();
        let (plan, theirs) = (world.root.join("plan.md"), world.root.join("bob-plan.md"));
        std::fs::write(&plan, "- [ ] alpha\n").unwrap();
        let invite = alice.cmd(&["invite", "--kind", "doc", plan.to_str().unwrap()]).await.unwrap();
        bob.cmd(&["join", invite["link"].as_str().unwrap(), theirs.to_str().unwrap()]).await.unwrap();
        alice.expect("joined").await;
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
        let invite = alice.cmd(&["invite", "--kind", "doc"]).await.unwrap();
        let error = bob.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap_err();
        assert!(format!("{error:#}").contains("does not support doc groups"), "{error:#}");
        let error = bob.cmd(&["invite", "--kind", "doc"]).await.unwrap_err();
        assert!(format!("{error:#}").contains("no plugin for doc groups"), "{error:#}");
        let error = bob.cmd(&["doc", "attach", "x"]).await.unwrap_err();
        assert!(format!("{error:#}").contains("no plugin for doc groups"), "{error:#}");
        // Alice's plugin answers her doc's commands, and refuses those it does not know.
        let error = alice.cmd(&["doc", "frobnicate"]).await.unwrap_err();
        assert!(format!("{error:#}").contains("usage: letmeknow doc attach"), "{error:#}");
        let readme = world.root.join("readme.txt");
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
        use lmk_kind_doc::ydoc;
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
        assert_eq!(first.cmd(&["identity", "list"]).await.unwrap()["identities"][0]["name"], "Alice");
        let bob = world.start("bob", HOUR).await;
        bob.cmd(&["identity", "create", "Robert"]).await.unwrap();
        let invite = second.cmd(&["invite", "--for", "Bob (Acme)"]).await.unwrap();
        bob.cmd(&["join", invite["link"].as_str().unwrap()]).await.unwrap();
        second.expect("joined").await;
        for agent in [&first, &second] {
            let contacts = agent.cmd(&["contacts"]).await.unwrap();
            assert_eq!(contacts["contacts"][0]["name"], "Bob (Acme)", "{contacts}");
        }
        let members = second.cmd(&["members"]).await.unwrap();
        let bob_seen = members["members"].as_array().unwrap().iter().find(|m| m["name"] == "Bob").unwrap().clone();
        assert_eq!(bob_seen["identity"]["how"], "verified");
        // An opening the second records reaches the first.
        second.cmd(&["open", "Alice"]).await.unwrap();
        let groups = first.cmd(&["groups"]).await.unwrap();
        assert_eq!((groups[0]["group"].as_str(), groups[0]["joined"].as_bool()), (invite["group"].as_str(), Some(false)));
        // Once the first stops, the second acts for the device.
        first.stop().await;
        let mut listed = second.cmd(&["identity", "list"]).await;
        for _ in 0..60 {
            if listed.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            listed = second.cmd(&["identity", "list"]).await;
        }
        assert_eq!(listed.unwrap()["identities"][0]["name"], "Alice");
        assert!(second.printed().await.iter().all(|e| e["type"] != "warning"));
    });
}

#[test]
fn a_message_after_some_from_before_its_reader_joined_shows_them_missing_at_once() {
    local(async {
        let world = world("before").await;
        let (alice, mut bob, group) = pair(&world, HOUR).await;
        let before = alice.cmd(&["send", "@bob before carol"]).await.unwrap();
        bob.expect("message").await;
        let mut carol = world.start("carol", HOUR).await;
        carol.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        // Alice's Welcome named her message, so Bob's, which comes after it, does not wait for it.
        bob.cmd(&["send", "@carol see above"]).await.unwrap();
        let got = carol.expect("message").await;
        assert_eq!(got["content"], "@carol see above");
        assert_eq!(got["missing"], json!([before["id"]]));
    });
}

#[test]
fn a_message_waits_for_those_it_comes_after_then_shows_them_missing() {
    local(async {
        let mut world = world("wait").await;
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        // Bob writes while Alice is away, and leaves before she is back, so her Welcome to Carol cannot name it.
        alice.stop().await;
        let unseen = bob.cmd(&["send", "while alice is away"]).await.unwrap();
        bob.stop().await;
        let alice = world.start("alice", HOUR).await;
        world.causal_wait = Duration::from_secs(2);
        let mut carol = world.start("carol", HOUR).await;
        carol.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        let bob = world.start("bob", HOUR).await;
        // Once Bob and Carol have synced, no sync ends before the wait does.
        for _ in 0..40 {
            let online = bob.cmd(&["status"]).await.unwrap()["groups"][0]["online"].clone();
            if online.as_array().unwrap().iter().any(|member| member["name"] == "Carol") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let sent = std::time::Instant::now();
        bob.cmd(&["send", "@carol see above"]).await.unwrap();
        let got = carol.expect("message").await;
        assert!(sent.elapsed() >= Duration::from_millis(1500), "{:?}", sent.elapsed());
        assert_eq!(got["content"], "@carol see above");
        assert_eq!(got["missing"], json!([unseen["id"]]));
    });
}

#[test]
fn a_message_after_one_that_cannot_come_shows_the_gap_once_a_sync_ends() {
    local(async {
        let world = world("gap").await;
        let (mut alice, mut bob, group) = pair(&world, HOUR).await;
        alice.stop().await;
        let unseen = bob.cmd(&["send", "while alice is away"]).await.unwrap();
        bob.stop().await;
        let alice = world.start("alice", HOUR).await;
        let mut carol = world.start("carol", HOUR).await;
        carol.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
        carol.stop().await;
        let bob = world.start("bob", HOUR).await;
        bob.cmd(&["send", "@carol see above"]).await.unwrap();
        // Back, Carol syncs; that cannot bring Bob's first message, from before she joined, so she does not wait 5 minutes.
        let mut carol = world.start("carol", HOUR).await;
        let got = carol.expect("message").await;
        assert_eq!(got["content"], "@carol see above");
        assert_eq!(got["missing"], json!([unseen["id"]]));
    });
}

/// git, as the git plugin's caller runs it, in `repo`.
fn git(repo: &Path, args: &[&str]) -> String {
    let config = ["-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "init.defaultBranch=main"];
    let out = std::process::Command::new("git").arg("-C").arg(repo).args(config).args(args).output().unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
fn a_removed_member_cannot_stall_a_git_groups_log() {
    local(async {
        let world = world("git").await;
        let mut alice = world.start("alice", HOUR).await;
        let bob = world.start("bob", HOUR).await;
        let mut carol = world.start("carol", HOUR).await;
        let group = alice.cmd(&["invite", "--kind", "git", "--name", "Repo"]).await.unwrap()["group"].as_str().unwrap().to_owned();
        for joiner in [&bob, &carol] {
            joiner.cmd(&["join", alice.cmd(&["invite", &format!("--group={group}")]).await.unwrap()["link"].as_str().unwrap()]).await.unwrap();
            alice.expect("joined").await;
        }
        let repo = world.root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        let push = async |old: &str, n: u32| {
            std::fs::write(repo.join("file.txt"), n.to_string()).unwrap();
            git(&repo, &["add", "file.txt"]);
            git(&repo, &["commit", "-qm", &format!("change {n}")]);
            let (new, bundle) = (git(&repo, &["rev-parse", "HEAD"]), world.root.join(format!("{n}.bundle")));
            let range = if old == "-" { "main".to_owned() } else { format!("{old}..main") };
            git(&repo, &["bundle", "create", bundle.to_str().unwrap(), &range]);
            let pushed = alice.cmd(&["git", "push", &group, "refs/heads/main", old, &new, bundle.to_str().unwrap()]).await.unwrap();
            for _ in 0..80 {
                if bob.cmd(&["git", "list", &group]).await.is_ok_and(|list| list["refs"]["refs/heads/main"] == new.as_str()) {
                    return (new, pushed["position"].clone());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            panic!("bob did not take push {n}");
        };
        let (first, position) = push("-", 1).await;
        assert_eq!(position, 1);

        // Alice removes Carol, who still knows the id of the log the group's pushes were ordered in, and appends to it an
        // id of a message no member holds. The order went on in a new log, after the last push.
        let members = alice.cmd(&["members"]).await.unwrap();
        let fp = members["members"].as_array().unwrap().iter().find(|m| m["name"] == "Carol").unwrap()["fp"].as_str().unwrap().to_owned();
        alice.cmd(&["remove", &fp]).await.unwrap();
        carol.expect("removed").await;
        let entries = |dir: &Path| std::fs::read_dir(dir).unwrap().flatten().map(|entry| std::fs::read(entry.path()).unwrap()).collect::<Vec<_>>();
        let logs = std::fs::read_dir(world.root.join("logs")).unwrap().flatten().map(|dir| dir.path());
        let old = logs.filter(|dir| entries(dir).iter().any(|entry| entry == b"end")).collect::<Vec<_>>();
        assert_eq!(old.len(), 1, "the removal ended the old log");
        let next = entries(&old[0]).len() + 1;
        std::fs::write(old[0].join(format!("{next}.entry")), [9; 32]).unwrap();
        let (_, position) = push(&first, 2).await;
        assert_eq!(position, 2, "the order goes on where the old log ended");
    });
}
