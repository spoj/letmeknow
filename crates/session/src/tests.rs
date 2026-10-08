//! The CLI talking to running sessions over their command channels, with the test doubles behind the traits.

use anyhow::Result;
use clap::Parser;
use lmk_proto::Bytes;
use lmk_proto::group::{IdentityRef, Service};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use crate::cli::{Cli, Command, session_dir};
use crate::fake::{Shared, World, member, set_online};
use crate::node::Member;
use crate::session::Config;

struct Agent {
    handle: String,
    member: Member,
    events: mpsc::UnboundedReceiver<String>,
    _stop: oneshot::Sender<()>,
}

fn home(test: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("lmk-session-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    home
}

fn identity() -> IdentityRef {
    IdentityRef { id: Bytes(rand::random::<[u8; 32]>().to_vec()), membership: Service::Folder("/tmp/lmk-test".into()) }
}

async fn start(world: &Shared, home: &Path, handle: &str, me: Member, hold: Duration) -> Agent {
    let config = Config {
        handle: handle.into(),
        dir: session_dir(home, handle).unwrap(),
        name: me.name.clone(),
        hold,
        keep_log: false,
        membership: Service::Folder("/tmp/lmk-test".into()),
    };
    let (out, events) = mpsc::unbounded_channel();
    let (stop, stopped) = oneshot::channel::<()>();
    let (world, joining) = (world.clone(), me.clone());
    tokio::task::spawn_local(async move {
        let parts = move |_: &Config, inbound| {
            let parts = World::join(&world, joining.clone(), inbound);
            let mut node = world.lock().unwrap();
            let node = node.nodes.get_mut(&joining.iroh).unwrap();
            node.identities.extend(joining.identity.map(|c| (c.identity, c.name)));
            Ok(parts)
        };
        let print = move |line: String| drop(out.send(line));
        crate::listen(config, parts, print, async { drop(stopped.await) }).await.unwrap();
    });
    let mut agent = Agent { handle: handle.into(), member: me, events, _stop: stop };
    let ready = agent.expect("ready").await;
    assert_eq!(keys(&ready), keys(&serde_json::json!({ "type": 0, "session": 0, "member": 0, "state": 0 })));
    agent
}

async fn cmd(home: &Path, agent: &Agent, args: &[&str]) -> Result<Value> {
    let home_arg = home.to_str().unwrap();
    let base = ["letmeknow", "--home", home_arg, "--session", agent.handle.as_str()];
    let cli = Cli::try_parse_from(base.iter().chain(args))?;
    let Command::Request(request) = cli.command else { panic!("not a request") };
    crate::cli::call(home, &agent.handle, request).await
}

impl Agent {
    /// The next event of `kind`, skipping others.
    async fn expect(&mut self, kind: &str) -> Value {
        loop {
            let line = tokio::time::timeout(Duration::from_secs(8), self.events.recv()).await.expect("an event").unwrap();
            let event: Value = serde_json::from_str(&line).unwrap();
            if event["type"] == kind {
                return event;
            }
            assert_ne!(event["type"], "warning", "{event}");
        }
    }

    /// What was printed, after a moment for what is on its way.
    async fn printed(&mut self) -> Vec<Value> {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut printed = Vec::new();
        while let Ok(line) = self.events.try_recv() {
            printed.push(serde_json::from_str(&line).unwrap());
        }
        printed
    }
}

fn keys(value: &Value) -> BTreeSet<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

/// Alice makes a group and invites Bob, for whom the link is meant.
async fn pair(test: &str, hold: Duration) -> (Shared, PathBuf, Agent, Agent, String) {
    let (world, home) = (Shared::default(), home(test));
    let mut alice = start(&world, &home, "alice", member("Alice", None, ""), hold).await;
    let bob = start(&world, &home, "bob", member("Bob", Some(identity()), "Robert"), hold).await;
    let invite = cmd(&home, &alice, &["invite", "--for", "Bob (Acme)"]).await.unwrap();
    assert_eq!(keys(&invite), keys(&serde_json::json!({ "link": 0, "group": 0, "kind": 0, "expires_in": 0, "for": 0 })));
    let link = invite["link"].as_str().unwrap();
    assert!(link.starts_with("https://letmeknow.dev/i#1.g."));
    let joined = cmd(&home, &bob, &["join", link]).await.unwrap();
    assert_eq!(joined["group"], invite["group"]);
    assert_eq!(joined["members"].as_array().unwrap().len(), 2);
    let event = alice.expect("joined").await;
    assert_eq!(event["member"]["name"], "Bob");
    assert_eq!(event["by"]["name"], "Alice");
    assert_eq!(event["how"], "invite");
    (world, home, alice, bob, invite["group"].as_str().unwrap().to_owned())
}

fn local<F: std::future::Future>(test: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&runtime, test)
}

#[test]
fn messages_that_do_not_concern_a_session_wait_for_one_that_does() {
    local(async {
        let (_world, home, mut alice, bob, group) = pair("steer", Duration::from_secs(3600)).await;
        let sent = cmd(&home, &bob, &["send", "the build is green"]).await.unwrap();
        assert_eq!(sent["held_by"][0]["name"], "Alice");
        assert!(sent.get("pending").is_none());
        assert!(alice.printed().await.iter().all(|e| e["type"] != "message"));
        cmd(&home, &bob, &["send", "@alice can you deploy?"]).await.unwrap();
        let first = alice.expect("message").await;
        let second = alice.expect("message").await;
        assert_eq!((first["content"].as_str(), first["direct"].as_bool()), (Some("the build is green"), Some(false)));
        assert_eq!((second["content"].as_str(), second["direct"].as_bool()), (Some("@alice can you deploy?"), Some(true)));
        assert_eq!(keys(&second), keys(&serde_json::json!({ "type": 0, "group": 0, "id": 0, "from": 0, "direct": 0, "content": 0 })));
        assert_eq!(second["group"], group.as_str());
        // Bob is Alice's contact under the name the link was for, verified; his own name for himself is only a claim.
        assert_eq!(second["from"]["identity"]["name"], "Bob (Acme)");
        assert_eq!(second["from"]["identity"]["how"], "verified");
        assert_eq!(second["from"]["added_by"]["name"], "Alice");
        // The read frontier: Alice's answer comes after what she was shown, and a reply to Bob wakes him.
        let id = second["id"].as_str().unwrap();
        let answer = cmd(&home, &alice, &["send", "--reply-to", id, "on it"]).await.unwrap();
        let read = cmd(&home, &alice, &["read", answer["id"].as_str().unwrap(), "--ancestors", "2"]).await.unwrap();
        let read: Vec<&str> = read.as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
        assert_eq!(read.len(), 3);
        assert_eq!(read[2], answer["id"].as_str().unwrap());
        let mut bob = bob;
        let reply = bob.expect("message").await;
        assert_eq!(reply["reply_to"], id);
        // Shown text is forgotten.
        let read = cmd(&home, &alice, &["read", id]).await.unwrap();
        assert!(read[0]["content"].is_null());
    });
}

#[test]
fn held_messages_print_once_the_hold_runs_out() {
    local(async {
        let (_world, home, mut alice, bob, _) = pair("hold", Duration::from_secs(1)).await;
        cmd(&home, &bob, &["send", "fyi"]).await.unwrap();
        assert!(alice.printed().await.is_empty());
        assert_eq!(alice.expect("message").await["content"], "fyi");
    });
}

#[test]
fn send_reports_who_holds_a_message_or_that_it_is_pending_or_refused() {
    local(async {
        let (world, home, mut alice, bob, _) = pair("pending", Duration::from_secs(3600)).await;
        set_online(&world, &bob.member, false).unwrap();
        let sent = cmd(&home, &alice, &["send", "anyone?"]).await.unwrap();
        assert_eq!(sent["pending"], true);
        let status = cmd(&home, &alice, &["status"]).await.unwrap();
        assert_eq!(status["groups"][0]["online"], serde_json::json!([]));
        assert_eq!(status["groups"][0]["only_here"][0]["id"], sent["id"]);
        assert!(status["warning"].is_string());
        set_online(&world, &bob.member, true).unwrap();
        world.lock().unwrap().refuse.insert(bob.member.iroh.clone(), "too large".into());
        let sent = cmd(&home, &alice, &["send", "--to", "Bob", "big"]).await.unwrap();
        assert_eq!(sent["refused"][0]["reason"], "too large");
        assert_eq!(sent["refused"][0]["member"]["name"], "Bob");
        assert_eq!(sent["to"].as_array().unwrap().len(), 1);
        assert!(alice.printed().await.iter().all(|e| e["type"] != "warning"));
    });
}

#[test]
fn an_attachment_is_pending_until_its_file_arrives() {
    local(async {
        let (world, home, mut alice, bob, _) = pair("attach", Duration::from_secs(3600)).await;
        world.lock().unwrap().hold_files = true;
        let file = home.join("token.txt");
        std::fs::write(&file, "s3cret").unwrap();
        let sent = cmd(&home, &bob, &["send", "--to", "Alice", "--attach", file.to_str().unwrap(), "the token"]).await.unwrap();
        assert_eq!(sent["attachment"]["pending"], true);
        let message = alice.expect("message").await;
        assert_eq!(message["attachment"]["pending"], true);
        assert_eq!(message["attachment"]["name"], "token.txt");
        assert!(message["attachment"]["link"].as_str().unwrap().starts_with("lmk:"));
        World::release_files(&world);
        let arrived = alice.expect("attachment").await;
        assert_eq!(keys(&arrived), keys(&serde_json::json!({ "type": 0, "group": 0, "message": 0, "name": 0, "path": 0 })));
        assert_eq!(arrived["message"], message["id"]);
        let path = arrived["path"].as_str().unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "s3cret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let fetched = cmd(&home, &alice, &["fetch", message["attachment"]["link"].as_str().unwrap()]).await.unwrap();
        assert_eq!(fetched["bytes"], 6);
    });
}

#[test]
fn a_doc_is_a_file_that_others_edit_too() {
    local(async {
        let (world, home) = (Shared::default(), home("doc"));
        let mut alice = start(&world, &home, "alice", member("Alice", None, ""), Duration::from_secs(3600)).await;
        let mut bob = start(&world, &home, "bob", member("Bob", None, ""), Duration::from_secs(3600)).await;
        let plan = home.join("plan.md");
        std::fs::write(&plan, "- [ ] alpha\n- [ ] beta\n").unwrap();
        let invite = cmd(&home, &alice, &["invite", "--kind", "doc", "--name", "Plan", plan.to_str().unwrap()]).await.unwrap();
        assert_eq!(invite["file"], plan.to_str().unwrap());
        let theirs = home.join("bob-plan.md");
        let joined = cmd(&home, &bob, &["join", invite["link"].as_str().unwrap(), theirs.to_str().unwrap()]).await.unwrap();
        assert_eq!(joined["kind"], "doc");
        alice.expect("joined").await;
        // The doc's text arrives a moment later, from whoever admitted Bob.
        cmd(&home, &bob, &["groups"]).await.unwrap();
        let edited = bob.expect("edited").await;
        assert_eq!(edited["by"][0]["name"], "Alice");
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "- [ ] alpha\n- [ ] beta\n");
        // Bob ticks a line and adds one that mentions Alice; Alice meanwhile changes another.
        std::fs::write(&theirs, "- [x] alpha\n- [ ] beta\n- [ ] gamma @alice\n").unwrap();
        std::fs::write(&plan, "- [ ] alpha\n- [ ] beta (Tuesday)\n").unwrap();
        let edited = alice.expect("edited").await;
        assert_eq!(keys(&edited), keys(&serde_json::json!({ "type": 0, "group": 0, "file": 0, "by": 0, "lines": 0, "direct": 0 })));
        assert_eq!(edited["by"][0]["name"], "Bob");
        assert_eq!(edited["direct"], true);
        assert_eq!(std::fs::read_to_string(&plan).unwrap(), "- [x] alpha\n- [ ] beta (Tuesday)\n- [ ] gamma @alice\n");
        // Bob's edit to a line was not to the line Alice changed, so nothing is lost; his file gets her change.
        cmd(&home, &bob, &["groups"]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        cmd(&home, &bob, &["groups"]).await.unwrap();
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "- [x] alpha\n- [ ] beta (Tuesday)\n- [ ] gamma @alice\n");
        assert!(bob.printed().await.iter().all(|e| e["type"] != "warning"));
        let attached = home.join("chart.png");
        std::fs::write(&attached, b"\x89PNG....").unwrap();
        let link = cmd(&home, &alice, &["attach", attached.to_str().unwrap()]).await.unwrap();
        assert!(link["markdown"].as_str().unwrap().starts_with("![chart.png](lmk:"));
    });
}

#[test]
fn membership_changes_wake_and_a_removed_session_is_told() {
    local(async {
        let (_world, home, mut alice, mut bob, group) = pair("remove", Duration::from_secs(3600)).await;
        let named = cmd(&home, &alice, &["name", "Release"]).await.unwrap();
        assert_eq!(named["settings"]["name"], "Release");
        let settings = bob.expect("settings").await;
        assert_eq!((settings["settings"]["name"].as_str(), settings["by"]["name"].as_str()), (Some("Release"), Some("Alice")));
        let members = cmd(&home, &bob, &["members", "--group", "Release"]).await.unwrap();
        let names: Vec<&str> = members["members"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["Alice", "Bob"]);
        assert_eq!(members["members"][1]["you"], true);
        assert!(cmd(&home, &alice, &["remove", "Carol"]).await.is_err());
        cmd(&home, &alice, &["remove", "Bob"]).await.unwrap();
        let left = alice.expect("left").await;
        assert_eq!(left["member"]["name"], "Bob");
        let removed = bob.expect("removed").await;
        assert_eq!((removed["group"].as_str(), removed["by"]["name"].as_str()), (Some(group.as_str()), Some("Alice")));
        assert_eq!(cmd(&home, &bob, &["groups"]).await.unwrap(), serde_json::json!([]));
    });
}

#[test]
fn a_leaving_member_is_removed_by_another() {
    local(async {
        let (_world, home, mut alice, mut bob, _) = pair("leave", Duration::from_secs(3600)).await;
        let left = cmd(&home, &bob, &["leave"]).await.unwrap();
        assert_eq!(left["left"], true);
        assert_eq!(alice.expect("left").await["member"]["name"], "Bob");
        bob.expect("removed").await;
    });
}

#[test]
fn introductions_are_shown_until_accepted() {
    local(async {
        let (world, home, alice, bob, _) = pair("introduce", Duration::from_secs(3600)).await;
        let mut carol = start(&world, &home, "carol", member("Carol", None, ""), Duration::from_secs(3600)).await;
        let invite = cmd(&home, &alice, &["invite", "--group", "x"]).await;
        assert!(invite.is_err());
        let groups = cmd(&home, &alice, &["groups"]).await.unwrap();
        let group = groups[0]["group"].as_str().unwrap();
        let invite = cmd(&home, &alice, &["invite", "--group", group]).await.unwrap();
        cmd(&home, &carol, &["join", invite["link"].as_str().unwrap()]).await.unwrap();
        let introduced = cmd(&home, &alice, &["introduce", "Bob", "--to", "Carol"]).await.unwrap();
        assert_eq!(introduced["identity"]["name"], "Bob (Acme)");
        let members = cmd(&home, &carol, &["members"]).await.unwrap();
        let event = carol.expect("introduced").await;
        assert_eq!((event["by"]["name"].as_str(), event["how"].as_str()), (Some("Alice"), Some("introduce")));
        let bob_seen = members["members"].as_array().unwrap().iter().find(|m| m["name"] == "Bob").unwrap().clone();
        assert_eq!(bob_seen["identity"]["how"], "unknown");
        assert_eq!(bob_seen["identity"]["name"], "Robert");
        assert_eq!(bob_seen["identity"]["claim"], true);
        assert_eq!(bob_seen["identity"]["introduced"][0]["by"]["name"], "Alice");
        assert_eq!(bob_seen["identity"]["introduced"][0]["name"], "Bob (Acme)");
        let contacts = cmd(&home, &carol, &["contacts"]).await.unwrap();
        let id = contacts["introductions"][0]["identity"].as_str().unwrap().to_owned();
        cmd(&home, &carol, &["contacts", "accept", &id]).await.unwrap();
        let members = cmd(&home, &carol, &["members"]).await.unwrap();
        let bob_seen = members["members"].as_array().unwrap().iter().find(|m| m["name"] == "Bob").unwrap().clone();
        assert_eq!((bob_seen["identity"]["how"].as_str(), bob_seen["identity"]["name"].as_str()), (Some("introduced"), Some("Bob (Acme)")));
        assert!(cmd(&home, &carol, &["send", "--to", "Bob (Acme)", "hi"]).await.is_ok());
        drop(bob);
    });
}

#[test]
fn the_command_channel_needs_its_token_and_a_running_session() {
    local(async {
        let home = home("channel");
        let world = Shared::default();
        let alice = start(&world, &home, "alice", member("Alice", None, ""), Duration::from_secs(3600)).await;
        let endpoint: Value = serde_json::from_slice(&std::fs::read(session_dir(&home, "alice").unwrap().join("endpoint")).unwrap()).unwrap();
        let port = endpoint["port"].as_u64().unwrap() as u16;
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (read, mut write) = stream.into_split();
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        write.write_all(b"{\"token\":\"nope\",\"request\":{\"cmd\":\"groups\"}}\n").await.unwrap();
        let mut line = String::new();
        tokio::io::BufReader::new(read).read_line(&mut line).await.unwrap();
        assert!(line.contains("bad token"));
        assert_eq!(crate::cli::running_session(&home).await.unwrap(), "alice");
        let missing = Agent { handle: "nobody".into(), ..alice };
        let error = cmd(&home, &missing, &["groups"]).await.unwrap_err().to_string();
        assert!(error.contains("not running"), "{error}");
    });
}
