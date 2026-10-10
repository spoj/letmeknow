//! The plugin as the session runs it: JSON lines on stdin and stdout.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use lmk_proto::Bytes;
use serde_json::{Value, json};

#[test]
fn its_groups_carry_chat() {
    let dir = std::env::temp_dir().join(format!("lmk-kind-git-{}", std::process::id()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_letmeknow-kind-git")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", json!({ "type": "start", "id": 0, "kind": "git", "dir": dir })).unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let answer: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(answer, json!({ "type": "answer", "id": 0, "answer": { "chat": true } }));
    drop(stdin);
    child.wait().unwrap();
}

/// A state whose bundle arrives after this session took a newer state is not taken.
#[test]
fn a_state_older_than_one_taken_while_its_bundle_came_is_ignored() {
    let dir = std::env::temp_dir().join(format!("lmk-kind-git-older-{}", std::process::id()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_letmeknow-kind-git")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut next = || {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        serde_json::from_str::<Value>(&line).unwrap()
    };
    let state = |state: Value| Bytes(serde_json::to_vec(&state).unwrap());
    for message in [
        json!({ "type": "start", "id": 0, "kind": "git", "dir": dir }),
        json!({ "type": "group", "group": "g" }),
        json!({ "type": "state", "group": "g", "data": state(json!({ "position": 5, "refs": {}, "bundle": "older" })) }),
        json!({ "type": "state", "group": "g", "data": state(json!({ "position": 8, "refs": {}, "bundle": null })) }),
        json!({ "type": "answer", "id": 1, "answer": { "data": Bytes(b"not a bundle".to_vec()) } }),
        json!({ "type": "sync", "id": 2 }),
    ] {
        writeln!(stdin, "{message}").unwrap();
    }
    let fetch = loop {
        let message = next();
        if message["type"] == "fetch" {
            break message;
        }
    };
    assert_eq!(fetch["id"], 1);
    assert_eq!(next(), json!({ "type": "log", "group": "g", "after": 8 }));
    assert_eq!(next(), json!({ "type": "answer", "id": 2, "answer": {} }));
    drop(stdin);
    child.wait().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

/// At a loss of its own, the plugin stops: it takes no later entry, refuses pushes, hands out no state and asks for one,
/// until it takes a state past the loss.
#[test]
fn a_loss_of_its_own_stops_it_until_a_state_past_it() {
    let dir = std::env::temp_dir().join(format!("lmk-kind-git-lost-{}", std::process::id()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_letmeknow-kind-git")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut send = |message: Value| writeln!(stdin, "{message}").unwrap();
    let mut answer = |id: u64| loop {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let message: Value = serde_json::from_str(&line).unwrap();
        if message["type"] == "answer" && message["id"] == id {
            return message;
        }
    };
    let push = |n: u64| json!({ "type": "push", "ref": "refs/heads/main", "old": null, "new": format!("{n:040}"), "bundle": null, "subjects": [] });
    let entry = |position: u64| json!({ "type": "entry", "group": "g", "position": position, "id": "00", "from": { "name": "Ann" }, "payload": push(position) });
    let lost = |position: u64, you: bool| json!({ "type": "lost", "group": "g", "position": position, "member": { "you": you }, "positions": [position], "ids": [] });
    let state = |position: u64| json!({ "type": "state", "group": "g", "data": Bytes(serde_json::to_vec(&json!({ "position": position, "refs": {}, "bundle": null })).unwrap()) });
    send(json!({ "type": "start", "id": 0, "kind": "git", "dir": dir }));
    send(json!({ "type": "group", "group": "g", "id": 1, "command": "invite", "settings": { "name": "Repo" } }));
    answer(1);
    send(lost(2, false));
    send(lost(3, true));
    send(entry(4));
    send(json!({ "type": "command", "id": 2, "args": ["push", "g", "refs/heads/main", "-", "abc", "-"] }));
    assert!(answer(2)["error"].as_str().unwrap().contains("lost the message at log position 3"));
    send(json!({ "type": "snapshot", "group": "g", "id": 3 }));
    assert_eq!(answer(3)["answer"], json!({}), "no state while stopped");
    send(json!({ "type": "command", "id": 4, "args": ["list", "g", "--push"] }));
    assert_eq!(answer(4)["answer"]["refs"], json!({}), "the entry after the loss was not taken");
    send(state(2));
    send(state(5));
    send(json!({ "type": "command", "id": 5, "args": ["push", "g", "refs/heads/main", "-", "abc", "-"] }));
    let sent = loop {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let message: Value = serde_json::from_str(&line).unwrap();
        if message["type"] == "send" {
            break message;
        }
    };
    assert_eq!(sent["payload"]["new"], "abc", "it takes pushes again from a state past the loss");
    drop(send);
    child.kill().unwrap();
    child.wait().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}
