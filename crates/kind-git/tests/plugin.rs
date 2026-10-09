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
