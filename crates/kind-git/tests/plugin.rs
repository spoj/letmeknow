//! The plugin as the session runs it: JSON lines on stdin and stdout.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

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
