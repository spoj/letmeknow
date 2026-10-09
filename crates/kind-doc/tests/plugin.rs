//! The plugin as the session runs it: JSON lines on stdin and stdout.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

struct Plugin {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<Value>,
}

impl Plugin {
    fn start(dir: &std::path::Path) -> Plugin {
        let mut child = Command::new(env!("CARGO_BIN_EXE_letmeknow-kind-doc")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let (stdin, stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                tx.send(serde_json::from_str(&line.unwrap()).unwrap()).unwrap();
            }
        });
        let mut plugin = Plugin { child, stdin, lines };
        plugin.send(json!({ "type": "start", "kind": "doc", "dir": dir }));
        plugin
    }

    fn send(&mut self, message: Value) {
        writeln!(self.stdin, "{message}").unwrap();
    }

    /// The next line of `kind`, skipping others.
    fn next(&self, kind: &str) -> Value {
        loop {
            let line = self.lines.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|_| panic!("no {kind}"));
            if line["type"] == kind {
                return line;
            }
        }
    }
}

#[test]
fn a_doc_in_a_file_its_commands_and_frames() {
    let dir = std::env::temp_dir().join(format!("lmk-kind-doc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plan.md"), "- [ ] alpha\n").unwrap();
    std::fs::write(dir.join("chart.png"), b"\x89PNG....").unwrap();
    let mut plugin = Plugin::start(&dir.join("state"));
    let me = json!({ "name": "Alice", "fp": "aa" });
    let group = json!({ "type": "group", "group": "g1", "settings": { "name": "Plan" }, "me": me, "id": 1, "command": "invite", "args": ["plan.md"], "cwd": dir });
    plugin.send(group);
    let edit = plugin.next("send");
    assert_eq!(edit["payload"]["type"], "edit", "the file's text is the new doc's");
    assert_eq!(plugin.next("answer")["answer"]["file"], dir.join("plan.md").to_str().unwrap());

    plugin.send(json!({ "type": "command", "id": 2, "args": ["attach", "--group=Plan", "chart.png"], "cwd": dir }));
    let add = plugin.next("add");
    assert_eq!(add["group"], "g1");
    plugin.send(json!({ "type": "answer", "id": add["id"], "answer": { "link": "lmk:x" } }));
    let attached = plugin.next("answer");
    assert_eq!((&attached["id"], &attached["answer"]["markdown"]), (&json!(2), &json!("![chart.png](lmk:x)")));

    // A member whose doc differs gets this doc's state vector; one that sends its own gets a diff, to it alone.
    plugin.send(json!({ "type": "frame", "group": "g1", "from": { "fp": "bb" }, "frame": { "doc": { "snapshot": "AA" } } }));
    let frame = plugin.next("frame");
    assert_eq!((&frame["to"], frame["frame"]["doc_sv"]["sv"].is_string()), (&json!("bb"), true));
    plugin.send(json!({ "type": "frame", "group": "g1", "from": { "fp": "bb" }, "frame": { "doc_sv": { "sv": "AA" } } }));
    let diff = plugin.next("send");
    assert_eq!((&diff["to"], &diff["payload"]["type"]), (&json!("bb"), &json!("diff")));

    // Another member's edit reaches the file at the next sync, told as `edited`.
    plugin.send(json!({ "type": "message", "group": "g1", "from": { "name": "Bob", "fp": "bb" }, "payload": diff["payload"], "held": false }));
    plugin.send(json!({ "type": "sync", "id": 3 }));
    plugin.next("answer");
    plugin.send(json!({ "type": "gone", "group": "g1" }));
    plugin.send(json!({ "type": "sync", "id": 4 }));
    plugin.next("answer");
    assert!(dir.join("plan.md").exists(), "a file the agent named stays");
    assert!(!dir.join("state").join("g1.yjs").exists());
    drop(plugin.stdin);
    assert!(plugin.child.wait().unwrap().success());
}
