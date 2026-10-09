//! Kinds' plugins: executables named `letmeknow-kind-<kind>`, found in the session's plugin directories (beside its own
//! executable, then PATH), each run while the session has groups of its kind and spoken to in JSON lines on stdin and
//! stdout (PROTOCOL.md, Plugins).

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;

const PREFIX: &str = "letmeknow-kind-";

/// The plugins in `dirs`, by kind; of two with one name, the first directory's.
pub fn discover(dirs: &[PathBuf]) -> BTreeMap<String, PathBuf> {
    let mut found = BTreeMap::new();
    for dir in dirs {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let name = name.strip_suffix(std::env::consts::EXE_SUFFIX).unwrap_or(&name);
            if let Some(kind) = name.strip_prefix(PREFIX)
                && !kind.is_empty()
                && !kind.contains('.')
                && entry.path().is_file()
            {
                found.entry(kind.to_owned()).or_insert(entry.path());
            }
        }
    }
    found
}

/// The directories a session looks in for plugins: its executable's, then PATH's.
pub fn dirs() -> Vec<PathBuf> {
    let own = std::env::current_exe().ok().and_then(|exe| Some(exe.parent()?.to_path_buf()));
    let path = std::env::var_os("PATH").map(|path| std::env::split_paths(&path).collect::<Vec<_>>()).unwrap_or_default();
    own.into_iter().chain(path).collect()
}

struct Running {
    _child: Child,
    stdin: ChildStdin,
}

/// A plugin that stops within this long of its start is not started again by itself.
const STEADY: std::time::Duration = std::time::Duration::from_secs(60);

pub struct Plugins {
    pub found: BTreeMap<String, PathBuf>,
    running: HashMap<String, Running>,
    started: HashMap<String, std::time::Instant>,
    /// Each plugin's lines, and `None` once it stopped.
    lines: mpsc::UnboundedSender<(String, Option<Value>)>,
}

impl Plugins {
    pub fn new(found: BTreeMap<String, PathBuf>) -> (Self, mpsc::UnboundedReceiver<(String, Option<Value>)>) {
        let (lines, rx) = mpsc::unbounded_channel();
        (Plugins { found, running: HashMap::new(), started: HashMap::new(), lines }, rx)
    }

    pub fn running(&self) -> Vec<String> {
        self.running.keys().cloned().collect()
    }

    pub fn is_running(&self, kind: &str) -> bool {
        self.running.contains_key(kind)
    }

    /// Starts a kind's plugin; the session's first message to it is `start`.
    pub async fn start(&mut self, kind: &str) -> Result<()> {
        let path = self.found.get(kind).with_context(|| format!("this session has no plugin for {kind} groups ({PREFIX}{kind})"))?;
        let mut child = Command::new(path).stdin(Stdio::piped()).stdout(Stdio::piped()).kill_on_drop(true).spawn()?;
        let (stdin, stdout) = (child.stdin.take().expect("piped"), child.stdout.take().expect("piped"));
        let (lines, name) = (self.lines.clone(), kind.to_owned());
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                match serde_json::from_str(&line) {
                    Ok(value) => drop(lines.send((name.clone(), Some(value)))),
                    Err(error) => eprintln!("{PREFIX}{name} wrote {line:?}: {error}"),
                }
            }
            lines.send((name, None)).ok();
        });
        self.running.insert(kind.to_owned(), Running { _child: child, stdin });
        self.started.insert(kind.to_owned(), std::time::Instant::now());
        Ok(())
    }

    pub async fn send(&mut self, kind: &str, message: &Value) -> Result<()> {
        let running = self.running.get_mut(kind).with_context(|| format!("the {kind} plugin is not running"))?;
        let written = running.stdin.write_all(format!("{message}\n").as_bytes()).await;
        if written.is_err() {
            self.running.remove(kind);
        }
        written.with_context(|| format!("the {kind} plugin stopped"))
    }

    /// A plugin's stdout closed; whether it had run steadily, and may be started again.
    pub fn stopped(&mut self, kind: &str) -> bool {
        self.running.remove(kind);
        self.started.get(kind).is_some_and(|at| at.elapsed() > STEADY)
    }
}
