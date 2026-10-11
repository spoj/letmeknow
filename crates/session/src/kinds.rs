//! Kinds' plugins: executables named `letmeknow-kind-<kind>`, found in the session's plugin directories (beside its own
//! executable, then PATH), each run while the session has groups of its kind and spoken to in JSON lines on stdin and
//! stdout.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
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
    child: Child,
    /// Lines for its stdin.
    stdin: mpsc::UnboundedSender<String>,
    started: Instant,
}

/// How long a plugin has to end once its stdin closes, as the session stops.
const STOP_WAIT: Duration = Duration::from_secs(5);
/// A plugin that stops within this long of its start is not started again by itself.
const STEADY: Duration = Duration::from_secs(60);

/// The plugins found, speaking JSON lines over their stdio.
pub struct Plugins {
    pub found: BTreeMap<String, PathBuf>,
    /// Where each kind's plugin keeps its state, in a directory named after its kind.
    dir: PathBuf,
    running: Mutex<HashMap<String, Running>>,
    /// Each plugin's lines, and `None` once it stopped.
    lines: mpsc::UnboundedSender<(String, Option<Value>)>,
}

impl Plugins {
    pub fn new(found: BTreeMap<String, PathBuf>, dir: PathBuf) -> (Self, mpsc::UnboundedReceiver<(String, Option<Value>)>) {
        let (lines, rx) = mpsc::unbounded_channel();
        (Plugins { found, dir, running: Mutex::default(), lines }, rx)
    }
}

impl Plugins {
    /// Stops every plugin: its stdin closes, and it is killed unless it ended within `STOP_WAIT`.
    pub async fn stop(&self) {
        let running: Vec<Running> = self.running.lock().unwrap().drain().map(|(_, running)| running).collect();
        for Running { mut child, stdin, .. } in running {
            drop(stdin);
            tokio::time::timeout(STOP_WAIT, child.wait()).await.ok();
        }
    }
}

impl lmk_client::Plugins for Plugins {
    fn kinds(&self) -> Vec<String> {
        self.found.keys().cloned().collect()
    }

    fn start(&self, kind: &str) -> Result<Value> {
        let path = self.found.get(kind).with_context(|| format!("this session has no plugin for {kind} groups ({PREFIX}{kind})"))?;
        let mut child = Command::new(path).stdin(Stdio::piped()).stdout(Stdio::piped()).kill_on_drop(true).spawn()?;
        let (mut stdin, stdout) = (child.stdin.take().expect("piped"), child.stdout.take().expect("piped"));
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
        let (writer, mut written) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(line) = written.recv().await {
                if stdin.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        let running = Running { child, stdin: writer, started: Instant::now() };
        self.running.lock().unwrap().insert(kind.to_owned(), running);
        Ok(json!({ "dir": self.dir.join(kind) }))
    }

    fn running(&self) -> Vec<String> {
        self.running.lock().unwrap().keys().cloned().collect()
    }

    fn send(&self, kind: &str, message: &Value) -> Result<()> {
        let running = self.running.lock().unwrap();
        let running = running.get(kind).with_context(|| format!("the {kind} plugin is not running"))?;
        running.stdin.send(format!("{message}\n")).ok().with_context(|| format!("the {kind} plugin stopped"))
    }

    fn stopped(&self, kind: &str) -> bool {
        self.running.lock().unwrap().remove(kind).is_some_and(|running| running.started.elapsed() > STEADY)
    }
}
