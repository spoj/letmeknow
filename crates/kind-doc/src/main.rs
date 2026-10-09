//! `letmeknow-kind-doc`: the doc kind's plugin for the session process, in the plugin protocol (PROTOCOL.md) on stdin
//! and stdout. It keeps each doc in a file, named on `invite` or `join` or else in its own directory, and brings file
//! and doc into step from their base, the text both last had: once the file is quiet for 1 second or the doc for 2,
//! and whenever the session asks (`sync`), before it prints anything and before each command. Others' edits it tells
//! of as one `edited` event per doc. Its own state is in the directory `start` names: per group, the doc's Yjs state
//! (`<group>.yjs`) and its file's binding (`<group>.json`).

mod file;

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use lmk_kind_doc::{Docs, answer, bytes, str, ydoc};
use lmk_proto::Bytes;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::{Value, json};

use file::Quiet;

enum Input {
    Host(String),
    /// A doc's file changed.
    File(String),
    Closed,
}

/// A doc's file, kept in step with the doc; what of it is saved.
#[derive(Clone, Default)]
struct Saved {
    path: PathBuf,
    /// The text file and doc last had in common.
    base: String,
    /// Whether this plugin made the file, which then goes with the group.
    made: bool,
    /// A file's changes on their way onto the doc: the file's text, and the edit that carries them, until the base is
    /// the result. A plugin that stopped meanwhile applies the edit again, which a doc takes at most once.
    carrying: Option<(String, Vec<u8>)>,
}

impl Saved {
    fn to_json(&self) -> Value {
        let carrying = self.carrying.as_ref().map(|(file, edit)| json!({ "file": file, "edit": Bytes(edit.clone()) }));
        json!({ "path": self.path, "base": self.base, "made": self.made, "carrying": carrying })
    }

    fn from_json(value: &Value) -> Result<Self> {
        let carrying = match &value["carrying"] {
            Value::Null => None,
            carrying => Some((str(&carrying["file"])?.to_owned(), bytes(&carrying["edit"])?)),
        };
        let path = PathBuf::from(str(&value["path"])?);
        Ok(Saved { path, base: str(&value["base"])?.to_owned(), made: value["made"] == true, carrying })
    }
}

struct Binding {
    saved: Saved,
    quiet: Quiet,
    /// Watches the file's directory, as editors often replace a file rather than write into it.
    _watcher: Option<RecommendedWatcher>,
    /// The members whose changes came in since the last sync.
    editors: Vec<Value>,
    /// While an `edited` event waits to be printed: the text the agent was last told of, and who changed it since.
    told: Option<(String, Vec<Value>)>,
    /// This session as the group's members see it, for mentions.
    me: Value,
}

/// A request of ours waiting for the session's answer: an `attach` command's file.
struct Attaching {
    command: Value,
    name: String,
    image: bool,
}

struct Plugin {
    dir: PathBuf,
    docs: Docs,
    bindings: HashMap<String, Binding>,
    names: HashMap<String, String>,
    attaching: HashMap<u64, Attaching>,
    requests: u64,
    input: mpsc::Sender<Input>,
    out: Vec<Value>,
}

fn main() -> Result<()> {
    let (input, inputs) = mpsc::channel();
    let host = input.clone();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if host.send(Input::Host(line)).is_err() {
                return;
            }
        }
        host.send(Input::Closed).ok();
    });
    let mut plugin =
        Plugin { dir: PathBuf::new(), docs: Docs::default(), bindings: HashMap::new(), names: HashMap::new(), attaching: HashMap::new(), requests: 0, input, out: Vec::new() };
    loop {
        let next = match plugin.due() {
            Some(due) => inputs.recv_timeout(due.saturating_duration_since(Instant::now())),
            None => inputs.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected),
        };
        match next {
            Ok(Input::Host(line)) => plugin.host(&line),
            Ok(Input::File(group)) => {
                if let Some(binding) = plugin.bindings.get_mut(&group) {
                    binding.quiet.file_changed(Instant::now());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => plugin.tick(),
            Ok(Input::Closed) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
        let mut stdout = std::io::stdout().lock();
        for message in plugin.out.drain(..) {
            writeln!(stdout, "{message}")?;
        }
        stdout.flush()?;
    }
}

fn warning(group: &str, text: String) -> Value {
    json!({ "type": "event", "group": group, "event": { "type": "warning", "text": text }, "wake": true })
}

impl Plugin {
    fn due(&self) -> Option<Instant> {
        self.bindings.values().filter_map(|binding| binding.quiet.due()).min()
    }

    fn tick(&mut self) {
        let now = Instant::now();
        let due: Vec<String> = self.bindings.iter().filter(|(_, b)| b.quiet.due().is_some_and(|at| at <= now)).map(|(g, _)| g.clone()).collect();
        for group in due {
            self.sync_or_warn(&group);
        }
    }

    fn host(&mut self, line: &str) {
        let message: Value = match serde_json::from_str(line) {
            Ok(message) => message,
            Err(error) => return eprintln!("letmeknow-kind-doc: {error}: {line}"),
        };
        if let Err(error) = self.take(&message) {
            let group = message["group"].as_str().unwrap_or_default();
            match message.get("id") {
                Some(id) if message["type"] != "answer" => self.out.push(answer(id, Err(error))),
                _ => self.out.push(warning(group, format!("{error:#}"))),
            }
        }
    }

    fn take(&mut self, message: &Value) -> Result<()> {
        let group = message["group"].as_str().unwrap_or_default().to_owned();
        match str(&message["type"])? {
            "start" => {
                self.dir = PathBuf::from(str(&message["dir"])?);
                std::fs::create_dir_all(&self.dir)?;
                self.out.push(answer(&message["id"], Ok(json!({}))));
            }
            "group" => {
                let file = self.open(&group, message)?;
                if let Some(id) = message.get("id") {
                    self.out.push(answer(id, Ok(json!({ "file": file }))));
                }
            }
            "gone" => {
                self.gone(&group)?;
                self.out.push(answer(&message["id"], Ok(json!({}))));
            }
            "command" => self.command(message)?,
            "sync" => {
                let groups: Vec<String> = self.bindings.keys().cloned().collect();
                for group in groups {
                    self.sync_or_warn(&group);
                }
                self.out.push(answer(&message["id"], Ok(json!({}))));
            }
            "printed" => {
                if let Some(binding) = self.bindings.get_mut(&group) {
                    binding.told = None;
                }
            }
            "answer" => self.answered(message)?,
            _ => {
                if let Some((group, from)) = self.docs.handle(message, &mut self.out)? {
                    self.save_state(&group)?;
                    if let Some(binding) = self.bindings.get_mut(&group) {
                        binding.quiet.doc_changed(Instant::now());
                        if !binding.editors.iter().any(|e| e["fp"] == from["fp"]) {
                            binding.editors.push(from);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn state_path(&self, group: &str) -> PathBuf {
        self.dir.join(format!("{group}.yjs"))
    }

    fn saved_path(&self, group: &str) -> PathBuf {
        self.dir.join(format!("{group}.json"))
    }

    fn save_state(&self, group: &str) -> Result<()> {
        replace(&self.state_path(group), self.docs.state(group)?)
    }

    fn save(&self, group: &str) -> Result<()> {
        let saved = self.bindings[group].saved.to_json();
        replace(&self.saved_path(group), saved.to_string().as_bytes())
    }

    /// A group of this session: its doc, and its file. With `args`, from `invite` or `join`, the file is `args[0]` (or a
    /// new one in this plugin's directory); a doc 0.10 kept comes with `import`. Returns the file's path.
    fn open(&mut self, group: &str, message: &Value) -> Result<PathBuf> {
        let import = &message["import"];
        let state = match std::fs::read(self.state_path(group)) {
            Ok(state) => state,
            Err(_) if import["state"].is_string() => bytes(&import["state"])?,
            Err(_) => ydoc::new(""),
        };
        self.docs.open(group, state, &mut self.out)?;
        self.save_state(group)?;
        self.names.insert(group.to_owned(), message["settings"]["name"].as_str().unwrap_or_default().to_owned());
        let me = message["me"].clone();
        let saved = match std::fs::read(self.saved_path(group)) {
            Ok(saved) => Some(Saved::from_json(&serde_json::from_slice(&saved)?)?),
            Err(_) if import["path"].is_string() => Some(Saved::from_json(import)?),
            Err(_) => None,
        };
        if let Some(saved) = saved {
            let path = saved.path.clone();
            self.follow(group, saved, me);
            self.save(group)?;
            self.resume(group)?;
            return Ok(path);
        }
        let cwd = Path::new(message["cwd"].as_str().unwrap_or("."));
        let named = message["args"].get(0).map(|file| anyhow::Ok(cwd.join(str(file)?))).transpose()?;
        if let Some(path) = &named
            && self.bindings.values().any(|b| b.saved.path == *path)
        {
            bail!("{} already holds another doc", path.display());
        }
        let path = match named {
            Some(path) => {
                ensure!(message["command"] != "join" || !path.exists(), "{} exists; name a new file for the doc", path.display());
                path
            }
            None => self.dir.join("docs").join(format!("{}-{}.md", self.slug(group), &group[..group.len().min(8)])),
        };
        // A new group's file brings its text in; a joined group's file starts with the doc's.
        let base = if message["command"] == "join" { self.docs.text(group)? } else { String::new() };
        if !path.exists() {
            file::write_file(&path, &base)?;
        }
        let made = message["args"].get(0).is_none();
        self.follow(group, Saved { path: path.clone(), base, made, carrying: None }, me);
        self.save(group)?;
        self.sync(group)?;
        Ok(path)
    }

    fn slug(&self, group: &str) -> String {
        let name: String = self.names[group].chars().map(|c| if c.is_alphanumeric() { c } else { '-' }).collect();
        Some(name.trim_matches('-').to_owned()).filter(|name| !name.is_empty()).unwrap_or("doc".into())
    }

    /// Where a binding was left: a plugin stopped while carrying a file's changes onto the doc finishes, and one stopped
    /// after writing the file but before storing its base takes the file as the base.
    fn resume(&mut self, group: &str) -> Result<()> {
        if let Some((file, edit)) = self.bindings[group].saved.carrying.clone() {
            self.docs.edit(group, edit, &mut self.out)?;
            self.save_state(group)?;
            self.set_base(group, file)?;
        }
        let text = self.docs.text(group)?;
        let path = self.bindings[group].saved.path.clone();
        if std::fs::read_to_string(&path).is_ok_and(|file| file.replace("\r\n", "\n") == text) {
            self.set_base(group, text)?;
        }
        Ok(())
    }

    /// Watches a doc's file, which is brought into step once it has been quiet for a moment.
    fn follow(&mut self, group: &str, saved: Saved, me: Value) {
        let (input, changed, name) = (self.input.clone(), group.to_owned(), saved.path.file_name().map(ToOwned::to_owned));
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            if let Ok(event) = event
                && !event.kind.is_access()
                && event.paths.iter().any(|p| p.file_name() == name.as_deref())
            {
                input.send(Input::File(changed.clone())).ok();
            }
        })
        .and_then(|mut watcher| watcher.watch(saved.path.parent().expect("a file is in a directory"), RecursiveMode::NonRecursive).map(|()| watcher));
        if let Err(error) = &watcher {
            let text = format!("cannot watch {}: {error}; what you write there is taken at your next command", saved.path.display());
            self.out.push(warning(group, text));
        }
        self.out.push(json!({ "type": "info", "group": group, "info": { "file": saved.path } }));
        let binding = Binding { saved, quiet: Quiet::default(), _watcher: watcher.ok(), editors: Vec::new(), told: None, me };
        self.bindings.insert(group.to_owned(), binding);
    }

    fn gone(&mut self, group: &str) -> Result<()> {
        // A file the agent named stays; one this plugin made goes with the group.
        if let Some(binding) = self.bindings.remove(group)
            && binding.saved.made
            && binding.saved.path.exists()
        {
            std::fs::remove_file(&binding.saved.path)?;
        }
        self.docs.states.remove(group);
        for path in [self.state_path(group), self.saved_path(group)] {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    fn sync_or_warn(&mut self, group: &str) {
        if let Err(error) = self.sync(group) {
            self.out.push(warning(group, format!("{error:#}")));
        }
    }

    /// Brings a doc and its file into step. What changed in the file since they last were (its base) is carried line by
    /// line onto the doc as it is now and sent; the file then gets the doc's text. A line both changed keeps the doc's
    /// version, with a warning. What others changed in the doc meanwhile is told as `edited`.
    fn sync(&mut self, group: &str) -> Result<()> {
        let binding = self.bindings.get_mut(group).context("not a doc of this session")?;
        binding.quiet = Quiet::default();
        let (path, base) = (binding.saved.path.clone(), binding.saved.base.clone());
        let editors = std::mem::take(&mut binding.editors);
        let file = match std::fs::read_to_string(&path) {
            Ok(text) => text.replace("\r\n", "\n"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => base.clone(),
            Err(error) => return Err(error).with_context(|| format!("cannot read {}", path.display())),
        };
        let current = self.docs.text(group)?;
        let (text, lost) = if file == base { (current.clone(), Vec::new()) } else { file::rebase(&base, &file, &current) };
        if text != current {
            let edit = ydoc::edit(self.docs.state(group)?, &text)?;
            self.bindings.get_mut(group).unwrap().saved.carrying = Some((file.clone(), edit.clone()));
            self.save(group)?;
            self.docs.edit(group, edit, &mut self.out)?;
            self.save_state(group)?;
        }
        if text != file {
            file::write_file(&path, &text)?;
        }
        self.set_base(group, text)?;
        if !lost.is_empty() {
            let text = format!("others changed these lines of {} meanwhile, so your changes to them were not kept: {}", path.display(), lost.join(" | "));
            self.out.push(warning(group, text));
        }
        if current != base {
            // One `edited` event per doc waits, telling of every change since the agent was last told.
            let binding = self.bindings.get_mut(group).unwrap();
            let (since, by) = binding.told.get_or_insert_with(|| (base.clone(), Vec::new()));
            for editor in editors {
                if !by.iter().any(|e| e["fp"] == editor["fp"]) {
                    by.push(editor);
                }
            }
            let lines = file::changed(since, &current).0;
            let direct = file::changed(&base, &current).1.iter().any(|line| mentions(line, &binding.me));
            let event = json!({ "type": "edited", "file": path, "by": by, "lines": lines, "direct": direct });
            self.out.push(json!({ "type": "event", "group": group, "event": event, "wake": direct, "key": "edited" }));
        }
        Ok(())
    }

    /// Records the text a doc and its file have in common, once the file's changes are on the doc.
    fn set_base(&mut self, group: &str, base: String) -> Result<()> {
        let saved = &mut self.bindings.get_mut(group).unwrap().saved;
        saved.base = base;
        saved.carrying = None;
        self.save(group)
    }

    /// `letmeknow doc attach [--group <group>] <path>`: makes a file linkable from a doc; answers with its markdown link.
    fn command(&mut self, message: &Value) -> Result<()> {
        let args = message["args"].as_array().context("no args")?.iter().filter_map(Value::as_str);
        let args: Vec<&str> = args.flat_map(|arg| arg.strip_prefix("--group=").map_or(vec![arg], |group| vec!["--group", group])).collect();
        let (group, path) = match args[..] {
            ["attach", path] => (None, path),
            ["attach", "--group", group, path] | ["attach", path, "--group", group] => (Some(group), path),
            _ => bail!("usage: letmeknow doc attach [--group <doc>] <path>"),
        };
        let group = self.resolve(group)?;
        let path = Path::new(message["cwd"].as_str().unwrap_or(".")).join(path);
        let data = std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let name = path.file_name().map_or_else(String::new, |n| n.to_string_lossy().replace(['[', ']'], ""));
        let image = matches!(&data[..], [0x89, b'P', b'N', b'G', ..] | [0xff, 0xd8, 0xff, ..] | [b'G', b'I', b'F', b'8', ..])
            || data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP";
        self.requests += 1;
        self.attaching.insert(self.requests, Attaching { command: message["id"].clone(), name, image });
        self.out.push(json!({ "type": "add", "id": self.requests, "group": group, "data": Bytes(data) }));
        Ok(())
    }

    fn answered(&mut self, message: &Value) -> Result<()> {
        let attaching = self.attaching.remove(&message["id"].as_u64().unwrap_or_default()).context("an answer to nothing asked")?;
        let answered = match &message["error"] {
            Value::Null => {
                let link = str(&message["answer"]["link"])?;
                let markdown = format!("{}[{}]({link})", if attaching.image { "!" } else { "" }, attaching.name);
                Ok(json!({ "link": link, "markdown": markdown }))
            }
            error => Err(anyhow::anyhow!("{}", error.as_str().unwrap_or_default())),
        };
        self.out.push(answer(&attaching.command, answered));
        Ok(())
    }

    /// The doc a command acts on: the one named (by id or name), or else this session's one doc.
    fn resolve(&self, group: Option<&str>) -> Result<String> {
        let named: Vec<&String> = self.bindings.keys().filter(|g| group.is_none_or(|name| *g == name || self.names[*g] == name)).collect();
        match (&named[..], group) {
            ([group], _) => Ok((*group).clone()),
            ([], Some(group)) => bail!("no doc {group}"),
            ([], None) => bail!("this session is in no doc; create one with `invite --kind doc`, or join one with `join`"),
            (_, _) => bail!("this session is in several docs; pass --group"),
        }
    }
}

/// Writes a file whole, through a rename.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("new");
    std::fs::write(&temp, bytes)?;
    Ok(std::fs::rename(&temp, path)?)
}

/// Whether a described member answers to `name`, in any case: its name, the first word of it, or its identity's name
/// when this session knows it (as the session's own `--to` and mentions do).
fn answers(member: &Value, name: &str) -> bool {
    let (name, own) = (name.to_lowercase(), member["name"].as_str().unwrap_or_default().to_lowercase());
    let first: String = own.chars().take_while(|c| c.is_alphanumeric()).collect();
    let identity = &member["identity"];
    own == name
        || first == name
        || identity["error"].is_null()
            && identity["how"] != "unknown"
            && identity["name"].as_str().is_some_and(|identity| identity.to_lowercase() == name)
}

/// Whether `text` mentions `member`: "@" and a name it answers to.
fn mentions(text: &str, member: &Value) -> bool {
    text.match_indices('@').any(|(at, _)| {
        let name: String = text[at + 1..].chars().take_while(|c| c.is_alphanumeric() || "-_".contains(*c)).collect();
        !text[..at].ends_with(char::is_alphanumeric) && !name.is_empty() && answers(member, &name)
    })
}
