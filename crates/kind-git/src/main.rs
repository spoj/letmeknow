//! `letmeknow-kind-git`: the git kind's plugin for the session process, in the plugin protocol (PROTOCOL.md) on stdin and
//! stdout. It keeps each group's repository bare in its directory (`repos/<group>.git`), with the branches as far as
//! every push is checked, and its branches and the pushes not yet checked in `<group>.json`. git reaches it through
//! `git-remote-lmk`, which runs `letmeknow git list` and `letmeknow git push`.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use lmk_kind_git::{Branches, Push, State, Verdict, answer, bytes};
use lmk_proto::Bytes;
use serde_json::{Value, json};

struct Group {
    name: String,
    /// None until the group's state arrives, for a group joined.
    branches: Option<Branches>,
    /// A bundle is being fetched to be checked.
    checking: bool,
}

/// A request of ours waiting for the session's answer.
enum Waiting {
    /// A push's bundle being added; then the push is sent as a held message, its bundle spread, and its message's id
    /// appended.
    Add { command: Value, group: String, push: Push },
    Send { command: Value, group: String, push: Push },
    /// The bundle spreading, and the members that hold the push's message.
    Spread { command: Value, group: String, message: String, held_by: Vec<Value> },
    Append { command: Value },
    /// A pushed bundle, to check.
    Check { group: String, position: u64 },
    /// The bundle of a state this session hands a member.
    Snapshot { asked: Value, state: State },
    /// The bundle of a state handed to this session.
    Restore { group: String, state: State },
}

struct Plugin {
    dir: PathBuf,
    groups: HashMap<String, Group>,
    waiting: HashMap<u64, Waiting>,
    /// Whether this session's own pushes counted when their entries were taken, by position.
    won: HashMap<u64, bool>,
    requests: u64,
    out: Vec<Value>,
}

fn main() -> Result<()> {
    let mut plugin =
        Plugin { dir: PathBuf::new(), groups: HashMap::new(), waiting: HashMap::new(), won: HashMap::new(), requests: 0, out: Vec::new() };
    for line in std::io::stdin().lock().lines() {
        plugin.host(&line?);
        let mut stdout = std::io::stdout().lock();
        for message in plugin.out.drain(..) {
            writeln!(stdout, "{message}")?;
        }
        stdout.flush()?;
    }
    Ok(())
}

fn warning(group: &str, text: String) -> Value {
    json!({ "type": "event", "group": group, "event": { "type": "warning", "text": text }, "wake": true })
}

/// Runs git on a repository; its output, trimmed.
fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").arg("--git-dir").arg(repo).args(args).output().context("cannot run git")?;
    ensure!(output.status.success(), "git {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim());
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// Whether a push's bundle brings `new` after `old` into the repository, which takes its commits.
fn check(repo: &Path, push: &Push, bundle: Option<&Path>) -> Verdict {
    let good = || -> Result<()> {
        if let Some(bundle) = bundle {
            git(repo, &["bundle", "unbundle", bundle.to_str().context("a path that is not UTF-8")?])?;
        }
        if let Some(new) = &push.new {
            git(repo, &["cat-file", "-e", &format!("{new}^{{commit}}")])?;
            if let Some(old) = &push.old {
                git(repo, &["merge-base", "--is-ancestor", old, new])?;
            }
        }
        Ok(())
    };
    if good().is_ok() { Verdict::Good } else { Verdict::Bad }
}

/// Sets the repository's branches to `refs`.
fn set_refs(repo: &Path, refs: &BTreeMap<String, String>) -> Result<()> {
    let listed = git(repo, &["for-each-ref", "--format=%(refname) %(objectname)"])?;
    let held: BTreeMap<&str, &str> = listed.lines().filter_map(|line| line.split_once(' ')).collect();
    for name in held.keys().filter(|name| !refs.contains_key(**name)) {
        git(repo, &["update-ref", "-d", name])?;
    }
    for (name, sha) in refs.iter().filter(|(name, sha)| held.get(name.as_str()) != Some(&sha.as_str())) {
        git(repo, &["update-ref", name, sha])?;
    }
    Ok(())
}

/// Writes a file whole, through a rename.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("new");
    std::fs::write(&temp, bytes)?;
    Ok(std::fs::rename(&temp, path)?)
}

impl Plugin {
    fn host(&mut self, line: &str) {
        let message: Value = match serde_json::from_str(line) {
            Ok(message) => message,
            Err(error) => return eprintln!("letmeknow-kind-git: {error}: {line}"),
        };
        if let Err(error) = self.take(&message) {
            let group = message["group"].as_str().unwrap_or_default();
            match message.get("id") {
                Some(id) if message["type"] != "answer" => self.out.push(answer(id, Err(error))),
                _ => self.out.push(warning(group, format!("{error:#}"))),
            }
        }
    }

    fn repo(&self, group: &str) -> PathBuf {
        self.dir.join("repos").join(format!("{group}.git"))
    }

    fn saved(&self, group: &str) -> PathBuf {
        self.dir.join(format!("{group}.json"))
    }

    fn save(&self, group: &str) -> Result<()> {
        let branches = self.groups[group].branches.as_ref().context("no branches yet")?;
        replace(&self.saved(group), &serde_json::to_vec(branches)?)
    }

    fn request(&mut self, mut message: Value, waiting: Waiting) {
        self.requests += 1;
        message["id"] = json!(self.requests);
        self.waiting.insert(self.requests, waiting);
        self.out.push(message);
    }

    fn take(&mut self, message: &Value) -> Result<()> {
        let group = message["group"].as_str().unwrap_or_default().to_owned();
        match message["type"].as_str().unwrap_or_default() {
            "start" => {
                self.dir = PathBuf::from(message["dir"].as_str().context("no dir")?);
                std::fs::create_dir_all(self.dir.join("repos"))?;
                self.out.push(answer(&message["id"], Ok(json!({ "chat": true }))));
            }
            "group" => {
                self.open(&group, message)?;
                if let Some(id) = message.get("id") {
                    self.out.push(answer(id, Ok(json!({ "remote": format!("lmk::{group}") }))));
                }
            }
            "gone" => {
                self.groups.remove(&group);
                for path in [self.repo(&group), self.saved(&group)] {
                    match path.is_dir() {
                        true => std::fs::remove_dir_all(path)?,
                        false if path.exists() => std::fs::remove_file(path)?,
                        false => {}
                    }
                }
                self.out.push(answer(&message["id"], Ok(json!({}))));
            }
            "entry" => self.entry(&group, message)?,
            "message" if message["payload"]["type"] == "push" && message["payload"]["bundle"].is_string() => {
                // A push's bundle, ahead of its entry: held, and so fetched, within this session's limit.
                self.out.push(json!({ "type": "hold", "group": group, "links": [message["payload"]["bundle"]] }));
            }
            "state" => self.state(&group, serde_json::from_slice(&bytes(&message["data"])?)?)?,
            "snapshot" => self.snapshot(&group, &message["id"])?,
            "synced" => self.check_next(&group)?,
            "command" => self.command(message)?,
            "sync" => self.out.push(answer(&message["id"], Ok(json!({})))),
            "answer" => self.answered(message)?,
            _ => {}
        }
        Ok(())
    }

    /// A group of this session: its repository and branches. A new group follows its log from the start; a joined
    /// one once its state arrives.
    fn open(&mut self, group: &str, message: &Value) -> Result<()> {
        let repo = self.repo(group);
        if !repo.exists() {
            let output = Command::new("git").args(["init", "--quiet", "--bare"]).arg(&repo).output().context("cannot run git")?;
            ensure!(output.status.success(), "git init: {}", String::from_utf8_lossy(&output.stderr).trim());
        }
        let kept = match std::fs::read(self.saved(group)) {
            Ok(kept) => Some(serde_json::from_slice::<Branches>(&kept)?),
            Err(_) if message["command"] == "invite" => Some(Branches::default()),
            Err(_) => None,
        };
        let follow = match &kept {
            Some(branches) => json!({ "type": "log", "group": group, "after": branches.position }),
            None => json!({ "type": "log", "group": group }),
        };
        let name = message["settings"]["name"].as_str().unwrap_or_default().to_owned();
        self.groups.insert(group.to_owned(), Group { name, branches: kept, checking: false });
        if self.groups[group].branches.is_some() {
            self.save(group)?;
        }
        self.out.push(follow);
        self.out.push(json!({ "type": "info", "group": group, "info": { "remote": format!("lmk::{group}") } }));
        self.check_next(group)
    }

    fn entry(&mut self, group: &str, message: &Value) -> Result<()> {
        let branches = self.groups.get_mut(group).and_then(|g| g.branches.as_mut()).context("an entry before the group's state")?;
        let position = message["position"].as_u64().context("no position")?;
        if let Some(taken) = branches.take(position, message["from"].clone(), &message["payload"]) {
            let (push, from) = (taken.push.clone(), taken.from.clone());
            let counts = branches.counts(position);
            if let Some(link) = &push.bundle {
                self.out.push(json!({ "type": "hold", "group": group, "links": [link] }));
            }
            if from["you"] == true {
                self.won.insert(position, counts);
            } else if counts {
                let event = json!({ "type": "pushed", "by": from, "ref": push.branch, "old": push.old, "new": push.new, "subjects": push.subjects });
                self.out.push(json!({ "type": "event", "group": group, "event": event }));
            }
        }
        self.save(group)?;
        self.check_next(group)
    }

    /// Checks the next push not checked yet, fetching its bundle; one without a bundle at once.
    fn check_next(&mut self, group: &str) -> Result<()> {
        loop {
            let Some(g) = self.groups.get(group) else { return Ok(()) };
            let Some(taken) = g.branches.as_ref().and_then(Branches::unchecked).filter(|_| !g.checking) else { return Ok(()) };
            let (position, push) = (taken.position, taken.push.clone());
            match &push.bundle {
                Some(link) => {
                    self.groups.get_mut(group).unwrap().checking = true;
                    let fetch = json!({ "type": "fetch", "group": group, "link": link });
                    self.request(fetch, Waiting::Check { group: group.to_owned(), position });
                    return Ok(());
                }
                None => {
                    let verdict = check(&self.repo(group), &push, None);
                    self.judged(group, position, verdict)?;
                }
            }
        }
    }

    /// Records a push's verdict, and brings the repository's branches up to what is checked.
    fn judged(&mut self, group: &str, position: u64, verdict: Verdict) -> Result<()> {
        let branches = self.groups.get_mut(group).and_then(|g| g.branches.as_mut()).context("not a group of this session")?;
        let push = branches.pushes.iter().find(|taken| taken.position == position).map(|taken| taken.push.clone());
        branches.judge(position, verdict);
        let refs = branches.checked();
        if verdict == Verdict::Bad
            && let Some(push) = push
        {
            let text = format!("a push to {} at log position {position} is void: its bundle does not bring {:?} after {:?}", push.branch, push.new, push.old);
            self.out.push(warning(group, text));
        }
        set_refs(&self.repo(group), &refs)?;
        self.save(group)
    }

    /// A state a member handed this session: taken if it is no older than what this session has.
    fn state(&mut self, group: &str, state: State) -> Result<()> {
        let g = self.groups.get(group).context("not a group of this session")?;
        if g.branches.as_ref().is_some_and(|branches| state.position < branches.position) {
            return Ok(());
        }
        match state.bundle.clone() {
            Some(link) => {
                self.out.push(json!({ "type": "hold", "group": group, "links": [link] }));
                let fetch = json!({ "type": "fetch", "group": group, "link": link });
                self.request(fetch, Waiting::Restore { group: group.to_owned(), state });
                Ok(())
            }
            None => self.restore(group, state, None),
        }
    }

    fn restore(&mut self, group: &str, state: State, bundle: Option<&Path>) -> Result<()> {
        let repo = self.repo(group);
        if let Some(bundle) = bundle {
            git(&repo, &["bundle", "unbundle", bundle.to_str().context("a path that is not UTF-8")?])?;
        }
        set_refs(&repo, &state.refs)?;
        let g = self.groups.get_mut(group).context("not a group of this session")?;
        g.branches = Some(Branches::from_state(&state));
        g.checking = false;
        self.save(group)?;
        self.out.push(json!({ "type": "log", "group": group, "after": state.position }));
        Ok(())
    }

    /// The group's state, to hand a member: its branches as far as every push is checked, with a bundle of them.
    fn snapshot(&mut self, group: &str, asked: &Value) -> Result<()> {
        let Some(branches) = self.groups.get(group).and_then(|g| g.branches.as_ref()) else {
            self.out.push(answer(asked, Ok(json!({}))));
            return Ok(());
        };
        let state = State { position: branches.settled, refs: branches.refs.clone(), bundle: None };
        if state.refs.is_empty() {
            self.out.push(answer(asked, Ok(json!({ "data": Bytes(serde_json::to_vec(&state)?) }))));
            return Ok(());
        }
        let path = self.dir.join(format!("{group}.bundle"));
        let mut args = vec!["bundle", "create", "--quiet", path.to_str().context("a path that is not UTF-8")?];
        args.extend(state.refs.keys().map(String::as_str));
        git(&self.repo(group), &args)?;
        let data = std::fs::read(&path)?;
        std::fs::remove_file(&path)?;
        let add = json!({ "type": "add", "group": group, "data": Bytes(data) });
        self.request(add, Waiting::Snapshot { asked: asked.clone(), state });
        Ok(())
    }

    /// `letmeknow git list <group> [--push]` and `letmeknow git push <group> <ref> <old> <new> <bundle> [<subject>...]`,
    /// which `git-remote-lmk` runs; `-` stands for none.
    fn command(&mut self, message: &Value) -> Result<()> {
        let args: Vec<&str> = message["args"].as_array().context("no args")?.iter().filter_map(Value::as_str).collect();
        let none = |arg: &str| (arg != "-").then(|| arg.to_owned());
        match args[..] {
            ["list", group, ref flags @ ..] => {
                let group = self.resolve(group)?;
                let branches = self.groups[&group].branches.as_ref().context("this session has not caught up on the group yet")?;
                let refs = if flags == ["--push"] { branches.tips() } else { branches.checked() };
                let head = refs.keys().find(|name| *name == "refs/heads/main").or(refs.keys().next());
                self.out.push(answer(&message["id"], Ok(json!({ "refs": refs, "head": head, "repo": self.repo(&group) }))));
            }
            ["push", group, branch, old, new, bundle, ref subjects @ ..] => {
                let group = self.resolve(group)?;
                let branches = self.groups[&group].branches.as_ref().context("this session has not caught up on the group yet")?;
                let (old, new) = (none(old), none(new));
                ensure!(branches.tips().get(branch) == old.as_ref(), "fetch first");
                let subjects = subjects.iter().map(|s| s.to_string()).collect();
                let push = Push { branch: branch.to_owned(), old, new, bundle: None, subjects };
                let command = message["id"].clone();
                match none(bundle) {
                    Some(path) => {
                        let data = std::fs::read(&path).with_context(|| format!("cannot read {path}"))?;
                        let add = json!({ "type": "add", "group": group, "data": Bytes(data) });
                        self.request(add, Waiting::Add { command, group, push });
                    }
                    None => self.send(command, &group, push),
                }
            }
            _ => bail!("the git kind's commands are for git-remote-lmk: use `git remote add <name> lmk::<group>`, then git push and git fetch"),
        }
        Ok(())
    }

    /// Sends a push as a held message, which members hold, and fetch its bundle, ahead of its entry.
    fn send(&mut self, command: Value, group: &str, push: Push) {
        let mut payload = serde_json::to_value(&push).expect("JSON");
        payload["type"] = json!("push");
        let send = json!({ "type": "send", "group": group, "payload": payload, "held": true });
        self.request(send, Waiting::Send { command, group: group.to_owned(), push });
    }

    /// Appends a push's message to the log, once another member holds it and its bundle.
    fn append(&mut self, command: Value, group: &str, message: &str, held: bool) {
        if !held {
            let error = anyhow::anyhow!("no other member is online to take the push, so it was not made; push again once one is");
            return self.out.push(answer(&command, Err(error)));
        }
        self.request(json!({ "type": "append", "group": group, "message": message }), Waiting::Append { command });
    }

    fn answered(&mut self, message: &Value) -> Result<()> {
        let waiting = self.waiting.remove(&message["id"].as_u64().unwrap_or_default()).context("an answer to nothing asked")?;
        let answered = match &message["error"] {
            Value::Null => Ok(&message["answer"]),
            error => Err(anyhow::anyhow!("{}", error.as_str().unwrap_or_default())),
        };
        match (waiting, answered) {
            (Waiting::Add { command, group, mut push }, Ok(added)) => {
                push.bundle = Some(added["link"].as_str().context("no link")?.to_owned());
                self.send(command, &group, push);
            }
            (Waiting::Send { command, group, push }, Ok(sent)) => {
                let message = sent["id"].as_str().context("no id")?.to_owned();
                let held_by = sent["held_by"].as_array().cloned().unwrap_or_default();
                match push.bundle {
                    Some(link) => {
                        let spread = json!({ "type": "spread", "group": group, "link": link });
                        self.request(spread, Waiting::Spread { command, group, message, held_by });
                    }
                    None => self.append(command, &group, &message, !held_by.is_empty()),
                }
            }
            (Waiting::Spread { command, group, message, held_by }, Ok(spread)) => {
                let holds_both = |member: &Value| held_by.iter().any(|held| held["fp"] == member["fp"]);
                let both = spread["held_by"].as_array().is_some_and(|holders| holders.iter().any(holds_both));
                self.append(command, &group, &message, both);
            }
            (Waiting::Append { command }, Ok(appended)) => {
                let position = appended["position"].as_u64().context("no position")?;
                let answered = match self.won.remove(&position) {
                    Some(true) => Ok(json!({ "position": position })),
                    Some(false) => Err(anyhow::anyhow!("fetch first")),
                    None => Err(anyhow::anyhow!("the log did not take the push; push again")),
                };
                self.out.push(answer(&command, answered));
            }
            (
                Waiting::Add { command, .. } | Waiting::Send { command, .. } | Waiting::Spread { command, .. } | Waiting::Append { command },
                Err(error),
            ) => {
                self.out.push(answer(&command, Err(error)));
            }
            (Waiting::Check { group, position }, fetched) => {
                let Some(g) = self.groups.get_mut(&group) else { return Ok(()) };
                g.checking = false;
                // A bundle no member online holds is checked once one is.
                let Ok(fetched) = fetched else { return Ok(()) };
                let Some(push) = g.branches.as_ref().and_then(|b| b.pushes.iter().find(|t| t.position == position)).map(|t| t.push.clone()) else {
                    return Ok(());
                };
                let path = self.dir.join(format!("{group}-{position}.bundle"));
                std::fs::write(&path, bytes(&fetched["data"])?)?;
                let verdict = check(&self.repo(&group), &push, Some(&path));
                std::fs::remove_file(&path)?;
                self.judged(&group, position, verdict)?;
                self.check_next(&group)?;
            }
            (Waiting::Snapshot { asked, mut state }, added) => {
                let answered = added.and_then(|added| {
                    state.bundle = Some(added["link"].as_str().context("no link")?.to_owned());
                    Ok(json!({ "data": Bytes(serde_json::to_vec(&state)?) }))
                });
                self.out.push(answer(&asked, answered));
            }
            (Waiting::Restore { group, state }, fetched) => {
                let path = self.dir.join(format!("{group}-state.bundle"));
                std::fs::write(&path, bytes(&fetched?["data"])?)?;
                let restored = self.restore(&group, state, Some(&path));
                std::fs::remove_file(&path)?;
                restored?;
            }
        }
        Ok(())
    }

    /// A group by id or name.
    fn resolve(&self, group: &str) -> Result<String> {
        let named: Vec<&String> = self.groups.keys().filter(|g| *g == group || self.groups[*g].name == group).collect();
        match named[..] {
            [group] => Ok(group.clone()),
            [] => bail!("this session is in no git group {group}"),
            _ => bail!("several git groups are named {group}; use its id"),
        }
    }
}
