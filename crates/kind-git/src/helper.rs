//! `git-remote-lmk`: git's remote helper for `lmk::<group>` (gitremote-helpers(7)), with the `fetch` and `push`
//! capabilities. It asks the running session's git plugin, through `letmeknow git list` and `letmeknow git push`, and
//! fetches from the plugin's repository of the group. A push sends a bundle of the commits the group lacks; branches only
//! fast-forward, so a force push is refused.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

/// `letmeknow` beside this executable, where the release and the npm package put it, or else on PATH.
fn letmeknow() -> PathBuf {
    let name = format!("letmeknow{}", std::env::consts::EXE_SUFFIX);
    let beside = std::env::current_exe().ok().map(|exe| exe.with_file_name(&name));
    beside.filter(|path| path.exists()).unwrap_or_else(|| name.into())
}

/// Runs `letmeknow git <args>` against the running session; its answer.
fn session(args: &[&str]) -> Result<Value> {
    let output = Command::new(letmeknow()).arg("git").args(args).output().context("cannot run letmeknow")?;
    ensure!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr).trim().trim_start_matches("letmeknow: "));
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// Runs git in the repository git runs this helper for; its output, trimmed.
fn git(args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).output().context("cannot run git")?;
    ensure!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr).trim());
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

struct Helper {
    group: String,
    /// The group's branches, as the last `list` showed them.
    refs: BTreeMap<String, String>,
    repo: String,
}

fn main() {
    let group = std::env::args().nth(2).unwrap_or_default();
    let mut helper = Helper { group: group.strip_prefix("lmk::").unwrap_or(&group).to_owned(), refs: BTreeMap::new(), repo: String::new() };
    if let Err(error) = helper.run() {
        eprintln!("git-remote-lmk: {error:#}");
        std::process::exit(1);
    }
}

impl Helper {
    fn run(&mut self) -> Result<()> {
        let mut lines = std::io::stdin().lock().lines();
        let mut out = std::io::stdout().lock();
        while let Some(line) = lines.next() {
            let line = line?;
            let mut batch = vec![line.clone()];
            if line.starts_with("fetch ") || line.starts_with("push ") {
                for next in lines.by_ref() {
                    let next = next?;
                    if next.is_empty() {
                        break;
                    }
                    batch.push(next);
                }
            }
            let answer = match line.split(' ').next().unwrap_or_default() {
                "" => return Ok(()),
                "capabilities" => "fetch\npush\n\n".to_owned(),
                "list" => self.list(line == "list for-push")?,
                "fetch" => self.fetch(&batch)?,
                "push" => batch.iter().map(|push| self.push(push.trim_start_matches("push "))).collect::<String>() + "\n",
                other => bail!("unknown command {other}"),
            };
            out.write_all(answer.as_bytes())?;
            out.flush()?;
        }
        Ok(())
    }

    fn list(&mut self, push: bool) -> Result<String> {
        let mut args = vec!["list", self.group.as_str()];
        if push {
            args.push("--push");
        }
        let listed = session(&args)?;
        self.refs = serde_json::from_value(listed["refs"].clone())?;
        self.repo = listed["repo"].as_str().context("no repo")?.to_owned();
        let mut answer: String = self.refs.iter().map(|(name, sha)| format!("{sha} {name}\n")).collect();
        if let Some(head) = listed["head"].as_str() {
            answer += &format!("@{head} HEAD\n");
        }
        Ok(answer + "\n")
    }

    /// Fetches the branches asked for from the plugin's repository of the group.
    fn fetch(&self, batch: &[String]) -> Result<String> {
        let names: Vec<&str> = batch.iter().filter_map(|line| line.split(' ').nth(2)).filter(|name| *name != "HEAD").collect();
        let mut args = vec!["-c", "protocol.file.allow=always", "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", &self.repo];
        args.extend(names);
        git(&args)?;
        Ok("\n".into())
    }

    /// One `push <src>:<dst>`: answers `ok <dst>` or `error <dst> <why>`.
    fn push(&self, spec: &str) -> String {
        let (src, dst) = spec.split_once(':').unwrap_or((spec, spec));
        match self.pushed(src, dst) {
            Ok(()) => format!("ok {dst}\n"),
            Err(error) => format!("error {dst} {}\n", format!("{error:#}").replace('\n', " ")),
        }
    }

    fn pushed(&self, src: &str, dst: &str) -> Result<()> {
        ensure!(!src.starts_with('+'), "force pushes are not supported: branches only fast-forward");
        let old = self.refs.get(dst).cloned();
        let new = (!src.is_empty()).then(|| git(&["rev-parse", "--verify", &format!("{src}^{{commit}}")])).transpose()?;
        let Some(new) = new else {
            session(&["push", &self.group, dst, old.as_deref().context("no such branch")?, "-", "-"])?;
            return Ok(());
        };
        if let Some(old) = &old {
            ensure!(git(&["cat-file", "-e", &format!("{old}^{{commit}}")]).is_ok(), "fetch first");
            ensure!(git(&["merge-base", "--is-ancestor", old, &new]).is_ok(), "non-fast-forward");
        }
        // The group's branches that this repository has: the commits the bundle need not bring.
        let known: Vec<&str> = self.refs.values().map(String::as_str).filter(|sha| git(&["cat-file", "-e", &format!("{sha}^{{commit}}")]).is_ok()).collect();
        let bundle = std::env::temp_dir().join(format!("lmk-push-{}.bundle", std::process::id()));
        let bundle_path = bundle.to_str().context("a temporary path that is not UTF-8")?;
        let mut create = vec!["bundle", "create", "--quiet", bundle_path, src, "--not"];
        create.extend(&known);
        let made = git(&create).is_ok();
        let mut log = vec!["log", "--format=%s", "-n", "50", &new, "--not"];
        log.extend(&known);
        let subjects = git(&log)?;
        ensure!(made || subjects.is_empty(), "cannot bundle {src}; push a branch");
        let mut args = vec!["push", self.group.as_str(), dst, old.as_deref().unwrap_or("-"), &new, if made { bundle_path } else { "-" }];
        args.extend(subjects.lines());
        let pushed = session(&args);
        if made {
            std::fs::remove_file(&bundle)?;
        }
        pushed.map(drop)
    }
}
