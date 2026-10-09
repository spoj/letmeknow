//! The git kind: a repository's branches, which members push to through the group's kind log. A push is a held message
//! naming the branch, its old and new commit, the bundle that brings the commits (a file), and their subjects; the log
//! orders the pushes by their messages' ids. Every member applies the log in order: an update counts only if `old` is
//! the branch's tip at that point. A member checks each bundle once
//! it has it; one whose `new` does not follow `old` voids its update for every member, since a file's content is fixed
//! by its hash. The group's state is its branches as of a log position, with a full bundle.
//!
//! `Branches` is what every host of the kind keeps alike: the session's plugin `letmeknow-kind-git` (src/main.rs),
//! which keeps a bare repository, with `git-remote-lmk` (src/helper.rs) for git; and the browser's display-only in-page
//! plugin (`Page`), which shows the pushes and checks no bundle.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result};
use lmk_proto::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A protocol message's field as bytes (unpadded base64url).
pub fn bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::from_value::<Bytes>(value.clone())?.0)
}

/// The answer to a host's request.
pub fn answer(id: &Value, answer: Result<Value>) -> Value {
    match answer {
        Ok(answer) => json!({ "type": "answer", "id": id, "answer": answer }),
        Err(error) => json!({ "type": "answer", "id": id, "error": format!("{error:#}") }),
    }
}

/// A push, as its message names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Push {
    #[serde(rename = "ref")]
    pub branch: String,
    pub old: Option<String>,
    pub new: Option<String>,
    /// The file link of the bundle that brings `new`'s commits; none if they need none.
    pub bundle: Option<String>,
    pub subjects: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Its bundle is not checked yet.
    Pending,
    Good,
    /// Its bundle does not bring `new` after `old`: void.
    Bad,
}

/// A push taken from the log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Taken {
    pub position: u64,
    /// The position of the entry taken before it.
    pub before: u64,
    pub from: Value,
    pub push: Push,
    pub verdict: Verdict,
}

/// The state a member hands another: the branches as of a log position, and a bundle of all their commits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub position: u64,
    pub refs: BTreeMap<String, String>,
    pub bundle: Option<String>,
}

/// A group's branches as its log leaves them.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Branches {
    /// The log position of the last entry taken.
    pub position: u64,
    /// The branches as of `settled`: every push up to it is checked and applied.
    pub refs: BTreeMap<String, String>,
    pub settled: u64,
    /// The pushes after `settled`, in log order.
    pub pushes: Vec<Taken>,
}

impl Branches {
    pub fn from_state(state: &State) -> Self {
        Branches { position: state.position, refs: state.refs.clone(), settled: state.position, pushes: Vec::new() }
    }

    /// Takes an entry of the log. Returns its push, if it is one.
    pub fn take(&mut self, position: u64, from: Value, payload: &Value) -> Option<&Taken> {
        let before = std::mem::replace(&mut self.position, position);
        let push = (payload["type"] == "push").then(|| serde_json::from_value::<Push>(payload.clone()).ok()).flatten();
        let Some(push) = push else {
            self.settle();
            return None;
        };
        self.pushes.push(Taken { position, before, from, push, verdict: Verdict::Pending });
        self.pushes.last()
    }

    /// The branches after replaying the pushes, but void ones: those checked so far, or all, counting those not
    /// checked yet. Also the positions of the pushes that counted.
    fn replay(&self, checked: bool) -> (BTreeMap<String, String>, Vec<u64>) {
        let (mut refs, mut counted) = (self.refs.clone(), Vec::new());
        for taken in &self.pushes {
            match taken.verdict {
                Verdict::Pending if checked => break,
                Verdict::Bad => continue,
                _ => {}
            }
            let push = &taken.push;
            if refs.get(&push.branch) != push.old.as_ref() {
                continue;
            }
            match &push.new {
                Some(new) => refs.insert(push.branch.clone(), new.clone()),
                None => refs.remove(&push.branch),
            };
            counted.push(taken.position);
        }
        (refs, counted)
    }

    /// The branches as far as every push is checked: what a member's repository holds.
    pub fn checked(&self) -> BTreeMap<String, String> {
        self.replay(true).0
    }

    /// The branches counting the pushes not checked yet: what a push must build on.
    pub fn tips(&self) -> BTreeMap<String, String> {
        self.replay(false).0
    }

    /// Whether the push at `position` counts: `old` was its branch's tip there, and its bundle is not void.
    pub fn counts(&self, position: u64) -> bool {
        self.replay(false).1.contains(&position)
    }

    /// The first push whose bundle is not checked yet.
    pub fn unchecked(&self) -> Option<&Taken> {
        self.pushes.iter().find(|taken| taken.verdict == Verdict::Pending)
    }

    /// Records a push's verdict, and folds the checked pushes into the branches.
    pub fn judge(&mut self, position: u64, verdict: Verdict) {
        if let Some(taken) = self.pushes.iter_mut().find(|taken| taken.position == position) {
            taken.verdict = verdict;
        }
        self.settle();
    }

    fn settle(&mut self) {
        let checked = self.pushes.iter().take_while(|taken| taken.verdict != Verdict::Pending).count();
        self.refs = self.checked();
        self.pushes.drain(..checked);
        self.settled = self.pushes.first().map_or(self.position, |first| first.before);
    }
}

/// Where the browser's in-page plugin keeps each group's branches: the page's records.
pub trait Store {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn put(&self, key: &str, value: &[u8]);
    fn delete(&self, key: &str);
}

/// The git kind as the browser's display-only in-page plugin: it follows the log, keeps each group's branches in the
/// page's records under `kind/git/<group>`, and tells of each push that counts as a `pushed` event. It checks no bundle,
/// holds no files and hands no state; a member that joins through it gets the state from another member.
pub struct Page<S: Store> {
    store: S,
    groups: HashMap<String, Branches>,
}

impl<S: Store> Page<S> {
    pub fn new(store: S) -> Self {
        Page { store, groups: HashMap::new() }
    }

    /// Takes in one message of the host; returns what it sends.
    pub fn input(&mut self, message: &Value) -> Vec<Value> {
        let mut out = Vec::new();
        if let Err(error) = self.take(message, &mut out) {
            match message.get("id") {
                Some(id) if message["type"] != "answer" => out.push(answer(id, Err(error))),
                _ => out.push(json!({ "type": "event", "group": message["group"], "event": { "type": "warning", "text": format!("{error:#}") } })),
            }
        }
        out
    }

    fn save(&self, group: &str) -> Result<()> {
        self.store.put(&format!("kind/git/{group}"), &serde_json::to_vec(&self.groups[group])?);
        Ok(())
    }

    fn take(&mut self, message: &Value, out: &mut Vec<Value>) -> Result<()> {
        let group = message["group"].as_str().unwrap_or_default().to_owned();
        match message["type"].as_str().unwrap_or_default() {
            "group" => {
                let kept = self.store.get(&format!("kind/git/{group}")).map(|kept| serde_json::from_slice::<Branches>(&kept)).transpose()?;
                match kept {
                    Some(branches) => {
                        out.push(json!({ "type": "log", "group": group, "after": branches.position }));
                        self.groups.insert(group, branches);
                    }
                    None => out.push(json!({ "type": "log", "group": group })),
                }
                if let Some(id) = message.get("id") {
                    out.push(answer(id, Ok(json!({}))));
                }
            }
            "gone" => {
                self.groups.remove(&group);
                self.store.delete(&format!("kind/git/{group}"));
            }
            "state" => {
                let state: State = serde_json::from_slice(&bytes(&message["data"])?)?;
                if self.groups.get(&group).is_none_or(|branches| state.position >= branches.position) {
                    out.push(json!({ "type": "log", "group": group, "after": state.position }));
                    self.groups.insert(group.clone(), Branches::from_state(&state));
                    self.save(&group)?;
                }
            }
            "entry" => {
                let branches = self.groups.get_mut(&group).context("an entry of a log not followed")?;
                let position = message["position"].as_u64().unwrap_or_default();
                if let Some(taken) = branches.take(position, message["from"].clone(), &message["payload"]) {
                    let push = taken.push.clone();
                    let counted = branches.counts(position);
                    branches.judge(position, Verdict::Good);
                    if counted {
                        let event = json!({ "type": "pushed", "by": message["from"], "ref": push.branch, "old": push.old, "new": push.new, "subjects": push.subjects });
                        out.push(json!({ "type": "event", "group": group, "event": event }));
                    }
                }
                self.save(&group)?;
            }
            "snapshot" => out.push(answer(&message["id"], Ok(json!({})))),
            "command" => out.push(answer(&message["id"], Err(anyhow::anyhow!("the git kind has no commands in a browser")))),
            "sync" => out.push(answer(&message["id"], Ok(json!({})))),
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push(branch: &str, old: Option<&str>, new: Option<&str>) -> Value {
        json!({ "type": "push", "ref": branch, "old": old, "new": new, "bundle": null, "subjects": [] })
    }

    #[test]
    fn an_update_counts_only_from_the_tip_and_a_void_bundle_voids_what_built_on_it() {
        let mut branches = Branches::default();
        branches.take(1, json!(null), &push("main", None, Some("a")));
        branches.take(2, json!(null), &push("main", Some("a"), Some("b")));
        branches.take(3, json!(null), &push("main", Some("a"), Some("c")));
        branches.take(4, json!(null), &push("main", Some("b"), Some("d")));
        assert!(branches.counts(2) && !branches.counts(3) && branches.counts(4));
        assert_eq!(branches.tips()["main"], "d");
        assert!(branches.checked().is_empty(), "nothing is checked yet");

        branches.judge(1, Verdict::Good);
        assert_eq!((branches.refs["main"].as_str(), branches.settled), ("a", 1));
        branches.judge(2, Verdict::Bad);
        assert!(branches.counts(3) && !branches.counts(4), "b is void, so c follows a and d does not");
        assert_eq!(branches.tips()["main"], "c");
        branches.judge(3, Verdict::Good);
        branches.judge(4, Verdict::Good);
        assert_eq!((branches.refs["main"].as_str(), branches.settled, branches.pushes.len()), ("c", 4, 0));

        branches.take(5, json!(null), &push("main", Some("c"), None));
        branches.judge(5, Verdict::Good);
        assert!(branches.refs.is_empty(), "a branch is deleted");
        branches.take(6, json!(null), &json!({ "type": "other" }));
        assert_eq!(branches.settled, 6);
    }

    struct Memory(std::cell::RefCell<HashMap<String, Vec<u8>>>);

    impl Store for &Memory {
        fn get(&self, key: &str) -> Option<Vec<u8>> {
            self.0.borrow().get(key).cloned()
        }
        fn put(&self, key: &str, value: &[u8]) {
            self.0.borrow_mut().insert(key.into(), value.to_vec());
        }
        fn delete(&self, key: &str) {
            self.0.borrow_mut().remove(key);
        }
    }

    #[test]
    fn the_page_follows_from_a_state_and_tells_of_pushes_that_count() {
        let memory = Memory(Default::default());
        let mut page = Page::new(&memory);
        let out = page.input(&json!({ "type": "group", "group": "g", "id": 1 }));
        assert_eq!(out[0], json!({ "type": "log", "group": "g" }), "a joiner without state asks for one");
        let state = State { position: 3, refs: [("refs/heads/main".into(), "a".into())].into(), bundle: None };
        let out = page.input(&json!({ "type": "state", "group": "g", "data": Bytes(serde_json::to_vec(&state).unwrap()) }));
        assert_eq!(out[0], json!({ "type": "log", "group": "g", "after": 3 }));
        let entry = |position, payload| json!({ "type": "entry", "group": "g", "position": position, "id": "00", "from": { "name": "Ann" }, "payload": payload });
        let out = page.input(&entry(4, push("refs/heads/main", Some("a"), Some("b"))));
        assert_eq!(out[0]["event"]["type"], "pushed");
        assert!(page.input(&entry(5, push("refs/heads/main", Some("a"), Some("c")))).is_empty(), "a push that lost is not told");
        let mut page = Page::new(&memory);
        let out = page.input(&json!({ "type": "group", "group": "g" }));
        assert_eq!(out[0], json!({ "type": "log", "group": "g", "after": 5 }), "it resumes where it was");
    }
}
