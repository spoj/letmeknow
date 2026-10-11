//! The kinds whose groups share one Yjs document: the doc kind, one markdown text that every member edits at once
//! (`ydoc`), and the table kind, rows of typed fields (`table`). Their payloads are live: edits go to the members online;
//! two members that meet compare their documents by a hash of each one's snapshot (`snapshot`), and if they differ, each
//! sends the other a `diff` against the other's state vector (`sv`), all to that member alone. Whoever admits a joiner
//! hands it the document's state. A doc links files as `lmk:` links, which members hold while it does.
//!
//! `States` is what every host of these kinds does alike, in the plugin protocol: the session's plugins
//! `letmeknow-kind-doc` and `letmeknow-kind-table` (`plugin`), which keep each document in a file, and the browser's
//! in-page plugins (`Page`), which its views bind to.

#[cfg(not(target_arch = "wasm32"))]
mod file;
#[cfg(not(target_arch = "wasm32"))]
pub mod plugin;
pub mod table;
pub mod ydoc;

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use lmk_proto::Bytes;
use serde_json::{Value, json};

/// A protocol message's field as bytes (unpadded base64url).
pub fn bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::from_value::<Bytes>(value.clone())?.0)
}

pub fn str(value: &Value) -> Result<&str> {
    value.as_str().context("expected a string")
}

/// The answer to a host's request.
pub fn answer(id: &Value, answer: Result<Value>) -> Value {
    match answer {
        Ok(answer) => json!({ "type": "answer", "id": id, "answer": answer }),
        Err(error) => json!({ "type": "answer", "id": id, "error": format!("{error:#}") }),
    }
}

/// A kind whose groups share a Yjs document.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Doc,
    Table,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Doc => "doc",
            Kind::Table => "table",
        }
    }

    /// The document of a new group.
    fn new_state(self) -> Vec<u8> {
        match self {
            Kind::Doc => ydoc::new(""),
            Kind::Table => table::new(),
        }
    }

    /// The files a document links.
    fn links(self, state: &[u8]) -> Result<Vec<String>> {
        match self {
            Kind::Doc => Ok(ydoc::links(&ydoc::text(state)?)),
            Kind::Table => Ok(Vec::new()),
        }
    }
}

/// The documents of this session's groups of one kind, by group id: each one's Yjs state.
pub struct States {
    pub kind: Kind,
    pub states: HashMap<String, Vec<u8>>,
}

impl States {
    pub fn new(kind: Kind) -> Self {
        States { kind, states: HashMap::new() }
    }

    pub fn state(&self, group: &str) -> Result<&[u8]> {
        self.states.get(group).map(Vec::as_slice).with_context(|| format!("not a {} of this session", self.kind.name()))
    }

    /// Takes in what every host takes in alike: `message` (`edit`, `diff`, `snapshot`, `sv`), `synced`, `state` and
    /// `snapshot`; what it sends goes to `out`. Returns the group whose document changed and the member who changed it,
    /// if any. Other messages are the host's.
    pub fn handle(&mut self, message: &Value, out: &mut Vec<Value>) -> Result<Option<(String, Value)>> {
        let group = message["group"].as_str().unwrap_or_default().to_owned();
        let (payload, to) = (&message["payload"], &message["from"]["fp"]);
        match (str(&message["type"])?, payload["type"].as_str()) {
            ("message", Some("edit" | "diff")) => {
                self.apply(&group, &bytes(&payload["update"])?, out)?;
                Ok(Some((group, message["from"].clone())))
            }
            ("message", Some("snapshot")) => {
                let state = self.state(&group)?;
                if bytes(&payload["snapshot"])? != ydoc::snapshot(state)? {
                    let sv = json!({ "type": "sv", "sv": Bytes(ydoc::state_vector(state)?) });
                    out.push(json!({ "type": "send", "group": group, "to": to, "payload": sv }));
                }
                Ok(None)
            }
            ("message", Some("sv")) => {
                let diff = json!({ "type": "diff", "update": Bytes(ydoc::diff(self.state(&group)?, &bytes(&payload["sv"])?)?) });
                out.push(json!({ "type": "send", "group": group, "to": to, "payload": diff }));
                Ok(None)
            }
            ("state", _) => {
                self.apply(&group, &bytes(&message["data"])?, out)?;
                Ok(Some((group, message["from"].clone())))
            }
            ("synced", _) => {
                let snapshot = json!({ "type": "snapshot", "snapshot": Bytes(ydoc::snapshot(self.state(&group)?)?.to_vec()) });
                out.push(json!({ "type": "send", "group": group, "to": message["member"]["fp"], "payload": snapshot }));
                Ok(None)
            }
            ("snapshot", _) => {
                out.push(answer(&message["id"], Ok(json!({ "data": Bytes(self.state(&group)?.to_vec()) }))));
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Applies an edit made here and sends it to the members online.
    pub fn edit(&mut self, group: &str, update: Vec<u8>, out: &mut Vec<Value>) -> Result<()> {
        self.apply(group, &update, out)?;
        out.push(json!({ "type": "send", "group": group, "payload": { "type": "edit", "update": Bytes(update) } }));
        Ok(())
    }

    /// Applies an update; if the document links other files than before, tells the host which.
    fn apply(&mut self, group: &str, update: &[u8], out: &mut Vec<Value>) -> Result<()> {
        let old = self.state(group)?;
        let new = ydoc::apply(old, update)?;
        let links = self.kind.links(&new)?;
        if links != self.kind.links(old)? {
            out.push(json!({ "type": "links", "group": group, "links": links }));
        }
        self.states.insert(group.to_owned(), new);
        Ok(())
    }

    /// Opens a group's document from its saved state, and tells the host which files it links.
    pub fn open(&mut self, group: &str, state: Vec<u8>, out: &mut Vec<Value>) -> Result<()> {
        let links = self.kind.links(&state)?;
        out.push(json!({ "type": "links", "group": group, "links": links }));
        self.states.insert(group.to_owned(), state);
        Ok(())
    }
}

/// Where the browser's in-page plugins keep each document: the page's records.
pub trait Store {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn put(&self, key: &str, value: &[u8]);
    fn delete(&self, key: &str);
}

/// A kind as the browser's in-page plugin: it keeps each group's document in the page's records, under
/// `kind/<kind>/<group>`, and the page's views bind to it through commands: `state <group>` gives the state,
/// `diff <group> <state vector>` what a view lacks, and `edit <group> <update>` takes a view's edit. It tells of others'
/// changes as `edited` events.
pub struct Page<S: Store> {
    states: States,
    store: S,
}

impl<S: Store> Page<S> {
    pub fn new(kind: Kind, store: S) -> Self {
        Page { states: States::new(kind), store }
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

    fn key(&self, group: &str) -> String {
        format!("kind/{}/{group}", self.states.kind.name())
    }

    fn take(&mut self, message: &Value, out: &mut Vec<Value>) -> Result<()> {
        let group = message["group"].as_str().unwrap_or_default();
        match str(&message["type"])? {
            "group" => {
                let state = self.store.get(&self.key(group)).unwrap_or_else(|| self.states.kind.new_state());
                self.store.put(&self.key(group), &state);
                self.states.open(group, state, out)?;
                if let Some(id) = message.get("id") {
                    out.push(answer(id, Ok(json!({}))));
                }
            }
            "start" => out.push(answer(&message["id"], Ok(json!({})))),
            "gone" => {
                self.states.states.remove(group);
                self.store.delete(&self.key(group));
                out.push(answer(&message["id"], Ok(json!({}))));
            }
            "command" => {
                let answer_to = &message["id"];
                let args: Vec<&str> = message["args"].as_array().context("no args")?.iter().filter_map(Value::as_str).collect();
                let answered = match args[..] {
                    ["state", group] => json!({ "state": Bytes(self.states.state(group)?.to_vec()) }),
                    ["diff", group, sv] => {
                        let sv = bytes(&json!(sv))?;
                        json!({ "diff": Bytes(ydoc::diff(self.states.state(group)?, &sv)?) })
                    }
                    ["edit", group, update] => {
                        self.states.edit(group, bytes(&json!(update))?, out)?;
                        self.store.put(&self.key(group), self.states.state(group)?);
                        json!({})
                    }
                    _ => bail!("the {} kind's commands in a browser are state, diff and edit", self.states.kind.name()),
                };
                out.push(answer(answer_to, Ok(answered)));
            }
            "sync" => out.push(answer(&message["id"], Ok(json!({})))),
            _ => {
                if let Some((group, from)) = self.states.handle(message, out)? {
                    self.store.put(&self.key(&group), self.states.state(&group)?);
                    out.push(json!({ "type": "event", "group": group, "event": { "type": "edited", "by": [from] } }));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(out: &[Value], kind: &str) -> Value {
        out.iter().find(|m| m["type"] == kind).cloned().unwrap_or_else(|| panic!("no {kind} in {out:?}"))
    }

    #[test]
    fn two_docs_that_differ_converge_through_a_diff() {
        let (mut a, mut b, mut out) = (States::new(Kind::Doc), States::new(Kind::Doc), Vec::new());
        let base = ydoc::new("- [ ] alpha\n");
        a.open("g", base.clone(), &mut out).unwrap();
        b.open("g", base.clone(), &mut out).unwrap();
        a.edit("g", ydoc::edit(&base, "- [x] alpha\n").unwrap(), &mut out).unwrap();
        let link = "lmk:".to_owned() + &"ab".repeat(32) + ".5#" + &"cd".repeat(32);
        assert_eq!(sent(&out, "links")["links"], json!([]));
        out.clear();
        b.edit("g", ydoc::edit(&base, &format!("- [ ] alpha\n[spec]({link})\n")).unwrap(), &mut out).unwrap();
        assert_eq!(sent(&out, "links")["links"], json!([link]));
        let (ann, ben) = (json!({ "fp": "aa" }), json!({ "fp": "bb" }));

        out.clear();
        a.handle(&json!({ "type": "synced", "group": "g", "member": ben }), &mut out).unwrap();
        let snapshot = sent(&out, "send");
        assert_eq!((&snapshot["to"], &snapshot["payload"]["type"]), (&json!("bb"), &json!("snapshot")));
        out.clear();
        b.handle(&json!({ "type": "message", "group": "g", "from": ann, "payload": snapshot["payload"] }), &mut out).unwrap();
        let sv = sent(&out, "send");
        assert_eq!((&sv["to"], &sv["payload"]["type"]), (&json!("aa"), &json!("sv")));
        out.clear();
        a.handle(&json!({ "type": "message", "group": "g", "from": ben, "payload": sv["payload"] }), &mut out).unwrap();
        let diff = sent(&out, "send");
        assert_eq!((&diff["to"], &diff["payload"]["type"]), (&json!("bb"), &json!("diff")));
        let changed = b.handle(&json!({ "type": "message", "group": "g", "from": ann, "payload": diff["payload"] }), &mut out).unwrap();
        assert_eq!(changed, Some(("g".into(), ann)));
        assert_eq!(ydoc::text(b.state("g").unwrap()).unwrap(), format!("- [x] alpha\n[spec]({link})\n"));
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
    fn the_page_keeps_a_doc_and_its_editors_edit_it() {
        let memory = Memory(Default::default());
        let mut page = Page::new(Kind::Doc, &memory);
        page.input(&json!({ "type": "group", "group": "g", "id": 1 }));
        let out = page.input(&json!({ "type": "command", "id": 2, "args": ["state", "g"] }));
        let state = bytes(&sent(&out, "answer")["answer"]["state"]).unwrap();
        assert_eq!(ydoc::text(&state).unwrap(), "");
        let update = Bytes(ydoc::edit(&state, "and now\n").unwrap());
        let out = page.input(&json!({ "type": "command", "id": 3, "args": ["edit", "g", update] }));
        assert_eq!(sent(&out, "send")["payload"]["type"], "edit");
        assert_eq!(ydoc::text(&(&memory).get("kind/doc/g").unwrap()).unwrap(), "and now\n");
        page.input(&json!({ "type": "gone", "group": "g" }));
        assert!((&memory).get("kind/doc/g").is_none());
    }
}
