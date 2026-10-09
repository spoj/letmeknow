//! The doc kind: one markdown text that every member edits at once, a Yjs document. Edits go live to the members online
//! and are not held; two members that meet compare their docs by a hash of each one's snapshot (`doc` frames), and if
//! they differ, each sends the other a `diff` against the other's state vector (`doc_sv`). An inviter hands a joiner
//! the doc's state. The doc links files as `lmk:` links, which members hold while it does.
//!
//! `Docs` is what every host of the kind does alike, in the plugin protocol (PROTOCOL.md): the session's plugin
//! `letmeknow-kind-doc` (src/main.rs), which keeps each doc in a file, and the browser's in-page plugin (`Page`),
//! which an editor binds to.

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

/// The docs of this session's doc groups, by group id: each one's Yjs state.
#[derive(Default)]
pub struct Docs {
    pub states: HashMap<String, Vec<u8>>,
}

impl Docs {
    pub fn state(&self, group: &str) -> Result<&[u8]> {
        self.states.get(group).map(Vec::as_slice).context("not a doc of this session")
    }

    pub fn text(&self, group: &str) -> Result<String> {
        ydoc::text(self.state(group)?)
    }

    /// Takes in what every host takes in alike: `message` (`edit`, `diff`), `frame` (`doc`, `doc_sv`), `synced`,
    /// `state` and `snapshot`; what it sends goes to `out`. Returns the group whose doc changed and the member who
    /// changed it, if any. Other messages are the host's.
    pub fn handle(&mut self, message: &Value, out: &mut Vec<Value>) -> Result<Option<(String, Value)>> {
        let group = message["group"].as_str().unwrap_or_default().to_owned();
        match str(&message["type"])? {
            "message" if matches!(message["payload"]["type"].as_str(), Some("edit" | "diff")) => {
                self.apply(&group, &bytes(&message["payload"]["update"])?, out)?;
                Ok(Some((group, message["from"].clone())))
            }
            "state" => {
                self.apply(&group, &bytes(&message["data"])?, out)?;
                Ok(Some((group, message["from"].clone())))
            }
            "frame" => {
                let to = &message["from"]["fp"];
                let state = self.state(&group)?;
                if let Some(snapshot) = message["frame"]["doc"].get("snapshot") {
                    if bytes(snapshot)? != ydoc::snapshot(state)? {
                        let sv = Bytes(ydoc::state_vector(state)?);
                        out.push(json!({ "type": "frame", "group": group, "to": to, "frame": { "doc_sv": { "sv": sv } } }));
                    }
                } else if let Some(sv) = message["frame"]["doc_sv"].get("sv") {
                    let diff = json!({ "type": "diff", "update": Bytes(ydoc::diff(state, &bytes(sv)?)?) });
                    out.push(json!({ "type": "send", "group": group, "to": to, "payload": diff }));
                }
                Ok(None)
            }
            "synced" => {
                let snapshot = Bytes(ydoc::snapshot(self.state(&group)?)?.to_vec());
                let to = &message["member"]["fp"];
                out.push(json!({ "type": "frame", "group": group, "to": to, "frame": { "doc": { "snapshot": snapshot } } }));
                Ok(None)
            }
            "snapshot" => {
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

    /// Applies an update; if the doc links other files than before, tells the host which.
    fn apply(&mut self, group: &str, update: &[u8], out: &mut Vec<Value>) -> Result<()> {
        let old = self.state(group)?;
        let new = ydoc::apply(old, update)?;
        let links = ydoc::links(&ydoc::text(&new)?);
        if links != ydoc::links(&ydoc::text(old)?) {
            out.push(json!({ "type": "links", "group": group, "links": links }));
        }
        self.states.insert(group.to_owned(), new);
        Ok(())
    }

    /// Opens a group's doc from its saved state, and tells the host which files it links.
    pub fn open(&mut self, group: &str, state: Vec<u8>, out: &mut Vec<Value>) -> Result<()> {
        let links = ydoc::links(&ydoc::text(&state)?);
        out.push(json!({ "type": "links", "group": group, "links": links }));
        self.states.insert(group.to_owned(), state);
        Ok(())
    }
}

/// Where the browser's in-page plugin keeps each doc's state: the page's records.
pub trait Store {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn put(&self, key: &str, value: &[u8]);
    fn delete(&self, key: &str);
}

/// The doc kind as the browser's in-page plugin: it keeps each doc's state in the page's records, under `kind/doc/<group>`,
/// and its editors bind to it through commands: `state <group>` gives the state, `diff <group> <state vector>` what an
/// editor lacks, and `edit <group> <update>` takes an editor's edit. It tells of others' changes as `edited` events.
pub struct Page<S: Store> {
    docs: Docs,
    store: S,
}

impl<S: Store> Page<S> {
    pub fn new(store: S) -> Self {
        Page { docs: Docs::default(), store }
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

    fn take(&mut self, message: &Value, out: &mut Vec<Value>) -> Result<()> {
        let group = message["group"].as_str().unwrap_or_default();
        let key = format!("kind/doc/{group}");
        match str(&message["type"])? {
            "group" => {
                let imported = message["import"].get("state").map(bytes).transpose()?;
                let state = self.store.get(&key).or(imported).unwrap_or_else(|| ydoc::new(""));
                self.store.put(&key, &state);
                self.docs.open(group, state, out)?;
                if let Some(id) = message.get("id") {
                    out.push(answer(id, Ok(json!({}))));
                }
            }
            "gone" => {
                self.docs.states.remove(group);
                self.store.delete(&key);
            }
            "command" => {
                let answer_to = &message["id"];
                let args: Vec<&str> = message["args"].as_array().context("no args")?.iter().filter_map(Value::as_str).collect();
                let answered = match args[..] {
                    ["state", group] => json!({ "state": Bytes(self.docs.state(group)?.to_vec()) }),
                    ["diff", group, sv] => {
                        let sv = bytes(&json!(sv))?;
                        json!({ "diff": Bytes(ydoc::diff(self.docs.state(group)?, &sv)?) })
                    }
                    ["edit", group, update] => {
                        self.docs.edit(group, bytes(&json!(update))?, out)?;
                        self.store.put(&format!("kind/doc/{group}"), self.docs.state(group)?);
                        json!({})
                    }
                    _ => bail!("the doc kind's commands in a browser are state, diff and edit"),
                };
                out.push(answer(answer_to, Ok(answered)));
            }
            "sync" => out.push(answer(&message["id"], Ok(json!({})))),
            _ => {
                if let Some((group, from)) = self.docs.handle(message, out)? {
                    self.store.put(&format!("kind/doc/{group}"), self.docs.state(&group)?);
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
    fn two_docs_that_differ_converge_through_frames_and_a_diff() {
        let (mut a, mut b, mut out) = (Docs::default(), Docs::default(), Vec::new());
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
        let frame = sent(&out, "frame");
        assert_eq!(frame["to"], "bb");
        out.clear();
        b.handle(&json!({ "type": "frame", "group": "g", "from": ann, "frame": frame["frame"] }), &mut out).unwrap();
        let frame = sent(&out, "frame");
        assert!(frame["frame"]["doc_sv"]["sv"].is_string());
        out.clear();
        a.handle(&json!({ "type": "frame", "group": "g", "from": ben, "frame": frame["frame"] }), &mut out).unwrap();
        let diff = sent(&out, "send");
        assert_eq!((&diff["to"], &diff["payload"]["type"]), (&json!("bb"), &json!("diff")));
        let changed = b.handle(&json!({ "type": "message", "group": "g", "from": ann, "payload": diff["payload"], "held": false }), &mut out).unwrap();
        assert_eq!(changed, Some(("g".into(), ann)));
        assert_eq!(b.text("g").unwrap(), format!("- [x] alpha\n[spec]({link})\n"));
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
    fn the_page_keeps_a_doc_imported_from_0_10_and_its_editors_edit_it() {
        let memory = Memory(Default::default());
        let mut page = Page::new(&memory);
        let old = Bytes(ydoc::new("from 0.10\n"));
        page.input(&json!({ "type": "group", "group": "g", "id": 1, "import": { "state": old } }));
        let out = page.input(&json!({ "type": "command", "id": 2, "args": ["state", "g"] }));
        let state = bytes(&sent(&out, "answer")["answer"]["state"]).unwrap();
        assert_eq!(ydoc::text(&state).unwrap(), "from 0.10\n");
        let update = Bytes(ydoc::edit(&state, "from 0.10\nand now\n").unwrap());
        let out = page.input(&json!({ "type": "command", "id": 3, "args": ["edit", "g", update] }));
        assert_eq!(sent(&out, "send")["payload"]["type"], "edit");
        assert_eq!(ydoc::text(&(&memory).get("kind/doc/g").unwrap()).unwrap(), "from 0.10\nand now\n");
        page.input(&json!({ "type": "gone", "group": "g" }));
        assert!((&memory).get("kind/doc/g").is_none());
    }
}
