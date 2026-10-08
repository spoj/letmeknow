//! A doc group's text: a Yjs document holding one text, so the browser (Yjs) and the session process (yrs) edit the
//! same document. Its state is a Yjs update holding everything.

use anyhow::Result;
use lmk_proto::links::FileLink;
use sha2::{Digest, Sha256};
use similar::{ChangeTag, TextDiff};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{Doc, GetString, Options, ReadTxn, StateVector, Text, Transact, Update};

/// The name of the text inside the document, which the browser binds to its editor.
const TEXT: &str = "text";

/// The state of a new document holding `text`.
pub fn new(text: &str) -> Vec<u8> {
    let doc = Doc::new();
    let body = doc.get_or_insert_text(TEXT);
    body.insert(&mut doc.transact_mut(), 0, text);
    doc.transact().encode_state_as_update_v1(&StateVector::default())
}

fn load(state: &[u8]) -> Result<Doc> {
    // A fresh client id for every load: edits made here must never reuse the clock of an earlier client.
    let doc = Doc::with_options(Options::default());
    doc.transact_mut().apply_update(Update::decode_v1(state)?)?;
    Ok(doc)
}

/// Applies an update to a document's state. An update may arrive before the updates it builds on; until those arrive
/// it is kept as it came.
pub fn apply(state: &[u8], update: &[u8]) -> Result<Vec<u8>> {
    let doc = load(state)?;
    doc.transact_mut().apply_update(Update::decode_v1(update)?)?;
    let txn = doc.transact();
    if txn.store().pending_update().is_none() && txn.store().pending_ds().is_none() {
        return Ok(txn.encode_state_as_update_v1(&StateVector::default()));
    }
    Ok(yrs::merge_updates_v1([state, update])?)
}

pub fn text(state: &[u8]) -> Result<String> {
    let doc = load(state)?;
    let body = doc.get_or_insert_text(TEXT);
    Ok(body.get_string(&doc.transact()))
}

/// SHA-256 of the doc's snapshot, which two members compare: deletions do not move a state vector.
pub fn snapshot(state: &[u8]) -> Result<[u8; 32]> {
    Ok(Sha256::digest(load(state)?.transact().snapshot().encode_v1()).into())
}

pub fn state_vector(state: &[u8]) -> Result<Vec<u8>> {
    Ok(load(state)?.transact().state_vector().encode_v1())
}

/// What a member whose state vector is `sv` lacks.
pub fn diff(state: &[u8], sv: &[u8]) -> Result<Vec<u8>> {
    Ok(load(state)?.transact().encode_state_as_update_v1(&StateVector::decode_v1(sv)?))
}

/// The update that makes the text of `state` read `new`, as edits on `state`.
pub fn edit(state: &[u8], new: &str) -> Result<Vec<u8>> {
    let doc = load(state)?;
    let body = doc.get_or_insert_text(TEXT);
    let old = body.get_string(&doc.transact());
    let before = doc.transact().state_vector();
    {
        let mut txn = doc.transact_mut();
        let mut at = 0;
        for change in TextDiff::from_chars(old.as_str(), new).iter_all_changes() {
            let value = change.value();
            let len = value.len() as u32;
            match change.tag() {
                ChangeTag::Equal => at += len,
                ChangeTag::Delete => body.remove_range(&mut txn, at, len),
                ChangeTag::Insert => {
                    body.insert(&mut txn, at, value);
                    at += len;
                }
            }
        }
    }
    Ok(doc.transact().encode_state_as_update_v1(&before))
}

/// The file links in a text.
pub fn links(text: &str) -> Vec<FileLink> {
    text.match_indices("lmk:")
        .filter_map(|(at, _)| {
            let link: String =
                text[at..].chars().take_while(|c| c.is_ascii_alphanumeric() || ":.#".contains(*c)).collect();
            FileLink::parse(&link).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n";

    #[test]
    fn edits_merge_with_concurrent_ones() {
        let state = new(BASE);
        let theirs = edit(&state, "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n- [ ] delta\n").unwrap();
        let ours = edit(&state, "- [x] alpha\n- [ ] beta\n- [ ] gamma\n").unwrap();
        let merged = apply(&apply(&state, &theirs).unwrap(), &ours).unwrap();
        assert_eq!(text(&merged).unwrap(), "- [x] alpha\n- [ ] beta\n- [ ] gamma\n- [ ] delta\n");
    }

    #[test]
    fn an_update_that_arrives_early_waits_for_the_one_it_builds_on() {
        let state = new(BASE);
        let first = edit(&state, "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n- [ ] delta\n").unwrap();
        let second =
            edit(&apply(&state, &first).unwrap(), "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n- [x] delta\n").unwrap();
        let early = apply(&state, &second).unwrap();
        assert_eq!(text(&early).unwrap(), BASE);
        assert_eq!(
            text(&apply(&early, &first).unwrap()).unwrap(),
            "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n- [x] delta\n"
        );
    }

    #[test]
    fn members_that_differ_converge_by_diff() {
        let state = new(BASE);
        let ours = apply(&state, &edit(&state, "- [x] alpha\n- [ ] beta\n- [ ] gamma\n").unwrap()).unwrap();
        let theirs = apply(&state, &edit(&state, "- [ ] alpha\n- [ ] gamma\n").unwrap()).unwrap();
        assert_ne!(snapshot(&ours).unwrap(), snapshot(&theirs).unwrap());
        let ours = apply(&ours, &diff(&theirs, &state_vector(&ours).unwrap()).unwrap()).unwrap();
        let theirs = apply(&theirs, &diff(&ours, &state_vector(&theirs).unwrap()).unwrap()).unwrap();
        assert_eq!(text(&ours).unwrap(), "- [x] alpha\n- [ ] gamma\n");
        assert_eq!(snapshot(&ours).unwrap(), snapshot(&theirs).unwrap());
    }
}
