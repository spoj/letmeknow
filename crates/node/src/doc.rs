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
    Ok(load(state)?
        .transact()
        .encode_state_as_update_v1(&StateVector::decode_v1(sv)?))
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
            let link: String = text[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || ":.#".contains(*c))
                .collect();
            FileLink::parse(&link).ok()
        })
        .collect()
}
