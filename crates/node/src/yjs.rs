//! The Yjs state of a devices group's contacts, synced as a doc's text was: live edits, and diffs answering the state
//! vector of a member whose snapshot differs (deletions do not move a state vector).

use anyhow::Result;
use sha2::{Digest, Sha256};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{Doc, Options, ReadTxn, StateVector, Transact, Update};

fn load(state: &[u8]) -> Result<Doc> {
    // A fresh client id for every load: edits made here must never reuse the clock of an earlier client.
    let doc = Doc::with_options(Options::default());
    doc.transact_mut().apply_update(Update::decode_v1(state)?)?;
    Ok(doc)
}

/// Applies an update to a state. An update may arrive before the updates it builds on; until those arrive it is kept
/// as it came.
pub fn apply(state: &[u8], update: &[u8]) -> Result<Vec<u8>> {
    let doc = load(state)?;
    doc.transact_mut().apply_update(Update::decode_v1(update)?)?;
    let txn = doc.transact();
    if txn.store().pending_update().is_none() && txn.store().pending_ds().is_none() {
        return Ok(txn.encode_state_as_update_v1(&StateVector::default()));
    }
    Ok(yrs::merge_updates_v1([state, update])?)
}

/// SHA-256 of the snapshot, which two members compare.
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
