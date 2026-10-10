//! A group's duties, each derived from committed records and idempotent: a pass runs at the log's head after each
//! advance, at start, and every `TIMER`. It drops what the group kept past H; commits at most once, with every Remove
//! due (members whose counted `leave` was sealed in their current membership, and members whose devices their
//! identities dropped) and this session's update if due (each T, at an offset of its own); asks the others to remove
//! this session while it leaves; announces this session's known losses; and in a devices group, has the devices kind
//! run its own (`Event::Duties`).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use lmk_core::group::{self as core, Change};
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::group::{Control, DEVICES, type_of};
use n0_future::time::{Duration, sleep};
use serde_json::json;
use sha2::{Digest, Sha256};

use std::collections::BTreeMap;

use lmk_core::identity::{KeyLog, Verdict};
use lmk_proto::group::Credential;

use crate::groups::renaming;
use crate::{Dropped, Event, G, Inner, Observation, State, Work, now};

/// How often every group's duties run, besides as its log moves.
pub(crate) const TIMER: Duration = Duration::from_secs(10 * 60);

/// When the leaf of the member with key `key`, last updated at `updated`, is next due an update, in milliseconds: at its
/// first slot after `updated`, its slots every `update` seconds at an offset by a hash of its key, so that members
/// update apart.
pub(crate) fn next_update(updated: u64, update: u32, key: &[u8]) -> u64 {
    let t = update.max(1) as u64 * 1000;
    let offset = u64::from_be_bytes(Sha256::digest(key)[..8].try_into().unwrap()) % t;
    (updated + t - offset) / t * t + offset
}

/// What a pass commits on the group as it stands, if anything: the Removes due and this session's update; with the
/// members removed whose devices were dropped.
fn due<P: Provider>(st: &State<P>, g: &G) -> Option<(Change, Vec<core::Member>)> {
    let me = st.me(g.mls.id());
    let members = g.mls.members();
    let added = |key: &[u8]| g.mls.added().iter().rev().find(|added| added.member.key.0 == key).map_or(0, |added| added.epoch);
    let left = |m: &core::Member| g.rec.leaves.iter().any(|(key, epoch)| key.0 == m.key && *epoch >= added(&m.key));
    let others = members.iter().filter(|m| m.key != me);
    let dropped: Vec<core::Member> = others.clone().filter(|m| m.credential.as_ref().is_some_and(|c| dropped(&st.keys, c))).cloned().collect();
    let remove: Vec<u32> = others.filter(|m| left(m) || dropped.iter().any(|d| d.index == m.index)).map(|m| m.index).collect();
    let own = members.iter().find(|m| m.index == g.mls.own_index())?;
    let name = renaming(&g.mls, st.device.as_deref());
    let leaf = &st.session.leaf;
    let update = own.leaf.as_ref() != Some(leaf) || name.is_some() || now() >= next_update(g.rec.updated, g.mls.settings().update, me);
    (update || !remove.is_empty()).then(|| (Change { remove, leaf: Some(leaf.clone()), name, ..Change::default() }, dropped))
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Runs a pass of a group's duties; if one runs, another once it ends.
    pub(crate) fn duties(self: &Arc<Self>, gid: &[u8]) {
        {
            let mut passing = self.passing.lock().unwrap();
            if let Some(again) = passing.get_mut(gid) {
                *again = true;
                return;
            }
            passing.insert(gid.to_vec(), false);
        }
        let (inner, gid) = (self.clone(), gid.to_vec());
        self.spawn(async move {
            loop {
                if let Err(error) = inner.pass(&gid).await
                    && inner.lock().groups.contains_key(&gid)
                {
                    inner.warn(Some(&gid), format!("{error:#}"));
                }
                let mut passing = inner.passing.lock().unwrap();
                if !std::mem::take(passing.get_mut(&gid).unwrap()) {
                    passing.remove(&gid);
                    return;
                }
            }
        });
    }

    async fn pass(self: &Arc<Self>, gid: &[u8]) -> Result<()> {
        let (commit, next) = {
            let mut st = self.lock();
            let Some(g) = st.groups.get(gid) else { return Ok(()) };
            if !g.mls.active() || g.rec.position < st.log(gid)?.logged || g.waiting {
                return Ok(());
            }
            if g.rec.leaving && g.mls.members().len() == 1 {
                st.observe(|| Observation::Dropped { group: Bytes(gid.to_vec()), reason: Dropped::Forgotten });
                drop(st);
                self.gone(gid, None);
                return Ok(());
            }
            let expired = g.rec.expired;
            st.expire(gid)?;
            st.scrub |= st.group(gid)?.rec.expired != expired;
            self.leaving(&mut st, gid)?;
            self.announce(&mut st, gid)?;
            if st.group(gid)?.mls.settings().kind == DEVICES {
                self.events.send(Event::Duties { group: Bytes(gid.to_vec()) }).ok();
            }
            let g = st.group(gid)?;
            (due(&st, g).is_some(), next_update(g.rec.updated, g.mls.settings().update, st.me(gid)))
        };
        self.time(gid, next);
        if !commit {
            return Ok(());
        }
        let removing = Mutex::new(Vec::new());
        let committed = self
            .commit(gid, |st, g| {
                let Some((change, dropped)) = due(st, g) else { return Ok(None) };
                *removing.lock().unwrap() = dropped;
                Ok(Some(change))
            })
            .await?;
        let removed = removing.into_inner().unwrap();
        if committed.is_some() && !removed.is_empty() {
            self.revoked(gid, removed)?;
        }
        Ok(())
    }

    /// While this session leaves a group, it asks the others to remove it, unless a `leave` of its own counts in the
    /// current or prior epoch, or is being sent.
    fn leaving(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        let g = st.group(gid)?;
        let (me, epoch) = (st.me(gid), g.mls.epoch());
        let counts = g.rec.leaves.iter().any(|(key, sealed)| key.0 == me && sealed + 1 >= epoch);
        if g.rec.leaving && !counts && !st.sending(gid)?.iter().any(|(_, payload)| type_of(payload) == "leave") {
            self.start_send(st, gid, &json!({ "type": "leave" }))?;
        }
        Ok(())
    }

    /// Announces this session's known losses that no counted `lost` of its own, nor one being sent, names.
    fn announce(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
        let g = st.group(gid)?;
        let me = st.me(gid);
        let mut told: BTreeSet<u64> = g.rec.losses.values().filter(|(key, _)| key.0 == me).flat_map(|(_, lost)| lost.clone()).collect();
        for (_, payload) in st.sending(gid)? {
            if let Ok(Control::Lost { positions }) = serde_json::from_value(payload) {
                told.extend(positions);
            }
        }
        let positions: Vec<u64> = g.rec.lost.iter().filter(|position| !told.contains(position)).collect();
        if !positions.is_empty() {
            self.start_send(st, gid, &serde_json::to_value(Control::Lost { positions })?)?;
        }
        Ok(())
    }

    /// Runs the group's duties again at `at`, when this session's update is due, if that is sooner than `TIMER`.
    fn time(self: &Arc<Self>, gid: &[u8], at: u64) {
        let wait = at.saturating_sub(now());
        if wait == 0 || wait >= TIMER.as_millis() as u64 || !self.timers.lock().unwrap().insert(gid.to_vec()) {
            return;
        }
        let (inner, gid) = (self.clone(), gid.to_vec());
        self.spawn(async move {
            sleep(Duration::from_millis(wait)).await;
            inner.timers.lock().unwrap().remove(&gid);
            inner.work.send(Work::Duties(gid)).ok();
        });
    }

    /// Tells that this session's commit removed members whose devices were dropped, and which members they added or
    /// let in by their invites.
    fn revoked(&self, gid: &[u8], removed: Vec<core::Member>) -> Result<()> {
        let st = self.lock();
        let g = st.group(gid)?;
        let by_them = |key: &[u8]| removed.iter().any(|m| m.key == key);
        let invites: Vec<&Bytes> = g.rec.invites.iter().filter(|rule| by_them(&rule.by.0)).map(|rule| &rule.hash).collect();
        let let_in = |m: &core::Member| {
            let added = g.mls.added().iter().rev().find(|added| added.member.key.0 == m.key);
            added.is_some_and(|added| by_them(&added.by.key.0) || added.invite.as_ref().is_some_and(|invite| invites.contains(&invite)))
        };
        let added = g.mls.members().into_iter().filter(let_in).filter_map(|m| st.member(gid, &m)).collect();
        let removed = removed.iter().filter_map(|m| st.member(gid, m)).collect();
        self.events.send(Event::Revoked { group: Bytes(gid.to_vec()), removed, added }).ok();
        Ok(())
    }
}

/// Whether a member's device was dropped from its identity's list, as the key logs held show it.
fn dropped(keys: &BTreeMap<Vec<u8>, KeyLog>, credential: &Credential) -> bool {
    let log = credential.identity().and_then(|identity| keys.get(&identity.id.0));
    log.is_some_and(|log| log.verify(credential) == Verdict::Dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_member_updates_every_t_at_an_offset_of_its_own() {
        let day = 24 * 3600;
        let (a, b) = (next_update(0, day, b"a"), next_update(0, day, b"b"));
        assert!(a != b && a <= day as u64 * 1000 && b <= day as u64 * 1000);
        for updated in [1, a - 1, a, a + 1, a + 5 * 3600 * 1000] {
            let next = next_update(updated, day, b"a");
            assert!(next > updated && next <= updated + day as u64 * 1000, "{updated}: {next}");
            assert_eq!(next % (day as u64 * 1000), a % (day as u64 * 1000), "on the member's slot");
        }
    }
}
