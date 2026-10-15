//! A group's duties, each derived from committed records and idempotent: a pass runs at the log's head after each
//! advance, at start, and every `TIMER`. It drops what the group kept past H; commits at most once, with every Remove
//! due (members whose `leave` the cut it builds keeps, and members whose devices their identities dropped) and this
//! session's update if due (each T, at an offset of its own), which first fetches for at most `HEAR` what the last commit
//! kept and connected members hold past the cut; and in an identity group, has the identity kind run its own
//! (`Event::Duties`).

use std::sync::{Arc, Mutex};

use anyhow::Result;
use lmk_core::group::{self as core, Change, MAX_CUT_STEP};
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::group::IDENTITY;
use lmk_proto::held::Ref;
use n0_future::time::{Duration, sleep};
use sha2::{Digest, Sha256};

use std::collections::BTreeMap;

use lmk_core::public::{PublicLog, Verdict};
use lmk_net::peers::HEAR;
use lmk_proto::group::Credential;
use lmk_proto::peer::Seqs;

use crate::groups::renaming;
use crate::held::delivered_key;
use crate::reading::{admitted_key, commit_key};
use crate::{Event, G, Inner, State, Work, days, get, now};

/// How often every group's duties run, besides as its log moves.
pub(crate) const TIMER: Duration = Duration::from_secs(10 * 60);
/// How soon a pass runs again while an update waits for its fetch.
const BLOCKED: u64 = 10_000;

/// When the leaf of the member with key `key`, last updated at `updated`, is next due an update, in milliseconds: at its
/// first slot after `updated`, its slots every `update` seconds at an offset by a hash of its key, so that members
/// update apart.
pub(crate) fn next_update(updated: u64, update: u32, key: &[u8]) -> u64 {
    let t = update.max(1) as u64 * 1000;
    let offset = u64::from_be_bytes(Sha256::digest(key)[..8].try_into().unwrap()) % t;
    (updated + t - offset) / t * t + offset
}

impl<P: Provider> State<P> {
    /// The cut a commit this session builds now carries: per member of the epoch, from the cut state on, each seq it
    /// holds sealed in the current epoch whose `prev` chains to the last; its own only as far as another member's
    /// summary shows held.
    pub(crate) fn cut_for(&self, gid: &[u8]) -> Result<Vec<Ref>> {
        let g = self.group(gid)?;
        let (epoch, me) = (g.mls.epoch(), self.me(gid));
        let mut cut = Vec::new();
        for r in g.mls.cut() {
            let (mut seq, mut id) = (r.seq, r.id.clone());
            while seq < r.seq + MAX_CUT_STEP {
                let Some(record) = self.record_at(gid, &r.key.0, r.joined, seq + 1)? else { break };
                let sealed = record.sealing.as_ref().is_some_and(|(sealed, _)| *sealed == epoch);
                let chained = record.header.prev.as_ref() == (seq > 0).then_some(&id);
                if !sealed || !chained || (r.key.0 == me && self.holders_of(gid, seq + 1)?.is_empty()) {
                    break;
                }
                (seq, id) = (seq + 1, record.id);
            }
            cut.push(Ref { key: r.key.clone(), joined: r.joined, seq, id });
        }
        Ok(cut)
    }

    /// When the fetch an update waits on ends, while it waits for what `fetchable` lists.
    fn fetch_wait(&mut self, gid: &[u8], now: u64) -> Result<Option<u64>> {
        let live = self.fetchable(gid)?;
        let g = self.group_mut(gid)?;
        if g.fetch.is_none() && !live.is_empty() {
            g.fetch = Some((live.clone(), now));
        }
        Ok(g.fetch.as_ref().filter(|(fixed, since)| waits(fixed, *since, &live, now)).map(|(_, since)| since + HEAR))
    }

    /// Drops what the group kept past H: delivered messages (but this session's own that no cut kept), commit entries,
    /// invites, file links, earlier logs, and memberships that ended with nothing left here.
    fn expire(&mut self, gid: &[u8]) -> Result<()> {
        let before = now().saturating_sub(days(self.group(gid)?.mls.settings().carry));
        self.drop_earlier(gid, before)?;
        let g = self.group_mut(gid)?;
        g.rec.files.retain(|(_, at)| *at >= before);
        g.rec.invites.retain(|rule| rule.expires >= before);
        let (old, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut g.rec.commits).into_iter().partition(|(_, at)| *at < before);
        g.rec.commits = kept;
        for (epoch, _) in old {
            self.provider.delete(&commit_key(gid, epoch))?;
            self.provider.delete(&admitted_key(gid, epoch))?;
        }
        let rec = &self.group(gid)?.rec;
        let (mut first, last) = (rec.first.max(1), rec.index);
        while first <= last {
            if let Some(id) = get::<Bytes>(&self.provider, &delivered_key(gid, first))?
                && let Some(record) = self.record(gid, &id.0)?
            {
                if record.delivered.as_ref().is_some_and(|d| d.at >= before) || record.plaintext.is_some() {
                    break;
                }
                let h = &record.header;
                if let Some(author) = self.group_mut(gid)?.author_mut(&h.author.0, h.joined) {
                    author.servable.remove(h.seq);
                }
                self.unstore(gid, &record)?;
                self.scrub = true;
            }
            first += 1;
        }
        let rec = &mut self.group_mut(gid)?.rec;
        rec.first = first;
        let keep = rec.keep.clone();
        rec.authors.retain(|a| !a.ended || !a.servable.is_empty() || a.held != a.delivered || keep.iter().any(|k| k.key == a.key && k.joined == a.joined));
        self.save(gid)
    }
}

/// What a pass commits on the group as it stands, if anything: the Removes due and this session's update; with the
/// members removed whose devices were dropped.
fn due<P: Provider>(st: &State<P>, g: &G) -> Result<Option<(Change, Vec<core::Member>)>> {
    let gid = g.mls.id();
    let me = st.me(gid);
    let cut = st.cut_for(gid)?;
    let members = g.mls.members();
    let others = members.iter().filter(|m| m.key != me);
    let dropped = |m: &&core::Member| m.credential.as_ref().is_some_and(|c| dropped(&st.public, c));
    let dropped: Vec<core::Member> = others.clone().filter(dropped).cloned().collect();
    let kept = |m: &core::Member| g.left(&m.key).is_some_and(|seq| cut.iter().any(|r| r.key.0 == m.key && r.seq >= seq));
    let remove: Vec<u32> = others.filter(|m| kept(m) || g.left_behind(&m.key) || dropped.iter().any(|d| d.index == m.index)).map(|m| m.index).collect();
    let Some(own) = members.iter().find(|m| m.index == g.mls.own_index()) else { return Ok(None) };
    let name = renaming(&g.mls, st.device.as_deref());
    let leaf = &st.session.leaf;
    let update = own.leaf.as_ref() != Some(leaf) || name.is_some() || now() >= next_update(g.rec.updated, g.mls.settings().update, me);
    Ok((update || !remove.is_empty()).then(|| (Change { remove, leaf: Some(leaf.clone()), name, cut, ..Change::default() }, dropped)))
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
            if !g.mls.active() || !st.at_head(gid) || g.waiting {
                return Ok(());
            }
            if g.rec.leaving && g.mls.members().len() == 1 {
                drop(st);
                self.gone(gid, None);
                return Ok(());
            }
            st.expire(gid)?;
            if st.group(gid)?.mls.settings().kind == IDENTITY {
                st.events.push(Event::Duties { group: Bytes(gid.to_vec()) });
            }
            let tick = st.tick();
            let g = st.group(gid)?;
            let next = next_update(g.rec.updated, g.mls.settings().update, st.me(gid));
            let pending = due(&st, g)?;
            // A pass that removes commits at once.
            let removing = pending.as_ref().is_some_and(|(change, _)| !change.remove.is_empty());
            let fetch = if pending.is_some() && !removing { st.fetch_wait(gid, tick)? } else { None };
            let next = match fetch {
                Some(until) => (now() + BLOCKED).min(until),
                None => next,
            };
            (pending.is_some() && fetch.is_none(), next)
        };
        self.time(gid, next);
        if !commit {
            return Ok(());
        }
        let removing = Mutex::new(Vec::new());
        let committed = self
            .commit(gid, |st, g| {
                let Some((change, dropped)) = due(st, g)? else { return Ok(None) };
                *removing.lock().unwrap() = dropped;
                Ok(Some(change))
            })
            .await?;
        let removed = removing.into_inner().unwrap();
        if committed.is_some() && !removed.is_empty() {
            self.revoked(gid, &removed)?;
        }
        Ok(())
    }

    /// Runs the group's duties again at `at`, if that is sooner than `TIMER` and than the run already timed.
    fn time(self: &Arc<Self>, gid: &[u8], at: u64) {
        let wait = at.saturating_sub(now());
        if wait == 0 || wait >= TIMER.as_millis() as u64 {
            return;
        }
        {
            let mut timers = self.timers.lock().unwrap();
            if timers.get(gid).is_some_and(|due| *due <= at) {
                return;
            }
            timers.insert(gid.to_vec(), at);
        }
        let (inner, gid) = (self.clone(), gid.to_vec());
        self.spawn(async move {
            sleep(Duration::from_millis(wait)).await;
            {
                let mut timers = inner.timers.lock().unwrap();
                if timers.get(&gid) == Some(&at) {
                    timers.remove(&gid);
                }
            }
            inner.work.send(Work::Duties(gid)).ok();
        });
    }

    /// Tells that this session's commit removed members whose devices were dropped, and which members they added or
    /// let in by their invites.
    fn revoked(&self, gid: &[u8], removed: &[core::Member]) -> Result<()> {
        let mut st = self.lock();
        let g = st.group(gid)?;
        let by_them = |key: &[u8]| removed.iter().any(|m| m.key == key);
        let invites: Vec<&Bytes> = g.rec.invites.iter().filter(|rule| by_them(&rule.by.0)).map(|rule| &rule.hash).collect();
        let let_in = |m: &core::Member| {
            let added = g.mls.added().iter().rev().find(|added| added.member.key.0 == m.key);
            added.is_some_and(|added| by_them(&added.by.key.0) || added.invite.as_ref().is_some_and(|invite| invites.contains(&invite)))
        };
        let added = g.mls.members().into_iter().filter(let_in).filter_map(|m| st.member(gid, &m)).collect();
        let removed = removed.iter().filter_map(|m| st.member(gid, m)).collect();
        st.events.push(Event::Revoked { group: Bytes(gid.to_vec()), removed, added });
        Ok(())
    }
}

/// Whether an update waits on its fetch: while `live`, the seqs connected members list that it lacks, still holds any of
/// `fixed`, those it listed when it first waited in this epoch `since`, for at most `HEAR`.
fn waits(fixed: &[Seqs], since: u64, live: &[Seqs], now: u64) -> bool {
    now < since + HEAR && live.iter().any(|want| fixed.iter().any(|f| f.key == want.key && f.joined == want.joined && !f.seqs.intersection(&want.seqs).is_empty()))
}

/// Whether a member's device was dropped from its identity's list, as the public logs held show it.
fn dropped(public: &BTreeMap<Vec<u8>, PublicLog>, credential: &Credential) -> bool {
    let log = credential.identity().and_then(|identity| public.get(&identity.id.0));
    log.is_some_and(|log| log.verify(credential) == Verdict::Dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lmk_proto::ranges::Ranges;

    fn seqs(key: &[u8], joined: u64, seqs: &[u64]) -> Seqs {
        Seqs { key: Bytes(key.to_vec()), joined, seqs: seqs.iter().copied().collect::<Ranges>() }
    }

    #[test]
    fn an_update_waits_for_what_was_listed_when_it_first_waited_for_at_most_hear() {
        let fixed = [seqs(b"a", 0, &[3, 4])];
        assert!(waits(&fixed, 1_000, &[seqs(b"a", 0, &[4]), seqs(b"b", 0, &[9])], 5_000), "seq 4 still lacking");
        assert!(!waits(&fixed, 1_000, &[seqs(b"b", 0, &[9])], 5_000), "nothing fixed is still lacking");
        assert!(!waits(&fixed, 1_000, &[seqs(b"a", 0, &[3])], 1_000 + HEAR), "HEAR is up");
    }

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
