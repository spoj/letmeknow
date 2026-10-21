//! A group's duties, each derived from committed records and idempotent: a pass runs at the log's head after each
//! advance, at start, and at this session's next update, and one whose commit failed again after `RETRY`. It drops what
//! the group kept past H, and commits at most once, with every Remove due (members whose `leave` the cut it builds
//! keeps, and members left behind in an epoch whose log was let go, as the service answered at most a day before) and
//! this session's update if due: T after the last, at an offset of its own, once the group delivered a message or
//! changed its members since. The update first fetches for at most `HEAR` what the last commit kept and connected
//! members hold past the cut. T grows with the group, so that its members update about hourly between them, up to three
//! days: an online member's update shows it is there well within the services' retention.

use std::sync::Arc;

use anyhow::Result;
use lmk_core::group::{Change, MAX_CUT_STEP};
use lmk_proto::Bytes;
use lmk_proto::group::{Control, Leaf};
use lmk_proto::clock::corrected;
use lmk_proto::held::Ref;
use n0_future::time::{Duration, sleep};
use sha2::{Digest, Sha256};

use lmk_net::peers::HEAR;
use lmk_proto::peer::Seqs;

use crate::held::delivered_key;
use crate::reading::commit_key;
use crate::{G, Inner, State, Work, days, get, now};

/// How soon a pass runs again while an update waits for its fetch.
const BLOCKED: u64 = 10_000;
/// How soon a pass runs again after its commit failed, as while the service is down.
const RETRY: u64 = 10 * 60 * 1000;
/// How often a member asks which members' logs their services let go, at most, in milliseconds.
const EVICT: u64 = 24 * 3600 * 1000;
/// How long after the group moved past the last epoch this session showed itself in, by a commit or message of its own,
/// it sends a `present`: after the updates a message stirs, and well before the services let that epoch's log go, a
/// week after.
pub(crate) const PRESENT: u64 = 2 * 24 * 3600 * 1000;

/// T, in milliseconds, for a group of `members` whose settings name `update` seconds: that, times the members past 24
/// over 24, up to three times that.
pub(crate) fn interval(update: u32, members: usize) -> u64 {
    update.max(1) as u64 * 1000 * (members as u64).clamp(24, 72) / 24
}

/// When the leaf of the member with key `key`, last updated at `updated`, is next due an update, in milliseconds: at its
/// first slot after `updated`, its slots every `t` milliseconds at an offset by a hash of its key, so that members
/// update apart.
pub(crate) fn next_update(updated: u64, t: u64, key: &[u8]) -> u64 {
    let offset = u64::from_be_bytes(Sha256::digest(key)[..8].try_into().unwrap()) % t;
    (updated + t - offset) / t * t + offset
}

/// When this session's update in a group is next due, if the group stirred since its last: at once for a joiner that has
/// not updated yet.
fn next(g: &G, me: &[u8]) -> u64 {
    match g.rec.updated {
        0 => 0,
        updated => next_update(updated, interval(g.mls.settings().update, g.mls.members().len()), me),
    }
}

impl State {
    /// The cut a commit this session builds now carries: per member of the epoch, from the cut state on, each seq it
    /// holds sealed in the current epoch whose `prev` chains to the last; its own only as far as another member that
    /// may have them holds them.
    pub(crate) fn cut_for(&self, gid: &[u8]) -> Result<Vec<Ref>> {
        let g = self.group(gid)?;
        let (epoch, me) = (g.mls.epoch(), self.me());
        let mut cut = Vec::new();
        for r in g.mls.cut() {
            let mut kept = r.clone();
            while kept.seq < r.seq + MAX_CUT_STEP {
                let Some(record) = self.record_at(gid, &r.key.0, r.joined, kept.seq + 1)? else { break };
                let sealed = record.sealing.as_ref().is_some_and(|(sealed, _)| *sealed == epoch);
                let chained = record.header.prev.as_ref().map(|(id, _)| id) == (kept.seq > 0).then_some(&kept.id);
                if !sealed || !chained || (r.key.0 == me && self.unheld(gid, &record)?) {
                    break;
                }
                kept = Ref { seq: kept.seq + 1, id: record.id, epoch: record.header.epoch, ..kept };
            }
            cut.push(kept);
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
    /// invites, earlier logs, and memberships that ended with nothing left here.
    fn expire(&mut self, gid: &[u8]) -> Result<()> {
        let before = now().saturating_sub(days(self.group(gid)?.mls.settings().carry));
        self.drop_earlier(gid, before)?;
        let g = self.group_mut(gid)?;
        g.rec.invites.retain(|rule| rule.expires >= before);
        let g = self.group(gid)?;
        // A record of an Add stays while its member is in the group, while its invite admits, and for H, so that
        // an invite told late finds itself used.
        let members: Vec<Vec<u8>> = g.mls.members().into_iter().map(|m| m.key).collect();
        let usable: Vec<Bytes> = g.rec.invites.iter().filter(|rule| rule.expires > corrected()).map(|rule| rule.hash.clone()).collect();
        let keep = |added: &lmk_core::group::Added| {
            added.at >= before || members.contains(&added.member.0) || usable.contains(&added.invite)
        };
        self.groups.get_mut(gid).unwrap().mls.forget_added(&self.provider, keep)?;
        let g = self.group_mut(gid)?;
        let (old, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut g.rec.commits).into_iter().partition(|(_, at)| *at < before);
        g.rec.commits = kept;
        for (epoch, _) in old {
            self.provider.delete(&commit_key(gid, epoch))?;
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

/// What a pass commits on the group as it stands, if anything: the Removes due and this session's update.
fn due(st: &State, g: &G) -> Result<Option<Change>> {
    let gid = g.mls.id();
    let me = st.me();
    let cut = st.cut_for(gid)?;
    let members = g.mls.members();
    let kept = |m: &&lmk_core::group::Member| g.left(&m.key).is_some_and(|seq| cut.iter().any(|r| r.key.0 == m.key && r.seq >= seq));
    let remove: Vec<u32> = members.iter().filter(|m| m.key != me).filter(|m| kept(m) || g.left_behind(&m.key)).map(|m| m.index).collect();
    let Some(own) = members.iter().find(|m| m.index == g.mls.own_index()) else { return Ok(None) };
    let leaf = Leaf { intro: g.rec.intro.clone(), ..st.session.leaf.clone() };
    let update = own.leaf.as_ref() != Some(&leaf) || g.rec.stirred && now() >= next(g, me);
    Ok((update || !remove.is_empty()).then(|| Change { remove, leaf: Some(leaf), cut, ..Change::default() }))
}

impl Inner {
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
            let tick = st.tick();
            let g = st.group(gid)?;
            if !g.rec.lost.is_empty() {
                let lost = Control::Lost { lost: g.rec.lost.clone() };
                self.send(&mut st, gid, &serde_json::to_value(lost)?, None)?;
                st.group_mut(gid)?.rec.lost.clear();
                st.save(gid)?;
            }
            let g = st.group(gid)?;
            let behind = g.rec.present < g.mls.epoch();
            if behind && tick >= g.rec.passed + PRESENT {
                self.send(&mut st, gid, &serde_json::to_value(Control::Present)?, None)?;
            }
            let g = st.group(gid)?;
            let present = if g.rec.present < g.mls.epoch() { g.rec.passed + PRESENT } else { u64::MAX };
            let next = if g.rec.stirred { next(g, st.me()) } else { u64::MAX }.min(present);
            let pending = due(&st, g)?;
            // A pass that removes commits at once.
            let removing = pending.as_ref().is_some_and(|change| !change.remove.is_empty());
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
        let committed = async {
            let asked = self.lock().group(gid)?.rec.evicted;
            if now() >= asked + EVICT {
                self.ask_behind(gid).await?;
                let mut st = self.lock();
                st.group_mut(gid)?.rec.evicted = now();
                st.save(gid)?;
            }
            self.commit(gid, due).await
        };
        if let Err(error) = committed.await {
            self.time(gid, now() + RETRY);
            return Err(error);
        }
        Ok(())
    }

    /// Commits this session's update at once, as a joiner does to merge its leaf, which its Add left unmerged, into the
    /// tree: what it costs each later commit then grows with the log of the group's size, not with its size.
    pub(crate) async fn merge(self: &Arc<Self>, gid: &[u8]) -> Result<()> {
        self.commit(gid, due).await.map(drop)
    }

    /// Runs the group's duties again at `at`, unless a run is timed sooner.
    fn time(self: &Arc<Self>, gid: &[u8], at: u64) {
        let wait = at.saturating_sub(now());
        if wait == 0 || at == u64::MAX {
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
}

/// Whether an update waits on its fetch: while `live`, the seqs connected members list that it lacks, still holds any of
/// `fixed`, those it listed when it first waited in this epoch `since`, for at most `HEAR`.
fn waits(fixed: &[Seqs], since: u64, live: &[Seqs], now: u64) -> bool {
    now < since + HEAR && live.iter().any(|want| fixed.iter().any(|f| f.key == want.key && f.joined == want.joined && !f.seqs.intersection(&want.seqs).is_empty()))
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
    fn t_grows_with_the_group_from_24_members_up_to_three_times() {
        let day = 24 * 3600;
        assert_eq!(interval(day, 3), interval(day, 24));
        assert_eq!(interval(day, 48), 2 * interval(day, 24));
        assert_eq!(interval(day, 1000), 3 * interval(day, 24));
    }

    #[test]
    fn each_member_updates_every_t_at_an_offset_of_its_own() {
        let day = 24 * 3600 * 1000;
        let (a, b) = (next_update(0, day, b"a"), next_update(0, day, b"b"));
        assert!(a != b && a <= day && b <= day);
        for updated in [1, a - 1, a, a + 1, a + 5 * 3600 * 1000] {
            let next = next_update(updated, day, b"a");
            assert!(next > updated && next <= updated + day, "{updated}: {next}");
            assert_eq!(next % day, a % day, "on the member's slot");
        }
    }
}
