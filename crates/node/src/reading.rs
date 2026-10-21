//! Reading a group's logs of commits strictly in order, each epoch's from the commit that moved the group to it, its
//! entries after that epoch's first valid commit passed over. A commit deletes the keys of the epoch before the current
//! one, whose messages the last commit kept: before it applies, this session waits for those it lacks as
//! `Peers::wait` decides, unless the commit was made more than H ago, and what it still lacks then is lost to it. The
//! commits made before a wait began, which it missed while away, share that wait; a session started only to invite
//! another does not wait.
//! Applying a commit moves the cuts: what they kept, and the memberships that ended and began.

use anyhow::{Context, Result};
use lmk_core::group::{self as core, Verdict};
use lmk_proto::Bytes;
use lmk_proto::clock::corrected;
use lmk_proto::peer::{Admitted, Frame, Seqs};
use lmk_proto::ranges::Ranges;

use crate::held::Author;
use crate::{Epoch, Event, Inner, Lost, LostOf, Out, State, Work, days, put};

/// How many of a group's last logs a commit tells the connected members it removes.
const TOLD: usize = 8;

/// The answer to the Add that ended an epoch, which its committer keeps for H for a joiner whose answer was lost.
pub(crate) fn commit_key(gid: &[u8], epoch: u64) -> Vec<u8> {
    [b"node/commit/".as_slice(), gid, b"/", &epoch.to_be_bytes()].concat()
}

impl Inner {
    /// Reads the stored entries of a group's log this session has not judged yet, in order.
    pub(crate) fn advance(&self, st: &mut State, gid: &[u8]) -> Result<()> {
        while let Some(g) = st.groups.get(gid)
            && g.mls.active()
            && g.rec.position < st.held_to(gid)?
        {
            let position = g.rec.position + 1;
            let entry = st.group_entry(gid, position)?.context("a stored entry is missing")?;
            if !self.judge(st, gid, position, &entry)? {
                break;
            }
        }
        if st.groups.contains_key(gid) {
            st.save(gid)?;
            if st.at_head(gid) {
                self.work.send(Work::Duties(gid.to_vec())).ok();
            }
        }
        self.advanced.notify_waiters();
        Ok(())
    }

    /// Judges and applies the entry at the next position; false if it waits, or the group is gone from this session.
    fn judge(&self, st: &mut State, gid: &[u8], position: u64, entry: &[u8]) -> Result<bool> {
        let g = st.groups.get_mut(gid).unwrap();
        match g.mls.judge(&st.provider, entry)? {
            Verdict::Skipped { .. } => {}
            Verdict::Copied => {
                let text = "a copy of this session's state committed in the group, so this session stops using it: join it again from a new session";
                self.warn(Some(gid), text.into());
                self.work.send(Work::Gone(gid.to_vec())).ok();
                return Ok(false);
            }
            Verdict::Commit { removes, time } => return self.apply(st, gid, position, entry, removes, time),
        }
        st.group_mut(gid)?.rec.position = position;
        Ok(true)
    }

    /// Whether the commit at `position`, made at `time`, may apply now: while this session lacks messages the last
    /// commit kept, which it deletes the keys of, it waits as `Peers::wait` decides, asking for them meanwhile; not for a
    /// commit made more than H ago, whose kept messages no member carries any more.
    fn cleared(&self, st: &mut State, gid: &[u8], position: u64, time: u64) -> Result<bool> {
        let now = st.tick();
        let g = st.group_mut(gid)?;
        let read = match g.reading {
            Some(read) if time < read => read,
            _ => *g.reading.insert(now),
        };
        g.waiting = true;
        let prior = g.mls.epoch().saturating_sub(1);
        self.open_all(st, gid, prior)?;
        st.refresh(gid);
        let g = st.group(gid)?;
        let carried = time + days(g.mls.settings().carry) >= corrected();
        let lacking = if carried { g.lacking() } else { Vec::new() };
        let waiting = self.wait_for_kept && st.peers.wait(&Bytes(gid.to_vec()), &lacking, read, now);
        if waiting {
            tracing::debug!("waiting at position {position} for {} memberships' kept messages", lacking.len());
        }
        st.group_mut(gid)?.waiting = waiting;
        Ok(!waiting)
    }

    /// Applies the commit at `position`, unless it waits (`cleared`); false if it waits, or removed this session.
    fn apply(&self, st: &mut State, gid: &[u8], position: u64, entry: &[u8], removes: bool, time: u64) -> Result<bool> {
        if !self.cleared(st, gid, position, time)? {
            return Ok(false);
        }
        let now = st.tick();
        let ending = st.group(gid)?.mls.epoch();
        if removes {
            self.open_all(st, gid, ending)?;
        }
        self.lose(st, gid)?;
        let g = st.groups.get_mut(gid).unwrap();
        let inner = g.mls.open_entry(&st.provider, entry)?;
        let ended = Epoch { epoch: ending, capability: g.mls.capability(&st.provider)?, service: g.mls.settings().membership };
        let mut applied = g.mls.apply(&st.provider, entry)?;
        let current = g.mls.epoch();
        g.fetch = None;
        g.changed = true;
        let members = g.mls.members();
        let by = members.iter().find(|m| m.index == applied.by).cloned();
        if !applied.added.is_empty() || !applied.removed.is_empty() {
            g.rec.stirred = true;
        }
        if applied.own {
            (g.rec.committed, g.rec.present) = (current, current);
            if applied.updated {
                (g.rec.updated, g.rec.stirred) = (now, false);
            }
        } else if g.rec.present == ending {
            g.rec.passed = time;
        }
        if let Some(core::Admission { welcome, cut, sig }) = applied.admission.take() {
            put(&st.provider, &commit_key(gid, ending), &Admitted { commit: Bytes(inner), welcome: Bytes(welcome), cut, sig: Bytes(sig) })?;
            st.group_mut(gid)?.rec.commits.push((ending, now));
        }
        self.cuts(st, gid, &applied, ending)?;
        st.moved(gid, &applied, ended)?;
        st.scrub = true;
        st.gate = true;
        let core::Applied { added, removed, gone, .. } = applied;
        for member in &removed {
            st.unhear(gid, &member.key)?;
        }
        // The members it removed that are connected are told at once, by the group's last logs in order, as one may be a
        // commit or two behind: no peer brings them later commits.
        let mut logs: Vec<(u64, Vec<u8>)> = st.group_logs(gid).into_iter().filter_map(|id| Some((st.logs.get(&id)?.since, id))).collect();
        logs.sort();
        let told = logs.len().saturating_sub(TOLD);
        let frames: Vec<Frame> = logs[told..].iter().filter_map(|(_, id)| {
            let head = st.logs.get(id)?.head.clone()?;
            Some(Frame::Entries { log: Bytes(id.clone()), entries: st.entries(id, 0), head })
        }).collect();
        for peer in removed.iter().filter_map(|member| crate::endpoint_id(&member.leaf.as_ref()?.key.0)).filter(|peer| st.peers.is_connected(peer.as_bytes())) {
            for frame in &frames {
                st.out.push(Out::Frame { peer, frame: frame.clone() });
            }
        }
        self.work.send(Work::Applied { group: gid.to_vec(), by, added, removed, gone }).ok();
        st.group_mut(gid)?.rec.position = position;
        if gone {
            return Ok(false);
        }
        st.next_log(gid, position)?;
        st.refresh(gid);
        let g = st.group_mut(gid)?;
        let (early, later): (Vec<_>, Vec<_>) = std::mem::take(&mut g.early).into_iter().partition(|(_, ciphertext)| core::claim(ciphertext).is_ok_and(|(_, epoch)| epoch == current));
        g.early = later;
        for (peer, ciphertext) in early {
            self.take(st, gid, Some(peer), vec![ciphertext], true)?;
        }
        Ok(true)
    }

    /// What this session lacks of what the last commit kept is lost to it, as the next commit applies.
    fn lose(&self, st: &mut State, gid: &[u8]) -> Result<()> {
        let lacking = st.group(gid)?.lacking();
        if lacking.is_empty() {
            return Ok(());
        }
        let g = st.group_mut(gid)?;
        for Seqs { key, joined, seqs } in &lacking {
            let author = g.author_mut(&key.0, *joined).context("an author")?;
            author.lost = author.lost.union(seqs);
        }
        g.changed = true;
        g.rec.lost.extend(lacking.iter().cloned());
        let messages = lacking.iter().map(|lost| LostOf { from: st.member_by_key(gid, &lost.key.0), joined: lost.joined, seqs: lost.seqs.iter().collect(), ids: Vec::new() });
        let member = st.member_by_key(gid, st.me());
        st.events.push(Event::Lost(Lost { group: Bytes(gid.to_vec()), member, messages: messages.collect() }));
        Ok(())
    }

    /// Moves the memberships as an applied commit says: each cut, what it kept above this session's baselines to hold
    /// before the next commit, the kept sealings frozen, the memberships that ended (their messages past their final
    /// cuts dropped, their leaves forgotten) and began.
    fn cuts(&self, st: &mut State, gid: &[u8], applied: &core::Applied, ending: u64) -> Result<()> {
        let me = st.me().to_vec();
        let g = st.group_mut(gid)?;
        let own = g.mls.joined(&me).or_else(|| applied.cut.iter().find(|r| r.key.0 == me).map(|r| r.joined));
        let mut keep = Vec::new();
        let mut kept_own = Ranges::default();
        for r in &applied.cut {
            if g.author(&r.key.0, r.joined).is_none() {
                g.rec.authors.push(Author::new(r.key.clone(), r.joined, 0));
            }
            // What a cut keeps of a membership was all sent before this session joined, or all after.
            if own.is_some_and(|own| r.epoch < own) {
                g.before(&r.key.0, r.joined, r.seq);
            }
            let author = g.author_mut(&r.key.0, r.joined).unwrap();
            let kept = Ranges::range(author.cut.max(author.baseline) + 1, r.seq);
            if r.key.0 == me && Some(r.joined) == own {
                kept_own = kept.clone();
            }
            (author.cut, author.known) = (r.seq, author.known.max(r.seq));
            for (seq, sealed) in author.sealed.range(..=r.seq) {
                if *sealed != ending {
                    author.servable.remove(*seq);
                }
            }
            author.sealed.retain(|seq, _| *seq > r.seq);
            keep.extend(author.seqs(&kept));
        }
        g.rec.keep = keep;
        let state = g.mls.cut().to_vec();
        for r in &state {
            if g.author(&r.key.0, r.joined).is_none() {
                g.rec.authors.push(Author::new(r.key.clone(), r.joined, 0));
            }
        }
        let mut dropped = Vec::new();
        for author in g.rec.authors.iter_mut().filter(|a| !a.ended && !state.iter().any(|r| r.key == a.key && r.joined == a.joined)) {
            author.ended = true;
            let past = author.held.difference(&author.delivered).difference(&Ranges::range(1, author.cut));
            for seq in past.iter() {
                dropped.push((author.key.clone(), author.joined, seq));
            }
            author.held = author.held.difference(&past);
            author.servable = author.servable.difference(&past);
            author.sealed.clear();
        }
        g.rec.leaves.retain(|(key, joined, _)| state.iter().any(|r| r.key == *key && r.joined == *joined));
        for (key, joined, seq) in dropped {
            if let Some(record) = st.record_at(gid, &key.0, joined, seq)? {
                st.unstore(gid, &record)?;
            }
        }
        if let Some(joined) = own {
            for seq in kept_own.iter() {
                if let Some(mut record) = st.record_at(gid, &me, joined, seq)? {
                    record.plaintext = None;
                    st.store(gid, &record)?;
                }
            }
        }
        Ok(())
    }
}

impl State {
    /// Records that the member with key `key` is at `epoch`, unless this session knows it is past it.
    pub(crate) fn at(&mut self, gid: &[u8], key: &[u8], epoch: u64) -> Result<()> {
        let g = self.group_mut(gid)?;
        match g.rec.members.iter_mut().find(|(member, _)| member.0 == key) {
            Some((_, at)) => *at = (*at).max(epoch),
            None => g.rec.members.push((Bytes(key.to_vec()), epoch)),
        }
        Ok(())
    }

    /// Moves what this session knows of its members' epochs as a commit applied: the epoch it ended keeps its log while a
    /// member is still in it; the committer and the members it added are in the epoch it began; the removed are forgotten.
    fn moved(&mut self, gid: &[u8], applied: &core::Applied, ended: Epoch) -> Result<()> {
        let me = self.me().to_vec();
        let current = self.group(gid)?.mls.epoch();
        let members = self.group(gid)?.mls.members();
        let committer = members.iter().find(|m| m.index == applied.by).map(|m| m.key.clone());
        for key in committer.into_iter().chain(applied.added.iter().map(|m| m.key.clone())).filter(|key| *key != me) {
            self.at(gid, &key, current)?;
        }
        let g = self.group_mut(gid)?;
        g.rec.members.retain(|(key, _)| members.iter().any(|m| m.key == key.0));
        g.rec.epochs.push(ended);
        g.rec.epochs.retain(|e| g.rec.members.iter().any(|(_, at)| *at == e.epoch));
        Ok(())
    }
}
