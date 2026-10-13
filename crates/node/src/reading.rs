//! Reading a group's logs of commits strictly in order, each epoch's from the commit that moved the group to it, its
//! entries after that epoch's first valid commit passed over. A commit deletes the keys of the epoch before the current
//! one, whose messages the last commit kept: before it applies, this session waits for those it lacks as
//! `Peers::wait` decides, and what it still lacks then is lost to it. Applying a commit moves the cuts: what they kept,
//! and the memberships that ended and began.

use anyhow::{Context, Result};
use lmk_core::group::{self as core, Verdict};
use lmk_core::provider::Provider;
use lmk_net::peers::Decision;
use lmk_proto::Bytes;
use lmk_proto::entry::Entry;
use lmk_proto::peer::Seqs;
use lmk_proto::ranges::Ranges;

use crate::held::Author;
use crate::{Event, Inner, Lost, LostOf, State, Work};

/// The commit entry that ended an epoch, kept for H for a joiner it added whose answer was lost.
pub(crate) fn commit_key(gid: &[u8], epoch: u64) -> Vec<u8> {
    [b"node/commit/".as_slice(), gid, b"/", &epoch.to_be_bytes()].concat()
}

impl<P: Provider + Send + 'static> Inner<P> {
    /// Reads the stored entries of a group's log this session has not judged yet, in order.
    pub(crate) fn advance(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
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
    fn judge(&self, st: &mut State<P>, gid: &[u8], position: u64, entry: &[u8]) -> Result<bool> {
        let g = st.groups.get_mut(gid).unwrap();
        match g.mls.judge(&st.provider, entry)? {
            Verdict::Skipped { .. } => {}
            Verdict::Copied => {
                let text = "a copy of this session's state committed in the group, so this session stops using it: join it again, or revoke this device if it may be stolen";
                self.warn(Some(gid), text.into());
                self.work.send(Work::Gone(gid.to_vec())).ok();
                return Ok(false);
            }
            Verdict::Commit { removes } => return self.apply(st, gid, position, entry, removes),
        }
        st.group_mut(gid)?.rec.position = position;
        Ok(true)
    }

    /// Whether the commit at `position` may apply now: while this session lacks messages the last commit kept, which
    /// it deletes the keys of, it waits as `Peers::wait` decides, asking for them meanwhile.
    fn cleared(&self, st: &mut State<P>, gid: &[u8], position: u64) -> Result<bool> {
        let now = st.tick();
        let g = st.group_mut(gid)?;
        let read = match g.reading {
            Some((at, read)) if at == position => read,
            _ => {
                g.reading = Some((position, now));
                now
            }
        };
        g.waiting = true;
        let prior = g.mls.epoch().saturating_sub(1);
        self.open_all(st, gid, prior)?;
        st.refresh(gid);
        let lacking = st.group(gid)?.lacking();
        let waiting = st.peers.wait(&Bytes(gid.to_vec()), &lacking, read, now) == Decision::Wait;
        if waiting {
            tracing::debug!("waiting at position {position} for {} memberships' kept messages", lacking.len());
        }
        st.group_mut(gid)?.waiting = waiting;
        Ok(!waiting)
    }

    /// Applies the commit at `position`, unless it waits (`cleared`); false if it waits, or removed this session.
    fn apply(&self, st: &mut State<P>, gid: &[u8], position: u64, entry: &[u8], removes: bool) -> Result<bool> {
        if !self.cleared(st, gid, position)? {
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
        let welcome = Entry::parse(&inner)?.welcome;
        let applied = g.mls.apply(&st.provider, entry)?;
        let current = g.mls.epoch();
        g.reading = None;
        g.changed = true;
        let members = g.mls.members();
        let by = members.iter().find(|m| m.index == applied.by).cloned();
        if applied.own {
            (g.rec.updated, g.rec.committed) = (now, current);
        }
        if welcome.is_some() {
            st.provider.put(&commit_key(gid, ending), &inner)?;
            st.group_mut(gid)?.rec.commits.push((ending, now));
        }
        self.cuts(st, gid, &applied, ending)?;
        st.observe_identities()?;
        st.scrub = true;
        st.gate = true;
        let gone = applied.gone;
        if !gone {
            st.events.push(Event::Heard { group: Bytes(gid.to_vec()) });
        }
        let core::Applied { added, how, removed, settings, .. } = applied;
        for member in &removed {
            st.unhear(gid, &member.key)?;
        }
        self.work.send(Work::Applied { group: gid.to_vec(), by, added, how, removed, settings, gone }).ok();
        st.group_mut(gid)?.rec.position = position;
        if gone {
            return Ok(false);
        }
        let old = st.group(gid)?.rec.log.0.clone();
        let log = st.next_log(gid, position)?;
        self.work.send(Work::Follow { log, old }).ok();
        let g = st.group_mut(gid)?;
        let (early, later): (Vec<_>, Vec<_>) = std::mem::take(&mut g.early).into_iter().partition(|(_, ciphertext)| core::claim(ciphertext).is_ok_and(|(_, epoch)| epoch == current));
        g.early = later;
        for (peer, ciphertext) in early {
            self.take(st, gid, Some(peer), vec![ciphertext])?;
        }
        Ok(true)
    }

    /// What this session lacks of what the last commit kept is lost to it, as the next commit applies.
    fn lose(&self, st: &mut State<P>, gid: &[u8]) -> Result<()> {
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
        let messages = lacking.iter().map(|lost| LostOf { from: st.member_by_key(gid, &lost.key.0), joined: lost.joined, seqs: lost.seqs.iter().collect(), ids: Vec::new() });
        let member = st.member_by_key(gid, st.me(gid));
        st.events.push(Event::Lost(Lost { group: Bytes(gid.to_vec()), member, messages: messages.collect() }));
        Ok(())
    }

    /// Moves the memberships as an applied commit says: each cut, what it kept above this session's baselines to hold
    /// before the next commit, the kept sealings frozen, the memberships that ended (their messages past their final
    /// cuts dropped, their leaves forgotten) and began.
    fn cuts(&self, st: &mut State<P>, gid: &[u8], applied: &core::Applied, ending: u64) -> Result<()> {
        let me = st.me(gid).to_vec();
        let now = st.tick();
        let g = st.group_mut(gid)?;
        let own = g.mls.joined(&me).or_else(|| applied.cut.iter().find(|r| r.key.0 == me).map(|r| r.joined));
        let mut keep = Vec::new();
        let mut kept_own = Ranges::default();
        for r in &applied.cut {
            if g.author(&r.key.0, r.joined).is_none() {
                g.rec.authors.push(Author::new(r.key.clone(), r.joined, 0));
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
        g.rec.unkept = g.rec.authors.iter().any(|a| !a.ended && !a.sealed.is_empty()).then_some(now);
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
