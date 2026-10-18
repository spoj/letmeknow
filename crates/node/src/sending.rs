//! Sending held messages: a send is sealed, saved and delivered to this session in one step, and pushed to the
//! neighbours; nothing of it involves the membership service. The author keeps its plaintext until a cut keeps it, and
//! seals it again in each epoch until then, once it is at the head of its log.

use anyhow::{Context, Result, ensure};
use iroh::EndpointId;
use lmk_core::group::{FRAMING, MAX_MESSAGE};
use lmk_net::peers::ANSWER;
use lmk_proto::Bytes;
use lmk_proto::held::{self, Header};
use lmk_proto::peer::{Frame, Seqs, Summary};
use lmk_proto::ranges::Ranges;
use serde_json::Value;

use crate::held::Record;
use crate::{Inner, SendError, State};

impl State {
    /// The summaries of the group's epoch that members connected now sent, other than this session's own.
    fn online_summaries(&self, gid: &[u8]) -> Result<Vec<&Summary>> {
        let g = self.group(gid)?;
        let (me, epoch) = (self.me(), g.mls.epoch());
        let connected = self.peers.neighbours(&Bytes(gid.to_vec()));
        let members = g.mls.members();
        let reached = |member: &Bytes| members.iter().find(|m| m.key == member.0).and_then(|m| m.leaf.as_ref()).is_some_and(|leaf| connected.iter().any(|key| key.as_slice() == leaf.key.0.as_slice()));
        let group = Bytes(gid.to_vec());
        let summaries = self.peers.heard(&group).map(|heard| &heard.summary);
        Ok(summaries.filter(|summary| summary.member.0 != me && summary.epoch == epoch && reached(&summary.member)).collect())
    }

    /// The memberships whose summaries show that they hold this session's message `seq` sealed in this epoch, from
    /// members connected now: a commit may keep the message on their word.
    pub(crate) fn holders_of(&self, gid: &[u8], seq: u64) -> Result<Vec<Bytes>> {
        let me = self.me();
        let joined = self.group(gid)?.mls.joined(me).context("a member of its group")?;
        let holds = |summary: &&Summary| summary.sealed.iter().any(|sealed| sealed.key.0 == me && sealed.joined == joined && sealed.seqs.contains(seq));
        Ok(self.online_summaries(gid)?.into_iter().filter(holds).map(|summary| summary.member.clone()).collect())
    }

    /// Whether this session's message waits for another member to hold it: some other member joined by the epoch it was
    /// sent in, and none connected shows it held. One sent before the others joined is no one else's to have.
    pub(crate) fn unheld(&self, gid: &[u8], record: &Record) -> Result<bool> {
        let g = self.group(gid)?;
        let me = self.me();
        let entitled = g.mls.members().iter().any(|m| m.key != me && g.mls.joined(&m.key).is_some_and(|joined| joined <= record.header.epoch));
        Ok(entitled && self.holders_of(gid, record.header.seq)?.is_empty())
    }

    /// What this session lacks of what the last commit kept, and of the seqs past the cut of each other membership that
    /// connected members show sealed in this epoch, unless this session holds them sealed in this epoch: what an update
    /// fetches before it commits.
    pub(crate) fn fetchable(&self, gid: &[u8]) -> Result<Vec<Seqs>> {
        let g = self.group(gid)?;
        let (me, epoch) = (self.me(), g.mls.epoch());
        let online = self.online_summaries(gid)?;
        let mut fetch = g.lacking();
        for cut in g.mls.cut().iter().filter(|cut| cut.key.0 != me) {
            let Some(author) = g.author(&cut.key.0, cut.joined) else { continue };
            let listed = online.iter().flat_map(|summary| &summary.sealed).filter(|sealed| sealed.key == cut.key && sealed.joined == cut.joined).fold(Ranges::default(), |all, sealed| all.union(&sealed.seqs));
            let sealed: Ranges = author.sealed.iter().filter(|(_, sealed)| **sealed == epoch).map(|(seq, _)| *seq).collect();
            let lacking = listed.intersection(&Ranges::range(cut.seq.max(author.baseline) + 1, u64::MAX)).difference(&sealed).difference(&author.lost);
            fetch.extend(author.seqs(&lacking));
        }
        Ok(fetch)
    }

    /// This session's messages of its latest membership of the group that no cut kept, by id.
    pub(crate) fn not_kept(&self, gid: &[u8]) -> Result<Vec<Bytes>> {
        let me = self.me();
        let Some(mine) = self.group(gid)?.rec.authors.iter().filter(|a| a.key.0 == me).max_by_key(|a| a.joined) else { return Ok(Vec::new()) };
        let mut ids = Vec::new();
        for seq in mine.cut + 1..=mine.last() {
            ids.extend(self.id_at(gid, me, mine.joined, seq)?);
        }
        Ok(ids)
    }
}

impl Inner {
    /// Sends a held payload in a step: seals it in the current epoch with this session's next seq, after the messages
    /// it seals again first, and with the deps its client showed; delivers it to this session and pushes it. Answers
    /// its id.
    pub(crate) fn send(&self, st: &mut State, gid: &[u8], payload: &Value, reply_to: Option<&[u8]>) -> Result<Bytes> {
        self.reseal(st, gid)?;
        let now = st.tick();
        let me = st.me().to_vec();
        let g = st.group(gid)?;
        let joined = g.mls.joined(&me).context("a member of its group")?;
        let seq = g.current(&me).context("its own membership")?.last() + 1;
        if let Some(reply_to) = reply_to {
            ensure!(st.record(gid, reply_to)?.is_some_and(|record| record.delivered.is_some()), "reply_to names no message delivered here");
        }
        // A message a cut kept may be gone after H; the cut names it.
        let kept = g.mls.cut().iter().find(|r| r.key.0 == me && r.joined == joined).context("its own cut")?;
        let prev = match seq {
            1 => None,
            _ if kept.seq == seq - 1 => Some((kept.id.clone(), kept.epoch)),
            _ => {
                let prev = st.record_at(gid, &me, joined, seq - 1)?.context("this session's previous message")?;
                Some((prev.id, prev.header.epoch))
            }
        };
        let control = lmk_proto::group::Control::TYPES.contains(&lmk_proto::group::type_of(payload));
        let deps = if control { Vec::new() } else { st.deps(gid)? };
        let header = Header {
            group: Bytes(gid.to_vec()),
            author: Bytes(me.clone()),
            joined,
            seq,
            epoch: st.group(gid)?.mls.epoch(),
            prev,
            deps,
            reply_to: reply_to.map(|id| Bytes(id.to_vec())),
            payload: payload.clone(),
        };
        let plaintext = header.encode();
        let size = plaintext.len() + FRAMING;
        if size > MAX_MESSAGE {
            return Err(SendError::Size(format!("the message is {size} bytes, over the 16 MiB members take")).into());
        }
        let g = st.groups.get_mut(gid).unwrap();
        if !g.sending.take(plaintext.len(), 1.0, now) {
            return Err(SendError::Rate.into());
        }
        let ciphertext = g.mls.seal(&st.provider, &st.session, &plaintext)?;
        let epoch = g.mls.epoch();
        let author = g.author_mut(&me, joined).unwrap();
        author.held.insert(seq);
        author.known = author.known.max(seq);
        author.servable.insert(seq);
        author.sealed.insert(seq, epoch);
        g.changed = true;
        let id = Bytes(held::id(&plaintext).to_vec());
        let record = Record { id: id.clone(), header, plaintext: Some(Bytes(plaintext)), sealing: Some((epoch, Bytes(ciphertext.clone()))), opened: now, released: false, delivered: None };
        st.store(gid, &record)?;
        self.control(st, gid, &record.header)?;
        self.deliver(st, gid, record)?;
        st.broadcast(gid, Frame::Held { group: Bytes(gid.to_vec()), items: vec![Bytes(ciphertext)], answers: None });
        st.save(gid)?;
        Ok(id)
    }

    /// Seals this session's messages past its cut again in the current epoch, in seq order, and pushes them in frames,
    /// to each member that joined before they were sent: once per epoch, at the head of its log, once the log has been
    /// read.
    pub(crate) fn reseal(&self, st: &mut State, gid: &[u8]) -> Result<()> {
        let g = st.group(gid)?;
        let epoch = g.mls.epoch();
        let read = st.logs.get(&g.rec.log.0).is_some_and(|log| log.at > 0);
        if g.rec.resealed >= epoch || !read || !st.at_head(gid) {
            return Ok(());
        }
        let me = st.me().to_vec();
        let Some(mine) = g.current(&me).cloned() else { return Ok(()) };
        let mut items = Vec::new();
        for seq in mine.cut + 1..=mine.last() {
            let mut record = st.record_at(gid, &me, mine.joined, seq)?.context("this session's message past its cut")?;
            let plaintext = record.plaintext.clone().context("this session's plaintext past its cut")?;
            let g = st.groups.get_mut(gid).unwrap();
            let ciphertext = g.mls.seal(&st.provider, &st.session, &plaintext.0)?;
            g.author_mut(&me, mine.joined).unwrap().sealed.insert(seq, epoch);
            record.sealing = Some((epoch, Bytes(ciphertext.clone())));
            st.store(gid, &record)?;
            items.push((record.header.epoch, Bytes(ciphertext)));
        }
        let g = st.group_mut(gid)?;
        g.rec.resealed = epoch;
        g.changed |= !items.is_empty();
        for peer in st.peers.neighbours(&Bytes(gid.to_vec())) {
            let peer = EndpointId::from_bytes(&peer)?;
            let joined = st.joined_of(gid, &peer);
            for items in frames(items.iter().filter(|(sent, _)| *sent >= joined).map(|(_, item)| item.clone()).collect()) {
                st.emit(gid, peer, Frame::Held { group: Bytes(gid.to_vec()), items, answers: None });
            }
        }
        st.save(gid)
    }
}

/// Splits ciphertexts into frames of at most `ANSWER` bytes, as answers are; one that is larger goes alone.
fn frames(items: Vec<Bytes>) -> Vec<Vec<Bytes>> {
    let mut frames: Vec<Vec<Bytes>> = Vec::new();
    let mut size = 0;
    for item in items {
        size += item.0.len();
        match frames.last_mut() {
            Some(frame) if size <= ANSWER => frame.push(item),
            _ => {
                size = item.0.len();
                frames.push(vec![item]);
            }
        }
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reseals_are_pushed_in_frames_of_at_most_answer_bytes() {
        let item = |len: usize| Bytes(vec![0; len]);
        let sizes = |frames: Vec<Vec<Bytes>>| frames.iter().map(|frame| frame.iter().map(|item| item.0.len()).collect::<Vec<_>>()).collect::<Vec<_>>();
        let half = ANSWER / 2;
        assert_eq!(sizes(frames(vec![item(half), item(half), item(1)])), vec![vec![half, half], vec![1]]);
        assert_eq!(sizes(frames(vec![item(10), item(ANSWER + 5), item(10)])), vec![vec![10], vec![ANSWER + 5], vec![10]]);
        assert!(frames(Vec::new()).is_empty());
    }
}
