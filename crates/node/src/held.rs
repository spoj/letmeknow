//! Held messages: taken by the membership and seq their ciphertexts claim in the clear, opened in each membership's seq
//! order within a window, kept by id and by membership and seq, and delivered in causal order once their requirements,
//! `prev` and deps, are resolved: delivered, given up, lost, kept before this session joined, or past a final cut.
//! Giving up releases dependents only: what was given up is still asked for, and is delivered `late` if it comes.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use iroh::EndpointId;
use lmk_core::group::{self as core, MAX_MESSAGE};
use lmk_proto::Bytes;
use lmk_proto::group::{Control, type_of};
use lmk_proto::held::Header;
use lmk_proto::peer::{Frame, Seqs};
use lmk_proto::ranges::Ranges;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Event, G, Inner, Lost, LostOf, Member, Message, Rule, State, Work, get, put};

/// How far past a membership's lowest wanted seq ciphertexts are opened as they come: openmls opens none more than
/// 1,000 behind the newest it opened of a sender.
const WINDOW: u64 = 500;
/// The bytes of ciphertexts a group keeps unopened, of its epoch and the next.
const UNOPENED: usize = 2 * MAX_MESSAGE;
/// How many hashes of ciphertexts taken are remembered.
const SEEN: usize = 8192;
/// How long after a message opened a requirement this session does not hold holds it: while no connected member's
/// summary shows that requirement held, and at most.
pub(crate) const HOLD_OFF: u64 = 2_000;
pub(crate) const GIVE_UP: u64 = 30_000;

/// A membership of the group as this session knows it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Author {
    pub key: Bytes,
    pub joined: u64,
    /// Its seqs up to here were kept before this session joined: they are not this session's to have.
    pub baseline: u64,
    /// Its seqs up to here are kept: its final cut once it ended.
    pub cut: u64,
    pub ended: bool,
    /// The highest seq this session knows it has.
    pub known: u64,
    /// Its seqs this session held (opened, or its own), delivered, gave up on (still wanted), lost, and showed (its
    /// client marked them), and those named in a `missing` already.
    pub held: Ranges,
    pub delivered: Ranges,
    pub given_up: Ranges,
    pub lost: Ranges,
    pub shown: Ranges,
    pub reported: Ranges,
    /// The seqs whose sealing this session holds for others: one they open while it is not kept, and the one of the
    /// epoch whose cut kept it once it is.
    pub servable: Ranges,
    /// The epochs of the sealings held of its seqs past its cut.
    pub sealed: BTreeMap<u64, u64>,
}

impl Author {
    pub(crate) fn new(key: Bytes, joined: u64, baseline: u64) -> Self {
        Author { key, joined, baseline, cut: baseline, known: baseline, ..Author::default() }
    }

    /// Its seqs that hold up no dependent.
    fn resolved(&self) -> Ranges {
        let resolved = Ranges::range(1, self.baseline).union(&self.delivered).union(&self.given_up).union(&self.lost);
        if self.ended { resolved.union(&Ranges::range(self.cut + 1, u64::MAX)) } else { resolved }
    }

    /// Whether every seq up to `seq` is resolved.
    fn through(&self, seq: u64) -> bool {
        Ranges::range(1, seq).difference(&self.resolved()).is_empty()
    }

    /// The seqs it has that this session wants: known, neither held nor lost, past its baseline and within its final cut.
    pub(crate) fn wanted(&self) -> Ranges {
        let last = if self.ended { self.known.min(self.cut) } else { self.known };
        Ranges::range(self.baseline + 1, last).difference(&self.held).difference(&self.lost)
    }

    /// Its lowest seq this session neither holds nor lost.
    fn lowest(&self) -> u64 {
        Ranges::range(self.baseline + 1, u64::MAX).difference(&self.held).difference(&self.lost).first().unwrap()
    }

    /// Its last seq this session holds: of this session's own membership, its last sent, as others' claims do not
    /// move it.
    pub(crate) fn last(&self) -> u64 {
        self.held.ranges().last().map_or(self.baseline, |&(_, last)| last)
    }

    /// Its last seq this session knows was sent from its own messages or a cut: what another's dep alone cannot
    /// raise.
    fn evidence(&self) -> u64 {
        self.last().max(self.cut)
    }

    pub(crate) fn seqs(&self, seqs: &Ranges) -> Option<Seqs> {
        (!seqs.is_empty()).then(|| Seqs { key: self.key.clone(), joined: self.joined, seqs: seqs.clone() })
    }
}

/// A held message as this session keeps it.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Record {
    pub id: Bytes,
    pub header: Header,
    /// Its author's exact plaintext, which its author keeps until a cut keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<Bytes>,
    /// The latest sealing of it this session holds, and its epoch: frozen once a cut keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealing: Option<(u64, Bytes)>,
    /// When it was opened here, or sent.
    pub opened: u64,
    /// Waited `GIVE_UP` on a dep past what this session knows was sent: that dep is met once all known sent is.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub released: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<Delivered>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Delivered {
    pub index: u64,
    pub at: u64,
    pub sender: Member,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<Seqs>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub late: bool,
}

impl Record {
    pub(crate) fn message(&self, gid: &[u8]) -> Option<Message> {
        let delivered = self.delivered.as_ref()?;
        let h = &self.header;
        Some(Message {
            id: self.id.clone(),
            group: Bytes(gid.to_vec()),
            index: delivered.index,
            at: delivered.at,
            sender: delivered.sender.clone(),
            joined: h.joined,
            seq: h.seq,
            reply_to: h.reply_to.as_ref().map(|r| r.id.clone()),
            payload: h.payload.clone(),
            missing: delivered.missing.clone(),
            late: delivered.late,
        })
    }
}

pub(crate) fn record_key(gid: &[u8], id: &[u8]) -> Vec<u8> {
    [b"node/message/".as_slice(), gid, b"/", id].concat()
}

pub(crate) fn seq_key(gid: &[u8], key: &[u8], joined: u64, seq: u64) -> Vec<u8> {
    [b"node/seq/".as_slice(), gid, b"/", key, b"/", &joined.to_be_bytes(), &seq.to_be_bytes()].concat()
}

pub(crate) fn delivered_key(gid: &[u8], index: u64) -> Vec<u8> {
    [b"node/delivered/".as_slice(), gid, b"/", &index.to_be_bytes()].concat()
}

/// A flood bucket: messages and bytes, refilled per second, `scale` times the sender's own.
#[derive(Clone, Debug)]
pub(crate) struct Bucket {
    messages: f64,
    bytes: f64,
    at: u64,
}

impl Default for Bucket {
    fn default() -> Self {
        Bucket { messages: f64::MAX, bytes: f64::MAX, at: 0 }
    }
}

impl Bucket {
    pub(crate) fn take(&mut self, bytes: usize, scale: f64, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.at) as f64 / 1000.0;
        self.messages = (self.messages + elapsed * scale).min(100.0 * scale);
        self.bytes = (self.bytes + elapsed * 65536.0 * scale).min(MAX_MESSAGE as f64 * scale);
        self.at = now;
        let take = self.messages >= 1.0 && self.bytes >= bytes as f64;
        if take {
            self.messages -= 1.0;
            self.bytes -= bytes as f64;
        }
        take
    }
}

impl G {
    pub(crate) fn author(&self, key: &[u8], joined: u64) -> Option<&Author> {
        self.rec.authors.iter().find(|a| a.key.0 == key && a.joined == joined)
    }

    pub(crate) fn author_mut(&mut self, key: &[u8], joined: u64) -> Option<&mut Author> {
        self.rec.authors.iter_mut().find(|a| a.key.0 == key && a.joined == joined)
    }

    /// The current membership of the member with key `key`.
    pub(crate) fn current(&self, key: &[u8]) -> Option<&Author> {
        self.author(key, self.mls.joined(key)?)
    }

    /// Puts a membership's seqs through `seq`, sent before this session joined, behind its baseline: not its to have.
    pub(crate) fn before(&mut self, key: &[u8], joined: u64, seq: u64) {
        let Some(author) = self.author_mut(key, joined) else { return };
        author.baseline = author.baseline.max(seq);
        author.known = author.known.max(seq);
    }

    /// Seqs that became known: not asked for until `HOLD_OFF` passed, as their pushes are likely on the way.
    pub(crate) fn learn(&mut self, key: &[u8], joined: u64, seq: u64, now: u64) {
        let Some(author) = self.author_mut(key, joined) else { return };
        if seq > author.known {
            let fresh = Ranges::range(author.known + 1, seq);
            author.known = seq;
            self.fresh.push((Bytes(key.to_vec()), joined, fresh, now));
        }
    }

    /// What this session wants of each membership now, and, second, the seqs it holds sealed in an ended epoch, which it
    /// wants sealed again: known, neither held nor lost nor waiting unopened here, and not learned of within `HOLD_OFF`.
    /// A commit keeps only what is sealed in its own epoch, so a holder must show the second sealed in this one.
    pub(crate) fn wanted(&mut self, now: u64, me: &[u8]) -> (Vec<Seqs>, Vec<Seqs>) {
        self.fresh.retain(|(_, _, _, at)| now < at + HOLD_OFF);
        let epoch = self.mls.epoch();
        let (mut wanted, mut stale) = (Vec::new(), Vec::new());
        for author in &self.rec.authors {
            let ended: Ranges = match author.key.0 == me {
                true => Ranges::default(),
                false => author.sealed.iter().filter(|(_, sealed)| **sealed < epoch).map(|(seq, _)| *seq).collect(),
            };
            let learned = self.fresh.iter().filter(|(key, joined, _, _)| *key == author.key && *joined == author.joined).fold(Ranges::default(), |all, (_, _, seqs, _)| all.union(seqs));
            let unopened: Ranges = self.unopened.keys().filter(|(k, j, _)| *k == author.key && *j == author.joined).map(|(_, _, s)| *s).collect();
            let pending = |seqs: Ranges| seqs.difference(&learned).difference(&unopened);
            wanted.extend(author.seqs(&pending(author.wanted())));
            stale.extend(author.seqs(&pending(ended)));
        }
        (wanted, stale)
    }

    /// What the last commit kept above this session's baselines that it neither holds nor lost.
    pub(crate) fn lacking(&self) -> Vec<Seqs> {
        let lacking = self.rec.keep.iter().filter_map(|kept| {
            let author = self.author(&kept.key.0, kept.joined)?;
            author.seqs(&kept.seqs.difference(&author.held).difference(&author.lost))
        });
        lacking.collect()
    }
}

impl State {
    pub(crate) fn record(&self, gid: &[u8], id: &[u8]) -> Result<Option<Record>> {
        get(&self.provider, &record_key(gid, id))
    }

    pub(crate) fn id_at(&self, gid: &[u8], key: &[u8], joined: u64, seq: u64) -> Result<Option<Bytes>> {
        get(&self.provider, &seq_key(gid, key, joined, seq))
    }

    pub(crate) fn record_at(&self, gid: &[u8], key: &[u8], joined: u64, seq: u64) -> Result<Option<Record>> {
        let Some(id) = self.id_at(gid, key, joined, seq)? else { return Ok(None) };
        self.record(gid, &id.0)
    }

    /// Saves a record under its id, and its membership and seq.
    pub(crate) fn store(&self, gid: &[u8], record: &Record) -> Result<()> {
        let h = &record.header;
        put(&self.provider, &seq_key(gid, &h.author.0, h.joined, h.seq), &record.id)?;
        put(&self.provider, &record_key(gid, &record.id.0), record)
    }

    /// Deletes a record, and its membership and seq's, and its delivery index's.
    pub(crate) fn unstore(&self, gid: &[u8], record: &Record) -> Result<()> {
        let h = &record.header;
        self.provider.delete(&seq_key(gid, &h.author.0, h.joined, h.seq))?;
        if let Some(delivered) = &record.delivered {
            self.provider.delete(&delivered_key(gid, delivered.index))?;
        }
        self.provider.delete(&record_key(gid, &record.id.0))
    }

    /// The group's delivered messages this session holds, in delivery order.
    pub(crate) fn messages(&self, gid: &[u8]) -> Result<Vec<Message>> {
        let rec = &self.group(gid)?.rec;
        let mut messages = Vec::new();
        for index in rec.first.max(1)..=rec.index {
            let Some(id) = get::<Bytes>(&self.provider, &delivered_key(gid, index))? else { continue };
            messages.extend(self.message(gid, &id.0)?);
        }
        Ok(messages)
    }

    pub(crate) fn message(&self, gid: &[u8], id: &[u8]) -> Result<Option<Message>> {
        Ok(self.record(gid, id)?.and_then(|record| record.message(gid)))
    }

    /// A member by its key: the current one, or a bare one if it is gone.
    pub(crate) fn member_by_key(&self, gid: &[u8], key: &[u8]) -> Member {
        let found = self.groups.get(gid).and_then(|g| g.mls.members().into_iter().find(|m| m.key == key));
        found.map_or_else(|| Member { key: Bytes(key.to_vec()), iroh: Bytes::default(), revision: 0 }, |m| Member::from(&m))
    }

    /// The deps of a message this session sends now: its frontier, of messages it still holds.
    pub(crate) fn deps(&self, gid: &[u8]) -> Result<Vec<lmk_proto::held::Ref>> {
        let mut deps = Vec::new();
        for r in &self.group(gid)?.rec.frontier {
            if self.record_at(gid, &r.key.0, r.joined, r.seq)?.is_some() {
                deps.push(r.clone());
            }
        }
        Ok(deps)
    }

    /// Marks a message its client showed: the frontier drops what it depends on, and takes it unless a message there
    /// depends on it, as one shown late does.
    pub(crate) fn show(&mut self, gid: &[u8], record: &Record) -> Result<()> {
        let h = &record.header;
        let me = self.me().to_vec();
        let g = self.group_mut(gid)?;
        let own = h.author.0 == me && g.mls.joined(&me) == Some(h.joined);
        let Some(author) = g.author_mut(&h.author.0, h.joined) else { return Ok(()) };
        author.shown.insert(h.seq);
        if own {
            return Ok(());
        }
        let covers = |by: &Header, r: &lmk_proto::held::Ref| {
            (by.author == r.key && by.joined == r.joined && by.seq > r.seq) || by.deps.iter().any(|d| d.key == r.key && d.joined == r.joined && d.seq >= r.seq)
        };
        let shown = lmk_proto::held::Ref { key: h.author.clone(), joined: h.joined, seq: h.seq, id: record.id.clone(), epoch: h.epoch };
        let mut covered = false;
        for r in self.group(gid)?.rec.frontier.clone() {
            let Some(by) = self.record_at(gid, &r.key.0, r.joined, r.seq)? else { continue };
            covered |= r == shown || covers(&by.header, &shown);
        }
        let frontier = &mut self.group_mut(gid)?.rec.frontier;
        frontier.retain(|r| !covers(h, r));
        if !covered {
            frontier.push(shown);
        }
        Ok(())
    }
}

impl Inner {
    /// Takes held ciphertexts a peer sent, or that came early: opens what is in order, keeps a while what is not,
    /// passes on what it opened unless they answered this session's `want`, to members that joined before it was sent,
    /// and delivers what is ready.
    pub(crate) fn take(&self, st: &mut State, gid: &[u8], from: Option<EndpointId>, ciphertexts: Vec<Vec<u8>>, forward: bool) -> Result<()> {
        let mut opened = Vec::new();
        for ciphertext in ciphertexts {
            opened.extend(self.take_one(st, gid, from, ciphertext)?);
        }
        self.open_unopened(st, gid, &mut opened)?;
        let group = Bytes(gid.to_vec());
        if forward && !opened.is_empty() && !st.peers.full_mesh(&group) {
            for peer in st.peers.neighbours(&group) {
                let peer = EndpointId::from_bytes(&peer)?;
                let joined = st.joined_of(gid, &peer);
                let items: Vec<Bytes> = opened.iter().filter(|(_, sent)| *sent >= joined).map(|(ciphertext, _)| Bytes(ciphertext.clone())).collect();
                if Some(peer) != from && !items.is_empty() {
                    st.emit(gid, peer, Frame::Held { group: group.clone(), items, answers: None });
                }
            }
        }
        self.deliver_ready(st, gid)?;
        if st.group(gid)?.fetch.is_some() {
            self.work.send(Work::Duties(gid.to_vec())).ok();
        }
        Ok(())
    }

    /// Takes one ciphertext; the ciphertext and the epoch its message was sent in, if it opened.
    fn take_one(&self, st: &mut State, gid: &[u8], from: Option<EndpointId>, ciphertext: Vec<u8>) -> Result<Option<(Vec<u8>, u64)>> {
        let now = st.tick();
        let g = st.group_mut(gid)?;
        let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
        if ciphertext.len() > MAX_MESSAGE || g.seen.contains(&hash) {
            return Ok(None);
        }
        let Ok((claim, epoch)) = core::claim(&ciphertext) else { return Ok(None) };
        let current = g.mls.epoch();
        let room = |g: &G| g.early.iter().map(|(_, c)| c.len()).chain(g.unopened.values().map(|(_, c)| c.len())).sum::<usize>() + ciphertext.len() <= UNOPENED;
        if epoch == current + 1 {
            if let Some(peer) = from
                && room(g)
            {
                g.early.push((peer, ciphertext));
            }
            return Ok(None);
        }
        let Some(author) = g.author(&claim.key.0, claim.joined).filter(|_| epoch <= current && epoch + 1 >= current) else { return Ok(None) };
        let newer = author.sealed.get(&claim.seq).is_some_and(|sealed| epoch > *sealed);
        let wanted = !author.held.contains(claim.seq) && !author.lost.contains(claim.seq);
        if claim.seq <= author.baseline || (author.ended && claim.seq > author.cut) || !(newer || wanted) {
            return Ok(None);
        }
        let lowest = author.lowest();
        let membership = (claim.key.clone(), claim.joined);
        let waiting = g.waiting;
        let taken = claim.seq < lowest + WINDOW && (waiting || newer || g.buckets.entry(membership).or_default().take(ciphertext.len(), 2.0, now));
        if !taken {
            if room(g) {
                remember(&mut g.seen, hash);
                g.unopened.insert((claim.key, claim.joined, claim.seq), (epoch, ciphertext));
            }
            return Ok(None);
        }
        remember(&mut g.seen, hash);
        self.open_one(st, gid, ciphertext)
    }

    /// Opens the unopened ciphertexts that are now in order, within the window and the buckets.
    fn open_unopened(&self, st: &mut State, gid: &[u8], opened: &mut Vec<(Vec<u8>, u64)>) -> Result<()> {
        loop {
            let now = st.tick();
            let g = st.group_mut(gid)?;
            let waiting = g.waiting;
            let ready = g.unopened.iter().find(|((key, joined, seq), _)| g.author(&key.0, *joined).is_some_and(|a| *seq < a.lowest() + WINDOW)).map(|(claim, _)| claim.clone());
            let Some(claim) = ready else { return Ok(()) };
            let (_, ciphertext) = &g.unopened[&claim];
            let size = ciphertext.len();
            if !waiting && !g.buckets.entry((claim.0.clone(), claim.1)).or_default().take(size, 2.0, now) {
                return Ok(());
            }
            let (_, ciphertext) = g.unopened.remove(&claim).unwrap();
            opened.extend(self.open_one(st, gid, ciphertext)?);
        }
    }

    /// Opens every ciphertext kept unopened that is of epoch `epoch`, as its keys are about to go.
    pub(crate) fn open_all(&self, st: &mut State, gid: &[u8], epoch: u64) -> Result<()> {
        let g = st.group_mut(gid)?;
        let claims: Vec<_> = g.unopened.iter().filter(|(_, (sealed, _))| *sealed <= epoch).map(|(claim, _)| claim.clone()).collect();
        for claim in claims {
            let (_, ciphertext) = st.group_mut(gid)?.unopened.remove(&claim).unwrap();
            self.open_one(st, gid, ciphertext)?;
        }
        Ok(())
    }

    /// Opens a ciphertext and keeps its message, or its newer sealing of a message not kept yet; the ciphertext and the
    /// epoch its message was sent in, if either.
    fn open_one(&self, st: &mut State, gid: &[u8], ciphertext: Vec<u8>) -> Result<Option<(Vec<u8>, u64)>> {
        let now = st.tick();
        let g = st.groups.get_mut(gid).context("this session is not in that group")?;
        let opened = match g.mls.open(&st.provider, &ciphertext) {
            Ok(opened) => opened,
            Err(error) => {
                tracing::debug!("a held message did not open: {error:#}");
                if error.is::<core::Unheld>() {
                    self.unheld(st, gid, &ciphertext)?;
                }
                return Ok(None);
            }
        };
        let h = opened.header;
        let id = opened.id;
        // Its sealing shows its author in that epoch, for its log's retention.
        if h.author.0 != st.me() && st.group(gid)?.mls.joined(&h.author.0) == Some(h.joined) {
            st.at(gid, &h.author.0, opened.epoch)?;
        }
        match st.id_at(gid, &h.author.0, h.joined, h.seq)? {
            Some(held) if held.0 == id => {
                let mut record = st.record(gid, &id)?.context("a held message without its record")?;
                let author = st.group_mut(gid)?.author_mut(&h.author.0, h.joined).context("an author")?;
                if h.seq <= author.cut || record.sealing.as_ref().is_some_and(|(sealed, _)| *sealed >= opened.epoch) {
                    return Ok(None);
                }
                author.sealed.insert(h.seq, opened.epoch);
                author.servable.insert(h.seq);
                st.group_mut(gid)?.changed = true;
                record.sealing = Some((opened.epoch, Bytes(ciphertext.clone())));
                st.store(gid, &record)?;
                // A leaver's resealed messages may let the next cut keep its `leave`.
                if st.group(gid)?.rec.leaves.iter().any(|(key, joined, _)| *key == h.author && *joined == h.joined) {
                    self.work.send(Work::Duties(gid.to_vec())).ok();
                }
                return Ok(Some((ciphertext, h.epoch)));
            }
            Some(_) => {
                self.warn(Some(gid), format!("{} sent two held messages as its seq {}: this session keeps the first", crate::fp(&h.author.0), h.seq));
                return Ok(None);
            }
            None => {}
        }
        if h.seq > 1
            && let Some(prev) = st.id_at(gid, &h.author.0, h.joined, h.seq - 1)?
            && Some(&prev) != h.prev.as_ref().map(|(id, _)| id)
        {
            self.warn(Some(gid), format!("{} sent a held message whose prev is not its seq {}: this session keeps the first", crate::fp(&h.author.0), h.seq - 1));
            return Ok(None);
        }
        let me = st.me().to_vec();
        let g = st.group_mut(gid)?;
        let own = g.mls.joined(&me).context("a member of its group")?;
        if let Some((_, sent)) = &h.prev
            && *sent < own
        {
            g.before(&h.author.0, h.joined, h.seq - 1);
        }
        for dep in h.deps.iter().filter(|dep| dep.epoch < own) {
            g.before(&dep.key.0, dep.joined, dep.seq);
        }
        g.learn(&h.author.0, h.joined, h.seq.saturating_sub(1), now);
        for dep in &h.deps {
            g.learn(&dep.key.0, dep.joined, dep.seq, now);
        }
        let author = g.author_mut(&h.author.0, h.joined).context("an author")?;
        author.held.insert(h.seq);
        author.known = author.known.max(h.seq);
        author.servable.insert(h.seq);
        if h.seq > author.cut {
            author.sealed.insert(h.seq, opened.epoch);
        }
        g.changed = true;
        let record = Record { id: Bytes(id.to_vec()), header: h, plaintext: None, sealing: Some((opened.epoch, Bytes(ciphertext.clone()))), opened: now, released: false, delivered: None };
        st.store(gid, &record)?;
        self.control(st, gid, &record.header)?;
        Ok(Some((ciphertext, record.header.epoch)))
    }

    /// A ciphertext of a kept seq that is too old to open: no sealing of it can come that opens, so it is lost.
    fn unheld(&self, st: &mut State, gid: &[u8], ciphertext: &[u8]) -> Result<()> {
        let (claim, _) = core::claim(ciphertext)?;
        let g = st.group_mut(gid)?;
        let Some(author) = g.author_mut(&claim.key.0, claim.joined) else { return Ok(()) };
        if claim.seq > author.cut || author.held.contains(claim.seq) || author.lost.contains(claim.seq) {
            return Ok(());
        }
        author.lost.insert(claim.seq);
        g.changed = true;
        g.rec.lost.push(Seqs { key: claim.key.clone(), joined: claim.joined, seqs: Ranges::range(claim.seq, claim.seq) });
        self.work.send(Work::Duties(gid.to_vec())).ok();
        let from = st.member_by_key(gid, &claim.key.0);
        let messages = vec![LostOf { from, joined: claim.joined, seqs: vec![claim.seq], ids: Vec::new() }];
        let member = st.member_by_key(gid, st.me());
        st.events.push(Event::Lost(Lost { group: Bytes(gid.to_vec()), member, messages }));
        Ok(())
    }

    /// Acts on one of the core's payloads as it opens, or as this session sends it.
    pub(crate) fn control(&self, st: &mut State, gid: &[u8], h: &Header) -> Result<()> {
        if !Control::TYPES.contains(&type_of(&h.payload)) {
            return Ok(());
        }
        let Ok(control) = serde_json::from_value(h.payload.clone()) else { return Ok(()) };
        let me = st.me().to_vec();
        let rec = &mut st.group_mut(gid)?.rec;
        match control {
            Control::Leave => {
                rec.leaves.push((h.author.clone(), h.joined, h.seq));
                self.work.send(Work::Duties(gid.to_vec())).ok();
            }
            Control::Invite { hash, expires } => {
                if !rec.invites.iter().any(|rule| rule.hash == hash) {
                    rec.invites.push(Rule { hash, expires, by: h.author.clone() });
                }
            }
            // Each author is told of its own seqs lost, of those it knows it sent.
            Control::Lost { lost } if h.author.0 != me => {
                let mut messages = Vec::new();
                for lost in lost.iter().filter(|lost| lost.key.0 == me) {
                    let Some(last) = st.group(gid)?.author(&me, lost.joined).map(|a| a.last().max(a.cut)) else { continue };
                    let seqs: Vec<u64> = lost.seqs.intersection(&Ranges::range(1, last)).iter().collect();
                    let mut ids = Vec::new();
                    for &seq in &seqs {
                        ids.extend(st.id_at(gid, &me, lost.joined, seq)?);
                    }
                    if !seqs.is_empty() {
                        messages.push(LostOf { from: st.member_by_key(gid, &me), joined: lost.joined, seqs, ids });
                    }
                }
                if !messages.is_empty() {
                    let member = st.member_by_key(gid, &h.author.0);
                    st.events.push(Event::Lost(Lost { group: Bytes(gid.to_vec()), member, messages }));
                }
            }
            Control::Lost { .. } | Control::Present => {}
        }
        Ok(())
    }

    /// Delivers every held message whose requirements are resolved, each membership's in seq order.
    pub(crate) fn deliver_ready(&self, st: &mut State, gid: &[u8]) -> Result<()> {
        loop {
            let g = st.group(gid)?;
            let mut ready = None;
            for author in &g.rec.authors {
                let Some(seq) = author.held.difference(&author.delivered).first() else { continue };
                if !author.through(seq - 1) {
                    continue;
                }
                let record = st.record_at(gid, &author.key.0, author.joined, seq)?.context("a held message without its record")?;
                let reach = |dep: &lmk_proto::held::Ref, a: &Author| if record.released { dep.seq.min(a.evidence()) } else { dep.seq };
                let met = |dep: &lmk_proto::held::Ref| g.author(&dep.key.0, dep.joined).is_none_or(|a| a.through(reach(dep, a)));
                if record.header.deps.iter().all(met) {
                    ready = Some(record);
                    break;
                }
            }
            let Some(record) = ready else { break };
            self.deliver(st, gid, record)?;
        }
        st.save(gid)
    }

    /// Delivers a held message: its index, what its requirements reached that was given up, and an event for the client
    /// unless it is the core's or this session's own.
    pub(crate) fn deliver(&self, st: &mut State, gid: &[u8], mut record: Record) -> Result<()> {
        let now = st.tick();
        let h = record.header.clone();
        let mut requirements: Vec<(Bytes, u64, u64)> = h.deps.iter().map(|dep| (dep.key.clone(), dep.joined, dep.seq)).collect();
        if h.seq > 1 {
            requirements.push((h.author.clone(), h.joined, h.seq - 1));
        }
        let sender = st.member_by_key(gid, &h.author.0);
        let me = st.me().to_vec();
        let shown = !Control::TYPES.contains(&type_of(&h.payload)) && h.author.0 != me;
        let g = st.group_mut(gid)?;
        let mut missing = Vec::new();
        for (key, joined, seq) in requirements.iter().filter(|_| shown) {
            if let Some(author) = g.author_mut(&key.0, *joined) {
                let given_up = author.given_up.through(*seq).difference(&author.reported);
                author.reported = author.reported.union(&given_up);
                missing.extend(author.seqs(&given_up));
            }
        }
        let author = g.author_mut(&h.author.0, h.joined).context("an author")?;
        let late = author.given_up.contains(h.seq);
        author.delivered.insert(h.seq);
        // A `present` stirs no update: updates would move the others past what they showed, and they would answer.
        if type_of(&h.payload) != "present" && !std::mem::replace(&mut g.rec.stirred, true) {
            self.work.send(Work::Duties(gid.to_vec())).ok();
        }
        g.rec.index += 1;
        let index = g.rec.index;
        record.delivered = Some(Delivered { index, at: now, sender, missing, late });
        put(&st.provider, &delivered_key(gid, index), &record.id)?;
        st.store(gid, &record)?;
        if shown && let Some(message) = record.message(gid) {
            st.events.push(Event::Message(message));
        }
        Ok(())
    }

    /// Gives up, at the log's head, on what the held messages next in line require and this session does not hold,
    /// of what it knows was sent: after `HOLD_OFF` once no holder, by summaries, may still be asked, else after
    /// `GIVE_UP`, then held ones too, as two pending messages may require each other. A dep past what it knows was sent
    /// is met after `GIVE_UP` once all it knows was sent is. Then delivers.
    pub(crate) fn give_up(&self, st: &mut State, gid: &[u8]) -> Result<()> {
        if !st.at_head(gid) {
            return Ok(());
        }
        let now = st.tick();
        let group = Bytes(gid.to_vec());
        let g = st.group(gid)?;
        let mut giving = Vec::new();
        let mut releasing = Vec::new();
        for author in &g.rec.authors {
            let Some(seq) = author.held.difference(&author.delivered).first() else { continue };
            let Some(record) = st.record_at(gid, &author.key.0, author.joined, seq)? else { continue };
            let waited = now.saturating_sub(record.opened);
            if waited < HOLD_OFF {
                continue;
            }
            let mut requirements: Vec<(Bytes, u64, u64)> = record.header.deps.iter().map(|dep| (dep.key.clone(), dep.joined, dep.seq)).collect();
            requirements.push((author.key.clone(), author.joined, seq - 1));
            for (key, joined, seq) in requirements {
                let Some(required) = g.author(&key.0, joined) else { continue };
                if seq > required.evidence() && waited >= GIVE_UP && !record.released && !releasing.contains(&record.id) {
                    releasing.push(record.id.clone());
                }
                let unopened: Ranges = g.unopened.keys().filter(|(k, j, _)| *k == key && *j == joined).map(|(_, _, s)| *s).collect();
                let mut lacking = Ranges::range(1, seq.min(required.evidence())).difference(&required.resolved()).difference(&unopened);
                if waited < GIVE_UP {
                    lacking = lacking.difference(&required.held);
                }
                let untried = || required.seqs(&lacking).is_some_and(|lacking| st.peers.holder(&group, &[lacking], now));
                if !lacking.is_empty() && (waited >= GIVE_UP || !untried()) {
                    giving.push((key, joined, lacking));
                }
            }
        }
        if giving.is_empty() && releasing.is_empty() {
            return Ok(());
        }
        for id in releasing {
            let mut record = st.record(gid, &id.0)?.context("a held message without its record")?;
            record.released = true;
            st.store(gid, &record)?;
        }
        let g = st.group_mut(gid)?;
        for (key, joined, lacking) in giving {
            let author = g.author_mut(&key.0, joined).unwrap();
            author.given_up = author.given_up.union(&lacking);
        }
        self.deliver_ready(st, gid)
    }
}


fn remember(seen: &mut std::collections::VecDeque<[u8; 32]>, hash: [u8; 32]) {
    if seen.len() >= SEEN {
        seen.pop_front();
    }
    seen.push_back(hash);
}
