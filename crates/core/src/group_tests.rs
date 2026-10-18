//! Groups on our API, and the openmls behaviour the group log relies on: storage that commits and rolls back with our
//! records, forged messages that leave no trace, commits from one's own leaf, and two epochs of keys.

use super::*;
use crate::provider::SqliteProvider;
use lmk_proto::group::{ChatMessage, REVISION, Service};
use std::path::Path;
use sha2::{Digest, Sha256};

/// A membership service at `domain`, for logs no test reaches.
pub(crate) fn service(domain: &str) -> Service {
    Service::Serve { key: ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes().into(), domain: domain.into(), rest: Default::default() }
}

pub(crate) fn settings() -> Settings {
    Settings { protocol: PROTOCOL, carry: 7, update: lmk_proto::group::UPDATE, membership: service("lmk.example") }
}

pub(crate) fn leaf(name: &str) -> Leaf {
    Leaf { key: Bytes(name.as_bytes().to_vec()), revision: REVISION }
}

const INVITE: [u8; 32] = [7; 32];

/// An entry as a member read it: its verdict, and for a commit what applying it did.
type Read = (Verdict, Option<Applied>);

pub(crate) struct Member {
    pub provider: SqliteProvider,
    pub session: Session,
    pub group: Option<Group>,
    /// Next log position to read (0-based here).
    pub pos: usize,
    /// The ids of the held messages this member sent, in seq order.
    /// Its held messages' ids, with the epochs it sent them in.
    sent: Vec<([u8; 32], u64)>,
}

impl Member {
    pub fn new(provider: SqliteProvider, name: &str) -> Self {
        let session = Session::create(&provider, leaf(name)).unwrap();
        Member { provider, session, group: None, pos: 0, sent: Vec::new() }
    }

    pub fn g(&mut self) -> &mut Group {
        self.group.as_mut().unwrap()
    }

    pub fn cut(&self) -> Vec<Ref> {
        self.group.as_ref().unwrap().cut().to_vec()
    }

    pub fn commit(&mut self, change: Change) -> Commit {
        let group = self.group.as_mut().unwrap();
        group.commit(&self.provider, &self.session, change).unwrap()
    }

    pub fn cancel(&mut self) {
        self.group.as_mut().unwrap().cancel(&self.provider).unwrap();
    }

    /// Judges each entry not read yet, and applies the commits.
    pub fn read(&mut self, log: &[Vec<u8>]) -> Vec<Read> {
        let mut read = Vec::new();
        while self.pos < log.len() {
            let group = self.group.as_mut().unwrap();
            let verdict = group.judge(&self.provider, &log[self.pos]).unwrap();
            let applied = matches!(verdict, Verdict::Commit { .. }).then(|| group.apply(&self.provider, &log[self.pos]).unwrap());
            read.push((verdict, applied));
            self.pos += 1;
        }
        read
    }

    /// The next held message this member sends, sealed in the current epoch.
    pub fn send(&mut self, text: &str) -> Vec<u8> {
        let group = self.group.as_ref().unwrap();
        let header = Header {
            group: Bytes(group.id().to_vec()),
            author: Bytes(self.session.key().to_vec()),
            joined: group.joined(self.session.key()).unwrap(),
            seq: self.sent.len() as u64 + 1,
            epoch: group.epoch(),
            prev: self.sent.last().map(|(id, epoch)| (Bytes(id.to_vec()), *epoch)),
            deps: vec![],
            reply_to: None,
            payload: message(text),
        };
        let plaintext = header.encode();
        self.sent.push((held::id(&plaintext), group.epoch()));
        self.seal(&plaintext)
    }

    /// A held plaintext, sealed in the current epoch.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.group.as_mut().unwrap().seal(&self.provider, &self.session, plaintext).unwrap()
    }

    pub fn open(&mut self, bytes: &[u8]) -> Result<Opened> {
        let group = self.group.as_mut().unwrap();
        group.open(&self.provider, bytes)
    }

    /// The inner entry of a commit this member can open in its current epoch.
    pub fn open_inner(&self, wire: &[u8]) -> Vec<u8> {
        self.group.as_ref().unwrap().open_entry(&self.provider, wire).unwrap()
    }

    pub fn seal_inner(&self, inner: &[u8]) -> Vec<u8> {
        self.group.as_ref().unwrap().seal_entry(&self.provider, inner).unwrap()
    }

    pub fn index_of(&self, name: &str) -> u32 {
        let group = self.group.as_ref().unwrap();
        group.members().iter().find(|m| m.leaf.as_ref().unwrap().key.0 == name.as_bytes()).unwrap().index
    }

    /// Joins by the inner entry of the commit that added this member, and the Welcome of its Add, which its committer
    /// posted at `pos`.
    pub fn join(&mut self, entry: &[u8], admission: &Admission, pos: usize, package: &[u8]) {
        let reference = key_package_reference(&self.provider, package).unwrap();
        self.group = Some(Group::join(&self.provider, entry, &admission.welcome, &admission.sig, &reference).unwrap());
        self.pos = pos;
    }
}

impl Member {
    /// A copy of this member, its storage and all, as a stolen or restored device holds it.
    fn copy(&self) -> Self {
        let provider = self.provider.copy();
        let session = Session::load(&provider).unwrap();
        let group = self.group.as_ref().map(|group| Group::load(&provider, group.id()).unwrap());
        Member { provider, session, group, pos: self.pos, sent: self.sent.clone() }
    }
}

/// A database in memory.
pub(crate) fn memory() -> SqliteProvider {
    SqliteProvider::open(Path::new(":memory:")).unwrap()
}

pub(crate) fn message(text: &str) -> serde_json::Value {
    let message = ChatMessage { content: text.into(), to: vec![], urgent: false, attachment: None, sent_at: None };
    serde_json::to_value(message).unwrap()
}

fn text(opened: &Opened) -> &str {
    opened.header.payload["content"].as_str().expect("a message")
}

/// A commit's entry, signed by `signer`.
fn entry_of(signer: &SignatureKeyPair, commit: Vec<u8>) -> Vec<u8> {
    let sig = signer.sign(&signed(&commit)).unwrap();
    Entry { commit, sig }.encode()
}

/// A signature key no member holds.
fn stranger() -> SignatureKeyPair {
    let key = ed25519_dalek::SigningKey::from_bytes(&crate::random());
    SignatureKeyPair::from_raw(SignatureScheme::ED25519, key.to_bytes().to_vec(), key.verifying_key().to_bytes().to_vec())
}

/// The authenticated data of a commit that names `cut`, for commits built past `Group::commit`.
fn cut_aad(cut: &[Ref]) -> Vec<u8> {
    serde_json::to_vec(&Aad { cut: cut.to_vec(), ..Aad::default() }).unwrap()
}

/// A commit built past `Group::commit`'s rules: a key update naming `cut`, proposing `settings` if given. It is kept as
/// `m`'s pending commit, as `Group::commit` keeps one.
fn unruled(m: &mut Member, cut: Vec<Ref>, settings: Option<Settings>) -> Vec<u8> {
    let group = m.group.as_mut().unwrap();
    let aad = Aad { cut, ..Aad::default() };
    group.mls.set_aad(serde_json::to_vec(&aad).unwrap());
    let mut builder = group.mls.commit_builder().consume_proposal_store(false).force_self_update(true);
    if let Some(settings) = &settings {
        builder = builder.propose_group_context_extensions(context_extensions(settings).unwrap()).unwrap();
    }
    let bundle = builder
        .load_psks(m.provider.storage())
        .unwrap()
        .build(m.provider.rand(), m.provider.crypto(), &m.session.signer, |_| true)
        .unwrap()
        .stage_commit(&m.provider)
        .unwrap();
    let entry = entry_of(&m.session.signer, bundle.into_messages().0.to_bytes().unwrap());
    let wire = group.seal_entry(&m.provider, &entry).unwrap();
    group.state.posted = Some(Posted { inner: Bytes(entry), wire: Bytes(wire.clone()), add_refs: vec![], admission: None });
    group.state.aad = aad;
    wire
}

/// The refusal `Group::commit` gives a commit built with `change`, which must be refused.
fn refused(m: &mut Member, change: Change) -> String {
    let group = m.group.as_mut().unwrap();
    group.commit(&m.provider, &m.session, change).err().expect("refused").to_string()
}

/// The refusal `Group::join` gives an entry and its Welcome for `package`, which must be refused.
fn join_error(m: &Member, entry: &[u8], admission: &Admission, package: &[u8]) -> String {
    let reference = key_package_reference(&m.provider, package).unwrap();
    Group::join(&m.provider, entry, &admission.welcome, &admission.sig, &reference).err().expect("refused").to_string()
}

/// The entry of `cut` for the member with `key`.
fn at<'a>(cut: &'a mut [Ref], key: &[u8]) -> &'a mut Ref {
    cut.iter_mut().find(|r| r.key.0 == key).unwrap()
}

/// Cuts that `rules` refuses, each with a word of its refusal, made from the valid cut `good`, where `a` is at seq 2 and
/// `b` at seq 0.
fn refusable(good: &[Ref], a: &[u8], b: &[u8]) -> Vec<(Vec<Ref>, &'static str)> {
    let mut cases = vec![(good[1..].to_vec(), "does not name each member"), (good.iter().rev().cloned().collect(), "does not name each member")];
    let mut joined = good.to_vec();
    at(&mut joined, b).joined = 9;
    cases.push((joined, "does not name each member"));
    let mut below = good.to_vec();
    let behind = at(&mut below, a);
    behind.seq = 1;
    behind.id = Bytes(vec![4; 32]);
    cases.push((below, "below the last"));
    let mut same = good.to_vec();
    at(&mut same, a).id = Bytes(vec![7; 32]);
    cases.push((same, "below the last"));
    let mut short = good.to_vec();
    at(&mut short, a).id = Bytes(vec![7; 31]);
    cases.push((short, "does not fit its seq"));
    let mut zero = good.to_vec();
    at(&mut zero, b).id = Bytes(vec![1; 32]);
    cases.push((zero, "does not fit its seq"));
    cases
}

/// A header from `m` in `group`, as its first message would be, but for the membership it claims.
fn header(m: &Member, group: &[u8], joined: u64) -> Header {
    Header { group: Bytes(group.to_vec()), author: Bytes(m.session.key().to_vec()), joined, seq: 1, epoch: joined, prev: None, deps: vec![], reply_to: None, payload: message("forged") }
}

struct World {
    m: Vec<Member>,
    log: Vec<Vec<u8>>,
}

impl World {
    fn new(names: &[&str]) -> Self {
        World { m: names.iter().map(|name| Member::new(memory(), name)).collect(), log: Vec::new() }
    }

    fn post(&mut self, entry: Vec<u8>) -> usize {
        self.log.push(entry);
        self.log.len()
    }

    fn post_inner(&mut self, inner: Vec<u8>) -> usize {
        let sealed = self.m[0].seal_inner(&inner);
        self.post(sealed)
    }

    fn read(&mut self, who: &[usize]) -> Vec<Vec<Read>> {
        who.iter().map(|&i| self.m[i].read(&self.log)).collect()
    }

    /// `creator` makes the group and adds `others` in one commit.
    fn found(&mut self, creator: usize, others: &[usize]) {
        let c = &mut self.m[creator];
        c.group = Some(Group::create(&c.provider, &c.session, &settings()).unwrap());
        let adds: Vec<_> = others.iter().map(|&i| self.m[i].session.key_package(&self.m[i].provider).unwrap()).collect();
        let cut = self.m[creator].cut();
        let commit = self.m[creator].commit(Change { cut, add: adds.clone(), invite: Some(INVITE.into()), ..Change::default() });
        let inner = self.m[creator].open_inner(&commit.entry);
        let admission = commit.admission.clone().unwrap();
        let pos = self.post(commit.entry);
        self.read(&[creator]);
        for (&i, package) in others.iter().zip(adds) {
            self.m[i].join(&inner, &admission, pos, &package);
        }
    }

    fn agree(&mut self, who: &[usize]) {
        let first = (self.m[who[0]].g().epoch(), self.m[who[0]].g().epoch_authenticator().to_vec());
        for &i in who {
            let g = self.m[i].g();
            assert_eq!((g.epoch(), g.epoch_authenticator().to_vec()), first, "member {i} diverged");
        }
    }

    fn key_package(&self, i: usize) -> Vec<u8> {
        self.m[i].session.key_package(&self.m[i].provider).unwrap()
    }
}

fn is_commit(read: &Read) -> bool {
    read.1.is_some()
}

fn applied(read: &Read) -> &Applied {
    read.1.as_ref().expect("a commit")
}

#[test]
fn commit_race() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1, 2]);
    let e = w.m[0].g().epoch();
    let cut = w.m[0].cut();
    let a = w.m[0].commit(Change { cut, ..Change::default() });
    let kp_d = w.key_package(3);
    let cut = w.m[1].cut();
    let b = w.m[1].commit(Change { cut, add: vec![kp_d.clone()], invite: Some(INVITE.into()), ..Change::default() });
    assert!(w.m[0].g().posted().is_some() && w.m[1].g().posted().is_some());
    w.post(a.entry);
    w.post(b.entry);
    let read = w.read(&[0, 1, 2]);
    assert!(matches!(applied(&read[0][0]), Applied { own: true, .. }));
    assert!(matches!(applied(&read[1][0]), Applied { own: false, .. }));
    assert!(matches!(read[1][1].0, Verdict::Skipped { .. }));
    assert!(matches!(read[2][1].0, Verdict::Skipped { .. }));
    assert!(w.m[1].g().posted().is_none() && w.m[1].g().epoch() == e + 1);
    w.agree(&[0, 1, 2]);

    let cut = w.m[1].cut();
    let b2 = w.m[1].commit(Change { cut, add: vec![kp_d.clone()], invite: Some(INVITE.into()), ..Change::default() });
    let inner = w.m[1].open_inner(&b2.entry);
    let admission = b2.admission.clone().unwrap();
    let pos = w.post(b2.entry);
    let read = w.read(&[0, 1, 2]);
    let Applied { added, by, .. } = applied(&read[0][0]);
    assert_eq!(added[0].key, w.m[3].session.key());
    assert_eq!(*by, w.m[1].g().own_index());
    w.m[3].join(&inner, &admission, pos, &kp_d);
    w.agree(&[0, 1, 2, 3]);
    let added = w.m[0].g().added().last().unwrap().clone();
    assert_eq!((added.member.0, added.epoch), (w.m[3].session.key().to_vec(), e + 2));

    // A commit the log never took is cancelled, and the group carries on.
    let cut = w.m[2].cut();
    let _unposted = w.m[2].commit(Change { cut, ..Change::default() });
    w.m[2].cancel();
    let hi = w.m[2].send("still here");
    assert_eq!(text(&w.m[0].open(&hi).unwrap()), "still here");
    w.agree(&[0, 1, 2, 3]);
}

#[test]
fn a_commit_carries_when_its_committer_made_it() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    lmk_proto::clock::set(|| 1_700_000_000_000);
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1]);
    assert!(read.iter().all(|read| matches!(read[0].0, Verdict::Commit { time: 1_700_000_000_000, .. })));
}

#[test]
fn junk_is_skipped() {
    let mut w = World::new(&["A", "B", "C", "D", "X"]);
    w.found(0, &[1, 2, 3]);
    let cut = w.m[1].cut();
    let old = w.m[1].commit(Change { cut, ..Change::default() });
    let p_old = w.post(old.entry);
    w.read(&[0, 1, 2, 3]);
    w.post(b"\xde\xad\xbe\xef".to_vec());
    w.post(w.log[p_old - 1].clone());
    let app = w.m[3].send("hello");
    w.post_inner(Entry { commit: app, sig: vec![0; 64] }.encode());
    let x = &mut w.m[4];
    x.group = Some(Group::create(&x.provider, &x.session, &settings()).unwrap());
    let cut = w.m[4].cut();
    let foreign = w.m[4].commit(Change { cut, ..Change::default() });
    w.post(foreign.entry);
    // A removes C; C, not having read it, commits a key update and then a removal of A.
    let c = w.m[0].index_of("C");
    let cut = w.m[0].cut();
    let remove_c = w.m[0].commit(Change { cut, remove: vec![c], ..Change::default() });
    w.post(remove_c.entry);
    let cut = w.m[2].cut();
    let c_update = w.m[2].commit(Change { cut, ..Change::default() });
    w.post(c_update.entry);
    w.m[2].cancel();
    let a = w.m[2].index_of("A");
    let cut = w.m[2].cut();
    let c_remove_a = w.m[2].commit(Change { cut, remove: vec![a], ..Change::default() });
    w.post(c_remove_a.entry);
    let read = w.read(&[0, 1, 3, 2]);
    for reader in &read[..3] {
        let commits: Vec<bool> = reader.iter().map(is_commit).collect();
        assert_eq!(commits, [false, false, false, false, true, false, false]);
    }
    assert!(matches!(applied(&read[3][4]), Applied { gone: true, .. }));
    assert!(!w.m[2].g().active());
    w.agree(&[0, 1, 3]);
    let hi = w.m[1].send("after the junk");
    assert_eq!(text(&w.m[0].open(&hi).unwrap()), "after the junk");
    assert_eq!(text(&w.m[3].open(&hi).unwrap()), "after the junk");
    let cut = w.m[3].cut();
    let next = w.m[3].commit(Change { cut, ..Change::default() });
    w.post(next.entry);
    w.read(&[0, 1, 3]);
    w.agree(&[0, 1, 3]);
}

/// A commit entry counts only with its committer's signature over the commit, and a log entry holds no Welcome.
#[test]
fn a_commit_entry_needs_its_committers_signature() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1, 2]);
    let kp = w.key_package(3);
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, add: vec![kp], invite: Some(INVITE.into()), ..Change::default() });
    let inner = w.m[0].open_inner(&commit.entry);
    let Entry { commit: bytes, .. } = Entry::parse(&inner).unwrap();
    assert_eq!(inner.len(), 1 + 4 + bytes.len() + 64, "an entry is its commit and signature");
    w.post_inner(entry_of(&stranger(), bytes));
    let read = w.read(&[0, 2]);
    assert!(read.iter().flatten().all(|read| matches!(&read.0, Verdict::Skipped { reason, .. } if reason.contains("did not sign"))));
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2]);
    assert!(read.iter().all(|reader| is_commit(reader.last().unwrap())));
    w.agree(&[0, 1, 2]);
}

#[test]
fn a_commit_never_applies_through_open() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, ..Change::default() });
    let inner = w.m[0].open_inner(&commit.entry);
    let Entry { commit: bytes, .. } = Entry::parse(&inner).unwrap();
    assert!(w.m[1].open(&bytes).is_err());
    w.post(commit.entry);
    w.read(&[0, 1]);
    w.agree(&[0, 1]);
}

/// Proof: with `max_past_epochs(1)`, an epoch's messages open after the commit that ends it, not after the next; and
/// opened in order, a sender's messages stay within openmls's window of 1,000 out of order.
#[test]
fn two_epochs_of_keys() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let e0 = w.m[0].g().epoch();
    let m1 = w.m[0].send("m1");
    let m2 = w.m[0].send("m2");
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    let opened = w.m[1].open(&m1).unwrap();
    assert_eq!((text(&opened), opened.epoch), ("m1", e0));
    assert_eq!(opened.id, held::id(&opened.plaintext));
    assert!(w.m[1].open(&m1).is_err(), "a used key is gone");
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    assert!(w.m[1].open(&m2).unwrap_err().is::<Unheld>(), "two commits on, the epoch's keys are gone");
    assert!(w.m[2].open(&m1).unwrap_err().is::<Unheld>());

    let batch: Vec<_> = (1..=1_100).map(|i| w.m[0].send(&format!("n{i}"))).collect();
    let mut late = w.m[1].copy();
    assert_eq!(text(&late.open(&batch[1_099]).unwrap()), "n1100");
    assert!(late.open(&batch[50]).is_err(), "more than 1,000 behind its sender's newest opened");
    assert_eq!(text(&late.open(&batch[150]).unwrap()), "n151");
    for (i, bytes) in batch.iter().enumerate() {
        assert_eq!(text(&w.m[1].open(bytes).unwrap()), format!("n{}", i + 1));
    }
}

/// Proof: a message that openmls rejects after it advanced the claimed sender's keys leaves no trace, so the sender's
/// real messages still open. The forger, a copy of B's state, seals as B but signs with another key: valid AEAD, bad
/// signature, B's leaf index and generation.
#[test]
fn a_forged_message_leaves_no_trace() {
    let mut a = Member::new(memory(), "A");
    let mut b = Member::new(memory(), "B");
    a.group = Some(Group::create(&a.provider, &a.session, &settings()).unwrap());
    let kp = b.session.key_package(&b.provider).unwrap();
    let cut = a.cut();
    let commit = a.commit(Change { cut, add: vec![kp.clone()], invite: Some(INVITE.into()), ..Change::default() });
    let inner = a.open_inner(&commit.entry);
    let admission = commit.admission.clone().unwrap();
    let log = vec![commit.entry];
    a.read(&log);
    b.join(&inner, &admission, 1, &kp);
    let real = |b: &mut Member, text: &str| b.send(text);
    let first = real(&mut b, "first");
    let forger = b.copy();
    let mut forger = forger;
    let forged = forger.group.as_mut().unwrap().mls.create_message(&forger.provider, &stranger(), &serde_json::to_vec(&message("forged")).unwrap()).unwrap().to_bytes().unwrap();
    let second = real(&mut b, "second");
    a.provider.begin().unwrap();
    assert!(a.open(&forged).is_err());
    a.provider.commit().unwrap();
    assert_eq!(text(&a.open(&second).unwrap()), "second", "the forgery used the generation of B's second message");
    assert_eq!(text(&a.open(&first).unwrap()), "first");

    // Without the savepoint, openmls keeps what the forgery did: B's next real message no longer opens.
    let forged = forger.group.as_mut().unwrap().mls.create_message(&forger.provider, &stranger(), &serde_json::to_vec(&message("forged")).unwrap()).unwrap().to_bytes().unwrap();
    let third = real(&mut b, "third");
    let group = a.group.as_mut().unwrap();
    let message = parse::<MlsMessageIn>(&forged).unwrap().try_into_protocol_message().unwrap();
    assert!(group.mls.process_message(&a.provider, message).is_err());
    assert!(a.open(&third).is_err());
}

/// Proof: one SQLite connection, openmls's storage borrowing it. A step's openmls writes and our own records commit
/// together, or are lost together; after a rollback to a savepoint, `MlsGroup::load` gives the group as it was before.
#[test]
fn a_step_commits_or_rolls_back_with_openmls() {
    let dir = std::env::temp_dir().join(format!("lmk-core-step-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut a = Member::new(SqliteProvider::open(&dir.join("a.db")).unwrap(), "A");
    let mut b = Member::new(memory(), "B");
    a.group = Some(Group::create(&a.provider, &a.session, &settings()).unwrap());
    let kp = b.session.key_package(&b.provider).unwrap();
    let cut = a.cut();
    let commit = a.commit(Change { cut, add: vec![kp.clone()], invite: Some(INVITE.into()), ..Change::default() });
    let inner = a.open_inner(&commit.entry);
    let admission = commit.admission.clone().unwrap();
    let log = vec![commit.entry];
    a.read(&log);
    b.join(&inner, &admission, 1, &kp);
    let id = a.g().id().to_vec();
    let one = b.send("one");
    let two = b.send("two");

    // A step that opens a message and records it, rolled back to its savepoint: openmls's state is as before.
    a.provider.begin().unwrap();
    a.provider.savepoint().unwrap();
    assert_eq!(text(&a.open(&one).unwrap()), "one");
    a.provider.put(b"opened", b"one").unwrap();
    a.provider.rollback_to().unwrap();
    let reloaded = MlsGroup::load(a.provider.storage(), &GroupId::from_slice(&id)).unwrap().unwrap();
    a.g().mls = reloaded;
    assert_eq!(a.provider.get(b"opened").unwrap(), None);
    assert_eq!(text(&a.open(&one).unwrap()), "one", "the message opens again");
    a.provider.put(b"opened", b"one").unwrap();
    a.provider.commit().unwrap();

    // A step cut short, as by a crash, leaves nothing of it: neither openmls's writes nor ours.
    a.provider.begin().unwrap();
    assert_eq!(text(&a.open(&two).unwrap()), "two");
    a.provider.put(b"opened", b"two").unwrap();
    drop(a);
    let provider = SqliteProvider::open(&dir.join("a.db")).unwrap();
    let session = Session::load(&provider).unwrap();
    let group = Group::load(&provider, &id).unwrap();
    let mut a = Member { provider, session, group: Some(group), pos: 1, sent: Vec::new() };
    assert_eq!(a.provider.get(b"opened").unwrap().unwrap(), b"one");
    assert_eq!(text(&a.open(&two).unwrap()), "two", "the crashed step's opening is undone");
    assert!(a.open(&one).is_err(), "the committed step's opening stays");
    drop(a);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Proof: openmls cannot open a commit from one's own leaf, and says so from unsigned sender data; with the entry's
/// signature, one's own commit, a copied state's, and junk under one's own leaf index are told apart.
#[test]
fn commits_from_ones_own_leaf_are_told_apart() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let mut copy = w.m[0].copy();
    // Junk: the copy's commit, signed by another key. Then the copy's commit as it signs it.
    let junk = copy.commit(Change { cut: copy.cut(), ..Change::default() });
    let inner = copy.open_inner(&junk.entry);
    let Entry { commit, .. } = Entry::parse(&inner).unwrap();
    w.post_inner(entry_of(&stranger(), commit));
    copy.cancel();
    let copied = copy.commit(Change { cut: copy.cut(), ..Change::default() });
    w.post(copied.entry);
    let read = w.read(&[0, 1]);
    assert!(matches!(&read[0][0].0, Verdict::Skipped { reason, .. } if reason.contains("this session's leaf")));
    assert_eq!(read[0][1].0, Verdict::Copied);
    assert!(matches!(&read[1][0].0, Verdict::Skipped { reason, .. } if reason.contains("did not sign")));
    assert!(is_commit(&read[1][1]), "to the others, the copy's commit is A's");
    // One's own commit, by its saved bytes, while the original has one pending.
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let mut copy = w.m[0].copy();
    let cut = w.m[0].cut();
    let own = w.m[0].commit(Change { cut, ..Change::default() });
    let copied = copy.commit(Change { cut: copy.cut(), ..Change::default() });
    w.post(own.entry);
    w.post(copied.entry);
    let read = w.read(&[0]);
    assert!(matches!(applied(&read[0][0]), Applied { own: true, .. }));
    assert!(matches!(read[0][1].0, Verdict::Skipped { .. }), "the copy's commit is for an epoch past");
}

#[test]
fn settings_in_the_welcome() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1, 2]);
    assert!(w.m[2].g().mls.extensions().required_capabilities().is_some());

    let kp = w.key_package(3);
    let cut = w.m[2].cut();
    let commit = w.m[2].commit(Change { cut, add: vec![kp.clone()], invite: Some(INVITE.into()), ..Change::default() });
    let inner = w.m[2].open_inner(&commit.entry);
    let admission = commit.admission.clone().unwrap();
    let pos = w.post(commit.entry);
    w.read(&[0, 1, 2]);
    w.m[3].join(&inner, &admission, pos, &kp);
    assert_eq!(w.m[3].g().settings(), settings());
    w.agree(&[0, 1, 2, 3]);
}

#[test]
fn leaf_data() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let leaves: Vec<_> = w.m[0].g().members().into_iter().map(|m| m.leaf.unwrap()).collect();
    assert_eq!(leaves, [leaf("A"), leaf("B"), leaf("C")]);
    let b = w.m[2].index_of("B");
    let moved = Leaf { key: Bytes(b"moved".to_vec()), ..leaf("B") };
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, leaf: Some(moved.clone()), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    for i in 0..3 {
        assert_eq!(w.m[i].g().members()[b as usize].leaf.as_ref(), Some(&moved));
    }
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    assert_eq!(w.m[0].g().members()[b as usize].leaf.as_ref(), Some(&moved), "a key update keeps the leaf data");
    w.agree(&[0, 1, 2]);
}

#[test]
fn key_packages_never_expire() {
    let w = World::new(&["A"]);
    let key_package = key_package_in(&w.m[0].provider, &w.key_package(0)).unwrap();
    let lifetime = key_package.life_time();
    assert_eq!((lifetime.not_before(), lifetime.not_after()), (0, u64::MAX));
}

/// Commits that break the app's rules are skipped by every member, the committer too.
#[test]
fn rules_bind_everyone() {
    let mut w = World::new(&["A", "B", "C", "E"]);
    w.found(0, &[1, 2]);

    // Settings are fixed when a group is made: a commit that proposes them is refused by every member.
    let mut changed = settings();
    changed.protocol = PROTOCOL + 1;
    let cut = w.m[1].cut();
    let wire = unruled(&mut w.m[1], cut, Some(changed));
    w.post(wire);
    let read = w.read(&[0, 1, 2]);
    assert!(matches!(&read[1][0].0, Verdict::Skipped { reason } if reason.contains("GroupContextExtensions")));
    assert!(read.iter().all(|reader| !is_commit(&reader[0])));
    w.agree(&[0, 1, 2]);

    // A proposal by reference: B proposes adding E to C alone, and C commits it by reference.
    let kp = key_package_in(&w.m[3].provider, &w.key_package(3)).unwrap();
    let b = &mut w.m[1];
    let (proposal, _) = b.group.as_mut().unwrap().mls.propose_add_member(&b.provider, &b.session.signer, &kp).unwrap();
    let proposal = proposal.to_bytes().unwrap();
    let c = &mut w.m[2];
    let cut = c.cut();
    let group = c.group.as_mut().unwrap();
    let message = parse::<MlsMessageIn>(&proposal).unwrap().try_into_protocol_message().unwrap();
    let ProcessedMessageContent::ProposalMessage(queued) = group.mls.process_message(&c.provider, message).unwrap().into_content() else {
        panic!()
    };
    group.mls.store_pending_proposal(c.provider.storage(), *queued).unwrap();
    group.mls.set_aad(cut_aad(&cut));
    let (commit, _, _) = group.mls.commit_to_pending_proposals(&c.provider, &c.session.signer).unwrap();
    let entry = entry_of(&c.session.signer, commit.to_bytes().unwrap());
    let wire = group.seal_entry(&c.provider, &entry).unwrap();
    group.state.posted = Some(Posted { inner: Bytes(entry), wire: Bytes(wire.clone()), add_refs: vec![], admission: None });
    w.post_inner(entry_of(&w.m[1].session.signer, proposal));
    w.post(wire);
    let read = w.read(&[0, 1, 2]);
    assert!(read.iter().all(|reader| reader.iter().all(|a| !is_commit(a))));
    assert!(matches!(&read[2][1].0, Verdict::Skipped { reason } if reason.contains("reference")));
    w.agree(&[0, 1, 2]);
}

/// A removed member's messages sealed before its removal still open, while the keys of their epoch are kept.
#[test]
fn a_removed_members_messages_open_up_to_its_final_cut() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let early = w.m[2].send("before my removal");
    let past = w.m[2].send("past my final cut");
    let id = w.m[1].open(&early).unwrap().id;
    let (c, key) = (w.m[1].index_of("C"), w.m[2].session.key().to_vec());
    let mut cut = w.m[1].cut();
    let last = at(&mut cut, &key);
    last.seq = 1;
    last.id = Bytes(id.to_vec());
    let commit = w.m[1].commit(Change { cut, remove: vec![c], ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2]);
    assert_eq!(applied(&read[0][0]).removed[0].key, key);
    assert!(matches!(read[2][0].0, Verdict::Commit { removes: true, .. }));
    assert!(!w.m[2].g().active());
    w.agree(&[0, 1]);
    let opened = w.m[0].open(&early).unwrap();
    assert_eq!((opened.header.author.0.as_slice(), text(&opened)), (key.as_slice(), "before my removal"));
    assert!(w.m[0].open(&past).unwrap_err().to_string().contains("final cut"));
}

#[test]
fn another_protocol_is_refused_at_join() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings()).unwrap());
    let mut future = w.m[0].g().settings();
    future.protocol = PROTOCOL + 1;
    let package = w.key_package(1);
    let reference = key_package_reference(&w.m[1].provider, &package).unwrap();
    let kp = key_package_in(&w.m[1].provider, &package).unwrap();
    let a = &mut w.m[0];
    let group = a.group.as_mut().unwrap();
    let cut = group.cut().to_vec();
    group.mls.set_aad(cut_aad(&cut));
    let bundle = group
        .mls
        .commit_builder()
        .propose_group_context_extensions(context_extensions(&future).unwrap())
        .unwrap()
        .propose_adds([kp])
        .load_psks(a.provider.storage())
        .unwrap()
        .build(a.provider.rand(), a.provider.crypto(), &a.session.signer, |_| true)
        .unwrap()
        .stage_commit(&a.provider)
        .unwrap();
    let (commit, welcome, _) = bundle.into_messages();
    let entry = entry_of(&a.session.signer, commit.to_bytes().unwrap());
    let welcome = welcome.unwrap().to_bytes().unwrap();
    let sig = a.session.signer.sign(&welcome_signed(&entry, &welcome)).unwrap();
    group.mls.merge_pending_commit(&a.provider).unwrap();
    let error = Group::join(&w.m[1].provider, &entry, &welcome, &sig, &reference).err().unwrap();
    assert!(error.to_string().contains(&format!("protocol {}", PROTOCOL + 1)), "{error}");
}

#[test]
fn state_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("lmk-core-restart-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut log = Vec::new();
    let mut a = Member::new(SqliteProvider::open(&dir.join("a.db")).unwrap(), "A");
    let b = Member::new(SqliteProvider::open(&dir.join("b.db")).unwrap(), "B");
    a.group = Some(Group::create(&a.provider, &a.session, &settings()).unwrap());
    let kp = b.session.key_package(&b.provider).unwrap();
    let cut = a.cut();
    let commit = a.commit(Change { cut, add: vec![kp.clone()], invite: Some(INVITE.into()), ..Change::default() });
    let inner = a.open_inner(&commit.entry);
    let admission = commit.admission.clone().unwrap();
    log.push(commit.entry);
    a.read(&log);
    let id = a.g().id().to_vec();
    let mut b = Member { pos: 1, ..b };
    b.join(&inner, &admission, 1, &kp);
    // B adds C, then restarts before reading a separately re-enveloped copy of its pending inner Entry.
    let mut c = Member::new(memory(), "C");
    let c_package = c.session.key_package(&c.provider).unwrap();
    let c_ref = key_package_reference(&c.provider, &c_package).unwrap();
    let cut = b.cut();
    let pending = b.commit(Change { cut, add: vec![c_package.clone()], invite: Some(INVITE.into()), ..Change::default() });
    let pending_admission = pending.admission.clone().unwrap();
    let inner = a.open_inner(&pending.entry);
    let rewrapped = a.seal_inner(&inner);
    assert_ne!(rewrapped, pending.entry);
    log.push(rewrapped);
    drop(b);
    let provider = SqliteProvider::open(&dir.join("b.db")).unwrap();
    let session = Session::load(&provider).unwrap();
    let group = Group::load(&provider, &id).unwrap();
    assert_eq!(group.posted().unwrap(), pending.entry);
    assert_eq!(group.state.posted.as_ref().unwrap().add_refs, vec![c_ref]);
    let mut b = Member { provider, session, group: Some(group), pos: 1, sent: Vec::new() };
    assert!(applied(&b.read(&log)[0]).own);
    a.read(&log);
    assert_eq!(a.g().epoch_authenticator(), b.g().epoch_authenticator());
    assert_eq!(a.g().added().last().unwrap().key_package_ref, c_ref);
    assert_eq!(b.g().added().last().unwrap().key_package_ref, c_ref);
    c.join(&inner, &pending_admission, log.len(), &c_package);
    assert_eq!(a.g().epoch_authenticator(), c.g().epoch_authenticator());
    let hi = b.send("after a restart");
    assert_eq!(text(&a.open(&hi).unwrap()), "after a restart");
    // Windows cannot delete a database that is still open.
    drop((a, b));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_payload_that_could_seal_over_the_limit_is_refused() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let key = w.m[0].session.key().to_vec();
    let (id, joined) = (w.m[0].g().id().to_vec(), w.m[0].g().joined(&key).unwrap());
    let sized = |len: usize| {
        let base = Header { payload: message(""), ..header(&w.m[0], &id, joined) }.encode().len();
        Header { payload: message(&"x".repeat(len - base)), ..header(&w.m[0], &id, joined) }.encode()
    };
    let (over, most) = (sized(MAX_MESSAGE - FRAMING + 1), sized(MAX_MESSAGE - FRAMING));
    let a = &mut w.m[0];
    let group = a.group.as_mut().unwrap();
    let error = group.seal(&a.provider, &a.session, &over).unwrap_err();
    assert_eq!(error.to_string(), format!("the message is {} bytes, over the 16 MiB members take", MAX_MESSAGE + 1));
    let sealed = group.seal(&a.provider, &a.session, &most).unwrap();
    assert!(sealed.len() <= MAX_MESSAGE);
}

/// A held message opens to its header in its epoch under the id of its plaintext; the author's reseal of the same
/// plaintext after a commit opens in the next epoch under that id, for a member that opened the first copy and for one
/// that did not.
#[test]
fn held_messages_keep_their_id_across_epochs() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let e = w.m[0].g().epoch();
    let hi = w.m[0].send("hi");
    let first = w.m[1].open(&hi).unwrap();
    assert_eq!(first.id, held::id(&first.plaintext));
    assert_eq!((text(&first), first.epoch, first.header.seq, first.header.prev.is_none()), ("hi", e, 1, true));
    assert_eq!(first.header.author.0, w.m[0].session.key());
    let plaintext = first.plaintext.clone();
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    let again = w.m[0].seal(&plaintext);
    let second = w.m[1].open(&again).unwrap();
    assert_eq!((second.id, second.epoch), (first.id, e + 1));
    assert_eq!((second.plaintext.clone(), second.header.clone()), (plaintext, first.header));
    assert_eq!(w.m[2].open(&again).unwrap().id, first.id);
}

/// What a held message's header is checked against once MLS opens it: its MLS sender's signature key, its claim, its
/// group, and its author's membership.
#[test]
fn held_headers_are_checked() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let id = w.m[0].group.as_ref().unwrap().id().to_vec();
    let joined = w.m[0].group.as_ref().unwrap().joined(w.m[0].session.key()).unwrap();
    // A's header, sealed by B: the MLS sender is not the author.
    let plaintext = header(&w.m[0], &id, joined).encode();
    let sealed = w.m[1].seal(&plaintext);
    assert!(w.m[2].open(&sealed).unwrap_err().to_string().contains("did not author"));
    // Claiming another seq than its header's.
    let claim = Claim { seq: 2, ..header(&w.m[0], &id, joined).claim() };
    let epoch = w.m[1].g().epoch();
    let a = &mut w.m[0];
    let g = a.group.as_mut().unwrap();
    g.mls.set_aad(serde_json::to_vec(&claim).unwrap());
    let sealed = g.mls.create_message(&a.provider, &a.session.signer, &plaintext).unwrap().to_bytes().unwrap();
    assert_eq!(crate::group::claim(&sealed).unwrap(), (claim, epoch), "the claim reads in the clear");
    assert!(w.m[1].open(&sealed).unwrap_err().to_string().contains("claimed otherwise"));
    // Another group's.
    let other = header(&w.m[0], &[9; 16], joined).encode();
    let sealed = w.m[0].seal(&other);
    assert!(w.m[1].open(&sealed).unwrap_err().to_string().contains("of another group"));
    // A membership of A's other than its current one.
    let stale = header(&w.m[0], &id, joined + 1).encode();
    let sealed = w.m[0].seal(&stale);
    assert!(w.m[1].open(&sealed).unwrap_err().to_string().contains("another membership"));
    let hi = w.m[0].send("hi");
    assert_eq!(text(&w.m[1].open(&hi).unwrap()), "hi");
    let b = &mut w.m[1];
    let again = b.group.as_mut().unwrap().open(&b.provider, &hi).unwrap_err();
    assert!(again.is::<Unheld>(), "opened before: {again}");
}

/// Cuts advance, a removed member leaves them, an added one starts at seq 0 of the new epoch, and every cut `rules`
/// refuses is refused by `commit` too.
#[test]
fn cuts_advance_and_refuse_what_rules_refuse() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1, 2]);
    let (a, b, c, d) = (w.m[0].session.key().to_vec(), w.m[1].session.key().to_vec(), w.m[2].session.key().to_vec(), w.m[3].session.key().to_vec());
    w.m[0].send("m1");
    let m2 = w.m[0].send("m2");
    let id2 = w.m[1].open(&m2).unwrap().id;
    let mut cut = w.m[0].cut();
    let advanced = at(&mut cut, &a);
    advanced.seq = 2;
    advanced.id = Bytes(id2.to_vec());
    let commit = w.m[0].commit(Change { cut: cut.clone(), ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2]);
    assert_eq!(applied(&read[1][0]).cut, cut);
    assert_eq!(w.m[2].cut(), cut);
    w.agree(&[0, 1, 2]);
    for (bad, why) in refusable(&cut, &a, &b) {
        let error = refused(&mut w.m[0], Change { cut: bad, ..Change::default() });
        assert!(error.contains(why), "{error}");
    }
    assert!(w.m[0].g().posted().is_none());

    // B sends in the new epoch, and A commits a cut that takes it, adds D and removes C.
    let b1 = w.m[1].send("b1");
    let id_b1 = w.m[0].open(&b1).unwrap().id;
    let mut cut = w.m[0].cut();
    let reply = at(&mut cut, &b);
    reply.seq = 1;
    reply.id = Bytes(id_b1.to_vec());
    let c_index = w.m[0].index_of("C");
    let kp_d = w.key_package(3);
    let next = w.m[0].g().epoch() + 1;
    let commit = w.m[0].commit(Change { cut: cut.clone(), add: vec![kp_d], remove: vec![c_index], invite: Some(INVITE.into()), ..Change::default() });
    w.post(commit.entry);
    let mut expected: Vec<Ref> = cut.iter().filter(|r| r.key.0 != c).cloned().collect();
    expected.push(Ref { key: Bytes(d), joined: next, seq: 0, id: Bytes::default(), epoch: 0 });
    expected.sort();
    let read = w.read(&[0, 1, 2]);
    assert_eq!(applied(&read[1][0]).cut, cut);
    assert_eq!(w.m[1].cut(), expected);
    assert!(!w.m[2].g().active());
    w.agree(&[0, 1]);
}

/// Commits whose cut `rules` refuses are skipped by every member that reads them. A copy of B, past the rules, builds
/// each; the valid commit that follows is applied.
#[test]
fn members_skip_commits_with_refused_cuts() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let (a, b) = (w.m[0].session.key().to_vec(), w.m[1].session.key().to_vec());
    w.m[0].send("m1");
    let m2 = w.m[0].send("m2");
    let id2 = w.m[1].open(&m2).unwrap().id;
    let mut good = w.m[0].cut();
    let advanced = at(&mut good, &a);
    advanced.seq = 2;
    advanced.id = Bytes(id2.to_vec());
    let commit = w.m[0].commit(Change { cut: good.clone(), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    w.agree(&[0, 1, 2]);
    for (bad, why) in refusable(&good, &a, &b) {
        let mut liar = w.m[1].copy();
        let wire = unruled(&mut liar, bad, None);
        w.post(wire);
        for reader in w.read(&[0, 2]) {
            assert!(matches!(&reader[0].0, Verdict::Skipped { reason, .. } if reason.contains(why)), "{why}");
        }
    }
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2]);
    assert!(read.iter().all(|reader| is_commit(reader.last().unwrap())));
    w.agree(&[0, 1, 2]);
}

/// A joiner starts at the cut of the commit that added it: the members' cut, and seq 0 for itself. An entry a member did
/// not sign, or one with another commit's Welcome, is refused, and leaves the package usable for the right entry.
#[test]
fn a_joiner_starts_at_the_commits_cut() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1]);
    w.m[0].send("m1");
    let m2 = w.m[0].send("m2");
    let id2 = w.m[1].open(&m2).unwrap().id;
    let (a, c) = (w.m[0].session.key().to_vec(), w.m[2].session.key().to_vec());
    let next = w.m[0].g().epoch() + 1;
    let mut cut = w.m[0].cut();
    let advanced = at(&mut cut, &a);
    advanced.seq = 2;
    advanced.id = Bytes(id2.to_vec());
    let kp_c = w.key_package(2);
    let commit = w.m[0].commit(Change { cut: cut.clone(), add: vec![kp_c.clone()], invite: Some(INVITE.into()), ..Change::default() });
    let inner = w.m[0].open_inner(&commit.entry);
    let admission = commit.admission.clone().unwrap();
    let pos = w.post(commit.entry);
    w.read(&[0, 1]);
    let mut expected = cut;
    expected.push(Ref { key: Bytes(c), joined: next, seq: 0, id: Bytes::default(), epoch: 0 });
    expected.sort();

    let Entry { commit: bytes, .. } = Entry::parse(&inner).unwrap();
    let before = w.m[2].provider.rows();
    let forged = entry_of(&stranger(), bytes.clone());
    assert!(join_error(&w.m[2], &forged, &admission, &kp_c).contains("did not sign"));
    assert_eq!(w.m[2].provider.rows(), before);
    let by_another_member = entry_of(&w.m[1].session.signer, bytes.clone());
    assert!(join_error(&w.m[2], &by_another_member, &admission, &kp_c).contains("did not sign"), "only the committer vouches for its cut");
    assert_eq!(w.m[2].provider.rows(), before);
    let welcome = Admission { sig: stranger().sign(&welcome_signed(&inner, &admission.welcome)).unwrap(), ..admission.clone() };
    assert!(join_error(&w.m[2], &inner, &welcome, &kp_c).contains("a Welcome its sender did not sign"));
    assert_eq!(w.m[2].provider.rows(), before);
    let kp_d = w.key_package(3);
    let mut other = w.m[0].copy();
    let cut = other.cut();
    let theirs = other.commit(Change { cut, add: vec![kp_d], invite: Some(INVITE.into()), ..Change::default() });
    join_error(&w.m[2], &inner, &theirs.admission.unwrap(), &kp_c);
    assert_eq!(w.m[2].provider.rows(), before);

    w.m[2].join(&inner, &admission, pos, &kp_c);
    assert_eq!(w.m[2].cut(), expected);
    w.agree(&[0, 1, 2]);
}

/// A commit that removes a member and adds a KeyPackage with its key is refused by its builder's rules.
#[test]
fn a_removed_key_cannot_be_added_back_in_the_same_commit() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let package = w.m[1].session.key_package(&w.m[1].provider).unwrap();
    let b = w.m[0].index_of("B");
    let cut = w.m[0].cut();
    let error = refused(&mut w.m[0], Change { cut, add: vec![package], invite: Some([1; 32].into()), remove: vec![b], ..Change::default() });
    assert!(error.contains("adds a key it removes"), "{error}");
    assert!(w.m[0].g().posted().is_none());
}

/// An Add must name the invite it came in by, and an invite must come with an Add: `rules` refuses either alone.
#[test]
fn an_add_and_its_invite_come_together() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1]);
    let package = w.m[2].session.key_package(&w.m[2].provider).unwrap();
    let cut = w.m[0].cut();
    let error = refused(&mut w.m[0], Change { cut: cut.clone(), add: vec![package], ..Change::default() });
    assert!(error.contains("an Add that names no invite"), "{error}");
    let error = refused(&mut w.m[0], Change { cut, invite: Some(INVITE.into()), ..Change::default() });
    assert!(error.contains("an invite with no Add"), "{error}");
    assert!(w.m[0].g().posted().is_none());
    w.agree(&[0, 1]);
}

/// A member's credential names its leaf's key, as a held message's sender is known by it: a KeyPackage whose credential
/// names another key is not added, and a commit whose update path does is refused by its members and by a joiner it adds.
#[test]
fn a_credential_that_names_another_key_is_refused() {
    let mut w = World::new(&["M", "B", "C"]);
    w.found(0, &[1]);
    let forger = stranger();
    let b = &w.m[1];
    let naming_b = |key: &[u8]| CredentialWithKey { credential: BasicCredential::new(b.session.key().to_vec()).into(), signature_key: key.into() };
    let package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities())
        .leaf_node_extensions(leaf_extensions(&leaf("forger")).unwrap())
        .key_package_lifetime(Lifetime::init(0, u64::MAX))
        .build(CIPHERSUITE, &b.provider, &forger, naming_b(forger.public()))
        .unwrap();
    let package = MlsMessageOut::from(package.key_package().clone()).to_bytes().unwrap();
    let forged = naming_b(w.m[0].session.key());
    let cut = w.m[0].cut();
    let error = refused(&mut w.m[0], Change { cut: cut.clone(), add: vec![package], invite: Some(INVITE.into()), ..Change::default() });
    assert!(error.contains("a credential that names another key"), "{error}");

    // Built as `Group::commit` builds it but past `rules`, as a forger's client would.
    let package = w.key_package(2);
    let m = &mut w.m[0];
    let g = m.group.as_mut().unwrap();
    g.mls.set_aad(serde_json::to_vec(&Aad { invite: Some(INVITE.into()), cut, ..Aad::default() }).unwrap());
    let bundle = g
        .mls
        .commit_builder()
        .force_self_update(true)
        .leaf_node_parameters(LeafNodeParameters::builder().with_credential_with_key(forged).build())
        .propose_adds(vec![key_package_in(&m.provider, &package).unwrap()]);
    let bundle = bundle.load_psks(m.provider.storage()).unwrap().build(m.provider.rand(), m.provider.crypto(), &m.session.signer, |_| true).unwrap();
    let (commit, welcome, _) = bundle.stage_commit(&m.provider).unwrap().into_messages();
    let entry = entry_of(&m.session.signer, commit.to_bytes().unwrap());
    let welcome = welcome.unwrap().to_bytes().unwrap();
    let admission = Admission { sig: m.session.signer.sign(&welcome_signed(&entry, &welcome)).unwrap(), welcome };
    assert!(join_error(&w.m[2], &entry, &admission, &package).contains("a member whose credential names another key"));
    let m = &w.m[0];
    let wire = m.group.as_ref().unwrap().seal_entry(&m.provider, &entry).unwrap();
    w.post(wire);
    let read = w.read(&[1]);
    assert!(matches!(&read[0][0].0, Verdict::Skipped { reason, .. } if reason.contains("a credential that names another key")), "{:?}", read[0][0].0);
}

/// An Add's committer keeps its Welcome, with which the joiner joins; another member keeps none.
#[test]
fn the_committer_keeps_the_welcome_of_its_add() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1]);
    let package = w.key_package(2);
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, add: vec![package.clone()], invite: Some(INVITE.into()), ..Change::default() });
    let inner = w.m[0].open_inner(&commit.entry);
    let pos = w.post(commit.entry);
    let read = w.read(&[0, 1]);
    let admission = applied(&read[0][0]).admission.clone().expect("the committer keeps the Welcome");
    assert!(applied(&read[1][0]).admission.is_none(), "another member keeps none");
    w.m[2].join(&inner, &admission, pos, &package);
    w.agree(&[0, 1, 2]);
}

/// Opens one receiver's messages from one sender in one epoch: `n` held messages, the first `n` of the sender's.
fn sealed_batch(n: usize) -> (World, Vec<Vec<u8>>) {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let batch = (1..=n).map(|i| w.m[0].send(&format!("n{i}"))).collect();
    (w, batch)
}

/// openmls keeps a sender's keys for the last 1,000 generations: a message 1,000 behind the newest opened is lost to the
/// receiver, one 999 behind is not.
#[test]
fn a_held_message_1000_generations_behind_is_lost() {
    let (mut w, batch) = sealed_batch(1_001);
    for (i, bytes) in batch.iter().enumerate().skip(1) {
        assert_eq!(text(&w.m[1].open(bytes).unwrap()), format!("n{}", i + 1));
    }
    assert!(w.m[1].open(&batch[0]).is_err());
}

#[test]
fn a_held_message_999_generations_behind_still_opens() {
    let (mut w, batch) = sealed_batch(1_000);
    for bytes in &batch[1..] {
        w.m[1].open(bytes).unwrap();
    }
    assert_eq!(text(&w.m[1].open(&batch[0]).unwrap()), "n1");
}

#[test]
fn held_messages_open_in_ascending_order_past_the_window() {
    let (mut w, batch) = sealed_batch(5_000);
    for (i, bytes) in batch.iter().enumerate() {
        assert_eq!(text(&w.m[1].open(bytes).unwrap()), format!("n{}", i + 1));
    }
}

/// A forgotten group leaves no key of its epochs in the database: openmls drops each epoch's key pairs as the next merges,
/// except those of the epoch a removing commit ends.
#[test]
fn a_forgotten_group_leaves_no_epoch_keys() {
    let dir = std::env::temp_dir().join(format!("lmk-core-forget-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (path, other) = (dir.join("a.db"), dir.join("b.db"));
    let mut a = Member::new(SqliteProvider::open(&path).unwrap(), "A");
    let b = Member::new(SqliteProvider::open(&other).unwrap(), "B");
    a.group = Some(Group::create(&a.provider, &a.session, &settings()).unwrap());
    let kp = b.session.key_package(&b.provider).unwrap();
    let cut = a.cut();
    let commit = a.commit(Change { cut, add: vec![kp.clone()], invite: Some(INVITE.into()), ..Change::default() });
    let inner = a.open_inner(&commit.entry);
    let admission = commit.admission.clone().unwrap();
    let mut log = vec![commit.entry];
    a.read(&log);
    let mut b = Member { pos: 1, ..b };
    b.join(&inner, &admission, 1, &kp);
    for _ in 0..3 {
        let cut = a.cut();
        log.push(a.commit(Change { cut, ..Change::default() }).entry);
        a.read(&log);
        b.read(&log);
    }
    let keys = |path: &Path| -> i64 {
        rusqlite::Connection::open(path).unwrap().query_row("SELECT COUNT(*) FROM openmls_epoch_keys_pairs", [], |r| r.get(0)).unwrap()
    };
    assert_eq!(a.g().epoch(), 4);
    assert!(keys(&path) > 0, "the current epoch's keys are stored");
    assert!(keys(&other) > 0, "the joiner's current epoch's keys are stored");
    let cut = a.cut();
    let remove = a.index_of("B");
    log.push(a.commit(Change { cut, remove: vec![remove], ..Change::default() }).entry);
    a.read(&log);
    b.read(&log);
    assert!(!b.g().active(), "B is removed");
    assert!(keys(&other) > 0, "openmls keeps the key pairs of the epoch the removing commit ends");
    a.group.take().unwrap().delete(&a.provider).unwrap();
    b.group.take().unwrap().delete(&b.provider).unwrap();
    assert_eq!((keys(&path), keys(&other)), (0, 0), "no epoch's keys stay, of the committer's or the removed joiner's");
    drop((a, b));
    std::fs::remove_dir_all(dir).unwrap();
}

#[path = "group_epoch_tests.rs"]
mod epoch;
