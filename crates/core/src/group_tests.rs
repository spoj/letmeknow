//! Groups on our API, and the openmls behaviour the group log relies on: storage that commits and rolls back with our
//! records, forged messages that leave no trace, commits from one's own leaf, and two epochs of keys.

use super::*;
use crate::provider::SqliteProvider;
use lmk_proto::group::{ChatMessage, Device, Service};
use std::path::Path;
use sha2::{Digest, Sha256};

/// A membership service at `domain`, for logs no test reaches.
pub(crate) fn service(domain: &str) -> Service {
    Service::Serve { key: ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes().into(), domain: domain.into(), rest: Default::default() }
}

/// The domain of the service tests' groups are on.
const DOMAIN: &str = "lmk.example";

pub(crate) fn settings() -> Settings {
    Settings { protocol: PROTOCOL, carry: 7, update: lmk_proto::group::UPDATE, membership: service(DOMAIN), admins: vec![], admitted: vec![] }
}

/// The iroh key of the session named `name`.
fn iroh(name: &str) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&Sha256::digest(name).into())
}

/// The leaf of the session with key `session`, by the iroh key of `name`, which proves it, naming no device.
pub(crate) fn leaf(name: &str, session: &[u8]) -> Leaf {
    use ed25519_dalek::Signer as _;
    let iroh = iroh(name);
    let proof = iroh.sign(&[LEAF, session].concat()).to_bytes().to_vec();
    Leaf { key: Bytes(iroh.verifying_key().to_bytes().to_vec()), proof: Bytes(proof), home: DOMAIN.into(), device: None }
}

/// A device key, by a byte of its seed: the 0th is every test member's, unless it moves (`Member::on`).
pub(crate) fn device(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn key_of(device: &ed25519_dalek::SigningKey) -> Bytes {
    Bytes(device.verifying_key().to_bytes().to_vec())
}

/// The invite tests' Adds carry, which only a node checks against its rules.
fn invite() -> Invited {
    Invited { by: Bytes(vec![7; 32]), joined: 0, secret: Bytes(vec![7; 16]) }
}

/// The group a commit entry is of, as a link names it.
fn group_of(entry: &[u8]) -> [u8; 16] {
    let MlsMessageBodyIn::PrivateMessage(message) = parse::<MlsMessageIn>(&Entry::parse(entry).unwrap().commit).unwrap().extract() else { panic!() };
    message.group_id().as_slice().try_into().unwrap()
}

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
    /// A member on device 0, as all are by default: the founder's device makes them all admins.
    pub fn new(provider: SqliteProvider, name: &str) -> Self {
        let session = Session::create(&provider, |session| leaf(name, session)).unwrap();
        let mut member = Member { provider, session, group: None, pos: 0, sent: Vec::new() };
        member.on(Some(&device(0)));
        member
    }

    /// Puts this member's session on `device`, or on none, before it is in a group: its leaf names the device's
    /// certificate of it.
    pub fn on(&mut self, device: Option<&ed25519_dalek::SigningKey>) {
        let certified = device.map(|device| Device::sign(device, self.session.key()));
        let leaf = Leaf { device: certified, ..self.session.leaf.clone() };
        self.session.set_leaf(&self.provider, leaf).unwrap();
    }

    pub fn g(&mut self) -> &mut Group {
        self.group.as_mut().unwrap()
    }

    pub fn cut(&self) -> Vec<Cut> {
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
        let key = iroh(name).verifying_key().to_bytes();
        group.members().iter().find(|m| m.leaf.key.0 == key).unwrap().index
    }

    /// Joins by the inner entry of the commit that added this member, and the Welcome of its Add, which its committer
    /// posted at `pos`.
    pub fn join(&mut self, entry: &[u8], admission: &Admission, pos: usize, package: &[u8]) {
        let reference = key_package_reference(&self.provider, package).unwrap();
        self.group = Some(Group::join(&self.provider, entry, admission, &reference, &group_of(entry), DOMAIN).unwrap());
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

/// The authenticated data of a commit that moves `moved`, for commits built past `Group::commit`.
fn cut_aad(moved: &[Cut]) -> Vec<u8> {
    serde_json::to_vec(&Aad { moved: moved.to_vec(), ..Aad::default() }).unwrap()
}

/// A commit built past `Group::commit`'s rules, with the authenticated data `aad`: a key update, with what `propose`
/// proposes. It is kept as `m`'s pending commit, as `Group::commit` keeps one.
fn unruled(m: &mut Member, aad: Aad, propose: impl for<'a> FnOnce(CommitBuilder<'a, Initial>) -> CommitBuilder<'a, Initial>) -> Vec<u8> {
    let group = m.group.as_mut().unwrap();
    group.mls.set_aad(serde_json::to_vec(&aad).unwrap());
    let builder = propose(group.mls.commit_builder().consume_proposal_store(false).force_self_update(true));
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
    Group::join(&m.provider, entry, admission, &reference, &group_of(entry), DOMAIN).err().expect("refused").to_string()
}

/// The entry of `cut` for the member with `key`.
fn at<'a>(cut: &'a mut [Cut], key: &[u8]) -> &'a mut Cut {
    cut.iter_mut().find(|r| r.key.0 == key).unwrap()
}

/// Moved cut entries that `rules` refuses, each with a word of its refusal, against a cut state where `a` is at seq 2
/// and `b` at seq 0, and `stale` is a's seq 3 as sealed in the epoch before.
fn refusable(good: &[Cut], a: &[u8], b: &[u8], stale: &Cut) -> Vec<(Vec<Cut>, &'static str)> {
    let entry = |key: &[u8], seq: u64, id: Vec<u8>| Cut { id: Bytes(id), seq, ..good.iter().find(|r| r.key.0 == key).unwrap().clone() };
    let mut two = vec![entry(a, 3, vec![6; 32]), entry(b, 1, vec![5; 32])];
    two.sort();
    two.reverse();
    let joined = Cut { joined: 9, ..entry(b, 1, vec![5; 32]) };
    let unsigned = Cut { sealed: stale.sealed + 1, ..entry(b, 1, vec![5; 32]) };
    vec![
        (two, "does not name each member"),
        (vec![entry(a, 3, vec![6; 32]), entry(a, 3, vec![6; 32])], "does not name each member"),
        (vec![joined], "names no member"),
        (vec![entry(a, 1, vec![4; 32])], "below the last"),
        (vec![entry(a, 2, vec![7; 32])], "below the last"),
        (vec![stale.clone()], "of another epoch"),
        (vec![unsigned], "did not sign"),
    ]
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
        let commit = self.m[creator].commit(Change { cut, add: adds.clone(), invite: Some(invite()), ..Change::default() });
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
    let b = w.m[1].commit(Change { cut, add: vec![kp_d.clone()], invite: Some(invite()), ..Change::default() });
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
    let b2 = w.m[1].commit(Change { cut, add: vec![kp_d.clone()], invite: Some(invite()), ..Change::default() });
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
    let commit = w.m[1].commit(Change { cut, add: vec![kp], invite: Some(invite()), ..Change::default() });
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
    assert!(w.m[1].open(&m2).is_err(), "two commits on, the epoch's keys are gone");
    assert!(w.m[2].open(&m1).is_err());

    let batch: Vec<_> = (1..=1_100).map(|i| w.m[0].send(&format!("n{i}"))).collect();
    let mut late = w.m[1].copy();
    assert_eq!(text(&late.open(&batch[1_099]).unwrap()), "n1100");
    assert!(late.open(&batch[50]).is_err(), "more than 1,000 behind its sender's newest opened");
    assert_eq!(text(&late.open(&batch[150]).unwrap()), "n151");
    for (i, bytes) in batch.iter().enumerate() {
        assert_eq!(text(&w.m[1].open(bytes).unwrap()), format!("n{}", i + 1));
    }
}

/// Proof: a message that openmls rejects leaves no trace, so the sender's real messages still open. The forger, a copy
/// of B's state, seals as B but signs with another key: valid AEAD, bad signature, B's leaf index and generation.
#[test]
fn a_forged_message_leaves_no_trace() {
    let mut a = Member::new(memory(), "A");
    let mut b = Member::new(memory(), "B");
    a.group = Some(Group::create(&a.provider, &a.session, &settings()).unwrap());
    let kp = b.session.key_package(&b.provider).unwrap();
    let cut = a.cut();
    let commit = a.commit(Change { cut, add: vec![kp.clone()], invite: Some(invite()), ..Change::default() });
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
    let message = parse::<MlsMessageIn>(&forged).unwrap().try_into_protocol_message().unwrap();
    assert!(a.group.as_mut().unwrap().mls.process_message(&a.provider, message).is_err());
    assert_eq!(text(&a.open(&second).unwrap()), "second", "the forgery used the generation of B's second message");
    assert_eq!(text(&a.open(&first).unwrap()), "first");
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
    let commit = a.commit(Change { cut, add: vec![kp.clone()], invite: Some(invite()), ..Change::default() });
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
    let commit = w.m[2].commit(Change { cut, add: vec![kp.clone()], invite: Some(invite()), ..Change::default() });
    let inner = w.m[2].open_inner(&commit.entry);
    let admission = commit.admission.clone().unwrap();
    let pos = w.post(commit.entry);
    w.read(&[0, 1, 2]);
    w.m[3].join(&inner, &admission, pos, &kp);
    let admins = vec![Bytes(w.m[0].session.key().to_vec()), key_of(&device(0))];
    assert_eq!(w.m[3].g().settings(), Settings { admins, ..settings() });
    w.agree(&[0, 1, 2, 3]);
}

#[test]
fn leaf_data() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let leaves: Vec<_> = w.m[0].g().members().into_iter().map(|m| m.leaf).collect();
    assert_eq!(leaves, [0, 1, 2].map(|i| w.m[i].session.leaf.clone()));
    let b = w.m[2].index_of("B");
    let moved = Leaf { home: "moved.example".into(), ..w.m[1].session.leaf.clone() };
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, leaf: Some(moved.clone()), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    for i in 0..3 {
        assert_eq!(w.m[i].g().members()[b as usize].leaf, moved);
    }
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    assert_eq!(w.m[0].g().members()[b as usize].leaf, moved, "a key update keeps the leaf data");
    w.agree(&[0, 1, 2]);
}

#[test]
fn key_packages_never_expire() {
    let w = World::new(&["A"]);
    let key_package = key_package_in(&w.m[0].provider, &w.key_package(0)).unwrap();
    let lifetime = key_package.life_time();
    assert_eq!((lifetime.not_before(), lifetime.not_after()), (0, u64::MAX));
}

#[test]
fn deleting_a_key_package_leaves_only_what_was_there_before_it() {
    let w = World::new(&["A"]);
    w.key_package(0);
    let provider = &w.m[0].provider;
    let before = provider.rows();
    let package = w.key_package(0);
    assert_ne!(provider.rows(), before);
    delete_key_package(provider, &package).unwrap();
    assert_eq!(provider.rows(), before);
}

/// Commits that break the app's rules are skipped by every member, the committer too.
#[test]
fn rules_bind_everyone() {
    let mut w = World::new(&["A", "B", "C", "E"]);
    w.found(0, &[1, 2]);

    // A group's protocol is fixed when it is made: an admin's commit that changes it is refused by every member.
    let mut changed = w.m[1].g().settings();
    changed.protocol = PROTOCOL + 1;
    let wire = unruled(&mut w.m[1], Aad::default(), |b| b.propose_group_context_extensions(context_extensions(&changed).unwrap()).unwrap());
    w.post(wire);
    let read = w.read(&[0, 1, 2]);
    assert!(matches!(&read[1][0].0, Verdict::Skipped { reason } if reason.contains("more than the admins and admitted devices")));
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
    let (c, key) = (w.m[1].index_of("C"), w.m[2].session.key().to_vec());
    let mut cut = w.m[1].cut();
    *at(&mut cut, &key) = claim(w.m[1].g().id(), &early).unwrap();
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
    let sig = a.session.signer.sign(&welcome_signed(&entry, &serde_json::to_vec(&cut).unwrap(), &welcome)).unwrap();
    let admission = Admission { welcome, cut, sig };
    group.mls.merge_pending_commit(&a.provider).unwrap();
    let error = Group::join(&w.m[1].provider, &entry, &admission, &reference, &group_of(&entry), DOMAIN).err().unwrap();
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
    let commit = a.commit(Change { cut, add: vec![kp.clone()], invite: Some(invite()), ..Change::default() });
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
    let pending = b.commit(Change { cut, add: vec![c_package.clone()], invite: Some(invite()), ..Change::default() });
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

/// What a sealing of a held message is checked against: the signature of the author it claims, and once MLS opens it,
/// its MLS sender's signature key, its claim, its group, and its author's membership.
#[test]
fn held_headers_are_checked() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let id = w.m[0].group.as_ref().unwrap().id().to_vec();
    let joined = w.m[0].group.as_ref().unwrap().joined(w.m[0].session.key()).unwrap();
    let epoch = w.m[0].g().epoch();
    let plaintext = header(&w.m[0], &id, joined).encode();
    let claim = Ref { key: Bytes(w.m[0].session.key().to_vec()), joined, seq: 1, id: Bytes(held::id(&plaintext).to_vec()), epoch: joined };
    // The plaintext as member `by` seals it claiming `claim`, its sealing signed by A.
    let signed_by_a = |w: &mut World, by: usize, claim: &Ref| {
        let m = &mut w.m[by];
        let g = m.group.as_mut().unwrap();
        g.mls.set_aad(serde_json::to_vec(claim).unwrap());
        let bytes = g.mls.create_message(&m.provider, &m.session.signer, &plaintext).unwrap().to_bytes().unwrap();
        let sig = w.m[0].session.sign(&[SEALING, &held::sealing(&id, claim, epoch, &Sha256::digest(&bytes))].concat());
        [bytes, sig].concat()
    };
    // A's header, sealed by B: B's signature is not A's, and with A's the MLS sender is not the author.
    let sealed = w.m[1].seal(&plaintext);
    assert!(w.m[2].open(&sealed).unwrap_err().to_string().contains("did not sign"));
    let sealed = signed_by_a(&mut w, 1, &claim);
    assert!(w.m[2].open(&sealed).unwrap_err().to_string().contains("did not author"));
    // Claiming another seq than its header's.
    let claim = Ref { seq: 2, ..claim };
    let sealed = signed_by_a(&mut w, 0, &claim);
    let claimed = crate::group::claim(&id, &sealed).unwrap();
    assert_eq!((claimed.seq, claimed.sealed), (2, epoch), "the claim reads in the clear");
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
    assert!(b.group.as_mut().unwrap().open(&b.provider, &hi).is_err(), "opened before");
}

/// Cuts advance, a removed member leaves them, an added one starts at seq 0 of the new epoch, and every cut `rules`
/// refuses is refused by `commit` too.
#[test]
fn cuts_advance_and_refuse_what_rules_refuse() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1, 2]);
    let (a, b, c, d) = (w.m[0].session.key().to_vec(), w.m[1].session.key().to_vec(), w.m[2].session.key().to_vec(), w.m[3].session.key().to_vec());
    let gid = w.m[0].g().id().to_vec();
    w.m[0].send("m1");
    let m2 = w.m[0].send("m2");
    let stale = claim(&gid, &w.m[0].send("m3")).unwrap();
    let mut cut = w.m[0].cut();
    *at(&mut cut, &a) = claim(&gid, &m2).unwrap();
    let commit = w.m[0].commit(Change { cut: cut.clone(), ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2]);
    assert_eq!(applied(&read[1][0]).cut, cut);
    assert_eq!(w.m[2].cut(), cut);
    w.agree(&[0, 1, 2]);
    for (bad, why) in refusable(&cut, &a, &b, &stale) {
        let error = refused(&mut w.m[0], Change { cut: bad, ..Change::default() });
        assert!(error.contains(why), "{error}");
    }
    assert!(w.m[0].g().posted().is_none());

    // B sends in the new epoch, and A commits a cut that takes it, adds D and removes C.
    let mut cut = w.m[0].cut();
    *at(&mut cut, &b) = claim(&gid, &w.m[1].send("b1")).unwrap();
    let c_index = w.m[0].index_of("C");
    let kp_d = w.key_package(3);
    let next = w.m[0].g().epoch() + 1;
    let commit = w.m[0].commit(Change { cut: cut.clone(), add: vec![kp_d], remove: vec![c_index], invite: Some(invite()), ..Change::default() });
    w.post(commit.entry);
    let mut expected: Vec<Cut> = cut.iter().filter(|r| r.key.0 != c).cloned().collect();
    expected.push(Cut { key: Bytes(d), joined: next, ..Cut::default() });
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
    let gid = w.m[0].g().id().to_vec();
    w.m[0].send("m1");
    let m2 = w.m[0].send("m2");
    let stale = claim(&gid, &w.m[0].send("m3")).unwrap();
    let mut good = w.m[0].cut();
    *at(&mut good, &a) = claim(&gid, &m2).unwrap();
    let commit = w.m[0].commit(Change { cut: good.clone(), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    w.agree(&[0, 1, 2]);
    for (bad, why) in refusable(&good, &a, &b, &stale) {
        let mut liar = w.m[1].copy();
        let wire = unruled(&mut liar, Aad { moved: bad, ..Aad::default() }, |b| b);
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
/// not sign, or one with another commit's Welcome, is refused, and leaves the package usable for the right entry; so is
/// a cut its committer signed with an entry that is no sealing its member signed before the joiner's epoch, or one that
/// names the joiner.
#[test]
fn a_joiner_starts_at_the_commits_cut() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1]);
    let gid = w.m[0].g().id().to_vec();
    w.m[0].send("m1");
    let m2 = w.m[0].send("m2");
    let (a, b, c) = (w.m[0].session.key().to_vec(), w.m[1].session.key().to_vec(), w.m[2].session.key().to_vec());
    let next = w.m[0].g().epoch() + 1;
    let mut cut = w.m[0].cut();
    *at(&mut cut, &a) = claim(&gid, &m2).unwrap();
    let kp_c = w.key_package(2);
    let commit = w.m[0].commit(Change { cut: cut.clone(), add: vec![kp_c.clone()], invite: Some(invite()), ..Change::default() });
    let inner = w.m[0].open_inner(&commit.entry);
    let admission = commit.admission.clone().unwrap();
    let pos = w.post(commit.entry);
    w.read(&[0, 1]);
    let mut expected = cut;
    expected.push(Cut { key: Bytes(c.clone()), joined: next, ..Cut::default() });
    expected.sort();

    let Entry { commit: bytes, .. } = Entry::parse(&inner).unwrap();
    let before = w.m[2].provider.rows();
    let forged = entry_of(&stranger(), bytes.clone());
    assert!(join_error(&w.m[2], &forged, &admission, &kp_c).contains("did not sign"));
    assert_eq!(w.m[2].provider.rows(), before);
    let by_another_member = entry_of(&w.m[1].session.signer, bytes.clone());
    assert!(join_error(&w.m[2], &by_another_member, &admission, &kp_c).contains("did not sign"), "only the committer vouches for its cut");
    assert_eq!(w.m[2].provider.rows(), before);
    let welcome = Admission { sig: stranger().sign(&welcome_signed(&inner, &serde_json::to_vec(&admission.cut).unwrap(), &admission.welcome)).unwrap(), ..admission.clone() };
    assert!(join_error(&w.m[2], &inner, &welcome, &kp_c).contains("a Welcome its sender did not sign"));
    assert_eq!(w.m[2].provider.rows(), before);
    let kp_d = w.key_package(3);
    let mut other = w.m[0].copy();
    let cut = other.cut();
    let theirs = other.commit(Change { cut, add: vec![kp_d], invite: Some(invite()), ..Change::default() });
    join_error(&w.m[2], &inner, &theirs.admission.unwrap(), &kp_c);
    assert_eq!(w.m[2].provider.rows(), before);
    let (mut unsigned, mut later, mut naming) = (admission.cut.clone(), admission.cut.clone(), admission.cut.clone());
    let moved = at(&mut unsigned, &b);
    (moved.seq, moved.id) = (1, Bytes(vec![5; 32]));
    *at(&mut later, &a) = claim(&gid, &w.m[0].send("m3")).unwrap();
    naming.push(Cut { key: Bytes(c), ..Cut::default() });
    naming.sort();
    for cut in [unsigned, later, naming] {
        let sig = w.m[0].session.signer.sign(&welcome_signed(&inner, &serde_json::to_vec(&cut).unwrap(), &admission.welcome)).unwrap();
        assert!(join_error(&w.m[2], &inner, &Admission { cut, sig, ..admission.clone() }, &kp_c).contains("a malformed cut"));
        assert_eq!(w.m[2].provider.rows(), before);
    }

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
    let error = refused(&mut w.m[0], Change { cut, add: vec![package], invite: Some(invite()), remove: vec![b], ..Change::default() });
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
    let error = refused(&mut w.m[0], Change { cut, invite: Some(invite()), ..Change::default() });
    assert!(error.contains("an invite with no Add"), "{error}");
    assert!(w.m[0].g().posted().is_none());
    w.agree(&[0, 1]);
}

/// An Add uses an invite only by its secret: B's Add naming A's invite with another secret leaves it unused, and an Add
/// with its secret uses it, for every member.
#[test]
fn an_add_uses_an_invite_only_by_its_secret() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1]);
    let invite = Invited { by: Bytes(w.m[0].session.key().to_vec()), joined: 0, secret: Bytes(vec![3; 16]) };
    let hash = invite.hash(w.m[0].g().id());
    for (joiner, secret, used) in [(2, vec![4; 16], false), (3, vec![3; 16], true)] {
        let package = w.key_package(joiner);
        let cut = w.m[1].cut();
        let commit = w.m[1].commit(Change { cut, add: vec![package], invite: Some(Invited { secret: Bytes(secret), ..invite.clone() }), ..Change::default() });
        w.post(commit.entry);
        w.read(&[0, 1]);
        w.agree(&[0, 1]);
        assert_eq!([w.m[0].g().used(&hash.0), w.m[1].g().used(&hash.0)], [used; 2]);
    }
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
        .leaf_node_extensions(leaf_extensions(&leaf("forger", forger.public())).unwrap())
        .key_package_lifetime(Lifetime::init(0, u64::MAX))
        .build(CIPHERSUITE, &b.provider, &forger, naming_b(forger.public()))
        .unwrap();
    let package = MlsMessageOut::from(package.key_package().clone()).to_bytes().unwrap();
    let forged = naming_b(w.m[0].session.key());
    let cut = w.m[0].cut();
    let error = refused(&mut w.m[0], Change { cut: cut.clone(), add: vec![package], invite: Some(invite()), ..Change::default() });
    assert!(error.contains("a credential that names another key"), "{error}");

    // Built as `Group::commit` builds it but past `rules`, as a forger's client would.
    let package = w.key_package(2);
    let m = &mut w.m[0];
    let g = m.group.as_mut().unwrap();
    g.mls.set_aad(serde_json::to_vec(&Aad { invite: Some(invite()), ..Aad::default() }).unwrap());
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
    let admission = Admission { sig: m.session.signer.sign(&welcome_signed(&entry, &serde_json::to_vec(&cut).unwrap(), &welcome)).unwrap(), welcome, cut };
    assert!(join_error(&w.m[2], &entry, &admission, &package).contains("a member whose credential names another key"));
    let m = &w.m[0];
    let wire = m.group.as_ref().unwrap().seal_entry(&m.provider, &entry).unwrap();
    w.post(wire);
    let read = w.read(&[1]);
    assert!(matches!(&read[0][0].0, Verdict::Skipped { reason, .. } if reason.contains("a credential that names another key")), "{:?}", read[0][0].0);
}

/// Every leaf a commit brings, by an Add or an update, has a domain as its home, the proof of the iroh key it names, and
/// a device certificate of its session if it names one, and no two members' leaves name one iroh key once the commit
/// applies: any other is refused by the commit's builder, an Add's as its joiner asks too, and skipped by every member.
#[test]
fn a_commit_bringing_an_unproven_leaf_or_a_shared_iroh_key_is_refused() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1, 2]);
    let c = (w.m[2].session.key().to_vec(), w.m[2].session.leaf.key.clone());
    // Leaves of `m`, each with a word of its refusal: one naming C's iroh key, which did not sign it; one whose home is no
    // domain; one whose device certified C; and one that C's iroh key signed.
    let bad = |m: &Member| {
        let own = m.session.leaf.clone();
        [
            (Leaf { key: c.1.clone(), ..own.clone() }, "iroh key did not sign"),
            (Leaf { home: "Relay.example".into(), ..own.clone() }, "no domain"),
            (Leaf { device: Some(Device::sign(&device(0), &c.0)), ..own.clone() }, "device did not certify"),
            (Leaf { device: own.device.clone(), ..leaf("C", m.session.key()) }, "one iroh key"),
        ]
    };
    for (leaf, why) in bad(&w.m[1]) {
        let cut = w.m[1].cut();
        let error = refused(&mut w.m[1], Change { cut, leaf: Some(leaf.clone()), ..Change::default() });
        assert!(error.contains(why), "{error}");
        let update = LeafNodeParameters::builder().with_extensions(leaf_extensions(&leaf).unwrap()).build();
        w.refused_past_rules(1, Aad::default(), |b| b.leaf_node_parameters(update), &[0, 2], why);
    }
    w.read(&[1]);
    for (leaf, why) in bad(&w.m[3]) {
        let d = &mut w.m[3];
        d.session.set_leaf(&d.provider, leaf).unwrap();
        let package = w.key_package(3);
        // A KeyPackage alone shows all but whose iroh key its leaf names too.
        match key_package_leaf(&w.m[0].provider, &package) {
            Err(error) => assert!(error.to_string().contains(why), "{error}"),
            Ok(_) => assert_eq!(why, "one iroh key"),
        }
        let cut = w.m[0].cut();
        let error = refused(&mut w.m[0], Change { cut, add: vec![package.clone()], invite: Some(invite()), ..Change::default() });
        assert!(error.contains(why), "{error}");
        let add = key_package_in(&w.m[0].provider, &package).unwrap();
        w.refused_past_rules(0, Aad { invite: Some(invite()), ..Aad::default() }, |b| b.propose_adds([add]), &[1, 2], why);
    }
    w.read(&[0]);
    w.agree(&[0, 1, 2]);
}

/// A joiner refuses a group with a leaf that is not proven, as its founder's, which no commit brought, can be, or with two
/// leaves that name one iroh key, as an Add built past the rules can make.
#[test]
fn a_joiner_refuses_a_group_with_an_unproven_leaf_or_a_shared_iroh_key() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    let homeless = Leaf { home: "Relay.example".into(), ..a.session.leaf.clone() };
    a.session.set_leaf(&a.provider, homeless).unwrap();
    a.group = Some(Group::create(&a.provider, &a.session, &settings()).unwrap());
    let package = w.key_package(1);
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, add: vec![package.clone()], invite: Some(invite()), ..Change::default() });
    let (inner, admission) = (w.m[0].open_inner(&commit.entry), commit.admission.unwrap());
    assert!(join_error(&w.m[1], &inner, &admission, &package).contains("no domain"));

    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings()).unwrap());
    let b = &mut w.m[1];
    let shared = Leaf { device: b.session.leaf.device.clone(), ..leaf("A", b.session.key()) };
    b.session.set_leaf(&b.provider, shared).unwrap();
    let package = w.key_package(1);
    let cut = w.m[0].cut();
    let m = &mut w.m[0];
    let g = m.group.as_mut().unwrap();
    g.mls.set_aad(serde_json::to_vec(&Aad { invite: Some(invite()), ..Aad::default() }).unwrap());
    let bundle = g.mls.commit_builder().propose_adds(vec![key_package_in(&m.provider, &package).unwrap()]);
    let bundle = bundle.load_psks(m.provider.storage()).unwrap().build(m.provider.rand(), m.provider.crypto(), &m.session.signer, |_| true).unwrap();
    let (commit, welcome, _) = bundle.stage_commit(&m.provider).unwrap().into_messages();
    let entry = entry_of(&m.session.signer, commit.to_bytes().unwrap());
    let welcome = welcome.unwrap().to_bytes().unwrap();
    let admission = Admission { sig: m.session.signer.sign(&welcome_signed(&entry, &serde_json::to_vec(&cut).unwrap(), &welcome)).unwrap(), welcome, cut };
    assert!(join_error(&w.m[1], &entry, &admission, &package).contains("one iroh key"));
}

/// A KeyPackage must carry the unbounded lifetime `Session::key_package` gives: none with a bounded lifetime is taken in,
/// and an Add of one built past `Group::commit` is skipped by every member while it is valid, as it would be once expired.
#[test]
fn a_key_package_with_a_bounded_lifetime_is_refused() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1]);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    for (joiner, lifetime) in [(2, Lifetime::init(0, now + 300)), (3, Lifetime::init(1, u64::MAX))] {
        let m = &w.m[joiner];
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .leaf_node_extensions(leaf_extensions(&m.session.leaf).unwrap())
            .key_package_lifetime(lifetime)
            .build(CIPHERSUITE, &m.provider, &m.session.signer, m.session.with_key())
            .unwrap();
        let bytes = MlsMessageOut::from(bundle.key_package().clone()).to_bytes().unwrap();
        let error = key_package_leaf(&w.m[0].provider, &bytes).unwrap_err().to_string();
        assert!(error.contains("bounded lifetime"), "{error}");
        let cut = w.m[0].cut();
        let error = refused(&mut w.m[0], Change { cut, add: vec![bytes], invite: Some(invite()), ..Change::default() });
        assert!(error.contains("bounded lifetime"), "{error}");
        w.refused_past_rules(0, Aad { invite: Some(invite()), ..Aad::default() }, |b| b.propose_adds([bundle.key_package().clone()]), &[1], "bounded lifetime");
        w.read(&[0]);
        w.agree(&[0, 1]);
    }
}

/// An Add's committer keeps its Welcome, with which the joiner joins; another member keeps none.
#[test]
fn the_committer_keeps_the_welcome_of_its_add() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1]);
    let package = w.key_package(2);
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, add: vec![package.clone()], invite: Some(invite()), ..Change::default() });
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
    let commit = a.commit(Change { cut, add: vec![kp.clone()], invite: Some(invite()), ..Change::default() });
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

/// An Add alone carries no update path, so the joiner's own update merges it into the tree; an update carries one.
#[test]
fn only_an_add_alone_goes_without_an_update_path() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1]);
    let package = w.key_package(2);
    let cut = w.m[0].cut();
    let add = w.m[0].commit(Change { cut, add: vec![package.clone()], invite: Some(invite()), ..Change::default() });
    let (admission, inner) = (add.admission.clone().unwrap(), w.m[0].open_inner(&add.entry));
    let pos = w.post(add.entry);
    let read = w.read(&[0, 1]);
    assert!(!applied(&read[0][0]).updated && !applied(&read[1][0]).updated);
    w.m[2].join(&inner, &admission, pos, &package);
    let cut = w.m[2].cut();
    let update = w.m[2].commit(Change { cut, ..Change::default() });
    w.post(update.entry);
    let read = w.read(&[0, 1, 2]);
    assert!(read.iter().all(|reader| applied(&reader[0]).updated));
    w.agree(&[0, 1, 2]);
}

impl World {
    /// `by` adds `joiner`, which joins; `readers` read the commit.
    fn add(&mut self, by: usize, joiner: usize, readers: &[usize]) {
        let package = self.key_package(joiner);
        let cut = self.m[by].cut();
        let commit = self.m[by].commit(Change { cut, add: vec![package.clone()], invite: Some(invite()), ..Change::default() });
        let (inner, admission) = (self.m[by].open_inner(&commit.entry), commit.admission.clone().unwrap());
        let pos = self.post(commit.entry);
        self.read(readers);
        self.m[joiner].join(&inner, &admission, pos, &package);
    }

    /// `by` commits the group's settings as `edit` changes them; `readers` read the commit.
    fn settle(&mut self, by: usize, edit: impl FnOnce(&mut Settings), readers: &[usize]) {
        let mut settings = self.m[by].g().settings();
        edit(&mut settings);
        let cut = self.m[by].cut();
        let commit = self.m[by].commit(Change { cut, settings: Some(settings), ..Change::default() });
        self.post(commit.entry);
        self.read(readers);
    }

    /// Posts what a copy of member `i` commits past the rules, and checks that every member of `readers`, but `i`, which
    /// finds its state copied, skips it for a reason with `why`.
    fn refused_past_rules(&mut self, i: usize, aad: Aad, propose: impl for<'a> FnOnce(CommitBuilder<'a, Initial>) -> CommitBuilder<'a, Initial>, readers: &[usize], why: &str) {
        let mut liar = self.m[i].copy();
        let wire = unruled(&mut liar, aad, propose);
        self.post(wire);
        for reader in self.read(readers) {
            assert!(matches!(&reader[0].0, Verdict::Skipped { reason } if reason.contains(why)), "{:?}", reader[0].0);
        }
    }
}

/// A group's first admins are its founder and the device that certified it, whatever the settings it is made with name.
#[test]
fn a_group_starts_with_its_founder_and_its_device_as_admins() {
    let mut w = World::new(&["A", "B", "C"]);
    w.m[2].on(None);
    w.found(0, &[1, 2]);
    let [a, b, c] = [0, 1, 2].map(|i| w.m[i].session.key().to_vec());
    assert_eq!(w.m[2].g().settings().admins, [Bytes(a), key_of(&device(0))]);
    assert!(w.m[2].g().admin(&b), "a session on the founder's device is an admin");
    assert!(!w.m[0].g().admin(&c), "one on no device is not");
    let mut x = Member::new(memory(), "X");
    x.on(None);
    x.group = Some(Group::create(&x.provider, &x.session, &Settings { admins: vec![Bytes(vec![9; 32])], ..settings() }).unwrap());
    assert_eq!(x.g().settings().admins, [Bytes(x.session.key().to_vec())]);
}

/// A member that is no admin adds only sessions that a device admitted or an admin certified: not one on another device,
/// or on none. An admin adds any, and admits devices.
#[test]
fn a_member_that_is_no_admin_adds_only_sessions_on_admitted_devices() {
    let (admins, admitted) = (device(1), device(4));
    let mut w = World::new(&["A", "B", "C", "D", "E", "F"]);
    for (i, device) in [(0, &admins), (1, &device(2)), (2, &device(3)), (3, &admitted), (4, &admins)] {
        w.m[i].on(Some(device));
    }
    w.m[5].on(None);
    w.found(0, &[1]);
    w.add(1, 4, &[0, 1]);
    w.agree(&[0, 1, 4]);
    for joiner in [2, 3, 5] {
        let (package, cut) = (w.key_package(joiner), w.m[1].cut());
        let error = refused(&mut w.m[1], Change { cut, add: vec![package], invite: Some(invite()), ..Change::default() });
        assert!(error.contains("neither admitted nor an admin"), "{error}");
    }
    let package = key_package_in(&w.m[2].provider, &w.key_package(2)).unwrap();
    w.refused_past_rules(1, Aad { invite: Some(invite()), ..Aad::default() }, |b| b.propose_adds([package]), &[0, 4], "neither admitted nor an admin");

    w.settle(0, |s| s.admitted.push(key_of(&admitted)), &[0, 1, 4]);
    assert_eq!(w.m[1].g().settings().admitted, [key_of(&admitted)]);
    w.add(1, 3, &[0, 1, 4]);
    w.add(0, 5, &[0, 1, 3, 4]);
    w.agree(&[0, 1, 3, 4, 5]);
    let leaf = w.m[2].session.leaf.clone();
    assert!(!w.m[3].g().admits(&leaf));
}

/// A member that is no admin removes only members whose leave of their current membership its commit carries; an admin
/// removes any.
#[test]
fn a_member_that_is_no_admin_removes_only_members_that_signed_their_leave() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    for i in 1..4 {
        w.m[i].on(None);
    }
    w.found(0, &[1, 2, 3]);
    let (c, d) = (w.m[0].index_of("C"), w.m[0].index_of("D"));
    let [leave, other] = [2, 3].map(|i| w.m[i].group.as_ref().unwrap().leave(&w.m[i].session).unwrap());
    let key = w.m[2].session.key().to_vec();
    assert!(w.m[1].g().left(&key, &leave.0) && !w.m[1].g().left(&key, &other.0));
    for left in [vec![], vec![other.clone()]] {
        let cut = w.m[1].cut();
        let error = refused(&mut w.m[1], Change { cut, remove: vec![c], left, ..Change::default() });
        assert!(error.contains("did not sign its leave"), "{error}");
    }
    w.refused_past_rules(1, Aad { left: vec![other], ..Aad::default() }, |b| b.propose_removals([LeafNodeIndex::new(c)]), &[0, 2, 3], "did not sign its leave");
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, remove: vec![c], left: vec![leave.clone()], ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2, 3]);
    assert!(applied(&read[2][0]).gone);
    w.agree(&[0, 1, 3]);

    // C, added again with its key, is not removed by its earlier membership's leave; D is, by the admin, with none.
    let gone = w.m[2].group.take().unwrap();
    gone.delete(&w.m[2].provider).unwrap();
    w.add(0, 2, &[0, 1, 3]);
    let c = w.m[0].index_of("C");
    let cut = w.m[1].cut();
    let error = refused(&mut w.m[1], Change { cut, remove: vec![c], left: vec![leave], ..Change::default() });
    assert!(error.contains("did not sign its leave"), "{error}");
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, remove: vec![d], ..Change::default() });
    w.post(commit.entry);
    assert!(applied(&w.read(&[0, 1, 2, 3])[3][0]).gone);
    w.agree(&[0, 1, 2]);
}

/// Only an admin changes a group's settings, and only its admins and admitted devices, leaving it an admin: every member
/// skips any other change.
#[test]
fn only_an_admin_changes_the_admins_and_admitted_devices() {
    let mut w = World::new(&["A", "B", "C"]);
    for i in 1..3 {
        w.m[i].on(Some(&device(i as u8)));
    }
    w.found(0, &[1, 2]);
    let (b, c) = (Bytes(w.m[1].session.key().to_vec()), Bytes(w.m[2].session.key().to_vec()));
    let cut = w.m[1].cut();
    let mut changed = w.m[1].g().settings();
    changed.admitted.push(key_of(&device(2)));
    let error = refused(&mut w.m[1], Change { cut, settings: Some(changed.clone()), ..Change::default() });
    assert!(error.contains("no admin"), "{error}");
    w.refused_past_rules(1, Aad::default(), |b| b.propose_group_context_extensions(context_extensions(&changed).unwrap()).unwrap(), &[0, 2], "by a member that is no admin");

    w.settle(0, |s| s.admins = vec![b.clone()], &[0, 1, 2]);
    let a = w.m[0].session.key().to_vec();
    assert!(w.m[2].g().admin(&b.0) && !w.m[2].g().admin(&a), "the admins are B alone");
    w.settle(1, |s| s.admins.push(key_of(&device(2))), &[0, 1, 2]);
    assert!(w.m[0].g().admin(&c.0), "C is an admin by its device");
    let fixed: [fn(&mut Settings); 4] = [|s| s.carry += 1, |s| s.update += 1, |s| s.protocol += 1, |s| s.membership = service("other.example")];
    for change in fixed {
        let mut changed = w.m[1].g().settings();
        change(&mut changed);
        let cut = w.m[1].cut();
        let error = refused(&mut w.m[1], Change { cut, settings: Some(changed), ..Change::default() });
        assert!(error.contains("more than the admins and admitted devices"), "{error}");
    }
    let (cut, settings) = (w.m[1].cut(), w.m[1].g().settings());
    let error = refused(&mut w.m[1], Change { cut, settings: Some(Settings { admins: vec![], ..settings }), ..Change::default() });
    assert!(error.contains("leaves the group no admin"), "{error}");
    let settings = w.m[1].g().settings();
    let required = RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(SETTINGS_EXTENSION)], &[], &[]);
    let fewer = vec![Extension::RequiredCapabilities(required), Extension::Unknown(SETTINGS_EXTENSION, UnknownExtension(serde_json::to_vec(&settings).unwrap()))];
    let fewer = Extensions::from_vec(fewer).unwrap();
    w.refused_past_rules(1, Aad::default(), |b| b.propose_group_context_extensions(fewer).unwrap(), &[0, 2], "other context extensions");
    w.agree(&[0, 1, 2]);

    // Any member updates.
    let cut = w.m[0].cut();
    let update = w.m[0].commit(Change { cut, ..Change::default() });
    w.post(update.entry);
    assert!(w.read(&[0, 1, 2]).iter().all(|reader| applied(reader.last().unwrap()).updated));
    w.agree(&[0, 1, 2]);
}
