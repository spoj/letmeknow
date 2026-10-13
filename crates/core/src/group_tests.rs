//! Groups on our API, and the openmls behaviour the group log relies on: storage that commits and rolls back with our
//! records, forged messages that leave no trace, commits from one's own leaf, and two epochs of keys.

use super::*;
use crate::provider::MemoryProvider;
use lmk_proto::group::{CHAT, ChatMessage, REVISION, Service};
use sha2::{Digest, Sha256};

/// A membership service at `relay`, for logs no test reaches.
pub(crate) fn service(relay: &str) -> Service {
    Service::Serve { key: ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes().into(), relay: relay.into(), addrs: vec![], rest: Default::default() }
}

pub(crate) fn settings(name: &str) -> Settings {
    Settings {
        protocol: PROTOCOL,
        kind: CHAT.into(),
        name: name.into(),
        carry: 7,
        update: lmk_proto::group::UPDATE,
        membership: service("https://lmk.example"),
        public: None,
        rest: Default::default(),
    }
}

pub(crate) fn leaf(name: &str) -> Leaf {
    Leaf { key: Bytes(name.as_bytes().to_vec()), relay: "https://relay.example/".into(), kinds: vec![CHAT.into()], revision: REVISION }
}

/// An entry as a member read it: its verdict, and for a commit what applying it did.
type Read = (Verdict, Option<Applied>);

pub(crate) struct Member<P: Provider = MemoryProvider> {
    pub provider: P,
    pub session: Session,
    pub group: Option<Group>,
    /// Next log position to read (0-based here).
    pub pos: usize,
    /// The ids of the held messages this member sent, in seq order.
    sent: Vec<[u8; 32]>,
}

impl<P: Provider> Member<P> {
    pub fn new(provider: P, name: &str) -> Self {
        let session = Session::create(&provider, name, leaf(name)).unwrap();
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
            prev: self.sent.last().map(|id| Bytes(id.to_vec())),
            deps: vec![],
            reply_to: None,
            payload: message(text),
        };
        let plaintext = header.encode();
        self.sent.push(held::id(&plaintext));
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
        group.members().iter().find(|m| m.credential.as_ref().unwrap().name == name).unwrap().index
    }

    /// Joins by the inner entry of the commit that added this member, which its committer posted at `pos`.
    pub fn join(&mut self, entry: &[u8], pos: usize, package: &[u8]) {
        let reference = key_package_reference(&self.provider, package).unwrap();
        self.group = Some(Group::join(&self.provider, entry, &reference).unwrap());
        self.pos = pos;
    }
}

impl Member<MemoryProvider> {
    /// A copy of this member, its storage and all, as a stolen or restored device holds it.
    fn copy(&self) -> Self {
        let provider = MemoryProvider::load(self.provider.records());
        let session = Session::load(&provider).unwrap();
        let group = self.group.as_ref().map(|group| Group::load(&provider, group.id()).unwrap());
        Member { provider, session, group, pos: self.pos, sent: self.sent.clone() }
    }
}

pub(crate) fn message(text: &str) -> serde_json::Value {
    let message = ChatMessage { content: text.into(), to: vec![], urgent: false, attachment: None, sent_at: None };
    serde_json::to_value(message).unwrap()
}

fn text(opened: &Opened) -> &str {
    opened.header.payload["content"].as_str().expect("a message")
}

/// A commit's entry, signed by `signer`.
fn entry_of(signer: &SignatureKeyPair, commit: Vec<u8>, welcome: Option<Vec<u8>>) -> Vec<u8> {
    let sig = signer.sign(&signed(&commit, welcome.as_deref())).unwrap();
    Entry { commit, welcome, sig }.encode()
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

/// A commit built past `Group::commit`'s rules: a key update naming `cut`, with `settings` and `leaf` if given. It is
/// kept as `m`'s pending commit, as `Group::commit` keeps one.
fn unruled(m: &mut Member, cut: Vec<Ref>, settings: Option<Settings>, leaf: Option<LeafNodeParameters>) -> Vec<u8> {
    let group = m.group.as_mut().unwrap();
    let aad = Aad { cut, ..Aad::default() };
    group.mls.set_aad(serde_json::to_vec(&aad).unwrap());
    let mut builder = group.mls.commit_builder().consume_proposal_store(false).force_self_update(true);
    if let Some(settings) = &settings {
        builder = builder.propose_group_context_extensions(context_extensions(settings).unwrap()).unwrap();
    }
    if let Some(leaf) = leaf {
        builder = builder.leaf_node_parameters(leaf);
    }
    let bundle = builder
        .load_psks(m.provider.storage())
        .unwrap()
        .build(m.provider.rand(), m.provider.crypto(), &m.session.signer, |_| true)
        .unwrap()
        .stage_commit(&m.provider)
        .unwrap();
    let entry = entry_of(&m.session.signer, bundle.into_messages().0.to_bytes().unwrap(), None);
    let wire = group.seal_entry(&m.provider, &entry).unwrap();
    group.state.posted = Some(Posted { inner: Bytes(entry), wire: Bytes(wire.clone()), add_refs: vec![] });
    group.state.aad = aad;
    wire
}

/// The refusal `Group::commit` gives a commit built with `change`, which must be refused.
fn refused(m: &mut Member, change: Change) -> String {
    let group = m.group.as_mut().unwrap();
    group.commit(&m.provider, &m.session, change).err().expect("refused").to_string()
}

/// The refusal `Group::join` gives an entry for `package`, which must be refused.
fn join_error(m: &Member, entry: &[u8], package: &[u8]) -> String {
    let reference = key_package_reference(&m.provider, package).unwrap();
    Group::join(&m.provider, entry, &reference).err().expect("refused").to_string()
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
    Header { group: Bytes(group.to_vec()), author: Bytes(m.session.key().to_vec()), joined, seq: 1, prev: None, deps: vec![], reply_to: None, payload: message("forged") }
}

fn live(m: &Member, payload: &serde_json::Value) -> Vec<u8> {
    let (wire, id) = m.group.as_ref().unwrap().seal_live(&m.provider, &m.session, payload).unwrap();
    assert_eq!(m.group.as_ref().unwrap().open_live(&m.provider, &wire).unwrap().2, id);
    wire
}

/// The sender's key and the payload of a live payload `m` opens, if it opens.
fn open_live(m: &Member, wire: &[u8]) -> Result<(Vec<u8>, serde_json::Value)> {
    let (sender, payload, _) = m.group.as_ref().unwrap().open_live(&m.provider, wire)?;
    Ok((sender.key, payload))
}

struct World {
    m: Vec<Member>,
    log: Vec<Vec<u8>>,
}

impl World {
    fn new(names: &[&str]) -> Self {
        World { m: names.iter().map(|name| Member::new(MemoryProvider::default(), name)).collect(), log: Vec::new() }
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
        c.group = Some(Group::create(&c.provider, &c.session, &settings("Plan")).unwrap());
        let adds: Vec<_> = others.iter().map(|&i| self.m[i].session.key_package(&self.m[i].provider).unwrap()).collect();
        let cut = self.m[creator].cut();
        let commit = self.m[creator].commit(Change { cut, add: adds.clone(), how: Some(How::Invite), ..Change::default() });
        let inner = self.m[creator].open_inner(&commit.entry);
        let pos = self.post(commit.entry);
        self.read(&[creator]);
        for (&i, package) in others.iter().zip(adds) {
            self.m[i].join(&inner, pos, &package);
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
    let b = w.m[1].commit(Change { cut, add: vec![kp_d.clone()], how: Some(How::Invite), ..Change::default() });
    assert!(w.m[0].g().posted().is_some() && w.m[1].g().posted().is_some());
    w.post(a.entry);
    w.post(b.entry);
    let read = w.read(&[0, 1, 2]);
    assert!(matches!(applied(&read[0][0]), Applied { own: true, lost: false, .. }));
    assert!(matches!(applied(&read[1][0]), Applied { own: false, lost: true, .. }));
    assert!(matches!(read[1][1].0, Verdict::Skipped { lost: false, .. }));
    assert!(matches!(read[2][1].0, Verdict::Skipped { .. }));
    assert!(w.m[1].g().posted().is_none() && w.m[1].g().epoch() == e + 1);
    w.agree(&[0, 1, 2]);

    let cut = w.m[1].cut();
    let b2 = w.m[1].commit(Change { cut, add: vec![kp_d.clone()], how: Some(How::Invite), ..Change::default() });
    let inner = w.m[1].open_inner(&b2.entry);
    let pos = w.post(b2.entry);
    let read = w.read(&[0, 1, 2]);
    let Applied { added, by, .. } = applied(&read[0][0]);
    assert_eq!((added[0].credential.as_ref().unwrap().name.as_str(), *by), ("D", w.m[1].g().own_index()));
    w.m[3].join(&inner, pos, &kp_d);
    w.agree(&[0, 1, 2, 3]);
    let added = w.m[0].g().added().last().unwrap().clone();
    assert_eq!((added.member.name.as_str(), added.by.name.as_str(), added.epoch), ("D", "B", e + 2));

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
    w.post_inner(Entry { commit: app, welcome: None, sig: vec![0; 64] }.encode());
    let x = &mut w.m[4];
    x.group = Some(Group::create(&x.provider, &x.session, &settings("other")).unwrap());
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
    assert!(matches!(applied(&read[3][4]), Applied { gone: true, lost: true, .. }));
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

/// A commit entry counts only with its committer's signature over the commit and its Welcome.
#[test]
fn a_commit_entry_needs_its_committers_signature() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1, 2]);
    let kp = w.key_package(3);
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, add: vec![kp], how: Some(How::Invite), ..Change::default() });
    let inner = w.m[0].open_inner(&commit.entry);
    let Entry { commit: bytes, welcome, sig } = Entry::parse(&inner).unwrap();
    // Signed by a stranger, or carrying another Welcome than the committer signed.
    w.post_inner(entry_of(&stranger(), bytes.clone(), welcome));
    w.post_inner(Entry { commit: bytes, welcome: Some(b"another welcome".to_vec()), sig }.encode());
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
fn a_forged_message_leaves_no_trace<P: Provider>(providers: impl Fn(&str) -> P) {
    let mut a = Member::new(providers("a"), "A");
    let mut b = Member::new(MemoryProvider::default(), "B");
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let kp = b.session.key_package(&b.provider).unwrap();
    let cut = a.cut();
    let commit = a.commit(Change { cut, add: vec![kp.clone()], how: Some(How::Invite), ..Change::default() });
    let inner = a.open_inner(&commit.entry);
    let log = vec![commit.entry];
    a.read(&log);
    b.join(&inner, 1, &kp);
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

#[test]
fn a_forged_message_leaves_no_trace_in_memory() {
    a_forged_message_leaves_no_trace(|_| MemoryProvider::default());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn a_forged_message_leaves_no_trace_in_sqlite() {
    let dir = std::env::temp_dir().join(format!("lmk-core-forged-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    a_forged_message_leaves_no_trace(|name| crate::provider::SqliteProvider::open(&dir.join(format!("{name}.db"))).unwrap());
    std::fs::remove_dir_all(dir).ok();
}

/// Proof: one SQLite connection, openmls's storage borrowing it. A step's openmls writes and our own records commit
/// together, or are lost together; after a rollback to a savepoint, `MlsGroup::load` gives the group as it was before.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn a_step_commits_or_rolls_back_with_openmls() {
    use crate::provider::SqliteProvider;
    let dir = std::env::temp_dir().join(format!("lmk-core-step-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut a = Member::new(SqliteProvider::open(&dir.join("a.db")).unwrap(), "A");
    let mut b = Member::new(MemoryProvider::default(), "B");
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let kp = b.session.key_package(&b.provider).unwrap();
    let cut = a.cut();
    let commit = a.commit(Change { cut, add: vec![kp.clone()], how: Some(How::Invite), ..Change::default() });
    let inner = a.open_inner(&commit.entry);
    let log = vec![commit.entry];
    a.read(&log);
    b.join(&inner, 1, &kp);
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
    let Entry { commit, welcome, .. } = Entry::parse(&inner).unwrap();
    w.post_inner(entry_of(&stranger(), commit, welcome));
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

/// A member that renames the group keeps a field of the settings that a newer letmeknow wrote.
#[test]
fn a_rename_keeps_settings_fields_the_renamer_does_not_know() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let mut newer = w.m[0].g().settings();
    newer.rest.insert("color".into(), "red".into());
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, settings: Some(newer), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1]);
    let renamed = Settings { name: "Release".into(), ..w.m[1].g().settings() };
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, settings: Some(renamed), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1]);
    let settings = w.m[0].g().settings();
    assert_eq!((settings.name.as_str(), &settings.rest["color"]), ("Release", &serde_json::json!("red")));
}

#[test]
fn settings_in_the_welcome() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1, 2]);
    let mut changed = w.m[0].g().settings();
    changed.name = "Plan v2".into();
    changed.carry = 30;
    changed.membership = service("https://elsewhere.example");
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, settings: Some(changed.clone()), ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2]);
    assert!(applied(&read[1][0]).settings);
    assert_eq!(w.m[1].g().settings(), changed);
    assert_eq!(w.m[2].g().settings(), changed);
    assert!(w.m[2].g().mls.extensions().required_capabilities().is_some());

    let kp = w.key_package(3);
    let cut = w.m[2].cut();
    let commit = w.m[2].commit(Change { cut, add: vec![kp.clone()], how: Some(How::Invite), ..Change::default() });
    let inner = w.m[2].open_inner(&commit.entry);
    let pos = w.post(commit.entry);
    w.read(&[0, 1, 2]);
    w.m[3].join(&inner, pos, &kp);
    assert_eq!(w.m[3].g().settings(), changed);
    w.agree(&[0, 1, 2, 3]);
}

#[test]
fn leaf_data() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let leaves: Vec<_> = w.m[0].g().members().into_iter().map(|m| m.leaf.unwrap()).collect();
    assert_eq!(leaves, [leaf("A"), leaf("B"), leaf("C")]);
    let moved = Leaf { relay: "https://relay2.example/".into(), ..leaf("B") };
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, leaf: Some(moved.clone()), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    let b = w.m[2].index_of("B");
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

/// A member renames itself in an update; a message from before the rename still names its sender.
#[test]
fn a_member_renames_itself() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let before = w.m[1].send("before the rename");
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, name: Some("Bee".into()), ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2]);
    assert!(read.iter().all(|reader| is_commit(&reader[0])));
    w.agree(&[0, 1, 2]);
    let b = w.m[0].index_of("Bee");
    assert_eq!(w.m[2].g().members()[b as usize].leaf.as_ref(), Some(&leaf("B")), "the leaf data stays");
    let opened = w.m[2].open(&before).unwrap();
    assert_eq!(opened.sender.name.as_str(), "B");
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

    // Our own API refuses to build a commit that breaks them.
    let mut bad = w.m[1].g().settings();
    bad.kind = "doc".into();
    let cut = w.m[1].cut();
    let error = refused(&mut w.m[1], Change { cut, settings: Some(bad.clone()), ..Change::default() });
    assert!(error.contains("kind"));
    assert!(w.m[1].g().posted().is_none());

    // A kind change, built around it, and then a protocol change.
    for change in [|s: &mut Settings| s.kind = "doc".into(), |s: &mut Settings| s.protocol = PROTOCOL + 1] {
        let mut bad = w.m[1].g().settings();
        change(&mut bad);
        let cut = w.m[1].cut();
        let wire = unruled(&mut w.m[1], cut, Some(bad), None);
        w.post(wire);
        let read = w.read(&[0, 1, 2]);
        assert!(matches!(&read[1][0].0, Verdict::Skipped { lost: true, .. }));
        assert!(read.iter().all(|reader| !is_commit(&reader[0])));
        w.agree(&[0, 1, 2]);
    }

    // An update that changes the committer's credential beyond its name: C claims an identity.
    let identity = lmk_proto::group::IdentityRef { id: Bytes(vec![1; 32]), membership: service("https://lmk.example") };
    w.m[2].session.credential.certificate = Some(lmk_proto::group::Certificate { identity, device: Bytes(vec![2; 32]), name: "Ann".into(), device_name: "laptop".into(), sig: Bytes(vec![3; 64]) }.into());
    let cut = w.m[2].cut();
    let c = &mut w.m[2];
    let leaf = LeafNodeParameters::builder()
        .with_credential_with_key(c.session.with_key())
        .with_extensions(leaf_extensions(&c.session.leaf).unwrap())
        .build();
    let wire = unruled(c, cut, None, Some(leaf));
    w.post(wire);
    let read = w.read(&[0, 1, 2]);
    assert!(matches!(&read[2][0].0, Verdict::Skipped { lost: true, reason } if reason.contains("authorization")));
    assert!(!is_commit(&read[0][0]) && !is_commit(&read[1][0]));
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
    let entry = entry_of(&c.session.signer, commit.to_bytes().unwrap(), None);
    let wire = group.seal_entry(&c.provider, &entry).unwrap();
    group.state.posted = Some(Posted { inner: Bytes(entry), wire: Bytes(wire.clone()), add_refs: vec![] });
    w.post_inner(entry_of(&w.m[1].session.signer, proposal, None));
    w.post(wire);
    let read = w.read(&[0, 1, 2]);
    assert!(read.iter().all(|reader| reader.iter().all(|a| !is_commit(a))));
    assert!(matches!(&read[2][1].0, Verdict::Skipped { lost: true, reason } if reason.contains("reference")));
    w.agree(&[0, 1, 2]);
}

#[test]
fn private_certificates_refresh_but_cannot_rebind_a_membership() {
    use crate::device::{public, sign};
    use lmk_proto::group::IdentityRef;
    use lmk_proto::public::certified;
    let mut w = World::new(&["A", "B", "Later"]);
    let device = crate::random();
    let id = crate::random();
    let key: [u8; 32] = w.m[0].session.key().try_into().unwrap();
    let of = |id: [u8; 32], seed: &[u8; 32], key: [u8; 32], name: &str, label: &str| Certificate {
        identity: IdentityRef { id: id.into(), membership: service("https://lmk.example") },
        device: public(seed).into(), name: name.into(), device_name: label.into(),
        sig: Bytes(sign(seed, &certified(&key, &id, &public(seed), name, label))),
    };
    let original = of(id, &device, key, "Ann", "phone");
    w.m[0].session.credential.certificate = Some(Box::new(original));
    w.found(0, &[1]);
    let refreshed = of(id, &device, key, "Ann Lee", "pocket");
    let mut forged = refreshed.clone();
    forged.name = "unsigned label".into();
    for certificate in [forged, of(crate::random(), &device, key, "Ann Lee", "pocket"), of(id, &crate::random(), key, "Ann Lee", "pocket"), of(id, &device, crate::random(), "Ann Lee", "pocket")] {
        let a = &mut w.m[0];
        let before: std::collections::BTreeMap<_, _> = a.provider.records().into_iter().collect();
        let cut = a.cut();
        assert!(refused(a, Change { cut, certificate: Some(certificate), ..Change::default() }).contains("authorization"));
        assert!(a.g().posted().is_none());
        assert_eq!(a.provider.records().into_iter().collect::<std::collections::BTreeMap<_, _>>(), before, "refused refresh leaves no stored residue");
    }
    let b = &mut w.m[1];
    let before: std::collections::BTreeMap<_, _> = b.provider.records().into_iter().collect();
    let attached = of(id, &device, b.session.key().try_into().unwrap(), "Ann", "phone");
    let cut = b.cut();
    assert!(refused(b, Change { cut, certificate: Some(attached), ..Change::default() }).contains("authorization"));
    assert_eq!(b.provider.records().into_iter().collect::<std::collections::BTreeMap<_, _>>(), before, "an anonymous leaf cannot acquire an identity");
    let cut = w.m[0].cut();
    let losing = w.m[0].commit(Change { cut, certificate: Some(refreshed.clone()), ..Change::default() });
    let cut = w.m[1].cut();
    let competing = w.m[1].commit(Change { cut, name: Some("Bee".into()), ..Change::default() });
    w.post(competing.entry);
    w.post(losing.entry);
    assert!(w.read(&[0, 1]).iter().all(|r| is_commit(&r[0]) && !is_commit(&r[1])));
    w.agree(&[0, 1]);
    assert!(w.m[0].g().posted().is_none());
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, certificate: Some(refreshed.clone()), ..Change::default() });
    w.post(commit.entry);
    assert!(w.read(&[0, 1]).iter().all(|r| is_commit(&r[0])));
    w.agree(&[0, 1]);
    let kp = w.key_package(2);
    let cut = w.m[1].cut();
    let add = w.m[1].commit(Change { cut, add: vec![kp.clone()], how: Some(How::Invite), ..Change::default() });
    let inner = w.m[1].open_inner(&add.entry);
    let pos = w.post(add.entry);
    w.read(&[0, 1]);
    w.m[2].join(&inner, pos, &kp);
    for reader in &mut w.m {
        let a = reader.g().members().into_iter().find(|m| m.key == key).unwrap().credential.unwrap();
        assert_eq!(a.name, "A");
        assert_eq!(a.certificate.as_deref(), Some(&refreshed));
    }
    // Bypass our API, including valid signatures for forbidden authorization tuples.
    let mut forged = refreshed;
    forged.name = "unsigned".into();
    let attached = of(id, &device, w.m[1].session.key().try_into().unwrap(), "Ann", "phone");
    for (author, certificate, signed) in [
        (0, None, false),
        (0, Some(forged), false),
        (0, Some(of(crate::random(), &device, key, "Ann", "phone")), true),
        (0, Some(of(id, &crate::random(), key, "Ann", "phone")), true),
        (1, Some(attached), true),
    ] {
        let before: Vec<_> = w.m.iter_mut().map(|m| (m.g().epoch(), m.g().members().into_iter().map(|m| (m.key, m.credential)).collect::<Vec<_>>())).collect();
        let a = &mut w.m[author];
        let mut unsigned = a.session.credential.clone();
        unsigned.certificate = certificate.map(Box::new);
        assert_eq!(crate::public::verify_certificate(&unsigned), signed);
        let leaf = LeafNodeParameters::builder().with_credential_with_key(CredentialWithKey {
            credential: BasicCredential::new(serde_json::to_vec(&unsigned).unwrap()).into(),
            signature_key: a.session.signer.public().into(),
        }).build();
        let cut = a.cut();
        let wire = unruled(a, cut, None, Some(leaf));
        w.post(wire);
        assert!(w.read(&[0, 1, 2]).iter().all(|r| matches!(&r[0].0, Verdict::Skipped { reason, .. } if reason.contains("authorization"))));
        w.agree(&[0, 1, 2]);
        for (reader, (epoch, members)) in w.m.iter_mut().zip(before) {
            assert_eq!(reader.g().epoch(), epoch);
            assert_eq!(reader.g().members().into_iter().map(|m| (m.key, m.credential)).collect::<Vec<_>>(), members);
            assert!(reader.g().posted().is_none());
        }
    }
}

#[test]
fn credentials_are_checked_not_enforced() {
    use crate::device::{public, sign};
    use crate::public::{PublicLog, Verdict, create};
    use lmk_proto::group::{Certificate, IdentityRef};
    use lmk_proto::public::certified;
    let mut w = World::new(&["A", "M"]);
    let laptop = crate::random();
    let (id, first) = create(&laptop, service("https://lmk.example"));
    let log = PublicLog::replay(&id, [first.as_slice()]).unwrap();
    let identity = IdentityRef { id: id.into(), membership: service("https://lmk.example") };
    // A speaks as Alice, certified by her laptop; M claims her identity with A's certificate.
    let sig = Bytes(sign(&laptop, &certified(w.m[0].session.key().try_into().unwrap(), &id, &public(&laptop), "Alice", "laptop")));
    let certificate = Certificate { identity, device: public(&laptop).into(), name: "Alice".into(), device_name: "laptop".into(), sig };
    w.m[0].session.credential.certificate = Some(certificate.clone().into());
    w.m[1].session.credential.certificate = Some(certificate.into());
    let m = key_package_credential(&w.m[0].provider, &w.key_package(1)).unwrap();
    assert_eq!(log.verify(&m), Verdict::Unverified);
    w.found(0, &[1]);
    w.agree(&[0, 1]);
    let checked: Vec<Verdict> = w.m[1].g().members().iter().map(|member| log.verify(member.credential.as_ref().unwrap())).collect();
    assert_eq!(checked, [Verdict::Authorized, Verdict::Unverified]);
    let hi = w.m[1].send("hi from M");
    let opened = w.m[0].open(&hi).unwrap();
    assert_eq!((opened.sender.key.0, opened.sender.name), (w.m[1].session.key().to_vec(), "M".to_owned()));
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
    assert_eq!(applied(&read[0][0]).removed[0].credential.as_ref().unwrap().name, "C");
    assert!(matches!(read[2][0].0, Verdict::Commit { removes: true }));
    assert!(!w.m[2].g().active());
    w.agree(&[0, 1]);
    let opened = w.m[0].open(&early).unwrap();
    assert_eq!((opened.sender.name.as_str(), text(&opened)), ("C", "before my removal"));
    assert!(w.m[0].open(&past).unwrap_err().to_string().contains("final cut"));
}

#[test]
fn another_protocol_is_refused_at_join() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
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
    let entry = entry_of(&a.session.signer, commit.to_bytes().unwrap(), Some(welcome.unwrap().to_bytes().unwrap()));
    group.mls.merge_pending_commit(&a.provider).unwrap();
    let error = Group::join(&w.m[1].provider, &entry, &reference).err().unwrap();
    assert!(error.to_string().contains(&format!("protocol {}", PROTOCOL + 1)), "{error}");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn state_survives_a_restart() {
    use crate::provider::SqliteProvider;
    let dir = std::env::temp_dir().join(format!("lmk-core-restart-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut log = Vec::new();
    let mut a = Member::new(SqliteProvider::open(&dir.join("a.db")).unwrap(), "A");
    let b = Member::new(SqliteProvider::open(&dir.join("b.db")).unwrap(), "B");
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let kp = b.session.key_package(&b.provider).unwrap();
    let cut = a.cut();
    let commit = a.commit(Change { cut, add: vec![kp.clone()], how: Some(How::Invite), ..Change::default() });
    let inner = a.open_inner(&commit.entry);
    log.push(commit.entry);
    a.read(&log);
    let id = a.g().id().to_vec();
    let mut b = Member { pos: 1, ..b };
    b.join(&inner, 1, &kp);
    // B adds C, then restarts before reading a separately re-enveloped copy of its pending inner Entry.
    let mut c = Member::new(MemoryProvider::default(), "C");
    let c_package = c.session.key_package(&c.provider).unwrap();
    let c_ref = key_package_reference(&c.provider, &c_package).unwrap();
    let cut = b.cut();
    let pending = b.commit(Change { cut, add: vec![c_package.clone()], how: Some(How::Invite), ..Change::default() });
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
    c.join(&inner, log.len(), &c_package);
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
    assert_eq!(error.to_string(), format!("the message is {} bytes, over the 1 MiB members take", MAX_MESSAGE + 1));
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
    let commit = w.m[0].commit(Change { cut: cut.clone(), add: vec![kp_d], how: Some(How::Invite), remove: vec![c_index], ..Change::default() });
    w.post(commit.entry);
    let mut expected: Vec<Ref> = cut.iter().filter(|r| r.key.0 != c).cloned().collect();
    expected.push(Ref { key: Bytes(d), joined: next, seq: 0, id: Bytes::default() });
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
        let wire = unruled(&mut liar, bad, None, None);
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
    let commit = w.m[0].commit(Change { cut: cut.clone(), add: vec![kp_c.clone()], how: Some(How::Invite), ..Change::default() });
    let inner = w.m[0].open_inner(&commit.entry);
    let pos = w.post(commit.entry);
    w.read(&[0, 1]);
    let mut expected = cut;
    expected.push(Ref { key: Bytes(c), joined: next, seq: 0, id: Bytes::default() });
    expected.sort();

    let Entry { commit: bytes, welcome, .. } = Entry::parse(&inner).unwrap();
    let before = w.m[2].provider.records();
    let forged = entry_of(&stranger(), bytes.clone(), welcome.clone());
    assert!(join_error(&w.m[2], &forged, &kp_c).contains("did not sign"));
    assert_eq!(w.m[2].provider.records(), before);
    let by_another_member = entry_of(&w.m[1].session.signer, bytes.clone(), welcome);
    assert!(join_error(&w.m[2], &by_another_member, &kp_c).contains("did not sign"), "only the committer vouches for its cut");
    assert_eq!(w.m[2].provider.records(), before);
    let kp_d = w.key_package(3);
    let mut other = w.m[0].copy();
    let cut = other.cut();
    let theirs = other.commit(Change { cut, add: vec![kp_d], how: Some(How::Invite), ..Change::default() });
    let mixed = entry_of(&w.m[0].session.signer, bytes, theirs.welcome);
    join_error(&w.m[2], &mixed, &kp_c);
    assert_eq!(w.m[2].provider.records(), before);

    w.m[2].join(&inner, pos, &kp_c);
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
    let error = refused(&mut w.m[0], Change { cut, add: vec![package], how: Some(How::Invite), remove: vec![b], ..Change::default() });
    assert!(error.contains("adds a key it removes"), "{error}");
    assert!(w.m[0].g().posted().is_none());
}

/// A joiner refuses a group with a member whose credential names another key than its leaf's: that member could claim
/// the other key's messages.
#[test]
fn a_joiner_refuses_a_member_whose_credential_names_another_key() {
    let mut w = World::new(&["M", "B"]);
    w.m[0].session.credential.key = Bytes(w.m[1].session.key().to_vec());
    let package = w.key_package(1);
    let m = &mut w.m[0];
    m.group = Some(Group::create(&m.provider, &m.session, &settings("Plan")).unwrap());
    // Built as `Group::commit` builds it but past `rules`, which refuses M's own leaf, as a forger's client would not.
    let g = m.group.as_mut().unwrap();
    g.mls.set_aad(cut_aad(&g.state.cut));
    let bundle = g.mls.commit_builder().force_self_update(true).propose_adds(vec![key_package_in(&m.provider, &package).unwrap()]);
    let bundle = bundle.load_psks(m.provider.storage()).unwrap().build(m.provider.rand(), m.provider.crypto(), &m.session.signer, |_| true).unwrap();
    let (commit, welcome, _) = bundle.stage_commit(&m.provider).unwrap().into_messages();
    let entry = entry_of(&m.session.signer, commit.to_bytes().unwrap(), welcome.map(|welcome| welcome.to_bytes().unwrap()));
    assert!(join_error(&w.m[1], &entry, &package).contains("a member whose credential names another key"));
}

/// A live payload opens for the members of its epoch, from a current member, verified and unaltered; the members of
/// another epoch, and a member removed since, do not open it.
#[test]
fn live_payloads_open_only_in_their_epoch() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let edit = serde_json::json!({ "type": "edit", "text": "hi" });
    let wire = live(&w.m[0], &edit);
    assert_eq!(open_live(&w.m[1], &wire).unwrap(), (w.m[0].session.key().to_vec(), edit.clone()));
    let again = live(&w.m[0], &edit);
    let b = &w.m[1];
    let id = |wire: &[u8]| b.group.as_ref().unwrap().open_live(&b.provider, wire).unwrap().2;
    assert_ne!(id(&again), id(&wire), "the same payload sent again is another payload");
    let mut tampered = wire.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(open_live(&w.m[1], &tampered).is_err());

    let early = live(&w.m[2], &edit);
    let cut = w.m[1].cut();
    let commit = w.m[1].commit(Change { cut, ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    assert!(open_live(&w.m[0], &early).is_err(), "sealed in an earlier epoch");
    assert!(open_live(&w.m[0], &wire).is_err(), "sealed in an earlier epoch");

    let from_c = live(&w.m[2], &edit);
    let c = w.m[0].index_of("C");
    let cut = w.m[0].cut();
    let commit = w.m[0].commit(Change { cut, remove: vec![c], ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    assert!(open_live(&w.m[1], &from_c).is_err(), "from a member removed since");
    let current = live(&w.m[1], &edit);
    assert_eq!(open_live(&w.m[0], &current).unwrap().1, edit);
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

#[path = "group_epoch_tests.rs"]
mod epoch;
