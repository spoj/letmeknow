//! Groups on our API, and the openmls behaviour the group log relies on: storage that commits and rolls back with our
//! records, forged messages that leave no trace, commits from one's own leaf, entry MACs, and two epochs of keys.

use super::*;
use crate::provider::MemoryProvider;
use lmk_proto::group::{CHAT, ChatMessage, Control, Named, REVISION, Service};

pub(crate) fn settings(name: &str) -> Settings {
    Settings {
        protocol: PROTOCOL,
        kind: CHAT.into(),
        name: name.into(),
        open: vec![],
        carry: 7,
        membership: Service::Folder("/tmp/lmk".into()),
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
}

impl<P: Provider> Member<P> {
    pub fn new(provider: P, name: &str) -> Self {
        let session = Session::create(&provider, name, leaf(name)).unwrap();
        Member { provider, session, group: None, pos: 0 }
    }

    pub fn g(&mut self) -> &mut Group {
        self.group.as_mut().unwrap()
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

    pub fn send(&mut self, text: &str) -> Vec<u8> {
        let group = self.group.as_mut().unwrap();
        group.seal(&self.provider, &self.session, &message(text), false).unwrap().1
    }

    pub fn open(&mut self, bytes: &[u8]) -> Result<Opened> {
        let group = self.group.as_mut().unwrap();
        group.open(&self.provider, bytes)
    }

    /// The log entry of a message this member sealed in its current epoch.
    pub fn entry(&mut self, bytes: &[u8]) -> Vec<u8> {
        let group = self.group.as_ref().unwrap();
        group.entry(&self.provider, &Sha256::digest(bytes).into()).unwrap()
    }

    pub fn index_of(&self, name: &str) -> u32 {
        let group = self.group.as_ref().unwrap();
        group.members().iter().find(|m| m.credential.as_ref().unwrap().name == name).unwrap().index
    }

    pub fn join(&mut self, welcome: &[u8], pos: usize) {
        self.group = Some(Group::join(&self.provider, welcome).unwrap());
        self.pos = pos;
    }
}

impl Member<MemoryProvider> {
    /// A copy of this member, its storage and all, as a stolen or restored device holds it.
    fn copy(&self) -> Self {
        let provider = MemoryProvider::load(self.provider.records());
        let session = Session::load(&provider).unwrap();
        let group = self.group.as_ref().map(|group| Group::load(&provider, group.id()).unwrap());
        Member { provider, session, group, pos: self.pos }
    }
}

pub(crate) fn message(text: &str) -> serde_json::Value {
    let message = ChatMessage { content: text.into(), after: vec![], to: vec![], reply_to: None, urgent: false, attachment: None };
    serde_json::to_value(message).unwrap()
}

fn text(opened: &Opened) -> &str {
    opened.payload["content"].as_str().expect("a message")
}

/// A commit's entry, signed by `signer`.
fn entry_of(signer: &SignatureKeyPair, commit: Vec<u8>, welcome: Option<Vec<u8>>) -> Vec<u8> {
    let sig = signer.sign(&signed(&commit, welcome.as_deref())).unwrap();
    Entry::Commit { commit, welcome, sig }.encode()
}

/// A signature key no member holds.
fn stranger() -> SignatureKeyPair {
    let key = ed25519_dalek::SigningKey::from_bytes(&crate::random());
    SignatureKeyPair::from_raw(SignatureScheme::ED25519, key.to_bytes().to_vec(), key.verifying_key().to_bytes().to_vec())
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

    fn read(&mut self, who: &[usize]) -> Vec<Vec<Read>> {
        who.iter().map(|&i| self.m[i].read(&self.log)).collect()
    }

    /// `creator` makes the group and adds `others` in one commit.
    fn found(&mut self, creator: usize, others: &[usize]) {
        let c = &mut self.m[creator];
        c.group = Some(Group::create(&c.provider, &c.session, &settings("Plan")).unwrap());
        let adds = others.iter().map(|&i| self.m[i].session.key_package(&self.m[i].provider).unwrap()).collect();
        let commit = self.m[creator].commit(Change { add: adds, how: Some(How::Invite), ..Change::default() });
        let pos = self.post(commit.entry);
        self.read(&[creator]);
        for &i in others {
            self.m[i].join(commit.welcome.as_ref().unwrap(), pos);
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
    let a = w.m[0].commit(Change::default());
    let kp_d = w.key_package(3);
    let b = w.m[1].commit(Change { add: vec![kp_d.clone()], how: Some(How::Invite), ..Change::default() });
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

    let b2 = w.m[1].commit(Change { add: vec![kp_d], how: Some(How::Invite), ..Change::default() });
    let pos = w.post(b2.entry);
    let read = w.read(&[0, 1, 2]);
    let Applied { added, by, .. } = applied(&read[0][0]);
    assert_eq!((added[0].credential.as_ref().unwrap().name.as_str(), *by), ("D", w.m[1].g().own_index()));
    w.m[3].join(&b2.welcome.unwrap(), pos);
    w.agree(&[0, 1, 2, 3]);
    let added = w.m[0].g().added().last().unwrap().clone();
    assert_eq!((added.member.name.as_str(), added.by.name.as_str(), added.epoch), ("D", "B", e + 2));

    // A commit the log never took is cancelled, and the group carries on.
    let _unposted = w.m[2].commit(Change::default());
    w.m[2].cancel();
    let hi = w.m[2].send("still here");
    assert_eq!(text(&w.m[0].open(&hi).unwrap()), "still here");
    w.agree(&[0, 1, 2, 3]);
}

#[test]
fn junk_is_skipped() {
    let mut w = World::new(&["A", "B", "C", "D", "X"]);
    w.found(0, &[1, 2, 3]);
    let old = w.m[1].commit(Change::default());
    let p_old = w.post(old.entry);
    w.read(&[0, 1, 2, 3]);
    w.post(b"\xde\xad\xbe\xef".to_vec());
    w.post(w.log[p_old - 1].clone());
    let app = w.m[3].send("hello");
    w.post(Entry::Commit { commit: app, welcome: None, sig: vec![0; 64] }.encode());
    let x = &mut w.m[4];
    x.group = Some(Group::create(&x.provider, &x.session, &settings("other")).unwrap());
    let foreign = w.m[4].commit(Change::default());
    w.post(foreign.entry);
    // A removes C; C, not having read it, commits a key update and then a removal of A.
    let c = w.m[0].index_of("C");
    let remove_c = w.m[0].commit(Change { remove: vec![c], ..Change::default() });
    w.post(remove_c.entry);
    let c_update = w.m[2].commit(Change::default());
    w.post(c_update.entry);
    w.m[2].cancel();
    let a = w.m[2].index_of("A");
    let c_remove_a = w.m[2].commit(Change { remove: vec![a], ..Change::default() });
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
    let next = w.m[3].commit(Change::default());
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
    let commit = w.m[1].commit(Change { add: vec![kp], how: Some(How::Invite), ..Change::default() });
    let Entry::Commit { commit: bytes, welcome, sig } = Entry::parse(&commit.entry).unwrap() else { panic!() };
    // Signed by a stranger, or carrying another Welcome than the committer signed.
    w.post(entry_of(&stranger(), bytes.clone(), welcome));
    w.post(Entry::Commit { commit: bytes, welcome: Some(b"another welcome".to_vec()), sig }.encode());
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
    let commit = w.m[0].commit(Change::default());
    let Entry::Commit { commit: bytes, .. } = Entry::parse(&commit.entry).unwrap() else { panic!() };
    assert!(w.m[1].open(&bytes).is_err());
    w.post(commit.entry);
    w.read(&[0, 1]);
    w.agree(&[0, 1]);
}

/// Proof: a message entry counts under the epoch current when it is read, judged strictly in log order, one's own
/// commits included; its MAC is the epoch's `MLS-Exporter("letmeknow entry", "", 32)` over the id.
#[test]
fn a_message_entry_counts_in_the_epoch_it_is_read_in() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let hi = w.m[1].send("hi");
    let entry = w.m[1].entry(&hi);
    let id: [u8; 32] = Sha256::digest(&hi).into();
    let c = &w.m[2];
    let exported = c.group.as_ref().unwrap().mls.export_secret(c.provider.crypto(), "letmeknow entry", &[], 32).unwrap();
    let mac = c.provider.crypto().hmac(HashType::Sha2_256, &exported, &id).unwrap();
    assert_eq!(entry, [&[2], &id[..], mac.as_slice()].concat());
    w.post(entry.clone());
    // A's own commit comes next in the log: the same entry again, after it, is under another epoch.
    let commit = w.m[0].commit(Change::default());
    w.post(commit.entry);
    w.post(entry.clone());
    let read = w.read(&[0, 1, 2]);
    for reader in &read {
        assert_eq!(reader[0].0, Verdict::Message { id });
        assert!(is_commit(&reader[1]));
        assert!(matches!(&reader[2].0, Verdict::Skipped { reason, .. } if reason.contains("MAC")));
    }
    // A forged MAC, and a non-member's, never count.
    w.post(Entry::Message { id, mac: [0; 32] }.encode());
    assert!(w.read(&[0, 1, 2]).iter().all(|reader| matches!(reader[0].0, Verdict::Skipped { .. })));
    // A message sealed in the new epoch counts in it.
    let later = w.m[2].send("later");
    let entry = w.m[2].entry(&later);
    w.post(entry);
    assert!(w.read(&[0, 1, 2]).iter().all(|reader| matches!(reader[0].0, Verdict::Message { .. })));
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
    let commit = w.m[1].commit(Change::default());
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    let opened = w.m[1].open(&m1).unwrap();
    assert_eq!((text(&opened), opened.epoch), ("m1", e0));
    assert_eq!(opened.id, <[u8; 32]>::from(Sha256::digest(&m1)));
    assert!(w.m[1].open(&m1).is_err(), "a used key is gone");
    let commit = w.m[1].commit(Change::default());
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
    let commit = a.commit(Change { add: vec![kp], how: Some(How::Invite), ..Change::default() });
    let log = vec![commit.entry];
    a.read(&log);
    b.join(commit.welcome.as_ref().unwrap(), 1);
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
    let commit = a.commit(Change { add: vec![b.session.key_package(&b.provider).unwrap()], how: Some(How::Invite), ..Change::default() });
    let log = vec![commit.entry];
    a.read(&log);
    b.join(commit.welcome.as_ref().unwrap(), 1);
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
    let mut a = Member { provider, session, group: Some(group), pos: 1 };
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
    let junk = copy.commit(Change::default());
    let Entry::Commit { commit, welcome, .. } = Entry::parse(&junk.entry).unwrap() else { panic!() };
    w.post(entry_of(&stranger(), commit, welcome));
    copy.cancel();
    let copied = copy.commit(Change::default());
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
    let own = w.m[0].commit(Change::default());
    let copied = copy.commit(Change::default());
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
    let commit = w.m[0].commit(Change { settings: Some(newer), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1]);
    let renamed = Settings { name: "Release".into(), ..w.m[1].g().settings() };
    let commit = w.m[1].commit(Change { settings: Some(renamed), ..Change::default() });
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
    changed.open.push(Named { id: Bytes(vec![1; 32]), name: "Alice".into(), rest: Default::default() });
    changed.membership = Service::Folder("/elsewhere".into());
    let commit = w.m[0].commit(Change { settings: Some(changed.clone()), ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2]);
    assert!(applied(&read[1][0]).settings);
    assert_eq!(w.m[1].g().settings(), changed);
    assert_eq!(w.m[2].g().settings(), changed);
    assert!(w.m[2].g().mls.extensions().required_capabilities().is_some());

    let kp = w.key_package(3);
    let commit = w.m[2].commit(Change { add: vec![kp], how: Some(How::Invite), ..Change::default() });
    let pos = w.post(commit.entry);
    w.read(&[0, 1, 2]);
    w.m[3].join(&commit.welcome.unwrap(), pos);
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
    let commit = w.m[1].commit(Change { leaf: Some(moved.clone()), ..Change::default() });
    w.post(commit.entry);
    w.read(&[0, 1, 2]);
    let b = w.m[2].index_of("B");
    for i in 0..3 {
        assert_eq!(w.m[i].g().members()[b as usize].leaf.as_ref(), Some(&moved));
    }
    let commit = w.m[1].commit(Change::default());
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
    let commit = w.m[1].commit(Change { name: Some("Bee".into()), ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2]);
    assert!(read.iter().all(|reader| is_commit(&reader[0])));
    w.agree(&[0, 1, 2]);
    let b = w.m[0].index_of("Bee");
    assert_eq!(w.m[2].g().members()[b as usize].leaf.as_ref(), Some(&leaf("B")), "the leaf data stays");
    let opened = w.m[2].open(&before).unwrap();
    assert_eq!((opened.sender.name.as_str(), opened.current), ("B", Some(b)));
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
    let b = &mut w.m[1];
    let error = b.group.as_mut().unwrap().commit(&b.provider, &b.session, Change { settings: Some(bad.clone()), ..Change::default() });
    assert!(error.err().unwrap().to_string().contains("kind"));
    assert!(w.m[1].g().posted().is_none());

    // A kind change, built around it, and then a protocol change.
    for change in [|s: &mut Settings| s.kind = "doc".into(), |s: &mut Settings| s.protocol = PROTOCOL + 1] {
        let mut bad = w.m[1].g().settings();
        change(&mut bad);
        let b = &mut w.m[1];
        let group = b.group.as_mut().unwrap();
        let bundle = group
            .mls
            .commit_builder()
            .consume_proposal_store(false)
            .force_self_update(true)
            .propose_group_context_extensions(context_extensions(&bad).unwrap())
            .unwrap()
            .load_psks(b.provider.storage())
            .unwrap()
            .build(b.provider.rand(), b.provider.crypto(), &b.session.signer, |_| true)
            .unwrap()
            .stage_commit(&b.provider)
            .unwrap();
        let entry = entry_of(&b.session.signer, bundle.into_messages().0.to_bytes().unwrap(), None);
        group.state.posted = Some(Bytes(entry.clone()));
        w.post(entry);
        let read = w.read(&[0, 1, 2]);
        assert!(matches!(&read[1][0].0, Verdict::Skipped { lost: true, .. }));
        assert!(read.iter().all(|reader| !is_commit(&reader[0])));
        w.agree(&[0, 1, 2]);
    }

    // An update that changes the committer's credential beyond its name: C claims an identity.
    let identity = lmk_proto::group::IdentityRef { id: Bytes(vec![1; 32]), membership: Service::Folder("/tmp/lmk".into()) };
    w.m[2].session.credential.identity = Some(identity);
    let c = &mut w.m[2];
    let group = c.group.as_mut().unwrap();
    let leaf = LeafNodeParameters::builder()
        .with_credential_with_key(c.session.with_key())
        .with_extensions(leaf_extensions(&c.session.leaf).unwrap())
        .build();
    let bundle = group
        .mls
        .commit_builder()
        .consume_proposal_store(false)
        .force_self_update(true)
        .leaf_node_parameters(leaf)
        .load_psks(c.provider.storage())
        .unwrap()
        .build(c.provider.rand(), c.provider.crypto(), &c.session.signer, |_| true)
        .unwrap()
        .stage_commit(&c.provider)
        .unwrap();
    let entry = entry_of(&c.session.signer, bundle.into_messages().0.to_bytes().unwrap(), None);
    group.state.posted = Some(Bytes(entry.clone()));
    w.post(entry);
    let read = w.read(&[0, 1, 2]);
    assert!(matches!(&read[2][0].0, Verdict::Skipped { lost: true, reason } if reason.contains("credential")));
    assert!(!is_commit(&read[0][0]) && !is_commit(&read[1][0]));
    w.agree(&[0, 1, 2]);

    // A proposal by reference: B proposes adding E to C alone, and C commits it by reference.
    let kp = key_package_in(&w.m[3].provider, &w.key_package(3)).unwrap();
    let b = &mut w.m[1];
    let (proposal, _) = b.group.as_mut().unwrap().mls.propose_add_member(&b.provider, &b.session.signer, &kp).unwrap();
    let proposal = proposal.to_bytes().unwrap();
    let c = &mut w.m[2];
    let group = c.group.as_mut().unwrap();
    let message = parse::<MlsMessageIn>(&proposal).unwrap().try_into_protocol_message().unwrap();
    let ProcessedMessageContent::ProposalMessage(queued) = group.mls.process_message(&c.provider, message).unwrap().into_content() else {
        panic!()
    };
    group.mls.store_pending_proposal(c.provider.storage(), *queued).unwrap();
    let (commit, _, _) = group.mls.commit_to_pending_proposals(&c.provider, &c.session.signer).unwrap();
    let entry = entry_of(&c.session.signer, commit.to_bytes().unwrap(), None);
    group.state.posted = Some(Bytes(entry.clone()));
    w.post(entry_of(&w.m[1].session.signer, proposal, None));
    w.post(entry);
    let read = w.read(&[0, 1, 2]);
    assert!(read.iter().all(|reader| reader.iter().all(|a| !is_commit(a))));
    assert!(matches!(&read[2][1].0, Verdict::Skipped { lost: true, reason } if reason.contains("reference")));
    w.agree(&[0, 1, 2]);
}

#[test]
fn credentials_are_checked_not_enforced() {
    use crate::identity::{DAY, KeyLog, certify, check, create};
    use lmk_proto::group::IdentityRef;
    use lmk_proto::identity::Certified;
    let mut w = World::new(&["A", "M"]);
    let seed = crate::random();
    let (id, first) = create(&seed, "Alice", Service::Folder("/tmp/lmk".into()));
    let log = KeyLog::replay(&id, [first.as_slice()]).unwrap();
    let identity = IdentityRef { id: id.into(), membership: Service::Folder("/tmp/lmk".into()) };
    // A speaks as Alice, with a certificate; M claims her identity without one.
    w.m[0].session.credential.identity = Some(identity.clone());
    w.m[1].session.credential.identity = Some(identity);
    let a = &w.m[0].session.credential;
    let certified = Certified { identity: id.into(), key: a.key.clone(), name: a.name.clone(), device: "laptop".into(), device_key: None, added_by: None, expires: DAY };
    let certificate = certify(&seed, &certified);
    let m = key_package_credential(&w.m[0].provider, &w.key_package(1)).unwrap();
    assert!(check(Some(&certificate), &m, &log, 0).is_err());
    w.found(0, &[1]);
    w.agree(&[0, 1]);
    let checked: Vec<bool> =
        w.m[1].g().members().iter().map(|member| check(Some(&certificate), member.credential.as_ref().unwrap(), &log, 0).is_ok()).collect();
    assert_eq!(checked, [true, false]);
    let hi = w.m[1].send("hi from M");
    let opened = w.m[0].open(&hi).unwrap();
    assert_eq!((opened.sender.key.0, opened.sender.name), (w.m[1].session.key().to_vec(), "M".to_owned()));
}

/// A removed member's messages sealed before its removal still open, while the keys of their epoch are kept.
#[test]
fn leave_and_removed_senders() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let early = w.m[2].send("before my removal");
    let c = &mut w.m[2];
    let (_, leave) = c.group.as_mut().unwrap().leave(&c.provider, &c.session).unwrap();
    let opened = w.m[1].open(&leave).unwrap();
    assert_eq!((opened.payload.clone(), opened.live), (serde_json::to_value(Control::Leave).unwrap(), false));
    let commit = w.m[1].commit(Change { remove: vec![opened.current.unwrap()], ..Change::default() });
    w.post(commit.entry);
    let read = w.read(&[0, 1, 2]);
    assert_eq!(applied(&read[0][0]).removed[0].credential.as_ref().unwrap().name, "C");
    assert!(matches!(read[2][0].0, Verdict::Commit { removes: true }));
    assert!(!w.m[2].g().active());
    w.agree(&[0, 1]);
    let opened = w.m[0].open(&early).unwrap();
    assert_eq!((opened.current, text(&opened)), (None, "before my removal"));
}

#[test]
fn another_protocol_is_refused_at_join() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan")).unwrap());
    let mut future = w.m[0].g().settings();
    future.protocol = PROTOCOL + 1;
    let kp = key_package_in(&w.m[1].provider, &w.key_package(1)).unwrap();
    let a = &mut w.m[0];
    let group = a.group.as_mut().unwrap();
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
    let welcome = bundle.into_messages().1.unwrap().to_bytes().unwrap();
    group.mls.merge_pending_commit(&a.provider).unwrap();
    let error = Group::join(&w.m[1].provider, &welcome).err().unwrap();
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
    let commit = a.commit(Change { add: vec![b.session.key_package(&b.provider).unwrap()], how: Some(How::Invite), ..Change::default() });
    log.push(commit.entry);
    a.read(&log);
    let id = a.g().id().to_vec();
    let mut b = Member { pos: 1, ..b };
    b.join(commit.welcome.as_ref().unwrap(), 1);
    // B commits, then restarts before reading the log.
    let pending = b.commit(Change::default());
    log.push(pending.entry);
    drop(b);
    let provider = SqliteProvider::open(&dir.join("b.db")).unwrap();
    let session = Session::load(&provider).unwrap();
    let group = Group::load(&provider, &id).unwrap();
    assert!(group.posted().is_some());
    let mut b = Member { provider, session, group: Some(group), pos: 1 };
    assert!(applied(&b.read(&log)[0]).own);
    a.read(&log);
    assert_eq!(a.g().epoch_authenticator(), b.g().epoch_authenticator());
    let hi = b.send("after a restart");
    assert_eq!(text(&a.open(&hi).unwrap()), "after a restart");
    // Windows cannot delete a database that is still open.
    drop((a, b));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_live_payload_is_marked_so_in_the_clear() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let a = &mut w.m[0];
    let epoch = a.g().epoch();
    let edit = serde_json::json!({ "type": "edit" });
    let group = a.group.as_mut().unwrap();
    let (_, live) = group.seal(&a.provider, &a.session, &edit, true).unwrap();
    let (_, held) = group.seal(&a.provider, &a.session, &message("hi"), false).unwrap();
    assert_eq!((header(&live).unwrap(), header(&held).unwrap()), ((epoch, true), (epoch, false)));
    let live: Vec<bool> = [live, held].iter().map(|c| w.m[1].open(c).unwrap().live).collect();
    assert_eq!(live, [true, false]);
}

#[test]
fn a_payload_that_could_seal_over_the_limit_is_refused() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let a = &mut w.m[0];
    let push = |pad: usize| serde_json::json!({ "type": "push", "pad": "x".repeat(pad) });
    let largest = MAX_MESSAGE - FRAMING - serde_json::to_vec(&push(0)).unwrap().len();
    let group = a.group.as_mut().unwrap();
    let error = group.seal(&a.provider, &a.session, &push(largest + 1), false).unwrap_err();
    assert_eq!(error.to_string(), format!("the message is {} bytes, over the 1 MiB members take", MAX_MESSAGE + 1));
    let (_, sealed) = group.seal(&a.provider, &a.session, &push(largest), false).unwrap();
    assert!(sealed.len() <= MAX_MESSAGE);
    assert!(!w.m[1].open(&sealed).unwrap().live);
}
