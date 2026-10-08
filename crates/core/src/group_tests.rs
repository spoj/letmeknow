//! The spike/mls scenarios, on our API, plus the determinism rules.

use super::*;
use crate::provider::MemoryProvider;
use lmk_proto::group::{Kind, Named, Service};

pub(crate) fn settings(name: &str) -> Settings {
    Settings {
        protocol: PROTOCOL,
        kind: Kind::Chat,
        name: name.into(),
        open: vec![],
        keep: 90,
        membership: Service::Folder("/tmp/lmk".into()),
        devices_of: None,
        openings: vec![],
    }
}

pub(crate) fn leaf(name: &str) -> Leaf {
    Leaf { key: Bytes(name.as_bytes().to_vec()), relay: "https://relay.example/".into() }
}

pub(crate) struct Member<P: Provider = MemoryProvider> {
    pub provider: P,
    pub device: Device,
    pub session: Session,
    pub group: Option<Group>,
    /// Next log position to read (0-based here).
    pub pos: usize,
}

impl<P: Provider> Member<P> {
    pub fn new(provider: P, name: &str) -> Self {
        let device = Device::new(&format!("{name}'s laptop"));
        let session = Session::create(&provider, &device, name, None, leaf(name)).unwrap();
        Member { provider, device, session, group: None, pos: 0 }
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

    pub fn read(&mut self, log: &[Vec<u8>], now: u64) -> Vec<Applied> {
        let mut applied = Vec::new();
        while self.pos < log.len() {
            let group = self.group.as_mut().unwrap();
            applied.push(group.apply(&self.provider, &log[self.pos], now).unwrap());
            self.pos += 1;
        }
        applied
    }

    pub fn send(&mut self, text: &str) -> Vec<u8> {
        let group = self.group.as_mut().unwrap();
        group.seal(&self.provider, &self.session, &message(text)).unwrap().1
    }

    pub fn open(&mut self, bytes: &[u8], now: u64) -> Result<Opened> {
        let group = self.group.as_mut().unwrap();
        group.open(&self.provider, bytes, now)
    }

    pub fn index_of(&self, name: &str) -> u32 {
        let group = self.group.as_ref().unwrap();
        group.members().iter().find(|m| m.credential.as_ref().unwrap().name == name).unwrap().index
    }

    pub fn join(&mut self, welcome: &[u8], pos: usize) {
        self.group = Some(Group::join(&self.provider, welcome, Window::default()).unwrap());
        self.pos = pos;
    }
}

pub(crate) fn message(text: &str) -> Payload {
    Payload::Message {
        content: text.into(),
        after: vec![],
        to: vec![],
        reply_to: None,
        urgent: false,
        attachment: None,
    }
}

fn text(opened: &Opened) -> &str {
    let Payload::Message { content, .. } = &opened.payload else { panic!("not a message") };
    content
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

    fn read(&mut self, who: &[usize]) -> Vec<Vec<Applied>> {
        self.read_at(who, 0)
    }

    fn read_at(&mut self, who: &[usize], now: u64) -> Vec<Vec<Applied>> {
        who.iter().map(|&i| self.m[i].read(&self.log, now)).collect()
    }

    /// `creator` makes the group and adds `others` in one commit.
    fn found(&mut self, creator: usize, others: &[usize]) {
        let c = &mut self.m[creator];
        c.group = Some(Group::create(&c.provider, &c.session, &settings("Plan"), Window::default()).unwrap());
        let adds = others.iter().map(|&i| self.m[i].session.key_package(&self.m[i].provider).unwrap()).collect();
        let commit = self.m[creator].commit(Change { add: adds, ..Change::default() });
        let pos = self.post(commit.commit);
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

fn is_commit(applied: &Applied) -> bool {
    matches!(applied, Applied::Commit { .. })
}

#[test]
fn commit_race() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1, 2]);
    let e = w.m[0].g().epoch();
    let a = w.m[0].commit(Change::default());
    let kp_d = w.key_package(3);
    let b = w.m[1].commit(Change { add: vec![kp_d.clone()], ..Change::default() });
    assert!(w.m[0].g().pending() && w.m[1].g().pending());
    w.post(a.commit);
    w.post(b.commit);
    let applied = w.read(&[0, 1, 2]);
    assert!(matches!(applied[0][0], Applied::Commit { own: true, lost: false, .. }));
    assert!(matches!(applied[1][0], Applied::Commit { own: false, lost: true, .. }));
    assert!(matches!(applied[1][1], Applied::Skipped { lost: false, .. }));
    assert!(matches!(applied[2][1], Applied::Skipped { .. }));
    assert!(!w.m[1].g().pending() && w.m[1].g().epoch() == e + 1);
    w.agree(&[0, 1, 2]);

    let b2 = w.m[1].commit(Change { add: vec![kp_d], ..Change::default() });
    let pos = w.post(b2.commit);
    let applied = w.read(&[0, 1, 2]);
    let Applied::Commit { added, by, .. } = &applied[0][0] else { panic!() };
    assert_eq!((added[0].credential.as_ref().unwrap().name.as_str(), *by), ("D", w.m[1].g().own_index()));
    w.m[3].join(&b2.welcome.unwrap(), pos);
    w.agree(&[0, 1, 2, 3]);
    let added = w.m[0].g().added().last().unwrap().clone();
    assert_eq!((added.member.name.as_str(), added.by.name.as_str(), added.epoch), ("D", "B", e + 2));

    // A commit the log never took is cancelled, and the group carries on.
    let _unposted = w.m[2].commit(Change::default());
    w.m[2].cancel();
    let hi = w.m[2].send("still here");
    assert_eq!(text(&w.m[0].open(&hi, 0).unwrap()), "still here");
    w.agree(&[0, 1, 2, 3]);
}

#[test]
fn junk_is_skipped() {
    let mut w = World::new(&["A", "B", "C", "D", "X"]);
    w.found(0, &[1, 2, 3]);
    let old = w.m[1].commit(Change::default());
    let p_old = w.post(old.commit);
    w.read(&[0, 1, 2, 3]);
    w.post(b"\xde\xad\xbe\xef".to_vec());
    w.post(w.log[p_old - 1].clone());
    let app = w.m[3].send("hello");
    w.post(app);
    let x = &mut w.m[4];
    x.group = Some(Group::create(&x.provider, &x.session, &settings("other"), Window::default()).unwrap());
    let foreign = w.m[4].commit(Change::default());
    w.post(foreign.commit);
    // A removes C; C, not having read it, commits a key update and then a removal of A.
    let c = w.m[0].index_of("C");
    let remove_c = w.m[0].commit(Change { remove: vec![c], ..Change::default() });
    w.post(remove_c.commit);
    let c_update = w.m[2].commit(Change::default());
    w.post(c_update.commit);
    w.m[2].cancel();
    let a = w.m[2].index_of("A");
    let c_remove_a = w.m[2].commit(Change { remove: vec![a], ..Change::default() });
    w.post(c_remove_a.commit);
    let applied = w.read(&[0, 1, 3, 2]);
    for reader in &applied[..3] {
        let commits: Vec<bool> = reader.iter().map(is_commit).collect();
        assert_eq!(commits, [false, false, false, false, true, false, false]);
    }
    assert!(matches!(applied[3][4], Applied::Commit { gone: true, lost: true, .. }));
    assert!(!w.m[2].g().active());
    w.agree(&[0, 1, 3]);
    let hi = w.m[1].send("after the junk");
    assert_eq!(text(&w.m[0].open(&hi, 0).unwrap()), "after the junk");
    assert_eq!(text(&w.m[3].open(&hi, 0).unwrap()), "after the junk");
    let next = w.m[3].commit(Change::default());
    w.post(next.commit);
    w.read(&[0, 1, 3]);
    w.agree(&[0, 1, 3]);
}

#[test]
fn a_commit_never_applies_through_open() {
    let mut w = World::new(&["A", "B"]);
    w.found(0, &[1]);
    let commit = w.m[0].commit(Change::default());
    assert!(w.m[1].open(&commit.commit, 0).is_err());
    w.post(commit.commit);
    w.read(&[0, 1]);
    w.agree(&[0, 1]);
}

#[test]
fn past_epochs() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let e0 = w.m[0].g().epoch();
    let m1 = w.m[0].send("m1");
    let m2 = w.m[0].send("m2");
    let m3 = w.m[0].send("m3");
    for i in 0..60 {
        let commit = w.m[i % 3].commit(Change::default());
        w.post(commit.commit);
        w.read(&[0, 1, 2]);
    }
    w.agree(&[0, 1, 2]);
    for (bytes, expect) in [(&m1, "m1"), (&m3, "m3"), (&m2, "m2")] {
        let opened = w.m[1].open(bytes, 0).unwrap();
        assert_eq!((text(&opened), opened.epoch), (expect, e0));
        assert_eq!(opened.sender.name, "A");
        assert_eq!(opened.id, <[u8; 32]>::from(Sha256::digest(bytes)));
    }
    assert!(w.m[1].open(&m1, 0).is_err(), "a used key is gone");

    // Count cap: a smaller window drops older epochs at once.
    let c = &mut w.m[2];
    c.group.as_mut().unwrap().set_window(&c.provider, Window { epochs: 10, ..Window::default() }).unwrap();
    assert!(w.m[2].open(&m1, 0).is_err());

    // Age: epochs that began longer ago than the window are dropped.
    let late = w.m[0].send("late");
    let commit = w.m[0].commit(Change::default());
    w.post(commit.commit);
    w.read(&[0, 1, 2]);
    let b = &mut w.m[1];
    b.group.as_mut().unwrap().set_window(&b.provider, Window { age: Duration::ZERO, ..Window::default() }).unwrap();
    assert!(w.m[1].open(&late, 0).is_err());
    assert_eq!(text(&w.m[2].open(&late, 0).unwrap()), "late");

    // Out of order: up to 1000 per sender.
    let batch: Vec<_> = (1..=10).map(|i| w.m[0].send(&format!("n{i}"))).collect();
    assert_eq!(text(&w.m[1].open(&batch[9], 0).unwrap()), "n10");
    assert_eq!(text(&w.m[1].open(&batch[0], 0).unwrap()), "n1");
}

#[test]
fn settings_in_the_welcome() {
    let mut w = World::new(&["A", "B", "C", "D"]);
    w.found(0, &[1, 2]);
    let mut changed = w.m[0].g().settings();
    changed.name = "Plan v2".into();
    changed.keep = 30;
    changed.open.push(Named { id: Bytes(vec![1; 32]), name: "Alice".into() });
    changed.membership = Service::Folder("/elsewhere".into());
    let commit = w.m[0].commit(Change { settings: Some(changed.clone()), ..Change::default() });
    w.post(commit.commit);
    let applied = w.read(&[0, 1, 2]);
    assert!(matches!(applied[1][0], Applied::Commit { settings: true, .. }));
    assert_eq!(w.m[1].g().settings(), changed);
    assert_eq!(w.m[2].g().settings(), changed);
    assert!(w.m[2].g().mls.extensions().required_capabilities().is_some());

    let kp = w.key_package(3);
    let commit = w.m[2].commit(Change { add: vec![kp], ..Change::default() });
    let pos = w.post(commit.commit);
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
    let moved = Leaf { key: Bytes(b"B".to_vec()), relay: "https://relay2.example/".into() };
    let commit = w.m[1].commit(Change { leaf: Some(moved.clone()), ..Change::default() });
    w.post(commit.commit);
    w.read(&[0, 1, 2]);
    let b = w.m[2].index_of("B");
    for i in 0..3 {
        assert_eq!(w.m[i].g().members()[b as usize].leaf.as_ref(), Some(&moved));
    }
    let commit = w.m[1].commit(Change::default());
    w.post(commit.commit);
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

    // Our own API refuses to build a commit that breaks them.
    let mut bad = w.m[1].g().settings();
    bad.kind = Kind::Doc;
    let b = &mut w.m[1];
    let error = b.group.as_mut().unwrap().commit(
        &b.provider,
        &b.session,
        Change { settings: Some(bad.clone()), ..Change::default() },
    );
    assert!(error.err().unwrap().to_string().contains("kind"));
    assert!(!w.m[1].g().pending());

    // A kind change, built around it, and then a protocol change.
    for change in [|s: &mut Settings| s.kind = Kind::Doc, |s: &mut Settings| s.protocol = 2] {
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
        let bytes = bundle.into_messages().0.to_bytes().unwrap();
        group.state.posted = Some(Bytes(bytes.clone()));
        w.post(bytes);
        let applied = w.read(&[0, 1, 2]);
        assert!(matches!(&applied[1][0], Applied::Skipped { lost: true, .. }));
        assert!(applied.iter().all(|reader| !is_commit(&reader[0])));
        w.agree(&[0, 1, 2]);
    }

    // An update that changes the committer's device: C claims another device.
    let other = Device::new("someone else's");
    w.m[2].session.credential = other.credential("C", w.m[2].session.key(), None);
    let c = &mut w.m[2];
    let group = c.group.as_mut().unwrap();
    let mut leaf = LeafNodeParameters::builder().with_credential_with_key(c.session.with_key()).build();
    leaf = LeafNodeParameters::builder()
        .with_credential_with_key(leaf.credential_with_key().unwrap().clone())
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
    let bytes = bundle.into_messages().0.to_bytes().unwrap();
    group.state.posted = Some(Bytes(bytes.clone()));
    w.post(bytes);
    let applied = w.read(&[0, 1, 2]);
    assert!(matches!(&applied[2][0], Applied::Skipped { lost: true, reason } if reason.contains("device")));
    assert!(!is_commit(&applied[0][0]) && !is_commit(&applied[1][0]));
    w.agree(&[0, 1, 2]);

    // A proposal by reference: B proposes adding E to C alone, and C commits it by reference.
    let kp = key_package_in(&w.m[3].provider, &w.key_package(3)).unwrap();
    let b = &mut w.m[1];
    let (proposal, _) = b.group.as_mut().unwrap().mls.propose_add_member(&b.provider, &b.session.signer, &kp).unwrap();
    let proposal = proposal.to_bytes().unwrap();
    let c = &mut w.m[2];
    let group = c.group.as_mut().unwrap();
    let message = parse::<MlsMessageIn>(&proposal).unwrap().try_into_protocol_message().unwrap();
    let ProcessedMessageContent::ProposalMessage(queued) =
        group.mls.process_message(&c.provider, message).unwrap().into_content()
    else {
        panic!()
    };
    group.mls.store_pending_proposal(c.provider.storage(), *queued).unwrap();
    let (commit, _, _) = group.mls.commit_to_pending_proposals(&c.provider, &c.session.signer).unwrap();
    let commit = commit.to_bytes().unwrap();
    group.state.posted = Some(Bytes(commit.clone()));
    w.post(proposal);
    w.post(commit);
    let applied = w.read(&[0, 1, 2]);
    assert!(applied.iter().all(|reader| reader.iter().all(|a| !is_commit(a))));
    assert!(matches!(&applied[2][1], Applied::Skipped { lost: true, reason } if reason.contains("reference")));
    w.agree(&[0, 1, 2]);
}

#[test]
fn credentials_are_checked_not_enforced() {
    use crate::identity::{DeviceList, Verdict, check, create};
    let mut w = World::new(&["A", "M"]);
    let (id, first) = create(&w.m[0].device, "Alice", Service::Folder("/tmp/lmk".into()));
    let list = DeviceList::replay(&id, [first.as_slice()]).unwrap();
    let identity = IdentityRef { id: id.into(), membership: Service::Folder("/tmp/lmk".into()) };
    let a = &mut w.m[0];
    a.session = Session::create(&a.provider, &a.device, "A", Some(identity.clone()), leaf("A")).unwrap();
    // M claims Alice's identity from a device not on her list.
    let m = &mut w.m[1];
    m.session = Session::create(&m.provider, &m.device, "M", Some(identity), leaf("M")).unwrap();
    let (credential, key) = key_package_credential(&w.m[0].provider, &w.key_package(1)).unwrap();
    assert_eq!(check(&credential, &key, Some(&list)), Verdict::NotListed);
    w.found(0, &[1]);
    w.agree(&[0, 1]);
    let verdicts: Vec<_> = w.m[1]
        .g()
        .members()
        .iter()
        .map(|member| check(member.credential.as_ref().unwrap(), &member.key, Some(&list)))
        .collect();
    assert_eq!(verdicts, [Verdict::Verified, Verdict::NotListed]);
    let hi = w.m[1].send("hi from M");
    let opened = w.m[0].open(&hi, 0).unwrap();
    let sender = &w.m[0].g().members()[opened.current.unwrap() as usize];
    assert_eq!(check(&opened.sender, &sender.key, Some(&list)), Verdict::NotListed);
}

#[test]
fn leave_and_removed_senders() {
    let mut w = World::new(&["A", "B", "C"]);
    w.found(0, &[1, 2]);
    let early = w.m[2].send("before my removal");
    let later = w.m[2].send("also before");
    let c = &mut w.m[2];
    let (_, leave) = c.group.as_mut().unwrap().leave(&c.provider, &c.session).unwrap();
    let opened = w.m[1].open(&leave, 0).unwrap();
    assert_eq!(opened.payload, Payload::Leave);
    let commit = w.m[1].commit(Change { remove: vec![opened.current.unwrap()], ..Change::default() });
    w.post(commit.commit);
    let applied = w.read_at(&[0, 1, 2], 1_000);
    let Applied::Commit { removed, .. } = &applied[0][0] else { panic!() };
    assert_eq!(removed[0].credential.as_ref().unwrap().name, "C");
    assert!(!w.m[2].g().active());
    w.agree(&[0, 1]);
    let opened = w.m[0].open(&early, 1_000 + REMOVED_GRACE).unwrap();
    assert_eq!((opened.current, text(&opened)), (None, "before my removal"));
    assert!(w.m[0].open(&later, 1_001 + REMOVED_GRACE).is_err());
}

#[test]
fn another_protocol_is_refused_at_join() {
    let mut w = World::new(&["A", "B"]);
    let a = &mut w.m[0];
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan"), Window::default()).unwrap());
    let mut future = w.m[0].g().settings();
    future.protocol = 2;
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
    let error = Group::join(&w.m[1].provider, &welcome, Window::default()).err().unwrap();
    assert!(error.to_string().contains("protocol 2"), "{error}");
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
    a.group = Some(Group::create(&a.provider, &a.session, &settings("Plan"), Window::default()).unwrap());
    let commit = a.commit(Change { add: vec![b.session.key_package(&b.provider).unwrap()], ..Change::default() });
    log.push(commit.commit);
    a.read(&log, 0);
    let id = a.g().id().to_vec();
    let mut b = Member { pos: 1, ..b };
    b.join(commit.welcome.as_ref().unwrap(), 1);
    // B commits, then restarts before reading the log.
    let pending = b.commit(Change::default());
    log.push(pending.commit);
    drop(b);
    let provider = SqliteProvider::open(&dir.join("b.db")).unwrap();
    let session = Session::load(&provider).unwrap();
    let group = Group::load(&provider, &id).unwrap();
    assert!(group.pending());
    let mut b = Member { device: Device::new("unused"), provider, session, group: Some(group), pos: 1 };
    assert!(matches!(b.read(&log, 0)[0], Applied::Commit { own: true, .. }));
    a.read(&log, 0);
    assert_eq!(a.g().epoch_authenticator(), b.g().epoch_authenticator());
    let hi = b.send("after a restart");
    assert_eq!(text(&a.open(&hi, 0).unwrap()), "after a restart");
    std::fs::remove_dir_all(dir).unwrap();
}
