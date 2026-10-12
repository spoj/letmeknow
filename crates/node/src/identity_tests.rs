use super::*;
use crate::Config;
use lmk_core::provider::MemoryProvider;
use lmk_core::public::{PublicLog, Verdict};
use lmk_membership::store::Store;
use lmk_proto::frame::{self, ALPN, Open};
use lmk_proto::group::{CHAT, Credential};
use lmk_proto::head::reference;
use lmk_proto::membership::{Latest, Page, Reply, Request};
use lmk_testing::{Relay, relay};
use tokio::sync::Notify;
use tokio::time::{Duration, timeout};

const WAIT: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct ReadGate {
    peer: iroh::EndpointId,
    log: [u8; 32],
    remaining: usize,
    reached: Arc<Notify>,
    release: Arc<Notify>,
}

struct Authority {
    store: Store,
    gate: Mutex<Option<ReadGate>>,
    stale: Mutex<Option<(iroh::EndpointId, [u8; 32], Page)>>,
}

impl Authority {
    fn log(&self, capability: &[u8; 32]) -> [u8; 32] {
        reference(&self.store.key().verifying_key().to_bytes(), capability)
    }

    fn read(&self, log: &[u8]) -> Page {
        self.store.read(log.try_into().unwrap(), 0).unwrap()
    }
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Authority") }
}

impl iroh::protocol::ProtocolHandler for Authority {
    async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), iroh::protocol::AcceptError> {
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let _: Open = frame::read(&mut recv).await.unwrap();
            let request: Request = frame::read(&mut recv).await.unwrap();
            let answer = match request {
                Request::Read { capability, after } => {
                    let log = self.log(&capability);
                    let gate = {
                        let mut gate = self.gate.lock().unwrap();
                        match gate.as_mut() {
                            Some(g) if g.peer == connection.remote_id() && g.log == log => {
                                g.remaining -= 1;
                                if g.remaining == 0 { gate.take() } else { None }
                            }
                            _ => None,
                        }
                    };
                    if let Some(gate) = gate {
                        gate.reached.notify_one();
                        gate.release.notified().await;
                    }
                    let stale = self.stale.lock().unwrap().clone();
                    let page = match stale {
                        Some((peer, id, page)) if peer == connection.remote_id() && id == log => {
                            assert!(after <= page.head.length);
                            Page { after, entries: page.entries.into_iter().skip(after as usize).collect(), head: page.head }
                        }
                        _ => self.store.read(&log, after).unwrap(),
                    };
                    serde_json::to_value(Reply::Ok(page)).unwrap()
                }
                Request::Append { capability, entries, public } => serde_json::to_value(Reply::Ok(self.store.append(&self.log(&capability), &entries, public).unwrap())).unwrap(),
                Request::Head { capability } => serde_json::to_value(Reply::Ok(Latest { head: self.store.head(&self.log(&capability)).unwrap() })).unwrap(),
                // No subscription delivery: the test controls when each node reads and applies history.
                Request::Subscribe { .. } => continue,
            };
            frame::write(&mut send, &answer).await.unwrap();
            send.finish().unwrap();
        }
        Ok(())
    }
}

async fn device(relay: &Relay, name: &str) -> (Node<MemoryProvider>, Identity<MemoryProvider>) {
    let device = Device::new(name);
    let config = Config {
        handle: name.into(), device: Some(device.clone()), relay: relay.url.clone(), ca: relay.ca(),
        home: None, files: None, disk: None, file_limit: 0, kinds: vec![CHAT.into(), IDENTITY.into()], durable: None,
    };
    let (node, _events) = Node::start(MemoryProvider::default(), config).await.unwrap();
    let identity = Identity::new(node.clone(), device, Arc::new(|_| Ok(())));
    (node, identity)
}

struct Race {
    relay: Relay,
    authority: Arc<Authority>,
    router: iroh::protocol::Router,
    a: Node<MemoryProvider>,
    a_identity: Identity<MemoryProvider>,
    c: Node<MemoryProvider>,
    c_identity: Identity<MemoryProvider>,
    b: Node<MemoryProvider>,
    b_identity: Identity<MemoryProvider>,
    identity: IdentityRef,
    gid: Bytes,
}

impl Race {
    async fn new(with_b: bool) -> Self {
        let relay = relay().await;
        let store = Store::initialize(&std::env::temp_dir().join(format!("lmk-identity-{:x}", u128::from_le_bytes(lmk_core::random())))).unwrap();
        let endpoint = relay.endpoint(iroh::SecretKey::from_bytes(&store.key().to_bytes())).await;
        let membership = Service::Serve { key: Bytes(endpoint.id().as_bytes().to_vec()), relay: relay.url.to_string(), addrs: vec![], rest: Default::default() };
        let authority = Arc::new(Authority { store, gate: Mutex::default(), stale: Mutex::default() });
        let router = iroh::protocol::Router::builder(endpoint).accept(ALPN, authority.clone()).spawn();
        let (a, a_identity) = device(&relay, "A").await;
        let (c, c_identity) = device(&relay, "C").await;
        let (b, b_identity) = device(&relay, "B").await;
        let identity = a_identity.create("Identity", membership).await.unwrap();
        let gid = a_identity.group().unwrap();
        c_identity.join(&Invite::parse(&a_identity.invite().await.unwrap()).unwrap()).await.unwrap();
        a_identity.duties(&gid.0).await.unwrap();
        if with_b {
            b_identity.join(&Invite::parse(&c_identity.invite().await.unwrap()).unwrap()).await.unwrap();
            c_identity.duties(&gid.0).await.unwrap();
        }
        a.inner.caught_up(&gid.0).await.unwrap();
        a.read_public(&identity).await.unwrap();
        // Keep A's service client, but no peer pump, follow, polling or automatic duties can apply C's later commit.
        let mut tasks: Vec<_> = a.inner.tasks.lock().unwrap().drain(..).collect();
        tasks.extend(a.inner.follows.lock().unwrap().drain().map(|(_, task)| task));
        for task in &tasks { task.abort(); }
        for task in tasks { let _ = task.await; }
        Self { relay, authority, router, a, a_identity, c, c_identity, b, b_identity, identity, gid }
    }

    fn gate(&self, log: [u8; 32], remaining: usize) -> (Arc<Notify>, Arc<Notify>) {
        let (reached, release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        *self.authority.gate.lock().unwrap() = Some(ReadGate { peer: self.a.net().id(), log, remaining, reached: reached.clone(), release: release.clone() });
        (reached, release)
    }

    async fn close(self) {
        for node in [&self.a, &self.b, &self.c] { node.shutdown().await.unwrap(); }
        self.router.shutdown().await.unwrap();
    }
}

async fn captured_roster_race(remove: bool, leave: bool) {
    let r = Race::new(remove).await;
    let address = r.authority.log(&lmk_proto::public::address(&r.identity.id.0));
    let old_epoch = r.a.epoch(&r.gid.0).unwrap();
    let (reached, release) = r.gate(address, 2);
    let (a, gid) = (r.a_identity.clone(), r.gid.clone());
    let pending = tokio::spawn(async move {
        if leave { a.leave().await.map(drop) } else { a.duties(&gid.0).await }
    });
    timeout(WAIT, reached.notified()).await.expect("A reached its second directory read after capturing the old roster");
    let certificate = if remove {
        let certificate = r.b_identity.certify(&[7; 32]).unwrap();
        r.c_identity.remove(&r.b_identity.key().unwrap().0).await.unwrap();
        certificate
    } else {
        r.b_identity.join(&Invite::parse(&r.c_identity.invite().await.unwrap()).unwrap()).await.unwrap();
        r.c_identity.duties(&r.gid.0).await.unwrap();
        r.b_identity.certify(&[7; 32]).unwrap()
    };
    let credential = Credential { key: [7; 32].into(), name: "external session".into(), certificate: Some(Box::new(certificate)) };
    let expected = if remove { Verdict::Dropped } else { Verdict::Authorized };
    let (observer, _) = device(&r.relay, "Observer").await;
    let published = observer.read_public(&r.identity).await.unwrap();
    assert_eq!(published.verify(&credential), expected);
    let cut = r.authority.store.head(&address).unwrap().length;
    assert_eq!(r.a.epoch(&r.gid.0).unwrap(), old_epoch, "private application is still delayed");
    release.notify_one();
    let result = timeout(WAIT, pending).await.unwrap().unwrap();
    let page = r.authority.read(&address);
    let mut view = PublicLog::replay(r.identity.id.0.as_slice().try_into().unwrap(), [page.entries[0].0.as_slice()]).unwrap();
    for (index, entry) in page.entries.iter().enumerate().skip(1) {
        if view.apply(&entry.0) && index as u64 + 1 >= cut {
            assert_eq!(view.verify(&credential), expected, "an ACCEPTED successor transiently reversed B's authorization");
            assert_eq!(view.writers, published.writers, "an obsolete intent became an accepted successor");
        }
    }
    assert_eq!(observer.read_public(&r.identity).await.unwrap().verify(&credential), expected);
    assert!(result.unwrap_err().to_string().contains("directory advanced"));
    assert_eq!(r.a.epoch(&r.gid.0).unwrap(), old_epoch);
    if leave {
        assert!(!r.a.leaving(&r.gid.0), "refused publication must retain the leave intent for a complete retry");
        r.a_identity.leave().await.unwrap();
        let after = observer.read_public(&r.identity).await.unwrap();
        assert!(!after.writers.contains(&r.a.key_in(&r.gid.0)));
        assert_eq!(after.verify(&credential), Verdict::Authorized, "retry keeps the added device, omitting only self");
    }
    observer.shutdown().await.unwrap();
    r.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn second_read_after_add_cannot_rebase_a_captured_roster() { captured_roster_race(false, false).await; }

#[tokio::test(flavor = "multi_thread")]
async fn second_read_after_remove_cannot_reauthorize_a_captured_roster() { captured_roster_race(true, false).await; }

#[tokio::test(flavor = "multi_thread")]
async fn second_read_race_preserves_omit_self_leave_intent() { captured_roster_race(false, true).await; }

#[tokio::test(flavor = "multi_thread")]
async fn publication_waits_for_application_not_just_a_received_page() {
    let r = Race::new(false).await;
    r.b_identity.join(&Invite::parse(&r.c_identity.invite().await.unwrap()).unwrap()).await.unwrap();
    r.c_identity.duties(&r.gid.0).await.unwrap();
    let log = r.a.log(&r.gid.0).unwrap();
    let page = r.authority.read(&log.0);
    {
        let mut st = r.a.inner.lock();
        let held = st.log(&log.0).unwrap().length();
        let mut hash = st.hash_at(&log.0, held).unwrap().unwrap();
        for (pos, entry) in page.entries.iter().enumerate().skip(held as usize) {
            hash = lmk_proto::head::next(&hash, &entry.0);
            st.provider.put(&crate::logs::entry_key(&log.0, pos as u64 + 1), &[hash.as_slice(), &entry.0].concat()).unwrap();
        }
        st.logs.get_mut(&log.0).unwrap().head = Some(page.head);
        st.save_log(&log.0).unwrap();
        assert!(st.group(&r.gid.0).unwrap().rec.position < st.held_to(&r.gid.0).unwrap());
    }
    let (reached, release) = r.gate(log.0.as_slice().try_into().unwrap(), 1);
    let (a, gid) = (r.a_identity.clone(), r.gid.clone());
    let pending = tokio::spawn(async move { a.duties(&gid.0).await });
    timeout(WAIT, reached.notified()).await.unwrap();
    release.notify_one();
    // A second public read is reachable only after the accepted-application barrier.
    let (published, proceed) = r.gate(r.authority.log(&lmk_proto::public::address(&r.identity.id.0)), 1);
    assert!(timeout(Duration::from_millis(100), published.notified()).await.is_err(), "receipt alone allowed writer derivation");
    {
        let mut st = r.a.inner.lock();
        r.a.inner.advance(&mut st, &r.gid.0).unwrap();
        assert_eq!(st.group(&r.gid.0).unwrap().rec.position, st.held_to(&r.gid.0).unwrap());
    }
    timeout(WAIT, published.notified()).await.unwrap();
    proceed.notify_one();
    timeout(WAIT, pending).await.unwrap().unwrap().unwrap();
    assert_eq!(r.a.members(&r.gid.0).unwrap().len(), 3);
    r.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authorized_unobserved_historical_sender_does_not_change_the_ledger() {
    let relay = relay().await;
    let (observer, own) = device(&relay, "observer").await;
    let (peer, _) = device(&relay, "former").await;
    own.create("Observer", relay.service.clone()).await.unwrap();
    let settings = Settings { protocol: PROTOCOL, kind: CHAT.into(), name: "chat".into(), carry: 7, update: UPDATE,
        membership: relay.service.clone(), public: None, rest: Default::default() };
    let gid = observer.create(settings, Some(own.certify(&observer.key().0).unwrap())).unwrap();
    let seed = lmk_core::random();
    let (id, first) = lmk_core::public::create(&seed, relay.service.clone());
    let identity = IdentityRef { id: id.into(), membership: relay.service.clone() };
    let key = lmk_core::device::public(&seed);
    let certificate = Certificate { identity: identity.clone(), device: key.into(), name: "Unobserved".into(), device_name: "phone".into(),
        sig: Bytes(lmk_core::device::sign(&seed, &certified(peer.key().0.as_slice().try_into().unwrap(), &id, &key, "Unobserved", "phone"))) };
    peer.join(&observer.invite(&gid.0, None, crate::INVITE_VALID).await.unwrap(), Some(certificate)).await.unwrap();
    let historical = observer.inner.lock().group(&gid.0).unwrap().mls.members().into_iter().find(|m| m.key == peer.key().0).unwrap();
    assert!(observer.members(&gid.0).unwrap().iter().find(|m| m.key == peer.key()).unwrap().identity.as_ref().unwrap().error.is_some());
    observer.remove(&gid.0, &peer.key().0).await.unwrap();
    let before = observer.inner.lock().provider.get(b"node/identity-bindings").unwrap();
    assert!(before.is_some(), "the observer's original binding is already durable");
    let endpoint = relay.endpoint(iroh::SecretKey::from_bytes(&lmk_core::random())).await;
    let client = lmk_membership::client::ServeClient::for_service(endpoint, &relay.service).unwrap();
    client.append(&lmk_proto::public::address(&id), &[first], true).await.unwrap();
    observer.read_public(&identity).await.unwrap();
    for _ in 0..3 {
        let st = observer.inner.lock();
        // The same former-member path used when reading.rs opens historical ciphertext.
        let claim = st.member(&gid.0, &historical).unwrap().identity.unwrap();
        assert_eq!(claim.name, "Unobserved");
        assert!(claim.error.is_none() && claim.observed.is_none());
        assert_eq!(st.provider.get(b"node/identity-bindings").unwrap(), before);
        assert!(!st.bindings.iter().any(|(id, _)| *id == identity.id));
    }
    observer.shutdown().await.unwrap();
    peer.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn known_public_revocation_does_not_bind_an_authenticated_private_prefix() {
    // Characterization of the remaining design blocker, NOT an accepted freshness guarantee.
    let r = Race::new(true).await;
    let log = r.a.log(&r.gid.0).unwrap();
    let prefix = r.authority.read(&log.0);
    let certificate = r.b_identity.certify(&[7; 32]).unwrap();
    let credential = Credential { key: [7; 32].into(), name: "external session".into(), certificate: Some(Box::new(certificate)) };
    r.c_identity.remove(&r.b_identity.key().unwrap().0).await.unwrap();
    let revoked = r.a.read_public(&r.identity).await.unwrap();
    assert_eq!(revoked.verify(&credential), Verdict::Dropped, "A already knows the public revocation");
    *r.authority.stale.lock().unwrap() = Some((r.a.net().id(), log.0.as_slice().try_into().unwrap(), prefix));
    r.a_identity.duties(&r.gid.0).await.unwrap();
    let (observer, _) = device(&r.relay, "Observer").await;
    assert_eq!(observer.read_public(&r.identity).await.unwrap().verify(&credential), Verdict::Authorized,
        "remaining blocker: an unchanged public predecessor does not prove private freshness; maintenance reauthorizes B");
    observer.shutdown().await.unwrap();
    r.close().await;
}
