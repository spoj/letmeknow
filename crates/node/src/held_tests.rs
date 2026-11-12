use super::*;
use crate::{Config, INVITE_VALID, Node};
use lmk_core::provider::SqliteProvider;
use lmk_proto::group::{PROTOCOL, Settings, UPDATE};
use tokio::sync::mpsc::UnboundedReceiver;

async fn members() -> (Node, Node, Bytes, UnboundedReceiver<Event>) {
    let relay = lmk_testing::relay().await;
    let config = Config { home: relay.domain.clone(), post: relay.post(), ca: relay.ca(), device: ed25519_dalek::SigningKey::from_bytes(&[9; 32]) };
    let alice = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config.clone()).await.unwrap().0;
    let (bob, mut events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config).await.unwrap();
    let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
    let gid = bob.create(settings).unwrap();
    alice.join(&bob.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    for node in [&alice, &bob] {
        let tasks: Vec<_> = node.inner.tasks.lock().unwrap().drain(..).collect();
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            if let Err(error) = task.await {
                assert!(error.is_cancelled());
            }
        }
    }
    bob.read_group(&gid.0).await.unwrap();
    alice.read_group(&gid.0).await.unwrap();
    assert_eq!(alice.epoch(&gid.0).unwrap(), bob.epoch(&gid.0).unwrap());
    while events.try_recv().is_ok() {}
    (alice, bob, gid, events)
}

fn seal(node: &Node, gid: &Bytes, seq: u64, prev: Option<(Bytes, u64)>, text: &str) -> (Bytes, Vec<u8>) {
    let mut st = node.inner.lock();
    let g = st.group(&gid.0).unwrap();
    let header = Header {
        group: gid.clone(), author: Bytes(st.session.key().to_vec()), joined: 1, seq, epoch: g.mls.epoch(), prev,
        deps: vec![], reply_to: None, payload: serde_json::json!({ "type": "message", "content": text }),
    };
    let plaintext = header.encode();
    let State { provider, session, groups, .. } = &mut *st;
    let ciphertext = groups.get_mut(&gid.0).unwrap().mls.seal(provider, session, &plaintext).unwrap();
    (Bytes(lmk_proto::held::id(&plaintext).to_vec()), ciphertext)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_messages_as_one_seq_warn_and_keep_the_first() {
    let (alice, bob, gid, mut events) = members().await;
    let (first, ciphertext) = seal(&alice, &gid, 1, None, "first");
    let (other, equivocation) = seal(&alice, &gid, 1, None, "other");
    {
        let mut st = bob.inner.lock();
        assert!(bob.inner.open_one(&mut st, &gid.0, ciphertext).unwrap().is_some());
        assert!(bob.inner.open_one(&mut st, &gid.0, equivocation).unwrap().is_none());
        assert_eq!(st.id_at(&gid.0, &alice.key().0, 1, 1).unwrap(), Some(first));
        assert!(st.record(&gid.0, &other.0).unwrap().is_none());
    }
    let text = format!("{} sent two held messages as its seq 1: this session keeps the first", crate::fp(&alice.key().0));
    assert!(matches!(events.try_recv().unwrap(), Event::Warning { group: Some(group), text: warning } if group == gid && warning == text));
    for node in [alice, bob] {
        node.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prev_other_than_the_preceding_seq_warns_and_is_not_kept() {
    let (alice, bob, gid, mut events) = members().await;
    let (first, ciphertext) = seal(&alice, &gid, 1, None, "first");
    let (bad, equivocation) = seal(&alice, &gid, 2, Some((Bytes(vec![0; 32]), 2)), "wrong prev");
    let (second, valid) = seal(&alice, &gid, 2, Some((first.clone(), 2)), "right prev");
    {
        let mut st = bob.inner.lock();
        assert!(bob.inner.open_one(&mut st, &gid.0, ciphertext).unwrap().is_some());
        assert!(bob.inner.open_one(&mut st, &gid.0, equivocation).unwrap().is_none());
        assert!(st.id_at(&gid.0, &alice.key().0, 1, 2).unwrap().is_none());
        assert!(st.record(&gid.0, &bad.0).unwrap().is_none());
        assert!(bob.inner.open_one(&mut st, &gid.0, valid).unwrap().is_some());
        assert_eq!(st.id_at(&gid.0, &alice.key().0, 1, 1).unwrap(), Some(first));
        assert_eq!(st.id_at(&gid.0, &alice.key().0, 1, 2).unwrap(), Some(second));
    }
    let text = format!("{} sent a held message whose prev is not its seq 1: this session keeps the first", crate::fp(&alice.key().0));
    assert!(matches!(events.try_recv().unwrap(), Event::Warning { group: Some(group), text: warning } if group == gid && warning == text));
    for node in [alice, bob] {
        node.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_before_a_join_in_a_later_cut_is_neither_lacking_nor_lost() {
    let relay = lmk_testing::relay().await;
    let config = |seed| Config { home: relay.domain.clone(), post: relay.post(), ca: relay.ca(), device: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]) };
    let alice = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(1)).await.unwrap().0;
    let bob = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(2)).await.unwrap().0;
    let carol = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(3)).await.unwrap().0;
    let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
    let gid = alice.create(settings).unwrap();
    bob.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let tasks: Vec<_> = bob.inner.tasks.lock().unwrap().drain(..).collect();
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    alice.read_group(&gid.0).await.unwrap();
    bob.read_group(&gid.0).await.unwrap();
    let before = bob.inner.send(&mut bob.inner.lock(), &gid.0, &serde_json::json!({ "type": "message", "content": "before Carol" }), None).unwrap();

    carol.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    for node in [&alice, &carol] {
        let tasks: Vec<_> = node.inner.tasks.lock().unwrap().drain(..).collect();
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }
    for node in [&alice, &bob, &carol] {
        node.read_group(&gid.0).await.unwrap();
    }

    let after = bob.inner.send(&mut bob.inner.lock(), &gid.0, &serde_json::json!({ "type": "message", "content": "after Carol" }), None).unwrap();
    let (first, second) = {
        let st = bob.inner.lock();
        let first = st.record(&gid.0, &before.0).unwrap().unwrap().sealing.unwrap().1.0;
        let second = st.record(&gid.0, &after.0).unwrap().unwrap().sealing.unwrap().1.0;
        (first, second)
    };
    alice.inner.take(&mut alice.inner.lock(), &gid.0, None, vec![first, second.clone()], false).unwrap();
    alice.inner.commit(&gid.0, |_, _| Ok(Some(core::Change::default()))).await.unwrap();

    carol.read_group(&gid.0).await.unwrap();
    carol.inner.take(&mut carol.inner.lock(), &gid.0, None, vec![second], false).unwrap();
    assert!(carol.message(&gid.0, &after.0).unwrap().is_some_and(|m| m.missing.is_empty()));

    let lacking = carol.inner.lock().group(&gid.0).unwrap().lacking();
    alice.inner.commit(&gid.0, |_, _| Ok(Some(core::Change::default()))).await.unwrap();
    carol.read_group(&gid.0).await.unwrap();
    let waited = carol.epoch(&gid.0).unwrap() < alice.epoch(&gid.0).unwrap();
    {
        let mut st = carol.inner.lock();
        st.time += 200_000;
        carol.inner.advance(&mut st, &gid.0).unwrap();
    }
    let lost = carol.inner.lock().group(&gid.0).unwrap().rec.lost.clone();
    for node in [alice, bob, carol] {
        node.shutdown().await.unwrap();
    }
    assert_eq!((lacking.is_empty(), waited, lost.is_empty()), (true, false, true), "lacking={lacking:?} waited={waited} lost={lost:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ciphertext_past_the_window_opens_when_the_lowest_seq_moves() {
    let (alice, bob, gid, _) = members().await;
    let (id, ciphertext) = seal(&alice, &gid, WINDOW + 1, Some((Bytes(vec![0; 32]), 2)), "past the window");
    let (_, first) = seal(&alice, &gid, 1, None, "first");
    {
        let mut st = bob.inner.lock();
        assert!(bob.inner.take_one(&mut st, &gid.0, None, ciphertext.clone()).unwrap().is_none());
        assert_eq!(st.group(&gid.0).unwrap().unopened.len(), 1);
        assert!(st.record(&gid.0, &id.0).unwrap().is_none());
        let mut opened = Vec::new();
        bob.inner.open_unopened(&mut st, &gid.0, &mut opened).unwrap();
        assert!(opened.is_empty());
        assert!(bob.inner.take_one(&mut st, &gid.0, None, first).unwrap().is_some());
        bob.inner.open_unopened(&mut st, &gid.0, &mut opened).unwrap();
        assert_eq!(opened, vec![(ciphertext, 2)]);
        assert!(st.group(&gid.0).unwrap().unopened.is_empty());
        assert_eq!(st.id_at(&gid.0, &alice.key().0, 1, WINDOW + 1).unwrap(), Some(id));
    }
    for node in [alice, bob] {
        node.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ciphertext_past_the_flood_bucket_opens_after_it_refills() {
    let (alice, bob, gid, _) = members().await;
    let (id, ciphertext) = seal(&alice, &gid, 1, None, "past the bucket");
    {
        let mut st = bob.inner.lock();
        // The bucket's clock stays fixed until this test advances it.
        st.time = crate::now() + 60_000;
        let at = st.time;
        st.group_mut(&gid.0).unwrap().buckets.insert((alice.key(), 1), Bucket { messages: 0.0, bytes: 0.0, at });
        assert!(bob.inner.take_one(&mut st, &gid.0, None, ciphertext.clone()).unwrap().is_none());
        assert_eq!(st.group(&gid.0).unwrap().unopened.len(), 1);
        assert!(st.record(&gid.0, &id.0).unwrap().is_none());
        let mut opened = Vec::new();
        bob.inner.open_unopened(&mut st, &gid.0, &mut opened).unwrap();
        assert!(opened.is_empty());
        assert_eq!(st.group(&gid.0).unwrap().unopened.len(), 1);
        st.time += 1000;
        bob.inner.open_unopened(&mut st, &gid.0, &mut opened).unwrap();
        assert_eq!(opened, vec![(ciphertext, 2)]);
        assert!(st.group(&gid.0).unwrap().unopened.is_empty());
        assert_eq!(st.id_at(&gid.0, &alice.key().0, 1, 1).unwrap(), Some(id));
    }
    for node in [alice, bob] {
        node.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ciphertext_past_the_window_is_dropped_when_its_epochs_keys_go() {
    let (alice, bob, gid, _) = members().await;
    let (edge, past) = seal(&alice, &gid, WINDOW + 1, Some((Bytes(vec![0; 32]), 2)), "just past the window");
    let (far, huge) = seal(&alice, &gid, 1 << 63, Some((Bytes(vec![0; 32]), 2)), "far past the window");
    {
        let mut st = bob.inner.lock();
        st.time = crate::now();
        for ciphertext in [past, huge] {
            assert!(bob.inner.take_one(&mut st, &gid.0, None, ciphertext).unwrap().is_none());
        }
        assert_eq!(st.group(&gid.0).unwrap().unopened.len(), 2);
        bob.inner.open_all(&mut st, &gid.0, 2).unwrap();
        assert!(st.group(&gid.0).unwrap().unopened.is_empty());
        st.time += HOLD_OFF + 1;
        bob.inner.give_up(&mut st, &gid.0).unwrap();
        assert!(st.record(&gid.0, &edge.0).unwrap().is_none());
        assert!(st.record(&gid.0, &far.0).unwrap().is_none());
        assert!(st.events.is_empty());
    }
    for node in [alice, bob] {
        node.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn messages_made_ready_as_a_commit_applies_deliver_at_once_and_leave_the_session_idle() {
    let relay = lmk_testing::relay().await;
    let dir = tempfile::tempdir().unwrap();
    let carol_db = dir.path().join("carol.db");
    let config = |seed| Config { home: relay.domain.clone(), post: relay.post(), ca: relay.ca(), device: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]) };
    let alice = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(1)).await.unwrap().0;
    let bob = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(2)).await.unwrap().0;
    let carol = Node::start(SqliteProvider::open(&carol_db).unwrap(), config(3)).await.unwrap().0;
    let dave = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(4)).await.unwrap().0;
    let erin = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(5)).await.unwrap().0;
    let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
    let gid = alice.create(settings).unwrap();
    for joiner in [&bob, &carol, &dave, &erin] {
        joiner.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    }
    for node in [&alice, &bob, &carol, &dave, &erin] {
        let tasks: Vec<_> = node.inner.tasks.lock().unwrap().drain(..).collect();
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }
    for node in [&alice, &bob, &carol, &dave, &erin] {
        node.read_group(&gid.0).await.unwrap();
    }

    let msg = |text| serde_json::json!({ "type": "message", "content": text });
    let sealing = |node: &Node, id: &Bytes| node.inner.lock().record(&gid.0, &id.0).unwrap().unwrap().sealing.unwrap().1.0;
    let by_open = alice.inner.send(&mut alice.inner.lock(), &gid.0, &msg("from open_all"), None).unwrap();
    let lost_msg = bob.inner.send(&mut bob.inner.lock(), &gid.0, &msg("lost"), None).unwrap();
    let after_lost = bob.inner.send(&mut bob.inner.lock(), &gid.0, &msg("after lost"), None).unwrap();
    alice.inner.take(&mut alice.inner.lock(), &gid.0, None, vec![sealing(&bob, &lost_msg)], false).unwrap();
    {
        let mut st = carol.inner.lock();
        st.time = crate::now() + 600_000;
        let at = st.time;
        let joined = st.group(&gid.0).unwrap().mls.joined(&alice.key().0).unwrap();
        st.group_mut(&gid.0).unwrap().buckets.insert((alice.key(), joined), Bucket { messages: 0.0, bytes: 0.0, at });
        carol.inner.take(&mut st, &gid.0, None, vec![sealing(&alice, &by_open), sealing(&bob, &after_lost)], false).unwrap();
        assert_eq!(st.group(&gid.0).unwrap().unopened.len(), 1);
    }

    alice.inner.commit(&gid.0, |_, _| Ok(Some(core::Change::default()))).await.unwrap();
    for node in [&carol, &dave, &erin] {
        node.read_group(&gid.0).await.unwrap();
    }

    let unkept_dave = dave.inner.send(&mut dave.inner.lock(), &gid.0, &msg("unkept"), None).unwrap();
    erin.inner.take(&mut erin.inner.lock(), &gid.0, None, vec![sealing(&dave, &unkept_dave)], false).unwrap();
    erin.mark_shown(&gid.0, std::slice::from_ref(&unkept_dave)).unwrap();
    let after_ended = erin.inner.send(&mut erin.inner.lock(), &gid.0, &msg("after ended"), None).unwrap();
    carol.inner.take(&mut carol.inner.lock(), &gid.0, None, vec![sealing(&erin, &after_ended)], false).unwrap();
    for id in [&by_open, &after_lost, &after_ended] {
        assert!(carol.message(&gid.0, &id.0).unwrap().is_none());
    }

    alice.remove(&gid.0, std::slice::from_ref(&dave.key())).await.unwrap();
    carol.read_group(&gid.0).await.unwrap();
    assert!(carol.message(&gid.0, &by_open.0).unwrap().is_some(), "open_all delivers while waiting");
    assert!(carol.message(&gid.0, &after_lost.0).unwrap().is_none());
    assert!(carol.message(&gid.0, &after_ended.0).unwrap().is_none());
    {
        let mut st = carol.inner.lock();
        st.time += 200_000;
        carol.inner.advance(&mut st, &gid.0).unwrap();
    }
    for id in [&by_open, &after_lost, &after_ended] {
        assert!(carol.message(&gid.0, &id.0).unwrap().is_some());
    }
    for node in [alice, bob, carol, dave, erin] {
        node.shutdown().await.unwrap();
    }

    let carol = Node::start(SqliteProvider::open(&carol_db).unwrap(), config(3)).await.unwrap().0;
    for id in [&by_open, &after_lost, &after_ended] {
        assert!(carol.message(&gid.0, &id.0).unwrap().is_some());
    }
    n0_future::time::timeout(n0_future::time::Duration::from_secs(30), async {
        while carol.inner.lock().next_poll().is_some_and(|at| at <= crate::now() + 60_000) {
            n0_future::time::sleep(n0_future::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Carol goes idle");
    carol.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_commit_removing_this_session_delivers_what_became_ready_before_forgetting_the_group() {
    let relay = lmk_testing::relay().await;
    let config = |seed| Config { home: relay.domain.clone(), post: relay.post(), ca: relay.ca(), device: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]) };
    let alice = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(1)).await.unwrap().0;
    let bob = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(2)).await.unwrap().0;
    let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
    let gid = alice.create(settings).unwrap();
    bob.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let tasks: Vec<_> = bob.inner.tasks.lock().unwrap().drain(..).collect();
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    alice.read_group(&gid.0).await.unwrap();
    bob.read_group(&gid.0).await.unwrap();

    let msg = |text| serde_json::json!({ "type": "message", "content": text });
    let sealing = |node: &Node, id: &Bytes| node.inner.lock().record(&gid.0, &id.0).unwrap().unwrap().sealing.unwrap().1.0;
    let before_carol = alice.inner.send(&mut alice.inner.lock(), &gid.0, &msg("before Carol"), None).unwrap();
    bob.inner.take(&mut bob.inner.lock(), &gid.0, None, vec![sealing(&alice, &before_carol)], false).unwrap();
    bob.mark_shown(&gid.0, std::slice::from_ref(&before_carol)).unwrap();

    let (carol, mut events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config(3)).await.unwrap();
    carol.join(&alice.invite(&gid.0, INVITE_VALID, None).await.unwrap()).await.unwrap();
    let tasks: Vec<_> = alice.inner.tasks.lock().unwrap().drain(..).collect();
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    for node in [&alice, &bob, &carol] {
        node.read_group(&gid.0).await.unwrap();
    }
    while events.try_recv().is_ok() {}

    let farewell = bob.inner.send(&mut bob.inner.lock(), &gid.0, &msg("farewell"), None).unwrap();
    {
        let mut st = carol.inner.lock();
        st.time = crate::now() + 600_000;
        let at = st.time;
        let joined = st.group(&gid.0).unwrap().mls.joined(&bob.key().0).unwrap();
        st.group_mut(&gid.0).unwrap().buckets.insert((bob.key(), joined), Bucket { messages: 0.0, bytes: 0.0, at });
        carol.inner.take(&mut st, &gid.0, None, vec![sealing(&bob, &farewell)], false).unwrap();
        assert_eq!(st.group(&gid.0).unwrap().unopened.len(), 1);
    }

    alice.remove(&gid.0, std::slice::from_ref(&carol.key())).await.unwrap();
    let _ = carol.read_group(&gid.0).await;
    let mut delivered = Vec::new();
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), events.recv()).await.unwrap().unwrap() {
            Event::Message(m) => delivered.push(m.id),
            Event::Removed { group, .. } if group == gid => break,
            _ => {}
        }
    }
    assert_eq!(delivered, [farewell]);
    assert!(!carol.groups().contains(&gid));
    for node in [alice, bob, carol] {
        node.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unopened_ciphertexts_within_the_window_open_before_their_epochs_keys_go_despite_the_bucket() {
    let (alice, bob, gid, _) = members().await;
    let (id, ciphertext) = seal(&alice, &gid, WINDOW + 1, Some((Bytes(vec![0; 32]), 2)), "past the window");
    let (first, blocked) = seal(&alice, &gid, 1, None, "past the bucket");
    {
        let mut st = bob.inner.lock();
        // No real time refills the bucket while open_all bypasses it.
        st.time = crate::now() + 60_000;
        let at = st.time;
        st.group_mut(&gid.0).unwrap().buckets.insert((alice.key(), 1), Bucket { messages: 0.0, bytes: 0.0, at });
        for ciphertext in [ciphertext, blocked] {
            assert!(bob.inner.take_one(&mut st, &gid.0, None, ciphertext).unwrap().is_none());
        }
        assert_eq!(st.group(&gid.0).unwrap().unopened.len(), 2);
        bob.inner.open_all(&mut st, &gid.0, 1).unwrap();
        assert_eq!(st.group(&gid.0).unwrap().unopened.len(), 2);
        assert!(st.record(&gid.0, &id.0).unwrap().is_none());
        assert!(st.record(&gid.0, &first.0).unwrap().is_none());
        bob.inner.open_all(&mut st, &gid.0, 2).unwrap();
        assert!(st.group(&gid.0).unwrap().unopened.is_empty());
        assert_eq!(st.id_at(&gid.0, &alice.key().0, 1, WINDOW + 1).unwrap(), Some(id));
        assert_eq!(st.id_at(&gid.0, &alice.key().0, 1, 1).unwrap(), Some(first));
    }
    for node in [alice, bob] {
        node.shutdown().await.unwrap();
    }
}

/// A stranger's hello of groups this session has not added is kept only as its latest, and dropped as it disconnects.
#[tokio::test(flavor = "multi_thread")]
async fn a_strangers_early_hello_is_its_latest_and_goes_when_it_disconnects() {
    use lmk_proto::{frame, peer::At};
    let relay = lmk_testing::relay().await;
    let config = Config { home: relay.domain.clone(), post: relay.post(), ca: relay.ca(), device: ed25519_dalek::SigningKey::from_bytes(&[1; 32]) };
    let bob = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config).await.unwrap().0;
    let stranger = relay.endpoint(iroh::SecretKey::from_bytes(&[99; 32])).await;
    let conn = stranger.connect(iroh::EndpointAddr::new(bob.net().id()).with_relay_url(relay.url.clone()), frame::ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    frame::write(&mut send, &frame::Open { stream: frame::Stream::Peer }).await.unwrap();
    let hello = |group: u8| Frame::Hello { groups: vec![At { group: Bytes(vec![group; 16]), log: [0; 32], head: None, seen: BTreeMap::new(), intros: vec![], expired: vec![] }] };
    frame::write(&mut send, &hello(1)).await.unwrap();
    frame::write(&mut send, &hello(2)).await.unwrap();
    let timeout = n0_future::time::Duration::from_secs(5);
    n0_future::time::timeout(timeout, async {
        while !bob.inner.lock().early_hellos.iter().any(|(_, at)| at.group.0 == [2; 16]) {
            n0_future::time::sleep(n0_future::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Bob read the stranger's second hello");
    assert_eq!(bob.inner.lock().early_hellos.len(), 1);
    conn.close(0u32.into(), b"bye");
    stranger.close().await;
    n0_future::time::timeout(timeout, async {
        while !bob.inner.lock().early_hellos.is_empty() {
            n0_future::time::sleep(n0_future::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the stranger's hello went with it");
    bob.shutdown().await.unwrap();
}

/// While a join is in flight, the members its link names are read whole, as an admitter's first hello, which comes before
/// the Welcome, holds every intro of the group: a stranger's frame past `MAX_ASK` still closes its connection, and once
/// the join ends the members are no longer read whole.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_reads_whole_the_members_its_link_names_while_it_joins() {
    use lmk_net::{Admit, Groups, Net};
    use lmk_proto::{Answer, frame, links::Invite, peer::{Admitted, At, Join, Signed}};
    /// Lets every frame go, serves every peer, and refuses each join once told to.
    struct Fake(tokio::sync::watch::Receiver<bool>);
    impl Groups for Fake {
        fn admit(&self, _: &EndpointId, frame: Frame) -> Option<Frame> {
            Some(frame)
        }
        fn serves(&self, _: &EndpointId) -> bool {
            true
        }
    }
    impl Admit for Fake {
        fn join(&self, _: EndpointId, _: Join) -> n0_future::boxed::BoxFuture<Answer<Admitted>> {
            let mut refuse = self.0.clone();
            Box::pin(async move {
                refuse.wait_for(|told| *told).await.unwrap();
                Answer::Refused { refused: "no".into() }
            })
        }
    }
    let relay = lmk_testing::relay().await;
    let config = Config { home: relay.domain.clone(), post: relay.post(), ca: relay.ca(), device: ed25519_dalek::SigningKey::from_bytes(&[1; 32]) };
    let bob = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config).await.unwrap().0;
    let endpoint = lmk_net::builder([relay.url.clone()]).ca_tls_config(relay.ca()).bind().await.unwrap();
    endpoint.online().await;
    let (refuse, refusing) = tokio::sync::watch::channel(false);
    let fake = std::sync::Arc::new(Fake(refusing));
    let (member, mut events) = Net::spawn(endpoint, fake.clone(), fake).await.unwrap();
    let link = Invite { secret: [7; 16], domain: relay.domain.clone(), members: vec![(*member.id().as_bytes(), relay.domain.clone())] };
    let joining = n0_future::task::spawn({
        let bob = bob.clone();
        async move { bob.join(&link).await }
    });
    let timeout = n0_future::time::Duration::from_secs(20);
    n0_future::time::timeout(timeout, async { while !matches!(events.recv().await, Some(lmk_net::Event::Connected(..))) {} })
        .await
        .expect("Bob dialed the member");
    let intro = Signed { body: Bytes(vec![7; 1024]), sig: Bytes(vec![7; 64]) };
    let hello = Frame::Hello { groups: vec![At { group: Bytes(vec![1; 16]), log: [0; 32], head: None, seen: BTreeMap::new(), intros: vec![intro; 64], expired: vec![] }] };
    assert!(frame::encode(&hello).len() - 4 > frame::MAX_ASK as usize);
    assert!(member.frame(bob.net().id(), hello.clone()));
    n0_future::time::timeout(timeout, async {
        while !bob.inner.lock().early_hellos.iter().any(|(peer, _)| *peer == member.id()) {
            n0_future::time::sleep(n0_future::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Bob read the member's hello");
    let stranger = relay.endpoint(iroh::SecretKey::from_bytes(&[99; 32])).await;
    let conn = stranger.connect(iroh::EndpointAddr::new(bob.net().id()).with_relay_url(relay.url.clone()), frame::ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    frame::write(&mut send, &frame::Open { stream: frame::Stream::Peer }).await.unwrap();
    frame::write(&mut send, &hello).await.unwrap();
    n0_future::time::timeout(timeout, conn.closed()).await.expect("Bob closed the stranger's connection");
    assert!(bob.inner.lock().early_hellos.iter().all(|(peer, _)| *peer == member.id()));
    refuse.send(true).unwrap();
    assert_eq!(format!("{:#}", joining.await.unwrap().unwrap_err()), "refused: no");
    assert!(!bob.inner.serves(&member.id()));
    stranger.close().await;
    member.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}
