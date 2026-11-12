use super::*;
use crate::{Config, Node};
use lmk_core::provider::SqliteProvider;
use lmk_proto::group::{PROTOCOL, Settings, UPDATE};

#[tokio::test(flavor = "multi_thread")]
async fn a_copied_sessions_commit_warns_and_stops_using_the_group() {
    let relay = lmk_testing::relay().await;
    let config = Config { home: relay.domain.clone(), post: relay.post(), ca: relay.ca(), device: ed25519_dalek::SigningKey::from_bytes(&[9; 32]) };
    let (node, mut events) = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config).await.unwrap();
    let settings = Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] };
    let gid = node.create(settings).unwrap();
    {
        let mut st = node.inner.lock();
        let mut copy = core::Group::load(&st.provider, &gid.0).unwrap();
        let commit = copy.commit(&st.provider, &st.session, core::Change { cut: copy.cut().to_vec(), ..core::Change::default() }).unwrap();
        let position = st.group(&gid.0).unwrap().rec.position;
        let epoch = st.group(&gid.0).unwrap().mls.epoch();
        assert!(!node.inner.judge(&mut st, &gid.0, position + 1, &commit.entry).unwrap());
        let g = st.group(&gid.0).unwrap();
        assert_eq!(g.rec.position, position);
        assert_eq!(g.mls.epoch(), epoch);
    }
    assert!(matches!(events.try_recv().unwrap(), Event::Warning { group: Some(group), text }
        if group == gid && text == "a copy of this session's state committed in the group, so this session stops using it: join it again from a new session"));
    let removed = tokio::time::timeout(std::time::Duration::from_secs(5), events.recv()).await.unwrap().unwrap();
    assert!(matches!(removed, Event::Removed { group, by: None, .. } if group == gid));
    assert!(!node.groups().contains(&gid));
    node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removed_member_two_commits_behind_learns_it() {
    use crate::INVITE_VALID;
    use iroh::EndpointId;

    let relay = lmk_testing::relay().await;
    let config = Config { home: relay.domain.clone(), post: relay.post(), ca: relay.ca(), device: ed25519_dalek::SigningKey::from_bytes(&[9; 32]) };
    let alice = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config.clone()).await.unwrap().0;
    let bob = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config.clone()).await.unwrap().0;
    let spare = Node::start(SqliteProvider::open(":memory:".as_ref()).unwrap(), config).await.unwrap().0;
    let gid = alice.create(Settings { protocol: PROTOCOL, carry: 7, update: UPDATE, membership: relay.service.clone(), admins: vec![], admitted: vec![] }).unwrap();
    bob.join(&alice.invite(&gid.0, INVITE_VALID, Some(&bob.key().0)).await.unwrap()).await.unwrap();
    spare.join(&alice.invite(&gid.0, INVITE_VALID, Some(&spare.key().0)).await.unwrap()).await.unwrap();
    let (alice_key, bob_key, spare_key) = (alice.key(), bob.key(), spare.key());
    spare.shutdown().await.unwrap();
    alice.read_group(&gid.0).await.unwrap();
    bob.read_group(&gid.0).await.unwrap();
    for task in bob.inner.tasks.lock().unwrap().drain(..) {
        task.abort();
    }

    let log_1 = alice.log(&gid.0).unwrap();
    alice.remove(&gid.0, std::slice::from_ref(&spare_key)).await.unwrap();
    let log_2 = alice.log(&gid.0).unwrap();
    alice.remove(&gid.0, std::slice::from_ref(&bob_key)).await.unwrap();
    let frames: Vec<Frame> = {
        let st = alice.inner.lock();
        [log_1, log_2].into_iter().map(|id| Frame::Entries { log: id.clone(), entries: st.entries(&id.0, 0), head: st.logs[&id.0].head.clone().unwrap() }).collect()
    };
    let alice_iroh = EndpointId::from_bytes(&alice.address().0).unwrap();
    {
        let mut st = bob.inner.lock();
        st.time = crate::now() + 60_000;
        let now = st.tick();
        st.peers.connect(*alice_iroh.as_bytes(), std::collections::BTreeSet::from([gid.clone()]), false, now);
        let g = st.group_mut(&gid.0).unwrap();
        g.author_mut(&alice_key.0, 0).unwrap().cut = 1;
        g.rec.keep = vec![Seqs { key: alice_key.clone(), joined: 0, seqs: Ranges::range(1, 1) }];
    }
    for frame in frames.into_iter().rev() {
        bob.inner.peer_event(lmk_net::Event::Frame(alice_iroh, frame));
    }
    let removed = {
        let mut st = bob.inner.lock();
        st.time += lmk_net::peers::WAIT + 1_000;
        bob.inner.advance(&mut st, &gid.0).unwrap();
        !st.group(&gid.0).is_ok_and(|g| g.mls.active())
    };
    for node in [alice, bob] {
        node.shutdown().await.unwrap();
    }
    assert!(removed, "Bob dropped the removing Entries frame while waiting at the prior commit and never learned he was removed");
}
