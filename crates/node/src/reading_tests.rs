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
