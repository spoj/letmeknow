mod common;

use common::*;
use ed25519_dalek::SigningKey;
use iroh::RelayUrl;
use lmk_net::Event;
use lmk_proto::{
    Answer,
    links::Invite,
    peer::Joiner,
};
use yrs::{ReadTxn, Text, Transact, updates::decoder::Decode};

const G: &[u8] = b"group";

fn service() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_head_swap_and_contradiction() {
    let relay = relay().await;
    let keys = keys(3);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
    let log = |entries: &[&[u8]]| Group { members: members.clone(), log: entries.iter().map(|e| e.to_vec()).collect(), ..Group::default() };
    let service = service();
    let mut a = node(&relay, keys[0].clone(), Fake::new(&service).with(G, log(&[b"e1", b"e2", b"e3"])), Options::default()).await;
    let mut b = node(&relay, keys[1].clone(), Fake::new(&service).with(G, log(&[b"e1", b"e2"])), Options::default()).await;
    // The service showed C another third entry.
    let relay_only = Options { relay_only: true, ..Options::default() };
    let mut c = node(&relay, keys[2].clone(), Fake::new(&service).with(G, log(&[b"e1", b"e2", b"x3"])), relay_only).await;

    a.net.dial(members[1], relay.url.clone()).await.unwrap();
    a.synced(G, members[1]).await;
    b.synced(G, members[0]).await;
    assert_eq!(b.fake.log(G), a.fake.log(G), "B caught up from A's commits");

    c.net.dial(members[0], relay.url.clone()).await.unwrap();
    for (node, peer) in [(&mut a, members[2]), (&mut c, members[0])] {
        let event = node.until(|e| matches!(e, Event::Contradiction { .. })).await;
        let Event::Contradiction { group, peer: from, ours, theirs } = event else { unreachable!() };
        assert_eq!((group.as_slice(), from), (G, peer));
        assert_eq!((ours.length, theirs.length), (3, 3));
        assert_ne!(ours.hash, theirs.hash);
    }
    assert_eq!(c.fake.log(G)[2], b"x3", "nothing applied across a contradiction");

    b.net.dial(members[2], relay.url.clone()).await.unwrap();
    b.until(|e| matches!(e, Event::Contradiction { peer, .. } if *peer == members[2])).await;
    assert_eq!(a.net.connected().len(), 2);
    for node in [&a, &b, &c] {
        node.net.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn messages_sync_after_both_were_offline() {
    let relay = relay().await;
    let keys = keys(2);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
    let service = service();
    let log: Vec<Vec<u8>> = (1..=5).map(|n| vec![n]).collect();
    let group = |floor, joined| Group { members: members.clone(), log: log.clone(), floor, joined, ..Group::default() };
    // A was there from the start; B joined at epoch 2 and accepts nothing below epoch 3.
    let fake_a = Fake::new(&service).with(G, group(0, 0));
    let fake_b = Fake::new(&service).with(G, group(3, 2));
    let before_b_joined = message(1, "a1");
    let below_b_floor = message(2, "a2");
    let from_a = [message(4, "a4"), message(5, "a5")];
    let from_b = [message(3, "b3"), message(5, "b5")];
    let both = message(4, "both");
    for m in [&before_b_joined, &below_b_floor, &from_a[0], &from_a[1], &both] {
        fake_a.hold(G, m.clone());
    }
    for m in [&from_b[0], &from_b[1], &both] {
        fake_b.hold(G, m.clone());
    }

    let mut a = node(&relay, keys[0].clone(), fake_a, Options::default()).await;
    let mut b = node(&relay, keys[1].clone(), fake_b, Options { relay_only: true, ..Options::default() }).await;
    b.net.dial(members[0], relay.url.clone()).await.unwrap();
    a.synced(G, members[1]).await;
    b.synced(G, members[0]).await;
    for m in &from_a {
        assert!(b.fake.holds(G, m));
    }
    for m in &from_b {
        assert!(a.fake.holds(G, m));
    }
    assert!(!b.fake.holds(G, &before_b_joined), "nothing from before B joined");
    assert!(!b.fake.holds(G, &below_b_floor), "nothing below B's floor");
    assert!(b.fake.groups.lock().unwrap()[G].given_up.is_empty(), "nothing below B's floor was even offered");
    assert_eq!(b.fake.groups.lock().unwrap()[G].held.len(), 5);

    let live = message(5, "live");
    assert_eq!(a.net.send(G, live.clone()), vec![members[1]]);
    eventually("the live message arrives", || b.fake.holds(G, &live)).await;
    a.net.shutdown().await.unwrap();
    b.net.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn doc_converges_by_diff() {
    let relay = relay().await;
    let keys = keys(2);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
    let service = service();
    let docs = [yrs::Doc::with_client_id(1), yrs::Doc::with_client_id(2)];
    docs[0].get_or_insert_text("text").insert(&mut docs[0].transact_mut(), 0, "hello world");
    let base = docs[0].transact().encode_state_as_update_v1(&Default::default());
    docs[1].transact_mut().apply_update(yrs::Update::decode_v1(&base).unwrap()).unwrap();
    // Apart: A only deletes, which leaves its state vector as it was; B only inserts.
    docs[0].get_or_insert_text("text").remove_range(&mut docs[0].transact_mut(), 0, 6);
    docs[1].get_or_insert_text("text").push(&mut docs[1].transact_mut(), "!");
    let [doc_a, doc_b] = docs;
    let group = |doc| Group { members: members.clone(), log: vec![b"e1".to_vec()], doc: Some(doc), ..Group::default() };
    let a = node(&relay, keys[0].clone(), Fake::new(&service).with(G, group(doc_a)), Options::default()).await;
    let b = node(&relay, keys[1].clone(), Fake::new(&service).with(G, group(doc_b)), Options::default()).await;
    a.net.dial(members[1], relay.url.clone()).await.unwrap();
    eventually("the docs converge", || a.fake.text(G) == "world!" && b.fake.text(G) == "world!").await;
    a.net.shutdown().await.unwrap();
    b.net.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn file_from_two_holders_one_cut_off() {
    let relay = relay().await;
    let keys = keys(3);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
    let service = service();
    let group = || Group { members: members.clone(), log: vec![b"e1".to_vec()], ..Group::default() };
    let (fake_a, fake_b, fake_c) = (Fake::new(&service).with(G, group()), Fake::new(&service).with(G, group()), Fake::new(&service).with(G, group()));
    let a = node(&relay, keys[0].clone(), fake_a.clone(), Options::default()).await;
    let b = node(&relay, keys[1].clone(), fake_b.clone(), Options::default()).await;
    // C would fetch only files up to 1 MiB unasked.
    let c = node(&relay, keys[2].clone(), fake_c.clone(), Options { file_limit: 1 << 20, ..Options::default() }).await;

    let plain: Vec<u8> = (0..16 << 20).map(|i: u32| (i % 251) as u8).collect();
    let link = a.net.add_file(std::io::Cursor::new(plain.clone())).await.unwrap();
    assert_eq!(link.size, plain.len() as u64);
    // B fetches it from A first.
    b.net.dial(members[0], relay.url.clone()).await.unwrap();
    for fake in [&fake_a, &fake_b, &fake_c] {
        fake.groups.lock().unwrap().get_mut(G).unwrap().files.push(link.clone());
    }
    b.net.fetch(G, &link).await.unwrap();

    c.net.dial(members[0], relay.url.clone()).await.unwrap();
    c.net.dial(members[1], relay.url.clone()).await.unwrap();
    assert_eq!(c.net.held(link.hash).await.unwrap(), 0, "16 MiB is over C's limit, so C waits to be asked");
    // B stops counting C as a member partway through the transfer: after about 3 MiB, at 16 KiB a check.
    *fake_b.cut.lock().unwrap() = Some((members[2], 200));
    c.net.fetch(G, &link).await.unwrap();
    assert_eq!(*fake_b.cut.lock().unwrap(), Some((members[2], 0)), "B cut C off mid-transfer");
    let mut out = Vec::new();
    c.net.read_file(&link, &mut out).await.unwrap();
    assert!(out == plain);
    for node in [&a, &b, &c] {
        node.net.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn small_files_are_fetched_unasked() {
    let relay = relay().await;
    let keys = keys(2);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
    let service = service();
    let group = || Group { members: members.clone(), log: vec![b"e1".to_vec()], ..Group::default() };
    let a = node(&relay, keys[0].clone(), Fake::new(&service).with(G, group()), Options::default()).await;
    let link = a.net.add_file(std::io::Cursor::new(b"attachment".to_vec())).await.unwrap();
    a.fake.groups.lock().unwrap().get_mut(G).unwrap().files.push(link.clone());
    let mut b = node(&relay, keys[1].clone(), Fake::new(&service).with(G, group()), Options::default()).await;
    b.fake.groups.lock().unwrap().get_mut(G).unwrap().files.push(link.clone());
    b.net.dial(members[0], relay.url.clone()).await.unwrap();
    b.until(|e| *e == Event::Fetched(link.hash)).await;
    let mut out = Vec::new();
    b.net.read_file(&link, &mut out).await.unwrap();
    assert_eq!(out, b"attachment");
    assert_eq!(a.net.holders(G, link.hash).await, vec![members[1]]);
    a.net.shutdown().await.unwrap();
    b.net.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_and_join() {
    let relay = relay().await;
    let keys = keys(2);
    let service = service();
    let inviter = node(&relay, keys[0].clone(), Fake::new(&service), Options::default()).await;
    let joiner = node(&relay, keys[1].clone(), Fake::new(&service), Options { relay_only: true, ..Options::default() }).await;
    let invite = |secret| Invite { device: false, key: *keys[0].public().as_bytes(), secret, relay: Some(relay.url.to_string()) };
    let request = || Joiner::Member { key_package: lmk_proto::Bytes(b"kp".to_vec()) };

    let Answer::Ok(admitted) = joiner.net.redeem(&invite(SECRET), request()).await.unwrap() else { panic!("refused") };
    assert_eq!((admitted.welcome.0.as_slice(), admitted.position), (&b"welcome"[..], 3));
    let refused = joiner.net.redeem(&invite([0; 16]), request()).await.unwrap();
    assert_eq!(refused, Answer::Refused { refused: "unknown secret".into() });
    let joined = joiner.net.join(keys[0].public(), relay.url.clone(), b"open", b"kp".to_vec()).await.unwrap();
    assert!(matches!(joined, Answer::Ok(admitted) if admitted.welcome.0 == b"open"));
    inviter.net.shutdown().await.unwrap();
    joiner.net.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_of_one_device_find_each_other() {
    let relay = relay().await;
    let home = tempfile::tempdir().unwrap();
    let keys = keys(2);
    let options = || Options { home: Some(home.path().to_path_buf()), ..Options::default() };
    let service = service();
    let a = node(&relay, keys[0].clone(), Fake::new(&service), options()).await;
    let mut b = node(&relay, keys[1].clone(), Fake::new(&service), options()).await;
    let published = home.path().join("addresses").join(format!("{}.json", keys[0].public()));
    eventually("A publishes its addresses", || published.exists()).await;
    // A relay that is not there: only the published addresses lead to A.
    let nowhere: RelayUrl = "https://localhost:1".parse().unwrap();
    b.net.dial(keys[0].public(), nowhere).await.unwrap();
    b.until(|e| *e == Event::Connected(keys[0].public())).await;
    a.net.shutdown().await.unwrap();
    assert!(!published.exists());
    b.net.shutdown().await.unwrap();
}

#[test]
fn builds_for_the_browser() {
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/wasm-check");
    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "lmk-net", "--target", "wasm32-unknown-unknown", "--target-dir"])
        .arg(target)
        .status()
        .unwrap();
    assert!(status.success());
}
