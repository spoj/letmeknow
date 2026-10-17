mod common;

use std::time::{Duration, Instant};

use common::*;
use iroh::RelayUrl;
use lmk_net::Event;
use n0_future::StreamExt;
use lmk_proto::{
    Answer, Bytes, frame,
    peer::{Frame, Join, Seqs},
    ranges::Ranges,
};

const G: &[u8] = b"group";

fn want(n: u64) -> Frame {
    let wants = vec![Seqs { key: Bytes(vec![1]), joined: 0, seqs: Ranges::range(n, n) }];
    Frame::Want { group: Bytes(G.to_vec()), epoch: 0, wants, ids: Vec::new() }
}

/// Each side of a new connection is told of it, then of the frames on its `peer` stream in order; frames of either
/// side's groups pass whatever the gate, which is the node's; a closed connection is told too.
#[tokio::test(flavor = "multi_thread")]
async fn frames_go_both_ways_in_order() {
    let relay = relay().await;
    let keys = keys(2);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
    let mut a = node(&relay, keys[0].clone(), Fake::new(), Options::default()).await;
    let mut b = node(&relay, keys[1].clone(), Fake::new(), Options { relay_only: true, ..Options::default() }).await;
    a.net.dial(members[1], vec![relay.url.clone()], Box::pin(std::future::ready(vec![]))).await.unwrap();
    assert_eq!(a.until(|e| matches!(e, Event::Connected(..))).await, Event::Connected(members[1], true));
    assert_eq!(b.until(|e| matches!(e, Event::Connected(..))).await, Event::Connected(members[0], false));
    for n in 1..=3 {
        assert!(a.net.frame(members[1], want(n)));
    }
    for n in 1..=3 {
        assert_eq!(b.until(|e| matches!(e, Event::Frame(..))).await, Event::Frame(members[0], want(n)));
    }
    assert!(b.net.frame(members[0], want(4)));
    assert_eq!(a.until(|e| matches!(e, Event::Frame(..))).await, Event::Frame(members[1], want(4)));
    b.net.shutdown().await.unwrap();
    a.until(|e| *e == Event::Disconnected(members[1])).await;
    assert!(!a.net.frame(members[1], want(5)), "no frame goes to a peer not connected");
    a.net.shutdown().await.unwrap();
}

/// A frame this session does not know, as a newer letmeknow may send, is skipped, and the stream stays up.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_frame_is_skipped() {
    let relay = relay().await;
    let keys = keys(2);
    let mut a = node(&relay, keys[0].clone(), Fake::new(), Options::default()).await;
    let peer = lmk_net::builder([relay.url.clone()]).secret_key(keys[1].clone()).ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([relay.cert.clone()]));
    let peer = peer.bind().await.unwrap();
    let conn = peer.connect(iroh::EndpointAddr::new(keys[0].public()).with_relay_url(relay.url.clone()), frame::ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    frame::write(&mut send, &frame::Open { stream: frame::Stream::Peer }).await.unwrap();
    frame::write(&mut send, &want(1)).await.unwrap();
    frame::write(&mut send, &serde_json::json!({"newer": {"group": "Zw"}})).await.unwrap();
    frame::write(&mut send, &want(2)).await.unwrap();
    let from = keys[1].public();
    assert_eq!(a.until(|e| matches!(e, Event::Frame(..))).await, Event::Frame(from, want(1)));
    assert_eq!(a.until(|e| matches!(e, Event::Frame(..))).await, Event::Frame(from, want(2)));
    a.net.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn file_from_two_holders_one_cut_off() {
    let relay = relay().await;
    let keys = keys(3);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
        let group = || Group { members: members.clone(), ..Group::default() };
    let (fake_a, fake_b, fake_c) = (Fake::new().with(G, group()), Fake::new().with(G, group()), Fake::new().with(G, group()));
    let a = node(&relay, keys[0].clone(), fake_a.clone(), Options::default()).await;
    let b = node(&relay, keys[1].clone(), fake_b.clone(), Options::default()).await;
    // C goes through the relay, and would fetch only files up to 1 MiB unasked.
    let c = node(&relay, keys[2].clone(), fake_c.clone(), Options { file_limit: 1 << 20, relay_only: true, ..Options::default() }).await;

    let plain: Vec<u8> = (0..16 << 20).map(|i: u32| (i % 251) as u8).collect();
    let link = a.net.add_file(std::io::Cursor::new(plain.clone())).await.unwrap();
    assert_eq!(link.size, plain.len() as u64);
    // B fetches it from A first.
    b.net.dial(members[0], vec![relay.url.clone()], Box::pin(std::future::ready(vec![]))).await.unwrap();
    for fake in [&fake_a, &fake_b, &fake_c] {
        fake.groups.lock().unwrap().get_mut(G).unwrap().files.push(link.clone());
    }
    b.net.fetch(G, &link).await.unwrap();

    c.net.dial(members[1], vec![relay.url.clone()], Box::pin(std::future::ready(vec![]))).await.unwrap();
    assert_eq!(c.net.held(link.hash).await.unwrap(), 0, "16 MiB is over C's limit, so C waits to be asked");
    // B, the one holder C knows, stops counting C as a member partway through the transfer: after about 3 MiB, at
    // 16 KiB a check. C then finds A, and the same fetch takes the rest from it.
    *fake_b.cut.lock().unwrap() = Some((members[2], 200));
    let resume = async {
        eventually("B cut C off mid-transfer", || *fake_b.cut.lock().unwrap() == Some((members[2], 0))).await;
        assert!(c.net.held(link.hash).await.unwrap() > 0);
        c.net.dial(members[0], vec![relay.url.clone()], Box::pin(std::future::ready(vec![]))).await.unwrap();
        c.net.fetch(G, &link).await.unwrap();
    };
    let (fetched, ()) = tokio::join!(c.net.fetch(G, &link), resume);
    fetched.unwrap();
    let mut out = Vec::new();
    c.net.read_file(&link, &mut out).await.unwrap();
    assert!(out == plain);
    for node in [&a, &b, &c] {
        node.net.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn small_files_are_fetched_when_wanted() {
    let relay = relay().await;
    let keys = keys(2);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
        let group = || Group { members: members.clone(), ..Group::default() };
    let a = node(&relay, keys[0].clone(), Fake::new().with(G, group()), Options::default()).await;
    let link = a.net.add_file(std::io::Cursor::new(b"attachment".to_vec())).await.unwrap();
    a.fake.groups.lock().unwrap().get_mut(G).unwrap().files.push(link.clone());
    let mut b = node(&relay, keys[1].clone(), Fake::new().with(G, group()), Options::default()).await;
    b.fake.groups.lock().unwrap().get_mut(G).unwrap().files.push(link.clone());
    b.net.dial(members[0], vec![relay.url.clone()], Box::pin(std::future::ready(vec![]))).await.unwrap();
    b.net.want_files(members[0], G);
    b.until(|e| *e == Event::Fetched(link.hash)).await;
    let mut out = Vec::new();
    b.net.read_file(&link, &mut out).await.unwrap();
    assert_eq!(out, b"attachment");
    assert_eq!(a.net.holders(G, link.hash).collect::<Vec<_>>().await, vec![members[1]]);
    a.net.shutdown().await.unwrap();
    b.net.shutdown().await.unwrap();
}

/// Each request to be admitted goes on a stream of its own, answered there.
#[tokio::test(flavor = "multi_thread")]
async fn requests_to_be_admitted_are_answered_each_on_its_stream() {
    let relay = relay().await;
    let keys = keys(2);
    let member = node(&relay, keys[0].clone(), Fake::new(), Options::default()).await;
    let joiner = node(&relay, keys[1].clone(), Fake::new(), Options { relay_only: true, ..Options::default() }).await;
    let join = |secret: [u8; 16]| Join { secret: Bytes::from(secret), key_package: Bytes(b"kp".to_vec()) };
    let ask = |join| joiner.net.join(keys[0].public(), vec![relay.url.clone()], Box::pin(std::future::ready(vec![])), join);
    joiner.net.dial(keys[0].public(), vec![relay.url.clone()], Box::pin(std::future::ready(vec![]))).await.unwrap();
    let (invited, refused) = tokio::join!(ask(join(SECRET)), ask(join([0; 16])));
    assert!(matches!(invited.unwrap(), Answer::Ok(admitted) if admitted.commit.0 == b"invited"));
    assert_eq!(refused.unwrap(), Answer::Refused { refused: "unknown secret".into() });
    member.net.shutdown().await.unwrap();
    joiner.net.shutdown().await.unwrap();
}

/// Sessions of one device reach each other by the addresses they publish in `LETMEKNOW_HOME`, with no relay.
#[tokio::test(flavor = "multi_thread")]
async fn sessions_of_one_device_find_each_other() {
    let relay = relay().await;
    let home = tempfile::tempdir().unwrap();
    let keys = keys(2);
    let options = || Options { home: Some(home.path().to_path_buf()), ..Options::default() };
    let a = node(&relay, keys[0].clone(), Fake::new(), options()).await;
    let b = node(&relay, keys[1].clone(), Fake::new(), options()).await;
    let published = home.path().join("addresses").join(format!("{}.json", keys[0].public()));
    let addresses = || std::fs::read(&published).ok().and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    eventually("A publishes its addresses", || addresses().is_some_and(|a| a["addrs"].as_array().is_some_and(|addrs| !addrs.is_empty()))).await;
    // A relay that is not there: only the published addresses lead to A.
    let nowhere: RelayUrl = "https://localhost:1".parse().unwrap();
    b.net.dial(keys[0].public(), vec![nowhere], Box::pin(std::future::ready(vec![]))).await.unwrap();
    assert_eq!(b.net.connected(), [keys[0].public()]);
    a.net.shutdown().await.unwrap();
    assert!(!published.exists());
    b.net.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn files_no_group_links_are_deleted() {
    let relay = relay().await;
    let keys = keys(1);
    let fake = Fake::new().with(G, Group { members: vec![keys[0].public()], ..Group::default() });
    let options = Options { collect: std::time::Duration::from_millis(100), ..Options::default() };
    let a = node(&relay, keys[0].clone(), fake, options).await;
    let linked = a.net.add_file(std::io::Cursor::new(b"linked".to_vec())).await.unwrap();
    let unlinked = a.net.add_file(std::io::Cursor::new(b"unlinked".to_vec())).await.unwrap();
    a.fake.groups.lock().unwrap().get_mut(G).unwrap().files.push(linked.clone());
    tokio::time::timeout(WAIT, async {
        while a.net.has(unlinked.hash).await.unwrap() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the file no group links is deleted");
    assert!(a.net.has(linked.hash).await.unwrap());
    a.fake.groups.lock().unwrap().get_mut(G).unwrap().files.clear();
    tokio::time::timeout(WAIT, async {
        while a.net.has(linked.hash).await.unwrap() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("and so is one no longer linked");
}

/// A peer on relay R2, dialed with a stale hint on R1 and the fallback [R1, R2]: connected in about 2 s, by one
/// connection that is never replaced.
#[tokio::test(flavor = "multi_thread")]
async fn stale_hint_reaches_peer_through_fallback() {
    let rs = relays(3).await;
    let keys = keys(2);
    let mut a = node(&rs[0], keys[0].clone(), Fake::new(), Options::default()).await;
    let mut b = node(&rs[2], keys[1].clone(), Fake::new(), Options::default()).await;
    let started = Instant::now();
    a.net.dial(keys[1].public(), vec![rs[1].url.clone()], Box::pin(std::future::ready(vec![rs[1].url.clone(), rs[2].url.clone()]))).await.unwrap();
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(2) && took < Duration::from_secs(4), "connected after {took:?}");
    assert_eq!(a.net.connected(), [keys[1].public()]);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(links(&mut a.events), [Event::Connected(keys[1].public(), true)]);
    assert_eq!(links(&mut b.events), [Event::Connected(keys[0].public(), false)]);
}

/// A fallback that takes long does not hold back a dial the hint reaches: the hint is dialed at once.
#[tokio::test(flavor = "multi_thread")]
async fn slow_fallback_does_not_hold_back_the_hint() {
    let rs = relays(1).await;
    let keys = keys(2);
    let a = node(&rs[0], keys[0].clone(), Fake::new(), Options::default()).await;
    let _b = node(&rs[0], keys[1].clone(), Fake::new(), Options::default()).await;
    let started = Instant::now();
    let slow = async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        vec![]
    };
    a.net.dial(keys[1].public(), vec![rs[0].url.clone()], Box::pin(slow)).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(2), "connected after {:?}", started.elapsed());
}

/// The connection events queued so far.
fn links(events: &mut tokio::sync::mpsc::UnboundedReceiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| events.try_recv().ok()).filter(|event| matches!(event, Event::Connected(..) | Event::Disconnected(_))).collect()
}

/// A dial to a key nobody holds gives up when iroh's handshake does, about 32 s after it starts: 2 s at the hint, then
/// 30 s at all relays, as long as a peer that is starting up may take to come online.
#[tokio::test(flavor = "multi_thread")]
async fn dial_to_absent_key_gives_up() {
    let rs = relays(2).await;
    let keys = keys(3);
    let a = node(&rs[0], keys[0].clone(), Fake::new(), Options::default()).await;
    let started = Instant::now();
    let dialed = a.net.dial(keys[2].public(), vec![rs[1].url.clone()], Box::pin(std::future::ready(vec![rs[0].url.clone(), rs[1].url.clone()]))).await;
    let took = started.elapsed();
    assert!(dialed.is_err());
    assert!(took >= Duration::from_secs(30) && took < Duration::from_secs(40), "gave up after {took:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn home_relay_is_reported() {
    let relay = relay().await;
    let mut a = node(&relay, keys(1)[0].clone(), Fake::new(), Options::default()).await;
    assert_eq!(a.until(|event| matches!(event, Event::Home(_))).await, Event::Home(relay.url.clone()));
}
