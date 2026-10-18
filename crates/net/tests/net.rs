mod common;

use std::time::{Duration, Instant};

use common::*;
use lmk_net::Event;
use lmk_proto::{
    Answer, Bytes, frame,
    peer::{Frame, Join, Seqs},
    ranges::Ranges,
};

const G: &[u8] = b"group";

fn want(n: u64) -> Frame {
    let wants = vec![Seqs { key: Bytes(vec![1]), joined: 0, seqs: Ranges::range(n, n) }];
    Frame::Want { group: Bytes(G.to_vec()), epoch: 0, wants }
}

/// Each side of a new connection is told of it, then of the frames on its `peer` stream in order; frames of either
/// side's groups pass whatever the gate, which is the node's; a closed connection is told too.
#[tokio::test(flavor = "multi_thread")]
async fn frames_go_both_ways_in_order() {
    let relay = relay().await;
    let keys = keys(2);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
    let mut a = node(&relay, keys[0].clone(), false).await;
    let mut b = node(&relay, keys[1].clone(), true).await;
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
    let mut a = node(&relay, keys[0].clone(), false).await;
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

/// Each request to be admitted goes on a stream of its own, answered there.
#[tokio::test(flavor = "multi_thread")]
async fn requests_to_be_admitted_are_answered_each_on_its_stream() {
    let relay = relay().await;
    let keys = keys(2);
    let member = node(&relay, keys[0].clone(), false).await;
    let joiner = node(&relay, keys[1].clone(), true).await;
    let join = |secret: [u8; 16]| Join { secret: Bytes::from(secret), key_package: Bytes(b"kp".to_vec()) };
    let ask = |join| joiner.net.join(keys[0].public(), vec![relay.url.clone()], Box::pin(std::future::ready(vec![])), join);
    joiner.net.dial(keys[0].public(), vec![relay.url.clone()], Box::pin(std::future::ready(vec![]))).await.unwrap();
    let (invited, refused) = tokio::join!(ask(join(SECRET)), ask(join([0; 16])));
    assert!(matches!(invited.unwrap(), Answer::Ok(admitted) if admitted.commit.0 == b"invited"));
    assert_eq!(refused.unwrap(), Answer::Refused { refused: "unknown secret".into() });
    member.net.shutdown().await.unwrap();
    joiner.net.shutdown().await.unwrap();
}

/// A peer on relay R2, dialed with a stale hint on R1 and the fallback [R1, R2]: connected in about 2 s, by one
/// connection that is never replaced.
#[tokio::test(flavor = "multi_thread")]
async fn stale_hint_reaches_peer_through_fallback() {
    let rs = relays(3).await;
    let keys = keys(2);
    let mut a = node(&rs[0], keys[0].clone(), false).await;
    let mut b = node(&rs[2], keys[1].clone(), false).await;
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
    let a = node(&rs[0], keys[0].clone(), false).await;
    let _b = node(&rs[0], keys[1].clone(), false).await;
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
    let a = node(&rs[0], keys[0].clone(), false).await;
    let started = Instant::now();
    let dialed = a.net.dial(keys[2].public(), vec![rs[1].url.clone()], Box::pin(std::future::ready(vec![rs[0].url.clone(), rs[1].url.clone()]))).await;
    let took = started.elapsed();
    assert!(dialed.is_err());
    assert!(took >= Duration::from_secs(30) && took < Duration::from_secs(40), "gave up after {took:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn home_relay_is_reported() {
    let relay = relay().await;
    let mut a = node(&relay, keys(1)[0].clone(), false).await;
    assert_eq!(a.until(|event| matches!(event, Event::Home(_))).await, Event::Home(relay.url.clone()));
}
