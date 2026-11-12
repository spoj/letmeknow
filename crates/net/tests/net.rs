mod common;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

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
    a.net.dial(members[1], vec![relay.url.clone()]).await.unwrap();
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

/// Two peers that each queue more at once than a stream's window takes read while they write, so neither stalls.
#[tokio::test(flavor = "multi_thread")]
async fn two_peers_writing_much_at_once_do_not_stall() {
    let relay = relay().await;
    let keys = keys(2);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
    let mut a = node(&relay, keys[0].clone(), true).await;
    let mut b = node(&relay, keys[1].clone(), true).await;
    a.net.dial(members[1], vec![relay.url.clone()]).await.unwrap();
    a.until(|e| matches!(e, Event::Connected(..))).await;
    b.until(|e| matches!(e, Event::Connected(..))).await;
    let big = Frame::Held { group: Bytes(G.to_vec()), items: vec![Bytes(vec![7; 10 << 20])], answers: None };
    let (a_big, b_big) = (big.clone(), big.clone());
    for (fa, fb) in [(want(1), want(1)), (want(2), want(2)), (a_big, b_big)] {
        assert!(a.net.frame(members[1], fa));
        assert!(b.net.frame(members[0], fb));
    }
    let frames = [want(1), want(2), big];
    tokio::join!(
        async {
            for f in &frames {
                assert!(matches!(a.until(|e| matches!(e, Event::Frame(..))).await, Event::Frame(from, got) if from == members[1] && &got == f));
            }
        },
        async {
            for f in &frames {
                assert!(matches!(b.until(|e| matches!(e, Event::Frame(..))).await, Event::Frame(from, got) if from == members[0] && &got == f));
            }
        },
    );
    a.net.shutdown().await.unwrap();
    b.net.shutdown().await.unwrap();
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

/// Bytes that come on a peer's stream are told before their frame is whole, which through a slow relay takes long.
#[tokio::test(flavor = "multi_thread")]
async fn bytes_coming_are_told_before_their_frame_is_whole() {
    let relay = relay().await;
    let keys = keys(2);
    let mut a = node(&relay, keys[0].clone(), false).await;
    let peer = lmk_net::builder([relay.url.clone()]).secret_key(keys[1].clone()).ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([relay.cert.clone()]));
    let peer = peer.bind().await.unwrap();
    let conn = peer.connect(iroh::EndpointAddr::new(keys[0].public()).with_relay_url(relay.url.clone()), frame::ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    frame::write(&mut send, &frame::Open { stream: frame::Stream::Peer }).await.unwrap();
    frame::write(&mut send, &want(1)).await.unwrap();
    let from = keys[1].public();
    assert_eq!(a.until(|e| matches!(e, Event::Frame(..))).await, Event::Frame(from, want(1)));
    let bytes = frame::encode(&want(2));
    send.write_all(&bytes[..8]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    send.write_all(&bytes[8..16]).await.unwrap();
    assert_eq!(a.until(|e| matches!(e, Event::Arriving(..))).await, Event::Arriving(from));
    send.write_all(&bytes[16..]).await.unwrap();
    assert_eq!(a.until(|e| matches!(e, Event::Frame(..))).await, Event::Frame(from, want(2)));
    a.net.shutdown().await.unwrap();
}

/// A frame larger than its reader takes is left out, so what is queued after it arrives and the connection stays.
#[tokio::test(flavor = "multi_thread")]
async fn a_frame_past_max_frame_is_left_out() {
    let relay = relay().await;
    let keys = keys(2);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
    let mut a = node(&relay, keys[0].clone(), false).await;
    let mut b = node(&relay, keys[1].clone(), true).await;
    a.net.dial(members[1], vec![relay.url.clone()]).await.unwrap();
    assert_eq!(a.until(|e| matches!(e, Event::Connected(..))).await, Event::Connected(members[1], true));
    assert_eq!(b.until(|e| matches!(e, Event::Connected(..))).await, Event::Connected(members[0], false));
    let oversized = Frame::Held { group: Bytes(G.to_vec()), items: vec![Bytes(vec![7; 25 << 20])], answers: None };
    assert!(frame::encode(&oversized).len() - 4 > frame::MAX_FRAME as usize);
    assert!(a.net.frame(members[1], oversized));
    assert!(a.net.frame(members[1], want(1)));
    assert_eq!(b.until(|e| matches!(e, Event::Frame(..))).await, Event::Frame(members[0], want(1)));
    assert!(b.net.frame(members[0], want(2)));
    assert_eq!(a.until(|e| matches!(e, Event::Frame(..))).await, Event::Frame(members[1], want(2)));
    a.net.shutdown().await.unwrap();
    b.net.shutdown().await.unwrap();
}

/// A frame past `MAX_ASK` from a peer that serves no group is not read: the connection closes with it, as it is a stranger's.
#[tokio::test(flavor = "multi_thread")]
async fn a_frame_past_max_ask_from_a_peer_served_no_group_closes_the_connection() {
    let relay = relay().await;
    let keys = keys(2);
    let members: Vec<_> = keys.iter().map(|k| k.public()).collect();
    let mut a = node(&relay, keys[0].clone(), false).await;
    let mut b = node_with(&relay, keys[1].clone(), true, Arc::new(NoGroups)).await;
    a.net.dial(members[1], vec![relay.url.clone()]).await.unwrap();
    a.until(|e| matches!(e, Event::Connected(..))).await;
    b.until(|e| matches!(e, Event::Connected(..))).await;
    let large = Frame::Held { group: Bytes(G.to_vec()), items: vec![Bytes(vec![7; 100 << 10])], answers: None };
    assert!(frame::encode(&large).len() - 4 > frame::MAX_ASK as usize);
    assert!(a.net.frame(members[1], large));
    assert_eq!(b.until(|e| matches!(e, Event::Frame(..) | Event::Disconnected(..))).await, Event::Disconnected(members[0]));
    a.net.shutdown().await.unwrap();
    b.net.shutdown().await.unwrap();
}

/// A connection is counted before it opens any stream, and one that only asks for admission is closed as a stranger.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_without_a_peer_stream_is_counted_and_closed() {
    use lmk_net::peers::{Out, Peers, STRANGER};

    let relay = relay().await;
    let keys = keys(2);
    let mut member = node(&relay, keys[0].clone(), false).await;
    let joiner = lmk_net::builder([relay.url.clone()]).secret_key(keys[1].clone()).ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([relay.cert.clone()]));
    let joiner = joiner.bind().await.unwrap();
    let conn = joiner.connect(iroh::EndpointAddr::new(keys[0].public()).with_relay_url(relay.url.clone()), frame::ALPN).await.unwrap();
    let connected = tokio::time::timeout(WAIT, member.events.recv()).await.expect("the connection was counted").unwrap();
    assert_eq!(connected, Event::Connected(keys[1].public(), false));
    let mut peers = Peers::new(0, *keys[0].public().as_bytes());
    peers.connect(*keys[1].public().as_bytes(), Default::default(), false, 0);
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    frame::write(&mut send, &frame::Open { stream: frame::Stream::Admission }).await.unwrap();
    frame::write(&mut send, &Join { secret: Bytes::from(SECRET), key_package: Bytes(b"kp".to_vec()) }).await.unwrap();
    let answer: Answer<lmk_proto::peer::Admitted> = frame::read(&mut recv).await.unwrap();
    assert!(matches!(answer, Answer::Ok(_)));
    assert_eq!(peers.poll(STRANGER), vec![Out::Close(*keys[1].public().as_bytes())]);
    member.net.close(keys[1].public());
    assert_eq!(tokio::time::timeout(WAIT, member.events.recv()).await.unwrap().unwrap(), Event::Disconnected(keys[1].public()));
    tokio::time::timeout(WAIT, conn.closed()).await.expect("the stranger's connection closed");
    member.net.shutdown().await.unwrap();
}

/// A connection whose `peer` stream does not open within `ASK`, whether the peer dialed in and opened none or refused
/// the dialer's, is closed, and what was queued for it goes.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_whose_peer_stream_never_opens_is_closed() {
    let relay = relay().await;
    let keys = keys(3);
    let mut a = node(&relay, keys[0].clone(), false).await;
    let inbound = lmk_net::builder([relay.url.clone()])
        .secret_key(keys[1].clone())
        .ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([relay.cert.clone()]))
        .bind()
        .await
        .unwrap();
    let in_conn = inbound.connect(iroh::EndpointAddr::new(keys[0].public()).with_relay_url(relay.url.clone()), frame::ALPN).await.unwrap();
    let no_streams = iroh::endpoint::QuicTransportConfig::builder().max_concurrent_bidi_streams(0u32.into()).build();
    let outbound = lmk_net::builder([relay.url.clone()])
        .secret_key(keys[2].clone())
        .ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([relay.cert.clone()]))
        .alpns(vec![frame::ALPN.to_vec()])
        .transport_config(no_streams)
        .bind()
        .await
        .unwrap();
    tokio::time::timeout(WAIT, outbound.online()).await.expect("online");
    let accepting = tokio::spawn({
        let outbound = outbound.clone();
        async move { outbound.accept().await.unwrap().await.unwrap() }
    });
    a.net.dial(keys[2].public(), vec![relay.url.clone()]).await.unwrap();
    let out_conn = accepting.await.unwrap();
    for _ in 0..2 {
        a.until(|e| matches!(e, Event::Connected(..))).await;
    }
    for peer in [keys[1].public(), keys[2].public()] {
        assert!(a.net.frame(peer, want(1)));
    }
    let closed = tokio::time::timeout(Duration::from_secs(40), async {
        let first = a.events.recv().await.unwrap();
        let second = a.events.recv().await.unwrap();
        (first, second)
    })
    .await
    .expect("both connections without a peer stream closed");
    for peer in [keys[1].public(), keys[2].public()] {
        assert!(closed.0 == Event::Disconnected(peer) || closed.1 == Event::Disconnected(peer));
        assert!(!a.net.frame(peer, want(2)), "the closed connection keeps no queued frames");
    }
    assert!(matches!(in_conn.closed().await, iroh::endpoint::ConnectionError::ApplicationClosed(_)));
    assert!(matches!(out_conn.closed().await, iroh::endpoint::ConnectionError::ApplicationClosed(_)));
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
    let ask = |join| joiner.net.join(keys[0].public(), vec![relay.url.clone()], join);
    joiner.net.dial(keys[0].public(), vec![relay.url.clone()]).await.unwrap();
    let (invited, refused) = tokio::join!(ask(join(SECRET)), ask(join([0; 16])));
    assert!(matches!(invited.unwrap(), Answer::Ok(admitted) if admitted.commit.0 == b"invited"));
    assert_eq!(refused.unwrap(), Answer::Refused { refused: "unknown secret".into() });
    member.net.shutdown().await.unwrap();
    joiner.net.shutdown().await.unwrap();
}

/// A dial to a key nobody holds gives up when iroh's handshake does, about 30 s after it starts, as long as a peer that
/// is starting up may take to come online.
#[tokio::test(flavor = "multi_thread")]
async fn dial_to_absent_key_gives_up() {
    let relay = relay().await;
    let keys = keys(2);
    let a = node(&relay, keys[0].clone(), false).await;
    let started = Instant::now();
    let dialed = a.net.dial(keys[1].public(), vec![relay.url.clone()]).await;
    let took = started.elapsed();
    assert!(dialed.is_err());
    assert!(took >= Duration::from_secs(28) && took < Duration::from_secs(40), "gave up after {took:?}");
}

/// A peer whose frames the node does not take yet waits to send more: they are not kept for it without bound.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_sends_faster_than_the_node_takes_waits() {
    const FRAMES: usize = 200;
    let relay = relay().await;
    let keys = keys(2);
    let mut a = node(&relay, keys[0].clone(), false).await;
    let peer = lmk_net::builder([relay.url.clone()]).secret_key(keys[1].clone()).ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([relay.cert.clone()]));
    let peer = peer.bind().await.unwrap();
    let conn = peer.connect(iroh::EndpointAddr::new(keys[0].public()).with_relay_url(relay.url.clone()), frame::ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    frame::write(&mut send, &frame::Open { stream: frame::Stream::Peer }).await.unwrap();
    let held = Frame::Held { group: Bytes(G.to_vec()), items: vec![Bytes(vec![0; 256 << 10])], answers: None };
    let mut sending = tokio::spawn(async move {
        for _ in 0..FRAMES {
            frame::write(&mut send, &held).await.unwrap();
        }
        send
    });
    assert!(tokio::time::timeout(Duration::from_secs(10), &mut sending).await.is_err(), "the peer waits while the node takes nothing");
    for _ in 0..FRAMES {
        a.until(|e| matches!(e, Event::Frame(..))).await;
    }
    tokio::time::timeout(WAIT, sending).await.expect("the peer sent the rest").unwrap();
    a.net.shutdown().await.unwrap();
}

/// A peer that keeps its connection and reads nothing is closed two minutes after the write to it stopped moving, and
/// what was queued for it goes.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_does_not_read_is_closed() {
    let relay = relay().await;
    let keys = keys(2);
    let mut a = node(&relay, keys[0].clone(), false).await;
    let peer = lmk_net::builder([relay.url.clone()]).secret_key(keys[1].clone()).ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([relay.cert.clone()])).clear_ip_transports();
    let peer = peer.bind().await.unwrap();
    let conn = peer.connect(iroh::EndpointAddr::new(keys[0].public()).with_relay_url(relay.url.clone()), frame::ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    frame::write(&mut send, &frame::Open { stream: frame::Stream::Peer }).await.unwrap();
    a.until(|e| matches!(e, Event::Connected(..))).await;
    let held = Frame::Held { group: Bytes(G.to_vec()), items: vec![Bytes(vec![0; 256 << 10])], answers: None };
    for _ in 0..200 {
        assert!(a.net.frame(keys[1].public(), held.clone()));
    }
    let disconnected = tokio::time::timeout(Duration::from_secs(120) + WAIT, a.events.recv()).await.expect("the stalled writer closed the connection").unwrap();
    assert_eq!(disconnected, Event::Disconnected(keys[1].public()));
    assert!(matches!(conn.closed().await, iroh::endpoint::ConnectionError::ApplicationClosed(_)));
    assert!(!a.net.frame(keys[1].public(), want(1)), "the closed connection keeps no queued frames");
    a.net.shutdown().await.unwrap();
}

/// A stream whose opening frame is not sent within `ASK` is dropped, so a stream opened after it is still answered.
#[tokio::test(flavor = "multi_thread")]
async fn a_stream_that_never_sends_open_ends_its_wait() {
    use tokio::io::AsyncWriteExt;
    let relay = relay().await;
    let keys = keys(2);
    let member = node(&relay, keys[0].clone(), false).await;
    let peer = lmk_net::builder([relay.url.clone()]).secret_key(keys[1].clone()).ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([relay.cert.clone()]));
    let peer = peer.bind().await.unwrap();
    let conn = peer.connect(iroh::EndpointAddr::new(keys[0].public()).with_relay_url(relay.url.clone()), frame::ALPN).await.unwrap();
    let (mut peer_send, _peer_recv) = conn.open_bi().await.unwrap();
    frame::write(&mut peer_send, &frame::Open { stream: frame::Stream::Peer }).await.unwrap();
    let (mut stalled_send, _stalled_recv) = conn.open_bi().await.unwrap();
    stalled_send.write_u8(0).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    frame::write(&mut send, &frame::Open { stream: frame::Stream::Admission }).await.unwrap();
    frame::write(&mut send, &Join { secret: Bytes::from(SECRET), key_package: Bytes(b"kp".to_vec()) }).await.unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(40), frame::read::<Answer<lmk_proto::peer::Admitted>, _>(&mut recv))
        .await
        .expect("the stalled stream's wait ended")
        .unwrap();
    assert!(matches!(answer, Answer::Ok(_)));
    member.net.shutdown().await.unwrap();
}

/// A joiner's request is small: a stream that announces a larger one is dropped, not read.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_to_be_admitted_that_is_too_large_is_dropped() {
    use tokio::io::AsyncWriteExt;
    let relay = relay().await;
    let keys = keys(2);
    let member = node(&relay, keys[0].clone(), false).await;
    let joiner = lmk_net::builder([relay.url.clone()]).secret_key(keys[1].clone()).ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([relay.cert.clone()]));
    let joiner = joiner.bind().await.unwrap();
    let conn = joiner.connect(iroh::EndpointAddr::new(keys[0].public()).with_relay_url(relay.url.clone()), frame::ALPN).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    frame::write(&mut send, &frame::Open { stream: frame::Stream::Admission }).await.unwrap();
    send.write_u32(frame::MAX_ASK + 1).await.unwrap();
    let answer = tokio::time::timeout(WAIT, frame::read::<Answer<lmk_proto::peer::Admitted>, _>(&mut recv)).await.expect("the stream ended");
    assert!(answer.is_err());
    member.net.shutdown().await.unwrap();
}
