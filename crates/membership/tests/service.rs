use std::{net::Ipv4Addr, sync::Mutex, time::Duration};

use anyhow::Result;
use iroh::{Endpoint, RelayMode, SecretKey, endpoint::{Connection, presets}, protocol::{AcceptError, ProtocolHandler, Router}};
use lmk_membership::{Frontier, InvalidProof, Refused, client::ServeClient, service::{CONNECTION_STREAMS, Policy, Service}, store::Store};
use lmk_proto::{Bytes, frame::{self, ALPN, Open, Stream}, head::{self, Head}, membership::{self, Latest, Page, Reply, Request, Subscribed}};
use tokio::{io::AsyncWriteExt, sync::oneshot, time::timeout};

struct TestService {
    _dir: tempfile::TempDir,
    service: Router,
    client: ServeClient,
    endpoint: Endpoint,
    key: [u8; 32],
}

impl TestService {
    async fn new(policy: Policy) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::initialize(&dir.path().join("state")).unwrap();
        let secret = SecretKey::from_bytes(&store.key().to_bytes());
        let key = *secret.public().as_bytes();
        let server = endpoint(Some(secret)).await;
        let service = Router::builder(server).accept(ALPN, Service::new(store, policy)).spawn();
        let endpoint = endpoint(None).await;
        let client = ServeClient::new(endpoint.clone(), &key, "", &service.endpoint().bound_sockets().iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap();
        Self { _dir: dir, service, client, endpoint, key }
    }

    fn empty(&self, c: &[u8; 32]) -> Frontier { Frontier::empty(self.key, head::reference(&self.key, c)) }

    async fn close(self) {
        drop(self.client);
        self.endpoint.close().await;
        self.service.shutdown().await.unwrap();
    }
}

async fn endpoint(secret: Option<SecretKey>) -> Endpoint {
    let mut builder = Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled).clear_ip_transports().bind_addr((Ipv4Addr::LOCALHOST, 0)).unwrap();
    if let Some(secret) = secret { builder = builder.secret_key(secret); }
    builder.bind().await.unwrap()
}

#[tokio::test]
async fn complete_gap_pages_capabilities_and_public_directories() {
    timeout(Duration::from_secs(15), async {
        let net = TestService::new(Policy::default()).await;
        let c = [7; 32];
        let empty = net.empty(&c);
        let first = net.client.append(&c, &[b"one".to_vec()], false).await.unwrap();
        assert_eq!(first.head.log_ref, *empty.log_ref());
        assert!(empty.head().is_none(), "append reply is not an installed anchor");
        let one = net.client.read(&c, &empty).await.unwrap();
        let anchor = one.frontier().clone();
        net.client.append(&c, &[b"two".to_vec(), b"three".to_vec()], false).await.unwrap();
        let mut subscription = net.client.subscribe(vec![(c, anchor)]).await.unwrap();
        let page = subscription.next().await.unwrap().unwrap();
        assert_eq!((page.page().after, page.page().head.length), (1, 3));
        assert_eq!(page.page().entries, [Bytes(b"two".to_vec()), Bytes(b"three".to_vec())]);
        assert_eq!(page.frontier().length(), 3);
        subscription.cancel().await;
        let d = *empty.log_ref();
        assert_eq!(net.client.head(&d).await.unwrap().length, 0, "D as a capability hashes again");
        assert_ne!(net.client.head(&d).await.unwrap().log_ref, d);
        assert!(net.client.read(&d, &net.empty(&d)).await.unwrap().page().entries.is_empty());
        net.client.append(&d, &[vec![9]], false).await.unwrap();
        assert_eq!(net.client.head(&d).await.unwrap().length, 1);
        assert_eq!(net.client.head(&c).await.unwrap().length, 3);
        assert!(net.client.read(&d, &empty).await.is_err());
        let public = lmk_proto::public::address(&[8; 32]);
        let hint = net.client.append(&public, &[vec![2]], true).await.unwrap();
        assert_eq!(hint.head.log_ref, head::reference(&net.key, &public));
        assert_eq!(net.client.read(&public, &net.empty(&public)).await.unwrap().page().entries, [Bytes(vec![2])]);
        net.close().await;
    }).await.unwrap();
}

#[tokio::test]
async fn legal_maximum_envelopes_fit_with_base64_and_json_framing() {
    timeout(Duration::from_secs(15), async {
        let net = TestService::new(Policy::default()).await;
        let c = [7; 32];
        let appended = net.client.append(&c, &vec![vec![42; membership::MAX_ENTRY]; 2], false).await.unwrap();
        let page = net.client.read(&c, &net.empty(&c)).await.unwrap();
        assert_eq!(page.page().entries.len(), 2);
        assert_eq!(page.page().entries[0].0.len(), membership::MAX_ENTRY);
        assert_eq!(page.page().entries[1].0.len(), membership::MAX_ENTRY);
        assert_eq!(page.page().head.hash, appended.head.hash);
        net.close().await;
    }).await.unwrap();
}

#[tokio::test]
async fn racing_appends_are_hints_until_coverage_is_read() {
    timeout(Duration::from_secs(15), async {
        let net = TestService::new(Policy::default()).await;
        let c = [7; 32];
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..4u8 {
            let client = net.client.clone();
            tasks.spawn(async move { (client.append(&c, &[vec![i]], false).await.unwrap(), i) });
        }
        let mut positions = Vec::new();
        while let Some(result) = tasks.join_next().await { positions.push(result.unwrap()); }
        positions.sort_by_key(|(a, _)| a.position);
        assert_eq!(positions.iter().map(|(a, _)| a.position).collect::<Vec<_>>(), [1, 2, 3, 4]);
        let empty = net.empty(&c);
        let page = net.client.read(&c, &empty).await.unwrap();
        assert_eq!(page.page().entries, positions.iter().map(|(_, i)| Bytes(vec![*i])).collect::<Vec<_>>());
        assert_eq!(page.frontier().length(), 4);
        assert!(empty.head().is_none());
        net.close().await;
    }).await.unwrap();
}

#[tokio::test]
async fn rate_and_stream_limits_preserve_other_connections() {
    timeout(Duration::from_secs(15), async {
        let net = TestService::new(Policy { appends_per_minute: 1, ..Policy::default() }).await;
        let c = [7; 32];
        net.client.append(&c, &[vec![1]], false).await.unwrap();
        assert_eq!(net.client.append(&c, &[vec![2]], false).await.unwrap_err().downcast::<Refused>().unwrap().0, "rate");
        assert_eq!(net.client.append(&c, &[], false).await.unwrap_err().downcast::<Refused>().unwrap().0, "size");
        let anchor = net.client.read(&c, &net.empty(&c)).await.unwrap().frontier().clone();
        let mut subscriptions = Vec::new();
        for _ in 0..CONNECTION_STREAMS { subscriptions.push(net.client.subscribe(vec![(c, anchor.clone())]).await.unwrap()); }
        assert!(net.client.head(&c).await.is_err(), "a stream over the limit must be reset, not queued indefinitely");
        let other_endpoint = endpoint(None).await;
        let other = ServeClient::new(other_endpoint.clone(), &net.key, "", &net.service.endpoint().bound_sockets().iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap();
        assert_eq!(other.head(&c).await.unwrap().length, 1);
        for subscription in subscriptions { subscription.cancel().await; }
        other_endpoint.close().await;
        drop(other);
        net.close().await;
    }).await.unwrap();
}

#[tokio::test]
async fn full_subscription_capacity_leaves_short_request_slots_available() {
    timeout(Duration::from_secs(15), async {
        let net = TestService::new(Policy::default()).await;
        let c = [7; 32];
        let mut endpoints = Vec::new();
        let mut subscriptions = Vec::new();
        for _ in 0..lmk_membership::service::MAX_SUBSCRIBERS / CONNECTION_STREAMS {
            let endpoint = endpoint(None).await;
            let connection = endpoint.connect(net.service.endpoint().addr(), ALPN).await.unwrap();
            for _ in 0..CONNECTION_STREAMS {
                let (mut send, mut recv) = connection.open_bi().await.unwrap();
                frame::write(&mut send, &Open { stream: Stream::Membership }).await.unwrap();
                frame::write(&mut send, &Request::Subscribe { capabilities: vec![c] }).await.unwrap();
                assert!(matches!(membership::read_frame::<Reply<Subscribed>, _>(&mut recv).await.unwrap(), Reply::Ok(_)));
                let Reply::Ok(initial) = membership::read_frame::<Reply<Latest>, _>(&mut recv).await.unwrap() else { panic!("initial head refused") };
                net.empty(&c).check(&initial.head, None).unwrap();
                subscriptions.push((send, recv));
            }
            endpoints.push(endpoint);
        }
        assert_eq!(net.client.head(&c).await.unwrap().length, 0);
        let error = net.client.subscribe(vec![(c, net.empty(&c))]).await.err().unwrap();
        assert_eq!(error.downcast::<Refused>().unwrap().0, "busy");
        drop(subscriptions);
        for endpoint in endpoints { endpoint.close().await; }
        net.close().await;
    }).await.unwrap();
}

#[derive(Debug)]
struct Probe {
    key: ed25519_dalek::SigningKey,
    capability: [u8; 32],
    tamper: bool,
    gap: bool,
    entered: Mutex<Option<oneshot::Sender<()>>>,
    read_stopped: Mutex<Option<oneshot::Sender<()>>>,
    subscription_stopped: Mutex<Option<oneshot::Sender<()>>>,
}

impl ProtocolHandler for Probe {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let mut tasks = tokio::task::JoinSet::new();
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let _: Open = membership::read_frame(&mut recv).await.unwrap();
            let request: Request = membership::read_frame(&mut recv).await.unwrap();
            let d = head::reference(self.key.verifying_key().as_bytes(), &self.capability);
            let h0 = head::start(self.key.verifying_key().as_bytes(), &d);
            let head = if self.gap { Head::sign(&self.key, &d, 2, head::next(&head::next(&h0, b"one"), b"two"), 0) }
                else { Head::sign(&self.key, &d, 0, h0, 0) };
            match request {
                Request::Subscribe { .. } => {
                    let stopped = self.subscription_stopped.lock().unwrap().take().unwrap();
                    tasks.spawn(async move {
                        frame::write(&mut send, &Reply::Ok(Subscribed {})).await.unwrap();
                        frame::write(&mut send, &Reply::Ok(Latest { head })).await.unwrap();
                        let _ = recv.read_to_end(1).await;
                        stopped.send(()).unwrap();
                    });
                }
                Request::Read { .. } => {
                    if self.tamper {
                        frame::write(&mut send, &Reply::Ok(Page { after: 0, entries: vec![Bytes(b"one".to_vec()), Bytes(b"BAD".to_vec())], head })).await.unwrap();
                        send.shutdown().await.unwrap();
                    } else {
                        self.entered.lock().unwrap().take().unwrap().send(()).unwrap();
                        let stopped = self.read_stopped.lock().unwrap().take().unwrap();
                        tasks.spawn(async move {
                            send.stopped().await.unwrap();
                            stopped.send(()).unwrap();
                        });
                    }
                }
                _ => panic!("unexpected request"),
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn cancellation_owns_idle_and_gap_read_streams() {
    timeout(Duration::from_secs(15), async {
        for gap in [false, true] {
            let secret = SecretKey::generate();
            let key = ed25519_dalek::SigningKey::from_bytes(&secret.to_bytes());
            let s = key.verifying_key().to_bytes();
            let c = [7; 32];
            let (entered, read_entered) = oneshot::channel();
            let (read_stopped, stopped_read) = oneshot::channel();
            let (subscription_stopped, stopped_subscription) = oneshot::channel();
            let probe = Probe { key, capability: c, tamper: false, gap, entered: Mutex::new(Some(entered)), read_stopped: Mutex::new(Some(read_stopped)), subscription_stopped: Mutex::new(Some(subscription_stopped)) };
            let router = Router::builder(endpoint(Some(secret)).await).accept(ALPN, probe).spawn();
            let endpoint = endpoint(None).await;
            let client = ServeClient::new(endpoint.clone(), &s, "", &router.endpoint().bound_sockets().iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap();
            let subscription = client.subscribe(vec![(c, Frontier::empty(s, head::reference(&s, &c)))]).await.unwrap();
            if gap {
                read_entered.await.unwrap();
                subscription.cancel().await;
                stopped_read.await.unwrap();
            } else { drop(subscription); }
            stopped_subscription.await.unwrap();
            endpoint.close().await;
            router.shutdown().await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn tampered_gap_page_never_delivers_a_prefix_or_contradiction() {
    timeout(Duration::from_secs(15), async {
        let secret = SecretKey::generate();
        let key = ed25519_dalek::SigningKey::from_bytes(&secret.to_bytes());
        let s = key.verifying_key().to_bytes();
        let c = [7; 32];
        let (stopped, ended) = oneshot::channel();
        let probe = Probe { key, capability: c, tamper: true, gap: true, entered: Mutex::new(None), read_stopped: Mutex::new(None), subscription_stopped: Mutex::new(Some(stopped)) };
        let router = Router::builder(endpoint(Some(secret)).await).accept(ALPN, probe).spawn();
        let endpoint = endpoint(None).await;
        let client = ServeClient::new(endpoint.clone(), &s, "", &router.endpoint().bound_sockets().iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap();
        let empty = Frontier::empty(s, head::reference(&s, &c));
        let mut sub = client.subscribe(vec![(c, empty.clone())]).await.unwrap();
        let first = sub.next().await.unwrap().unwrap_err();
        assert!(first.is::<InvalidProof>());
        assert!(sub.next().await.is_none());
        assert!(empty.head().is_none());
        ended.await.unwrap();
        endpoint.close().await;
        router.shutdown().await.unwrap();
    }).await.unwrap();
}

#[derive(Debug)]
struct PrivateClose;

impl ProtocolHandler for PrivateClose {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (_send, mut recv) = connection.accept_bi().await.unwrap();
        let _: Open = membership::read_frame(&mut recv).await.unwrap();
        let _: Request = membership::read_frame(&mut recv).await.unwrap();
        connection.close(1u32.into(), b"raw capability, entry and credential");
        Ok(())
    }
}

#[tokio::test]
async fn transport_errors_cannot_echo_private_close_reasons() {
    timeout(Duration::from_secs(15), async {
        let router = Router::builder(endpoint(None).await).accept(ALPN, PrivateClose).spawn();
        let endpoint = endpoint(None).await;
        let client = ServeClient::new(endpoint.clone(), router.endpoint().id().as_bytes(), "", &router.endpoint().bound_sockets().iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap();
        let error = client.append(&[7; 32], &[b"opaque".to_vec()], false).await.unwrap_err();
        assert_eq!(format!("{error:#}"), "membership transport interrupted");
        endpoint.close().await;
        router.shutdown().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn oversized_frame_is_rejected_before_reading_body() {
    timeout(Duration::from_secs(15), async {
        let net = TestService::new(Policy::default()).await;
        let connection = net.endpoint.connect(net.service.endpoint().addr(), ALPN).await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        frame::write(&mut send, &Open { stream: Stream::Membership }).await.unwrap();
        send.write_all(&((membership::MAX_BODY + 1) as u32).to_be_bytes()).await.unwrap();
        assert!(matches!(membership::read_frame::<Reply<()>, _>(&mut recv).await.unwrap(), Reply::Refused(membership::Refusal::Policy)));
        net.close().await;
    }).await.unwrap();
}
