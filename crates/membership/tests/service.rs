use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use ed25519_dalek::SigningKey;
use iroh::{
    Endpoint, EndpointAddr, RelayConfig, RelayMap, RelayMode, SecretKey,
    endpoint::{Builder, presets},
    protocol::Router,
    tls::CaTlsConfig,
};
use iroh_relay::{
    RelayQuicConfig,
    server::{CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server, ServerConfig, TlsConfig},
};
use lmk_membership::{
    Contradiction, Forged, Membership, Refused,
    client::ServeClient,
    service::{Policy, Service},
    store::Store,
};
use lmk_proto::{
    Answer, Bytes,
    frame::{self, ALPN, Open, Stream},
};
use lmk_transport::Iroh;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

struct Net {
    _server: Server,
    config: RelayConfig,
    cert: CertificateDer<'static>,
    dir: PathBuf,
}

async fn net(name: &str) -> Net {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let mut relay = RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.tls = Some(TlsConfig::new(
        (Ipv4Addr::LOCALHOST, 0),
        CertConfig::Manual {
            server_config: tls.clone(),
        },
    ));
    let mut quic = QuicConfig::new((Ipv6Addr::UNSPECIFIED, 0));
    quic.server_config = Some(tls);
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    config.quic = Some(quic);
    let server = Server::spawn(config).await.unwrap();
    let url = format!("https://localhost:{}", server.https_addr().unwrap().port())
        .parse()
        .unwrap();
    let config = RelayConfig::new(url, Some(RelayQuicConfig::new(server.quic_addr().unwrap().port())));
    let dir = std::env::temp_dir().join(format!("lmk-membership-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Net {
        _server: server,
        config,
        cert,
        dir,
    }
}

impl Net {
    fn builder(&self) -> Builder {
        Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Custom(RelayMap::from_iter([self.config.clone()])))
            .ca_tls_config(CaTlsConfig::custom_roots([self.cert.clone()]))
    }

    async fn service(&self, secret: &SecretKey, signer: SigningKey, db: &str, policy: Policy) -> Router {
        let store = Store::open(&self.dir.join(db), signer).unwrap();
        let endpoint = self.builder().secret_key(secret.clone()).bind().await.unwrap();
        let router = Router::builder(endpoint)
            .accept(ALPN, Service::new(store, policy))
            .spawn();
        tokio::time::timeout(Duration::from_secs(10), router.endpoint().online())
            .await
            .unwrap();
        router
    }

    /// A client that reaches the service only through the relay.
    async fn client(&self, service: &SecretKey) -> ServeClient {
        let endpoint = self.builder().clear_ip_transports().bind().await.unwrap();
        let relay = self.config.url.to_string();
        ServeClient::new(Arc::new(Iroh(endpoint)), service.public().as_bytes(), &relay, &[]).unwrap()
    }
}

fn signer(secret: &SecretKey) -> SigningKey {
    SigningKey::from_bytes(&secret.to_bytes())
}

fn entries(page: &[Bytes]) -> Vec<&[u8]> {
    page.iter().map(|e| e.0.as_slice()).collect()
}

async fn read_all(client: &ServeClient, log: &[u8]) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    loop {
        let page = client.read(log, all.len() as u64).await.unwrap();
        if page.entries.is_empty() {
            return all;
        }
        all.extend(page.entries.into_iter().map(|e| e.0));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn append_read_subscribe() {
    let net = net("basic").await;
    let secret = SecretKey::generate();
    let _service = net
        .service(&secret, signer(&secret), "store.db", Policy::default())
        .await;
    let (alice, bob) = (net.client(&secret).await, net.client(&secret).await);

    let mut notices = alice.subscribe(vec![Bytes(b"g".to_vec())]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(bob.append(b"g", &[b"one".to_vec()]).await.unwrap().position, 1);
    let behind = net.client(&secret).await;
    assert_eq!(behind.read(b"g", 0).await.unwrap().entries.len(), 1);
    assert_eq!(bob.append(b"g", &[b"two".to_vec()]).await.unwrap().position, 2);
    for (position, entry) in [(1, b"one"), (2, b"two")] {
        let notice = notices.next().await.unwrap().unwrap();
        assert_eq!(
            (notice.position, notice.entry.0.as_slice()),
            (position, entry.as_slice())
        );
    }
    let page = alice.read(b"g", 0).await.unwrap();
    assert_eq!(
        (entries(&page.entries), page.head.length),
        (vec![b"one".as_slice(), b"two"], 2)
    );
    assert_eq!(alice.read(b"g", 1).await.unwrap().entries.len(), 1);
    assert_eq!(alice.head(b"g").await.unwrap().length, 2);
    assert_eq!(alice.head(b"empty").await.unwrap().length, 0);

    // A subscriber whose chain stops at 1 gets 2 as well when 3 arrives.
    let mut catching_up = behind.subscribe(vec![Bytes(b"g".to_vec())]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    bob.append(b"g", &[b"three".to_vec()]).await.unwrap();
    for (position, entry) in [(2, b"two".as_slice()), (3, b"three")] {
        let notice = catching_up.next().await.unwrap().unwrap();
        assert_eq!((notice.position, notice.entry.0.as_slice()), (position, entry));
    }
    assert_eq!(behind.chain(b"g").unwrap().length(), 3);
    assert_eq!(read_all(&bob, b"g").await.len(), 3);

    // A batch comes as one notice per entry, each with its own head; another log's appends wake no one here.
    bob.append(b"other", &[b"elsewhere".to_vec()]).await.unwrap();
    bob.append(b"g", &[b"four".to_vec(), b"five".to_vec()]).await.unwrap();
    for (position, entry) in [(3, b"three".as_slice()), (4, b"four".as_slice()), (5, b"five")] {
        let notice = notices.next().await.unwrap().unwrap();
        assert_eq!((notice.position, notice.entry.0.as_slice(), notice.head.length), (position, entry, position));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn racing_appends_get_one_order() {
    let net = net("race").await;
    let secret = SecretKey::generate();
    let policy = Policy {
        appends_per_minute: 1000,
        ..Policy::default()
    };
    let _service = net.service(&secret, signer(&secret), "store.db", policy).await;
    let clients = [net.client(&secret).await, net.client(&secret).await];
    let tasks = clients.iter().enumerate().map(|(c, client)| {
        let client = client.clone();
        tokio::spawn(async move {
            let mut positions = Vec::new();
            for i in 0..20 {
                let entry = format!("{c}-{i}");
                positions.push((client.append(b"g", &[entry.as_bytes().to_vec()]).await.unwrap().position, entry));
            }
            positions
        })
    });
    let mut positions: Vec<(u64, String)> = Vec::new();
    for task in tasks.collect::<Vec<_>>() {
        positions.extend(task.await.unwrap());
    }
    positions.sort();
    assert_eq!(
        positions.iter().map(|p| p.0).collect::<Vec<_>>(),
        (1..=40).collect::<Vec<_>>()
    );
    let order: Vec<Vec<u8>> = positions.into_iter().map(|p| p.1.into_bytes()).collect();
    for client in &clients {
        assert_eq!(read_all(client, b"g").await, order);
    }
    assert_eq!(
        clients[0].chain(b"g").unwrap().hashes,
        clients[1].chain(b"g").unwrap().hashes
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals() {
    let net = net("refusals").await;
    let secret = SecretKey::generate();
    let policy = Policy {
        max_entry: 10,
        appends_per_minute: 1,
        ..Policy::default()
    };
    let _service = net.service(&secret, signer(&secret), "store.db", policy).await;
    let client = net.client(&secret).await;
    let refused = |r: anyhow::Result<_>| r.unwrap_err().downcast::<Refused>().unwrap().0;
    assert_eq!(refused(client.append(b"g", &[b"x".to_vec(), vec![0; 11]]).await), "size");
    assert_eq!(refused(client.append(&[0; 65], &[b"x".to_vec()]).await), "policy");
    assert_eq!(refused(client.append(b"g", &[]).await), "policy");
    // Several entries count as one append.
    let appended = client.append(b"g", &[b"x".to_vec(), b"y".to_vec(), b"z".to_vec()]).await.unwrap();
    assert_eq!((appended.position, appended.head.length), (1, 3));
    assert_eq!(refused(client.append(b"g", &[b"w".to_vec()]).await), "rate");

    // A request of a newer letmeknow.
    let endpoint = net.builder().clear_ip_transports().bind().await.unwrap();
    let addr = EndpointAddr::new(secret.public()).with_relay_url(net.config.url.clone());
    let (mut send, mut recv) = endpoint.connect(addr, ALPN).await.unwrap().open_bi().await.unwrap();
    frame::write(&mut send, &Open { stream: Stream::Membership }).await.unwrap();
    frame::write(&mut send, &serde_json::json!({"compact": {"log": "Zw"}})).await.unwrap();
    let answer: Answer<()> = frame::read(&mut recv).await.unwrap();
    assert_eq!(answer, Answer::Refused { refused: "unknown request".into() });
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_and_contradicting_heads() {
    let net = net("heads").await;
    let secret = SecretKey::generate();

    // A service whose heads are not signed by its key.
    let impostor = net
        .service(
            &secret,
            SigningKey::from_bytes(&[9; 32]),
            "impostor.db",
            Policy::default(),
        )
        .await;
    let client = net.client(&secret).await;
    assert!(client.head(b"g").await.unwrap_err().is::<Forged>());
    impostor.shutdown().await.unwrap();

    // The service shows the client one log, then, after losing its database, another.
    let honest = net.service(&secret, signer(&secret), "one.db", Policy::default()).await;
    let client = net.client(&secret).await;
    client.append(b"g", &[b"a".to_vec()]).await.unwrap();
    client.append(b"g", &[b"b".to_vec()]).await.unwrap();
    let ours = client.chain(b"g").unwrap().head;
    honest.shutdown().await.unwrap();

    let split = net.service(&secret, signer(&secret), "two.db", Policy::default()).await;
    let other = net.client(&secret).await;
    other.append(b"g", &[b"x".to_vec()]).await.unwrap();
    other.append(b"g", &[b"y".to_vec()]).await.unwrap();
    let err = client
        .head(b"g")
        .await
        .unwrap_err()
        .downcast::<Contradiction>()
        .unwrap();
    assert_eq!((err.ours, err.theirs.length), (ours, 2));
    assert!(client.read(b"g", 1).await.unwrap_err().is::<Contradiction>());
    split.shutdown().await.unwrap();
}
