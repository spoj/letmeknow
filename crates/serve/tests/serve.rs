use std::{net::Ipv4Addr, path::Path, sync::Arc, time::Duration};

use ed25519_dalek::{Signature, VerifyingKey};
use iroh::tls::CaTlsConfig;
use lmk_membership::client::ServeClient;
use lmk_proto::{Bytes, directory::Directory, head, membership::{Answer, Append, Appended, Heads, Known, Moved, Page, Read, Refusal, refusal_message}};
use lmk_serve::{Certificate, ServeConfig, serve};
use rustls::pki_types::{CertificateDer, ServerName};
use serde::de::DeserializeOwned;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

/// A port free for TCP and UDP, below the ephemeral range: a port `bind(0)` returned could be taken by another test's relay
/// or endpoint before the service binds it.
fn free_port() -> u16 {
    loop {
        let port = rand::random_range(1024..32768);
        if std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() && std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}

async fn tls_connect(host: &str, port: u16, cert: &CertificateDer<'static>) -> tokio_rustls::client::TlsStream<TcpStream> {
    tls_over(TcpStream::connect((host, port)).await.unwrap(), cert).await
}

async fn tls_over(tcp: TcpStream, cert: &CertificateDer<'static>) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap()
}

async fn https_raw(host: &str, port: u16, cert: &CertificateDer<'static>, request: &[u8]) -> String {
    let mut tls = tls_connect(host, port, cert).await;
    tls.write_all(request).await.unwrap();
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response).await;
    String::from_utf8(response).unwrap()
}

async fn https_get(port: u16, cert: &CertificateDer<'static>, path: &str, headers: &str) -> String {
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}\r\n");
    https_raw("127.0.0.1", port, cert, request.as_bytes()).await
}

async fn http_get(port: u16, request: &str) -> String {
    let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();
    response
}

/// A service initialized in `state`, with a certificate for localhost and free ports.
fn configure(state: &Path) -> (ServeConfig, CertificateDer<'static>) {
    lmk_membership::store::Store::initialize(state).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(state.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(state.join("key.pem"), ck.signing_key.serialize_pem()).unwrap();

    let mut config = ServeConfig::new("localhost", state);
    (config.https_port, config.qad_port) = (free_port(), free_port());
    config.http_port = Some(free_port());
    config.certificate = Certificate::Files {
        chain: state.join("cert.pem"),
        key: state.join("key.pem"),
    };
    (config, ck.cert.der().clone())
}

async fn wait_for_https(port: u16) {
    for _ in 0..50 {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_relay_and_membership_without_frontend() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let (config, cert) = configure(&state);
    let (https, http) = (config.https_port, config.http_port.unwrap());
    let relay = config.relay_url();
    let service = config.service().unwrap();
    let server = tokio::spawn(serve(config));
    wait_for_https(https).await;
    for path in ["/", "/i", "/index.html", "/app.js", "/sw.js", "/membership", "/missing.js"] {
        let response = https_get(https, &cert, path, "").await;
        assert!(response.starts_with("HTTP/1.1 404"), "{path}: {response}");
    }
    let ping = https_get(https, &cert, "/ping", "Origin: https://frontend.example\r\n").await;
    assert!(ping.starts_with("HTTP/1.1 200") && ping.contains("access-control-allow-origin: *"), "{ping}");
    let lmk_proto::group::Service::Serve { key, .. } = &service else {
        unreachable!()
    };
    let health = https_get(https, &cert, "/health", "").await;
    let expected = format!(r#"{{"version":"{}","membership":"{}"}}"#, env!("CARGO_PKG_VERSION"), hex::encode(&key.0));
    assert!(health.starts_with("HTTP/1.1 200") && health.ends_with(&expected), "{health}");
    let directory = https_get(https, &cert, "/.well-known/letmeknow.json", "Origin: https://frontend.example\r\n").await;
    assert!(
        directory.starts_with("HTTP/1.1 200")
            && directory.contains("access-control-allow-origin: *")
            && directory.to_lowercase().contains("content-type: application/json"),
        "{directory}"
    );
    let directory = Directory::parse(directory.split_once("\r\n\r\n").unwrap().1.as_bytes()).unwrap();
    assert_eq!(directory.key.to_vec(), key.0);
    assert_eq!(directory.relay, relay);
    assert_eq!(directory.relays, [relay.as_str()]);
    let portal = http_get(
        http,
        "GET /generate_204 HTTP/1.1\r\nHost: localhost\r\nX-Iroh-Challenge: abc\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        portal.starts_with("HTTP/1.1 204") && portal.to_lowercase().contains("x-iroh-response: response abc"),
        "{portal}"
    );
    let moved = http_get(
        http,
        "GET /i?x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        moved
            .to_lowercase()
            .contains(&format!("location: https://localhost:{https}/i?x")),
        "{moved}"
    );

    let tls = CaTlsConfig::custom_roots([cert.clone()]).client_config(Arc::new(rustls::crypto::ring::default_provider())).unwrap();
    let https_post = lmk_membership::client::https(reqwest::Client::builder().tls_backend_preconfigured(tls).no_proxy().build().unwrap());
    let post: lmk_membership::client::Post = Arc::new(move |_: String, route, body| https_post(format!("localhost:{https}"), route, body));
    let client = ServeClient::for_service(post, &service).unwrap();
    let appended = tokio::time::timeout(Duration::from_secs(10), client.append(&[7; 32], &[b"commit".to_vec()], false))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(appended.position, 1);
    let lmk_proto::group::Service::Serve { key, .. } = &service else { unreachable!() };
    let key: [u8; 32] = key.0.as_slice().try_into().unwrap();
    let page = client.read(&[7; 32], &lmk_membership::Frontier::empty(key, lmk_proto::head::reference(&key, &[7; 32]))).await.unwrap();
    assert_eq!(page.page().entries[0].0, b"commit");
    let heads = client.heads(&[lmk_proto::membership::Known([7; 32], 0)]).await.unwrap();
    let head = heads[0].as_ref().unwrap();
    assert_eq!((head.length, head.hash), (page.page().head.length, page.page().head.hash));

    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn directory_names_the_relays_given() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let (mut config, cert) = configure(&state);
    config.relays = vec!["https://relay.example:8443".into(), "https://relay2.example".into()];
    let (https, relay) = (config.https_port, config.relay_url());
    let server = tokio::spawn(serve(config));
    wait_for_https(https).await;

    let response = https_get(https, &cert, "/.well-known/letmeknow.json", "").await;
    let directory = Directory::parse(response.split_once("\r\n\r\n").unwrap().1.as_bytes()).unwrap();
    assert_eq!(directory.relay, relay);
    assert_eq!(directory.relays, ["https://relay.example:8443", "https://relay2.example"]);
    server.abort();
}

const APP: &str = "https://letmeknow.dev";
const APPEND: &str = "/membership/1/append";

fn append_json(capability: u8, entry: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&Append { capability: [capability; 32], entries: vec![Bytes(entry.to_vec())], public: false }).unwrap()
}

fn post(path: &str, origin: Option<&str>, body: &[u8]) -> Vec<u8> {
    let origin = origin.map(|o| format!("Origin: {o}\r\n")).unwrap_or_default();
    let head = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\n{origin}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    [head.as_bytes(), body].concat()
}

fn answer<T: DeserializeOwned>(response: &str) -> Answer<T> {
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn membership_takes_appends_from_the_app_and_listed_origins_only() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let (mut config, cert) = configure(&state);
    config.origins = vec!["http://localhost:5173".into()];
    let (https, service) = (config.https_port, config.service().unwrap());
    let server = tokio::spawn(serve(config));
    wait_for_https(https).await;
    let lmk_proto::group::Service::Serve { key, .. } = &service else { unreachable!() };
    let key = VerifyingKey::from_bytes(key.0.as_slice().try_into().unwrap()).unwrap();

    let response = https_raw("127.0.0.1", https, &cert, &post(APPEND, Some(APP), &append_json(7, b"one"))).await;
    assert!(response.starts_with("HTTP/1.1 200") && response.to_lowercase().contains(&format!("access-control-allow-origin: {APP}")), "{response}");
    let Answer::Ok(appended) = answer::<Appended>(&response) else { panic!("{response}") };
    assert!(appended.head.verify(&key));

    let response = https_raw("127.0.0.1", https, &cert, &post(APPEND, Some("https://evil.example"), &append_json(8, b"x"))).await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    let read = serde_json::to_vec(&Read { capability: [8; 32], after: 0 }).unwrap();
    let response = https_raw("127.0.0.1", https, &cert, &post("/membership/1/read", None, &read)).await;
    let Answer::Ok(page) = answer::<Page>(&response) else { panic!("{response}") };
    assert!(page.entries.is_empty(), "a page of another origin appended");

    let response = https_raw("127.0.0.1", https, &cert, &post(APPEND, None, &append_json(9, b"y"))).await;
    assert!(response.starts_with("HTTP/1.1 200") && !response.to_lowercase().contains("access-control-allow-origin"), "{response}");
    let response = https_raw("127.0.0.1", https, &cert, &post(APPEND, Some("http://localhost:5173"), &append_json(10, b"z"))).await;
    assert!(response.starts_with("HTTP/1.1 200") && response.to_lowercase().contains("access-control-allow-origin: http://localhost:5173"), "{response}");

    let preflight = |path: &str, origin: &str| format!("OPTIONS {path} HTTP/1.1\r\nHost: localhost\r\nOrigin: {origin}\r\nAccess-Control-Request-Method: POST\r\nConnection: close\r\n\r\n");
    let response = https_raw("127.0.0.1", https, &cert, preflight(APPEND, APP).as_bytes()).await;
    let lower = response.to_lowercase();
    assert!(response.starts_with("HTTP/1.1 204") && lower.contains(&format!("access-control-allow-origin: {APP}")) && lower.contains("access-control-max-age: 600"), "{response}");
    let response = https_raw("127.0.0.1", https, &cert, preflight(APPEND, "https://evil.example").as_bytes()).await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");

    let response = https_raw("127.0.0.1", https, &cert, b"GET /membership/1/read HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 405"), "{response}");
    let response = https_raw("127.0.0.1", https, &cert, preflight("/membership/2/append", APP).as_bytes()).await;
    assert!(response.starts_with("HTTP/1.1 204") && response.to_lowercase().contains(&format!("access-control-allow-origin: {APP}")), "{response}");
    let response = https_raw("127.0.0.1", https, &cert, &post("/membership/2/append", Some(APP), &append_json(7, b"x"))).await;
    assert!(response.starts_with("HTTP/1.1 404") && response.to_lowercase().contains(&format!("access-control-allow-origin: {APP}")), "{response}");

    let response = https_raw("127.0.0.1", https, &cert, &post(APPEND, None, b"not json")).await;
    let Answer::<()>::Refused { refusal, sig } = answer(&response) else { panic!("{response}") };
    assert!(matches!(refusal, Refusal::Policy));
    assert!(Signature::from_slice(&sig.0).is_ok_and(|sig| key.verify_strict(&refusal_message(Refusal::Policy, b"not json"), &sig).is_ok()));
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_handshakes_and_headers_are_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let (config, cert) = configure(&state);
    let https = config.https_port;
    let server = tokio::spawn(serve(config));
    wait_for_https(https).await;

    let mut silent = TcpStream::connect((Ipv4Addr::LOCALHOST, https)).await.unwrap();
    let mut rest = Vec::new();
    assert!(timeout(Duration::from_secs(14), silent.read_to_end(&mut rest)).await.is_ok(), "a silent handshake was kept open");

    let mut tls = tls_connect("127.0.0.1", https, &cert).await;
    tls.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n").await.unwrap();
    let mut rest = Vec::new();
    assert!(timeout(Duration::from_secs(14), tls.read_to_end(&mut rest)).await.is_ok(), "stalled headers were kept open");
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn one_address_at_once_does_not_refuse_another() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let (config, cert) = configure(&state);
    let https = config.https_port;
    let server = tokio::spawn(serve(config));
    wait_for_https(https).await;

    let mut stalled = Vec::new();
    for _ in 0..8 {
        let mut tls = tls_connect("127.0.0.1", https, &cert).await;
        tls.write_all(format!("POST {APPEND} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n").as_bytes()).await.unwrap();
        stalled.push(tls);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let response = https_raw("127.0.0.1", https, &cert, &post(APPEND, None, &append_json(1, b"x"))).await;
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    let response = https_raw("::1", https, &cert, &post(APPEND, None, &append_json(2, b"x"))).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_that_does_not_drain_closes_its_connection() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let (config, cert) = configure(&state);
    let https = config.https_port;
    let server = tokio::spawn(serve(config));
    wait_for_https(https).await;

    let entries = vec![Bytes(vec![1; 1 << 20]), Bytes(vec![2; 1 << 20])];
    let append = serde_json::to_vec(&Append { capability: [3; 32], entries, public: false }).unwrap();
    let response = https_raw("127.0.0.1", https, &cert, &post(APPEND, None, &append)).await;
    assert!(matches!(answer::<Appended>(&response), Answer::Ok(_)), "{response}");
    let read = post("/membership/1/read", None, &serde_json::to_vec(&Read { capability: [3; 32], after: 0 }).unwrap());
    let page = https_raw("127.0.0.1", https, &cert, &read).await.len();

    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket.set_recv_buffer_size(4 << 10).unwrap();
    socket.connect(&std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, https)).into()).unwrap();
    socket.set_nonblocking(true).unwrap();
    let tls = tls_over(TcpStream::from_std(socket.into()).unwrap(), &cert).await;
    let (mut reader, mut writer) = tokio::io::split(tls);
    let pipelined = String::from_utf8(read).unwrap().replace("Connection: close\r\n", "").repeat(8);
    writer.write_all(pipelined.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(35)).await;
    let mut received = Vec::new();
    let _ = timeout(Duration::from_secs(20), reader.read_to_end(&mut received)).await.expect("the stalled connection was kept open");
    assert!(received.len() < 8 * page, "{} of {}", received.len(), 8 * page);
    server.abort();
}

/// The journal a service keeps, which an operator's unit writes at its level, as the service's own log lines.
#[derive(Clone, Default)]
struct Journal(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Journal {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

/// Echoes what a client sends, so that two endpoints connect and exchange bytes through the relay.
#[derive(Debug)]
struct Echo;

impl iroh::protocol::ProtocolHandler for Echo {
    async fn accept(&self, conn: iroh::endpoint::Connection) -> Result<(), iroh::protocol::AcceptError> {
        let (mut send, mut recv) = conn.accept_bi().await.map_err(iroh::protocol::AcceptError::from_err)?;
        let data = recv.read_to_end(64).await.map_err(iroh::protocol::AcceptError::from_err)?;
        send.write_all(&data).await.map_err(iroh::protocol::AcceptError::from_err)?;
        send.finish().map_err(iroh::protocol::AcceptError::from_err)?;
        conn.closed().await;
        Ok(())
    }
}

/// The forms a secret's bytes take in a log line: hex, base64url, and Debug's list of numbers.
fn forms(bytes: &[u8]) -> Vec<String> {
    use base64::Engine;
    vec![hex::encode(bytes), base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes), format!("{bytes:?}")]
}

#[tokio::test(flavor = "multi_thread")]
async fn the_journal_holds_no_addresses_keys_or_capabilities() {
    let journal = Journal::default();
    let writer = journal.clone();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info,iroh=off,iroh_relay=warn,lmk_membership=trace,lmk_serve=trace"))
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();
    tracing::info!("the control line");
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let (config, cert) = configure(&state);
    let (https, relay) = (config.https_port, config.relay_url());
    let service = config.service().unwrap();
    let server = tokio::spawn(serve(config));
    wait_for_https(https).await;
    let lmk_proto::group::Service::Serve { key, .. } = &service else { unreachable!() };
    let key: [u8; 32] = key.0.as_slice().try_into().unwrap();
    let capability = [7u8; 32];
    let append = post(APPEND, Some(APP), &append_json(7, b"one"));
    assert!(https_raw("127.0.0.1", https, &cert, &append).await.starts_with("HTTP/1.1 200"));
    let read = serde_json::to_vec(&Read { capability, after: 0 }).unwrap();
    assert!(https_raw("127.0.0.1", https, &cert, &post("/membership/1/read", Some(APP), &read)).await.starts_with("HTTP/1.1 200"));
    let heads = serde_json::to_vec(&Heads { logs: vec![Known(capability, 0)] }).unwrap();
    let response = https_raw("127.0.0.1", https, &cert, &post("/membership/1/heads", Some(APP), &heads)).await;
    let Answer::<Moved>::Ok(moved) = answer(&response) else { panic!("{response}") };
    assert_eq!(moved.heads.len(), 1);
    let public = serde_json::to_vec(&Append { capability: [9; 32], entries: vec![Bytes(vec![0; 17 << 10])], public: true }).unwrap();
    let response = https_raw("127.0.0.1", https, &cert, &post(APPEND, Some(APP), &public)).await;
    assert!(matches!(answer::<Appended>(&response), Answer::Refused { .. }), "{response}");
    let mut failed = TcpStream::connect((Ipv4Addr::LOCALHOST, https)).await.unwrap();
    failed.write_all(b"not a TLS handshake\r\n\r\n").await.unwrap();
    let mut ignored = Vec::new();
    let _ = failed.read_to_end(&mut ignored).await;

    let mut endpoints = Vec::new();
    for _ in 0..2 {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from(iroh::RelayConfig::new(relay.parse().unwrap(), Some(Default::default())))))
            .ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([cert.clone()]))
            .bind().await.unwrap();
        endpoints.push(endpoint);
    }
    let [dialer, listener]: [iroh::Endpoint; 2] = endpoints.try_into().unwrap();
    let router = iroh::protocol::Router::builder(listener.clone()).accept(b"journal/1", Echo).spawn();
    timeout(Duration::from_secs(30), listener.online()).await.unwrap();
    timeout(Duration::from_secs(30), dialer.online()).await.unwrap();
    let connection = dialer.connect(listener.addr(), b"journal/1").await.unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(b"through the relay").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"through the relay");
    let stranger = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from(iroh::RelayConfig::new(relay.parse().unwrap(), Some(Default::default())))))
        .bind().await.unwrap();
    assert!(timeout(Duration::from_secs(5), stranger.online()).await.is_err(), "a client that trusts no certificate does not reach the relay");

    let store = lmk_membership::store::Store::open(&state).unwrap();
    while store.expire(i64::MAX as u64).unwrap() {}
    drop(store);
    let response = https_raw("127.0.0.1", https, &cert, &post("/membership/1/read", Some(APP), &read)).await;
    assert!(matches!(answer::<Page>(&response), Answer::Expired { .. }), "{response}");
    let response = https_raw("127.0.0.1", https, &cert, &post("/membership/1/heads", Some(APP), &heads)).await;
    assert!(matches!(answer::<Moved>(&response), Answer::Ok(moved) if moved.expired.len() == 1), "{response}");
    router.shutdown().await.unwrap();
    server.abort();

    let text = String::from_utf8_lossy(&journal.0.lock().unwrap()).into_owned();
    assert!(text.contains("the control line"), "the control: the journal holds this process's lines:\n{text}");
    let reference = head::reference(&key, &capability);
    let mut secrets = vec![("the capability", forms(&capability)), ("the reference", forms(&reference)), ("the key", forms(&key)), ("an address", vec!["127.0.0.1".into()])];
    for endpoint in [&dialer, &listener, &stranger] {
        secrets.push(("an endpoint", [forms(endpoint.id().as_bytes()), vec![endpoint.id().to_string(), endpoint.id().fmt_short().to_string()]].concat()));
    }
    for (what, forms) in secrets {
        for form in forms {
            assert!(!text.contains(&form), "the journal holds {what} as {form}:\n{text}");
        }
    }
}
