use std::{net::Ipv4Addr, path::Path, sync::Arc, time::Duration};

use iroh::{Endpoint, RelayConfig, RelayMap, RelayMode, endpoint::presets, tls::CaTlsConfig};
use iroh_relay::RelayQuicConfig;
use lmk_membership::client::{Resolve, ServeClient};
use lmk_proto::directory::Directory;
use n0_future::boxed::BoxFuture;
use lmk_serve::{Certificate, ServeConfig, serve};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
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

async fn https_get(port: u16, cert: &CertificateDer<'static>, path: &str, headers: &str) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response).await;
    String::from_utf8(response).unwrap()
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
    (config.https_port, config.qad_port, config.membership_port) = (free_port(), free_port(), free_port());
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
    let (https, http, qad, membership) = (
        config.https_port,
        config.http_port.unwrap(),
        config.qad_port,
        config.membership_port,
    );
    let relay = config.relay_url();
    let service = config.service().unwrap();
    let server = tokio::spawn(serve(config));
    wait_for_https(https).await;
    let resolved = |directory: Directory| -> Resolve {
        Arc::new(move |_: String| -> BoxFuture<anyhow::Result<Directory>> {
            let directory = directory.clone();
            Box::pin(async move { Ok(directory) })
        })
    };

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
    let through_relay = directory.clone();
    assert_eq!(directory.addrs, [format!("localhost:{membership}")]);
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

    // Through the relay only.
    let relay_config = RelayConfig::new(relay.parse().unwrap(), Some(RelayQuicConfig::new(qad)));
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(RelayMap::from_iter([relay_config])))
        .ca_tls_config(CaTlsConfig::custom_roots([cert.clone()]))
        .clear_ip_transports()
        .bind()
        .await
        .unwrap();
    let client = ServeClient::for_service(endpoint, resolved(through_relay), &service).unwrap();
    let appended = tokio::time::timeout(Duration::from_secs(10), client.append(&[7; 32], &[b"commit".to_vec()], false))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(appended.position, 1);

    // Directly, on the membership port.
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let lmk_proto::group::Service::Serve { key, .. } = &service else {
        unreachable!()
    };
    let at_port = Directory { key: key.0.as_slice().try_into().unwrap(), addrs: vec![format!("127.0.0.1:{membership}")], relay: relay.clone(), relays: vec![relay.clone()] };
    let direct = ServeClient::for_service(endpoint, resolved(at_port), &service).unwrap();
    let service_key = key.0.as_slice().try_into().unwrap();
    let log_ref = lmk_proto::head::reference(&service_key, &[7; 32]);
    let page = direct.read(&[7; 32], &lmk_membership::Frontier::empty(service_key, log_ref)).await.unwrap();
    assert_eq!(page.page().entries[0].0, b"commit");
    let head = direct.head(&[7; 32]).await.unwrap();
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
