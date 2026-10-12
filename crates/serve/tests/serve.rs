use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use iroh::{Endpoint, RelayConfig, RelayMap, RelayMode, endpoint::presets, tls::CaTlsConfig};
use iroh_relay::RelayQuicConfig;
use lmk_membership::client::ServeClient;
use lmk_serve::{Certificate, ServeConfig, serve};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn free_port() -> u16 {
    let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = tcp.local_addr().unwrap().port();
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
        .map(|_| port)
        .unwrap_or_else(|_| free_port())
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

#[tokio::test(flavor = "multi_thread")]
async fn serves_relay_and_membership_without_frontend() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    lmk_membership::store::Store::initialize(&state).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(state.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(state.join("key.pem"), ck.signing_key.serialize_pem()).unwrap();
    let cert = ck.cert.der().clone();

    let mut config = ServeConfig::new("localhost", &state);
    (config.https_port, config.qad_port, config.membership_port) = (free_port(), free_port(), free_port());
    config.http_port = Some(free_port());
    config.certificate = Certificate::Files {
        chain: state.join("cert.pem"),
        key: state.join("key.pem"),
    };
    let (https, http, qad, membership) = (
        config.https_port,
        config.http_port.unwrap(),
        config.qad_port,
        config.membership_port,
    );
    let relay = config.relay_url();
    let service = config.service().unwrap();
    let server = tokio::spawn(serve(config));

    for _ in 0..50 {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, https)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
    let client = ServeClient::for_service(endpoint, &service).unwrap();
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
    let lmk_proto::group::Service::Serve { key, .. } = service else {
        unreachable!()
    };
    let direct = ServeClient::new(endpoint, &key.0, "", &[format!("127.0.0.1:{membership}")]).unwrap();
    let service_key = key.0.as_slice().try_into().unwrap();
    let log_ref = lmk_proto::head::reference(&service_key, &[7; 32]);
    let page = direct.read(&[7; 32], &lmk_membership::Frontier::empty(service_key, log_ref)).await.unwrap();
    assert_eq!(page.page().entries[0].0, b"commit");
    let head = direct.head(&[7; 32]).await.unwrap();
    assert_eq!((head.length, head.hash), (page.page().head.length, page.page().head.hash));

    server.abort();
}
