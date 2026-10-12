use serde_json::{Value, json};
use std::time::Duration;

#[cfg(not(test))]
const ENDPOINT: &str = "https://registry.npmjs.org/@letmeknow/cli/latest";
#[cfg(test)]
const ENDPOINT: &str = "http://127.0.0.1:0";
const TIMEOUT: Duration = Duration::from_secs(2);
const BODY_LIMIT: usize = 64 * 1024;

fn stable(version: &str) -> Option<[u32; 3]> {
    let mut parts = version.split('.');
    let mut numbers = [0; 3];
    for number in &mut numbers {
        let part = parts.next()?;
        if part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_digit())
            || part.len() > 1 && part.starts_with('0')
        {
            return None;
        }
        *number = part.parse().ok()?;
    }
    parts.next().is_none().then_some(numbers)
}

pub(crate) async fn check(ready: &mut Value) {
    check_at(ready, ENDPOINT, env!("CARGO_PKG_VERSION")).await;
}

async fn check_at(ready: &mut Value, endpoint: &str, current: &str) {
    let result = tokio::time::timeout(TIMEOUT, async {
        let tls = iroh::tls::CaTlsConfig::embedded().client_config(iroh::tls::default_provider()).map_err(|_| "network")?;
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| "network")?;
        let mut response = client.get(endpoint).send().await.map_err(|_| "network")?;
        if response.status() != reqwest::StatusCode::OK {
            return Err("http");
        }
        if response
            .content_length()
            .is_some_and(|length| length > BODY_LIMIT as u64)
        {
            return Err("body_limit");
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "network")? {
            if chunk.len() > BODY_LIMIT - body.len() {
                return Err("body_limit");
            }
            body.extend_from_slice(&chunk);
        }
        #[derive(serde::Deserialize)]
        struct Package {
            version: String,
        }
        let package: Package = serde_json::from_slice(&body).map_err(|_| "invalid")?;
        let latest = stable(&package.version).ok_or("invalid")?;
        Ok((package.version, latest))
    })
    .await
    .unwrap_or(Err("timeout"));
    match result {
        Ok((version, latest)) => {
            let current = stable(current).expect("the release version is stable");
            if latest[..2] > current[..2] {
                ready["newer_version"] = json!(version);
                ready["start_command"] = json!(format!(
                    "npx -y @letmeknow/cli@{}.{} listen",
                    latest[0], latest[1]
                ));
            }
        }
        Err(reason) => ready["version_check_error"] = json!(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn server(response: String, drip: bool) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            socket.read(&mut request).await.unwrap();
            if drip {
                for byte in response.bytes() {
                    if socket.write_all(&[byte]).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            } else if socket.write_all(response.as_bytes()).await.is_err() {
                return;
            }
            std::future::pending::<()>().await;
        });
        (url, task)
    }

    async fn checked(response: String) -> Value {
        let (url, task) = server(response, false).await;
        let mut ready =
            json!({"type": "ready", "bin": "/immutable/bin/letmeknow", "session": "old"});
        check_at(&mut ready, &url, "0.15.1").await;
        task.abort();
        assert_eq!(ready["bin"], "/immutable/bin/letmeknow");
        assert_eq!(ready["session"], "old");
        ready
    }

    fn response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn only_major_minor_advances_notify() {
        for (version, command) in [
            ("0.14.99", None),
            ("0.15.0", None),
            ("0.15.1", None),
            ("0.15.99", None),
            ("0.16.0", Some("npx -y @letmeknow/cli@0.16 listen")),
            ("1.0.3", Some("npx -y @letmeknow/cli@1.0 listen")),
        ] {
            let ready = checked(response(
                &json!({"version": version, "dist": {"tarball": "https://evil.invalid/run"}})
                    .to_string(),
            ))
            .await;
            assert_eq!(
                ready.get("newer_version"),
                command.map(|_| json!(version)).as_ref()
            );
            assert_eq!(
                ready.get("start_command"),
                command.map(|c| json!(c)).as_ref()
            );
            assert!(ready.get("version_check_error").is_none());
            assert!(!ready.to_string().contains("evil.invalid"));
        }
    }

    #[tokio::test]
    async fn malformed_prerelease_and_metadata_never_escape() {
        for body in [
            "{}",
            "{\"version\":42}",
            "secret response",
            "{\"version\":\"0.16.0-beta.1\"}",
            "{\"version\":\"0.16.0+build\"}",
            "{\"version\":\"00.16.0\"}",
            "{\"version\":\"0.016.0\"}",
            "{\"version\":\"0.16\"}",
            "{\"version\":\"0.16.0.1\"}",
            "{\"version\":\" 0.16.0\"}",
            "{\"version\":\"0.16.0; secret\"}",
            "{\"version\":\"0.16.4294967296\"}",
        ] {
            let ready = checked(response(body)).await;
            assert_eq!(
                ready,
                json!({"type":"ready", "bin":"/immutable/bin/letmeknow", "session":"old", "version_check_error":"invalid"})
            );
        }
    }

    #[tokio::test]
    async fn http_errors_and_redirects_are_not_followed_or_printed() {
        let redirect = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for status in [301, 302, 307, 308, 404, 500] {
            let ready = checked(format!(
                "HTTP/1.1 {status} Nope\r\nLocation: http://{}\r\nContent-Length: 6\r\n\r\nsecret",
                redirect.local_addr().unwrap()
            ))
            .await;
            assert_eq!(ready["version_check_error"], "http");
            assert!(ready.get("newer_version").is_none());
            assert!(!ready.to_string().contains("secret"));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), redirect.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn body_limit_with_and_without_content_length() {
        for raw in [
            response(&"x".repeat(BODY_LIMIT + 1)),
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                BODY_LIMIT + 1,
                "x".repeat(BODY_LIMIT + 1)
            ),
        ] {
            let ready = checked(raw).await;
            assert_eq!(ready["version_check_error"], "body_limit");
            assert!(ready.get("newer_version").is_none());
        }
        let body = format!("{{\"version\":\"0.16.0\"}}{}", " ".repeat(BODY_LIMIT - 20));
        assert_eq!(body.len(), BODY_LIMIT);
        assert_eq!(checked(response(&body)).await["newer_version"], "0.16.0");
    }

    #[tokio::test]
    async fn hung_headers_hung_body_and_drips_have_a_total_deadline() {
        for (raw, drip) in [
            (String::new(), false),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".into(),
                false,
            ),
            (response(&"x".repeat(200)), true),
        ] {
            let (url, task) = server(raw, drip).await;
            let started = std::time::Instant::now();
            let mut ready = json!({"type":"ready"});
            tokio::time::timeout(
                TIMEOUT + Duration::from_secs(2),
                check_at(&mut ready, &url, "0.15.1"),
            )
            .await
            .unwrap();
            assert!(started.elapsed() >= TIMEOUT);
            assert_eq!(
                ready,
                json!({"type":"ready", "version_check_error":"timeout"})
            );
            task.abort();
        }
    }

    #[tokio::test]
    async fn offline_check_is_explicit_and_does_not_claim_an_update() {
        let mut ready = json!({"type":"ready"});
        tokio::time::timeout(TIMEOUT + Duration::from_secs(2), check(&mut ready))
            .await
            .unwrap();
        assert_eq!(
            ready,
            json!({"type":"ready", "version_check_error":"network"})
        );
    }
}
