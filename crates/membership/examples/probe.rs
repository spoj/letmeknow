//! Checks a deployed `letmeknow serve` from outside: `probe <service key, hex> <domain>` appends to a fresh log over
//! HTTPS, reads it back, and checks the heads.

use std::sync::Arc;

use anyhow::{Result, ensure};
use lmk_membership::{Frontier, client::{ServeClient, https}};
use lmk_proto::{Bytes, group::Service};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (key, domain) = (hex::decode(&args[1])?, args[2].clone());
    let tls = iroh::tls::CaTlsConfig::embedded().client_config(Arc::new(rustls::crypto::ring::default_provider()))?;
    let http = reqwest::Client::builder().tls_backend_preconfigured(tls).no_proxy().build()?;
    let service: [u8; 32] = key.as_slice().try_into()?;
    let membership = Service::Serve { key: Bytes(key), domain, rest: Default::default() };
    let client = ServeClient::for_service(https(http), &membership)?;
    let log = lmk_proto::random::random::<32>();
    let anchor = Frontier::empty(service, lmk_proto::head::reference(&service, &log));
    let started = std::time::Instant::now();
    let appended = client.append(&log, &[b"probe".to_vec()]).await?;
    println!("appended at {} in {:?}", appended.position, started.elapsed());
    let page = client.read(&log, &anchor).await?;
    ensure!(page.page().entries.len() == 1 && page.page().head.length == 1, "unexpected probe page");
    println!("read back; heads verified");
    Ok(())
}
