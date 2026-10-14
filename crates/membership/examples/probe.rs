//! Checks a deployed `letmeknow serve` from outside: `probe <service key, hex> <relay URL>` appends to a fresh log
//! through the relay, reads it back, and checks the heads.

use std::sync::Arc;

use anyhow::{Result, ensure};
use iroh::{Endpoint, RelayConfig, RelayMap, RelayMode, endpoint::presets};
use iroh_relay::RelayQuicConfig;
use lmk_membership::{Frontier, client::{Resolve, ServeClient}};
use lmk_proto::{Bytes, directory::Directory, group::Service};
use n0_future::boxed::BoxFuture;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (key, relay) = (hex::decode(&args[1])?, &args[2]);
    let relays = RelayMap::from_iter([RelayConfig::new(relay.parse()?, Some(RelayQuicConfig::default()))]);
    let endpoint = Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(relays)).bind().await?;
    let service: [u8; 32] = key.as_slice().try_into()?;
    let directory = Directory { key: service, addrs: vec![], relay: relay.clone(), relays: vec![relay.clone()] };
    let resolve: Resolve = Arc::new(move |_: String| -> BoxFuture<Result<Directory>> {
        let directory = directory.clone();
        Box::pin(async move { Ok(directory) })
    });
    let membership = Service::Serve { key: Bytes(key), domain: "probe.invalid".into(), rest: Default::default() };
    let client = ServeClient::for_service(endpoint, resolve, &membership)?;
    let log = lmk_proto::random::random::<32>();
    let anchor = Frontier::empty(service, lmk_proto::head::reference(&service, &log));
    let started = std::time::Instant::now();
    let appended = client.append(&log, &[b"probe".to_vec()], false).await?;
    println!("appended at {} in {:?}", appended.position, started.elapsed());
    let page = client.read(&log, &anchor).await?;
    ensure!(page.page().entries.len() == 1 && page.page().head.length == 1, "unexpected probe page");
    println!("read back; heads verified");
    Ok(())
}
