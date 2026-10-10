//! Checks a deployed `letmeknow serve` from outside: `probe <service key, hex> <relay URL>` appends to a fresh log
//! through the relay, reads it back, and checks the heads.

use std::sync::Arc;

use anyhow::{Result, ensure};
use iroh::{Endpoint, RelayConfig, RelayMap, RelayMode, endpoint::presets};
use iroh_relay::RelayQuicConfig;
use lmk_membership::{Membership, client::ServeClient};
use lmk_transport::Iroh;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (key, relay) = (hex::decode(&args[1])?, &args[2]);
    let relays = RelayMap::from_iter([RelayConfig::new(relay.parse()?, Some(RelayQuicConfig::default()))]);
    let endpoint = Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(relays)).bind().await?;
    let client = ServeClient::new(Arc::new(Iroh(endpoint)), &key, relay, &[])?;
    let log = rand::random::<[u8; 16]>();
    let started = std::time::Instant::now();
    let appended = client.append(&log, &[b"probe".to_vec()]).await?;
    println!("appended at {} in {:?}", appended.position, started.elapsed());
    let page = client.read(&log, 0).await?;
    ensure!(page.entries.len() == 1 && page.head.length == 1, "read back {page:?}");
    println!("read back; heads verified");
    Ok(())
}
