use anyhow::{Result, ensure};
use iroh::{
    Endpoint, EndpointAddr, RelayMode,
    endpoint::{ConnectionError, presets},
};
use std::{net::SocketAddr, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(args.len() == 4, "KEY LOOPBACK_ADDRESS ALPN accept|refuse");
    let address: SocketAddr = args[1].parse()?;
    ensure!(address.ip().is_loopback(), "only loopback test endpoints");
    ensure!(matches!(args[3].as_str(), "accept" | "refuse"), "accept|refuse required");
    let endpoint = Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled).bind().await?;
    let target = EndpointAddr::new(args[0].parse()?).with_ip_addr(address);
    let result = tokio::time::timeout(Duration::from_secs(10), endpoint.connect(target, args[2].as_bytes())).await?;
    match (args[3].as_str(), result) {
        ("accept", Ok(connection)) => {
            connection.close(0u32.into(), b"fixture complete");
            println!("accepted");
        }
        ("refuse", Err(error)) => {
            let error = anyhow::Error::new(error);
            ensure!(
                error.chain().any(|cause| matches!(cause.downcast_ref::<ConnectionError>(),
                    Some(ConnectionError::ConnectionClosed(close)) if u64::from(close.error_code) == 0x178)),
                "not TLS no_application_protocol: {error:#}"
            );
            println!("refused: TLS no_application_protocol (0x178)");
        }
        (_, Ok(_)) => anyhow::bail!("ALPN unexpectedly accepted"),
        (_, Err(error)) => anyhow::bail!("ALPN unexpectedly refused: {error:#}"),
    }
    endpoint.close().await;
    Ok(())
}
