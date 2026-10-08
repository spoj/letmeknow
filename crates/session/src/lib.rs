pub mod cli;
pub mod doc;
pub mod node;
pub mod policy;
pub mod session;
mod store;
#[cfg(test)]
mod fake;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lmk_proto::Bytes;
use lmk_proto::group::Service;

/// letmeknow.dev's relay, which links leave out.
pub const RELAY: &str = "https://letmeknow.dev";

/// letmeknow.dev's membership service. Its key is fixed when the service is first deployed.
pub fn letmeknow_dev() -> Service {
    Service::Serve { key: Bytes(vec![0; 32]), relay: RELAY.into(), addrs: Vec::new() }
}

/// A membership service from its address: `letmeknow.dev`, `<iroh key>@<relay URL>`, or a folder's absolute path.
pub fn service(address: &str) -> Result<Service> {
    if address == "letmeknow.dev" {
        return Ok(letmeknow_dev());
    }
    if cli::is_folder(address) {
        return Ok(Service::Folder(address.into()));
    }
    let (key, relay) = address.split_once('@').context("a membership service is letmeknow.dev, <key>@<relay URL>, or a folder")?;
    Ok(Service::Serve { key: Bytes(URL_SAFE_NO_PAD.decode(key)?), relay: relay.into(), addrs: Vec::new() })
}

/// The skill text for agents.
pub const SKILL: &str = include_str!("../SKILL.md");

pub async fn serve(serve: cli::Serve) -> Result<()> {
    let mut config = lmk_serve::ServeConfig::new(serve.domain, serve.state);
    config.https_port = serve.https_port;
    config.http_port = Some(serve.http_port);
    config.membership_port = serve.membership_port;
    config.web = serve.web;
    if let (Some(chain), Some(key)) = (serve.cert, serve.key) {
        config.certificate = lmk_serve::Certificate::Files { chain, key };
    }
    lmk_serve::serve(config).await
}

/// Runs a session process: opens its state and command channel, then `session::run` until `shutdown`. `parts` makes
/// the group logic, peers and membership client, which send what arrives to the given channel.
pub async fn listen<C: node::Core, P: node::Peers, L: node::Log>(
    config: session::Config,
    parts: impl FnOnce(&session::Config, tokio::sync::mpsc::UnboundedSender<node::Inbound>) -> Result<(C, P, L)>,
    print: impl FnMut(String),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    cli::private_dir(&config.dir)?;
    let (inbound, queue) = tokio::sync::mpsc::unbounded_channel();
    cli::open_channel(&config.dir, inbound.clone()).await?;
    let (core, peers, log) = parts(&config, inbound.clone())?;
    let session = session::Session::open(config, core, peers, log, inbound)?;
    session::run(session, queue, print, shutdown).await
}

/// Resolves on Ctrl-C or, on Unix, SIGTERM.
pub async fn shutdown() {
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => drop(terminate.recv().await),
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate => {}
    }
}
