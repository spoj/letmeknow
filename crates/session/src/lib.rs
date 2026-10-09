pub mod cli;
pub mod kinds;
pub mod policy;
pub mod session;
mod store;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use lmk_core::device::Device;
use lmk_core::group::Window;
use lmk_core::provider::SqliteProvider;
use lmk_node::Node;
use lmk_proto::Bytes;
use lmk_proto::group::Service;
use std::path::{Path, PathBuf};

pub use lmk_proto::links::RELAY;

/// letmeknow.dev's membership service.
pub fn letmeknow_dev() -> Service {
    let key = hex::decode(lmk_proto::links::MEMBERSHIP_KEY).unwrap();
    Service::Serve { key: Bytes(key), relay: RELAY.into(), addrs: Vec::new() }
}

/// A membership service from its address: `letmeknow.dev`, `<iroh key, hex>@<relay URL>`, or a folder's absolute path.
pub fn service(address: &str) -> Result<Service> {
    if address == "letmeknow.dev" {
        return Ok(letmeknow_dev());
    }
    if let Some((key, relay)) = address.split_once("@https://") {
        let key = Bytes(hex::decode(key).context("a service key is hex")?);
        return Ok(Service::Serve { key, relay: format!("https://{relay}"), addrs: Vec::new() });
    }
    anyhow::ensure!(cli::is_folder(address), "a membership service is letmeknow.dev, <key>@<relay URL>, or a folder");
    Ok(Service::Folder(address.into()))
}

/// The skill text for agents.
pub const SKILL: &str = include_str!("../../../SKILL.md");

pub async fn serve(serve: cli::Serve) -> Result<()> {
    let mut config = lmk_serve::ServeConfig::new(serve.domain, serve.state);
    config.https_port = serve.https_port;
    config.http_port = Some(serve.http_port);
    config.membership_port = serve.membership_port;
    config.qad_port = serve.qad_port;
    config.web = serve.web;
    if let (Some(chain), Some(key)) = (serve.cert, serve.key) {
        config.certificate = lmk_serve::Certificate::Files { chain, key };
    }
    if let Service::Serve { key, relay, .. } = config.service()? {
        println!("membership: {}@{relay}", hex::encode(&key.0));
    }
    lmk_serve::serve(config).await
}

/// The relay and the certificate authorities a session process reaches its peers through.
#[derive(Clone)]
pub struct Network {
    pub relay: iroh::RelayUrl,
    pub ca: iroh::tls::CaTlsConfig,
}

impl Network {
    /// The relay at `relay`, trusting also the certificates in the PEM file `LETMEKNOW_CA` names, as a relay of one's
    /// own with a self-signed certificate needs.
    pub fn new(relay: &str) -> Result<Self> {
        let mut ca = iroh::tls::CaTlsConfig::embedded();
        if let Some(path) = std::env::var_os("LETMEKNOW_CA") {
            use rustls_pki_types::{CertificateDer, pem::PemObject};
            let roots: Vec<CertificateDer<'static>> =
                CertificateDer::pem_file_iter(&path)?.collect::<Result<_, _>>().context("reading LETMEKNOW_CA")?;
            ca = ca.with_extra_roots(roots);
        }
        Ok(Network { relay: relay.parse()?, ca })
    }
}

/// Runs a session process until `shutdown`: opens its command channel and its node; the session acts for the device
/// too while no other session process of the device does.
pub async fn listen(
    config: session::Config,
    home: &Path,
    network: Network,
    print: impl FnMut(String),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    cli::private_dir(&config.dir)?;
    let (inbound, queue) = tokio::sync::mpsc::unbounded_channel();
    cli::open_channel(&config.dir.join("endpoint"), inbound.clone()).await?;
    let device_file = home.join("device.json");
    let device = match device_file.exists() {
        true => Device::load(&device_file)?,
        false => {
            let device = Device::new(&gethostname::gethostname().to_string_lossy());
            device.save(&device_file)?;
            device
        }
    };
    let provider = SqliteProvider::open(&config.dir.join("session.db"))?;
    let kinds = [lmk_proto::group::CHAT.to_owned()].into_iter().chain(kinds::discover(&config.plugins).into_keys()).collect();
    let node_config = node_config(&network, home, &config.name, false, config.dir.join("files"), kinds);
    let node_config = lmk_node::Config { window: config.window, ..node_config };
    let (node, events) = Node::start(provider, device, node_config).await?;
    let session = session::Session::open(config, node, home, network, inbound).await?;
    session::run(session, queue, events, print, shutdown).await
}

fn node_config(network: &Network, home: &Path, name: &str, device_key: bool, files: PathBuf, kinds: Vec<String>) -> lmk_node::Config {
    lmk_node::Config {
        name: name.into(),
        device_key,
        relay: network.relay.clone(),
        ca: network.ca.clone(),
        home: Some(home.to_path_buf()),
        files: Some(files),
        disk: None,
        file_limit: 100 << 20,
        window: Window::default(),
        kinds,
    }
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
