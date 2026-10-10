pub mod cli;
pub mod kinds;
pub mod policy;
pub mod session;
mod store;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result, ensure};
use lmk_core::device::Device;
use lmk_core::provider::SqliteProvider;
use lmk_node::Node;
use lmk_proto::group::Service;
use std::path::{Path, PathBuf};

pub use lmk_proto::links::RELAY;

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
    print: impl FnMut(String) -> std::io::Result<()>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let format = home.join("format");
    let found = std::fs::read_to_string(&format).ok();
    ensure!(
        found.as_deref().map(str::trim) == Some("3") || found.is_none() && !home.join("device.json").exists(),
        "{} holds the state of an earlier letmeknow, which this one cannot read: move it away, or use another --home",
        home.display()
    );
    cli::private_dir(&config.dir)?;
    std::fs::write(&format, "3\n")?;
    let (inbound, queue) = tokio::sync::mpsc::unbounded_channel();
    cli::open_channel(&config.dir.join("endpoint"), inbound.clone()).await?;
    let device_file = home.join("device.json");
    if !device_file.exists() {
        Device::new(&gethostname::gethostname().to_string_lossy()).save(&device_file)?;
    }
    let db = store::open(&config.dir.join("session.db"))?;
    let name = session::Session::name(&db, &config)?;
    let provider = SqliteProvider::open(&config.dir.join("session.db"))?;
    let kinds = [lmk_proto::group::CHAT.to_owned()].into_iter().chain(kinds::discover(&config.plugins).into_keys()).collect();
    let node_config = node_config(&network, home, &name, None, config.dir.join("files"), kinds);
    let (node, events) = Node::start(provider, node_config).await?;
    let session = session::Session::open(config, (db, name), node, home, network, inbound).await?;
    session::run(session, queue, events, print, shutdown).await
}

fn node_config(network: &Network, home: &Path, name: &str, device: Option<Device>, files: PathBuf, kinds: Vec<String>) -> lmk_node::Config {
    lmk_node::Config {
        name: name.into(),
        device,
        relay: network.relay.clone(),
        ca: network.ca.clone(),
        home: Some(home.to_path_buf()),
        files: Some(files),
        disk: None,
        file_limit: 100 << 20,
        kinds,
        durable: None,
        observe: None,
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
