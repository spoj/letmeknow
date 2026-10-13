pub mod cli;
pub mod kinds;
pub mod policy;
pub mod session;
pub mod short;
mod store;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result, anyhow, bail, ensure};
use lmk_core::device::Device;
use lmk_core::provider::SqliteProvider;
use lmk_node::Node;
use lmk_proto::group::Service;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use lmk_proto::links::RELAY;

/// The skill text for agents.
pub const SKILL: &str = include_str!("../../../SKILL.md");

pub async fn serve(serve: cli::Serve) -> Result<()> {
    let mut config = lmk_serve::ServeConfig::new(serve.domain, serve.state);
    config.https_port = serve.https_port;
    config.http_port = Some(serve.http_port);
    config.membership_port = serve.membership_port;
    config.qad_port = serve.qad_port;
    config.policy.disk = serve.disk << 20;
    if let (Some(chain), Some(key)) = (serve.cert, serve.key) {
        config.certificate = lmk_serve::Certificate::Files { chain, key };
    }
    let service = if serve.initialize { config.initialize()? } else { config.service()? };
    if let Service::Serve { key, relay, .. } = service {
        println!("membership: {}@{relay}", hex::encode(&key.0));
    }
    if serve.initialize { return Ok(()); }
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
        found.as_deref().map(str::trim) == Some("5") || found.is_none() && !home.join("device.json").exists(),
        "{} holds the state of an earlier letmeknow, which this one cannot read: move it away, or use another --home",
        home.display()
    );
    cli::private_dir(&config.dir)?;
    std::fs::write(&format, "5\n")?;
    // One process runs a session, even when two start at once.
    let held = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(config.dir.join("session.lock"))?;
    match held.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => bail!("session {} is already running", config.handle),
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    let (inbound, queue) = tokio::sync::mpsc::unbounded_channel();
    cli::open_channel(&config.dir.join("endpoint"), inbound.clone()).await?;
    let device_file = home.join("device.json");
    if !device_file.exists() {
        Device::new(&gethostname::gethostname().to_string_lossy()).save(&device_file)?;
    }
    let db = store::open(&config.dir.join("session.db"))?;
    let provider = SqliteProvider::open(&config.dir.join("session.db"))?;
    let kinds = [lmk_proto::group::CHAT.to_owned()].into_iter().chain(kinds::discover(&config.plugins).into_keys()).collect();
    let node_config = node_config(&network, home, &config.handle, None, config.dir.join("files"), kinds);
    let (node, events) = Node::start(provider, node_config).await?;
    let session = session::Session::open(config, db, node, home, network, inbound, held).await?;
    session::run(session, queue, events, print, shutdown).await
}

/// This machine's sessions: each one's handle, whether its process answers, and its groups as it last wrote them.
pub async fn sessions(home: &Path) -> Result<Value> {
    let running = cli::running(home).await;
    let mut sessions = Vec::new();
    for entry in std::fs::read_dir(home.join("sessions")).into_iter().flatten().flatten() {
        let (dir, handle) = (entry.path(), entry.file_name().to_string_lossy().into_owned());
        let groups: Value = std::fs::read(dir.join("groups.json")).ok().and_then(|groups| serde_json::from_slice(&groups).ok()).unwrap_or(json!([]));
        sessions.push(json!({ "running": running.contains(&handle), "handle": handle, "groups": groups }));
    }
    sessions.sort_by(|a, b| a["handle"].as_str().cmp(&b["handle"].as_str()));
    Ok(json!({ "sessions": sessions }))
}

/// How long removing a session waits for another member of each of its groups to hold its leave.
const LEAVE_WAIT: Duration = Duration::from_secs(60);

/// Removes a session: stops its process if one runs, runs it here, printing nothing, until another member of each of its
/// groups holds its leave, and deletes it. Fails, keeping the session, where a leave is not held within `LEAVE_WAIT`.
/// Runs on a `LocalSet`, as `listen` does.
pub async fn remove(config: session::Config, home: &Path, network: Network) -> Result<Value> {
    let (handle, dir) = (config.handle.clone(), config.dir.clone());
    ensure!(dir.join("session.db").exists(), "no session {handle} here");
    if cli::connect(&dir.join("endpoint")).await.is_ok() {
        // Answered once it stopped, or not at all as its process exits.
        let _ = cli::call(home, &handle, cli::Request::Stop).await;
    }
    let (lines, mut printed) = tokio::sync::mpsc::unbounded_channel();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let at = home.to_path_buf();
    let running = tokio::task::spawn_local(async move {
        let print = move |line: String| {
            lines.send(line).ok();
            Ok(())
        };
        listen(config, &at, network, print, async { drop(stopped.await) }).await
    });
    let left = async {
        while let Some(line) = printed.recv().await {
            if serde_json::from_str::<Value>(&line)?["type"] == "ready" {
                break;
            }
        }
        let groups = cli::call(home, &handle, cli::Request::Client(lmk_client::Request::Groups)).await?;
        let mut waiting = Vec::new();
        for group in groups.as_array().context("groups are a list")? {
            let leave = lmk_client::Request::Leave { group: group["group"].as_str().map(str::to_owned), end: false };
            if cli::call(home, &handle, cli::Request::Client(leave)).await?["pending"] == true {
                waiting.push(group["group"].clone());
            }
        }
        let held = async {
            while !waiting.is_empty() {
                let line: Value = serde_json::from_str(&printed.recv().await.context("the session stopped")?)?;
                if line["type"] == "leave_held" || line["type"] == "removed" {
                    waiting.retain(|group| *group != line["group"]);
                }
            }
            anyhow::Ok(())
        };
        tokio::time::timeout(LEAVE_WAIT, held).await.map_err(|_| anyhow!("no other member of a group it left held its leave: the session stays; remove it again once one is online"))??;
        anyhow::Ok(groups)
    };
    let left = left.await;
    stop.send(()).ok();
    running.await??;
    let groups = left?;
    std::fs::remove_dir_all(&dir)?;
    Ok(json!({ "removed": handle, "left": groups.as_array().unwrap().iter().map(|g| &g["group"]).collect::<Vec<_>>() }))
}

fn node_config(network: &Network, home: &Path, handle: &str, device: Option<Device>, files: PathBuf, kinds: Vec<String>) -> lmk_node::Config {
    lmk_node::Config {
        handle: handle.into(),
        device,
        relay: network.relay.clone(),
        ca: network.ca.clone(),
        home: Some(home.to_path_buf()),
        files: Some(files),
        disk: None,
        file_limit: 100 << 20,
        kinds,
        durable: None,
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
