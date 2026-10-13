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
use lmk_membership::client::Resolve;
use lmk_node::Node;
use lmk_proto::Bytes;
use lmk_proto::directory::{Directory, MAX_BYTES, check_domain};
use lmk_proto::group::Service;
use lmk_proto::links::{DOMAIN, MEMBERSHIP_KEY};
use n0_future::boxed::BoxFuture;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Where letmeknow's releases are published.
pub const REGISTRY: &str = "https://registry.npmjs.org";
/// How long `ready` may wait for the registry to say whether a newer minor version is out.
const LOOKUP: Duration = Duration::from_secs(2);
/// How long a fetched directory answers without another fetch, and how long a fetch of one may take.
const FRESH: Duration = Duration::from_secs(10 * 60);
const FETCH: Duration = Duration::from_secs(5);
/// How long a domain whose fetch failed is not fetched again.
const RETRY: Duration = Duration::from_secs(60);

/// The skill text for agents.
pub const SKILL: &str = include_str!("../../../SKILL.md");

pub async fn serve(serve: cli::Serve) -> Result<()> {
    let mut config = lmk_serve::ServeConfig::new(serve.domain, serve.state);
    config.https_port = serve.https_port;
    config.http_port = Some(serve.http_port);
    config.membership_port = serve.membership_port;
    config.relays = serve.relays;
    config.qad_port = serve.qad_port;
    config.policy.disk = serve.disk << 20;
    if let (Some(chain), Some(key)) = (serve.cert, serve.key) {
        config.certificate = lmk_serve::Certificate::Files { chain, key };
    }
    let service = if serve.initialize { config.initialize()? } else { config.service()? };
    if let Service::Serve { key, domain, .. } = service {
        println!("membership: {domain}\nkey: {}", hex::encode(&key.0));
    }
    if serve.initialize { return Ok(()); }
    lmk_serve::serve(config).await
}

/// The relays and certificate authorities a session process reaches its peers through, and the directories it resolves.
#[derive(Clone)]
pub struct Network {
    /// The relays the session lives on instead of its directory's: `--relay`'s.
    pub chosen: Vec<iroh::RelayUrl>,
    /// The relays of its own directory, which `listen` fills in.
    pub relays: Vec<iroh::RelayUrl>,
    pub ca: iroh::tls::CaTlsConfig,
    pub resolve: Resolve,
    http: reqwest::Client,
}

impl Network {
    /// The network of the session at `home`: living on `chosen` relays, and trusting `ca`.
    pub fn new(home: &Path, chosen: &[String], ca: iroh::tls::CaTlsConfig) -> Result<Self> {
        let tls = ca.client_config(Arc::new(rustls::crypto::ring::default_provider()))?;
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(FETCH);
        if let Some(proxy) = proxy() {
            builder = builder.proxy(reqwest::Proxy::all(proxy)?);
        }
        let http = builder.build()?;
        Ok(Network {
            chosen: chosen.iter().map(|relay| relay.parse()).collect::<Result<_, _>>()?,
            relays: Vec::new(),
            ca,
            resolve: cached(home.join("directories"), fetch(http.clone())),
            http,
        })
    }
}

/// The certificate authorities a session process trusts: the built-in ones, and those in the PEM file `LETMEKNOW_CA`
/// names, as a relay of one's own with a self-signed certificate needs.
pub fn ca() -> Result<iroh::tls::CaTlsConfig> {
    let mut ca = iroh::tls::CaTlsConfig::embedded();
    if let Some(path) = std::env::var_os("LETMEKNOW_CA") {
        use rustls_pki_types::{CertificateDer, pem::PemObject};
        let roots: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(&path)?.collect::<Result<_, _>>().context("reading LETMEKNOW_CA")?;
        ca = ca.with_extra_roots(roots);
    }
    Ok(ca)
}

/// The proxy iroh uses: the first of HTTP_PROXY, http_proxy, HTTPS_PROXY and https_proxy that is a URL. NO_PROXY is ignored.
fn proxy() -> Option<String> {
    ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|url| reqwest::Url::parse(url).is_ok()))
}

/// Fetches a domain's directory over https, reading no more than a directory may be.
fn fetch(http: reqwest::Client) -> Resolve {
    Arc::new(move |domain: String| -> BoxFuture<Result<Directory>> {
        let http = http.clone();
        Box::pin(async move {
            let mut response = http.get(Directory::url(&domain)).send().await?.error_for_status()?;
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                body.extend_from_slice(&chunk);
                if body.len() > MAX_BYTES {
                    break;
                }
            }
            Directory::parse(&body)
        })
    })
}

/// Answers a domain's directory from its copy in `dir` while that is younger than `FRESH`. Otherwise fetches it with
/// `fetch`, stores it and answers it; where the fetch fails, answers the copy, else letmeknow.dev's built-in directory,
/// else the failure. A failed fetch is not repeated for `RETRY`.
fn cached(dir: PathBuf, fetch: Resolve) -> Resolve {
    let failed: Arc<Mutex<BTreeMap<String, Instant>>> = Default::default();
    Arc::new(move |domain: String| -> BoxFuture<Result<Directory>> {
        let (dir, fetch, failed) = (dir.clone(), fetch.clone(), failed.clone());
        Box::pin(async move {
            let file = dir.join(format!("{}.json", domain.replace(':', "_")));
            if age(&file).is_some_and(|age| age < FRESH) && let Some(directory) = stored(&file) {
                return Ok(directory);
            }
            let failed_at = failed.lock().unwrap().get(&domain).copied();
            let fetched = match failed_at {
                Some(at) if at.elapsed() < RETRY => Err(anyhow!("the fetch of {domain} failed less than a minute ago")),
                _ => fetch(domain.clone()).await.inspect_err(|_| {
                    failed.lock().unwrap().insert(domain.clone(), Instant::now());
                }),
            };
            match fetched {
                Ok(directory) => {
                    std::fs::create_dir_all(&dir)?;
                    std::fs::write(&file, serde_json::to_vec(&directory)?)?;
                    Ok(directory)
                }
                Err(error) => match stored(&file) {
                    Some(directory) => Ok(directory),
                    None if domain == DOMAIN => Ok(Directory::builtin()),
                    None => Err(error),
                },
            }
        })
    })
}

fn stored(file: &Path) -> Option<Directory> {
    Directory::parse(&std::fs::read(file).ok()?).ok()
}

fn age(file: &Path) -> Option<Duration> {
    std::fs::metadata(file).ok()?.modified().ok()?.elapsed().ok()
}

/// The directory of the own membership service at `domain`. Its key is pinned in `home` at the first directory that names
/// one; a later directory naming another key is refused, and letmeknow.dev's must name the built-in key.
async fn own_directory(home: &Path, network: &Network, domain: &str) -> Result<Directory> {
    ensure!(
        !domain.contains('@') && domain != "letmeknow.dev",
        "--membership <domain> names a membership service by its domain, such as {DOMAIN}, not {domain}: letmeknow 0.17's <key>@<relay> and letmeknow.dev are refused"
    );
    check_domain(domain)?;
    let directory = (network.resolve)(domain.to_owned()).await.with_context(|| format!("the membership service {domain} has no directory"))?;
    let key = hex::encode(directory.key);
    ensure!(domain != DOMAIN || key == MEMBERSHIP_KEY, "{DOMAIN}'s directory names key {key}, not letmeknow's {MEMBERSHIP_KEY}");
    let pins = home.join("membership.json");
    let mut pinned: BTreeMap<String, String> = if pins.exists() { serde_json::from_slice(&std::fs::read(&pins)?)? } else { BTreeMap::new() };
    match pinned.get(domain) {
        Some(pin) => ensure!(*pin == key, "the directory of {domain} names key {key}, but this home pinned {pin} at its first start"),
        None => {
            pinned.insert(domain.to_owned(), key);
            std::fs::write(&pins, serde_json::to_vec(&pinned)?)?;
        }
    }
    Ok(directory)
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
    let found = std::fs::read_to_string(&format).ok().map(|found| found.trim().to_owned());
    match found.as_deref() {
        Some("7") => {}
        None if !home.join("device.json").exists() => {}
        Some("6") => bail!(
            "{home} holds state that letmeknow 0.17 wrote (format 6), which this one cannot read: to keep using it, run `npx -y @letmeknow/cli@0.17 --home {home} listen`, or use another --home for this one",
            home = home.display()
        ),
        Some("5") => bail!(
            "{home} holds state that letmeknow 0.16 wrote (format 5), which this one cannot read: to keep using it, run `npx -y @letmeknow/cli@0.16 --home {home} listen`, or use another --home for this one",
            home = home.display()
        ),
        Some(newer) if newer.parse::<u32>().is_ok_and(|format| format > 7) => bail!(
            "{home} holds state that a newer letmeknow wrote (format {newer}), which this one cannot read: run the newest release, `npx -y @letmeknow/cli@latest --home {home} listen`, or use another --home for this one",
            home = home.display()
        ),
        _ => bail!("{} holds the state of an earlier letmeknow, which this one cannot read: move it away, or use another --home", home.display()),
    }
    cli::private_dir(&config.dir)?;
    std::fs::write(&format, "7\n")?;
    let directory = own_directory(home, &network, &config.membership).await?;
    let membership = Service::Serve { key: Bytes(directory.key.to_vec()), domain: config.membership.clone(), rest: Default::default() };
    let relays = directory.relays.iter().map(|relay| relay.parse()).collect::<Result<_, _>>()?;
    let network = Network { relays, ..network };
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
    let lookup = newer_minor(network.clone(), config.registry.clone());
    let (session, newer) = tokio::join!(session::Session::open(config, db, node, home, network, inbound, held, membership), lookup);
    session::run(session?, queue, events, print, shutdown, newer).await
}

/// The version of the newest release on `registry`, if its minor version is newer than this one's. Nothing if the registry
/// does not answer within `LOOKUP`.
async fn newer_minor(network: Network, registry: String) -> Option<String> {
    let body = network.http.get(format!("{registry}/@letmeknow/cli")).timeout(LOOKUP).send().await.ok()?.text().await.ok()?;
    let latest = semver::Version::parse(serde_json::from_str::<Value>(&body).ok()?["dist-tags"]["latest"].as_str()?).ok()?;
    let own = semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("this crate's version");
    ((latest.major, latest.minor) > (own.major, own.minor)).then(|| latest.to_string())
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

/// How long removing a session waits for the other members of its groups to remove it.
const LEAVE_WAIT: Duration = Duration::from_secs(60);

/// Removes a session: stops its process if one runs, runs it here, printing nothing, until the other members of each of its
/// groups have removed it, and deletes it. Fails, keeping the session, where that does not happen within `LEAVE_WAIT`.
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
                waiting.push((group["group"].clone(), group["name"].clone()));
            }
        }
        let held = async {
            while !waiting.is_empty() {
                let line: Value = serde_json::from_str(&printed.recv().await.context("the session stopped")?)?;
                // A line names a group by its name where no other group of the session's has it, else by its id.
                if line["type"] == "removed" {
                    waiting.retain(|(id, name)| *id != line["group"] && *name != line["group"]);
                }
            }
            anyhow::Ok(())
        };
        tokio::time::timeout(LEAVE_WAIT, held).await.map_err(|_| anyhow!("a group it left has not removed the session yet: the session stays; remove it again once another member is online"))??;
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
        relays: network.relays.clone(),
        chosen: network.chosen.clone(),
        resolve: network.resolve.clone(),
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
