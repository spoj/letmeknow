pub mod cli;
pub mod policy;
pub mod session;
pub mod short;
mod store;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result, anyhow, bail, ensure};
use lmk_core::provider::SqliteProvider;
use lmk_membership::client::{Post, Resolve, https};
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

/// How long a fetched directory answers without another fetch, and how long a fetch of one may take.
const FRESH: Duration = Duration::from_secs(10 * 60);
const FETCH: Duration = Duration::from_secs(5);
/// How long a connection to a service is kept idle: within the 150 seconds the service waits.
const IDLE: Duration = Duration::from_secs(140);
/// How long a domain whose last fetch failed, or is still under way, is not fetched again.
const RETRY: Duration = Duration::from_secs(60);

/// The skill text for agents.
pub const SKILL: &str = include_str!("../../../SKILL.md");

pub fn message_id(hex_id: &str) -> Result<[u8; 32]> {
    hex::decode(hex_id).ok().and_then(|id| id.try_into().ok()).with_context(|| format!("{hex_id} is not a message id"))
}

/// letmeknow.dev's membership service.
pub fn letmeknow_dev() -> Service {
    let key = hex::decode(MEMBERSHIP_KEY).unwrap();
    Service::Serve { key: Bytes(key), domain: DOMAIN.into(), rest: Default::default() }
}

/// How a member shows: this session as "you", another by its fingerprint.
pub fn shown(member: &Value) -> String {
    if member["you"] == true {
        return "you".into();
    }
    member["fp"].as_str().unwrap_or_default().into()
}

pub async fn serve(serve: cli::Serve) -> Result<()> {
    let policy = serve.policy();
    let mut config = lmk_serve::ServeConfig::new(serve.domain, serve.state);
    config.https_port = serve.https_port;
    config.http_port = Some(serve.http_port);
    config.qad_port = serve.qad_port;
    config.policy = policy;
    config.relay_rate_limit = std::num::NonZeroU32::new(serve.relay_kib_per_second << 10).expect("a parsed rate is at least 1 KiB");
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

/// The certificate authorities a session process trusts, the directories it resolves and how it posts to services.
#[derive(Clone)]
pub struct Network {
    pub ca: iroh::tls::CaTlsConfig,
    pub resolve: Resolve,
    pub post: Post,
}

impl Network {
    /// The network of the session at `home`, trusting `ca`.
    pub fn new(home: &Path, ca: iroh::tls::CaTlsConfig) -> Result<Self> {
        let tls = ca.client_config(Arc::new(rustls::crypto::ring::default_provider()))?;
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_idle_timeout(IDLE)
            .timeout(FETCH);
        if let Some(proxy) = proxy() {
            builder = builder.proxy(reqwest::Proxy::all(proxy)?);
        }
        let http = builder.build()?;
        Ok(Network {
            ca,
            resolve: cached(home.join("directories"), fetch(http.clone())),
            post: https(http),
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
/// else the failure. A fetch is not repeated for `RETRY` after one that failed or started, so lookups during a fetch
/// do not start another.
fn cached(dir: PathBuf, fetch: Resolve) -> Resolve {
    let failed: Arc<Mutex<BTreeMap<String, Instant>>> = Default::default();
    Arc::new(move |domain: String| -> BoxFuture<Result<Directory>> {
        let (dir, fetch, failed) = (dir.clone(), fetch.clone(), failed.clone());
        Box::pin(async move {
            let file = dir.join(format!("{}.json", domain.replace(':', "_")));
            if age(&file).is_some_and(|age| age < FRESH) && let Some(directory) = stored(&file) {
                return Ok(directory);
            }
            let recent = {
                let mut failed = failed.lock().unwrap();
                let recent = failed.get(&domain).is_some_and(|at| at.elapsed() < RETRY);
                if !recent {
                    failed.insert(domain.clone(), Instant::now());
                }
                recent
            };
            let fetched = if recent {
                Err(anyhow!("a fetch of {domain} started less than a minute ago and has not succeeded"))
            } else {
                let fetched = fetch(domain.clone()).await;
                if fetched.is_ok() {
                    failed.lock().unwrap().remove(&domain);
                }
                fetched
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

/// Runs a session process until `shutdown`: opens its command channel and its node. A session that stops in no group is
/// deleted.
pub async fn listen(
    config: session::Config,
    home: &Path,
    network: Network,
    print: impl FnMut(String) -> std::io::Result<()>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    own_format(home)?;
    cli::private_dir(&config.dir)?;
    let directory = own_directory(home, &network, &config.membership).await?;
    let membership = Service::Serve { key: Bytes(directory.key.to_vec()), domain: config.membership.clone(), rest: Default::default() };
    // One process runs a session, even when two start at once.
    let held = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(config.dir.join("session.lock"))?;
    match held.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => bail!("this session is already running"),
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    let (inbound, queue) = tokio::sync::mpsc::unbounded_channel();
    cli::open_channel(&config.dir.join("endpoint"), inbound).await?;
    let db = store::open(&config.dir.join("session.db"))?;
    let provider = SqliteProvider::open(&config.dir.join("session.db"))?;
    let node_config = lmk_node::Config { home: config.membership.clone(), post: network.post.clone(), ca: network.ca.clone() };
    let (node, events) = Node::start(provider, node_config).await?;
    let dir = config.dir.clone();
    let mut session = session::Session::open(config, db, node, held, membership).await?;
    session.start(delete_stopped_in_no_group(home.to_owned()));
    session::run(session, queue, events, print, shutdown).await?;
    // A session that stops in no group leaves nothing behind.
    if serde_json::from_slice::<Vec<String>>(&std::fs::read(dir.join("groups.json"))?)?.is_empty() {
        std::fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

/// Refuses a home that another format of letmeknow's state is in, and marks it as this one's.
fn own_format(home: &Path) -> Result<()> {
    let format = home.join("format");
    let found = std::fs::read_to_string(&format).ok().map(|found| found.trim().to_owned());
    match found.as_deref() {
        Some("12") | None => {}
        Some(newer) if newer.parse::<u32>().is_ok_and(|format| format > 12) => bail!(
            "{home} holds state that a newer letmeknow wrote (format {newer}), which this one cannot read: run the newest release, `npx -y @letmeknow/cli@latest --home {home} listen`, or use another --home for this one",
            home = home.display()
        ),
        _ => bail!("{} holds the state of an earlier letmeknow, which this one cannot read: move it away, or use another --home", home.display()),
    }
    cli::private_dir(home)?;
    Ok(std::fs::write(&format, "12\n")?)
}

/// Makes a new session in `home`, living on the relay of `membership`, in a directory named by its fingerprint.
pub fn new_session(home: &Path, membership: &str) -> Result<PathBuf> {
    own_format(home)?;
    let sessions = home.join("sessions");
    cli::private_dir(&sessions)?;
    let new = sessions.join(format!(".new-{:08x}", rand::random::<u32>()));
    cli::private_dir(&new)?;
    let key = lmk_node::create(&SqliteProvider::open(&new.join("session.db"))?, membership)?;
    let dir = sessions.join(lmk_node::fp(&key.0));
    std::fs::rename(&new, &dir)?;
    Ok(dir)
}

/// Deletes the home's stopped sessions in no group, as each would have as it stopped: those that found, started again to
/// invite a new session, that they were removed while stopped. Answers what it warns of: one
/// not deleted, as when Windows finds a file of it open, is tried again as the next session starts.
async fn delete_stopped_in_no_group(home: PathBuf) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    for entry in std::fs::read_dir(home.join("sessions"))?.flatten() {
        let dir = entry.path();
        let deleted = || -> Result<()> {
            let Ok(groups) = std::fs::read(dir.join("groups.json")) else { return Ok(()) };
            if !serde_json::from_slice::<Vec<String>>(&groups)?.is_empty() {
                return Ok(());
            }
            let held = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("session.lock"))?;
            if held.try_lock().is_ok() {
                drop(held);
                std::fs::remove_dir_all(&dir)?;
            }
            Ok(())
        };
        if let Err(error) = deleted() {
            warnings.push(format!("deleting the stopped session {}, in no group: {error:#}", entry.file_name().to_string_lossy()));
        }
    }
    Ok(warnings)
}

/// This machine's sessions: each one's fingerprint, whether its process answers, and its groups as its `groups.json`
/// says.
pub async fn sessions(home: &Path) -> Result<Value> {
    let running = cli::running(home).await;
    let mut sessions = Vec::new();
    for entry in std::fs::read_dir(home.join("sessions")).into_iter().flatten().flatten() {
        let dir = entry.path();
        let Ok(fp) = std::fs::read_to_string(dir.join("fp")) else { continue };
        let groups: Vec<String> = std::fs::read(dir.join("groups.json")).ok().and_then(|groups| serde_json::from_slice(&groups).ok()).unwrap_or_default();
        let mut session = json!({ "fp": fp });
        if !groups.is_empty() {
            session["groups"] = json!(groups);
        }
        if running.contains(&entry.file_name().to_string_lossy().into_owned()) {
            session["running"] = json!(true);
        }
        sessions.push(session);
    }
    sessions.sort_by(|a, b| a["fp"].as_str().cmp(&b["fp"].as_str()));
    Ok(json!({ "sessions": sessions }))
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
