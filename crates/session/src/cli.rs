//! The `letmeknow` command line: `listen` runs a session process; most other commands are requests to it, over a
//! localhost port guarded by a token.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::session::Inbound;
use lmk_client::{IdentityOp, is_folder};

/// End-to-end encrypted chats and documents for agents and their people.
#[derive(Parser)]
#[command(name = "letmeknow", version)]
pub struct Cli {
    /// Agent session; each session is its own group member [default: listen picks a new handle; other commands use the one running session]
    #[arg(long, env = "LETMEKNOW_SESSION", global = true)]
    pub session: Option<String>,
    /// Where sessions and the device keep their state [default: the user's local data directory]
    #[arg(long, env = "LETMEKNOW_HOME", global = true)]
    pub home: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the session process, which runs the plugins of its groups' kinds, and print what arrives as NDJSON
    Listen {
        /// Display name, fixed when the session is created [default: <user>/<session>]
        #[arg(long, env = "LETMEKNOW_NAME")]
        name: Option<String>,
        /// Seconds a message or doc edit not addressed to this session may wait for something that wakes the agent anyway
        #[arg(long, env = "LETMEKNOW_HOLD", default_value_t = 3600)]
        hold: u64,
        /// Keep the text of messages once delivered, for audit; by default only ids, senders and references are kept
        #[arg(long)]
        keep_log: bool,
        /// The membership service for groups and identities this session creates: letmeknow.dev, <key, hex>@<relay URL>, or a folder
        #[arg(long, env = "LETMEKNOW_MEMBERSHIP", default_value = "letmeknow.dev")]
        membership: String,
        /// The relay this session is reached through
        #[arg(long, env = "LETMEKNOW_RELAY", default_value = crate::RELAY)]
        relay: String,
    },
    /// Print instructions for agents
    Skill,
    /// Run a membership service, an iroh relay and the web client (letmeknow.dev)
    Serve(Serve),
    /// git's remote helper for lmk:: remotes, where `git-remote-lmk` is not on PATH:
    /// `git config --global alias.remote-lmk '!letmeknow git-remote-lmk'`
    #[command(name = "git-remote-lmk")]
    GitRemoteLmk {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    #[command(flatten)]
    Request(Request),
    /// A command of a kind's plugin: `letmeknow <kind> <args>...`, such as `letmeknow doc attach <path>`
    #[command(external_subcommand)]
    Kind(Vec<String>),
}

#[derive(clap::Args, Debug)]
pub struct Serve {
    /// The domain to serve, with a certificate from Let's Encrypt unless --cert is given
    #[arg(long)]
    pub domain: String,
    #[arg(long, default_value_t = 443)]
    pub https_port: u16,
    #[arg(long, default_value_t = 80)]
    pub http_port: u16,
    /// The membership service's UDP port
    #[arg(long, default_value_t = 7843)]
    pub membership_port: u16,
    /// QUIC address discovery's UDP port
    #[arg(long, default_value_t = 7842)]
    pub qad_port: u16,
    /// Logs, keys and certificates
    #[arg(long)]
    pub state: PathBuf,
    /// The web client's files
    #[arg(long)]
    pub web: Option<PathBuf>,
    /// A certificate (PEM) to use instead of Let's Encrypt, with --key
    #[arg(long, requires = "key")]
    pub cert: Option<PathBuf>,
    #[arg(long, requires = "cert")]
    pub key: Option<PathBuf>,
}

/// Requests an agent sends to its session process: the client core's, and those of its own.
#[derive(Subcommand, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Send a message in a chat ("-" reads the text from stdin)
    #[command(display_order = 12)]
    Send {
        #[arg(long)]
        group: Option<String>,
        /// A member to address: its fingerprint, or a name it answers to (its name, the first word of it, or its
        /// identity's contact name, which addresses all that identity's sessions); repeat for several. "@name" in the text addresses too
        #[arg(long)]
        to: Vec<String>,
        /// Id of the message this answers
        #[arg(long)]
        reply_to: Option<String>,
        /// Deliver at once to every member, not only those addressed
        #[arg(long)]
        urgent: bool,
        /// File to attach ("-" reads stdin); each recipient's session saves it into a private file
        #[arg(long, value_name = "FILE")]
        attach: Option<String>,
        /// The attached file's name, set from its path
        #[arg(skip)]
        #[serde(default)]
        attach_name: String,
        text: String,
    },
    /// Show a message and its causal history
    #[command(display_order = 13)]
    Read {
        id: String,
        #[arg(long, default_value_t = 0)]
        ancestors: usize,
    },
    /// The file a message or a group's kind (a doc) links, decrypted into a file only you can read; prints its path
    #[command(display_order = 20)]
    Fetch { link: String },
    /// A command of a kind's plugin, from `letmeknow <kind> <args>...`.
    #[command(skip)]
    Kind { kind: String, args: Vec<String>, cwd: String },
    #[command(flatten)]
    #[serde(untagged)]
    Client(lmk_client::Request),
}

/// Where a running session process accepts requests: a localhost port guarded by a token.
#[derive(Serialize, Deserialize)]
struct Endpoint {
    port: u16,
    token: String,
}

#[derive(Serialize, Deserialize)]
struct Call {
    token: String,
    request: Request,
}

pub fn home_dir(home: Option<PathBuf>) -> Result<PathBuf> {
    match home {
        Some(home) => Ok(home),
        None => Ok(dirs::data_local_dir().context("no local data directory")?.join("letmeknow")),
    }
}

pub fn session_dir(home: &Path, session: &str) -> Result<PathBuf> {
    if session.is_empty() || !session.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        bail!("session names may contain only letters, digits, '.', '_' and '-'");
    }
    Ok(home.join("sessions").join(session))
}

const ADJECTIVES: [&str; 32] = [
    "amber", "bold", "brave", "brisk", "calm", "clever", "cosmic", "crisp", "eager", "fancy", "gentle", "glad", "golden",
    "happy", "jolly", "keen", "lively", "lucky", "mellow", "merry", "nimble", "proud", "quick", "quiet", "rapid", "shiny",
    "silver", "steady", "sunny", "swift", "tidy", "witty",
];
const NOUNS: [&str; 32] = [
    "badger", "beaver", "bison", "crane", "dolphin", "eagle", "falcon", "ferret", "finch", "fox", "gecko", "heron", "ibis",
    "jaguar", "koala", "lemur", "lynx", "marten", "moose", "newt", "otter", "owl", "panda", "puffin", "quail", "raven",
    "robin", "seal", "stoat", "tapir", "walrus", "wren",
];

/// A two-word handle not used by any existing session.
pub fn new_handle(home: &Path) -> Result<String> {
    loop {
        let [a, b]: [u8; 2] = rand::random();
        let handle = format!("{}-{}", ADJECTIVES[a as usize % 32], NOUNS[b as usize % 32]);
        if !session_dir(home, &handle)?.exists() {
            return Ok(handle);
        }
    }
}

pub async fn running_session(home: &Path) -> Result<String> {
    let mut running = Vec::new();
    for entry in std::fs::read_dir(home.join("sessions")).into_iter().flatten().flatten() {
        if connect(&entry.path().join("endpoint")).await.is_ok() {
            running.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    match running.as_slice() {
        [session] => Ok(session.clone()),
        [] => bail!("no session is running; start one with `letmeknow listen`"),
        _ => bail!("several sessions are running ({}); pass --session", running.join(", ")),
    }
}

pub async fn connect(endpoint: &Path) -> Result<(TcpStream, String)> {
    let endpoint: Endpoint = serde_json::from_slice(&std::fs::read(endpoint)?)?;
    Ok((TcpStream::connect(("127.0.0.1", endpoint.port)).await?, endpoint.token))
}

/// Opens a command channel, written to `endpoint_path`: requests that come with its token go to `inbound`.
pub async fn open_channel(endpoint_path: &Path, inbound: mpsc::UnboundedSender<Inbound>) -> Result<()> {
    if connect(endpoint_path).await.is_ok() {
        bail!("{} is already answered by a running session", endpoint_path.display());
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let token = hex::encode(rand::random::<[u8; 32]>());
    let endpoint = Endpoint { port: listener.local_addr()?.port(), token: token.clone() };
    private_file(endpoint_path, &serde_json::to_vec(&endpoint)?)?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(answer(stream, token.clone(), inbound.clone()));
        }
    });
    Ok(())
}

async fn answer(stream: TcpStream, token: String, inbound: mpsc::UnboundedSender<Inbound>) {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    if BufReader::new(read).read_line(&mut line).await.is_err() {
        return;
    }
    let response = match serde_json::from_str::<Call>(&line) {
        Ok(call) if call.token == token => {
            let (reply, answer) = oneshot::channel();
            let _ = inbound.send((call.request, reply));
            answer.await.unwrap_or_else(|_| json!({ "error": "session process stopped" }))
        }
        Ok(_) => json!({ "error": "bad token" }),
        Err(error) => json!({ "error": format!("bad request: {error}") }),
    };
    let _ = write.write_all(format!("{response}\n").as_bytes()).await;
}

/// Sends a request to the running session and returns its answer. Files the request names are read, or made absolute,
/// here, and a kind's arguments go with this directory: the session process runs elsewhere.
pub async fn call(home: &Path, session: &str, mut request: Request) -> Result<Value> {
    if let Request::Send { text, attach, attach_name, .. } = &mut request {
        if let Some(file) = attach {
            let (bytes, name) = match file.as_str() {
                "-" => {
                    let mut bytes = Vec::new();
                    std::io::stdin().read_to_end(&mut bytes)?;
                    (bytes, "attachment".into())
                }
                path => {
                    let name = Path::new(path).file_name().context("--attach names no file")?.to_string_lossy().into_owned();
                    (std::fs::read(path).with_context(|| format!("cannot read {path}"))?, name)
                }
            };
            *attach_name = name;
            *file = B64.encode(bytes);
        }
        if text == "-" {
            text.clear();
            std::io::stdin().read_to_string(text)?;
        }
    }
    if let Request::Client(lmk_client::Request::Invite { cwd, .. } | lmk_client::Request::Join { cwd, .. }) | Request::Kind { cwd, .. } =
        &mut request
    {
        *cwd = absolute(".")?;
    }
    let membership = match &mut request {
        Request::Client(
            lmk_client::Request::Invite { membership, .. } | lmk_client::Request::Identity { op: IdentityOp::Create { membership, .. } },
        ) => membership.as_mut(),
        _ => None,
    };
    if let Some(membership) = membership.filter(|m| is_folder(m)) {
        *membership = absolute(membership)?;
    }
    let channel = connect(&session_dir(home, session)?.join("endpoint"))
        .await
        .with_context(|| format!("session {session} is not running; start it with `letmeknow --session {session} listen`"))?;
    exchange(channel, request).await
}

/// Sends a request over a command channel and returns its answer.
pub async fn exchange((stream, token): (TcpStream, String), request: Request) -> Result<Value> {
    let (read, mut write) = stream.into_split();
    write.write_all(format!("{}\n", serde_json::to_string(&Call { token, request })?).as_bytes()).await?;
    let mut line = String::new();
    BufReader::new(read).read_line(&mut line).await?;
    let response: Value = serde_json::from_str(&line).context("session process closed the connection")?;
    if let Some(error) = response.get("error").and_then(Value::as_str) {
        bail!("{error}");
    }
    Ok(response)
}

fn absolute(path: &str) -> Result<String> {
    let absolute: PathBuf = std::path::absolute(path)?.components().collect();
    Ok(absolute.to_str().context("path is not UTF-8")?.to_owned())
}

#[cfg(unix)]
pub fn private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    Ok(std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?)
}

#[cfg(not(unix))]
pub fn private_dir(dir: &Path) -> Result<()> {
    Ok(std::fs::create_dir_all(dir)?)
}

#[cfg(unix)]
pub fn private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    Ok(file.write_all(contents)?)
}

#[cfg(not(unix))]
pub fn private_file(path: &Path, contents: &[u8]) -> Result<()> {
    Ok(std::fs::write(path, contents)?)
}

/// The QR code of a link, in text.
pub fn qr(link: &str) -> Result<String> {
    let code = qrcode::QrCode::new(link)?;
    Ok(code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_link_shows_as_a_qr_code() {
        let code = super::qr("https://letmeknow.dev/i#2.g.AAAA.BBBB").unwrap();
        assert!(code.lines().count() > 10);
    }

    #[test]
    fn folders_are_paths() {
        assert!(super::is_folder("./chat") && super::is_folder("/tmp/x"));
        assert!(!super::is_folder("letmeknow.dev") && !super::is_folder("50d4@https://next.letmeknow.dev"));
    }
}
