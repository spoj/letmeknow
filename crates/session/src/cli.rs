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

use crate::node::Inbound;

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
    /// Run the session process, which keeps each doc's file in step, and print what arrives as NDJSON
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
        /// The membership service for groups and identities this session creates: letmeknow.dev, <key>@<relay URL>, or a folder
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
    #[command(flatten)]
    Request(Request),
}

#[derive(clap::Args, Debug)]
pub struct Serve {
    /// The domain to get a certificate for from Let's Encrypt
    #[arg(long)]
    pub domain: Option<String>,
    #[arg(long, default_value_t = 443)]
    pub https_port: u16,
    #[arg(long, default_value_t = 80)]
    pub http_port: u16,
    /// The membership service's UDP port
    #[arg(long, default_value_t = 7843)]
    pub membership_port: u16,
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

/// Requests an agent sends to its session process.
#[derive(Subcommand, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Make a one-time invite link, valid for 10 minutes: into a group (a new one unless --group is given), or with --identity, for another device to join an identity
    Invite {
        #[arg(long)]
        group: Option<String>,
        /// What a new group shares: a chat (messages in order) or a doc (one text everyone edits at once)
        #[arg(long, value_parser = ["chat", "doc"], default_value = "chat", conflicts_with = "group")]
        kind: String,
        /// The new group's name
        #[arg(long, conflicts_with = "group")]
        name: Option<String>,
        /// A new doc's file: kept in step with the doc, and its first text if it exists [default: a new file in the session's state]
        #[arg(conflicts_with_all = ["group", "identity"])]
        file: Option<String>,
        /// Days members hold a new group's messages and files for one another
        #[arg(long, default_value_t = 90, conflicts_with = "group")]
        keep: u32,
        /// The new group's membership service [default: listen's]
        #[arg(long, conflicts_with = "group")]
        membership: Option<String>,
        /// What this session speaks as in a new group: one of its device's identities [default: the device's first]
        #[arg(long = "as", value_name = "IDENTITY")]
        #[serde(rename = "as")]
        as_: Option<String>,
        /// Whom the link is for: whoever redeems it becomes your contact under this name, verified
        #[arg(long = "for", value_name = "NAME")]
        #[serde(rename = "for")]
        for_: Option<String>,
        /// A contact: only that identity can redeem the link
        #[arg(long)]
        to: Option<String>,
        /// Also show the link as a QR code, on stderr
        #[arg(long)]
        qr: bool,
        /// Invite another device (a machine or a browser) into this identity, instead of a session into a group
        #[arg(long, conflicts_with_all = ["group", "as_", "name", "for_", "to"])]
        identity: Option<String>,
    },
    /// Join a group through an invite link, or a group open to your identity by its id; a device link adds this device to an identity
    Join {
        target: String,
        /// For a doc: a new file to keep in step with it [default: a new file in the session's state]
        file: Option<String>,
        /// What this session speaks as in the group: one of its device's identities [default: the device's first]
        #[arg(long = "as", value_name = "IDENTITY")]
        #[serde(rename = "as")]
        as_: Option<String>,
    },
    /// Send a message in a chat ("-" reads the text from stdin)
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
    Read {
        id: String,
        #[arg(long, default_value_t = 0)]
        ancestors: usize,
    },
    /// List members of a group
    Members {
        #[arg(long)]
        group: Option<String>,
    },
    /// List this session's groups, and those open to its identities
    Groups,
    /// Remove a member (by fingerprint or name) from a group
    Remove {
        #[arg(long)]
        group: Option<String>,
        member: String,
    },
    /// Leave a group
    Leave {
        #[arg(long)]
        group: Option<String>,
    },
    /// Name the group, for everyone in it
    Name {
        #[arg(long)]
        group: Option<String>,
        name: String,
    },
    /// Let sessions of an identity join the group without an invite (they run `join <group>`), or with --close, no longer
    Open {
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        close: bool,
        identity: String,
    },
    /// Make a file linkable from a doc; prints the markdown link to put into the doc's file
    Attach {
        #[arg(long)]
        group: Option<String>,
        path: String,
    },
    /// The file a doc or message links, decrypted into a file only you can read; prints its path
    Fetch { link: String },
    /// The members online in each group, and what only this session holds
    Status,
    /// Identities this device is on: create one, list them, or take a device off one
    Identity {
        #[command(subcommand)]
        op: IdentityOp,
    },
    /// Your identity's contacts, and introductions waiting to be accepted
    Contacts {
        #[command(subcommand)]
        op: Option<ContactsOp>,
    },
    /// Tell a member who another member's identity is to you
    Introduce {
        #[arg(long)]
        group: Option<String>,
        member: String,
        #[arg(long)]
        to: String,
    },
}

#[derive(Subcommand, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum IdentityOp {
    /// Start an identity with this device as its first device
    Create {
        name: String,
        /// The membership service that keeps its device list [default: listen's]
        #[arg(long)]
        membership: Option<String>,
    },
    /// The identities this device is on, and their devices
    List,
    /// Take a device, by key, off an identity's list
    Remove {
        #[arg(long)]
        identity: Option<String>,
        device: String,
    },
}

#[derive(Subcommand, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ContactsOp {
    /// Accept an introduction: the identity becomes a contact, known as introduced
    Accept {
        identity: String,
        /// Your name for it [default: the introducer's]
        #[arg(long)]
        name: Option<String>,
    },
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

async fn connect(endpoint: &Path) -> Result<(TcpStream, String)> {
    let endpoint: Endpoint = serde_json::from_slice(&std::fs::read(endpoint)?)?;
    Ok((TcpStream::connect(("127.0.0.1", endpoint.port)).await?, endpoint.token))
}

/// Opens the command channel of the session in `dir`: requests that come with its token go to `inbound`.
pub async fn open_channel(dir: &Path, inbound: mpsc::UnboundedSender<Inbound>) -> Result<()> {
    let endpoint_path = dir.join("endpoint");
    if connect(&endpoint_path).await.is_ok() {
        bail!("session {} is already running", dir.display());
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let token = hex::encode(rand::random::<[u8; 32]>());
    let endpoint = Endpoint { port: listener.local_addr()?.port(), token: token.clone() };
    private_file(&endpoint_path, &serde_json::to_vec(&endpoint)?)?;
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
            let _ = inbound.send(Inbound::Request(call.request, reply));
            answer.await.unwrap_or_else(|_| json!({ "error": "session process stopped" }))
        }
        Ok(_) => json!({ "error": "bad token" }),
        Err(error) => json!({ "error": format!("bad request: {error}") }),
    };
    let _ = write.write_all(format!("{response}\n").as_bytes()).await;
}

/// Sends a request to the running session and returns its answer. Files the request names are read, or made absolute,
/// here: the session process runs elsewhere.
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
    let file = match &mut request {
        Request::Attach { path, .. } => Some(path),
        Request::Invite { file, .. } | Request::Join { file, .. } => file.as_mut(),
        _ => None,
    };
    if let Some(file) = file {
        *file = absolute(file)?;
    }
    let membership = match &mut request {
        Request::Invite { membership, .. } | Request::Identity { op: IdentityOp::Create { membership, .. } } => membership.as_mut(),
        _ => None,
    };
    if let Some(membership) = membership.filter(|m| is_folder(m)) {
        *membership = absolute(membership)?;
    }
    // A doc a member joins already has its text, which would be merged with the file's.
    if let Request::Join { file: Some(file), .. } = &request
        && Path::new(file).exists()
    {
        bail!("{file} exists; name a new file for the doc");
    }
    let (stream, token) = connect(&session_dir(home, session)?.join("endpoint"))
        .await
        .with_context(|| format!("session {session} is not running; start it with `letmeknow --session {session} listen`"))?;
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

/// A membership address names a folder when it is a path.
pub fn is_folder(address: &str) -> bool {
    address.contains(['/', '\\']) || address.starts_with('.')
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
