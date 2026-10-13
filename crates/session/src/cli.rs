//! The `letmeknow` command line: `listen` runs a session process; most other commands are requests to it, over a
//! localhost port guarded by a token.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::session::Inbound;
use lmk_proto::links::Invite;

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
        /// Seconds a message or doc edit not addressed to this session may wait for something that wakes the agent anyway
        #[arg(long, env = "LETMEKNOW_HOLD", default_value_t = 3600)]
        hold: u64,
        /// Keep the text of messages once delivered, for audit; by default only ids, senders and references are kept
        #[arg(long)]
        keep_log: bool,
        /// The domain of the membership service for groups and identities this session creates
        #[arg(long, env = "LETMEKNOW_MEMBERSHIP", default_value = lmk_proto::links::DOMAIN)]
        membership: String,
        /// A relay this session is reached through, instead of its directory's; repeat for several
        #[arg(long, env = "LETMEKNOW_RELAY", value_delimiter = ',')]
        relay: Vec<String>,
    },
    /// This machine's sessions: each one's handle, whether it runs, and its groups
    Sessions {
        #[command(subcommand)]
        op: Option<SessionsOp>,
    },
    /// Print instructions for agents
    Skill,
    /// Run a membership service and an iroh relay
    Serve(Serve),
    #[command(flatten)]
    Request(Request),
    /// A command of a kind's plugin: `letmeknow <kind> <args>...`, such as `letmeknow doc attach <path>`
    #[command(external_subcommand)]
    Kind(Vec<String>),
}

#[derive(Subcommand)]
pub enum SessionsOp {
    /// Stop a session if it runs, leave its groups, and delete it, once the other members have removed it from each group
    Remove {
        handle: String,
        /// The domain of the session's membership service
        #[arg(long, env = "LETMEKNOW_MEMBERSHIP", default_value = lmk_proto::links::DOMAIN)]
        membership: String,
        /// A relay the session is reached through, instead of its directory's; repeat for several
        #[arg(long, env = "LETMEKNOW_RELAY", value_delimiter = ',')]
        relay: Vec<String>,
    },
}

#[derive(clap::Args, Debug)]
pub struct Serve {
    /// Offline: create a NEW authority/store in a nonexistent --state directory, print public config, and exit
    #[arg(long)]
    pub initialize: bool,
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
    /// The relays its directory names, which members live on; default its own
    #[arg(long, num_args = 1..)]
    pub relays: Vec<String>,
    /// QUIC address discovery's UDP port
    #[arg(long, default_value_t = 7842)]
    pub qad_port: u16,
    /// Logs, keys and certificates
    #[arg(long)]
    pub state: PathBuf,
    /// MiB the membership database may use: its pages in use and its WAL. Appends past it are refused as quota
    #[arg(long, default_value_t = 4096)]
    pub disk: u64,
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
        /// A member to address: its fingerprint, or a name it answers to (its identity's name, which addresses all the
        /// identity's sessions, its device's or its handle, or the first word of one); repeat for several. "@name" in the
        /// text addresses too
        #[arg(long)]
        to: Vec<String>,
        /// Id of the message this answers, or any unique beginning of it
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
    /// Show a chat message: of your own, who holds and who was shown it
    #[command(display_order = 13)]
    Read {
        /// Its id, or any unique beginning of it
        id: String,
        /// Show first this many of the chat messages in its causal past that this session delivered, latest last
        #[arg(long, default_value_t = 0)]
        ancestors: usize,
    },
    /// The file a message or a group's kind (a doc) links, decrypted into a file only you can read; prints its path
    #[command(display_order = 20)]
    Fetch { link: String },
    /// A command of a kind's plugin, from `letmeknow <kind> <args>...`.
    #[command(skip)]
    Kind { kind: String, args: Vec<String>, cwd: String },
    /// `identity join <link>`: sent as the client's `join`.
    #[command(skip)]
    #[serde(skip)]
    IdentityJoin { link: String },
    /// `status --group <group>`: the client's `status`, of that group only.
    #[command(skip)]
    #[serde(skip)]
    Status { group: String },
    /// `sessions remove`: stops the session, answered once it stopped.
    #[command(skip)]
    Stop,
    /// An add for this session, which the session acting for the device hands it: joins `group` as `join` does, unless
    /// it is in it already, and prints `joined`, naming `device`, which sent the add.
    #[command(skip)]
    Added { link: String, group: lmk_proto::Bytes, device: String },
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

/// Parses a command line. `identity join` and `status --group` are this command line's, beside the client core's
/// commands.
pub fn parse<T: Into<OsString> + Clone>(args: impl IntoIterator<Item = T>) -> Result<Cli, clap::Error> {
    let join = clap::Command::new("join")
        .about("Add this device to an identity, through a device link (`identity invite` makes them)")
        .arg(clap::Arg::new("link").value_name("LINK").required(true));
    let group = clap::Arg::new("group").long("group").value_name("GROUP").help("Only this group");
    let command = Cli::command()
        .mut_subcommand("identity", |identity| identity.subcommand(join))
        .mut_subcommand("status", |status| status.arg(group));
    let mut matches = hyphens(command).try_get_matches_from(args)?;
    let request = match matches.subcommand() {
        Some(("identity", identity)) => {
            identity.subcommand_matches("join").and_then(|join| join.get_one::<String>("link")).map(|link| Request::IdentityJoin { link: link.clone() })
        }
        Some(("status", status)) => status.get_one::<String>("group").map(|group| Request::Status { group: group.clone() }),
        _ => None,
    };
    match request {
        Some(request) => Ok(Cli {
            session: matches.get_one::<String>("session").cloned(),
            home: matches.get_one::<PathBuf>("home").cloned(),
            command: Command::Request(request),
        }),
        None => Cli::from_arg_matches_mut(&mut matches),
    }
}

/// Lets every value start with '-', as ids and fingerprints in base64url do, and text may. Known flags stay flags.
fn hyphens(command: clap::Command) -> clap::Command {
    command.mut_args(|arg| if arg.get_action().takes_values() { arg.allow_hyphen_values(true) } else { arg }).mut_subcommands(hyphens)
}

pub fn home_dir(home: Option<PathBuf>) -> Result<PathBuf> {
    match home {
        Some(home) => Ok(home),
        None => Ok(dirs::data_local_dir().context("no local data directory")?.join("letmeknow-v6")),
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

/// How long finding the running session waits for each to answer: on Windows a refused connection takes seconds.
const PROBE: Duration = Duration::from_millis(200);

/// The handles of the sessions in `home` whose processes answer, in order.
pub async fn running(home: &Path) -> Vec<String> {
    let mut probes = tokio::task::JoinSet::new();
    for entry in std::fs::read_dir(home.join("sessions")).into_iter().flatten().flatten() {
        probes.spawn(async move {
            let answered = tokio::time::timeout(PROBE, connect(&entry.path().join("endpoint"))).await;
            matches!(answered, Ok(Ok(_))).then(|| entry.file_name().to_string_lossy().into_owned())
        });
    }
    let mut running: Vec<String> = probes.join_all().await.into_iter().flatten().collect();
    running.sort();
    running
}

pub async fn running_session(home: &Path) -> Result<String> {
    let running = running(home).await;
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

/// Sends a request to the running session and returns its answer: made short, but for `members`, and for a kind's
/// commands, which their plugin answers. Files the request names are read, or made absolute, here, and a kind's arguments
/// go with this directory: the session process runs elsewhere.
pub async fn call(home: &Path, session: &str, mut request: Request) -> Result<Value> {
    if let Request::Client(lmk_client::Request::Join { target, .. }) = &request {
        ensure!(
            !Invite::parse(target.trim()).is_ok_and(|invite| invite.device),
            "that is a device link, which adds this device to an identity: to do that, run `letmeknow identity join <link>`"
        );
    }
    let mut only = None;
    match request {
        Request::IdentityJoin { link } => {
            ensure!(Invite::parse(link.trim())?.device, "that is not a device link; `identity invite` makes them");
            request = Request::Client(lmk_client::Request::Join { target: link, args: Vec::new(), cwd: String::new() })
        }
        Request::Status { group } => {
            only = Some(group);
            request = Request::Client(lmk_client::Request::Status);
        }
        _ => {}
    }
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
    let full = matches!(request, Request::Client(lmk_client::Request::Members { .. }) | Request::Kind { .. });
    let channel = connect(&session_dir(home, session)?.join("endpoint"))
        .await
        .with_context(|| format!("session {session} is not running; start it with `letmeknow --session {session} listen`"))?;
    let mut answer = exchange(channel, request).await?;
    if let Some(group) = only {
        let groups = answer["groups"].as_array_mut().context("status lists groups")?;
        groups.retain(|g| g["group"] == group.as_str() || g["name"] == group.as_str());
        match groups.len() {
            0 => bail!("unknown group {group}"),
            1 => {}
            _ => bail!("several groups are named {group}; pass its id"),
        }
        // The warning counts the sends held only here in every group.
        if groups[0]["only_here"] == json!([]) {
            answer.as_object_mut().context("status is an object")?.remove("warning");
        }
    }
    if !full {
        crate::short::compact(&mut answer);
    }
    Ok(answer)
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
    use super::{Command, Request, parse};

    #[test]
    fn a_value_may_start_with_a_hyphen() {
        let cli = parse(["letmeknow", "send", "--to", "-Ia", "- an item", "--urgent"]).unwrap();
        let Command::Request(Request::Send { to, text, urgent, .. }) = cli.command else { panic!("not a send") };
        assert_eq!((to, text.as_str(), urgent), (vec!["-Ia".to_owned()], "- an item", true));
        assert!(matches!(parse(["letmeknow", "read", "-Ia"]).unwrap().command, Command::Request(Request::Read { id, .. }) if id == "-Ia"));
        assert_eq!(parse(["letmeknow", "send", "--help"]).err().unwrap().kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn relays_repeat_and_the_membership_is_a_domain() {
        let cli = parse(["letmeknow", "listen", "--relay", "https://a.example", "--relay", "https://b.example"]).unwrap();
        let Command::Listen { membership, relay, .. } = cli.command else { panic!("not listen") };
        assert_eq!((membership.as_str(), relay), ("relay.letmeknow.dev", vec!["https://a.example".to_owned(), "https://b.example".into()]));
    }

    #[test]
    fn a_link_shows_as_a_qr_code() {
        let code = super::qr("https://letmeknow.dev/i#5.g.AAAA.BBBB").unwrap();
        assert!(code.lines().count() > 10);
    }
}
