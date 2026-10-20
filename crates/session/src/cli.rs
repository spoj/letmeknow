//! The `letmeknow` command line: `listen` runs a session process; most other commands are requests to it, over a
//! localhost port guarded by a token.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use lmk_membership::service::Policy;
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

/// End-to-end encrypted chats for agents and their people.
#[derive(Parser)]
#[command(name = "letmeknow", version)]
pub struct Cli {
    /// Agent session; each session is its own group member [default: listen picks a new handle; other commands use the one running session]
    #[arg(long, env = "LETMEKNOW_SESSION", global = true)]
    pub session: Option<String>,
    /// Where sessions keep their state [default: the user's local data directory]
    #[arg(long, env = "LETMEKNOW_HOME", global = true)]
    pub home: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the session process, and print what arrives as NDJSON
    Listen {
        /// Seconds a message not addressed to this session may wait for something that wakes the agent anyway
        #[arg(long, env = "LETMEKNOW_HOLD", default_value_t = 3600)]
        hold: u64,
        /// The domain of the membership service for groups this session creates
        #[arg(long, env = "LETMEKNOW_MEMBERSHIP", default_value = lmk_proto::links::DOMAIN)]
        membership: String,
    },
    /// This machine's sessions: each one's handle, whether it runs, and its groups
    Sessions,
    /// The groups each new session of this home joins as it starts, through a session of the home in it
    Auto {
        #[command(subcommand)]
        change: Option<Auto>,
    },
    /// The groups this home keeps one session in: a new session joins one as it starts while none of the home's sessions in it runs, and removes those
    Autorep {
        #[command(subcommand)]
        change: Option<Auto>,
    },
    /// Print instructions for agents
    Skill,
    /// Run a membership service and an iroh relay
    Serve(Serve),
    #[command(flatten)]
    Request(Request),
}

#[derive(Subcommand)]
pub enum Auto {
    /// Add a group that a session of this home is in; it leaves the other list (auto or autorep)
    Add {
        #[arg(long)]
        group: String,
    },
    Remove {
        #[arg(long)]
        group: String,
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
    /// QUIC address discovery's UDP port
    #[arg(long, default_value_t = 7842)]
    pub qad_port: u16,
    /// Logs, keys and certificates
    #[arg(long)]
    pub state: PathBuf,
    /// MiB the membership database may use: its pages in use and its WAL. Appends past it are refused as quota
    #[arg(long, default_value_t = Policy::default().disk >> 20)]
    pub disk: u64,
    /// Days a group's log is kept after its first entry, 7 to 25
    #[arg(long, default_value_t = Policy::default().retention_days, value_parser = clap::value_parser!(u64).range(7..=lmk_proto::membership::MAX_RETENTION_DAYS))]
    pub retention: u64,
    /// Appends each address may make a minute
    #[arg(long, default_value_t = Policy::default().appends_per_minute)]
    pub appends_per_minute: u32,
    /// MiB each address may append a day
    #[arg(long, default_value_t = Policy::default().append_bytes_per_day >> 20)]
    pub append_mib_per_day: u64,
    /// Reads each address may make a minute
    #[arg(long, default_value_t = Policy::default().reads_per_minute)]
    pub reads_per_minute: u32,
    /// MiB each address may read a minute
    #[arg(long, default_value_t = Policy::default().read_bytes_per_minute >> 20)]
    pub read_mib_per_minute: u64,
    /// Logs each address may start a day, by their first entries
    #[arg(long, default_value_t = Policy::default().new_logs_per_day)]
    pub new_logs_per_day: u64,
    /// Requests each source may have in flight
    #[arg(long, default_value_t = Policy::default().requests_at_once)]
    pub requests_at_once: usize,
    /// MiB of requests and answers each source may have in flight
    #[arg(long, default_value_t = Policy::default().bytes_at_once >> 20)]
    pub mib_at_once: u64,
    /// MiB of requests and answers in flight over all sources
    #[arg(long, default_value_t = Policy::default().bytes_at_once_in_all >> 20)]
    pub mib_at_once_in_all: u64,
    /// Requests that work on the database at once
    #[arg(long, default_value_t = Policy::default().db_work)]
    pub db_work: usize,
    /// Sources each rate limit tracks at once; past them, new sources are refused
    #[arg(long, default_value_t = Policy::default().sources)]
    pub sources: usize,
    /// KiB a second the relay reads from each connection
    #[arg(long, default_value_t = lmk_serve::RELAY_RATE >> 10, value_parser = clap::value_parser!(u32).range(1..=(u32::MAX >> 10) as i64))]
    pub relay_kib_per_second: u32,
    /// A certificate (PEM) to use instead of Let's Encrypt, with --key
    #[arg(long, requires = "key")]
    pub cert: Option<PathBuf>,
    #[arg(long, requires = "cert")]
    pub key: Option<PathBuf>,
}

impl Serve {
    /// The membership service's limits, as the flags set them.
    pub fn policy(&self) -> Policy {
        Policy {
            retention_days: self.retention,
            disk: self.disk << 20,
            appends_per_minute: self.appends_per_minute,
            append_bytes_per_day: self.append_mib_per_day << 20,
            reads_per_minute: self.reads_per_minute,
            read_bytes_per_minute: self.read_mib_per_minute << 20,
            new_logs_per_day: self.new_logs_per_day,
            requests_at_once: self.requests_at_once,
            bytes_at_once: self.mib_at_once << 20,
            bytes_at_once_in_all: self.mib_at_once_in_all << 20,
            db_work: self.db_work,
            sources: self.sources,
        }
    }
}

/// Requests an agent sends to its session process: JSON objects tagged by `cmd`, which are also the command line's
/// subcommands.
#[derive(Subcommand, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Make a one-time invite link, valid for 10 minutes, into a chat: a new one unless --group is given
    #[command(display_order = 10)]
    Invite {
        #[arg(long)]
        group: Option<String>,
        /// Only this member, by fingerprint, may join with the link
        #[arg(long = "for", value_name = "FP")]
        #[serde(rename = "for", default, skip_serializing_if = "Option::is_none")]
        for_member: Option<String>,
        /// Days members carry a new group's messages for one another
        #[arg(long, default_value_t = 7, conflicts_with = "group")]
        #[serde(default = "carry")]
        carry: u32,
    },
    /// Join a group through an invite link
    #[command(display_order = 11)]
    Join { target: String },
    /// List members of a group
    #[command(display_order = 14)]
    Members {
        #[arg(long)]
        group: Option<String>,
    },
    /// List this session's groups
    #[command(display_order = 15)]
    Groups,
    /// Remove a member, by fingerprint, from a group
    #[command(display_order = 16)]
    Remove {
        #[arg(long)]
        group: Option<String>,
        member: String,
    },
    /// Leave a group; with --end, end it for everyone: remove the other members, and leave
    #[command(display_order = 17)]
    Leave {
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        #[serde(default)]
        end: bool,
    },
    /// The members this session is connected to in each group, and what only this session holds
    #[command(display_order = 21)]
    Status {
        /// Only this group
        #[arg(long)]
        group: Option<String>,
    },
    /// Send a message in a chat ("-" reads the text from stdin)
    #[command(display_order = 12)]
    Send {
        #[arg(long)]
        group: Option<String>,
        /// A member to address, by fingerprint; repeat for several
        #[arg(long)]
        to: Vec<String>,
        /// Id of the message this answers, or any unique beginning of it
        #[arg(long)]
        reply_to: Option<String>,
        /// Deliver at once to every member, not only those addressed
        #[arg(long)]
        urgent: bool,
        /// File to attach ("-" reads stdin), up to about 12 MiB; each recipient's session saves it into a private file
        #[arg(long, value_name = "FILE")]
        attach: Option<String>,
        /// The attached file's name, set from its path
        #[arg(skip)]
        #[serde(default)]
        attach_name: String,
        text: String,
    },
    /// Show a chat message
    #[command(display_order = 13)]
    Read {
        /// Its id, or any unique beginning of it
        id: String,
    },
}

fn carry() -> u32 {
    7
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

/// Parses a command line.
pub fn parse<T: Into<OsString> + Clone>(args: impl IntoIterator<Item = T>) -> Result<Cli, clap::Error> {
    Cli::from_arg_matches_mut(&mut hyphens(Cli::command()).try_get_matches_from(args)?)
}

/// Lets every value start with '-', as ids and fingerprints in base64url do, and text may. Known flags stay flags.
fn hyphens(command: clap::Command) -> clap::Command {
    command.mut_args(|arg| if arg.get_action().takes_values() { arg.allow_hyphen_values(true) } else { arg }).mut_subcommands(hyphens)
}

pub fn home_dir(home: Option<PathBuf>) -> Result<PathBuf> {
    match home {
        Some(home) => Ok(home),
        None => Ok(dirs::data_local_dir().context("no local data directory")?.join("letmeknow-v12")),
    }
}

pub fn session_dir(home: &Path, session: &str) -> Result<PathBuf> {
    if session.is_empty() || !session.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        bail!("session names may contain only letters, digits, '.', '_' and '-'");
    }
    Ok(home.join("sessions").join(session))
}

/// A handle of 8 hex digits not used by any existing session.
pub fn new_handle(home: &Path) -> Result<String> {
    loop {
        let handle = format!("{:08x}", rand::random::<u32>());
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

/// Sends a request to the running session and returns its answer: made short, but for `members`. Files the request
/// names are read here: the session process runs elsewhere.
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
    let full = matches!(request, Request::Members { .. });
    let channel = connect(&session_dir(home, session)?.join("endpoint"))
        .await
        .with_context(|| format!("session {session} is not running; start it with `letmeknow --session {session} listen`"))?;
    let mut answer = exchange(channel, request).await?;
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

#[cfg(test)]
mod tests {
    use super::{Command, Policy, Request, parse};

    #[test]
    fn a_value_may_start_with_a_hyphen() {
        let cli = parse(["letmeknow", "send", "--to", "-Ia", "- an item", "--urgent"]).unwrap();
        let Command::Request(Request::Send { to, text, urgent, .. }) = cli.command else { panic!("not a send") };
        assert_eq!((to, text.as_str(), urgent), (vec!["-Ia".to_owned()], "- an item", true));
        assert!(matches!(parse(["letmeknow", "read", "-Ia"]).unwrap().command, Command::Request(Request::Read { id, .. }) if id == "-Ia"));
        assert_eq!(parse(["letmeknow", "send", "--help"]).err().unwrap().kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn the_membership_is_a_domain() {
        let Command::Listen { membership, .. } = parse(["letmeknow", "listen"]).unwrap().command else { panic!("not listen") };
        assert_eq!(membership, "relay.letmeknow.dev");
    }

    #[test]
    fn a_service_keeps_logs_for_a_week_to_25_days() {
        let retention = |days: &[&str]| parse([&["letmeknow", "serve", "--domain", "relay.example", "--state", "s"], days].concat()).map(|cli| match cli.command {
            Command::Serve(serve) => serve.retention,
            _ => panic!("not serve"),
        });
        assert_eq!(retention(&[]).unwrap(), 7);
        assert_eq!(retention(&["--retention", "25"]).unwrap(), 25);
        assert!(retention(&["--retention", "6"]).is_err() && retention(&["--retention", "26"]).is_err());
    }

    #[test]
    fn a_service_has_the_default_limits_unless_flags_set_them() {
        let policy = |flags: &[&str]| match parse([&["letmeknow", "serve", "--domain", "relay.example", "--state", "s"], flags].concat()).unwrap().command {
            Command::Serve(serve) => serve.policy(),
            _ => panic!("not serve"),
        };
        assert_eq!(format!("{:?}", policy(&[])), format!("{:?}", Policy::default()));
        let set = policy(&["--append-mib-per-day", "1", "--new-logs-per-day", "50000", "--sources", "10"]);
        assert_eq!((set.append_bytes_per_day, set.new_logs_per_day, set.sources), (1 << 20, 50_000, 10));
    }
}
