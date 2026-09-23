mod relay;
mod session;
mod store;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use session::{Event, Request, Session};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

/// End-to-end encrypted group chat for agents.
#[derive(Parser)]
#[command(name = "letmeknow", version)]
struct Cli {
    /// Agent session; each session is its own group member [default: listen picks a new handle; other commands use the one running session]
    #[arg(long, env = "LETMEKNOW_SESSION", global = true)]
    session: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the session process and print delivered messages as NDJSON
    Listen {
        /// Display name, fixed when the session is created [default: <user>/<session>]
        #[arg(long, env = "LETMEKNOW_NAME")]
        name: Option<String>,
        /// Relay for groups this session creates
        #[arg(long, env = "LETMEKNOW_RELAY", default_value = "https://letmeknow.dev")]
        relay: String,
    },
    /// Print instructions for agents (SKILL.md)
    Skill,
    #[command(flatten)]
    Request(Request),
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

#[tokio::main]
async fn main() -> ExitCode {
    rustls::crypto::ring::default_provider().install_default().expect("first crypto provider");
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("letmeknow: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Listen { name, relay } => {
            let session = match cli.session {
                Some(session) => session,
                None => new_handle()?,
            };
            listen(&session, name, relay).await
        }
        Command::Skill => {
            print!("{}", include_str!("../../SKILL.md"));
            Ok(())
        }
        Command::Request(request) => {
            let session = match cli.session {
                Some(session) => session,
                None => running_session().await?,
            };
            call(&session, request).await
        }
    }
}

fn sessions_dir() -> Result<PathBuf> {
    let home = match std::env::var_os("LETMEKNOW_HOME") {
        Some(home) => PathBuf::from(home),
        None => dirs::data_local_dir().context("no local data directory")?.join("letmeknow"),
    };
    Ok(home.join("sessions"))
}

fn session_dir(session: &str) -> Result<PathBuf> {
    if session.is_empty() || !session.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        bail!("session names may contain only letters, digits, '.', '_' and '-'");
    }
    Ok(sessions_dir()?.join(session))
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
fn new_handle() -> Result<String> {
    loop {
        let mut pick = [0u8; 2];
        getrandom::fill(&mut pick).map_err(|e| anyhow::anyhow!("randomness: {e}"))?;
        let handle = format!("{}-{}", ADJECTIVES[pick[0] as usize % 32], NOUNS[pick[1] as usize % 32]);
        if !session_dir(&handle)?.exists() {
            return Ok(handle);
        }
    }
}

async fn running_session() -> Result<String> {
    let mut running = Vec::new();
    for entry in std::fs::read_dir(sessions_dir()?).into_iter().flatten().flatten() {
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

async fn listen(session: &str, name: Option<String>, relay: String) -> Result<()> {
    let dir = session_dir(session)?;
    private_dir(&dir)?;
    let endpoint_path = dir.join("endpoint");
    if connect(&endpoint_path).await.is_ok() {
        bail!("session {session} is already running");
    }

    let (events, mut queue) = mpsc::unbounded_channel();
    let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "agent".into());
    let rename = name.is_some();
    let name = name.unwrap_or_else(|| format!("{user}/{session}"));
    let mut state = Session::open(&dir, name, rename, relay.trim_end_matches('/').to_owned(), events.clone())?;

    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let mut token = [0u8; 32];
    getrandom::fill(&mut token).map_err(|e| anyhow::anyhow!("randomness: {e}"))?;
    let endpoint = Endpoint { port: listener.local_addr()?.port(), token: hex::encode(token) };
    private_file(&endpoint_path, &serde_json::to_vec(&endpoint)?)?;
    let token = endpoint.token;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream, token.clone(), events.clone()));
        }
    });
    println!("{}", json!({ "type": "ready", "session": session, "member": state.person(), "state": dir }));

    let mut shutdown = std::pin::pin!(shutdown());
    loop {
        tokio::select! {
            Some(event) = queue.recv() => state.handle(event).await,
            _ = &mut shutdown => break,
        }
    }
    let _ = std::fs::remove_file(&endpoint_path);
    Ok(())
}

/// Resolves on Ctrl-C or, on Unix, SIGTERM. Created once so a signal arriving mid-request is not lost.
async fn shutdown() {
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

#[cfg(unix)]
fn private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    Ok(std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?)
}

#[cfg(not(unix))]
fn private_dir(dir: &Path) -> Result<()> {
    Ok(std::fs::create_dir_all(dir)?)
}

#[cfg(unix)]
fn private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    Ok(file.write_all(contents)?)
}

#[cfg(not(unix))]
fn private_file(path: &Path, contents: &[u8]) -> Result<()> {
    Ok(std::fs::write(path, contents)?)
}

async fn serve(stream: TcpStream, token: String, events: mpsc::UnboundedSender<Event>) {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    if BufReader::new(read).read_line(&mut line).await.is_err() {
        return;
    }
    let response = match serde_json::from_str::<Call>(&line) {
        Ok(call) if call.token == token => {
            let (reply, answer) = oneshot::channel();
            let _ = events.send(Event::Request(call.request, reply));
            answer.await.unwrap_or_else(|_| json!({ "error": "session process stopped" }))
        }
        Ok(_) => json!({ "error": "bad token" }),
        Err(error) => json!({ "error": format!("bad request: {error}") }),
    };
    let _ = write.write_all(format!("{response}\n").as_bytes()).await;
}

async fn call(session: &str, mut request: Request) -> Result<()> {
    if let Request::Send { text, .. } = &mut request
        && text == "-"
    {
        text.clear();
        std::io::stdin().read_to_string(text)?;
    }
    let (stream, token) = connect(&session_dir(session)?.join("endpoint"))
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
    println!("{response}");
    Ok(())
}

async fn connect(endpoint: &Path) -> Result<(TcpStream, String)> {
    let endpoint: Endpoint = serde_json::from_slice(&std::fs::read(endpoint)?)?;
    Ok((TcpStream::connect(("127.0.0.1", endpoint.port)).await?, endpoint.token))
}
