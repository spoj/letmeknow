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
    /// Agent session; each session is its own group member
    #[arg(long, env = "LETMEKNOW_SESSION", default_value = "default", global = true)]
    session: String,
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
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Listen { name, relay } => listen(&cli.session, name, relay).await,
        Command::Request(request) => call(&cli.session, request).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("letmeknow: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn session_dir(session: &str) -> Result<PathBuf> {
    if session.is_empty() || !session.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        bail!("session names may contain only letters, digits, '.', '_' and '-'");
    }
    let home = match std::env::var_os("LETMEKNOW_HOME") {
        Some(home) => PathBuf::from(home),
        None => dirs::data_local_dir().context("no local data directory")?.join("letmeknow"),
    };
    Ok(home.join("sessions").join(session))
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

    loop {
        tokio::select! {
            Some(event) = queue.recv() => state.handle(event).await,
            _ = tokio::signal::ctrl_c() => break,
            _ = terminated() => break,
        }
    }
    let _ = std::fs::remove_file(&endpoint_path);
    Ok(())
}

#[cfg(unix)]
async fn terminated() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => drop(terminate.recv().await),
        Err(_) => std::future::pending().await,
    }
}

#[cfg(not(unix))]
async fn terminated() {
    std::future::pending().await
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
