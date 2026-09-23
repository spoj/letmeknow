mod relay;
mod session;
mod store;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use session::{Event, Request, Session};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
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
        /// Display name, fixed when the session is created [default: $USER/<session>]
        #[arg(long, env = "LETMEKNOW_NAME")]
        name: Option<String>,
        /// Relay for groups this session creates
        #[arg(long, env = "LETMEKNOW_RELAY", default_value = "https://letmeknow.dev")]
        relay: String,
    },
    #[command(flatten)]
    Request(Request),
}

#[tokio::main]
async fn main() -> ExitCode {
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
        None => match std::env::var_os("XDG_DATA_HOME") {
            Some(data) => PathBuf::from(data).join("letmeknow"),
            None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".local/share/letmeknow"),
        },
    };
    Ok(home.join("sessions").join(session))
}

async fn listen(session: &str, name: Option<String>, relay: String) -> Result<()> {
    let dir = session_dir(session)?;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    let socket = dir.join("sock");
    if UnixStream::connect(&socket).await.is_ok() {
        bail!("session {session} is already running");
    }
    let _ = std::fs::remove_file(&socket);

    let (events, mut queue) = mpsc::unbounded_channel();
    let default_name = format!("{}/{session}", std::env::var("USER").unwrap_or_else(|_| "agent".into()));
    let rename = name.is_some();
    let mut state = Session::open(&dir, name.unwrap_or(default_name), rename, relay.trim_end_matches('/').to_owned(), events.clone())?;
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream, events.clone()));
        }
    });
    println!("{}", json!({ "type": "ready", "session": session, "member": state.person(), "socket": socket }));

    let mut terminate = signal(SignalKind::terminate())?;
    loop {
        tokio::select! {
            Some(event) = queue.recv() => state.handle(event).await,
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
        }
    }
    let _ = std::fs::remove_file(&socket);
    Ok(())
}

async fn serve(stream: UnixStream, events: mpsc::UnboundedSender<Event>) {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    if BufReader::new(read).read_line(&mut line).await.is_err() {
        return;
    }
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(request) => {
            let (reply, answer) = oneshot::channel();
            let _ = events.send(Event::Request(request, reply));
            answer.await.unwrap_or_else(|_| json!({ "error": "session process stopped" }))
        }
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
    let socket = session_dir(session)?.join("sock");
    let stream = connect(&socket, session).await?;
    let (read, mut write) = stream.into_split();
    write.write_all(format!("{}\n", serde_json::to_string(&request)?).as_bytes()).await?;
    let mut line = String::new();
    BufReader::new(read).read_line(&mut line).await?;
    let response: Value = serde_json::from_str(&line).context("session process closed the connection")?;
    if let Some(error) = response.get("error").and_then(Value::as_str) {
        bail!("{error}");
    }
    println!("{response}");
    Ok(())
}

async fn connect(socket: &Path, session: &str) -> Result<UnixStream> {
    UnixStream::connect(socket)
        .await
        .with_context(|| format!("session {session} is not running; start it with `letmeknow listen --session {session}`"))
}
