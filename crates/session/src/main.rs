use letmeknow::cli::{Cli, Command, Request, SessionsOp, call, home_dir, new_handle, running_session, session_dir};
use letmeknow::kinds;
use letmeknow::session::Config;
use std::process::ExitCode;
use std::time::Duration;

#[tokio::main]
async fn main() -> ExitCode {
    use std::io::IsTerminal;
    use tracing_subscriber::EnvFilter;
    // Dependencies' logs, such as openmls's errors on messages of a past epoch, do not concern the agent.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off,letmeknow=warn,lmk=warn"));
    tracing_subscriber::fmt().with_env_filter(filter).with_ansi(std::io::stderr().is_terminal()).with_writer(std::io::stderr).init();
    let cli = letmeknow::cli::parse(std::env::args_os()).unwrap_or_else(|error| error.exit());
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("letmeknow: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let home = home_dir(cli.home)?;
    match cli.command {
        Command::Listen { hold, keep_log, membership, relay } => {
            let handle = match cli.session {
                Some(session) => session,
                None => new_handle(&home)?,
            };
            let config = Config {
                dir: session_dir(&home, &handle)?,
                handle,
                hold: Duration::from_secs(hold),
                keep_log,
                membership: lmk_client::service(&membership)?,
                plugins: kinds::dirs(),
            };
            let print = |line: String| {
                use std::io::Write;
                writeln!(std::io::stdout(), "{line}")
            };
            // Work in flight runs on the loop's thread: the client starts a plugin, and takes in its lines, a step at a time.
            let listen = letmeknow::listen(config, &home, letmeknow::Network::new(&relay)?, print, letmeknow::shutdown());
            tokio::task::LocalSet::new().run_until(listen).await
        }
        Command::Sessions { op: None } => {
            println!("{}", letmeknow::sessions(&home).await?);
            Ok(())
        }
        Command::Sessions { op: Some(SessionsOp::Remove { handle, relay }) } => {
            let config = Config {
                dir: session_dir(&home, &handle)?,
                handle,
                hold: Duration::from_secs(3600),
                keep_log: false,
                membership: lmk_client::service("letmeknow.dev")?,
                plugins: kinds::dirs(),
            };
            let remove = letmeknow::remove(config, &home, letmeknow::Network::new(&relay)?);
            println!("{}", tokio::task::LocalSet::new().run_until(remove).await?);
            Ok(())
        }
        Command::Skill => {
            print!("{}", letmeknow::SKILL);
            Ok(())
        }
        Command::Serve(serve) => letmeknow::serve(serve).await,
        Command::Kind(mut args) => {
            let kind = args.remove(0);
            let session = match cli.session {
                Some(session) => session,
                None => running_session(&home).await?,
            };
            println!("{}", letmeknow::short::line(&call(&home, &session, Request::Kind { kind, args, cwd: String::new() }).await?));
            Ok(())
        }
        Command::Request(request) => {
            let session = match cli.session {
                Some(session) => session,
                None => running_session(&home).await?,
            };
            let qr = matches!(
                request,
                Request::Client(
                    lmk_client::Request::Invite { qr: true, .. } | lmk_client::Request::Identity { op: lmk_client::IdentityOp::Invite { qr: true } }
                )
            );
            let answer = call(&home, &session, request).await?;
            println!("{}", letmeknow::short::line(&answer));
            if qr && let Some(link) = answer["link"].as_str() {
                eprintln!("{}", letmeknow::cli::qr(link)?);
            }
            Ok(())
        }
    }
}
