use clap::Parser;
use letmeknow::cli::{Cli, Command, Request, call, home_dir, new_handle, running_session, session_dir};
use letmeknow::session::Config;
use std::process::ExitCode;
use std::time::Duration;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_writer(std::io::stderr).init();
    match run(Cli::parse()).await {
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
        Command::Listen { name, hold, keep_log, membership, relay } => {
            let handle = match cli.session {
                Some(session) => session,
                None => new_handle(&home)?,
            };
            let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "agent".into());
            let config = Config {
                dir: session_dir(&home, &handle)?,
                name: name.unwrap_or_else(|| format!("{user}/{handle}")),
                handle,
                hold: Duration::from_secs(hold),
                keep_log,
                membership: letmeknow::service(&membership)?,
            };
            let print = |line: String| println!("{line}");
            letmeknow::listen(config, &home, letmeknow::Network::new(&relay)?, print, letmeknow::shutdown()).await
        }
        Command::Skill => {
            print!("{}", letmeknow::SKILL);
            Ok(())
        }
        Command::Serve(serve) => letmeknow::serve(serve).await,
        Command::Request(request) => {
            let session = match cli.session {
                Some(session) => session,
                None => running_session(&home).await?,
            };
            let qr = matches!(request, Request::Invite { qr: true, .. });
            let answer = call(&home, &session, request).await?;
            println!("{answer}");
            if qr && let Some(link) = answer["link"].as_str() {
                eprintln!("{}", letmeknow::cli::qr(link)?);
            }
            Ok(())
        }
    }
}
