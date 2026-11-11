use letmeknow::cli::{Cli, Command, call, device_dir, home_dir, running_session, session_dir, session_named};
use letmeknow::session::Config;
use letmeknow::Network;
use std::process::ExitCode;

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
    match cli.command {
        Command::Skill => {
            print!("{}", letmeknow::SKILL);
            return Ok(());
        }
        Command::Serve(serve) => return letmeknow::serve(serve).await,
        _ => {}
    }
    let device = device_dir(cli.home.as_deref())?;
    let home = home_dir(cli.home)?;
    match cli.command {
        Command::Listen { membership, detached } => {
            let network = Network::new(&home, letmeknow::ca()?)?;
            let dir = match cli.session {
                Some(session) => session_dir(&home, &session_named(&home, session)?)?,
                None => letmeknow::new_session(&home, &membership)?,
            };
            let config = Config { dir, device, membership, detached };
            let print = |line: String| {
                use std::io::Write;
                writeln!(std::io::stdout(), "{line}")
            };
            // Work in flight runs on the loop's thread, a step at a time.
            let listen = letmeknow::listen(config, &home, network, print, letmeknow::shutdown());
            tokio::task::LocalSet::new().run_until(listen).await
        }
        Command::Attach => {
            let session = match cli.session {
                Some(session) => session_named(&home, session)?,
                None => running_session(&home).await?,
            };
            let print = |line: String| {
                use std::io::Write;
                writeln!(std::io::stdout(), "{line}")
            };
            letmeknow::cli::attach(&home, &session, print).await
        }
        Command::Sessions => {
            println!("{}", letmeknow::sessions(&home).await?);
            Ok(())
        }
        Command::Device => {
            let key = letmeknow::device(&device)?.verifying_key().to_bytes();
            println!("{}", serde_json::json!({ "fp": lmk_node::fp(&key), "key": hex::encode(key) }));
            Ok(())
        }
        Command::Skill | Command::Serve(_) => unreachable!(),
        Command::Request(request) => {
            let session = match cli.session {
                Some(session) => session_named(&home, session)?,
                None => running_session(&home).await?,
            };
            let answer = call(&home, &session, request).await?;
            println!("{}", letmeknow::short::line(&answer));
            Ok(())
        }
    }
}
