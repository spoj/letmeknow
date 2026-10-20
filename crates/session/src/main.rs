use letmeknow::cli::{Cli, Command, call, home_dir, new_handle, running_session, session_dir};
use letmeknow::session::Config;
use letmeknow::Network;
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
        Command::Listen { hold, membership } => {
            let network = Network::new(&home, letmeknow::ca()?)?;
            let handle = match cli.session {
                Some(session) => session,
                None => new_handle(&home)?,
            };
            let config = Config {
                dir: session_dir(&home, &handle)?,
                handle,
                hold: Duration::from_secs(hold),
                membership,
            };
            let print = |line: String| {
                use std::io::Write;
                writeln!(std::io::stdout(), "{line}")
            };
            // Work in flight runs on the loop's thread, a step at a time.
            let listen = letmeknow::listen(config, &home, network, print, letmeknow::shutdown());
            tokio::task::LocalSet::new().run_until(listen).await
        }
        Command::Sessions => {
            println!("{}", letmeknow::sessions(&home).await?);
            Ok(())
        }
        Command::Auto { change } => {
            println!("{}", letmeknow::change_auto(&home, false, change)?);
            Ok(())
        }
        Command::Autorep { change } => {
            println!("{}", letmeknow::change_auto(&home, true, change)?);
            Ok(())
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
            let answer = call(&home, &session, request).await?;
            println!("{}", letmeknow::short::line(&answer));
            Ok(())
        }
    }
}
