use std::path::{Path, PathBuf};
use std::process::Command;

use lmk_proto::directory::Directory;

fn letmeknow(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_letmeknow")).arg("--home").arg(home).args(args).env_remove("LETMEKNOW_SESSION").output().unwrap()
}

/// A home in `dir` whose membership directory is its built-in copy, stored as fresh: `listen` fetches nothing.
fn seeded_home(dir: &Path) -> PathBuf {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join("directories")).unwrap();
    std::fs::write(home.join("directories/relay.letmeknow.dev.json"), serde_json::to_vec(&Directory::builtin()).unwrap()).unwrap();
    home
}

#[test]
fn the_binary_prints_the_skill_and_needs_a_session_for_requests() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let skill = letmeknow(&home, &["skill"]);
    assert!(String::from_utf8(skill.stdout).unwrap().starts_with("---\nname: letmeknow"));
    let groups = letmeknow(&home, &["groups"]);
    assert!(!groups.status.success());
    assert!(String::from_utf8(groups.stderr).unwrap().contains("no session is running"));
    let send = letmeknow(&home, &["--session", "swift-koala", "send", "hi"]);
    assert!(String::from_utf8(send.stderr).unwrap().contains("swift-koala is not running"));
    let bad = letmeknow(&home, &["invite", "--no-such-flag"]);
    assert!(!bad.status.success());
}

/// Unless RUST_LOG asks for them, dependencies' logs stay out of stderr; logs to a pipe have no colour.
#[test]
fn the_binary_logs_what_rust_log_asks_without_colour_in_a_pipe() {
    use std::io::BufRead;
    for (rust_log, quiet) in [(None, true), (Some("debug"), false)] {
        let dir = tempfile::tempdir().unwrap();
        let home = seeded_home(dir.path());
        let mut command = Command::new(env!("CARGO_BIN_EXE_letmeknow"));
        command.arg("--home").arg(&home).args(["listen", "--relay", "http://127.0.0.1:1"]).env_remove("LETMEKNOW_SESSION").env_remove("RUST_LOG");
        command.env("LETMEKNOW_REGISTRY", "http://127.0.0.1:1");
        if let Some(rust_log) = rust_log {
            command.env("RUST_LOG", rust_log);
        }
        let mut child = command.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let mut ready = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut ready).unwrap();
        assert!(ready.contains(r#""type":"ready""#), "{ready}");
        child.kill().unwrap();
        let stderr = String::from_utf8(child.wait_with_output().unwrap().stderr).unwrap();
        assert_eq!(stderr.is_empty(), quiet, "{stderr}");
        assert!(!stderr.contains('\x1b'), "{stderr}");
    }
}

/// Termux may run the binary through Android's linker, which /proc/self/exe then names; `ready` names the binary.
#[test]
fn the_binary_names_itself_as_termux_names_it() {
    use std::io::BufRead;
    let dir = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_letmeknow"));
    command.arg("--home").arg(seeded_home(dir.path())).args(["listen", "--relay", "http://127.0.0.1:1"]).env_remove("LETMEKNOW_SESSION");
    command.env("TERMUX_EXEC__PROC_SELF_EXE", "/data/data/com.termux/files/home/letmeknow");
    command.env("LETMEKNOW_REGISTRY", "http://127.0.0.1:1");
    let mut child = command.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().unwrap();
    let mut ready = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut ready).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(ready.contains(r#""bin":"/data/data/com.termux/files/home/letmeknow""#), "{ready}");
}

/// A home that 0.15 made is refused, and left as it is.
#[test]
fn the_binary_leaves_an_earlier_home_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::write(home.join("format"), "4\n").unwrap();
    let listen = letmeknow(home, &["listen", "--relay", "http://127.0.0.1:1"]);
    assert!(!listen.status.success());
    assert!(String::from_utf8(listen.stderr).unwrap().contains("earlier letmeknow"));
    assert_eq!(std::fs::read_to_string(home.join("format")).unwrap(), "4\n");
    assert!(!home.join("sessions").exists());
}
