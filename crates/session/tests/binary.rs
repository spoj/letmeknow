use std::path::{Path, PathBuf};
use std::process::Command;

use lmk_proto::directory::Directory;

fn letmeknow(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_letmeknow")).arg("--home").arg(home).args(args).env_remove("LETMEKNOW_SESSION").output().unwrap()
}

/// A home in `dir` holding a fresh directory of `localhost:1`, where nothing listens: `listen --membership localhost:1`
/// fetches nothing, and lives on a relay that is down.
fn seeded_home(dir: &Path) -> PathBuf {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join("directories")).unwrap();
    std::fs::write(home.join("directories/localhost_1.json"), serde_json::to_vec(&Directory::builtin()).unwrap()).unwrap();
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
    let send = letmeknow(&home, &["--session", "0123abcd", "send", "hi"]);
    assert!(String::from_utf8(send.stderr).unwrap().contains("no session of this machine has a fingerprint that begins 0123abcd"));
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
        command.arg("--home").arg(&home).args(["listen", "--membership", "localhost:1"]).env_remove("LETMEKNOW_SESSION").env_remove("RUST_LOG");
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
    command.arg("--home").arg(seeded_home(dir.path())).args(["listen", "--membership", "localhost:1"]).env_remove("LETMEKNOW_SESSION");
    command.env("TERMUX_EXEC__PROC_SELF_EXE", "/data/data/com.termux/files/home/letmeknow");
    command.env("LETMEKNOW_REGISTRY", "http://127.0.0.1:1");
    let mut child = command.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().unwrap();
    let mut ready = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut ready).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(ready.contains(r#""bin":"/data/data/com.termux/files/home/letmeknow""#), "{ready}");
}

/// A home that an earlier release made is refused, and left as it is.
#[test]
fn the_binary_leaves_an_earlier_home_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::write(home.join("format"), "4\n").unwrap();
    let listen = letmeknow(home, &["listen"]);
    assert!(!listen.status.success());
    assert!(String::from_utf8(listen.stderr).unwrap().contains("earlier letmeknow"));
    assert_eq!(std::fs::read_to_string(home.join("format")).unwrap(), "4\n");
    assert!(!home.join("sessions").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn the_binary_refuses_an_earlier_home_in_the_default_device_directory() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("letmeknow");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(home.join("format"), "4\n").unwrap();
    std::fs::write(home.join("device.json"), r#"{"name":"old device"}"#).unwrap();
    for command in ["device", "listen"] {
        let output = Command::new(env!("CARGO_BIN_EXE_letmeknow"))
            .arg(command)
            .env("XDG_DATA_HOME", dir.path())
            .env_remove("LETMEKNOW_HOME")
            .env_remove("LETMEKNOW_SESSION")
            .output().unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(&format!("{} holds the state of an earlier letmeknow, which this one cannot read: move it away", home.display())), "{error}");
        assert_eq!(std::fs::read_to_string(home.join("format")).unwrap(), "4\n");
        assert_eq!(std::fs::read_to_string(home.join("device.json")).unwrap(), r#"{"name":"old device"}"#);
        assert!(!dir.path().join("letmeknow-v14").exists());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn the_binary_runs_skill_and_serve_with_an_earlier_home_in_the_default_device_directory() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("letmeknow");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(home.join("format"), "4\n").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_letmeknow"))
            .args(args)
            .env("XDG_DATA_HOME", dir.path())
            .env_remove("LETMEKNOW_HOME")
            .env_remove("LETMEKNOW_SESSION")
            .output().unwrap()
    };
    let skill = run(&["skill"]);
    assert!(skill.status.success(), "{}", String::from_utf8_lossy(&skill.stderr));
    assert!(String::from_utf8(skill.stdout).unwrap().starts_with("---\nname: letmeknow"));
    let state = dir.path().join("state");
    let serve = run(&["serve", "--initialize", "--domain", "relay.example", "--state", state.to_str().unwrap()]);
    assert!(serve.status.success(), "{}", String::from_utf8_lossy(&serve.stderr));
    assert!(String::from_utf8(serve.stdout).unwrap().starts_with("membership: relay.example\nkey: "));
    assert!(String::from_utf8(run(&["sessions"]).stderr).unwrap().contains("earlier letmeknow"));
    assert!(!dir.path().join("letmeknow-v14").exists());
}

#[test]
fn the_binary_reuses_the_device_key_in_an_explicit_current_home() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("format"), "14\n").unwrap();
    let first = letmeknow(dir.path(), &["device"]);
    assert!(first.status.success());
    let again = letmeknow(dir.path(), &["device"]);
    assert!(again.status.success());
    assert_eq!(first.stdout, again.stdout);
}

#[cfg(unix)]
#[test]
fn the_command_channel_recovers_after_running_out_of_file_descriptors() {
    use std::io::{BufRead, Read, Write};
    let dir = tempfile::tempdir().unwrap();
    let home = seeded_home(dir.path());
    let mut listen = Command::new("sh")
        .args(["-c", "ulimit -n 128 && exec \"$1\" --home \"$2\" listen --membership localhost:1", "sh", env!("CARGO_BIN_EXE_letmeknow"), home.to_str().unwrap()])
        .env_remove("LETMEKNOW_SESSION")
        .env("LETMEKNOW_REGISTRY", "http://127.0.0.1:1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = std::io::BufReader::new(listen.stdout.take().unwrap());
    let mut ready = String::new();
    stdout.read_line(&mut ready).unwrap();
    let fp = serde_json::from_str::<serde_json::Value>(&ready).unwrap()["fp"].as_str().unwrap().to_owned();
    let endpoint: serde_json::Value = serde_json::from_slice(&std::fs::read(home.join("sessions").join(&fp).join("endpoint")).unwrap()).unwrap();
    let port = endpoint["port"].as_u64().unwrap() as u16;

    let mut held = Vec::new();
    for _ in 0..160 {
        let Ok(stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else { break };
        held.push(stream);
    }
    if let Ok(mut probe) = std::net::TcpStream::connect(("127.0.0.1", port)) {
        probe.set_read_timeout(Some(std::time::Duration::from_millis(300))).unwrap();
        let _ = probe.write_all(b"{}\n");
        let _ = probe.read(&mut [0; 1]);
    }
    drop(held);

    let groups = letmeknow(&home, &["--session", &fp, "groups"]);
    listen.kill().unwrap();
    listen.wait().unwrap();
    assert!(groups.status.success(), "{}", String::from_utf8_lossy(&groups.stderr));
}

/// A session run with `listen --detached` prints `ready`, and runs on once its reader is gone; `attach` prints its `ready`
/// as its reader, and another `attach` meanwhile fails.
#[test]
fn the_binary_attaches_one_reader_to_a_detached_session() {
    use std::io::BufRead;
    let dir = tempfile::tempdir().unwrap();
    let home = seeded_home(dir.path());
    let spawn = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_letmeknow"));
        command.arg("--home").arg(&home).args(args).env_remove("LETMEKNOW_SESSION").env("LETMEKNOW_REGISTRY", "http://127.0.0.1:1");
        command.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().unwrap()
    };
    let ready = |child: &mut std::process::Child| {
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        serde_json::from_str::<serde_json::Value>(&line).unwrap()
    };
    let mut listen = spawn(&["listen", "--detached", "--membership", "localhost:1"]);
    let fp = ready(&mut listen)["fp"].as_str().unwrap().to_owned();
    let mut reader = spawn(&["--session", &fp, "attach"]);
    assert_eq!(ready(&mut reader)["fp"], fp.as_str());
    let again = letmeknow(&home, &["--session", &fp, "attach"]);
    assert!(String::from_utf8(again.stderr).unwrap().contains("has a reader attached already"));
    for child in [&mut reader, &mut listen] {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
