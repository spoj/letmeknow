use std::process::Command;

fn letmeknow(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_letmeknow")).arg("--home").arg(home).args(args).env_remove("LETMEKNOW_SESSION").output().unwrap()
}

#[test]
fn the_binary_prints_the_skill_and_needs_a_session_for_requests() {
    let home = std::env::temp_dir().join(format!("lmk-binary-{}", std::process::id()));
    let skill = letmeknow(&home, &["skill"]);
    assert!(String::from_utf8(skill.stdout).unwrap().starts_with("---\nname: letmeknow"));
    let groups = letmeknow(&home, &["groups"]);
    assert!(!groups.status.success());
    assert!(String::from_utf8(groups.stderr).unwrap().contains("no session is running"));
    let send = letmeknow(&home, &["--session", "swift-koala", "send", "hi"]);
    assert!(String::from_utf8(send.stderr).unwrap().contains("swift-koala is not running"));
    let bad = letmeknow(&home, &["invite", "--kind", "spreadsheet"]);
    assert!(!bad.status.success());
}

/// Unless RUST_LOG asks for them, dependencies' logs stay out of stderr; logs to a pipe have no colour.
#[test]
fn the_binary_logs_what_rust_log_asks_without_colour_in_a_pipe() {
    use std::io::BufRead;
    for (rust_log, quiet) in [(None, true), (Some("debug"), false)] {
        let home = std::env::temp_dir().join(format!("lmk-binary-log-{}-{quiet}", std::process::id()));
        let mut command = Command::new(env!("CARGO_BIN_EXE_letmeknow"));
        command.arg("--home").arg(&home).args(["listen", "--relay", "http://127.0.0.1:1"]).env_remove("LETMEKNOW_SESSION").env_remove("RUST_LOG");
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
