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
