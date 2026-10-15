#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the pinned published @letmeknow/linux-x64@0.15.1 binary in LMK_0_15_BIN"]
fn published_writer_refuses_without_mutation_and_guard_removal_is_a_negative_control() {
    use std::{fs, process::Command};
    use lmk_membership::store::Store;
    use lmk_proto::{Bytes, head};
    use rusqlite::Connection;

    let binary = std::env::var_os("LMK_0_15_BIN").expect("LMK_0_15_BIN must name the published binary, not a shared cargo target");
    let version = Command::new(&binary).arg("--version").output().unwrap();
    assert_eq!(String::from_utf8(version.stdout).unwrap().trim(), "letmeknow 0.15.1");
    for guard in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let state = root.join("state");
        let store = Store::initialize(&state).unwrap();
        let d = head::reference(store.key().verifying_key().as_bytes(), &[7; 32]);
        let tip = store.append(&d, &[Bytes(vec![42])], false).unwrap().0.head;
        drop(store);
        let db_path = state.join("membership.db");
        if !guard {
            // A version marker alone does not stop the published writer creating legacy storage.
            Connection::open(&db_path).unwrap().execute_batch("DROP VIEW entries").unwrap();
        }
        let before = fs::read(&db_path).unwrap();
        let key = fs::read(state.join("membership.key")).unwrap();
        let ready = fs::read(state.join("membership.ready")).unwrap();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(root.join("cert.pem"), certificate.cert.pem()).unwrap();
        fs::write(root.join("cert.key"), certificate.signing_key.serialize_pem()).unwrap();
        let output = Command::new("timeout").arg("20s").arg(&binary)
            .args(["serve", "--domain", "localhost", "--https-port", "0", "--http-port", "0", "--qad-port", "0", "--state"])
            .arg(&state).arg("--cert").arg(root.join("cert.pem")).arg("--key").arg(root.join("cert.key"))
            .env("LETMEKNOW_HOME", root.join("home")).output().unwrap();
        assert!(!output.status.success());
        assert_ne!(output.status.code(), Some(124), "old executable must refuse rather than time out");
        let stderr = String::from_utf8(output.stderr).unwrap();
        if guard {
            assert!(stderr.contains("views may not be indexed"), "expected structural refusal: {stderr}");
            assert_eq!(fs::read(&db_path).unwrap(), before, "old executable must not change any database bytes");
            let store = Store::open(&state).unwrap();
            assert_eq!(store.head(&d).unwrap().hash, tip.hash);
            assert_eq!(store.read(&d, 0).unwrap().entries, [Bytes(vec![42])]);
        } else {
            assert!(stderr.contains("view"), "negative control should fail only after creating legacy storage: {stderr}");
            let db = Connection::open(&db_path).unwrap();
            assert_eq!(db.query_row("SELECT count(*) FROM sqlite_schema WHERE name='entries' AND type='table'", [], |r| r.get::<_, u64>(0)).unwrap(), 1);
            assert_ne!(fs::read(&db_path).unwrap(), before);
        }
        assert_eq!(fs::read(state.join("membership.key")).unwrap(), key);
        assert_eq!(fs::read(state.join("membership.ready")).unwrap(), ready);
    }
}
