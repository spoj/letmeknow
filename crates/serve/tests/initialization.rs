use lmk_membership::store::Store;
use lmk_proto::group::Service;
use lmk_serve::{Certificate, ServeConfig};

#[test]
fn offline_initialization_emits_only_the_durable_public_configuration() {
    let path = std::env::temp_dir().join(format!("lmk-bootstrap-{:032x}", u128::from_be_bytes(lmk_proto::random::random::<16>())));
    let config = ServeConfig::new("relay.example", &path);
    assert!(config.service().is_err());
    assert!(!path.exists());
    let public = config.initialize().unwrap();
    assert_eq!(config.service().unwrap(), public);
    let Service::Serve { key, relay, .. } = public else { panic!("expected serve") };
    assert_eq!(relay, "https://relay.example");
    let store = Store::open(&path).unwrap();
    assert_eq!(key.0, store.key().verifying_key().as_bytes());
    assert!(config.initialize().is_err());
    assert_eq!(std::fs::read(path.join("membership.key")).unwrap(), store.key().to_bytes());
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn restart_rejects_missing_store_before_certificates_or_listeners() {
    let path = std::env::temp_dir().join(format!("lmk-bootstrap-loss-{:032x}", u128::from_be_bytes(lmk_proto::random::random::<16>())));
    let mut config = ServeConfig::new("localhost", &path);
    config.initialize().unwrap();
    std::fs::remove_file(path.join("membership.db")).unwrap();
    config.certificate = Certificate::Files { chain: path.join("nonexistent-cert"), key: path.join("nonexistent-key") };
    let error = lmk_serve::serve(config).await.unwrap_err();
    assert!(error.to_string().contains("unable to open database"));
    assert!(!path.join("membership.db").exists());
    assert!(!path.join("acme").exists());
    std::fs::remove_dir_all(path).unwrap();
}

