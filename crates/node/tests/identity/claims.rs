use super::*;
use lmk_membership::client::ServeClient;

pub(super) fn binding_record(db: &Path) -> Option<Vec<u8>> {
    let mut provider = SqliteProvider::open(db).unwrap();
    let record = provider.get(b"node/identity-bindings").unwrap();
    provider.close().unwrap();
    record
}

#[tokio::test(flavor = "multi_thread")]
async fn every_public_body_is_keys_only_through_rename_restatement_removal_and_closure() {
    let relay = relay().await;
    let dir = folder("keys-only-bodies");
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("device.db");
    let (laptop, devices) = stored_device(&relay, "device-canary-1734567890123", &db).await;
    let identity = devices.create("identity-canary-1734567890123", relay.service.clone()).await.unwrap();
    let gid = devices_group(&laptop.node);
    let endpoint = relay.endpoint(iroh::SecretKey::from_bytes(&lmk_core::random())).await;
    let reader = ServeClient::for_service(endpoint, lmk_testing::resolve(), &identity.membership).unwrap();
    let address = lmk_proto::public::address(&identity.id.0);
    let initial = reader.head(&address).await.unwrap();
    devices.rename("renamed-identity-canary").await.unwrap();
    devices.rename_device("renamed-device-canary").await.unwrap();
    devices.duties(&gid.0).await.unwrap();
    assert_eq!(reader.head(&address).await.unwrap().length, initial.length, "rename must not publish descriptions or clocks");
    let key = devices.key().unwrap();
    laptop.node.shutdown().await.unwrap();
    drop((laptop, devices));

    let (laptop, devices) = stored_device(&relay, "renamed-device-canary", &db).await;
    devices.duties(&gid.0).await.unwrap();
    assert_eq!(reader.head(&address).await.unwrap().length, initial.length, "restart preserves the publication day");
    laptop.node.shutdown().await.unwrap();
    drop((laptop, devices));
    let mut provider = SqliteProvider::open(&db).unwrap();
    let rec_key = [b"node/group/".as_slice(), &gid.0].concat();
    let mut rec: Value = serde_json::from_slice(&provider.get(&rec_key).unwrap().unwrap()).unwrap();
    rec["publication_day"] = json!(lmk_node::now() / 86_400_000 - 182);
    provider.put(&rec_key, &serde_json::to_vec(&rec).unwrap()).unwrap();
    provider.close().unwrap();
    let (laptop, devices) = stored_device(&relay, "renamed-device-canary", &db).await;
    devices.duties(&gid.0).await.unwrap();
    let restated = reader.head(&address).await.unwrap().length;
    assert_eq!(restated, initial.length + 1, "182 local days restates the same keys");
    for _ in 0..3 {
        laptop.node.read_public(&identity).await.unwrap();
        devices.duties(&gid.0).await.unwrap();
    }
    assert_eq!(reader.head(&address).await.unwrap().length, restated);

    let (mut phone, phone_devices) = device(&relay, "other-device-canary").await;
    routed(&mut phone, phone_devices.clone());
    phone_devices.join(&lmk_proto::links::Invite::parse(&devices.invite().await.unwrap()).unwrap()).await.unwrap();
    lists(&laptop.node, &identity, &[key.clone(), phone_devices.key().unwrap()]).await;
    let revoked = phone_devices.key().unwrap();
    phone.node.shutdown().await.unwrap();
    devices.remove(&revoked.0).await.unwrap();
    lists(&laptop.node, &identity, std::slice::from_ref(&key)).await;
    assert!(devices.leave().await.unwrap());
    let mut bodies = Vec::new();
    let Service::Serve { key, .. } = &identity.membership else { unreachable!() };
    let key: [u8; 32] = key.0.as_slice().try_into().unwrap();
    let mut frontier = lmk_membership::Frontier::empty(key, lmk_proto::head::reference(&key, &address));
    loop {
        let page = reader.read(&address, &frontier).await.unwrap();
        if page.page().entries.is_empty() { break; }
        frontier = page.frontier().clone();
        for entry in page.into_page().entries {
            let envelope = lmk_core::public::open(&identity.id.0, &entry.0).unwrap();
            let body: Value = serde_json::from_slice(&envelope.body.0).unwrap();
            let mut fields: Vec<_> = body.as_object().unwrap().keys().map(String::as_str).collect();
            fields.sort();
            assert_eq!(fields, if bodies.is_empty() { vec!["membership", "prev", "writers"] } else { vec!["prev", "writers"] });
            assert!(body["writers"].as_array().unwrap().iter().all(Value::is_string));
            let raw = String::from_utf8(envelope.body.0).unwrap();
            assert!(!raw.contains("canary") && !raw.contains("1734567890123"), "decrypted body leaked a label/precise clock: {raw}");
            bodies.push(body);
        }
    }
    assert!(bodies.len() >= 5, "create, maintenance, add, removal, closure were all read");
    assert!(bodies.iter().any(|body| body["writers"].as_array().unwrap().contains(&json!(revoked))));
    assert_eq!(bodies.last().unwrap()["writers"], json!([]), "an ID held before removal still opens closure");
    laptop.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn installed_bindings_survive_refresh_collision_restart_and_group_deletion() {
    let relay = relay().await;
    let dir = folder("observed-bindings");
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("observer.db");
    let mut observer = stored(&relay, "observer", &db).await;
    let (identity, device) = identity(&relay, &observer.node, relay.service.clone()).await;
    assert!(binding_record(&db).is_none(), "directory lookup alone must not observe names");
    let gid = observer.node.create(settings(CHAT, &relay), None).unwrap();
    let peer = session(&relay, "peer").await;
    let first = certificate(&identity, &device, &peer.node.key(), "Ann", "phone");
    peer.node.join(&observer.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), Some(first.clone())).await.unwrap();
    observer.checked(&gid, "peer", true).await;
    let record = binding_record(&db).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&record).unwrap(), json!([[identity.id, "Ann"]]));
    let first_warning = observer.until(|e| match e { Event::Warning { text, .. } if text.contains("First locally observed") => Some(text), _ => None }).await;
    assert!(first_warning.contains(&serde_json::to_value(&identity.id).unwrap().as_str().unwrap().to_string()));
    let epoch = peer.node.epoch(&gid.0).unwrap();
    peer.node.recertify(&gid.0, first).await.unwrap();
    assert_eq!(peer.node.epoch(&gid.0).unwrap(), epoch, "identical claims commit nothing");

    let renamed = certificate(&identity, &device, &peer.node.key(), "Ann Lee", "pocket");
    peer.node.recertify(&gid.0, renamed).await.unwrap();
    let rename_warning = observer.until(|e| match e { Event::Warning { text, .. } if text.contains("changed name claims") => Some(text), _ => None }).await;
    assert!(rename_warning.contains("Ann Lee") && rename_warning.contains("Ann"));
    let member = observer.checked(&gid, "peer", true).await;
    assert_eq!(member.device_name, "pocket");
    assert_eq!(member.identity.unwrap().observed.unwrap().names, ["Ann", "Ann Lee"]);
    let endpoint = relay.endpoint(iroh::SecretKey::from_bytes(&lmk_core::random())).await;
    let directory = ServeClient::for_service(endpoint, lmk_testing::resolve(), &identity.membership).unwrap();
    assert_eq!(directory.head(&lmk_proto::public::address(&identity.id.0)).await.unwrap().length, 1, "refresh is private, not directory growth");
    let phone = certificate(&identity, &device, &peer.node.key(), "Ann Lee", "another label");
    peer.node.recertify(&gid.0, phone).await.unwrap();
    eventually("device label refresh", || observer.node.members(&gid.0).unwrap().iter().any(|m| m.device_name == "another label")).await;
    let stored = binding_record(&db).unwrap();
    while let Ok(e) = observer.events.try_recv() {
        assert!(!matches!(e, Event::Warning { text, .. } if text.contains("observed identity")), "device-only rename is not a binding change");
    }
    observer.node.shutdown().await.unwrap();
    drop(observer);
    let mut observer = super::stored(&relay, "observer", &db).await;
    let reminder = observer.until(|e| match e { Event::Warning { text, .. } if text.contains("Previously observed") => Some(text), _ => None }).await;
    assert!(reminder.contains("Ann Lee") && reminder.contains("Ann"));
    assert_eq!(binding_record(&db).unwrap(), stored);

    let public = observer.node.read_public(&identity).await.unwrap();
    publish(&relay, &observer.node, &identity, public.next(&device, vec![])).await;
    observer.until(|e| matches!(e, Event::Left { member, .. } if member.name == "peer").then_some(())).await;
    observer.node.leave(&gid.0).await.unwrap();
    assert_eq!(binding_record(&db).unwrap(), stored, "revocation and leaving all groups retain the baseline");
    observer.node.shutdown().await.unwrap();
    drop(observer);
    let mut observer = super::stored(&relay, "observer", &db).await;
    let (other, other_device) = super::identity(&relay, &observer.node, relay.service.clone()).await;
    let gid = observer.node.create(settings(CHAT, &relay), None).unwrap();
    let collision = session(&relay, "collision").await;
    collision.node.join(&observer.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), Some(certificate(&other, &other_device, &collision.node.key(), "ann", "desk"))).await.unwrap();
    let warning = observer.until(|e| match e { Event::Warning { text, .. } if text.contains("Names are not unique") => Some(text), _ => None }).await;
    for id in [&identity.id, &other.id] {
        assert!(warning.contains(serde_json::to_value(id).unwrap().as_str().unwrap()), "both full IDs in warning: {warning}");
    }
    let observed = observer.checked(&gid, "collision", true).await.identity.unwrap().observed.unwrap();
    assert_eq!(observed.names, ["ann"]);
    assert_eq!(observed.other_ids, std::slice::from_ref(&identity.id));
    assert_eq!(serde_json::from_slice::<Value>(&binding_record(&db).unwrap()).unwrap(), json!([[identity.id, "Ann"], [identity.id, "Ann Lee"], [other.id, "ann"]]));
    let fresh_db = dir.join("different-handle.db");
    let fresh = super::stored(&relay, "different-handle", &fresh_db).await;
    assert!(binding_record(&fresh_db).is_none(), "different handles are independent observers");
    fresh.node.shutdown().await.unwrap();
    observer.node.shutdown().await.unwrap();
    peer.node.shutdown().await.unwrap();
    collision.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_installed_claims_cannot_supply_names_or_poison_observations_or_targeted_admission() {
    let relay = relay().await;
    let dir = folder("invalid-observations");
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("observer.db");
    let mut observer = stored(&relay, "observer", &db).await;
    let (identity, device) = identity(&relay, &observer.node, relay.service.clone()).await;
    let gid = observer.node.create(settings(CHAT, &relay), None).unwrap();
    let legitimate = session(&relay, "legitimate").await;
    legitimate.node.join(&observer.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), Some(certificate(&identity, &device, &legitimate.node.key(), "Ann", "phone"))).await.unwrap();
    observer.checked(&gid, "legitimate", true).await;
    let baseline = binding_record(&db).unwrap();
    eventually("authorized peer connection", || observer.node.online(&gid.0).unwrap().iter().any(|m| m.key == legitimate.node.key())).await;
    legitimate.node.send_live(&gid.0, &json!({ "type": "presence", "identity": { "id": identity.id, "name": "Poison" }, "device_name": "Poison" }), None).unwrap();
    observer.until(|e| matches!(e, Event::Live { payload, .. } if payload["identity"]["name"] == "Poison").then_some(())).await;
    assert_eq!(binding_record(&db).unwrap(), baseline, "even an authorized peer's live profile is not a roster credential");
    for mutation in 0..7 {
        let handle = format!("bad-{mutation}");
        let bad = session(&relay, &handle).await;
        let mut claim = certificate(&identity, &device, &bad.node.key(), "Ann", "phone");
        match mutation {
            0 => claim.name = "Poison".into(),
            1 => claim.device_name = "Poison".into(),
            2 => claim.sig.0[0] ^= 1,
            3 => claim = certificate(&identity, &device, &legitimate.node.key(), "Poison", "phone"),
            4 => claim = certificate(&identity, &lmk_core::random(), &bad.node.key(), "Poison", "phone"),
            5 => claim.device.0.truncate(31),
            _ => claim.identity.id.0.truncate(31),
        }
        let target = observer.node.invite(&gid.0, Some(identity.id.clone()), INVITE_VALID).await.unwrap();
        assert!(bad.node.join(&target, Some(claim.clone())).await.is_err(), "invalid claim {mutation} cannot redeem an identity-targeted invite");
        bad.node.join(&observer.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), Some(claim)).await.unwrap();
        let member = observer.checked(&gid, &handle, false).await;
        let claim = member.identity.unwrap();
        assert!(claim.name.is_empty() && claim.observed.is_none() && member.device_name.is_empty());
        assert_eq!(binding_record(&db).unwrap(), baseline, "mutation {mutation} changed the binding record");
        observer.node.remove(&gid.0, &bad.node.key().0).await.unwrap();
        bad.node.shutdown().await.unwrap();
    }
    let renamed = certificate(&identity, &device, &legitimate.node.key(), "Ann Lee", "phone");
    legitimate.node.recertify(&gid.0, renamed).await.unwrap();
    eventually("legitimate name compared to the original", || binding_record(&db).is_some_and(|r| serde_json::from_slice::<Value>(&r).unwrap() == json!([[identity.id, "Ann"], [identity.id, "Ann Lee"]]))).await;
    observer.node.shutdown().await.unwrap();
    legitimate.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_late_directory_response_cannot_observe_a_roster_that_was_left() {
    let relay = relay().await;
    let dir = folder("late-observation");
    std::fs::create_dir_all(&dir).unwrap();
    let (gate, mut reaching) = Gate::new();
    let (membership, service) = served(&relay, &dir.join("service"), |service| Gated { service, gate: gate.clone() }).await;
    let seed = lmk_core::random();
    let (id, first) = lmk_core::public::create(&seed, membership.clone());
    let identity = IdentityRef { id: id.into(), membership: membership.clone() };
    let endpoint = relay.endpoint(iroh::SecretKey::from_bytes(&lmk_core::random())).await;
    ServeClient::for_service(endpoint, lmk_testing::resolve(), &membership).unwrap().append(&lmk_proto::public::address(&id), &[first], true).await.unwrap();
    gate.set(false);
    let db = dir.join("observer.db");
    let observer = stored(&relay, "observer", &db).await;
    let gid = observer.node.create(settings(CHAT, &relay), Some(certificate(&identity, &seed, &observer.node.key(), "Too late", "phone"))).unwrap();
    let reader = observer.node.clone();
    let lookup = tokio::spawn(async move { reader.read_public(&identity).await });
    tokio::time::timeout(WAIT, async {
        loop {
            if reaching.recv().await.unwrap().0 == observer.node.net().id().as_bytes() { break; }
        }
    }).await.unwrap();
    assert!(binding_record(&db).is_none());
    observer.node.leave(&gid.0).await.unwrap();
    gate.set(true);
    tokio::time::timeout(WAIT, lookup).await.unwrap().unwrap().unwrap();
    assert!(binding_record(&db).is_none(), "an authenticated response authorizes no departed/historical roster");
    observer.node.shutdown().await.unwrap();
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn observation_events_wait_for_storage_and_failure_never_releases_them() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for fail in [false, true] {
        let relay = relay().await;
        let dir = folder(if fail { "observation-fail" } else { "observation-hold" });
        let db = dir.join("observer.db");
        std::fs::create_dir_all(&dir).unwrap();
        let held = Arc::new(AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let mut cfg = config(&relay, "observer", None, &[CHAT, KIND]);
        let (holding, releasing) = (held.clone(), release.clone());
        cfg.durable = Some(Arc::new(move || {
            let (holding, releasing) = (holding.clone(), releasing.clone());
            Box::pin(async move {
                if holding.load(Ordering::SeqCst) {
                    releasing.notified().await;
                    anyhow::ensure!(!fail, "injected observation storage failure");
                }
                Ok(())
            })
        }));
        let (node, events) = Node::start(SqliteProvider::open(&db).unwrap(), cfg).await.unwrap();
        let mut observer = Session { node, events };
        let (identity, device) = identity(&relay, &observer.node, relay.service.clone()).await;
        let gid = observer.node.create(settings(CHAT, &relay), None).unwrap();
        let peer = session(&relay, "peer").await;
        peer.node.join(&observer.node.invite(&gid.0, None, INVITE_VALID).await.unwrap(), Some(certificate(&identity, &device, &peer.node.key(), "Ann", "phone"))).await.unwrap();
        observer.until(|e| matches!(e, Event::Warning { text, .. } if text.contains("First locally observed")).then_some(())).await;
        while observer.events.try_recv().is_ok() {}
        held.store(true, Ordering::SeqCst);
        peer.node.recertify(&gid.0, certificate(&identity, &device, &peer.node.key(), "Ann Lee", "phone")).await.unwrap();
        eventually("observation staged before output", || binding_record(&db).is_some_and(|r| String::from_utf8(r).unwrap().contains("Ann Lee"))).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        while let Ok(e) = observer.events.try_recv() {
            assert!(!matches!(e, Event::Warning { text, .. } if text.contains("Ann Lee")), "observation escaped held storage");
        }
        held.store(false, Ordering::SeqCst);
        release.notify_waiters();
        if fail {
            observer.until(|e| matches!(e, Event::Warning { text, .. } if text.contains("injected observation storage failure")).then_some(())).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            while let Ok(e) = observer.events.try_recv() {
                assert!(!matches!(e, Event::Warning { text, .. } if text.contains("Ann Lee")), "observation escaped failed storage");
            }
        } else {
            observer.until(|e| matches!(e, Event::Warning { text, .. } if text.contains("Ann Lee")).then_some(())).await;
        }
        observer.node.shutdown().await.unwrap();
        peer.node.shutdown().await.unwrap();
    }
}
