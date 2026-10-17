use super::*;

#[test]
fn signed_rename_reaches_all_native_sessions_and_offline_leaves_wait_for_resume() {
    local(async {
        let world = world("private-rename").await;
        let mut owner = world.start("owner", HOUR).await;
        let mut side = world.start_in("owner", "side", HOUR).await;
        let tablet = world.start("tablet", HOUR).await;
        let mut observer = world.start("observer", HOUR).await;
        owner.cmd(&["identity", "create", "Alice"]).await.unwrap();
        let link = owner.cmd(&["identity", "invite"]).await.unwrap();
        tablet.cmd(&["identity", "join", link["link"].as_str().unwrap()]).await.unwrap();
        let identity = owner.cmd(&["identity", "list"]).await.unwrap()["identity"].as_str().unwrap().to_owned();
        let mut groups = Vec::new();
        for name in ["one", "two", "three"] {
            let made = observer.cmd(&["invite", "--name", name]).await.unwrap();
            let gid = made["group"].as_str().unwrap().to_owned();
            owner.cmd(&["join", made["link"].as_str().unwrap()]).await.unwrap();
            for joiner in [&side, &tablet] {
                let link = observer.cmd(&["invite", "--group", &gid]).await.unwrap();
                joiner.cmd(&["join", link["link"].as_str().unwrap()]).await.unwrap();
            }
            groups.push(gid);
        }
        // An observation wakes an hour-held observer without another command to flush it.
        let first = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let event: Value = serde_json::from_str(&observer.events.recv().await.unwrap()).unwrap();
                if event["type"] == "warning" && event["text"].as_str().unwrap().contains("First locally observed") { break event; }
            }
        }).await.unwrap();
        assert!(first["text"].as_str().unwrap().contains(&identity));
        assert!(first["text"].as_str().unwrap().contains("not been independently verified"));
        side.cmd(&["identity", "rename", "--device", "studio"]).await.unwrap();
        tablet.cmd(&["identity", "rename", "Alice Lee"]).await.unwrap();
        let warning = tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let event: Value = serde_json::from_str(&observer.events.recv().await.unwrap()).unwrap();
                if event["type"] == "warning" && event["text"].as_str().unwrap().contains("Alice Lee") { break event; }
            }
        }).await.unwrap();
        assert!(warning["text"].as_str().unwrap().contains(&identity), "compaction preserves the full ID");
        for gid in &groups {
            let members = tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    let members = observer.cmd(&["members", "--group", gid]).await.unwrap();
                    let peers: Vec<_> = members["members"].as_array().unwrap().iter().filter(|m| m["you"] != true).collect();
                    if peers.len() == 3 && peers.iter().all(|m| m["identity"]["name"] == "Alice Lee") && peers.iter().filter(|m| m["device"] == "studio").count() == 2 { break members; }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }).await.unwrap();
            for peer in members["members"].as_array().unwrap().iter().filter(|m| m["you"] != true) {
                assert_eq!(peer["identity"]["id"], identity);
                assert_eq!(peer["identity"]["how"], "observed");
                assert_eq!(peer["identity"]["observed"]["names"], json!(["Alice", "Alice Lee"]));
            }
            let status = observer.cmd(&["status", "--group", gid]).await.unwrap().to_string();
            assert!(status.contains("identity_warnings") && status.contains(&identity) && status.contains("Alice Lee"));
        }
        let (owner_fp, side_fp) = (owner.fp.clone(), side.fp.clone());
        side.stop().await;
        owner.stop().await;
        tablet.cmd(&["identity", "rename", "Alice Final"]).await.unwrap();
        let chat = &groups[0];
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let members = observer.cmd(&["members", "--group", chat]).await.unwrap();
                let peers = members["members"].as_array().unwrap();
                if peers.iter().any(|m| m["fp"] == tablet.fp && m["identity"]["name"] == "Alice Final") {
                    for fp in [&owner_fp, &side_fp] {
                        assert_eq!(peers.iter().find(|m| m["fp"] == **fp).unwrap()["identity"]["name"], "Alice Lee", "offline leaves are not relabeled from another device's profile");
                    }
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }).await.unwrap();
        let side = world.start_in("owner", "side", HOUR).await;
        let owner = world.start("owner", HOUR).await;
        assert_eq!((&owner.fp, &side.fp), (&owner_fp, &side_fp));
        for gid in &groups {
            tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    let members = observer.cmd(&["members", "--group", gid]).await.unwrap();
                    if members["members"].as_array().unwrap().iter().filter(|m| m["you"] != true).all(|m| m["identity"]["name"] == "Alice Final") { break; }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }).await.unwrap();
        }
        observer.stop().await;
        let observer = world.start("observer", HOUR).await;
        let members = observer.cmd(&["members", "--group", chat]).await.unwrap();
        let observed = members["members"].as_array().unwrap().iter().find(|m| m["fp"] == side_fp).unwrap();
        assert_eq!(observed["identity"]["observed"]["names"], json!(["Alice", "Alice Lee", "Alice Final"]));
        assert!(observer.cmd(&["status", "--group", chat]).await.unwrap().to_string().contains(&identity));
    });
}
