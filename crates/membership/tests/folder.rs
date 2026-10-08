use std::{path::PathBuf, time::Duration};

use lmk_membership::{Contradiction, Membership, folder::FolderClient};
use lmk_proto::{Bytes, head::Head};

fn folder(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lmk-folder-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn tip(head: Head) -> (u64, Bytes) {
    (head.length, head.hash)
}

async fn read_all(client: &FolderClient, log: &[u8]) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    loop {
        let page = client.read(log, all.len() as u64).await.unwrap();
        if page.entries.is_empty() {
            return all;
        }
        all.extend(page.entries.into_iter().map(|e| e.0));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers() {
    let dir = folder("race");
    let tasks: Vec<_> = (0..4)
        .map(|w| {
            let client = FolderClient::new(&dir);
            tokio::spawn(async move {
                let mut positions = Vec::new();
                for i in 0..25 {
                    let entry = format!("{w}-{i}");
                    positions.push((
                        client
                            .append(b"g", entry.as_bytes())
                            .await
                            .unwrap()
                            .position,
                        entry,
                    ));
                }
                positions
            })
        })
        .collect();
    let mut positions = Vec::new();
    for task in tasks {
        positions.extend(task.await.unwrap());
    }
    positions.sort();
    assert_eq!(
        positions.iter().map(|p| p.0).collect::<Vec<_>>(),
        (1..=100).collect::<Vec<_>>()
    );
    let order: Vec<Vec<u8>> = positions.into_iter().map(|p| p.1.into_bytes()).collect();
    let (a, b) = (FolderClient::new(&dir), FolderClient::new(&dir));
    assert_eq!(read_all(&a, b"g").await, order);
    assert_eq!(read_all(&b, b"g").await, order);
    assert_eq!(
        tip(a.head(b"g").await.unwrap()),
        tip(b.chain(b"g").unwrap().head)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn subscribe_and_tamper() {
    let dir = folder("subscribe");
    let (alice, bob) = (FolderClient::new(&dir), FolderClient::new(&dir));
    bob.append(b"g", b"before").await.unwrap();
    let mut notices = alice.subscribe(vec![Bytes(b"g".to_vec())]).await.unwrap();
    bob.append(b"g", b"one").await.unwrap();
    bob.append(b"g", b"two").await.unwrap();
    for (position, entry) in [(2, b"one"), (3, b"two")] {
        let notice = tokio::time::timeout(Duration::from_secs(5), notices.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            (notice.position, notice.entry.0.as_slice()),
            (position, entry.as_slice())
        );
    }
    assert_eq!(
        tip(alice.head(b"g").await.unwrap()),
        tip(bob.head(b"g").await.unwrap())
    );

    std::fs::write(dir.join(hex::encode(b"g")).join("2.entry"), b"rewritten").unwrap();
    assert!(alice.read(b"g", 1).await.unwrap_err().is::<Contradiction>());
    std::fs::remove_dir_all(&dir).unwrap();
}
