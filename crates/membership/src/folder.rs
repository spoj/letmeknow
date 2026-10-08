//! The local-folder kind of membership service: one file per entry, `<folder>/<log id, hex>/<position>.entry`.

use std::{
    collections::HashMap,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use async_trait::async_trait;
use lmk_proto::{
    Bytes,
    head::{self, Head},
    membership::{Appended, Notice, Page},
};
use notify::{RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::{Chain, Membership, Subscription, chain::Chains, store::now};

const PAGE_BYTES: usize = 4 << 20;

#[derive(Clone)]
pub struct FolderClient(Arc<Inner>);

struct Inner {
    dir: PathBuf,
    chains: Chains,
}

fn entry_path(dir: &Path, position: u64) -> PathBuf {
    dir.join(format!("{position}.entry"))
}

/// The entries after `after`, up to about `PAGE_BYTES`.
fn entries(dir: &Path, after: u64) -> Result<Vec<Bytes>> {
    let (mut entries, mut bytes) = (Vec::new(), 0);
    while bytes < PAGE_BYTES {
        match std::fs::read(entry_path(dir, after + 1 + entries.len() as u64)) {
            Ok(entry) => {
                bytes += entry.len();
                entries.push(Bytes(entry));
            }
            Err(err) if err.kind() == ErrorKind::NotFound => break,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(entries)
}

/// The highest position in a log's directory.
fn last(dir: &Path) -> Result<u64> {
    let mut last = 0;
    for file in std::fs::read_dir(dir)? {
        let name = file?.file_name();
        if let Some(position) = name
            .to_str()
            .and_then(|n| n.strip_suffix(".entry"))
            .and_then(|n| n.parse().ok())
        {
            last = last.max(position);
        }
    }
    Ok(last)
}

fn unsigned(log: &[u8], length: u64, hash: [u8; 32]) -> Head {
    Head {
        log: log.into(),
        length,
        hash: hash.into(),
        time: now(),
        sig: Bytes::default(),
    }
}

impl FolderClient {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FolderClient(Arc::new(Inner {
            dir: dir.into(),
            chains: Chains::new(None),
        }))
    }

    fn log_dir(&self, log: &[u8]) -> PathBuf {
        self.0.dir.join(hex::encode(log))
    }

    fn length(&self, log: &[u8]) -> u64 {
        self.0.chains.get(log).map_or(0, |c| c.length())
    }

    /// Reads a page and checks it against the chain, which first catches up to `after`.
    fn page(&self, log: &[u8], after: u64) -> Result<Page> {
        let dir = self.log_dir(log);
        while self.length(log) < after {
            let len = self.length(log);
            let entries = entries(&dir, len)?;
            if entries.is_empty() {
                break;
            }
            self.check(log, len, entries)?;
        }
        let len = self.length(log);
        if after > len {
            return self.check(log, len, vec![]);
        }
        self.check(log, after, entries(&dir, after)?)
    }

    fn check(&self, log: &[u8], after: u64, entries: Vec<Bytes>) -> Result<Page> {
        let start = self
            .0
            .chains
            .get(log)
            .map_or_else(|| head::start(log), |c| c.hash_at(after).expect("within"));
        let hash = entries
            .iter()
            .fold(start, |hash, entry| head::next(&hash, &entry.0));
        let head = unsigned(log, after + entries.len() as u64, hash);
        self.0.chains.page(log, after, &entries, &head)?;
        Ok(Page { entries, head })
    }
}

#[async_trait]
impl Membership for FolderClient {
    async fn append(&self, log: &[u8], entry: &[u8]) -> Result<Appended> {
        let dir = self.log_dir(log);
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join(format!(".{:016x}.tmp", rand::random::<u64>()));
        std::fs::write(&tmp, entry)?;
        let mut position = last(&dir)? + 1;
        // A hard link is an exclusive create that also makes the whole entry appear at once.
        let linked = loop {
            match std::fs::hard_link(&tmp, entry_path(&dir, position)) {
                Err(err) if err.kind() == ErrorKind::AlreadyExists => position += 1,
                linked => break linked,
            }
        };
        std::fs::remove_file(&tmp)?;
        linked?;
        self.page(log, position - 1)?;
        let hash = self
            .0
            .chains
            .get(log)
            .and_then(|c| c.hash_at(position))
            .expect("read back");
        Ok(Appended {
            position,
            head: unsigned(log, position, hash),
        })
    }

    async fn read(&self, log: &[u8], after: u64) -> Result<Page> {
        self.page(log, after)
    }

    async fn head(&self, log: &[u8]) -> Result<Head> {
        loop {
            let page = self.page(log, self.length(log))?;
            if page.entries.is_empty() {
                return Ok(page.head);
            }
        }
    }

    async fn subscribe(&self, logs: Vec<Bytes>) -> Result<Subscription> {
        let (wake, mut woken) = mpsc::unbounded_channel();
        let mut watcher = notify::recommended_watcher(move |_| {
            let _ = wake.send(());
        })?;
        let mut next = HashMap::new();
        for log in logs {
            let dir = self.log_dir(&log.0);
            std::fs::create_dir_all(&dir)?;
            watcher.watch(&dir, RecursiveMode::NonRecursive)?;
            let start = match self.0.chains.get(&log.0) {
                Some(chain) => chain.length(),
                None => last(&dir)?,
            };
            next.insert(log, start);
        }
        let (out, notices) = mpsc::channel(64);
        let client = self.clone();
        tokio::spawn(async move {
            let _watcher = watcher;
            let mut poll = tokio::time::interval(Duration::from_secs(2));
            loop {
                tokio::select! {
                    _ = poll.tick() => {}
                    Some(()) = woken.recv() => {}
                }
                for (log, after) in &mut next {
                    loop {
                        let page = match client.page(&log.0, *after) {
                            Ok(page) if page.entries.is_empty() => break,
                            Ok(page) => page,
                            Err(err) => {
                                let _ = out.send(Err(err)).await;
                                return;
                            }
                        };
                        for entry in page.entries {
                            *after += 1;
                            let notice = Notice {
                                log: log.clone(),
                                position: *after,
                                entry,
                                head: page.head.clone(),
                            };
                            if out.send(Ok(notice)).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        });
        Ok(Subscription(notices))
    }

    fn chain(&self, log: &[u8]) -> Option<Chain> {
        self.0.chains.get(log)
    }

    fn set_chain(&self, chain: Chain) {
        self.0.chains.set(chain)
    }
}
