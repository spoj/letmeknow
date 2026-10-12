use std::{fs::{File, OpenOptions}, path::{Path, PathBuf}, sync::{Arc, Mutex}};

use anyhow::{Context, Result, ensure};
use n0_future::boxed::BoxFuture;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{Archive, Batch, Hash, Pins};

struct Open {
    db: Connection,
    _lease: File,
    _temporary: Option<tempfile::TempDir>,
}

#[derive(Clone)]
pub(crate) struct Native {
    open: Arc<Mutex<Option<Open>>>,
    slots: Arc<tokio::sync::Semaphore>,
    pub scratch: PathBuf,
}

impl Native {
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let temporary = path.is_none().then(tempfile::tempdir).transpose()?;
        let db_path = match path { Some(path) => std::fs::canonicalize(path)?, None => temporary.as_ref().unwrap().path().join("records.sqlite3") };
        let mut name = db_path.as_os_str().to_os_string();
        name.push(".epoch-scratch");
        let scratch = PathBuf::from(name);
        let mut name = db_path.as_os_str().to_os_string();
        name.push(".epoch-lock");
        let lease = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(PathBuf::from(name))?;
        lease.try_lock().context("this session's epoch archive is already open")?;
        if scratch.exists() { std::fs::remove_dir_all(&scratch)?; }
        std::fs::create_dir(&scratch)?;
        let db = Connection::open(&db_path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA cache_size=-4096;
            CREATE TABLE IF NOT EXISTS lmk_epoch_blocks (id BLOB PRIMARY KEY, data BLOB NOT NULL,
                raw INTEGER NOT NULL, refs INTEGER NOT NULL, owner BLOB) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS lmk_epoch_garbage ON lmk_epoch_blocks(refs) WHERE owner IS NULL;
            CREATE INDEX IF NOT EXISTS lmk_epoch_owner ON lmk_epoch_blocks(owner) WHERE owner IS NOT NULL;
            CREATE TABLE IF NOT EXISTS lmk_epoch_edges (parent BLOB NOT NULL, child BLOB NOT NULL, PRIMARY KEY(parent,child)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS lmk_epoch_pins (slot BLOB PRIMARY KEY, root BLOB NOT NULL) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS lmk_epoch_usage (raw INTEGER PRIMARY KEY, bytes INTEGER NOT NULL);
            INSERT OR IGNORE INTO lmk_epoch_usage VALUES(0,0),(1,0);")?;
        Ok(Self { open: Arc::new(Mutex::new(Some(Open { db, _lease: lease, _temporary: temporary }))), slots: Arc::new(tokio::sync::Semaphore::new(4)), scratch })
    }

    fn collect(&self) -> BoxFuture<Result<()>> {
        let native = self.clone();
        Box::pin(async move {
            while native.run(|db| {
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let more = collect(&tx)?;
                tx.commit()?;
                Ok(more)
            }).await? { tokio::task::yield_now().await; }
            Ok(())
        })
    }

    fn run<T: Send + 'static>(&self, f: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static) -> BoxFuture<Result<T>> {
        let (open, slots) = (self.open.clone(), self.slots.clone());
        Box::pin(async move {
            let permit = slots.acquire_owned().await?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let mut open = open.lock().unwrap();
                f(&mut open.as_mut().context("epoch archive closed")?.db)
            }).await?
        })
    }
}

fn pins(tx: &Transaction<'_>, pins: Pins) -> Result<()> {
    for (slot, root) in pins {
        let old: Option<Hash> = tx.query_row("SELECT root FROM lmk_epoch_pins WHERE slot=?", [&slot], |r| r.get(0)).optional()?;
        if let Some(old) = old { tx.execute("UPDATE lmk_epoch_blocks SET refs=refs-1 WHERE id=?", [old])?; }
        tx.execute("DELETE FROM lmk_epoch_pins WHERE slot=?", [&slot])?;
        if let Some(root) = root {
            ensure!(tx.execute("UPDATE lmk_epoch_blocks SET refs=refs+1 WHERE id=?", [root])? == 1, "published epoch archive block missing");
            tx.execute("INSERT INTO lmk_epoch_pins VALUES(?,?)", params![slot, root])?;
        }
    }
    Ok(())
}

fn collect(tx: &Transaction<'_>) -> Result<bool> {
    for _ in 0..128 {
        let row: Option<(Hash, bool, u64)> = tx.query_row("SELECT id,raw,length(data) FROM lmk_epoch_blocks WHERE refs=0 AND owner IS NULL LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
        let Some((id, raw, bytes)) = row else { return Ok(false) };
        let children: Vec<Hash> = tx.prepare("SELECT child FROM lmk_epoch_edges WHERE parent=?")?.query_map([id], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        for child in children { tx.execute("UPDATE lmk_epoch_blocks SET refs=refs-1 WHERE id=?", [child])?; }
        tx.execute("DELETE FROM lmk_epoch_edges WHERE parent=?", [id])?;
        tx.execute("DELETE FROM lmk_epoch_blocks WHERE id=?", [id])?;
        tx.execute("UPDATE lmk_epoch_usage SET bytes=bytes-? WHERE raw=?", params![bytes, raw])?;
    }
    Ok(true)
}

impl crate::ProofTemp for Native {
    fn write(&self, target: Batch, after: u64, bytes: Vec<u8>) -> BoxFuture<Result<()>> {
        let path = self.scratch.join(crate::hex(&target));
        self.run(move |_| {
            std::fs::create_dir_all(&path)?;
            std::fs::write(path.join(after.to_string()), bytes)?;
            Ok(())
        })
    }

    fn read(&self, target: Batch, after: u64) -> BoxFuture<Result<Vec<u8>>> {
        let path = self.scratch.join(crate::hex(&target)).join(after.to_string());
        self.run(move |_| Ok(std::fs::read(path)?))
    }

    fn remove(&self, target: Batch) -> BoxFuture<Result<()>> {
        let path = self.scratch.join(crate::hex(&target));
        self.run(move |_| match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        })
    }

    fn close(&self) -> BoxFuture<Result<()>> {
        let slots = self.slots.clone();
        Box::pin(async move { let _permit = slots.acquire_many_owned(4).await?; Ok(()) })
    }
}

impl Archive for Native {
    fn read(&self, hash: Hash) -> BoxFuture<Result<Vec<u8>>> {
        self.run(move |db| Ok(db.query_row("SELECT data FROM lmk_epoch_blocks WHERE id=?", [hash], |r| r.get(0))?))
    }

    fn write(&self, batch: Batch, raw: bool, hash: Hash, children: Vec<Hash>, bytes: Vec<u8>) -> BoxFuture<Result<()>> {
        self.run(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if tx.query_row("SELECT 1 FROM lmk_epoch_blocks WHERE id=?", [hash], |_| Ok(())).optional()?.is_some() { return Ok(()); }
            let used: u64 = tx.query_row("SELECT bytes FROM lmk_epoch_usage WHERE raw=?", [raw], |r| r.get(0))?;
            ensure!(used + bytes.len() as u64 <= if raw { crate::logs::RAW_LIMIT } else { crate::logs::EVIDENCE_LIMIT }, "cold epoch archive capacity exhausted");
            tx.execute("INSERT INTO lmk_epoch_blocks VALUES(?,?,?,0,?)", params![hash, bytes, raw, batch])?;
            for child in children {
                ensure!(tx.execute("UPDATE lmk_epoch_blocks SET refs=refs+1 WHERE id=?", [child])? == 1, "missing archive child");
                tx.execute("INSERT INTO lmk_epoch_edges VALUES(?,?)", params![hash, child])?;
            }
            tx.execute("UPDATE lmk_epoch_usage SET bytes=bytes+? WHERE raw=?", params![bytes.len(), raw])?;
            tx.commit()?;
            Ok(())
        })
    }

    fn publish(&self, batch: Batch, roots: Pins) -> BoxFuture<Result<()>> {
        let native = self.clone();
        Box::pin(async move {
            native.run(move |db| {
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                pins(&tx, roots)?;
                tx.execute("UPDATE lmk_epoch_blocks SET owner=NULL WHERE owner=?", [batch])?;
                tx.commit()?;
                Ok(())
            }).await?;
            native.collect().await
        })
    }

    fn discard(&self, batch: Batch) -> BoxFuture<Result<()>> {
        let native = self.clone();
        Box::pin(async move {
            native.run(move |db| {
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.execute("UPDATE lmk_epoch_blocks SET owner=NULL WHERE owner=?", [batch])?;
                tx.commit()?;
                Ok(())
            }).await?;
            native.collect().await
        })
    }

    fn recover(&self, roots: Pins) -> BoxFuture<Result<()>> {
        let native = self.clone();
        Box::pin(async move {
            native.run(move |db| {
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let old: Vec<Hash> = tx.prepare("SELECT root FROM lmk_epoch_pins")?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
                tx.execute("DELETE FROM lmk_epoch_pins", [])?;
                for root in old { tx.execute("UPDATE lmk_epoch_blocks SET refs=refs-1 WHERE id=?", [root])?; }
                pins(&tx, roots)?;
                tx.execute("UPDATE lmk_epoch_blocks SET owner=NULL", [])?;
                tx.commit()?;
                Ok(())
            }).await?;
            native.collect().await
        })
    }

    fn close(&self) -> BoxFuture<Result<()>> {
        let (open, slots) = (self.open.clone(), self.slots.clone());
        Box::pin(async move {
            let permit = slots.acquire_many_owned(4).await?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                open.lock().unwrap().take();
            }).await?;
            Ok(())
        })
    }
}
