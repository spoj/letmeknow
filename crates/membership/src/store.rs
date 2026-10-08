//! The logs of `letmeknow serve`, in SQLite.

use std::{
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ed25519_dalek::SigningKey;
use lmk_proto::{
    Bytes,
    head::{self, Head},
    membership::{Appended, Page},
};
use rusqlite::{Connection, OptionalExtension, params};

pub struct Store {
    db: Mutex<Connection>,
    key: SigningKey,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

impl Store {
    pub fn open(path: &Path, key: SigningKey) -> Result<Self> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "NORMAL")?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS logs (id BLOB PRIMARY KEY, length INTEGER NOT NULL, hash BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS entries (log BLOB NOT NULL, position INTEGER NOT NULL, entry BLOB NOT NULL,
                 hash BLOB NOT NULL, time INTEGER NOT NULL, PRIMARY KEY (log, position)) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS entries_time ON entries (time);",
        )?;
        Ok(Store {
            db: Mutex::new(db),
            key,
        })
    }

    fn sign(&self, log: &[u8], length: u64, hash: [u8; 32]) -> Head {
        Head::sign(&self.key, log, length, hash, now())
    }

    fn latest(db: &Connection, log: &[u8]) -> Result<(u64, [u8; 32])> {
        let row = db
            .query_row("SELECT length, hash FROM logs WHERE id = ?", [log], |r| {
                Ok((r.get::<_, u64>(0)?, r.get::<_, [u8; 32]>(1)?))
            })
            .optional()?;
        Ok(row.unwrap_or((0, head::start(log))))
    }

    /// Appends `entry`, creating the log if it is new.
    pub fn append(&self, log: &[u8], entry: &[u8]) -> Result<Appended> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        let (length, hash) = Self::latest(&tx, log)?;
        let (position, hash) = (length + 1, head::next(&hash, entry));
        tx.execute(
            "INSERT INTO entries (log, position, entry, hash, time) VALUES (?, ?, ?, ?, ?)",
            params![log, position, entry, hash, now()],
        )?;
        tx.execute(
            "INSERT INTO logs (id, length, hash) VALUES (?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET length = ?2, hash = ?3",
            params![log, position, hash],
        )?;
        tx.commit()?;
        Ok(Appended {
            position,
            head: self.sign(log, position, hash),
        })
    }

    /// The entries after `after`, up to about `max_bytes`, or `None` if some of them have expired.
    pub fn read(&self, log: &[u8], after: u64, max_bytes: usize) -> Result<Option<Page>> {
        let db = self.db.lock().unwrap();
        let (length, hash) = Self::latest(&db, log)?;
        let mut rows = db.prepare_cached(
            "SELECT position, entry, hash FROM entries WHERE log = ? AND position > ? ORDER BY position",
        )?;
        let mut rows = rows.query(params![log, after])?;
        let (mut entries, mut bytes, mut last) = (Vec::new(), 0, None);
        while bytes < max_bytes
            && let Some(row) = rows.next()?
        {
            let (position, entry, hash): (u64, Vec<u8>, [u8; 32]) = (row.get(0)?, row.get(1)?, row.get(2)?);
            if position != after + 1 + entries.len() as u64 {
                return Ok(None);
            }
            bytes += entry.len();
            entries.push(Bytes(entry));
            last = Some((position, hash));
        }
        if last.is_none() && after < length {
            return Ok(None);
        }
        let (length, hash) = last.unwrap_or((length, hash));
        Ok(Some(Page {
            entries,
            head: self.sign(log, length, hash),
        }))
    }

    pub fn head(&self, log: &[u8]) -> Result<Head> {
        let (length, hash) = Self::latest(&self.db.lock().unwrap(), log)?;
        Ok(self.sign(log, length, hash))
    }

    /// Deletes entries appended before `time`; their logs keep their length and hash.
    pub fn expire(&self, time: u64) -> Result<usize> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .execute("DELETE FROM entries WHERE time < ?", [time])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_read_expire() {
        let dir = std::env::temp_dir().join(format!("lmk-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = SigningKey::from_bytes(&[3; 32]);
        let store = Store::open(&dir.join("store.db"), key.clone()).unwrap();
        assert_eq!(store.head(b"g").unwrap().length, 0);
        assert_eq!(store.append(b"g", b"one").unwrap().position, 1);
        let two = store.append(b"g", b"two").unwrap();
        assert_eq!(two.position, 2);
        assert!(two.head.verify(&key.verifying_key()));
        let expected = head::next(&head::next(&head::start(b"g"), b"one"), b"two");
        assert_eq!(two.head.hash.0, expected);

        let page = store.read(b"g", 0, 1).unwrap().unwrap();
        assert_eq!((page.entries, page.head.length), (vec![Bytes(b"one".to_vec())], 1));
        let page = store.read(b"g", 1, 1 << 20).unwrap().unwrap();
        assert_eq!((page.entries.len(), page.head.length), (1, 2));
        let page = store.read(b"g", 2, 1 << 20).unwrap().unwrap();
        assert_eq!((page.entries.len(), page.head.hash.0), (0, expected.to_vec()));

        assert_eq!(store.expire(now() + 1).unwrap(), 2);
        assert!(store.read(b"g", 0, 1 << 20).unwrap().is_none());
        assert_eq!(store.read(b"g", 2, 1 << 20).unwrap().unwrap().head.length, 2);
        assert_eq!(store.append(b"g", b"three").unwrap().position, 3);
        assert_eq!(store.read(b"g", 2, 1 << 20).unwrap().unwrap().entries.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
