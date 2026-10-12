//! The logs of `letmeknow serve`, in SQLite.

use std::{path::Path, sync::Mutex};

use anyhow::Result;
use ed25519_dalek::SigningKey;
use lmk_proto::{
    Bytes,
    clock::now,
    head::{self, Head},
    membership::{Appended, Page},
};
use rusqlite::{Connection, OptionalExtension, params};

pub struct Store {
    db: Mutex<Connection>,
    key: SigningKey,
}

impl Store {
    pub fn open(path: &Path, key: SigningKey) -> Result<Self> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.pragma_update(None, "fullfsync", true)?;
        // `public` marks a log kept whole while it is appended to; `appended`, in milliseconds, is its last append.
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS logs (id BLOB PRIMARY KEY, length INTEGER NOT NULL, hash BLOB NOT NULL,
                 public INTEGER NOT NULL DEFAULT 0, appended INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS entries (log BLOB NOT NULL, position INTEGER NOT NULL, entry BLOB NOT NULL,
                 hash BLOB NOT NULL, time INTEGER NOT NULL, PRIMARY KEY (log, position)) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS entries_time ON entries (time);",
        )?;
        // A database of 0.13 has its logs, without these columns.
        let public: bool = db.query_row("SELECT count(*) FROM pragma_table_info('logs') WHERE name = 'public'", [], |r| r.get(0))?;
        if !public {
            db.execute_batch(
                "ALTER TABLE logs ADD COLUMN public INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE logs ADD COLUMN appended INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
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

    /// Appends entries one after another, creating the log if it is new, as a public one if `public`; answers the first
    /// one's position.
    pub fn append(&self, log: &[u8], entries: &[Bytes], public: bool) -> Result<Appended> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        let (length, mut hash) = Self::latest(&tx, log)?;
        let mut position = length;
        for entry in entries {
            (position, hash) = (position + 1, head::next(&hash, &entry.0));
            tx.execute(
                "INSERT INTO entries (log, position, entry, hash, time) VALUES (?, ?, ?, ?, ?)",
                params![log, position, entry.0, hash, now()],
            )?;
        }
        tx.execute(
            "INSERT INTO logs (id, length, hash, public, appended) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (id) DO UPDATE SET length = ?2, hash = ?3, appended = ?5",
            params![log, position, hash, public, now()],
        )?;
        tx.commit()?;
        Ok(Appended {
            position: length + 1,
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

    /// The signed head after `position` entries of a log.
    pub fn head_at(&self, log: &[u8], position: u64) -> Result<Head> {
        let db = self.db.lock().unwrap();
        let hash: [u8; 32] = db.query_row("SELECT hash FROM entries WHERE log = ? AND position = ?", params![log, position], |r| r.get(0))?;
        Ok(self.sign(log, position, hash))
    }

    pub fn head(&self, log: &[u8]) -> Result<Head> {
        let (length, hash) = Self::latest(&self.db.lock().unwrap(), log)?;
        Ok(self.sign(log, length, hash))
    }

    /// Deletes the entries appended before `time` of logs but public ones, and every entry of a public log last appended
    /// to before then. Logs keep their length and hash, so that one deleted does not start again.
    pub fn expire(&self, time: u64) -> Result<usize> {
        let db = self.db.lock().unwrap();
        let entries = db.execute("DELETE FROM entries WHERE time < ?1 AND log IN (SELECT id FROM logs WHERE public = 0)", [time])?;
        let public = db.execute("DELETE FROM entries WHERE log IN (SELECT id FROM logs WHERE public = 1 AND appended < ?1)", [time])?;
        Ok(entries + public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_append_returns_no_head_when_commit_fails() {
        let dir = std::env::temp_dir().join(format!("lmk-store-durable-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db");
        let key = SigningKey::from_bytes(&[3; 32]);
        let store = Store::open(&path, key.clone()).unwrap();
        {
            let db = store.db.lock().unwrap();
            assert_eq!(db.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0)).unwrap(), "wal");
            assert_eq!(db.query_row("PRAGMA synchronous", [], |r| r.get::<_, u32>(0)).unwrap(), 2);
            assert_eq!(db.query_row("PRAGMA fullfsync", [], |r| r.get::<_, u32>(0)).unwrap(), 1);
            db.execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE parent (id INTEGER PRIMARY KEY);
                 CREATE TABLE child (id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
                 CREATE TRIGGER fail_commit AFTER INSERT ON entries BEGIN INSERT INTO child VALUES (1); END;",
            ).unwrap();
        }
        assert!(store.append(b"g", &[Bytes(b"not committed".to_vec())], false).is_err());
        assert_eq!(store.head(b"g").unwrap().length, 0);
        assert!(store.read(b"g", 0, 1024).unwrap().unwrap().entries.is_empty());
        store.db.lock().unwrap().execute_batch("DROP TRIGGER fail_commit").unwrap();
        let appended = store.append(b"g", &[Bytes(b"committed".to_vec())], false).unwrap();
        let reader = Store::open(&path, key).unwrap();
        assert_eq!(reader.head(b"g").unwrap().hash, appended.head.hash);
        assert_eq!(reader.read(b"g", 0, 1024).unwrap().unwrap().entries, [Bytes(b"committed".to_vec())]);
        drop((reader, store));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn append_read_expire() {
        let dir = std::env::temp_dir().join(format!("lmk-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = SigningKey::from_bytes(&[3; 32]);
        let store = Store::open(&dir.join("store.db"), key.clone()).unwrap();
        assert_eq!(store.head(b"g").unwrap().length, 0);
        assert_eq!(store.append(b"g", &[Bytes(b"one".to_vec())], false).unwrap().position, 1);
        let two = store.append(b"g", &[Bytes(b"two".to_vec())], false).unwrap();
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
        let batch = store.append(b"g", &[Bytes(b"three".to_vec()), Bytes(b"four".to_vec())], false).unwrap();
        assert_eq!((batch.position, batch.head.length), (3, 4));
        assert_eq!(store.read(b"g", 2, 1 << 20).unwrap().unwrap().entries.len(), 2);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_public_log_is_kept_whole_and_deleted_only_a_while_after_its_last_append() {
        let dir = std::env::temp_dir().join(format!("lmk-store-public-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("store.db"), SigningKey::from_bytes(&[3; 32])).unwrap();
        store.append(b"p", &[Bytes(b"first".to_vec())], true).unwrap();
        store.append(b"g", &[Bytes(b"one".to_vec())], false).unwrap();
        let before_second = now() + 1;
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.append(b"p", &[Bytes(b"second".to_vec())], false).unwrap();
        assert_eq!(store.expire(before_second).unwrap(), 1, "the group log's entry, not the public log's first");
        assert_eq!(store.read(b"p", 0, 1 << 20).unwrap().unwrap().entries.len(), 2);
        assert_eq!(store.expire(now() + 1).unwrap(), 2, "once appended to before the time, the public log goes whole");
        assert!(store.read(b"p", 0, 1 << 20).unwrap().is_none());
        assert_eq!(store.append(b"p", &[Bytes(b"again".to_vec())], true).unwrap().position, 3, "and does not start again");
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_database_of_0_13_gains_the_columns() {
        let dir = std::env::temp_dir().join(format!("lmk-store-old-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db");
        let old = Connection::open(&path).unwrap();
        old.execute_batch(
            "CREATE TABLE logs (id BLOB PRIMARY KEY, length INTEGER NOT NULL, hash BLOB NOT NULL) WITHOUT ROWID;
             INSERT INTO logs VALUES (x'67', 0, x'00');",
        )
        .unwrap();
        drop(old);
        let store = Store::open(&path, SigningKey::from_bytes(&[3; 32])).unwrap();
        store.append(b"p", &[Bytes(b"first".to_vec())], true).unwrap();
        assert_eq!(store.read(b"p", 0, 1 << 20).unwrap().unwrap().entries.len(), 1);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
