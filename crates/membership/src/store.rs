//! Disposable authority and its durable, reference-only SQLite store.

use std::{fs::{self, OpenOptions}, io::Write, path::{Path, PathBuf}, sync::Mutex};

use anyhow::{Context, Result, anyhow, ensure};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit}};
use ed25519_dalek::SigningKey;
use lmk_proto::{Bytes, clock::now, head::{self, Head}, membership::{self, Appended, Page}};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::{Expired, Refused};
/// What one expiry pass does at most: logs it lets go, and entries and bytes it deletes.
const MARK_LOGS: usize = 1024;
const EXPIRE_ROWS: usize = 1024;
const EXPIRE_BYTES: u64 = 4 << 20;
pub const DAY_MS: u64 = 86_400_000;
const STATS_DAYS: u64 = 7;
const FORMAT: u32 = 5;
pub const DISK_BYTES: u64 = 4 << 30;
const GROUP_EXPIRY: &str = "SELECT reference FROM anchors WHERE public=0 AND opened<? LIMIT ?";
const PUBLIC_EXPIRY: &str = "SELECT reference FROM anchors WHERE public=1 AND day<? LIMIT ?";
const DOOMED: &str = "SELECT reference FROM doomed LIMIT 1";
const DOOMED_RECORDS: &str = "SELECT position,length(sealed) FROM records WHERE reference=? ORDER BY position LIMIT ?";
const READ_RECORDS: &str = "SELECT sealed FROM records WHERE reference=? AND position>? ORDER BY position LIMIT ?";
const TOTALS: &str = "SELECT day,entries,bytes FROM totals WHERE day>=? AND day<? ORDER BY day";

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub struct DayTotals { pub day: u64, pub entries: u64, pub bytes: u64 }

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub struct Stats { pub days: Vec<DayTotals> }

pub struct Store {
    db: Mutex<Connection>,
    key: SigningKey,
    wal: PathBuf,
    pub(crate) disk: u64,
}

/// A log as the store addresses it: its reference, and the key its entries and state are sealed under. The capability
/// gives both; the store keeps neither.
#[derive(Clone)]
pub struct Log { pub reference: [u8; 32], key: [u8; 32] }

/// Seals with a fresh nonce. Records and a log's state are sealed alike, so a stale copy of either is ciphertext: SQLite
/// leaves moved rows in its pages' free space, which `secure_delete` does not clear.
fn seal(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    let nonce = lmk_proto::random::random::<24>();
    let sealed = XChaCha20Poly1305::new(key.into()).encrypt((&nonce).into(), plain).unwrap();
    [nonce.as_slice(), &sealed].concat()
}

fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    let (nonce, sealed) = sealed.split_at_checked(24).context("a sealed row is shorter than its nonce")?;
    let nonce: &[u8; 24] = nonce.try_into()?;
    XChaCha20Poly1305::new(key.into()).decrypt(nonce.into(), sealed).map_err(|_| anyhow!("a sealed row does not open"))
}

/// A record's entry and the head hash after it.
fn record(key: &[u8; 32], sealed: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let plain = open(key, sealed)?;
    let (entry, hash) = plain.split_at(plain.len() - 32);
    Ok((entry.to_vec(), hash.try_into()?))
}

/// A live log's length, hash and kind, or none if no entry was ever appended to it. An expired log is an error.
fn tip(db: &Connection, log: &Log) -> Result<Option<(u64, [u8; 32], bool)>> {
    let live: Option<(Vec<u8>, bool)> = db.query_row("SELECT sealed,public FROM anchors WHERE reference=?", [log.reference], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let Some((sealed, public)) = live else {
        if db.query_row("SELECT EXISTS(SELECT 1 FROM expired WHERE reference=?)", [log.reference], |r| r.get(0))? {
            return Err(Expired(log.reference).into());
        }
        return Ok(None);
    };
    let state = open(&log.key, &sealed)?;
    let hash: [u8; 32] = state[8..].try_into()?;
    Ok(Some((u64::from_be_bytes(state[..8].try_into()?), hash, public)))
}

/// The database's pages in use plus its WAL file, which keeps its high-water size until a truncating checkpoint.
fn used(db: &Connection, wal: &Path) -> Result<u64> {
    let (pages, free, size): (u64, u64, u64) = db.query_row(
        "SELECT (SELECT page_count FROM pragma_page_count), (SELECT freelist_count FROM pragma_freelist_count), (SELECT page_size FROM pragma_page_size)",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    Ok((pages - free) * size + fs::metadata(wal)?.len())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    Ok(fs::File::open(path)?.sync_all()?)
}

/// Windows cannot flush a directory; NTFS journals its entries.
#[cfg(not(unix))]
fn sync_dir(_: &Path) -> Result<()> {
    Ok(())
}

impl Store {
    /// Requires a new directory; interrupted initialization must be abandoned, not resumed with its key.
    pub fn initialize(state: &Path) -> Result<Self> {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut dir = fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
        dir.create(state)?;
        sync_dir(state.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?;
        let key = SigningKey::from_bytes(&lmk_proto::random::random::<32>());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(state.join("membership.key"))?;
        file.write_all(&key.to_bytes())?;
        file.sync_all()?;
        sync_dir(state)?;
        let db = Connection::open(state.join("membership.db"))?;
        db.busy_timeout(std::time::Duration::from_millis(250))?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.pragma_update(None, "fullfsync", true)?;
        db.pragma_update(None, "secure_delete", true)?;
        db.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL,
                 authority BLOB NOT NULL CHECK(length(authority)=32), public_bytes INTEGER NOT NULL);
             CREATE TABLE totals (day INTEGER PRIMARY KEY, entries INTEGER NOT NULL, bytes INTEGER NOT NULL);
             CREATE TABLE anchors (reference BLOB PRIMARY KEY CHECK(length(reference)=32), public INTEGER NOT NULL,
                 opened INTEGER NOT NULL, day INTEGER NOT NULL, bytes INTEGER NOT NULL, sealed BLOB NOT NULL) WITHOUT ROWID;
             CREATE INDEX group_expiry ON anchors(opened) WHERE public=0;
             CREATE INDEX public_expiry ON anchors(day) WHERE public=1;
             CREATE TABLE expired (reference BLOB PRIMARY KEY CHECK(length(reference)=32)) WITHOUT ROWID;
             CREATE TABLE doomed (reference BLOB PRIMARY KEY CHECK(length(reference)=32)) WITHOUT ROWID;
             CREATE TABLE records (reference BLOB NOT NULL, position INTEGER NOT NULL, sealed BLOB NOT NULL,
                 PRIMARY KEY(reference,position)) WITHOUT ROWID;
             CREATE VIEW logs AS SELECT reference,public,day FROM anchors;
             CREATE VIEW entries AS SELECT reference,position FROM records;",
        )?;
        db.execute("INSERT INTO metadata VALUES(1,?,?,0)", params![FORMAT, key.verifying_key().as_bytes()])?;
        db.execute_batch("COMMIT; PRAGMA wal_checkpoint(TRUNCATE);")?;
        sync_dir(state)?;
        let mut ready = options.open(state.join("membership.ready"))?;
        ready.write_all(key.verifying_key().as_bytes())?;
        ready.sync_all()?;
        sync_dir(state)?;
        Ok(Self { db: Mutex::new(db), key, wal: state.join("membership.db-wal"), disk: DISK_BYTES })
    }

    pub fn open(state: &Path) -> Result<Self> {
        let bytes: [u8; 32] = fs::read(state.join("membership.key"))?.try_into().map_err(|_| anyhow::anyhow!("invalid membership key file"))?;
        let key = SigningKey::from_bytes(&bytes);
        ensure!(fs::read(state.join("membership.ready"))? == key.verifying_key().as_bytes(), "incomplete membership initialization");
        let path = state.join("membership.db");
        let check = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let (format, authority): (u32, Vec<u8>) = check.query_row("SELECT format,authority FROM metadata WHERE id=1", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
        ensure!(format == FORMAT && authority == key.verifying_key().as_bytes(), "incompatible membership store or authority");
        let guards: u32 = check.query_row("SELECT count(*) FROM sqlite_schema WHERE type='view' AND name IN ('logs','entries')", [], |r| r.get(0))?;
        ensure!(guards == 2, "incompatible membership schema");
        drop(check);
        let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        db.busy_timeout(std::time::Duration::from_millis(250))?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.pragma_update(None, "fullfsync", true)?;
        db.pragma_update(None, "secure_delete", true)?;
        Ok(Self { db: Mutex::new(db), key, wal: state.join("membership.db-wal"), disk: DISK_BYTES })
    }

    pub fn key(&self) -> &SigningKey { &self.key }

    pub fn log(&self, capability: &[u8; 32]) -> Log {
        Log { reference: head::reference(self.key.verifying_key().as_bytes(), capability), key: head::sealing(capability) }
    }

    fn sign(&self, log_ref: &[u8; 32], length: u64, hash: [u8; 32]) -> Head {
        Head::sign(&self.key, log_ref, length, hash, now())
    }

    pub fn append(&self, log: &Log, entries: &[Bytes], public: bool) -> Result<(Appended, u64)> {
        ensure!(membership::valid_append(entries), Refused("size".into()));
        let bytes = entries.iter().map(|e| e.0.len() as u64).sum::<u64>();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let live = tip(&tx, log)?;
        let (length, mut hash, stored) = live.unwrap_or((0, head::start(self.key.verifying_key().as_bytes(), &log.reference), public));
        ensure!(stored == public, Refused("policy".into()));
        ensure!(used(&tx, &self.wal)? + bytes <= self.disk, Refused("quota".into()));
        if public {
            let public_bytes: u64 = tx.query_row("SELECT public_bytes FROM metadata", [], |r| r.get(0))?;
            ensure!(public_bytes + bytes <= self.disk / 10, Refused("quota".into()));
            tx.execute("UPDATE metadata SET public_bytes=public_bytes+?", [bytes])?;
        }
        let end = length + entries.len() as u64;
        let day = now() / DAY_MS;
        for (index, entry) in entries.iter().enumerate() {
            hash = head::next(&hash, &entry.0);
            let sealed = seal(&log.key, &[entry.0.as_slice(), &hash].concat());
            tx.execute("INSERT INTO records VALUES(?,?,?)", params![log.reference, length + index as u64 + 1, sealed])?;
        }
        let state = seal(&log.key, &[&end.to_be_bytes()[..], &hash].concat());
        tx.execute(
            "INSERT INTO anchors VALUES(?1,?2,?3,?3,?4,?5) ON CONFLICT(reference) DO UPDATE
             SET sealed=?5, day=?3, bytes=bytes+?4",
            params![log.reference, public, day, bytes, state],
        )?;
        tx.execute("INSERT INTO totals VALUES(?1,?2,?3) ON CONFLICT(day) DO UPDATE SET entries=entries+?2,bytes=bytes+?3",
            params![day, entries.len() as u64, bytes])?;
        tx.commit()?;
        Ok((Appended { position: length + 1, head: self.sign(&log.reference, end, hash) }, entries.len() as u64))
    }

    /// Touches a public log whose last entry is `entry`, byte for byte: its day moves, and nothing is stored. None, and
    /// nothing changes, when it is not so.
    pub fn touch(&self, log: &Log, entry: &[u8]) -> Result<Option<Appended>> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some((length, hash, true)) = tip(&tx, log)? else { return Ok(None) };
        let sealed: Vec<u8> = tx.query_row("SELECT sealed FROM records WHERE reference=? AND position=?", params![log.reference, length], |r| r.get(0))?;
        if record(&log.key, &sealed)?.0 != entry { return Ok(None) }
        tx.execute("UPDATE anchors SET day=? WHERE reference=?", params![now() / DAY_MS, log.reference])?;
        tx.commit()?;
        Ok(Some(Appended { position: length, head: self.sign(&log.reference, length, hash) }))
    }

    pub fn read(&self, log: &Log, after: u64) -> Result<Page> {
        let db = self.db.lock().unwrap();
        let (length, mut hash) = self.state(&db, log)?;
        ensure!(after <= length, Refused("policy".into()));
        let mut query = db.prepare_cached(READ_RECORDS)?;
        let mut rows = query.query(params![log.reference, after, membership::PAGE_ROWS as u64])?;
        let mut entries = Vec::new();
        let mut encoded = membership::PAGE_OVERHEAD;
        while let Some(row) = rows.next()? {
            let (entry, next_hash) = record(&log.key, &row.get::<_, Vec<u8>>(0)?)?;
            let entry = Bytes(entry);
            let size = membership::encoded_entry_bytes(&entry);
            if encoded + size > membership::MAX_BODY { break; }
            entries.push(entry);
            encoded += size;
            hash = next_hash;
        }
        Ok(Page { after, head: self.sign(&log.reference, after + entries.len() as u64, hash), entries })
    }

    pub fn head(&self, log: &Log) -> Result<Head> {
        let (length, hash) = self.state(&self.db.lock().unwrap(), log)?;
        Ok(self.sign(&log.reference, length, hash))
    }

    pub fn length(&self, log: &Log) -> Result<u64> {
        Ok(tip(&self.db.lock().unwrap(), log)?.map_or(0, |(length, _, _)| length))
    }

    /// The heads of the logs whose length differs from the one given, and the references of those that expired.
    pub fn moved(&self, logs: &[(Log, u64)]) -> Result<(Vec<Head>, Vec<[u8; 32]>)> {
        let db = self.db.lock().unwrap();
        let (mut heads, mut expired) = (Vec::new(), Vec::new());
        for (log, length) in logs {
            match self.state(&db, log) {
                Ok((held, hash)) if held != *length => heads.push(self.sign(&log.reference, held, hash)),
                Ok(_) => {}
                Err(error) if error.is::<Expired>() => expired.push(log.reference),
                Err(error) => return Err(error),
            }
        }
        Ok((heads, expired))
    }

    /// The length and hash of a log, which a log never appended to has as none.
    fn state(&self, db: &Connection, log: &Log) -> Result<(u64, [u8; 32])> {
        Ok(tip(db, log)?.map_or((0, head::start(self.key.verifying_key().as_bytes(), &log.reference)), |(length, hash, _)| (length, hash)))
    }

    pub fn stats(&self) -> Result<Stats> {
        let db = self.db.lock().unwrap();
        let today = now() / DAY_MS;
        let start = today.saturating_sub(STATS_DAYS);
        let mut days: Vec<_> = (start..today).map(|day| DayTotals { day, entries: 0, bytes: 0 }).collect();
        let mut query = db.prepare_cached(TOTALS)?;
        let mut rows = query.query(params![start, today])?;
        while let Some(row) = rows.next()? {
            let total = DayTotals { day: row.get(0)?, entries: row.get(1)?, bytes: row.get(2)? };
            let index = (total.day - start) as usize;
            days[index] = total;
        }
        Ok(Stats { days })
    }

    /// One bounded pass of expiry, then a truncating checkpoint of the WAL. A group's log goes once its first entry's day
    /// is before `before_day`, a directory's once its last append's is; a log that goes keeps only its reference. Returns
    /// whether more is left for another pass.
    pub fn expire(&self, before_day: u64) -> Result<bool> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut logs: Vec<[u8; 32]> = tx.prepare_cached(GROUP_EXPIRY)?
            .query_map(params![before_day, MARK_LOGS as u64], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        let room = (MARK_LOGS - logs.len()) as u64;
        logs.extend(tx.prepare_cached(PUBLIC_EXPIRY)?.query_map(params![before_day, room], |r| r.get(0))?.collect::<rusqlite::Result<Vec<[u8; 32]>>>()?);
        for reference in &logs {
            let (public, bytes): (bool, u64) = tx.query_row("SELECT public,bytes FROM anchors WHERE reference=?", [reference], |r| Ok((r.get(0)?, r.get(1)?)))?;
            tx.execute("DELETE FROM anchors WHERE reference=?", [reference])?;
            tx.execute("INSERT INTO expired VALUES(?)", [reference])?;
            tx.execute("INSERT INTO doomed VALUES(?)", [reference])?;
            if public {
                tx.execute("UPDATE metadata SET public_bytes=public_bytes-?", [bytes])?;
            }
        }
        let more = reap(&tx)?;
        tx.execute("DELETE FROM totals WHERE day<?", [(now() / DAY_MS).saturating_sub(STATS_DAYS)])?;
        tx.commit()?;
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(more || logs.len() == MARK_LOGS)
    }
}

/// Deletes the entries of logs that expired, up to a pass's rows and bytes. Returns whether any are left.
fn reap(tx: &rusqlite::Transaction) -> Result<bool> {
    let (mut rows, mut bytes) = (0usize, 0u64);
    loop {
        if rows == EXPIRE_ROWS { return Ok(true); }
        let Some(reference) = tx.query_row(DOOMED, [], |r| r.get::<_, [u8; 32]>(0)).optional()? else { return Ok(false) };
        let batch: Vec<(u64, u64)> = tx.prepare_cached(DOOMED_RECORDS)?
            .query_map(params![reference, (EXPIRE_ROWS - rows) as u64], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
        if batch.is_empty() {
            tx.execute("DELETE FROM doomed WHERE reference=?", [reference])?;
            continue;
        }
        for (position, size) in batch {
            if bytes + size > EXPIRE_BYTES { return Ok(true); }
            tx.execute("DELETE FROM records WHERE reference=? AND position=?", params![reference, position])?;
            rows += 1;
            bytes += size;
        }
    }
}

#[cfg(test)]
#[path = "store_sql_tests.rs"]
mod sql_tests;

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static DAY: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    /// Sets this test thread's clock to the middle of `day`.
    fn on(day: u64) {
        DAY.set(day);
        lmk_proto::clock::set(|| DAY.get() * DAY_MS + DAY_MS / 2);
    }

    fn state() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        (dir, path)
    }

    /// Whether the store's files hold `needle`, which a checkpoint or a deletion may leave behind.
    fn leaked(path: &Path, needle: &[u8]) -> bool {
        ["membership.db", "membership.db-wal"].iter()
            .filter_map(|file| fs::read(path.join(file)).ok())
            .any(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
    }

    #[test]
    fn durable_restart_and_transaction_abort() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let d = store.log(&[7; 32]);
        {
            let db = store.db.lock().unwrap();
            assert_eq!(db.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0)).unwrap(), "wal");
            assert_eq!(db.query_row("PRAGMA synchronous", [], |r| r.get::<_, u32>(0)).unwrap(), 2);
            assert_eq!(db.query_row("PRAGMA fullfsync", [], |r| r.get::<_, u32>(0)).unwrap(), 1);
            assert_eq!(db.query_row("PRAGMA secure_delete", [], |r| r.get::<_, u32>(0)).unwrap(), 1);
            db.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY);
                CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
                CREATE TRIGGER abort_append AFTER INSERT ON records BEGIN INSERT INTO child VALUES(1); END;").unwrap();
        }
        assert!(store.append(&d, &[Bytes(b"uncommitted".to_vec())], false).is_err());
        assert_eq!(store.head(&d).unwrap().length, 0);
        assert!(store.read(&d, 0).unwrap().entries.is_empty());
        assert_eq!(store.db.lock().unwrap().query_row("SELECT count(*) FROM totals", [], |r| r.get::<_, u64>(0)).unwrap(), 0);
        store.db.lock().unwrap().execute_batch("DROP TRIGGER abort_append").unwrap();
        let (appended, _) = store.append(&d, &[Bytes(b"committed".to_vec())], false).unwrap();
        let s = store.key().verifying_key();
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.key().verifying_key(), s);
        assert_eq!(store.head(&d).unwrap().hash, appended.head.hash);
        assert_eq!(store.read(&d, 0).unwrap().entries, [Bytes(b"committed".to_vec())]);
        drop(store);
    }

    #[test]
    fn a_group_log_goes_by_its_first_entry_and_a_directory_by_its_last_append() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let (group, directory) = (store.log(&[1; 32]), store.log(&[2; 32]));
        on(100);
        store.append(&group, &[Bytes(vec![1])], false).unwrap();
        store.append(&directory, &[Bytes(vec![1])], true).unwrap();
        on(110);
        store.append(&group, &[Bytes(vec![2])], false).unwrap();
        store.touch(&directory, &[1]).unwrap().unwrap();
        assert!(!store.expire(101).unwrap());
        assert_eq!(store.read(&group, 0).unwrap_err().downcast_ref::<Expired>().unwrap().0, group.reference);
        assert_eq!(store.read(&directory, 0).unwrap().entries, [Bytes(vec![1])]);
        store.expire(111).unwrap();
        assert_eq!(store.read(&directory, 0).unwrap_err().downcast_ref::<Expired>().unwrap().0, directory.reference);
    }

    #[test]
    fn an_expired_log_answers_expired_and_never_starts_again() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let log = store.log(&[7; 32]);
        on(10);
        store.append(&log, &[Bytes(vec![1])], false).unwrap();
        on(11);
        store.expire(11).unwrap();
        let db = store.db.lock().unwrap();
        assert_eq!(db.query_row("SELECT count(*) FROM anchors", [], |r| r.get::<_, u64>(0)).unwrap(), 0);
        assert_eq!(db.query_row("SELECT reference FROM expired", [], |r| r.get::<_, [u8; 32]>(0)).unwrap(), log.reference);
        drop(db);
        assert_eq!(store.read(&log, 0).unwrap_err().downcast_ref::<Expired>().unwrap().0, log.reference);
        assert_eq!(store.append(&log, &[Bytes(vec![2])], false).unwrap_err().downcast_ref::<Expired>().unwrap().0, log.reference);
        assert_eq!(store.head(&log).unwrap_err().downcast_ref::<Expired>().unwrap().0, log.reference);
        assert_eq!(store.length(&log).unwrap_err().downcast_ref::<Expired>().unwrap().0, log.reference);
        assert_eq!(store.moved(&[(log.clone(), 0), (store.log(&[8; 32]), 0)]).unwrap(), (vec![], vec![log.reference]));
        assert_eq!(store.moved(&[(store.log(&[8; 32]), 0)]).unwrap(), (vec![], vec![]));
        assert_eq!(store.moved(&[(store.log(&[8; 32]), 1)]).unwrap().0.len(), 1);
    }

    #[test]
    fn a_directory_touch_moves_its_day_and_stores_nothing() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let (directory, group) = (store.log(&[3; 32]), store.log(&[4; 32]));
        on(10);
        let (first, stored) = store.append(&directory, &[Bytes(b"entry".to_vec())], true).unwrap();
        assert_eq!((first.position, stored), (1, 1));
        on(12);
        let touch = store.touch(&directory, b"entry").unwrap().unwrap();
        assert_eq!((touch.position, touch.head.length, touch.head.hash), (1, 1, first.head.hash));
        assert!(store.touch(&directory, b"other").unwrap().is_none());
        assert_eq!(store.db.lock().unwrap().query_row("SELECT count(*) FROM records", [], |r| r.get::<_, u64>(0)).unwrap(), 1);
        store.expire(11).unwrap();
        assert_eq!(store.read(&directory, 0).unwrap().entries, [Bytes(b"entry".to_vec())]);
        let (next, stored) = store.append(&directory, &[Bytes(b"next".to_vec())], true).unwrap();
        assert_eq!((next.position, stored), (2, 1));
        assert!(store.touch(&directory, b"entry").unwrap().is_none(), "a touch is of the last entry");
        store.append(&group, &[Bytes(b"same".to_vec())], false).unwrap();
        assert!(store.touch(&group, b"same").unwrap().is_none(), "only a public log is touched");
        store.expire(13).unwrap();
        assert!(store.read(&directory, 0).unwrap_err().is::<Expired>());
    }

    #[test]
    fn a_leaked_store_holds_no_expired_bytes() {
        const LOGS: usize = 3_000;
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let capabilities: Vec<[u8; 32]> = (0..LOGS).map(|_| lmk_proto::random::random()).collect();
        // Appends in scrambled order, so pages split, merge and defragment, leaving stale copies of rows in them.
        let mut order: Vec<usize> = (0..3 * LOGS).collect();
        order.sort_by_key(|&x| (x as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut markers = vec![Vec::new(); LOGS];
        let mut head_hash = None;
        for x in order {
            let i = x / 3;
            let mut entry = lmk_proto::random::random::<16>().to_vec();
            entry.extend(vec![0x5a; 100 + (x * 37) % 900]);
            markers[i].push(entry[..16].to_vec());
            on(if i < LOGS / 2 { 10 } else { 11 });
            let log = store.log(&capabilities[i]);
            store.append(&log, &[Bytes(entry)], false).unwrap();
            if i == 0 { head_hash = Some(store.head(&log).unwrap().hash); }
        }
        let gone: std::collections::HashSet<&[u8]> = markers[..LOGS / 2].iter().flatten().map(Vec::as_slice).collect();
        let kept = store.log(&capabilities[LOGS - 1]).reference;
        assert!(leaked(&path, &kept), "the control: a kept log's reference is in the file");
        on(11);
        while store.expire(11).unwrap() {}
        let files: Vec<Vec<u8>> = ["membership.db", "membership.db-wal"].iter().map(|f| fs::read(path.join(f)).unwrap()).collect();
        assert!(files.iter().all(|bytes| !bytes.windows(16).any(|window| gone.contains(window))), "an expired entry is in the file");
        assert!(!leaked(&path, &head_hash.unwrap()), "an expired log's head hash is in the file");
        assert!(leaked(&path, &kept));
        assert_eq!(fs::metadata(path.join("membership.db-wal")).unwrap().len(), 0);
        drop(store);
    }

    #[test]
    fn expiry_passes_are_bounded_and_finish() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        on(10);
        for log in 0..3u8 {
            for _ in 0..16 {
                store.append(&store.log(&[log; 32]), &vec![Bytes(vec![log; 100]); membership::APPEND_ROWS], false).unwrap();
            }
        }
        for log in 3..5u8 {
            for _ in 0..6 {
                store.append(&store.log(&[log; 32]), &[Bytes(vec![log; membership::MAX_ENTRY]), Bytes(vec![log; membership::MAX_ENTRY])], false).unwrap();
            }
        }
        let count = |sql: &str| store.db.lock().unwrap().query_row(sql, [], |r| r.get::<_, u64>(0)).unwrap();
        on(11);
        let mut passes = 0;
        loop {
            let (rows, bytes) = (count("SELECT count(*) FROM records"), count("SELECT coalesce(sum(length(sealed)),0) FROM records"));
            let more = store.expire(11).unwrap();
            assert!(rows - count("SELECT count(*) FROM records") <= EXPIRE_ROWS as u64);
            assert!(bytes - count("SELECT coalesce(sum(length(sealed)),0) FROM records") <= EXPIRE_BYTES);
            passes += 1;
            if !more { break; }
        }
        assert!(passes >= 5, "{passes}");
        assert_eq!(count("SELECT count(*) FROM records"), 0);
        assert_eq!(count("SELECT count(*) FROM doomed"), 0);
        assert_eq!(count("SELECT count(*) FROM expired"), 5);
    }

    #[test]
    fn daily_totals_go_after_seven_days() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let totals = || store.db.lock().unwrap().query_row("SELECT count(*) FROM totals", [], |r| r.get::<_, u64>(0)).unwrap();
        on(10);
        store.append(&store.log(&[1; 32]), &[Bytes(vec![1])], false).unwrap();
        on(16);
        store.expire(0).unwrap();
        assert_eq!(totals(), 1);
        on(17);
        store.expire(0).unwrap();
        assert_eq!(totals(), 1);
        on(18);
        store.expire(0).unwrap();
        assert_eq!(totals(), 0);
    }

    #[test]
    fn lost_or_mismatched_state_never_initializes() {
        let (_dir, missing) = state();
        assert!(Store::open(&missing).is_err());
        assert!(!missing.exists());
        for lost in ["membership.key", "membership.db", "membership.ready"] {
            let (_dir, path) = state();
            let store = Store::initialize(&path).unwrap();
            store.append(&store.log(&[7; 32]), &[Bytes(vec![1])], false).unwrap();
            drop(store);
            fs::remove_file(path.join(lost)).unwrap();
            assert!(Store::open(&path).is_err());
            assert!(Store::initialize(&path).is_err());
            assert!(!path.join(lost).exists());
        }
        for fault in ["empty", "authority", "format"] {
            let (_dir, path) = state();
            let store = Store::initialize(&path).unwrap();
            store.append(&store.log(&[7; 32]), &[Bytes(vec![1])], false).unwrap();
            drop(store);
            let db_path = path.join("membership.db");
            if fault == "empty" { fs::write(&db_path, []).unwrap(); }
            else {
                let db = Connection::open(&db_path).unwrap();
                db.execute_batch(if fault == "format" { "UPDATE metadata SET format=999" } else { "UPDATE metadata SET authority=zeroblob(32)" }).unwrap();
            }
            let before = fs::read(&db_path).unwrap();
            assert!(Store::open(&path).is_err());
            assert_eq!(fs::read(&db_path).unwrap(), before);
        }
    }

    #[test]
    fn append_size_limits_are_transactional() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let d = store.log(&[7; 32]);
        assert!(store.append(&d, &vec![Bytes(vec![1]); membership::APPEND_ROWS+1], false).is_err());
        assert!(store.append(&d, &[Bytes(vec![1; membership::MAX_ENTRY+1])], false).is_err());
        assert!(store.append(&d, &vec![Bytes(vec![1; membership::MAX_ENTRY]); 3], false).is_err());
        store.append(&d, &[Bytes(vec![1])], false).unwrap();
        assert_eq!(store.head(&d).unwrap().length, 1);
        drop(store);
    }

    #[test]
    fn disk_budget_counts_pages_in_use_and_wal_before_insert() {
        let (_dir, path) = state();
        let mut store = Store::initialize(&path).unwrap();
        let d = store.log(&[7; 32]);
        store.append(&d, &[Bytes(vec![1])], false).unwrap();
        let before = used(&store.db.lock().unwrap(), &store.wal).unwrap();
        store.disk = before + 99;
        assert_eq!(store.append(&d, &[Bytes(vec![2; 100])], false).unwrap_err().downcast::<Refused>().unwrap().0, "quota");
        assert_eq!(store.head(&d).unwrap().length, 1);
        store.disk = before + 100;
        store.append(&d, &[Bytes(vec![2; 100])], false).unwrap();
        assert_eq!(store.head(&d).unwrap().length, 2);
        drop(store);
    }

    #[test]
    fn public_logs_share_a_tenth_of_the_disk_until_they_expire() {
        let (_dir, path) = state();
        let mut store = Store::initialize(&path).unwrap();
        store.disk = 10 << 20;
        store.append(&store.log(&[7; 32]), &[Bytes(vec![1; membership::MAX_ENTRY])], true).unwrap();
        assert_eq!(store.append(&store.log(&[8; 32]), &[Bytes(vec![2])], true).unwrap_err().downcast::<Refused>().unwrap().0, "quota");
        store.append(&store.log(&[8; 32]), &[Bytes(vec![2])], false).unwrap();
        store.expire(now() / DAY_MS + 1).unwrap();
        store.append(&store.log(&[9; 32]), &[Bytes(vec![2])], true).unwrap();
        drop(store);
    }

    #[test]
    fn heads_name_only_the_logs_whose_length_differs() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let (a, b) = (store.log(&[1; 32]), store.log(&[2; 32]));
        store.append(&a, &[Bytes(vec![1])], false).unwrap();
        assert_eq!((store.length(&a).unwrap(), store.length(&b).unwrap()), (1, 0));
        let (moved, expired) = store.moved(&[(a.clone(), 0), (a.clone(), 1), (b, 0)]).unwrap();
        assert!(expired.is_empty());
        assert_eq!(moved.len(), 1);
        assert_eq!((moved[0].log_ref, moved[0].length), (a.reference, 1));
        drop(store);
    }

    #[test]
    fn completed_site_totals_survive_failures_restart_and_expiry() {
        lmk_proto::clock::set(|| 10 * DAY_MS);
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        store.append(&store.log(&[1; 32]), &[Bytes(vec![1; 3]), Bytes(vec![2; 5])], false).unwrap();
        store.append(&store.log(&[2; 32]), &[Bytes(vec![3; 7])], true).unwrap();
        assert!(store.stats().unwrap().days.iter().all(|d| d.entries == 0 && d.bytes == 0));
        lmk_proto::clock::set(|| 11 * DAY_MS);
        let expected = store.stats().unwrap();
        assert_eq!(expected.days.len(), 7);
        assert_eq!(expected.days[6], DayTotals { day: 10, entries: 3, bytes: 15 });
        store.append(&store.log(&[1; 32]), &[Bytes(vec![1; 9])], false).unwrap();
        store.db.lock().unwrap().execute_batch("CREATE TRIGGER fail_totals BEFORE UPDATE ON totals BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
        assert!(store.append(&store.log(&[3; 32]), &[Bytes(vec![1; 10])], false).is_err());
        assert_eq!(store.head(&store.log(&[3; 32])).unwrap().length, 0);
        assert_eq!(store.stats().unwrap(), expected);
        store.expire(12).unwrap();
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.stats().unwrap(), expected);
        lmk_proto::clock::set(|| 12 * DAY_MS);
        let stats = store.stats().unwrap();
        assert_eq!(stats.days[5], DayTotals { day: 10, entries: 3, bytes: 15 });
        assert_eq!(stats.days[6], DayTotals { day: 11, entries: 1, bytes: 9 });
        assert!(stats.days[..5].iter().all(|d| d.entries == 0 && d.bytes == 0));
        lmk_proto::clock::set(|| 18 * DAY_MS);
        assert_eq!(store.stats().unwrap().days[0], DayTotals { day: 11, entries: 1, bytes: 9 });
        lmk_proto::clock::set(|| 19 * DAY_MS);
        assert!(store.stats().unwrap().days.iter().all(|d| d.entries == 0 && d.bytes == 0));
        drop(store);
    }

    #[test]
    fn pages_are_bounded() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let d = store.log(&[7; 32]);
        for _ in 0..17 { store.append(&d, &vec![Bytes(vec![1]); membership::APPEND_ROWS], false).unwrap(); }
        assert_eq!(store.read(&d, 0).unwrap().entries.len(), membership::PAGE_ROWS);
        let d = store.log(&[8; 32]);
        for _ in 0..3 { store.append(&d, &[Bytes(vec![3; membership::MAX_ENTRY])], false).unwrap(); }
        let page = store.read(&d, 0).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert!(serde_json::to_vec(&membership::Answer::Ok(&page)).unwrap().len() < membership::MAX_BODY);
        assert_eq!(store.read(&d, 2).unwrap().entries.len(), 1);
        drop(store);
    }

    /// The target's store, built and read from a cold cache: 3.6M live logs and 44M expired references, which a year of
    /// commits makes. Each of 100,000 memberships asks every two minutes for its group's log and for four directories
    /// it follows (an assumed average), so the bar is 100,000 times five over 120 seconds. Run with
    /// `cargo test --release -- --ignored heads_keep`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "builds the target's store: about 30 minutes in release"]
    fn heads_keep_the_target_rate_from_a_cold_cache() {
        const LIVE: u64 = 3_600_000;
        const EXPIRED: u64 = 44_000_000;
        const BAR: f64 = 100_000.0 * 5.0 / 120.0;
        // On disk: a temporary directory in /tmp may be a RAM disk too small for the store.
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let path = dir.path().join("state");
        let store = Store::initialize(&path).unwrap();
        let capability = |i: u64| -> [u8; 32] { let mut c = [0; 32]; c[24..].copy_from_slice(&i.to_be_bytes()); c };
        let started = std::time::Instant::now();
        {
            let mut db = store.db.lock().unwrap();
            for batch in (1..=LIVE + EXPIRED).collect::<Vec<_>>().chunks(100_000) {
                let tx = db.transaction().unwrap();
                {
                    let mut live = tx.prepare_cached("INSERT INTO anchors VALUES(?1,0,0,0,1,?2)").unwrap();
                    let mut expired = tx.prepare_cached("INSERT INTO expired VALUES(?)").unwrap();
                    for &i in batch {
                        let log = store.log(&capability(i));
                        if i <= LIVE {
                            let state = seal(&log.key, &[&1u64.to_be_bytes()[..], &[0; 32]].concat());
                            live.execute(params![log.reference, state]).unwrap();
                        } else {
                            expired.execute([log.reference]).unwrap();
                        }
                    }
                }
                tx.commit().unwrap();
            }
            db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        }
        println!("built in {:?}", started.elapsed());
        drop(store);
        // A new connection has no pages cached, and the file's pages are dropped from the operating system's cache.
        drop_cache(&path.join("membership.db"));
        let store = Store::open(&path).unwrap();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut draw = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            1 + seed % (LIVE + EXPIRED)
        };
        let requests = 200;
        let started = std::time::Instant::now();
        let mut answered = 0;
        for _ in 0..requests {
            let logs: Vec<(Log, u64)> = (0..membership::HEAD_LOGS).map(|_| (store.log(&capability(draw())), 0)).collect();
            let (heads, expired) = store.moved(&logs).unwrap();
            answered += heads.len() + expired.len();
        }
        let rate = (requests * membership::HEAD_LOGS) as f64 / started.elapsed().as_secs_f64();
        assert_eq!(answered, requests * membership::HEAD_LOGS);
        println!("heads: {rate:.0} log lookups a second, cold; the bar is {BAR:.0}");
        assert!(rate >= BAR, "{rate:.0} log lookups a second");
    }

    #[cfg(target_os = "linux")]
    fn drop_cache(path: &Path) {
        use std::os::unix::io::AsRawFd;
        let file = fs::File::open(path).unwrap();
        // SAFETY: the descriptor is open for the call, and the advice only lets the kernel drop clean pages.
        assert_eq!(unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) }, 0);
    }

    #[test]
    fn opaque_schema_and_structural_legacy_refusal() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let capability = lmk_proto::random::random::<32>();
        let d = store.log(&capability);
        store.append(&d, &[Bytes(vec![42])], false).unwrap();
        let db = store.db.lock().unwrap();
        assert!(db.execute_batch("CREATE TABLE IF NOT EXISTS logs(id BLOB PRIMARY KEY, length INTEGER NOT NULL, hash BLOB NOT NULL, public INTEGER NOT NULL DEFAULT 0, appended INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS entries(log BLOB NOT NULL, position INTEGER NOT NULL, entry BLOB NOT NULL, hash BLOB NOT NULL,time INTEGER NOT NULL, PRIMARY KEY(log,position)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS entries_time ON entries(time);").is_err());
        assert_eq!(db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table'", [], |r| r.get::<_, u64>(0)).unwrap(), 6);
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        assert!(!fs::read(path.join("membership.db")).unwrap().windows(32).any(|w| w == capability));
        drop(db);
        assert_eq!(store.read(&d, 0).unwrap().entries, [Bytes(vec![42])]);
        drop(store);
    }
}
