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
const FORMAT: u32 = 7;
pub const DISK_BYTES: u64 = 4 << 30;
const EXPIRY: &str = "SELECT reference FROM anchors WHERE opened<? LIMIT ?";
const DOOMED: &str = "SELECT reference FROM doomed LIMIT 1";
const DOOMED_RECORDS: &str = "SELECT position,length(sealed) FROM records WHERE reference=? ORDER BY position LIMIT ?";
const READ_RECORDS: &str = "SELECT sealed FROM records WHERE reference=? AND position>? ORDER BY position LIMIT ?";
const FORGOTTEN: &str = "SELECT reference FROM expired WHERE day<? AND NOT EXISTS(SELECT 1 FROM doomed WHERE doomed.reference=expired.reference) LIMIT ?";

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

/// A live log's length and hash, or none if no entry was ever appended to it. An expired log is an error.
fn tip(db: &Connection, log: &Log) -> Result<Option<(u64, [u8; 32])>> {
    let live: Option<Vec<u8>> = db.query_row("SELECT sealed FROM anchors WHERE reference=?", [log.reference], |r| r.get(0)).optional()?;
    let Some(sealed) = live else {
        if db.query_row("SELECT EXISTS(SELECT 1 FROM expired WHERE reference=?)", [log.reference], |r| r.get(0))? {
            return Err(Expired(log.reference).into());
        }
        return Ok(None);
    };
    let state = open(&log.key, &sealed)?;
    Ok(Some((u64::from_be_bytes(state[..8].try_into()?), state[8..].try_into()?)))
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
                 authority BLOB NOT NULL CHECK(length(authority)=32), passed INTEGER NOT NULL);
             CREATE TABLE anchors (reference BLOB PRIMARY KEY CHECK(length(reference)=32), opened INTEGER NOT NULL,
                 sealed BLOB NOT NULL) WITHOUT ROWID;
             CREATE INDEX expiry ON anchors(opened);
             CREATE TABLE expired (reference BLOB PRIMARY KEY CHECK(length(reference)=32), day INTEGER NOT NULL) WITHOUT ROWID;
             CREATE INDEX forgetting ON expired(day);
             CREATE TABLE doomed (reference BLOB PRIMARY KEY CHECK(length(reference)=32)) WITHOUT ROWID;
             CREATE TABLE records (reference BLOB NOT NULL, position INTEGER NOT NULL, sealed BLOB NOT NULL,
                 PRIMARY KEY(reference,position)) WITHOUT ROWID;
             CREATE VIEW logs AS SELECT reference,opened FROM anchors;
             CREATE VIEW entries AS SELECT reference,position FROM records;",
        )?;
        db.execute("INSERT INTO metadata VALUES(1,?,?,?)", params![FORMAT, key.verifying_key().as_bytes(), now() / DAY_MS])?;
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
        let mut db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        db.busy_timeout(std::time::Duration::from_millis(250))?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.pragma_update(None, "fullfsync", true)?;
        db.pragma_update(None, "secure_delete", true)?;
        // The retention counts only days the service runs: live logs' days move on by those since the last expiry pass.
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (passed, today): (u64, u64) = (tx.query_row("SELECT passed FROM metadata", [], |r| r.get(0))?, now() / DAY_MS);
        if today > passed {
            tx.execute("UPDATE anchors SET opened=opened+?", [today - passed])?;
            tx.execute("UPDATE metadata SET passed=?", [today])?;
        }
        tx.commit()?;
        Ok(Self { db: Mutex::new(db), key, wal: state.join("membership.db-wal"), disk: DISK_BYTES })
    }

    pub fn key(&self) -> &SigningKey { &self.key }

    pub fn log(&self, capability: &[u8; 32]) -> Log {
        Log { reference: head::reference(self.key.verifying_key().as_bytes(), capability), key: head::sealing(capability) }
    }

    fn sign(&self, log_ref: &[u8; 32], length: u64, hash: [u8; 32]) -> Head {
        Head::sign(&self.key, log_ref, length, hash, now())
    }

    /// Appends entries to a log. None opens a group log: it records an empty log, or moves an empty log's `opened` day
    /// to today, and changes nothing once the log has an entry. A log's first entry sets `opened` to its day.
    pub fn append(&self, log: &Log, entries: &[Bytes]) -> Result<Appended> {
        ensure!(membership::valid_append(entries), Refused("size".into()));
        let bytes = entries.iter().map(|e| e.0.len() as u64).sum::<u64>();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (length, mut hash) = self.state(&tx, log)?;
        if entries.is_empty() && length > 0 {
            return Ok(Appended { head: self.sign(&log.reference, length, hash) });
        }
        ensure!(used(&tx, &self.wal)? + bytes <= self.disk, Refused("quota".into()));
        let end = length + entries.len() as u64;
        let day = now() / DAY_MS;
        for (index, entry) in entries.iter().enumerate() {
            hash = head::next(&hash, &entry.0);
            let sealed = seal(&log.key, &[entry.0.as_slice(), &hash].concat());
            tx.execute("INSERT INTO records VALUES(?,?,?)", params![log.reference, length + index as u64 + 1, sealed])?;
        }
        let state = seal(&log.key, &[&end.to_be_bytes()[..], &hash].concat());
        tx.execute(
            "INSERT INTO anchors VALUES(?1,?2,?3) ON CONFLICT(reference) DO UPDATE SET sealed=?3, opened=CASE WHEN ?4 THEN ?2 ELSE opened END",
            params![log.reference, day, state, length == 0],
        )?;
        tx.commit()?;
        Ok(Appended { head: self.sign(&log.reference, end, hash) })
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

    /// Whether the store records a log, empty or not; an error if it let it go.
    pub fn records(&self, log: &Log) -> Result<bool> {
        Ok(tip(&self.db.lock().unwrap(), log)?.is_some())
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
        Ok(tip(db, log)?.unwrap_or((0, head::start(self.key.verifying_key().as_bytes(), &log.reference))))
    }

    /// One bounded pass of expiry, then a truncating checkpoint of the WAL, recording its day. A log goes once its `opened`
    /// day is before `before_day`, and keeps only its reference and the day it went; `EXPIRED_DAYS` after, once its
    /// entries are deleted, the reference goes too. Returns whether more is left for another pass.
    pub fn expire(&self, before_day: u64) -> Result<bool> {
        let today = now() / DAY_MS;
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let forgotten = tx.execute(
            &format!("DELETE FROM expired WHERE reference IN ({FORGOTTEN})"),
            params![today.saturating_sub(membership::EXPIRED_DAYS), MARK_LOGS as u64],
        )?;
        let logs: Vec<[u8; 32]> = tx.prepare_cached(EXPIRY)?
            .query_map(params![before_day, MARK_LOGS as u64], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        for reference in &logs {
            tx.execute("DELETE FROM anchors WHERE reference=?", [reference])?;
            tx.execute("INSERT INTO expired VALUES(?,?)", params![reference, today])?;
            tx.execute("INSERT INTO doomed VALUES(?)", [reference])?;
        }
        let more = reap(&tx)?;
        tx.execute("UPDATE metadata SET passed=?", [today])?;
        tx.commit()?;
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(more || logs.len() == MARK_LOGS || forgotten == MARK_LOGS)
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
        assert!(store.append(&d, &[Bytes(b"uncommitted".to_vec())]).is_err());
        assert_eq!(store.read(&d, 0).unwrap().head.length, 0);
        assert!(store.read(&d, 0).unwrap().entries.is_empty());
        store.db.lock().unwrap().execute_batch("DROP TRIGGER abort_append").unwrap();
        let appended = store.append(&d, &[Bytes(b"committed".to_vec())]).unwrap();
        let s = store.key().verifying_key();
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.key().verifying_key(), s);
        assert_eq!(store.read(&d, 0).unwrap().head.hash, appended.head.hash);
        assert_eq!(store.read(&d, 0).unwrap().entries, [Bytes(b"committed".to_vec())]);
        drop(store);
    }

    #[test]
    fn a_group_log_goes_by_its_first_entry() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let group = store.log(&[1; 32]);
        on(100);
        store.append(&group, &[Bytes(vec![1])]).unwrap();
        on(110);
        store.append(&group, &[Bytes(vec![2])]).unwrap();
        assert!(!store.expire(101).unwrap());
        assert_eq!(store.read(&group, 0).unwrap_err().downcast_ref::<Expired>().unwrap().0, group.reference);
    }

    #[test]
    fn an_expired_log_answers_expired() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let log = store.log(&[7; 32]);
        on(10);
        store.append(&log, &[Bytes(vec![1])]).unwrap();
        on(11);
        store.expire(11).unwrap();
        let db = store.db.lock().unwrap();
        assert_eq!(db.query_row("SELECT count(*) FROM anchors", [], |r| r.get::<_, u64>(0)).unwrap(), 0);
        assert_eq!(db.query_row("SELECT reference FROM expired", [], |r| r.get::<_, [u8; 32]>(0)).unwrap(), log.reference);
        drop(db);
        assert_eq!(store.read(&log, 0).unwrap_err().downcast_ref::<Expired>().unwrap().0, log.reference);
        assert_eq!(store.append(&log, &[Bytes(vec![2])]).unwrap_err().downcast_ref::<Expired>().unwrap().0, log.reference);
        assert_eq!(store.moved(&[(log.clone(), 0), (store.log(&[8; 32]), 0)]).unwrap(), (vec![], vec![log.reference]));
        assert_eq!(store.moved(&[(store.log(&[8; 32]), 0)]).unwrap(), (vec![], vec![]));
        assert_eq!(store.moved(&[(store.log(&[8; 32]), 1)]).unwrap().0.len(), 1);
    }

    /// A log that went answers so for `EXPIRED_DAYS`, and is forgotten after, once its entries are deleted.
    #[test]
    fn an_expired_log_is_forgotten_after_expired_days() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let log = store.log(&[7; 32]);
        on(10);
        store.append(&log, &[Bytes(vec![1])]).unwrap();
        on(11);
        store.expire(11).unwrap();
        on(11 + membership::EXPIRED_DAYS);
        store.expire(0).unwrap();
        assert!(store.read(&log, 0).unwrap_err().is::<Expired>(), "through its last day");
        on(12 + membership::EXPIRED_DAYS);
        store.db.lock().unwrap().execute("INSERT INTO doomed VALUES(?)", [log.reference]).unwrap();
        store.expire(0).unwrap();
        assert!(store.read(&log, 0).unwrap_err().is::<Expired>(), "while its entries are deleted");
        store.expire(0).unwrap();
        assert_eq!(store.read(&log, 0).unwrap().head.length, 0, "forgotten");
    }

    fn opened(store: &Store, log: &Log) -> u64 {
        store.db.lock().unwrap().query_row("SELECT opened FROM anchors WHERE reference=?", [log.reference], |r| r.get(0)).unwrap()
    }

    #[test]
    fn an_open_records_or_moves_only_an_empty_group_log() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let (group, gone) = (store.log(&[1; 32]), store.log(&[3; 32]));
        on(10);
        let open = store.append(&group, &[]).unwrap();
        assert_eq!((open.head.length, opened(&store, &group)), (0, 10), "an open records an empty log");
        store.append(&gone, &[]).unwrap();
        on(12);
        store.append(&group, &[]).unwrap();
        assert_eq!(opened(&store, &group), 12, "and moves an empty log's day");
        on(13);
        store.append(&group, &[Bytes(b"commit".to_vec())]).unwrap();
        assert_eq!(opened(&store, &group), 13, "a first entry sets the day");
        on(15);
        let open = store.append(&group, &[]).unwrap();
        assert_eq!((open.head.length, opened(&store, &group)), (1, 13), "an open changes nothing past it");

        store.expire(11).unwrap();
        assert!(store.append(&gone, &[]).unwrap_err().is::<Expired>(), "a log that went is not opened again");
        assert!(store.records(&group).unwrap());
    }

    #[test]
    fn a_service_stopped_past_the_retention_lets_no_live_log_go_at_its_start() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let group = store.log(&[1; 32]);
        on(10);
        store.append(&group, &[]).unwrap();
        store.expire(3).unwrap();
        drop(store);
        on(30);
        let store = Store::open(&path).unwrap();
        store.expire(30 - 7).unwrap();
        assert!(store.records(&group).unwrap(), "the retention counts the days it ran");
        drop(store);
        let store = Store::open(&path).unwrap();
        store.expire(32).unwrap();
        assert!(store.records(&group).is_err(), "a start on the day of the last pass moves nothing");
    }

    #[test]
    fn a_start_on_the_day_after_the_last_pass_moves_days_by_one() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let group = store.log(&[1; 32]);
        on(10);
        store.append(&group, &[]).unwrap();
        store.expire(3).unwrap();
        drop(store);
        on(11);
        let store = Store::open(&path).unwrap();
        store.expire(11).unwrap();
        assert!(store.records(&group).unwrap(), "their day 10 moved to 11");
        store.expire(12).unwrap();
        assert!(store.records(&group).is_err(), "and no further");
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
            store.append(&log, &[Bytes(entry)]).unwrap();
            if i == 0 { head_hash = Some(store.read(&log, 0).unwrap().head.hash); }
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
                store.append(&store.log(&[log; 32]), &vec![Bytes(vec![log; 100]); membership::APPEND_ROWS]).unwrap();
            }
        }
        for log in 3..5u8 {
            for _ in 0..6 {
                store.append(&store.log(&[log; 32]), &[Bytes(vec![log; membership::MAX_ENTRY]), Bytes(vec![log; membership::MAX_ENTRY])]).unwrap();
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
    fn lost_or_mismatched_state_never_initializes() {
        let (_dir, missing) = state();
        assert!(Store::open(&missing).is_err());
        assert!(!missing.exists());
        for lost in ["membership.key", "membership.db", "membership.ready"] {
            let (_dir, path) = state();
            let store = Store::initialize(&path).unwrap();
            store.append(&store.log(&[7; 32]), &[Bytes(vec![1])]).unwrap();
            drop(store);
            fs::remove_file(path.join(lost)).unwrap();
            assert!(Store::open(&path).is_err());
            assert!(Store::initialize(&path).is_err());
            assert!(!path.join(lost).exists());
        }
        for fault in ["empty", "authority", "format"] {
            let (_dir, path) = state();
            let store = Store::initialize(&path).unwrap();
            store.append(&store.log(&[7; 32]), &[Bytes(vec![1])]).unwrap();
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
        assert!(store.append(&d, &vec![Bytes(vec![1]); membership::APPEND_ROWS+1]).is_err());
        assert!(store.append(&d, &[Bytes(vec![1; membership::MAX_ENTRY+1])]).is_err());
        assert!(store.append(&d, &vec![Bytes(vec![1; membership::MAX_ENTRY]); 3]).is_err());
        store.append(&d, &[Bytes(vec![1])]).unwrap();
        assert_eq!(store.read(&d, 0).unwrap().head.length, 1);
        drop(store);
    }

    #[test]
    fn disk_budget_counts_pages_in_use_and_wal_before_insert() {
        let (_dir, path) = state();
        let mut store = Store::initialize(&path).unwrap();
        let d = store.log(&[7; 32]);
        store.append(&d, &[Bytes(vec![1])]).unwrap();
        let before = used(&store.db.lock().unwrap(), &store.wal).unwrap();
        store.disk = before + 99;
        assert_eq!(store.append(&d, &[Bytes(vec![2; 100])]).unwrap_err().downcast::<Refused>().unwrap().0, "quota");
        assert_eq!(store.read(&d, 0).unwrap().head.length, 1);
        store.disk = before + 100;
        store.append(&d, &[Bytes(vec![2; 100])]).unwrap();
        assert_eq!(store.read(&d, 0).unwrap().head.length, 2);
        drop(store);
    }

    #[test]
    fn heads_name_only_the_logs_whose_length_differs() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let (a, b) = (store.log(&[1; 32]), store.log(&[2; 32]));
        store.append(&a, &[Bytes(vec![1])]).unwrap();
        assert_eq!((store.read(&a, 0).unwrap().head.length, store.read(&b, 0).unwrap().head.length), (1, 0));
        let (moved, expired) = store.moved(&[(a.clone(), 0), (a.clone(), 1), (b, 0)]).unwrap();
        assert!(expired.is_empty());
        assert_eq!(moved.len(), 1);
        assert_eq!((moved[0].log_ref, moved[0].length), (a.reference, 1));
        drop(store);
    }

    #[test]
    fn pages_are_bounded() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let d = store.log(&[7; 32]);
        for _ in 0..17 { store.append(&d, &vec![Bytes(vec![1]); membership::APPEND_ROWS]).unwrap(); }
        assert_eq!(store.read(&d, 0).unwrap().entries.len(), membership::PAGE_ROWS);
        let d = store.log(&[8; 32]);
        for _ in 0..3 { store.append(&d, &[Bytes(vec![3; membership::MAX_ENTRY])]).unwrap(); }
        let page = store.read(&d, 0).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert!(serde_json::to_vec(&membership::Answer::Ok(&page)).unwrap().len() < membership::MAX_BODY);
        assert_eq!(store.read(&d, 2).unwrap().entries.len(), 1);
        drop(store);
    }

    #[test]
    fn opaque_schema_and_structural_legacy_refusal() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let capability = lmk_proto::random::random::<32>();
        let d = store.log(&capability);
        store.append(&d, &[Bytes(vec![42])]).unwrap();
        let db = store.db.lock().unwrap();
        assert!(db.execute_batch("CREATE TABLE IF NOT EXISTS logs(id BLOB PRIMARY KEY, length INTEGER NOT NULL, hash BLOB NOT NULL, public INTEGER NOT NULL DEFAULT 0, appended INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS entries(log BLOB NOT NULL, position INTEGER NOT NULL, entry BLOB NOT NULL, hash BLOB NOT NULL,time INTEGER NOT NULL, PRIMARY KEY(log,position)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS entries_time ON entries(time);").is_err());
        assert_eq!(db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table'", [], |r| r.get::<_, u64>(0)).unwrap(), 5);
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        assert!(!fs::read(path.join("membership.db")).unwrap().windows(32).any(|w| w == capability));
        drop(db);
        assert_eq!(store.read(&d, 0).unwrap().entries, [Bytes(vec![42])]);
        drop(store);
    }
}
