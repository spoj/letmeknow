//! Disposable authority and its durable, reference-only SQLite store.

use std::{fs::{self, OpenOptions}, io::Write, path::{Path, PathBuf}, sync::Mutex};

use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;
use lmk_proto::{Bytes, clock::now, head::{self, Head}, membership::{self, Appended, Page}};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::Refused;
const EXPIRE_ROWS: usize = 1024;
const EXPIRE_BYTES: u64 = 4 << 20;
pub const DAY_MS: u64 = 86_400_000;
const STATS_DAYS: u64 = 7;
const FORMAT: u32 = 3;
pub const DISK_BYTES: u64 = 4 << 30;
const PRIVATE_EXPIRY: &str = "SELECT reference,position,length(entry) FROM records WHERE expiry_day<? ORDER BY expiry_day LIMIT ?";
const PUBLIC_EXPIRY: &str = "SELECT reference FROM anchors WHERE public=1 AND rows>0 AND day<? ORDER BY day LIMIT 1";
const PUBLIC_RECORDS: &str = "SELECT reference,position,length(entry) FROM records WHERE reference=? ORDER BY position LIMIT ?";
const READ_RECORDS: &str = "SELECT position,entry,hash FROM records WHERE reference=? AND position>? ORDER BY position LIMIT ?";
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
        db.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL,
                 authority BLOB NOT NULL CHECK(length(authority)=32), logs INTEGER NOT NULL, rows INTEGER NOT NULL, bytes INTEGER NOT NULL);
             CREATE TABLE totals (day INTEGER PRIMARY KEY, entries INTEGER NOT NULL, bytes INTEGER NOT NULL);
             CREATE TABLE anchors (reference BLOB PRIMARY KEY CHECK(length(reference)=32), length INTEGER NOT NULL,
                 hash BLOB NOT NULL CHECK(length(hash)=32), public INTEGER NOT NULL, day INTEGER NOT NULL,
                 rows INTEGER NOT NULL, bytes INTEGER NOT NULL) WITHOUT ROWID;
             CREATE INDEX public_expiry ON anchors(day) WHERE public=1 AND rows>0;
             CREATE TABLE records (reference BLOB NOT NULL, position INTEGER NOT NULL, entry BLOB NOT NULL,
                 hash BLOB NOT NULL CHECK(length(hash)=32), expiry_day INTEGER, PRIMARY KEY(reference,position)) WITHOUT ROWID;
             CREATE INDEX private_expiry ON records(expiry_day) WHERE expiry_day IS NOT NULL;
             CREATE VIEW logs AS SELECT reference,length,hash FROM anchors;
             CREATE VIEW entries AS SELECT reference,position FROM records;",
        )?;
        db.execute("INSERT INTO metadata VALUES(1,?,?,0,0,0)", params![FORMAT, key.verifying_key().as_bytes()])?;
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
        Ok(Self { db: Mutex::new(db), key, wal: state.join("membership.db-wal"), disk: DISK_BYTES })
    }

    pub fn key(&self) -> &SigningKey { &self.key }

    fn sign(&self, log_ref: &[u8; 32], length: u64, hash: [u8; 32]) -> Head {
        Head::sign(&self.key, log_ref, length, hash, now())
    }

    pub fn append(&self, log_ref: &[u8; 32], entries: &[Bytes], public: bool) -> Result<Appended> {
        ensure!(membership::valid_append(entries), Refused("size".into()));
        let bytes = entries.iter().map(|e| e.0.len() as u64).sum::<u64>();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing = tx.query_row(
            "SELECT length,hash,public FROM anchors WHERE reference=?", [log_ref],
            |r| Ok((r.get::<_, u64>(0)?, r.get::<_, [u8; 32]>(1)?, r.get::<_, bool>(2)?)),
        ).optional()?;
        let (length, mut hash, public) = existing.unwrap_or((0, head::start(self.key.verifying_key().as_bytes(), log_ref), public));
        ensure!(used(&tx, &self.wal)? + bytes <= self.disk, Refused("quota".into()));
        let end = length + entries.len() as u64;
        let day = now() / DAY_MS;
        for (index, entry) in entries.iter().enumerate() {
            hash = head::next(&hash, &entry.0);
            tx.execute("INSERT INTO records VALUES(?,?,?,?,?)", params![log_ref, length + index as u64 + 1, entry.0, hash, (!public).then_some(day)])?;
        }
        tx.execute(
            "INSERT INTO anchors VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(reference) DO UPDATE
             SET length=?2, hash=?3, day=?5, rows=rows+?6, bytes=bytes+?7",
            params![log_ref, end, hash, public, day, entries.len() as u64, bytes],
        )?;
        tx.execute("INSERT INTO totals VALUES(?1,?2,?3) ON CONFLICT(day) DO UPDATE SET entries=entries+?2,bytes=bytes+?3",
            params![day, entries.len() as u64, bytes])?;
        tx.commit()?;
        Ok(Appended { position: length + 1, head: self.sign(log_ref, end, hash) })
    }

    pub fn read(&self, log_ref: &[u8; 32], after: u64) -> Result<Page> {
        let db = self.db.lock().unwrap();
        let tip: Option<(u64, [u8; 32])> = db.query_row("SELECT length,hash FROM anchors WHERE reference=?", [log_ref], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let (length, mut hash) = tip.unwrap_or((0, head::start(self.key.verifying_key().as_bytes(), log_ref)));
        ensure!(after <= length, Refused("policy".into()));
        let mut query = db.prepare_cached(READ_RECORDS)?;
        let mut rows = query.query(params![log_ref, after, membership::PAGE_ROWS as u64])?;
        let mut entries = Vec::new();
        let mut encoded = membership::PAGE_OVERHEAD;
        while let Some(row) = rows.next()? {
            let (position, entry, next_hash): (u64, Vec<u8>, [u8; 32]) = (row.get(0)?, row.get(1)?, row.get(2)?);
            ensure!(position == after + entries.len() as u64 + 1, Refused("expired".into()));
            let entry = Bytes(entry);
            let size = membership::encoded_entry_bytes(&entry);
            if encoded + size > membership::MAX_BODY { break; }
            entries.push(entry);
            encoded += size;
            hash = next_hash;
        }
        ensure!(!entries.is_empty() || after == length, Refused("expired".into()));
        Ok(Page { after, head: self.sign(log_ref, after + entries.len() as u64, hash), entries })
    }

    pub fn head(&self, log_ref: &[u8; 32]) -> Result<Head> {
        let tip: Option<(u64, [u8; 32])> = self.db.lock().unwrap().query_row("SELECT length,hash FROM anchors WHERE reference=?", [log_ref], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let (length, hash) = tip.unwrap_or((0, head::start(self.key.verifying_key().as_bytes(), log_ref)));
        Ok(self.sign(log_ref, length, hash))
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

    /// Row/payload work caps, not an I/O latency promise. Never remove sequence/hash anchors or daily totals.
    pub fn expire(&self, before_day: u64) -> Result<usize> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut expired: Vec<([u8; 32], u64, u64)> = tx.prepare_cached(PRIVATE_EXPIRY)?.query_map(params![before_day, EXPIRE_ROWS as u64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
        if expired.len() < EXPIRE_ROWS {
            let public: Option<[u8; 32]> = tx.query_row(PUBLIC_EXPIRY, [before_day], |r| r.get(0)).optional()?;
            if let Some(reference) = public {
                let mut query = tx.prepare_cached(PUBLIC_RECORDS)?;
                expired.extend(query.query_map(params![reference, (EXPIRE_ROWS - expired.len()) as u64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?);
            }
        }
        let mut bytes = 0;
        let keep = expired.iter().take_while(|(_, _, size)| {
            if bytes + size > EXPIRE_BYTES { return false; }
            bytes += size;
            true
        }).count();
        expired.truncate(keep);
        for (reference, position, size) in &expired {
            tx.execute("DELETE FROM records WHERE reference=? AND position=?", params![reference, position])?;
            tx.execute("UPDATE anchors SET rows=rows-1,bytes=bytes-? WHERE reference=?", params![size, reference])?;
        }
        tx.commit()?;
        Ok(expired.len())
    }
}

#[cfg(test)]
#[path = "store_sql_tests.rs"]
mod sql_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        (dir, path)
    }

    #[test]
    fn durable_restart_and_transaction_abort() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let d = head::reference(store.key().verifying_key().as_bytes(), &[7; 32]);
        {
            let db = store.db.lock().unwrap();
            assert_eq!(db.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0)).unwrap(), "wal");
            assert_eq!(db.query_row("PRAGMA synchronous", [], |r| r.get::<_, u32>(0)).unwrap(), 2);
            assert_eq!(db.query_row("PRAGMA fullfsync", [], |r| r.get::<_, u32>(0)).unwrap(), 1);
            db.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY);
                CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
                CREATE TRIGGER abort_append AFTER INSERT ON records BEGIN INSERT INTO child VALUES(1); END;").unwrap();
        }
        assert!(store.append(&d, &[Bytes(b"uncommitted".to_vec())], false).is_err());
        assert_eq!(store.head(&d).unwrap().length, 0);
        assert!(store.read(&d, 0).unwrap().entries.is_empty());
        assert_eq!(store.db.lock().unwrap().query_row("SELECT count(*) FROM totals", [], |r| r.get::<_, u64>(0)).unwrap(), 0);
        store.db.lock().unwrap().execute_batch("DROP TRIGGER abort_append").unwrap();
        let appended = store.append(&d, &[Bytes(b"committed".to_vec())], false).unwrap();
        let s = store.key().verifying_key();
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.key().verifying_key(), s);
        assert_eq!(store.head(&d).unwrap().hash, appended.head.hash);
        assert_eq!(store.read(&d, 0).unwrap().entries, [Bytes(b"committed".to_vec())]);
        drop(store);
    }

    #[test]
    fn expiry_and_public_retention_use_days_and_keep_anchors() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let d = [7; 32];
        let public = [8; 32];
        for r in [&d, &public] { store.append(r, &[Bytes(vec![1])], *r == public).unwrap(); }
        let day = now() / DAY_MS;
        store.db.lock().unwrap().execute("UPDATE records SET expiry_day=? WHERE reference=?", params![day-2, d]).unwrap();
        store.db.lock().unwrap().execute("UPDATE anchors SET day=? WHERE reference=?", params![day-2, public]).unwrap();
        store.append(&public, &[Bytes(vec![2])], false).unwrap();
        assert_eq!(store.expire(day).unwrap(), 1);
        assert_eq!(store.read(&public, 0).unwrap().entries.len(), 2);
        assert_eq!(store.read(&d, 0).unwrap_err().downcast::<Refused>().unwrap().0, "expired");
        let anchor = store.head(&d).unwrap();
        assert_eq!(anchor.length, 1);
        assert_eq!(store.read(&d, 1).unwrap().head.hash, anchor.hash);
        assert_eq!(store.append(&d, &[Bytes(vec![3])], false).unwrap().position, 2);
        assert_eq!(store.expire(day+1).unwrap(), 3);
        assert_eq!(store.head(&public).unwrap().length, 2);
        assert_eq!(store.append(&public, &[Bytes(vec![4])], true).unwrap().position, 3);
        assert_eq!(store.read(&public, 2).unwrap().entries.len(), 1);
        drop(store);
    }

    #[test]
    fn lost_or_mismatched_state_never_initializes() {
        let (_dir, missing) = state();
        assert!(Store::open(&missing).is_err());
        assert!(!missing.exists());
        for lost in ["membership.key", "membership.db", "membership.ready"] {
            let (_dir, path) = state();
            let store = Store::initialize(&path).unwrap();
            store.append(&[7; 32], &[Bytes(vec![1])], false).unwrap();
            drop(store);
            fs::remove_file(path.join(lost)).unwrap();
            assert!(Store::open(&path).is_err());
            assert!(Store::initialize(&path).is_err());
            assert!(!path.join(lost).exists());
        }
        for fault in ["empty", "authority", "format"] {
            let (_dir, path) = state();
            let store = Store::initialize(&path).unwrap();
            store.append(&[7; 32], &[Bytes(vec![1])], false).unwrap();
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
        let d = [7; 32];
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
        let d = [7; 32];
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
    fn completed_site_totals_survive_failures_restart_and_expiry() {
        lmk_proto::clock::set(|| 10 * DAY_MS);
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        store.append(&[1; 32], &[Bytes(vec![1; 3]), Bytes(vec![2; 5])], false).unwrap();
        store.append(&[2; 32], &[Bytes(vec![3; 7])], true).unwrap();
        assert!(store.stats().unwrap().days.iter().all(|d| d.entries == 0 && d.bytes == 0));
        lmk_proto::clock::set(|| 11 * DAY_MS);
        let expected = store.stats().unwrap();
        assert_eq!(expected.days.len(), 7);
        assert_eq!(expected.days[6], DayTotals { day: 10, entries: 3, bytes: 15 });
        store.append(&[1; 32], &[Bytes(vec![1; 9])], false).unwrap();
        store.db.lock().unwrap().execute_batch("CREATE TRIGGER fail_totals BEFORE UPDATE ON totals BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
        assert!(store.append(&[3; 32], &[Bytes(vec![1; 10])], false).is_err());
        assert_eq!(store.head(&[3; 32]).unwrap().length, 0);
        assert_eq!(store.stats().unwrap(), expected);
        assert_eq!(store.expire(12).unwrap(), 4);
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
    fn large_entry_expiry_and_foreground_append_share_bounded_batches() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        for _ in 0..8 { store.append(&[7; 32], &[Bytes(vec![3; membership::MAX_ENTRY])], false).unwrap(); }
        let day = now()/DAY_MS;
        store.db.lock().unwrap().execute("UPDATE records SET expiry_day=?", [day-1]).unwrap();
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let expiry = scope.spawn(|| { start.wait(); store.expire(day).unwrap() });
            start.wait();
            store.append(&[8; 32], &[Bytes(vec![9])], false).unwrap();
            assert_eq!(expiry.join().unwrap(), 4);
        });
        assert_eq!(store.read(&[8; 32], 0).unwrap().entries, [Bytes(vec![9])]);
        assert_eq!(store.read(&[7; 32], 4).unwrap().entries.len(), 2);
        drop(store);
    }

    #[test]
    fn expiry_payload_budget_bounds_large_private_and_public_deletions() {
        for public in [false, true] {
            let (_dir, path) = state();
            let store = Store::initialize(&path).unwrap();
            for _ in 0..5 { store.append(&[7; 32], &[Bytes(vec![3; membership::MAX_ENTRY])], public).unwrap(); }
            assert_eq!(store.expire(now()/DAY_MS+1).unwrap(), 4);
            assert_eq!(store.head(&[7; 32]).unwrap().length, 5);
            assert_eq!(store.read(&[7; 32], 4).unwrap().entries[0].0.len(), membership::MAX_ENTRY);
            assert_eq!(store.append(&[8; 32], &[Bytes(vec![9])], false).unwrap().position, 1);
            assert_eq!(store.expire(now()/DAY_MS+1).unwrap(), 2);
            drop(store);
        }
    }

    #[test]
    fn pages_and_expiry_work_are_bounded() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let d = [7; 32];
        for _ in 0..17 { store.append(&d, &vec![Bytes(vec![1]); membership::APPEND_ROWS], false).unwrap(); }
        assert_eq!(store.read(&d, 0).unwrap().entries.len(), membership::PAGE_ROWS);
        assert_eq!(store.expire(now()/DAY_MS+1).unwrap(), EXPIRE_ROWS);
        assert_eq!(store.expire(now()/DAY_MS+1).unwrap(), 64);
        let d = [8; 32];
        for _ in 0..3 { store.append(&d, &[Bytes(vec![3; membership::MAX_ENTRY])], false).unwrap(); }
        let page = store.read(&d, 0).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert!(serde_json::to_vec(&membership::Reply::Ok(&page)).unwrap().len() < membership::MAX_BODY);
        assert_eq!(store.read(&d, 2).unwrap().entries.len(), 1);
        drop(store);
    }

    #[test]
    fn opaque_schema_and_structural_legacy_refusal() {
        let (_dir, path) = state();
        let store = Store::initialize(&path).unwrap();
        let capability = lmk_proto::random::random::<32>();
        let d = head::reference(store.key().verifying_key().as_bytes(), &capability);
        store.append(&d, &[Bytes(vec![42])], false).unwrap();
        let db = store.db.lock().unwrap();
        assert!(db.execute_batch("CREATE TABLE IF NOT EXISTS logs(id BLOB PRIMARY KEY, length INTEGER NOT NULL, hash BLOB NOT NULL, public INTEGER NOT NULL DEFAULT 0, appended INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS entries(log BLOB NOT NULL, position INTEGER NOT NULL, entry BLOB NOT NULL, hash BLOB NOT NULL,time INTEGER NOT NULL, PRIMARY KEY(log,position)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS entries_time ON entries(time);").is_err());
        assert_eq!(db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table'", [], |r| r.get::<_, u64>(0)).unwrap(), 4);
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        assert!(!fs::read(path.join("membership.db")).unwrap().windows(32).any(|w| w == capability));
        drop(db);
        assert_eq!(store.read(&d, 0).unwrap().entries, [Bytes(vec![42])]);
        drop(store);
    }
}
