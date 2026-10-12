//! openmls providers with room for our own state: SQLite natively, memory in the browser. A step's writes, openmls's
//! and ours, commit together; a savepoint within it rolls both back.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, RwLock};

use anyhow::Result;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::StorageProvider;

pub use openmls_rust_crypto::RustCrypto;

/// An openmls provider that also keeps our own records, by key.
pub trait Provider: OpenMlsProvider<StorageProvider: StorageProvider<1, Error: Send + Sync + 'static>> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn path(&self) -> Option<std::path::PathBuf> { None }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;
    fn delete(&self, key: &[u8]) -> Result<()>;
    /// Starts a step: every write until `commit` is kept or lost together.
    fn begin(&self) -> Result<()>;
    fn commit(&self) -> Result<()>;
    /// A point within the step to roll back to; savepoints nest.
    fn savepoint(&self) -> Result<()>;
    /// Undoes every write since the innermost savepoint, and drops it.
    fn rollback_to(&self) -> Result<()>;
    /// Drops the innermost savepoint, keeping what was written since.
    fn release(&self) -> Result<()>;
    /// Leaves in its files no copy of what was deleted or overwritten. Outside a step.
    fn scrub(&self) -> Result<()> {
        Ok(())
    }
    /// Closes its files, at the node's shutdown: the node itself is not dropped then, as its peers hold it.
    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The browser's provider: openmls's records in a `MemoryStorage`, ours beside them; the browser persists the changes
/// (`changes`), ours under keys starting with `lmk/`.
#[derive(Default)]
pub struct MemoryProvider {
    crypto: RustCrypto,
    pub storage: MemoryStorage,
    ours: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    savepoints: Mutex<Vec<Savepoint>>,
    /// Our keys not yet acknowledged by `persisted`.
    dirty: Mutex<HashSet<Vec<u8>>>,
    /// A digest of each of openmls's persisted records.
    shadow: Mutex<HashMap<Vec<u8>, u64>>,
}

/// openmls's records as they stood, and the old values of our records written since.
struct Savepoint {
    openmls: HashMap<Vec<u8>, Vec<u8>>,
    ours: HashMap<Vec<u8>, Option<Vec<u8>>>,
}

impl OpenMlsProvider for MemoryProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }

    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }

    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

const OURS: &[u8] = b"lmk/";

fn digest(value: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

impl MemoryProvider {
    /// A provider holding these persisted records.
    pub fn load(records: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> Self {
        let provider = MemoryProvider::default();
        for (key, value) in records {
            match key.strip_prefix(OURS) {
                Some(ours) => drop(provider.ours.write().unwrap().insert(ours.to_vec(), value)),
                None => {
                    provider.shadow.lock().unwrap().insert(key.clone(), digest(&value));
                    provider.storage.values.write().unwrap().insert(key, value);
                }
            }
        }
        provider
    }

    /// Every record in memory, between steps.
    pub fn records(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let openmls = self.storage.values.read().unwrap().clone().into_iter();
        let ours = self.ours.read().unwrap().clone().into_iter().map(|(key, value)| ([OURS, &key].concat(), value));
        openmls.chain(ours).collect()
    }

    /// Unpersisted records and deletions, between steps. Serialize saves and acknowledge only successful commits
    /// with `persisted`; writes made while a save is in flight remain in the next batch.
    pub fn changes(&self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let mut changes = Vec::new();
        let ours = self.ours.read().unwrap();
        for key in self.dirty.lock().unwrap().iter() {
            changes.push(([OURS, key].concat(), ours.get(key).cloned()));
        }
        let values = self.storage.values.read().unwrap();
        let shadow = self.shadow.lock().unwrap();
        for (key, value) in values.iter() {
            if shadow.get(key) != Some(&digest(value)) {
                changes.push((key.clone(), Some(value.clone())));
            }
        }
        for key in shadow.keys().filter(|key| !values.contains_key(*key)) {
            changes.push((key.clone(), None));
        }
        changes
    }

    pub fn persisted(&self, changes: &[(Vec<u8>, Option<Vec<u8>>)]) {
        let ours = self.ours.read().unwrap();
        let mut dirty = self.dirty.lock().unwrap();
        let mut shadow = self.shadow.lock().unwrap();
        for (key, value) in changes {
            match key.strip_prefix(OURS) {
                Some(key) => {
                    if ours.get(key) == value.as_ref() {
                        dirty.remove(key);
                    }
                }
                None => match value {
                    Some(value) => { shadow.insert(key.clone(), digest(value)); }
                    None => { shadow.remove(key); }
                },
            }
        }
    }

    fn touch(&self, key: &[u8], old: Option<Vec<u8>>) {
        self.dirty.lock().unwrap().insert(key.to_vec());
        if let Some(savepoint) = self.savepoints.lock().unwrap().last_mut() {
            savepoint.ours.entry(key.to_vec()).or_insert(old);
        }
    }
}

impl Provider for MemoryProvider {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.ours.read().unwrap().get(key).cloned())
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let old = self.ours.write().unwrap().insert(key.to_vec(), value.to_vec());
        self.touch(key, old);
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let old = self.ours.write().unwrap().remove(key);
        self.touch(key, old);
        Ok(())
    }

    /// The memory is the step: the browser persists it between steps.
    fn begin(&self) -> Result<()> {
        Ok(())
    }

    fn commit(&self) -> Result<()> {
        Ok(())
    }

    fn savepoint(&self) -> Result<()> {
        let openmls = self.storage.values.read().unwrap().clone();
        self.savepoints.lock().unwrap().push(Savepoint { openmls, ours: HashMap::new() });
        Ok(())
    }

    fn rollback_to(&self) -> Result<()> {
        let savepoint = self.savepoints.lock().unwrap().pop().expect("a savepoint");
        *self.storage.values.write().unwrap() = savepoint.openmls;
        let mut ours = self.ours.write().unwrap();
        for (key, old) in savepoint.ours {
            match old {
                Some(old) => ours.insert(key, old),
                None => ours.remove(&key),
            };
        }
        Ok(())
    }

    fn release(&self) -> Result<()> {
        let mut savepoints = self.savepoints.lock().unwrap();
        let released = savepoints.pop().expect("a savepoint");
        if let Some(outer) = savepoints.last_mut() {
            for (key, old) in released.ours {
                outer.ours.entry(key).or_insert(old);
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::{Cbor, SqliteProvider};

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::borrow::Borrow;
    use std::cell::Cell;
    use std::path::Path;
    use std::rc::Rc;

    use anyhow::Result;
    use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
    use openmls_traits::OpenMlsProvider;
    use rusqlite::OptionalExtension;

    use super::RustCrypto;

    /// openmls state as CBOR: compact, and readable back (bincode is not).
    #[derive(Default)]
    pub struct Cbor;

    #[derive(Debug)]
    pub struct CborError(String);

    impl std::fmt::Display for CborError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for CborError {}

    impl Codec for Cbor {
        type Error = CborError;

        fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
            let mut out = Vec::new();
            ciborium::into_writer(value, &mut out).map_err(|e| CborError(e.to_string()))?;
            Ok(out)
        }

        fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, CborError> {
            ciborium::from_reader(slice).map_err(|e| CborError(e.to_string()))
        }
    }

    /// The one connection, which openmls's storage borrows.
    pub struct Db(Rc<Connection>);

    impl Borrow<Connection> for Db {
        fn borrow(&self) -> &Connection {
            &self.0
        }
    }

    /// One SQLite file and one connection: openmls's tables, and ours (`lmk`).
    pub struct SqliteProvider {
        crypto: RustCrypto,
        db: Rc<Connection>,
        storage: SqliteStorageProvider<Cbor, Db>,
        savepoints: Cell<u32>,
    }

    // SAFETY: the connection's two handles are both in here, so they move between threads together, and `&self` is
    // only ever used from one thread at a time: the node holds the provider under a lock.
    unsafe impl Send for SqliteProvider {}

    const PRAGMAS: &str = "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA fullfsync = ON; PRAGMA secure_delete = ON;";

    impl SqliteProvider {
        pub fn open(path: &Path) -> Result<Self> {
            let mut connection = Connection::open(path)?;
            connection.execute_batch(PRAGMAS)?;
            SqliteStorageProvider::<Cbor, &mut Connection>::new(&mut connection).run_migrations()?;
            connection.execute_batch("CREATE TABLE IF NOT EXISTS lmk (key BLOB PRIMARY KEY, value BLOB NOT NULL)")?;
            let db = Rc::new(connection);
            let storage = SqliteStorageProvider::new(Db(db.clone()));
            Ok(SqliteProvider { crypto: RustCrypto::default(), db, storage, savepoints: Cell::new(0) })
        }
    }

    impl OpenMlsProvider for SqliteProvider {
        type CryptoProvider = RustCrypto;
        type RandProvider = RustCrypto;
        type StorageProvider = SqliteStorageProvider<Cbor, Db>;

        fn storage(&self) -> &Self::StorageProvider {
            &self.storage
        }

        fn crypto(&self) -> &RustCrypto {
            &self.crypto
        }

        fn rand(&self) -> &RustCrypto {
            &self.crypto
        }
    }

    impl super::Provider for SqliteProvider {
        fn path(&self) -> Option<std::path::PathBuf> {
            self.db.path().filter(|path| !path.is_empty()).map(std::path::PathBuf::from)
        }

        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            Ok(self.db.query_row("SELECT value FROM lmk WHERE key = ?1", [key], |row| row.get(0)).optional()?)
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.db.execute("INSERT OR REPLACE INTO lmk (key, value) VALUES (?1, ?2)", (key, value))?;
            Ok(())
        }

        fn delete(&self, key: &[u8]) -> Result<()> {
            self.db.execute("DELETE FROM lmk WHERE key = ?1", [key])?;
            Ok(())
        }

        fn begin(&self) -> Result<()> {
            // A deferred transaction that reads and then writes after the session's other connection wrote fails at
            // once, without waiting.
            Ok(self.db.execute_batch("BEGIN IMMEDIATE")?)
        }

        fn commit(&self) -> Result<()> {
            Ok(self.db.execute_batch("COMMIT")?)
        }

        fn savepoint(&self) -> Result<()> {
            self.savepoints.set(self.savepoints.get() + 1);
            Ok(self.db.execute_batch(&format!("SAVEPOINT s{}", self.savepoints.get()))?)
        }

        fn rollback_to(&self) -> Result<()> {
            let n = self.savepoints.replace(self.savepoints.get() - 1);
            Ok(self.db.execute_batch(&format!("ROLLBACK TO s{n}; RELEASE s{n}"))?)
        }

        fn release(&self) -> Result<()> {
            let n = self.savepoints.replace(self.savepoints.get() - 1);
            Ok(self.db.execute_batch(&format!("RELEASE s{n}"))?)
        }

        /// `secure_delete` zeroes deleted records in the database, but the WAL keeps earlier versions of their pages
        /// until a checkpoint overwrites it; TRUNCATE empties it.
        fn scrub(&self) -> Result<()> {
            let busy: i64 = self.db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
            anyhow::ensure!(busy == 0, "the database was busy, so deleted records stay in its WAL for now");
            Ok(())
        }

        /// Both handles move to an empty database in memory, so the file closes, and can be deleted on Windows.
        fn close(&mut self) -> Result<()> {
            let memory = Rc::new(Connection::open_in_memory()?);
            self.storage = SqliteStorageProvider::new(Db(memory.clone()));
            self.db = memory;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::provider::Provider;

        #[test]
        fn commits_sync_the_wal_before_becoming_visible() {
            let dir = std::env::temp_dir().join(format!("lmk-core-durable-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("state.db");
            let provider = SqliteProvider::open(&path).unwrap();
            assert_eq!(provider.db.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0)).unwrap(), "wal");
            assert_eq!(provider.db.query_row("PRAGMA synchronous", [], |r| r.get::<_, u32>(0)).unwrap(), 2);
            assert_eq!(provider.db.query_row("PRAGMA fullfsync", [], |r| r.get::<_, u32>(0)).unwrap(), 1);
            let reader = SqliteProvider::open(&path).unwrap();
            provider.begin().unwrap();
            provider.put(b"head", b"one").unwrap();
            assert_eq!(reader.get(b"head").unwrap(), None);
            provider.commit().unwrap();
            assert_eq!(reader.get(b"head").unwrap(), Some(b"one".to_vec()));
            drop((reader, provider));
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{MemoryProvider, Provider, SqliteProvider};

    #[test]
    fn failed_save_is_still_in_an_otherwise_empty_barrier() {
        let provider = MemoryProvider::default();
        provider.put(b"head", b"one").unwrap();
        provider.storage.values.write().unwrap().insert(b"mls".to_vec(), b"epoch".to_vec());
        let failed: std::collections::HashMap<_, _> = provider.changes().into_iter().collect();
        let retry = provider.changes();
        assert_eq!(retry.iter().cloned().collect::<std::collections::HashMap<_, _>>(), failed);
        let reloaded = MemoryProvider::load(retry.iter().cloned().map(|(key, value)| (key, value.unwrap())));
        assert_eq!(reloaded.get(b"head").unwrap(), Some(b"one".to_vec()));
        assert_eq!(reloaded.storage.values.read().unwrap().get(b"mls".as_slice()).unwrap(), b"epoch");
        provider.persisted(&retry);
        assert!(provider.changes().is_empty());
        assert!(reloaded.changes().is_empty());
    }

    #[test]
    fn successful_save_does_not_acknowledge_intervening_writes() {
        let provider = MemoryProvider::load([
            (b"lmk/deleted".to_vec(), b"old".to_vec()),
            (b"mls".to_vec(), b"old".to_vec()),
        ]);
        provider.put(b"head", b"one").unwrap();
        provider.delete(b"deleted").unwrap();
        provider.storage.values.write().unwrap().insert(b"mls".to_vec(), b"new".to_vec());
        let saving = provider.changes();
        provider.put(b"head", b"two").unwrap();
        provider.put(b"deleted", b"back").unwrap();
        provider.storage.values.write().unwrap().insert(b"mls".to_vec(), b"old".to_vec());
        provider.persisted(&saving);
        let next: std::collections::HashMap<_, _> = provider.changes().into_iter().collect();
        assert_eq!(next.get(b"lmk/head".as_slice()), Some(&Some(b"two".to_vec())));
        assert_eq!(next.get(b"lmk/deleted".as_slice()), Some(&Some(b"back".to_vec())));
        assert_eq!(next.get(b"mls".as_slice()), Some(&Some(b"old".to_vec())));
        provider.persisted(&next.into_iter().collect::<Vec<_>>());
        provider.delete(b"head").unwrap();
        provider.storage.values.write().unwrap().remove(b"mls".as_slice());
        let deleted = provider.changes();
        assert_eq!(deleted.len(), 2);
        assert!(deleted.iter().all(|(_, value)| value.is_none()));
        assert_eq!(provider.changes().len(), 2);
        provider.persisted(&deleted);
        assert!(provider.changes().is_empty());
    }

    /// The database files that hold `secret`. The `-shm` file holds only the WAL's index, and Windows locks parts of it.
    fn in_files(dir: &std::path::Path, secret: &[u8]) -> Vec<String> {
        let files = std::fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().path());
        let files = files.filter(|path| !path.to_string_lossy().ends_with("-shm"));
        let holding = files.filter(|path| std::fs::read(path).unwrap().windows(secret.len()).any(|w| w == secret));
        holding.map(|path| path.display().to_string()).collect()
    }

    #[test]
    fn deleted_records_are_in_no_file() {
        let dir = std::env::temp_dir().join(format!("lmk-core-scrub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let provider = SqliteProvider::open(&dir.join("state.db")).unwrap();
        let small = b"a secret that must not linger".to_vec();
        let large: Vec<u8> = small.iter().cycle().take(20_000).copied().collect();
        provider.put(b"kept", b"something else").unwrap();
        provider.put(b"small", &small).unwrap();
        provider.put(b"large", &large).unwrap();
        provider.put(b"replaced", &[b"old ".as_slice(), &small].concat()).unwrap();
        assert!(!in_files(&dir, &small).is_empty());
        provider.delete(b"small").unwrap();
        provider.delete(b"large").unwrap();
        provider.put(b"replaced", b"new").unwrap();
        provider.scrub().unwrap();
        assert_eq!(in_files(&dir, &small), Vec::<String>::new());
        assert_eq!(provider.get(b"kept").unwrap().unwrap(), b"something else");
        // Windows cannot delete a database that is still open.
        drop(provider);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
