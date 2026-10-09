//! openmls providers with room for our own state: SQLite natively, memory in the browser.

use anyhow::Result;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::StorageProvider;

/// An openmls provider that also keeps our own records, by key.
pub trait Provider: OpenMlsProvider<StorageProvider: StorageProvider<1, Error: Send + Sync + 'static>> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;
    fn delete(&self, key: &[u8]) -> Result<()>;
    /// Leaves in its files no copy of what was deleted or overwritten.
    fn scrub(&self) -> Result<()> {
        Ok(())
    }
}

/// The browser's provider: everything in one `MemoryStorage`, whose `values` the browser persists, one record per key.
/// Our own records sit under keys starting with `lmk/`.
#[derive(Default)]
pub struct MemoryProvider {
    crypto: RustCrypto,
    pub storage: MemoryStorage,
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

fn memory_key(key: &[u8]) -> Vec<u8> {
    [b"lmk/".as_slice(), key].concat()
}

impl Provider for MemoryProvider {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.storage.values.read().unwrap().get(&memory_key(key)).cloned())
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.storage.values.write().unwrap().insert(memory_key(key), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.storage.values.write().unwrap().remove(&memory_key(key));
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::{Cbor, SqliteProvider};

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::path::Path;

    use anyhow::Result;
    use openmls_rust_crypto::RustCrypto;
    use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
    use openmls_traits::OpenMlsProvider;
    use rusqlite::OptionalExtension;

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

    /// One SQLite file: openmls's tables, and ours (`lmk`) on a second connection.
    pub struct SqliteProvider {
        crypto: RustCrypto,
        storage: SqliteStorageProvider<Cbor, Connection>,
        ours: Connection,
    }

    const PRAGMAS: &str = "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA secure_delete = ON;";

    impl SqliteProvider {
        pub fn open(path: &Path) -> Result<Self> {
            let connection = Connection::open(path)?;
            connection.execute_batch(PRAGMAS)?;
            let mut storage = SqliteStorageProvider::new(connection);
            storage.run_migrations()?;
            let ours = Connection::open(path)?;
            ours.execute_batch(PRAGMAS)?;
            ours.execute_batch("CREATE TABLE IF NOT EXISTS lmk (key BLOB PRIMARY KEY, value BLOB NOT NULL)")?;
            Ok(SqliteProvider { crypto: RustCrypto::default(), storage, ours })
        }
    }

    impl OpenMlsProvider for SqliteProvider {
        type CryptoProvider = RustCrypto;
        type RandProvider = RustCrypto;
        type StorageProvider = SqliteStorageProvider<Cbor, Connection>;

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
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            Ok(self.ours.query_row("SELECT value FROM lmk WHERE key = ?1", [key], |row| row.get(0)).optional()?)
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.ours.execute("INSERT OR REPLACE INTO lmk (key, value) VALUES (?1, ?2)", (key, value))?;
            Ok(())
        }

        fn delete(&self, key: &[u8]) -> Result<()> {
            self.ours.execute("DELETE FROM lmk WHERE key = ?1", [key])?;
            Ok(())
        }

        /// `secure_delete` zeroes deleted records in the database, but the WAL keeps earlier versions of their pages
        /// until a checkpoint overwrites it; TRUNCATE empties it.
        fn scrub(&self) -> Result<()> {
            let busy: i64 = self.ours.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
            anyhow::ensure!(busy == 0, "the database was busy, so deleted records stay in its WAL for now");
            Ok(())
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{Provider, SqliteProvider};

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
