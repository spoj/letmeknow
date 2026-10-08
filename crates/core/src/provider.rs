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
    }
}
