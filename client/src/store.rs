use anyhow::Result;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use std::path::Path;

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub type Storage = SqliteStorageProvider<JsonCodec, Connection>;

pub struct Provider {
    crypto: RustCrypto,
    storage: Storage,
}

impl Provider {
    pub fn open(path: &Path) -> Result<Self> {
        let mut storage = Storage::new(Connection::open(path)?);
        storage.run_migrations()?;
        Ok(Self { crypto: RustCrypto::default(), storage })
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = Storage;

    fn storage(&self) -> &Storage {
        &self.storage
    }

    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }

    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

pub const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS identity (name TEXT NOT NULL, public BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS groups (gid TEXT PRIMARY KEY, relay TEXT NOT NULL, cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS epochs (gid TEXT NOT NULL, epoch INTEGER NOT NULL, auth TEXT NOT NULL, PRIMARY KEY (gid, epoch));
CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, gid TEXT NOT NULL, sender TEXT NOT NULL, payload TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS posted (id TEXT PRIMARY KEY);
";
