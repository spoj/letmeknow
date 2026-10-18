//! What the session process keeps beside its node's state, in the same SQLite file.

use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA secure_delete = ON;
-- Chat messages taken in, so that each is printed once, with when, in milliseconds, and the file its attachment is saved
-- in: kept for the group's H.
CREATE TABLE IF NOT EXISTS taken (id BLOB PRIMARY KEY, gid BLOB NOT NULL, at INTEGER NOT NULL, attachment TEXT);
";

pub fn open(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    db.busy_timeout(lmk_core::provider::BUSY)?;
    db.execute_batch(SCHEMA)?;
    Ok(db)
}
