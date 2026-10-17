//! What the session process keeps beside its node's state, in the same SQLite file.

use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA secure_delete = ON;
-- Chat messages taken in, so that each is printed once, with when, in milliseconds: kept for the group's H.
CREATE TABLE IF NOT EXISTS taken (id BLOB PRIMARY KEY, gid BLOB NOT NULL, at INTEGER NOT NULL);
-- Attachments of messages taken in, kept as long as their messages are; `path` once the file arrived.
CREATE TABLE IF NOT EXISTS attachments (hash BLOB NOT NULL, gid BLOB NOT NULL, message BLOB NOT NULL, link TEXT NOT NULL,
    name TEXT NOT NULL, wakes INTEGER NOT NULL, path TEXT, PRIMARY KEY (hash, message));
";

pub fn open(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    db.execute_batch(SCHEMA)?;
    Ok(db)
}
