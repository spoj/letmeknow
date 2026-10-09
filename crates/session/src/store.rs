//! What the session process keeps beside its node's state, in the same SQLite file.

use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA secure_delete = ON;
CREATE TABLE IF NOT EXISTS session (name TEXT NOT NULL);
-- Chat messages taken in: printed, or waiting to print; `seen` once printed or read: the read frontier.
CREATE TABLE IF NOT EXISTS taken (id BLOB PRIMARY KEY, gid BLOB NOT NULL, seen INTEGER NOT NULL DEFAULT 0);
-- Attachments of messages taken in; `path` once the file arrived.
CREATE TABLE IF NOT EXISTS attachments (hash BLOB NOT NULL, gid BLOB NOT NULL, message BLOB NOT NULL, link TEXT NOT NULL,
    name TEXT NOT NULL, wakes INTEGER NOT NULL, path TEXT, PRIMARY KEY (hash, message));
";

pub fn open(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    db.execute_batch(SCHEMA)?;
    Ok(db)
}
