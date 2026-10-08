//! The session's own state: one SQLite database in its state directory. MLS and peer state live with their parts.

use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA secure_delete = ON;
CREATE TABLE IF NOT EXISTS session (name TEXT NOT NULL);
-- The groups this session is in, and how far it has read each one's log.
CREATE TABLE IF NOT EXISTS groups (gid BLOB PRIMARY KEY, position INTEGER NOT NULL);
-- Chat messages taken in; `seen` once printed or read: the read frontier. Text goes once seen, unless --keep-log.
CREATE TABLE IF NOT EXISTS messages (id BLOB PRIMARY KEY, gid BLOB NOT NULL, sender TEXT NOT NULL, payload TEXT NOT NULL,
    seen INTEGER NOT NULL DEFAULT 0, mine INTEGER NOT NULL DEFAULT 0);
-- What this session sent that no other member holds yet: a message id, or a file's hash.
CREATE TABLE IF NOT EXISTS pending (id BLOB PRIMARY KEY, gid BLOB NOT NULL, what TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS docs (gid BLOB PRIMARY KEY, state BLOB NOT NULL);
-- A doc's file, and its base: the text the file and the doc last had in common.
CREATE TABLE IF NOT EXISTS bindings (gid BLOB PRIMARY KEY, path TEXT NOT NULL, base TEXT NOT NULL);
-- Attachments of messages taken in; `path` once the file arrived.
CREATE TABLE IF NOT EXISTS attachments (hash BLOB NOT NULL, gid BLOB NOT NULL, message BLOB NOT NULL, link TEXT NOT NULL,
    name TEXT NOT NULL, wakes INTEGER NOT NULL, path TEXT, PRIMARY KEY (hash, message));
-- Who told this session who an identity is, and under what name, until it is a contact.
CREATE TABLE IF NOT EXISTS introductions (identity BLOB NOT NULL, by TEXT NOT NULL, name TEXT NOT NULL, ref TEXT NOT NULL,
    PRIMARY KEY (identity, by));
";

pub fn open(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    db.execute_batch(SCHEMA)?;
    Ok(db)
}
