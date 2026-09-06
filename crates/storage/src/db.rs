use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

pub fn open_database<P: AsRef<Path>>(path: P) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("failed to open SQLite database")?;
    configure_connection(&connection)?;
    initialize_schema(&connection)?;
    Ok(connection)
}

pub fn open_memory_database() -> Result<Connection> {
    let connection = Connection::open_in_memory().context("failed to open in-memory database")?;
    configure_connection(&connection)?;
    initialize_schema(&connection)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection) -> Result<()> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.pragma_update(None, "mmap_size", 268_435_456_i64)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "cache_size", -64_000_i64)?;
    Ok(())
}

fn initialize_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY,
            uuid TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            last_updated INTEGER NOT NULL,
            auto_update_interval INTEGER NOT NULL DEFAULT 86400,
            etag TEXT
        );

        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY,
            hash BLOB NOT NULL UNIQUE CHECK(length(hash) = 32),
            name TEXT NOT NULL,
            country_code TEXT NOT NULL CHECK(length(country_code) = 2),
            raw_payload BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS node_sources (
            node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
            sub_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
            PRIMARY KEY(node_id, sub_id)
        );

        CREATE TABLE IF NOT EXISTS node_diagnostics (
            node_id INTEGER PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
            last_tested INTEGER NOT NULL DEFAULT 0,
            latency_ms INTEGER NOT NULL DEFAULT 65535 CHECK(latency_ms BETWEEN 0 AND 65535),
            jitter_ms INTEGER NOT NULL DEFAULT 0 CHECK(jitter_ms BETWEEN 0 AND 65535),
            packet_loss REAL NOT NULL DEFAULT 0.0 CHECK(packet_loss BETWEEN 0.0 AND 100.0),
            health_score INTEGER NOT NULL DEFAULT 0 CHECK(health_score BETWEEN 0 AND 100),
            is_operational INTEGER NOT NULL DEFAULT 0 CHECK(is_operational IN (0, 1))
        );

        CREATE INDEX IF NOT EXISTS idx_node_sources_sub ON node_sources(sub_id);
        CREATE INDEX IF NOT EXISTS idx_diag_latency ON node_diagnostics(latency_ms);
        "#,
    )?;
    Ok(())
}
