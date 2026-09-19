use anyhow::{Context, Result};
use myproxy_ir::CanonicalNode;
use rusqlite::{params, Connection, OpenFlags};
use std::path::Path;

use crate::ProtocolKind;

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
            protocol_kind INTEGER NOT NULL DEFAULT 0,
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
    ensure_protocol_kind_column(connection)?;
    Ok(())
}

/// Adds the `protocol_kind` column to databases created before the column
/// existed, then backfills it from each stored payload in a single pass.
fn ensure_protocol_kind_column(connection: &Connection) -> Result<()> {
    let has_column = {
        let mut statement = connection.prepare("PRAGMA table_info(nodes)")?;
        let mut rows = statement.query([])?;
        let mut found = false;
        while let Some(row) = rows.next()? {
            if row.get::<_, String>(1)? == "protocol_kind" {
                found = true;
                break;
            }
        }
        found
    };
    if has_column {
        return Ok(());
    }
    connection.execute_batch(
        "ALTER TABLE nodes ADD COLUMN protocol_kind INTEGER NOT NULL DEFAULT 0",
    )?;
    let mut select = connection.prepare("SELECT id, raw_payload FROM nodes")?;
    let mut update = connection.prepare("UPDATE nodes SET protocol_kind = ?2 WHERE id = ?1")?;
    let mut rows = select.query([])?;
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let payload: Vec<u8> = row.get(1)?;
        let node: CanonicalNode = match bincode::deserialize(&payload) {
            Ok(node) => node,
            Err(_) => continue,
        };
        update.execute(params![id, ProtocolKind::from(&node.protocol).discriminant()])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use myproxy_ir::{
        CanonicalNode, EndpointTarget, NodeMetadata, ProtocolSpec, SecuritySpec, TransportSpec,
        VlessConfig,
    };
    use uuid::Uuid;

    fn vless_node() -> CanonicalNode {
        CanonicalNode::try_new(
            NodeMetadata::new(1, "Legacy node", *b"DE", 1).unwrap(),
            EndpointTarget::domain("example.com", 443).unwrap(),
            ProtocolSpec::Vless(VlessConfig {
                uuid: Uuid::nil(),
                flow: None,
            }),
            TransportSpec::Tcp,
            SecuritySpec::None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn legacy_database_gains_and_backfills_protocol_kind() {
        let connection = open_memory_database().unwrap();
        connection
            .execute_batch(
                r#"
                DROP TABLE node_diagnostics;
                DROP TABLE node_sources;
                DROP TABLE nodes;
                CREATE TABLE nodes (
                    id INTEGER PRIMARY KEY,
                    hash BLOB NOT NULL UNIQUE CHECK(length(hash) = 32),
                    name TEXT NOT NULL,
                    country_code TEXT NOT NULL CHECK(length(country_code) = 2),
                    raw_payload BLOB NOT NULL
                );
                "#,
            )
            .unwrap();
        let node = vless_node();
        let payload = bincode::serialize(&node).unwrap();
        connection
            .execute(
                "INSERT INTO nodes (hash, name, country_code, raw_payload) VALUES (?1, ?2, ?3, ?4)",
                params![&node.hash[..], node.meta.label.as_ref(), "DE", payload],
            )
            .unwrap();

        initialize_schema(&connection).unwrap();

        let kind: u8 = connection
            .query_row("SELECT protocol_kind FROM nodes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kind, ProtocolKind::from(&node.protocol).discriminant());
        let store = crate::DenseNodeStore::hydrate_from_db(&connection).unwrap();
        assert_eq!(store.protocol_kinds, vec![ProtocolKind::from(&node.protocol)]);
    }
}
