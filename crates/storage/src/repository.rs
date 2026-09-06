use anyhow::{bail, Result};
use bincode;
use myproxy_ir::{CanonicalHash, CanonicalNode, SubId};
use myproxy_parser::IngestionReport;
use rusqlite::{params, Connection, Transaction};
use std::collections::HashSet;

pub struct SubscriptionRecord<'a> {
    pub id: SubId,
    pub uuid: &'a str,
    pub name: &'a str,
    pub url: &'a str,
    pub last_updated: u64,
    pub auto_update_interval: u64,
    pub etag: Option<&'a str>,
}

pub struct NodeRepository;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncResult {
    pub inserted_nodes: usize,
    pub linked_nodes: usize,
    pub removed_orphans: usize,
}

impl NodeRepository {
    pub fn sync_subscription(
        connection: &Connection,
        record: SubscriptionRecord<'_>,
        report: &IngestionReport,
        allow_empty: bool,
    ) -> Result<SyncResult> {
        if report.successful_nodes.is_empty() && !allow_empty {
            bail!("refusing to replace subscription with an empty or entirely invalid snapshot");
        }

        let tx = connection.unchecked_transaction()?;
        let sub_id = record.id;
        upsert_subscription_tx(&tx, &record)?;
        let (inserted_nodes, node_ids) = ensure_nodes(&tx, &report.successful_nodes)?;
        tx.execute(
            "DELETE FROM node_sources WHERE sub_id = ?1",
            params![sub_id],
        )?;

        let mut link_statement = tx.prepare_cached(
            "INSERT OR IGNORE INTO node_sources (node_id, sub_id) VALUES (?1, ?2)",
        )?;
        for node_id in &node_ids {
            link_statement.execute(params![node_id, sub_id])?;
        }
        drop(link_statement);

        let removed_orphans = tx.execute(
            "DELETE FROM nodes WHERE NOT EXISTS (SELECT 1 FROM node_sources WHERE node_sources.node_id = nodes.id)",
            [],
        )?;
        tx.commit()?;

        Ok(SyncResult {
            inserted_nodes,
            linked_nodes: node_ids.len(),
            removed_orphans,
        })
    }

    pub fn upsert_subscription(
        connection: &Connection,
        record: SubscriptionRecord<'_>,
    ) -> Result<()> {
        connection.execute(
            r#"INSERT INTO subscriptions
               (id, uuid, name, url, last_updated, auto_update_interval, etag)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
               ON CONFLICT(id) DO UPDATE SET
                 uuid = excluded.uuid,
                 name = excluded.name,
                 url = excluded.url,
                 last_updated = excluded.last_updated,
                 auto_update_interval = excluded.auto_update_interval,
                 etag = excluded.etag"#,
            params![
                record.id,
                record.uuid,
                record.name,
                record.url,
                record.last_updated,
                record.auto_update_interval,
                record.etag
            ],
        )?;
        Ok(())
    }

    pub fn bulk_insert_nodes(
        tx: &Transaction<'_>,
        sub_id: SubId,
        nodes: &[CanonicalNode],
    ) -> Result<usize> {
        let mut inserted = 0;
        let mut insert_node = tx.prepare_cached(
            r#"INSERT INTO nodes (hash, name, country_code, raw_payload)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT(hash) DO NOTHING"#,
        )?;
        let mut find_node = tx.prepare_cached("SELECT id FROM nodes WHERE hash = ?1")?;
        let mut insert_source = tx.prepare_cached(
            "INSERT OR IGNORE INTO node_sources (node_id, sub_id) VALUES (?1, ?2)",
        )?;
        let mut insert_diagnostics =
            tx.prepare_cached("INSERT OR IGNORE INTO node_diagnostics (node_id) VALUES (?1)")?;

        for node in nodes {
            let country = std::str::from_utf8(&node.meta.country_code).unwrap_or("UN");
            let payload = bincode::serialize(node)?;
            let was_inserted = insert_node.execute(params![
                &node.hash[..],
                node.meta.label.as_ref(),
                country,
                payload
            ])? == 1;
            let node_id: i64 = find_node.query_row(params![&node.hash[..]], |row| row.get(0))?;
            insert_source.execute(params![node_id, sub_id])?;
            insert_diagnostics.execute(params![node_id])?;
            if was_inserted {
                inserted += 1;
            }
        }
        Ok(inserted)
    }

    pub fn load_all_hashes(connection: &Connection) -> Result<HashSet<CanonicalHash>> {
        let mut statement = connection.prepare("SELECT hash FROM nodes")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut hashes = HashSet::new();
        for row in rows {
            let bytes = row?;
            let hash: CanonicalHash = bytes.try_into().map_err(|bytes: Vec<u8>| {
                anyhow::anyhow!("database contains hash with {} bytes", bytes.len())
            })?;
            hashes.insert(hash);
        }
        Ok(hashes)
    }

    pub fn decode_node_payload(bytes: &[u8]) -> Result<CanonicalNode> {
        let node: CanonicalNode = bincode::deserialize(bytes)?;
        if node.hash != node_hash(&node)? {
            bail!("stored node hash does not match its payload");
        }
        Ok(node)
    }
}

fn upsert_subscription_tx(tx: &Transaction<'_>, record: &SubscriptionRecord<'_>) -> Result<()> {
    tx.execute(
        r#"INSERT INTO subscriptions
           (id, uuid, name, url, last_updated, auto_update_interval, etag)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
           ON CONFLICT(id) DO UPDATE SET
             uuid = excluded.uuid,
             name = excluded.name,
             url = excluded.url,
             last_updated = excluded.last_updated,
             auto_update_interval = excluded.auto_update_interval,
             etag = excluded.etag"#,
        params![
            record.id,
            record.uuid,
            record.name,
            record.url,
            record.last_updated,
            record.auto_update_interval,
            record.etag
        ],
    )?;
    Ok(())
}

fn ensure_nodes(tx: &Transaction<'_>, nodes: &[CanonicalNode]) -> Result<(usize, Vec<i64>)> {
    let mut inserted = 0;
    let mut ids = Vec::with_capacity(nodes.len());
    let mut insert_node = tx.prepare_cached(
        r#"INSERT INTO nodes (hash, name, country_code, raw_payload)
           VALUES (?1, ?2, ?3, ?4)
           ON CONFLICT(hash) DO NOTHING"#,
    )?;
    let mut find_node = tx.prepare_cached("SELECT id FROM nodes WHERE hash = ?1")?;
    let mut insert_diagnostics =
        tx.prepare_cached("INSERT OR IGNORE INTO node_diagnostics (node_id) VALUES (?1)")?;
    let mut seen = HashSet::with_capacity(nodes.len());

    for node in nodes {
        if !seen.insert(node.hash) {
            continue;
        }
        let country = std::str::from_utf8(&node.meta.country_code).unwrap_or("UN");
        let payload = bincode::serialize(node)?;
        if insert_node.execute(params![
            &node.hash[..],
            node.meta.label.as_ref(),
            country,
            payload
        ])? == 1
        {
            inserted += 1;
        }
        let node_id: i64 = find_node.query_row(params![&node.hash[..]], |row| row.get(0))?;
        insert_diagnostics.execute(params![node_id])?;
        ids.push(node_id);
    }
    Ok((inserted, ids))
}

fn node_hash(node: &CanonicalNode) -> Result<CanonicalHash> {
    let identity = node.functional_identity_bytes()?;
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(identity).into())
}
