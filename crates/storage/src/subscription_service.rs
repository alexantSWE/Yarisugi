use anyhow::Result;
use myproxy_parser::{ingest_with_timestamp, IngestionReport};
use rusqlite::Connection;

use crate::{NodeRepository, StoreSnapshot, SubscriptionRecord, SyncResult};

/// The outcome of parsing and atomically replacing one subscription snapshot.
///
/// Parse failures are preserved in the report. They do not abort a refresh if
/// at least one valid node was parsed. An empty or entirely invalid payload is
/// protected by default and cannot clear an existing subscription.
#[derive(Debug)]
pub struct SubscriptionRefresh {
    pub report: IngestionReport,
    pub sync: SyncResult,
}

pub struct SubscriptionService;

impl SubscriptionService {
    pub fn refresh(
        connection: &Connection,
        record: SubscriptionRecord<'_>,
        raw_payload: &[u8],
        allow_empty: bool,
    ) -> Result<SubscriptionRefresh> {
        let report = ingest_with_timestamp(raw_payload, record.id, record.last_updated);
        let sync = NodeRepository::sync_subscription(connection, record, &report, allow_empty)?;
        Ok(SubscriptionRefresh { report, sync })
    }

    /// Refreshes persistence first, then makes its corresponding dense snapshot
    /// visible to readers with one atomic store publication.
    pub fn refresh_and_publish(
        connection: &Connection,
        snapshot: &StoreSnapshot,
        record: SubscriptionRecord<'_>,
        raw_payload: &[u8],
        allow_empty: bool,
    ) -> Result<SubscriptionRefresh> {
        let refresh = Self::refresh(connection, record, raw_payload, allow_empty)?;
        snapshot.replace_from_db(connection)?;
        Ok(refresh)
    }
}
