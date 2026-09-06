mod db;
mod query_engine;
mod repository;
mod snapshot;
mod soa_store;

pub use db::{open_database, open_memory_database};
pub use query_engine::{query, SortCriteria};
pub use repository::{NodeRepository, SubscriptionRecord, SyncResult};
pub use snapshot::StoreSnapshot;
pub use soa_store::{DenseNodeStore, UNTESTED_LATENCY};

#[cfg(test)]
mod tests {
    use super::*;
    use myproxy_ir::{
        CanonicalNode, EndpointTarget, NodeMetadata, ProtocolSpec, SecuritySpec, TransportSpec,
        VlessConfig,
    };
    use myproxy_parser::IngestionReport;
    use uuid::Uuid;

    fn node(label: &str) -> CanonicalNode {
        CanonicalNode::try_new(
            NodeMetadata::new(1, label, *b"DE", 1).unwrap(),
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
    fn duplicate_nodes_keep_both_subscription_sources() {
        let connection = open_memory_database().unwrap();
        NodeRepository::upsert_subscription(
            &connection,
            SubscriptionRecord {
                id: 1,
                uuid: "one",
                name: "One",
                url: "https://one",
                last_updated: 1,
                auto_update_interval: 86400,
                etag: None,
            },
        )
        .unwrap();
        NodeRepository::upsert_subscription(
            &connection,
            SubscriptionRecord {
                id: 2,
                uuid: "two",
                name: "Two",
                url: "https://two",
                last_updated: 1,
                auto_update_interval: 86400,
                etag: None,
            },
        )
        .unwrap();
        let first = node("First");
        let second = node("Second");
        let tx = connection.unchecked_transaction().unwrap();
        assert_eq!(
            NodeRepository::bulk_insert_nodes(&tx, 1, &[first.clone()]).unwrap(),
            1
        );
        assert_eq!(
            NodeRepository::bulk_insert_nodes(&tx, 2, &[second]).unwrap(),
            0
        );
        tx.commit().unwrap();
        let store = DenseNodeStore::hydrate_from_db(&connection).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.has_source(0, 1));
        assert!(store.has_source(0, 2));
        assert_eq!(
            query(&store, "first", None, Some(2), SortCriteria::NameAsc),
            vec![0]
        );
    }

    fn subscription(id: u16) -> SubscriptionRecord<'static> {
        SubscriptionRecord {
            id,
            uuid: if id == 1 { "one" } else { "two" },
            name: "Test subscription",
            url: "https://example.invalid/subscription",
            last_updated: 1,
            auto_update_interval: 86400,
            etag: None,
        }
    }

    #[test]
    fn sync_replaces_sources_and_collects_only_orphans() {
        let connection = open_memory_database().unwrap();
        let shared = node("Shared");
        let report = IngestionReport {
            total_entries_scanned: 1,
            successful_nodes: vec![shared],
            duplicates_omitted: 0,
            failed_entries: Vec::new(),
        };

        NodeRepository::sync_subscription(&connection, subscription(1), &report, false).unwrap();
        NodeRepository::sync_subscription(&connection, subscription(2), &report, false).unwrap();
        let empty = IngestionReport::default();

        let result =
            NodeRepository::sync_subscription(&connection, subscription(1), &empty, true).unwrap();
        assert_eq!(result.removed_orphans, 0);
        assert_eq!(
            DenseNodeStore::hydrate_from_db(&connection).unwrap().len(),
            1
        );

        let result =
            NodeRepository::sync_subscription(&connection, subscription(2), &empty, true).unwrap();
        assert_eq!(result.removed_orphans, 1);
        assert_eq!(
            DenseNodeStore::hydrate_from_db(&connection).unwrap().len(),
            0
        );
    }

    #[test]
    fn empty_refresh_is_rejected_by_default() {
        let connection = open_memory_database().unwrap();
        let report = IngestionReport::default();
        assert!(
            NodeRepository::sync_subscription(&connection, subscription(1), &report, false)
                .is_err()
        );
    }

    #[test]
    fn snapshot_replaces_without_mutating_existing_readers() {
        let connection = open_memory_database().unwrap();
        let snapshot = StoreSnapshot::new(DenseNodeStore::default());
        assert_eq!(snapshot.load().len(), 0);
        let report = IngestionReport {
            total_entries_scanned: 1,
            successful_nodes: vec![node("Snapshot")],
            duplicates_omitted: 0,
            failed_entries: Vec::new(),
        };
        NodeRepository::sync_subscription(&connection, subscription(1), &report, false).unwrap();
        snapshot.replace_from_db(&connection).unwrap();
        assert_eq!(snapshot.load().len(), 1);
    }
}
