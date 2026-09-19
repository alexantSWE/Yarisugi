use anyhow::Result;
use arc_swap::{ArcSwap, Guard};
use rusqlite::Connection;
use std::sync::Arc;

use crate::{DenseNodeStore, MetricsArena};

#[derive(Clone, Copy, Debug)]
pub struct MetricUpdate {
    pub node_id: u32,
    pub latency_ms: u16,
    pub health_score: u8,
}

/// Two independently published layers: a cold node store and a hot metric
/// arena. Both are aligned by dense index so metric updates resolve node ids
/// against the store's index map without cloning the full store.
pub struct StoreSnapshot {
    store: ArcSwap<DenseNodeStore>,
    metrics: ArcSwap<MetricsArena>,
}

impl StoreSnapshot {
    pub fn new(store: DenseNodeStore) -> Self {
        let metrics = MetricsArena::from_store(&store);
        Self {
            store: ArcSwap::from_pointee(store),
            metrics: ArcSwap::from_pointee(metrics),
        }
    }

    pub fn load(&self) -> Guard<Arc<DenseNodeStore>> {
        self.store.load()
    }

    pub fn load_full(&self) -> Arc<DenseNodeStore> {
        self.store.load_full()
    }

    pub fn load_metrics(&self) -> Guard<Arc<MetricsArena>> {
        self.metrics.load()
    }

    pub fn replace(&self, store: DenseNodeStore) -> Arc<DenseNodeStore> {
        let store = Arc::new(store);
        let metrics = Arc::new(MetricsArena::from_store(&store));
        self.store.store(Arc::clone(&store));
        self.metrics.store(metrics);
        store
    }

    /// Publishes metric updates by copy-on-write over the hot arena only and
    /// swaps it atomically. Existing readers retain their immutable metrics for
    /// the duration of their frame.
    pub fn publish_metrics(&self, updates: &[MetricUpdate]) -> Arc<MetricsArena> {
        let mut replacement = (*self.metrics.load_full()).clone();
        let store = self.store.load();
        for update in updates {
            if let Some(index) = store.index_of(update.node_id) {
                replacement.apply_update(index, update.latency_ms, update.health_score);
            }
        }
        let replacement = Arc::new(replacement);
        self.metrics.store(Arc::clone(&replacement));
        replacement
    }

    /// Applies a batch by copy-on-write over the whole store and publishes it
    /// atomically. The hot arena is rebuilt to stay aligned with the new store.
    pub fn update_metrics_batch(&self, updates: &[MetricUpdate]) -> Arc<DenseNodeStore> {
        let mut replacement = (*self.load_full()).clone();
        for update in updates {
            replacement.update_metrics(update.node_id, update.latency_ms, update.health_score);
        }
        self.replace(replacement)
    }

    pub fn replace_from_db(&self, connection: &Connection) -> Result<()> {
        self.replace(DenseNodeStore::hydrate_from_db(connection)?);
        Ok(())
    }
}