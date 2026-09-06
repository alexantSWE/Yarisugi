use anyhow::Result;
use arc_swap::{ArcSwap, Guard};
use rusqlite::Connection;
use std::sync::Arc;

use crate::DenseNodeStore;

#[derive(Clone, Copy, Debug)]
pub struct MetricUpdate {
    pub node_id: u32,
    pub latency_ms: u16,
    pub health_score: u8,
}

pub struct StoreSnapshot {
    store: ArcSwap<DenseNodeStore>,
}

impl StoreSnapshot {
    pub fn new(store: DenseNodeStore) -> Self {
        Self {
            store: ArcSwap::from_pointee(store),
        }
    }

    pub fn load(&self) -> Guard<Arc<DenseNodeStore>> {
        self.store.load()
    }

    pub fn load_full(&self) -> Arc<DenseNodeStore> {
        self.store.load_full()
    }

    pub fn replace(&self, store: DenseNodeStore) -> Arc<DenseNodeStore> {
        let store = Arc::new(store);
        self.store.store(Arc::clone(&store));
        store
    }

    /// Applies a batch by copy-on-write and publishes it atomically. Existing
    /// readers retain their immutable snapshot for the duration of their frame.
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
