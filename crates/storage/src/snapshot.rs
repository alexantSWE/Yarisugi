use anyhow::Result;
use arc_swap::{ArcSwap, Guard};
use rusqlite::Connection;
use std::sync::Arc;

use crate::DenseNodeStore;

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

    pub fn replace_from_db(&self, connection: &Connection) -> Result<()> {
        let replacement = Arc::new(DenseNodeStore::hydrate_from_db(connection)?);
        self.store.store(replacement);
        Ok(())
    }
}
