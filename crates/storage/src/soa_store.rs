use anyhow::Result;
use rusqlite::Connection;
use std::collections::HashMap;

pub const UNTESTED_LATENCY: u16 = u16::MAX;

#[derive(Clone, Debug, Default)]
pub struct DenseNodeStore {
    pub node_ids: Vec<u32>,
    pub country_codes: Vec<[u8; 2]>,
    pub latencies_ms: Vec<u16>,
    pub health_scores: Vec<u8>,
    pub names: Vec<Box<str>>,
    pub name_lower: Vec<Box<str>>,
    pub source_offsets: Vec<u32>,
    pub source_sub_ids: Vec<u16>,
    id_to_index: HashMap<u32, usize>,
}

impl DenseNodeStore {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            node_ids: Vec::with_capacity(capacity),
            country_codes: Vec::with_capacity(capacity),
            latencies_ms: Vec::with_capacity(capacity),
            health_scores: Vec::with_capacity(capacity),
            names: Vec::with_capacity(capacity),
            name_lower: Vec::with_capacity(capacity),
            source_offsets: Vec::with_capacity(capacity + 1),
            source_sub_ids: Vec::with_capacity(capacity),
            id_to_index: HashMap::with_capacity(capacity),
        }
    }

    pub fn hydrate_from_db(connection: &Connection) -> Result<Self> {
        let mut store = Self::with_capacity(50_000);
        let mut statement = connection.prepare(
            r#"SELECT n.id, n.country_code, n.name,
                      COALESCE(d.latency_ms, 65535), COALESCE(d.health_score, 0)
               FROM nodes n
               LEFT JOIN node_diagnostics d ON d.node_id = n.id
               ORDER BY n.id"#,
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id: u32 = row.get(0)?;
            let country = country_code(row.get::<_, String>(1)?.as_bytes());
            let name: String = row.get(2)?;
            let latency: u16 = row.get(3)?;
            let health: u8 = row.get(4)?;
            let index = store.node_ids.len();
            store.node_ids.push(id);
            store.country_codes.push(country);
            store.latencies_ms.push(latency);
            store.health_scores.push(health);
            store.name_lower.push(name.to_lowercase().into_boxed_str());
            store.names.push(name.into_boxed_str());
            store.id_to_index.insert(id, index);
        }
        let mut sources = vec![Vec::<u16>::new(); store.len()];
        let mut source_statement = connection
            .prepare("SELECT node_id, sub_id FROM node_sources ORDER BY node_id, sub_id")?;
        let mut source_rows = source_statement.query([])?;
        while let Some(source_row) = source_rows.next()? {
            let node_id: u32 = source_row.get(0)?;
            let sub_id: u16 = source_row.get(1)?;
            if let Some(&index) = store.id_to_index.get(&node_id) {
                sources[index].push(sub_id);
            }
        }
        store.source_offsets.push(0);
        for source_ids in sources {
            store.source_sub_ids.extend(source_ids);
            store.source_offsets.push(store.source_sub_ids.len() as u32);
        }
        Ok(store)
    }

    pub fn len(&self) -> usize {
        self.node_ids.len()
    }
    pub fn is_empty(&self) -> bool {
        self.node_ids.is_empty()
    }

    pub fn update_metrics(&mut self, node_id: u32, latency_ms: u16, health_score: u8) {
        if let Some(&index) = self.id_to_index.get(&node_id) {
            self.latencies_ms[index] = latency_ms;
            self.health_scores[index] = health_score.min(100);
        }
    }

    pub fn has_source(&self, index: usize, sub_id: u16) -> bool {
        let start = self.source_offsets[index] as usize;
        let end = self.source_offsets[index + 1] as usize;
        self.source_sub_ids[start..end].contains(&sub_id)
    }
}

fn country_code(bytes: &[u8]) -> [u8; 2] {
    if bytes.len() == 2 && bytes[0].is_ascii_uppercase() && bytes[1].is_ascii_uppercase() {
        [bytes[0], bytes[1]]
    } else {
        *b"UN"
    }
}
