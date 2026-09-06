use anyhow::{Context, Result};
use myproxy_ir::{CanonicalNode, ProtocolSpec};
use rusqlite::Connection;
use std::collections::HashMap;

pub const UNTESTED_LATENCY: u16 = u16::MAX;

/// A compact protocol label suitable for the hot query/rendering path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolKind {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Tuic,
    WireGuard,
}

impl ProtocolKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Vless => "VLESS",
            Self::Vmess => "VMess",
            Self::Trojan => "Trojan",
            Self::Shadowsocks => "SS",
            Self::Hysteria2 => "HY2",
            Self::Tuic => "TUIC",
            Self::WireGuard => "WireGuard",
        }
    }
}

impl From<&ProtocolSpec> for ProtocolKind {
    fn from(value: &ProtocolSpec) -> Self {
        match value {
            ProtocolSpec::Vless(_) => Self::Vless,
            ProtocolSpec::Vmess(_) => Self::Vmess,
            ProtocolSpec::Trojan(_) => Self::Trojan,
            ProtocolSpec::Shadowsocks(_) => Self::Shadowsocks,
            ProtocolSpec::Hysteria2(_) => Self::Hysteria2,
            ProtocolSpec::Tuic(_) => Self::Tuic,
            ProtocolSpec::WireGuard(_) => Self::WireGuard,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HotNodeRow {
    pub id: u32,
    pub country_code: [u8; 2],
    pub latency_ms: u16,
    pub health_score: u8,
    pub name: Box<str>,
    pub protocol: ProtocolKind,
    pub source_sub_ids: Vec<u16>,
}

#[derive(Clone, Debug, Default)]
pub struct DenseNodeStore {
    pub node_ids: Vec<u32>,
    pub country_codes: Vec<[u8; 2]>,
    pub latencies_ms: Vec<u16>,
    pub health_scores: Vec<u8>,
    pub protocol_kinds: Vec<ProtocolKind>,
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
            protocol_kinds: Vec::with_capacity(capacity),
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
            r#"SELECT n.id, n.country_code, n.name, n.raw_payload,
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
            let payload: Vec<u8> = row.get(3)?;
            let node: CanonicalNode = bincode::deserialize(&payload)
                .context("stored canonical node payload could not be decoded")?;
            let latency: u16 = row.get(4)?;
            let health: u8 = row.get(5)?;
            let index = store.node_ids.len();
            store.node_ids.push(id);
            store.country_codes.push(country);
            store.latencies_ms.push(latency);
            store.health_scores.push(health);
            store
                .protocol_kinds
                .push(ProtocolKind::from(&node.protocol));
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

    /// Builds a dense snapshot without SQLite. This is used by the GUI's
    /// deterministic development fixture and keeps the same SOA invariants.
    pub fn from_hot_rows(rows: impl IntoIterator<Item = HotNodeRow>) -> Self {
        let rows = rows.into_iter().collect::<Vec<_>>();
        let mut store = Self::with_capacity(rows.len());
        store.source_offsets.push(0);
        for row in rows {
            let index = store.node_ids.len();
            store.node_ids.push(row.id);
            store.country_codes.push(row.country_code);
            store.latencies_ms.push(row.latency_ms);
            store.health_scores.push(row.health_score.min(100));
            store.protocol_kinds.push(row.protocol);
            store
                .name_lower
                .push(row.name.to_lowercase().into_boxed_str());
            store.names.push(row.name);
            store.id_to_index.insert(store.node_ids[index], index);
            store.source_sub_ids.extend(row.source_sub_ids);
            store.source_offsets.push(store.source_sub_ids.len() as u32);
        }
        store
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
