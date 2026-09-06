use crate::CanonicalNode;
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoreCapability {
    Vless,
    VlessReality,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Tuic,
    WireGuard,
    WebSocket,
    Grpc,
    HttpUpgrade,
    XHttp,
    Multiplexing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreCapabilities {
    pub core_name: String,
    pub version: String,
    pub supported: BTreeSet<CoreCapability>,
}

impl CoreCapabilities {
    pub fn supports(&self, capability: CoreCapability) -> bool {
        self.supported.contains(&capability)
    }
}

pub trait CoreAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn probe_capabilities(&self, binary_path: &Path) -> Result<CoreCapabilities>;
    fn compile_outbound(&self, node: &CanonicalNode, caps: &CoreCapabilities) -> Result<Value>;
    fn validate_config(&self, binary_path: &Path, config_json: &[u8]) -> Result<()>;
}
