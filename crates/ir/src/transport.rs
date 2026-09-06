use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportSpec {
    Tcp,
    WebSocket(WebSocketConfig),
    Grpc(GrpcConfig),
    HttpUpgrade(HttpUpgradeConfig),
    XHttp(XHttpConfig),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketConfig {
    pub path: Arc<str>,
    pub host: Option<Arc<str>>,
    pub max_early_data: u32,
    pub early_data_header: Option<Arc<str>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrpcConfig {
    pub service_name: Arc<str>,
    pub multi_mode: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpUpgradeConfig {
    pub path: Arc<str>,
    pub host: Option<Arc<str>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XHttpConfig {
    pub mode: XHttpMode,
    pub path: Arc<str>,
    pub host: Option<Arc<str>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum XHttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecuritySpec {
    None,
    Tls(StandardTlsConfig),
    Reality(RealityConfig),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardTlsConfig {
    pub server_name: Arc<str>,
    pub alpn: Vec<Arc<str>>,
    pub fingerprint: UtlsFingerprint,
    pub allow_insecure: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityConfig {
    pub server_name: Arc<str>,
    pub public_key: Arc<str>,
    pub short_id: Arc<str>,
    pub spider_x: Option<Arc<str>>,
    pub fingerprint: UtlsFingerprint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UtlsFingerprint {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Randomized,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MuxSpec {
    pub enabled: bool,
    pub concurrency: u16,
    pub protocol: MuxProtocol,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MuxProtocol {
    Smux,
    Yamux,
    H2Mux,
}
