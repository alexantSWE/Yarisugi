use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolSpec {
    Vless(VlessConfig),
    Vmess(VmessConfig),
    Trojan(TrojanConfig),
    Shadowsocks(ShadowsocksConfig),
    Hysteria2(Hysteria2Config),
    Tuic(TuicConfig),
    WireGuard(WireGuardConfig),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessConfig {
    pub uuid: Uuid,
    pub flow: Option<VlessFlow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VlessFlow {
    XtlsRprxVision,
    XtlsRprxVisionUdp443,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmessConfig {
    pub uuid: Uuid,
    pub alter_id: u16,
    pub cipher: VmessCipher,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmessCipher {
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrojanConfig {
    pub password: Arc<str>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    pub method: ShadowsocksCipher,
    pub password: Arc<str>,
    pub plugin: Option<Arc<str>>,
    pub plugin_opts: Option<Arc<str>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowsocksCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
    Ss2022Blake3Aes128Gcm,
    Ss2022Blake3Aes256Gcm,
    Ss2022Blake3Chacha20Poly1305,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hysteria2Config {
    pub password: Arc<str>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub obfs: Option<Hysteria2Obfs>,
    pub port_hopping: Option<Arc<str>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hysteria2Obfs {
    pub obfs_type: Arc<str>,
    pub password: Arc<str>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuicConfig {
    pub uuid: Uuid,
    pub password: Arc<str>,
    pub congestion_control: TuicCongestion,
    pub udp_relay_mode: TuicUdpRelay,
    pub zero_rtt_handshake: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TuicCongestion {
    Bbr,
    Cubic,
    NewReno,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TuicUdpRelay {
    Native,
    Quic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardConfig {
    pub private_key: Arc<str>,
    pub peer_public_key: Arc<str>,
    pub preshared_key: Option<Arc<str>>,
    pub local_address: Vec<IpAddr>,
    pub reserved: Option<[u8; 3]>,
    pub mtu: Option<u16>,
}
