mod adapter;
mod protocol;
mod transport;

pub use adapter::{CoreAdapter, CoreCapabilities, CoreCapability};
pub use protocol::{
    Hysteria2Config, Hysteria2Obfs, ProtocolSpec, ShadowsocksCipher, ShadowsocksConfig,
    TrojanConfig, TuicConfig, TuicCongestion, TuicUdpRelay, VlessConfig, VlessFlow, VmessCipher,
    VmessConfig, WireGuardConfig,
};
pub use transport::{
    GrpcConfig, HttpUpgradeConfig, MuxProtocol, MuxSpec, RealityConfig, SecuritySpec,
    StandardTlsConfig, TransportSpec, UtlsFingerprint, WebSocketConfig, XHttpConfig, XHttpMode,
};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub type NodeId = u32;
pub type SubId = u16;
pub type CanonicalHash = [u8; 32];

/// Increment when the functional identity encoding changes incompatibly.
pub const CANONICAL_HASH_VERSION: u8 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalNode {
    pub hash: CanonicalHash,
    pub meta: NodeMetadata,
    pub endpoint: EndpointTarget,
    pub protocol: ProtocolSpec,
    pub transport: TransportSpec,
    pub security: SecuritySpec,
    pub mux: Option<MuxSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeMetadata {
    pub sub_id: SubId,
    pub label: Arc<str>,
    pub country_code: [u8; 2],
    pub import_timestamp: u64,
}

impl NodeMetadata {
    pub fn new(
        sub_id: SubId,
        label: impl Into<Arc<str>>,
        country_code: [u8; 2],
        import_timestamp: u64,
    ) -> Result<Self> {
        if !country_code.iter().all(u8::is_ascii_uppercase) {
            bail!("country code must use uppercase ASCII letters");
        }
        Ok(Self {
            sub_id,
            label: label.into(),
            country_code,
            import_timestamp,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointTarget {
    Ip(SocketAddr),
    Domain { host: Arc<str>, port: u16 },
}

impl EndpointTarget {
    pub fn ip(address: SocketAddr) -> Self {
        Self::Ip(address)
    }

    pub fn domain(host: impl AsRef<str>, port: u16) -> Result<Self> {
        if port == 0 {
            bail!("endpoint port cannot be zero");
        }
        let normalized = normalize_host(host.as_ref())?;
        Ok(Self::Domain {
            host: normalized.into(),
            port,
        })
    }

    fn normalize(&self) -> Result<Self> {
        match self {
            Self::Ip(address) if address.port() != 0 => Ok(self.clone()),
            Self::Ip(_) => bail!("endpoint port cannot be zero"),
            Self::Domain { host, port } => Self::domain(host.as_ref(), *port),
        }
    }
}

#[derive(Serialize)]
struct FunctionalIdentity<'a> {
    version: u8,
    endpoint: &'a EndpointTarget,
    protocol: &'a ProtocolSpec,
    transport: &'a TransportSpec,
    security: &'a SecuritySpec,
    mux: &'a Option<MuxSpec>,
}

impl CanonicalNode {
    pub fn try_new(
        meta: NodeMetadata,
        endpoint: EndpointTarget,
        protocol: ProtocolSpec,
        transport: TransportSpec,
        security: SecuritySpec,
        mux: Option<MuxSpec>,
    ) -> Result<Self> {
        let endpoint = endpoint.normalize()?;
        let mux = mux.filter(|value| value.enabled);
        let identity = FunctionalIdentity {
            version: CANONICAL_HASH_VERSION,
            endpoint: &endpoint,
            protocol: &protocol,
            transport: &transport,
            security: &security,
            mux: &mux,
        };
        let bytes = bincode::serialize(&identity)?;
        let hash = Sha256::digest(bytes).into();
        Ok(Self {
            hash,
            meta,
            endpoint,
            protocol,
            transport,
            security,
            mux,
        })
    }

    pub fn functional_identity_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&FunctionalIdentity {
            version: CANONICAL_HASH_VERSION,
            endpoint: &self.endpoint,
            protocol: &self.protocol,
            transport: &self.transport,
            security: &self.security,
            mux: &self.mux,
        })?)
    }

    pub fn hash_hex(&self) -> String {
        self.hash.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

fn normalize_host(host: &str) -> Result<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.contains('/')
        || host.contains(char::is_whitespace)
    {
        bail!("invalid endpoint hostname");
    }
    if host.parse::<IpAddr>().is_ok() {
        bail!("IP addresses must use EndpointTarget::Ip");
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn node(label: &'static str, sub_id: SubId) -> CanonicalNode {
        let metadata = NodeMetadata::new(sub_id, label, *b"DE", 1).unwrap();
        CanonicalNode::try_new(
            metadata,
            EndpointTarget::domain("Example.COM.", 443).unwrap(),
            ProtocolSpec::Vless(VlessConfig {
                uuid: Uuid::nil(),
                flow: Some(VlessFlow::XtlsRprxVision),
            }),
            TransportSpec::Tcp,
            SecuritySpec::None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn metadata_does_not_change_functional_hash() {
        assert_eq!(node("Frankfurt", 1).hash, node("VIP Frankfurt", 2).hash);
    }

    #[test]
    fn hostnames_are_normalized_before_hashing() {
        let first = node("one", 1);
        let metadata = NodeMetadata::new(1, "two", *b"DE", 2).unwrap();
        let second = CanonicalNode::try_new(
            metadata,
            EndpointTarget::domain("example.com", 443).unwrap(),
            first.protocol.clone(),
            first.transport.clone(),
            first.security.clone(),
            None,
        )
        .unwrap();
        assert_eq!(first.hash, second.hash);
    }

    #[test]
    fn disabled_mux_is_not_a_distinct_identity() {
        let plain = node("plain", 1);
        let metadata = NodeMetadata::new(1, "mux", *b"DE", 2).unwrap();
        let disabled = CanonicalNode::try_new(
            metadata,
            plain.endpoint.clone(),
            plain.protocol.clone(),
            plain.transport.clone(),
            plain.security.clone(),
            Some(MuxSpec {
                enabled: false,
                concurrency: 32,
                protocol: MuxProtocol::Smux,
            }),
        )
        .unwrap();
        assert_eq!(plain.hash, disabled.hash);
        assert!(disabled.mux.is_none());
    }
}
