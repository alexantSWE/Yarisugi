use myproxy_ir::{CanonicalNode, EndpointTarget, ProtocolSpec};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

pub mod socket_health;

/// How deep a probe goes.
///
/// Only `L4Ping` is implemented end-to-end today. The deeper tiers are part of
/// the protocol roadmap: `ProtocolHandshake` needs per-protocol TLS (stock
/// rustls cannot replay uTLS client fingerprints) and `FullEgress204` needs a
/// working protocol client for the candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeDepth {
    L4Ping,
    ProtocolHandshake,
    FullEgress204,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFailure {
    Refused,
    TimedOut,
    Unresolvable,
    NoReply,
    Io,
}

#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub label: String,
    pub country_code: [u8; 2],
    pub protocol: &'static str,
    /// Socket round-trip in ms; missing for UDP targets that silently passed
    /// (L4 UDP cannot measure RTT without a real transcript).
    pub latency_ms: Option<u16>,
    pub alive: bool,
    pub failure: Option<ProbeFailure>,
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub concurrency_limit: usize,
    pub connect_timeout: Duration,
    pub udp_reply_window: Duration,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            // Modest: a firewalled ISP will start dropping/reputation-burning a
            // client that hammers thousands of peer addresses at once. Used by
            // the tiered shortlist's cheap sweep and the GUI burst alike.
            concurrency_limit: 512,
            connect_timeout: Duration::from_millis(800),
            udp_reply_window: Duration::from_millis(300),
        }
    }
}

#[derive(Clone)]
pub struct ProbeEngine {
    semaphore: Arc<Semaphore>,
    config: ProbeConfig,
}

impl ProbeEngine {
    pub fn new(config: ProbeConfig) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(config.concurrency_limit.max(1))),
            config,
        }
    }

    pub async fn probe(&self, node: &CanonicalNode, depth: ProbeDepth) -> ProbeOutcome {
        let (latency, failure) = match depth {
            ProbeDepth::L4Ping => self.ping(&node.endpoint, &node.protocol).await,
            _ => (None, Some(ProbeFailure::Io)),
        };
        build_outcome(node, latency, failure)
    }

    async fn ping(
        &self,
        endpoint: &EndpointTarget,
        protocol: &ProtocolSpec,
    ) -> (Option<u16>, Option<ProbeFailure>) {
        match endpoint {
            EndpointTarget::Ip(address) => self.probe_addr(address, protocol).await,
            EndpointTarget::Domain { host, port } => {
                let Ok(addresses) = lookup_host((host.as_ref(), *port)).await else {
                    return (None, Some(ProbeFailure::Unresolvable));
                };
                let addresses: Vec<SocketAddr> = addresses.collect();
                if addresses.is_empty() {
                    return (None, Some(ProbeFailure::Unresolvable));
                }
                let mut first_failure = None;
                for address in addresses {
                    let (latency, failure) = self.probe_addr(&address, protocol).await;
                    if latency.is_some() || failure.is_none() {
                        return (latency, failure);
                    }
                    if first_failure.is_none() {
                        first_failure = failure;
                    }
                }
                (None, first_failure.or(Some(ProbeFailure::Refused)))
            }
        }
    }

    async fn probe_addr(
        &self,
        address: &SocketAddr,
        protocol: &ProtocolSpec,
    ) -> (Option<u16>, Option<ProbeFailure>) {
        let _permit = match self.semaphore.acquire().await {
            Ok(permit) => permit,
            Err(_) => return (None, Some(ProbeFailure::Io)),
        };
        match protocol {
            ProtocolSpec::Shadowsocks(_)
            | ProtocolSpec::Vless(_)
            | ProtocolSpec::Vmess(_)
            | ProtocolSpec::Trojan(_) => match self.tcp_connect(address).await {
                Ok(rtt) => (Some(rtt), None),
                Err(failure) => (None, Some(failure)),
            },
            ProtocolSpec::Hysteria2(_)
            | ProtocolSpec::Tuic(_)
            | ProtocolSpec::WireGuard(_) => match self.udp_reach(address).await {
                Ok(Some(rtt)) => (Some(rtt), None),
                Ok(None) => (None, None),
                Err(failure) => (None, Some(failure)),
            },
        }
    }

    async fn tcp_connect(&self, address: &SocketAddr) -> Result<u16, ProbeFailure> {
        let started = Instant::now();
        match timeout(self.config.connect_timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                drop(stream);
                Ok(ms_elapsed(started))
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                Err(ProbeFailure::Refused)
            }
            Ok(Err(_)) => Err(ProbeFailure::Io),
            Err(_) => Err(ProbeFailure::TimedOut),
        }
    }

    async fn udp_reach(
        &self,
        address: &SocketAddr,
    ) -> Result<Option<u16>, ProbeFailure> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|_| ProbeFailure::Io)?;
        socket
            .connect(address)
            .await
            .map_err(|_| ProbeFailure::Io)?;
        let _ = socket.send(&[0u8; 1]).await;
        let started = Instant::now();
        let mut buffer = [0u8; 256];
        // A port-unreachable ICMP error surfaces on recv after the send; a
        // silently dropped target instead yields the window timeout.
        match timeout(self.config.udp_reply_window, socket.recv(&mut buffer)).await {
            Ok(Ok(_)) => Ok(Some(ms_elapsed(started))),
            Ok(Err(error)) => match error.kind() {
                std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::NetworkUnreachable => Err(ProbeFailure::Refused),
                _ => Ok(None),
            },
            Err(_) => Ok(None),
        }
    }
}

/// Probes every node concurrently, bounded by the engine semaphore. Result
/// order is not guaranteed; callers should sort by label.
pub async fn probe_batch(
    engine: &ProbeEngine,
    nodes: &[CanonicalNode],
    depth: ProbeDepth,
) -> Vec<ProbeOutcome> {
    let mut handles = Vec::with_capacity(nodes.len());
    for node in nodes {
        let node = node.clone();
        let engine = engine.clone();
        handles.push(tokio::spawn(async move { engine.probe(&node, depth).await }));
    }
    let mut results = Vec::with_capacity(nodes.len());
    for handle in handles {
        if let Ok(outcome) = handle.await {
            results.push(outcome);
        }
    }
    results
}

fn build_outcome(
    node: &CanonicalNode,
    latency: Option<u16>,
    failure: Option<ProbeFailure>,
) -> ProbeOutcome {
    let udp = matches!(
        node.protocol,
        ProtocolSpec::Hysteria2(_) | ProtocolSpec::Tuic(_) | ProtocolSpec::WireGuard(_)
    );
    let alive = latency.is_some() || (udp && failure.is_none());
    ProbeOutcome {
        label: node.meta.label.to_string(),
        country_code: node.meta.country_code,
        protocol: protocol_name(&node.protocol),
        latency_ms: latency,
        alive,
        failure,
    }
}

fn ms_elapsed(started: Instant) -> u16 {
    u16::try_from(started.elapsed().as_millis()).unwrap_or(u16::MAX / 2)
}

pub fn protocol_name(protocol: &ProtocolSpec) -> &'static str {
    match protocol {
        ProtocolSpec::Vless(_) => "vless",
        ProtocolSpec::Vmess(_) => "vmess",
        ProtocolSpec::Trojan(_) => "trojan",
        ProtocolSpec::Shadowsocks(_) => "ss",
        ProtocolSpec::Hysteria2(_) => "hysteria2",
        ProtocolSpec::Tuic(_) => "tuic",
        ProtocolSpec::WireGuard(_) => "wireguard",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myproxy_ir::{
        Hysteria2Config, NodeMetadata, ShadowsocksConfig, ShadowsocksCipher, TransportSpec,
    };
    use std::net::SocketAddr;
    use tokio::net::{TcpListener, UdpSocket};

    fn tcp_node(label: &str, address: SocketAddr) -> CanonicalNode {
        CanonicalNode::try_new(
            NodeMetadata::new(1, label, *b"DE", 1).unwrap(),
            EndpointTarget::Ip(address),
            ProtocolSpec::Shadowsocks(ShadowsocksConfig {
                method: ShadowsocksCipher::Aes128Gcm,
                password: "secret".into(),
                plugin: None,
                plugin_opts: None,
            }),
            TransportSpec::Tcp,
            myproxy_ir::SecuritySpec::None,
            None,
        )
        .unwrap()
    }

    fn udp_node(label: &str, address: SocketAddr) -> CanonicalNode {
        CanonicalNode::try_new(
            NodeMetadata::new(1, label, *b"DE", 1).unwrap(),
            EndpointTarget::Ip(address),
            ProtocolSpec::Hysteria2(Hysteria2Config {
                password: "secret".into(),
                up_mbps: None,
                down_mbps: None,
                obfs: None,
                port_hopping: None,
            }),
            TransportSpec::Tcp,
            myproxy_ir::SecuritySpec::None,
            None,
        )
        .unwrap()
    }

    fn engine() -> ProbeEngine {
        ProbeEngine::new(ProbeConfig {
            connect_timeout: Duration::from_millis(300),
            udp_reply_window: Duration::from_millis(100),
            ..ProbeConfig::default()
        })
    }

    #[tokio::test]
    async fn tcp_alive_on_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let node = tcp_node("loop", address);
        let outcome = engine().probe(&node, ProbeDepth::L4Ping).await;
        assert!(outcome.alive);
        assert!(outcome.latency_ms.is_some());
        assert!(outcome.failure.is_none());
    }

    #[tokio::test]
    async fn tcp_refused_on_closed_loopback_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let node = tcp_node("closed", address);
        let outcome = engine().probe(&node, ProbeDepth::L4Ping).await;
        assert!(!outcome.alive);
        assert_eq!(outcome.failure, Some(ProbeFailure::Refused));
    }

    #[tokio::test]
    async fn unreachable_domain_is_dead() {
        let node = tcp_node(
            "nowhere",
            SocketAddr::from(([127, 0, 0, 1], 1)),
        );
        let node = CanonicalNode::try_new(
            node.meta.clone(),
            EndpointTarget::domain("nonexistent.invalid", 443).unwrap(),
            node.protocol.clone(),
            node.transport.clone(),
            node.security.clone(),
            None,
        )
        .unwrap();
        let outcome = engine().probe(&node, ProbeDepth::L4Ping).await;
        assert!(!outcome.alive);
        assert_eq!(outcome.failure, Some(ProbeFailure::Unresolvable));
    }

    #[tokio::test]
    async fn udp_silent_pass_counts_as_alive() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let node = udp_node("hy2", address);
        let outcome = engine().probe(&node, ProbeDepth::L4Ping).await;
        assert!(outcome.alive);
        assert!(outcome.latency_ms.is_none());
        assert!(outcome.failure.is_none());
    }

    #[tokio::test]
    async fn udp_icmp_refused_on_closed_loopback_port() {
        let node = udp_node("hy2-dead", "127.0.0.1:62999".parse().unwrap());
        let outcome = engine().probe(&node, ProbeDepth::L4Ping).await;
        assert!(!outcome.alive);
        assert_eq!(outcome.failure, Some(ProbeFailure::Refused));
    }

    #[tokio::test]
    async fn unimplemented_depths_report_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = tcp_node("deep", listener.local_addr().unwrap());
        let outcome = engine().probe(&node, ProbeDepth::FullEgress204).await;
        assert!(!outcome.alive);
    }

    #[tokio::test]
    async fn batch_preserves_individual_results() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = tcp_node("good", listener.local_addr().unwrap());
        let bad = tcp_node(
            "closed",
            SocketAddr::new(listener.local_addr().unwrap().ip(), 1),
        );
        let results = probe_batch(&engine(), &[good, bad], ProbeDepth::L4Ping).await;
        let alive = results.iter().filter(|outcome| outcome.alive).count();
        assert_eq!(alive, 1);
    }
}