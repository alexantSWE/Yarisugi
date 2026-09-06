use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub const PROTOCOL_VERSION: u32 = 1;
pub const WATCHDOG_TIMEOUT_SECS: u64 = 5;
pub const HEARTBEAT_INTERVAL_SECS: u64 = 2;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const DEFAULT_SOCKET_PATH: &str = "/run/myproxy/netd.sock";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetdRequest {
    Handshake {
        client_version: u32,
    },
    EnableRouting {
        session_id: u64,
        tproxy_port: u16,
        proxy_fwmark: u32,
        table_id: u32,
        dns_ipv4: Option<Ipv4Addr>,
        bypass_subnets: Vec<String>,
    },
    DisableRouting {
        session_id: u64,
    },
    Heartbeat {
        session_id: u64,
        sequence: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetdResponse {
    HandshakeOk {
        daemon_version: u32,
        session_id: u64,
    },
    RoutingEnabled,
    RoutingDisabled,
    HeartbeatAck {
        sequence: u64,
    },
    State {
        routing_active: bool,
    },
    Error(String),
}
