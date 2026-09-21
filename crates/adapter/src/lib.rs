use anyhow::{bail, Context, Result};
use myproxy_ir::{
    CanonicalNode, CoreAdapter, CoreCapabilities, CoreCapability, EndpointTarget, MuxProtocol,
    MuxSpec, ProtocolSpec, SecuritySpec, TransportSpec, UtlsFingerprint, VlessFlow,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

pub mod egress;
pub mod supervisor;

/// Compiles canonical nodes into sing-box JSON. The adapter is the shim between
/// the IR and the core: `compile_outbound` produces a ready-to-embed outbound,
/// `compile_full_config` assembles the tproxy + routing skeleton around it.
#[derive(Default)]
pub struct SingboxAdapter;

impl SingboxAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl CoreAdapter for SingboxAdapter {
    fn name(&self) -> &'static str {
        "sing-box"
    }

    fn probe_capabilities(&self, binary_path: &Path) -> Result<CoreCapabilities> {
        let version = Command::new(binary_path)
            .arg("version")
            .output()
            .with_context(|| format!("failed to run `{} version`", binary_path.display()))?;
        if !version.status.success() {
            bail!("sing-box failed to report its version");
        }
        let first_line = String::from_utf8_lossy(&version.stdout)
            .lines()
            .next()
            .unwrap_or("unknown")
            .to_owned();
        Ok(CoreCapabilities {
            core_name: "sing-box".into(),
            version: first_line,
            supported: BTreeSet::from([
                CoreCapability::Vless,
                CoreCapability::VlessReality,
                CoreCapability::Vmess,
                CoreCapability::Trojan,
                CoreCapability::Shadowsocks,
                CoreCapability::Hysteria2,
                CoreCapability::Tuic,
                CoreCapability::WireGuard,
                CoreCapability::WebSocket,
                CoreCapability::Grpc,
                CoreCapability::HttpUpgrade,
                CoreCapability::XHttp,
                CoreCapability::Multiplexing,
            ]),
        })
    }

    fn compile_outbound(
        &self,
        node: &CanonicalNode,
        _capabilities: &CoreCapabilities,
    ) -> Result<Value> {
        compile_outbound(node)
    }

    fn validate_config(&self, binary_path: &Path, config_json: &[u8]) -> Result<()> {
        use std::io::Write;
        let dir = std::env::temp_dir().join("myproxy-adapter");
        std::fs::create_dir_all(&dir)?;
        let config_path = dir.join("config.json");
        let mut file = std::fs::File::create(&config_path)?;
        file.write_all(config_json)?;
        file.flush()?;
        let output = Command::new(binary_path)
            .args(["check", "-c"])
            .arg(&config_path)
            .stdin(Stdio::null())
            .output()
            .with_context(|| {
                format!("failed to run `{} check -c {config_path:?}`", binary_path.display())
            })?;
        if !output.status.success() {
            bail!(
                "sing-box rejected the config: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
}

pub fn compile_outbound(node: &CanonicalNode) -> Result<Value> {
    let (server, port) = match &node.endpoint {
        EndpointTarget::Ip(address) => (address.ip().to_string(), address.port()),
        EndpointTarget::Domain { host, port } => (host.to_string(), *port),
    };
    let mut builder = OutboundBuilder::new(node)
        .server(&server)?
        .server_port(port)
        .tag(node.meta.label.as_ref());
    match &node.protocol {
        ProtocolSpec::Vless(config) => {
            builder.set("type", "vless");
            builder.set("uuid", config.uuid.to_string());
            if let Some(flow) = &config.flow {
                builder.set("flow", flow_name(*flow));
            }
            builder.set("packet_encoding", "xudp");
            builder.embed_transport(&node.transport);
            builder.embed_security(&node.security);
            builder.embed_mux(&node.mux);
        }
        ProtocolSpec::Vmess(config) => {
            builder.set("type", "vmess");
            builder.set("uuid", config.uuid.to_string());
            builder.set("alter_id", config.alter_id);
            builder.set("security", cipher_name(&config.cipher));
            builder.embed_transport(&node.transport);
            builder.embed_security(&node.security);
            builder.embed_mux(&node.mux);
        }
        ProtocolSpec::Trojan(config) => {
            builder.set("type", "trojan");
            builder.set("password", config.password.to_string());
            builder.embed_transport(&node.transport);
            builder.embed_security(&node.security);
            builder.embed_mux(&node.mux);
        }
        ProtocolSpec::Shadowsocks(config) => {
            builder.set("type", "shadowsocks");
            builder.set("method", ss_method(&config.method));
            builder.set("password", config.password.to_string());
            if let Some(plugin) = &config.plugin {
                builder.set("plugin", plugin.to_string());
                if let Some(opts) = &config.plugin_opts {
                    builder.set("plugin_opts", opts.to_string());
                }
            }
        }
        ProtocolSpec::Hysteria2(config) => {
            builder.set("type", "hysteria2");
            builder.set("password", config.password.to_string());
            if let Some(up) = config.up_mbps {
                builder.set("up_mbps", up);
            }
            if let Some(down) = config.down_mbps {
                builder.set("down_mbps", down);
            }
            if let Some(obfs) = &config.obfs {
                builder.set(
                    "obfs",
                    json!({ "type": obfs.obfs_type, "password": obfs.password }),
                );
            }
            if let Some(port_hopping) = &config.port_hopping {
                builder.set("port_hopping", port_hopping.to_string());
            }
        }
        ProtocolSpec::Tuic(config) => {
            builder.set("type", "tuic");
            builder.set("uuid", config.uuid.to_string());
            builder.set("password", config.password.to_string());
            builder.set("congestion_control", congestion_name(&config.congestion_control));
            builder.set("udp_relay_mode", relay_mode(&config.udp_relay_mode));
            builder.set(
                "zero_rtt_handshake",
                config.zero_rtt_handshake,
            );
        }
        ProtocolSpec::WireGuard(config) => {
            builder.set("type", "wireguard");
            builder.set("private_key", config.private_key.to_string());
            builder.set(
                "local_address",
                json!(config
                    .local_address
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()),
            );
            let mut peer = Map::new();
            peer.insert(
                "public_key".into(),
                json!(config.peer_public_key.to_string()),
            );
            if let Some(preshared) = &config.preshared_key {
                peer.insert("preshared_key".into(), json!(preshared.to_string()));
            }
            builder.set("peers", Value::Array(vec![Value::Object(peer)]));
            if let Some(reserved) = config.reserved {
                builder.set("reserved", json!(reserved));
            }
            if let Some(mtu) = config.mtu {
                builder.set("mtu", mtu);
            }
        }
    }
    Ok(builder.finish())
}

/// Tproxy inbound bound to `listen` on every address family so locally marked
/// traffic (see the netd nftables ruleset) is handed to the core.
pub fn compile_tproxy_inbound(listen: &str, port: u16) -> Value {
    json!({
        "type": "tproxy",
        "tag": "tproxy-in",
        "listen": listen,
        "listen_port": port,
    })
}

/// Routes every connection to the single proxy outbound. Marks outbound
/// sockets with `mark` so the kernel policy routing (nftables output chain)
/// keeps the core's own traffic clear of the TPROXY loop. Sniffing runs as a
/// rule action (the legacy inbound `sniff`/`sniff_override_destination` fields
/// were removed in sing-box 1.13.0) so TLS SNI / sniffed protocols can override
/// the transparent destination before the route rule applies.
pub fn compile_routing(outbound_tag: &str, mark: u32, auto_detect_interface: bool) -> Value {
    json!({
        "auto_detect_interface": auto_detect_interface,
        "default_mark": mark,
        "rules": [
            { "action": "sniff", "override_destination": true },
            { "action": "route", "outbound": outbound_tag }
        ]
    })
}

/// DoH resolver used by the tunneled DNS section. The resolver is dialed via
/// `detour` through the node's outbound, so the *client's* local network (which
/// may firewall well-known DoH providers) is irrelevant: only the node's egress
/// network has to serve it. Defaults to Cloudflare; switch if a node's ISP has
/// poor reachability to a given provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DnsProvider {
    #[default]
    Cloudflare,
    Quad9,
    Google,
    AdGuard,
    Custom(&'static str),
}

impl DnsProvider {
    /// RFC 8484 DoH host. The sing-box `https` DNS server type dials
    /// `/dns-query` on this host over TLS.
    pub fn server(self) -> &'static str {
        match self {
            DnsProvider::Cloudflare => "1.1.1.1",
            DnsProvider::Quad9 => "dns.quad9.net",
            DnsProvider::Google => "dns.google",
            DnsProvider::AdGuard => "dns.adguard-dns.com",
            DnsProvider::Custom(host) => host,
        }
    }
}

/// A LAN DNS resolver used for traffic the tunnel does **not** carry. In a
/// network that blocks secure DNS from the machine itself (TLS/QUIC/DNSCrypt
/// all dead on the wire), the only reliable untunnelled resolver is a plain
/// UDP server on the LAN -- conventionally the default gateway or a Pi-hole
/// / AdGuard Home box. Defaults to the gateway discovered via `/proc/net/route`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalDns {
    pub ipv4: Ipv4Addr,
    pub port: u16,
}

impl LocalDns {
    pub fn new(ipv4: Ipv4Addr, port: u16) -> Self {
        Self { ipv4, port }
    }
}

/// Reads the IPv4 default gateway from `/proc/net/route` (the first line whose
/// destination is `00000000`, addresses in little-endian hex).
pub fn default_gateway_v4() -> Option<Ipv4Addr> {
    let contents = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_route_table(&contents)
}

fn parse_route_table(contents: &str) -> Option<Ipv4Addr> {
    for line in contents.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let _interface = fields.next()?;
        let destination = fields.next()?;
        if destination != "00000000" {
            continue;
        }
        let gateway = fields.next()?;
        let hex = u32::from_str_radix(gateway, 16).ok()?;
        return Some(Ipv4Addr::from(hex.swap_bytes()));
    }
    None
}

/// Assembles a complete, immediately consumable sing-box config.
pub fn compile_full_config(
    node: &CanonicalNode,
    _caps: &CoreCapabilities,
    tproxy_port: u16,
    mark: u32,
    dns_provider: DnsProvider,
    local_dns: Option<LocalDns>,
) -> Result<Value> {
    use serde_json::json;
    let outbound = compile_outbound(node)?;
    let outbound_tag = outbound
        .get("tag")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "proxy".into());
    let outbounds = vec![json!({ "type": "direct", "tag": "direct" }), outbound];
    let dns = compile_dns(&outbound_tag, dns_provider, local_dns);
    Ok(json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [compile_tproxy_inbound("::", tproxy_port)],
        "outbounds": outbounds,
        "route": compile_routing(&outbound_tag, mark, true),
        "dns": dns
    }))
}

/// Builds the DNS section that owns queries hijacked by the tproxy inbound
/// (see the netd ruleset, which intercepts dport 53 before the local bypass).
/// Queries are answered over a remote DoH server routed *through* the proxy
/// outbound via `detour` (the `tunnel-dns` server), so resolution never leaks
/// to the ISP gateway and never loops back into the tproxy. When `local` is
/// given, a second `local-dns` server (plain UDP on the LAN, dialed via the
/// `direct` outbound) is added and gets every query whose connection is routed
/// to the direct outbound -- so once per-domain direct rules exist, e.g. for
/// streaming or LAN devices pinned to `direct`, they resolve without the
/// tunnel and without the machine's filtered secure-DNS attempt. Until such
/// rules exist (no `direct`-routed connections today), the extra server is
/// dormant but correct.
pub fn compile_dns(proxy_outbound: &str, provider: DnsProvider, local: Option<LocalDns>) -> Value {
    let mut servers = vec![json!({
        "type": "https",
        "tag": "tunnel-dns",
        "server": provider.server(),
        "detour": proxy_outbound
    })];
    let mut rules = vec![];
    if let Some(local) = local {
        servers.push(json!({
            "type": "udp",
            "tag": "local-dns",
            "server": local.ipv4.to_string(),
            "server_port": local.port,
            "detour": "direct"
        }));
        rules.push(json!({
            "outbound": ["direct"],
            "server": "local-dns"
        }));
    }
    // Explicit fallback: anything not pinned to the direct outbound resolves
    // through the tunnel (or, with no matching rule yet, the default server).
    rules.push(json!({ "server": "tunnel-dns" }));
    json!({
        "servers": servers,
        "rules": rules,
        "strategy": "ipv4_only",
        "independent_cache": false
    })
}

struct OutboundBuilder {
    value: Map<String, Value>,
}

impl OutboundBuilder {
    fn new(node: &CanonicalNode) -> Self {
        let mut value = Map::new();
        value.insert("tag".into(), json!(node.meta.label.to_string()));
        let mut builder = Self { value };
        builder.embed_mux(&node.mux);
        builder
    }

    fn server(mut self, server: &str) -> Result<Self> {
        Self::validate(server)?;
        self.set("server", server.to_string());
        Ok(self)
    }

    fn server_port(mut self, port: u16) -> Self {
        self.set("server_port", port);
        self
    }

    fn tag(mut self, tag: &str) -> Self {
        self.set("tag", tag.to_string());
        self
    }

    fn validate(server: &str) -> Result<()> {
        if server.is_empty() || server.contains(char::is_whitespace) {
            bail!("invalid server address: {server:?}");
        }
        Ok(())
    }

    fn set(&mut self, key: &str, value: impl Into<Value>) {
        self.value.insert(key.into(), value.into());
    }

    fn embed_mux(&mut self, mux: &Option<MuxSpec>) {
        if let Some(mux) = mux {
            self.set(
                "multiplex",
                json!({
                    "enabled": mux.enabled,
                    "protocol": mux_protocol(mux.protocol),
                    "max_connections": mux.concurrency,
                }),
            );
        }
    }

    fn embed_transport(&mut self, transport: &TransportSpec) {
        match transport {
            TransportSpec::Tcp => {}
            TransportSpec::WebSocket(config) => {
                let mut headers = Map::new();
                if let Some(host) = &config.host {
                    headers.insert("Host".into(), json!(host.to_string()));
                }
                let mut ws = Map::new();
                ws.insert("type".into(), json!("ws"));
                ws.insert("path".into(), json!(config.path.to_string()));
                if !headers.is_empty() {
                    ws.insert("headers".into(), Value::Object(headers));
                }
                ws.insert("max_early_data".into(), json!(config.max_early_data));
                ws.insert("early_data_header_name".into(), json!(config.early_data_header));
                self.set("transport", Value::Object(ws));
            }
            TransportSpec::Grpc(config) => {
                self.set(
                    "transport",
                    json!({
                        "type": "grpc",
                        "service_name": config.service_name,
                        "mode": if config.multi_mode { "multi" } else { "gun" },
                    }),
                );
            }
            TransportSpec::HttpUpgrade(config) => {
                let mut map = Map::new();
                map.insert("type".into(), json!("httpupgrade"));
                if let Some(host) = &config.host {
                    map.insert("host".into(), json!(host.to_string()));
                }
                map.insert("path".into(), json!(config.path.to_string()));
                self.set("transport", Value::Object(map));
            }
            TransportSpec::XHttp(config) => {
                self.set(
                    "transport",
                    json!({
                        "type": "xhttp",
                        "mode": xhttp_mode(&config.mode),
                        "path": config.path,
                    }),
                );
            }
        }
    }

    fn embed_security(&mut self, security: &SecuritySpec) {
        match security {
            SecuritySpec::None => {}
            SecuritySpec::Tls(config) => {
                let mut tls = Map::new();
                tls.insert("enabled".into(), json!(true));
                tls.insert("server_name".into(), json!(config.server_name.to_string()));
                tls.insert("insecure".into(), json!(config.allow_insecure));
                if !config.alpn.is_empty() {
                    tls.insert(
                        "alpn".into(),
                        json!(config.alpn.iter().map(ToString::to_string).collect::<Vec<_>>()),
                    );
                }
                Self::embed_utls(&mut tls, config.fingerprint);
                self.set("tls", Value::Object(tls));
            }
            SecuritySpec::Reality(config) => {
                let mut tls = Map::new();
                tls.insert("enabled".into(), json!(true));
                tls.insert("server_name".into(), json!(config.server_name.to_string()));
                Self::embed_utls(&mut tls, config.fingerprint);
                let mut reality = Map::new();
                reality.insert("enabled".into(), json!(true));
                reality.insert("public_key".into(), json!(config.public_key.to_string()));
                reality.insert("short_id".into(), json!(config.short_id.to_string()));
                if let Some(spider_x) = &config.spider_x {
                    reality.insert("spider_x".into(), json!(spider_x.to_string()));
                }
                tls.insert("reality".into(), Value::Object(reality));
                self.set("tls", Value::Object(tls));
            }
        }
    }

    fn embed_utls(tls: &mut Map<String, Value>, fingerprint: UtlsFingerprint) {
        let name = fingerprint_name(fingerprint);
        match name {
            None => {}
            Some(name) => {
                tls.insert(
                    "utls".into(),
                    json!({
                        "enabled": true,
                        "fingerprint": name,
                    }),
                );
            }
        }
    }

    fn finish(self) -> Value {
        Value::Object(self.value)
    }
}

fn flow_name(flow: VlessFlow) -> &'static str {
    match flow {
        VlessFlow::XtlsRprxVision => "xtls-rprx-vision",
        VlessFlow::XtlsRprxVisionUdp443 => "xtls-rprx-vision-udp443",
    }
}

fn cipher_name(cipher: &myproxy_ir::VmessCipher) -> &'static str {
    match cipher {
        myproxy_ir::VmessCipher::Auto => "auto",
        myproxy_ir::VmessCipher::Aes128Gcm => "aes-128-gcm",
        myproxy_ir::VmessCipher::Chacha20Poly1305 => "chacha20-poly1305",
        myproxy_ir::VmessCipher::None => "none",
    }
}

fn ss_method(method: &myproxy_ir::ShadowsocksCipher) -> &'static str {
    match method {
        myproxy_ir::ShadowsocksCipher::Aes128Gcm => "aes-128-gcm",
        myproxy_ir::ShadowsocksCipher::Aes256Gcm => "aes-256-gcm",
        myproxy_ir::ShadowsocksCipher::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        myproxy_ir::ShadowsocksCipher::Ss2022Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
        myproxy_ir::ShadowsocksCipher::Ss2022Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
        myproxy_ir::ShadowsocksCipher::Ss2022Blake3Chacha20Poly1305 => {
            "2022-blake3-chacha20-poly1305"
        }
    }
}

fn congestion_name(value: &myproxy_ir::TuicCongestion) -> &'static str {
    match value {
        myproxy_ir::TuicCongestion::Bbr => "bbr",
        myproxy_ir::TuicCongestion::Cubic => "cubic",
        myproxy_ir::TuicCongestion::NewReno => "new_reno",
    }
}

fn relay_mode(value: &myproxy_ir::TuicUdpRelay) -> &'static str {
    match value {
        myproxy_ir::TuicUdpRelay::Native => "native",
        myproxy_ir::TuicUdpRelay::Quic => "quic",
    }
}

fn mux_protocol(value: MuxProtocol) -> &'static str {
    match value {
        MuxProtocol::Smux => "smux",
        MuxProtocol::Yamux => "yamux",
        MuxProtocol::H2Mux => "h2mux",
    }
}

fn xhttp_mode(value: &myproxy_ir::XHttpMode) -> &'static str {
    match value {
        myproxy_ir::XHttpMode::StreamOne => "stream-one",
        myproxy_ir::XHttpMode::StreamUp => "stream-up",
        myproxy_ir::XHttpMode::PacketUp => "packet-up",
    }
}

fn fingerprint_name(value: UtlsFingerprint) -> Option<&'static str> {
    match value {
        UtlsFingerprint::Chrome => Some("chrome"),
        UtlsFingerprint::Firefox => Some("firefox"),
        UtlsFingerprint::Safari => Some("safari"),
        UtlsFingerprint::Edge => Some("edge"),
        UtlsFingerprint::Randomized => Some("randomized"),
        UtlsFingerprint::None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myproxy_ir::*;
    use std::sync::Arc;
    use uuid::Uuid;

    fn caps() -> CoreCapabilities {
        CoreCapabilities {
            core_name: "sing-box".into(),
            version: "1.12.0 (test)".into(),
            supported: BTreeSet::from([
                CoreCapability::Vless,
                CoreCapability::VlessReality,
                CoreCapability::Vmess,
                CoreCapability::Trojan,
                CoreCapability::Shadowsocks,
                CoreCapability::Hysteria2,
                CoreCapability::Tuic,
                CoreCapability::WireGuard,
                CoreCapability::WebSocket,
                CoreCapability::Grpc,
                CoreCapability::Multiplexing,
            ]),
        }
    }

    fn node(protocol: ProtocolSpec, transport: TransportSpec, security: SecuritySpec) -> CanonicalNode {
        CanonicalNode::try_new(
            NodeMetadata::new(1, "edge-test", *b"DE", 1).unwrap(),
            EndpointTarget::domain("edge.example.com", 443).unwrap(),
            protocol,
            transport,
            security,
            None,
        )
        .unwrap()
    }

    #[test]
    fn full_config_accepted_by_real_singbox() {
        let binary = std::env::var_os("SING_BOX_BIN")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("/usr/bin/sing-box"));
        if !binary.exists() {
            eprintln!("skipping: no sing-box binary at {}", binary.display());
            return;
        }
        let config = compile_full_config(
            &node(
                ProtocolSpec::Shadowsocks(ShadowsocksConfig {
                    method: ShadowsocksCipher::Chacha20IetfPoly1305,
                    password: "pass".into(),
                    plugin: None,
                    plugin_opts: None,
                }),
                TransportSpec::Tcp,
                SecuritySpec::None,
            ),
            &caps(),
            12345,
            0x1,
            DnsProvider::Quad9,
            Some(LocalDns::new("192.168.1.1".parse().unwrap(), 53)),
        )
        .unwrap();
        SingboxAdapter
            .validate_config(&binary, &serde_json::to_vec(&config).unwrap())
            .unwrap_or_else(|error| {
                panic!(
                    "real sing-box rejected the full compiled config: {error:#}"
                )
            });
    }

    #[test]
    fn vless_reality_websocket_outbound_shape() {
        let node = node(
            ProtocolSpec::Vless(VlessConfig {
                uuid: Uuid::nil(),
                flow: Some(VlessFlow::XtlsRprxVision),
            }),
            TransportSpec::WebSocket(WebSocketConfig {
                path: "/proxy".into(),
                host: Some("edge.example.com".into()),
                max_early_data: 0,
                early_data_header: None,
            }),
            SecuritySpec::Reality(RealityConfig {
                server_name: "www.example.org".into(),
                public_key: "PKEY".into(),
                short_id: "deadbeef".into(),
                spider_x: None,
                fingerprint: UtlsFingerprint::Chrome,
            }),
        );
        let outbound = compile_outbound(&node).unwrap();
        assert_eq!(outbound["type"], "vless");
        assert_eq!(outbound["server"], "edge.example.com");
        assert_eq!(outbound["server_port"], 443);
        assert_eq!(outbound["flow"], "xtls-rprx-vision");
        assert_eq!(outbound["transport"]["type"], "ws");
        assert_eq!(outbound["transport"]["headers"]["Host"], "edge.example.com");
        assert_eq!(outbound["tls"]["server_name"], "www.example.org");
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbound["tls"]["reality"]["public_key"], "PKEY");
        assert_eq!(outbound["tls"]["reality"]["short_id"], "deadbeef");
    }

    #[test]
    fn trojan_tls_outbound_shape() {
        let node = node(
            ProtocolSpec::Trojan(TrojanConfig {
                password: "hunter2".into(),
            }),
            TransportSpec::Tcp,
            SecuritySpec::Tls(StandardTlsConfig {
                server_name: "edge.example.com".into(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                fingerprint: UtlsFingerprint::Randomized,
                allow_insecure: false,
            }),
        );
        let outbound = compile_outbound(&node).unwrap();
        assert_eq!(outbound["type"], "trojan");
        assert_eq!(outbound["password"], "hunter2");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "randomized");
        assert_eq!(outbound["tls"]["alpn"][0], "h2");
    }

    #[test]
    fn shadowsocks_methods_and_plugin_preserved() {
        let node = node(
            ProtocolSpec::Shadowsocks(ShadowsocksConfig {
                method: ShadowsocksCipher::Ss2022Blake3Chacha20Poly1305,
                password: "pass".into(),
                plugin: Some("obfs-local".into()),
                plugin_opts: Some("obfs=http".into()),
            }),
            TransportSpec::Tcp,
            SecuritySpec::None,
        );
        let outbound = compile_outbound(&node).unwrap();
        assert_eq!(outbound["method"], "2022-blake3-chacha20-poly1305");
        assert_eq!(outbound["plugin"], "obfs-local");
        assert_eq!(outbound["plugin_opts"], "obfs=http");
        assert!(outbound.get("tls").is_none());
    }

    #[test]
    fn hysteria2_carries_rates_and_obfs() {
        let node = node(
            ProtocolSpec::Hysteria2(Hysteria2Config {
                password: "hy".into(),
                up_mbps: Some(30),
                down_mbps: Some(100),
                obfs: Some(Hysteria2Obfs {
                    obfs_type: "salamander".into(),
                    password: "sop".into(),
                }),
                port_hopping: Some("443,8443".into()),
            }),
            TransportSpec::Tcp,
            SecuritySpec::None,
        );
        let outbound = compile_outbound(&node).unwrap();
        assert_eq!(outbound["type"], "hysteria2");
        assert_eq!(outbound["up_mbps"], 30);
        assert_eq!(outbound["obfs"]["type"], "salamander");
        assert_eq!(outbound["port_hopping"], "443,8443");
    }

    #[test]
    fn tuic_and_wireguard_map_core_fields() {
        let tuic = node(
            ProtocolSpec::Tuic(TuicConfig {
                uuid: Uuid::nil(),
                password: "tp".into(),
                congestion_control: TuicCongestion::Bbr,
                udp_relay_mode: TuicUdpRelay::Quic,
                zero_rtt_handshake: true,
            }),
            TransportSpec::Tcp,
            SecuritySpec::None,
        );
        let outbound = compile_outbound(&tuic).unwrap();
        assert_eq!(outbound["congestion_control"], "bbr");
        assert_eq!(outbound["udp_relay_mode"], "quic");
        assert_eq!(outbound["zero_rtt_handshake"], true);

        let wg = node(
            ProtocolSpec::WireGuard(WireGuardConfig {
                private_key: Arc::from("PRIV"),
                peer_public_key: Arc::from("PUB"),
                preshared_key: Some(Arc::from("PSK")),
                local_address: vec!["10.0.0.2".parse().unwrap()],
                reserved: Some([0, 0, 0]),
                mtu: Some(1280),
            }),
            TransportSpec::Tcp,
            SecuritySpec::None,
        );
        let outbound = compile_outbound(&wg).unwrap();
        assert_eq!(outbound["type"], "wireguard");
        assert_eq!(outbound["private_key"], "PRIV");
        assert_eq!(outbound["local_address"][0], "10.0.0.2");
        assert_eq!(outbound["peers"][0]["public_key"], "PUB");
        assert_eq!(outbound["peers"][0]["preshared_key"], "PSK");
        assert_eq!(outbound["reserved"][0], 0);
        assert_eq!(outbound["mtu"], 1280);
    }

    #[test]
    fn vmess_cipher_and_grpc_transport() {
        let node = node(
            ProtocolSpec::Vmess(VmessConfig {
                uuid: Uuid::nil(),
                alter_id: 0,
                cipher: VmessCipher::Chacha20Poly1305,
            }),
            TransportSpec::Grpc(GrpcConfig {
                service_name: "trojan.grpc".into(),
                multi_mode: true,
            }),
            SecuritySpec::None,
        );
        let outbound = compile_outbound(&node).unwrap();
        assert_eq!(outbound["type"], "vmess");
        assert_eq!(outbound["security"], "chacha20-poly1305");
        assert_eq!(outbound["transport"]["type"], "grpc");
        assert_eq!(outbound["transport"]["mode"], "multi");
        assert_eq!(outbound["transport"]["service_name"], "trojan.grpc");
    }

    #[test]
    fn full_config_assembles_tproxy_skeleton() {
        let node = node(
            ProtocolSpec::Vless(VlessConfig {
                uuid: Uuid::nil(),
                flow: None,
            }),
            TransportSpec::Tcp,
            SecuritySpec::None,
        );
        let config = compile_full_config(
            &node,
            &caps(),
            12345,
            0x1,
            DnsProvider::default(),
            Some(LocalDns::new("192.168.1.1".parse().unwrap(), 53)),
        )
        .unwrap();
        assert_eq!(config["inbounds"][0]["type"], "tproxy");
        assert_eq!(config["inbounds"][0]["listen_port"], 12345);
        assert_eq!(config["outbounds"][0]["type"], "direct");
        assert_eq!(config["route"]["default_mark"], 0x1);
        assert_eq!(config["route"]["auto_detect_interface"], true);
        assert_eq!(config["dns"]["servers"][0]["tag"], "tunnel-dns");
        assert_eq!(config["dns"]["servers"][0]["detour"], "edge-test");
        assert_eq!(config["dns"]["servers"][0]["type"], "https");
        assert_eq!(config["dns"]["servers"][0]["server"], "1.1.1.1");
        assert_eq!(config["dns"]["servers"][1]["tag"], "local-dns");
        assert_eq!(config["dns"]["servers"][1]["type"], "udp");
        assert_eq!(config["dns"]["servers"][1]["server"], "192.168.1.1");
        assert_eq!(config["dns"]["servers"][1]["detour"], "direct");
        assert_eq!(config["dns"]["rules"][0]["outbound"][0], "direct");
        assert_eq!(config["dns"]["rules"][0]["server"], "local-dns");
        assert_eq!(config["dns"]["rules"][1]["server"], "tunnel-dns");
    }

    #[test]
    fn dns_without_local_dns_keeps_single_tunnel_backbone() {
        let dns = compile_dns("proxy", DnsProvider::Cloudflare, None);
        assert_eq!(
            dns["servers"].as_array().map(Vec::len),
            Some(1),
            "no local resolver configured -> single tunnel server"
        );
        assert_eq!(dns["servers"][0]["tag"], "tunnel-dns");
        assert_eq!(dns["rules"].as_array().map(Vec::len), Some(1));
        assert_eq!(dns["rules"][0]["server"], "tunnel-dns");
    }

    #[test]
    fn gateway_route_table_is_parsed_le_endian() {
        // Destination 00000000 is the default route; gateway "0101A8C0" is
        // 192.168.1.1 in little-endian hex.
        let table = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
wlan0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";
        assert_eq!(
            parse_route_table(table),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(parse_route_table(table.lines().next().unwrap()), None);
        assert_eq!(parse_route_table(""), None);
        assert_eq!(
            parse_route_table("Iface\nX\t00000000\t0000A8C0\tF"),
            Some("192.168.0.0".parse().unwrap()),
            "any zero destination still parses, whatever the interface name"
        );
        assert_eq!(parse_route_table("Iface\nX\t00000000\tzzzz\tF"), None);
    }
}