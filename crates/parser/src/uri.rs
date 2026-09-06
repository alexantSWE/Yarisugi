use crate::{make_metadata, ParseError};
use myproxy_ir::*;
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use simd_json::serde::from_slice;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

pub fn parse_entry(raw: &str, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let url = Url::parse(raw).map_err(|error| ParseError::InvalidUri(error.to_string()))?;
    match url.scheme() {
        "vless" => parse_vless(url, sub_id, timestamp),
        "vmess" => parse_vmess(url, sub_id, timestamp),
        "trojan" => parse_trojan(url, sub_id, timestamp),
        "ss" => parse_shadowsocks(url, sub_id, timestamp),
        "hysteria2" | "hy2" => parse_hysteria2(url, sub_id, timestamp),
        "tuic" => parse_tuic(url, sub_id, timestamp),
        scheme => Err(ParseError::UnsupportedFormat(scheme.to_owned())),
    }
}

fn parse_vless(url: Url, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let uuid = parse_uuid(url.username())?;
    let endpoint = endpoint(&url, 443)?;
    let query = Query::new(&url);
    let transport = parse_transport(&query)?;
    let security = parse_security(&query)?;
    let flow = match query.get("flow").as_deref() {
        Some("xtls-rprx-vision") => Some(VlessFlow::XtlsRprxVision),
        Some("xtls-rprx-vision-udp443") => Some(VlessFlow::XtlsRprxVisionUdp443),
        Some(value) if !value.is_empty() => return Err(invalid("flow", value)),
        _ => None,
    };
    let label = label(&url, "VLESS Node");
    let meta = make_metadata(sub_id, &label, timestamp)?;
    CanonicalNode::try_new(
        meta,
        endpoint,
        ProtocolSpec::Vless(VlessConfig { uuid, flow }),
        transport,
        security,
        None,
    )
    .map_err(|error| ParseError::InvalidEndpoint(error.to_string()))
}

fn parse_vmess(url: Url, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let payload = if url.host_str().is_some() {
        url.host_str().unwrap_or_default()
    } else {
        url.path().trim_start_matches('/')
    };
    if payload.is_empty() {
        return Err(ParseError::MissingField("vmess payload"));
    }
    let mut decoded =
        crate::format::decode_bundle(payload.as_bytes()).map_err(ParseError::Base64Decode)?;
    let wire: VmessWire =
        from_slice(&mut decoded).map_err(|error| ParseError::Json(error.to_string()))?;
    let host = wire
        .add
        .as_deref()
        .ok_or(ParseError::MissingField("add"))?
        .to_owned();
    let port = parse_u16(
        wire.port.as_ref().ok_or(ParseError::MissingField("port"))?,
        "port",
    )?;
    let uuid = parse_uuid(wire.id.as_deref().ok_or(ParseError::MissingField("id"))?)?;
    let transport = parse_vmess_transport(&wire);
    let security = parse_vmess_security(&wire);
    let cipher = match wire
        .scy
        .as_deref()
        .unwrap_or("auto")
        .to_ascii_lowercase()
        .as_str()
    {
        "auto" => VmessCipher::Auto,
        "aes-128-gcm" => VmessCipher::Aes128Gcm,
        "chacha20-poly1305" => VmessCipher::Chacha20Poly1305,
        "none" => VmessCipher::None,
        value => return Err(invalid("scy", value)),
    };
    let label = wire.ps.unwrap_or_else(|| "VMess Node".into());
    let meta = make_metadata(sub_id, &label, timestamp)?;
    let endpoint = endpoint_from_host(&host, port)?;
    let aid = wire.aid.unwrap_or_else(|| serde_json::Value::from(0));
    CanonicalNode::try_new(
        meta,
        endpoint,
        ProtocolSpec::Vmess(VmessConfig {
            uuid,
            alter_id: parse_u16(&aid, "aid")?,
            cipher,
        }),
        transport,
        security,
        None,
    )
    .map_err(|error| ParseError::InvalidEndpoint(error.to_string()))
}

fn parse_trojan(url: Url, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let password = percent_decode_str(url.username())
        .decode_utf8()
        .map_err(|_| ParseError::InvalidValue {
            field: "password",
            value: "invalid UTF-8".into(),
        })?;
    if password.is_empty() {
        return Err(ParseError::MissingField("password"));
    }
    let query = Query::new(&url);
    let label = label(&url, "Trojan Node");
    let meta = make_metadata(sub_id, &label, timestamp)?;
    CanonicalNode::try_new(
        meta,
        endpoint(&url, 443)?,
        ProtocolSpec::Trojan(TrojanConfig {
            password: password.into(),
        }),
        parse_transport(&query)?,
        parse_security(&query)?,
        None,
    )
    .map_err(|error| ParseError::InvalidEndpoint(error.to_string()))
}

fn parse_shadowsocks(url: Url, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let userinfo = url.username();
    let decoded =
        crate::format::decode_bundle(userinfo.as_bytes()).map_err(ParseError::Base64Decode)?;
    let credentials = String::from_utf8(decoded).map_err(|_| ParseError::InvalidValue {
        field: "credentials",
        value: "invalid UTF-8".into(),
    })?;
    let (method, password) = credentials
        .split_once(':')
        .ok_or(ParseError::MissingField("method/password"))?;
    let method = parse_ss_method(method)?;
    let endpoint = endpoint(&url, 0)?;
    let query = Query::new(&url);
    let label = label(&url, "Shadowsocks Node");
    let meta = make_metadata(sub_id, &label, timestamp)?;
    CanonicalNode::try_new(
        meta,
        endpoint,
        ProtocolSpec::Shadowsocks(ShadowsocksConfig {
            method,
            password: password.into(),
            plugin: query.get("plugin").map(Into::into),
            plugin_opts: None,
        }),
        TransportSpec::Tcp,
        SecuritySpec::None,
        None,
    )
    .map_err(|error| ParseError::InvalidEndpoint(error.to_string()))
}

fn parse_hysteria2(url: Url, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let password = percent_decode_str(url.username())
        .decode_utf8()
        .map_err(|_| ParseError::InvalidValue {
            field: "password",
            value: "invalid UTF-8".into(),
        })?;
    if password.is_empty() {
        return Err(ParseError::MissingField("password"));
    }
    let query = Query::new(&url);
    let obfs = query.get("obfs").map(|obfs_type| Hysteria2Obfs {
        obfs_type: obfs_type.into(),
        password: query.get("obfs-password").unwrap_or_default().into(),
    });
    let label = label(&url, "Hysteria2 Node");
    let meta = make_metadata(sub_id, &label, timestamp)?;
    CanonicalNode::try_new(
        meta,
        endpoint(&url, 443)?,
        ProtocolSpec::Hysteria2(Hysteria2Config {
            password: password.into(),
            up_mbps: query.get("up").and_then(|value| value.parse().ok()),
            down_mbps: query.get("down").and_then(|value| value.parse().ok()),
            obfs,
            port_hopping: query.get("mport").map(Into::into),
        }),
        TransportSpec::Tcp,
        SecuritySpec::None,
        None,
    )
    .map_err(|error| ParseError::InvalidEndpoint(error.to_string()))
}

fn parse_tuic(url: Url, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let uuid = parse_uuid(url.username())?;
    let password = url.password().unwrap_or_default().to_owned();
    let query = Query::new(&url);
    let congestion_control = match query
        .get("congestion_control")
        .as_deref()
        .unwrap_or("cubic")
    {
        "bbr" => TuicCongestion::Bbr,
        "new_reno" => TuicCongestion::NewReno,
        "cubic" => TuicCongestion::Cubic,
        value => return Err(invalid("congestion_control", value)),
    };
    let udp_relay_mode = match query.get("udp_relay_mode").as_deref().unwrap_or("native") {
        "native" => TuicUdpRelay::Native,
        "quic" => TuicUdpRelay::Quic,
        value => return Err(invalid("udp_relay_mode", value)),
    };
    let label = label(&url, "TUIC Node");
    let meta = make_metadata(sub_id, &label, timestamp)?;
    CanonicalNode::try_new(
        meta,
        endpoint(&url, 443)?,
        ProtocolSpec::Tuic(TuicConfig {
            uuid,
            password: password.into(),
            congestion_control,
            udp_relay_mode,
            zero_rtt_handshake: query.get("zero_rtt_handshake").as_deref() == Some("true"),
        }),
        TransportSpec::Tcp,
        SecuritySpec::None,
        None,
    )
    .map_err(|error| ParseError::InvalidEndpoint(error.to_string()))
}

fn parse_ss_method(value: &str) -> Result<ShadowsocksCipher, ParseError> {
    match value.to_ascii_lowercase().as_str() {
        "aes-128-gcm" => Ok(ShadowsocksCipher::Aes128Gcm),
        "aes-256-gcm" => Ok(ShadowsocksCipher::Aes256Gcm),
        "chacha20-ietf-poly1305" => Ok(ShadowsocksCipher::Chacha20IetfPoly1305),
        "2022-blake3-aes-128-gcm" => Ok(ShadowsocksCipher::Ss2022Blake3Aes128Gcm),
        "2022-blake3-aes-256-gcm" => Ok(ShadowsocksCipher::Ss2022Blake3Aes256Gcm),
        "2022-blake3-chacha20-poly1305" => Ok(ShadowsocksCipher::Ss2022Blake3Chacha20Poly1305),
        other => Err(invalid("method", other)),
    }
}

struct Query {
    values: std::collections::HashMap<String, String>,
}
impl Query {
    fn new(url: &Url) -> Self {
        Self {
            values: url
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect(),
        }
    }
    fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }
}

#[derive(Deserialize)]
struct VmessWire {
    #[serde(rename = "add")]
    add: Option<String>,
    port: Option<serde_json::Value>,
    id: Option<String>,
    aid: Option<serde_json::Value>,
    scy: Option<String>,
    net: Option<String>,
    host: Option<String>,
    path: Option<String>,
    tls: Option<String>,
    sni: Option<String>,
    alpn: Option<String>,
    fp: Option<String>,
    ps: Option<String>,
}

fn parse_transport(query: &Query) -> Result<TransportSpec, ParseError> {
    match query.get("type").as_deref().unwrap_or("tcp") {
        "tcp" => Ok(TransportSpec::Tcp),
        "ws" => Ok(TransportSpec::WebSocket(WebSocketConfig {
            path: query.get("path").unwrap_or_else(|| "/".into()).into(),
            host: query.get("host").map(Into::into),
            max_early_data: query
                .get("ed")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            early_data_header: query.get("eh").map(Into::into),
        })),
        "grpc" => Ok(TransportSpec::Grpc(GrpcConfig {
            service_name: query.get("serviceName").unwrap_or_default().into(),
            multi_mode: query.get("mode").as_deref() == Some("multi"),
        })),
        "xhttp" => Ok(TransportSpec::XHttp(XHttpConfig {
            mode: parse_xhttp_mode(query.get("mode").as_deref()),
            path: query.get("path").unwrap_or_else(|| "/".into()).into(),
            host: query.get("host").map(Into::into),
        })),
        value => Err(invalid("type", value)),
    }
}

fn parse_security(query: &Query) -> Result<SecuritySpec, ParseError> {
    match query.get("security").as_deref().unwrap_or("none") {
        "none" | "" => Ok(SecuritySpec::None),
        "tls" => Ok(SecuritySpec::Tls(StandardTlsConfig {
            server_name: query.get("sni").unwrap_or_default().into(),
            alpn: split_csv(query.get("alpn")),
            fingerprint: parse_fingerprint(query.get("fp").as_deref()),
            allow_insecure: query
                .get("allowInsecure")
                .as_deref()
                .is_some_and(|value| value == "1" || value == "true"),
        })),
        "reality" => Ok(SecuritySpec::Reality(RealityConfig {
            server_name: query.get("sni").unwrap_or_default().into(),
            public_key: query
                .get("pbk")
                .ok_or(ParseError::MissingField("pbk"))?
                .into(),
            short_id: query.get("sid").unwrap_or_default().into(),
            spider_x: query.get("spx").map(Into::into),
            fingerprint: parse_fingerprint(query.get("fp").as_deref()),
        })),
        value => Err(invalid("security", value)),
    }
}

fn parse_vmess_transport(wire: &VmessWire) -> TransportSpec {
    match wire.net.as_deref().unwrap_or("tcp") {
        "ws" => TransportSpec::WebSocket(WebSocketConfig {
            path: wire.path.clone().unwrap_or_else(|| "/".into()).into(),
            host: wire.host.clone().map(Into::into),
            max_early_data: 0,
            early_data_header: None,
        }),
        "grpc" => TransportSpec::Grpc(GrpcConfig {
            service_name: wire.path.clone().unwrap_or_default().into(),
            multi_mode: false,
        }),
        _ => TransportSpec::Tcp,
    }
}
fn parse_vmess_security(wire: &VmessWire) -> SecuritySpec {
    if wire.tls.as_deref().unwrap_or("") == "tls" {
        SecuritySpec::Tls(StandardTlsConfig {
            server_name: wire.sni.clone().unwrap_or_default().into(),
            alpn: split_csv(wire.alpn.clone()),
            fingerprint: parse_fingerprint(wire.fp.as_deref()),
            allow_insecure: false,
        })
    } else {
        SecuritySpec::None
    }
}
fn parse_xhttp_mode(mode: Option<&str>) -> XHttpMode {
    match mode {
        Some("packet-up") => XHttpMode::PacketUp,
        Some("stream-up") => XHttpMode::StreamUp,
        _ => XHttpMode::StreamOne,
    }
}
fn parse_fingerprint(value: Option<&str>) -> UtlsFingerprint {
    match value.unwrap_or("").to_ascii_lowercase().as_str() {
        "chrome" => UtlsFingerprint::Chrome,
        "firefox" => UtlsFingerprint::Firefox,
        "safari" => UtlsFingerprint::Safari,
        "edge" => UtlsFingerprint::Edge,
        "randomized" | "random" => UtlsFingerprint::Randomized,
        _ => UtlsFingerprint::None,
    }
}
fn split_csv(value: Option<String>) -> Vec<Arc<str>> {
    value
        .unwrap_or_default()
        .split(',')
        .filter(|value| !value.is_empty())
        .map(Into::into)
        .collect()
}
fn parse_uuid(value: &str) -> Result<Uuid, ParseError> {
    Uuid::parse_str(value).map_err(|_| ParseError::InvalidUuid(value.to_owned()))
}
fn parse_u16(value: &serde_json::Value, field: &'static str) -> Result<u16, ParseError> {
    let value = value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .ok_or(ParseError::MissingField(field))?;
    u16::try_from(value).map_err(|_| invalid(field, value.to_string()))
}
fn endpoint(url: &Url, default_port: u16) -> Result<EndpointTarget, ParseError> {
    let host = url.host_str().ok_or(ParseError::MissingField("host"))?;
    let port = url
        .port()
        .or((default_port != 0).then_some(default_port))
        .ok_or(ParseError::MissingField("port"))?;
    endpoint_from_host(host, port)
}
fn endpoint_from_host(host: &str, port: u16) -> Result<EndpointTarget, ParseError> {
    if port == 0 {
        return Err(ParseError::InvalidEndpoint("port cannot be zero".into()));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(EndpointTarget::Ip(SocketAddr::new(ip, port)))
    } else {
        EndpointTarget::domain(host, port)
            .map_err(|error| ParseError::InvalidEndpoint(error.to_string()))
    }
}
fn label(url: &Url, fallback: &str) -> String {
    url.fragment()
        .map(|value| percent_decode_str(value).decode_utf8_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.into())
}
fn invalid(field: &'static str, value: impl Into<String>) -> ParseError {
    ParseError::InvalidValue {
        field,
        value: value.into(),
    }
}
