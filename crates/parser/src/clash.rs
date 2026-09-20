use crate::error::ParseError;
use myproxy_ir::*;
use serde_yaml::{Mapping, Value};
use std::sync::Arc;

/// Parses a Clash / Clash Meta YAML subscription into canonical nodes.
///
/// Each `proxies:` item maps to one `Result`: supported proxy types produce a
/// node, unsupported types (ssr, hysteria v1, snell, ...) produce a per-item
/// failure so the caller can report exactly which entries were skipped.
pub fn ingest_clash_yaml(
    raw: &str,
    sub_id: SubId,
    timestamp: u64,
) -> Result<Vec<Result<CanonicalNode, ParseError>>, ParseError> {
    let document: Value = serde_yaml::from_str(raw)
        .map_err(|error| ParseError::Json(format!("Clash YAML: {error}")))?;
    let proxies = map_get(&document, "proxies")
        .and_then(Value::as_sequence)
        .ok_or(ParseError::MissingField("proxies"))?;
    Ok(proxies
        .iter()
        .map(|item| parse_proxy(item, sub_id, timestamp))
        .collect())
}

fn parse_proxy(item: &Value, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let name = string_at(item, "name").unwrap_or_else(|| "Unnamed Proxy".into());
    let proxy_type = string_at(item, "type").unwrap_or_default();
    match proxy_type.as_str() {
        "ss" => parse_ss(item, sub_id, timestamp),
        "vmess" => parse_vmess(item, sub_id, timestamp),
        "trojan" => parse_trojan(item, sub_id, timestamp),
        "vless" => parse_vless(item, sub_id, timestamp),
        "hysteria2" => parse_hysteria2(item, sub_id, timestamp),
        "tuic" => parse_tuic(item, sub_id, timestamp),
        "" => Err(ParseError::MissingField("type")),
        other => Err(ParseError::UnsupportedFormat(format!(
            "Clash proxy type `{other}` ({name}) is not supported"
        ))),
    }
}

fn parse_ss(item: &Value, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let method = crate::uri::parse_ss_method(
        string_at(item, "cipher").as_deref().unwrap_or(""),
    )?;
    let password = string_at(item, "password").unwrap_or_default();
    let metadata = make_metadata(sub_id, &label_of(item)?, timestamp)?;
    CanonicalNode::try_new(
        metadata,
        endpoint(item)?,
        ProtocolSpec::Shadowsocks(ShadowsocksConfig {
            method,
            password: password.into(),
            plugin: None,
            plugin_opts: None,
        }),
        TransportSpec::Tcp,
        SecuritySpec::None,
        None,
    )
    .map_err(to_invalid_endpoint)
}

fn parse_vmess(item: &Value, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let uuid = parse_uuid(string_at(item, "uuid").as_deref().unwrap_or(""))?;
    let alter_id = u16_at(item, "alterId")?.unwrap_or(0);
    let cipher = match string_at(item, "cipher").as_deref().unwrap_or("auto") {
        "auto" => VmessCipher::Auto,
        "aes-128-gcm" => VmessCipher::Aes128Gcm,
        "chacha20-poly1305" => VmessCipher::Chacha20Poly1305,
        "none" => VmessCipher::None,
        value => return Err(invalid("cipher", value)),
    };
    let metadata = make_metadata(sub_id, &label_of(item)?, timestamp)?;
    CanonicalNode::try_new(
        metadata,
        endpoint(item)?,
        ProtocolSpec::Vmess(VmessConfig {
            uuid,
            alter_id,
            cipher,
        }),
        parse_transport(item)?,
        parse_vmess_security(item),
        None,
    )
    .map_err(to_invalid_endpoint)
}

fn parse_trojan(item: &Value, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let password = string_at(item, "password").unwrap_or_default();
    if password.is_empty() {
        return Err(ParseError::MissingField("password"));
    }
    let metadata = make_metadata(sub_id, &label_of(item)?, timestamp)?;
    CanonicalNode::try_new(
        metadata,
        endpoint(item)?,
        ProtocolSpec::Trojan(TrojanConfig {
            password: password.into(),
        }),
        parse_transport(item)?,
        parse_security(item, "trojan")?,
        None,
    )
    .map_err(to_invalid_endpoint)
}

fn parse_vless(item: &Value, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let uuid = parse_uuid(string_at(item, "uuid").as_deref().unwrap_or(""))?;
    let flow = match string_at(item, "flow").as_deref() {
        Some("xtls-rprx-vision") => Some(VlessFlow::XtlsRprxVision),
        Some("xtls-rprx-vision-udp443") => Some(VlessFlow::XtlsRprxVisionUdp443),
        Some(value) if !value.is_empty() => return Err(invalid("flow", value)),
        _ => None,
    };
    let metadata = make_metadata(sub_id, &label_of(item)?, timestamp)?;
    CanonicalNode::try_new(
        metadata,
        endpoint(item)?,
        ProtocolSpec::Vless(VlessConfig { uuid, flow }),
        parse_transport(item)?,
        parse_security(item, "vless")?,
        None,
    )
    .map_err(to_invalid_endpoint)
}

fn parse_hysteria2(item: &Value, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let password = string_at(item, "password").unwrap_or_default();
    if password.is_empty() {
        return Err(ParseError::MissingField("password"));
    }
    let obfs = string_at(item, "obfs").map(|obfs_type| Hysteria2Obfs {
        obfs_type: obfs_type.into(),
        password: string_at(item, "obfs-password").unwrap_or_default().into(),
    });
    let metadata = make_metadata(sub_id, &label_of(item)?, timestamp)?;
    CanonicalNode::try_new(
        metadata,
        endpoint(item)?,
        ProtocolSpec::Hysteria2(Hysteria2Config {
            password: password.into(),
            up_mbps: numeric_at(item, "up").and_then(|value| u32::try_from(value).ok()),
            down_mbps: numeric_at(item, "down").and_then(|value| u32::try_from(value).ok()),
            obfs,
            port_hopping: string_at(item, "ports").map(Into::into),
        }),
        TransportSpec::Tcp,
        SecuritySpec::None,
        None,
    )
    .map_err(to_invalid_endpoint)
}

fn parse_tuic(item: &Value, sub_id: SubId, timestamp: u64) -> Result<CanonicalNode, ParseError> {
    let uuid = parse_uuid(string_at(item, "uuid").as_deref().unwrap_or(""))?;
    let password = string_at(item, "password").unwrap_or_default();
    let congestion_control = match string_at(item, "congestion-controller")
        .as_deref()
        .unwrap_or("cubic")
    {
        "bbr" => TuicCongestion::Bbr,
        "new_reno" => TuicCongestion::NewReno,
        "cubic" => TuicCongestion::Cubic,
        value => return Err(invalid("congestion-controller", value)),
    };
    let udp_relay_mode = match string_at(item, "udp-relay-mode")
        .as_deref()
        .unwrap_or("native")
    {
        "native" => TuicUdpRelay::Native,
        "quic" => TuicUdpRelay::Quic,
        value => return Err(invalid("udp-relay-mode", value)),
    };
    let metadata = make_metadata(sub_id, &label_of(item)?, timestamp)?;
    CanonicalNode::try_new(
        metadata,
        endpoint(item)?,
        ProtocolSpec::Tuic(TuicConfig {
            uuid,
            password: password.into(),
            congestion_control,
            udp_relay_mode,
            zero_rtt_handshake: bool_at(item, "zero-rtt-handshake").unwrap_or(false),
        }),
        TransportSpec::Tcp,
        SecuritySpec::None,
        None,
    )
    .map_err(to_invalid_endpoint)
}

fn parse_transport(item: &Value) -> Result<TransportSpec, ParseError> {
    let network = string_at(item, "network").unwrap_or_else(|| "tcp".into());
    let ws_opts = value_at(item, "ws-opts").and_then(Value::as_mapping);
    let path = ws_opts
        .and_then(|opts| mapping_get(opts, "path"))
        .map(string_value)
        .or_else(|| {
            ws_opts
                .and_then(|opts| mapping_get(opts, "serviceName"))
                .map(string_value)
        });
    let host = ws_opts
        .and_then(|opts| mapping_get(opts, "headers"))
        .and_then(Value::as_mapping)
        .and_then(|headers| mapping_get(headers, "Host"))
        .map(string_value);
    match network.as_str() {
        "tcp" | "" => Ok(TransportSpec::Tcp),
        "ws" => Ok(TransportSpec::WebSocket(WebSocketConfig {
            path: path.unwrap_or_else(|| "/".into()).into(),
            host: host.map(Into::into),
            max_early_data: 0,
            early_data_header: None,
        })),
        "grpc" => Ok(TransportSpec::Grpc(GrpcConfig {
            service_name: path.unwrap_or_default().into(),
            multi_mode: false,
        })),
        "httpupgrade" => Ok(TransportSpec::HttpUpgrade(HttpUpgradeConfig {
            path: path.unwrap_or_else(|| "/".into()).into(),
            host: host.map(Into::into),
        })),
        value => Err(invalid("network", value)),
    }
}

fn parse_security(item: &Value, kind: &str) -> Result<SecuritySpec, ParseError> {
    let servername = string_at(item, "servername")
        .or_else(|| string_at(item, "sni"))
        .unwrap_or_default();
    let fingerprint = fingerprint(string_at(item, "client-fingerprint").as_deref());
    if let Some(reality) = value_at(item, "reality-opts") {
        let public_key = string_in(reality, "public-key")
            .or_else(|| string_in(reality, "public_key"))
            .ok_or(ParseError::MissingField("public-key"))?;
        let short_id = string_in(reality, "short-id")
            .or_else(|| string_in(reality, "short_id"))
            .unwrap_or_default();
        let server_name = if servername.is_empty() {
            string_at(item, "server").unwrap_or_default()
        } else {
            servername
        };
        return Ok(SecuritySpec::Reality(RealityConfig {
            server_name: server_name.into(),
            public_key: public_key.into(),
            short_id: short_id.into(),
            spider_x: string_in(reality, "spider-x")
                .or_else(|| string_in(reality, "spider_x"))
                .map(Into::into),
            fingerprint,
        }));
    }
    let tls_enabled = bool_at(item, "tls").unwrap_or(kind == "trojan") || !servername.is_empty();
    if tls_enabled {
        Ok(SecuritySpec::Tls(StandardTlsConfig {
            server_name: servername.into(),
            alpn: alpn(item),
            fingerprint,
            allow_insecure: bool_at(item, "allow-insecure").unwrap_or(false),
        }))
    } else {
        Ok(SecuritySpec::None)
    }
}

fn parse_vmess_security(item: &Value) -> SecuritySpec {
    if !bool_at(item, "tls").unwrap_or(false) {
        return SecuritySpec::None;
    }
    SecuritySpec::Tls(StandardTlsConfig {
        server_name: string_at(item, "servername").unwrap_or_default().into(),
        alpn: alpn(item),
        fingerprint: fingerprint(string_at(item, "client-fingerprint").as_deref()),
        allow_insecure: bool_at(item, "allow-insecure").unwrap_or(false),
    })
}

fn alpn(item: &Value) -> Vec<Arc<str>> {
    value_at(item, "alpn")
        .and_then(Value::as_sequence)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(Into::into)
                .collect()
        })
        .unwrap_or_default()
}

fn fingerprint(value: Option<&str>) -> UtlsFingerprint {
    match value.unwrap_or("").to_ascii_lowercase().as_str() {
        "chrome" => UtlsFingerprint::Chrome,
        "firefox" => UtlsFingerprint::Firefox,
        "safari" => UtlsFingerprint::Safari,
        "edge" => UtlsFingerprint::Edge,
        "randomized" | "random" => UtlsFingerprint::Randomized,
        _ => UtlsFingerprint::None,
    }
}

fn parse_uuid(value: &str) -> Result<uuid::Uuid, ParseError> {
    uuid::Uuid::parse_str(value).map_err(|_| ParseError::InvalidUuid(value.to_owned()))
}

fn endpoint(item: &Value) -> Result<EndpointTarget, ParseError> {
    let host = string_at(item, "server").ok_or(ParseError::MissingField("server"))?;
    let port = u16_at(item, "port")?.ok_or(ParseError::MissingField("port"))?;
    crate::uri::endpoint_from_host(&host, port)
}

fn label_of(item: &Value) -> Result<String, ParseError> {
    string_at(item, "name").ok_or(ParseError::MissingField("name"))
}

fn make_metadata(sub_id: SubId, label: &str, timestamp: u64) -> Result<NodeMetadata, ParseError> {
    crate::make_metadata(sub_id, label, timestamp)
}

fn value_at<'a>(item: &'a Value, key: &str) -> Option<&'a Value> {
    map_get(item, key)
}

fn bool_at(item: &Value, key: &str) -> Option<bool> {
    map_get(item, key).and_then(Value::as_bool)
}

fn string_at(item: &Value, key: &str) -> Option<String> {
    map_get(item, key).map(string_value)
}

fn string_in(item: &Value, key: &str) -> Option<String> {
    map_get(item, key).map(string_value)
}

fn string_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => String::new(),
    }
}

fn u16_at(item: &Value, key: &'static str) -> Result<Option<u16>, ParseError> {
    match map_get(item, key) {
        None => Ok(None),
        Some(value) => {
            let parsed = value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                .and_then(|value| u16::try_from(value).ok());
            match parsed {
                Some(port) => Ok(Some(port)),
                None => Err(invalid(key, string_value(value))),
            }
        }
    }
}

fn numeric_at(item: &Value, key: &str) -> Option<u64> {
    map_get(item, key).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })
}

fn map_get<'a>(item: &'a Value, key: &str) -> Option<&'a Value> {
    item.as_mapping()
        .and_then(|mapping| mapping_get(mapping, key))
}

fn mapping_get<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.into()))
}

fn to_invalid_endpoint(error: anyhow::Error) -> ParseError {
    ParseError::InvalidEndpoint(error.to_string())
}

fn invalid(field: &'static str, value: impl Into<String>) -> ParseError {
    ParseError::InvalidValue {
        field,
        value: value.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
proxies:
  - name: "SS JP 🇯🇵"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: secret
  - name: "VMess - Tokyo [JP]"
    type: vmess
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 0
    cipher: auto
    tls: true
    servername: host.example.com
    network: ws
    ws-opts:
      path: /ws?ed=2048
      headers:
        Host: host.example.com
  - name: "Trojan Deutschland"
    type: trojan
    server: t.example.net
    port: 443
    password: hunter2
    sni: t.example.net
  - name: "VLESS Reality"
    type: vless
    server: r.example.org
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    servername: www.example.org
    reality-opts:
      public-key: AABBCCDD
      short-id: 1234
  - name: "Hy2 SG"
    type: hysteria2
    server: 2001:db8::1
    port: 443
    password: hy
    up: "30"
    down: "100"
    obfs: salamander
    obfs-password: sop
    ports: "443,8443"
  - name: "TUIC - San Jose"
    type: tuic
    server: t.example.com
    port: 7788
    uuid: 22222222-2222-2222-2222-222222222222
    password: tpass
    congestion-controller: bbr
    udp-relay-mode: quic
  - name: "Old SSR"
    type: ssr
    server: x.example.com
    port: 8443
"#;

    #[test]
    fn parses_supported_clash_proxy_types() {
        let results = ingest_clash_yaml(SAMPLE, 7, 42).expect("yaml parses");
        let nodes: Vec<_> = results
            .iter()
            .filter_map(|result| result.as_ref().ok())
            .collect();
        assert_eq!(nodes.len(), 6);

        assert!(matches!(
            &nodes[0].protocol,
            ProtocolSpec::Shadowsocks(ShadowsocksConfig {
                method: ShadowsocksCipher::Aes128Gcm,
                ..
            })
        ));
        assert_eq!(nodes[0].meta.country_code, *b"JP"); // emoji wins

        assert!(matches!(
            &nodes[1].protocol,
            ProtocolSpec::Vmess(VmessConfig { alter_id: 0, .. })
        ));
        assert!(matches!(
            &nodes[1].transport,
            TransportSpec::WebSocket(WebSocketConfig { path, host, .. })
                if path.as_ref() == "/ws?ed=2048" && host.as_deref() == Some("host.example.com")
        ));
        assert!(matches!(
            &nodes[1].security,
            SecuritySpec::Tls(StandardTlsConfig { ref server_name, .. })
                if server_name.as_ref() == "host.example.com"
        ));
        assert_eq!(nodes[1].meta.country_code, *b"JP"); // bracket tag

        assert!(matches!(&nodes[2].protocol, ProtocolSpec::Trojan(TrojanConfig { .. })));
        assert!(matches!(&nodes[2].security, SecuritySpec::Tls(_))); // trojan defaults to tls
        assert_eq!(nodes[2].meta.country_code, *b"DE"); // dictionary

        assert!(matches!(
            &nodes[3].security,
            SecuritySpec::Reality(RealityConfig {
                ref public_key,
                ref short_id,
                ref server_name,
                ..
            }) if public_key.as_ref() == "AABBCCDD" && short_id.as_ref() == "1234" && server_name.as_ref() == "www.example.org"
        ));
        assert!(matches!(
            &nodes[3].endpoint,
            EndpointTarget::Domain { ref host, .. } if host.as_ref() == "r.example.org"
        ));

        assert!(matches!(
            &nodes[4].protocol,
            ProtocolSpec::Hysteria2(Hysteria2Config {
                up_mbps: Some(30),
                down_mbps: Some(100),
                obfs: Some(Hysteria2Obfs { .. }),
                ..
            })
        ));
        assert!(matches!(&nodes[4].endpoint, EndpointTarget::Ip(_)));

        assert!(matches!(
            &nodes[5].protocol,
            ProtocolSpec::Tuic(TuicConfig {
                congestion_control: TuicCongestion::Bbr,
                udp_relay_mode: TuicUdpRelay::Quic,
                ..
            })
        ));
        assert_eq!(nodes[5].meta.country_code, *b"US");
    }

    #[test]
    fn unsupported_proxy_types_are_per_item_failures() {
        let results = ingest_clash_yaml(SAMPLE, 7, 42).unwrap();
        let failures: Vec<_> = results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .collect();
        assert_eq!(failures.len(), 1);
        assert!(matches!(
            failures[0],
            ParseError::UnsupportedFormat(reason) if reason.contains("ssr")
        ));
    }

    #[test]
    fn missing_proxies_section_is_an_error() {
        let result = ingest_clash_yaml("proxy-groups: []", 1, 1);
        assert!(matches!(result, Err(ParseError::MissingField("proxies"))));
    }
}