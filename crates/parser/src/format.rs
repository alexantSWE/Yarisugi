use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;

const MAX_DECODED_BYTES: usize = 8 * 1024 * 1024;

pub fn decode_bundle(raw: &[u8]) -> Result<Vec<u8>, String> {
    let compact: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if compact.is_empty() || compact.len() > MAX_DECODED_BYTES.saturating_mul(2) {
        return Err("empty or oversized Base64 input".into());
    }
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(decoded) = engine.decode(&compact) {
            if decoded.len() <= MAX_DECODED_BYTES {
                return Ok(decoded);
            }
        }
    }
    Err("unsupported alphabet, padding, or input length".into())
}

pub fn scheme_of(entry: &str) -> Option<&str> {
    let (scheme, _) = entry.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+.-".contains(&byte))
    {
        return None;
    }
    Some(scheme)
}

pub fn looks_like_supported_entry(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| text.lines().any(|line| is_supported_scheme(line.trim())))
}

pub fn is_supported_scheme(entry: &str) -> bool {
    matches!(
        scheme_of(entry).map(str::to_ascii_lowercase).as_deref(),
        Some("vless")
            | Some("vmess")
            | Some("trojan")
            | Some("ss")
            | Some("hysteria2")
            | Some("hy2")
            | Some("tuic")
    )
}

/// Well-known subscription container formats that are not plain URI entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    ClashYaml,
    SingBoxJson,
}

/// Recognizes well-known subscription container formats so callers can route
/// them to a dedicated parser or emit a single precise failure.
pub fn detect_container(text: &str) -> Option<ContainerKind> {
    if looks_like_clash_yaml(text) {
        return Some(ContainerKind::ClashYaml);
    }
    if looks_like_singbox_json(text) {
        return Some(ContainerKind::SingBoxJson);
    }
    None
}

fn looks_like_clash_yaml(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        line == "proxies:" || line == "proxy-groups:" || line == "rules:"
    })
}

fn looks_like_singbox_json(text: &str) -> bool {
    if !text.trim_start().starts_with('{') {
        return false;
    }
    #[derive(Deserialize)]
    struct ContainerProbe {
        outbounds: Option<serde_json::Value>,
        inbounds: Option<serde_json::Value>,
    }
    let mut bytes = text.as_bytes().to_vec();
    match simd_json::serde::from_slice::<ContainerProbe>(&mut bytes) {
        Ok(probe) => probe.outbounds.is_some() || probe.inbounds.is_some(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD_NO_PAD;

    #[test]
    fn accepts_unpadded_url_safe_payloads() {
        let encoded = STANDARD_NO_PAD.encode(b"vless://example.com:443");
        assert!(looks_like_supported_entry(
            &decode_bundle(encoded.as_bytes()).unwrap()
        ));
    }

    #[test]
    fn rejects_random_decodable_text_at_dispatch_boundary() {
        let decoded = decode_bundle(b"Zm9v").unwrap();
        assert!(!looks_like_supported_entry(&decoded));
    }

    #[test]
    fn detects_clash_yaml_containers() {
        let yaml = "proxies:\n  - name: edge-01\n    type: ss\n    server: 1.2.3.4\n";
        assert_eq!(detect_container(yaml), Some(ContainerKind::ClashYaml));
    }

    #[test]
    fn detects_singbox_json_containers() {
        let json = r#"{"log":{},"outbounds":[{"type":"direct"}]}"#;
        assert_eq!(detect_container(json), Some(ContainerKind::SingBoxJson));
    }

    #[test]
    fn leaves_supported_uri_entries_alone() {
        assert!(detect_container("vless://a@example.com:443#DE").is_none());
    }
}
