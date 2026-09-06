use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;

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
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return false,
    };
    text.lines().any(|line| {
        matches!(
            scheme_of(line.trim())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("vless")
                | Some("vmess")
                | Some("trojan")
                | Some("ss")
                | Some("hysteria2")
                | Some("hy2")
                | Some("tuic")
        )
    })
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
}
