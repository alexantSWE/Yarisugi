mod clash;
mod error;
mod format;
mod metadata;
mod uri;

pub use error::{IngestionReport, ParseError, ParseFailure};

use myproxy_ir::{CanonicalHash, NodeMetadata, SubId};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ENTRIES: usize = 100_000;
const MAX_FAILURES: usize = 10_000;
const MAX_SNIPPET_BYTES: usize = 160;

pub fn ingest_subscription(raw: &[u8], sub_id: SubId) -> IngestionReport {
    ingest_with_timestamp(raw, sub_id, current_timestamp())
}

pub fn ingest_with_timestamp(raw: &[u8], sub_id: SubId, import_timestamp: u64) -> IngestionReport {
    let mut report = IngestionReport::default();
    let text = match std::str::from_utf8(raw) {
        Ok(text) => text,
        Err(error) => {
            record_failure(
                &mut report,
                0,
                1,
                raw,
                ParseError::InvalidUri(error.to_string()),
            );
            return report;
        }
    };
    let mut entries = collect_entries(text);

    if !entries.is_empty() && !entries.iter().any(|(_, entry)| format::is_supported_scheme(entry)) {
        match format::detect_container(text) {
            Some(format::ContainerKind::ClashYaml) => {
                ingest_clash_document(&mut report, raw, text, sub_id, import_timestamp);
                return report;
            }
            Some(format::ContainerKind::SingBoxJson) => {
                record_failure(
                    &mut report,
                    0,
                    1,
                    raw,
                    ParseError::UnsupportedFormat(
                        "sing-box JSON configuration is not supported; use proxy URI entries".into(),
                    ),
                );
                return report;
            }
            None => {}
        }
        let joined: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        match format::decode_bundle(joined.as_bytes()) {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(decoded_text) if format::looks_like_supported_entry(decoded_text.as_bytes()) => {
                    entries = collect_entries(&decoded_text);
                }
                Ok(decoded_text) => {
                    match format::detect_container(&decoded_text) {
                        Some(format::ContainerKind::ClashYaml) => {
                            ingest_clash_document(&mut report, raw, &decoded_text, sub_id, import_timestamp);
                            return report;
                        }
                        Some(format::ContainerKind::SingBoxJson) => {
                            record_failure(
                                &mut report,
                                0,
                                1,
                                raw,
                                ParseError::UnsupportedFormat(
                                    "sing-box JSON configuration is not supported; use proxy URI entries".into(),
                                ),
                            );
                            return report;
                        }
                        None => record_failure(
                            &mut report,
                            0,
                            1,
                            raw,
                            ParseError::UnsupportedFormat(
                                "input is not a supported URI bundle".into(),
                            ),
                        ),
                    }
                }
                Err(_) => record_failure(
                    &mut report,
                    0,
                    1,
                    raw,
                    ParseError::UnsupportedFormat("input is not a supported URI bundle".into()),
                ),
            },
            Err(error) => record_failure(&mut report, 0, 1, raw, ParseError::Base64Decode(error)),
        }
    }

    let mut seen = HashSet::<CanonicalHash>::with_capacity(entries.len().min(MAX_ENTRIES));
    for (entry_index, (line_number, entry)) in entries.into_iter().take(MAX_ENTRIES).enumerate() {
        report.total_entries_scanned += 1;
        match uri::parse_entry(&entry, sub_id, import_timestamp) {
            Ok(node) => {
                if seen.insert(node.hash) {
                    report.successful_nodes.push(node);
                } else {
                    report.duplicates_omitted += 1;
                }
            }
            Err(reason) => record_failure(
                &mut report,
                entry_index,
                line_number,
                entry.as_bytes(),
                reason,
            ),
        }
    }
    report
}

fn ingest_clash_document(
    report: &mut IngestionReport,
    raw: &[u8],
    text: &str,
    sub_id: SubId,
    import_timestamp: u64,
) {
    let results = match clash::ingest_clash_yaml(text, sub_id, import_timestamp) {
        Ok(results) => results,
        Err(reason) => {
            record_failure(report, 0, 1, raw, reason);
            return;
        }
    };
    let mut seen = HashSet::<CanonicalHash>::with_capacity(results.len().min(MAX_ENTRIES));
    for (index, result) in results.into_iter().take(MAX_ENTRIES).enumerate() {
        report.total_entries_scanned += 1;
        match result {
            Ok(node) if seen.insert(node.hash) => report.successful_nodes.push(node),
            Ok(_) => report.duplicates_omitted += 1,
            Err(reason) => record_failure(report, index, index + 1, raw, reason),
        }
    }
}

fn record_failure(
    report: &mut IngestionReport,
    entry_index: usize,
    line_number: usize,
    raw: &[u8],
    reason: ParseError,
) {
    if report.failed_entries.len() < MAX_FAILURES {
        report.failed_entries.push(ParseFailure {
            entry_index,
            line_number,
            raw_snippet: safe_snippet(raw),
            reason,
        });
    }
}

fn safe_snippet(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let scheme = format::scheme_of(text.trim()).unwrap_or("entry");
    let snippet = format!("{scheme}://[redacted]");
    snippet.chars().take(MAX_SNIPPET_BYTES).collect()
}

fn collect_entries(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim();
            (!line.is_empty() && !line.starts_with('#')).then_some((index + 1, line.to_owned()))
        })
        .collect()
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn make_metadata(
    sub_id: SubId,
    label: &str,
    import_timestamp: u64,
) -> Result<NodeMetadata, ParseError> {
    NodeMetadata::new(
        sub_id,
        label.to_owned(),
        metadata::extract_country_code(label),
        import_timestamp,
    )
    .map_err(|error| ParseError::InvalidValue {
        field: "metadata",
        value: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn malformed_entry_does_not_abort_valid_entries() {
        let input = b"vless://00000000-0000-0000-0000-000000000000@example.com:443#DE\nvless://not-a-uuid@example.com:443";
        let report = ingest_with_timestamp(input, 1, 10);
        assert_eq!(report.successful_nodes.len(), 1);
        assert_eq!(report.failed_entries.len(), 1);
    }

    #[test]
    fn multi_line_base64_payload_is_decoded_as_one_bundle() {
        let payload =
            "vless://00000000-0000-0000-0000-000000000000@example.com:443#DE\nvless://11111111-1111-1111-1111-111111111111@example.org:443#US";
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        let wrapped = encoded
            .as_bytes()
            .chunks(48)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let report = ingest_with_timestamp(wrapped.as_bytes(), 1, 10);
        assert_eq!(report.successful_nodes.len(), 2);
    }

    #[test]
    fn clash_yaml_is_ingested() {
        let input = b"proxies:\n  - name: edge\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-128-gcm\n    password: secret\n";
        let report = ingest_with_timestamp(input, 1, 10);
        assert_eq!(report.successful_nodes.len(), 1);
        assert_eq!(report.failed_entries.len(), 0);
        assert_eq!(report.successful_nodes[0].meta.country_code, *b"UN");
    }

    #[test]
    fn shadowsocks_plugin_opts_are_preserved() {
        let link = "ss://YWVzLTEyOC1nY206cGFzcw@example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dsecret.example#SSE";
        let report = ingest_with_timestamp(link.as_bytes(), 1, 10);
        assert_eq!(report.successful_nodes.len(), 1);
        match &report.successful_nodes[0].protocol {
            myproxy_ir::ProtocolSpec::Shadowsocks(config) => {
                assert_eq!(config.plugin.as_deref(), Some("obfs-local"));
                assert_eq!(
                    config.plugin_opts.as_deref(),
                    Some("obfs=http;obfs-host=secret.example")
                );
            }
            _ => panic!("expected shadowsocks node"),
        }
    }
}
