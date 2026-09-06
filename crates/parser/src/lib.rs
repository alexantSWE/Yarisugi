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
    let mut entries: Vec<(usize, String)> = text
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim();
            (!line.is_empty() && !line.starts_with('#')).then_some((index + 1, line.to_owned()))
        })
        .collect();

    if entries.len() == 1 && format::scheme_of(&entries[0].1).is_none() {
        match format::decode_bundle(entries[0].1.as_bytes()) {
            Ok(decoded) if format::looks_like_supported_entry(&decoded) => {
                if let Ok(decoded_text) = String::from_utf8(decoded) {
                    entries = decoded_text
                        .lines()
                        .enumerate()
                        .filter_map(|(index, line)| {
                            let line = line.trim();
                            (!line.is_empty() && !line.starts_with('#'))
                                .then_some((index + 1, line.to_owned()))
                        })
                        .collect();
                }
            }
            Ok(_) => record_failure(
                &mut report,
                0,
                1,
                raw,
                ParseError::UnsupportedFormat("input is not a supported URI bundle".into()),
            ),
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

    #[test]
    fn malformed_entry_does_not_abort_valid_entries() {
        let input = b"vless://00000000-0000-0000-0000-000000000000@example.com:443#DE\nvless://not-a-uuid@example.com:443";
        let report = ingest_with_timestamp(input, 1, 10);
        assert_eq!(report.successful_nodes.len(), 1);
        assert_eq!(report.failed_entries.len(), 1);
    }
}
