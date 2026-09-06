use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("unsupported format or scheme: {0}")]
    UnsupportedFormat(String),
    #[error("malformed URI: {0}")]
    InvalidUri(String),
    #[error("Base64 decoding failed: {0}")]
    Base64Decode(String),
    #[error("JSON deserialization failed: {0}")]
    Json(String),
    #[error("missing mandatory field: {0}")]
    MissingField(&'static str),
    #[error("invalid UUID: {0}")]
    InvalidUuid(String),
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("invalid value for {field}: {value}")]
    InvalidValue { field: &'static str, value: String },
}

#[derive(Debug, Clone)]
pub struct ParseFailure {
    pub entry_index: usize,
    pub line_number: usize,
    pub raw_snippet: String,
    pub reason: ParseError,
}

#[derive(Debug, Default)]
pub struct IngestionReport {
    pub total_entries_scanned: usize,
    pub successful_nodes: Vec<myproxy_ir::CanonicalNode>,
    pub duplicates_omitted: usize,
    pub failed_entries: Vec<ParseFailure>,
}
