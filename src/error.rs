use thiserror::Error;

/// Typed engine errors. The `blueline` binary maps these into `anyhow`
/// contexts; CI/MCP surfaces (later phases) can branch on the variants.
#[derive(Debug, Error)]
pub enum BluelineError {
    #[error("invalid package spec `{0}`: expected `<name>@<version>`")]
    InvalidPackageSpec(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("registry response for `{0}`: {1}")]
    Manifest(String, String),

    #[error("extraction failed: {0}")]
    Extraction(String),

    #[error("extraction limit exceeded: {0}")]
    ExtractionLimit(String),

    #[error("integrity verification failed: {0}")]
    Verification(String),

    #[error("baseline store: {0}")]
    Store(String),

    #[error("policy error: {0}")]
    Policy(String),

    #[error("advisory error: {0}")]
    Advisory(String),

    #[error("provenance error: {0}")]
    Provenance(String),
}
