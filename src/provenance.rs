use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::error::BluelineError;
use crate::policy::Policy;
use crate::store::BaselineStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceStatus {
    Verified,
    Unverified,
    Missing,
    FailedMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceReport {
    pub status: ProvenanceStatus,
    pub slsa_level: u32,
    pub builder_id: Option<String>,
    pub source_repo: Option<String>,
    pub commit_sha: Option<String>,
    pub workflow_path: Option<String>,
    pub registry_signature_present: bool,
    pub registry_signature_key_id: Option<String>,
    pub message: Option<String>,
}

impl ProvenanceReport {
    pub fn missing(has_signature: bool, key_id: Option<String>) -> Self {
        Self {
            status: ProvenanceStatus::Missing,
            slsa_level: 0,
            builder_id: None,
            source_repo: None,
            commit_sha: None,
            workflow_path: None,
            registry_signature_present: has_signature,
            registry_signature_key_id: key_id,
            message: Some("No SLSA build attestation published for this release".into()),
        }
    }

    pub fn failed_mismatch(details: &str) -> Self {
        Self {
            status: ProvenanceStatus::FailedMismatch,
            slsa_level: 0,
            builder_id: None,
            source_repo: None,
            commit_sha: None,
            workflow_path: None,
            registry_signature_present: false,
            registry_signature_key_id: None,
            message: Some(format!("Provenance digest mismatch: {details}")),
        }
    }
}

#[derive(Debug, Deserialize)]
struct NpmAttestationEnvelope {
    #[serde(default)]
    attestations: Vec<NpmAttestationItem>,
}

#[derive(Debug, Deserialize)]
struct NpmAttestationItem {
    #[serde(default)]
    bundle: Option<SigstoreBundle>,
}

#[derive(Debug, Deserialize)]
struct SigstoreBundle {
    #[serde(rename = "dsseEnvelope")]
    #[serde(default)]
    dsse_envelope: Option<DsseEnvelope>,
}

#[derive(Debug, Deserialize)]
struct DsseEnvelope {
    #[serde(default)]
    payload: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InTotoStatement {
    #[serde(default)]
    subject: Vec<InTotoSubject>,
    #[serde(default)]
    predicate: Option<InTotoPredicate>,
}

#[derive(Debug, Deserialize)]
struct InTotoSubject {
    #[serde(default)]
    digest: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct InTotoPredicate {
    #[serde(default)]
    builder: Option<InTotoBuilder>,
    #[serde(default)]
    invocation: Option<InTotoInvocation>,
}

#[derive(Debug, Deserialize)]
struct InTotoBuilder {
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InTotoInvocation {
    #[serde(rename = "configSource")]
    #[serde(default)]
    config_source: Option<InTotoConfigSource>,
}

#[derive(Debug, Deserialize)]
struct InTotoConfigSource {
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    digest: std::collections::HashMap<String, String>,
    #[serde(rename = "entryPoint")]
    #[serde(default)]
    entry_point: Option<String>,
}

/// Parse and verify Sigstore / SLSA in-toto statement against tarball integrity sha512.
pub fn parse_attestation_payload(
    raw_payload_base64: &str,
    expected_integrity: &str,
) -> Result<ProvenanceReport, BluelineError> {
    let engine = base64::engine::general_purpose::STANDARD;
    let decoded_bytes = engine.decode(raw_payload_base64.trim()).map_err(|e| {
        BluelineError::Provenance(format!("failed to base64-decode DSSE payload: {e}"))
    })?;

    let statement: InTotoStatement = serde_json::from_slice(&decoded_bytes).map_err(|e| {
        BluelineError::Provenance(format!("failed to parse in-toto statement JSON: {e}"))
    })?;

    let expected_hex_or_b64 = expected_integrity
        .strip_prefix("sha512-")
        .unwrap_or(expected_integrity);

    let expected_hex = engine
        .decode(expected_hex_or_b64)
        .ok()
        .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());

    let digest_matched = statement.subject.iter().any(|subj| {
        subj.digest.get("sha512").is_some_and(|val| {
            val == expected_hex_or_b64
                || val == expected_integrity
                || expected_hex
                    .as_deref()
                    .is_some_and(|hex| val.eq_ignore_ascii_case(hex))
        })
    });

    if !digest_matched {
        return Ok(ProvenanceReport::failed_mismatch(
            "tarball sha512 does not match in-toto statement subject digest",
        ));
    }

    let mut builder_id = None;
    let mut source_repo = None;
    let mut commit_sha = None;
    let mut workflow_path = None;

    if let Some(pred) = statement.predicate {
        builder_id = pred.builder.and_then(|b| b.id);
        if let Some(cfg) = pred.invocation.and_then(|invoc| invoc.config_source) {
            source_repo = cfg.uri;
            workflow_path = cfg.entry_point;
            commit_sha = cfg
                .digest
                .get("sha1")
                .or_else(|| cfg.digest.get("sha256"))
                .cloned();
        }
    }

    Ok(ProvenanceReport {
        status: ProvenanceStatus::Verified,
        slsa_level: 3,
        builder_id,
        source_repo,
        commit_sha,
        workflow_path,
        registry_signature_present: true,
        registry_signature_key_id: None,
        message: None,
    })
}

/// Inspect registry metadata or fetch attestations bundle for target package.
pub fn inspect_provenance(
    package: &str,
    version: &str,
    expected_integrity: &str,
    signatures_json: Option<&serde_json::Value>,
    store: Option<&BaselineStore>,
    _policy: &Policy,
) -> ProvenanceReport {
    // 1. Check registry signature presence
    let (has_sig, sig_key_id) = signatures_json
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .map_or((false, None), |sig| {
            (
                true,
                sig.get("keyid").and_then(|k| k.as_str()).map(String::from),
            )
        });

    // 2. Check local provenance cache
    if let Some(store) = store
        && let Ok(Some(cached)) = store.get_cached_provenance(package, version)
    {
        return ProvenanceReport {
            status: ProvenanceStatus::Verified,
            slsa_level: cached.slsa_level,
            builder_id: cached.builder_id,
            source_repo: cached.source_repo,
            commit_sha: cached.commit_sha,
            workflow_path: cached.workflow_path,
            registry_signature_present: cached.signature_valid || has_sig,
            registry_signature_key_id: sig_key_id,
            message: None,
        };
    }

    // 3. Attempt to fetch npm attestations endpoint
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_millis(3000))
        .build();

    let encoded_pkg = package.replace('/', "%2f");
    let attestations_url =
        format!("https://registry.npmjs.org/-/npm/v1/attestations/{encoded_pkg}@{version}");
    let resp_res = agent
        .get(&attestations_url)
        .set("Accept", "application/json")
        .set("User-Agent", "blueline-security/0.1.0")
        .call();

    if let Ok(resp) = resp_res {
        let mut reader = resp.into_reader().take(1024 * 1024);
        let mut body = String::new();
        if reader.read_to_string(&mut body).is_ok()
            && let Ok(envelope) = serde_json::from_str::<NpmAttestationEnvelope>(&body)
        {
            for item in envelope.attestations {
                if let Some(payload_b64) = item
                    .bundle
                    .and_then(|b| b.dsse_envelope)
                    .and_then(|d| d.payload)
                    && let Ok(mut report) =
                        parse_attestation_payload(&payload_b64, expected_integrity)
                {
                    report.registry_signature_present = has_sig;
                    report.registry_signature_key_id = sig_key_id.clone();

                    // Cache in SQLite store
                    if let Some(store) = store {
                        let _ = store.record_provenance(
                            package,
                            version,
                            report.builder_id.as_deref(),
                            report.source_repo.as_deref(),
                            report.commit_sha.as_deref(),
                            report.workflow_path.as_deref(),
                            report.slsa_level,
                            has_sig,
                        );
                    }

                    return report;
                }
            }
        }
    }

    // Default: missing SLSA provenance
    ProvenanceReport::missing(has_sig, sig_key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_intoto_statement() {
        let intoto_json = r#"{
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "pkg:npm/express@4.21.2",
                    "digest": {
                        "sha512": "abc123expected"
                    }
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {
                    "id": "https://github.com/actions/runner"
                },
                "invocation": {
                    "configSource": {
                        "uri": "git+https://github.com/expressjs/express@refs/heads/main",
                        "digest": {
                            "sha1": "7ab3c49"
                        },
                        "entryPoint": ".github/workflows/release.yml"
                    }
                }
            }
        }"#;

        let b64 = base64::engine::general_purpose::STANDARD.encode(intoto_json.as_bytes());
        let report = parse_attestation_payload(&b64, "sha512-abc123expected").unwrap();

        assert_eq!(report.status, ProvenanceStatus::Verified);
        assert_eq!(report.slsa_level, 3);
        assert_eq!(
            report.builder_id.as_deref(),
            Some("https://github.com/actions/runner")
        );
        assert_eq!(
            report.source_repo.as_deref(),
            Some("git+https://github.com/expressjs/express@refs/heads/main")
        );
        assert_eq!(report.commit_sha.as_deref(), Some("7ab3c49"));
        assert_eq!(
            report.workflow_path.as_deref(),
            Some(".github/workflows/release.yml")
        );
    }

    #[test]
    fn flags_digest_mismatch_as_failure() {
        let intoto_json = r#"{
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "pkg:npm/express@4.21.2",
                    "digest": {
                        "sha512": "different_hash"
                    }
                }
            ]
        }"#;

        let b64 = base64::engine::general_purpose::STANDARD.encode(intoto_json.as_bytes());
        let report = parse_attestation_payload(&b64, "sha512-expected_real_hash").unwrap();

        assert_eq!(report.status, ProvenanceStatus::FailedMismatch);
    }

    #[test]
    fn empty_subject_attestation_fails_closed() {
        let intoto_json = r#"{
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {
                    "id": "https://github.com/actions/runner"
                }
            }
        }"#;

        let b64 = base64::engine::general_purpose::STANDARD.encode(intoto_json.as_bytes());
        let report = parse_attestation_payload(&b64, "sha512-anything").unwrap();

        assert_eq!(report.status, ProvenanceStatus::FailedMismatch);
    }
}
