use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::BluelineError;
use crate::policy::Policy;
use crate::registry::{Checksum, Ecosystem};
use crate::store::BaselineStore;

/// Sent on every registry request, so the shared validating agent sets it in
/// one place rather than each call site remembering to.
const USER_AGENT: &str = "blueline-security/0.1.0";

/// Ceiling on one attestation body. A DSSE envelope for a large multi-platform
/// release runs to a few hundred kilobytes; a megabyte is generous, and going
/// over it is an error rather than a truncation. Truncating produced text that
/// then failed to parse, which reported a *missing* attestation for a release
/// that has one -- the parser mistaking "too much" for "nothing".
const MAX_ATTESTATION_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceStatus {
    /// A build statement was published and its subject digest matched the
    /// bytes under review. No DSSE signature and no Sigstore certificate chain
    /// were checked, so this is not a statement about who built it.
    Attested,
    /// Reserved for a real Sigstore verification path, which needs a
    /// dependency this project has not approved. Nothing produces it yet, so
    /// `require_provenance` is never satisfied in practice. It is disclosed
    /// rather than refused, because refusing would block every release that set
    /// the key before blueline could check a signature at all; a claim that
    /// cannot be verified is still refused.
    CryptographicallyVerified,
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

    pub fn unverified(msg: &str) -> Self {
        Self::unverified_with_signature(msg, false, None)
    }

    /// As `unverified`, but keeping the registry signature evidence the caller
    /// already holds.
    ///
    /// The signature block comes from the packument, which arrived before the
    /// attestation fetch was attempted, so a failed attestation request is no
    /// reason to forget it. Dropping it here would make `require_signatures`
    /// report a *missing* signature for a release that published one, which is
    /// the opposite of what happened.
    pub fn unverified_with_signature(
        msg: &str,
        has_signature: bool,
        key_id: Option<String>,
    ) -> Self {
        Self {
            status: ProvenanceStatus::Unverified,
            slsa_level: 0,
            builder_id: None,
            source_repo: None,
            commit_sha: None,
            workflow_path: None,
            registry_signature_present: has_signature,
            registry_signature_key_id: key_id,
            message: Some(format!("Provenance unverified: {msg}")),
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

/// Parse and verify a Sigstore / SLSA in-toto statement against the tarball
/// checksum. The subject digest must equal the expected digest content
/// (case-insensitive hex) for the checksum's algorithm.
pub fn parse_attestation_payload(
    raw_payload_base64: &str,
    expected_integrity: &Checksum,
) -> Result<ProvenanceReport, BluelineError> {
    let engine = base64::engine::general_purpose::STANDARD;
    let decoded_bytes = engine.decode(raw_payload_base64.trim()).map_err(|e| {
        BluelineError::Provenance(format!("failed to base64-decode DSSE payload: {e}"))
    })?;

    let statement: InTotoStatement = serde_json::from_slice(&decoded_bytes).map_err(|e| {
        BluelineError::Provenance(format!("failed to parse in-toto statement JSON: {e}"))
    })?;

    let alg_key = expected_integrity.alg.name();
    let digest_matched = statement.subject.iter().any(|subj| {
        subj.digest
            .get(alg_key)
            .is_some_and(|val| val.eq_ignore_ascii_case(&expected_integrity.value_hex))
    });

    if !digest_matched {
        return Ok(ProvenanceReport::failed_mismatch(&format!(
            "tarball {alg_key} does not match in-toto statement subject digest"
        )));
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
        status: ProvenanceStatus::Attested,
        // No signature was checked, so no SLSA level is earned.
        slsa_level: 0,
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
/// `attestations_base` is the registry base serving the npm attestations
/// endpoint (threaded from the resolved registry, never hardcoded).
pub fn inspect_provenance(
    package: &str,
    version: &str,
    expected_integrity: &Checksum,
    signatures_json: Option<&serde_json::Value>,
    attestations_base: &str,
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
        && let Ok(Some(cached)) = store.get_cached_provenance(Ecosystem::Npm, package, version)
    {
        return ProvenanceReport {
            status: ProvenanceStatus::Attested,
            // Cached rows written before this change may carry a level that
            // was never earned, so it is not read back.
            slsa_level: 0,
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
    //
    // The base is operator config and so is trusted; the *response* is not. A
    // registry that answers with a 302 can point this at the loopback
    // interface or a link-local metadata address, and a bare `AgentBuilder`
    // follows up to five such hops to any host. Every other registry fetch in
    // the tree goes through `registry_agent`, whose documented purpose is that
    // each hop is SSRF-validated rather than followed blindly; these two sites
    // built their own agent and so opted out of the check the rest of the
    // codebase relies on.
    //
    // `download_bounded` also fixes the size cap's direction: the old
    // `take(1 MiB)` silently truncated a larger body, and the truncated text
    // then failed to parse, so an over-cap response reported *missing*
    // provenance for a release that has some. Over the cap is now an error,
    // which is the direction this parser wants.
    let encoded_pkg = package.replace('/', "%2f");
    let base = attestations_base.trim_end_matches('/');
    let attestations_url = format!("{base}/-/npm/v1/attestations/{encoded_pkg}@{version}");
    let agent = crate::registry::http_util::registry_agent_with_timeout(
        USER_AGENT,
        base,
        std::time::Duration::from_millis(3000),
    );

    // A failed fetch is not evidence that nobody published anything, and the
    // two used to be the same report. The endpoint answers 404 for a release
    // with no provenance, which is a real and common answer; everything else
    // (refused connection, 5xx, body over the cap, a refused redirect, a body
    // that would not parse) means the question was never answered. Reported as
    // `Missing` those all said "no SLSA build attestation published for this
    // release", which is the one status a `require_provenance` policy reads as
    // verified absence. Since absence became LOW and score-neutral, a registry
    // outage now produced a verdict identical to a clean pass.
    let fetched = crate::registry::http_util::download_bounded_optional(
        &agent,
        base,
        &attestations_url,
        MAX_ATTESTATION_BYTES,
        5,
        &[("Accept", "application/json")],
    );

    let Some(bytes) = (match fetched {
        Ok(bytes) => bytes,
        Err(e) => {
            return ProvenanceReport::unverified_with_signature(
                &e.to_string(),
                has_sig,
                sig_key_id,
            );
        }
    }) else {
        // 404: the registry states there is no attestation for this release.
        return ProvenanceReport::missing(has_sig, sig_key_id);
    };

    let Some(body) = String::from_utf8(bytes).ok() else {
        return ProvenanceReport::unverified_with_signature(
            "the attestations endpoint sent a non-UTF-8 body",
            has_sig,
            sig_key_id,
        );
    };

    match serde_json::from_str::<NpmAttestationEnvelope>(&body) {
        Ok(envelope) => {
            for item in envelope.attestations {
                if let Some(payload_b64) = item
                    .bundle
                    .and_then(|b| b.dsse_envelope)
                    .and_then(|d| d.payload)
                {
                    match parse_attestation_payload(&payload_b64, expected_integrity) {
                        Ok(mut report) => {
                            report.registry_signature_present = has_sig;
                            report.registry_signature_key_id = sig_key_id.clone();

                            // Cache in SQLite store, but only an attestation
                            // that actually verified. A digest mismatch is an
                            // integrity failure, and the cache has no status
                            // column, so a cache hit replays as `Attested`
                            // unconditionally: writing a mismatch would launder
                            // it into a passing verdict on every later review.
                            if report.status == ProvenanceStatus::Attested
                                && let Some(store) = store
                            {
                                let _ = store.record_provenance(
                                    Ecosystem::Npm,
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
                        Err(e) => {
                            return ProvenanceReport::unverified_with_signature(
                                &e.to_string(),
                                has_sig,
                                sig_key_id,
                            );
                        }
                    }
                }
            }
        }
        Err(e) => {
            return ProvenanceReport::unverified_with_signature(
                &format!("parsing the npm attestations response: {e}"),
                has_sig,
                sig_key_id,
            );
        }
    }

    // A well-formed envelope carrying no attestations. The registry answered,
    // and the answer is that there are none.
    ProvenanceReport::missing(has_sig, sig_key_id)
}

#[derive(Debug, Deserialize)]
struct PyPiProvenanceResponse {
    #[serde(default)]
    attestation_bundles: Vec<PyPiAttestationBundle>,
    #[serde(default)]
    attestations: Vec<NpmAttestationItem>,
}

#[derive(Debug, Deserialize)]
struct PyPiAttestationBundle {
    #[serde(default)]
    attestations: Vec<NpmAttestationItem>,
}

/// Parse PEP 740 provenance response JSON and verify in-toto subject hash.
///
/// Accepts two shapes: a `attestations` / `attestation_bundles` document and a
/// bare DSSE envelope. A body matching neither is a parse failure, not absence:
/// it is what a captive portal or an error page under a 200 looks like, and
/// returning `missing` for it told a `require_provenance` policy that nobody
/// published provenance when in fact nobody answered.
pub fn parse_pypi_provenance_json(
    body: &str,
    expected_integrity: &Checksum,
) -> Result<ProvenanceReport, BluelineError> {
    let mut had_attestations = false;
    let mut mismatch_details = None;
    let envelope_error = match serde_json::from_str::<PyPiProvenanceResponse>(body) {
        Ok(resp) => {
            let mut all_items = resp.attestations;
            for bundle in resp.attestation_bundles {
                all_items.extend(bundle.attestations);
            }
            for item in all_items {
                if let Some(payload_b64) = item
                    .bundle
                    .and_then(|b| b.dsse_envelope)
                    .and_then(|d| d.payload)
                {
                    had_attestations = true;
                    let mut report = parse_attestation_payload(&payload_b64, expected_integrity)?;
                    // An exhaustive match rather than a two-armed `if`, and the
                    // reason is the mutation gate. It reported `==` to `!=` on
                    // the `FailedMismatch` test as a survivor: with only two
                    // possible statuses, `status != FailedMismatch` is true for
                    // `Attested`, and that arm returns early above, so no test
                    // can observe the difference. Here a mutant would have to
                    // delete or reorder an arm, which is a compile error rather
                    // than a survivor someone has to explain away.
                    match report.status {
                        ProvenanceStatus::Attested => {
                            report.message = Some(
                                "PEP 740 attestation verified (crypto verification not performed)"
                                    .into(),
                            );
                            return Ok(report);
                        }
                        ProvenanceStatus::FailedMismatch => {
                            mismatch_details = report.message;
                        }
                        other => {
                            return Err(BluelineError::Provenance(format!(
                                "an in-toto statement produced an unexpected status {other:?}"
                            )));
                        }
                    }
                }
            }
            // A well-formed envelope that carries no attestation. The registry
            // answered, and the answer is that there are none.
            None
        }
        Err(envelope_err) => Some(envelope_err),
    };

    // Direct DSSE envelope format: {"payload": "..."}
    if let Ok(dsse) = serde_json::from_str::<DsseEnvelope>(body)
        && let Some(payload_b64) = dsse.payload
    {
        had_attestations = true;
        let mut report = parse_attestation_payload(&payload_b64, expected_integrity)?;
        // Exhaustive for the same reason as the envelope arm above.
        match report.status {
            ProvenanceStatus::Attested => {
                report.message =
                    Some("PEP 740 attestation verified (crypto verification not performed)".into());
                return Ok(report);
            }
            ProvenanceStatus::FailedMismatch => {
                mismatch_details = report.message;
            }
            other => {
                return Err(BluelineError::Provenance(format!(
                    "a DSSE payload produced an unexpected status {other:?}"
                )));
            }
        }
    }

    if had_attestations {
        let msg = mismatch_details
            .unwrap_or_else(|| "subject digest does not match release artifact".into());
        return Ok(ProvenanceReport::failed_mismatch(&msg));
    }

    // Neither shape parsed, so this body is not a provenance document. Reported
    // as an error rather than absence: a 200 carrying an HTML error page is a
    // registry that did not answer, and calling it "no attestation published"
    // hands a clean bill of health to an outage.
    if let Some(envelope_err) = envelope_error {
        return Err(BluelineError::Provenance(format!(
            "the provenance response matched neither the PEP 740 envelope nor a DSSE \
             payload: {envelope_err}"
        )));
    }

    // The envelope parsed and carried no attestation. The registry answered,
    // and the answer is that there are none.
    Ok(ProvenanceReport::missing(false, None))
}

/// Inspect PEP 740 provenance for a PyPI release.
pub fn inspect_provenance_pypi(
    package: &str,
    version: &str,
    filename: &str,
    expected_integrity: &Checksum,
    registry_base: &str,
    store: Option<&BaselineStore>,
    _policy: &Policy,
) -> ProvenanceReport {
    let norm = crate::version::canonicalize_name(package);

    // 1. Check local cache
    if let Some(store) = store
        && let Ok(Some(cached)) = store.get_cached_provenance(Ecosystem::PyPi, package, version)
    {
        return ProvenanceReport {
            status: ProvenanceStatus::Attested,
            // Cached rows written before this change may carry a level that
            // was never earned, so it is not read back.
            slsa_level: 0,
            builder_id: cached.builder_id,
            source_repo: cached.source_repo,
            commit_sha: cached.commit_sha,
            workflow_path: cached.workflow_path,
            registry_signature_present: cached.signature_valid,
            registry_signature_key_id: None,
            message: Some(
                "PEP 740 attestation verified from cache (crypto verification not performed)"
                    .into(),
            ),
        };
    }

    // 2. Fetch PyPI provenance endpoint. Same reasoning as the npm attestations
    // fetch above: the configured base is trusted, the response is not, so the
    // agent validates every resolved address and every redirect hop is checked
    // rather than followed blindly.
    let base = registry_base.trim_end_matches('/');
    let provenance_url = format!("{base}/integrity/{norm}/{version}/{filename}/provenance");
    let agent = crate::registry::http_util::registry_agent_with_timeout(
        USER_AGENT,
        base,
        std::time::Duration::from_millis(3000),
    );

    // The same split as the npm lane above, for the same reason: only a 404
    // from this endpoint states that no provenance was published. A 5xx, a
    // refused connection, a body over the cap, or a body that would not parse
    // mean the question went unanswered, and reporting those as `Missing` let a
    // registry outage read as verified absence to any `require_provenance`
    // policy.
    let fetched = crate::registry::http_util::download_bounded_optional(
        &agent,
        base,
        &provenance_url,
        MAX_ATTESTATION_BYTES,
        5,
        &[("Accept", "application/json")],
    );

    let fetched = match fetched {
        Ok(Some(bytes)) => bytes,
        // 404: PEP 740 says there is no attestation for this file.
        Ok(None) => return ProvenanceReport::missing(false, None),
        Err(e) => return ProvenanceReport::unverified(&e.to_string()),
    };

    let body = match String::from_utf8(fetched) {
        Ok(body) => body,
        Err(_) => {
            return ProvenanceReport::unverified("the provenance endpoint sent a non-UTF-8 body");
        }
    };

    match parse_pypi_provenance_json(&body, expected_integrity) {
        Ok(report) => {
            if report.status == ProvenanceStatus::Attested
                && let Some(store) = store
            {
                let _ = store.record_provenance(
                    Ecosystem::PyPi,
                    package,
                    version,
                    report.builder_id.as_deref(),
                    report.source_repo.as_deref(),
                    report.commit_sha.as_deref(),
                    report.workflow_path.as_deref(),
                    report.slsa_level,
                    false,
                );
            }
            report
        }
        Err(e) => ProvenanceReport::unverified(&e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ChecksumAlg;
    use sha2::{Digest, Sha512};

    fn ck(tag: &str) -> Checksum {
        let mut hasher = Sha512::new();
        hasher.update(tag.as_bytes());
        Checksum {
            alg: ChecksumAlg::Sha512,
            value_hex: format!("{:x}", hasher.finalize()),
        }
    }

    #[test]
    fn parses_valid_intoto_statement() {
        let intoto_json = r#"{
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "pkg:npm/express@4.21.2",
                    "digest": {
                        "sha512": "__HEX__"
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

        let expected = ck("expected");
        let intoto_json = intoto_json.replace("__HEX__", &expected.value_hex);
        let b64 = base64::engine::general_purpose::STANDARD.encode(intoto_json.as_bytes());
        let report = parse_attestation_payload(&b64, &expected).unwrap();

        assert_eq!(report.status, ProvenanceStatus::Attested);
        // The fixture carries a matching subject digest and no signature, so
        // no SLSA level is earned. This assertion used to be 3.
        assert_eq!(report.slsa_level, 0);
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
        let report = parse_attestation_payload(&b64, &ck("expected_real_hash")).unwrap();

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
        let report = parse_attestation_payload(&b64, &ck("anything")).unwrap();

        assert_eq!(report.status, ProvenanceStatus::FailedMismatch);
    }

    #[test]
    fn parses_pypi_provenance_bundles() {
        let expected_sha256 = Checksum {
            alg: ChecksumAlg::Sha256,
            value_hex: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".into(),
        };

        let statement = format!(
            r#"{{
                "_type": "https://in-toto.io/Statement/v0.1",
                "subject": [
                    {{
                        "name": "pkg:pypi/requests@2.31.0",
                        "digest": {{
                            "sha256": "{}"
                        }}
                    }}
                ],
                "predicateType": "https://slsa.dev/provenance/v0.2"
            }}"#,
            expected_sha256.value_hex
        );
        let b64 = base64::engine::general_purpose::STANDARD.encode(statement.as_bytes());
        let bundle_json = format!(
            r#"{{
                "attestation_bundles": [
                    {{
                        "attestations": [
                            {{
                                "bundle": {{
                                    "dsseEnvelope": {{
                                        "payload": "{b64}"
                                    }}
                                }}
                            }}
                        ]
                    }}
                ]
            }}"#
        );

        let report = parse_pypi_provenance_json(&bundle_json, &expected_sha256).unwrap();
        assert_eq!(report.status, ProvenanceStatus::Attested);
        assert!(
            report
                .message
                .unwrap()
                .contains("crypto verification not performed")
        );
    }
    #[test]
    fn an_attestation_never_claims_an_slsa_level() {
        // A statement with no signatures and no verification material at all
        // must not come back claiming a build level.
        let expected = ck("level-zero");
        let statement = r#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "pkg", "digest": {"sha512": "__HEX__"}}],
            "predicateType": "https://slsa.dev/provenance/v0.1",
            "predicate": {"builder": {"id": "https://github.com/actions/runner"}}
        }"#;
        let statement = statement.replace("__HEX__", &expected.value_hex);
        let b64 = base64::engine::general_purpose::STANDARD.encode(statement.as_bytes());
        let report = parse_attestation_payload(&b64, &expected).unwrap();
        assert_eq!(report.status, ProvenanceStatus::Attested);
        assert_eq!(
            report.slsa_level, 0,
            "no signature was checked, so no level is earned"
        );
    }

    #[test]
    fn unverified_is_distinguishable_from_missing() {
        let report = ProvenanceReport::unverified("boom");
        assert_eq!(
            report.status,
            ProvenanceStatus::Unverified,
            "a check that could not run is not the same as nothing being published"
        );
    }

    /// What `registry_signature_present` is built from, and the reason
    /// `provenance.require_signatures` is refused at load: it is the presence of a
    /// block, never a verification of one. Nothing in this function compares the
    /// tarball against the signature, so any non-empty array sets it.
    #[test]
    fn a_published_signature_block_marks_the_registry_signature_present() {
        let signatures = serde_json::json!([
            {"keyid": "SHA256:abc", "sig": "c2ln"},
            {"keyid": "SHA256:def", "sig": "c2lnMg=="},
        ]);
        let report = inspect_provenance(
            "pkg",
            "1.0.0",
            &ck("tarball"),
            Some(&signatures),
            "http://127.0.0.1:9",
            None,
            &Policy::default(),
        );
        assert!(
            report.registry_signature_present,
            "a published block is what this reports, which is why the policy key that read it \
             as verification is refused at load"
        );
        assert_eq!(
            report.registry_signature_key_id.as_deref(),
            Some("SHA256:abc")
        );
    }

    /// No block, or one that is not a signature list, leaves the gate shut.
    #[test]
    fn an_absent_or_unusable_signature_block_leaves_the_gate_shut() {
        for signatures in [
            None,
            Some(serde_json::json!({})),
            Some(serde_json::json!([])),
        ] {
            let report = inspect_provenance(
                "pkg",
                "1.0.0",
                &ck("tarball"),
                signatures.as_ref(),
                "http://127.0.0.1:9",
                None,
                &Policy::default(),
            );
            assert!(
                !report.registry_signature_present,
                "{signatures:?} is not a signature list, so nothing is reported as published"
            );
        }
    }

    /// The SSRF shape, end to end through the real entry point.
    ///
    /// Two listeners. The second serves a *valid* PEP 740 attestation whose
    /// subject digest matches. The first is the configured registry base and
    /// answers `302 Location: <second>`. The second is a different authority on
    /// a private address, which `validate_download_url` refuses because it does
    /// not match the base host.
    ///
    /// Built so the two outcomes are distinguishable, which a redirect to an
    /// unroutable address would not be: following the redirect yields
    /// `Attested`, refusing it yields `Missing`. Before the fix both fetch sites
    /// built a bare `ureq::AgentBuilder`, whose redirect default is 5, so the
    /// registry could hand blueline an attestation body from whatever host it
    /// named -- including a link-local metadata service.
    ///
    /// The handlers read the request before replying. Writing first and closing
    /// with unread request bytes still in the receive queue makes the kernel
    /// send RST rather than FIN, which truncates the response and made this test
    /// fail roughly a third of the time for reasons that had nothing to do with
    /// the code under test.
    #[test]
    fn a_provenance_redirect_to_another_host_is_not_followed() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        fn reply(stream: std::net::TcpStream, head: &str, body: &[u8]) {
            let mut stream = stream;
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        }

        fn serve(listener: TcpListener, head: String, body: Vec<u8>) {
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let (h, b) = (head.clone(), body.clone());
                    std::thread::spawn(move || reply(stream, &h, &b));
                }
            });
        }

        let expected = ck("tarball");
        let statement = format!(
            r#"{{"_type":"https://in-toto.io/Statement/v0.1",
                 "subject":[{{"name":"pkg:pypi/requests@2.31.0",
                             "digest":{{"sha512":"{}"}}}}],
                 "predicateType":"https://slsa.dev/provenance/v0.2",
                 "predicate":{{"builder":{{"id":"https://github.com/actions/runner"}}}}}}"#,
            expected.value_hex
        );
        let b64 = base64::engine::general_purpose::STANDARD.encode(statement.as_bytes());
        let body = format!(
            r#"{{"attestations":[{{"bundle":{{"dsseEnvelope":{{"payload":"{b64}"}}}}}}]}}"#
        );

        // Control: the payload is genuinely attesting, so a `Missing` below can
        // only mean the redirect was refused -- not that the fixture is inert.
        assert_eq!(
            parse_pypi_provenance_json(&body, &expected)
                .expect("the fixture payload must parse")
                .status,
            ProvenanceStatus::Attested,
            "control: this body attests, so refusing the redirect is observable"
        );

        // The redirect target: a valid attestation, on a private address.
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_base = format!("http://{}", target.local_addr().unwrap());
        serve(
            target,
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            ),
            body.into_bytes(),
        );

        // The configured base, which redirects there.
        let base = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", base.local_addr().unwrap());
        let location = format!(
            "{target_base}/integrity/requests/2.31.0/requests-2.31.0-py3-none-any.whl/provenance"
        );
        serve(
            base,
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            ),
            Vec::new(),
        );

        let report = inspect_provenance_pypi(
            "requests",
            "2.31.0",
            "requests-2.31.0-py3-none-any.whl",
            &expected,
            &base_url,
            None,
            &Policy::default(),
        );

        assert_ne!(
            report.status,
            ProvenanceStatus::Attested,
            "an attestation reached only by following a redirect to a different \
             private host must not be trusted: {report:?}"
        );
    }

    /// The bare DSSE form, `{"payload": "..."}`, on its own.
    ///
    /// `parse_pypi_provenance_json` accepts two shapes: an `attestations` array
    /// and a bare DSSE envelope. Only the array form had a test, so the second
    /// shape's "is this attested?" comparison was never exercised — and a
    /// comparison inverted there does not change the band, only whether the
    /// report is returned early, so nothing else would notice either.
    #[test]
    fn the_bare_dsse_form_is_parsed_and_reported_as_attested() {
        let expected = ck("tarball");
        let statement = format!(
            r#"{{"_type":"https://in-toto.io/Statement/v0.1",
                 "subject":[{{"name":"pkg:pypi/requests@2.31.0",
                             "digest":{{"sha512":"{}"}}}}],
                 "predicateType":"https://slsa.dev/provenance/v0.2",
                 "predicate":{{"builder":{{"id":"https://github.com/actions/runner"}}}}}}"#,
            expected.value_hex
        );
        let b64 = base64::engine::general_purpose::STANDARD.encode(statement.as_bytes());
        let body = format!(r#"{{"payload":"{b64}"}}"#);

        let report =
            parse_pypi_provenance_json(&body, &expected).expect("the bare DSSE form must parse");
        assert_eq!(
            report.status,
            ProvenanceStatus::Attested,
            "a matching subject digest is attested: {report:?}"
        );
        assert_eq!(
            report.slsa_level, 0,
            "no signature was checked, so no level"
        );
        assert_eq!(
            report.builder_id.as_deref(),
            Some("https://github.com/actions/runner")
        );

        // The same body with a digest that does not match is a mismatch, not an
        // attestation, and not a clean pass either.
        let other = ck("a-different-tarball");
        let mismatched = parse_pypi_provenance_json(&body, &other).expect("must parse");
        assert_eq!(
            mismatched.status,
            ProvenanceStatus::FailedMismatch,
            "a digest that does not match the bytes under review is a mismatch"
        );
    }

    /// An attested PyPI release is written to the provenance cache.
    ///
    /// The write is gated on the status being `Attested`, and that gate is the
    /// only thing between a verified subject digest and a row in the store. With
    /// it inverted the review still reports `Attested` on the card and caches
    /// nothing, so the next review re-fetches and a policy reading the cache sees
    /// no provenance at all.
    #[test]
    fn an_attested_pypi_release_is_written_to_the_provenance_cache() {
        let expected = ck("tarball");
        // Built with `json!` rather than a raw string: a hand-written statement
        // with this much nesting is easy to malform, and a malformed one fails as
        // "unverified", which is a different finding and would make this test
        // pass for the wrong reason.
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "pkg:pypi/requests@2.31.0",
                "digest": {"sha512": expected.value_hex}
            }],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {"id": "https://github.com/actions/runner"},
                "invocation": {
                    "configSource": {
                        "uri": "git+https://github.com/psf/requests",
                        "digest": {"sha1": "deadbeef"},
                        "entryPoint": ".github/workflows/w.yml"
                    }
                }
            }
        });
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&statement).unwrap());
        let body = format!(
            r#"{{"attestations":[{{"bundle":{{"dsseEnvelope":{{"payload":"{b64}"}}}}}}]}}"#
        );

        // Control: the body really does attest, so a cache miss below can only
        // mean the write was skipped.
        assert_eq!(
            parse_pypi_provenance_json(&body, &expected)
                .expect("the fixture body must parse")
                .status,
            ProvenanceStatus::Attested,
            "control: this body attests"
        );

        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("blueline.db")).unwrap();
        let server = provenance_fixture_server(body);

        let report = inspect_provenance_pypi(
            "requests",
            "2.31.0",
            "requests-2.31.0-py3-none-any.whl",
            &expected,
            &server,
            Some(&store),
            &Policy::default(),
        );
        assert_eq!(report.status, ProvenanceStatus::Attested, "{report:?}");

        let cached = store
            .get_cached_provenance(Ecosystem::PyPi, "requests", "2.31.0")
            .expect("the cache read must not error")
            .expect("an attested release must leave a provenance row behind");
        assert_eq!(
            cached.source_repo.as_deref(),
            Some("git+https://github.com/psf/requests"),
            "the cached row must carry what the statement said"
        );
    }

    /// A digest mismatch is an integrity failure, and the cache has no status
    /// column to tell a `FailedMismatch` row from an `Attested` one: a cache hit
    /// replays as `Attested` unconditionally (`src/provenance.rs:272`). The PyPI
    /// lane already guarded its write with `status == Attested`; the npm lane
    /// did not, so it wrote the failure into the cache and every later review of
    /// that release read back `Attested`, which under `require_provenance`
    /// drops the only finding that blocks. A digest mismatch continues to refuse
    /// regardless of the key, so this laundered an integrity failure into a pass.
    #[test]
    fn an_npm_digest_mismatch_is_not_cached_as_an_attestation() {
        let expected = ck("tarball");
        // The statement attests a *different* digest than the one under review,
        // so the parse must produce a mismatch rather than an attestation.
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "pkg:npm/lodash@4.17.20",
                "digest": {"sha512": "00".repeat(64)}
            }],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {"id": "https://github.com/actions/runner"},
                "invocation": {
                    "configSource": {
                        "uri": "git+https://github.com/lodash/lodash",
                        "digest": {"sha1": "deadbeef"},
                        "entryPoint": ".github/workflows/w.yml"
                    }
                }
            }
        });
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&statement).unwrap());
        let body = format!(
            r#"{{"attestations":[{{"bundle":{{"dsseEnvelope":{{"payload":"{b64}"}}}}}}]}}"#
        );

        // Control: the fixture really does mismatch, so a cache hit below could
        // only come from the failure having been written.
        assert_eq!(
            parse_attestation_payload(&b64, &expected)
                .expect("the fixture payload must parse")
                .status,
            ProvenanceStatus::FailedMismatch,
            "control: this body must mismatch the digest under review"
        );

        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("blueline.db")).unwrap();
        let server = provenance_fixture_server(body);

        let report = inspect_provenance(
            "lodash",
            "4.17.20",
            &expected,
            None,
            &server,
            Some(&store),
            &Policy::default(),
        );
        assert_eq!(
            report.status,
            ProvenanceStatus::FailedMismatch,
            "the review itself must still refuse: {report:?}"
        );

        let cached = store
            .get_cached_provenance(Ecosystem::Npm, "lodash", "4.17.20")
            .expect("the cache read must not error");
        assert!(
            cached.is_none(),
            "a digest mismatch must leave no provenance row: {cached:?}"
        );
    }

    /// A single-purpose listener that answers every request with `status` and
    /// `body`. Reads the request before replying: closing with unread bytes
    /// queued makes the kernel send RST, which truncates the response.
    fn provenance_status_server(status: &'static str, body: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let body = body.as_bytes().to_vec();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let head = format!(
                    "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        base
    }

    /// A registry answer that is not an authoritative "there is none" is not
    /// evidence that there is none.
    ///
    /// Both provenance lanes ended every uneventful fetch with
    /// `ProvenanceReport::missing(..)`, so a 500, a refused connection, a body
    /// over the cap, and a body that would not parse all arrived as
    /// `ProvenanceStatus::Missing` — the one status a policy that set
    /// `require_provenance` reads as "nobody published provenance for this
    /// release". Since absence became LOW and score-neutral, that made every one
    /// of those failures produce a verdict byte-identical to a clean pass.
    ///
    /// This is the shape 102d23c fixed for advisories, where a lookup that never
    /// happened was indistinguishable from a clean one. The established answer
    /// in this tree is a status that means "no answer was obtained", and
    /// `Unverified` is already mapped to a refusal under the policy key.
    ///
    /// Asserted on the status rather than the message, so rewording the
    /// disclosure cannot turn this back into a tautology.
    #[test]
    fn a_provenance_fetch_that_never_completed_is_not_reported_as_absence() {
        let expected = ck("tarball");

        // A 200 carrying something that is not a provenance document at all.
        // Reachable and answered, so the only thing missing is the answer.
        let garbage = provenance_status_server("HTTP/1.1 200 OK", "<html>not json</html>");
        let report = inspect_provenance_pypi(
            "requests",
            "2.31.0",
            "requests-2.31.0-py3-none-any.whl",
            &expected,
            &garbage,
            None,
            &Policy::default(),
        );
        assert_eq!(
            report.status,
            ProvenanceStatus::Unverified,
            "a body that would not parse must not read as absence: {report:?}"
        );

        // A server error. The registry answered, but not with an answer.
        let broken = provenance_status_server("HTTP/1.1 500 Internal Server Error", "boom");
        let report = inspect_provenance_pypi(
            "requests",
            "2.31.0",
            "requests-2.31.0-py3-none-any.whl",
            &expected,
            &broken,
            None,
            &Policy::default(),
        );
        assert_eq!(
            report.status,
            ProvenanceStatus::Unverified,
            "a 500 must not read as absence: {report:?}"
        );

        // And the npm lane, which had the same fallthrough.
        let broken = provenance_status_server("HTTP/1.1 502 Bad Gateway", "boom");
        let report = inspect_provenance(
            "pkg",
            "1.0.0",
            &expected,
            None,
            &broken,
            None,
            &Policy::default(),
        );
        assert_eq!(
            report.status,
            ProvenanceStatus::Unverified,
            "a 502 on the npm lane must not read as absence: {report:?}"
        );
    }

    /// The other half of the same decision, and the reason the fix above is not
    /// a blanket "any error is unverifiable".
    ///
    /// npm's attestations endpoint answers 404 for a release nobody published
    /// provenance for, and that is an authoritative statement of absence. It is
    /// also the overwhelmingly common case, and treating it as unverifiable
    /// would put back exactly the behaviour 799853e removed: a clean release
    /// with no provenance, refused under the very key meant to ask for it.
    #[test]
    fn an_authoritative_404_is_still_absence() {
        let expected = ck("tarball");
        let absent = provenance_status_server("HTTP/1.1 404 Not Found", "");

        let report = inspect_provenance_pypi(
            "requests",
            "2.31.0",
            "requests-2.31.0-py3-none-any.whl",
            &expected,
            &absent,
            None,
            &Policy::default(),
        );
        assert_eq!(
            report.status,
            ProvenanceStatus::Missing,
            "a 404 from the provenance endpoint means nobody published any: {report:?}"
        );

        let report = inspect_provenance(
            "pkg",
            "1.0.0",
            &expected,
            None,
            &absent,
            None,
            &Policy::default(),
        );
        assert_eq!(
            report.status,
            ProvenanceStatus::Missing,
            "same on the npm lane: {report:?}"
        );
    }

    /// A 200 that is a well-formed envelope carrying no attestations is
    /// absence too, and must keep saying so. Without this the fix would pass by
    /// reporting `Unverified` for everything and lose the real answer.
    #[test]
    fn a_well_formed_empty_envelope_is_still_absence() {
        let empty = provenance_status_server("HTTP/1.1 200 OK", r#"{"attestations":[]}"#);

        let report = inspect_provenance(
            "pkg",
            "1.0.0",
            &ck("tarball"),
            None,
            &empty,
            None,
            &Policy::default(),
        );
        assert_eq!(
            report.status,
            ProvenanceStatus::Missing,
            "an empty attestation list is a real answer: {report:?}"
        );

        let report = inspect_provenance_pypi(
            "requests",
            "2.31.0",
            "requests-2.31.0-py3-none-any.whl",
            &ck("tarball"),
            &empty,
            None,
            &Policy::default(),
        );
        assert_eq!(
            report.status,
            ProvenanceStatus::Missing,
            "an empty attestation list is a real answer: {report:?}"
        );
    }

    /// A single-purpose listener that answers every request with `body`.
    /// Reads the request before replying: closing with unread bytes queued makes
    /// the kernel send RST, which truncates the response.
    fn provenance_fixture_server(body: String) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let body = body.into_bytes();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        base
    }

    /// The attestation body cap, asserted as a value.
    ///
    /// Every provenance fixture is a few hundred bytes, so the cap was only ever
    /// exercised as "much larger than the fixture" — which a wrong constant
    /// satisfies just as well. The fetch already has a byte cap of its own; this
    /// one has to be a number someone chose, and 1 MiB is the choice.
    #[test]
    fn the_attestation_body_cap_is_one_mebibyte() {
        assert_eq!(MAX_ATTESTATION_BYTES, 1024 * 1024);
        assert_eq!(MAX_ATTESTATION_BYTES, 1_048_576);
    }
}
