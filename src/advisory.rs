use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::error::BluelineError;
use crate::policy::Policy;
use crate::registry::Ecosystem;
use crate::store::BaselineStore;
use crate::verdict::VerdictBand;

/// Maximum payload size allowed when receiving OSV API responses (1 MB).
const MAX_OSV_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Default timeout in milliseconds for advisory network calls.
const DEFAULT_TIMEOUT_MS: u64 = 3000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryStatus {
    Clean,
    Vulnerable,
    Unverified,
    StaleCache,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryItem {
    pub id: String,
    pub summary: String,
    pub details: String,
    pub aliases: Vec<String>,
    pub severity: VerdictBand,
    pub cvss_score: Option<f64>,
    pub is_malware: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryReport {
    pub status: AdvisoryStatus,
    pub hits: Vec<AdvisoryItem>,
    pub source: String,
    pub message: Option<String>,
}

impl AdvisoryReport {
    pub fn clean(source: &str) -> Self {
        Self {
            status: AdvisoryStatus::Clean,
            hits: Vec::new(),
            source: source.to_string(),
            message: None,
        }
    }

    pub fn unverified(reason: &str) -> Self {
        Self {
            status: AdvisoryStatus::Unverified,
            hits: Vec::new(),
            source: "osv.dev".to_string(),
            message: Some(reason.to_string()),
        }
    }

    pub fn has_blocking(&self) -> bool {
        self.hits
            .iter()
            .any(|h| h.severity == VerdictBand::Block || h.is_malware)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct OsvQueryResponse {
    #[serde(default)]
    pub(crate) vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OsvVuln {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) summary: Option<String>,
    #[serde(default)]
    pub(crate) details: Option<String>,
    #[serde(default)]
    pub(crate) aliases: Vec<String>,
    #[serde(default)]
    pub(crate) severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub(crate) database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OsvSeverity {
    #[serde(rename = "type")]
    pub(crate) severity_type: String,
    pub(crate) score: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OsvDatabaseSpecific {
    #[serde(default)]
    pub(crate) severity: Option<String>,
    #[serde(default)]
    pub(crate) malicious: Option<bool>,
}

/// OSV.dev ecosystem identifier for a blueline ecosystem. Exact casing is
/// dictated by the OSV schema (`CratesIO` and `PyPI` are not snake_case).
/// The AUR has no OSV coverage; the value is unreachable until the AUR
/// adapter wires advisory handling explicitly.
fn osv_ecosystem(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Cargo => "CratesIO",
        Ecosystem::PyPi => "PyPI",
        Ecosystem::Aur => "AUR",
    }
}

pub fn fetch_advisories(
    package: &str,
    version: &str,
    ecosystem: Ecosystem,
    store: Option<&BaselineStore>,
    policy: &Policy,
) -> Result<AdvisoryReport, BluelineError> {
    // The recall index is local, curated truth: a hit blocks regardless of
    // the OSV path, and never routes through the advisory cache (a stale
    // OSV cache entry must not mask a fresh revocation).
    if let Some(revocation) = crate::recall::lookup(ecosystem, package, version)? {
        return Ok(AdvisoryReport {
            status: AdvisoryStatus::Vulnerable,
            hits: vec![AdvisoryItem {
                id: revocation.id,
                summary: format!("revoked by recall index: {}", revocation.reason),
                details: String::new(),
                aliases: Vec::new(),
                severity: VerdictBand::Block,
                cvss_score: None,
                is_malware: true,
            }],
            source: "blueline-recall".to_string(),
            message: None,
        });
    }

    if !policy.policy.check_advisories {
        return Ok(AdvisoryReport::unverified(
            "advisory checking disabled by policy",
        ));
    }

    // 1. Check SQLite cache
    let mut stale_fallback = None;
    if let Some(store) = store
        && let Ok(Some(cached)) = store.get_cached_advisories(ecosystem, package, version)
    {
        if !cached.is_expired {
            if let Ok(report) = serde_json::from_str::<AdvisoryReport>(&cached.advisories_json) {
                return Ok(report);
            }
        } else if let Ok(mut report) =
            serde_json::from_str::<AdvisoryReport>(&cached.advisories_json)
        {
            report.status = AdvisoryStatus::StaleCache;
            stale_fallback = Some(report);
        }
    }

    // 2. Query OSV.dev REST API
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_millis(DEFAULT_TIMEOUT_MS))
        .build();

    let query_payload = serde_json::json!({
        "version": version,
        "package": {
            "name": package,
            "ecosystem": osv_ecosystem(ecosystem)
        }
    });

    let payload_str = query_payload.to_string();
    let resp_result = agent
        .post("https://api.osv.dev/v1/query")
        .set("Content-Type", "application/json")
        .set("User-Agent", "blueline-security/0.1.0")
        .send_string(&payload_str);

    match resp_result {
        Ok(resp) => {
            let mut reader = resp.into_reader().take(MAX_OSV_RESPONSE_BYTES);
            let mut body = String::new();
            if let Err(e) = reader.read_to_string(&mut body) {
                return fallback_or_fail(
                    stale_fallback,
                    policy,
                    &format!("failed to read OSV response body: {e}"),
                );
            }

            let osv_resp: OsvQueryResponse = match serde_json::from_str(&body) {
                Ok(r) => r,
                Err(e) => {
                    return fallback_or_fail(
                        stale_fallback,
                        policy,
                        &format!("invalid JSON from OSV API: {e}"),
                    );
                }
            };

            let report = parse_osv_response(osv_resp, policy);

            // Cache report in SQLite store
            if let Some(store) = store
                && let Ok(report_json) = serde_json::to_string(&report)
            {
                let ttl = if report.hits.is_empty() {
                    policy.advisories.clean_cache_ttl_secs()
                } else {
                    policy.advisories.vulnerable_cache_ttl_secs()
                };
                let _ = store.put_cached_advisories(
                    ecosystem,
                    package,
                    version,
                    &report_json,
                    report.hits.len(),
                    report.has_blocking(),
                    ttl,
                );
            }

            Ok(report)
        }
        Err(e) => fallback_or_fail(
            stale_fallback,
            policy,
            &format!("OSV advisory request failed: {e}"),
        ),
    }
}

fn fallback_or_fail(
    stale_fallback: Option<AdvisoryReport>,
    policy: &Policy,
    err_msg: &str,
) -> Result<AdvisoryReport, BluelineError> {
    // Checked before the stale fallback. Serving a cached report while the
    // policy says fail closed returned a possibly month-old answer as if it
    // were fresh, and a stale CLEAN report produces no hits and no staleness
    // disclosure, so it was indistinguishable from a clean pass.
    if policy.policy.fail_closed_network {
        return Err(BluelineError::Advisory(format!(
            "{err_msg} (failing closed as configured by policy)"
        )));
    }

    if let Some(stale) = stale_fallback {
        return Ok(stale);
    }

    Ok(AdvisoryReport::unverified(err_msg))
}

pub(crate) fn parse_osv_response(resp: OsvQueryResponse, policy: &Policy) -> AdvisoryReport {
    if resp.vulns.is_empty() {
        return AdvisoryReport::clean("osv.dev");
    }

    let mut hits = Vec::new();
    for v in resp.vulns {
        let is_malware = check_is_malware(&v);
        let cvss = extract_cvss_score(&v);
        let severity = calculate_advisory_severity(is_malware, cvss, &v, policy);

        hits.push(AdvisoryItem {
            id: v.id,
            summary: v.summary.unwrap_or_else(|| "No summary provided".into()),
            details: v.details.unwrap_or_default(),
            aliases: v.aliases,
            severity,
            cvss_score: cvss,
            is_malware,
        });
    }

    AdvisoryReport {
        status: AdvisoryStatus::Vulnerable,
        hits,
        source: "osv.dev".to_string(),
        message: None,
    }
}

fn check_is_malware(v: &OsvVuln) -> bool {
    if let Some(ref db_spec) = v.database_specific {
        if db_spec.malicious == Some(true) {
            return true;
        }
        if let Some(ref sev) = db_spec.severity
            && (sev.eq_ignore_ascii_case("MALWARE") || sev.eq_ignore_ascii_case("MALICIOUS"))
        {
            return true;
        }
    }
    if v.id.starts_with("MAL-") {
        return true;
    }
    if let Some(ref s) = v.summary {
        let low = s.to_lowercase();
        if low.contains("malicious package") || low.contains("embedded malware") {
            return true;
        }
    }
    false
}

/// Parse standard CVSS v3.0 / v3.1 vector string and calculate the base score (0.0 to 10.0).
pub fn parse_cvss_vector(vector: &str) -> Option<f64> {
    if !vector.starts_with("CVSS:3.0") && !vector.starts_with("CVSS:3.1") {
        return None;
    }

    let mut av: Option<f64> = None;
    let mut ac: Option<f64> = None;
    let mut pr: Option<&str> = None;
    let mut ui: Option<f64> = None;
    let mut scope_changed = false;
    let mut c: Option<f64> = None;
    let mut i: Option<f64> = None;
    let mut a: Option<f64> = None;

    for part in vector.split('/') {
        let mut kv = part.splitn(2, ':');
        let k = kv.next()?;
        let v = kv.next().unwrap_or_default();
        match k {
            "AV" => {
                av = match v {
                    "N" => Some(0.85),
                    "A" => Some(0.62),
                    "L" => Some(0.55),
                    "P" => Some(0.20),
                    _ => None,
                };
            }
            "AC" => {
                ac = match v {
                    "L" => Some(0.77),
                    "H" => Some(0.44),
                    _ => None,
                };
            }
            "PR" => {
                pr = Some(v);
            }
            "UI" => {
                ui = match v {
                    "N" => Some(0.85),
                    "R" => Some(0.62),
                    _ => None,
                };
            }
            "S" => {
                scope_changed = v == "C";
            }
            "C" => {
                c = match v {
                    "H" => Some(0.56),
                    "L" => Some(0.22),
                    "N" => Some(0.0),
                    _ => None,
                };
            }
            "I" => {
                i = match v {
                    "H" => Some(0.56),
                    "L" => Some(0.22),
                    "N" => Some(0.0),
                    _ => None,
                };
            }
            "A" => {
                a = match v {
                    "H" => Some(0.56),
                    "L" => Some(0.22),
                    "N" => Some(0.0),
                    _ => None,
                };
            }
            _ => {}
        }
    }

    let av = av?;
    let ac = ac?;
    let ui = ui?;
    let c = c?;
    let i = i?;
    let a = a?;
    let pr_code = pr?;

    let pr_val = match (scope_changed, pr_code) {
        (false, "N") => 0.85,
        (false, "L") => 0.62,
        (false, "H") => 0.27,
        (true, "N") => 0.85,
        (true, "L") => 0.68,
        (true, "H") => 0.50,
        _ => return None,
    };

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    if iss <= 0.0 {
        return Some(0.0);
    }

    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };

    let exploitability = 8.22 * av * ac * pr_val * ui;

    let base_score = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };

    let rounded = ((base_score.clamp(0.0, 10.0) * 10.0).ceil()) / 10.0;
    Some(rounded)
}

/// Base score from a CVSS v2 vector string, per the CVSS v2.0 base equation
/// (formula version 2.10):
///
/// ```text
/// BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
/// Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
/// Exploitability = 20*AccessVector*AccessComplexity*Authentication
/// f(Impact) = 0 when Impact is 0, 1.176 otherwise
/// ```
///
/// A v2 vector is the reason `OsvSeverity::severity_type` is read: unlike a v3
/// vector it carries no `CVSS:3.x` prefix to identify it, so the declared type
/// is the only thing that says how the string is to be read. Anything that is
/// not a complete, well-formed v2 base vector scores as `None` rather than
/// being guessed at.
pub fn parse_cvss_v2_vector(vector: &str) -> Option<f64> {
    let mut av: Option<f64> = None;
    let mut ac: Option<f64> = None;
    let mut au: Option<f64> = None;
    let mut c: Option<f64> = None;
    let mut i: Option<f64> = None;
    let mut a: Option<f64> = None;

    for part in vector.split('/') {
        let mut kv = part.splitn(2, ':');
        let k = kv.next()?;
        let v = kv.next().unwrap_or_default();
        let slot = match k {
            "AV" => &mut av,
            "AC" => &mut ac,
            "Au" => &mut au,
            "C" => &mut c,
            "I" => &mut i,
            "A" => &mut a,
            // A v2 base vector has exactly six metrics. An unknown name means
            // this is not one, and scoring it anyway is a guess.
            _ => return None,
        };
        if slot.is_some() {
            // A repeated metric is ambiguous, so it is not a vector.
            return None;
        }
        // Matched per metric, not by value alone. A shared `(_, "P")` arm would
        // accept `AV:P`, which is not a v2 access vector, and score it with the
        // confidentiality-impact weight: a malformed vector scoring *lower* than
        // a well-formed one is the wrong way to fail.
        *slot = Some(match (k, v) {
            ("AV", "L") => 0.395,
            ("AV", "A") => 0.646,
            ("AV", "N") => 1.0,
            ("AC", "H") => 0.35,
            ("AC", "M") => 0.61,
            ("AC", "L") => 0.71,
            ("Au", "M") => 0.45,
            ("Au", "S") => 0.56,
            ("Au", "N") => 0.704,
            ("C" | "I" | "A", "N") => 0.0,
            ("C" | "I" | "A", "P") => 0.275,
            ("C" | "I" | "A", "C") => 0.660,
            _ => return None,
        });
    }

    let impact = 10.41 * (1.0 - (1.0 - c?) * (1.0 - i?) * (1.0 - a?));
    let exploitability = 20.0 * av? * ac? * au?;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * 1.176;
    // v2 rounds to nearest; the v3 `Roundup` used by `parse_cvss_vector` is a
    // different function and rounds ties up.
    Some((base_score.clamp(0.0, 10.0) * 10.0).round() / 10.0)
}

/// Whether an OSV `severity[].type` declares a CVSS v2 score. Compared
/// case-insensitively because the member is attacker-shaped, but only the one
/// spelling is scored: an unrecognised type is left unscored exactly as before,
/// never scored as something it might not be.
fn declares_cvss_v2(severity_type: &str) -> bool {
    severity_type.trim().eq_ignore_ascii_case("CVSS_V2")
}

fn extract_cvss_score(v: &OsvVuln) -> Option<f64> {
    for s in &v.severity {
        // Parse explicit numeric float or full CVSS vector string
        if let Ok(score) = s.score.parse::<f64>() {
            return Some(score);
        }
        if let Some(score) = parse_cvss_vector(&s.score) {
            return Some(score);
        }
        if declares_cvss_v2(&s.severity_type)
            && let Some(score) = parse_cvss_v2_vector(&s.score)
        {
            return Some(score);
        }
    }
    None
}

/// The band a numeric base score supports. Shared by every scoring path, so no
/// threshold can drift between them.
fn band_from_score(score: f64, policy: &Policy) -> VerdictBand {
    if score >= 9.0 && policy.advisories.block_on_critical_cve {
        VerdictBand::Block
    } else if score >= 7.0 {
        VerdictBand::High
    } else if score >= 4.0 {
        VerdictBand::Medium
    } else {
        VerdictBand::Low
    }
}

/// The band a source's own severity label supports, when it is one of the four
/// labels this tool knows. Anything else is not a signal.
fn band_from_declared_severity(sev: &str, policy: &Policy) -> Option<VerdictBand> {
    match sev.to_uppercase().as_str() {
        "CRITICAL" => Some(if policy.advisories.block_on_critical_cve {
            VerdictBand::Block
        } else {
            VerdictBand::High
        }),
        "HIGH" => Some(VerdictBand::High),
        "MODERATE" | "MEDIUM" => Some(VerdictBand::Medium),
        "LOW" => Some(VerdictBand::Low),
        _ => None,
    }
}

fn calculate_advisory_severity(
    is_malware: bool,
    cvss: Option<f64>,
    v: &OsvVuln,
    policy: &Policy,
) -> VerdictBand {
    if is_malware && policy.advisories.block_on_malware {
        return VerdictBand::Block;
    }

    // Every signal the advisory offers is read, and the strongest one wins
    // (`VerdictBand` orders Low < Medium < High < Block). The score used to
    // return early, so a source that also labelled its own advisory CRITICAL
    // was reported at the score's band instead; reading a second signal can
    // only raise the band here, never lower it.
    let from_score = cvss.map(|score| band_from_score(score, policy));
    let from_label = v
        .database_specific
        .as_ref()
        .and_then(|db_spec| db_spec.severity.as_deref())
        .and_then(|sev| band_from_declared_severity(sev, policy));

    match (from_score, from_label) {
        (Some(a), Some(b)) => a.max(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => VerdictBand::Medium,
    }
}

#[cfg(test)]
mod tests {
    /// A v2 vector's metric values are per-metric. Matching them by value alone
    /// let `AV:P` be scored with the partial-impact weight, so a malformed
    /// vector scored 4.1 where the well-formed one scores 7.5 -- an advisory
    /// under-reported because of a typo in attacker-shaped remote data.
    #[test]
    fn cvss_v2_rejects_a_value_that_is_not_valid_for_its_metric() {
        for bad in [
            "AV:P/AC:L/Au:N/C:P/I:P/A:P",
            "AC:N/AV:L/Au:N/C:P/I:P/A:P",
            "Au:C/AV:N/AC:L/C:P/I:P/A:P",
            "AV:N/AC:L/Au:N/C:X/I:P/A:P",
            "AV:N/AC:L/Au:N/C:P/I:P",
        ] {
            assert_eq!(
                parse_cvss_v2_vector(bad),
                None,
                "`{bad}` is not a well-formed v2 base vector and must not score"
            );
        }
    }

    /// The well-formed vector the malformed one above was derived from must
    /// keep its NVD score, so the stricter match did not break the real path.
    #[test]
    fn cvss_v2_still_scores_the_reference_vector() {
        assert_eq!(
            parse_cvss_v2_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P"),
            Some(7.5)
        );
    }

    use super::*;

    /// A cached report must not be served while the policy says fail closed.
    /// It did, which returned a possibly month-old answer as if it were fresh,
    /// and a stale CLEAN report produces neither hits nor a staleness
    /// disclosure, so it read as a clean pass.
    #[test]
    fn fail_closed_network_outranks_a_stale_cached_report() {
        let mut policy = Policy::default();
        policy.policy.fail_closed_network = true;
        let stale = AdvisoryReport {
            status: AdvisoryStatus::Clean,
            hits: Vec::new(),
            source: "cache".to_string(),
            message: None,
        };
        let result = fallback_or_fail(Some(stale.clone()), &policy, "osv unreachable");
        assert!(
            result.is_err(),
            "fail_closed_network must not be satisfied by a cached report"
        );

        // Without the policy the fallback is still the answer.
        let mut lenient = Policy::default();
        lenient.policy.fail_closed_network = false;
        assert!(fallback_or_fail(Some(stale), &lenient, "osv unreachable").is_ok());
    }

    #[test]
    fn parses_empty_response_as_clean() {
        let resp = OsvQueryResponse { vulns: Vec::new() };
        let report = parse_osv_response(resp, &Policy::default());
        assert_eq!(report.status, AdvisoryStatus::Clean);
        assert!(report.hits.is_empty());
        assert!(!report.has_blocking());
    }

    #[test]
    fn detects_malware_and_critical_advisories() {
        let json = r#"{
            "vulns": [
                {
                    "id": "MAL-2026-0001",
                    "summary": "Malicious package containing credential stealer",
                    "details": "Exfiltrates npm credentials",
                    "aliases": ["GHSA-1234"],
                    "database_specific": {
                        "malicious": true,
                        "severity": "CRITICAL"
                    }
                }
            ]
        }"#;

        let resp: OsvQueryResponse = serde_json::from_str(json).unwrap();
        let report = parse_osv_response(resp, &Policy::default());
        assert_eq!(report.status, AdvisoryStatus::Vulnerable);
        assert_eq!(report.hits.len(), 1);
        assert!(report.hits[0].is_malware);
        assert_eq!(report.hits[0].severity, VerdictBand::Block);
        assert!(report.has_blocking());
    }

    /// A CVSS v2 vector carries no prefix that says how to read it, the way a
    /// v3 one starts `CVSS:3.x`, so the declared `severity` type is the only
    /// thing that says the string is a v2 vector. It was read off the wire and
    /// dropped, so a v2-only advisory scored nothing and fell to the Medium
    /// default however critical its vector was.
    #[test]
    fn osv_cvss_v2_severity_type_is_scored_into_the_band() {
        let json = r#"{
            "vulns": [
                {
                    "id": "CVE-2002-0392",
                    "summary": "Legacy advisory carrying only a CVSS v2 vector",
                    "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]
                }
            ]
        }"#;

        let resp: OsvQueryResponse = serde_json::from_str(json).unwrap();
        let report = parse_osv_response(resp, &Policy::default());
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].cvss_score, Some(10.0));
        assert_eq!(report.hits[0].severity, VerdictBand::Block);
        assert!(report.has_blocking());
    }

    /// The guard on the guard: adding a second signal must never hand a
    /// reviewer a weaker band than the one the strongest available signal
    /// supports. A v2 vector that scores 5.0 must not talk a `CRITICAL`
    /// database-specific rating down to MEDIUM.
    #[test]
    fn a_declared_band_is_never_overridden_by_a_lower_score() {
        let json = r#"{
            "vulns": [
                {
                    "id": "CVE-2011-3152",
                    "summary": "Rated CRITICAL by the database, scored 6.4 by CVSS v2",
                    "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:N"}],
                    "database_specific": {"severity": "CRITICAL"}
                }
            ]
        }"#;

        let resp: OsvQueryResponse = serde_json::from_str(json).unwrap();
        let report = parse_osv_response(resp, &Policy::default());
        assert_eq!(report.hits[0].cvss_score, Some(6.4));
        assert_eq!(report.hits[0].severity, VerdictBand::Block);
    }

    #[test]
    fn osv_ecosystem_casing_matches_schema() {
        assert_eq!(osv_ecosystem(crate::registry::Ecosystem::Npm), "npm");
        assert_eq!(osv_ecosystem(crate::registry::Ecosystem::Cargo), "CratesIO");
        assert_eq!(osv_ecosystem(crate::registry::Ecosystem::PyPi), "PyPI");
    }

    #[test]
    fn parses_cvss_vector_strings_correctly() {
        // Critical RCE vector
        let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let score = parse_cvss_vector(vector).unwrap();
        assert_eq!(score, 9.8);

        // High privilege escalation vector
        let vector_high = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N";
        let score_high = parse_cvss_vector(vector_high).unwrap();
        assert_eq!(score_high, 6.5);
    }

    /// Every vector here is one the NVD CVSS v2 calculator publishes a base
    /// score for, so the equation is pinned against the reference rather than
    /// against itself. The v2 base equation is not the v3 one: it carries the
    /// `-1.5` term and the `f(Impact)` multiplier, and it rounds to nearest
    /// where v3 rounds up.
    #[test]
    fn cvss_v2_base_scores_match_the_nvd_reference_vectors() {
        for (vector, expected) in [
            // CVE-2002-0392, the specification's own worked example.
            ("AV:N/AC:L/Au:N/C:N/I:N/A:C", 7.8),
            ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0),
            // CVE-2011-3152.
            ("AV:N/AC:L/Au:N/C:P/I:P/A:N", 6.4),
            // CVE-2014-0160 (Heartbleed).
            ("AV:N/AC:L/Au:N/C:P/I:N/A:N", 5.0),
            // CVE-2022-22530.
            ("AV:N/AC:L/Au:S/C:N/I:P/A:C", 7.5),
            // No impact at all: f(Impact) is 0, so the score is 0.0.
            ("AV:L/AC:H/Au:M/C:N/I:N/A:N", 0.0),
        ] {
            assert_eq!(parse_cvss_v2_vector(vector), Some(expected), "{vector}");
        }
    }

    /// A v2 vector that is not a v2 vector scores as nothing rather than as a
    /// guess. Each of these is unscored today too, so this pins that the new
    /// path never invents a number.
    #[test]
    fn cvss_v2_vector_rejects_anything_that_is_not_one() {
        for vector in [
            // v3 vector: the self-identifying prefix, not a v2 metric set.
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            // Missing a metric, and one with no value.
            "AV:N/AC:L/Au:N/C:C/I:C",
            "AV:N/AC:L/Au:N/C:C/I:C/A:",
            // Unknown metric value, unknown metric name, repeated metric.
            "AV:N/AC:L/Au:N/C:C/I:C/A:X",
            "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C",
            "AV:N/AC:N/AC:L/Au:N/C:C/I:C/A:C",
            "",
        ] {
            assert_eq!(parse_cvss_v2_vector(vector), None, "{vector}");
        }
    }

    /// The declared type is the only thing that says a vector without a
    /// `CVSS:3.x` prefix is a v2 vector, so it is read to pick the parser. A
    /// v2 vector under a type that is not `CVSS_V2` stays unscored.
    #[test]
    fn only_the_declared_cvss_v2_type_selects_the_v2_parser() {
        let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
        let with_type = |t: &str| {
            serde_json::json!({
                "vulns": [{
                    "id": "CVE-2002-0392",
                    "severity": [{"type": t, "score": vector}]
                }]
            })
            .to_string()
        };
        let score_of = |t: &str| {
            let resp: OsvQueryResponse = serde_json::from_str(&with_type(t)).unwrap();
            parse_osv_response(resp, &Policy::default()).hits[0].cvss_score
        };

        assert_eq!(score_of("CVSS_V2"), Some(10.0));
        // Same vector, a type that does not declare v2: unscored, which is the
        // floor the Medium default then applies.
        assert_eq!(score_of("CVSS_V3"), None);
        assert_eq!(score_of("SOME_OTHER_SCALE"), None);
    }
}
