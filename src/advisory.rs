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
    #[allow(dead_code)]
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
    if let Some(stale) = stale_fallback {
        return Ok(stale);
    }

    if policy.policy.fail_closed_network {
        return Err(BluelineError::Advisory(format!(
            "{err_msg} (failing closed as configured by policy)"
        )));
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

fn extract_cvss_score(v: &OsvVuln) -> Option<f64> {
    for s in &v.severity {
        // Parse explicit numeric float or full CVSS vector string
        if let Ok(score) = s.score.parse::<f64>() {
            return Some(score);
        }
        if let Some(score) = parse_cvss_vector(&s.score) {
            return Some(score);
        }
    }
    None
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

    if let Some(score) = cvss {
        if score >= 9.0 && policy.advisories.block_on_critical_cve {
            return VerdictBand::Block;
        } else if score >= 7.0 {
            return VerdictBand::High;
        } else if score >= 4.0 {
            return VerdictBand::Medium;
        } else {
            return VerdictBand::Low;
        }
    }

    if let Some(ref db_spec) = v.database_specific
        && let Some(ref sev) = db_spec.severity
    {
        match sev.to_uppercase().as_str() {
            "CRITICAL" => {
                if policy.advisories.block_on_critical_cve {
                    return VerdictBand::Block;
                } else {
                    return VerdictBand::High;
                }
            }
            "HIGH" => return VerdictBand::High,
            "MODERATE" | "MEDIUM" => return VerdictBand::Medium,
            "LOW" => return VerdictBand::Low,
            _ => {}
        }
    }

    VerdictBand::Medium
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
