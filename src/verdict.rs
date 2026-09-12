use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "UPPERCASE")]
#[clap(rename_all = "lower")]
pub enum VerdictBand {
    #[value(alias = "LOW", alias = "Low")]
    Low,
    #[value(alias = "MEDIUM", alias = "Medium")]
    Medium,
    #[value(alias = "HIGH", alias = "High")]
    High,
    #[value(alias = "BLOCK", alias = "Block")]
    Block,
}

impl std::fmt::Display for VerdictBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerdictBand::Low => write!(f, "LOW"),
            VerdictBand::Medium => write!(f, "MEDIUM"),
            VerdictBand::High => write!(f, "HIGH"),
            VerdictBand::Block => write!(f, "BLOCK"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: VerdictBand,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    pub files_added: usize,
    pub files_removed: usize,
    pub files_modified: usize,
    pub lines_added: usize,
    pub lines_deleted: usize,
}

use crate::advisory::AdvisoryReport;
use crate::provenance::ProvenanceReport;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustSources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisories: Option<AdvisoryReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ProvenanceReport>,
}

/// A recursive review of a package referenced by the reviewed payload
/// (lifecycle-script delivery, PKGBUILD npm/bun delivery, wheel
/// .data/scripts). `chain` is the delivery path from the root review to
/// this child, e.g. `["pkgbase@1.0-1", "npm:evil-pkg@1.0.0"]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildReview {
    pub chain: Vec<String>,
    pub name: String,
    pub version: String,
    pub ecosystem: crate::registry::Ecosystem,
    pub band: VerdictBand,
    pub risk_score: u32,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub name: String,
    pub target_version: String,
    pub baseline_version: Option<String>,
    pub integrity: String,
    pub ecosystem: crate::registry::Ecosystem,
    pub band: VerdictBand,
    pub risk_score: u32,
    pub findings: Vec<Finding>,
    pub diff_summary: DiffSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_sources: Option<TrustSources>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recursive: Vec<ChildReview>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_verdict(recursive: Vec<ChildReview>) -> Verdict {
        Verdict {
            name: "pkg".to_string(),
            target_version: "1.0.0".to_string(),
            baseline_version: None,
            integrity: "sha512:aa".to_string(),
            ecosystem: crate::registry::Ecosystem::Npm,
            band: VerdictBand::Low,
            risk_score: 0,
            findings: Vec::new(),
            diff_summary: DiffSummary {
                files_added: 0,
                files_removed: 0,
                files_modified: 0,
                lines_added: 0,
                lines_deleted: 0,
            },
            trust_sources: None,
            recursive,
        }
    }

    #[test]
    fn recursive_field_is_skipped_when_empty() {
        let json = serde_json::to_string(&minimal_verdict(Vec::new())).unwrap();
        assert!(!json.contains("recursive"), "{json}");
        let populated = minimal_verdict(vec![ChildReview {
            chain: vec!["pkg@1.0.0".to_string(), "npm:dep@1.0.0".to_string()],
            name: "dep".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: crate::registry::Ecosystem::Npm,
            band: VerdictBand::High,
            risk_score: 25,
            findings: Vec::new(),
        }]);
        let json = serde_json::to_string(&populated).unwrap();
        assert!(json.contains("\"recursive\""), "{json}");
        let parsed: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.recursive.len(), 1);
        assert_eq!(parsed.recursive[0].chain.len(), 2);
    }
}
