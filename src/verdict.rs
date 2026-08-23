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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
