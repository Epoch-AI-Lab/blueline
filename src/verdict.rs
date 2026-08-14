use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VerdictBand {
    Low,
    Medium,
    High,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub name: String,
    pub target_version: String,
    pub baseline_version: Option<String>,
    pub integrity: String,
    pub band: VerdictBand,
    pub risk_score: u32,
    pub findings: Vec<Finding>,
    pub diff_summary: DiffSummary,
}
