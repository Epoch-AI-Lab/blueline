use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::lockfile::compute_lockfile_delta;
use crate::policy::Policy;
use crate::render::sanitize_terminal;
use crate::review::evaluate_package;
use crate::store::BaselineStore;
use crate::verdict::{Verdict, VerdictBand};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiOutputFormat {
    Auto,
    Text,
    Markdown,
    Json,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CiReviewItem {
    pub name: String,
    pub old_version: Option<String>,
    pub new_version: String,
    pub is_dev: bool,
    pub verdict: Verdict,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CiReport {
    pub base_ref: String,
    pub lockfile_path: String,
    pub total_evaluated: usize,
    pub unchanged_count: usize,
    pub max_band: VerdictBand,
    pub passed: bool,
    pub items: Vec<CiReviewItem>,
}

#[derive(Debug, Clone, Copy)]
pub struct CiContext<'a> {
    pub base_ref: &'a str,
    pub lockfile_path: &'a str,
    pub registry_base: &'a str,
    pub fail_on: Option<VerdictBand>,
}

pub fn run(
    base_ref: &str,
    lockfile_path: &Path,
    registry_base: &str,
    policy_path: Option<&Path>,
    format: CiOutputFormat,
    fail_on_override: Option<VerdictBand>,
) -> anyhow::Result<()> {
    let policy = Policy::load_or_default(policy_path)?;
    let store =
        BaselineStore::open().map_err(|e| anyhow::anyhow!("opening baseline store: {e}"))?;

    let head_content = fs::read_to_string(lockfile_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read head lockfile at `{}`: {e}",
            lockfile_path.display()
        )
    })?;

    let base_content = extract_base_lockfile(base_ref, lockfile_path)?;

    let lockfile_str = lockfile_path.display().to_string();
    let ctx = CiContext {
        base_ref,
        lockfile_path: &lockfile_str,
        registry_base,
        fail_on: fail_on_override,
    };

    let report = evaluate_lockfile_diff(&base_content, &head_content, &ctx, &store, &policy)?;

    // Render output
    match format {
        CiOutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{json}");
        }
        CiOutputFormat::Markdown => {
            let md = render_markdown_summary(&report);
            println!("{md}");
        }
        CiOutputFormat::Text | CiOutputFormat::Auto => {
            render_text_summary(&report);
        }
    }

    // Emit to $GITHUB_STEP_SUMMARY if present
    if let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") {
        let trimmed = summary_path.trim();
        if !trimmed.is_empty() {
            let md = render_markdown_summary(&report);
            if let Ok(mut file) = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(trimmed)
            {
                let _ = writeln!(file, "\n{md}");
            }
        }
    }

    if !report.passed {
        let fail_threshold = if let Some(band) = fail_on_override {
            band
        } else {
            parse_band_str(&policy.ci.fail_on).unwrap_or(VerdictBand::High)
        };
        anyhow::bail!(
            "CI review failed: highest risk band `{}` reached or exceeded failure threshold `{fail_threshold}`",
            report.max_band
        );
    }

    Ok(())
}

pub fn evaluate_lockfile_diff(
    base_content: &str,
    head_content: &str,
    ctx: &CiContext<'_>,
    store: &BaselineStore,
    policy: &Policy,
) -> anyhow::Result<CiReport> {
    let delta = compute_lockfile_delta(base_content, head_content)?;

    let mut items = Vec::new();
    let mut max_band = VerdictBand::Low;

    let total_to_eval = delta.added.len() + delta.upgraded.len();
    if total_to_eval > policy.ci.max_evaluations {
        anyhow::bail!(
            "CI review exceeded maximum configured package evaluations ({} > {})",
            total_to_eval,
            policy.ci.max_evaluations
        );
    }

    // Process added packages
    for entry in &delta.added {
        if !policy.ci.include_dev && entry.is_dev {
            continue;
        }

        let (verdict, _, _) = evaluate_package(
            &entry.name,
            &entry.version,
            ctx.registry_base,
            store,
            policy,
        )?;

        if verdict.band > max_band {
            max_band = verdict.band;
        }

        items.push(CiReviewItem {
            name: entry.name.clone(),
            old_version: None,
            new_version: entry.version.clone(),
            is_dev: entry.is_dev,
            verdict,
        });
    }

    // Process upgraded packages
    for upgrade in &delta.upgraded {
        if !policy.ci.include_dev && upgrade.is_dev {
            continue;
        }

        let (verdict, _, _) = evaluate_package(
            &upgrade.name,
            &upgrade.new_version,
            ctx.registry_base,
            store,
            policy,
        )?;

        if verdict.band > max_band {
            max_band = verdict.band;
        }

        items.push(CiReviewItem {
            name: upgrade.name.clone(),
            old_version: Some(upgrade.old_version.clone()),
            new_version: upgrade.new_version.clone(),
            is_dev: upgrade.is_dev,
            verdict,
        });
    }

    let fail_threshold = if let Some(band) = ctx.fail_on {
        band
    } else {
        parse_band_str(&policy.ci.fail_on).unwrap_or(VerdictBand::High)
    };

    let passed = max_band < fail_threshold;

    Ok(CiReport {
        base_ref: ctx.base_ref.to_string(),
        lockfile_path: ctx.lockfile_path.to_string(),
        total_evaluated: items.len(),
        unchanged_count: delta.unchanged_count,
        max_band,
        passed,
        items,
    })
}

fn extract_base_lockfile(base_ref: &str, lockfile_path: &Path) -> anyhow::Result<String> {
    let spec = format!("{}:{}", base_ref, lockfile_path.display());
    let output = Command::new("git")
        .args(["show", &spec])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to execute git show `{spec}`: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // If file did not exist in base ref (e.g. initial commit of lockfile), return empty v3 template
        if stderr.contains("does not exist") || stderr.contains("path not in") {
            return Ok(r#"{"lockfileVersion": 3, "packages": {}}"#.to_string());
        }
        anyhow::bail!("git show `{spec}` failed: {stderr}");
    }

    String::from_utf8(output.stdout)
        .map_err(|e| anyhow::anyhow!("base lockfile from git is not valid UTF-8: {e}"))
}

fn parse_band_str(s: &str) -> Option<VerdictBand> {
    match s.trim().to_lowercase().as_str() {
        "low" => Some(VerdictBand::Low),
        "medium" => Some(VerdictBand::Medium),
        "high" => Some(VerdictBand::High),
        "block" => Some(VerdictBand::Block),
        _ => None,
    }
}

pub fn render_markdown_summary(report: &CiReport) -> String {
    let mut out = String::new();
    out.push_str("## 🛡️ Blueline CI Security Review\n\n");
    out.push_str(&format!(
        "**Base Ref:** `{}` · **Evaluated Packages:** {} · **Unchanged:** {}\n\n",
        report.base_ref, report.total_evaluated, report.unchanged_count
    ));

    if report.items.is_empty() {
        out.push_str("✅ **No new or upgraded packages detected in lockfile diff.**\n");
        return out;
    }

    let status_badge = if report.passed {
        "✅ **PASSED**"
    } else {
        "❌ **FAILED**"
    };

    out.push_str(&format!(
        "**Status:** {} (Max Risk Band: `{}`)\n\n",
        status_badge, report.max_band
    ));

    out.push_str("| Package | Old Version | New Version | Risk Score | Band | Findings |\n");
    out.push_str("| :--- | :--- | :--- | :---: | :---: | :--- |\n");

    for item in &report.items {
        let old_v = item.old_version.as_deref().unwrap_or("*(new)*");
        let findings_summary = if item.verdict.findings.is_empty() {
            "None (Clean)".to_string()
        } else {
            item.verdict
                .findings
                .iter()
                .map(|f| format!("`{}`: {}", f.rule_id, sanitize_terminal(&f.title)))
                .collect::<Vec<_>>()
                .join("<br/>")
        };

        out.push_str(&format!(
            "| **{}** | `{}` | `{}` | {} | `{}` | {} |\n",
            sanitize_terminal(&item.name),
            old_v,
            item.new_version,
            item.verdict.risk_score,
            item.verdict.band,
            findings_summary
        ));
    }

    out
}

pub fn render_text_summary(report: &CiReport) {
    println!("\n=======================================================");
    println!("             BLUELINE CI REVIEW SUMMARY                ");
    println!("=======================================================");
    println!("Base Ref:          {}", report.base_ref);
    println!("Evaluated:         {}", report.total_evaluated);
    println!("Unchanged:         {}", report.unchanged_count);
    println!("Max Risk Band:     {}", report.max_band);
    println!(
        "Status:            {}",
        if report.passed { "PASSED" } else { "FAILED" }
    );
    println!("-------------------------------------------------------");

    for item in &report.items {
        let old_v = item.old_version.as_deref().unwrap_or("new");
        println!(
            "{:<30} {:<10} -> {:<10} | Score: {:<3} | Band: {:<6}",
            sanitize_terminal(&item.name),
            old_v,
            item.new_version,
            item.verdict.risk_score,
            item.verdict.band
        );
        for f in &item.verdict.findings {
            println!("  ! [{}] {}", f.rule_id, sanitize_terminal(&f.title));
        }
    }
    println!("=======================================================\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_band_strings() {
        assert_eq!(parse_band_str("low"), Some(VerdictBand::Low));
        assert_eq!(parse_band_str("MEDIUM"), Some(VerdictBand::Medium));
        assert_eq!(parse_band_str("high"), Some(VerdictBand::High));
        assert_eq!(parse_band_str("block"), Some(VerdictBand::Block));
        assert_eq!(parse_band_str("unknown"), None);
    }

    #[test]
    fn renders_markdown_table() {
        let report = CiReport {
            base_ref: "origin/main".to_string(),
            lockfile_path: "package-lock.json".to_string(),
            total_evaluated: 1,
            unchanged_count: 5,
            max_band: VerdictBand::Low,
            passed: true,
            items: vec![CiReviewItem {
                name: "lodash".to_string(),
                old_version: Some("4.17.20".to_string()),
                new_version: "4.17.21".to_string(),
                is_dev: false,
                verdict: Verdict {
                    name: "lodash".to_string(),
                    target_version: "4.17.21".to_string(),
                    baseline_version: Some("4.17.20".to_string()),
                    integrity: "sha512-test".to_string(),
                    band: VerdictBand::Low,
                    risk_score: 5,
                    findings: vec![],
                    diff_summary: crate::verdict::DiffSummary {
                        files_added: 0,
                        files_removed: 0,
                        files_modified: 1,
                        lines_added: 2,
                        lines_deleted: 1,
                    },
                    trust_sources: None,
                },
            }],
        };

        let md = render_markdown_summary(&report);
        assert!(md.contains("lodash"));
        assert!(md.contains("4.17.21"));
        assert!(md.contains("PASSED"));
    }
}
