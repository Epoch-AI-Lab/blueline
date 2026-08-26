use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::lockfile::{compute_delta_from_maps, compute_lockfile_delta};
use crate::policy::Policy;
use crate::registry::Ecosystem;
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
    pub ecosystem: Ecosystem,
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    base_ref: &str,
    lockfile_path: &Path,
    registry_base: &str,
    ecosystem: Ecosystem,
    policy_path: Option<&Path>,
    format: CiOutputFormat,
    fail_on_override: Option<VerdictBand>,
    output_file: Option<&Path>,
) -> anyhow::Result<()> {
    let policy = Policy::load_or_default(policy_path)?;
    let store = BaselineStore::open()?;

    let head_content = fs::read_to_string(lockfile_path).map_err(|e| {
        let hint = if e.kind() == std::io::ErrorKind::NotFound {
            " (use `--lockfile <path>` to specify a different path)"
        } else {
            ""
        };
        anyhow::anyhow!(
            "failed to read head lockfile at `{}`: {e}{hint}",
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
        ecosystem,
    };

    let report = evaluate_lockfile_diff(&base_content, &head_content, &ctx, &store, &policy)?;

    // Render output
    let output_str = match format {
        CiOutputFormat::Json => serde_json::to_string_pretty(&report)?,
        CiOutputFormat::Markdown => render_markdown_summary(&report),
        CiOutputFormat::Text | CiOutputFormat::Auto => render_text_summary_to_string(&report),
    };

    println!("{output_str}");

    if let Some(out_path) = output_file {
        fs::write(out_path, &output_str).map_err(|e| {
            anyhow::anyhow!("failed to write CI report to `{}`: {e}", out_path.display())
        })?;
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
        let fail_threshold = fail_on_override
            .unwrap_or_else(|| parse_band_str(&policy.ci.fail_on).unwrap_or(VerdictBand::High));
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
    let is_cargo = ctx.ecosystem == Ecosystem::Cargo
        || Path::new(ctx.lockfile_path)
            .file_name()
            .is_some_and(|n| n == "Cargo.lock");
    let delta = if is_cargo {
        let base_pkgs = crate::lockfile::parse_cargo_lock_packages(base_content)?;
        let head_pkgs = crate::lockfile::parse_cargo_lock_packages(head_content)?;
        compute_delta_from_maps(&base_pkgs, &head_pkgs)
    } else {
        compute_lockfile_delta(base_content, head_content)?
    };

    let total_to_eval = delta.added.len() + delta.upgraded.len();
    if total_to_eval > policy.ci.max_evaluations {
        anyhow::bail!(
            "CI review exceeded maximum configured package evaluations ({} > {})",
            total_to_eval,
            policy.ci.max_evaluations
        );
    }

    let mut items = Vec::new();
    let mut max_band = VerdictBand::Low;

    let eval_candidates = delta
        .added
        .iter()
        .map(|e| (&e.name, None, &e.version, e.is_dev))
        .chain(delta.upgraded.iter().map(|u| {
            (
                &u.name,
                Some(u.old_version.clone()),
                &u.new_version,
                u.is_dev,
            )
        }));

    for (name, old_version, new_version, is_dev) in eval_candidates {
        if !policy.ci.include_dev && is_dev {
            continue;
        }

        let (verdict, _, _, _) = evaluate_package(
            name,
            new_version,
            ctx.ecosystem,
            ctx.registry_base,
            store,
            policy,
        )?;

        max_band = max_band.max(verdict.band);

        items.push(CiReviewItem {
            name: name.to_string(),
            old_version,
            new_version: new_version.to_string(),
            is_dev,
            verdict,
        });
    }

    let fail_threshold = ctx
        .fail_on
        .unwrap_or_else(|| parse_band_str(&policy.ci.fail_on).unwrap_or(VerdictBand::High));

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
    let trimmed_ref = base_ref.trim();
    if trimmed_ref.starts_with('-') || trimmed_ref.is_empty() {
        anyhow::bail!("invalid git base ref `{base_ref}`: cannot start with '-' or be empty");
    }

    let spec = format!("{trimmed_ref}:{}", lockfile_path.display());
    let output = Command::new("git")
        .args(["show", &spec])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to execute git show `{spec}`: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        const NOT_IN_BASE: [&str; 4] = [
            "does not exist",
            "path not in",
            "exists on disk, but not in",
            "does not exist in",
        ];
        if NOT_IN_BASE.iter().any(|pat| stderr.contains(pat)) {
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

fn escape_markdown_cell(s: &str) -> String {
    let sanitized = sanitize_terminal(s);
    sanitized.replace('|', "\\|").replace('\n', "<br/>")
}

pub fn render_markdown_summary(report: &CiReport) -> String {
    let mut out = String::new();
    out.push_str("## 🛡️ Blueline CI Security Review\n\n");
    out.push_str(&format!(
        "**Base Ref:** `{}` · **Evaluated Packages:** {} · **Unchanged:** {}\n\n",
        escape_markdown_cell(&report.base_ref),
        report.total_evaluated,
        report.unchanged_count
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
                .map(|f| {
                    format!(
                        "`{}`: {}",
                        escape_markdown_cell(&f.rule_id),
                        escape_markdown_cell(&f.title)
                    )
                })
                .collect::<Vec<_>>()
                .join("<br/>")
        };

        out.push_str(&format!(
            "| **{}** | `{}` | `{}` | {} | `{}` | {} |\n",
            escape_markdown_cell(&item.name),
            escape_markdown_cell(old_v),
            escape_markdown_cell(&item.new_version),
            item.verdict.risk_score,
            item.verdict.band,
            findings_summary
        ));
    }

    out
}

pub fn render_text_summary_to_string(report: &CiReport) -> String {
    let mut out = String::new();
    out.push_str("\n=======================================================\n");
    out.push_str("             BLUELINE CI REVIEW SUMMARY                \n");
    out.push_str("=======================================================\n");
    out.push_str(&format!("Base Ref:          {}\n", report.base_ref));
    out.push_str(&format!("Evaluated:         {}\n", report.total_evaluated));
    out.push_str(&format!("Unchanged:         {}\n", report.unchanged_count));
    out.push_str(&format!("Max Risk Band:     {}\n", report.max_band));
    out.push_str(&format!(
        "Status:            {}\n",
        if report.passed { "PASSED" } else { "FAILED" }
    ));
    out.push_str("-------------------------------------------------------\n");

    for item in &report.items {
        let old_v = item.old_version.as_deref().unwrap_or("new");
        out.push_str(&format!(
            "{:<30} {:<10} -> {:<10} | Score: {:<3} | Band: {:<6}\n",
            sanitize_terminal(&item.name),
            old_v,
            item.new_version,
            item.verdict.risk_score,
            item.verdict.band
        ));
        for f in &item.verdict.findings {
            out.push_str(&format!(
                "  ! [{}] {}\n",
                f.rule_id,
                sanitize_terminal(&f.title)
            ));
        }
    }
    out.push_str("=======================================================\n");
    out
}

pub fn render_text_summary(report: &CiReport) {
    print!("{}", render_text_summary_to_string(report));
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
    fn rejects_flag_like_base_refs() {
        let err =
            extract_base_lockfile("--output=/tmp/pwn", Path::new("package-lock.json")).unwrap_err();
        assert!(err.to_string().contains("cannot start with '-'"));

        let err_empty = extract_base_lockfile("  ", Path::new("package-lock.json")).unwrap_err();
        assert!(err_empty.to_string().contains("or be empty"));
    }

    #[test]
    fn escapes_markdown_cells() {
        let report = CiReport {
            base_ref: "origin/main".to_string(),
            lockfile_path: "package-lock.json".to_string(),
            total_evaluated: 1,
            unchanged_count: 5,
            max_band: VerdictBand::Block,
            passed: false,
            items: vec![CiReviewItem {
                name: "malicious|pkg".to_string(),
                old_version: None,
                new_version: "1.0.0".to_string(),
                is_dev: false,
                verdict: Verdict {
                    name: "malicious|pkg".to_string(),
                    target_version: "1.0.0".to_string(),
                    baseline_version: None,
                    integrity: "sha512-test".to_string(),
                    ecosystem: crate::registry::Ecosystem::Npm,
                    band: VerdictBand::Block,
                    risk_score: 95,
                    findings: vec![crate::verdict::Finding {
                        rule_id: "EVAL|NETWORK".to_string(),
                        severity: VerdictBand::Block,
                        title: "eval | payload\nmultiline".to_string(),
                        description: "desc".to_string(),
                    }],
                    diff_summary: crate::verdict::DiffSummary {
                        files_added: 1,
                        files_removed: 0,
                        files_modified: 0,
                        lines_added: 10,
                        lines_deleted: 0,
                    },
                    trust_sources: None,
                },
            }],
        };

        let md = render_markdown_summary(&report);
        assert!(md.contains(r"malicious\|pkg"));
        assert!(md.contains(r"EVAL\|NETWORK"));
        assert!(md.contains(r"eval \| payload<br/>multiline"));
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
                    ecosystem: crate::registry::Ecosystem::Npm,
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

    #[test]
    fn renders_text_summary_to_string() {
        let report = CiReport {
            base_ref: "origin/main".to_string(),
            lockfile_path: "package-lock.json".to_string(),
            total_evaluated: 1,
            unchanged_count: 3,
            max_band: VerdictBand::Low,
            passed: true,
            items: vec![],
        };
        let text = render_text_summary_to_string(&report);
        assert!(text.contains("BLUELINE CI REVIEW SUMMARY"));
        assert!(text.contains("Base Ref:          origin/main"));
        assert!(text.contains("Status:            PASSED"));
    }

    #[test]
    fn invalid_git_ref_fails_closed() {
        let res = extract_base_lockfile("-leading-hyphen", Path::new("package-lock.json"));
        assert!(res.is_err());
        let res_nonexistent =
            extract_base_lockfile("nonexistent_ref_123456789", Path::new("package-lock.json"));
        assert!(res_nonexistent.is_err());
    }

    #[test]
    fn cargo_dispatch_by_filename_or_ecosystem() {
        // Kills the || → && mutant at evaluate_lockfile_diff:142.
        // Either condition alone must select the Cargo parser.
        let cargo_toml = r#"
version = 4
[[package]]
name = "a"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#;
        let empty_toml = "version = 4\n";
        let store =
            BaselineStore::open_at(&tempfile::tempdir().unwrap().path().join("t.db")).unwrap();
        let policy = Policy::load_or_default(None).unwrap();

        // Case 1: filename is Cargo.lock but ecosystem is Npm → must still parse as Cargo.
        let ctx_file = CiContext {
            base_ref: "origin/main",
            lockfile_path: "Cargo.lock",
            registry_base: "https://index.crates.io",
            fail_on: Some(VerdictBand::Block),
            ecosystem: crate::registry::Ecosystem::Npm,
        };
        let r1 =
            evaluate_lockfile_diff(cargo_toml, empty_toml, &ctx_file, &store, &policy).unwrap();
        // a 1.0.0 removed (was in base, not in head) → removed path, still a valid cargo diff
        assert_eq!(r1.unchanged_count, 0);

        // Case 2: ecosystem is Cargo but path is not Cargo.lock → must still parse as Cargo.
        let ctx_eco = CiContext {
            base_ref: "origin/main",
            lockfile_path: "my.lock",
            registry_base: "https://index.crates.io",
            fail_on: Some(VerdictBand::Block),
            ecosystem: crate::registry::Ecosystem::Cargo,
        };
        let r2 = evaluate_lockfile_diff(cargo_toml, empty_toml, &ctx_eco, &store, &policy).unwrap();
        assert_eq!(r2.unchanged_count, 0);

        // Case 3: neither matches → npm JSON path (empty JSON object would be npm, not cargo).
        let ctx_npm = CiContext {
            base_ref: "origin/main",
            lockfile_path: "package-lock.json",
            registry_base: "https://registry.npmjs.org",
            fail_on: Some(VerdictBand::Block),
            ecosystem: crate::registry::Ecosystem::Npm,
        };
        // npm empty packages JSON should parse as npm, not cargo.
        let npm_json =
            r#"{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0"}}}"#;
        let empty_npm = r#"{"lockfileVersion": 3, "packages": {}}"#;
        let r3 = evaluate_lockfile_diff(npm_json, empty_npm, &ctx_npm, &store, &policy).unwrap();
        assert_eq!(r3.unchanged_count, 0);
    }
}
