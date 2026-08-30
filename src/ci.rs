use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::lockfile::{compute_delta_from_maps, compute_lockfile_delta};
use crate::policy::Policy;
use crate::registry::Ecosystem;
use crate::render::{sanitize_single_line, sanitize_terminal};
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

fn is_cargo_lockfile(ecosystem: Ecosystem, lockfile_path: &Path) -> bool {
    ecosystem == Ecosystem::Cargo || lockfile_path.file_name().is_some_and(|n| n == "Cargo.lock")
}

fn is_pypi_lockfile(ecosystem: Ecosystem, lockfile_path: &Path) -> bool {
    ecosystem == Ecosystem::PyPi
        || lockfile_path.file_name().is_some_and(|n| {
            let s = n.to_string_lossy();
            s.contains("requirements") || s.ends_with(".txt")
        })
}

fn check_evaluation_budget(added: usize, upgraded: usize, max: usize) -> anyhow::Result<usize> {
    let total = added + upgraded;
    if total > max {
        anyhow::bail!(
            "CI review exceeded maximum configured package evaluations ({} > {})",
            total,
            max
        );
    }
    Ok(total)
}

fn evaluation_skipped(include_dev: bool, is_dev: bool) -> bool {
    !include_dev && is_dev
}

fn band_passes(max_band: VerdictBand, threshold: VerdictBand) -> bool {
    max_band < threshold
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

    let is_cargo = is_cargo_lockfile(ecosystem, lockfile_path);
    let is_pypi = is_pypi_lockfile(ecosystem, lockfile_path);
    let base_content = extract_base_lockfile(base_ref, lockfile_path, is_cargo, is_pypi)?;

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
    let is_cargo = is_cargo_lockfile(ctx.ecosystem, Path::new(ctx.lockfile_path));
    let is_pypi = is_pypi_lockfile(ctx.ecosystem, Path::new(ctx.lockfile_path));

    let (delta, head_integrity_map) = if is_cargo {
        let base_pkgs = crate::lockfile::parse_cargo_lock_packages(base_content)?;
        let head_pkgs = crate::lockfile::parse_cargo_lock_packages(head_content)?;
        let mut integrity_map = std::collections::HashMap::new();
        for pkg in head_pkgs.values() {
            if let Some(integ) = &pkg.integrity {
                integrity_map.insert(pkg.name.clone(), integ.clone());
            }
        }
        (
            compute_delta_from_maps(&base_pkgs, &head_pkgs),
            integrity_map,
        )
    } else if is_pypi {
        let base_pkgs = crate::lockfile::parse_requirements_txt_packages(base_content)?;
        let head_pkgs = crate::lockfile::parse_requirements_txt_packages(head_content)?;
        let mut integrity_map = std::collections::HashMap::new();
        for pkg in head_pkgs.values() {
            if let Some(integ) = &pkg.integrity {
                integrity_map.insert(pkg.name.clone(), integ.clone());
                integrity_map.insert(crate::version::canonicalize_name(&pkg.name), integ.clone());
            }
        }
        (
            compute_delta_from_maps(&base_pkgs, &head_pkgs),
            integrity_map,
        )
    } else {
        (
            compute_lockfile_delta(base_content, head_content)?,
            std::collections::HashMap::new(),
        )
    };

    check_evaluation_budget(
        delta.added.len(),
        delta.upgraded.len(),
        policy.ci.max_evaluations,
    )?;

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
        if evaluation_skipped(policy.ci.include_dev, is_dev) {
            continue;
        }

        let (mut verdict, _, checksum, _) = evaluate_package(
            name,
            new_version,
            ctx.ecosystem,
            ctx.registry_base,
            store,
            policy,
        )?;

        // If lockfile declared a hash, verify it matches
        if let Some(expected_integ) = head_integrity_map
            .get(name)
            .or_else(|| head_integrity_map.get(&crate::version::canonicalize_name(name)))
        {
            let matches_integ = expected_integ.split_whitespace().any(|expected_one| {
                let expected_hex = expected_one.strip_prefix("sha256:").unwrap_or(expected_one);
                checksum.value_hex.eq_ignore_ascii_case(expected_hex)
                    || checksum.to_display().eq_ignore_ascii_case(expected_one)
            });

            if !matches_integ {
                verdict.findings.push(crate::verdict::Finding {
                    rule_id: "R10_LOCKFILE_HASH_MISMATCH".into(),
                    severity: VerdictBand::Block,
                    title: format!("Lockfile hash mismatch for `{name}`"),
                    description: format!(
                        "Lockfile pinned `{expected_integ}`, but downloaded release has checksum `{}`",
                        checksum.to_display()
                    ),
                });
                verdict.band = VerdictBand::Block;
                verdict.risk_score = verdict.risk_score.saturating_add(50);
            }
        }

        max_band = update_max_band(max_band, verdict.band);

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

    let passed = band_passes(max_band, fail_threshold);

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

fn extract_base_lockfile(
    base_ref: &str,
    lockfile_path: &Path,
    is_cargo: bool,
    is_pypi: bool,
) -> anyhow::Result<String> {
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
        if is_missing_base_error(&stderr) {
            if is_cargo {
                return Ok("version = 4\n".to_string());
            }
            if is_pypi {
                return Ok(String::new());
            }
            return Ok(r#"{"lockfileVersion": 3, "packages": {}}"#.to_string());
        }
        anyhow::bail!("git show `{spec}` failed: {stderr}");
    }

    String::from_utf8(output.stdout)
        .map_err(|e| anyhow::anyhow!("base lockfile from git is not valid UTF-8: {e}"))
}

fn parse_band_str(s: &str) -> Option<VerdictBand> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("low") {
        Some(VerdictBand::Low)
    } else if t.eq_ignore_ascii_case("medium") {
        Some(VerdictBand::Medium)
    } else if t.eq_ignore_ascii_case("high") {
        Some(VerdictBand::High)
    } else if t.eq_ignore_ascii_case("block") {
        Some(VerdictBand::Block)
    } else {
        None
    }
}

fn is_missing_base_error(stderr: &str) -> bool {
    const NOT_IN_BASE: [&str; 2] = ["does not exist", "exists on disk, but not in"];
    NOT_IN_BASE.iter().any(|pat| stderr.contains(pat))
}

fn update_max_band(current: VerdictBand, next: VerdictBand) -> VerdictBand {
    current.max(next)
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
    out.push_str(&format!(
        "Base Ref:          {}\n",
        sanitize_single_line(&report.base_ref)
    ));
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
            sanitize_single_line(&item.name),
            sanitize_single_line(old_v),
            sanitize_single_line(&item.new_version),
            item.verdict.risk_score,
            item.verdict.band
        ));
        for f in &item.verdict.findings {
            out.push_str(&format!(
                "  ! [{}] {}\n",
                sanitize_single_line(&f.rule_id),
                sanitize_single_line(&f.title)
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
    fn parses_band_strings_with_whitespace_and_case() {
        assert_eq!(parse_band_str("  low  "), Some(VerdictBand::Low));
        assert_eq!(parse_band_str("\tMEDIUM\n"), Some(VerdictBand::Medium));
        assert_eq!(parse_band_str("  HIGH "), Some(VerdictBand::High));
        assert_eq!(parse_band_str(" Block "), Some(VerdictBand::Block));
        assert_eq!(parse_band_str("  unknown  "), None);
    }

    #[test]
    fn missing_base_error_matches_each_pattern_independently() {
        assert!(is_missing_base_error(
            "fatal: path 'Cargo.lock' does not exist in 'HEAD'"
        ));
        assert!(is_missing_base_error(
            "fatal: path 'Cargo.lock' exists on disk, but not in 'HEAD'"
        ));
        assert!(is_missing_base_error("does not exist"));
        assert!(!is_missing_base_error("fatal: ambiguous argument 'HEAD'"));
        assert!(!is_missing_base_error(
            "fatal: ambiguous argument 'HEAD~999': unknown revision or path not in the working tree"
        ));
        assert!(!is_missing_base_error(""));
    }

    #[test]
    fn missing_base_error_any_not_all() {
        assert!(is_missing_base_error("does not exist"));
        assert!(is_missing_base_error("exists on disk, but not in 'HEAD'"));
        assert!(!is_missing_base_error("path not in the working tree"));
    }

    #[test]
    fn max_band_tracks_maximum_not_minimum() {
        assert_eq!(
            update_max_band(VerdictBand::Low, VerdictBand::Block),
            VerdictBand::Block
        );
        assert_eq!(
            update_max_band(VerdictBand::Block, VerdictBand::Low),
            VerdictBand::Block
        );
        assert_eq!(
            update_max_band(VerdictBand::Medium, VerdictBand::High),
            VerdictBand::High
        );
        assert_eq!(
            update_max_band(VerdictBand::High, VerdictBand::High),
            VerdictBand::High
        );
        assert_eq!(
            update_max_band(VerdictBand::Low, VerdictBand::Low),
            VerdictBand::Low
        );
    }

    #[test]
    fn cargo_lockfile_dispatch_matches_each_signal_independently() {
        assert!(is_cargo_lockfile(Ecosystem::Cargo, Path::new("Cargo.lock")));
        assert!(is_cargo_lockfile(
            Ecosystem::Cargo,
            Path::new("package-lock.json")
        ));
        assert!(is_cargo_lockfile(Ecosystem::Npm, Path::new("Cargo.lock")));
        assert!(is_cargo_lockfile(
            Ecosystem::Npm,
            Path::new("sub/dir/Cargo.lock")
        ));
        assert!(!is_cargo_lockfile(
            Ecosystem::Npm,
            Path::new("package-lock.json")
        ));
        assert!(!is_cargo_lockfile(
            Ecosystem::Npm,
            Path::new("sub/dir/package-lock.json")
        ));
        assert!(!is_cargo_lockfile(Ecosystem::Npm, Path::new("cargo.lock")));
    }

    #[test]
    fn pypi_lockfile_dispatch_matches_signals() {
        assert!(is_pypi_lockfile(
            Ecosystem::PyPi,
            Path::new("requirements.txt")
        ));
        assert!(is_pypi_lockfile(
            Ecosystem::PyPi,
            Path::new("random-name.lock")
        ));
        assert!(is_pypi_lockfile(
            Ecosystem::Npm,
            Path::new("requirements.txt")
        ));
        assert!(is_pypi_lockfile(
            Ecosystem::Npm,
            Path::new("requirements-dev.txt")
        ));
        assert!(!is_pypi_lockfile(
            Ecosystem::Npm,
            Path::new("package-lock.json")
        ));
        assert!(!is_pypi_lockfile(Ecosystem::Cargo, Path::new("Cargo.lock")));
    }

    #[test]
    fn evaluation_budget_sums_both_kinds_and_allows_exact_boundary() {
        let err = check_evaluation_budget(2, 1, 2).unwrap_err();
        assert_eq!(
            err.to_string(),
            "CI review exceeded maximum configured package evaluations (3 > 2)"
        );
        assert_eq!(check_evaluation_budget(1, 1, 2).unwrap(), 2);
        assert_eq!(check_evaluation_budget(1, 0, 2).unwrap(), 1);
        assert_eq!(check_evaluation_budget(0, 0, 0).unwrap(), 0);
    }

    #[test]
    fn only_dev_packages_are_skipped_and_only_when_not_included() {
        assert!(evaluation_skipped(false, true));
        assert!(!evaluation_skipped(false, false));
        assert!(!evaluation_skipped(true, true));
        assert!(!evaluation_skipped(true, false));
    }

    #[test]
    fn band_equal_to_threshold_fails_and_below_passes() {
        assert!(band_passes(VerdictBand::Medium, VerdictBand::High));
        assert!(!band_passes(VerdictBand::High, VerdictBand::High));
        assert!(!band_passes(VerdictBand::Low, VerdictBand::Low));
        assert!(!band_passes(VerdictBand::Block, VerdictBand::High));
    }

    #[test]
    fn rejects_flag_like_base_refs() {
        let err = extract_base_lockfile(
            "--output=/tmp/pwn",
            Path::new("package-lock.json"),
            false,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot start with '-'"));

        let err_ws_flag =
            extract_base_lockfile("  --evil", Path::new("package-lock.json"), false, false)
                .unwrap_err();
        assert!(err_ws_flag.to_string().contains("cannot start with '-'"));

        let err_empty =
            extract_base_lockfile("  ", Path::new("package-lock.json"), false, false).unwrap_err();
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
    fn escapes_markdown_cells_strips_terminal_escapes() {
        let report = CiReport {
            base_ref: "origin/main\x1b[31mred\x1b[0m".to_string(),
            lockfile_path: "package-lock.json".to_string(),
            total_evaluated: 1,
            unchanged_count: 0,
            max_band: VerdictBand::Block,
            passed: false,
            items: vec![CiReviewItem {
                name: "pkg\x1b[2Jinjected".to_string(),
                old_version: Some("1.0.0\x1b[31m".to_string()),
                new_version: "2.0.0\x1b[31m".to_string(),
                is_dev: false,
                verdict: Verdict {
                    name: "pkg".to_string(),
                    target_version: "2.0.0".to_string(),
                    baseline_version: None,
                    integrity: "sha512-test".to_string(),
                    ecosystem: crate::registry::Ecosystem::Npm,
                    band: VerdictBand::Block,
                    risk_score: 90,
                    findings: vec![crate::verdict::Finding {
                        rule_id: "R01\x1b[2Jevil".to_string(),
                        severity: VerdictBand::Block,
                        title: "title\x1b[31m|pipe\nnewline".to_string(),
                        description: "desc".to_string(),
                    }],
                    diff_summary: crate::verdict::DiffSummary {
                        files_added: 0,
                        files_removed: 0,
                        files_modified: 0,
                        lines_added: 0,
                        lines_deleted: 0,
                    },
                    trust_sources: None,
                },
            }],
        };
        let md = render_markdown_summary(&report);
        assert!(!md.contains('\x1b'), "markdown must strip terminal escapes");
        assert!(md.contains(r"title\|pipe<br/>newline"));
        assert!(!md.contains("injected\x1b"));
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
    fn renders_text_summary_sanitizes_versions_and_findings() {
        let report = CiReport {
            base_ref: "origin/main\x1b[31mred".to_string(),
            lockfile_path: "package-lock.json".to_string(),
            total_evaluated: 1,
            unchanged_count: 0,
            max_band: VerdictBand::High,
            passed: false,
            items: vec![CiReviewItem {
                name: "pkg\x1b[2Jeval".to_string(),
                old_version: Some("1.0.0\x1b[31m".to_string()),
                new_version: "2.0.0\x1b[2J".to_string(),
                is_dev: false,
                verdict: Verdict {
                    name: "pkg".to_string(),
                    target_version: "2.0.0".to_string(),
                    baseline_version: None,
                    integrity: "sha512-test".to_string(),
                    ecosystem: crate::registry::Ecosystem::Npm,
                    band: VerdictBand::High,
                    risk_score: 80,
                    findings: vec![crate::verdict::Finding {
                        rule_id: "R01\x1b[31m".to_string(),
                        severity: VerdictBand::High,
                        title: "evil\x1b[2Jtitle".to_string(),
                        description: "desc".to_string(),
                    }],
                    diff_summary: crate::verdict::DiffSummary {
                        files_added: 0,
                        files_removed: 0,
                        files_modified: 0,
                        lines_added: 0,
                        lines_deleted: 0,
                    },
                    trust_sources: None,
                },
            }],
        };
        let text = render_text_summary_to_string(&report);
        assert!(
            !text.contains('\x1b'),
            "text summary must strip escapes from all fields"
        );
        assert!(text.contains("pkg"));
        assert!(text.contains("1.0.0"));
        assert!(text.contains("2.0.0"));
        assert!(text.contains("R01"));
    }

    #[test]
    fn renders_text_summary_strips_newlines_via_single_line() {
        let report = CiReport {
            base_ref: "origin/main\nInjected: evil".to_string(),
            lockfile_path: "package-lock.json".to_string(),
            total_evaluated: 1,
            unchanged_count: 0,
            max_band: VerdictBand::High,
            passed: false,
            items: vec![CiReviewItem {
                name: "pkg\nInjected line".to_string(),
                old_version: Some("1.0.0\nfake".to_string()),
                new_version: "2.0.0\nfake".to_string(),
                is_dev: false,
                verdict: Verdict {
                    name: "pkg".to_string(),
                    target_version: "2.0.0".to_string(),
                    baseline_version: None,
                    integrity: "sha512-test".to_string(),
                    ecosystem: crate::registry::Ecosystem::Npm,
                    band: VerdictBand::High,
                    risk_score: 80,
                    findings: vec![crate::verdict::Finding {
                        rule_id: "R01\nInject".to_string(),
                        severity: VerdictBand::High,
                        title: "title\nwith newline".to_string(),
                        description: "desc".to_string(),
                    }],
                    diff_summary: crate::verdict::DiffSummary {
                        files_added: 0,
                        files_removed: 0,
                        files_modified: 0,
                        lines_added: 0,
                        lines_deleted: 0,
                    },
                    trust_sources: None,
                },
            }],
        };
        let text = render_text_summary_to_string(&report);
        assert!(
            text.contains("origin/main Injected: evil"),
            "newline in base_ref must be flattened to space: {text}"
        );
        assert!(
            text.contains("pkg Injected line"),
            "newline in name must be flattened: {text}"
        );
        assert!(
            !text.lines().any(|l| l.trim_start().starts_with("Injected")),
            "newline injection must not create new line: {text}"
        );
        assert!(!text.contains("pkg\nInjected"), "newline must not survive");
    }

    #[test]
    fn invalid_git_ref_fails_closed() {
        let res = extract_base_lockfile(
            "-leading-hyphen",
            Path::new("package-lock.json"),
            false,
            false,
        );
        assert!(res.is_err());
        let res_nonexistent = extract_base_lockfile(
            "nonexistent_ref_123456789",
            Path::new("package-lock.json"),
            false,
            false,
        );
        assert!(res_nonexistent.is_err());
    }

    #[test]
    fn cargo_missing_base_returns_empty_cargo_toml() {
        let cargo_empty = extract_base_lockfile(
            "HEAD",
            Path::new("Cargo.lock.missing-for-test-xyz"),
            true,
            false,
        )
        .unwrap();
        assert_eq!(cargo_empty, "version = 4\n");
        assert!(crate::lockfile::parse_cargo_lock_packages(&cargo_empty).is_ok());
        let npm_empty = extract_base_lockfile(
            "HEAD",
            Path::new("package-lock.missing-for-test-xyz"),
            false,
            false,
        )
        .unwrap();
        assert_eq!(npm_empty, r#"{"lockfileVersion": 3, "packages": {}}"#);
        assert!(crate::lockfile::parse_lockfile_packages(&npm_empty).is_ok());
        let pypi_empty = extract_base_lockfile(
            "HEAD",
            Path::new("requirements.missing-for-test-xyz.txt"),
            false,
            true,
        )
        .unwrap();
        assert_eq!(pypi_empty, "");
        assert!(crate::lockfile::parse_requirements_txt_packages(&pypi_empty).is_ok());
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
