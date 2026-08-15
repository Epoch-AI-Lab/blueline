use crate::diff::{Delta, FileKind};
use crate::verdict::{DiffSummary, Finding, Verdict, VerdictBand};

pub fn evaluate(
    name: &str,
    integrity: &str,
    delta: &Delta,
    is_unreviewed_baseline: bool,
) -> Verdict {
    let mut findings = Vec::new();

    // R01: Lifecycle scripts
    for script in &delta.new_lifecycle_scripts {
        findings.push(Finding {
            rule_id: "R01_LIFECYCLE_SCRIPT_ADDED".into(),
            severity: VerdictBand::Block,
            title: format!("New install-time lifecycle script: `{script}`"),
            description: format!(
                "The package added `{script}` to package.json scripts which executes automatically on install."
            ),
        });
    }

    for script in &delta.modified_lifecycle_scripts {
        findings.push(Finding {
            rule_id: "R01_LIFECYCLE_SCRIPT_MODIFIED".into(),
            severity: VerdictBand::High,
            title: format!("Modified lifecycle script: `{script}`"),
            description: format!(
                "The command for lifecycle script `{script}` was modified between releases."
            ),
        });
    }

    // Native build trigger: binding.gyp in root triggers node-gyp rebuild on install
    if delta.binding_gyp_added
        || delta
            .files_added
            .iter()
            .any(|f| f.relative_path == "binding.gyp")
    {
        findings.push(Finding {
            rule_id: "R01_BINDING_GYP_ADDED".into(),
            severity: VerdictBand::Block,
            title: "Automated native build trigger: `binding.gyp`".into(),
            description: "The package added `binding.gyp` in root which triggers `node-gyp rebuild` automatically on install.".into(),
        });
    } else if delta
        .files_modified
        .iter()
        .any(|f| f.relative_path == "binding.gyp")
    {
        findings.push(Finding {
            rule_id: "R01_BINDING_GYP_MODIFIED".into(),
            severity: VerdictBand::High,
            title: "Modified native build file: `binding.gyp`".into(),
            description: "The `binding.gyp` native build configuration was modified between releases.".into(),
        });
    }

    // R02: Native executables or binaries
    for exe in &delta.new_executables {
        findings.push(Finding {
            rule_id: "R02_EXECUTABLE_ADDED".into(),
            severity: VerdictBand::High,
            title: format!("Executable or script added: `{exe}`"),
            description: format!(
                "File `{exe}` has an executable extension or executable filesystem permissions."
            ),
        });
    }

    // R02: Opaque oversized files added/modified
    for file in &delta.files_added {
        if file.kind == FileKind::OpaqueTooLarge {
            findings.push(Finding {
                rule_id: "R02_OPAQUE_LARGE_FILE_ADDED".into(),
                severity: VerdictBand::High,
                title: format!("Opaque oversized file added: `{}`", file.relative_path),
                description: format!(
                    "File `{}` exceeds the diff inspection cap and cannot be inspected as text.",
                    file.relative_path
                ),
            });
        }
    }
    for file in &delta.files_modified {
        if file.kind == FileKind::OpaqueTooLarge {
            findings.push(Finding {
                rule_id: "R02_OPAQUE_LARGE_FILE_ADDED".into(),
                severity: VerdictBand::High,
                title: format!("Opaque oversized file modified: `{}`", file.relative_path),
                description: format!(
                    "File `{}` exceeds the diff inspection cap and cannot be inspected as text.",
                    file.relative_path
                ),
            });
        }
    }

    for bin in &delta.new_binaries {
        if !delta.new_executables.contains(bin) {
            let is_opaque_large = delta
                .files_added
                .iter()
                .chain(delta.files_modified.iter())
                .any(|f| &f.relative_path == bin && f.kind == FileKind::OpaqueTooLarge);
            if !is_opaque_large {
                findings.push(Finding {
                    rule_id: "R02_BINARY_BLOB_ADDED".into(),
                    severity: VerdictBand::High,
                    title: format!("Binary or opaque blob added: `{bin}`"),
                    description: format!(
                        "File `{bin}` contains NUL bytes or non-UTF-8 content and cannot be inspected as text."
                    ),
                });
            }
        }
    }

    // R03: Suspicious code in text diffs (eval, child_process, base64 payload)
    for file in delta.files_added.iter().chain(delta.files_modified.iter()) {
        if file.kind == FileKind::Text
            && let Some(diff_text) = &file.unified_diff
        {
            scan_diff_for_suspicious_patterns(&file.relative_path, diff_text, &mut findings);
        }
    }

    // R04: Dependency changes
    if !delta.new_dependencies.is_empty() {
        let deps_str = delta
            .new_dependencies
            .iter()
            .map(|(d, v)| format!("{d}@{v}"))
            .collect::<Vec<_>>()
            .join(", ");
        let has_suspicious_url = delta
            .new_dependencies
            .iter()
            .any(|(_, v)| is_non_semver_url(v));

        findings.push(Finding {
            rule_id: "R04_DEPENDENCY_ADDED".into(),
            severity: if has_suspicious_url {
                VerdictBand::High
            } else {
                VerdictBand::Medium
            },
            title: format!(
                "{} new runtime dependencies added",
                delta.new_dependencies.len()
            ),
            description: format!("Added dependencies: {deps_str}"),
        });
    }

    // R05: Large diff anomaly on patch or non-standard semver
    if let Some(base_ver_str) = &delta.baseline_version {
        match (
            semver::Version::parse(base_ver_str),
            semver::Version::parse(&delta.target_version),
        ) {
            (Ok(base_v), Ok(target_v)) => {
                if base_v.major == target_v.major
                    && base_v.minor == target_v.minor
                    && delta.total_lines_added > 500
                {
                    findings.push(Finding {
                        rule_id: "R05_LARGE_PATCH_DIFF".into(),
                        severity: VerdictBand::Medium,
                        title: format!("Large patch delta (+{} lines)", delta.total_lines_added),
                        description: format!(
                            "Patch release {base_v} -> {target_v} added {} lines across {} files.",
                            delta.total_lines_added,
                            delta.files_added.len() + delta.files_modified.len()
                        ),
                    });
                }
            }
            _ => {
                findings.push(Finding {
                    rule_id: "R05_NON_STANDARD_VERSION".into(),
                    severity: VerdictBand::Medium,
                    title: "Non-standard version format".into(),
                    description: format!(
                        "Baseline `{base_ver_str}` or target `{}` does not conform to strict semver.",
                        delta.target_version
                    ),
                });
            }
        }
    }

    // R06: First sighting
    if delta.baseline_version.is_none() {
        findings.push(Finding {
            rule_id: "R06_FIRST_SIGHTING".into(),
            severity: VerdictBand::Medium,
            title: "First sighting: no known-clean baseline exists".into(),
            description: "No previous version was found to diff against; full tarball inspected."
                .into(),
        });
    }

    // R07: Unreviewed predecessor baseline
    if is_unreviewed_baseline {
        let base_ver = delta.baseline_version.as_deref().unwrap_or("unknown");
        findings.push(Finding {
            rule_id: "R07_UNREVIEWED_PREDECESSOR_BASELINE".into(),
            severity: VerdictBand::Medium,
            title: format!("Unreviewed baseline version `{base_ver}`"),
            description: format!(
                "Baseline version `{base_ver}` was selected from registry history and has not been approved locally."
            ),
        });
    }

    let mut score: u32 = 0;
    let mut band = VerdictBand::Low;

    for f in &findings {
        match f.severity {
            VerdictBand::Block => {
                score = score.saturating_add(50);
                band = VerdictBand::Block;
            }
            VerdictBand::High => {
                score = score.saturating_add(25);
                if band < VerdictBand::High {
                    band = VerdictBand::High;
                }
            }
            VerdictBand::Medium => {
                let add = if f.rule_id == "R06_FIRST_SIGHTING" {
                    15
                } else {
                    10
                };
                score = score.saturating_add(add);
                if band < VerdictBand::Medium {
                    band = VerdictBand::Medium;
                }
            }
            VerdictBand::Low => {}
        }
    }

    let capped_score = score.min(100);

    // Escalate to Block if accumulated risk score reaches 80+
    if capped_score >= 80 {
        band = VerdictBand::Block;
    }

    Verdict {
        name: name.to_string(),
        target_version: delta.target_version.clone(),
        baseline_version: delta.baseline_version.clone(),
        integrity: integrity.to_string(),
        band,
        risk_score: capped_score,
        findings,
        diff_summary: DiffSummary {
            files_added: delta.files_added.len(),
            files_removed: delta.files_removed.len(),
            files_modified: delta.files_modified.len(),
            lines_added: delta.total_lines_added,
            lines_deleted: delta.total_lines_deleted,
        },
    }
}

fn is_non_semver_url(v: &str) -> bool {
    let lower = v.to_lowercase();
    lower.starts_with("git")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
        || lower.starts_with("bitbucket:")
        || lower.starts_with("ssh://")
        || lower.starts_with("file:")
        || lower.starts_with("link:")
        || lower.starts_with("npm:")
}

fn scan_diff_for_suspicious_patterns(path: &str, diff: &str, findings: &mut Vec<Finding>) {
    let mut flagged_eval = false;
    let mut flagged_child_proc = false;
    let mut flagged_base64_exec = false;
    let mut flagged_high_entropy = false;

    let mut added_lines = Vec::new();
    for line in diff.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            added_lines.push(&line[1..]);
        }
    }

    let combined_added = added_lines.join("\n");

    // Check multi-line combined added text
    if is_eval_invocation(&combined_added) {
        flagged_eval = true;
        findings.push(Finding {
            rule_id: "R03_EVAL_USAGE".into(),
            severity: VerdictBand::High,
            title: format!("Dynamic code evaluation in `{path}`"),
            description: format!("Diff introduced `eval()` or `new Function()` in `{path}`."),
        });
    }

    if is_child_proc_invocation(&combined_added) {
        flagged_child_proc = true;
        findings.push(Finding {
            rule_id: "R03_CHILD_PROCESS".into(),
            severity: VerdictBand::High,
            title: format!("Process execution primitive in `{path}`"),
            description: format!("Diff introduced child_process execution calls in `{path}`."),
        });
    }

    if is_base64_decode(&combined_added) {
        flagged_base64_exec = true;
        findings.push(Finding {
            rule_id: "R03_BASE64_DECODE".into(),
            severity: VerdictBand::Medium,
            title: format!("Base64 decoding in `{path}`"),
            description: format!("Diff introduced base64 decode calls in `{path}`."),
        });
    }

    for line in &added_lines {
        if !flagged_eval && is_eval_invocation(line) {
            flagged_eval = true;
            findings.push(Finding {
                rule_id: "R03_EVAL_USAGE".into(),
                severity: VerdictBand::High,
                title: format!("Dynamic code evaluation in `{path}`"),
                description: format!("Diff introduced `eval()` or `new Function()` in `{path}`."),
            });
        }

        if !flagged_child_proc && is_child_proc_invocation(line) {
            flagged_child_proc = true;
            findings.push(Finding {
                rule_id: "R03_CHILD_PROCESS".into(),
                severity: VerdictBand::High,
                title: format!("Process execution primitive in `{path}`"),
                description: format!("Diff introduced child_process execution calls in `{path}`."),
            });
        }

        if !flagged_base64_exec && is_base64_decode(line) {
            flagged_base64_exec = true;
            findings.push(Finding {
                rule_id: "R03_BASE64_DECODE".into(),
                severity: VerdictBand::Medium,
                title: format!("Base64 decoding in `{path}`"),
                description: format!("Diff introduced base64 decode calls in `{path}`."),
            });
        }

        if !flagged_high_entropy && is_suspicious_high_entropy(line) {
            flagged_high_entropy = true;
            findings.push(Finding {
                rule_id: "R03_HIGH_ENTROPY".into(),
                severity: VerdictBand::High,
                title: format!("High-entropy obfuscated token in `{path}`"),
                description: format!(
                    "Diff introduced high-entropy obfuscated string/payload in `{path}`."
                ),
            });
        }
    }
}

fn unescape_js(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('x') => {
                    chars.next();
                    let mut hex = String::new();
                    for _ in 0..2 {
                        if let Some(&h) = chars.peek()
                            && h.is_ascii_hexdigit()
                        {
                            hex.push(chars.next().unwrap());
                        }
                    }
                    if hex.len() == 2
                        && let Ok(val) = u8::from_str_radix(&hex, 16)
                    {
                        out.push(val as char);
                    } else {
                        out.push('\\');
                        out.push('x');
                        out.push_str(&hex);
                    }
                }
                Some('u') => {
                    chars.next();
                    if chars.peek() == Some(&'{') {
                        chars.next();
                        let mut hex = String::new();
                        while let Some(&h) = chars.peek() {
                            if h == '}' {
                                chars.next();
                                break;
                            }
                            if h.is_ascii_hexdigit() {
                                hex.push(chars.next().unwrap());
                            } else {
                                break;
                            }
                        }
                        if let Ok(code) = u32::from_str_radix(&hex, 16)
                            && let Some(ch) = char::from_u32(code)
                        {
                            out.push(ch);
                        } else {
                            out.push('\\');
                            out.push('u');
                            out.push('{');
                            out.push_str(&hex);
                            out.push('}');
                        }
                    } else {
                        let mut hex = String::new();
                        for _ in 0..4 {
                            if let Some(&h) = chars.peek()
                                && h.is_ascii_hexdigit()
                            {
                                hex.push(chars.next().unwrap());
                            }
                        }
                        if hex.len() == 4
                            && let Ok(code) = u32::from_str_radix(&hex, 16)
                            && let Some(ch) = char::from_u32(code)
                        {
                            out.push(ch);
                        } else {
                            out.push('\\');
                            out.push('u');
                            out.push_str(&hex);
                        }
                    }
                }
                Some(&d) if ('0'..='7').contains(&d) => {
                    // Octal escape sequence (e.g. \145 \166 \141 \154)
                    let mut oct = String::new();
                    oct.push(chars.next().unwrap());
                    for _ in 0..2 {
                        if let Some(&o) = chars.peek()
                            && ('0'..='7').contains(&o)
                        {
                            oct.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }
                    if let Ok(val) = u8::from_str_radix(&oct, 8) {
                        out.push(val as char);
                    } else {
                        out.push('\\');
                        out.push_str(&oct);
                    }
                }
                _ => {
                    out.push(c);
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn strip_comments_and_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' {
            if let Some(&'*') = chars.peek() {
                chars.next();
                while let Some(ch) = chars.next() {
                    if ch == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        break;
                    }
                }
                continue;
            } else if let Some(&'/') = chars.peek() {
                chars.next();
                for ch in chars.by_ref() {
                    if ch == '\n' {
                        break;
                    }
                }
                continue;
            }
        }
        if !c.is_whitespace() {
            out.push(c);
        }
    }
    out
}

fn is_eval_invocation(s: &str) -> bool {
    let unescaped = unescape_js(s);
    let s_clean = strip_comments_and_whitespace(&unescaped);
    s_clean.contains("eval(")
        || s_clean.contains("eval`")
        || s_clean.contains("newFunction(")
        || s_clean.contains("newFunction`")
        || s_clean.contains("Function(")
        || s_clean.contains("Function`")
        || s_clean.contains("globalThis.eval")
        || s_clean.contains("window.eval")
        || s_clean.contains("global.eval")
        || s_clean.contains("globalThis[\"eval\"]")
        || s_clean.contains("globalThis['eval']")
        || s_clean.contains("globalThis[`eval`]")
        || s_clean.contains("window[\"eval\"]")
        || s_clean.contains("window['eval']")
        || s_clean.contains("window[`eval`]")
        || s_clean.contains("global[\"eval\"]")
        || s_clean.contains("global['eval']")
        || s_clean.contains("global[`eval`]")
        || s_clean.contains("this[\"eval\"]")
        || s_clean.contains("this['eval']")
        || s_clean.contains("this[`eval`]")
}

fn is_child_proc_invocation(s: &str) -> bool {
    let unescaped = unescape_js(s);
    let s_clean = strip_comments_and_whitespace(&unescaped);
    s_clean.contains("child_process")
        || s_clean.contains("execSync(")
        || s_clean.contains("spawnSync(")
        || s_clean.contains("execFileSync(")
        || s_clean.contains(".exec(")
        || s_clean.contains(".execSync(")
        || s_clean.contains(".execFile(")
        || s_clean.contains(".execFileSync(")
        || s_clean.contains(".spawn(")
        || s_clean.contains(".spawnSync(")
        || s_clean.contains(".fork(")
        || s_clean.contains("[\"exec\"](")
        || s_clean.contains("['exec'](")
        || s_clean.contains("[\"execSync\"](")
        || s_clean.contains("['execSync'](")
        || s_clean.contains("[\"spawn\"](")
        || s_clean.contains("['spawn'](")
        || s_clean.contains("[\"spawnSync\"](")
        || s_clean.contains("['spawnSync'](")
        || s_clean.contains("[\"execFile\"](")
        || s_clean.contains("['execFile'](")
        || s_clean.contains("[\"execFileSync\"](")
        || s_clean.contains("['execFileSync'](")
        || s_clean.contains("[\"fork\"](")
        || s_clean.contains("['fork'](")
        || s_clean.contains("process.binding('spawn_sync')")
        || s_clean.contains("process.binding(\"spawn_sync\")")
        || s_clean.contains("process._linkedBinding")
}

fn is_base64_decode(s: &str) -> bool {
    let unescaped = unescape_js(s);
    let s_clean = strip_comments_and_whitespace(&unescaped).to_ascii_lowercase();
    (s_clean.contains("buffer.from(")
        && (s_clean.contains("'base64'")
            || s_clean.contains("\"base64\"")
            || s_clean.contains("`base64`")
            || s_clean.contains("'base64url'")
            || s_clean.contains("\"base64url\"")
            || s_clean.contains("`base64url`")))
        || s_clean.contains("atob(")
        || s_clean.contains("btoa(")
}

fn is_suspicious_high_entropy(line: &str) -> bool {
    // Only check long tokens (> 64 chars) without whitespace
    for token in line.split_whitespace() {
        if token.len() >= 64 {
            let entropy = shannon_entropy(token);
            if entropy > 5.5 {
                return true;
            }
        }
    }
    false
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / total_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::FileChange;

    #[test]
    fn blocks_on_lifecycle_scripts() {
        let delta = Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.0.1".into(),
            files_added: vec![],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 5,
            total_lines_deleted: 0,
            new_executables: vec![],
            new_binaries: vec![],
            new_lifecycle_scripts: vec!["postinstall".into()],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, false);
        assert_eq!(verdict.band, VerdictBand::Block);
        assert!(verdict.risk_score >= 50);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R01_LIFECYCLE_SCRIPT_ADDED")
        );
    }

    #[test]
    fn flags_suspicious_eval_and_binaries() {
        let delta = Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.1.0".into(),
            files_added: vec![FileChange {
                relative_path: "index.js".into(),
                kind: FileKind::Text,
                lines_added: 2,
                lines_deleted: 0,
                is_executable: false,
                unified_diff: Some("+const x = eval(payload);\n".into()),
            }],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 2,
            total_lines_deleted: 0,
            new_executables: vec!["payload.node".into()],
            new_binaries: vec!["payload.node".into()],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, false);
        assert_eq!(verdict.band, VerdictBand::High);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R03_EVAL_USAGE")
        );
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R02_EXECUTABLE_ADDED")
        );
    }

    #[test]
    fn flags_opaque_large_file_added() {
        let delta = Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.0.1".into(),
            files_added: vec![FileChange {
                relative_path: "large.bin".into(),
                kind: FileKind::OpaqueTooLarge,
                lines_added: 0,
                lines_deleted: 0,
                is_executable: false,
                unified_diff: None,
            }],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 0,
            total_lines_deleted: 0,
            new_executables: vec![],
            new_binaries: vec!["large.bin".into()],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, false);
        assert_eq!(verdict.band, VerdictBand::High);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R02_OPAQUE_LARGE_FILE_ADDED")
        );
    }

    #[test]
    fn blocks_on_binding_gyp_addition() {
        let delta = Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.0.1".into(),
            files_added: vec![FileChange {
                relative_path: "binding.gyp".into(),
                kind: FileKind::Text,
                lines_added: 5,
                lines_deleted: 0,
                is_executable: false,
                unified_diff: None,
            }],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 5,
            total_lines_deleted: 0,
            new_executables: vec![],
            new_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: true,
        };

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, false);
        assert_eq!(verdict.band, VerdictBand::Block);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R01_BINDING_GYP_ADDED")
        );
    }

    #[test]
    fn detects_obfuscated_eval_and_multiline() {
        assert!(is_eval_invocation(r#"\x65val(payload)"#));
        assert!(is_eval_invocation(r#"\u0065val(payload)"#));
        assert!(is_eval_invocation("eval\n(payload)"));
        assert!(is_eval_invocation("window['\\x65val'](x)"));
    }

    #[test]
    fn detects_child_proc_variants() {
        assert!(is_child_proc_invocation("execSync('whoami')"));
        assert!(is_child_proc_invocation("spawnSync('ls')"));
        assert!(is_child_proc_invocation("execFileSync('sh')"));
        assert!(is_child_proc_invocation("child_process\n.execSync(cmd)"));
    }

    #[test]
    fn detects_non_semver_urls_in_dependencies() {
        let delta = Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.0.1".into(),
            files_added: vec![],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 0,
            total_lines_deleted: 0,
            new_executables: vec![],
            new_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![("malicious-pkg".into(), "ssh://git@host/repo".into())],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, false);
        assert_eq!(verdict.band, VerdictBand::High);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R04_DEPENDENCY_ADDED" && f.severity == VerdictBand::High)
        );
    }

    #[test]
    fn first_sighting_elevated_to_medium() {
        let delta = Delta {
            baseline_version: None,
            target_version: "1.0.0".into(),
            files_added: vec![FileChange {
                relative_path: "index.js".into(),
                kind: FileKind::Text,
                lines_added: 1,
                lines_deleted: 0,
                is_executable: false,
                unified_diff: None,
            }],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 1,
            total_lines_deleted: 0,
            new_executables: vec![],
            new_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, false);
        assert_eq!(verdict.band, VerdictBand::Medium);
        assert_eq!(verdict.risk_score, 15);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R06_FIRST_SIGHTING" && f.severity == VerdictBand::Medium)
        );
    }

    #[test]
    fn flags_unreviewed_predecessor_baseline() {
        let delta = Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.0.1".into(),
            files_added: vec![],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 0,
            total_lines_deleted: 0,
            new_executables: vec![],
            new_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, true);
        assert_eq!(verdict.band, VerdictBand::Medium);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R07_UNREVIEWED_PREDECESSOR_BASELINE")
        );
    }

    #[test]
    fn detects_octal_and_comment_obfuscations() {
        assert!(is_eval_invocation(r#"\145\166\141\154(payload)"#));
        assert!(is_eval_invocation("eval/*comment*/(payload)"));
        assert!(is_eval_invocation("new/**/Function(payload)"));
        assert!(is_eval_invocation("eval`payload`"));
        assert!(is_eval_invocation("Function('return this')()"));
    }

    #[test]
    fn detects_base64_variants_and_child_proc_bindings() {
        assert!(is_base64_decode("Buffer.from(x, 'base64url')"));
        assert!(is_base64_decode("Buffer.from(x, \"BASE64\")"));
        assert!(is_child_proc_invocation("process.binding('spawn_sync')"));
        assert!(is_child_proc_invocation(
            "process._linkedBinding('spawn_sync')"
        ));
    }

    #[test]
    fn escalates_to_block_on_high_accumulated_score() {
        let delta = Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.1.0".into(),
            files_added: vec![
                FileChange {
                    relative_path: "p1.exe".into(),
                    kind: FileKind::Binary,
                    lines_added: 0,
                    lines_deleted: 0,
                    is_executable: true,
                    unified_diff: None,
                },
                FileChange {
                    relative_path: "p2.exe".into(),
                    kind: FileKind::Binary,
                    lines_added: 0,
                    lines_deleted: 0,
                    is_executable: true,
                    unified_diff: None,
                },
                FileChange {
                    relative_path: "p3.exe".into(),
                    kind: FileKind::Binary,
                    lines_added: 0,
                    lines_deleted: 0,
                    is_executable: true,
                    unified_diff: None,
                },
                FileChange {
                    relative_path: "p4.exe".into(),
                    kind: FileKind::Binary,
                    lines_added: 0,
                    lines_deleted: 0,
                    is_executable: true,
                    unified_diff: None,
                },
            ],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 0,
            total_lines_deleted: 0,
            new_executables: vec![
                "p1.exe".into(),
                "p2.exe".into(),
                "p3.exe".into(),
                "p4.exe".into(),
            ],
            new_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, false);
        assert_eq!(verdict.risk_score, 100);
        assert_eq!(verdict.band, VerdictBand::Block);
    }
}
