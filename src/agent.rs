//! Agent-native enforcement: non-interactive, policy-bound review for
//! autonomous agents. `agent review` never prompts — the verdict band
//! decides, the machine-readable verdict goes to stdout, and exit codes
//! branch for CI and hooks. `agent gate` is the hook binding: it polices a
//! command line with the same install-reference scanner the review engine
//! uses and answers in the invoking product's native decision shape.

use std::io::Read;

use crate::cli::RegistryBases;
use crate::install_ref::{self};
use crate::policy::Policy;
use crate::recursive::{ReviewContext, child_ecosystem};
use crate::registry::Ecosystem;
use crate::store::BaselineStore;
use crate::verdict::VerdictBand;

/// Bounded hook stdin: hook payloads are small; anything larger is refused
/// rather than parsed.
const MAX_HOOK_STDIN_BYTES: usize = 64 * 1024;

/// The agent identity recorded in the audit trail: derived from the
/// process environment the agent sets, env NAMES only — values are never
/// stored (no telemetry beyond the local store).
pub fn detect_agent_identity(
    getenv: &dyn Fn(&str) -> Option<String>,
) -> (&'static str, Vec<&'static str>) {
    let claude = ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"];
    if claude.iter().any(|k| getenv(k).is_some()) {
        return ("claude-code", claude.to_vec());
    }
    let cursor = ["CURSOR_AGENT", "CURSOR_TRACE_ID"];
    if cursor.iter().any(|k| getenv(k).is_some()) {
        return ("cursor", cursor.to_vec());
    }
    let codex = ["CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED"];
    if codex.iter().any(|k| getenv(k).is_some()) {
        return ("codex", codex.to_vec());
    }
    ("unknown-agent", Vec::new())
}

fn identity_for_audit() -> String {
    format!(
        "agent:{}",
        detect_agent_identity(&|k| std::env::var(k).ok()).0
    )
}

/// Non-interactive review: JSON verdict on stdout, exit 0 when the policy
/// allows (Low), exit 2 otherwise. Never prompts, never marks anything
/// clean — an agent cannot bless baselines, only be told the verdict.
pub fn run(
    pkg_spec: &str,
    ecosystem: Ecosystem,
    bases: &RegistryBases,
    policy_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let policy = Policy::load_for_agent(policy_path)?;
    let _ = warn_on_ignored_env_policy(policy_path, &|k| std::env::var(k).ok());
    let registry = crate::review::ctxless_registry(ecosystem, bases)?;
    let (name, version) = crate::review::parse_spec_flexible(pkg_spec, registry.as_ref())?;
    let store = BaselineStore::open()?;

    let mut ctx = ReviewContext::new(&policy, bases.clone());
    let (verdict, _delta, _checksum, _) =
        crate::review::evaluate_package(&name, &version, ecosystem, &store, &policy, &mut ctx)?;

    println!("{}", serde_json::to_string(&verdict)?);

    let _ = store.record_audit_log(
        ecosystem,
        &verdict.name,
        &verdict.target_version,
        &verdict.integrity,
        "agent_review",
        verdict.risk_score,
        &verdict.band.to_string(),
        &identity_for_audit(),
        Some("agent mode; no interactive approval; known_clean untouched"),
    );

    if verdict.band == VerdictBand::Low {
        Ok(())
    } else {
        eprintln!(
            "agent: {}@{} verdict {} (score {}) exceeds the approval policy; exit 2",
            verdict.name, verdict.target_version, verdict.band, verdict.risk_score
        );
        std::process::exit(2);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum GateFormat {
    /// Exit codes only; verdict details on stderr.
    Plain,
    /// Claude Code PreToolUse structured decision.
    Claude,
    /// Cursor beforeShellExecution structured decision.
    Cursor,
}

struct GateDecision {
    allow: bool,
    reason: String,
}

/// The hook binding: police one command line. Every install reference the
/// command names is reviewed with the recursive engine; a reference whose
/// target cannot be resolved statically denies (fail closed); bare
/// installs (no operands) are allowed with a note that the manifest's
/// dependencies are policed by `blueline ci`.
pub fn gate(
    command: Option<&str>,
    format: GateFormat,
    bases: &RegistryBases,
    policy_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    // Fail closed: ANY internal error (unreadable policy, store failure,
    // oversized or undecodable hook stdin) is a DENY. Hook hosts treat
    // every non-2 non-zero exit as non-blocking, so an error exit would
    // let the command run ungated.
    let decision = (|| -> anyhow::Result<GateDecision> {
        let command = match command {
            Some(c) => c.to_string(),
            None => read_hook_command()?,
        };
        decide(&command, bases, policy_path)
    })()
    .unwrap_or_else(|e| GateDecision {
        allow: false,
        reason: format!("blueline gate failed closed: {e:#}"),
    });
    emit_decision(format, &decision)
}

fn read_hook_command() -> anyhow::Result<String> {
    read_hook_command_from(std::io::stdin())
}

fn hook_stdin_limit() -> u64 {
    MAX_HOOK_STDIN_BYTES as u64 + 1
}

fn hook_stdin_too_large(len: usize) -> bool {
    len > MAX_HOOK_STDIN_BYTES
}

fn read_hook_command_from<R: Read>(reader: R) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    reader
        .take(hook_stdin_limit())
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("reading hook stdin: {e}"))?;
    if hook_stdin_too_large(buf.len()) {
        anyhow::bail!("hook stdin exceeds {MAX_HOOK_STDIN_BYTES} bytes; refusing to parse");
    }
    let buf =
        String::from_utf8(buf).map_err(|e| anyhow::anyhow!("hook stdin is not UTF-8: {e}"))?;
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        anyhow::bail!("no --command given and hook stdin is empty");
    }
    // Claude Code PreToolUse: {"tool_input": {"command": ...}};
    // Cursor beforeShellExecution: {"command": ...}.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(c) = value.get("command").and_then(|v| v.as_str()) {
            return Ok(c.to_string());
        }
        if let Some(c) = value
            .get("tool_input")
            .and_then(|v| v.get("command"))
            .and_then(|v| v.as_str())
        {
            return Ok(c.to_string());
        }
        anyhow::bail!("hook stdin is JSON but carries no command field");
    }
    Ok(trimmed.to_string())
}

fn decide(
    command: &str,
    bases: &RegistryBases,
    policy_path: Option<&std::path::Path>,
) -> anyhow::Result<GateDecision> {
    let policy = Policy::load_for_agent(policy_path)?;
    let _ = warn_on_ignored_env_policy(policy_path, &|k| std::env::var(k).ok());
    // Shapes the token scanner cannot resolve are hard denials: pip flags
    // that name or redirect non-registry sources, inline registry-redirect
    // assignments (`PIP_INDEX_URL=...`, `NPM_CONFIG_*`, `CARGO_*`) and
    // `.npmrc` references, and manager tokens hidden behind quoting,
    // escapes, or command substitution.
    let mut reasons: Vec<String> = install_ref::gate_hard_denies(command)
        .into_iter()
        .map(|detail| format!("unreviewable invocation shape: {detail}"))
        .collect();
    // An exported redirect (`PIP_INDEX_URL`, `NPM_CONFIG_REGISTRY`,
    // `CARGO_*` in the gate's process environment) never appears in the
    // gated command line, so it cannot deny here — but it changes where
    // the install fetches from. Disclose it in the verdict reason and the
    // audit trail. Names only; values are never read or stored.
    let env_keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    let redirect_env = install_ref::redirect_env_present(env_keys.iter().map(String::as_str));
    let env_note = exported_redirect_note(&redirect_env);
    let refs = install_ref::scan_line(command);
    // A shape the scanner cannot resolve is decided on its own. Reviewing the
    // operands anyway would contact the registry, download tarballs, and write
    // evidence rows for a command already destined to be refused.
    if !reasons.is_empty() {
        let store = BaselineStore::open()?;
        let summary_detail = match &env_note {
            Some(note) => format!("command: {}; {note}", truncate_command(command)),
            None => format!("command: {}", truncate_command(command)),
        };
        let _ = store.record_audit_log(
            Ecosystem::Npm,
            "command",
            "gate",
            "",
            "agent_gate_summary",
            0,
            "HIGH",
            &identity_for_audit(),
            Some(&summary_detail),
        );
        return Ok(GateDecision {
            allow: false,
            reason: with_env_note(&deny_reason(&reasons), &env_note),
        });
    }
    if refs.is_empty() {
        return Ok(GateDecision {
            allow: true,
            reason: with_env_note(
                "no named package-manager install found in the command; the manifest's \
                 dependencies are policed by `blueline ci`",
                &env_note,
            ),
        });
    }
    let store = BaselineStore::open()?;
    let mut ctx = ReviewContext::new(&policy, bases.clone());
    for (manager, spec) in &refs {
        let label = format!("{} install of `{spec}`", manager.label());
        // An invocation whose target is dynamic or unreadable cannot be
        // reviewed — fail closed.
        if spec.is_empty() {
            reasons.push(format!("{label}: target is dynamic or unreadable"));
            continue;
        }
        let child_eco = child_ecosystem(*manager);
        let parsed = install_ref::raw_ref(install_ref::RefOrigin::CommandLine, *manager, spec);
        let Some((name, version)) = parsed.registry_spec() else {
            reasons.push(format!(
                "{label}: not a registry-installable spec; not reviewed"
            ));
            continue;
        };
        let version = match version {
            Some(v) => v.to_string(),
            None => match ctx.registry(child_eco).default_version(name) {
                Ok(Some(d)) => d,
                Ok(None) => {
                    reasons.push(format!("{label}: no versions found for `{name}`"));
                    continue;
                }
                Err(e) => {
                    reasons.push(format!("{label}: registry lookup failed: {e:#}"));
                    continue;
                }
            },
        };
        match crate::review::evaluate_scoped(name, &version, child_eco, &store, &policy, &mut ctx) {
            Ok((verdict, _, _, _)) => {
                let _ = store.record_audit_log(
                    child_eco,
                    &verdict.name,
                    &verdict.target_version,
                    &verdict.integrity,
                    "agent_gate",
                    verdict.risk_score,
                    &verdict.band.to_string(),
                    &identity_for_audit(),
                    Some(&format!("command: {}", truncate_command(command))),
                );
                if verdict.band != VerdictBand::Low {
                    reasons.push(format!(
                        "{label}: {name}@{version} verdict {} (score {})",
                        verdict.band, verdict.risk_score
                    ));
                }
            }
            Err(e) => reasons.push(format!("{label}: review failed: {e:#}")),
        }
    }
    let summary_detail = match &env_note {
        Some(note) => format!("command: {}; {note}", truncate_command(command)),
        None => format!("command: {}", truncate_command(command)),
    };
    let _ = store.record_audit_log(
        Ecosystem::Npm,
        "command",
        "gate",
        "",
        "agent_gate_summary",
        0,
        if reasons.is_empty() { "LOW" } else { "HIGH" },
        &identity_for_audit(),
        Some(&summary_detail),
    );
    if reasons.is_empty() {
        Ok(GateDecision {
            allow: true,
            reason: with_env_note("all named installs reviewed LOW", &env_note),
        })
    } else {
        Ok(GateDecision {
            allow: false,
            reason: with_env_note(&deny_reason(&reasons), &env_note),
        })
    }
}

/// Warning disclosed when redirect-capable variables are exported in the
/// gate's process environment. Names only — values are never inspected or
/// stored.
fn exported_redirect_note(names: &[String]) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    Some(format!(
        "warning: exported redirect environment present (names only): {}; \
         the install may fetch from elsewhere than the reviewed registry",
        names.join(", ")
    ))
}

fn with_env_note(reason: &str, env_note: &Option<String>) -> String {
    match env_note {
        Some(note) => format!("{reason}; {note}"),
        None => reason.to_string(),
    }
}

/// Ambient `BLUELINE_POLICY` is ignored by agent entry points unless an
/// explicit `--policy` flag names the file (see `Policy::load_for_agent`):
/// warn on stderr so a scoped shell that expected its policy notices, and
/// the audit trail keeps the decision it actually ran under.
fn warn_on_ignored_env_policy(
    policy_path: Option<&std::path::Path>,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> bool {
    if policy_path.is_none() && getenv("BLUELINE_POLICY").is_some() {
        eprintln!(
            "warning: ignoring BLUELINE_POLICY from the environment; \
             pass --policy to apply a policy file to agent review/gate"
        );
        return true;
    }
    false
}

fn deny_reason(reasons: &[String]) -> String {
    format!(
        "blueline refused the install: {}; bypass only by running the package \
         manager outside the gated tool",
        reasons.join("; ")
    )
}

fn truncate_command(command: &str) -> String {
    let line = crate::render::sanitize_single_line(command);
    let mut out: String = line.chars().take(200).collect();
    if out.len() < line.len() {
        out.push('…');
    }
    out
}

fn emit_decision(format: GateFormat, decision: &GateDecision) -> anyhow::Result<()> {
    let permission = if decision.allow { "allow" } else { "deny" };
    match format {
        GateFormat::Plain => {
            if !decision.allow {
                eprintln!("{}", decision.reason);
            }
        }
        GateFormat::Claude => {
            println!(
                "{}",
                serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": permission,
                        "permissionDecisionReason": decision.reason,
                    }
                })
            );
        }
        GateFormat::Cursor => {
            println!(
                "{}",
                serde_json::json!({
                    "permission": permission,
                    "user_message": decision.reason,
                })
            );
        }
    }
    if decision.allow {
        Ok(())
    } else {
        // Claude Code's documented contract: a policy hook must exit 2.
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of<'a>(map: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = map.iter().copied().collect();
        move |k: &str| map.get(k).map(|v| v.to_string())
    }

    #[test]
    fn identity_detection_pins_agent_envs() {
        let (id, _) = detect_agent_identity(&env_of(&[
            ("CLAUDECODE", "1"),
            ("CLAUDE_CODE_ENTRYPOINT", "cli"),
        ]));
        assert_eq!(id, "claude-code");
        let (id, _) = detect_agent_identity(&env_of(&[("CURSOR_AGENT", "1")]));
        assert_eq!(id, "cursor");
        let (id, _) = detect_agent_identity(&env_of(&[("CODEX_SANDBOX", "seatbelt")]));
        assert_eq!(id, "codex");
        let (id, _) = detect_agent_identity(&env_of(&[]));
        assert_eq!(id, "unknown-agent");
    }

    #[test]
    fn child_ecosystem_routes_every_manager_to_its_registry() {
        use crate::install_ref::RefManager;
        assert_eq!(child_ecosystem(RefManager::Npm), Ecosystem::Npm);
        assert_eq!(child_ecosystem(RefManager::Npx), Ecosystem::Npm);
        assert_eq!(child_ecosystem(RefManager::Pnpm), Ecosystem::Npm);
        assert_eq!(child_ecosystem(RefManager::Yarn), Ecosystem::Npm);
        assert_eq!(child_ecosystem(RefManager::Bun), Ecosystem::Npm);
        assert_eq!(child_ecosystem(RefManager::Bunx), Ecosystem::Npm);
        assert_eq!(child_ecosystem(RefManager::Pip), Ecosystem::PyPi);
        assert_eq!(child_ecosystem(RefManager::Cargo), Ecosystem::Cargo);
        assert_eq!(child_ecosystem(RefManager::Yay), Ecosystem::Aur);
        assert_eq!(child_ecosystem(RefManager::Paru), Ecosystem::Aur);
    }

    #[test]
    fn command_truncation_is_sanitized_and_bounded() {
        let long = format!("npm install {}\n\x1b[31mevil", "x".repeat(500));
        let out = truncate_command(&long);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\n'));
        assert!(out.chars().count() <= 201);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn exported_redirect_note_names_names_only() {
        assert!(exported_redirect_note(&[]).is_none());
        let note = exported_redirect_note(&[
            "NPM_CONFIG_REGISTRY".to_string(),
            "PIP_INDEX_URL".to_string(),
        ])
        .expect("names present must warn");
        assert!(note.contains("NPM_CONFIG_REGISTRY"));
        assert!(note.contains("PIP_INDEX_URL"));
        assert!(with_env_note("ok", &None) == "ok");
        assert!(with_env_note("ok", &Some("w".to_string())) == "ok; w");
    }

    #[test]
    fn hook_stdin_cap_is_exactly_64kib() {
        assert_eq!(MAX_HOOK_STDIN_BYTES, 65536);
        assert_eq!(MAX_HOOK_STDIN_BYTES, 64 * 1024);
        assert_eq!(hook_stdin_limit(), 65537);
    }

    #[test]
    fn audit_identity_carries_agent_prefix() {
        let identity = identity_for_audit();
        assert!(!identity.is_empty());
        assert!(identity.starts_with("agent:"));
        assert!(identity.len() > "agent:".len());
        assert_ne!(identity, "xyzzy");
    }

    #[test]
    fn hook_stdin_exact_max_is_accepted_whole() {
        let input = format!("echo {}", "a".repeat(MAX_HOOK_STDIN_BYTES - 5));
        assert!(input.len() <= MAX_HOOK_STDIN_BYTES);
        let out = read_hook_command_from(std::io::Cursor::new(input.clone()))
            .expect("exactly-MAX input must parse");
        assert_eq!(out, input);
        assert!(!hook_stdin_too_large(MAX_HOOK_STDIN_BYTES));
    }

    #[test]
    fn hook_stdin_max_plus_one_is_refused() {
        assert!(hook_stdin_too_large(MAX_HOOK_STDIN_BYTES + 1));
        let input = "b".repeat(MAX_HOOK_STDIN_BYTES + 1);
        let err = read_hook_command_from(std::io::Cursor::new(input))
            .expect_err("MAX+1 input must be refused");
        assert!(format!("{err:#}").contains("exceeds"));
        let oversized = "c".repeat(MAX_HOOK_STDIN_BYTES + 512);
        let err = read_hook_command_from(std::io::Cursor::new(oversized))
            .expect_err("oversized input must be refused");
        assert!(format!("{err:#}").contains(&MAX_HOOK_STDIN_BYTES.to_string()));
    }

    #[test]
    fn ignored_env_policy_warns_only_without_explicit_flag() {
        let present = &|_: &str| Some("/tmp/scoped-policy.toml".to_string());
        let absent: &dyn Fn(&str) -> Option<String> = &|_: &str| None;
        assert!(warn_on_ignored_env_policy(None, present));
        assert!(!warn_on_ignored_env_policy(
            Some(std::path::Path::new("/tmp/policy.toml")),
            present
        ));
        assert!(!warn_on_ignored_env_policy(None, absent));
    }

    #[test]
    fn ignored_env_policy_silent_when_flag_names_file() {
        let present = &|_: &str| Some("/tmp/scoped-policy.toml".to_string());
        let absent: &dyn Fn(&str) -> Option<String> = &|_: &str| None;
        assert!(!warn_on_ignored_env_policy(
            Some(std::path::Path::new("/tmp/policy.toml")),
            absent
        ));
        assert!(!warn_on_ignored_env_policy(None, absent));
        assert!(warn_on_ignored_env_policy(None, present));
    }

    #[test]
    fn command_truncation_boundary_is_exactly_200_chars() {
        let exact = "a".repeat(200);
        let out = truncate_command(&exact);
        assert_eq!(out, exact);
        assert!(!out.ends_with('…'));
        let over = "a".repeat(201);
        let out = truncate_command(&over);
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), 201);
        assert_eq!(out.len(), 200 + '…'.len_utf8());
    }
}
