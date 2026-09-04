use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::policy::Policy;
use crate::registry::Ecosystem;
use crate::review::{evaluate_package, parse_spec};
use crate::store::BaselineStore;

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<serde_json::Value>,
    method: String,
    params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

impl JsonRpcError {
    fn parse_error(msg: impl std::fmt::Display) -> Self {
        Self {
            code: -32700,
            message: msg.to_string(),
            data: None,
        }
    }

    fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Method not found: {method}"),
            data: None,
        }
    }

    fn invalid_params(msg: impl std::fmt::Display) -> Self {
        Self {
            code: -32602,
            message: msg.to_string(),
            data: None,
        }
    }

    fn internal_error(msg: impl std::fmt::Display) -> Self {
        Self {
            code: -32603,
            message: msg.to_string(),
            data: None,
        }
    }
}

pub fn run_stdio(
    bases: &crate::cli::RegistryBases,
    policy_path: Option<&Path>,
) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();

    let policy = Policy::load_or_default(policy_path)?;
    let store = BaselineStore::open()?;

    eprintln!("blueline-mcp: starting stdio server loop (ready for JSON-RPC 2.0)");

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("blueline-mcp: error reading stdin: {e}");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(e) => {
                let err_resp = JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: serde_json::Value::Null,
                    result: None,
                    error: Some(JsonRpcError::parse_error(format!("Parse error: {e}"))),
                };
                let resp_str = serde_json::to_string(&err_resp)?;
                writeln!(stdout, "{resp_str}")?;
                stdout.flush()?;
                continue;
            }
        };

        // Notifications don't require responses
        if request.id.is_none() {
            continue;
        }

        let id = request.id.unwrap_or(serde_json::Value::Null);
        let resp = match handle_request(&request.method, request.params, bases, &store, &policy) {
            Ok(result) => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(result),
                error: None,
            },
            Err(err) => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(err),
            },
        };

        let resp_str = serde_json::to_string(&resp)?;
        writeln!(stdout, "{resp_str}")?;
        stdout.flush()?;
    }

    eprintln!("blueline-mcp: shutting down stdio server loop");
    Ok(())
}

fn handle_request(
    method: &str,
    params: Option<serde_json::Value>,
    bases: &crate::cli::RegistryBases,
    store: &BaselineStore,
    policy: &Policy,
) -> Result<serde_json::Value, JsonRpcError> {
    match method {
        "ping" => Ok(json!({})),

        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "blueline",
                "version": env!("CARGO_PKG_VERSION")
            }
        })),

        "tools/list" => Ok(json!({
            "tools": [
                {
                    "name": "review_install",
                    "description": "Reviews a package release before installation. Performs sandboxed extraction, dual-release diffing, heuristic risk scoring, OSV advisory lookup, and (npm) Sigstore provenance verification.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "package": {
                                "type": "string",
                                "description": "Package specification in the format '<name>@<version>' (e.g. 'lodash@4.17.21')"
                            },
                            "ecosystem": {
                                "type": "string",
                                "enum": ["npm", "cargo", "pypi", "aur"],
                                "default": "npm",
                                "description": "Package ecosystem. npm reviews use dist-tags/semver; cargo reviews use the crates.io sparse index and refuse installs."
                            }
                        },
                        "required": ["package"]
                    }
                },
                {
                    "name": "check_known_clean",
                    "description": "Checks if a specific package version has been previously reviewed and approved as clean in the local baseline store.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "Package name (e.g. 'lodash')"
                            },
                            "version": {
                                "type": "string",
                                "description": "Package version (e.g. '4.17.21')"
                            },
                            "ecosystem": {
                                "type": "string",
                                "enum": ["npm", "cargo", "pypi", "aur"],
                                "default": "npm",
                                "description": "Package ecosystem to scope the baseline lookup."
                            }
                        },
                        "required": ["name", "version"]
                    }
                },
                {
                    "name": "inspect_diff",
                    "description": "Returns the text diff and file lists for a package against its baseline release.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "package": {
                                "type": "string",
                                "description": "Package specification '<name>@<version>'"
                            },
                            "ecosystem": {
                                "type": "string",
                                "enum": ["npm", "cargo", "pypi", "aur"],
                                "default": "npm",
                                "description": "Package ecosystem to review against."
                            }
                        },
                        "required": ["package"]
                    }
                }
            ]
        })),

        "tools/call" => {
            let params = params
                .ok_or_else(|| JsonRpcError::invalid_params("missing params in tools/call"))?;
            let tool_name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing tool name in tools/call"))?;
            let args = params.get("arguments").cloned().unwrap_or(json!({}));

            execute_tool(tool_name, &args, bases, store, policy)
        }

        other => Err(JsonRpcError::method_not_found(other)),
    }
}

/// Optional `ecosystem` tool argument. Defaults to npm; unknown values fail
/// with invalid-params instead of being silently coerced.
fn parse_ecosystem(args: &serde_json::Value) -> Result<Ecosystem, JsonRpcError> {
    match args.get("ecosystem") {
        None | Some(serde_json::Value::Null) => Ok(Ecosystem::Npm),
        Some(v) => {
            let s = v
                .as_str()
                .ok_or_else(|| JsonRpcError::invalid_params("`ecosystem` must be a string"))?;
            match s {
                "npm" => Ok(Ecosystem::Npm),
                "cargo" => Ok(Ecosystem::Cargo),
                "pypi" => Ok(Ecosystem::PyPi),
                "aur" => Ok(Ecosystem::Aur),
                other => Err(JsonRpcError::invalid_params(format!(
                    "unknown ecosystem `{other}`; expected npm, cargo, pypi, or aur"
                ))),
            }
        }
    }
}

fn execute_tool(
    name: &str,
    args: &serde_json::Value,
    bases: &crate::cli::RegistryBases,
    store: &BaselineStore,
    policy: &Policy,
) -> Result<serde_json::Value, JsonRpcError> {
    let ecosystem = parse_ecosystem(args)?;
    let base = bases.for_ecosystem(ecosystem);

    match name {
        "review_install" => {
            let pkg_spec = args
                .get("package")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing `package` argument"))?;

            let (pkg_name, version) = parse_spec(pkg_spec).map_err(|e| {
                JsonRpcError::invalid_params(format!("invalid package spec `{pkg_spec}`: {e}"))
            })?;

            let (verdict, _delta, _, _) = evaluate_package(
                &pkg_name, &version, ecosystem, base, store, policy,
            )
            .map_err(|e| {
                JsonRpcError::internal_error(format!("review error for `{pkg_spec}`: {e:#}"))
            })?;

            let recommendation = match verdict.band {
                crate::verdict::VerdictBand::Low => "APPROVE — Safe to install",
                crate::verdict::VerdictBand::Medium => {
                    "HOLD — Review recommended before installation"
                }
                crate::verdict::VerdictBand::High => "HOLD / CAUTION — High risk delta detected",
                crate::verdict::VerdictBand::Block => "BLOCK — Security policy violation detected",
            };

            let name = crate::render::sanitize_single_line(&verdict.name);
            let ver = crate::render::sanitize_single_line(&verdict.target_version);
            let mut text = format!(
                "## Blueline Review: {name}@{ver}\n\n**Verdict:** `{}` (Score: {}/100)\n**Recommendation:** {recommendation}\n\n",
                verdict.band, verdict.risk_score
            );

            if verdict.findings.is_empty() {
                text.push_str("✅ No suspicious heuristics or advisories triggered.\n");
            } else {
                text.push_str("### Findings:\n");
                for f in &verdict.findings {
                    let title = crate::render::sanitize_single_line(&f.title);
                    let desc = crate::render::sanitize_terminal(&f.description);
                    text.push_str(&format!("- **[{}]** {title}: {desc}\n", f.rule_id));
                }
            }

            Ok(json!({
                "content": [{ "type": "text", "text": text }],
                "isError": false,
                "structuredVerdict": verdict
            }))
        }

        "check_known_clean" => {
            let pkg_name = args
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing `name` argument"))?;
            let version = args
                .get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing `version` argument"))?;

            use crate::version::{AurVersionInfo, Pep440Version, VersionInfo};
            let (is_clean, clean_version_strings): (bool, Vec<String>) = match ecosystem {
                Ecosystem::Npm | Ecosystem::Cargo => {
                    let rows = store
                        .list_clean_versions::<semver::Version>(ecosystem, pkg_name)
                        .map_err(|e| JsonRpcError::internal_error(e.to_string()))?;
                    let strs: Vec<String> = rows.iter().map(|(v, _)| v.canonical()).collect();
                    let input = semver::Version::parse(version)
                        .map(|v| v.canonical())
                        .unwrap_or_else(|_| version.to_string());
                    (strs.iter().any(|s| s == &input), strs)
                }
                Ecosystem::PyPi => {
                    let rows = store
                        .list_clean_versions::<Pep440Version>(ecosystem, pkg_name)
                        .map_err(|e| JsonRpcError::internal_error(e.to_string()))?;
                    let strs: Vec<String> = rows.iter().map(|(v, _)| v.canonical()).collect();
                    let input = Pep440Version::parse(version)
                        .map(|v| v.canonical())
                        .unwrap_or_else(|_| version.to_string());
                    (strs.iter().any(|s| s == &input), strs)
                }
                Ecosystem::Aur => {
                    let rows = store
                        .list_clean_versions::<AurVersionInfo>(ecosystem, pkg_name)
                        .map_err(|e| JsonRpcError::internal_error(e.to_string()))?;
                    let strs: Vec<String> = rows.iter().map(|(v, _)| v.canonical()).collect();
                    let input = AurVersionInfo::parse(version)
                        .map(|v| v.canonical())
                        .unwrap_or_else(|_| version.to_string());
                    (strs.iter().any(|s| s == &input), strs)
                }
            };

            let name = crate::render::sanitize_single_line(pkg_name);
            let ver = crate::render::sanitize_single_line(version);
            let status = if is_clean {
                "KNOWN CLEAN (approved in local store)"
            } else {
                "NOT recorded as clean"
            };

            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!("Package {name}@{ver} is {status}.")
                }],
                "isClean": is_clean,
                "cleanVersions": clean_version_strings
            }))
        }

        "inspect_diff" => {
            let pkg_spec = args
                .get("package")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing `package` argument"))?;

            let (pkg_name, version) = parse_spec(pkg_spec).map_err(|e| {
                JsonRpcError::invalid_params(format!("invalid package spec `{pkg_spec}`: {e}"))
            })?;

            let (_verdict, delta, _, _) = evaluate_package(
                &pkg_name, &version, ecosystem, base, store, policy,
            )
            .map_err(|e| {
                JsonRpcError::internal_error(format!("review error for `{pkg_spec}`: {e:#}"))
            })?;

            let name = crate::render::sanitize_single_line(&pkg_name);
            let ver = crate::render::sanitize_single_line(&version);
            let mut diff_text = format!(
                "Diff summary for {name}@{ver}:\nFiles added: {}, removed: {}, modified: {}\n\n",
                delta.files_added.len(),
                delta.files_removed.len(),
                delta.files_modified.len()
            );

            for f in delta.files_added.iter().chain(delta.files_modified.iter()) {
                if let Some(unified) = &f.unified_diff {
                    let path = crate::render::sanitize_single_line(&f.relative_path);
                    let diff = crate::render::sanitize_terminal(unified);
                    diff_text.push_str(&format!("--- {path}\n{diff}\n"));
                }
            }

            Ok(json!({
                "content": [{ "type": "text", "text": diff_text }]
            }))
        }

        unknown => Err(JsonRpcError::invalid_params(format!(
            "unknown tool: {unknown}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::RegistryBases;

    fn test_bases() -> RegistryBases {
        RegistryBases {
            npm: "https://registry.npmjs.org".into(),
            cargo: "https://index.crates.io".into(),
            pypi: "https://pypi.org".into(),
            aur: "https://aur.archlinux.org".into(),
        }
    }

    #[test]
    fn handles_ping_request() {
        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        let resp = handle_request("ping", None, &test_bases(), &store, &policy).unwrap();
        assert_eq!(resp, json!({}));
    }

    #[test]
    fn handles_initialize_request() {
        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        let resp = handle_request("initialize", None, &test_bases(), &store, &policy).unwrap();
        assert_eq!(resp.get("protocolVersion").unwrap(), "2024-11-05");
        assert!(resp.get("capabilities").is_some());
    }

    #[test]
    fn handles_tools_list() {
        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        let resp = handle_request("tools/list", None, &test_bases(), &store, &policy).unwrap();
        let tools = resp.get("tools").and_then(|t| t.as_array()).unwrap();
        assert_eq!(tools.len(), 3);
        assert!(
            tools
                .iter()
                .any(|t| t.get("name").unwrap() == "review_install")
        );
        assert!(
            tools
                .iter()
                .any(|t| t.get("name").unwrap() == "check_known_clean")
        );
        assert!(
            tools
                .iter()
                .any(|t| t.get("name").unwrap() == "inspect_diff")
        );
    }

    #[test]
    fn returns_method_not_found_for_unknown_method() {
        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        let err =
            handle_request("nonexistent_method", None, &test_bases(), &store, &policy).unwrap_err();
        assert_eq!(err.code, -32601);
        assert!(err.message.contains("Method not found"));
    }

    #[test]
    fn returns_invalid_params_for_missing_tool_call_args() {
        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        let err = handle_request(
            "tools/call",
            Some(json!({"name": "check_known_clean", "arguments": {}})),
            &test_bases(),
            &store,
            &policy,
        )
        .unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("missing `name` argument"));
    }

    #[test]
    fn rejects_unknown_ecosystem_param() {
        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        let err = handle_request(
            "tools/call",
            Some(json!({
                "name": "review_install",
                "arguments": {"package": "serde@1.0.210", "ecosystem": "rubygems"}
            })),
            &test_bases(),
            &store,
            &policy,
        )
        .unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("unknown ecosystem"));
        assert!(err.message.contains("expected npm, cargo, pypi, or aur"));
    }

    #[test]
    fn ecosystem_param_defaults_to_npm_and_accepts_cargo_routing() {
        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        let unreachable = RegistryBases {
            npm: "http://127.0.0.1:1".into(),
            cargo: "http://127.0.0.1:1".into(),
            pypi: "http://127.0.0.1:1".into(),
            aur: "http://127.0.0.1:1".into(),
        };

        // Default (no ecosystem) routes to the npm base; the request fails on
        // the network side, not with invalid params.
        let err = handle_request(
            "tools/call",
            Some(json!({"name": "review_install", "arguments": {"package": "x@1.0.0"}})),
            &unreachable,
            &store,
            &policy,
        )
        .unwrap_err();
        assert_eq!(err.code, -32603);

        let err = handle_request(
            "tools/call",
            Some(json!({
                "name": "inspect_diff",
                "arguments": {"package": "serde@1.0.210", "ecosystem": "cargo"}
            })),
            &unreachable,
            &store,
            &policy,
        )
        .unwrap_err();
        assert_eq!(err.code, -32603);

        // AUR is accepted and routed to the aur base: the failure is the
        // network side, not invalid params.
        let err = handle_request(
            "tools/call",
            Some(json!({
                "name": "inspect_diff",
                "arguments": {"package": "yay@12.4.2-1", "ecosystem": "aur"}
            })),
            &unreachable,
            &store,
            &policy,
        )
        .unwrap_err();
        assert_eq!(err.code, -32603);
        assert!(err.message.contains("review error for `yay@12.4.2-1`"));
    }

    #[test]
    fn jsonrpc_error_constructors_have_spec_codes() {
        assert_eq!(JsonRpcError::parse_error("bad json").code, -32700);
        assert_eq!(JsonRpcError::method_not_found("unknown").code, -32601);
        assert_eq!(JsonRpcError::invalid_params("bad param").code, -32602);
        assert_eq!(JsonRpcError::internal_error("fail").code, -32603);
    }
}
