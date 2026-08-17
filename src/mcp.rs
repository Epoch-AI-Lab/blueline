use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::policy::Policy;
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

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

pub fn run_stdio(registry_base: &str, policy_path: Option<&Path>) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();

    let policy = Policy::load_or_default(policy_path)?;
    let store =
        BaselineStore::open().map_err(|e| anyhow::anyhow!("opening baseline store: {e}"))?;

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
                    error: Some(JsonRpcError {
                        code: -32700, // Parse error
                        message: format!("Parse error: {e}"),
                        data: None,
                    }),
                };
                let resp_str = serde_json::to_string(&err_resp)?;
                writeln!(stdout, "{resp_str}")?;
                stdout.flush()?;
                continue;
            }
        };

        // Notifications don't require responses
        if request.id.is_none() {
            if request.method == "notifications/initialized" {
                eprintln!("blueline-mcp: client initialized notification received");
            }
            continue;
        }

        let id = request.id.unwrap_or(serde_json::Value::Null);
        let resp = match handle_request(
            &request.method,
            request.params,
            registry_base,
            &store,
            &policy,
        ) {
            Ok(result) => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(result),
                error: None,
            },
            Err(err_msg) => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32603, // Internal error
                    message: err_msg,
                    data: None,
                }),
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
    registry_base: &str,
    store: &BaselineStore,
    policy: &Policy,
) -> Result<serde_json::Value, String> {
    match method {
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
                    "description": "Reviews an npm package release before installation. Performs sandboxed extraction, dual-release diffing, heuristic risk scoring, OSV advisory lookup, and Sigstore provenance verification.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "package": {
                                "type": "string",
                                "description": "Package specification in the format '<name>@<version>' (e.g. 'lodash@4.17.21')"
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
                            }
                        },
                        "required": ["package"]
                    }
                }
            ]
        })),

        "tools/call" => {
            let params = params.ok_or_else(|| "missing params in tools/call".to_string())?;
            let tool_name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing tool name in tools/call".to_string())?;
            let args = params.get("arguments").cloned().unwrap_or(json!({}));

            execute_tool(tool_name, &args, registry_base, store, policy)
        }

        other => Err(format!("unsupported method: {other}")),
    }
}

fn execute_tool(
    name: &str,
    args: &serde_json::Value,
    registry_base: &str,
    store: &BaselineStore,
    policy: &Policy,
) -> Result<serde_json::Value, String> {
    match name {
        "review_install" => {
            let pkg_spec = args
                .get("package")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing `package` argument".to_string())?;

            let (pkg_name, version) = parse_spec(pkg_spec)
                .map_err(|e| format!("invalid package spec `{pkg_spec}`: {e}"))?;

            let (verdict, _delta, _) =
                evaluate_package(&pkg_name, &version, registry_base, store, policy)
                    .map_err(|e| format!("review error for `{pkg_spec}`: {e:#}"))?;

            let recommendation = match verdict.band {
                crate::verdict::VerdictBand::Low => "APPROVE — Safe to install",
                crate::verdict::VerdictBand::Medium => {
                    "HOLD — Review recommended before installation"
                }
                crate::verdict::VerdictBand::High => "HOLD / CAUTION — High risk delta detected",
                crate::verdict::VerdictBand::Block => "BLOCK — Security policy violation detected",
            };

            let mut text = format!(
                "## Blueline Review: {}@{}\n\n**Verdict:** `{}` (Score: {}/100)\n**Recommendation:** {}\n\n",
                verdict.name,
                verdict.target_version,
                verdict.band,
                verdict.risk_score,
                recommendation
            );

            if !verdict.findings.is_empty() {
                text.push_str("### Findings:\n");
                for f in &verdict.findings {
                    text.push_str(&format!(
                        "- **[{}]** {}: {}\n",
                        f.rule_id, f.title, f.description
                    ));
                }
            } else {
                text.push_str("✅ No suspicious heuristics or advisories triggered.\n");
            }

            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": text
                    }
                ],
                "isError": false,
                "structuredVerdict": verdict
            }))
        }

        "check_known_clean" => {
            let pkg_name = args
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing `name` argument".to_string())?;
            let version = args
                .get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing `version` argument".to_string())?;

            let clean_versions = store
                .list_clean_versions(pkg_name)
                .map_err(|e| format!("baseline store error: {e}"))?;

            let is_clean = clean_versions.iter().any(|(v, _)| v.to_string() == version);
            let clean_version_strings: Vec<String> =
                clean_versions.iter().map(|(v, _)| v.to_string()).collect();

            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": format!(
                            "Package {}@{} is {}.",
                            pkg_name,
                            version,
                            if is_clean { "KNOWN CLEAN (approved in local store)" } else { "NOT recorded as clean" }
                        )
                    }
                ],
                "isClean": is_clean,
                "cleanVersions": clean_version_strings
            }))
        }

        "inspect_diff" => {
            let pkg_spec = args
                .get("package")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing `package` argument".to_string())?;

            let (pkg_name, version) = parse_spec(pkg_spec)
                .map_err(|e| format!("invalid package spec `{pkg_spec}`: {e}"))?;

            let (_verdict, delta, _) =
                evaluate_package(&pkg_name, &version, registry_base, store, policy)
                    .map_err(|e| format!("review error for `{pkg_spec}`: {e:#}"))?;

            let mut diff_text = format!("Diff summary for {}@{}:\n", pkg_name, version);
            diff_text.push_str(&format!(
                "Files added: {}, removed: {}, modified: {}\n\n",
                delta.files_added.len(),
                delta.files_removed.len(),
                delta.files_modified.len()
            ));

            for f in delta.files_added.iter().chain(delta.files_modified.iter()) {
                if let Some(unified) = &f.unified_diff {
                    diff_text.push_str(&format!("--- {}\n{}\n", f.relative_path, unified));
                }
            }

            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": diff_text
                    }
                ]
            }))
        }

        unknown => Err(format!("unknown tool: {unknown}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_initialize_request() {
        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        let resp = handle_request(
            "initialize",
            None,
            "https://registry.npmjs.org",
            &store,
            &policy,
        )
        .unwrap();
        assert_eq!(resp.get("protocolVersion").unwrap(), "2024-11-05");
        assert!(resp.get("capabilities").is_some());
    }

    #[test]
    fn handles_tools_list() {
        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        let resp = handle_request(
            "tools/list",
            None,
            "https://registry.npmjs.org",
            &store,
            &policy,
        )
        .unwrap();
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
}
