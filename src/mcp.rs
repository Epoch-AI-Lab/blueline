const MAX_REQUEST_LINE_BYTES: usize = 64 * 1024;
const JSONRPC_VERSION: &str = "2.0";

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
    let mut reader = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();

    let policy = Policy::load_or_default(policy_path)?;
    let store = BaselineStore::open()?;

    eprintln!("blueline-mcp: starting stdio server loop (ready for JSON-RPC 2.0)");

    loop {
        let line = match next_request_line(&mut reader) {
            Ok(Some(l)) => l,
            // A clean end of stream is a normal shutdown.
            Ok(None) => break,
            // A stream error is fatal, unlike a decode error. Falling through
            // to a clean exit told the host the gate succeeded while an
            // in-flight request went unanswered.
            Err(e) => return Err(anyhow::anyhow!("reading MCP stdin: {e}")),
        };
        match line {
            RequestLine::Skip => continue,
            RequestLine::Oversize => {
                write_error(
                    &mut stdout,
                    &format!("request exceeds {MAX_REQUEST_LINE_BYTES} bytes; refusing"),
                )?;
                // Framing is newline-delimited, so an oversized line cannot be
                // resynchronised. A host must treat a dead blueline-mcp as a
                // denial; see the same reasoning in agent.rs.
                return Err(anyhow::anyhow!(
                    "MCP request exceeds {MAX_REQUEST_LINE_BYTES} bytes; refusing"
                ));
            }
            RequestLine::InvalidUtf8 => {
                // One bad request must not kill the server.
                write_error(&mut stdout, "request is not valid UTF-8")?;
                continue;
            }
            RequestLine::Text(t) => {
                serve_request_line(&t, &mut stdout, bases, &store, &policy)?;
            }
        }
    }

    eprintln!("blueline-mcp: shutting down stdio server loop");
    Ok(())
}

/// Answer one framed request line. A request this server refuses to act on
/// (unparseable, wrong `jsonrpc` member) draws the same error shape and does
/// not stop the loop: one bad request must not kill the server.
fn serve_request_line<W: Write>(
    line: &str,
    out: &mut W,
    bases: &crate::cli::RegistryBases,
    store: &BaselineStore,
    policy: &Policy,
) -> anyhow::Result<()> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
        Ok(req) => req,
        Err(e) => {
            let err_resp = JsonRpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id: serde_json::Value::Null,
                result: None,
                error: Some(JsonRpcError::parse_error(format!("Parse error: {e}"))),
            };
            let resp_str = serde_json::to_string(&err_resp)?;
            writeln!(out, "{resp_str}")?;
            out.flush()?;
            return Ok(());
        }
    };

    if let Err(err) = check_protocol_version(&request) {
        write_error(out, &err.message)?;
        return Ok(());
    }
    // Notifications don't require responses
    if request.id.is_none() {
        return Ok(());
    }

    let id = request.id.unwrap_or(serde_json::Value::Null);
    let resp = match handle_request(&request.method, request.params, bases, store, policy) {
        Ok(result) => JsonRpcResponse {
            jsonrpc: JSONRPC_VERSION,
            id,
            result: Some(result),
            error: None,
        },
        Err(err) => JsonRpcResponse {
            jsonrpc: JSONRPC_VERSION,
            id,
            result: None,
            error: Some(err),
        },
    };

    let resp_str = serde_json::to_string(&resp)?;
    writeln!(out, "{resp_str}")?;
    out.flush()?;
    Ok(())
}

/// JSON-RPC 2.0 requires the `jsonrpc` member to be exactly `"2.0"`. It used to
/// be deserialized and dropped, so a `"1.0"` request — and a request with no
/// `jsonrpc` member at all — was dispatched as a 2.0 call.
fn check_protocol_version(req: &JsonRpcRequest) -> Result<(), JsonRpcError> {
    match req.jsonrpc.as_deref() {
        Some(JSONRPC_VERSION) => Ok(()),
        Some(other) => Err(JsonRpcError::parse_error(format!(
            "Invalid request: `jsonrpc` member must be \"{JSONRPC_VERSION}\", got `{other}`"
        ))),
        None => Err(JsonRpcError::parse_error(format!(
            "Invalid request: missing `jsonrpc` member; JSON-RPC requires \"{JSONRPC_VERSION}\""
        ))),
    }
}

/// One framed line off the MCP stdin stream, decoded. `Oversize` means the
/// cap was passed before a newline arrived, not that a longer line was read
/// and then measured.
#[derive(Debug)]
enum RequestLine {
    Skip,
    Text(String),
    Oversize,
    InvalidUtf8,
}

enum FrameStep {
    Eof,
    /// Bytes to hand back to the reader, and whether they ended the line.
    Take {
        len: usize,
        newline: bool,
    },
}

fn next_request_line<R: BufRead>(reader: &mut R) -> std::io::Result<Option<RequestLine>> {
    let mut raw: Vec<u8> = Vec::new();
    let mut any = false;
    loop {
        let step = {
            let available = match reader.fill_buf() {
                Ok(available) => available,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if available.is_empty() {
                FrameStep::Eof
            } else {
                match available.iter().position(|&b| b == b'\n') {
                    Some(nl) => {
                        push_bounded(&mut raw, &available[..nl]);
                        FrameStep::Take {
                            len: nl + 1,
                            newline: true,
                        }
                    }
                    None => {
                        push_bounded(&mut raw, available);
                        FrameStep::Take {
                            len: available.len(),
                            newline: false,
                        }
                    }
                }
            }
        };
        match step {
            FrameStep::Eof => {
                return Ok(if any || !raw.is_empty() {
                    Some(classify(raw))
                } else {
                    None
                });
            }
            FrameStep::Take { len, newline } => {
                reader.consume(len);
                any = true;
                // Refuse the moment the cap is passed rather than at the
                // newline: the line is already unreviewable, and the caller
                // treats `Oversize` as fatal, so there is nothing to resync.
                if raw.len() > MAX_REQUEST_LINE_BYTES {
                    return Ok(Some(RequestLine::Oversize));
                }
                if newline {
                    return Ok(Some(classify(raw)));
                }
            }
        }
    }
}

/// Copy at most what is still needed to prove the cap is passed, so the
/// resident bytes never exceed `MAX_REQUEST_LINE_BYTES + 1` no matter how much
/// the peer sends. `BufRead::read_until` (and therefore `split`) copies the
/// whole line first and bounds nothing; `agent.rs` has the same shape bounded
/// with `Read::take`.
fn push_bounded(buf: &mut Vec<u8>, chunk: &[u8]) {
    let room = MAX_REQUEST_LINE_BYTES + 1 - buf.len();
    buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
}

fn classify(raw: Vec<u8>) -> RequestLine {
    if raw.len() > MAX_REQUEST_LINE_BYTES {
        return RequestLine::Oversize;
    }
    match String::from_utf8(raw) {
        Ok(text) if text.trim().is_empty() => RequestLine::Skip,
        Ok(text) => RequestLine::Text(text),
        Err(_) => RequestLine::InvalidUtf8,
    }
}

fn write_error<W: Write>(out: &mut W, message: &str) -> anyhow::Result<()> {
    let resp = JsonRpcResponse {
        jsonrpc: JSONRPC_VERSION,
        id: serde_json::Value::Null,
        result: None,
        error: Some(JsonRpcError::parse_error(message.to_string())),
    };
    let text = serde_json::to_string(&resp)?;
    writeln!(out, "{text}")?;
    out.flush()?;
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

    match name {
        "review_install" => {
            let pkg_spec = args
                .get("package")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing `package` argument"))?;

            let (pkg_name, version) = parse_spec(pkg_spec, ecosystem).map_err(|e| {
                JsonRpcError::invalid_params(format!("invalid package spec `{pkg_spec}`: {e}"))
            })?;

            let mut rctx = crate::recursive::ReviewContext::new(policy, bases.clone());
            let (verdict, _delta, _, _) =
                evaluate_package(&pkg_name, &version, ecosystem, store, policy, &mut rctx)
                    .map_err(|e| {
                        JsonRpcError::internal_error(format!(
                            "review error for `{pkg_spec}`: {e:#}"
                        ))
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
                    // Compare with vercmp equality (libalpm treats a missing
                    // pkgrel as equal to its `-1` sibling), not canonical
                    // strings, so grammar-accepted spellings like `12.4.2`
                    // or `0:12.4.2-1` match the stored `12.4.2-1`.
                    let input = AurVersionInfo::parse(version).map_err(|e| {
                        JsonRpcError::invalid_params(format!("invalid version `{version}`: {e}"))
                    })?;
                    let strs: Vec<String> = rows.iter().map(|(v, _)| v.canonical()).collect();
                    (rows.iter().any(|(v, _)| *v == input), strs)
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

            let (pkg_name, version) = parse_spec(pkg_spec, ecosystem).map_err(|e| {
                JsonRpcError::invalid_params(format!("invalid package spec `{pkg_spec}`: {e}"))
            })?;

            let mut rctx = crate::recursive::ReviewContext::new(policy, bases.clone());
            let (_verdict, delta, _, _) =
                evaluate_package(&pkg_name, &version, ecosystem, store, policy, &mut rctx)
                    .map_err(|e| {
                        JsonRpcError::internal_error(format!(
                            "review error for `{pkg_spec}`: {e:#}"
                        ))
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
    fn check_known_clean_reports_true_only_for_marked_version() {
        use crate::registry::{Checksum, ChecksumAlg};
        use sha2::{Digest, Sha512};
        fn ck(tag: &str) -> Checksum {
            let mut hasher = Sha512::new();
            hasher.update(tag.as_bytes());
            Checksum {
                alg: ChecksumAlg::Sha512,
                value_hex: format!("{:x}", hasher.finalize()),
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        store
            .record_verified(Ecosystem::Npm, "express", "4.21.2", &ck("npm"))
            .unwrap();
        store
            .mark_clean(Ecosystem::Npm, "express", "4.21.2", &ck("npm"))
            .unwrap();
        store
            .record_verified(Ecosystem::PyPi, "requests", "2.28.1", &ck("pypi"))
            .unwrap();
        store
            .mark_clean(Ecosystem::PyPi, "requests", "2.28.1", &ck("pypi"))
            .unwrap();
        store
            .record_verified(Ecosystem::Aur, "yay", "12.4.2-1", &ck("aur"))
            .unwrap();
        store
            .mark_clean(Ecosystem::Aur, "yay", "12.4.2-1", &ck("aur"))
            .unwrap();

        let resp = handle_request(
            "tools/call",
            Some(json!({
                "name": "check_known_clean",
                "arguments": {"name": "express", "version": "4.21.2"}
            })),
            &test_bases(),
            &store,
            &policy,
        )
        .unwrap();
        assert_eq!(resp.get("isClean").unwrap(), &json!(true));

        let resp = handle_request(
            "tools/call",
            Some(json!({
                "name": "check_known_clean",
                "arguments": {"name": "express", "version": "4.21.3"}
            })),
            &test_bases(),
            &store,
            &policy,
        )
        .unwrap();
        assert_eq!(resp.get("isClean").unwrap(), &json!(false));

        let resp = handle_request(
            "tools/call",
            Some(json!({
                "name": "check_known_clean",
                "arguments": {"name": "requests", "version": "2.28.1", "ecosystem": "pypi"}
            })),
            &test_bases(),
            &store,
            &policy,
        )
        .unwrap();
        assert_eq!(resp.get("isClean").unwrap(), &json!(true));

        let resp = handle_request(
            "tools/call",
            Some(json!({
                "name": "check_known_clean",
                "arguments": {"name": "requests", "version": "2.28.2", "ecosystem": "pypi"}
            })),
            &test_bases(),
            &store,
            &policy,
        )
        .unwrap();
        assert_eq!(resp.get("isClean").unwrap(), &json!(false));

        let resp = handle_request(
            "tools/call",
            Some(json!({
                "name": "check_known_clean",
                "arguments": {"name": "yay", "version": "12.4.2-1", "ecosystem": "aur"}
            })),
            &test_bases(),
            &store,
            &policy,
        )
        .unwrap();
        assert_eq!(resp.get("isClean").unwrap(), &json!(true));

        let resp = handle_request(
            "tools/call",
            Some(json!({
                "name": "check_known_clean",
                "arguments": {"name": "yay", "version": "12.4.2-2", "ecosystem": "aur"}
            })),
            &test_bases(),
            &store,
            &policy,
        )
        .unwrap();
        assert_eq!(resp.get("isClean").unwrap(), &json!(false));

        // vercmp-equal spellings of the stored `12.4.2-1` report clean:
        // the pkgrel-less `12.4.2` and the epoch-explicit `0:12.4.2-1`
        // compare equal under libalpm rules even though their canonical
        // strings differ from the stored row.
        let resp = handle_request(
            "tools/call",
            Some(json!({
                "name": "check_known_clean",
                "arguments": {"name": "yay", "version": "12.4.2", "ecosystem": "aur"}
            })),
            &test_bases(),
            &store,
            &policy,
        )
        .unwrap();
        assert_eq!(resp.get("isClean").unwrap(), &json!(true));

        let resp = handle_request(
            "tools/call",
            Some(json!({
                "name": "check_known_clean",
                "arguments": {"name": "yay", "version": "0:12.4.2-1", "ecosystem": "aur"}
            })),
            &test_bases(),
            &store,
            &policy,
        )
        .unwrap();
        assert_eq!(resp.get("isClean").unwrap(), &json!(true));
    }

    #[test]
    fn a_line_at_the_cap_is_read_and_one_byte_over_is_refused() {
        let mut at_cap = vec![b'a'; MAX_REQUEST_LINE_BYTES];
        at_cap.push(b'\n');
        let mut reader = BufReader::new(&at_cap[..]);
        assert!(matches!(
            next_request_line(&mut reader).unwrap(),
            Some(RequestLine::Text(_))
        ));
        // A consumed line leaves the reader at a clean end of stream.
        assert!(next_request_line(&mut reader).unwrap().is_none());

        let mut over = vec![b'a'; MAX_REQUEST_LINE_BYTES + 1];
        over.push(b'\n');
        let mut reader = BufReader::new(&over[..]);
        assert!(matches!(
            next_request_line(&mut reader).unwrap(),
            Some(RequestLine::Oversize)
        ));
    }

    /// The cap has to bound the read, not just the check. The old loop used
    /// `lines()`, which reads a whole line into an unbounded `String` before
    /// anything looks at its length, so a peer that never sends a newline made
    /// the server buffer as much as it cared to send. The strongest observable
    /// proxy for "the buffer never grew to the size of what was sent" is the
    /// byte count the source was drained by: a bounded read stops within a few
    /// buffer-fills of the cap, an unbounded one drains the stream to EOF.
    #[test]
    fn newline_free_stream_is_refused_at_the_cap_without_reading_the_stream() {
        // Sized down so the accounting is tight rather than dominated by the
        // reader's own buffer.
        const CHUNK: usize = 64;
        const STREAM: usize = 8 * 1024 * 1024;

        struct Counting {
            remaining: usize,
            served: usize,
        }
        impl std::io::Read for Counting {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = buf.len().min(CHUNK).min(self.remaining);
                for b in &mut buf[..n] {
                    *b = b'a';
                }
                self.remaining -= n;
                self.served += n;
                Ok(n)
            }
        }

        let mut src = Counting {
            remaining: STREAM,
            served: 0,
        };
        let mut reader = BufReader::with_capacity(CHUNK, &mut src);

        assert!(matches!(
            next_request_line(&mut reader).unwrap(),
            Some(RequestLine::Oversize)
        ));
        assert!(
            src.served <= MAX_REQUEST_LINE_BYTES + 64 * CHUNK,
            "the refusal must land within a few reads of the cap, not after the stream: \
             served {} bytes of {STREAM}",
            src.served
        );
        assert!(
            src.remaining > STREAM / 2,
            "most of the stream must never be read: served {} of {STREAM}",
            src.served
        );
    }

    #[test]
    fn consecutive_requests_keep_their_framing() {
        let stream = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}"
        );
        let mut reader = BufReader::new(stream.as_bytes());
        for id in ["1", "2"] {
            match next_request_line(&mut reader).unwrap() {
                Some(RequestLine::Text(text)) => {
                    assert!(text.contains(&format!("\"id\":{id}")), "{text}")
                }
                other => panic!("request {id} did not frame: {other:?}"),
            }
        }
        assert!(next_request_line(&mut reader).unwrap().is_none());
    }

    #[test]
    fn non_utf8_line_is_flagged_and_a_blank_one_skipped() {
        let mut reader = BufReader::new(&b"{ \xff\xfe\n"[..]);
        assert!(matches!(
            next_request_line(&mut reader).unwrap(),
            Some(RequestLine::InvalidUtf8)
        ));
        let mut reader = BufReader::new(&b"   \n"[..]);
        assert!(matches!(
            next_request_line(&mut reader).unwrap(),
            Some(RequestLine::Skip)
        ));
        // An empty stream is a clean shutdown, not an empty request.
        let mut reader = BufReader::new(&b""[..]);
        assert!(next_request_line(&mut reader).unwrap().is_none());
    }

    #[test]
    fn jsonrpc_error_constructors_have_spec_codes() {
        assert_eq!(JsonRpcError::parse_error("bad json").code, -32700);
        assert_eq!(JsonRpcError::method_not_found("unknown").code, -32601);
        assert_eq!(JsonRpcError::invalid_params("bad param").code, -32602);
        assert_eq!(JsonRpcError::internal_error("fail").code, -32603);
    }

    /// JSON-RPC 2.0 requires `"jsonrpc":"2.0"`. The member was deserialized and
    /// never read, so a `"1.0"` request and a request without the member were
    /// both answered as ordinary 2.0 calls.
    #[test]
    fn rejects_wrong_or_absent_jsonrpc_member() {
        let temp = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&temp.path().join("store.db")).unwrap();
        let policy = Policy::default();
        let bases = test_bases();

        for (body, needle) in [
            (
                r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
                "must be \"2.0\"",
            ),
            (r#"{"id":1,"method":"ping"}"#, "missing `jsonrpc` member"),
        ] {
            let mut out: Vec<u8> = Vec::new();
            serve_request_line(body, &mut out, &bases, &store, &policy).unwrap();
            let resp: serde_json::Value =
                serde_json::from_str(String::from_utf8(out).unwrap().trim()).unwrap();
            assert_eq!(resp["jsonrpc"], "2.0", "{body}");
            assert_eq!(resp["id"], serde_json::Value::Null, "{body}");
            assert_eq!(resp["error"]["code"], -32700, "{body}");
            assert!(
                resp["error"]["message"].as_str().unwrap().contains(needle),
                "{body}: {resp}"
            );
            assert!(
                resp.get("result").is_none(),
                "a refused request must carry no result: {body}: {resp}"
            );
        }

        // The declared version is answered normally, so the check is not a
        // blanket refusal.
        let mut out: Vec<u8> = Vec::new();
        serve_request_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            &mut out,
            &bases,
            &store,
            &policy,
        )
        .unwrap();
        let resp: serde_json::Value =
            serde_json::from_str(String::from_utf8(out).unwrap().trim()).unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"], json!({}));
        assert!(resp.get("error").is_none(), "{resp}");
    }
}
