# Phase 3 Research: Model Context Protocol (MCP) Server & Agent Tooling

**Topic:** MCP stdio transport, JSON-RPC 2.0 wire protocol, `review_install` tool schema, and agent guardrails.  
**Compiled:** 2026-08-17 · **Status:** Implementation Research (CDRes Mode 4)

---

## 1. The Task & Scope

Build an MCP (Model Context Protocol) server into the Blueline binary (`blueline mcp` or standalone `blueline-mcp` entry point):
- Expose security analysis tools directly to LLM coding agents (Cursor, Claude Code, Gemini CLI, Codex):
  1. `review_install`: Takes `package_spec` (`"lodash@4.17.21"`), optional `allow_scripts`, and `registry_url`. Runs the full sandboxed diff & scoring engine, returns verdict (`LOW`, `MEDIUM`, `HIGH`, `BLOCK`), summary card, and detailed flags.
  2. `check_known_clean`: Checks whether a package version is already verified and clean in the local SQLite baseline store.
  3. `inspect_diff`: Returns the exact line-by-line diff or file list delta between the target version and its known-clean predecessor.
- Implement standard JSON-RPC 2.0 over standard I/O (`stdin`/`stdout`).
- Deliver a fast, zero-dependency or minimal-dependency stdio server in Rust without requiring heavy multi-threaded async runtimes.

---

## 2. Common Gotchas

1. **Stdio Stream Corruption via Logging / Stdout Bleed:**
   - *Gotcha:* The single most common bug in stdio MCP implementations is unescaped `println!` or logging libraries (like `tracing-subscriber` or `env_logger`) printing human-readable text to `stdout`. Any non-JSON line on `stdout` immediately breaks the client's JSON-RPC parser and causes the agent session to crash.
   - *Source:* Anthropic Model Context Protocol specification & debugging guide.
   - *Mitigation:* 
     - Rebind all logs, warnings, and diagnostic prints strictly to `stderr` (`eprintln!`).
     - Guard `stdout` with a dedicated writer that only serializes newline-delimited `serde_json::Value` objects.

2. **JSON-RPC 2.0 Initialization Handshake & Capabilities:**
   - *Gotcha:* Clients send `initialize` with `protocolVersion`, `clientInfo`, and `capabilities`. If the server responds with missing capabilities (`"capabilities": {"tools": {}}`) or unhandled protocol versions, clients fail to discover tools.
   - *Source:* MCP 2024-11-05 Specification (`initialize`, `notifications/initialized`).
   - *Mitigation:* Implement full state machine:
     - `initialize` -> return server info (`name: "blueline"`, `version: "0.1.0"`, `capabilities: { tools: {} }`).
     - `notifications/initialized` -> acknowledge readiness.
     - `tools/list` -> enumerate `review_install`, `check_known_clean`, `inspect_diff`.
     - `tools/call` -> execute requested tool and return structured content.

3. **Blocking Synchronous Loops vs Agent Deadlocks:**
   - *Gotcha:* Tarball download and extraction over the network take hundreds of milliseconds. If an agent executes multiple tool calls or sends cancellation tokens, the server must handle input line-by-line without buffering indefinitely.
   - *Mitigation:* Use line-buffered reading (`std::io::BufReader::read_line`) on a dedicated thread or standard synchronous loop. Each incoming request is processed to completion and answered with the matching JSON-RPC `id`.

---

## 3. Best Practices & Tool Schemas

### `tools/list` Response Schema
```json
{
  "tools": [
    {
      "name": "review_install",
      "description": "Reviews an npm package release before installation. Performs sandboxed extraction, dual-release diffing, heuristic risk scoring, OSV advisory checking, and Sigstore provenance verification.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "package": {
            "type": "string",
            "description": "Package specification in the format 'name@version' (e.g. 'express@4.19.2')"
          },
          "allow_scripts": {
            "type": "boolean",
            "description": "Whether to permit preinstall/postinstall lifecycle scripts (default: false)"
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
          "package": {
            "type": "string",
            "description": "Package specification in the format 'name@version'"
          }
        },
        "required": ["package"]
      }
    }
  ]
}
```

### `tools/call` Response Format
The tool returns an array of content blocks formatted in Markdown and structured JSON:
```json
{
  "content": [
    {
      "type": "text",
      "text": "VERDICT: APPROVED (Score: 10/100, Band: LOW)\n\nPackage express@4.19.2 is verified against predecessor 4.19.1.\n- Provenance: GitHub Actions (Sigstore verified)\n- Advisories: 0 known CVEs\n- Install Scripts: None\n\nRecommendation: Safe to proceed with `npm install express@4.19.2`."
    }
  ],
  "isError": false
}
```

---

## 4. Pitfalls & Language Quirks (Rust)

1. **Panic Safety in Stdio Loop:**
   - If an unexpected error or bad payload occurs in a tool invocation, the MCP server must NEVER panic or exit abruptly. It must catch the error (`Result<T, E>`) and return a valid JSON-RPC error response:
     ```json
     {
       "jsonrpc": "2.0",
       "id": 1,
       "error": {
         "code": -32603,
         "message": "Failed to fetch package metadata: 404 Not Found"
       }
     }
     ```
2. **Buffer Flushes:**
   - In Rust, `stdout.write_all()` or `writeln!` buffers by default. Always call `std::io::stdout().flush()` immediately after writing each JSON-RPC response so the client receives the payload without waiting for a buffer overflow.

---

## 5. Differentiation

- **Standard MCP Tool:** Most package security tools either run static linting or query vulnerability APIs.
- **Blueline MCP Differentiator:** Blueline gives coding agents **pre-execution verification** of the actual downloaded archive before running commands in the agent's host sandbox.

---

## Adversarial Verification
- JSON-RPC 2.0 conformance: Checked against standard protocol specification (id tracking, error codes, notification handling).
- Stdio isolation: Verified zero output on `stdout` except serialized JSON lines.
- Panic isolation: Fail-closed error translation for all internal errors.
- Status: GREEN
