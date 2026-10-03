# MCP Server

`src/mcp.rs`. Model Context Protocol JSON-RPC 2.0 over stdio, exposing three
tools. Protects the property that the MCP verdict is the **same D7 struct** the
CLI prints, sanitized — never a re-derived shape.

## Sub-features
- `run_stdio` — line-delimited JSON-RPC loop.
- Methods: `initialize`, `ping`, `tools/list`, `tools/call`.
- Tools: `review_install`, `check_known_clean`, `inspect_diff`.
- `parse_ecosystem`, error codes, `structuredVerdict`.
- Sanitization via `render::sanitize_single_line` / `sanitize_terminal`.

## How to get to it (user POV)
```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
   "name":"review_install","arguments":{"package":"express@4.21.2","ecosystem":"npm"}}}
```
Client config in practice:
```json
{"mcpServers":{"blueline":{"command":"blueline","args":["mcp"]}}}
```

## Driving it
`initialize` response:
```json
{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},
 "serverInfo":{"name":"blueline","version":"<CARGO_PKG_VERSION>"}}
```
`ping` → `{}` (the empty-object fix; `handles_ping_request` asserts equality).

| Tool | Required params | Optional | Result keys |
|---|---|---|---|
| `review_install` | `package` (`<name>@<version>`) | `ecosystem` | `content`, `isError`, **`structuredVerdict`** |
| `check_known_clean` | `name`, `version` | `ecosystem` | `content`, `isClean`, `cleanVersions` |
| `inspect_diff` | `package` | `ecosystem` | `content` only |

`ecosystem` accepts exactly `npm | cargo | pypi | aur`; missing or `null` →
`npm`; non-string → `-32602`; unknown → `-32602`.

Error codes: `-32700` parse, `-32601` method not found, `-32602` invalid params,
`-32603` internal. A parse error returns `id: null` and the loop **continues**.

Recommendation strings: `Low` → `"APPROVE — Safe to install"`;
`Medium` → `"HOLD — Review recommended before installation"`;
`High` → `"HOLD / CAUTION — High risk delta detected"`;
`Block` → `"BLOCK — Security policy violation detected"`.

## Gotchas
- **Notifications are dropped before dispatch.** `if request.id.is_none()
  { continue; }` fires ahead of any method match, so there is no
  `notifications/initialized` arm at all — which is exactly how the "no longer
  print an stderr note on `notifications/initialized`" change is realized.
  Adding a match arm below that line does nothing.
- **`ping` returns `{}`, not `null` or a status string.** The 0.1.0 fix; there
  is a regression test pinning the exact value.
- **MCP uses `Policy::load_or_default`, so it DOES honor `BLUELINE_POLICY`.** It
  is the only surface that does — `agent review` and `agent gate` deliberately do
  not.
- **There is no oversized-request bound.** `run_stdio` reads
  `reader.lines()` with no `take()`, no length cap, no depth cap. The 64 KiB
  refusal limit exists only on the `agent gate` hook-stdin path. Do not attribute
  a request bound to MCP.
- **`structuredVerdict` only exists on `review_install`.** `inspect_diff`
  returns `content` alone — no verdict, no `isError`.
- **Version comparison in `check_known_clean` is per-ecosystem and asymmetric:**
  npm/cargo use `semver::Version::canonical()` string equality, PyPI uses
  `Pep440Version`, AUR uses `AurVersionInfo` vercmp **equality** (so `12.4.2`
  matches a stored `0:12.4.2-1`, libalpm semantics). An unparseable **AUR**
  version is `-32602`; npm/PyPI unparseable versions fall back to raw string.
- **`flush()` after every response**, explicitly. Removing it deadlocks clients.
- **All untrusted strings pass through `sanitize_single_line`**
  (names, versions, paths, rule ids, titles, integrity) or `sanitize_terminal`
  (finding descriptions, unified diffs). `error.data` is always `None` and
  skipped; `result`/`error` skipped when `None`.
- **`review_install` failures surface as `-32603` with `{e:#}`** — the full
  anyhow chain, which is intentional for agent debugging.