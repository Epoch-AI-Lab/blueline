# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `blueline review <pkg@ver>` command with text and JSON output, `--registry`
  override, and a fail-closed `--yes` flag.
- `blueline install` command with sandboxed extraction and fail-closed script
  execution.
- `blueline ci --output-file <path>` parameter to save formatted CI review
  reports directly to disk.
- npm registry client with SHA-512 integrity verification before extraction.
- Line-level diff engine against the last known-clean release.
- Heuristic verdict engine with an ASCII review card and stable JSON verdict
  schema.
- Interactive `[a]pprove · [h]old · [d]iff` prompt persisting clean versions
  to the SQLite store.
- OSV and GitHub Advisory revocation cache and engine.
- Sigstore / SLSA provenance and attestation surfacing.
- Policy-as-code via `blueline.toml` (advisories, provenance, allow/blocklists).
- `blueline ci` lockfile diff scanner and PR reporting.
- Model Context Protocol (MCP) server and agent tools (`blueline mcp`).
- npm/npx wrapper shim (`@blueline/cli`).
- GitHub composite Action for PR checks.
- SQLite store with known-clean baselines, advisory/provenance caches, and an
  audit log.

### Changed

- Hardened static diff scanner against `String.fromCharCode` /
  `String.fromCodePoint` module-name reconstruction: charcode calls with
  plain integer arguments are folded to string literals before heuristic
  matching, closing one obfuscation route to `require(child_process)`.
- Hardened static AST/diff scanner with adjacent string literal folding to prevent concatenation evasion, dynamic global bracket invocations, String.fromCharCode property indexing, and indirect constructor/prototype references.
- Hardened static AST/diff scanner to detect reflection-based code execution (`Reflect.get`), global dynamic execution lookups (`globalThis['eval']`, `window['Function']`), and Node.js `worker_threads` imports without triggering false positives on benign JavaScript.
- Hardened archive extraction, SSRF checks, and executor isolation to fail
  closed on any doubt.
- Bounded registry reads with exact limits for packuments, tarballs, and
  redirects.
- Validated package name grammar, scoped URLs, and terminal escape sequences.
- Optimized static diff heuristic scanning, lockfile delta merging, SSRF IP validation, and terminal formatting with zero-allocation slice processing and O(N) two-pointer iteration.
- Optimized diff scanning performance.
- Clarified diagnostic stderr explanations when non-interactive input is piped
  without `--yes`.

### Fixed

- Isolated temporary build environment git repository resolution in CI test suites.

- IPv6 mutation testing by eliminating redundant address checks.
- Redirect handling and false-equivalent bounds in registry metadata.
- JSON output purity by suppressing trailing human messages under `--output json --yes`.
- Timer string dynamic code evaluation (`setTimeout`, `setInterval`, `setImmediate`) in diff scanner heuristics.
- Zero-width and bidirectional unicode formatting character evasion in JavaScript token stripping.
- In-toto attestation empty subject bypass in SLSA provenance verification by enforcing matching subject digest.
- MCP standard heartbeat `ping` method handling returning empty JSON object.
- Case-insensitive parsing and uppercase aliases for `--fail-on` verdict risk bands.
- GitHub Actions composite step hardening mapping action inputs into environment variables to prevent shell injection.
- MCP tool output terminal escape and BiDi control character sanitization.

### Security

- Fail-closed on every parse, extract, and verify boundary.
- Integrated `cargo-deny` in CI to enforce licenses, bans, sources, and security advisories using `deny.toml`.
- Expanded PR diff and matrix mutation testing to guard `executor.rs`, `lockfile.rs`, `ci.rs`, and `mcp.rs` boundaries against regressions.
- Hardened static heuristic scanner against inline module requires, paren-wrapped constructors, http2/dns primitives, timer string eval, zero-width unicode obfuscation, indirect eval aliases, dynamic `this[...]` evaluation, `process.dlopen`, `cluster`, `WebAssembly` compilation, and external HTTP client libraries.
- Mutation testing and supply-chain audits run on every PR (CI gate).
