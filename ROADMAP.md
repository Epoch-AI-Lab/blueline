# Blueline Roadmap

Phased plan from greenfield to hosted service. See `ARCHITECTURE.md` for the
decisions behind each phase.

## Phase 0 — Foundation ✅
- [x] Rust crate skeleton + `clap` CLI
- [x] `registry::npm` client (metadata + tarball fetch, read-only) — sha512 integrity verified before extraction, fail closed
- [x] Manifest parsing (`serde`/`serde_json`) — typed `PackageJson`
- [x] Tarball fetch + sandbox extraction (`tar` + `flate2`) — bounded, traversal/absolute/symlink/hardlink/dev-file rejected
- [x] SQLite baseline store (`rusqlite`): known-clean versions (schema v1)
- [x] Command: `blueline review <pkg@ver>` — text + JSON output, `--registry` override
- [x] Tests: unit (extract/registry/manifest/store/parse) + integration vs. local fixture registry (no network)

## Phase 1 — Wedge Primitive ✅
- [x] Baseline "known-clean" resolution (installed clean store version → semver registry predecessor)
- [x] Diff engine: dual-release file-level + line-level (`similar`)
- [x] Heuristic verdict engine + scoring (rules in `ARCHITECTURE.md` §2)
- [x] ASCII review card rendering (`comfy-table`) + stable JSON verdict schema
- [x] Interactive prompt: `[a]pprove · [h]old · [d]iff` with `clean = 1` SQLite store persistence
- [x] Node shim (`@blueline/cli`) + `npx blueline install` that performs/blocks the real `npm install`

## Phase 2 — Trust Sources ✅
- [x] OSV + GitHub Advisory revocation cache & engine (`src/advisory.rs`)
- [x] Provenance / attestation surfacing (Sigstore / SLSA) (`src/provenance.rs`)
- [x] `blueline.toml` policy-as-code (advisories, provenance enforcement, allow/blocklists) (`src/policy.rs`)
- [x] SQLite schema v2 (`advisory_cache`, `provenance_cache`, `audit_log`) (`src/store.rs`)

## Phase 3 — CI & Agents ✅
- [x] GitHub composite Action (`.github/actions/blueline-ci/action.yml`)
- [x] `blueline ci` lockfile diff scanner & PR reporting (`src/ci.rs`, `src/lockfile.rs`)
- [x] Model Context Protocol (MCP) server & agent tools (`src/mcp.rs`, `blueline mcp`)
- [x] Top-tier CI hardening with `cargo-deny` (`deny.toml`) and `cargo-fuzz` (`fuzz/`)

## Phase 4 — Hosted Service (paid, opt-in token)
- Recall index API (curated, faster than OSV; e.g. TanStack/router worm)
- Verdict-model endpoint (ML refines local score)
- Team policy sync · audit logs · SSO
- Token-gated upgrade path in CLI

## Phase 5 — Scale
- Multi-registry adapters (PyPI, cargo) via the `Registry` trait
- Enterprise SSO / SCIM
- Advisory feed contributions back to OSV / GitHub

---

## Status (from README)
- [x] Diff rendering engine (Rust)
- [x] npm/npx CLI wrapper
- [x] GitHub Action + CI check
- [x] MCP tool (agent hook)
- [ ] Revocation index + recall API
