# Blueline Roadmap

Phased plan from greenfield to hosted service. See `ARCHITECTURE.md` for the
decisions behind each phase.

## Phase 0 — Foundation
- Rust crate skeleton + `clap` CLI
- `registry::npm` client (metadata + tarball fetch, read-only)
- Manifest parsing (`serde`/`serde_json`)
- Tarball fetch + sandbox extraction (`tar` + `flate2`)
- SQLite baseline store (`rusqlite`): installed/known-clean versions, overrides, policy
- Command: `blueline review <pkg@ver>`

## Phase 1 — Wedge Primitive
- Diff engine: file-level + line-level (`similar`)
- ASCII review card rendering (`comfy-table`)
- Heuristic verdict engine + scoring (rules in `ARCHITECTURE.md` §2)
- Interactive prompt: `[a]pprove · [h]old · [d]iff`
- Node shim (`@blueline/cli`) + `npx blueline install` that performs/blocks the real `npm install`
- Baseline "known-clean" resolution (installed version → prior registry version)

## Phase 2 — Trust Sources
- OSV + GitHub Advisory revocation cache
- Provenance / attestation surfacing (sigstore / SLSA) — displayed, never trusted
- `blueline.toml` policy-as-code (thresholds, allow/blocklists, required-provenance)
- Persisted approval allowlist

## Phase 3 — CI & Agents
- GitHub composite Action: `blueline ci` scans lockfile / `package.json` PR diffs → comment + status check
- MCP server: `review_install` tool + optional guardrail (PATH shim) mode

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
- [x] Diff rendering engine (Rust) — *design target; no code shipped yet*
- [ ] npm/npx CLI wrapper
- [ ] GitHub Action + CI check
- [ ] MCP tool (agent hook)
- [ ] Revocation index + recall API
