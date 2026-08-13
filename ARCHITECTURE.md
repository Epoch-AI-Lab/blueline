# Blueline Architecture

> Approve the delta, not the download.

Blueline is a release-diff review desk for the package install line. It renders
every release as a proof sheet and demands sign-off before the byte runs.

**Hard rule: nothing executes until judged.** Tarballs are fetched, **integrity-verified
(sha512 SRI + registry signature, fail closed)**, then extracted read-only into a
sandboxed temp dir — never executed, diffed, and scored. The package's own code is
never run: even on approve, install proceeds with `npm install --ignore-scripts`,
and any `postinstall`/`preinstall` script is surfaced for a *separate* human decision.

> Note: the README lists the "Diff rendering engine (Rust)" as done. As of the
> initial commit only README, LICENSE, and brand assets exist. The engine is a
> design target, not shipped code.
>
> Update 2026-08-13: **Phase 0 shipped.** A `blueline` Rust binary exists:
> `registry::npm` (fetch + sha512-verified tarball download), typed manifest
> parsing, bounded sandbox extraction, and a SQLite `known_clean` baseline
> store behind `blueline review <pkg@ver>`. Diff/verdict/card rendering are
> Phase 1, still unshipped.

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Entry points                                                 │
│  • `npx blueline install <pkg>`  → Node shim → Rust binary   │
│  • `blueline review <pkg@ver>`   → Rust binary (direct)      │
│  • `blueline ci`                 → GitHub Action / CI         │
│  • `blueline-mcp`                → MCP server (agent hook)    │
└───────────────┬─────────────────────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────────────────┐
│  blueline (Rust binary) — the engine                          │
│                                                               │
│  registry::npm   ── fetch metadata + tarballs (read-only)     │
│  baseline::store ── SQLite: installed/known-clean versions,   │
│                     approval overrides, policy                │
│  extract         ── verify hash → bounded sandbox extract    │
│  diff            ── file-level + line-level (similar crate)   │
│  heuristic       ── rule engine → risk score → verdict        │
│  revocation      ── OSV / GitHub Advisory cache + hosted idx  │
│  provenance      ── sigstore/SLSA attestation *surfaced*,     │
│                     never trusted as sufficient               │
│  policy          ── blueline.toml (thresholds, allow/block)   │
│  render          ── ASCII review card (comfy-table)           │
│  executor        ── on approve: `npm install --ignore-scripts`│
└───────────────┬─────────────────────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────────────────┐
│  Hosted service (paid, opt-in token)                          │
│  • Recall index (curated, faster than OSV; e.g. TanStack worm)│
│  • Verdict model (ML refines local score)                     │
│  • Team policy sync · audit logs · SSO                        │
└─────────────────────────────────────────────────────────────┘
```

### Node shim (`@blueline/cli`)
A tiny npm package. Its `bin` is a JS launcher that resolves/installs the
platform-specific Rust binary (via per-platform optional deps
`@blueline/binary-{linux,darwin,win}-{x64,arm64}`) and `exec`s it. Rust does all
heavy lifting; Node only provides the `npx` ergonomics and PATH registration.
On approve, the shim delegates to `npm install --ignore-scripts` so the reviewed
package's own install scripts are never executed automatically (see D11).
The Rust binary is also directly installable (`cargo install` / direct download)
for non-Node environments.

### `Registry` trait
npm is the only implementation now, but the trait
(`fetch_manifest`, `fetch_tarball`, `list_versions`) exists from commit 1 so
PyPI/cargo plug in later without refactoring the engine.

### Extraction & untrusted-input safety
Every tarball and registry response is fully untrusted. The `extract` stage enforces:
- **Integrity first:** stream-hash the tarball during download and compare to the
  registry `dist.integrity` (sha512) and `dist.shasum`; verify the npm registry
  signature when present. Mismatch → `Verdict::Block` (fail closed) *before* extraction.
- **Bounded extraction:** hard caps on total unpacked bytes (e.g. 50× tarball size),
  entry count, per-entry size, open file descriptors, and a gzip decompress-ratio
  monitor (bomb guard). The temp dir is an RAII guard removed on drop/panic.
- **Reject dangerous entry types:** symlinks, hardlinks, and special files
  (char/block device, FIFO, socket) are rejected by default; absolute paths and `..`
  traversal are rejected; setuid/setgid bits are stripped. Pin `tar` ≥ 0.4.45 and
  prefer `cap-std`'s `Dir` for beneath-root (RESOLVE_BENEATH) resolution.
- **Sandbox the step:** run extract + diff in a Landlock-restricted child
  (read-only host FS, write only to the sandbox temp dir), capability-dropped,
  optionally seccomp-filtered, non-root. Linux uses Landlock; macOS/Windows fall
  back to the parser-level bounds above plus a dedicated non-writable temp dir.
- **Treat extracted bytes as hostile:** the extracted `package.json` (`scripts`,
  `bin`, `dependencies`) is diffed/flagged as attack surface, not trusted.

---

## 2. Key Technical Decisions

| #  | Decision                                            | Rationale                                                                 |
|----|-----------------------------------------------------|---------------------------------------------------------------------------|
| D1 | Rust core + Node shim                               | Security-critical path in a memory-safe, single-binary language; Node only for `npx` ergonomics. |
| D2 | Local deterministic heuristic first                 | Transparent, auditable, offline. Hosted ML *refines* score when token present — never required. Keeps "the wedge stays open" honest. |
| D3 | npm-only, `Registry` trait seam                     | Deepen one registry; avoid speculative multi-registry code now.           |
| D4 | Read-only sandbox extraction + integrity verify     | Core safety invariant. Verify sha512/signature *before* extract; bound size/entry/FD; reject symlinks/special files; Landlock-sandbox the step. Package code never runs. |
| D5 | Baseline = last known-clean version                 | Source: locally installed version in `node_modules` → else previous version in registry list (neutral verdict on first sighting). Overrides persisted in SQLite. |
| D6 | Revocation = OSV + GitHub Advisory cache            | Reuse the open vulnerability corpus; paid tier adds human-verified recall (hosted index). |
| D7 | Stable `Verdict` JSON schema                        | Same struct feeds CLI card, CI comment, and MCP tool. One source of truth.|
| D8 | No default telemetry in OSS                         | Privacy-by-default; hosted tier reports only with explicit token.         |
| D9 | Signed, SLSA-built release binaries                 | We audit supply chains — we must eat our own dog food.                    |
| D10| Policy-as-code (`blueline.toml`)                    | Per-project + global thresholds, allow/blocklists, required-provenance flags. |
| D11| Approve = `npm install --ignore-scripts`           | Honors "never execute": install proceeds without running lifecycle scripts; `postinstall` is surfaced for a separate human decision, not auto-run. |

### Verdict bands
- `LOW` — auto-approve path
- `MEDIUM`
- `HIGH`
- `BLOCK` — hard policy violation: new `postinstall`/`preinstall` script, known
  revocation, or unpinned dangerous delta

### Heuristic rule set (local, v1)
- New executable/binaries (executable bit, `.exe`, native bindings)
- `scripts` field additions (`postinstall`, `preinstall`, etc.)
- New/changed dependencies (transitive risk)
- Install-script presence
- Obfuscated / `base64` / `eval` in diff
- Maintainer/author change vs baseline
- Semver-major with large delta
- Missing/forged provenance (surfaced, not auto-fail)
- Revocation hit (BLOCK)

### MCP design
Explicit `review_install` tool (agent calls before install) is primary; optional
invasive PATH shim that routes `npm`/`npx` through blueline is secondary.
Recommend the explicit tool to avoid breaking agent toolchains.

---

## 3. Tech Stack (Rust core)

| Concern            | Crate / Tool                          |
|--------------------|---------------------------------------|
| CLI parsing        | `clap`                                |
| Registry HTTP      | `ureq` (small binary) or `reqwest`    |
| Tarball extract    | `tar` + `flate2`                      |
| Manifest / JSON    | `serde` + `serde_json`                |
| Local store        | `rusqlite` (SQLite)                   |
| Diffing            | `similar`                             |
| Version resolution | `semver`                              |
| Review card        | `comfy-table`                         |
| Interactive prompt | `inquire` or custom `[a]/[h]/[d]`     |

---

## 4. Open Risks

- **First-sighting bootstrap:** no baseline on initial install → default to a
  *neutral* verdict and flag "no known-clean baseline" rather than BLOCK.
- **`scripts` false positives:** legit packages (esbuild, core-js) use
  postinstall. Need an allowlist-by-maintainer or "review once, remember" flow.
- **Lockfile vs manifest:** `review` diffs a single package; `ci` must diff the
  whole lockfile. Two code paths — `ci` is Phase 3, not Phase 1.
