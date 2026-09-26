# Blueline Architecture

> Approve the delta, not the download.

Blueline is a release-diff review desk for the package install line. It renders
every release as a proof sheet and demands sign-off before the byte runs.

**Hard rule: nothing executes until judged.** Tarballs are fetched, **integrity-verified
(sha512 SRI, fail closed)**, then extracted read-only into a sandboxed temp dir —
never executed, diffed, and scored. The package's own code is
never run: even on approve, install proceeds with `npm install --ignore-scripts`,
and any `postinstall`/`preinstall` script is surfaced for a *separate* human decision.

> Status: Phases 0–4 plus the close-the-loop campaigns (recursive review,
> agent enforcement, local-first recall, dogfood & distribution) are shipped.
> See `ROADMAP.md`, `TODO.md`, and `CHANGELOG.md` for the per-release record.

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Entry points                                                 │
│  • `npx blueline-cli install <pkg>`  → Node shim → Rust binary   │
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
│  install_ref     ── scan payload for referenced installs      │
│  recursive       ── re-review referenced installs: depth caps,│
│                     cycle detection, roll-up                  │
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

### Node shim (`blueline-cli` / `@kridaydave/blueline-cli`)
A tiny npm package. Its `bin` is a JS launcher that resolves/installs the
platform-specific Rust binary (via per-platform optional deps
`@kridaydave/binary-{linux,darwin,win}-{x64,arm64}`) and `exec`s it. Rust does all
heavy lifting; Node only provides the `npx` ergonomics and PATH registration.
On approve, the shim delegates to `npm install --ignore-scripts` so the reviewed
package's own install scripts are never executed automatically (see D11).
The Rust binary is also directly installable (`cargo install` / direct download)
for non-Node environments.

### `Registry` trait
Four implementations ship behind it now: npm, crates.io, PyPI, and a
review-only AUR adapter (git history over the system `git` binary, static
PKGBUILD parsing, never executed). The trait (`list_releases`,
`default_version`, integrity-typed fetch) exists from commit 1 so each
registry plugged in later without refactoring the engine.

### Extraction & untrusted-input safety
Every tarball and registry response is fully untrusted. The `extract` stage enforces:
- **Integrity first:** download the tarball under a hard byte cap, then hash the
  buffered bytes and compare to the registry `dist.integrity` (sha512); a missing
  or non-sha512 `dist.integrity` is refused rather than downgraded. A mismatch
  aborts the review with a verification error *before* extraction — no verdict is
  produced, so there is nothing to approve or override.
- **Bounded extraction:** hard *absolute* caps, not multiples of the tarball
  size — entry count (100 000, checked before any write), per-entry unpacked
  size (128 MiB, checked against the header and again against the bytes actually
  written), and cumulative unpacked bytes (512 MiB). Tar metadata entries (GNU
  long name/link, pax extensions) carry their own 64 KiB cap and count against
  that total, so a long-name bomb cannot slip under it. A directory entry that
  declares payload is refused. There is no decompress-ratio monitor and no
  open-FD cap: the guard is the byte and entry budget, enforced on the declared
  size *and* on the inflated stream. The temp dir is an RAII guard removed on
  drop/panic.
- **Reject dangerous entry types:** symlinks, hardlinks, and special files
  (char/block device, FIFO, socket) are rejected by default; absolute paths, `..`
  traversal, and drive prefixes are rejected, as is a second entry normalizing
  onto a path already written (`a//b` and `a/b` are one entry, and the second
  would otherwise overwrite the first); setuid/setgid bits are stripped. Pin
  `tar` ≥ 0.4.45.
- **Sandbox the step (planned, not implemented):** the intent is to run extract
  + diff in a Landlock-restricted child (read-only host FS, write only to the
  sandbox temp dir), capability-dropped, optionally seccomp-filtered, non-root,
  with macOS/Windows falling back to the parser-level bounds above plus a
  dedicated non-writable temp dir. No Landlock, seccomp, `cap-std` or
  capability-drop code exists in `src/` today, and `Cargo.lock` carries none of
  those crates. What actually bounds a hostile archive is the parser-level
  budget above; there is no OS-level confinement behind it.
- **Treat extracted bytes as hostile:** the extracted `package.json` (`scripts`,
  `dependencies`) is diffed/flagged as attack surface, not trusted.

---

## 2. Key Technical Decisions

| #  | Decision                                            | Rationale                                                                 |
|----|-----------------------------------------------------|---------------------------------------------------------------------------|
| D1 | Rust core + Node shim                               | Security-critical path in a memory-safe, single-binary language; Node only for `npx` ergonomics. |
| D2 | Local deterministic heuristic first                 | Transparent, auditable, offline. Hosted ML *refines* score when token present — never required. Keeps "the wedge stays open" honest. |
| D3 | One registry deep, `Registry` trait seam, then four | Deepen one registry first; avoid speculative multi-registry code. npm, crates.io, PyPI, and review-only AUR now share the seam. |
| D4 | Read-only sandbox extraction + integrity verify     | Core safety invariant. Verify sha512/signature *before* extract; bound size/entry; reject symlinks/special files; Landlock-sandbox the step (planned). Package code never runs. |
| D5 | Baseline = last known-clean version                 | Source: locally installed version in `node_modules` → else previous version in registry list (neutral verdict on first sighting). Overrides persisted in SQLite. |
| D6 | Revocation = OSV + GitHub Advisory cache            | Reuse the open vulnerability corpus; paid tier adds human-verified recall (hosted index). |
| D7 | Stable `Verdict` JSON schema                        | Same struct feeds CLI card, CI comment, and MCP tool. One source of truth.|
| D8 | No default telemetry in OSS                         | Privacy-by-default; hosted tier reports only with explicit token.         |
| D9 | Signed, SLSA-built release binaries                 | We audit supply chains — we must eat our own dog food.                    |
| D10| Policy-as-code (`blueline.toml`)                    | Per-project + global thresholds, allow/blocklists, required-provenance flags. |
| D11| Approve = `npm install --ignore-scripts`           | Honors "never execute": install proceeds without running lifecycle scripts; `postinstall` is surfaced for a separate human decision, not auto-run. |
| D12| Recursive second-order review in the engine           | Install references found in reviewed payloads are re-reviewed with depth/budget caps, cycle detection, and child-to-parent roll-up (§5). Non-registry refs are disclosed, never resolved. |
| D13| Local-first recall index, no hosted dependency        | Curated revocations sync as a validated JSON snapshot (never the SQLite store); hits BLOCK through the advisory engine, staleness is disclosed (§5). |
| D14| Explicit agent tool primary, shim as backstop         | `review_install` is what well-behaved agents call; PATH shims and hook bindings enforce at the terminal/agent boundary with honest bypass docs (§5). |

### Verdict bands
- `LOW` — auto-approve path
- `MEDIUM`
- `HIGH`
- `BLOCK` — hard policy violation: new `postinstall`/`preinstall` script, known
  revocation, or unpinned dangerous delta

### Heuristic rule set (local, v1 — full inventory; bands tunable via policy)
- R00 — unparseable/unreadable baseline or PKGBUILD (fail closed), PKGBUILD scope disclosure
- R01 — lifecycle script added/modified, `binding.gyp` added/modified (native build trigger)
- R02 — executable/binary blob added/modified, opaque large file, new install script, entry-points script
- R03 — `child_process`, `eval`, VM execution, network primitives, high entropy in diff
- R04 — dependency added/modified, sdist build code
- R05 — large patch diff, non-standard version
- R06 — first sighting (no baseline), native platform wheel
- R07 — unreviewed predecessor baseline
- R08 — yanked predecessor (MEDIUM)
- R09 — advisory CVE / critical CVE / malware hit (BLOCK), yanked target
- R10 — maintainer transition, lockfile hash mismatch
- R11–R23 — PKGBUILD static rules (checksum SKIP, source drift, pipe-to-shell,
  eval family, indirection, cmd-subst in metadata, build-time network,
  homoglyph, validpgpkeys change, install/hook change, unpinned VCS,
  conditional execution, npm delivery); see §5 and `src/pkgbuild.rs`
- R24–R27 — recursive review (install-ref disclosure, depth cap, cycle, second-order roll-up); see §5
- R28 — recall-index staleness; see §5

### MCP design
Explicit `review_install` tool (agent calls before install) is primary; optional
invasive PATH shim that routes `npm`/`npx` through blueline is secondary.
Recommend the explicit tool to avoid breaking agent toolchains.

---

## 5. Second-order lanes (agent / recall / shim)

Install-time references (npm lifecycle scripts, wheel `.data/scripts`,
PKGBUILD npm/bun delivery) are first-class findings, reviewed recursively:

- **R24** — every statically visible reference is disclosed; band reflects
  pinnability (HIGH pinned, MEDIUM unpinned/dynamic, HIGH non-registry).
- **R25** — depth/budget caps (`[recursion] max_depth`, `max_child_reviews`)
  fail closed as HIGH findings, never silent skips.
- **R26** — install-reference cycles (A → B → A) are cut with a HIGH finding.
- **R27** — roll-up: a child finding at/above `child_block_band` escalates
  the parent via a second-order finding carrying the delivery chain.
- **R28** — recall-index staleness: MEDIUM past `[recall] max_age_hours`,
  HIGH when unreadable, BLOCK with `block_on_stale`.

### `ReviewContext` cycle (`src/recursive.rs`)

One `ReviewContext` spans a top-level evaluation. `enter_scope` pushes the
cycle key `(ecosystem, name, version)` and the human-readable delivery-chain
label; `exit_scope` pops both after the evaluation *including its children*.
Name identity in keys is ecosystem-scoped (`canonicalize_for_ecosystem`):
PEP 503 applies to PyPI only — npm/cargo/AUR `foo_bar` vs `foo-bar` are
distinct. The verdict schema (D7) carries the outcome in its `recursive`
field: `Vec<ChildReview>` with chain, band, score, and findings per child.

### Agent lane (`src/agent.rs`)

`agent review` (JSON verdict, exit 0/2, never marks clean) and `agent gate`
(hook binding policing one command line through the same scanner + engine).
Both load policy via `Policy::load_for_agent`, which **ignores
`BLUELINE_POLICY` unless `--policy` names the file** — ambient env is
attacker-shaped at the hook boundary — and warns on stderr when it does.
Redirect-capable env (`PIP_*`, `NPM_CONFIG_*`, `CARGO_*`) present at gate
time is disclosed by name (never value) in the reason and audit trail.

### Recall lane (`src/recall.rs`)

Curated revocation snapshot synced wholesale (`recall sync`, monotonic
`sequence`, backward moves refused without writing). Lookup normalizes
PyPI names on both sides (PEP 503) and compares versions by grammar
(`1.0` fires on `1.0.0`); other ecosystems match exactly. A hit BLOCKs via
the advisory engine *before* the `check_advisories` switch — disabling OSV
never silences recall — and never routes through the advisory cache.

### Shim lane (`src/shim.rs`)

Fail-closed bash shims for all eleven scanned managers (`npm`, `npx`,
`pnpm`, `yarn`, `bun`, `bunx`, `pip`, `pip3`, `cargo`, `yay`, `paru`)
routing through `agent gate --policy` before exec'ing the real binary.
Known bypasses stay documented in the README.

### Policy tables (`blueline.toml`)

| Table | Keys |
|---|---|
| `thresholds` | `max_low_score` (19), `max_medium_score` (49), `block_score` (80) |
| `policy` | `require_provenance`, `block_unreviewed_scripts`, `allow_git_dependencies`, `check_advisories`, `fail_closed_network` |
| `advisories` | `block_on_malware`, `block_on_critical_cve`, cache TTLs |
| `provenance` | `require_provenance`, `require_signatures`, `allowed_builders`, `allowed_repositories` (the last two enforced at Block) |
| `allowlist.packages` | exact `name` (+optional `ecosystem`), `allowed_scripts`, `allow_unreviewed_baseline` |
| `blocklist` | glob `packages` (+optional `ecosystem`), `maintainers` |
| `ci` | `fail_on`, `max_evaluations`, `include_dev` |
| `recursion` | `max_depth` (3, cap 16), `max_child_reviews` (8, cap 256), `child_block_band` (HIGH) |
| `recall` | `max_age_hours` (48), `block_on_stale` |

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

## 5. Defect policy

A defect is a defect regardless of when it arrived. "Pre-existing", "out of
scope", and "unrelated to this diff" describe the diff, not the bug, and none
of them is a reason to leave a hole in a tool whose whole promise is failing
loud on doubt.

Two consequences worth stating because they are easy to get wrong:

- **The store verifies its own schema.** `PRAGMA user_version` records how many
  migrations ran, not that they produced the schema the store queries. Opening
  checks every table and column in `EXPECTED_SCHEMA` directly
  (`src/store.rs::verify_schema`), so a file carrying a correct version counter
  with the wrong shape behind it is refused at open rather than failing
  mid-review on a missing column. The check is unconditional, so it also
  decides a lost migration race rather than a counter read.
- **A fix without a test that fails without it is a guess.** Mutation testing is
  the check on that: a surviving mutant is a gap in the suite, not a flake.
  Re-introduce the mutation, watch the test catch it, then restore.

