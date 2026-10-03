# Blueline Feature Map

Materialized memory for agents working in this repo. Read this index, then
open only the lane you are touching.

Start with [../AGENTS.md](../AGENTS.md) (guardrails + CI gate) and
[../ARCHITECTURE.md](../ARCHITECTURE.md) (decision table D1–D11, rules
R24–R28). This map is the *how*, not the *why*.

Also read **[drift.md](drift.md)** — where the shipped code and the project's own
docs disagree, with evidence. Four of those entries are fail-open paths in a
tool whose premise is failing closed.

Every command below was run against the built binary; every limit is the
literal in `src/`. If a number here disagrees with the code, the code wins —
and fix this file in the same branch.

## Entry points

| Lane | What it is for | File |
|---|---|---|
| [CLI surface](features/cli.md) | clap definitions, global flag→registry-base derivation, exit-code contract | `src/cli.rs`, `src/main.rs`, `src/lib.rs` |
| [Verdict schema & typed errors](features/verdict.md) | the D7 JSON contract every surface shares; `BluelineError` variants | `src/verdict.rs`, `src/error.rs` |
| [Typed errors](features/error.md) | every `BluelineError` variant and the boundary that collapses them | `src/error.rs` |

## Engine spine

| Lane | What it is for | File |
|---|---|---|
| [Review orchestration](features/review.md) | the one function every surface funnels through: resolve → verify → extract → diff → score → disclose | `src/review.rs` |
| [Heuristics & scoring](features/heuristic.md) | rule engine, risk-score arithmetic, band escalation | `src/heuristic.rs` |
| [Extraction](features/extract.md) | bounded tar/wheel unpack, entry-type rejection, path validation | `src/extract.rs` |
| [Wheel extraction](features/wheel_extract.md) | the `.data/scripts` and `.data/data` payload split | `src/wheel_extract.rs` |
| [Diff](features/diff.md) | file/line delta, executable + binary classification | `src/diff.rs` |
| [Manifest parsing](features/manifest.md) | `package.json`, packed `Cargo.toml`, `.SRCINFO` | `src/manifest.rs` |
| [Render](features/render.md) | review card, JSON purity, terminal/BiDi sanitizers | `src/render.rs` |

## Trust sources

| Lane | What it is for | File |
|---|---|---|
| [Advisory](features/advisory.md) | OSV.dev query, CVE parsing, cache TTLs, recall pre-check | `src/advisory.rs` |
| [Recall index](features/recall.md) | local curated revocations: sync, serve, staleness (R28) | `src/recall.rs` |
| [Provenance](features/provenance.md) | in-toto/DSSE attestation *surfacing* (one digest is verified) | `src/provenance.rs` |

## State & policy

| Lane | What it is for | File |
|---|---|---|
| [Baseline selection](features/baseline.md) | D5: local clean store → registry predecessor → first sighting | `src/baseline.rs` |
| [Store](features/store.md) | SQLite schema, migrations, baseline-tamper guard, audit log | `src/store.rs` |
| [Policy](features/policy.md) | `blueline.toml` keys, defaults, validation, agent-mode policy loading | `src/policy.rs` |
| [Version grammars](features/version.md) | `VersionInfo` seam: semver, PEP 440, libalpm vercmp | `src/version.rs` |

## Registries

| Lane | What it is for | File |
|---|---|---|
| [Registry seam + npm/cargo/pypi](features/registry.md) | `Registry` trait, SSRF-guarded HTTP, integrity-typed fetch | `src/registry/{mod,http_util,npm,cratesio,pypi}.rs` |
| [AUR](features/aur.md) | git-history-backed review-only adapter, PKGBUILD root requirement | `src/registry/aur.rs` |
| [PKGBUILD heuristics](features/pkgbuild.md) | hand-rolled shell tokenizer + rules R11–R23 | `src/pkgbuild.rs` |

## Second-order lanes

| Lane | What it is for | File |
|---|---|---|
| [Install references](features/install_ref.md) | static scanner for package-manager invocations inside payloads | `src/install_ref.rs` |
| [Recursive review](features/recursive.md) | depth/budget caps, cycle detection, R24–R27 roll-up | `src/recursive.rs` |

## Agent-facing surfaces

| Lane | What it is for | File |
|---|---|---|
| [Agent lane](features/agent.md) | `agent review` / `agent gate` — non-interactive verdict and hook binding | `src/agent.rs` |
| [Shim](features/shim.md) | fail-closed PATH shims for eleven package managers | `src/shim.rs` |
| [MCP server](features/mcp.md) | JSON-RPC 2.0 stdio, three tools, `structuredVerdict` | `src/mcp.rs` |
| [Executor](features/executor.md) | D11: `npm install --ignore-scripts` with argv scrubbing | `src/executor.rs` |
| [CI](features/ci.md) | lockfile-delta PR gate, report rendering, band→exit | `src/ci.rs` |
| [Lockfile parsing](features/lockfile.md) | `package-lock.json` / `Cargo.lock` / `requirements.txt` parsers | `src/lockfile.rs` |

## Cross-cutting facts you will need on day one

- **Rule IDs collide by number.** `R02` covers five distinct production rules;
  `R09` covers four; `R00` and `R10` are emitted from two different modules.
  Never grep a bare `R0x` and assume one rule.
- **Scoring is shared, not duplicated.** `evaluate_with_trust` and
  `apply_extra_findings` both call `heuristic::score_findings` for the weight
  table and `Policy::escalate_band` for the threshold pass. One copy of each.
  The threshold pass never downgrades a band a finding already earned.
- **The engine is fail-closed at boundaries and fail-*loud* in the middle.**
  Unresolvable references, unreadable baselines, and cycle cuts become HIGH
  findings; only structural corruption becomes an `Err`.
- **Only `install` mutates `known_clean`.** `review` records `clean = 0` evidence;
  `agent review` does not even record.