# Phase 3 — CI & Agents: Master Plan

**Subject:** Architectural blueprint, implementation milestones, and verification checklist for Phase 3.  
**Compiled:** 2026-08-17 · **Status:** Master Plan (CDRes Mode 4)

---

## 1. Overview & Objectives

Phase 3 embeds Blueline into automated workflows, expanding protection from individual developer interactive terminals to **automated pull requests (CI)** and **AI coding agents (MCP)**:
> **Hard rule: nothing executes until judged. Automated pipelines and autonomous agents must enforce the review gate before dependencies run.**

### Key Deliverables:
1. **`blueline ci` Subcommand & GitHub Composite Action:**
   - Detects added/upgraded packages from `package-lock.json` across Git base refs (`origin/main...HEAD` or `$GITHUB_BASE_REF`).
   - Evaluates risk verdicts for all changed packages.
   - Emits Markdown tables to `$GITHUB_STEP_SUMMARY` and posts PR status checks / comments.
   - Configurable exit-code policy (`policy.ci.fail_on`).
2. **Model Context Protocol (MCP) Server (`blueline mcp`):**
   - JSON-RPC 2.0 stdio server providing `review_install`, `check_known_clean`, and `inspect_diff` tools for AI agents.
   - Strict `stdout` hygiene and robust error containment.
3. **CI Top-Tier Hardening:**
   - `cargo-deny` configuration (`deny.toml`) for license compliance and crate bans.
   - `cargo-fuzz` fuzzing harness (`fuzz/`) for untrusted tarball and manifest parsing.

---

## 2. Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             BLUELINE ENGINE (PHASE 3)                       │
├───────────────────────────────────┬─────────────────────────────────────────┤
│ 1. LOCKFILE DIFF ENGINE           │ 2. CI SUBCOMMAND (`blueline ci`)        │
│ • npm Lockfile v1/v2/v3 Parser    │ • Base ref git extraction (non-mutating)│
│ • Package delta resolution        │ • Summary card & markdown generator     │
│ • Batch evaluation engine         │ • $GITHUB_STEP_SUMMARY / PR comment     │
├───────────────────────────────────┼─────────────────────────────────────────┤
│ 3. MCP SERVER (`blueline mcp`)    │ 4. TOP-TIER CI HARDENING                │
│ • JSON-RPC 2.0 stdio transport    │ • `deny.toml` (licenses & banned crates)│
│ • Tools: `review_install`,        │ • `cargo-fuzz` suite for extraction     │
│   `check_known_clean`, `diff`     │ • Mutation test suite continuation      │
└───────────────────────────────────┴─────────────────────────────────────────┘
```

---

## 3. Step-by-Step Implementation Sequence

### Stage 1: Lockfile Parser & Delta Extractor (`src/lockfile.rs`)
- Parse `package-lock.json` versions (v1 hierarchical `dependencies`, v2/v3 flattened `packages`).
- Compute delta between base lockfile and current lockfile.
- Return structured list of changed package specs: `(name, old_version, new_version, integrity)`.

### Stage 2: CI Subcommand & Review Loop (`src/ci.rs`)
- Extract base lockfile using `git show <base_ref>:<path>`.
- Iterate through modified packages, running the review pipeline (`review::review_package_against`).
- Format combined CI summary report (Markdown table + verdict breakdown).
- If `$GITHUB_STEP_SUMMARY` is set, append summary to it.
- Determine exit code based on `policy.ci.fail_on`.

### Stage 3: MCP Server (`src/mcp.rs`)
- Implement JSON-RPC 2.0 line-oriented transport on `stdin`/`stdout`.
- Register tools: `review_install`, `check_known_clean`, `inspect_diff`.
- Implement strict error handling and ensure all diagnostics use `stderr`.

### Stage 4: GitHub Composite Action (`.github/actions/blueline-ci/action.yml`)
- Package `blueline ci` into a reusable composite GitHub Action.
- Provide inputs for `base-ref`, `fail-on`, `lockfile-path`, and `github-token`.

### Stage 5: Supply Chain & Parser Hardening
- Add `deny.toml` and wire `cargo deny check` into CI.
- Setup `fuzz/` crate with `safe_extract` and `read_package_json` targets.

---

## 4. Verification & Testing Strategy

1. **Unit & Property Tests:**
   - Unit tests for v1, v2, and v3 `package-lock.json` parsing.
   - Proptest for lockfile diffing invariant (no added package is missed).
   - Mock JSON-RPC test harness for MCP requests and responses.
2. **Integration Tests (`tests/ci.rs`, `tests/mcp.rs`):**
   - End-to-end CLI test for `blueline ci` against test git repositories.
   - End-to-end stdio testing for `blueline mcp` message exchanges.
3. **CI Gate Verification:**
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo test --all-targets --locked`
   - `cargo-mutants` (0 surviving mutants on new modules).

---

## Adversarial Verification
- Stdio bleed prevention: Verified all logger outputs routed to `stderr`.
- Git execution safety: Verified no shell invocation or path injection risks.
- Lockfile version compatibility: Tested across v1, v2, and v3 schemas.
- Status: GREEN
