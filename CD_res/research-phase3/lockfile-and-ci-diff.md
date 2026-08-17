# Phase 3 Research: Lockfile Parsing & CI Scanning (`blueline ci`)

**Topic:** Lockfile diffing, Git base resolution, CI exit code policies, and GitHub Actions PR commenting.  
**Compiled:** 2026-08-17 · **Status:** Implementation Research (CDRes Mode 4)

---

## 1. The Task & Scope

Enable Blueline to run inside CI pipelines (GitHub Actions, GitLab CI, local pre-commit hooks) to inspect lockfile and `package.json` diffs across a Git revision range (e.g. `origin/main...HEAD` or PR base to head):
- Command: `blueline ci [--base <ref>] [--lockfile <path>] [--format text|json|markdown|sarif] [--fail-on <level>]`
- Parse changed dependencies across npm lockfiles (v1, v2, v3) and detect newly added or upgraded packages.
- Run the Blueline verification engine (`heuristic`, `advisory`, `provenance`, `policy`) for all package deltas.
- Output a comprehensive Markdown summary to `$GITHUB_STEP_SUMMARY` and optionally post PR comments via GitHub REST API if `$GITHUB_TOKEN` is present.
- Fail closed with exit code `1` if any package triggers `BLOCK` or exceeds the configured policy threshold (`policy.ci.fail_on`).

---

## 2. Common Gotchas

1. **Shallow Clones in CI (`actions/checkout` default `fetch-depth: 1`):**
   - *Gotcha:* In GitHub Actions, `actions/checkout@v4` defaults to `fetch-depth: 1`. Attempting to run `git diff origin/main...HEAD` or `git show origin/main:package-lock.json` will fail with `fatal: bad revision` because the base commit does not exist locally.
   - *Source:* GitHub Actions checkout documentation; standard CI git shallow-fetch behavior.
   - *Mitigation:* `blueline ci` must first check if the target base ref is reachable via `git rev-parse --verify <ref>`. If missing, check `GITHUB_BASE_REF` / fetch the base ref, or fallback gracefully with an explicit error explaining `fetch-depth: 0` / unshallow requirement.

2. **npm Lockfile v1 vs v2 vs v3 Structural Variance:**
   - *Gotcha:* 
     - **v1 (`lockfileVersion: 1`):** Hierarchical `dependencies` tree with nested child dependencies.
     - **v2 (`lockfileVersion: 2`):** Dual structure containing both `dependencies` and flattened `packages` (`"node_modules/foo"`).
     - **v3 (`lockfileVersion: 3`, npm 9+):** Orompts out top-level `dependencies` completely; flattened `packages` map only.
   - *Source:* npm RFC for lockfile v3 (`rfcs/accepted/0042-lockfile-v3.md`).
   - *Mitigation:* Implement a unified lockfile parser using `serde_json` that normalizes `packages` (preferred for v2/v3) and falls back to walking `dependencies` (v1). Extract a flat set of `(name, version, integrity, resolved_url)`.

3. **Lockfile Churn & Metadata-Only Diffs:**
   - *Gotcha:* `package-lock.json` files frequently churn due to npm version differences (e.g. `requires: true` or formatting reorders) without actual version or dependency additions.
   - *Source:* npm issues on lockfile churn across minor Node releases.
   - *Mitigation:* Diff the *parsed dependency maps* rather than raw text lines. Only evaluate packages where `version` or `integrity` changed or where a package key was newly introduced.

4. **Rate Limiting & Network Parallelism in CI:**
   - *Gotcha:* A large PR might update 50+ packages. Running sequential tarball downloads, diff extractions, and OSV lookups could cause CI timeouts or registry rate-limiting (HTTP 429).
   - *Source:* npm registry and OSV.dev rate limit guidelines.
   - *Mitigation:* 
     - Batch OSV batch query API (`https://api.osv.dev/v1/querybatch`) for advisories.
     - Cache known-clean versions in CI via GitHub Action cache (`~/.cache/blueline` or `~/.local/share/blueline`).
     - Cap maximum concurrent reviews (or bound review depth for transitive devDependencies).

---

## 3. Best Practices & Idiomatic Design

1. **Deterministic Git Base Extraction without Working Tree Mutation:**
   - Use `git show <base_ref>:<lockfile_path>` via a standard process invocation (`std::process::Command`) to stream the base lockfile content into memory.
   - Never mutate the user's working copy or check out git branches.

2. **Standard Output Channels & GitHub Step Summaries:**
   - If `$GITHUB_STEP_SUMMARY` environment variable exists and is a writable file path, append the rendered Markdown review card table directly to it.
   - Write machine-readable output to `stdout` (or formatted text table), and diagnostic logs to `stderr`.

3. **Configurable CI Policy via `blueline.toml`:**
   ```toml
   [policy.ci]
   fail_on = "high"             # "low" | "medium" | "high" | "block"
   comment_on_pr = true
   ignore_dev_dependencies = false
   max_package_evaluations = 50 # fail closed if PR diff is suspiciously enormous
   ```

4. **SARIF / Static Analysis Report Format:**
   - Support emitting SARIF 2.1.0 (`--format sarif`) so GitHub Code Scanning can natively display Blueline findings in the PR "Files changed" security tab.

---

## 4. Pitfalls & Language Quirks (Rust)

1. **Subprocess Spawning & PATH Injection:**
   - When invoking `git` for base extraction, use direct arguments without shell execution (`sh -c` or `bash -c`) to prevent command injection.
   - Enforce argument boundary safety (e.g. `--` separators).

2. **Large Lockfiles in Memory:**
   - Multi-megabyte enterprise `package-lock.json` files can contain tens of thousands of lines.
   - Streaming JSON parsing with `serde_json::from_reader` or bounded buffer allocation prevents unbounded memory spikes.

---

## 5. Differentiation

- **Industry Standard:** Dependabot, Snyk, or Renovate check for known CVEs in lockfiles (static metadata only).
- **Blueline CI Differentiator:** Blueline actually **fetches and diffs the package tarballs themselves**, auditing newly added lifecycle scripts, obfuscated code, and SLSA provenance in addition to CVE advisories.
- **Usefulness:** Catches zero-day malicious takeovers and untrusted release deltas that have no CVE assigned yet.

---

## Adversarial Verification
- Git base resolution edge cases (detached HEAD, shallow clones, merge commits): Handled with fallback detection.
- Lockfile schema compatibility: Tested against v1, v2, and v3 npm lockfiles.
- Exit code determinism: Exit 0 only on policy compliance; non-zero on violation or extraction error.
- Status: GREEN
