# Phase 2 — Adversarial Threat Model & Verification Review

**Subject:** Security analysis, failure modes, and adversarial attacks on Trust Sources.
**Compiled:** 2026-08-16 · **Status:** Technical Specification & Research

---

## 1. Adversarial Attack Surfaces

### 1.1 Malicious Provenance (The "TanStack Bypass")
- **Attack:** An attacker compromises a project maintainer's GitHub account or CI secrets, pushes malware directly through the official GitHub Actions workflow, and publishes to npm. The package carries 100% valid Sigstore / SLSA Level 3 attestations.
- **Blueline Defense:**
  - Provenance is treated as an *advisory context signal*, not an authorization pass.
  - The diff engine still inspects every line of code delta between baseline and target.
  - Heuristics (network calls, obfuscation, lifecycle script additions) execute unconditionally.

### 1.2 Advisory Database Latency (The Zero-Day Window)
- **Attack:** An attacker publishes a malicious package. OSV / GHSA has not yet received or indexed the CVE / advisory (window: 2 hours to 5 days).
- **Blueline Defense:**
  - Local heuristic diffing remains the first line of defense.
  - New packages or major deltas without an existing known-clean baseline are elevated in risk (first-sighting bootstrap warning).

### 1.3 Advisory Cache Poisoning & Stale Cache Bypasses
- **Attack:** An attacker attempts to exploit cached "clean" status for a package that has since been revoked.
- **Blueline Defense:**
  - Positive ("vulnerable") cache records have an aggressive TTL (1 hour).
  - Negative ("clean") cache records expire after 12 hours.
  - CLI provides an explicit `--clear-advisory-cache` / `--fresh-advisories` flag.
  - SQLite cache is protected by strict file permissions (`0600`).

### 1.4 Network Denial-of-Service / MITM on OSV Query
- **Attack:** An attacker disrupts DNS or network access to `api.osv.dev` to force Blueline into an uninspected pass state.
- **Blueline Defense:**
  - In strict mode (`--strict-advisories` or `policy.fail_closed_network = true`), network failure forces an immediate `Verdict::Block`.
  - In standard mode, the terminal displays an explicit, un-ignorable warning badge indicating advisories were unverified.

### 1.5 JSON Memory & Recursion Bombs in Attestations
- **Attack:** Registry returns an attestation bundle with deeply nested in-toto statements or a 50MB base64 payload.
- **Blueline Defense:**
  - Bound network body read to 1MB maximum.
  - Enforce bounded `serde_json` parsing depth.

---

## 2. Phase-2 Security Checklist
- [ ] Tarball hash must strictly match both npm `dist.integrity` AND the in-toto subject digest.
- [ ] All external text (advisory summaries, GitHub repo URLs) must be sanitized with BiDi / ANSI escape blockers.
- [ ] No remote code execution or dynamic schema expansion during attestation validation.
- [ ] All database queries parameterized; migrations idempotent.
- [ ] Mutation testing (`cargo-mutants`) score maintained at 0 surviving mutants on the new advisory/provenance modules.
