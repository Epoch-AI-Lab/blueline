# Phase 2 — Trust Sources & Intelligence: Master Plan

**Subject:** Comprehensive architectural roadmap, implementation phases, and verification checklist for Phase 2.
**Compiled:** 2026-08-16 · **Status:** Master Plan

---

## 1. Overview & Objectives

Phase 2 transitions Blueline from an isolated, purely local diff heuristic engine into a **connected, intelligence-augmented security review desk** without compromising its core rule:
> **Approve the delta, not the download. Nothing executes until judged.**

### Key Deliverables:
1. **OSV & GitHub Advisory Revocation Engine:** Real-time query + local SQLite caching for CVEs and active malware revocations.
2. **Provenance & Sigstore / SLSA Surfacing:** Cryptographic build attestation and npm registry signature validation, presented as context (never blind trust).
3. **Policy-as-Code (`blueline.toml`):** Configurable thresholds, CVE tolerances, and provenance enforcement per repository.
4. **SQLite Schema v2:** Persistent advisory cache, attestation records, and structured human audit trails.
5. **Updated Review Card & JSON Schema v2:** Clean terminal proof sheet with Trust Source blocks and stable JSON output.

---

## 2. Component Architecture & Work Breakdown

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             BLUELINE ENGINE (PHASE 2)                       │
├───────────────────────────────────┬─────────────────────────────────────────┤
│ 1. TRUST SOURCES CLIENT           │ 2. SQLITE STORE (v2)                    │
│ • OSV.dev REST API Client         │ • `advisory_cache` (12h TTL)            │
│ • npm Attestations & Keys Client  │ • `provenance_cache`                    │
│ • Strict Body/Timeout Caps (1MB)  │ • `audit_log` (Decisions trail)         │
├───────────────────────────────────┼─────────────────────────────────────────┤
│ 3. HEURISTIC & VERDICT ESCALATION │ 4. POLICY ENGINE (`blueline.toml`)      │
│ • Malware / Critical CVE → BLOCK  │ • `[policy.advisories]`                 │
│ • High CVE → High Severity        │ • `[policy.provenance]`                 │
│ • Provenance Drift Detection      │ • Script allowlists & blocklists        │
├───────────────────────────────────┼─────────────────────────────────────────┤
│ 5. TERMINAL PROOF SHEET & CLI     │ 6. AUTOMATED CI GATE & ADVERSARIAL TEST │
│ • Trust Sources ASCII Block       │ • 0 Surviving Mutants (`cargo-mutants`) │
│ • BiDi/ANSI Escaped Text Sanitizer│ • Property-based invariants (proptest)  │
│ • JSON Verdict Schema v2          │ • Mock offline / online test suites     │
└───────────────────────────────────┴─────────────────────────────────────────┘
```

---

## 3. Implementation Sequence

### Stage 1: Data Models & SQLite Schema v2
- Add migration `v2` in `src/store.rs` (`advisory_cache`, `provenance_cache`, `audit_log`).
- Implement cache lookup, storage, and TTL invalidation logic.

### Stage 2: OSV Advisory Client & Engine
- Implement `src/advisory.rs` with `ureq` blocking client for `https://api.osv.dev/v1/query`.
- Implement timeout bounds, body size caps, and error fallback modes.
- Integrate advisory scoring into `src/heuristic.rs`.

### Stage 3: Provenance & Attestation Extractor
- Implement `src/provenance.rs` to fetch and parse in-toto / SLSA v0.2/v1.0 bundles from `dist.attestations`.
- Verify digest match between tarball sha512 and in-toto subject.
- Surface repository URL, commit SHA, workflow path, and builder ID.

### Stage 4: Policy Extension (`src/policy.rs`)
- Expand TOML parser to handle `[policy.advisories]` and `[policy.provenance]`.
- Enforce strict blocking rules when policy constraints are violated.

### Stage 5: Terminal Card Rendering & Stable JSON Output
- Update `src/render.rs` to include the Trust Sources card section.
- Update `src/verdict.rs` to output JSON Schema v2 with full trust metadata.

### Stage 6: Hardening, Integration Tests & Mutation Verification
- Write unit tests against mock HTTP responses (offline/clean/malware/CVE).
- Run `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo mutants` across new modules.
