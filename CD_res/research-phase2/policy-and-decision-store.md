# Phase 2 — Policy-as-Code & Decision Store Hardening

**Subject:** Policy-as-code schema extension and SQLite schema v2/v3 architecture.
**Compiled:** 2026-08-16 · **Status:** Technical Specification & Research

---

## 1. Objectives

Phase 2 deepens the trust model by:
1. Enabling teams to enforce deterministic, machine-readable security policies across repos (`blueline.toml`).
2. Persisting human audit decisions and rationale alongside cryptographic signatures in SQLite so approved deltas never demand duplicate review across team members.
3. Managing local cache storage for OSV advisories and provenance attestations with automatic TTL eviction.

---

## 2. Policy-as-Code Specification (`blueline.toml`)

The `blueline.toml` schema is expanded to support fine-grained trust, advisories, and lifecycle policies:

```toml
# blueline.toml — Security Policy Definition

[thresholds]
# Risk score ceilings for automated bands
low = 20
medium = 50
high = 80

[policy]
# Global fail-closed settings
fail_closed_network = false       # If true, network failure on OSV/registry aborts install
allow_unreviewed_baseline = false # Escalate baseline-less first sightings to MEDIUM

[policy.advisories]
block_on_malware = true          # Immediate BLOCK on known malicious tags
block_on_critical_cve = true     # Block on CVSS >= 9.0
max_allowed_cvss = 7.0           # Maximum CVSS score allowed before BLOCK
cache_ttl_hours = 12             # Local advisory cache duration

[policy.provenance]
require_provenance = false       # Reject packages without Sigstore / SLSA attestation
require_registry_signature = true # Verify npm ECDSA signature on tarball integrity
warn_on_repo_change = true       # Alert when build repo differs from baseline

[policy.scripts]
# Fine-grained lifecycle script policy
block_new_lifecycle_scripts = true
allowlist_scripts = [
    { package = "esbuild", allowed_commands = ["node install.js"] },
    { package = "core-js", allowed_commands = ["node postinstall.js"] }
]

[allowlist]
# Packages granted relaxed thresholds
packages = [
    "@my-org/*",
    "react",
    "react-dom"
]

[blocklist]
# Packages permanently barred
packages = [
    "malicious-typosquat-*",
    "event-stream@3.3.6"
]
```

---

## 3. SQLite Schema Evolution (Migration v2)

The baseline SQLite store (`store.rs`) currently tracks `known_clean` records (v1). Migration v2 introduces dedicated tables for advisories, attestations, and audit logs.

### Schema DDL (Migration v2)
```sql
-- Track advisory query responses and TTL
CREATE TABLE IF NOT EXISTS advisory_cache (
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    advisories_json TEXT NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0,
    has_blocking_advisory INTEGER NOT NULL DEFAULT 0,
    fetched_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (package, version)
);
CREATE INDEX IF NOT EXISTS idx_advisory_cache_expiry ON advisory_cache(expires_at);

-- Track provenances and signatures
CREATE TABLE IF NOT EXISTS provenance_cache (
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    builder_id TEXT,
    source_repo TEXT,
    commit_sha TEXT,
    workflow_path TEXT,
    slsa_level INTEGER DEFAULT 0,
    signature_valid INTEGER NOT NULL DEFAULT 0,
    verified_at INTEGER NOT NULL,
    PRIMARY KEY (package, version)
);

-- Persisted human audit trail
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    integrity TEXT NOT NULL,
    action TEXT NOT NULL,         -- 'approve', 'hold', 'block', 'policy_override'
    score INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    decided_by TEXT NOT NULL,     -- OS username / CI actor
    notes TEXT,
    decided_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_pkg_ver ON audit_log(package, version);
```

---

## 4. Rust Engine Implementation Plan

1. **`src/policy.rs`**:
   - Add typed subsections: `AdvisoriesConfig`, `ProvenanceConfig`, `ScriptsPolicyConfig`.
   - Implement hierarchical merge: CLI flag overrides > `./blueline.toml` > `~/.config/blueline/config.toml` > Hardcoded defaults.
2. **`src/store.rs`**:
   - Add migration script `v2` using `rusqlite_migration`.
   - Add cache access methods: `get_cached_advisories()`, `put_advisories()`, `record_audit_decision()`.
   - Maintain WAL mode and strict transactional safety.
