# Phase 2 — Trust Sources & Intelligence Research: OSV & Advisory Revocation

**Subject:** Design, protocol specification, and fail-closed architecture for OSV and GitHub Advisory integration in Blueline.
**Compiled:** 2026-08-16 · **Status:** Technical Specification & Research

---

## 1. Threat Model & Rationale

Blueline Phase 1 evaluates diffs purely via local deterministic heuristics (syntactic changes, install scripts, obfuscation, binary additions). However, two classes of risk bypass local heuristic diffing:
1. **Known Revoked / Malicious Releases:** Packages already identified as malware or critical zero-days by the security community (e.g., typosquats, credential stealers) where the diff may mimic legitimate refactoring.
2. **Disclosed CVEs in Legitimate Code:** Upstream bugs (e.g., prototype pollution, path traversal in helper utilities) that do not trigger binary or shell execution heuristics.

Phase 2 introduces **Advisory Intelligence (D6)** to cross-reference target packages against the global open-source vulnerability database (OSV.dev / GitHub Advisory Database) before rendering the verdict.

---

## 2. Advisory Sources & Protocols

### 2.1 OSV.dev REST API
- **Endpoint:** `POST https://api.osv.dev/v1/query` (single query) or `POST https://api.osv.dev/v1/querybatch` (batch query).
- **Request Payload:**
  ```json
  {
    "version": "1.2.3",
    "package": {
      "name": "express",
      "ecosystem": "npm"
    }
  }
  ```
- **Response Payload:**
  ```json
  {
    "vulns": [
      {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Prototype pollution in express",
        "details": "...",
        "aliases": ["CVE-2024-XXXXX"],
        "modified": "2026-01-10T12:00:00Z",
        "published": "2026-01-08T00:00:00Z",
        "database_specific": {
          "severity": "HIGH",
          "github_reviewed": true
        },
        "severity": [
          {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        ],
        "affected": [
          {
            "package": {
              "name": "express",
              "ecosystem": "npm"
            },
            "ranges": [
              {
                "type": "SEMVER",
                "events": [
                  { "introduced": "1.0.0" },
                  { "fixed": "1.2.4" }
                ]
              }
            ]
          }
        ]
      }
    ]
  }
  ```

### 2.2 Protocol Invariants for Blueline
1. **Strict Timeout & Bounded Response:**
   - Network requests to `api.osv.dev` must use a strict timeout (default: 3000ms).
   - Response bodies must be capped (e.g., max 1 MB) to prevent memory exhaustion DoS.
2. **Fail-Closed vs Fail-Safe Policy:**
   - On network timeout or DNS failure:
     - By default in interactive CLI: Warn on terminal (`[!] OSV advisory database unreachable (offline mode)`), continue with local heuristics, but record advisory status as `unverified`.
     - In strict mode (`--strict-advisories` or `policy.advisories.fail_closed = true`): Fail closed with `Verdict::Block` if advisories cannot be verified.
3. **Ecosystem & Name Sanitization:**
   - Package name is normalized and validated against standard npm naming rules before interpolation into query payloads.

---

## 3. Local SQLite Advisory Cache

To preserve Blueline's sub-second local review speed and enable offline verification, advisory queries are backed by an SQLite cache.

### 3.1 SQLite Schema (Migration v2)
```sql
CREATE TABLE IF NOT EXISTS advisory_cache (
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    advisories_json TEXT NOT NULL,       -- Serialized Vec<AdvisorySummary>
    hit_count INTEGER NOT NULL DEFAULT 0,
    has_blocking_advisory INTEGER NOT NULL DEFAULT 0,
    fetched_at INTEGER NOT NULL,         -- Unix epoch seconds
    expires_at INTEGER NOT NULL,         -- Unix epoch seconds (TTL default 12 hours)
    PRIMARY KEY (package, version)
);

CREATE INDEX IF NOT EXISTS idx_advisory_expiry ON advisory_cache(expires_at);
```

### 3.2 Cache Lifecycle & TTL
- **Default TTL:** 12 hours for negative hits (clean), 1 hour for positive hits (vulnerabilities may receive fast retraction or updated metadata).
- **Stale Cache Handling:** If offline and cache is expired, Blueline uses stale cached advisories with an explicit `(stale cache)` warning badge in the review card.

---

## 4. Verdict Integration & Scoring Rules

Advisories map directly to verdict bands in [heuristic.rs](file:///home/kriday/Desktop/code/blueline/src/heuristic.rs):

| Advisory Classification | Criteria | Verdict Impact | Score Weight |
|-------------------------|----------|----------------|--------------|
| **Malicious / Malware** | Tagged as `MALWARE`, `npm-malicious`, or withdrawn as security risk | **`Verdict::Block`** (Hard failure) | +100 (Instant Block) |
| **Critical CVE** | CVSS Score $\ge 9.0$ or GitHub Severity `CRITICAL` | **`Verdict::Block`** | +50 |
| **High CVE** | CVSS Score $7.0 - 8.9$ or GitHub Severity `HIGH` | **`Verdict::High`** | +30 |
| **Medium / Low CVE** | CVSS Score $< 7.0$ | **`Verdict::Medium`** | +15 |

---

## 5. Security & Invariant Rules
- **No Remote Code in Advisory Parsing:** Deserialization parses into strictly typed Rust structs; unexpected fields are ignored.
- **BiDi / ANSI Sanitization:** Advisory titles and summaries are passed through the existing `render::sanitize_line` filter to prevent terminal injection.
