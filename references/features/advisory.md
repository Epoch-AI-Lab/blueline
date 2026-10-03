# Advisory

`src/advisory.rs`. OSV.dev revocation lookup with a SQLite cache. Protects the
property that **the local curated recall index is consulted before anything
else**, so disabling OSV never silences a revocation and a stale OSV cache entry
can never mask a fresh one.

## Sub-features
- `fetch_advisories` — the entry point.
- `osv_ecosystem` — the schema-cased mapping.
- `parse_osv_response` / `calculate_advisory_severity` / `check_is_malware`.
- `parse_cvss_vector` — hand-rolled CVSS v3.x calculator.
- `AdvisoryReport` / `AdvisoryItem` / `AdvisoryStatus`.
- `fallback_or_fail` — stale cache vs fail-closed vs unverified.

## How to get to it (user POV)
```sh
blueline review demo@1.0.0 --output json | jq '.trust_sources.advisories'
# {"status":"CLEAN","hits":[],"source":"osv.dev"}
blueline review demo@1.0.0 --output json | jq -r '.findings[] | select(.rule_id|startswith("R09"))'
```

## Driving it
Single endpoint: `POST https://api.osv.dev/v1/query`, no auth.
**There is no GitHub Advisory API call** — GHSA data arrives only via OSV
aliases. Headers: `Content-Type: application/json`,
`User-Agent: blueline-security/0.1.0`. `DEFAULT_TIMEOUT_MS = 3000`,
`MAX_OSV_RESPONSE_BYTES = 1 MiB`.

`osv_ecosystem` casing is load-bearing and pinned by
`osv_ecosystem_casing_matches_schema`:

| `Ecosystem` | OSV string |
|---|---|
| `Npm` | `npm` |
| `Cargo` | `CratesIO` |
| `PyPi` | `PyPI` |
| `Aur` | `AUR` (unreachable — no OSV AUR coverage) |

Cache TTLs come from `[advisories]`: clean `cache_ttl_hours_clean = 12`,
vulnerable `cache_ttl_hours_vulnerable = 1`. Chosen by `report.hits.is_empty()`,
not by status. `Unverified` and `StaleCache` reports are **never written** to the
cache.

Rule wiring: `R09_ADVISORY_MALWARE` (`Block`), `R09_ADVISORY_CRITICAL_CVE`
(`Block`), `R09_ADVISORY_CVE` (**`hit.severity` passed through verbatim**).

## Gotchas
- **The recall pre-check is the first statement in `fetch_advisories`.** A hit
  synthesizes an item with `severity: Block` **and `is_malware: true`**
  regardless of `block_on_malware`, and returns *before* the cache read and
  *before* `if !policy.policy.check_advisories`. Moving that block later makes
  `check_advisories = false` silence revocations; adding the hit to
  `put_cached_advisories` lets a stale row mask a fresh revocation. Both are
  named regressions in CHANGELOG.
- **`block_on_malware = false` does not soften a recall hit**, because
  `heuristic.rs` branches on `if hit.is_malware` → `Block` unconditionally. The
  flag only affects the `AdvisoryItem.severity` field the CVE branch reads.
- **`fallback_or_fail` ordering defeats `fail_closed_network`.** Priority is:
  (1) stale-but-parseable cache → `Ok(StaleCache)` **regardless of policy**;
  (2) `fail_closed_network` → `Err`; (3) `Ok(AdvisoryReport::unverified(..))`.
  Any expired-but-parseable row converts a hard network failure into a success
  even in strict mode.
- **`review.rs` converts `Err` to `unverified`, so `advisories` is always
  `Some`** and therefore `trust_sources` is always present in the verdict.
  Returning `None` on failure would delete the entire `trust_sources` block and
  destroy the evidence that the advisory lane ran. Do not "clean this up".
- **`AdvisoryReport::unverified` hardcodes `source: "osv.dev"`**, so wrapping a
  recall read error reports a lie. Read `status`/`message`, not `source`.
- **`fail_closed_network` has exactly one read site** and **cannot produce a
  BLOCK** — it only changes `status`/`message`. Its doc comment ("advisory or
  registry network calls") overstates it; provenance fetches are not gated.
- **A malformed-but-valid-JSON OSV response reads as CLEAN.** Every
  `OsvQueryResponse` field is `#[serde(default)]`, so `{"error":"rate limited"}`
  deserializes to an empty `vulns` → `AdvisoryReport::clean("osv.dev")`, which is
  then cached for 12 hours. There is no shape sanity check.
- **`is_malware` is an OR of four signals**, one of which is
  `v.id.starts_with("MAL-")` — prefix only. Any ID starting `MAL-` counts.
- **Unknown severity degrades to `Medium`, not `Low`** — deliberate fail-toward-
  disclosure. Combined with `max_medium_score: 49` this can move a band.
- **CVSS only parses `CVSS:3.0` / `CVSS:3.1`.** 2.0 and 4.0 vectors return
  `None`. Rounding is `ceil(x*10)/10` — always up. `extract_cvss_score` tries
  each entry as a bare float *then* as a vector, so an early vector beats a later
  float.
- **`check_advisories = false` renders identically to a network outage**
  (`[ UNVERIFIED ] unreachable (offline)`), which reads as a coverage hole.