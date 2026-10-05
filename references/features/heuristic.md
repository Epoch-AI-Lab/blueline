# Heuristics & Scoring

`src/heuristic.rs` (3337 lines, the largest module). Turns a `Delta` plus
trust sources into findings, a risk score, and a band. This lane *decides*, so
its arithmetic is the most load-bearing thing in the repo.

## Sub-features
- `evaluate_with_trust(...)` — the live entry point (11 positional args).
- `evaluate` / `evaluate_with_policy` — `#[allow(dead_code)]`, test-only paths.
- `apply_extra_findings` — late findings (R11–R28) rescored from scratch.
- `normalize_js` — 4-stage JS deobfuscation pipeline.
- Detectors: eval/child_process/VM/network/base64/entropy, homoglyph, repo allow.

## How to get to it (user POV)
```sh
blueline review demo@1.0.0 --output json | jq '.findings[] | {rule_id, severity}'
blueline review demo@1.0.0 --output json | jq '.risk_score'
```

## Driving it
Scoring loop (verified in source, duplicated at lines ~612 and ~686):

| Finding severity | Score add | Band effect |
|---|---|---|
| `Block` | `+50` | `band = Block` **latched unconditionally** |
| `High` | `+25` | `band = max(band, High)` |
| `Medium` | `+10` | `band = max(band, Medium)` |
| `Medium` **and** `rule_id == "R06_FIRST_SIGHTING"` | `+15` | same |
| `Low` | `+0` | none |

`risk_score = min(100, sum)`. Escalation (policy thresholds, defaults
`19 / 49 / 80`):

```rust
if capped >= block_score        { band = Block }        // >=
else if capped > max_medium     && band < High  { band = High }   // strict >
else if capped > max_low        && band < Medium{ band = Medium } // strict >
```

Effective bands: **≤19 LOW, 20–49 MEDIUM, 50–79 HIGH, ≥80 BLOCK** — but four
HIGH findings (100) are needed to reach BLOCK by accumulation, because 3×25=75.

Policy outcomes in the same function: `P01_PACKAGE_BLOCKED`,
`P02_LIFECYCLE_SCRIPT_ALLOWED`, `P02_BINDING_GYP_ALLOWED`,
`P03_PROVENANCE_DIGEST_MISMATCH`, `P03_PROVENANCE_REQUIRED_MISSING`,
`P03_SIGNATURE_REQUIRED_MISSING`, `P03_UNAUTHORIZED_BUILD_REPO`.

## Gotchas
- **Rule IDs collide by number.** `R02` = `EXECUTABLE_ADDED`,
  `OPAQUE_LARGE_FILE_ADDED`, `BINARY_BLOB_ADDED`, `BINARY_BLOB_MODIFIED`,
  `ENTRY_POINTS_SCRIPT`. `R09` = three advisory ids + `YANKED_TARGET`. `R06` =
  `FIRST_SIGHTING` (15 pts) and `NATIVE_PLATFORM_WHEEL` (0 pts). `R00`/`R10` are
  emitted from `review.rs`/`pkgbuild.rs`/`ci.rs`. Grep the full id, never `R02`.
- **The scoring block is shared, not copy-pasted.** `score_findings` owns the
  weight table including the single `rule_id == "R06_FIRST_SIGHTING"` string
  special case; `Policy::escalate_band` owns the threshold pass.
  `evaluate_with_trust` and `apply_extra_findings` both call them, so a late
  PKGBUILD/R24–R28 finding moves the band on the same terms as an original one.
- **The threshold pass never downgrades.** A band earned by a specific finding
  outranks the band the score alone would imply, so a BLOCK finding stays BLOCK
  even when its score lands in the HIGH range. `escalate_band` takes the
  finding-earned band as `current` and only ever moves it up.
- **Renaming or re-banding a rule changes the score.** Promoting a `Low` finding
  to `Medium` adds 10; two of them (20) cross `max_low_score: 19` and flip a
  LOW verdict to MEDIUM. `R02_ENTRY_POINTS_SCRIPT` alone is enough.
- **`allow_unreviewed_baseline` zeroes risk but keeps the finding visible.**
  R06/R07 become `Low` (0 points), so `--yes` auto-approves a first sighting.
  `allow_unreviewed_baseline_downgrades_bootstrap_findings_without_hiding_them`
  asserts the finding still exists. Do not delete downgraded findings.
- **`R01_LIFECYCLE_SCRIPT_ADDED` can be BLOCK (default);
  `R01_LIFECYCLE_SCRIPT_MODIFIED` is always HIGH.** Editing a maintainer's
  existing `postinstall` is treated more leniently than adding one.
- **`normalize_js` strips whitespace *inside string literals*.**
  `"hello world"` → `"helloworld"`, so `'base 64'` and `'child_ process'`
  evade the detectors. And `//` outside quotes truncates the rest of the line —
  `detects_eval_after_inline_url` only covers the *quoted* case.
- **`fold_char_code_calls` memoizes but invalidates the whole cache on every
  successful fold.** It is pinned by a perf test (`elapsed.as_secs() < 10` on
  200,000 unparseable markers) and by surrogate/out-of-range/u32-overflow cases.
- **`is_non_semver_url` has a 10-element `PREFIXES` array with no test.** Any
  entry added or reordered is unverifiable by the suite today. `git` (no colon)
  is a bare prefix; `npm:` is a prefix too.
- **FP traps that are deliberate:** `Buffer.from(x,'hex')` fires
  `R03_BASE64_DECODE`; any identifier ending in `from` followed by a quoted
  module name matches `contains_module_import` (the only prefix matcher without
  an identifier-boundary check); `has_child_proc_invocation` has no import gating,
  so a comment mentioning "cluster" fires HIGH.
- **`is_ignorable_js_char` (heuristic) and `is_dangerous_unicode` (render) are
  different lists.** The heuristic list omits `U+061C`; the render list omits
  `U+00AD`, `U+2060`, `U+180E`. Do not unify them without re-running both test
  sets.