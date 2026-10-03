# Verdict Schema & Typed Errors

`src/verdict.rs`, `src/error.rs`. This is decision D7: one `Verdict` struct
feeds the CLI card, the CI report, the MCP `structuredVerdict`, and `agent
review` stdout. Changing a field here is a breaking change for every consumer.

## Sub-features
- `VerdictBand { Low, Medium, High, Block }` — derives `Ord` **and** `ValueEnum`.
- `Verdict { name, target_version, baseline_version, integrity, ecosystem,
  band, risk_score, findings, diff_summary, trust_sources, recursive }`.
- `Finding { rule_id, severity, title, description }`.
- `DiffSummary`, `TrustSources { advisories, provenance }`, `ChildReview`.
- `BluelineError` — the `thiserror` enum; `anyhow` only at `main.rs`.

## How to get to it (user POV)
```sh
blueline --output json review express@4.21.2 | jq '.band, .risk_score'
blueline agent review express@4.21.2 | jq '.recursive'
blueline --output json review demo@1.0.0 | jq -r '.findings[] | "\(.severity) \(.rule_id)"'
```

## Driving it
Bands serialize UPPERCASE in JSON (`"LOW"|"MEDIUM"|"HIGH"|"BLOCK"`). CLI flags
accept lowercase plus `LOW`/`Low`/`HIGH`/`High` aliases (`ci --fail-on`).
`child_block_band` in `blueline.toml` is UPPERCASE.

Only two fields are omitted when empty: `trust_sources` (`Option::is_none`) and
`recursive` (`Vec::is_empty`). `baseline_version` is *always* emitted, as `null`.

## Gotchas
- **`VerdictBand` variant order IS the security order.** `Low < Medium < High <
  Block` is used pervasively as `if band < VerdictBand::High` and
  `child.band >= ctx.child_block_band()`. Reordering variants inverts every
  comparison in the codebase.
- **Four parsers of the same enum.** Hand-written `Display` (UPPERCASE), serde
  `rename_all = "UPPERCASE"`, clap `rename_all = "lower"` + aliases, and
  `ci::parse_band_str` (`Option` → `.unwrap_or(VerdictBand::High)`). A band edit
  must touch all four or the CI threshold silently becomes HIGH on a typo.
- **`baseline_version` has no `#[serde(default)]`.** Omitting it from a JSON
  document fails deserialization; `trust_sources` and `recursive` do default.
- **No schema version, no golden fixture, no compat check.** There is no
  `schema_version` field and no snapshot test over the verdict document. Renaming
  a field breaks `tests/support/cli.rs` readers silently. (`recall.rs` has its
  own `SNAPSHOT_SCHEMA: u64 = 1`, but that governs `recall_snapshot.json`, a
  different document.)
- **`risk_score` is `u32` and can exceed 100.** `ci.rs` does
  `risk_score.saturating_add(50)` for a lockfile hash mismatch with no
  re-`min(100)`. Rendering shows `/100`; the value may not match.
- **`BluelineError::Store` already renders as `"baseline store: {0}"`.** A call
  site that wraps it again produces the doubled prefix that CHANGELOG 0.1.0
  fixed. `recall.rs` still does this for a data-dir resolution failure.
- `LockfileError` implements `From<serde_json::Error>` manually instead of
  `#[from]` so `{e:#}` does not print the serde cause twice. Do not "simplify" it.
- `BluelineError::NotFound` is load-bearing beyond messaging: `recursive.rs`
  downcasts the error chain to pick **Medium** for an unresolvable referenced
  install, while every other failure becomes **High** ("Recursive review
  failed"). Widening the variant or losing it from the chain silently demotes
  real recursive-review failures.