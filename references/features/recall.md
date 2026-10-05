# Recall Index

`src/recall.rs` (1120 lines). The local-first curated revocation snapshot:
R28. Protects the property that **the index fails loud, not silent** — a stale
index is disclosed, an unreadable one is HIGH, and a backward `sequence` is
refused without writing.

## Sub-features
- `Snapshot` / `Revocation` / `SyncedSnapshot` + `SNAPSHOT_SCHEMA: u64 = 1`.
- `Snapshot::validate` — all-or-nothing.
- `lookup` / `cached_load` / `SNAPSHOT_CACHE`.
- `versions_match` / `names_match`.
- `stale_band` / `stale_band_at` (R28).
- `sync` (client) and `serve` (loopback service).

## How to get to it (user POV)
```sh
blueline recall sync --url http://127.0.0.1:7979
# synced recall snapshot: sequence 7, 412 revocations
blueline recall serve --port 7979 --snapshot revocations.json
# recall index serving on http://127.0.0.1:7979/revocations.json
blueline recall export-candidates --out candidates.json --limit 1000
```
`snapshot_path()` = `$BLUELINE_DATA_DIR/recall_snapshot.json`, else
`dirs::data_dir()/blueline/recall_snapshot.json`.

## Driving it
| Constant | Value |
|---|---|
| `MAX_SNAPSHOT_BYTES` | `8 * 1024 * 1024` (8388608) |
| `MAX_ENTRIES` | `10_000` |
| `MAX_TEXT_BYTES` (reason/id) | `512` |
| name length cap | `214` |
| `TIMESTAMP_SKEW_SECS` | `300` |
| `HTTP_READ_TIMEOUT_SECS` | `30` |

`sync` fetches `{url trimmed of trailing '/'}/revocations.json`, reads with
`.take(MAX + 1)`, refuses a backward `sequence` **before any write**, then writes
`recall_snapshot.json.tmp-<pid>` and `fs::rename`s. Equal sequence is accepted
and idempotent.

`serve` binds `("127.0.0.1", port)` — **IPv4 loopback only, hardcoded**.
`--port 0` gets an ephemeral port; the real port comes from `local_addr()` and is
printed on stdout. Routes: `/revocations.json` (exact file bytes) and `/health`
(`ok`); everything else 404.

`versions_match`: identity fast path first, then `Ecosystem::Npm | Cargo => false`
(dead arm — strict semver has no distinct-but-equal spellings), PyPI via
`Pep440Version` equality (`1.0` fires on `1.0.0`), AUR via `AurVersionInfo`
(pkgrel dropped, so `1.0` matches `1.0-1`). Either-side parse failure → `false`.

`stale_band`: absent file → `Ok(None)`; `age > max_age_hours * 3600` →
`block_on_stale ? Block : Medium`; corrupt/oversized → `Err`.

## Gotchas
- **The npm/cargo `=> false` arm is a deliberate dead arm**, pinned by
  `versions_match_equivalence_and_fallback`. Making npm recall matching "smarter"
  (semver ranges, `^1.0.0`) is a security regression, not a feature.
- **PEP 503 normalization applies on *both* sides and only for PyPI**
  (`lookup_normalizes_pypi_names_and_versions` pins that npm `foo_bar` does
  **not** fire on `foo-bar`).
- **R28 mapping:** `Ok(Some(band))` → finding at that band; `Ok(None)` → nothing;
  `Err(e)` → `R28_RECALL_STALE` at **High** with the message carrying `{e:#}`.
- **`serve` must validate *before* binding.** Otherwise an oversized index prints
  its banner and hangs forever accepting connections. `serve_refuses_oversized_index_at_startup`
  is the reusable shape for any new "must refuse, not hang" startup path:
  spawn the real binary via `std::process::Command` (not `assert_cmd::Command`,
  which hides `try_wait`/`kill`), pipe both stdios, poll `try_wait()` every
  20 ms against `Instant::now() + Duration::from_secs(10)`, then
  `child.kill(); child.wait(); panic!("oversized index hung serve instead of
  refusing at startup")`, and finally assert exit code `Some(1)` plus a stderr
  substring. Use `--port 0`.
- **The serve banner format is a load-bearing contract.** Both
  `serve_serves_at_cap_snapshot_with_health_endpoint` and
  `tests/recall_cli.rs::spawn_recall_server` read **one line of stdout** and
  split on the literal `"http://127.0.0.1:"`.
- **`load_at` is not stream-bounded.** It does `fs::read_to_string` and *then*
  checks the length, so a hostile multi-GB local file is fully resident before
  refusal. Only `sync` bounds the read.
- **`SNAPSHOT_CACHE` is a `OnceLock` single slot keyed only by mtime, not by
  path.** `set` is write-once, so the first writer wins for the process.
  `cached_load_hits_on_same_mtime_and_misses_on_change` has to future-date the
  probe mtime by 60 s to avoid a cross-test collision. Preserve that dance.
- **Two sides of the same predicate use different operators**, and both are
  pinned at the boundary: `load_at` rejects `> MAX`, `index_size_within_cap`
  accepts `<= MAX`. `stale_band_at` uses `age > max` (exactly at the window is
  *fresh*).
- **Validation is all-or-nothing** and includes: `all_versions == true` with a
  non-empty `versions` is "ambiguous" and rejected; every listed version must
  parse for its ecosystem.
- **`Snapshot::validate()` runs on every uncached `load_at`**, re-parsing every
  version string of every entry. That is the dominant cost of the lane.
- **`lookup` is a linear `find` over up to 10,000 entries** with a per-entry
  `canonicalize_name` allocation for PyPI. Mitigated only by `SNAPSHOT_CACHE`.
- **`sync` requires no auth and no TLS.** Anyone who can answer that request
  controls revocations. `serve` is loopback-only; `sync` will fetch `http://`.
- The padding fixtures (`snapshot_padded_to_bytes`) search for a *valid*
  snapshot of an exact byte length and `panic!` if they cannot find one — so any
  change to `MAX_ENTRIES`, `MAX_TEXT_BYTES`, the 214-char name cap, or the
  per-entry JSON shape breaks them.