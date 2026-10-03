# Store

`src/store.rs` (SQLite via `rusqlite` + `rusqlite_migration`). The durable
trust record. Protects the property that **a witnessed digest is immutable**:
re-recording a *different* digest for the same `name@version` is a refusal, not
an overwrite, so a republished tarball cannot erase what was seen before.

## Sub-features
- `BaselineStore::open` / `open_at`, `default_db_path`.
- `MIGRATIONS` (v1 → v3), STRICT tables.
- `record_verified` / `mark_clean` / `list_clean_versions<V>`.
- `get_cached_advisories` / `put_cached_advisories` (upsert).
- `get_cached_provenance` / `record_provenance` (upsert).
- `record_audit_log` / `audit_entries(limit)` / `AuditEntry`.
- `known_clean` (`#[cfg(test)]` row inspector).

## How to get to it (user POV)
```sh
export BLUELINE_DATA_DIR=$(mktemp -d)     # isolate; default is ~/.local/share/blueline
blueline review demo@1.0.0 -y             # records clean=1 for LOW only
blueline recall export-candidates --out candidates.json --limit 1000
sqlite3 "$BLUELINE_DATA_DIR/baseline.db" '.schema'
```

## Driving it
DB path resolution: `$BLUELINE_DATA_DIR/baseline.db`, else
`dirs::data_dir()/blueline/baseline.db`, else
`Store("could not determine the platform data directory (set BLUELINE_DATA_DIR)")`.

| Table | Columns | Key |
|---|---|---|
| `known_clean` | `ecosystem, name, version, integrity, clean INTEGER NOT NULL DEFAULT 0, reviewed_at` | `(ecosystem, name, version)` |
| `advisory_cache` | + `advisories_json, hit_count, has_blocking_advisory, fetched_at, expires_at` | `(ecosystem, package, version)`; index `idx_advisory_cache_expiry(expires_at)` |
| `provenance_cache` | + `builder_id, source_repo, commit_sha, workflow_path, slsa_level, signature_valid, verified_at` | `(ecosystem, package, version)` |
| `audit_log` | `id, ecosystem, package, version, integrity, action, score, verdict, decided_by, notes, decided_at` | none; index `idx_audit_pkg_ver(package, version)` |

**There is no `installed` table and no `policy` table.** Policy is a TOML file
re-read per invocation.

Connection setup: `busy_timeout(5000 ms)` before any migration, then
`journal_mode = WAL`.

Audit `action` values actually written (free-form `&str`, not an enum):
`approve_auto_yes`, `approve` (with `verdict` `approved` *or*
`approved_baseline_chain`), `hold`, `agent_gate`, `agent_review`,
`agent_gate_summary`.

## Gotchas
- **`record_verified` must never become an upsert.** The tamper guard is
  read-compare-then-either-`UPDATE reviewed_at` or `INSERT`. Replacing it with
  `ON CONFLICT DO UPDATE SET integrity = excluded.integrity` — the shape used
  by the two cache writers in the same file — silently reintroduces baseline
  poisoning. `integrity_change_is_rejected` asserts both the error *and* that
  `"the stored record must survive a rejected rewrite"`.
- **`mark_clean` is not a flag flip.** It requires the caller to already hold
  the exact `Checksum` that was verified; a missing or mismatching stored row
  errors, and `affected == 0` returns the *same* error string as a second,
  independent guard.
- **Comparison is on normalized digest content.** A legacy `sha512-<base64>` SRI
  row and a new `sha512:<hex>` row are judged equal
  (`re_record_with_same_integrity_is_idempotent`).
- **`clean` defaults to 0 and `record_verified` does not write the column.**
  Doc comment: "only a verdict may mark a version clean, so merely running a
  review never blesses a release." `records_verified_witness_as_unclean` pins it.
- **`allow_git_dependencies` and `provenance.allowed_builders` are declared
  policy keys that nothing reads.** `blocklist.maintainers`,
  `allowlist.packages[].max_risk`, and `allowlist.packages[].integrity` used to
  be silently inert too. `Policy::validate` now refuses all three, so setting
  them is a load-time error naming the mechanism that does govern the concern.
- **v1→v3 rebuilds `known_clean`, `advisory_cache`, and `provenance_cache` via
  `_new` copies** (PKs change to composites) and only `ALTER`s `audit_log`. The
  advisory expiry index is dropped with the old table and must be recreated
  after the rename.
- **Filesystem hardening is `#[cfg(unix)]` and mostly best-effort.** Parent dir
  `0o700`, DB `0o600`, symlink re-checked *before* and *after*
  `Connection::open`; `set_permissions` and the pre-create `OpenOptions` both
  use `let _ =`, so they are not fail-closed.
- **`AuditEntry` has `row.get::<_, i64>(5)? as u32`** — an unchecked narrowing
  cast. And `hit_count`/`slsa_level` use `.max(0) as u*`, which coerces a
  negative corrupted value to `0` rather than erroring.
- **Zero `unwrap()`/`expect()` in the 745 non-test lines of `store.rs`.** The
  AGENTS.md carve-out for "unreachable-reference unwraps in database loops" is
  currently unused here; the actual pattern is
  `row.map_err(|e| Store(...))?` + `.optional()`.
- `verification_never_blesses_or_overwrites` is a proptest with
  `failure_persistence: None` — a failure is **not reproducible from disk**.
- Tests that spawn the binary must set `BLUELINE_DATA_DIR`;
  `tests/support/cli.rs` does this structurally per `Cli`. One exception:
  `tests/pypi_cli.rs::ci_pypi_lockfile_hash_verification` sets only `HOME`.