# Blueline TODO

## Night run: multi-registry (2026-08-22, decisions locked by Kriday, no re-litigating)

Rulings:

- PyPI wheels: BORROW the `zip` crate (`default-features = false`, `features = ["deflate"]`). Wrap with our own limits, fail closed.
- PEP 440 ordering: BUILD it (hand-rolled, validated against packaging's public test vectors). No `pep440_rs`.
- Store schema v3 (ecosystem column + PK rebuild) is PRE-APPROVED (ask-first guardrail satisfied by this document).
- Only new dependency allowed: `zip`. Everything else uses what we have (`sha2`, `toml`, `serde_json`, `semver`); hex encoding hand-rolled.
- Every PR passes the CI gate: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all-targets --locked`.
- Every PR adds its CHANGELOG `[Unreleased]` entry (AGENTS.md rule).
- Branches stack: each bases on the previous branch. Open PRs with explicit `--base <previous-branch>` and say so in the body. Do NOT merge.
- NOTE: main is a protected branch - never push to main; work only on feature branches.

### PR1 `feat/registry-foundation` (bases on main)

- `src/version.rs` (new): `VersionInfo` seam (`parse` fail-closed, `canonical`, `is_prerelease`, `baseline_eligible_for`). Thin impl for `semver::Version`; `baseline.rs` + `store.rs::list_clean_versions` take `V: VersionInfo` instead of raw semver. Behavior byte-identical; existing tests prove it.
- `Checksum { alg: Sha256 | Sha512, value_hex }` in `src/registry/mod.rs`; `Package.integrity -> Option<Checksum>`; construction normalizes npm SRI (`sha512-<b64>`) and hex forms.
- `Release { version, yanked, publish_time: Option<i64> }`; replace `resolve_dist_tag` with `list_releases` + `default_version`. npm impl: `yanked=false`, `publish_time=None`, `default_version` = dist-tags.latest else highest stable (move the rfind logic out of `review.rs:406-431`).
- Extract SSRF/redirect/bounded-download plumbing from `npm.rs` into `src/registry/http_util.rs` (URL validation, private/local host checks, redirect loop with cap, bounded reads). Pure move; npm delegates.
- `Ecosystem { Npm, Cargo, PyPi }` + `fn ecosystem(&self)` on `Registry`.
- `store.rs` migration v3: `ecosystem TEXT NOT NULL DEFAULT 'npm'` on `known_clean`, `advisory_cache`, `provenance_cache`, `audit_log`; PK rebuilt to `(ecosystem, name, version)` via `_new` table swaps; old rows become npm-scoped. Integrity validator accepts `sha512-<b64>` and checksum display forms (`sha256:<hex>`); tamper check compares normalized values.
- `advisory.rs`: OSV ecosystem from the resolved value: `Npm->"npm"`, `Cargo->"CratesIO"`, `PyPi->"PyPI"` (exact casing matters).
- `policy.rs`: optional `ecosystem` on allow/blocklist rules; absent = match all.
- `provenance.rs`: stop hardcoding `registry.npmjs.org`; thread base/adapter through; digest compare takes `&Checksum`.
- Tests: v2-to-v3 migration test, checksum normalization units, http_util moved verbatim, all existing suites green.

### PR2 `feat/crates-io-adapter` (bases on PR1)

- `src/registry/cratesio.rs` on http_util:
  - `config.json` fetch; fail closed on `auth-required: true`.
  - Sparse index paths: `1/{a}`, `2/{ab}`, `3/{a}/{abc}`, `{c1}{c2}/{c3}{c4}/{name}` lowercased. NDJSON parse fail-closed: bad `vers` on a recognized row = error; unknown schema `v > 2` row skipped with a note; missing `yanked` = false. Byte cap on index responses.
  - `canonical_crate_name` (lowercase, `_` becomes `-`); `validate_crate_name` (alnum + `-` + `_`, max 64); compare returned entry `name` verbatim, mismatch = error.
- Download `.crate` (default CDN shape), verify sha256 vs `cksum` before extraction. No `extract.rs` changes.
- Post-extract structural check: exactly one top-level dir named `{canonical_name}-{version}`, else error.
- Minimal packed-`Cargo.toml` reader (existing `toml` crate): `build`, `links`, `[[bin]]` count/names, dependency maps, `[features]`.
- Review wiring: global `--ecosystem` (clap ValueEnum, default npm); `--index <url>` override for cargo; spec `serde@1.0.210` parses unchanged; `blueline install` refuses cargo with explanation (build.rs executes).
- Baseline: predecessor = highest non-yanked stable `< target`; all-yanked means FirstSighting with warning. New finding `R08_YANKED_PREDECESSOR` (MEDIUM): immediate prior release was yanked.
- Render/card/JSON gain `ecosystem` field, `sha256:<hex>` display. `mcp.rs` gains optional `ecosystem` param.
- Tests: fixture HTTP server serving config.json + index NDJSON + `.crate` bytes (pattern from `tests/cli.rs`); adversarial fixtures (traversal entry, symlink entry, root-name mismatch, bad checksum); unit tests for path calc, NDJSON edges, checksum verify, yanked-aware predecessor selection.

### PR3 `feat/cargo-lock-ci` (bases on PR2)

- `lockfile.rs`: `Cargo.lock` TOML parser producing the same `BTreeMap<String, PackageEntry>` shape; `checksum` maps to sha256-hex integrity; path/workspace deps lack checksum (None, still reviewed); `source = "git+..."` = informational non-registry entry honoring `allow_git_dependencies`.
- `ci.rs`: dispatch by filename (`Cargo.lock` means TOML parser) or explicit `--ecosystem`. Downstream delta/reporting reused untouched.
- Dogfood job in `.github/workflows/ci.yml`: on PRs touching `Cargo.lock`, run `blueline ci` against blueline itself, `--fail-on high`. Bootstrap a committed `blueline.toml` with `allow_unreviewed_baseline = true` for the current locked set.

### PR4 `feat/pypi-adapter` (bases on PR3)

- `Pep440Version` implementing `VersionInfo`: epoch, zero-padded release tuples, pre (`a` < `b` < `rc`, `c` folds to `rc`), post, dev, local; strict parse fail-closed. Port packaging's ordering vectors as unit tests.
- PEP 503 normalization (`[-_.]+` collapses to `-`, lowercase) + raw-name validation regex; normalize before every fetch, display registry-reported name.
- Wheel extraction via approved `zip` crate, wrapped: stored+deflate only; reject encrypted/multi-disk/duplicate names/symlink external attrs/traversal/absolute/NUL paths; enforce `ExtractionLimits`; inflated size must equal declared size; CRC32 verified. Reuses tempdir/special-bit/sandbox flow. `extract.rs` untouched.
- `PyPIRegistry` on http_util: `list_releases` via Simple API `/simple/{norm}/` (PEP 691/700 JSON: `hashes.sha256`, `yanked`, `upload-time` int epoch); `resolve` via legacy JSON API `/pypi/{norm}/{version}/json` (`info.maintainer_email`, `ownership.roles`). Never depend on the deprecated `releases` key.
- Artifact selection: default wheel (prefer `py3-none-any`, else deterministic lexicographic among non-yanked; disclose choice on card). `--artifact wheel|sdist`. Reviewing an sdist emits a finding: installing it executes build code.
- Findings: `R09_YANKED_TARGET` (MEDIUM) plus `yanked_reason`; new `entry_points.txt`/console_scripts or `.data/scripts` means PATH-executable delta finding; native-platform wheel flagged.
- Provenance (PEP 740, surface-only): `GET /integrity/{norm}/{ver}/{filename}/provenance`; decode DSSE statements, compare subject sha256 against the COMPUTED file digest (mismatch means FailedMismatch); 404 means Missing (neutral). Card states crypto verification not performed.
- CLI: `--ecosystem pypi`, `name==ver` accepted as alias for `name@ver`; extras/ranges/direct URLs rejected v1 with explicit errors; `blueline install` refuses pypi (no ignore-scripts analog; sdist build runs arbitrary code even under pip download).
- ci v1: pinned `requirements.txt` only. Parse `name==version`, tolerate comments/blanks, reject range specifiers by failing closed with line-numbered list of unpinned entries; capture `--hash=sha256:...`; hash mismatch vs fetched release = BLOCK.
- Fuzz targets: PEP 440 parser under existing `fuzz/`.

## Status

- [x] PR1 feat/registry-foundation
- [ ] PR2 feat/crates-io-adapter
- [ ] PR3 feat/cargo-lock-ci
- [ ] PR4 feat/pypi-adapter

Mark your PR's box `[x]` in the same branch before opening it.
