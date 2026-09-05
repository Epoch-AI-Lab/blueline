# Blueline TODO

## Night run: AUR support (2026-09-01, drafted — Kriday to veto any ruling before PR1 opens)

Motivation: the "Atomic Arch" campaign (June 2026) — 400+ orphaned AUR
packages adopted and backdoored via malicious commits to PKGBUILD/.install
files, delivering a Rust infostealer and optional eBPF rootkit. That attack is
a diff-detection problem and blueline's exact wedge.

Rulings:

- Review-only wedge. `blueline install` REFUSES AUR (building a PKGBUILD
  executes arbitrary shell code — same rationale as cargo/PyPI). Blueline
  reviews; the user builds with their own helper (pacman/yay/paru). No package
  manager, no pacman reimplementation.
- PKGBUILD and every file in an AUR repo are UNTRUSTED DATA: never sourced,
  never executed, and `makepkg --printsrcinfo` is forbidden (it sources the
  PKGBUILD and runs its code). Static parsing only; fail closed on any
  construct we cannot resolve.
- History and diffs via the SYSTEM `git` binary, fail closed if missing or
  any git invocation errors. No git crate, no new Rust dependency at all.
- Review bytes come from the verified clone at the pinned commit
  (`git archive {commit}` → existing hardened tar extraction), so content is
  bound to the commit hash. No second download path.
- Baseline anchor = AUR COMMIT HASH. `pkgver-pkgrel` is display-only
  (multiple commits can share it). A missing anchor commit fails closed with
  an explicit re-approval prompt; never silently re-anchor.
- Version ordering: BUILD `AurVersionInfo` per `vercmp(8)` — epoch overrules
  everything, pkgver compares as alternating alphanumeric segments (numeric
  numerically, alpha lexically, empty segment older), pkgrel only breaks
  pkgver ties. Port pacman's own test vectors. No crates.
- Every PR passes the CI gate: `cargo fmt --all && cargo clippy --all-targets
  -- -D warnings && cargo test --all-targets --locked`.
- Every PR adds its CHANGELOG `[Unreleased]` entry (AGENTS.md rule).
- Branches stack: each bases on the previous branch. Open PRs with explicit
  `--base <previous-branch>` and say so in the body. Do NOT merge.
- NOTE: main is a protected branch - never push to main; work only on feature
  branches.

### PR1 `feat/aur-foundation` (bases on main)

- `Ecosystem::Aur` (`aur`). Store untouched — schema v3's ecosystem column
  already scopes rows; no migration.
- `AurVersionInfo` implementing `VersionInfo`: strict fail-closed parse of
  `[epoch:]pkgver[-pkgrel]` (integer epoch/pkgrel, no garbage), canonical
  display form. Ordering per vercmp(8) as ruled above; pacman vectors as
  unit tests.
- Fuzz target `fuzz/fuzz_targets/aur_version.rs`.
- RPC v5 client on `http_util`: `GET /rpc/v5/info?arg[]={pkg}` returning
  Name, PackageBase, Version, Maintainer, NumVotes, OutOfDate, FirstSubmitted,
  LastModified. Fail closed on malformed JSON; 404-shaped response = "package
  not found in AUR". Respect the documented ~4,000 req/day limit via the
  existing cache machinery; no new store tables.
- Name mapping: resolve pkgname → pkgbase via RPC before ANY repo access.
  All git/snapshot/diff operations address pkgbase only (split packages).
- MCP `ecosystem` param accepts `aur`; `blueline install` refuses aur with
  the build-executes-PKGBUILD explanation.

### PR2 `feat/aur-adapter` (bases on PR1)

- `src/registry/aur.rs`:
  - History: `git clone https://aur.archlinux.org/{pkgbase}.git` (full
    history, no `--depth`) into a sandboxed tempdir. List releases = commits
    with their parsed version (static-parse `.SRCINFO`/PKGBUILD at each
    commit via `git show {c}:PKGBUILD`), bounded to the most recent 200
    commits; truncation is stated on the card, never silent.
  - Baseline: last approved commit hash from the store. Diff = `git diff
    {anchor}..{target}` over the WHOLE repo — every file is reviewed, not
    just PKGBUILD (the Atomic Arch payload lived in .install/.hook files).
  - Review payload: `git archive {commit}` piped through the existing
    hardened extraction (validate_entry_path/ExtractionLimits). Diff text
    rendering reuses the existing escaping/sanitization.
- New finding `R10_MAINTAINER_TRANSITION` (MEDIUM): RPC Maintainer changed
  since first sighting, or orphan (empty maintainer) adopted and updated —
  the exact Atomic Arch adoption signal.
- Review card/JSON: `ecosystem: aur`, version shown as `pkgver-pkgrel` plus
  short commit hash; card DISCLOSES the PKGBUILD-level blind spot (downloaded
  upstream sources are not reviewed — xz class).
- `--registry` override maps to the AUR base URL for tests; no `--index`
  (no alternate AURs in scope).

### PR3 `feat/pkgbuild-heuristics` (bases on PR2)

- New module `src/pkgbuild.rs`: static tokenizer + multi-pass variable
  resolution (fold assignments, normalize quoting incl. `$'...'` ANSI-C,
  single/double/backslash forms), then rule matching. Same fold-then-match
  pattern as the JS engine's `String.fromCharCode` folding. No subprocesses.
- Rules (risk bands tunable while stacking):
  - `R11_CHECKSUM_SKIP` (HIGH): `SKIP` in sha256sums without a
    signed-tag + `validpgpkeys` story.
  - `R12_SOURCE_URL_DRIFT` (MEDIUM): source URL/domain changed while
    `pkgver` unchanged.
  - `R13_PIPE_TO_SHELL` (HIGH): `curl|bash`, `wget|sh` and kin.
  - `R14_EVAL_FAMILY` (HIGH): `eval`, sourcing remote content, `bash -c`
    with dynamic payloads.
  - `R15_DYNAMIC_INDIRECTION` (MEDIUM): `${!var}`, array indexing into
    command position — fail-closed lean.
  - `R16_CMD_SUBST_IN_META` (MEDIUM): `$(...)`/backticks inside
    `source=()`/`depends=()` arrays. Note: command substitution inside
    `pkgver()` of VCS packages is normal and NOT flagged as such.
  - `R17_BUILD_TIME_NETWORK` (MEDIUM): network fetchers invoked inside
    `build()`/`package()` beyond makepkg's own source retrieval.
  - `R18_HOMOGLYPH` (HIGH): zero-width/BiDi/confusable unicode — reuse the
    existing sanitizers' logic.
  - `R19_VALIDPGPKEYS_CHANGE` (MEDIUM) and
    `R20_INSTALL_HOOK_CHANGE` (MEDIUM: any diff in .install/.hook files).
  - `R21_UNPINNED_VCS_SOURCE` (MEDIUM): `git+https://` sources without
    `#tag=`/`#commit=`.
  - `R22_CONDITIONAL_EXECUTION` (MEDIUM): commands guarded by `$EUID`,
    date/time, or randomness checks — cannot prove intent, so surface.
  - `R23_NPM_DELIVERY` (HIGH): `npm install`/`bun install` invoked in
    build/package/hooks (the Atomic Arch delivery). V1 emits the finding
    naming the package spec; piping it through the npm review engine is an
    explicit follow-up, NOT in scope of this night run.
- Benign-corpus gate: ≥100 real-world PKGBUILDs as fixtures; every rule must
  pass the corpus with zero false positives or ships at INFO band until
  tuned. TrustSight's published baseline is 81% of benign updates scoring 0 —
  we must beat it.
- Fuzz target for the static tokenizer under `fuzz/`.

### PR4 `feat/aur-integration` (bases on PR3)

- yay v13 `AURPreInstall` Lua hook recipe (README): ~10 lines invoking
  `blueline --ecosystem aur review <pkgbase>@<version> --yes --policy
  blueline.toml` to gate the build. Document the TOCTOU property: the hook
  reviews the bytes already downloaded, never a re-fetch.
- `blueline ci`: v1 accepts a file of `pkgbase@commit` lines (lockfile
  analog; `pacman -Qqm` output can be piped through the user's own tooling).
  No alpm linking.
- Policy: `ecosystem = "aur"` rules work via the existing optional-ecosystem
  matching; audit log records commit hashes.
- Docs: threat-model disclosure card copy and the "review with blueline,
  build with yay/paru" flow.

## Status

- [x] PR1 feat/aur-foundation
- [x] PR2 feat/aur-adapter
- [x] PR3 feat/pkgbuild-heuristics
- [ ] PR4 feat/aur-integration

Mark your PR's box `[x]` in the same branch before opening it.

---

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

## Status (multi-registry run — complete)

- [x] PR1 feat/registry-foundation
- [x] PR2 feat/crates-io-adapter
- [x] PR3 feat/cargo-lock-ci
- [x] PR4 feat/pypi-adapter

Mark your PR's box `[x]` in the same branch before opening it.
