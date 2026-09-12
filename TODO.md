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
  blueline.toml` to gate the build. Document the timing property honestly:
  the review re-pins the newest commit for that version at review time while
  yay builds its own download, so re-run the review right before the build
  and treat any version drift as a re-review signal.
- `blueline ci`: v1 accepts a pin file of `pkgbase@pkgver-pkgrel` lines
  (lockfile analog; `pacman -Qqm` output can be piped through the user's own
  tooling). No alpm linking.
- Policy: `ecosystem = "aur"` rules work via the existing optional-ecosystem
  matching; audit log records commit hashes.
- Docs: threat-model disclosure card copy and the "review with blueline,
  build with yay/paru" flow.

## Status

- [x] PR1 feat/aur-foundation
- [x] PR2 feat/aur-adapter
- [x] PR3 feat/pkgbuild-heuristics
- [x] PR4 feat/aur-integration

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

---

## Night run: close the loop (2026-09-12, drafted by the agent run — Kriday to veto any ruling before the PR opens)

One branch, `feat/close-the-loop`, carries all four campaigns; the PRs stack
per campaign with explicit `--base` per the convention above. Campaign briefs
2–4 are appended here at their campaign boundaries, before their first slice.

### Campaign 2 — agent-native enforcement (research brief)

Motivation, verified against the Claude Code hooks reference, the Cursor
hooks docs (1.7+), the Codex CLI execpolicy/config references, corepack/
pipx/volta docs, and 2025-2026 gate prior art (Socket MCP, Attach Guard):
Claude Code and Cursor both expose a stdin-JSON / exit-code-2 veto contract
at the tool-call boundary; Codex has no hook process (bind point is
Starlark prefix_rule + sandbox policy); PATH shims intercept the LAUNCHER
only (corepack/pipx/volta all share the same bypass family: absolute
paths, `command`, `env -i`, direct npm-cli.js), so per ARCHITECTURE.md the
MCP/explicit call is primary and the shim is the enforcement backstop for
the interactive terminal. `npm_execpath` is user-controllable (2linenodejs
CTF pivot) and must never be trusted for security decisions. Hooks are
repo-committable config and themselves an attack vector — recipes must
live in USER-level settings, not the repo, and say so.

Rulings (locked, no re-litigating):

1. Primary surface: `blueline agent <pkg>` — no interactive prompt ever,
   single-line JSON verdict on stdout (the D7 schema), deterministic exit
   codes (0 approve/Low, 2 blocked/refused, 1 error), human hints on
   stderr only. Approval is policy-bound: the verdict band decides, the
   same blueline.toml thresholds/allowlists apply.
2. Second surface: `blueline agent gate` — the hook binding. Input: the
   command line to police via `--command`, or hook stdin (Claude Code
   PreToolUse JSON and Cursor beforeShellExecution JSON are both accepted;
   the command string is extracted). Output via `--format claude|cursor|
   plain` in each product's native decision shape; plain (default) uses
   exit codes only. The command string is scanned with the SAME
   install-reference scanner as reviews (install_ref::scan_line) — one
   parser, one grammar, no second opinion to drift. Package operands are
   reviewed via the recursive engine; bare installs (no operands) are
   ALLOWED with a stderr note pointing at `blueline ci` (a bare install
   pulls the manifest's deps — policed by CI, disclosed honestly).
3. Backstop: `blueline shim install <npm|npx|pip|cargo|yay|paru...>
   [--dir <path>]` (and `blueline shim uninstall`) writes bash shims into
   a user-chosen dir. Shims extract specs from the invocation, run
   `blueline agent` per spec, and exec the REAL package manager (absolute
   path resolved at install time, PATH fallback excluding the shim dir)
   only when every verdict is Low. Fail closed everywhere: blueline
   missing, errored, or refusing ⇒ the install does not run. pip flags
   that name non-registry sources (-r/-e/--constraint/--target/...) are
   refused with a pointer to `blueline ci` rather than guessed at.
   `yay/paru -S` with operands reviews each AUR spec; update runs without
   operands pass through and are disclosed as a bypass in the docs.
4. The bypass list is documented on the card of truth (README): absolute
   binary paths, `command npm`, `env -i`, direct npm-cli.js, npx resolving
   from node_modules/.bin, PATH reordering, hook config tampering in
   repo-committable settings. No security theater: the shim is
   defense-in-depth for the terminal, hooks for the agent, CI for the
   manifest — the campaign says so in writing.
5. Audit: every `agent` decision writes the existing audit_log with
   `decided_by = "agent:<identity>"`; identity comes from process env
   (CLAUDECODE/CLAUDE_CODE_ENTRYPOINT → claude-code, CURSOR_* → cursor,
   CODEX_* → codex, else unknown-agent) and lands in `notes` (env names
   only, never values — no telemetry beyond the local store, D8 holds).
6. Codex CLI has no hook process: the recipe is a Starlark `prefix_rule`
   set to `prompt` for install verbs plus instructions to route installs
   through `blueline agent` — stated as advisory in the docs, not sold as
   enforcement.
7. No new dependencies; shims are generated scripts, parsing reuses
   install_ref; store schema untouched.

Slices:

- Slice 1 `agent-mode`: `src/agent.rs` — `blueline agent <pkg>` +
  `blueline agent gate`, identity detection, audit entries, exit codes,
  unit + integration tests.
- Slice 2 `shims`: `src/shim.rs` — install/uninstall for npm, npx, pip,
  cargo, yay, paru; fail-closed script templates; tests running real shim
  scripts against the fixture registry.
- Slice 3 `recipes`: README/Claude/Cursor/Codex recipes with the honest
  bypass list; user-level-settings warning; use-it pass.

### Campaign 1 — recursive review (research brief)

Motivation, verified against the TanStack postmortem, the Unit42 writeup,
StepSecurity's and Sonatype's Atomic Arch coverage: both campaigns delivered
through a **machine-resolved reference inside an already-reviewed artifact** —
TanStack injected `optionalDependencies: { "@tanstack/setup":
"github:tanstack/router#<orphan-sha>" }` whose `prepare` script ran at install
time (with valid SLSA L3 provenance, which attests the builder, not the
referenced install), and Atomic Arch's PKGBUILDs carried a one-line
`npm install atomic-lockfile` whose npm `preinstall` ran the infostealer. In
both, the reviewed diff is benign; the payload lives one hop away. OSV/GHSA
classify new malware on the order of ~3 days (28-day NVD median), so advisory
gating alone misses the window. The exploitable invariant: a reference whose
resolution happens on the victim machine is neither reviewed nor pinned.

Rulings (locked, no re-litigating):

1. Recursion lives in the ENGINE, not the CLI. `evaluate_with_registry` gains
   a threaded review context (depth, visited set, delivery chain, shared
   registries); every entry point — CLI `review`/`install`/`ci`, MCP
   `review_install` — inherits it with no surface-specific code.
2. Reference surfaces in v1: (a) npm manifest lifecycle scripts
   (`preinstall`/`install`/`postinstall`/`prepare`) invoking a package
   manager (`npm/npx/pnpm/yarn/bun` + `install/i/add/exec/x/dlx/run`) — the
   Shai-Hulud/TanStack lane; (b) PKGBUILD npm/bun delivery — the existing
   R23 scan, extended to yield the parsed spec; (c) wheel `.data/scripts`
   and entry-point-adjacent payloads scanned statically for pip/npm
   invocations. Entry points that reference the distribution's OWN modules
   are not recursion triggers (they execute deferred, but reference nothing
   installable; R02 already covers them).
3. Non-registry references (`git:`, URLs, `file:`) are NOT recursively
   reviewed in v1 — resolving arbitrary git hosts is a new trust surface.
   They keep their existing findings (R04 family) and the card discloses
   that referenced non-registry installs were not reviewed. No silent gap.
4. New rules: `R24_LIFECYCLE_INSTALL_REF` (HIGH) for a package-manager
   install invoked from an npm lifecycle script, with MEDIUM variants for an
   unpinned spec (mutable payload) and an unresolvable spec; dynamic/
   unparseable specs (command substitution etc.) surface as MEDIUM
   "unparseable install reference" — never guessed at. `R25_RECURSION_DEPTH`
   (HIGH, fail closed: the cap is stated, never silent) and
   `R26_RECURSION_CYCLE` (HIGH). Roll-up finding `R27_SECOND_ORDER` carries a
   child finding that meets the policy threshold into the parent verdict.
5. R23 graduates Low → MEDIUM: with recursion covering what it points at,
   the delivery line is a real second-order install signal; the INFO band
   existed only because nobody resolved the reference.
6. Policy (`[recursion]` in blueline.toml): `max_depth` default 3,
   `max_child_reviews` default 8 (bounds CI/fan-out cost; exceeding either
   emits R25, fail closed), `child_block_band` default `"high"` — a child
   finding at or above the band escalates the parent verdict; ambiguity
   resolves to block.
7. Cache/memo: a session-scoped driver holds one registry instance per
   ecosystem (today each `evaluate_package` call builds a fresh one) and a
   bounded in-memory tarball memo keyed `(ecosystem, name, version)`, cleared
   on overflow like the AUR `clone_cache`. The visited set is both cycle
   detection and the no-re-review memo. Store schema UNTOUCHED.
8. Children are never approved, never marked clean; `record_verified`
   evidence rows only. The parent decision decides; interactive approval
   happens once, on the parent.
9. Verdict JSON grows `recursive: Vec<ChildReview>` (skipped when empty)
   where `ChildReview = { chain: Vec<String>, name, version, ecosystem, band,
   risk_score, findings }`. Per D7 the CLI card, CI report, and MCP
   structuredVerdict all inherit it. The card renders the delivery chain
   ("delivered via: pkgbase → npm:package@ver").
10. `extract.rs` untouched (scanning happens post-extract on the extracted
    root and manifest views). No new dependencies. The npm-lifecycle
    reference extractor is hand-rolled token scanning with fail-closed
    bounds, same discipline as the PKGBUILD tokenizer; fuzz target added.

Slices (each independently green, small commits, CHANGELOG entry per slice):

- Slice 1 `ref-extraction`: reference extraction module (npm lifecycle
  scripts + PKGBUILD R23 spec plumbing + wheel `.data/scripts` scan),
  unit tests, CHANGELOG.
- Slice 2 `recursive-engine`: review context, recursive driver with depth
  cap / cycle detection / visited memo / registry + tarball reuse, child
  evaluation, unit + integration tests against the fixture registry.
- Slice 3 `rollup-render`: `ChildReview` in the verdict schema, policy
  `[recursion]`, R23 graduation, card chain rendering, MCP/CI inheritance
  tests, fuzz target.
- Slice 4 `use-it`: adversarial fixture registry (A → B backdoored chain)
  end-to-end BLOCK proof, README/ARCHITECTURE notes.

## Status: close the loop

- [x] Campaign 1: recursive review (slices: ref-extraction, recursive
  engine, rollup-render, use-it e2e; reviewers PASS; use-it: real binary
  BLOCKed the adversarial A→B chain and live AUR webtorrent-desktop review
  rendered R23 at MEDIUM)
- [x] Campaign 2: agent-native enforcement (slices: agent-mode, shims,
  recipes; review loop fixed gate fail-open P1s — error-deny, per-registry
  routing, flag/override/comment scanner shapes; use-it: real npm install
  through an installed shim blocked unapproved and ran approved, Claude
  Code + Cursor hook payloads denied/allowed with agent identities in the
  audit log)
- [x] Campaign 3: recall / revocation index (slices: recall-service,
  fold-in; use-it: e2e serve/sync/block, staleness disclosure and
  escalation, curation export pinned in tests/recall_cli.rs)
- [ ] Campaign 4: dogfood & distribution

Mark each campaign's box `[x]` in the same branch when it lands.
