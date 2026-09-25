# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Opening the store now verifies the schema itself instead of trusting
  `PRAGMA user_version`. A database file carrying the right version counter
  with the wrong shape behind it opened successfully and then failed partway
  through a review with a confusing missing-column error. Every table and
  column the store queries is checked on open, the check is unconditional, and
  the refusal names the file and what is missing so a user knows what to move
  aside. The version-counter guess it replaces also decided lost migration
  races, which the schema check now decides directly.
- `agent gate` now refuses an unreviewable invocation shape before it resolves
  any operand. A command carrying a registry override (or any other hard-deny
  shape) used to be scanned, then still reviewed, downloading tarballs from the
  registry the command was explicitly redirecting away from and writing
  evidence rows for an install that never ran. The denial is unchanged and
  still exit 2; only the wasted and misleading work is gone.
- Registry requests no longer stall for 90 seconds against a peer that accepts
  the connection and then goes quiet. All four adapters share one agent with a
  10s connect ceiling and a 30s per-read/write ceiling. No whole-request
  timeout is set, because `ureq` lets it override the per-operation values, and
  response size stays bounded by `RegistryLimits` as before.
- Concurrent first runs against one data directory no longer fail. `record_verified`
  inserts-then-verifies rather than checking-then-inserting, which removed a
  primary-key collision between two reviewers recording the same package; the
  schema check above absorbs the matching creation race.
- The unreviewed-baseline refusal hint now names the
  `allow_unreviewed_baseline = true` policy rule alongside the
  predecessor-approval command, and warns that walking the chain costs one run
  per version back. The README quickstart documents the same onboarding path.
- Recall snapshots validate each entry's package name against its own
  ecosystem grammar instead of a shared character class, so a path-shaped name
  such as `../etc` is refused instead of served.

### Changed

- `AGENTS.md` and `ARCHITECTURE.md` now state the defect policy explicitly:
  a bug is fixed even when it predates the branch, "pre-existing" is not a
  reason to leave it live, and a fix without a test that fails without it is
  a guess. Both record why, using this store bug as the worked example.


- Docs refresh: `ROADMAP.md` marks the local-first recall index shipped
  (hosted API stays under Someday); `ARCHITECTURE.md` drops the stale
  Phase-0/1 notes, lists the full R00–R28 heuristic inventory, and records
  the recursion (D12), local-first recall (D13), and agent-enforcement
  (D14) decisions.
- Mutation testing now covers the verdict path: `heuristic.rs`, `diff.rs`,
  `advisory.rs`, `provenance.rs`, `verdict.rs`, and the crates.io / AUR /
  `http_util` / registry-mod files join the `--file` scope in both mutants
  jobs.
- The `blueline-ci` composite action downloads the checksum-verified
  prebuilt release binary (new `version` input, default `latest`) instead
  of `cargo run --release` on every run; `build-from-source: true`
  preserves the source build for unreleased code, and this repo's dogfood
  job pins it.

## [0.3.1] - 2026-09-21

### Added

- PATH-shim routing (`blueline shim install|uninstall <npm|npx|pip|cargo|yay|paru>
  [--dir <path>]`): generated bash shims that rebuild the invocation and
  route it through `blueline agent gate` before the real package manager
  (resolved on PATH at install time, excluding the shim directory) runs.
  Fail closed everywhere — blueline missing, errored, or refusing means the
  install does not run, and a missing real binary refuses shim creation.
  The scanner gained `cargo install`, and `yay`/`paru -S` operands
  (AUR-grammar specs with `name=version` pinning), so all six managers are
  reviewed through one grammar; pip flags that name non-registry sources
  (`-r`, `-e`, `--constraint`, …) are refused with a pointer to
  `blueline ci`. `BLUELINE_REGISTRY` and `BLUELINE_POLICY` environment
  variables scope a shimmed shell to a mirror and a project policy.
- Agent-native enforcement (`blueline agent`): `agent review <pkg>` gives
  autonomous agents a policy-bound, never-interactive gate — single-line
  JSON verdict on stdout (the D7 schema, recursive reviews included),
  exit 0 when the policy allows and 2 when it refuses, human hints on
  stderr, no known_clean mutation (an agent cannot bless baselines), and
  an audit-log entry with `decided_by = "agent:<identity>"` where the
  identity comes from the agent's process environment (Claude Code,
  Cursor, Codex CLI; env names only, never values — no telemetry beyond
  the local store). `agent gate` is the hook binding: it polices a command
  line via `--command` or hook stdin (Claude Code PreToolUse and Cursor
  `beforeShellExecution` payloads both accepted), scans it with the same
  install-reference scanner the review engine uses, reviews every named
  install with the recursive engine, and answers with exit codes or the
  native decision JSON (`--format claude|cursor`). Dynamic or unresolvable
  targets deny fail closed; bare installs are allowed with a note that
  manifest dependencies are policed by `blueline ci`.
- Recursive review (`src/recursive.rs`): an install reference found in a
  reviewed payload — npm lifecycle scripts, PKGBUILD `npm`/`bun` delivery
  (R23), or PyPI wheel `.data/scripts` — is now piped through the same
  review engine as a second-order review instead of only being named.
  Referenced packages are re-reviewed with a depth cap (policy
  `recursion.max_depth`, default 3), a per-review child budget
  (`max_child_reviews`, default 8), cycle detection (A → B → A is cut and
  disclosed), and a session tarball memo so referenced packages are never
  re-downloaded. Every reference is disclosed as
  `R24_LIFECYCLE_INSTALL_REF` (HIGH when pinned, MEDIUM when unpinned,
  unresolvable, or dynamic; HIGH for non-registry git/URL/path specs, which
  are not recursively reviewed), cap overruns as `R25_RECURSION_DEPTH` and
  cycles as `R26_RECURSION_CYCLE` (both HIGH, fail closed), and a child
  finding at or above `recursion.child_block_band` (default HIGH) rolls up
  into the parent verdict as `R27_SECOND_ORDER` — a HIGH finding in a
  referenced package can BLOCK the parent. The JSON verdict schema grows a
  `recursive` array of child reviews (delivery chain, band, score,
  findings), so the CLI, CI reports, and the MCP `structuredVerdict` all
  carry the second-order results from the single source of truth; the
  review card renders each child's delivery chain and worst findings.
- Install-reference extraction (`src/install_ref.rs`), the scanning layer for
  recursive review: static detection of package-manager invocations that
  resolve another install at install/build time — npm lifecycle scripts
  (`preinstall`/`install`/`postinstall`/`prepare`/kin) invoking
  `npm`/`npx`/`pnpm`/`yarn`/`bun`/`pip` with a named spec, PKGBUILD npm/bun
  delivery specs exposed by the new `pkgbuild::npm_delivery_refs`, and wheel
  `.data/scripts` payloads. Each reference records its manager, origin, raw
  spec, whether the spec is exactly pinned, and whether it was statically
  parseable (dynamic shell payloads are disclosed unparseable, never
  guessed). Nothing executes or fetches — pure parsing of already-extracted
  bytes, bounded per line, with non-UTF-8 `.data/scripts` files surfaced as
  unparseable references instead of silently skipped.

- AUR integration (`feat/aur-integration`): `blueline --ecosystem aur ci
  --lockfile aur.lock` reviews added and version-changed pins from a file of
  one `pkgbase@pkgver-pkgrel` per line (blank lines and `#` comments
  skipped, malformed lines and double pins fail closed with line numbers,
  4096-entry cap, base read via `git show` like other ecosystems); a yay v13
  `AURPreInstall` Lua hook recipe in the README gating the build on
  `blueline review --yes`, with the re-review-on-drift timing note;
  `ecosystem = "aur"` policy scoping through the existing generic matcher;
  and README threat-model copy stating the repo-scripts-only scope, the
  review-with-blueline-build-with-yay flow, and the commit-bound audit
  integrity.
- PKGBUILD static heuristics (`src/pkgbuild.rs`, AUR reviews only): a
  hand-rolled tokenizer with quote-aware lexing (`$'...'` ANSI-C, line
  continuations, word-boundary comments), multi-pass variable folding,
  indexed and associative array writes, brace expansion, and fail-closed
  bounds (1 MiB, 64k lines, no new dependencies, nothing executed). Rules
  R11-R23 fire as verdict findings: R13 pipe-to-shell, R14 eval family, and
  R18 homoglyph at HIGH; R12 source drift, R15 true indirection, R16 command
  substitution in metadata, R19 validpgpkeys change, and R20 install/hook
  change at MEDIUM; R11 checksum SKIP, R17 build-time network, R21 unpinned
  VCS, R22 conditional guards, and R23 npm delivery at INFO after the benign
  corpus (137 real AUR PKGBUILDs in `tests/fixtures/pkgbuild_benign/`)
  showed each fires on legitimate packages. Baseline pair rules (R12, R19)
  run when a baseline exists; unparseable PKGBUILDs fail closed at HIGH;
  every card carries the scope disclosure that downloaded upstream sources
  are not reviewed. Fuzz target `fuzz/fuzz_targets/pkgbuild_tokenizer.rs`.
- AUR registry adapter (`blueline --ecosystem aur review <pkg>@<pkgver-pkgrel>`):
  a git-history-backed `AurRegistry` on the RPC v5 client — pkgname → pkgbase
  mapping, shallow clone (history cap + 1) of `{base}/{pkgbase}.git` through
  the system `git` binary (argv-only, never a shell, capped output reads,
  120s wall-clock kill per git invocation, clone urls pinned to the
  configured base at the verify boundary, any git failure fails closed), a
  200-commit-bounded history walk that states truncation and
  refuses to resolve when the cap could hide the requested version, per-commit
  static `.SRCINFO` parsing (PKGBUILDs are never sourced or executed and
  `makepkg` is never invoked), newest-commit-wins version identity under
  `AurVersionInfo` (commits sharing a `pkgver-pkgrel` collapse to the newest),
  `git archive` review bytes extracted by the existing hardened tar path and
  verified against a resolve-time sha256 digest so the store's baseline-tamper
  check catches history rewrites, `list_releases`/`default_version` over
  distinct parsed versions with commit timestamps as publish times, and a
  `release_author` hook exposing the pinned commit's self-declared author
  email.
- `R10_MAINTAINER_TRANSITION` (MEDIUM): fires when the target release's
  author identity differs from the baseline release's — the AUR maintainer
  transition that is the Atomic-Arch adoption signal. Unknown authorship on
  either side is treated as no signal, and other ecosystems are unaffected
  (the hook defaults to `None`).
- AUR review manifests: a static `.SRCINFO` reader (`read_aur_srcinfo`,
  bounded to 1 MiB and 64k lines, fail-closed on duplicate pkgbase sections,
  malformed lines, or unparseable `pkgver`/`pkgrel`/`epoch`) projecting onto
  the engine's manifest view with `depends` + `makedepends` merged; extracted
  AUR archives must carry `PKGBUILD` and `.SRCINFO` at their root or the
  review fails closed.
- The MCP `ecosystem` parameter now accepts all four ecosystems (`npm`,
  `cargo`, `pypi`, `aur`); AUR tool calls route to the AUR base URL, derived
  from the `--registry` override exactly like the CLI.
- AUR foundation (`--ecosystem aur`): `Ecosystem::Aur` plumbed through the
  store, policy, CLI, and MCP ecosystem keys; `AurVersionInfo` implementing
  the `VersionInfo` seam as a faithful port of libalpm's `vercmp` (validated
  against pacman's `vercmptest.sh` vectors, separator-run and
  alpha-segment semantics included) with strict fail-closed parsing and a
  fuzz target; and an AUR RPC v5 metadata client on the shared `http_util`
  plumbing (name grammar validation, query encoding, bounded reads,
  fail-closed response shape checks, verbatim name comparison,
  pkgname → pkgbase resolution). `blueline install` refuses AUR packages
  (building a PKGBUILD executes its shell script); `review` and `ci` fail
  closed until the AUR adapter PR lands.

### Changed

- npm distribution renamed to `blueline-cli` (alias `@kridaydave/blueline-cli`)
  with platform binaries under `@kridaydave/binary-*`: the previous names
  `blueline` and `@bluelinecli/cli` are frozen at 0.3.0 under a lost
  publisher account and receive no further updates. Install with
  `npx blueline-cli` / `npm install -g blueline-cli`; the installed
  command and the Rust binary stay `blueline`.
- The policy loader honors `BLUELINE_POLICY` (an absolute path) ahead of
  the default search, so shimmed shells and agent hooks running outside a
  project directory keep their policy scoping; a set-but-unreadable path
  fails closed, and an explicit `--policy` flag wins over the environment.
- `R23_NPM_DELIVERY` graduates from INFO to MEDIUM: recursive review now
  resolves and reviews the npm/bun packages a PKGBUILD delivery line names,
  so the delivery line is a true second-order signal. The three
  benign-corpus fixtures that fire it (joplin, bitwarden-cli, insomnia) are
  pinned as documented true positives in the corpus gate.
- Push-to-main mutation testing now mutates only the lines of the pushed
  commit (`git diff HEAD~1..HEAD` fed to `cargo mutants --in-diff`) instead of
  re-running the full trust-boundary file set on every merge, spread across a
  16-shard matrix.
- The MCP stdio server no longer prints an stderr note when it receives the
  client's `notifications/initialized` message.
- AUR adapter resource use: one shallow clone per pkgbase is now reused
  across the read-only history operations of a review (resolve walk,
  releases walk, author lookup), halving the clones each evaluation
  performs; the cache is keyed by the full clone url and capped, and
  `fetch_verified` still re-clones so its archive bytes remain a second,
  independent sample from the remote. AUR CI reports now carry a
  `removed_count` (rendered in the text and markdown summaries) so pins
  deleted from the pin file are visible instead of silently dropped.
  PKGBUILD `$'...'` `\xHH` and octal escapes now decode as raw bytes the
  way bash emits them (`\xc3\xa9` is `é`, not `Ã©`), with non-UTF-8 byte
  sequences becoming U+FFFD and over-one-byte octal escapes failing closed.

### Fixed

- Mutation-testing survivors in the close-the-loop trust boundary:
  `valid_npm_name` rejects a missing `@` up front (empty scope/pkg
  segments were already rejected by the segment grammar, so the extra
  disjuncts were dead logic); the pip non-registry scan and the yay/paru
  verb search drop inert index arithmetic; npm/cargo recall matching is
  pinned as exact (strict semver has no distinct-but-equal forms, the old
  parse-and-compare arm could never fire); the serve size cap is a
  boundary-tested predicate and the oversized-index refusal test kills a
  hung server instead of hanging the suite; `is_executable_file` is one
  function with cfg branches inside; and both `scan_words` walks carry
  fuel so a stalled index trips instead of looping. New pinning tests:
  pip exactness for non-semver (`2.31`), single-disjunct non-registry
  shapes, repeated `--package=` flags, and chained managers.
- A mutation-testing survivor in the recursive-review reference cap: the
  overflow disclosure fired one reference early (`>` vs `>=`), which would
  have flagged a payload carrying exactly the cap as overflowing. The
  boundary is now pinned by a test at exactly 32 references.
- The npm dogfood CI gate no longer hardcodes which shipped packages must
  appear in the evaluated set: a lockfile delta that adds platform
  binaries (as the completed platform matrix does) shifted the evaluated
  names and failed the assert even though the scan was healthy. The gate
  now asserts that every evaluated package is a shipped package, that the
  delta produces evaluations, and that unchanged packages are counted.
- Agent-gate hardening from the campaign review: every gate error path now
  DENIES instead of exiting 1 (hook hosts treat non-2 exits as
  non-blocking, so a hostile stdin payload sized to break the UTF-8 read,
  a corrupt store, or an unreadable policy previously let the command run
  ungated); gate-managed installs route to their own registries (`cargo
  install` → crates.io, `yay`/`paru -S` → the AUR, `pip` → PyPI — the
  wrong-registry routing previously reviewed an npm namesake); and the
  scanner + gate close the silent-allow shapes: `pip install -r/-e/-c`
  (non-registry sources), `npx --package=<pkg>`, `npm exec`/`npm x`/`bun x`
  (which execute packages exactly like npx), and manager tokens hidden
  behind quoting or backslash escapes. Oversized hook stdin is refused, a
  missing-real-binary or hostile-character install path refuses shim
  creation, real binaries are checked for the exec bit, each manager's
  shim passes only its own registry override, `pip3` ships as a shim
  target, and gate denials are audited.
- The gate scanner finds verbs behind leading global flags
  (`npm --no-fund install evil` was a silent allow), denies npm registry
  and config overrides in gated installs (`--registry=`, `--userconfig`,
  `--tag=`, `npm_config_*` env assignments, `npm config set registry` —
  reviewing one registry while installing from another), discloses
  dynamic `--package` values as unparseable markers instead of dropping
  them behind decoy positionals, and stops scanning at shell comments.
- The README hook recipes pin `BLUELINE_POLICY` for the hook environment
  (a repo's committed blueline.toml otherwise governs hooks fired with the
  repository as cwd) and disclose the remaining bypass surface.

## [0.3.0] - 2026-08-31

### Added

- PyPI registry adapter (`blueline --ecosystem pypi review <package>==<version>` / `<package>@<version>`):
  PEP 440 `Pep440Version` (`VersionInfo` seam, epoch, zero-padded release, `a<b<rc` with `c→rc`, `post`/`dev`/`local`) validated against `pypa/packaging` vectors, PEP 503 name normalization (`[-_.]+→-`, lowercased, strict validation), `zip` crate (`default-features=false, features=["deflate"]`) wheel extraction wrapped with stored+deflate-only, encrypted/duplicate/symlink/traversal/absolute/NUL/Corruption and `ExtractionLimits` plus inflated-size-vs-declared checks and CRC propagation, Simple API `GET /simple/{norm}/` (`hashes.sha256`, `yanked` bool|string, `upload-time` RFC3339) powering `list_releases` / `default_version` / `resolve` with deterministic wheel choice (`py3-none-any` preferred, else lex-min) and `sha256` pre-extract verification. `blueline install` refuses PyPI (sdist builds execute arbitrary code).
- PEP 740 provenance: PyPI provenance endpoint (`GET /integrity/{norm}/{ver}/{filename}/provenance`) parsing DSSE in-toto statements and verifying subject sha256 checksums with cache integration.
- PyPI security findings: `R09_YANKED_TARGET` for yanked releases, `R02_ENTRY_POINTS_SCRIPT` for console_scripts / .data/scripts, `R06_NATIVE_PLATFORM_WHEEL` for compiled binary extensions, and `R04_SDIST_BUILD_CODE` for source distributions.
- Pinned `requirements.txt` CI scanning: `blueline ci` parses `name==version` requirements, rejects unpinned range operators with line-numbered errors, and enforces `--hash=sha256:...` checksum validation with `BLOCK` verdicts on mismatch.
- PEP 440 parser fuzz target under `fuzz/fuzz_targets/pypi_version.rs`.
- Wheel extraction hardening (`src/wheel_extract.rs`) reusing `validate_entry_path` and `ExtractionLimits` with `0o644`/`0o755` and symlink-via-mode checks.
- crates.io registry adapter (`blueline --ecosystem cargo review <crate>@<ver>`):
  sparse-index NDJSON client with fail-closed parsing (bad `vers` on a
  recognized row aborts; unknown schema `v > 2` rows are skipped with a note;
  missing `yanked` reads as false), `config.json` handling that refuses
  authenticated registries, canonical crate names (`serde_json` → `serde-json`),
  and `.crate` downloads verified by sha256 against the index checksum before
  extraction. Extracted archives must unpack to exactly one top-level
  `{name}-{version}` directory.
- Packed `Cargo.toml` reader: `[package] build`/`links`, `[[bin]]` targets,
  dependency maps, and `[features]`; dependencies project onto the existing
  diff/heuristic engine.
- Global `--ecosystem` flag (default npm) and `--index` override for cargo
  reviews; `blueline install` refuses cargo packages (building a crate executes
  its `build.rs`).
- Yanked-aware baselines: the diff anchor skips yanked releases, an all-yanked
  history degrades to first sighting, and a new `R08_YANKED_PREDECESSOR`
  (MEDIUM) finding fires when the release immediately before the target was
  yanked.
- Review card/JSON gain an `ecosystem` field; integrity displays as the
  canonical digest (`sha256:<hex>` / `sha512:<hex>`) instead of the old
  "verified (sha512)" label.
- MCP `review_install`, `inspect_diff`, and `check_known_clean` accept an
  optional `ecosystem` parameter (`npm` default, `cargo`); unknown values are
  rejected.
- Cargo.lock CI dogfood: `blueline ci` now scans `Cargo.lock` (TOML) alongside
  `package-lock.json` (bounded, `__`/`_` canonicalization, `source = "git+…"`
  honored via `allow_git_dependencies`); new `dogfood-cargo` job in
  `.github/workflows/ci.yml:110` runs
  `cargo run -- --ecosystem cargo ci --lockfile Cargo.lock --fail-on high`
  on PRs touching `Cargo.lock` (diff check for `Cargo.lock`),
  bootstrapped via committed `blueline.toml:1` with
  `allow_unreviewed_baseline = true` for the current crate set (content
  heuristics still apply in full).

### Changed

- Baseline predecessor selection now consults `list_releases` (yank flags)
  instead of the plain version list.

- Multi-registry foundation: `Ecosystem` enum (`npm`/`cargo`/`pypi`) with a
  `Registry::ecosystem()` accessor, a typed `Checksum { alg, value_hex }`
  replacing raw SRI strings, and `Release { version, yanked, publish_time }`
  with `list_releases` + `default_version` replacing `resolve_dist_tag`.
- `VersionInfo` seam in `src/version.rs`: baseline selection and the store's
  clean-version listing now work over any version grammar (semver today,
  PEP 440 later).
- Shared registry HTTP plumbing in `src/registry/http_util.rs`: URL scheme
  validation, private/local-host SSRF guards, capped redirect following, and
  bounded reads, reusable by future registry adapters.
- Optional `ecosystem` field on policy allow/blocklist rules; absent means the
  rule matches every ecosystem. Plain-string blocklist entries keep working.
- Store schema v3: every table gains an `ecosystem` column with composite
  primary keys `(ecosystem, name, version)`; existing rows become npm-scoped.
- Advisory lookups send the resolved ecosystem to OSV.dev with exact schema
  casing (`npm`, `CratesIO`, `PyPI`).
- Provenance attestation endpoint is threaded from the configured registry
  base instead of hardcoding `registry.npmjs.org`; DSSE subject digests are
  compared against the typed checksum.
- Baseline integrity tamper checks compare normalized digest content, so
  legacy `sha512-<base64>` rows and new `sha512:<hex>` display forms are
  judged alike (fail-closed behavior unchanged).

### Fixed

- Registry 404s now report "package not found in registry" instead of a
  generic network error, in both the review and CI paths.
- Lockfile parse errors no longer print their cause twice.
- Interactive reviews can approve the unreviewed registry-predecessor
  baseline in the same session (`[y/N]` prompt after approving the target);
  non-interactive behavior is unchanged.
- Isolated `BLUELINE_DATA_DIR` in the remaining CLI tests that spawn the
  binary while asserting success (`ci_writes_report_to_output_file`,
  `ci_fail_on_case_insensitive`, `mcp_ping_heartbeat`,
  `mcp_stdio_handles_initialize_and_tools_list`), eliminating a flaky race on
  the real user data dir under parallel test runs.
- Pinned the fail-closed rejection of npm packuments advertising a non-sha512
  `dist.integrity` with an explicit regression test asserting the algorithm
  error, closing a surviving mutation-testing gap in `registry::npm`.

## [0.2.0] - 2026-08-22

### Added

- Tag-triggered release pipeline (`.github/workflows/release.yml`): cross-built
  native binaries for linux (x64 glibc/musl, arm64), macOS (x64, arm64), and
  Windows (x64, arm64), published as `@bluelinecli/binary-*` npm packages with
  provenance and attached to GitHub releases with SHA256SUMS.
- Release smoke gate: the shipped artifact must review a real package
  end-to-end through the npm path before shims publish.
- Dogfood CI job: our own composite Action reviews our own npm distribution
  lockfile (`package-lock.json`) on every PR.

- Published npm distribution: `blueline` and `@bluelinecli/cli` shims with the
  native binary delivered via `@bluelinecli/binary-*` platform packages
  (linux-x64-gnu at v0.1.0; other platforms build from source).

## [0.1.0] - 2026-08-22

### Added

- `blueline review <pkg@ver>` command with text and JSON output, `--registry`
  override, and a fail-closed `--yes` flag.
- `blueline install` command with sandboxed extraction and fail-closed script
  execution.
- `blueline ci --output-file <path>` parameter to save formatted CI review
  reports directly to disk.
- npm registry client with SHA-512 integrity verification before extraction.
- Line-level diff engine against the last known-clean release.
- Heuristic verdict engine with an ASCII review card and stable JSON verdict
  schema.
- Interactive `[a]pprove · [h]old · [d]iff` prompt persisting clean versions
  to the SQLite store.
- OSV and GitHub Advisory revocation cache and engine.
- Sigstore / SLSA provenance and attestation surfacing.
- Policy-as-code via `blueline.toml` (advisories, provenance, allow/blocklists).
- `allow_unreviewed_baseline` allowlist rule for scripted onboarding of packages without an approved baseline; bootstrap findings stay visible but stop contributing risk (rendered as `[INFO]`, `"LOW"` in JSON), while content heuristics still apply in full. Note: the declared package name can reach a LOW verdict with zero interaction, so both `review --yes` and non-interactive `install` will proceed for it when nothing else is wrong; approving via `--yes` also marks the version known-clean as the diff anchor for future releases. Old binaries ignore this config key and fail closed.
- `blueline ci` lockfile diff scanner and PR reporting.
- Model Context Protocol (MCP) server and agent tools (`blueline mcp`).
- npm/npx wrapper shim (`@blueline/cli`).
- GitHub composite Action for PR checks.
- SQLite store with known-clean baselines, advisory/provenance caches, and an
  audit log.

### Changed

- Hardened static diff scanner against `String.fromCharCode` /
  `String.fromCodePoint` module-name reconstruction: charcode calls with
  plain integer arguments are folded to string literals before heuristic
  matching, closing one obfuscation route to `require(child_process)`.
- Hardened static AST/diff scanner with adjacent string literal folding to prevent concatenation evasion, dynamic global bracket invocations, String.fromCharCode property indexing, and indirect constructor/prototype references.
- Hardened static AST/diff scanner to detect reflection-based code execution (`Reflect.get`), global dynamic execution lookups (`globalThis['eval']`, `window['Function']`), and Node.js `worker_threads` imports without triggering false positives on benign JavaScript.
- Hardened archive extraction, SSRF checks, and executor isolation to fail
  closed on any doubt.
- Bounded registry reads with exact limits for packuments, tarballs, and
  redirects.
- Validated package name grammar, scoped URLs, and terminal escape sequences.
- Optimized static diff heuristic scanning, lockfile delta merging, SSRF IP validation, and terminal formatting with zero-allocation slice processing and O(N) two-pointer iteration.
- Optimized diff scanning performance.
- Clarified diagnostic stderr explanations when non-interactive input is piped
  without `--yes`.

### Fixed

- Isolated temporary build environment git repository resolution in CI test suites.

- IPv6 mutation testing by eliminating redundant address checks.
- Doubled `baseline store:` prefix in error messages caused by redundant error wrapping in `review`, `ci`, and `mcp` entry points.
- Baseline refusals now print an actionable hint naming the exact command to run (which predecessor version to approve) or the policy escape hatch, instead of failing with no next step.
- Redirect handling and false-equivalent bounds in registry metadata.
- JSON output purity by suppressing trailing human messages under `--output json --yes`.
- Timer string dynamic code evaluation (`setTimeout`, `setInterval`, `setImmediate`) in diff scanner heuristics.
- Zero-width and bidirectional unicode formatting character evasion in JavaScript token stripping.
- In-toto attestation empty subject bypass in SLSA provenance verification by enforcing matching subject digest.
- MCP standard heartbeat `ping` method handling returning empty JSON object.
- Case-insensitive parsing and uppercase aliases for `--fail-on` verdict risk bands.
- GitHub Actions composite step hardening mapping action inputs into environment variables to prevent shell injection.
- MCP tool output terminal escape and BiDi control character sanitization.

### Security

- Fail-closed on every parse, extract, and verify boundary.
- Integrated `cargo-deny` in CI to enforce licenses, bans, sources, and security advisories using `deny.toml`.
- Expanded PR diff and matrix mutation testing to guard `executor.rs`, `lockfile.rs`, `ci.rs`, and `mcp.rs` boundaries against regressions.
- Hardened static heuristic scanner against inline module requires, paren-wrapped constructors, http2/dns primitives, timer string eval, zero-width unicode obfuscation, indirect eval aliases, dynamic `this[...]` evaluation, `process.dlopen`, `cluster`, `WebAssembly` compilation, and external HTTP client libraries.
- Mutation testing and supply-chain audits run on every PR (CI gate).
