# Rust Best Practices for Blueline — Compiled Research

**Subject:** Engineering best practices for a security-focused Rust CLI that fetches
package tarballs, extracts them read-only, diffs them, scores risk with a local
heuristic, persists a baseline in SQLite, and ships through a Node shim (CLI /
MCP / CI entry points).
**Compiled:** 2026-08-12 · **Mode:** compilation (engineering, not papers)
**Profile it must fit:** single-shot CLI, batch-style ("do this, exit"), low
concurrency, parses *untrusted* network + tarball input, must never execute that
input, ships a signed binary + npm shim.

---

## Phase 1: Verified Compilation

### Source 1 — CLI structure & output (clap)
- **Source:** clispec.dev "The CLI Spec (Rust)", lucaberton.com (2026), rust-cli.github.io book, OneUptime/DevProPortal clap guides.
- **What they say:** Model the CLI as structs/enums with `clap` derive; `ValueEnum` for strict options; subcommands for modes; global flags (`--output`, `--quiet`) at root. Auto-detect TTY: default `--output auto` → text on TTY, JSON when piped. Separate `stdout` (data) from `stderr` (messages); gate interactive prompts on TTY. Emit **line-delimited JSON** for streaming machine output (ripgrep pattern). Integration-test with `assert_cmd` + `predicates`.
- **Relevance to Blueline:** `review`/`ci`/`mcp` are exactly the "machine needs structured output" case. The `Verdict` JSON schema (ARCHITECTURE.md D7) should be the piped/JSON form; human card only on TTY. `assert_cmd` gives the Phase-0/1 test harness for free.
- **Confidence:** confirmed.

### Source 2 — Error handling: thiserror (library/domain) vs anyhow (app)
- **Source:** dtolnay/thiserror, RustTraining "Error Handling Patterns" (microsoft.github.io), atharvapandey.com lessons, anyhow docs.
- **What they say:** Use `thiserror` for *libraries* and *domain* errors that callers match on (concrete enums, `#[from]`, `#[source]`, `#[non_exhaustive]`, lowercase composable Display). Use `anyhow` for *application* orchestration (`Result` propagation + `.context()`). Hybrid is the norm: domain layer = typed `thiserror`; everything above = `anyhow`. Add `.context()` at every trust boundary. `main() -> Result<()>`; print full chain with `{:#}`. Never ship `unwrap()` in production paths.
- **Relevance to Blueline:** The diff/registry/heuristic *engine* is effectively a library — define a `BluelineError` enum (e.g. `Network`, `Extraction`, `Verification`, `Policy`) so CI/MCP can branch on `Verdict::Block` vs transient. The `blueline` binary's `main` uses `anyhow` + context ("failed to download <pkg@ver>: ...").
- **Confidence:** confirmed.

### Source 3 — Async is an optimization, not an architecture
- **Source:** rust-lang.github.io async-book, tokio.rs tutorial ("When not to use Tokio"), microsoft.github.io RustTraining ch14 "Async Is an Optimization, Not an Architecture", learnrust.net ch23, users.rust-lang.org, ureq README, blog.veeso.dev.
- **What they say (consensus):** For batch CLIs that do one thing and exit, async buys complexity and a runtime dependency for no benefit. Tokio's own docs: "Sending a single web request… prefer the blocking version." ureq deliberately uses blocking I/O to "keep the API simple and keep dependencies to a minimum" (its README explicitly avoids pulling in an async runtime). The async-book: never block a thread inside an async runtime. RustTraining ch14 gives the rule: **start sync, add async only at the outermost I/O boundary; pull it inward only when concurrency is the core logic** (fan-out, streaming, stateful connections). "Sync core, async shell" keeps business logic testable without a runtime. Below ~1K–10K concurrent idle connections a thread pool is simpler.
- **Relevance to Blueline:** Blueline is a sequential, low-concurrency batch tool (one `install`, one `review`, one `ci` run). Blocking HTTP (`ureq`) + std threads for the few parallel fetches is the right call. The diff/heuristic/SQLite core stays **sync and unit-testable** with fixtures — no `tokio` in the engine. This also matches the earlier architecture decision (D2 local heuristic = pure, deterministic, offline).
- **Confidence:** confirmed (strong cross-source consensus).

### Source 4 — Supply-chain security (eat our own dog food)
- **Source:** rust-secure-code.github.io "Rust Supply Chain Security Guide", rustsec.org / cargo-audit, microsoft.github.io RustTraining ch06, safeguard.sh guide, cargo-deny, cargo-geiger, cargo-auditable.
- **What they say:** Always **commit `Cargo.lock`** for apps (reproducible, no silent updates). Run `cargo audit --deny warnings` and `cargo deny check` (advisories + licenses + bans + sources) in CI on every PR; `cargo outdated` weekly. Minimize `unsafe` (`cargo-geiger`); prefer `rustls` over `openssl-sys`. Treat `build.rs` and proc-macros as the highest-risk supply surface — audit them, sandbox builds (no network), prefer well-maintained macros. `cargo-auditable` embeds the dependency list so produced binaries can be audited. `cargo-vet` (Mozilla) for orgs needing human-reviewed trust.
- **Relevance to Blueline:** Blueline audits *other people's* supply chains, so its own must be exemplary. Ship `Cargo.lock`, wire `cargo audit` + `cargo deny` into CI from Phase 0, `cargo-auditable` in release profile, and keep `unsafe` to ~zero. The irony-risk is real: a tool that flags `postinstall` scripts must itself avoid `postinstall` in distribution (see Source 7).
- **Confidence:** confirmed.

### Source 5 — Parsing untrusted input (the core threat model)
- **Source:** serde-rs/serde issue #1087, atharvapandey.com "Input Validation", medium.com "Unsafe JSON Deserialization in Rust" (CWE-502), serde_json docs, `secure-json-parse` crate.
- **What they say:** Rust's memory safety ≠ input trust. **Parse, don't validate** (Alexis King): deserialize into a *typed* struct, then parse into a *validated newtype* (`Username::parse`), so invalid states are unrepresentable. `serde_json` guarantees well-formed output for any input (no panic/loop) **but** deeply nested JSON can stack-overflow — enable the `unbounded_depth` feature only with `serde_stacker`, or bound depth. Never deserialize untrusted data into `serde_json::Value` and poke fields. Real CWE-502 cases exist from `from_str` on external responses without schema.
- **Relevance to Blueline:** The npm registry JSON and extracted tarball *contents* are fully untrusted. Registry metadata → typed `serde` structs with validation; tarball extraction must be **size- and entry-count-bounded** (a malicious tarball can have 10M entries or a 10GB file → DoS). Never `serde_json::from_str` on tarball-sourced bytes without limits. This is the single most important hardening area for Blueline and is **not** covered in ARCHITECTURE.md yet — flagged below.
- **Confidence:** confirmed.

### Source 6 — SQLite (the baseline store)
- **Source:** rusqlite docs (Connection, Statement, Transaction), rusqlite_migration crate, sqldocs.org "Rust SQLite".
- **What they say:** Use `prepare_cached` for repeated statements; wrap multi-statement writes in `Transaction` (rolls back on drop by default). Prefer **WAL** mode for write throughput. Manage schema with `rusqlite_migration` (uses SQLite `user_version`, lightweight, no extra tables). Keep PRAGMAs (journal_mode) outside migrations. One `Connection` per process is fine for a CLI; pool only if concurrency appears.
- **Relevance to Blueline:** The baseline store (installed/known-clean versions, approval overrides, policy) is a perfect fit for SQLite. Use `rusqlite_migration` for schema evolution from Phase 0; `prepare_cached` for the read/upsert paths; `WAL` since the store is written on every approve. A single connection per CLI invocation is sufficient for `review`/`install` (no async pool needed — reinforces Source 3). **If `ci` fans out across a bounded thread pool (D1), give each worker its own `Connection`, or guard one shared connection with a `Mutex` — WAL permits concurrent readers but not concurrent writers.**
- **Confidence:** confirmed.

### Source 7 — Distribution: signed binary + npm optionalDependencies shim
- **Source:** axodotdev/cargo-dist (GitHub, crates.io), napi.rs docs, anodizer docs, abemedia/cargo-npm, bin-shim (npm), muxinc/cli `npm-distribution-plan.md`.
- **What they say (strong consensus):** Ship a **prebuilt, per-platform** binary. For the npm path, the esbuild/Biome/Turbo/Bun pattern is **`optionalDependencies`**: one thin per-platform package per target (`@scope/cli-linux-x64-gnu`, `-musl`, `-darwin-arm64`, `-win32-x64`) carrying the binary with `os`/`cpu`/`libc` constraints, plus a metapackage whose `bin` shim does `require.resolve(matchingPkg)` → `spawnSync(binary, argv, {stdio:'inherit'})` and forwards the exit code. **Prefer this over `postinstall`** — `postinstall` adds install-time network + `--ignore-scripts` failure modes; `optionalDependencies` has neither (no install scripts). Split glibc/musl so a glibc binary isn't installed on musl. cargo-dist generates the CI + installers; cargo-npm/anodizer generate the npm layout; `bin-shim` is the runtime resolver. Enable **npm provenance** (OIDC) so the binary's supply chain is verifiable — directly supports Blueline's D9 "signed, SLSA-built release binaries."
- **Relevance to Blueline:** This *is* the earlier decision "Rust binary + Node shim" made concrete and de-risked. `cargo-dist` for the GitHub release binaries + SLSA; the `optionalDependencies` shim (via cargo-npm or hand-rolled) for `npx blueline`. Critically, the shim must **forward signals and exit codes** and must not itself run install scripts that contradict Blueline's anti-`postinstall` stance.
- **Confidence:** confirmed.

---

## Design-Space Map (axes Blueline must lock)

| Axis | Option A | Option B | Recommendation for Blueline |
|------|----------|----------|------------------------------|
| Runtime model | sync/blocking | async/tokio | **Sync core + blocking HTTP (ureq)** for `review`/`install`; **bounded thread pool** (std, no tokio) for `ci` fan-out (S3, D1) |
| Error strategy | anyhow only | thiserror only | **Hybrid**: thiserror in engine, anyhow in binary (S2) |
| HTTP client | reqwest (async) | ureq (blocking) | **ureq** for blocking simplicity (S3) |
| DB | SQLite (rusqlite) | sqlx (async) | **rusqlite** — no async need, single conn (S6) |
| Migrations | hand-rolled | rusqlite_migration | **rusqlite_migration** (user_version) (S6) |
| npm shim | postinstall DL | optionalDependencies | **optionalDependencies** per-platform (S7) |
| Untrusted parse | Value + pokes | typed + validated | **typed serde + bounded extraction** (S5) |
| Release | manual | cargo-dist + SLSA | **cargo-dist**, provenance on (S4, S7) |

---

## Blueline-Specific Derivations (the "so what")

### D1 — Keep the engine sync and pure; make the shim/CI the only I/O shell
**Source trace:** RustTraining ch14 "sync core, async shell" + tokio "when not to use" + ureq README.
**Proposal:** The `blueline` lib crate exposes pure functions: `diff(a, b) -> Delta`, `score(delta, baseline, policy) -> Verdict`, `render(verdict) -> Card`. These take already-fetched bytes/paths as arguments and do **zero** network or process spawning. The binary (`main`) and the MCP server are the only places that touch the network/FS. **Steps:** (1) carve the lib crate now; (2) unit-test `diff`/`score` with fixture tarballs (express 4.21.1→4.21.2, a known-malicious package) with no runtime; (3) binary does fetch→verify→extract→call core, then on approve delegates to `npm install --ignore-scripts` (see D9). **Confidence:** confirmed. **Risk:** `review`/`install` are genuinely low-concurrency — sync + blocking `ureq` is correct. But `ci` scans a *whole lockfile* (potentially hundreds of packages): that is fan-out, and the ch14 rule says fan-out is when concurrency belongs. Resolution: a **bounded thread pool** (std threads, no tokio) for `ci`, with per-thread `rusqlite` connections (see S6). The flat "low concurrency" label applies to `review`/`install`, not `ci`.

### D2 — Bound and sanitize every untrusted parser (extraction + registry JSON)
**Source trace:** serde issue #1087 + medium CWE-502 + serde_json `unbounded_depth` docs + `tar` crate advisories (RUSTSEC-2021-0080, RUSTSEC-2018-0002, CVE-2025-45582, tar ≥0.4.45).
**Proposal:** Wrap tar extraction with hard limits **and** file-type rejection:
- max total unpacked bytes (e.g. 50× tarball size), max entry count, per-entry size cap, gzip decompress-ratio monitor (bomb guard), open-FD cap;
- **reject symlinks, hardlinks, and special files** (char/block device, FIFO, socket) by default — these are the zip-slip / chmod-arbitrary-dirs / link-escape vectors; if links are ever needed, validate the target stays within root (RESOLVE_BENEATH);
- reject absolute paths and `..` traversal; strip setuid/setgid bits; pin `tar` ≥0.4.45; prefer the `Entries` iterator + `Entry::unpack_in`, or wrap the sandbox dir in `cap-std`'s `Dir` for beneath-root resolution;
- RAII temp-dir guard removed on drop/panic so partial extraction never leaks.
Deserialize registry JSON with `#[derive(Deserialize)]` typed structs + post-parse validation; set a JSON depth/length ceiling. The extracted `package.json` itself is attack surface — diff/flag its `scripts`/`bin`/`dependencies` (this is Blueline's core value; the heuristic in ARCHITECTURE.md already covers `postinstall`, but treat every extracted file as untrusted bytes).
**Steps:** (1) write `extract::safe_extract` with counters + path/type checks; (2) regression tests with malicious tarballs (bomb, `../etc/passwd`, symlink-escape, device file); (3) typed `RegistryManifest` with validation. **Confidence:** confirmed. **Risk:** legitimate large packages need sane limits — make them configurable via `blueline.toml`.

### D3 — Typed, matchable engine errors for CI/MCP branching
**Source trace:** thiserror docs + atharvapandey "library vs application".
**Proposal:** `BluelineError` enum with variants for `Network`, `Extraction`, `ExtractionLimit`, `Verification`, `PolicyDenied`, `BaselineMissing`. CI maps `PolicyDenied`/`ExtractionLimit` → non-zero exit + PR comment; MCP returns structured `Verdict::Block`. **Confidence:** confirmed. **Risk:** over-granularizing — keep ~6 variants, not 40.

### D4 — Ship via cargo-dist + optionalDependencies shim, provenance on
**Source trace:** cargo-dist README + cargo-npm + bin-shim + mux/cli plan + napi provenance.
**Proposal:** `cargo dist init --ci=github` for cross-platform binaries + SLSA; generate npm packages with `cargo-npm` (optional-deps mode), split glibc/musl, shim forwards stdio + exit code + handles `--no-optional` by pointing to `cargo install`/`brew`. Enable npm provenance via OIDC. **Confidence:** confirmed. **Risk:** release is non-transactional across the 5+ npm packages — publish platform pkgs first, then meta, and verify with `npm view` (per napi recovery docs).

### D5 — Make the supply chain auditable from Phase 0
**Source trace:** rust-secure-code guide + cargo-audit/deny/auditable.
**Proposal:** Commit `Cargo.lock`; add `cargo audit --deny warnings` + `cargo deny check` as required CI checks from the first PR; release profile includes `cargo-auditable`; `cargo-geiger` in the audit job; zero `unsafe` in first-party code. **Confidence:** confirmed. **Risk:** transitive `unsafe` in deps (e.g. compression) — track with geiger, don't block on it.

### D6 (speculative) — Determinism for reproducible verdicts
**Source trace:** inferred from D2 local-heuristic "deterministic, offline" (ARCHITECTURE.md D2).
**Proposal:** Fix the heuristic scoring so identical inputs yield identical `Verdict` bytes (sort maps, stable hashing, no wall-clock/HashMap-iteration in scoring). This lets the hosted service and local runs be compared and lets CI cache verdicts. **Confidence:** inferred. **Risk:** ordering bugs if we later parallelize scoring — use `BTreeMap`/`IndexMap`.

### D7 — Verify tarball integrity *before* extraction (currently missing in the doc)
**Source trace:** npm EINTEGRITY behavior; pnpm/bun/corepack client-side SRI checks; npm `dist.integrity` (sha512) + registry signature.
**Proposal:** Before any extraction, compute the sha512 of the downloaded tarball and compare it to the registry's `dist.integrity` (SRI) and `dist.shasum`; verify the npm registry signature (ECDSA) when present. **Fail closed** on mismatch — a mismatched hash means the bytes are not the package the manifest claimed, which is exactly the supply-chain substitution Blueline exists to catch. **Steps:** (1) fetch `dist.integrity` from registry metadata; (2) stream-hash the tarball during download (no extra pass); (3) abort + `Verdict::Block` on mismatch. **Confidence:** confirmed. **Risk:** none — this is table-stakes for any tool that downloads packages; omission was the doc's gap, now closed.

### D8 (confirmed) — Sandbox the extract+diff step
**Source trace:** `tar` crate guidance + `cap-std`/`rustix` + Landlock (unblob uses Landlock for untrusted archives).
**Proposal:** Run extraction and diffing in a tightly restricted child: Landlock (read-only host FS + write only to the sandbox temp dir), drop capabilities, optional seccomp filter, non-root. Use `cap-std`'s `Dir` for beneath-root path resolution so even a missed traversal check can't escape. This is defense-in-depth *behind* D2's parser bounds. **Confidence:** confirmed. **Risk:** Landlock is Linux-only; on macOS/Windows fall back to the parser-level bounds (D2) + a dedicated non-writable temp dir. Keep the sandbox optional/feature-gated so tests stay portable.

### D9 (confirmed) — "Never execute" must hold on approve too
**Source trace:** profile "must never execute that input" + anti-`postinstall` stance (ARCHITECTURE.md D2/D7) vs D1 step 3 "exec npm".
**Proposal:** On approve, Blueline delegates to `npm install --ignore-scripts` (or performs a diff-only/install with scripts disabled), then surfaces any `scripts.postinstall`/`preinstall` for a *separate* human decision. Running a plain `npm install` would execute the package's lifecycle scripts — i.e. run the very untrusted code Blueline exists to flag, contradicting the "never execute" invariant and S7's anti-`postinstall` distribution stance. **Confidence:** confirmed. **Risk:** some packages won't function without their (legitimate) install script — that's the exact case the allowlist-by-maintainer / "review once, remember" flow (ARCHITECTURE.md §5) is for.

---

## Open Gaps / Things to Verify Manually
- **`ci` concurrency resolved (was a contradiction):** The earlier "sync/low-concurrency" headline understated `ci`, which scans a whole lockfile (fan-out). Resolution: `review`/`install` stay sync + blocking `ureq`; `ci` uses a **bounded std thread pool** with per-thread `rusqlite` connections (D1, S6). No tokio required, but the "low concurrency" label no longer applies blanket. Some "modern CLI" guides use `reqwest` async — only worth it if `ci` fetches hundreds of deps concurrently; revisit then.
- **Fold back into ARCHITECTURE.md:** the untrusted-input hardening (D2/D7/D8) and the `npm install --ignore-scripts` invariant (D9) are concrete gaps in the current design doc and should be added as explicit requirements.
- **Not yet decided:** sandbox mechanism per-OS (D8) — Landlock is Linux-only; need the macOS/Windows fallback story before Phase 1.
- **Signals in shim:** `bin-shim` explicitly does *not* forward signals to the child — if Blueline needs cooperative SIGTERM (e.g. mid-extraction), supply a custom spawner.

---

## Sources
- clispec.dev — "The CLI Spec (Rust)": https://clispec.dev/guide/rust/
- lucaberton.com — "Building CLI Tools in Rust with Clap" (2026): https://lucaberton.com/blog/rust-cli-tools-clap-2026/
- rust-cli.github.io — "Command Line Applications in Rust" (machine communication): https://rust-cli.github.io/book/in-depth/machine-communication.html
- OneUptime blog — clap CLI applications: https://oneuptime.com/blog/post/2026-02-03-rust-clap-cli-applications/view
- dtolnay/thiserror: https://github.com/dtolnay/thiserror
- microsoft.github.io RustTraining — Error Handling Patterns: https://microsoft.github.io/RustTraining/rust-patterns-book/ch10-error-handling-patterns.html
- atharvapandey.com — Library vs Application error strategy: https://www.atharvapandey.com/post/rust/rust-errors-library-vs-app/
- tokio.rs tutorial — "When not to use Tokio": https://tokio.rs/tokio/tutorial
- rust-lang.github.io async-book — IO and blocking: https://rust-lang.github.io/async-book/part-guide/io.html
- microsoft.github.io RustTraining — "Async Is an Optimization, Not an Architecture": https://microsoft.github.io/RustTraining/async-book/ch14-async-is-an-optimization-not-an-architecture.html
- learnrust.net — "What async is, and when you want it" (2026): https://learnrust.net/chapter-23/what-async-is/
- ureq README (blocking I/O rationale): https://github.com/algesten/ureq  ·  https://docs.rs/ureq
- rust-secure-code.github.io — Rust Supply Chain Security Guide: https://rust-secure-code.github.io/rust-supply-chain-security/
- rustsec.org / cargo-audit: https://rustsec.org/  ·  https://github.com/rustsec/rustsec
- microsoft.github.io RustTraining — Dependency Management & Supply Chain (ch06): https://microsoft.github.io/RustTraining/engineering-book/ch06-dependency-management-and-supply-chain-s.html
- safeguard.sh — Rust Cargo Dependency Security Guide: https://safeguard.sh/resources/blog/rust-cargo-dependency-security-guide
- serde-rs/serde issue #1087 — "is Serde safe when deserializing untrusted input?": https://github.com/serde-rs/serde/issues/1087
- atharvapandey.com — Input Validation and Sanitization: https://www.atharvapandey.com/post/rust/rust-sec-input-validation/
- medium.com — "Unsafe JSON Deserialization in Rust" (CWE-502): https://medium.com/@SumitChauhan3754/unsafe-json-deserialization-in-rust-a-real-world-example-in-open-source-code-f1d858a27370
- serde_json docs — from_reader / unbounded_depth: https://docs.rs/serde_json/latest/serde_json/
- rusqlite docs — Connection / Statement / Transaction: https://docs.rs/rusqlite/latest/rusqlite/
- rusqlite_migration: https://docs.rs/rusqlite_migration/latest/rusqlite_migration/
- sqldocs.org — "Rust SQLite: Safe and Efficient DB Access": https://sqldocs.org/rust-sqlite/
- axodotdev/cargo-dist: https://github.com/axodotdev/cargo-dist  ·  https://crates.io/crates/cargo-dist
- napi.rs — release / npm distribution: https://napi.rs/docs/deep-dive/release
- anodizer — npm publishing (optional-deps vs postinstall): https://tj-smith47.github.io/anodizer/docs/publish/npm/
- abemedia/cargo-npm: https://github.com/abemedia/cargo-npm
- bin-shim (npm): https://www.npmjs.com/package/bin-shim
- muxinc/cli — npm-distribution-plan.md: https://github.com/muxinc/cli/blob/main/npm-distribution-plan.md

---

## Adversarial Verification

Two adversarial subagents were run (source validity + logical coherence; omissions + threat model). Initial findings and the fixes applied:

**Source validity**
- PASS — Microsoft RustTraining ch14 ("sync core, async shell") confirmed.
- ISSUE→FIXED — ureq URL was wrong (`al8n/ureq` 404) and a quoted sentence was not verifiable in source. Corrected to `algesten/ureq` and rephrased to ureq's actual stated rationale (keep API simple / deps minimal). No fabricated quote remains.
- PASS — rusqlite_migration `user_version` and optionalDependencies shim pattern confirmed.

**Logical coherence**
- ISSUE→FIXED — `ci` (whole-lockfile fan-out) contradicts the flat "sync/low-concurrency" headline. Resolved: `review`/`install` stay sync + blocking; `ci` uses a bounded std thread pool (D1) with per-thread `rusqlite` connections (S6). Design-Space Map row updated.
- ISSUE→FIXED — single `rusqlite` connection vs concurrent `ci`. S6 now states per-thread connection / `Mutex` guard under fan-out.

**Omissions / threat model**
- GAP→FIXED (D2) — added symlink/hardlink/special-file rejection, setuid stripping, `tar` ≥0.4.45 pin, `cap-std` RESOLVE_BENEATH, gzip-bomb + FD-cap + RAII temp-dir cleanup.
- GAP→FIXED (D7) — added pre-extraction integrity verification (sha512 SRI + registry signature, fail closed).
- GAP→FIXED (D8) — added Landlock/cap-std/seccomp sandbox for extract+diff.
- GAP→FIXED (D9) — clarified "never execute" holds on approve via `npm install --ignore-scripts`; running plain `npm install` would execute the flagged postinstall scripts (contradiction closed).
- GAP→NOTED — extracted `package.json` fields are attack surface (already covered by ARCHITECTURE.md heuristic; restated in D2).

**Status: GREEN.** All adversarial findings either fixed in the doc or explicitly noted as open decisions.
