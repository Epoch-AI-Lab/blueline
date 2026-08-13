# CI hardening — next tier (top-1% continuation)

## Context
Phase-1 CI hardening shipped: `fmt`, `clippy -D warnings`, `test --locked`,
`cargo-audit`, and **mutation testing** (`cargo-mutants`) across the fail-closed
surface (`extract` / `manifest` / `registry::npm` / `store`) with **0 missed
mutants** on 64 generated mutants. The 23 gaps the first scan exposed were closed
with boundary / setuid-strip / `list_versions` tests, and the no-bless /
no-overwrite invariant is locked by a `proptest` sequence test.

This file captures the remaining two high-signal additions to reach a genuine
top-1% CI for a tool that parses untrusted input. Pick these up when ready.

## Tier 2 items

### A. `cargo-deny` — license + advisory + banned-crate policy
- Add a `deny.toml` at repo root (seed via `cargo deny init`).
- CI job `deny`:
  ```yaml
  - uses: actions/checkout@v4
  - uses: taiki-e/install-action@v2
    with:
      tool: cargo-deny
  - run: cargo deny check
  ```
- Gotchas:
  - Without `deny.toml` cargo-deny errors ("no config") — start from `cargo deny init`.
  - Fetches the advisory DB over the network (like `cargo-audit`); allow egress in CI.
  - Current deps are MIT / Apache-2.0; run `cargo deny check licenses` to confirm
    the allow-list. Decide banned crates (e.g. copyleft) explicitly.
  - Keep `cargo-audit` too — `audit` = RUSTSEC DB; `deny` = licenses + bans + advisories in one.
- Decisions needed: allowed license set; any banned crates.

### B. `cargo-fuzz` — the marquee differentiator for untrusted parsing
- Add a `fuzz/` crate (own `Cargo.toml`) with `libfuzzer-sys` + `arbitrary`
  dev-deps; requires a **nightly** toolchain in CI (`dtolnay/rust-toolchain` or
  `rustup` + `toolchain: nightly`). Pin the nightly in `fuzz/rust-toolchain.toml`.
- Fuzz targets (the untrusted surface):
  - `safe_extract` — feed arbitrary bytes as the gzipped tarball. Assert: never
    panics; on success every extracted path stays within `dest` (no traversal),
    no symlinks / special files. **Single highest-value target for blueline.**
  - `read_package_json` — fuzz arbitrary JSON bytes. Assert: never panics; parses
    or errors cleanly.
- Gotchas:
  - `fuzz_target!` macro per target under `fuzz/fuzz_targets/*.rs`.
  - Raw bytes need no `arbitrary` derive — use `&[u8]` directly.
  - Fuzzing is long-running: run with a time budget
    (`cargo fuzz run <t> -- -max_total_time=300`) and upload corpus + artifacts.
  - **DEPENDENCY APPROVAL REQUIRED** (AGENTS.md: "ask first: adding a dependency"):
    `libfuzzer-sys`, `arbitrary` are NEW deps in `fuzz/Cargo.toml`. They don't
    touch the main binary's locked deps (separate crate) but add supply-chain
    surface. Needs kriday's go-ahead.
- Open question: required CI gate (slow) vs advisory/periodic run. Recommended:
  required on PRs touching `extract`/`manifest` (paths filter), full run nightly.

## Verification before merge
- [ ] `cargo deny check` green locally.
- [ ] `cargo +nightly fuzz run safe_extract` finds no panics on a short run; add a regression corpus.
- [ ] Both new CI jobs green on a PR.

## Out of scope (future)
- Coverage gating (`tarpaulin`) — secondary to mutation testing.
- Miri / sanitizers (nightly ASan/UBsan) — marginal in Rust; only if fuzzing surfaces UB.
