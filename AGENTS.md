# AGENTS.md

Blueline is a release-diff review desk for the package install line: a
security fail-closed CLI. Everything under `src/` parses untrusted package
data. Treat every parse/extract/verify boundary as a security surface and
fail closed on any doubt.

## Commands (run from repo root)

- Format: `cargo fmt --all`
- Lint:   `cargo clippy --all-targets -- -D warnings`
- Test:   `cargo test --all-targets --locked`

These three are exactly the CI gate (`.github/workflows/ci.yml`). If a change
passes locally it passes CI. The toolchain is pinned in `rust-toolchain.toml`
— do not run a different one.

## Guardrails

**Always**
- Run the three commands above before finishing any work.
- Fail closed: on any doubt in extraction, parsing, or verification, error
  out loud rather than guess.
- Use `anyhow` at the boundary (`run()` → `main`), `thiserror` inside modules.
- Commit `Cargo.lock` changes together with the dependency change that caused
  them.
- Read `ARCHITECTURE.md` before touching module boundaries.
- After each merged PR, add an entry to `CHANGELOG.md` under `[Unreleased]`
  in the same branch.

**Ask first**
- Adding a dependency — propose it and wait for a decision.
- Changing the extraction/verification pipeline in `extract.rs`.
- Changing the SQLite `known_clean` store in `store.rs`.

**Never**
- `unsafe` — a compile error via `#![forbid(unsafe_code)]` in `src/main.rs`.
- New `unwrap()`/`expect()` on untrusted input. Unreachable-reference unwraps
  in database loops are the only acceptable case; everything else must error.
- Skipping the CI gate. If CI breaks, fix it in the same branch.

## Conventions
- Do NOT USE Other languages to code. Use your harness tools
- Errors surface with alternate (`{e:#}`) formatting so the cause chain
  prints — see `src/main.rs`.
- Modules are self-contained under `src/`; `registry/` is a directory module.
- Unit tests live beside code; integration tests live in `tests/`.
- Do not add comments to code unless they earn their place.
