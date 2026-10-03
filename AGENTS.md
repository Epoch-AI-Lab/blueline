# AGENTS.md

Blueline is a release-diff review desk for the package install line: a
security fail-closed CLI. Everything under `src/` parses untrusted package
data. Treat every parse/extract/verify boundary as a security surface and
fail closed on any doubt.

## Commands (run from repo root)

```sh
./scripts/verify.sh            # fmt + clippy + test — the Rust gate
./scripts/verify.sh --mutants  # the gate, then mutation testing
./scripts/verify.sh --all      # the gate, plus mutation testing + cargo-deny
```

`scripts/verify.sh` runs the exact command lines `.github/workflows/ci.yml`
runs, and is the single source of truth for "did I pass?". It works from any
working directory — it resolves the repo root from its own location.

The three underlying commands are:

- Format: `cargo fmt --all -- --check`
- Lint:   `cargo clippy --all-targets --locked -- -D warnings`
- Test:   `cargo test --all-targets --locked`

Both extra flags matter and are easy to drop. `cargo fmt --all` *without*
`--check` rewrites your files instead of failing, so it reports success on
code CI will reject. `cargo clippy` without `--locked` may resolve a different
dependency graph than the committed `Cargo.lock`, so it lints code CI never
builds.

Those three are the *Rust* gate, not the whole gate. CI additionally runs a
`cargo deny` supply-chain audit and two dogfood jobs that review this
repository's own `Cargo.lock` and `package-lock.json`. `./scripts/verify.sh
--all` covers the supply-chain audit locally; the dogfood jobs need the binary
built. (`--all` also runs mutation testing — use `--fast` if you only want the
audit.)

The toolchain is pinned in `rust-toolchain.toml` — do not run a different
one. That pin only binds under `rustup`; on a machine without rustup the file
is inert and `cargo` silently uses the system toolchain, which is a *different*
compiler than CI. Check `rustc --version` against `rust-toolchain.toml` before
trusting a local pass.

`cargo-mutants` and `cargo-deny` are *not* rustup components; see the comment
in that file. Neither is installed by default, so `--mutants` and `--all` exit
127 until you `cargo install` them.

## Guardrails

**Always**
- Run `./scripts/verify.sh` before finishing any work.
- Run `./scripts/verify.sh --mutants` for security-critical work — anything
  touching extraction, integrity, policy, or the heuristic rule engine.
  Mutation testing is what proves the suite would catch a regression here,
  so audits don't have to. It is slow; that is the point.
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
- `unwrap()` in production code — a compile error via
  `#![deny(clippy::unwrap_used)]` in `src/lib.rs` and `src/main.rs`, switched
  on by `disallowed-methods` in `clippy.toml`. The only sanctioned uses are
  invariant unwraps that no input can reach (see the six annotated sites in
  `src/diff.rs`); they carry a per-site `#[allow]` and a reason. Do not
  widen an `#[allow]` to a whole function — that removes the guardrail for
  every future line in it.
- Skipping the CI gate. If CI breaks, fix it in the same branch.

## Conventions
- The engine is Rust. `src/` is the security-critical path and is written
  only in Rust; there are no exceptions to that within `src/`. Outside
  `src/`, other languages are used where the platform requires them and are
  legitimate, not a violation: the npm shims
  (`packages/{blueline,npx}/bin/blueline.js`), the benchmark harness
  (`scripts/benchmark_suite.py`, `scripts/verify_benchmarks.py`), and the
  packaging generator (`scripts/generate-packages.mjs`). Do not introduce a
  new non-Rust language; extend what is already there instead.
- Errors surface with alternate (`{e:#}`) formatting so the cause chain
  prints — see `src/main.rs`.
- Modules are self-contained under `src/`; `registry/` is a directory module.
- Unit tests live beside code; integration tests live in `tests/`.
- Do not add comments to code unless they earn their place.

## On `expect_used`

`clippy::unwrap_used` is denied crate-wide; `clippy::expect_used` is not, and
that asymmetry is deliberate. `allow-unwrap-in-tests = true` in `clippy.toml`
exempts `unwrap()` inside `#[test]` fns (~800 of them) but does **not**
exempt `expect_used` — it fires on ~15 pre-existing `expect()`/`expect_err()`
calls inside `#[cfg(test)]` modules (`agent`, `recall`, `recursive`,
`review`, `shim`).

So if `expect_used` ever becomes desirable, the correct form is a per-module
`#[allow(clippy::expect_used)]` on the `#[cfg(test)] mod tests` blocks, added
alongside a cleanup of those call sites. Do not add a crate-level deny: it
would fail the build on test code that is not production code, and the usual
response to that is to delete the lint.

Note also the config-form trap documented in `clippy.toml`:
`disallowed-methods = [{ path = "unwrap", msg = "..." }]` is a hard config
parse error, and the plain-string `["unwrap"]` form emits a misleading
"does not refer to a reachable function" warning on every run. The form in
use is `{ path = "unwrap", allow-invalid = true }`.

## Feature map

`references/README.md` maps each user-visible feature to the code that
implements it and the tests that prove it. Read it before changing a
feature's behaviour.
