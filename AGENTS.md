# AGENTS.md

Blueline is a release-diff review desk for the package install line: a
security fail-closed CLI. Everything under `src/` parses untrusted package
data. Treat every parse/extract/verify boundary as a security surface and
fail closed on any doubt.

## Commands (run from repo root)

```sh
./scripts/verify.sh            # fmt + clippy + test + references — the gate
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
- Workflows: `actionlint -shellcheck= -pyflakes=` (run it after touching
  `.github/`; see the Guardrails section)

The first three are the Rust gate (`.github/workflows/ci.yml`), and if a change
passes them it passes CI's Rust jobs. They are no longer *exactly* the gate: the
same workflow also runs `actionlint` over the workflows, a supply-chain audit,
and two dogfood jobs that run the built binary against this repository's own
`Cargo.lock` and `package-lock.json`. Mutant scope is `src/**/*.rs`, so a change
to a module outside `src/` is not mutation-tested at all. The toolchain is
pinned in `rust-toolchain.toml` — do not run a different one.

Two of those cannot be reproduced by the three commands above. A green local
run is necessary, not sufficient.

## Delegating
Review agents grade an answer. They do not derive one, and they inherit the
premise you hand them.

- Never hand a reviewer your own conclusion and ask it to check. A finding
  that says "there is a hole here" gets investigated by someone who has not
  seen your fixture, your reading of the dependency, or your test output.
  Verification that starts from your answer cannot escape your answer.
- When a finding contradicts you, treat your own reproduction as the suspect.
  A hand-built fixture proves only that the code does what the fixture
  exercises. Check that the fixture reaches the path its comment claims before
  you use it to close a finding: an extract.rs fixture that omitted the ustar
  version field let tar-rs yield the header instead of consuming it, and the
  resulting "false positive" shipped a 256 MiB allocation hole for a day.
- For a problem with an open answer and an expensive failure, draft several
  solutions in parallel and have a second group review the candidates. One
  candidate graded by one reviewer is a single point of failure wearing two
  hats. Comparing candidates also surfaces the combination nobody would have
  proposed alone.
- Confirm a mutation actually applied. Roughly one in three revert-and-test
  cycles in this repo silently changed nothing: a string replace that did not
  match, a stale `/tmp` backup restored over newer work, a `--lib` run against
  a `blueline` binary cargo had not rebuilt. Each one read as "verified".
- Treat a hand-picked revert as a floor, not evidence. It tests the one change
  you thought of. CI's `cargo mutants` enumerates the rest, and it found a
  survivor in the CVSS v2 scoring that six review passes and every manual check
  had cleared, because all six reference vectors used `AV:N` and its weight is
  1.0, so multiplying and dividing by it agree. Vary a fixture's constant
  before trusting it to pin the expression around it.
- Skip the fan-out for one-line changes. Deleting dead code does not need four
  agents. The bar is an open answer space and an expensive miss.

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
- Run the three commands above before finishing any work.
- Lint workflows with `actionlint` after touching `.github/`. GitHub compiles a
  workflow before running any step, so one bad expression yields a run with zero
  jobs that cannot be retried, and a message that does not name the line. It
  also expands expressions inside a `run:` block even when they sit in a shell
  comment, so writing `${{ }}` out literally in a comment takes the whole
  workflow down. That happened, and it failed every check in the repo for a day
  while a YAML parser reported the file as valid.

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
- Fix a bug you found, even when it predates the current branch. "Pre-existing",
  "out of scope", "unrelated to this diff", and "would widen the PR" are not
  reasons to leave a defect live in a fail-closed tool. Age is a fact about when
  a bug arrived, not an argument for keeping it. If a fix genuinely belongs in
  its own change, say so and open that change in the same session — do not
  report the finding and stop.

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
- Shipping a fix you could not verify. A patch with no test that fails without
  it is a guess. Re-introduce the bug, watch the test catch it, then restore.

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

`scripts/check-references.sh` resolves every source citation in `references/`
against the tracked tree and fails if a cited path is gone, a cited line falls
past the end of its file, or a lane file is unreachable from the index. It runs
in `./scripts/verify.sh` and as its own CI job. If you rename or move a source
file, run it rather than assuming the map still points at it.
