# Extraction sandbox

`src/sandbox.rs`. Runs the extraction step inside a Landlock-restricted child
process on Linux, and tells the truth when it cannot. This is the layer whose
absence [drift.md](../drift.md) entry 1 tracked for the life of the project: a
hostile archive used to be bounded only by the parser-level budget in
[extract](extract.md); now the kernel refuses a write, read or exec outside the
extraction directory had the extractor itself been buggy.

## Sub-features
- `extract()` — the production entry: spawn the child, or fall back and
  disclose. Everything in `review` routes through here.
- `spawn_child` / `spawn_child_on_linux` — resolve `current_exe`, pipe the
  archive in from a writer thread, bound the wait at `CHILD_TIMEOUT` (300s).
- `child_entrypoint` / `run_child` — the child half. Confines *before* reading
  a byte of stdin, then extracts in-process and replies.
- `confine()` / `confined::restrict_once` — the Landlock ruleset. ABI ladder
  V5 → V3 → V1 under `CompatLevel::HardRequirement`.
- `Reply` + `framed_reply_bytes` / `read_reply` — the child→parent protocol:
  a JSON body with a decimal length prefix, bounded on both ends.
- `map_child_result` — pure exit-code → result mapping, every arm unit-tested
  (no test may spawn from the harness, see the fork-bomb guard below).
- `SandboxLedger` / `SandboxSkip` / `P05_SANDBOX_UNAVAILABLE` — the disclosure.
- `may_spawn_child` / `may_spawn_child_given` — the fork-bomb guard.

## How to get to it (user POV)
Nothing to run: every `review`, `ci`, and recursive child review extracts
through it. The two things an operator can touch:

```toml
[policy]
require_sandbox = true   # refuse the review instead of disclosing a fallback
```

and the disclosure itself — `P05_SANDBOX_UNAVAILABLE` at **Low**, score-neutral,
when a review fell back to the in-process path. The key lives under `[policy]`,
not `[general]`: `Policy` derives `deny_unknown_fields`, so a `[general]` copy is
refused at load rather than silently doing nothing
(`require_sandbox_lives_under_the_policy_table` pins both).

## What this lane does not cover

**The AUR fetch.** `registry/aur.rs` builds the review bytes with `git clone`
and `git archive`, and both run as ordinary subprocesses of the review process.
Landlock cannot fix that: it has no say over the network, which is most of what
`clone` does, and a clone writes to its own working tree by design. The archive
that comes out of `git archive` is then confined on its way into the extractor,
like every other lane, but the git process that assembled it parsed the
attacker-chosen git objects with the full privileges of whatever invoked
blueline. That is the larger parser of the two.

What closes it is the refusal, not a ruleset: with `require_sandbox = true` an
AUR review stops before the first registry call
(`require_sandbox_refuses_an_aur_review_before_any_registry_call`), because a
confined extraction there would keep a promise the key cannot make. With the key
off, the default, the AUR lane reviews exactly as before.

## Driving it
- **Tiers** (`TIER_NAMES` is `["V5", "V3", "V1"]`): V5 is the ceiling that adds
  a filesystem right, V3 is the newest tier that adds `Truncate` without also
  demanding `IoctlDev`, V1 is the floor. V9 is deliberately not requested: its
  only filesystem addition is `ResolveUnix`, about sockets rather than files.
- **Confine-before-read.** A pipe needs no filesystem grant, so restricting
  first costs nothing on Linux and skips a whole spawn-plus-copy on platforms
  with nothing to confine with.
- **`Unsupported` vs `Failed`.** Only `restrict_self` narrows anything, so only
  its failure (and a `PathFd` open failure) is `Failed` → exit `UNUSABLE`,
  never a fallback. Everything else that fails before `restrict_self` is
  `Unsupported` → exit `UNAVAILABLE`, and the parent retries in-process over an
  untouched `dest`.
- **Reply framing.** The writer is bounded by `MAX_REPLY_BODY_BYTES`
  (`MAX_REPLY_BYTES - 32`), which reserves room for the length prefix so a
  ceiling-sized reply cannot deadlock a 64 KiB pipe the parent does not drain
  until the child exits. The reader keeps the larger `MAX_REPLY_BYTES`: its job
  is refusing a hostile peer, not fitting a pipe. An oversized reply is
  *truncated*, never relabelled: the outcome survives, the free text is cut to
  a character boundary with a `[message truncated to fit the reply frame]`
  marker.
- **Exit codes** (`sandbox::exit`): `OK 0`, `REFUSED 3` (the extractor's own
  refusal, rebuilt into its original variant by `rebuild_error`),
  `UNAVAILABLE 4` (nothing was applied, fall back), `UNUSABLE 5` (something
  narrowed or the child broke; `dest` may be partial, never a fallback).

## Gotchas
- **`may_spawn_child` is the fork-bomb guard. Never weaken it.** Under
  `cfg(test)` it is always false, because `current_exe()` in a test is the
  libtest harness: an unguarded self-exec re-ran the suite and fork-bombed the
  machine (2026-10-09, load average 733, reboot required). The guard is pinned
  by `the_test_harness_is_never_allowed_to_spawn_an_extraction_child` and
  `extraction_in_a_test_never_re_execs_the_harness` in this file, and by
  `tests/sandbox_spawns.rs` from outside the harness through the pure
  `may_spawn_child_given`.
- **The real confined path is only pinned on a Landlock Linux.**
  `a_real_child_extracts_and_reports_its_stats`,
  `a_real_child_refuses_a_traversal_archive` and
  `a_child_that_cannot_confine_never_reports_unavailable` drive the built
  binary with the child marker; the first two need Landlock and are
  `#[cfg(target_os = "linux")]`-gated for it. Everywhere else the protocol half
  is pinned by `map_child_result`'s unit tests. `cargo test --lib sandbox::`
  runs against whatever binary is already in `target/debug` and does not
  rebuild it, so a filtered run of these can fail on a stale binary.
- **No test calls `restrict_self` on the harness.** Two unit tests used to call
  `confine` directly; Landlock is irreversible and thread-inheriting, so every
  thread libtest spawned afterwards stayed narrowed for the rest of the run and
  an unrelated temp-dir test could fail with `EPERM` for no visible reason. The
  status comparison survives as a pure `is_fully_enforced`
  (`only_fully_enforced_reads_as_confined`) and the tier-or-refusal decision as
  a pure `tier_or_refusal`
  (`a_partly_enforced_ruleset_is_a_refusal_and_not_a_tier`), both pinned against
  all three `RulesetStatus` values. The tier the kernel granted is read back off
  the child's stderr (`a_confined_child_names_the_tier_it_established`).
- **`SandboxSkip` has three variants and all three fire in production.**
  `UnsupportedPlatform` (compile-time), `Unavailable` (the child's own words),
  `SelfExecUnavailable` (exec failed). A dead child or a failed confinement is
  *not* a skip — it is `ChildFailure::Unusable`, an error the review stops on.
- **The ledger is per-review, not per-archive.** A confined target plus an
  unconfined baseline yields one disclosure, which says "an archive in this
  review" rather than naming which.
- **The 300s `CHILD_TIMEOUT`** is the worst case for one wedged child, twice
  that with a baseline. It is a bound, not an expectation.
