# Blueline performance report

Status: the runtime numbers were measured 2026-10-11 against v0.3.1
(`2d7864e`), a tree that predates this file. Items 1, 2 and 4 of section 7 are
**implemented** on the `perf/overlap-and-window` branch, item 3 was finished on
2026-10-19, and section 10 is the dev-gate work, also implemented. Item 5
describes a file that no longer exists. Every number below was measured on the
dev box, and every one carries the command that produced it or the file and
line it came from.

Read this before starting work. Section 8 lists what is *not* known, and two of
the five items in section 7 rest on code reading rather than measurement.

---

## 1. The verdict

This is a project problem, not a Rust problem. The release binary uses **45 ms
of CPU** and **17 MB of RSS** to review a 200-file package. There is no
language-level overhead worth discussing at this scale.

What costs resources is two other things:

1. A blocking network round trip to `api.osv.dev` in the critical path, plus a
   fully serial evaluation loop in the `ci` lane.
2. Build artifacts. `target/debug` is **5.4 GB** on this box, and a single test
   pins a core and 280 MB for 25 seconds on every gate run.

---

## 2. Runtime, per review

Release binary, 4-core Fedora box, median of 7 runs against a loopback registry
serving synthetic npm packages with real sha512 integrity. Produced by
`scripts/perf_harness.py`.

| package | wall, default | wall, advisories off | CPU | peak RSS |
|---|---|---|---|---|
| 200 files x 40 B | 717 ms | 174 ms | 45 ms | 17.3 MB |
| 2000 files x 1 KB | 1077 ms | 533 ms | 381 ms | 17.5 MB |
| 2000 x 1 KB, 1% changed | 904 ms | 390 ms | 255 ms | 16.6 MB |
| 90 MB of text, line diffed | 6185 ms | data pending | 3340 ms | 117 MB |
| 96 MB of text, over diff cap | 1175 ms | data pending | 452 ms | 18 MB |

Startup is not a factor: 4 MB RSS, under 1 ms.

RSS is sampled from `/proc` across the process tree, so it covers the Landlock
extraction child as well as the parent. An earlier draft of this table carried
24 to 32 MB for the first three rows, which came from `wait4` rusage. That
method was discarded (see section 8) and those figures were wrong.

The last two rows are the same content volume on either side of the 2 MiB diff
cap (`MAX_DIFF_FILE_BYTES`, `src/diff.rs:11`). Line diffed, resident memory
lands at about 1.3x the content. Skipped as opaque, it stays at 18 MB. That is
roughly **19 ms of CPU per megabyte diffed**.

### The wall clock gap

One review, every request to the loopback registry, gap since the previous one:

```
   t (ms)      gap      bytes  path
    224.4    224.4        534  /cntpkg                     packument
    230.3      5.9       2273  /cntpkg/-/cntpkg-1.0.1.tgz   target tarball
    384.0    153.7       2254  /cntpkg/-/cntpkg-1.0.0.tgz   baseline tarball
   1145.9    762.0          0  404 attestation             670 ms gap

   default policy     1166 ms total
   advisories off      196 ms total
   CPU, either way      45 ms
```

Only four registry requests happen, so the packument memo at
`src/registry/npm.rs` is already doing its job. The 670 ms gap is a query to
`api.osv.dev`, which never touches the loopback registry and so does not appear
above. Measured directly:

```
POST https://api.osv.dev/v1/query    0.72s   0.56s   0.68s   0.77s
```

It is issued at `src/review.rs:294`, **after** extraction has finished, and it
depends on none of the extracted tree. On a small package it is about 75% of
total wall clock.

---

## 3. The serial case that hurts: `blueline ci`

| fact | value | where |
|---|---|---|
| evaluation loop | plain sequential `for` | `src/ci.rs:296`, `src/ci.rs:409` |
| default package cap | 100 | `src/policy.rs:464` |
| concurrency anywhere in `src/` | none, no `rayon`, no `par_iter` | whole crate |
| advisory cache on a CI runner | always cold, 12 h clean TTL | `src/policy.rs:404` |
| worst case network waiting | ~56 s | 100 x 560 ms |

Every package in a lockfile pays its own OSV round trip, in order, on a machine
where the advisory cache is always empty.

---

## 4. Build and disk cost

| command | wall | peak RSS |
|---|---|---|
| `cargo build --release --locked -j 2` (LTO on) | 3m06s | 970 MB |
| `cargo build --locked` (no-op) | 9.5 s | 377 MB |
| `touch src/diff.rs && cargo build --locked` | 4.1 s | 378 MB |
| `cargo test --all-targets --locked --no-run -j 2` | 32 s | 574 MB |

On disk:

| artifact | size |
|---|---|
| `target/debug` total | 5.4 GB |
| `target/debug/incremental` | 1.9 GB across **101** stale session caches |
| `target/debug/deps` | 3.0 GB |
| test binaries in `deps` | 32 |
| `target/debug/blueline` | 105 MB |
| `target/release/blueline` | 7.6 MB |

`Cargo.toml` sets only `[profile.release]`. There is no `[profile.dev]`, so the
dev profile is the cargo default: `opt-level=0`, full debuginfo, and unbounded
incremental compilation.

---

## 5. The dev gate

Superseded by section 10, which re-measured this after the dev-profile change.
Kept because the shape of the problem is still what it was.

`./scripts/verify.sh`, default stage set, warm build cache:

| stage | wall | CPU | peak RSS |
|---|---|---|---|
| `cargo fmt --all -- --check` | 0.7 s | 0.6 s | 76 MB |
| `cargo clippy --all-targets --locked -- -D warnings` | 5.5 s | 5.2 s | 437 MB |
| `cargo test --all-targets --locked` | **49.8 s** | **57.6 s** | **391 MB** |
| `scripts/check-references.sh` | 1.1 s | | |

The test stage is the entire cost, and inside it one test dominates.

---

## 6. `blueline-<hash>` at 40%+ CPU

The process Kriday sees is cargo's libtest harness from `target/debug/deps/`.
It is **not** a daemon and **not** the CLI. It exists only while `cargo test`
runs. If one is sitting there when no test is running, it is a stuck run and
`pkill -f 'blueline-'` clears it.

Module breakdown, timed by running each module's tests in isolation:

```
registry        94 tests   20.7 s
  registry::npm 18 tests   23.4 s   <- 20.3 s of this is one test
  registry::aur 31 tests   10.3 s
extract         56 tests    6.3 s
recall          51 tests    4.3 s
everything else           ~1.1 s each (that is bare process start)
```

The single test, run alone:

| test | wall | CPU | peak RSS |
|---|---|---|---|
| `registry::npm::tests::the_packument_memo_is_bounded_and_the_estimate_is_not_a_fig_leaf` | **25.7 s** | 22.96 s at 90% of one core | **280 MB** |
| `registry::npm::tests::the_packument_estimate_is_exact` (control) | 0.00 s | 0.00 s | 10 MB |

That one test is **half the wall clock of the entire 835-test lib suite**, and
it alone accounts for 280 MB of the test stage's 391 MB peak.

### Why

`src/registry/npm.rs:1232` builds a deliberately oversized fixture: 64 versions,
each carrying a signature block of two 2 MiB strings, so 256 MiB of
`serde_json::Value`.

`packument_size_estimate` at `src/registry/npm.rs:301` then calls
`serde_json::to_string` on each block purely to read `.len()`, materialising a
further ~256 MiB of transient `String`.

That is roughly half a gigabyte of allocation churn in a debug build at
`opt-level=0`.

### Production impact: none

The docstring at `src/registry/npm.rs:285` says it directly: the estimate is not
a security bound, and the fetch is byte-capped separately. No real review builds
a 256 MiB signature block. This is purely developer-experience cost.

A second, smaller contributor: eight tests in `src/registry/npm.rs` run mock HTTP
servers in a `while start.elapsed() < Duration::from_millis(600)` loop and
`a_packument_is_fetched_once_per_package` polls to a 10 s deadline. That is
about 4.8 s plus 2 s of pure sleeping, all inside `#[cfg(test)]`.

---

## 7. Ranked work items

Ordered by conviction, not by size of win.

### 1. Overlap the OSV query with the tarball fetch — IMPLEMENTED

`fetch_advisories` was called at `src/review.rs:294`, after both tarballs were
already extracted. The query takes about 560 ms and depends on none of that.
Resolution is now split into `resolve_advisories`, which returns `Ready`
without touching the network and `Pending` with the query already running,
and `PendingAdvisory::join`, called at scoring time. The security orderings
the item listed are all preserved and pinned by tests.

- Target: 717 ms wall becomes about 175 ms on a 200-file package, CPU unchanged
  at 45 ms.

### 2. Parallelise the `ci.rs` evaluation loop — IMPLEMENTED

`src/ci.rs:296` and `src/ci.rs:409` called `evaluate_package` one package at a
time. 100 packages at 560 ms each is about 56 s of network waiting. The
lockfile lane now runs up to eight workers, each with its own `ReviewContext`
and its own database handle, results ordered by candidate index. **The AUR
half (`evaluate_aur_ci_diff`) now runs through the same driver** with an
empty integrity map: same worker cap, same per-worker context and store
handle, same candidate-order guarantee, pinned by
`tests/aur_ci_parallel.rs` (slow-first pin still reported first).

- The store is already opened in WAL mode with a 5 s busy timeout at
  `src/store.rs:389`, so concurrent writers have a path.
- Findings are emitted in candidate order regardless of completion order,
  because CI output is diffed between runs.
- Each worker gets its own `ReviewContext`, which holds `RefCell`s.
- The budget check still refuses before any work starts, not after.
- Behaviour change: a failure in one package no longer stops the rest; a
  failed run now records `record_verified` and advisory-cache entries for
  packages the serial lane never reached.

### 3. Cap the incremental cache — IMPLEMENTED, in two halves

`[profile.dev]`/`[profile.test]` set `debug = "line-tables-only"` and emit no
debug info for dependencies, which shrank every cache and the 100 MB test
binary. That half does not stop them accumulating: cargo has no knob for the
count and `cargo clean` has no `--incremental`, so eviction has to be a script.
`scripts/prune_incremental.sh` is that script. It judges a session by the
newest file *inside* it rather than the directory's own mtime, because cargo
touches the directory when it reuses a session, which makes a week-dead cache
look recently used. Dry run by default; `--apply` to delete.

Measured 2026-10-18 at `fae8050`: `target/debug/incremental` was 4.1 GB across
251 sessions, 3.2 GB of them blueline's own 58. `cargo mutants` sets
`RUSTFLAGS`, which changes the fingerprint, so every mutation run writes a
fresh session; single sessions of 288 MB, 272 MB and 269 MB were all three to
four days old. 107 sessions older than three days totalled 1982 MB.

Deleting an incremental session cannot invalidate a built artifact. Cargo's
freshness check reads the fingerprint files in `.fingerprint`, not the session
directories; a `cargo test --no-run` after `--days 0 --apply` on the lab tree
was still a 0.46 s no-op. Worst case is one rebuild.

- Do not touch `[profile.release]`: `lto` and `strip` stay.
- CI builds with `--locked`, so this must not move `Cargo.lock` — it does not.

### 4. Stop reading every file twice — IMPLEMENTED

The scan half is done: `scan_tree` streams each file once through a 64 KiB
window for the hash, the NUL scan and the UTF-8 check, instead of `fs::read`
plus two passes. Peak memory is bounded by the window, not by the largest
file. The diff half still reads both sides whole in `diff_single_file`,
because `similar::TextDiff` needs the strings.

```
scan_tree()       src/diff.rs:59   target tree, was fs::read per file
scan_tree()       src/diff.rs:72   base tree,   was fs::read per file
diff_single_file  src/diff.rs:365  fs::read(old)   — unchanged
diff_single_file  src/diff.rs:369  fs::read(new)   — unchanged
```

- The SHA-256 of file contents must not change, because it decides whether a
  file is compared at all.
- `classify_bytes` must still see enough bytes to distinguish `Text`, `Binary`
  and `OpaqueTooLarge` at the 2 MiB cap.
- The extraction caps in `extract.rs` are a separate guard and must not be
  weakened.

**This one is read from the code, not isolated by a measurement.**

### 5. Tighten the sandbox poll — NOT APPLICABLE TO CURRENT MAIN

`wait_with_timeout` at `src/sandbox.rs:1120` polls `try_wait` on a 20 ms sleep,
twice per review for the target and baseline extractions. **`src/sandbox.rs`
does not exist on current `main`**: it was added after `2d7864e` and removed
again by the dead-code cleanup, and extraction is in-process on `extract.rs`
now. This item describes a file that is gone; the 174 ms no-advisories figure
it is measured against came from a tree that had it. Re-measure before acting.

- Keep the `CHILD_TIMEOUT` bound.
- Keep the comment explaining why `try_wait` is used at all.
- Latency only. No reply parsing, exit status handling or error path may move.

**Also read from the code, not isolated by a measurement.**

### 6. The 20-second test — DONE

Implemented in commit `b0055f3` ("Stop allocating whole documents just to
measure them"). `packument_size_estimate` now counts bytes through a
`CountingWriter` + `serde_json::to_writer` (`serialised_len`) instead of
building a transient `String`, so the 256 MiB signature block no longer
materialises a second 256 MiB `String` on every call. No assertion changed.

The remaining tension is unchanged and still open: the 256 MiB fixture exists
so the ceilings bind even when the arithmetic is mutated, and
`the_packument_memo_ceilings_are_the_documented_sizes` pins both constants
exactly. Whether one of those two is redundant is still a question about what
the test is for, and is left alone.

---

## 8. What is not known

Read these before trusting anything above.

- **No profiler.** `perf`, `valgrind` and `strace` are all absent on this box.
  There is no call graph and no syscall count. Items 4 and 5 are code reading.
- **Two first measurements were wrong and were discarded.** `wait4` rusage
  reported the same scenario at 24 MB and 71 MB on different runs, and folds
  reaped children into one figure, so it cannot separate the parent from the
  Landlock extraction child. Every memory number here comes from sampling
  `/proc/<pid>/status` across the process tree every 2 ms instead. Separately,
  the first scenario generator built one 8 MB file while labelling it 60. Both
  were fixed and re-measured.
- **The 90 MB and 96 MB rows have no advisories-off figure.** That cell reads
  data pending rather than a guess.
- **The 480 MB scenario failed, and it was not blueline.** `/tmp` on this box is
  a 3.8 GB tmpfs, RAM-backed, and extraction writes there. Blueline's own
  512 MiB extraction cap held and refused. Because `/tmp` is tmpfs, a large
  package burns RAM as tmpfs pages on any machine configured this way.
- **The toolchain pin is no longer inert here, so the numbers above are the odd
  ones out.** This line said `rustup` was missing and everything built with
  Fedora's 1.98.1. As of 2026-10-18 rustup 1.29.1 is installed and the 1.97.1
  channel in `rust-toolchain.toml` binds, so sections 1 to 8 are 1.98.1
  numbers and section 10 is 1.97.1. Re-measure before quoting a section 1 to
  8 figure as current.
- **The test suite was not run under mutation testing.** No claim here is about
  mutant coverage.

---

## 9. Reproducing this

```sh
# Runtime, wall clock, CPU and RSS, advisories on and off.
python3 scripts/perf_harness.py

# One scenario at a time, so the memory-heavy ones stay isolated.
ITERS=7 ONLY=many-small python3 scripts/perf_harness.py

# The dev gate, stage by stage.
/usr/bin/time -v cargo test --all-targets --locked

# The dominant test, alone, with real rusage.
BIN=target/debug/deps/blueline-<hash>
/usr/bin/time -v $BIN \
  registry::npm::tests::the_packument_memo_is_bounded_and_the_estimate_is_not_a_fig_leaf \
  --exact

# Every test binary on its own, no cargo in the way (section 10.1).
# Resolve the newest executable per target: target/debug/deps keeps several
# stale hashed binaries and measuring one of those reports an old build.
for b in $(ls -t target/debug/deps/blueline-* target/debug/deps/*-* | head -40); do
  [ -x "$b" ] && [ -z "$(echo "$b" | grep -E '\.(d|o|rlib)$')" ] || continue
  printf '%s %s tests\n' "$b" "$("$b" --list 2>/dev/null | grep -c ': test$')"
done

# Stale incremental caches. Dry run unless --apply.
scripts/prune_incremental.sh --days 3
```

### Running the test suite safely

`AGENTS.md` records the 2026-10-09 incident where the suite spawned 529 live
processes, load 733, and took the machine down. Measured again on 2026-10-11
with a process-count watchdog: the suite peaks at **6** processes and passes in
**42 s**, so the fork bomb does not currently reproduce. The watchdog is worth
keeping anyway.

```sh
# Kill the whole process group if the live process count crosses the cap.
scripts/perf_watchdog.sh 180 40 cargo test --all-targets --locked
```

It polls the process-group size every second, aborts at the cap or the wall
limit, and reports the peak. Use it rather than a bare `cargo test` when
experimenting near process-spawning code (the `git archive` path in the AUR
registry adapter is the one that actually forks here).

Measured again on 2026-10-19 at `fae8050` with the section 10 profile: the
suite still peaks at **6** processes and passes in **20 to 24 s**.

---

## 10. The dev gate, measured 2026-10-19

Sections 1 to 8 are about the shipped binary. This one is about the time and
the memory a developer spends before the shipped binary is ever involved. All of
it is `opt-level`, one script, and `Cargo.toml` lines, measured at `fae8050` on
the dev box under 1.97.1.

### 10.1 What the gate cost

`./scripts/verify.sh`, warm build cache, before:

| stage | wall | CPU | peak RSS |
|---|---|---|---|
| `cargo fmt --all -- --check` | 1.4 s | 1.1 s | 69 MB |
| `cargo clippy --all-targets --locked -- -D warnings` | 0.7 s | 0.4 s | 86 MB |
| `cargo test --all-targets --locked` | **46.4 s** | **53.2 s** | **342 MB** |
| `scripts/check-references.sh` | 0.3 s | 0.2 s | 11 MB |

Clippy is cheap only because its own cache is warm; cold it was 42.6 s. It is
not the target. The test stage was the whole cost, and it split like this,
timing each test binary directly with no cargo in the way:

| binary | tests | wall | CPU | peak RSS |
|---|---|---|---|---|
| `blueline` (lib) | 870 | 16.0 s | 29.5 s | 245 to 320 MB |
| `scenarios` | 22 | 13.7 s | 14.2 s | 25 MB |
| `aur_ci_parallel` | 1 | 3.5 s | 0.6 s | 4 MB |
| the other 12 binaries | 84 | 5.6 s | 4.8 s | 21 MB or less each |

Their sum is 38.8 s against a reported 46.4 s, so about 7.5 s is cargo running
15 binaries one after another plus freshness checks.

### 10.2 The change

`[profile.dev]`, `[profile.test]` and both `[profile.*.package."*"]` sections
now set `opt-level = 1`. `[profile.release]` is untouched, so nothing about the
shipped binary moved. Four variants were built on disk outside the repo and
compared interleaved, so a quiet machine could not favour one side:

| variant | lib 870 | memo test | scenarios |
|---|---|---|---|
| baseline, everything at 0 | 16.0 s | 5.2 s | 13.7 s |
| local crate 1, deps 0 | 13.2 s | 4.6 s | 11.7 s |
| local crate 0, deps 1 | 14.2 s | 5.9 s | **6.2 s** |
| everything at 1 | **5.3 s** | **0.11 s** | **3.8 s** |

The two halves do different work and both are needed:

* **Dependencies at 1 buys `scenarios`.** Those 22 tests spawn the real binary,
  and its time is sha2, flate2, walkdir, SQLite and the diff engine.
* **The local crate at 1 buys the packument memo test**, 5.2 s to 0.11 s.
  Nothing else moves it. Optimizing `serde_json` alone moved it by zero, and
  that is the expected result rather than a surprise: serde's serializer is
  generic, so it is monomorphized into blueline and compiled as blueline's own
  code. The crate that calls it is the crate that has to be optimized.

### 10.3 What it bought, in the repo

| | before | after |
|---|---|---|
| `cargo test --all-targets --locked`, wall | 41.7 / 50.6 s | **20.2 / 22.5 / 24.4 s** |
| same, CPU | 49.9 / 54.0 s | **14.1 / 15.1 / 15.4 s** |
| same, peak RSS | 328 / 358 MB | **249 / 272 / 282 MB** |
| whole gate, warm | 48.9 s | **23.8 s** |

That is **2.1x wall, 3.5x CPU and 27% less peak RSS**, with all 870 tests
passing and `cargo clippy --all-targets --locked -- -D warnings` clean at
opt-level 1. Per binary after: lib 5.6 s and 189 MB, scenarios 4.9 s,
`aur_ci_parallel` 3.3 s of which 2.8 s is waiting.

### 10.4 What it cost

| | cold full build | rebuild just blueline | one-file edit, all targets |
|---|---|---|---|
| baseline | 1 m 18 s | 34.9 s | 2.80 s |
| everything at 1 | 5 m 47 s | 129.4 s | 2.91 s |

`CARGO_BUILD_JOBS=2`, warm registry cache, empty target dir. The rebuild of
this repository at the new profile was 5 m 27 s, which matches. Max single
process during a cold build was 771 MB against 732 MB, so build RAM does not
move.

The daily loop is the part that matters and it does not get worse: touching one
source file and rebuilding every test target is 2.80 s before and 2.91 s after.
The cost lands once per cold build, and CI's first run after the change, since
every job caches `target/` with `swatinem/rust-cache@v2`.

It is level 1 and not 2 because the entire win is already banked at 1, and 2
costs more compile time for no measured return.

### 10.5 Memory during a dev run

* One test run writes **390 MB into TMPDIR**, and `/tmp` here is a 3.8 GB
  tmpfs, so that is RAM. Sampled high-water and `MemAvailable`:

  | TMPDIR | wall | lowest `MemAvailable` |
  |---|---|---|
  | `/tmp` (tmpfs) | 44.8 s, 47.6 s | 1189 to 1321 MB |
  | disk-backed | 64.7 s | 1493 MB |

  Moving TMPDIR to disk buys about 300 MB of available memory and costs 45% of
  the wall clock, because every extracted tarball and every fixture write goes
  through the filesystem instead of memory. On this box tmpfs is the right
  default. If memory ever becomes the binding constraint, that is the dial, and
  the fixture that writes the most is `src/extract.rs:1250` with a 64 MB
  payload.
* A third of the test stage's peak RSS is the memo test's 108 MB fixture. It
  has to carry more than `MAX_MEMOISED_PACKUMENT_BYTES` (64 MiB) for the
  ceiling to bind, so 96 MB of signature payload has to be real and resident.
  There is no honest way to shrink it without weakening what it proves.
* `target/debug` was 9.5 GB, of which 4.1 GB was incremental caches (section 7
  item 3) and 3.2 GB was 133 executables of which 16 were current. The rest
  were from before the `line-tables-only` change, at 82 to 149 MB each where
  the current ones are 10 to 51 MB. `cargo clean` reclaims all of it; the prune
  script stops it growing.

### 10.6 What this did not fix, and what is left

* `cargo nextest` is now the default in the gate. It overlaps the 15 test
  binaries instead of running them one at a time. Measured 2026-10-19 with 8
  threads: the whole gate went from 23.8 s to 11.4 s wall, 3.1x over the
  pre-opt-level baseline of 48.9 s. It is installed as a prebuilt binary from
  the GitHub releases page rather than built from source, and CI installs it
  through `taiki-e/install-action@v2`.
* `tests/aur_ci_parallel.rs:15` sleeps 1500 ms on purpose, to prove the
  slow-first candidate is still reported first. That is a real property and
  shrinking the delay weakens the test.
* Eight tests in `src/registry/npm.rs` used to spin a mock server in a
  `while start.elapsed() < 600ms` loop and then join the thread, so each cost
  600 ms of sleeping however fast the work was. Each loop now exits as soon as
  the expected number of requests has been served, with a 50 ms idle fallback
  and a 5 s safety deadline. Measured 2026-10-19: `cargo test --lib registry::npm`
  single-threaded went 7.11 s to 2.37 s, five consecutive runs all green.
* `test-threads = 8` in `.cargo/config.toml` and passed explicitly to
  `cargo nextest run`. On the baseline binaries: 1 thread 36 to 42 s, 4
  (default) 17 to 19 s at 275 MB, 8 threads 13.9 to 14.5 s at 387 to 449 MB.
  8 threads is 1.25x for 40 to 60% more peak RSS, which on a shared box is a
  trade rather than a win, but on a dedicated CI runner it is free.

### 10.7 Limits of section 10

* **The box has other tenants.** Load average ran 4 to 11 during the A/B, with
  firefox, synara and several agent servers resident. Every comparison is
  interleaved A/B and reported as a median of 2 to 3 rounds, but treat a single
  number as plus or minus 20%. The baseline test stage itself ranged 41.7 s to
  50.6 s across two interleaved rounds.
* **No profiler.** `perf`, `valgrind` and `strace` are still absent, so every
  conclusion here is from timing whole binaries rather than from a call graph.
  The monomorphization claim is the one that most deserves a profiler, though
  the A/B supports it directly: optimizing `serde_json` moved the memo test by
  zero.
* **Two lab runs skipped a test.** The profile variants were built from
  `git ls-files | tar`, which has no `.git`, so the two tests that shell out to
  `git show HEAD:` fail there
  (`ci::tests::cargo_missing_base_returns_empty_cargo_toml` and
  `ci_pypi_lockfile_hash_verification`). Both were skipped in the lab and pass
  in the repo. Not product bugs.
* **Cold build numbers are `-j2` with a warm registry cache.** A CI runner with
  a cold registry will be slower; the ratio should hold and the absolutes will
  not.