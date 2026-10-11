# Blueline performance report

Status: measured 2026-10-11 against v0.3.1 (`2d7864e`), a tree that predates
this file. Items 1, 2 and 4 of section 7 are **implemented** on the
`perf/overlap-and-window` branch; the rest are not. Every number below was
measured on the dev box, and every one carries the command that produced it or
the file and line it came from.

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

### 2. Parallelise the `ci.rs` evaluation loop — IMPLEMENTED (npm/cargo half)

`src/ci.rs:296` and `src/ci.rs:409` called `evaluate_package` one package at a
time. 100 packages at 560 ms each is about 56 s of network waiting. The
lockfile lane now runs up to eight workers, each with its own `ReviewContext`
and its own database handle, results ordered by candidate index. **The AUR
half (`evaluate_aur_ci_diff`) is still serial** and is not covered by this
item's implementation.

- The store is already opened in WAL mode with a 5 s busy timeout at
  `src/store.rs:389`, so concurrent writers have a path.
- Findings are emitted in candidate order regardless of completion order,
  because CI output is diffed between runs.
- Each worker gets its own `ReviewContext`, which holds `RefCell`s.
- The budget check still refuses before any work starts, not after.
- Behaviour change: a failure in one package no longer stops the rest; a
  failed run now records `record_verified` and advisory-cache entries for
  packages the serial lane never reached.

### 3. Cap the incremental cache — PARTIALLY IMPLEMENTED

`[profile.dev]`/`[profile.test]` now set `debug = "line-tables-only"` and emit
no debug info for dependencies. That **shrinks each of the 101 caches** and the
100 MB test binary; it does **not** stop them accumulating. Unbounded
incremental retention is what accumulates them, and nothing in this PR sets
`incremental = false` or bounds the cache count — cargo has no such knob, so a
real fix is periodic eviction (`cargo clean` in a hook, or a size-capped
`CARGO_TARGET_DIR`). Do not read the current diff as delivering this item.

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

### 6. The 20-second test

Not ranked because every fix touches a test mutation testing currently leans
on. The tension is real and documented at `src/registry/npm.rs:1315`: the
256 MiB fixture exists so the ceilings bind even when the arithmetic is mutated,
and `the_packument_memo_ceilings_are_the_documented_sizes` already pins both
constants exactly. One of those is redundant, and which one is a question about
what the test is for.

The least invasive option that keeps every assertion intact: change
`packument_size_estimate` to count bytes through a streaming writer instead of
building a `String`. That halves the work and removes the transient 256 MiB
without touching a single assertion. **It edits production code, so it needs
approval** per the "ask first" list in `AGENTS.md`.

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
- **The toolchain pin is inert here.** `rustup` is not installed, so the 1.97.1
  channel in `rust-toolchain.toml` did not apply and everything built with
  Fedora's 1.98.1. `AGENTS.md` already flags this as a CI-fidelity risk. The
  numbers above are 1.98.1 numbers.
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