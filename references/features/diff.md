# Diff

`src/diff.rs`. Produces the `Delta` the heuristics consume: file-level and
line-level changes, plus the executable/binary classifications that drive
`R02_*`. Protects the property that untrusted bytes are only *line-diffed* when
they are small, UTF-8, NUL-free text.

## Sub-features
- `FileKind { Text, Binary, OpaqueTooLarge }` and `classify_bytes`.
- `FileChange`, `DiskFileMeta`, `Delta` (17 fields).
- `compute_delta` — manifest lifecycle + dependency deltas.
- `diff_single_file` / `scan_tree` — the merge walk.
- `check_is_executable` / `is_executable_extension`.
- `find_package_prefix`.

## How to get to it (user POV)
```sh
blueline review demo@1.0.0 --output json | jq '.diff_summary'
blueline mcp   # inspect_diff tool returns the delta as text
```
`[d]` at the interactive prompt prints per-file unified diffs.

## Driving it
`MAX_DIFF_FILE_BYTES: u64 = 2 * 1024 * 1024` is the **only** cap in the module.
`classify_bytes` order: size → `contains(&0)` → `from_utf8` error → `Text`.
`similar::TextDiff::from_lines` then `iter_all_changes()` counts
`Insert`/`Delete`. Unified text uses `context_radius(3)` and headers
`a/{rel}` / `b/{rel}`.

Executable classification is platform-split:
- unix: `metadata.permissions().mode() & 0o111 != 0`
- windows: extension in `["exe","cmd","bat","sh"]`

Separately, `is_executable_extension` is a platform-independent 11-entry list
`["exe","dll","so","dylib","node","sh","bat","cmd","ps1","vbs","bin"]` applied
**in addition** on the added-file arm only.

## Gotchas
- **The two executable-extension lists are different on purpose** and a naive
  merge breaks `detects_binary_files` (which relies on `binary.node` appearing in
  both `new_binaries` and `new_executables`).
- **The extension fallback applies only to *added* files.** A modified `.sh`
  file whose mode bit did not change is never reported as newly executable —
  the modified arm is mode-transition only.
- **A `Binary → OpaqueTooLarge` flip fires neither new-binaries arm.** Both arms
  require `base != target_kind`, so that transition is invisible to
  `new_binaries` (though `R02_OPAQUE_LARGE_FILE_ADDED` still catches it from
  `FileChange.kind`).
- **Non-`Text` files contribute zero lines.** `diff_single_file` returns early
  with `lines_added = 0`, `lines_deleted = 0`, `unified_diff = None`, so no
  `R03_*` rule ever sees them. The 2 MiB cap is not a blind spot *because*
  `R02_OPAQUE_LARGE_FILE_ADDED` is emitted separately.
- **The `unwrap()`s in `scan_tree` are the sanctioned category** from AGENTS.md:
  `base_iter.next()` / `target_iter.next()` immediately after a `peek()`
  returned `Some`, with `#[allow(clippy::unwrap_used)]` and a comment. Do not
  "clean them up"; and do not add more elsewhere.
- **`diff_single_file`'s `from_utf8(...).unwrap_or("")` means a misclassified
  non-UTF-8 file diffs as "everything deleted."** It is unreachable in practice
  because `classify_bytes` already routed it to `Binary`.
- **`collect_all_dependencies` uses `or_insert`, so `dependencies` shadows
  `optionalDependencies` and `peerDependencies`.** A peer-range flip on an
  existing dep is invisible. Switching to `insert` would make it a *modified*
  dependency — a score-affecting change.
- **`binding.gyp` matching is asymmetric.** `compute_delta`'s
  `binding_gyp_added` is case-insensitive and matches at **any depth**;
  `heuristic.rs`'s modified arm compares `relative_path == "binding.gyp"`
  (exact, root-only). A nested or differently-cased modified `binding.gyp`
  never fires `R01_BINDING_GYP_MODIFIED`. Edit either side and the
  added/modified symmetry breaks.
- **`find_package_prefix` descends only when the root has exactly one entry and
  it is a directory.** Any second entry disables the descent (the npm `package/`
  prefix assumption).
- `Delta::is_empty()` is `#[allow(dead_code)]` and inspects only the three file
  vectors. `removed_dependencies` is also dead but kept for shape parity.