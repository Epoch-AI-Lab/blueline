# Architecture drift

Where the shipped code and the project's own documentation disagree, with the
evidence for each claim. Collected while writing the [feature map](README.md).

**Nothing here is fixed by editing a doc.** An entry that says a documented
guarantee is missing means the guarantee is missing — the doc is the easier
half of the pair, and fixing only the doc would make the codebase *less*
honest, not more. Confirm each against the cited source before acting on it,
then fix the code, then the doc, in that order.

Severity is this file's own judgement, not the project's.

| # | Drift | Severity |
|---|---|---|
| 1 | No decompress-ratio monitor, FD cap, Landlock/seccomp, or `cap-std` — all claimed in `ARCHITECTURE.md` §1 | **High** — the caps that *do* exist are per-entry size and entry count only |
| 2 | `dist.shasum` unparsed, npm registry signature unverified — both claimed in `ARCHITECTURE.md` §1; only `dist.integrity` sha512 is checked | **High** — a signature mismatch is currently invisible |
| 8 | SSRF guard fails **open** on DNS resolution failure, port hard-coded 443 | **High** — see below |
| 11 | PyPI `METADATA` parse fails **open** — an unreadable file yields an empty dependency set | **High** — fail-open in a fail-closed tool |
| 3 | Integrity mismatch surfaces as `Err` + exit 1, not `Verdict::Block` | Medium — a consumer keying on band never sees BLOCK |
| 4 | No cargo `-`/`_` name canonicalization, contrary to `CHANGELOG` 0.3.0 | Medium — `serde_json` and `serde-json` are distinct crates |
| 10 | `diff_single_file` coerces invalid UTF-8 to `""`, so a real change reads as all-add or all-delete | Medium — undocumented, silently mis-scores |
| 12 | `store.rs` discards the `0o600` pre-create error (`let _ =`) | Low — the DB may be more permissive than intended |
| 9 | `hex_to_bytes` uses `.unwrap_or(0)`, mapping invalid hex to byte `0` | Low — fails toward "valid-looking" |
| 5 | `registry/mod.rs` doc comments are stale ("npm is the only full impl for now") | Low — four ecosystems are implemented |
| 6 | Manager count is six in `CHANGELOG` 0.3.1, eleven in `ARCHITECTURE.md` §5; `--help` says eleven | Low — `--help` is authoritative |
| 7 | ~~Dead code: `Policy::is_maintainer_blocked`, `blocklist.maintainers`, `allowlist.packages[].max_risk` / `.integrity`~~ **resolved** — the three policy keys are now refused at load. Still dead: `BaselineStore::clear_advisory_cache`, `BaselineResolution::display_summary` | Low — the two remaining are test-only helpers, both `#[allow(dead_code)]` |

## Lane verification basis

Every lane below was written against the cited source and test names, not from
the prose docs.

| Lane | Basis |
|---|---|
| [cli](features/cli.md) | `src/cli.rs` + `--help` on all 8 subcommands and every nested one |
| [verdict](features/verdict.md) | `src/verdict.rs` full read |
| [error](features/error.md) | `src/error.rs` full read + cross-referenced callers |
| [heuristic](features/heuristic.md) | `src/heuristic.rs` production + all 52 test names |
| [diff](features/diff.md) | `src/diff.rs` production + all 7 test names |
| [render](features/render.md) | `src/render.rs` production + all 13 test names + 2 proptests |
| [version](features/version.md) | `src/version.rs` production + all 23 test names |
| [manifest](features/manifest.md) | `src/manifest.rs` production + all 32 test names |
| [lockfile](features/lockfile.md) | `src/lockfile.rs` production + all 13 test names |
| [ci](features/ci.md) | `src/ci.rs` production + all 32 test names |
| [registry](features/registry.md) | all six `src/registry/*.rs` + ~87 test names |
| [pkgbuild](features/pkgbuild.md) | `src/pkgbuild.rs` production + all 69 test names + the corpus gate |
| [extract](features/extract.md) | `src/extract.rs` production + all 42 test names |
| [store](features/store.md) | `src/store.rs` production + schema + 12 test names |
| [policy](features/policy.md) | `src/policy.rs` production + 15 test names |
| [baseline](features/baseline.md) | `src/baseline.rs` production + 12 test names |
| [review](features/review.md) | `src/review.rs` production + 31 test names |
| [wheel_extract](features/wheel_extract.md) | `src/wheel_extract.rs` (one line) |

## Evidence

Each finding is cited in its lane file with the exact source location.

1. **No decompress-ratio bomb guard, no FD cap, no Landlock/seccomp/capability
   drop, no `cap-std`, no non-writable temp dir.** ARCHITECTURE.md §1 claims all
   of them. See [extract](features/extract.md).
2. **`dist.shasum` is not parsed and the npm registry signature is not
   verified.** ARCHITECTURE.md §1 claims both. Only `dist.integrity` sha512 is
   checked. See [registry](features/registry.md).
3. **Integrity mismatch produces an `Err`, not `Verdict::Block`.** A CI report
   contains an error and exit 1, not a BLOCK verdict. See
   [extract](features/extract.md).
4. **No cargo `-`/`_` canonicalization.** `canonical_crate_name` only lowercases,
   so `serde_json` and `serde-json` are distinct crates — contrary to CHANGELOG
   0.3.0. See [registry](features/registry.md).
5. **`registry/mod.rs` doc comments are stale** ("npm is the only full impl for
   now") while all four ecosystems are implemented.
6. **CHANGELOG 0.3.1 says "all six managers are reviewed through one grammar"
   and "eleven scanned managers" in ARCHITECTURE.md §5 — the CLI enumerates
   eleven** (`npm npx pnpm yarn bun bunx pip pip3 cargo yay paru`) while the
   0.3.1 entry lists six. Both counts appear in the project's own docs; the
   `--help` text is authoritative and says eleven.
7. **`BaselineStore::clear_advisory_cache` and `BaselineResolution::display_summary`
   are dead.** Both are `#[allow(dead_code)]` with test-only callers, so the
   marker is deliberate rather than rot. See [store](features/store.md).

   This item originally also listed `Policy::is_maintainer_blocked`,
   `blocklist.maintainers`, and `allowlist.packages[].max_risk` / `.integrity`.
   Those were the sharp end: `serde` fields a user can set in `blueline.toml`
   that parsed cleanly and changed nothing, so a maintainer blocklist read as
   active protection and was not. They are now **refused at load** by
   `Policy::reject_unimplemented_keys`, with an error naming the rule and the
   check that does apply. `is_maintainer_blocked` is deleted, since no accepted
   config can reach it. Rated "Low" when this was first written, which
   understated it: a silently-ignored security control in a fail-closed tool is
   fail-open, not cosmetic.

   `Policy::calculate_band` was in this item too. It was worse than dead: a third
   copy of the score-to-band rule with *different* semantics, whose tests were
   the only executable spec of the thresholds. Resolved — the weight table is now
   `heuristic::score_findings` and the threshold pass is
   `Policy::escalate_band`, each with one copy and its own tests.
8. **The SSRF guard is fail-open on DNS resolution failure**, with port 443
   hard-coded regardless of the actual URL port — contradicting its own
   "prevent DNS rebinding" comment. See [registry](features/registry.md).
9. **`registry/mod.rs::hex_to_bytes` uses `.unwrap_or(0)`**, silently mapping
   invalid hex to byte `0`.
10. **`diff_single_file` silently converts invalid UTF-8 to `""`**, so a real
    change reads as all-add or all-delete. `ambiguous`, not documented. See
    [diff](features/diff.md).
11. **PyPI `METADATA` parsing fails OPEN** — `if let Ok(raw) = read_to_string(..)`
    swallows an unreadable file into an empty dependency set with no error. See
    [review](features/review.md).
12. **`store.rs` silently discards the `0o600` pre-create error** (`let _ =`).