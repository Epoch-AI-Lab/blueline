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
| 1 | No Landlock/seccomp/`cap-std` sandbox — the parser-level bounds are real, and every claim of an OS-level one is now removed from `README.md`, D4, the §1 diagram and the §1 header rule | **High, unfixed** — this is a real missing capability, and the fix is code, not wording |
| 2 | ~~npm registry signature checked for *presence* only~~ — **the key that read it as verification is refused at load; verification itself is still absent** | **High, unchanged in severity** — see below |
| 8 | ~~SSRF guard fails **open** on DNS failure, port 443 hard-coded~~ **resolved** — `ValidatingResolver` is the guard now, not the pre-flight check | High — see below |
| 11 | ~~PyPI `METADATA` parse fails **open**~~ **resolved** — every unreadable or undetermined-metadata case is a refusal | High — see below |
| 3 | Integrity mismatch surfaces as `Err` + exit 1, not `Verdict::Block` | Medium — a consumer keying on band never sees BLOCK |
| 4 | No cargo `-`/`_` name canonicalization, contrary to `CHANGELOG` 0.3.0 | Medium — `serde_json` and `serde-json` are distinct crates |
| 10 | `diff_single_file` coerces invalid UTF-8 to `""`, so a real change reads as all-add or all-delete | Medium — undocumented, silently mis-scores |
| 12 | `store.rs` discards the `0o600` pre-create error (`let _ =`) | Low — the DB may be more permissive than intended |
| 9 | `hex_to_bytes` uses `.unwrap_or(0)`, mapping invalid hex to byte `0` | Low — fails toward "valid-looking" |
| 5 | ~~`registry/mod.rs` doc comments are stale~~ **resolved** — both were deleted; the four adapters are all real. See below | Low |
| 6 | Manager count is six in `CHANGELOG` 0.3.1, eleven in `ARCHITECTURE.md` §5; `--help` says eleven | Low — `--help` is authoritative |
| 7 | ~~Dead code: `Policy::is_maintainer_blocked`, `blocklist.maintainers`, `allowlist.packages[].max_risk` / `.integrity`~~ **resolved** — the three policy keys are now refused at load. Still dead: `BaselineStore::clear_advisory_cache` | Low — test-only helper, `#[allow(dead_code)]` |

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

1. **No Landlock/seccomp/capability-drop sandbox and no `cap-std`. Still
   unfixed, and this entry stays live.** §1 has said "planned, not implemented"
   and named the parser-level budget as the real bound, but `README.md` still
   called the temp dir "an isolated sandbox", D4 still read "Read-only sandbox
   extraction", and the §1 header rule and §1 diagram both said "sandbox". Those
   are now corrected, so the *documentation* no longer claims a capability the
   code lacks — which is the half of this that prose could fix.

   The half prose could not fix is the missing capability itself, and it is the
   half that matters. What bounds a hostile archive today is
   `decompressed_stream_cap` plus the three `ExtractionLimits` fields, enforced
   on the declared size *and* on the inflated stream. There is no OS-level
   confinement behind that, so the guarantee a reader takes from the word
   "sandbox" does not exist. Closing this means adding a confinement mechanism
   (Landlock on Linux, `cap-std`, or seccomp), which is a dependency decision
   and therefore not something to do silently. See [extract](features/extract.md)
   for what the bounds actually are.
2. **The npm registry signature is read for presence and never verified. Partly
   resolved; the verification gap itself is untouched.** `release_signatures`
   still returns the block as raw JSON, nothing compares the bytes to it, and
   `dist.shasum` is still unparsed (the registry checksum that does run is
   sha512 for npm and sha256 for cargo, pypi and aur). What changed is the
   consequence: `[provenance] require_signatures = true` is now **refused at
   load** by `Policy::reject_unimplemented_keys`, with an error naming what the
   flag actually checked and naming the per-lane checksum that does run instead.
   Before, the key was accepted and any non-empty `dist.signatures` array
   satisfied it, so an operator who wrote it got a config that read as signature
   *verification* and was checked against nothing. A key that cannot fail closed
   is refused rather than honoured. This entry stays at **High, unchanged in
   severity**: refusing the key removes a control that looked active and was
   not, but a Sigstore verification path needs a dependency this project has not
   approved, and until one lands nothing verifies a registry signature.

   The engine keeps `P03_SIGNATURE_REQUIRED_MISSING` (BLOCK) for a caller that
   sets the flag directly, so an unsigned release is still refused. The
   direction it cannot close is the present case. See
   [registry](features/registry.md) and [policy](features/policy.md).
3. **Integrity mismatch produces an `Err`, not `Verdict::Block`.** A CI report
   contains an error and exit 1, not a BLOCK verdict. See
   [extract](features/extract.md).
4. **No cargo `-`/`_` canonicalization.** `canonical_crate_name` only lowercases,
   so `serde_json` and `serde-json` are distinct crates — contrary to CHANGELOG
   0.3.0. See [registry](features/registry.md).
5. **~~`registry/mod.rs` doc comments were stale~~ — resolved.** Two comments
   claimed npm was the only wired adapter ("npm is fully wired; cargo, PyPI,
   and AUR adapters build on these seams in later PRs", and "npm is the only
   full impl for now") while `NpmRegistry`, `CratesIoRegistry`, `PyPIRegistry`,
   and `AurRegistry` all implement the trait. Both comments are deleted.
6. **CHANGELOG 0.3.1 says "all six managers are reviewed through one grammar"
   and "eleven scanned managers" in ARCHITECTURE.md §5 — the CLI enumerates
   eleven** (`npm npx pnpm yarn bun bunx pip pip3 cargo yay paru`) while the
   0.3.1 entry lists six. Both counts appear in the project's own docs; the
   `--help` text is authoritative and says eleven.
7. **~~`BaselineStore::clear_advisory_cache` and
   `BaselineResolution::display_summary` are dead~~ — `display_summary` is
   deleted; `impl BaselineResolution` carries only `package()`. The one that
   remains is `clear_advisory_cache`, `#[allow(dead_code)]` with one test
   caller, so the marker is deliberate rather than rot. See
   [store](features/store.md).

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
8. **~~The SSRF guard is fail-open on DNS resolution failure~~ — resolved.**
   `is_private_or_local_host` is now the early-out and not the guard, which is
   what its own comment says. `registry_agent_with_timeout` builds the agent
   with `.resolver(validating_resolver_for(base))`, and
   `ValidatingResolver::resolve` runs where a name becomes an address: an
   empty answer is `NotFound` and any private answer is `PermissionDenied`, so
   a name that resolved publicly for the check and privately for the
   connection no longer gets through. Only the configured base is exempt.
   See [registry](features/registry.md).
9. **`registry/mod.rs::hex_to_bytes` uses `.unwrap_or(0)`**, silently mapping
   invalid hex to byte `0`.
10. **`diff_single_file` silently converts invalid UTF-8 to `""`**, so a real
    change reads as all-add or all-delete. `ambiguous`, not documented. See
    [diff](features/diff.md).
11. **~~PyPI `METADATA` parsing fails OPEN~~ — resolved.** The old
    `if let Ok(raw) = read_to_string(root.join("METADATA"))` is gone. A PyPI
    archive is now refused unless it carries exactly one core-metadata file
    at a location pip could install from, the file reads as UTF-8, and it
    declares a name and a version that agree with the resolved release. The
    refusals name which of those failed. Test
    `a_pypi_archive_whose_metadata_cannot_be_read_is_refused`. See
    [review](features/review.md).
12. **`store.rs` silently discards the `0o600` pre-create error** (`let _ =`).