# Review

The orchestrator: the `blueline review` and `blueline install` entry points, and
`evaluate_package` — the one function every lane in the codebase funnels through
(`ci`, `mcp`, `agent`, and recursive children all call it). It is 1008 lines of
production code and the only place the ordering of the trust pipeline is
decided. Read it before changing the order of anything.

## Sub-features

- `run` / `install`: the two CLI entry points, including every refusal path.
- `evaluate_package` → `evaluate_scoped` → `evaluate_with_registry<V>`: one
  evaluation, generic over version grammar.
- `interactive_prompt` / `offer_baseline_approval`: the human decision path.
- `prepare_extracted_root`: per-ecosystem manifest discovery + structural gates.
- `collect_install_refs` / `extract_for_ecosystem`.
- `bootstrap_hint`: the actionable-next-step messaging.

## How to get to it (user POV)

```sh
./target/debug/blueline review express
./target/debug/blueline review express@4.21.2 --output json
./target/debug/blueline review express -y
./target/debug/blueline install express --save-dev
./target/debug/blueline --ecosystem pypi review requests==2.32.3
./target/debug/blueline --ecosystem cargo review serde@1.0.219
./target/debug/blueline --ecosystem aur   review yacpt@11.2.1-1
```

## Driving it

```
review <PKG>   [--output auto|text|json]  [-y|--yes]   (alias --non-interactive)
install <PKG>  [NPM_ARGS]...               [-y|--yes]
```

Interactive prompt: `[a]pprove · [h]old · [d]diff > `, accepting
`a`/`approve`, `h`/`hold`, `d`/`diff`, case-insensitive, trimmed.
Baseline follow-up: `[y/N]`, only `y`/`yes` approves.

## Evaluation order

`evaluate_with_registry<V>` (review.rs:108-398), in exact order:

```
 1. parse target version for the ecosystem grammar
 2. registry_base = bases.for_ecosystem(ecosystem)
 3. registry.resolve(name, version)                      → Err propagates
 4. ctx.fetch_tarball (memoized; verifies integrity inside the adapter)
 5. REQUIRE target_pkg.integrity                          → refuse "unverifiable bytes"
 6. tempfile::tempdir()                                   (RAII guard)
 7. extract_for_ecosystem(...)
 8. prepare_extracted_root(...)                           → (root, PackageJson)
 9. store.record_verified(...)                            → witness, clean = 0
10. resolve_baseline(...)
11. if a baseline exists: fetch it, tempdir, extract, prepare_root,
    compute_delta(...); AUR also reads base_root/PKGBUILD
    else compute_delta(None, None, None, ...)
12. advisory::fetch_advisories(...)                       → degrades to Unverified
13. provenance::inspect_provenance (npm) / _pypi (pypi)   → None for cargo, aur
14. release_author() on both sides                        → author_changed
15. heuristic::evaluate_with_trust(...)                   → Verdict
16. AUR only: R00_BASELINE_UNREADABLE if the baseline PKGBUILD is unreadable,
    then pkgbuild::review_roots → apply_extra_findings
17. recall::stale_band(policy)                            → R28_RECALL_STALE
18. collect_install_refs + install_ref_findings; cap at MAX_INSTALL_REFS = 32
    → apply_extra_findings
19. ctx.review_children(...)                              → R27 roll-up
    → apply_extra_findings
```

Steps 16, 17, 18, and 19 all end in `apply_extra_findings`, which *recomputes*
score and band. Skipping that call is how a HIGH finding ends up rendered at
HIGH while the verdict still says LOW.

## Gotchas

**`install` refuses non-npm ecosystems before it loads policy or touches the
network**, and exits 2 each time:

```
cargo: building a crate executes its `build.rs` script, which blueline cannot sandbox
pypi:  installing a Python sdist executes arbitrary build code and wheels may contain installer hooks
aur:   building a package executes its PKGBUILD shell script, which blueline cannot sandbox
```

Each message names the `blueline review … --ecosystem <eco>` command to use
instead. This is the "never execute" invariant (D11) extended to every ecosystem.

**`install` renders text unconditionally** — no `--output` exists on it, and
there is no JSON branch. Do not add one without deciding what
`install --output json` would mean for the audit trail.

**`--yes` approves ONLY `VerdictBand::Low`.** Anything else prints
`"Cannot auto-approve {name}@{version}: risk verdict is {band} (score: {n}).
Refusing to proceed (--yes)."` plus `bootstrap_hint`, then **exits 2**.

**Non-interactive without `--yes` refuses unless the band is `Low`** — and here
is the asymmetry: `run` returns `Ok(())` **without marking clean**, printing
nothing, on a non-interactive `Low`. `install` returns `true` and proceeds to
`npm install --ignore-scripts`, also without marking clean. Only `run --yes` /
`install --yes` on `Low`, and interactive `[a]pprove`, ever write `clean = 1`.

**The interactive prompt requires BOTH stdin and stdout to be TTYs.**
`format != Json && stdin().is_terminal() && stdout().is_terminal()`. Piping
`--output json` into a file disables prompting entirely.

**`[h]old` and EOF both `exit(2)`** — not a return value. `read_line` returning
`0` prints `"Held (EOF)"` and exits 2. So you cannot loop the prompt from a
caller.

**The baseline follow-up prompt is honest about why it is safe.** Doc comment:
the baseline tarball "was already fetched and verified against the registry
checksum during this review, so approving it records a trust decision over bytes
that were verified moments ago." Anything but explicit `y`/`yes` leaves it
unapproved.

**A store failure during the baseline follow-up does NOT roll back the target
approval.** It prints `"note: could not approve baseline …; baseline left
unapproved"` and returns `Ok(())`. Test `chain_approval_rejects_non_y` and
`chain_approval_accepts_y_and_yes`.

**Audit actions are distinct strings, and `recall export-candidates` filters on
them.** `"approve"`, `"hold"`, `"approve_auto_yes"`, `"approved_baseline_chain"`,
plus `"agent_gate"` / `"agent_review"` from [agent](agent.md). The filter also
keeps anything with verdict `BLOCK` or `HIGH`.

**`step 5` requires an integrity checksum or the review dies.** Message:
`"{name}@{version}: registry provided no content checksum; refusing to trust
unverifiable bytes"`.

**PyPI core metadata is read from every legal location and anything but one is a
refusal.** `pypi_metadata_candidates` returns `METADATA`/`PKG-INFO` at the root
and one level down (a wheel's `.dist-info`, an sdist's single top-level
directory), and `prepare_extracted_root` requires exactly one. The refusals are:
no candidate at all; more than one, naming each path; unreadable or non-UTF-8
content; no declared name; no declared version; a declared version that
disagrees with the version the registry resolved. Tests
`a_pypi_archive_whose_metadata_cannot_be_read_is_refused` and the two-metadata
case alongside it.

`parse_pypi_core_metadata` is exact-prefix and case-sensitive on
`Requires-Dist:`, with no RFC-822 continuations and no
`Provides-Dist`/`Obsoletes-Dist`; the `;` marker is stripped and the
marker-stripped string becomes the map value keyed by its first whitespace
token.

**Cargo archives must unpack to exactly one `{canonical-name}-{version}`
directory.** `cratesio::verify_single_root` refuses anything else, *before* the
manifest is read. AUR archives must carry **both** `PKGBUILD` and `.SRCINFO` at
their root as files (a *directory* named `PKGBUILD` fails), and the `.SRCINFO`
pkgbase must equal the resolved pkgbase. npm uses `find_package_prefix` to
tolerate `package/`, single-directory (`@types/*`), and flat roots.

**`MAX_INSTALL_REFS = 32`, and the cap boundary is exactly right.** `refs.len() >
32` truncates to 32 and emits `R24_LIFECYCLE_INSTALL_REF` / HIGH / title
`"Install-reference cap exceeded"`. This `>` was a mutation survivor — it used
to be `>=` and flagged a payload carrying exactly the cap. Tests
`install_references_at_the_exact_cap_are_not_disclosed_as_overflow` and
`install_reference_overflow_is_truncated_and_disclosed`.

**`R28_RECALL_STALE` has two shapes.** `stale_band` returning `Ok(Some(band))`
→ title `"Recall index stale"`; `Err(e)` → severity forced to **HIGH**, title
`"Recall index unreadable"`. The comment: *"a blind revocation index is a
coverage hole, never silence."* There is a stray run of ~22 literal spaces
inside the stale description string (line 340) — cosmetic, but it is a literal
in user-visible output.

**`R00_BASELINE_UNREADABLE` / `R00_PKGBUILD_UNREADABLE` are HIGH and use the
same `rule_id` as their target counterparts.** A PKGBUILD that cannot be read is
disclosed, not scanned as an empty file. `base_text = Some("")` means "unreadable,
already surfaced"; `None` means first sighting; anything else diffs.

**`parse_spec` splits from the RIGHT** (`rsplitn(2, '@')`) so a scoped name's
leading `@` stays with the name, and it accepts PyPI's `name==version` alias. It
rejects names containing `[`, `]`, `@`, space, or tab. `parse_spec_flexible`
detects a version separator and otherwise calls `registry.default_version(name)`.

**A floating reference resolves the *current* default version, and must not reuse
a stale completed review for the same name.** Tests
`unpinned_reference_does_not_reuse_a_stale_pinned_review` and
`unpinned_reference_reuses_the_exact_completed_review`: reusing a completed
`1.0.0` review for a floating `foo` "would vouch for bytes the install never
fetches." These two are a matched pair — read both.

**`bootstrap_hint` is the actionable-next-step surface** and it is deliberately
specific: `R07` names the exact `blueline review {name}@{base}` command;
`R06_FIRST_SIGHTING` either says "Address the findings above first; a baseline
allowlist rule will not clear them" (when any other finding exceeds LOW) or
points at the `allow_unreviewed_baseline` allowlist rule. Every interpolated
value passes `render::sanitize_single_line`.

**`ctxless_registry` and `evaluate_scoped` are `pub(crate)`, not `pub`.** The
public surface is exactly `evaluate_package`, `run`, `install`, `parse_spec`.

## Public surface

```
pub(crate) fn ctxless_registry(ecosystem, bases) -> Result<Rc<dyn Registry>>
pub         fn evaluate_package(name, version, ecosystem, bases, store, policy, ctx) -> Result<(Verdict, Delta)>
pub(crate) fn evaluate_scoped(name, version, ecosystem, bases, store, policy, ctx) -> …
pub         fn run(pkg_spec, ecosystem, bases, output, policy_path, yes) -> anyhow::Result<()>
pub         fn install(pkg_spec, ecosystem, bases, npm_args, policy_path, yes) -> anyhow::Result<()>
pub         fn parse_spec(spec) -> Result<(String, String), BluelineError>
pub(crate) fn parse_spec_flexible(spec, registry) -> …
```

## Tests

31, across `mod tests` and `mod recursive_tests`.

```
baseline_unreadable_finding_is_high             target_unreadable_pkgbuild_is_disclosed_high
parses_plain_spec                              parses_scoped_spec
rejects_missing_at                             rejects_bad_semver
chain_approval_rejects_non_y                   chain_approval_accepts_y_and_yes
parse_spec_accepts_pypi_double_equals          flexible_spec_handles_pypi_alias
prepare_extracted_root_requires_aur_archive_files
prepare_extracted_root_refuses_aur_pkgbase_mismatch

lifecycle_reference_triggers_recursive_review   child_block_band_policy_lowering_rolls_up_medium_children
repeated_reference_reuses_cached_review_after_budget_spent
unpinned_reference_does_not_reuse_a_stale_pinned_review
unpinned_reference_reuses_the_exact_completed_review
recursive_pass_runs_on_modified_lifecycle_script_with_baseline
install_references_at_the_exact_cap_are_not_disclosed_as_overflow
install_reference_overflow_is_truncated_and_disclosed
review_children_maps_pkgbuild_refs_to_npm_and_pip_refs_to_pypi
cycle_is_cut_and_rolled_up                     second_visit_reuses_memo_without_refetch
child_budget_emits_r25_fail_closed             depth_zero_emits_r25_fail_closed
unpinned_reference_resolves_default_version_at_medium
unresolvable_reference_is_disclosed_at_medium  range_reference_is_disclosed_not_guessed
non_registry_reference_is_high_and_not_recursed
```

`second_visit_reuses_memo_without_refetch` asserts exactly two downloads — it is
the memo's pin. `prepare_extracted_root_requires_aur_archive_files` encodes
"missing PKGBUILD must disclose, never silent allow."