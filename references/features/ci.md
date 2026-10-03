# CI

`src/ci.rs` (1735 lines). The PR gate: diff a lockfile against a git base ref,
review every added/upgraded pin, render a report, and exit non-zero when the
band reaches the threshold. Protects the property that **an over-budget diff is
disclosed and fatal before any network work happens**.

## Sub-features
- `ci::run`, `evaluate_lockfile_diff`, `evaluate_aur_ci_diff`.
- `extract_base_lockfile` — `git show`, plus `is_missing_base_error`.
- `check_evaluation_budget`, `band_passes`, `update_max_band`, `parse_band_str`.
- `render_text_summary_to_string` / `render_markdown_summary` / `CiOutputFormat`.
- `parse_aur_ci_lines` — the `aur.lock` reader.
- `R10_LOCKFILE_HASH_MISMATCH`.

## How to get to it (user POV)
```sh
blueline ci --base origin/main --lockfile package-lock.json
blueline ci --base HEAD~1 --format markdown --output-file blueline.md
blueline --ecosystem cargo ci --lockfile Cargo.lock --fail-on high
blueline --ecosystem pypi  ci --lockfile requirements.txt --fail-on block
blueline --ecosystem aur   ci --lockfile aur.lock --base origin/main
blueline ci --format json --output-file blueline-dogfood.json
```

## Driving it
Verified exit codes:

| Situation | Code |
|---|---|
| report built, band under threshold | `0` |
| band reached `--fail-on` threshold | **1** |
| git `show` failure / bad base ref | **1** |
| lockfile missing or unparseable | **1** |
| `max_evaluations` overrun | **1** |
| `--output-file` write failure | **1** |

`ci` **never returns 2**. `passed = band_passes(max_band, fail_threshold)` where
`band_passes(max, threshold) = max < threshold` — an *equal* band is a failure.
`--fail-on low` fails everything, including an empty delta, because `max_band` is
initialized to `Low`.

Policy knobs: `[ci] fail_on = "high"`, `max_evaluations = 100`,
`include_dev = true`.

`CiOutputFormat::Auto` is **unconditionally Text** — no TTY detection, no
`GITHUB_ACTIONS` check. Only `GITHUB_STEP_SUMMARY` is read, and it is
*appended* to with errors swallowed (`let _ = writeln!`).

## Gotchas
- **Base ref comes from `git show`, not `git diff`.** Exactly
  `Command::new("git").args(["show", "{ref}:{lockfile_path}"])`. The only
  injection surface is a leading `-`, rejected with
  `if trimmed_ref.starts_with('-') || trimmed_ref.is_empty()` — note the error
  message interpolates the *untrimmed* ref. `rejects_flag_like_base_refs` covers
  `--output=/tmp/pwn`, `"  --evil"`, `"  "`.
- **`BASE_REF` is not read by the Rust code.** It exists only in
  `.github/workflows/ci.yml`; the CLI default is `origin/main`.
- **A *missing* base is an empty baseline, not an error.** `is_missing_base_error`
  matches exactly `"does not exist"` or `"exists on disk, but not in"` (OR'd —
  `missing_base_error_any_not_all` kills the `&&` mutant). Then it synthesizes
  `version = 4\n` for Cargo, `""` for PyPI/AUR, or
  `{"lockfileVersion": 3, "packages": {}}` otherwise — every head pin becomes
  `added`. A *different* git failure (ambiguous ref, unknown revision) is a hard
  error.
- **The budget check runs before the evaluation loop in *both* paths.**
  Overrun message: `"CI review exceeded maximum configured package evaluations
  ({total} > {max})"`, where `total = added + upgraded`. **Removed packages never
  count.** Skipped dev packages *do* (the skip is after the check).
- **`ci.fail_on` from TOML is never validated.** `parse_band_str` returns
  `Option` and all three call sites `.unwrap_or(VerdictBand::High)` — a typo
  like `fail_on = "critcal"` silently becomes HIGH.
- **AUR bounds (in `ci.rs`, not `lockfile.rs`):** `MAX_AUR_CI_LINES = 4096` (doubles
  as the entry cap via `map.len() >= 4096`), `MAX_AUR_CI_LINE_BYTES = 512`,
  `MAX_AUR_CI_FILE_BYTES = 2_097_152`. A repeated pkgbase with a different
  version bails: `"AUR CI file pins \`{name}\` twice with different versions"`.
- **`R10_LOCKFILE_HASH_MISMATCH` cannot fire for npm** — the npm
  `head_integrity_map` is deliberately empty (npm integrity is verified earlier
  inside the registry adapter). Cargo keys by **bare name** (two versions collide);
  PyPI keys by both `pkg.name` and its PEP 503 canonical form.
- **`canon_alias` must stay PyPI-gated.** Two tests exist solely to kill that
  leak: `lockfile_diff_classifies_changed_and_unchanged_with_stub_registry` and
  `lockfile_diff_keeps_pypi_alias_off_cargo_pins`.
- **The mismatch force-sets `band = Block` and adds an *uncapped* 50.**
  `risk_score.saturating_add(50)` skips the `.min(100)` used everywhere else, so
  the score can exceed 100.
- **The report is written even when the gate fails** — stdout, then
  `--output-file`, then `$GITHUB_STEP_SUMMARY`, and only then the `bail!`. The
  composite action depends on this (`continue-on-error: true`, then read the
  file).
- **`--output-file` does not imply a format.** `--output-file x.md` without
  `--format markdown` writes the *text* summary into `x.md`.
- **The markdown empty-delta branch returns early**, omitting `Status:` and
  `max_band` entirely ("✅ **No new or upgraded packages detected in lockfile
  diff.**"). A gate that greps the step summary for `PASSED` finds nothing on an
  empty delta.
- **Markdown and text escape differently, and both are mandatory**: markdown
  does `sanitize_terminal` then `|`→`\|` and `\n`→`<br/>`; text uses
  `sanitize_single_line`. `escapes_markdown_cells_strips_terminal_escapes` asserts
  `!md.contains('\x1b')`.
- **The dogfood gate asserts scanner health, not risk**, and no longer
  hardcodes which packages must appear — a delta adding platform binaries shifted
  the evaluated names and failed the assert. Adding a new shipped npm package to
  the repo means adding it to the workflow's `expected` set.