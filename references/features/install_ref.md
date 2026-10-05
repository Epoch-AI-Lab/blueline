# Install References

`src/install_ref.rs` (2029 lines). The static scanner that finds
package-manager invocations hiding inside an already-extracted payload — npm
lifecycle scripts, PKGBUILD npm/bun delivery, wheel `.data/scripts`. Protects
the property that **nothing executes**: this is pure parsing of bytes already on
disk, bounded per line, and a dynamic target is *disclosed*, never guessed.

## Sub-features
- `RefManager` (10 variants) / `RefOrigin` (4) / `InstallRef`.
- `raw_ref`, `registry_spec`, `split_spec`, `version_is_exact`.
- `has_dynamic_syntax` — the empty-spec marker rule.
- `from_npm_lifecycle` / `from_wheel_data_scripts`.
- `scan_line` / `scan_words` — the two fuel-bounded walks.
- `gate_hard_denies` + the four shape detectors the agent gate calls.

## How to get to it (user POV)
```sh
blueline review demo@1.0.0 --output json | jq '.recursive[] | {chain, name, band}'
blueline review demo@1.0.0 --output json | jq -r '.findings[] | select(.rule_id|startswith("R24")) | .description'
blueline agent gate --command 'npm install some-pkg'   # exercises scan_line directly
```

## Driving it
`RefManager`: `Npm, Npx, Pnpm, Yarn, Bun, Bunx, Pip, Cargo, Yay, Paru`
(`pip3` maps onto `Pip`). `ecosystem()`: `Pip→PyPi`, `Cargo→Cargo`,
`Yay|Paru→Aur`, everything else `→Npm` — the single mapping shared with
`recursive::child_ecosystem` and the agent gate.

`MAX_SCAN_LINE_BYTES: usize = 4096` (in this file);
`MAX_INSTALL_REFS: usize = 32` lives in `review.rs`.

Verbs: npm `install|i|add|exec|x`; bun `install|i|add|x`; pnpm/yarn
`install|i|add|dlx`; pip `install|i`; cargo `install`; yay/paru `starts_with("-s")`.
`Npx`/`Bunx` have no verb — the package is the first positional.

"Exactly pinned" (`version_is_exact`): pip = first char is an ASCII digit;
yay/paru = `AurVersionInfo::parse` ok; everything else = `semver::parse` ok.

## Gotchas
- **The two fuel loops in `scan_words` silently `break`, never error.** Each is
  `let mut fuel = toks.len(); if fuel == 0 { break; } fuel = fuel.saturating_sub(1);`
  — the bound is *line token count*, not the remaining distance. Exhausting it
  truncates the flag walk so the verb is never found and the reference is never
  reported. Given `fuel = toks.len()` and one advance per unit, they are
  currently unreachable; a new non-advancing branch re-opens the hang.
- **`positionals` has NO fuel loop** — bounded only by
  `MAX_SCAN_LINE_BYTES`.
- **The empty-spec marker is emitted once per invocation.**
  `if specs.last().map(String::is_empty) != Some(true)` — however many dynamic
  tokens follow, only one `""`. Comment: "A dynamic target is disclosed as the
  empty-spec marker, never silently dropped behind a decoy."
- **`has_dynamic_syntax` includes `"` and `'` and `\`**, so a quoted target is
  dynamic. `&`, `|`, `;`, `,`, `:`, `/` are *not* — those are command
  terminators handled earlier by `strip_token`.
- **`positionals`' `pending_package` branch does NOT apply the marker rule.**
  `positionals(&["--package","$DYN"], Npx, false)` is empty when called
  directly; only the earlier flag walk in `scan_words` catches
  `npx --package $EVIL serve`.
- **Range and unpinned are different code paths.** `b@^1.2.0` → `pinned: false`,
  `registry_spec() == Some(("b", Some("^1.2.0")))`, disclosed MEDIUM, and
  `recursive` is **empty** — it is not resolved to latest. A bare `b` → MEDIUM
  and `resolve_child_version` *does* call `default_version`.
- **`registry_spec` gates on per-ecosystem name grammar** with length caps 214
  (npm, PyPI) and 255 (AUR), each pinned at the boundary. `plain_npm_segment`
  rejects `~pkg`, `_pkg`, `.pkg`, `.`, `..` and requires `@` for a scoped name.
  Relaxing it re-opens path traversal through the recursive reviewer.
- **`npm --registry install evil` yields NOTHING** — `install` was swallowed as
  `--registry`'s value (`CONSUME_VALUE_FLAGS`). With a real value
  (`npm --registry https://x install evil`) it yields `evil`. Pinned by
  `consumed_flag_values_do_not_become_verbs`.
- **Scanning stops at `#`.** `split_whitespace().take_while(|w| !w.starts_with('#'))`.
- **Flag lists that are hand-maintained duplicates:** `MANAGERS` (11 entries) in
  `gate_hard_denies` vs `RefManager::label()` (10) — the extra is `pip3`. Adding
  a manager variant without editing `MANAGERS` silently disables the
  quoted-manager gate for it. Similarly `CONSUME_VALUE_FLAGS` (16) and the npm
  `OVERRIDES` (7) / pip `DANGEROUS` (8) lists overlap only partially —
  `-t`/`--target` is in the former but not the latter.
- **The quoted/escaped-manager rule hinges on `bare != word`.** A *plain*
  absolute path `/usr/bin/npm` is scanned normally and must NOT deny; a quoted
  or backslash-escaped one must. Trim sets are
  `['\\','"','\'','`','$','(','{']` leading and `['"','\'','`',')','}',';',',']'`
  trailing.
- **`scan_line` hardcodes `RefManager::Npm` for an oversized line and
  `RefManager::Pip` for an unreadable wheel script.** Cosmetic only
  (`registry_spec()` returns `None` when `!parseable`), but do not "improve" it
  without auditing every downstream consumer.