# Baseline Selection

`src/baseline.rs`. Decision D5's implemented form. Chooses what to diff a
release against and re-verifies the anchor against the registry before trusting
it. Protects the property that **a tampered stored baseline fails closed
rather than silently diffing against attacker-chosen bytes**.

## Sub-features
- `resolve_baseline<R: Registry + ?Sized, V: VersionInfo>`.
- `BaselineResolution { LocalApproved, RegistryPredecessor, FirstSighting }`.
- `BaselineSelection { resolution, prior_release_yanked, target_release_yanked }`.
- Read-time tamper cross-check against the registry.

## How to get to it (user POV)
```sh
blueline review demo@2.0.0 --output json | jq '.baseline_version'
blueline review demo@1.0.0            # with no stored baseline → FirstSighting
```
The card header shows `baseline {v}` or `no baseline (first sighting)`.

## Driving it
Algorithm, in order:

0. `registry.list_releases(name)?` — **`?`**, so a package-wide 404 fails closed
   *here*, before the loop below.
1. `target_release_yanked` = is the target version yanked.
2. `eligible` = releases that parse under `V` **and** pass `baseline_eligible_for`.
3. Walk `store.list_clean_versions::<V>` descending; for each, `registry.resolve`
   and compare `pkg.integrity` to the parsed stored digest:
   - equal → `LocalApproved`
   - differ or unparseable → **hard error** `"refusing to trust tampered baseline"`
   - registry reports `None` → **hard error** `"refusing to trust unverified baseline"`
   - `Err(Manifest)` → **`continue`** to the next older clean version
4. Else highest **non-yanked** eligible release → `RegistryPredecessor`.
5. Else → `FirstSighting`.

Rule wiring: `R06_FIRST_SIGHTING` when `baseline_version.is_none()`,
`R07_UNREVIEWED_PREDECESSOR_BASELINE` when `RegistryPredecessor`,
`R08_YANKED_PREDECESSOR` when `prior_release_yanked`,
`R09_YANKED_TARGET` when `target_release_yanked`.

## Gotchas
- **The `node_modules` tier of D5 does not exist.** ARCHITECTURE.md says
  "locally installed version in `node_modules` → else previous version in
  registry list". There is no `installed` table in the schema and no such code
  path. The implemented algorithm is **two-tier**: SQLite clean store → registry
  predecessor → FirstSighting. `lockfile.rs`'s `node_modules/…` strings are
  `package-lock.json` keys for the `ci` lane, not a baseline source.
- **The `Err(Manifest) => continue` branch is safe only because of step 0.**
  The comment at `baseline.rs:104-110` spells it out: *"A package-wide 404 … is
  gated earlier at `list_releases(name)?` above and fails closed there — it must
  never reach this loop, so do NOT reinterpret Manifest as a benign 'skip the
  candidate' for a missing package."* Replace `list_releases` with a
  404-tolerant call and this becomes a live fail-open.
- **Both yanked flags are attached to every return path**, including
  `LocalApproved`. Dropping them from that arm silently loses R08 for locally
  approved baselines. `BaselineSelection` makes them orthogonal to the
  resolution by design.
- **An all-yanked history degrades to FirstSighting but keeps
  `prior_release_yanked = true`** (`all_yanked_history_degrades_to_first_sighting_with_warning`)
  so the R08 disclosure survives the degradation.
- **`list_clean_versions` silently skips rows whose version string fails
  `V::parse`.** Not an error. It also sorts descending *in Rust* after an SQL
  read with no `ORDER BY`.
- **`MockRegistry::list_releases` in the test module sorts by
  `Pep440Version::canonical()` regardless of the test's `V`** — a deliberate
  cross-grammar sort so semver fixtures still order correctly. Do not "fix" it.
- **A predecessor with no registry integrity yields `UnreviewedBaseline::None`**
  and therefore no `[y/N]` prompt at all. The prompt is gated on
  `pkg.integrity.is_some()`, not on the resolution alone.
- `BaselineResolution::display_summary()` is `#[allow(dead_code)]` with three
  exact strings pinned by a test only. Nothing renders it.