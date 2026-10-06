# Registry

The `Registry` trait and its four adapters (npm, crates.io, PyPI, AUR) plus the
shared HTTP plumbing they all delegate to. This is the lane that turns
untrusted network bytes into verified local bytes, so its refusals are the last
line before [extract](extract.md).

## Sub-features

- `registry/mod.rs`: `Ecosystem`, `Checksum`, `ChecksumAlg`, `Package`,
  `Release`, the `Registry` trait.
- `registry/http_util.rs`: URL validation, SSRF guards, capped redirects,
  bounded reads.
- `registry/npm.rs`, `cratesio.rs`, `pypi.rs`, `aur.rs`.

## How to get to it (user POV)

```sh
./target/debug/blueline review <pkg>@<ver> --registry http://127.0.0.1:8080
./target/debug/blueline --ecosystem cargo review <crate>@<ver> --index http://127.0.0.1:8080
./target/debug/blueline --ecosystem pypi  review <pkg>@<ver>
./target/debug/blueline --ecosystem aur   review <pkgbase>@<pkgver>-<pkgrel>
```

Loopback registry bases are permitted — see the SSRF carve-out below.

## Gotchas

**npm signature verification and `dist.shasum` are NOT implemented.** Only
`dist.integrity` with algorithm `sha512` is checked. `Dist` has no `shasum`
field; grep `shasum` in `src/` returns nothing; there is no `signatures`/`pgp`
handling under `src/registry/`. ARCHITECTURE.md §1 claims both. See
[extract](extract.md).

**A non-sha512 `dist.integrity` is a hard refusal**, not a downgrade:
`"{name}@{version}: unsupported dist.integrity algorithm \`{alg}\`, expected
sha512"`. And a *missing* integrity is also fatal:
`"registry provided no dist.integrity; refusing to trust unverifiable bytes"`.

**The harness is fail-open on DNS failure.** `is_private_or_local_host`
resolves the hostname — *"to prevent DNS rebinding"* — with **port 443
hard-coded regardless of the URL's actual port**, and wraps it in `if let Ok(..)`,
so a resolution failure is treated as *allowed*. That contradicts the
function's own stated purpose. `ambiguous` whether it is deliberate.

**A private/local download host is allowed only if its host string equals the
registry base host.** `if is_private_or_local_host(&download_host) &&
base_host != download_host { Err(..) }`. This is the carve-out that makes the
loopback test fixtures and local mirrors work. Host comparison ignores port and
case.

**Redirects are hand-followed and re-validated on every hop.** Agents are built
with `.redirects(0)`; `download_bounded` calls `validate_download_url(base,
&current_url)` each iteration, so a redirect *to* a private host is refused.
Redirect status range is `301..=308` inclusive; cap is `max_redirects = 5`
(`redirects_followed > max_redirects` → error, so exactly 5 is allowed). A
missing `Location` header names the status in the error. Cross-host redirects
to *public* hosts are allowed — only private hosts are pinned.

**Every bounded read uses `take(max_bytes + 1)`.** The `+1` is the off-by-one
probe, so a body of exactly `max_bytes` passes. Exact-boundary tests exist for
every adapter: `packument_exact_limits_boundary`, `tarball_exact_limits_boundary`,
`redirect_exact_limits_boundary`, `pypi_packument_exact_limits_boundary`.

```
RegistryLimits::default()
  max_packument_bytes = 64 * 1024 * 1024      // 64 MiB
  max_tarball_bytes   = 512 * 1024 * 1024     // 512 MiB
  max_redirects       = 5
```

**`hex_to_bytes` uses `.unwrap_or(0)`** — an invalid hex pair silently becomes
byte `0` instead of erroring. The only non-fail-closed spot in `mod.rs`,
reachable only via `to_sri()` on an already-validated `value_hex`.

**`Checksum::parse` takes the FIRST recognized token of a whitespace-separated
list**, so npm's multi-algorithm `dist.integrity` resolves deterministically.
Accepted spellings: `sha512-<base64>` SRI, `sha256:<hex>` / `sha512:<hex>`
display, and bare hex inferred by length (64→sha256, 128→sha512). Anything else
is `unsupported checksum algorithm`. Test `picks_sha512_from_multi_algorithm_list`.

**`Ecosystem::Cargo` / `PyPi` / `Aur` mapping lives in `recursive::registry_for`,
not in `registry/mod.rs`.** Npm → `NpmRegistry::new(base)`, Cargo →
`CratesIoRegistry::new(base)`, PyPi → `PyPIRegistry::new(base)`, Aur →
`AurRegistry::new(base)`. Comment: *"Delegates to the manager's own mapping so
the gate and the recursive reviewer can never disagree about where a
`cargo install` or `yay -S` lands."*

**All four adapters implement `Registry`.** The seam is no longer
npm-only: `impl Registry for` resolves to `NpmRegistry`, `CratesIoRegistry`,
`PyPIRegistry`, and `AurRegistry`, plus the test doubles.

## npm

- Corgi packument: `Accept: application/vnd.npm.install-v1+json`.
- Scoped names percent-encode the slash: `name.replace('/', "%2f")`.
- 404 → `BluelineError::NotFound`. Test comment: *"A 404 must read as 'package
  not found in registry' (distinct from an outage) so a lockfile pointing at a
  ghost package is tamper evidence."*
- The packument's `name` is re-validated after parsing, and a metadata mismatch
  (`meta.name`/`meta.version` vs requested) is a hard error.
- Name grammar is `validate_package_name` + `is_valid_name_segment` — **there is
  no `valid_npm_name`**. Caps: empty or `len() > 214` → error; forbidden chars
  `\ ? # & %` and any control/whitespace; scopes are `@scope/rest` with both
  segments valid and no second `/`. Tests pin 214 OK / 215 rejected.
- `list_releases` always reports `yanked: false, publish_time: None` — the
  comment says the corgi packument does not expose either.
- `default_version` = `dist-tags.latest` unconditionally; else the highest
  stable semver; else the highest semver.

## crates.io

- `config.json` first: `auth-required: true` is a **refusal**
  (`"registry requires authentication (`auth-required`: true); refusing"`), and
  a missing/unusable `dl` is a refusal. Only `https://`/`http://` `dl` values
  are accepted.
- Sparse path: `1/{a}`, `2/{ab}`, `3/{a}/{abc}`, `{c1}{c2}/{c3}{c4}/{name}`.
  Name `len() > 64` → error.
- **There is NO `serde_json` → `serde-json` normalization.** `canonical_crate_name`
  only ASCII-lowercases. Tests `canonicalizes_names` asserts
  `canonical_crate_name("Serde_JSON") == "serde_json"`. crates.io's real index
  treats `-` and `_` as equivalent; this code does not. Consequence:
  `verify_single_root` expects a root literally `{lowercased-name}-{version}`.
  CHANGELOG 0.3.0's claim of `-`/`_` canonicalization is **wrong for this tree**.
- NDJSON fail-closed rules, verbatim: malformed JSON lines are errors; rows
  with unknown schema `v > 2` are skipped **with a note printed to stderr**;
  recognized rows with unparsable `vers` are errors; missing `yanked` reads false.
- Every index entry's `name` must equal the requested name → `"registry
  metadata mismatch: index entry reports name \`{}\`"`.
- `.crate` downloads verify sha256 against `cksum` before extraction; absence of
  a checksum or a non-sha256 algorithm is a refusal.
- `verify_single_root` post-extraction: exactly one root entry, must be a
  directory, must be named `{canonical}-{version}`. Tests
  `single_root_structural_check`.

## PyPI

- `GET {base}/simple/{normalized}/` with `Accept:
  application/vnd.pypi.simple.v1+json`. Content-type must contain `json`.
- **Deterministic wheel choice**: first `-py3-none-any.whl`, else
  `min_by_key(filename)` over `*.whl`, else `min_by_key` over all candidates.
  Candidate pool is version-matched files, preferring non-yanked.
- `yanked` is `#[serde(untagged)]` `NotYanked | Bool(bool) | Reason(String)`. A
  release is yanked if **any** of its files is yanked. `Reason("")` is not
  yanked.
- sha256 from `hashes["sha256"]` is required and verified **before** extraction.
- `parse_upload_time` is a hand-rolled RFC3339→epoch conversion using a Julian
  day formula, is `#[rustfmt::skip]`, and rejects month `00`/`13`, day `00`/`32`,
  and missing `T`. Fractional seconds are dropped. Tests pin
  `2024-01-17T16:53:12.779164Z → 1705510392` and `1970-01-01T00:00:00Z → 0`.
- **`resolve_package` performs no name-mismatch check**, unlike npm, crates.io,
  and AUR. `Package.name` comes from the server's response.
- `SimpleFile` is entirely `#[allow(dead_code)]`; `size` and `provenance` are
  parsed but never read. PEP 740 lives in [provenance](provenance.md).
- The file is minified — no blank lines between functions, no doc comments.

## AUR

The most involved adapter: RPC metadata plus a real `git` history walk.

**RPC v5 (`info`) fails closed in a 12-step chain**: name grammar →
`/rpc/v5/info?arg%5B%5D=<pct-encoded>` → 404 → content-type → size cap →
`version == 5` → `result_type == "multiinfo"` → `resultcount == results.len()`
→ exactly one result → non-empty → `info.name == name` (verbatim) →
`validate_aur_name(info.package_base)`. `Maintainer: null` means orphaned, not
an error.

**`encode_query_value` percent-encodes everything outside `A-Za-z0-9 . _ - ~`**,
so a name containing `+` or `@` cannot shift the query structure. Tests
`a+b → a%2Bb`, `a@b.c_d-e → a%40b.c_d-e`.

**Split packages are refused by pkgname.** `resolve_package` and
`releases_sorted` both return `InvalidPackageSpec("`{name}` is part of split
package base `{pkgbase}`; review `{pkgbase}@{version}` instead so the verdict and
baseline cannot silently change identity")`.

**Every `git` invocation is fixed argv, never a shell**, with `LC_ALL=C` ("Error-
message classification elsewhere matches git's English wording"). Caps:

```
MAX_HISTORY_COMMITS        = 200          (pub)
clone depth                = 201          (MAX_HISTORY_COMMITS + 1)
MAX_GIT_STDERR_BYTES       = 4096
MAX_GIT_SMALL_OUTPUT_BYTES = 64 * 1024    (rev-list, cat-file, author email)
GIT_TIMEOUT_SECS           = 120
GIT_STREAM_GRACE_SECS      = 5
MAX_CACHED_CLONES          = 8            → overflow CLEARS the whole cache
cat-file -t output cap     = 256 bytes
archive stdout cap         = max_tarball_bytes (512 MiB)
```

**The +1 commit depth is what makes truncation detectable inside a shallow
clone** — `rev-list --count HEAD` sees 201. Verbatim: *"The extra commit is what
keeps `truncated` detectable inside a shallow clone."* When truncation could hide
the requested version, the review **fails closed**: `resolve_package` appends
*"the walk stopped at the 200 newest commits, so an older matching commit would
be missed and the review fails closed"*, and `releases_sorted` errors outright.
Test `history_walk_caps_at_200_commits_and_states_truncation` builds 201 commits
and pins both messages.

**Deadlock/timeout handling is deliberate and documented at length.** Stderr and
stdout are drained on detached threads; the child runs in its own process group;
a 10 ms `try_wait` loop kills at 120 s; results are received with a **bounded
wait, not a `join`**, because transport children (`git-remote-https`, `ssh`)
inherit the pipes and can outlive `git`. A transport holding a pipe for 5 s
after exit → `"refusing to wait"`.

**`fetch_verified` deliberately bypasses the clone cache** so the archive bytes
are a *second, independent sample from the remote*. Comment at 553-557 is
explicit. Test `cached_repo_reuses_one_clone_per_url_and_drops_overflow`.

**Clone URLs are pinned at the verify boundary.** `pin_clone_url` accepts only
`{git_base}/{pkgbase}.git` for a validated pkgbase and refuses anything else —
*"rather than aiming `git clone` at an attacker-chosen scheme, host, or local
path."* The tarball URL grammar is exactly `git+<clone-url>#<40-hex>`.

**Per-commit `.SRCINFO` failures are skips; everything else propagates.** Absent
blob, over `SRCINFO_MAX_BYTES`, non-UTF-8, malformed, unparseable version →
`Ok(None)` counted as a skipped commit. A `git show` failure on an intact commit
is a skip **only** when `cat-file -t` says `commit` *and* the message contains
`does not exist`. Comment: *"so a corrupt or unreadable object cannot masquerade
as 'no parseable .SRCINFO'."* Test
`oversized_srcinfo_is_a_per_commit_skip_not_a_repo_error`.

**Ties on commit timestamp break toward the GREATER hash** —
`b.timestamp.cmp(&a.timestamp).then_with(|| b.hash.cmp(&a.hash))`. Test
`commit_history_tiebreaks_equal_timestamps_toward_the_greater_hash`.

**Commits sharing a `pkgver-pkgrel` collapse to the newest** when building
`list_releases`, and `list_versions` does NOT re-sort — the comment calls the old
semver re-sort "a latent inconsistency rather than an observable bug; not
re-sorting pins the order as a regression net." Two-component pkgvers like
`1.0-1` cannot be represented in semver and are **dropped**.

**`release_author` returns the pinned commit's `%ae`, degrading to `None` on any
failure** — self-declared identity, failures mean "unknown", never a finding.
It rejects an email containing any `char::is_control`.

## Public trait

```rust
pub trait Registry {
    fn ecosystem(&self) -> Ecosystem;
    fn resolve(&self, name: &str, version: &str) -> Result<Package, BluelineError>;
    fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError>;
    fn list_versions(&self, name: &str) -> Result<Vec<semver::Version>, BluelineError>;
    fn list_releases(&self, name: &str) -> Result<Vec<Release>, BluelineError>;
    fn default_version(&self, name: &str) -> Result<Option<String>, BluelineError>;
    fn release_author(&self, _pkg: &Package) -> Option<String> { None }   // the only defaulted method
}
```

`fetch_tarball` is documented as returning bytes *already* integrity-verified,
"fail closed on mismatch". `Package::integrity` is `Option<Checksum>` and its
absence is "fatal downstream".

## Tests

```
mod.rs:   parses_npm_sri_form_to_hex            sri_round_trips_through_display
          picks_sha512_from_multi_algorithm_list parses_display_and_bare_hex_forms
          fails_closed_on_bad_checksum_input     ecosystem_keys_are_stable

http_util: validates_download_url_ssrf_and_schemes  is_private_or_local_host_covers_all_ranges
           special_local_domain_and_non_canonical_ip_tests
           ssrf_rejects_alternative_encodings_and_ranges   relative_redirect_resolution

npm:       list_versions_orders_and_limits   validates_package_names
           mock_http_resolve_and_dist_tags   mock_http_redirect_handling
           packument_exact_limits_boundary   tarball_exact_limits_boundary
           redirect_exact_limits_boundary    packument_404_reports_not_found

cratesio:  maps_sparse_index_paths           canonicalizes_names
           parses_ndjson_fail_closed         single_root_structural_check
           rejects_auth_required_config      rejects_entry_name_mismatch
           rejects_checksum_mismatch_before_any_extract
           underscore_names_resolve_through_canonical_paths

pypi:      yanked_field_is_yanked            yanked_field_reasons
           select_prefers_universal          parse_upload_time_iso8601
           extracts_version_from_hyphenated_names
           pypi_packument_exact_limits_boundary

aur:       29 tests, incl. info_fails_closed_on_bad_rpc_shapes,
           info_fails_closed_on_name_mismatch, resolve_fails_closed_when_version_is_not_in_history,
           fetch_tarball_enforces_the_git_url_grammar, fetch_verified_pins_clone_urls_to_the_configured_base,
           cached_repo_reuses_one_clone_per_url_and_drops_overflow,
           history_walk_caps_at_200_commits_and_states_truncation,
           vercmp_equal_version_aliases_collapse_to_the_newest_commit,
           oversized_srcinfo_is_a_per_commit_skip_not_a_repo_error
```

All mock HTTP fixtures bind an ephemeral loopback listener and embed the real
base URL in the route bodies — no external network. Note the SSRF carve-out is
what makes that legal.