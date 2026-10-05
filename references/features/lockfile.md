# Lockfile Parsing

`src/lockfile.rs`. Bounded parsers for the three pinned-file dialects, plus the
delta merge. Protects the property that **an untrusted lockfile cannot steer the
scanner**: size-capped, grammar-checked, and normalized to per-ecosystem
identity before anything downstream compares names.

## Sub-features
- `parse_lockfile_packages` (npm `package-lock.json`).
- `parse_cargo_lock_packages` (`Cargo.lock`).
- `parse_requirements_txt_packages` (`requirements.txt`).
- `compute_delta_from_maps` / `compute_lockfile_delta`.
- `parse_npm_package` / `extract_package_name_from_path`.
- `LockfileError`.

## How to get to it (user POV)
```sh
blueline ci --lockfile package-lock.json --base origin/main
blueline --ecosystem cargo ci --lockfile Cargo.lock --fail-on high
blueline --ecosystem pypi ci --lockfile requirements.txt --fail-on block
```

## Driving it
| Constant | Value |
|---|---|
| `MAX_LOCKFILE_RECURSION_DEPTH` (npm v1) | `32` |
| `MAX_CARGO_LOCK_BYTES` | `10 * 1024 * 1024` (10485760) |
| `MAX_REQUIREMENTS_TXT_BYTES` | `10 * 1024 * 1024` |

Dispatch order in `ci.rs`: Cargo is tested **before** PyPI, so a file named
`Cargo.lock` scanned with `--ecosystem pypi` goes to the TOML parser. AUR
short-circuits earlier.

| Dialect | Map key | Notes |
|---|---|---|
| npm | normalized `node_modules` **path**, not name | `packages` (v2/v3) wins over `dependencies`; roots `""`/`"."` skipped; entries without `version` silently ignored |
| Cargo | `cargo/{name}@{version}` | `checksum` must be exactly 64 hex → `sha256:<hex>`; `source` stored verbatim in `resolved` |
| requirements.txt | PEP 503 canonical name | `entry.name` keeps the *original* spelling |

All three caps use strict `>`; each is pinned at exactly-cap and cap+1.

## Gotchas
- **`lockfile_version` is never range-validated.** Any integer (or absent) is
  accepted as long as `packages` or `dependencies` exists. Only when *neither*
  exists does the absence of `lockfileVersion` produce
  `MissingField("lockfileVersion")`. `{"lockfileVersion":2,"dependencies":{…}}`
  parses as v1.
- **npm v1 recursion silently truncates at depth 32** — `if depth > 32 { return; }`,
  no error, no finding. `v1_recursion_depth_limit_enforced` asserts exactly
  `MAX + 1 == 33` packages. That is a known fail-open corner.
- **The npm JSON path has no size cap and no entry cap.** Only the v1 recursion
  depth is bounded.
- **Cargo keys embed the version, so a version bump is `added` + `removed`, never
  `upgraded`.** `PackageUpgrade.old_version` is therefore always `None` for
  Cargo, and the markdown "Old Version" column shows `*(new)*`. A *checksum-only*
  change on the same key is the only `upgraded`.
- **`ci` skips any package whose `resolved` does not start with `"registry+"`.**
  Workspace members, `path+file://`, and `git+…` are all skipped —
  `test_cargo_lock_skips_local_and_path_packages_in_diff` asserts `items.len() == 0`.
  Loosening that sends workspace members to the registry resolver under their
  own names. (Whether `[policy] allow_git_dependencies` is consulted here is
  **unverified** — the code path shown excludes non-`registry+` unconditionally.)
- **`LockfileError` implements `From<serde_json::Error>` manually**, not
  `#[from]`, because Display already embeds the serde detail and `source()` would
  make `error: {e:#}` print it twice (`invalid_json_has_no_source_chain`). Do not
  "simplify" it.
- **requirements.txt skips any line starting with `-`** except `--hash`, so `-i`,
  `--extra-index-url`, `-r`, `-f` are silently dropped — typos included. Hashes
  are **not** mandatory; absence yields `integrity: None`. Multiple hashes join
  as space-separated `sha256:<hex>`, which is exactly what `Checksum::parse`
  consumes.
- **requirements.txt operator rejection is a substring scan over 8 operators**
  (`>= <= > < ~= != === @`) *before* the `==` split, and errors are **batched**:
  every offending line is collected into one message. `==` is deliberately
  excluded from that list.
- **requirements.txt extras are stripped to the base name** for the map key and
  validated to end with `]`. `Flask` → key `flask`, `entry.name = "Flask"`.
  Because the key is canonical, `Foo` and `foo` in one file **silently
  overwrite** each other — there is no duplicate detection, unlike Cargo, which
  errors on a differing duplicate.
- **`compute_delta_from_maps` ignores `is_dev` and `resolved` in the equality
  test.** A `resolved` URL change alone is invisible. It is a single O(n)
  `BTreeMap` merge on `Ordering`, with `Equal` meaning "same map key".
- **`is_dev` is only ever true for npm** (`pkg.dev`, `lockfile.rs:128`). Cargo,
  requirements.txt, and AUR hardcode `false`.