# Manifest Parsing

`src/manifest.rs`. Typed, bounded readers for the three manifest dialects,
each projected onto the npm `PackageJson` view so one heuristic engine serves
every ecosystem. Protects the property that an untrusted manifest is a bounded
read of known fields, never an arbitrary `serde_json::Value` blob.

## Sub-features
- `read_package_json` → `PackageJson` (camelCase, all fields defaulted).
- `read_packed_cargo_toml` → `PackedCargoToml` + `manifest_view()`.
- `read_aur_srcinfo` / `parse_aur_srcinfo` → a `PackageJson`.
- `LIFECYCLE_SCRIPTS` — the canonical 22-name list.

## How to get to it (user POV)
Not directly reachable; read inside `review`. `--registry` against a fixture is
the way to exercise it:
```sh
blueline --registry http://127.0.0.1:8080 review demo@1.0.0 --output json
```

## Driving it
| Constant | Value |
|---|---|
| `MAX_MANIFEST_BYTES` | `10 * 1024 * 1024` (10 MiB) |
| `SRCINFO_MAX_BYTES` | `1024 * 1024` (1 MiB, `pub`) |
| `MAX_SRCINFO_LINES` | `64 * 1024` (65536) |

`LIFECYCLE_SCRIPTS` in array order: `preinstall, install, postinstall,
preprepare, prepare, postprepare, prepack, postpack, prepublish,
prepublishOnly, preshrinkwrap, shrinkwrap, postshrinkwrap, preversion, version,
postversion, prestop, stop, poststop, prerestart, restart, postrestart`.
It is typed `&str; 22` — dropping an entry is a compile error, which is
intentional. `test` and `lint` are excluded by construction.

`PackedCargoToml::manifest_view()` projects onto the npm view: `[dependencies]`
→ `dependencies`, `[build-dependencies]` → `optional_dependencies`,
`[dev-dependencies]` → `peer_dependencies`, `scripts` is **always empty**, and
`gypfile = Some(build().is_some() || links().is_some() || !bins.is_empty())`.

## Gotchas
- **The 10 MiB manifest cap is deliberate and must not be tightened.** The test
  `accepts_small_manifest` carries this comment verbatim: *"Above the
  false-equivalent cap (10 + 1024 + 1024) but below the real one."* A tighter cap
  would look false-equivalent to an off-by-one mutation test. Same lesson in
  `npm.rs` (`512 + 1024 + 1024 = 2560` for tarballs, `64 + 1024 + 1024 = 2112`
  for packuments). If you reflow those tests, keep the arithmetic in the comment.
- **All three caps use `.take(MAX + 1)` then strict `>`.** Exactly-at-cap
  succeeds (`accepts_at_manifest_cap`, `srcinfo_line_cap_boundary_is_exact`),
  cap+1 fails. Changing `>` to `>=` makes the cap exclusive and breaks both.
- **PyPI `entry_points.txt` content is never parsed.** `R02_ENTRY_POINTS_SCRIPT`
  is a pure path-suffix test in `heuristic.rs`. A `console_scripts` entry
  pointing at an unexpected module is not detected — the rule only says "this
  wheel ships scripts".
- **`R04_SDIST_BUILD_CODE` fires on `setup.py` / `setup.cfg` only, and only for
  *added* files.** A `pyproject.toml` alone does not fire it.
- **`PackedCargoToml::package_field` returns `Some` only for a `String`.** A
  `[package] build = true` boolean yields `None` and is silently treated as
  absent — a fail-open direction.
- **A `[[bin]]` with only `path` counts in `bins.len()` but is absent from
  `bin_names()`.** `parses_packed_cargo_toml_surface` pins both numbers; do not
  assume they agree.
- **`dep_req_display` renders a non-string dependency as the literal
  `"(table)"`.** That string lands in `new_dependencies` and shows up on the
  review card.
- **`.SRCINFO` fail-closed grammar:** only *unindented* `pkgbase`/`pkgname` are
  legal headers; duplicate `pkgbase` is rejected; every header goes through
  `validate_aur_name`. A `#` comment line **fails**, because `#` is not in the
  key alphabet — comments are not part of the format.
- **`deps` is a `BTreeMap`, so a repeated dependency name overwrites** (later
  section wins). The version is assembled from `epoch`/`pkgver`/`pkgrel` and
  canonicalized through `AurVersionInfo`, so epoch is part of the identity.
- **`PackageJson` has no `deny_unknown_fields`** (`ignores_unknown_fields` pins
  that unknown keys are ignored) and is `#[allow(dead_code)]` as a whole struct.
- **Lifecycle scripts are emitted in `LIFECYCLE_SCRIPTS` order, not document
  order.** `flags_lifecycle_scripts` pins that.