# Version Grammars

`src/version.rs`. The `VersionInfo` seam that lets baseline selection, the
store's clean-version listing, and recall lookup work over *any* version
grammar. Protects the property that **names are ecosystem-scoped** — PEP 503
normalization applies to PyPI and nowhere else.

## Sub-features
- `trait VersionInfo` — `parse`, `canonical`, `is_prerelease`, and the provided
  `baseline_eligible_for`.
- `Pep440Version` — epoch, release, pre/post/dev/local.
- `AurVersionInfo` — libalpm `vercmp` port with pkgrel.
- `canonicalize_name` (PEP 503) / `canonicalize_for_ecosystem`.
- `validate_pypi_name`.
- `semver::Version` as the npm/cargo impl.

## How to get to it (user POV)
Version grammar shows up at the CLI boundary:
```sh
blueline review express@4.19.0            # npm/cargo: semver
blueline --ecosystem pypi review 'requests==2.31.0'
blueline --ecosystem aur  review yay@12.4.2-1
blueline --ecosystem pypi review 'x==2.0.0a1'   # prerelease
```

## Driving it
`baseline_eligible_for` (the default method, one line, load-bearing):
```rust
self < target && (target.is_prerelease() || !self.is_prerelease())
```
A stable version is never a baseline for a prerelease target; a prerelease is a
legal baseline only when the target is also a prerelease.

`canonicalize_name`: `to_ascii_lowercase()` then runs of `-`/`_`/`.` collapse to
a single `-`. **No trim** — `" already--normalized "` → `" already-normalized "`.
`canonicalize_for_ecosystem` applies it to `PyPi` only; npm/cargo/AUR pass the
name through unchanged.

PEP 440 `PRE_LABELS`: `preview→Rc, alpha→A, beta→B, pre→Rc, rc→Rc, a→A, b→B,
c→Rc`. Note `c` and `preview` map to `Rc`, so `1.0c1` canonicalizes to `1.0rc1`.

`AurVersionInfo::rpmvercmp` is a byte-exact port of libalpm's `rpmvercmp`,
validated against pacman's `vercmptest.sh` vectors.

## Gotchas
- **`canonicalize_name` does not trim, but `Pep440Version::parse` does.**
  `"   v1.0\t\n"` → `"1.0"`, while a name keeps its surrounding spaces. Easy to
  conflate.
- **PEP 440 release comparison is shorter-is-less only *after* trailing zeros
  are stripped** (`trimmed_release`). `1.0 == 1.0.0` but `1.0 < 1.0.0.1`. If you
  zero-pad in `canonical()` instead of in the compare, equality breaks.
- **`dev_rank` is inverted on purpose** (`1 if dev.is_none() else 0`), which is
  what makes `1.0.dev0 < 1.0a0`. `post` is *not* a prerelease
  (`is_prerelease = pre.is_some() || dev.is_some()`).
- **`validate_pkgver` rejects `+`, `~`, and `-`.** A pkgver like `2.0+git` is
  *unparseable*, which makes the commit a counted skip, not a repo error. All
  versions skipped ⇒ `list_releases` errors with `"parseable .SRCINFO"`.
- **PEP 440 parse bounds:** version string ≤ 256 bytes, ≤ 32 release segments,
  local segments `[A-Za-z0-9]` plus `. _ -` with no leading/trailing/adjacent
  separator. Overflow (`epoch`, local numeric) is a hard error.
- **`AurVersionInfo` compares pkgrel only when both sides carry one**, so
  `1.5 == 1.5-1` and an indexed `1.0` matches a queried `1.0-1`. Recall's
  version matching depends on exactly this.
- **`AurVersionInfo::is_prerelease()` is always `false`.** So an AUR
  prerelease-target policy is unreachable by construction.
- **`rpmvercmp` uses byte-length ordering, not `u64` parse, for pkgver.**
  `aur_version_long_numeric_segments_do_not_overflow` pins 40-nines behavior.
  Do not "clean up" the byte comparison into an integer compare.
- **`Pep440Version::list_versions` bridging is lossy** — `list_versions` can
  return fewer entries than `list_releases` (a PEP 440 version that cannot be
  expressed as semver drops out). A test asserts 4 releases but 3 versions.
- Fuzz targets: `fuzz/fuzz_targets/pypi_version.rs` and `aur_version.rs` both
  assert the **canonical round-trip** invariant: `parse(v).canonical()` must
  re-parse. That is the property, not panics.
- **`srcinfo_epoch_is_part_of_the_identity`** lives here and pins that
  `epoch=3, pkgver=1.0, pkgrel=2` → `"3:1.0-2"` — the epoch is never dropped.