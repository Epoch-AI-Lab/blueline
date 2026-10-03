# Extraction

`src/extract.rs`, `src/wheel_extract.rs` (a one-line re-export). Every byte the
heuristics ever see passes through here first. This is the lane where a naive
edit most directly becomes a sandbox escape.

## Sub-features
- `ExtractionLimits { max_unpacked_bytes, max_entries, max_entry_bytes }`.
- `safe_extract` — the hardened tar path.
- `safe_extract_wheel` — the zip/wheel path.
- `validate_entry_path` — shared path grammar.
- `strip_special_bits` — setuid/setgid removal.
- `ExtractStats { files, dirs, unpacked_bytes }`.

## How to get to it (user POV)
Not directly reachable. Extraction runs inside `review`, `ci`, and every
recursive child review. `--registry http://127.0.0.1:PORT` lets you point at a
fixture archive and exercise the whole path:

```sh
blueline --registry http://127.0.0.1:8080 review demo@1.0.0 --output json
```

## Driving it
Defaults (private consts, pinned by `defaults_are_sane`):

| Constant | Value |
|---|---|
| `DEFAULT_MAX_UNPACKED_BYTES` | `512 * 1024 * 1024` (536870912) |
| `DEFAULT_MAX_ENTRIES` | `100_000` |
| `DEFAULT_MAX_ENTRY_BYTES` | `128 * 1024 * 1024` (134217728) |
| `MAX_METADATA_ENTRY_BYTES` | `64 * 1024` (function-local, **not** overridable) |

Routing: `review::extract_for_ecosystem` picks `safe_extract_wheel` only when
`ecosystem == PyPi && tarball_url.ends_with(".whl")`; everything else, including
PyPI sdists, goes through `safe_extract`. Production passes
`ExtractionLimits::default()` — all three fields are currently **test-only knobs**.

Integrity algorithms: **npm sha512 only**, **cargo sha256 only**, **PyPI sha256
only**. Mismatch, missing checksum, or wrong algorithm is a hard error *before*
any byte is returned from `fetch_tarball`.

## Gotchas
- **There is no FD cap and no gzip-ratio bomb guard.** No `setrlimit`, no
  `RLIMIT`, no decompress-ratio bookkeeping anywhere in `src/`. The gzip stream
  goes straight to `tar::Archive`. The only thing bounding a bomb is the
  post-hoc accounting against the three limits. ARCHITECTURE.md's claims about
  "open file descriptors" and a "gzip decompress-ratio monitor" do **not**
  correspond to shipped code.
- **ARCHITECTURE.md's "50× tarball size" multiplier does not exist either.**
  `max_unpacked_bytes` is an absolute 512 MiB, independent of tarball size.
- **All three caps use strict `>` (inclusive at the boundary).**
  `entry_count_at_boundary`, `per_entry_size_at_boundary`, and
  `total_size_at_boundary` all construct exactly-at-cap payloads and assert
  success. Flipping `>` to `>=` breaks all three.
- **One line rejects every dangerous type:** `if !entry_type.is_file() &&
  !entry_type.is_dir()` → `ExtractionLimit("unsupported entry type …")`. That
  covers symlinks, hardlinks, devices, FIFOs, sockets, *and* any unknown
  typeflag. The `rejects_symlinks` / `rejects_hardlinks` tests assert on that
  shared message, not symlink-specific text.
- **Setuid/setgid are STRIPPED, not rejected**, and `strip_special_bits`
  unconditionally ORs `0o700` into directories on unix — the doc comment says
  that exists so tempdir cleanup succeeds. Making it stricter can break cleanup.
- **`validate_entry_path` rejects backslashes and colons unconditionally on
  Linux.** That kills `C:\` and ADS forms. Removing them as "Windows-only"
  breaks `rejects_backslash_in_path` and the colon half of
  `rejects_colons_and_reserved_dos_names`.
- **`WINDOWS_RESERVED_NAMES` is 22 entries** (`CON PRN AUX NUL COM1..COM9
  LPT1..LPT9 CONIN$ CONOUT$ CLOCK$`) and matches on the `Component::Normal`
  `stem` case-insensitively, so it fires on *nested* paths (`dir/com1.js`).
- **Metadata entries are skipped but still charged.** They count against
  `max_entries` and against `unpacked_bytes`
  (`metadata_entries_counted_against_limit`,
  `metadata_entry_accounts_for_total_unpacked_bytes`) — that is what stops a
  `@LongLink` flood from being free.
- **The zip path has extra rejections with no tar equivalent:** encrypted
  entries, `CompressionMethod` not `Stored | Deflated`, `enclosed_name()` None,
  normalized-path duplicates (`a.txt` vs `./a.txt`), and a
  `declared_size != actual_written` lie check. Modes are hard-set to
  `0o644`/`0o755` rather than stripped.
- **The error *variant* is load-bearing.** npm packument oversize maps to
  `BluelineError::Manifest`; every other oversize maps to `ExtractionLimit`.
  Adapters `.map_err` on `ExtractionLimit(_)` to rewrite the message — change
  the variant and the rewritten message disappears.