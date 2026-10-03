# AUR Adapter

`src/registry/aur.rs` (1859 lines). The only registry backed by **git history
over the system `git` binary**, and review-only — `blueline install` refuses
AUR unconditionally. It protects two things: the clone URL is pinned to the
configured base at the verify boundary, and the review bytes are a *second
independent sample* so history rewrites are caught by the store's tamper guard.

## Sub-features
- `AurRegistry` on RPC v5 (`{base}/rpc/v5/info?arg%5B%5D=…`), `RPC_VERSION = 5`.
- `git_output` — argv-only git with wall-clock and stream deadlines.
- `clone_repo` / `cached_repo` / `commit_history` / `archive_bytes`.
- `pin_clone_url` — the verify boundary.
- `commit_version` — per-commit static `.SRCINFO` read.
- `release_author` — commit author email for R10.
- `verify_commit_exists`, `parse_git_tarball_url`.

## How to get to it (user POV)
```sh
blueline --ecosystem aur review yay@12.4.2-1
blueline --ecosystem aur review 12.4.2-1            # pkgrel required
blueline --ecosystem aur ci --lockfile aur.lock --base origin/main
```
`aur.lock` is one `pkgbase@pkgver-pkgrel` per line; `#` comments and blanks are
skipped. Split packages must be reviewed by **pkgbase**, not pkgname — the
adapter refuses a pkgname whose `pkgbase` differs and tells you the right target.

## Driving it
| Constant | Value |
|---|---|
| `MAX_HISTORY_COMMITS` | `200` (public) |
| `GIT_TIMEOUT_SECS` | `120` |
| `GIT_STREAM_GRACE_SECS` | `5` |
| `MAX_CACHED_CLONES` | `8` |
| `MAX_GIT_STDERR_BYTES` | `4096` |
| `MAX_GIT_SMALL_OUTPUT_BYTES` | `64 * 1024` |

Clone is `git clone --quiet --depth 201 --single-branch`. The `+1` on 200 is
deliberate: `rev-list --count` must be able to *see* the cap so truncation is
detectable inside a shallow clone.

## Gotchas
- **`fetch_verified` must re-clone into a fresh temp dir, never use
  `cached_repo`.** The doc comment says why: "its re-clone exists so the archive
  bytes are a second, independent sample from the remote." Reusing the cached
  clone collapses resolve-time and verify-time into one sample and destroys
  `store::integrity_change_is_rejected` history-rewrite detection.
- **Clone depth `201` is load-bearing.** Dropping the `+1` makes
  `rev-list --count` return 200, `truncated` flips to `false`, and resolving an
  old version reports "not found" instead of stating truncation.
- **`pin_clone_url` is the real boundary, not `parse_git_tarball_url`.** The
  grammar helper happily accepts `git+/tmp/f/x.git#<40-hex>`. The pin requires
  the URL to `strip_prefix("{git_base}/")`, `strip_suffix(".git")`, and then
  pass `validate_aur_name`; failure must keep the substring `"clone url"` in the
  message (asserted at `aur.rs:1848`).
- **Resolve and releases treat truncation differently.** `resolve` appends
  "the walk stopped at the 200 newest commits…" to a not-found error;
  `list_releases` refuses outright. Making them symmetric silently narrows what
  resolve can find.
- **Git is argv-only, never a shell**, with `LC_ALL=C`, `stdin(null())`,
  `process_group(0)` on unix, a `try_wait()` poll every 10 ms, and pipes drained
  on detached threads with `recv_timeout(5s)` — "its transport still holds the
  stdout pipe after 5s; refusing to wait" is the anti-hang shape.
- **`commit_version`'s skip/fail split hinges on the English string
  `"does not exist"`** (hence `LC_ALL=C`). If `git cat-file -t` fails or the
  kind is not `commit`, the error **propagates** — that is what stops a corrupt
  object from being counted as "no .SRCINFO" and letting the wrong commit match.
  `oversized_srcinfo_is_a_per_commit_skip_not_a_repo_error` pins the skip counter.
- **The archive root is the repo root.** No pkgbase subdirectory. `review.rs`
  requires `PKGBUILD` **and** `.SRCINFO` to be *files* at the root and
  `manifest.name == canonical_name`, else `Manifest(...)` "refusing to review".
  That is why `verify_single_root` is cargo-only.
- **`release_author` returns `Option` on purpose.** Every failure (parse, pin,
  cache, `cat-file`, `log`, empty email, control chars) collapses to `None`,
  and `review.rs` treats `None` on either side as *no signal*. Making any of
  these a hard error turns an AUR outage into a failed review. The email is
  self-declared — a matching identity is not proof of the same person.
- **`list_versions` deliberately does not re-sort** ("pins the order as a
  regression net") and its semver mapping is lossy: `"1.0-1"` cannot be
  represented and is dropped.
- **Split packages are refused in both `resolve_package` and `releases_sorted`.**
  Newest-commit-wins: commits sharing a `pkgver-pkgrel` collapse to the newest.