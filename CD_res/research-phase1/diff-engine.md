# Diff engine research: ship file-level ops + binary/opaque classification first, add similar 3 with inline as the only new dependency, and treat "changed but unreadable" as a risk signal, never a silent skip

Research for Phase 1, wedge primitive, first item: the diff engine. Grounded in the shipped Phase 0 code (`src/extract.rs` caps at 512 MiB unpacked, 128 MiB per entry; `src/review.rs` keeps the review single-package, baseline in SQLite; `ARCHITECTURE.md` §2 ruleset already lists new executables, `scripts` additions, new deps, obfuscation, maintainer change). The engine's job is to produce the typed delta the heuristic ruleset (Phase 1, next item) consumes.

## 1. The `similar` crate: version, features, API, and the minified-file problem

**Current version: 3.1.2**, published 2026-08-04 per docs.rs. The `similar` crate page on crates.io showed 3.1.1 as the headline release (the scrape was likely cached); docs.rs lists 3.1.2 as the newest build. Maintained by Armin Ronacher (mitsuhiko), built for the insta snapshot testing library, Apache-2.0, and default-feature build has zero dependencies (bstr, hashbrown, serde, unicode-segmentation, web-time are all optional). [docs.rs/similar](https://docs.rs/similar/latest/similar/), [crates.io/similar](https://crates.io/crates/similar).

**Feature flags** (from the docs.rs crate page and the crate-level docs): `std` (default), `text` (default, enables `TextDiff` and the `udiff` module), `unicode` (grapheme diffing, pulls unicode-segmentation), `bytes` (byte-slice text APIs, pulls bstr), `inline` (per-line inline highlight refinement), `serde` (partial serialization of some types), `wasm32_web_time`, `hashbrown` (no_std map backend). [docs.rs/similar feature flags](https://docs.rs/similar/latest/similar/index.html).

**(a) File-level changed/added/removed lists.** `capture_diff_slices(Algorithm, &old, &new) -> Vec<DiffOp>` and the deadline variant give exactly the ops you need, with `DiffOp` being `Equal { old_index, new_index, len }`, `Delete { old_index, old_len }`, `Insert { new_index, new_len }`, `Replace { .. }`. For diffing by a derived key there is `capture_diff_slices_by_key`. There is no higher-level "changeset" type in `similar`. [docs.rs similar crate root](https://docs.rs/similar/latest/similar/). Note: a type literally named `Changeset` exists only in the older `difference` crate (2.0.0, last published 2018, effectively dead) and the `text_diff` crate. The implementer should not go looking for `similar::Changeset`; the equivalent is the `Vec<DiffOp>`.

**(b) Line-level unified diffs.** `TextDiff::from_lines(old, new)` then `diff.unified_diff().context_radius(n).header(a, b)` renders a standard unified diff; `UnifiedDiff::to_writer` streams bytes. `iter_changes()` yields per-item `Change` with `ChangeTag::{Equal, Delete, Insert}`; `grouped_ops(n)` isolates change clusters, and the docs explicitly say this "works for very long files if paired with this method". `iter_inline_changes()` (requires `inline` feature) performs a second-level diff inside adjacent line replacements, i.e. intra-line highlighting; it has a hardcoded 500 ms deadline, with explicit deadline/options variants for control. `Change::missing_newline` handles the "no newline at end of file" case. [TextDiff docs](https://docs.rs/similar/latest/similar/struct.TextDiff.html), [udiff docs](https://docs.rs/similar/latest/similar/udiff/index.html).

**Binary detection: `similar` is not a binary detector.** It diffs text (or byte slices with the `bytes` feature) but has no notion of "this is a binary file, do not diff". Binary detection must be done in Blueline, before calling similar. The ecosystem standard is content-based: git's `buffer_is_binary` flags a file as binary if it contains a NUL byte in the first 8000 bytes (`#define FIRST_FEW_BYTES 8000; return !!memchr(ptr, 0, size);` in `xdiff-interface.c`), and git additionally treats blobs over a `big_file_threshold` (512 MiB) as binary for diffing purposes. npm's own `npm diff` takes the opposite, extension-based route: `libnpmdiff`'s `should-print-patch.js` consults the `binary-extensions` npm package and emits only the file header (no patch) for those extensions, unless `--diff-text` is passed. A NUL-byte content check is the stronger, fail-closed choice for npm tarballs because it cannot be defeated by an attacker choosing a misleading extension, and it is what git itself trusts. Sources: [git `buffer_is_binary`](https://rtime.ciirc.cvut.cz/gitweb/git.git/commitdiff/6bfce93e04d13ecb42008a3cf214cc892f480f0c), [git large-file/binary discussion](https://secure.phabricator.com/T13143), [libnpmdiff `should-print-patch.js`](https://github.com/npm/cli/blob/latest/workspaces/libnpmdiff/lib/should-print-patch.js).

**Diffing a 10 MB minified JS file without OOM.** The risk is algorithmically bounded, so pick algorithms and tokenization deliberately:

- Never use `Algorithm::Lcs` at this scale: it is `O(N*M)` time and space and "mainly for small inputs, debugging, or reference behavior". `Algorithm::Myers` is `O((N+M)D)` time, `O(N+M)` space, and is the documented default "for a reason: good general quality, good performance, and robust behavior with deadlines". [similar::algorithms docs](https://docs.rs/similar/latest/similar/algorithms/index.html), [similar::myers docs](https://docs.rs/similar/latest/similar/algorithms/myers/index.html).
- A 10 MB minified file is usually a handful of lines, so `from_lines` itself is cheap. The expensive case is tokenizing the whole thing at word/char level. That is exactly why inline refinement diffs the replacement regions only, never the whole file, and why `iter_inline_changes` ships a default 500 ms deadline.
- The real OOM trap is unbounded output, not unbounded diffing: rendering a 10 MB one-line replacement as one hunk is memory-heavy. `grouped_ops` and `UnifiedDiff::to_writer` bound the render side.
- Similar's own changelog shows it has been hardened for adversarial inputs: "Added a global disjoint-input fast path to avoid pathological runtimes on large, fully distinct inputs", "Improved Myers performance on heavily unbalanced diffs", and automatic `IdentifyDistinct` above a size threshold. [CHANGELOG.md](https://github.com/mitsuhiko/similar/blob/HEAD/CHANGELOG.md).
- Deadlines: every algorithm has a `_deadline` variant; Myers degrades gracefully to a "pretty decent diff" when it bails, while LCS "produces weak approximations". `TextDiffConfig::deadline` sets this on the high-level API. Gotcha: deadline checks are silently disabled on wasm unless `wasm32_web_time` is on; irrelevant to Blueline (a native binary), but it explains why the option exists. [similar crate docs, Deadlines and Performance](https://docs.rs/similar/latest/similar/index.html).
- Other gotchas worth writing down now: (1) `from_lines` distinguishes `foo\n` from `foo` (trailing-newline philosophy), surfaced via `Change::missing_newline`; (2) byte diffs "work for latin1 but EBCDIC gives garbage", so decide text vs opaque on UTF-8 validity, not on bytes; (3) `iter_inline_changes`'s exact inline-detection behavior "is currently not defined and will likely change", so do not depend on its precise boundaries, only on its tags; (4) `serde` support is partial, so do not plan to serialize the full diff via that feature. [similar crate docs, Trailing Newlines and Bytes vs Unicode](https://docs.rs/similar/latest/similar/index.html).

## 2. Security-relevant diff signals: what actually caught real incidents

The signals in `ARCHITECTURE.md` §2 are the right list. Every one maps to a documented incident, and in each case the signal was present in a version-to-version diff:

- **event-stream 2018 (flatmap-stream).** A "new maintainer" (@right9ctrl) added a brand-new dependency `flatmap-stream` (`^0.1.0` range, so the later malicious `0.1.1` auto-resolved), then released `event-stream@3.3.6`. The payload lived only in the minified `index.min.js` as AES-encrypted blobs plus hex string literals, decrypted with the importing package's description as key. Detection happened only because a deprecation warning surfaced in nodemon, not by any tool. A diff review would have surfaced: new dependency, maintainer change, and a minified-only code delta. [A Systematic Analysis of the Event-Stream Incident (paper)](https://es-incident.github.io/paper.html), [npm blog analysis](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident), [Snyk postmortem](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/).
- **eslint-scope / eslint-config-eslint 2018.** Compromised maintainer account (reused password, no 2FA). `eslint-scope@3.7.2` and `eslint-config-eslint@5.0.2` each carried a `postinstall` script that exfiltrated `~/.npmrc` to pastebin. A user reported it 37 minutes after publish. The `postinstall` script was entirely new in that version: a pure scripts-field delta is the whole story. [ESLint postmortem](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/).
- **ua-parser-js 2021 (CVE-2021-4229 / GHSA-pjwm-rvh2-c87w).** Account takeover; three malicious versions (`0.7.29`, `0.8.0`, `1.0.0`) each added a `preinstall` script (`preinstall.js` + `preinstall.bat`/`preinstall.sh`) that downloaded and executed the XMRig miner (`jsextension`/`jsextension.exe`) and a credential stealer (`sdd.dll` → `create.dll`). The maintainer pointed to the package diff as the proof ("you can see the diff here", Renovate package-diff link). Diff-visible signals: new install scripts, new `.sh`/`.bat`/`.exe` files, maintainer account anomalies. [CISA alert](https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js), [GitHub Advisory GHSA-pjwm-rvh2-c87w](https://github.com/advisories/GHSA-pjwm-rvh2-c87w), [official issue with diff links](https://github.com/faisalman/ua-parser-js/issues/536), [BleepingComputer analysis](https://www.bleepingcomputer.com/news/security/popular-npm-library-hijacked-to-install-password-stealers-miners/), [Snyk CVE page](https://security.snyk.io/vuln/SNYK-JS-UAPARSERJS-1766952).
- **TanStack/router worm 2026 (CVE-2026-45321 / GHSA-g7cv-rxg3-hmpx).** 84 malicious versions across 42 `@tanstack/*` packages, published through the project's own OIDC-trusted GitHub Actions pipeline. Each tarball smuggled `router_init.js` (2,341,681 bytes, obfuscated, at package root and deliberately not listed in `package.json` "files"), plus an `optionalDependencies` entry pointing at an orphan git commit (`"@tanstack/setup": "github:tanstack/router#79ac49ee..."`) whose `prepare` script ran the payload (`bun run tanstack_runner.js && exit 1`, the `&& exit 1` making npm silently discard the failed optional install). The malware harvested AWS/GCP/K8s/Vault/npm/GitHub/SSH credentials and exfiltrated via the Session messenger network; it self-propagated by enumerating other packages the victim maintains. It carried valid SLSA provenance, which is exactly why provenance alone must not be trusted. Every one of these fingerprints is visible in a version diff: a 2.3 MB opaque new file, a git-spec dependency appearing in `optionalDependencies` where none existed, and new lifecycle scripts. [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem), [StepSecurity analysis](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem), [OSV entry](https://osv.dev/vulnerability/GHSA-g7cv-rxg3-hmpx), [CVE record](https://nvd.nist.gov/vuln/detail/cve-2026-45321), [socket.dev supply chain attacks page](https://socket.dev/supply-chain-attacks/mini-shai-hulud).
- **Socket / install-script campaigns.** Socket's risk tiers rank install scripts highest ("The majority of malware in npm is hidden in install scripts"), then obfuscated code, then native code, then high-entropy strings. Their 2025-2026 postinstall campaign (700+ GitHub repos, 8 Packagist packages) used `curl -skL ... -o /tmp/.sshd && chmod +x && /tmp/.sshd &` in `package.json` postinstall, planted across repositories that also ship JS build tooling. Diff-visible: a new `postinstall`, new shell files, embedded binaries. [Socket supply chain risk docs](https://docs.socket.dev/docs/supply-chain-risk), [Socket postinstall campaign post](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos), [npm's own install-scripts abuse post](https://blog.npmjs.org/post/141702881055/package-install-scripts-vulnerability.html).
- **npq (Liran Tal).** The closest prior-art tool to Blueline. Its "marshalls" encode exactly the review signals: `scripts` (pre/post install), `author` (new maintainer on the package within 21 days, dormant maintainer gap over ~6-9 months), `newBin` (new `bin` entry vs the previous version), `version-maturity` (version published less than 7 days ago), `typosquatting`, expired maintainer-email domains, plus provenance/signature checks. npq runs these on metadata before install; Blueline differs by diffing the extracted tarballs. [npq README](https://github.com/lirantal/npq).

**Synthesis for the ruleset.** The diff engine should expose, per release delta: added/changed/removed lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`), new `bin` entries, new/changed `dependencies`/`optionalDependencies` (especially git-spec or newly-broadened ranges), new executable or binary files (`.exe`, `.dll`, `.node`, `.sh`, `.bat`, executable bit), new opaque/minified/high-entropy file contents, maintainer/author deltas (from registry metadata, not the tarball), version jump and publish recency, and files present in the tarball but absent from the declared `files` allowlist (the TanStack tell). That last one only works because Blueline already extracts and reads the tarball directly.

## 3. Line-level diff quality: per-line classification is the substrate, unified diff is the rendering

They are not alternatives; one is derived from the other. `TextDiff` computes `Vec<DiffOp>` once (`DiffTag::{Equal, Delete, Insert, Replace}` over old/new index ranges), then exposes two views of the same object: `iter_changes()` (per-line `Change` with `ChangeTag`, i.e. the added/removed/context classification) and `unified_diff()` (rendered hunks). A heuristic engine wants the classification (count added/removed/replaced lines, find replacement runs to scan for obfuscation); the human card wants the unified render. The replace/equal distinction also matters for the review card: a single `Replace` of one giant minified line should be flagged as opaque, not presented as 40,000 added lines.

Unified diff alone is the interchange format (git, npm diff, GitHub all use it), and Blueline should be able to emit it for card copy-paste, but it is lossy for scoring: context lines are collapsed, tags are implied by line prefixes, and the format says nothing about replacements. Compute the diff once and derive both views from it, which is exactly what `TextDiff` supports.

**`diff` crate vs `similar`.** The `diff` crate (`diff.rs`, version 0.1.13) is LCS-only, has no algorithm choice, no deadlines, no unified-diff renderer, no inline highlighting, and its last release was 2022-06-29; it is essentially frozen. `difference` 2.0.0 is dead since 2018. `diffy` is oriented at parsing and applying patches (its `binary` feature applies git binary patches), which Blueline does not need since it generates rather than consumes diffs. `similar` 3 is the actively maintained choice and already named in `ARCHITECTURE.md` §3, so it is also the dependency-consistency choice. Sources: [diff on crates.io](https://crates.io/crates/diff), [difference on crates.io](https://crates.io/crates/difference), [diffy docs](https://docs.rs/diffy/latest/diffy/).

## 4. The minified / one-line file problem: "changed but unreadable" is a real and expected state

Minified or machine-generated single-line files are normal on npm (bundlers ship `dist/*.min.js`), so the engine must classify them, not crash on them. How the established tools handle it:

- **GitHub.** Hard diff limits: no single file's diff may exceed 20,000 loadable lines or ~1 MB of raw diff (current docs: 500 KB per file, 1 MB/20,000 lines per PR total, 300 files max in the diff endpoint view), and only the first 400 lines / 20 KB are auto-loaded per file. Files past the limit show a "Load diff" affordance or nothing. Huge PRs additionally hit an API 406 "too_large". `linguist-generated=true` in `.gitattributes` makes GitHub collapse a file by default in the PR view. [GitHub repo limits, diff limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits), [GitHub blog on diff page limits](https://github.blog/engineering/architecture-optimization/how-we-made-diff-pages-3x-faster/), [reviewdog issue documenting the 406](https://github.com/reviewdog/reviewdog/issues/1696), [customizing how changed files appear](https://docs.github.com/en/repositories/working-with-files/managing-files/customizing-how-changed-files-appear-on-github).
- **Gerrit.** Configurable `change.maxFileSizeDiff` makes file-diff requests fail above a size threshold, and very large files do not render a whole-file diff; binary heuristics treat UTF-16 (NUL-containing) files as binary. [Gerrit configuration docs](https://gerrit-review.googlesource.com/Documentation/config-gerrit.html), [Gerrit large-file thread](https://groups.google.com/g/repo-discuss/c/TaurI7tcets).
- **Review Board.** Review requests were explicitly built to "collapse minified files by default" so reviewers are not forced to read them. [Review Board review request #9337](https://reviews.reviewboard.org/r/9337/).
- **npm's own `npm diff`.** Binary files (by extension) get only the `---`/`+++` header with no patch; `--diff-text` forces a text diff. [libnpmdiff `format-diff.js`](https://github.com/npm/cli/blob/latest/workspaces/libnpmdiff/lib/format-diff.js).
- **Community practice for one-line data.** git `textconv` (e.g. `jq .` via a `diff=json` attribute) to pretty-print before diffing, and word/character-level diffing (meld, WinMerge, similar's `from_chars`/`from_words`) for intra-line change. [git diff filter for minified files](https://superuser.com/questions/698587/git-diff-filter-for-minimized-files), [comparing minified JS](https://stackoverflow.com/questions/8589434/tools-for-comparing-minimized-javascript-files).

**Is opaque-blob-changed a legitimate risk signal? Yes.** Every major review tool degrades large/minified/binary files to "changed, content not shown", and attackers exploit exactly that gap: the flatmap-stream payload lived only in the minified file; the TanStack payload was a 2.3 MB obfuscated single file. For Blueline the rule must be fail-closed-by-default: a changed file that cannot be diffed readably is classified `Binary` or `OpaqueChanged` and fed to the heuristic as a first-class signal (consistent with `ARCHITECTURE.md`: "obfuscated / base64 / eval in diff", "new executable/binaries"). It is never silently skipped and never labeled "no change". The heuristic ruleset decides the verdict; the diff engine's job is to not lose the fact that an unreadable delta exists.

## 5. Diffing a directory tree: sorted path merge, not a full edit script

Two extracted trees, `old/` and `new/`, each nested under `package/`. The task decomposes into: (1) enumerate both trees, (2) align by relative path, (3) per-path decide Added / Removed / Changed / Unchanged, (4) for changed text files run the line diff.

- **Enumeration: `walkdir` 2.5.0** (BurntSushi, Unlicense/MIT, published 2024-03-01). Symlink-following defaults off, which fits Blueline since `extract.rs` already rejects symlinks during unpacking. [walkdir docs](https://docs.rs/walkdir/latest/walkdir/).
- **Alignment: `similar`'s Changeset does not exist here.** There is no directory-tree diff API in similar. The file-level op pass is best done as a path-keyed map merge (BTreeMap<PathBuf, FileEntry> from each tree, union of keys, compare presence + size + hash), which is O(N log N) and deterministic. `capture_diff_slices_by_key` would produce a full edit script where a rename shows up as delete+insert, which is noise for npm packages whose paths rarely rename across releases; the map merge is simpler and is what the tools below effectively do.
- **npm's own implementation.** `libnpmdiff` (backs `npm diff`): fetches both tarballs via pacote, untars into memory (`untar.js` collects a `Set` of filenames and a `Map` of `{content, mode}` per file), then per file skips if `content` and `mode` are equal, emits a git-compatible header (`diff --git`, `deleted file mode` / `new file mode` / `old mode` lines, `index` line), and renders `createTwoFilesPatch` from the JS `diff` package with context 3. Content equality there is literal byte equality on the in-memory buffer; Blueline should add a size prefilter then a hash, so a 10 MB unchanged file is not read twice. [libnpmdiff index.js](https://github.com/npm/cli/blob/latest/workspaces/libnpmdiff/lib/index.js), [libnpmdiff format-diff.js](https://github.com/npm/cli/blob/latest/workspaces/libnpmdiff/lib/format-diff.js), [libnpmdiff untar.js](https://github.com/npm/cli/blob/latest/workspaces/libnpmdiff/lib/untar.js), [npm diff docs](https://docs.npmjs.com/cli/v10/commands/npm-diff).
- **Incident-validated diff tooling.** Package-diff services caught or demonstrated these incidents in practice: the ua-parser-js maintainer pointed reviewers at a Renovate package-diff link (`renovatebot.com/package-diff`), and diffend.io diffs were linked in the same thread as forensic evidence. These tools are the market validation for Blueline's core loop. [ua-parser-js issue #536 with diff links](https://github.com/faisalman/ua-parser-js/issues/536).

## Recommendations for Blueline

**Crate choices (YAGNI-trimmed).**
- Add `similar = { version = "3", features = ["inline"] }`. `inline` is needed for intra-line highlight of minified one-line files. Do not add `bytes` (reject non-UTF-8 as opaque instead of byte-diffing), `unicode` (grapheme diffing is not needed for npm JS), or `serde` (partial coverage; serialize the typed `Delta` yourself).
- Add `walkdir = "2"` for tree enumeration.
- Do not add `diff`, `difference`, or `diffy` (dead, dead, and apply-oriented). Reuse the `sha2` dependency already in `Cargo.toml` for content-equality hashing.

**Module shape.**
- `diff::tree_diff(old_root, new_root, limits) -> Result<Delta, DiffError>`: walk both trees, strip the `package/` prefix, build path-keyed entries, compute per-path `FileOp`.
- `diff::file_diff(path, old_bytes, new_bytes, limits) -> Result<Change, DiffError>`: classify fragment first, then optionally line-diff. Classification order: NUL byte in first 8 KiB (git's `buffer_is_binary`) or non-UTF-8 → `Binary`; byte count above a cap (reuse the 128 MiB per-entry extract cap as an upper bound, but a far smaller line-diff cap like a few thousand lines) or line count above a cap → `OpaqueChanged`; otherwise text.
- For text: `TextDiff::configure().algorithm(Algorithm::Myers).deadline(now + ~1s)`, consume `ops()` for `LineStats { added, deleted, replaced }`, detect replace-runs that are single giant lines (flag for obfuscation scanning), and render unified hunks via `unified_diff()` only when the card needs them (defer, or cap hunk count with `grouped_ops`).

**Typed output.**
```
struct Delta {
    from: String,                    // baseline version
    to: String,                      // reviewed version
    entries: Vec<FileDelta>,         // one per path, sorted
    summary: DeltaSummary,           // counts + signals for the heuristic
    scripts_added: Vec<String>,      // lifecycle script keys new/changed in this delta
    bin_added: Vec<String>,
    deps_added: BTreeMap<String, String>,   // incl. optionalDependencies, git-specs
    manifest_changed: bool,
}
enum FileOp { Added, Removed, Changed(Change), Unchanged }
enum FragmentKind { Text, Binary, OpaqueChanged }
struct Change { kind: FragmentKind, line_stats: Option<LineStats>, hunks: Option<Vec<String>> }
```
This is the wedge: `entries` + `summary` alone feed the Phase 1 heuristic (new `.sh`/`.bat`/`.exe`, new 2.3 MB opaque file, new script key, new git-spec dep are all visible in `FileOp`/`FragmentKind` without any line diff). Hunks stay `Option` until the render stage.

**Fail-closed edge cases.**
- **Empty diff between two different versions**: not an error, but not silent either. Emit an `Unchanged`-only `Delta` and surface "identical tarball bytes under a new version" as a note; a republished-unchanged version is itself a review signal, and per D5 the baseline bookkeeping still must run.
- **Both trees missing / baseline unresolvable**: error out loud (`DiffError::NoBaseline`) and do not fabricate an empty delta; per `ARCHITECTURE.md` D5 a first sighting is a neutral "no known-clean baseline" verdict, but that verdict comes from the caller, not from a fake empty diff.
- **Binary/opaque detection**: classify conservatively. When in doubt between text and opaque, and the bytes are valid UTF-8, attempt the line diff with a deadline; if the diff cannot be produced within the deadline or the line is pathologically long, downgrade to `OpaqueChanged`. Never skip the file from the delta, never mark it Unchanged.
- **Over-limit files**: mark `OpaqueChanged` (mirroring git's big-file binary treatment) rather than OOM on tokenization or hunk rendering.

**Build FIRST (YAGNI).** (1) tree walk + path-keyed merge → `Delta` with `FileOp`/`FragmentKind` and content-equality via size+hash; (2) binary/opaque classification; (3) `LineStats` aggregation for text files using `similar`'s `TextDiff` ops with a deadline. That already catches every incident in section 2 (new preinstall script, new `.sh`/`.bat`/`.exe`, new opaque 2.3 MB file, new dependency). Defer: unified-hunk rendering into the card, inline word-level highlighting beyond the `inline` feature default, rename detection, diff persistence/patch file output, and any `serde` on similar types.

## Sources

- https://docs.rs/similar/latest/similar/
- https://docs.rs/similar/latest/similar/algorithms/index.html
- https://docs.rs/similar/latest/similar/algorithms/myers/index.html
- https://docs.rs/similar/latest/similar/struct.TextDiff.html
- https://docs.rs/similar/latest/similar/udiff/index.html
- https://crates.io/crates/similar
- https://github.com/mitsuhiko/similar
- https://github.com/mitsuhiko/similar/blob/HEAD/CHANGELOG.md
- https://github.com/mitsuhiko/similar/issues/15 (Myers heuristics, distinct-line bail)
- https://crates.io/crates/diff
- https://crates.io/crates/difference
- https://docs.rs/diffy/latest/diffy/
- https://docs.rs/walkdir/latest/walkdir/
- https://docs.npmjs.com/cli/v10/commands/npm-diff
- https://github.com/npm/cli/tree/latest/workspaces/libnpmdiff
- https://github.com/npm/cli/blob/latest/workspaces/libnpmdiff/lib/index.js
- https://github.com/npm/cli/blob/latest/workspaces/libnpmdiff/lib/format-diff.js
- https://github.com/npm/cli/blob/latest/workspaces/libnpmdiff/lib/untar.js
- https://github.com/npm/cli/blob/latest/workspaces/libnpmdiff/lib/should-print-patch.js
- https://es-incident.github.io/paper.html
- https://es-incident.github.io/payloads.html
- https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident
- https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/
- https://github.com/dominictarr/event-stream/issues/115
- https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/
- https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js
- https://github.com/advisories/GHSA-pjwm-rvh2-c87w/
- https://github.com/faisalman/ua-parser-js/issues/536
- https://www.bleepingcomputer.com/news/security/popular-npm-library-hijacked-to-install-password-stealers-miners/
- https://security.snyk.io/vuln/SNYK-JS-UAPARSERJS-1766952
- https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
- https://osv.dev/vulnerability/GHSA-g7cv-rxg3-hmpx
- https://nvd.nist.gov/vuln/detail/cve-2026-45321
- https://github.com/tanstack/router/issues/7383
- https://socket.dev/supply-chain-attacks/mini-shai-hulud
- https://docs.socket.dev/docs/supply-chain-risk
- https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos
- https://blog.npmjs.org/post/141702881055/package-install-scripts-vulnerability.html
- https://github.com/lirantal/npq
- https://rtime.ciirc.cvut.cz/gitweb/git.git/commitdiff/6bfce93e04d13ecb42008a3cf214cc892f480f0c (git `buffer_is_binary`)
- https://secure.phabricator.com/T13143 (git treats large text files as binary)
- https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits
- https://github.blog/engineering/architecture-optimization/how-we-made-diff-pages-3x-faster/
- https://docs.github.com/en/repositories/working-with-files/managing-files/customizing-how-changed-files-appear-on-github
- https://github.com/reviewdog/reviewdog/issues/1696
- https://gerrit-review.googlesource.com/Documentation/config-gerrit.html
- https://groups.google.com/g/repo-discuss/c/TaurI7tcets
- https://reviews.reviewboard.org/r/9337/
- https://superuser.com/questions/698587/git-diff-filter-for-minimized-files
- https://stackoverflow.com/questions/8589434/tools-for-comparing-minimized-javascript-files
- https://stackoverflow.com/questions/76457826/how-does-text-auto-work-how-does-git-determine-if-something-is-a-text-file

## Adversarial self-check

- **Exact latest `similar` version ambiguity**: docs.rs lists 3.1.2 published 2026-08-04; the crates.io page scrape returned 3.1.1 at the top of the versions list. Most likely 3.1.2 is the newest and the crates.io scrape was cached; I did not fetch crates.io's JSON API to confirm the canonical `max_stable_version`. Either way `similar = "3"` is correct.
- **Memory bounds of `similar` on multi-MB inputs**: the `O(N+M)` space claim comes from the Myers module docs; I found no published benchmark of `TextDiff::from_lines` on a 10 MB single-line file. The plan therefore always pairs line diffing with a size/line cap and a deadline and downgrades to `OpaqueChanged` on the cap. The "no OOM" argument is a design guarantee, not a measured one.
- **`iter_inline_changes` semantics**: the docs state the exact inline-detection behavior "is currently not defined and will likely change". I verified the API surface (features, deadline variants, `InlineChangeOptions`) but not its exact intra-line behavior. Blueline should treat inline output as display-only and never feed its precise boundaries into scoring.
- **GitHub's per-line length behavior**: GitHub's docs state file/PR limits but say nothing about a maximum line length; community reports indicate long lines render with horizontal scrolling. I could not verify a documented single-line cap, so the minified-line story rests on GitHub's line-count/size limits, not a line-length rule.
- **JS `diff` package performance**: libnpmdiff uses the JS `diff` package for `createTwoFilesPatch`; I verified the source calls and options but did not benchmark it against a 10 MB file. It is cited as the behavior reference for header-only binary output, not as a performance baseline.
- **Incident attribution detail**: event-stream, ua-parser-js, and eslint-scope facts come from primary postmortems and advisories; the TanStack worm facts come from first-party postmortem, StepSecurity, OSV, and NVD summaries, all mutually consistent as of today's date. I did not independently reverse the tarballs.
- **Renovate/diffend internals**: the ua-parser-js thread links Renovate package-diff and diffend.io URLs as the detection/demonstration artifacts. I verified the links exist in the official thread but did not inspect either tool's implementation, so nothing about them is claimed beyond "the community used package diffs as evidence".
- **`walkdir` version**: 2.5.0, published 2024-03-01 (confirmed via docs.rs and crates.io).
- **`serde` coverage in `similar`**: docs.rs lists a `serde` feature and says "serialization to some types"; I did not enumerate which types, hence the recommendation to serialize Blueline's own `Delta` rather than rely on it.
