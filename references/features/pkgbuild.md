# PKGBUILD

A hand-rolled, quote-aware bash tokenizer plus thirteen static rules over
PKGBUILDs. AUR only. Nothing here sources a PKGBUILD, invokes `makepkg`, or
shells out. It protects AUR reviews from the fact that a PKGBUILD *is* a shell
script — every rule is an attempt to see remote-code-execution patterns in text
that will be executed by someone else's build later.

## Sub-features

- Bounds: 1 MiB, 64k lines, and seven inner caps.
- `split_words` / `decode_ansi_c` / `parse_dollar`: the lexer.
- `join_continuations` / `strip_comment` / `split_array_elements`: the line layer.
- Multi-pass variable folding: `FoldedValue::{Known, Unknown}`.
- `check()` for single-file rules, `check_pair()` for baseline-diff rules.
- `review_roots`: the entry point, including the four `R00_*` scope rules.
- `npm_delivery_refs`: hands specs to [recursive](recursive.md).

## How to get to it (user POV)

AUR reviews only:

```sh
./target/debug/blueline --ecosystem aur review <pkgbase>@<pkgver>-<pkgrel> --output text
```

R11–R23 findings appear in the card's `Security Findings` section; `R23_NPM_DELIVERY`
also produces a recursive npm review.

## Gotchas

**Every rule's severity was set by a 137-PKGBUILD benign corpus, not by taste.**
Six rules carry the verbatim comment *"INFO until tuned"*. Raising one back
without re-running `tests/pkgbuild_heuristics.rs::benign_corpus_scores_zero_above_info`
will fail the gate. The corpus is `tests/fixtures/pkgbuild_benign/` — 137 real
PKGBUILDs at the commits pinned in `manifest.tsv`, collected 2026-09-05. Its
README: *"A firing rule ships demoted to INFO until tuned; fixtures are never
edited to make a rule pass."* **Never edit a fixture to make a rule pass.**

**Three fixtures are pinned as documented TRUE POSITIVES for R23 only:**
`016-insomnia`, `018-bitwarden-cli`, `078-joplin-desktop`. They genuinely run
`npm install` in their build. `r23_is_medium_and_fires_on_all_three_true_positive_fixtures`
asserts each fires ≥1 hit and that every hit is exactly `MEDIUM`.

**`R00_PKGBUILD_UNREADABLE` and `R00_PKGBUILD_UNPARSEABLE` return
immediately.** No other rule runs — not even `R00_PKGBUILD_SCOPE`, the scope
disclosure that is otherwise emitted on every path. `R00_BASELINE_UNPARSEABLE`
is non-fatal: pair rules are skipped but target findings and R20 still appear.

**`R00_PKGBUILD_SCOPE` is always emitted last on every successful path:**
*"review covers repo scripts only; downloaded upstream sources are not
reviewed."* Every AUR card carries it.

**Pair rules only run with a baseline.** R12 and R19 need two PKGBUILDs;
`baseline_pkgbuild` is `None` for first sighting. `Some("")` means "the baseline
PKGBUILD was unreadable, already surfaced at HIGH" — both skip pair rules. First
sighting therefore produces *strictly fewer* findings, which is not the same as
safer. Test `first_sighting_skips_pair_rules`.

**`check_r13`, `r14`, `r17`, `r22` return on the FIRST matching line** — at most
one finding each per PKGBUILD. `r11` joins all matches into one finding;
`r23` accumulates into a `HashSet` on the evidence string. So "how many R13s" is
always 0 or 1.

**`$"…"` is `Tainted` outright, and backticks inside double quotes are
`Tainted`.** Both abort folding rather than producing a `Known` value, which is
the fail-closed direction. `$'…'` routes to the ANSI-C decoder.

**`$'…'` decodes `\xHH` and octal as RAW BYTES, not Latin-1.** The buffer is
built as bytes and lossily converted at the end, so `\xc3\xa9` is `é` not `Ã©`
and non-UTF-8 becomes U+FFFD. Octal `> u8::MAX` **fails closed**. Tests
`ansi_c_hex_escapes_emit_bytes_not_latin1_chars`,
`ansi_c_non_utf8_bytes_survive_as_replacement_chars`,
`ansi_c_octal_above_one_byte_fails_closed`.

**An undefined variable is `Unknown`, never empty.** Test
`undefined_var_is_unknown_not_empty`. `Unknown` values are what make R12 fire
"blind" and R19 report `<unknown>`.

**Folding runs at most `MAX_FOLD_PASSES = 8` and stops early at a fixed point.**
Indexed writes are applied **in source order** with gaps filled by the sentinel
`"$(__blueline_pad)"`, so `source[1]='SKIP'` overrides exactly slot 1. Test
`indexed_assignment_overrides_slot`. `arch` arrays stay distinct
(`source` ≠ `source_x86_64`) — test `arch_arrays_stay_separate`.

**`#` starts a comment only at a word boundary** — whitespace or one of
`; & | ( { ) < >`. So `git+https://x/y.git#commit=abc` keeps its `#` (test
`hash_inside_word_is_not_a_comment`) but `bar>#x` truncates to `bar>` (test
`redirect_hash_is_a_comment`).

**Associative-array writes parse but are never read.** Comment: *"Rules never
read assoc storage, but the write must not crash the parse and the value still
folds for taint tracking."* `non_ascii_index_becomes_assoc_without_panic` pins
the no-panic property.

**Function names allow `-`; variable names do not.** Split-package
`package_foo-bar()` needs it. `func_head` accepts `name() {`, `name () {`,
`name() (`, `function name {`, `function name() {`.

**Function bodies AND top-level shell are scanned.** Top-level non-assignment,
non-function lines are stored under the pseudo-key `"<top>"`, with `export`/
`local`/`declare`/`typeset` prefixes stripped so their assignments still fold.
Comment: *"`makepkg` sources the file, so these lines execute."* Tests
`subshell_body_is_scanned`, `hyphenated_package_func_is_scanned`,
`top_level_shell_is_scanned`.

**Bodies are comment-stripped before rules run**, so a commented-out
`curl | bash` inside a function does not fire R13. Test
`body_rules_quiet_on_commented_lines`.

**R13 also fires on process substitution** — `bash <(curl …)` — with no `|` in
sight. It fires *only* when a fetcher runs inside the substitution immediately
following an interpreter word. Test
`r13_fires_on_interpreter_process_substitution`; and
`diff <(a) <(b)` / `python <(echo hi)` stay quiet.

**R14 deliberately stays quiet on static `eval`.** Comment: *"freerdp's
`eval "depends+=(...)"` is a benign conditional-depends idiom."* It requires the
line to also contain `$ ` `` ` ``, `|`, `;`, `curl`, `wget`, or `bash`.
`bash -c` is only HIGH when the payload is dynamic or a fetcher.

**R15 fires only on TRUE indirection.** `${!name}` is indirection;
`${!arr[@]}`, `${!pre*}`, `${!pre@}` list keys and stay quiet. Test
`r15_fires_on_true_indirection_only`, `r15_quiet_on_plain_default`.

**R16 scans raw array elements, not folded values** — otherwise `pkgver()`'s
`git describe` would fire. Test `r16_fires_in_source_not_pkgver`.

**R17 skips the `pkgver` function entirely** — build-time fetches are INFO
because "benign builds fetch at build time too (tor-browser-bin pulls checksums
to verify, logseq fetches)."

**R18 scans the ENTIRE raw file** for 18 code points, not just added lines:
`00AD 180E 200B 200C 200D 200E 200F 202A 202B 202C 202D 202E 2060 2066 2067
2068 2069 FEFF`. HIGH, because invisible-unicode in a PKGBUILD is essentially
always malicious.

**R19 ignores key ORDER** — both sides are sorted before comparison. If either
side has an `Unknown` entry it degrades to LOW (`"<unknown>"` rendered) rather
than MEDIUM.

**R21 fires only when NO fragment part starts with `tag=` or `commit=`.**
`#branch=main` does not count as pinned — comment: *"bare `git+https://` tracking
HEAD is the AUR -git norm (two dozen corpus hits)."*

**R22 matches whole words only.** `strip_token` trims quotes, `; ( ) , \` { }`
then leading `$(` then leading `$`. `shuffled` and `"valid -u flag"` do not fire.
Test `r22_ignores_word_substrings`.

**R20 is emitted only from `review_roots`, never from `check()`.** It scans the
file delta for paths ending `.install`, ending `.hook`, or matching a name from
the target/baseline PKGBUILD's `install=`.

**`R23` and `npm_delivery_refs` use DIFFERENT grammars and do not agree.**
R23's `scan_r23` matches `words.windows(2)` over
managers `[npm, bun] × verbs [install, i, ci, add, exec, run, x, dlx]`, plus any
line containing the word `npx`. `npm_delivery_refs` delegates to
`install_ref::scan_line`, which excludes `npm run` (a local script) and
`npm ci` (the manifest's own deps). So a line can produce an R23 finding and no
install reference, or vice versa. That is by design — R23 is disclosure,
`npm_delivery_refs` feeds recursion.

**A PKGBUILD that fails static parsing yields NO `npm_delivery_refs`** — the
function returns `Vec::new()`. The HIGH `R00_PKGBUILD_UNPARSEABLE` finding is
what fails that review. Test `npm_delivery_refs_unparseable_pkgbuild_is_empty`.

**Evidence strings always use the ORIGINAL line**, never the match-normalized
text (`"cu"rl`, `$'\x63url'`, `b"a"sh` normalize for matching only).

**Bounds (all exact-boundary tested where it matters):**

```
PKGBUILD_MAX_BYTES    = 1_048_576   (1 MiB)   test: byte_cap_is_exact
PKGBUILD_MAX_LINES    = 64_000
MAX_ASSIGNMENTS       = 4096
MAX_ARRAY_ELEMENTS    = 4096
MAX_FOLDED_BYTES      = 65_536
MAX_FOLD_PASSES       = 8
MAX_NESTING_DEPTH     = 16
```

## Rule table

Run order inside `check()`: r11, r13, r14, r23, r15, r16, r17, r18, r21, r22.
`check_pair()`: r12, then r19. R20 only from `review_roots`.

| rule_id | Severity | Fires when |
|---|---|---|
| `R11_CHECKSUM_SKIP` | LOW | `SKIP` in a `*sums*` array at an index whose paired `source{suffix}[idx]` is not VCS and not signature-covered |
| `R12_SOURCE_URL_DRIFT` | LOW / MEDIUM | LOW when any `source*` entry is `Unknown` (blind); MEDIUM when sorted known URLs differ and both `pkgver` are `Known` with the *same* version |
| `R13_PIPE_TO_SHELL` | HIGH | `curl\|wget\|aria2c\|axel` piped into `bash\|sh\|dash\|zsh\|fish\|python\|python3\|perl\|ruby\|php`, or an interpreter consuming `<(fetcher)` |
| `R14_EVAL_FAMILY` | HIGH / MEDIUM | dynamic `eval`; remote `source`/`.`; process-substitution source; `$`-prefixed/`/dev/stdin`/`/dev/tcp` source target (**MEDIUM**); dynamic `bash -c` |
| `R15_DYNAMIC_INDIRECTION` | MEDIUM | any `${!name}` indirection |
| `R16_CMD_SUBST_IN_META` | MEDIUM | backtick or `$(` in a raw element of `source*`/`depends*`/`makedepends*`/`optdepends*`/`checkdepends*` |
| `R17_BUILD_TIME_NETWORK` | LOW | a fetcher word, or `git clone`/`git fetch`, in any shell body except `pkgver` |
| `R18_HOMOGLYPH` | HIGH | any of 18 invisible/BiDi code points anywhere in the file |
| `R19_VALIDPGPKEYS_CHANGE` | MEDIUM / LOW | `validpgpkeys*` sets differ (order ignored); LOW if either side has `Unknown` |
| `R20_INSTALL_HOOK_CHANGE` | MEDIUM | `.install`/`.hook`/PKGBUILD-`install=`-named paths in the file delta |
| `R21_UNPINNED_VCS_SOURCE` | LOW | a `source*` entry with a `git+`/`hg+`/`svn+`/`bzr+` URL and no `tag=`/`commit=` fragment |
| `R22_CONDITIONAL_EXECUTION` | LOW | `$euid`/`$uid`/`$random`/`$srandom`, `/dev/urandom`, `shuf`, `id -u`, or `date` with `$(`/`` ` `` |
| `R23_NPM_DELIVERY` | MEDIUM | npm/bun × `install\|i\|ci\|add\|exec\|run\|x\|dlx`, or any `npx` |
| `R00_PKGBUILD_UNREADABLE` | HIGH | target `PKGBUILD` missing or empty → **returns** |
| `R00_PKGBUILD_UNPARSEABLE` | HIGH | `parse_pkgbuild` errors → **returns** |
| `R00_BASELINE_UNPARSEABLE` | HIGH | baseline `parse_pkgbuild` errors → pair rules skipped, rest continues |
| `R00_PKGBUILD_SCOPE` | LOW | always, last |

`R00_BASELINE_UNPARSEABLE` and `R00_BASELINE_UNREADABLE` are emitted from
[review](review.rs)'s side (`R00_BASELINE_UNREADABLE`, HIGH) and land in the
same HIGH band as the unparseable case.

## Tests

69 in `pkgbuild.rs`, plus 2 in `tests/pkgbuild_heuristics.rs`.

Tokenizer: `single_quotes_block_expansion`, `double_quotes_fold_vars`,
`ansi_c_escapes_fold`, `bad_ansi_c_escape_fails_closed`,
`ansi_c_hex_escapes_emit_bytes_not_latin1_chars`,
`ansi_c_non_utf8_bytes_survive_as_replacement_chars`,
`ansi_c_octal_above_one_byte_fails_closed`, `backslash_newline_joins_lines`,
`comments_strip_unquoted_only`, `arch_arrays_stay_separate`,
`multipass_fold_resolves_chain`, `undefined_var_is_unknown_not_empty`,
`indirection_is_unknown`, `command_subst_in_source_is_unknown`,
`backtick_in_depends_is_unknown`, `concat_split_folds_before_match`,
`func_bodies_captured_raw`, `byte_cap_is_exact`, `unterminated_quote_fails_closed`,
`unterminated_subst_fails_closed`, `suspicious_unicode_detected`,
`tokenize_roundtrip_parses`, `multibyte_inside_subst_does_not_panic`,
`non_ascii_index_becomes_assoc_without_panic`, `hash_inside_word_is_not_a_comment`,
`redirect_hash_is_a_comment`.

Per-rule quiet/fire pairs (the shape is the point): `r11_fires_on_bare_skip` /
`r11_quiet_with_signed_story` / `r11_quiet_for_vcs_without_keys`,
`r12_fires_on_host_swap_same_pkgver` / `r12_quiet_on_pkgver_bump`,
`r13_fires_on_curl_pipe_bash` / `r13_quiet_on_curl_to_tar`,
`r14_quiet_on_static_eval` / `r14_quiet_on_static_bash_c`,
`r19_fires_on_key_change` / `r19_ignores_key_order`,
`r22_fires_on_euid_and_random` / `r22_ignores_word_substrings`.

Corpus gate: `benign_corpus_scores_zero_above_info`,
`r23_is_medium_and_fires_on_all_three_true_positive_fixtures`.

Fuzz target: `fuzz/fuzz_targets/pkgbuild_tokenizer.rs`.