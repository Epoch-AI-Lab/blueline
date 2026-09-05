# Implementation Research: PKGBUILD heuristics (PR3)

## The Task
Static PKGBUILD review in `src/pkgbuild.rs` on Rust 2024 (pinned toolchain in
`rust-toolchain.toml`), no new dependencies. Tokenizer plus multi-pass
variable resolution, then rule matching for R11-R23. Same fold-then-match
shape as the JS engine. Fail closed on anything unresolvable. Bounded reads.
Fuzz target for the tokenizer. Benign corpus of 100+ real PKGBUILDs with zero
false positives per rule or the rule ships at INFO.

## 1. Common Gotchas
- Quoting changes everything. Single quotes block expansion, double quotes
  allow `$`, backtick and `$(...)` but block word splitting, `$'...'` does
  ANSI-C escapes. Source: GNU Bash manual, Quoting and Shell Expansions
  sections. Avoid by tokenizing quote state first, never regexing raw text.
- Expansion order is fixed: brace, tilde, parameter/variable, command
  substitution, arithmetic, word splitting, glob, quote removal. Source: GNU
  Bash manual 3.5. Avoid by folding in that order and treating unresolved
  expansions as unknown, which fails closed.
- Arrays are the metadata. `source=()`, `depends=()`, `sha256sums=()` carry
  the security signal, plus arch-suffixed variants like `source_x86_64`.
  Source: PKGBUILD(5) man page, ArchWiki PKGBUILD. Avoid by parsing array
  assignment as a first-class node, not as flat text.
- `pkgver()` in VCS packages normally runs `git describe` style command
  substitution. That is benign in that one spot and a flag everywhere else.
  Source: PKGBUILD(5) USING VCS SOURCES. Avoid by scoping R16 to
  `source`/`depends` arrays only.
- `SKIP` checksums are normal for VCS sources, malicious elsewhere. The
  signed-tag plus `validpgpkeys` story is what separates them. Source:
  ArchWiki integrity section. Avoid by pairing R11 with `validpgpkeys`
  presence instead of flagging bare `SKIP`.

## 2. Best Practices
- Hand-rolled lexer, no generator. `rustc_lexer` is hand-written for control
  over spans and errors. Source: Rust Compiler Development Guide, Lexing and
  parsing chapter. Why idiomatic here: bounded fail-closed errors beat
  generator output, and the night run forbids new deps anyway.
- Fold then match. Our JS engine folds `String.fromCharCode` to literals
  before heuristic matching. Same move applies: normalize quoting, fold
  plain assignments, then run string rules. Source: `src/heuristic.rs` in
  this repo.
- Bound everything like the SRCINFO parser. 1 MiB and 64k-line caps,
  reject duplicates and malformed lines. Source: `src/manifest.rs`
  `parse_aur_srcinfo`. Why: extracted PKGBUILD text is hostile input.
- Test against real corpus plus adversarial fixtures. ShellCheck's value is
  its test dir of real scripts plus edge cases. Source: ShellCheck repo
  layout. Why: R-rules need the 100-PKGBUILD zero-FP gate plus evasion
  fixtures (concat split, `$'...'` hiding, indirection).

## 3. Pitfalls & Language Quirks
- `${!var}` indirection and `$@`/`$*` extras expand one word to many words.
  Flag as R15 MEDIUM and stop resolving that value. Source: GNU Bash manual
  3.5 exception note.
- Backticks nest badly and hide in plain sight. Treat backtick substitution
  exactly like `$(...)` for R16/R17. Source: Bash Pitfalls list, command
  substitution notes.
- `source file` and `. file` execute local shell. Remote URL in that
  position is R14 HIGH. Local filename is still MEDIUM since content is
  untrusted. Fails closed either way.
- Homoglyphs survive tokenizing. Zero-width and BiDi chars hide `curl|sh`.
  Reuse the existing sanitizer logic before matching, same as the JS engine
  does. Source: this repo's diff scanner hardening in CHANGELOG 0.1.0.
- `pkgver`/`pkgrel`/`epoch` look numeric but accept VCS counters and epoch
  prefixes. Never assume numeric. Reuse `AurVersionInfo` grammar for
  comparisons, never `parse::<u64>`.

## 4. Differentiation
- Industry standard is ShellCheck (full POSIX analysis, warnings) or
  mvdan/sh and flash/mystsh (full AST in Go/Rust). Those answer "is this
  script correct". We answer "did this diff get dangerous", fail closed, no
  new deps, tuned for the AUR adopt-and-backdoor shape.
- Our approach: lossy fold plus rule matching over assignments, arrays, and
  function bodies, scoped to the R11-R23 list, with unknown constructs
  failing closed instead of parsing fully.
- Is the difference useful: yes for this wedge. Full AST crates are GPL
  (flash/mystsh) or new deps, both rejected by the night-run rulings. A
  smaller hand parser we own is auditable and keeps the binary small.

## Recommendation
Build `src/pkgbuild.rs` as tokenizer, assignment folder, array reader, then
one function per rule R11-R23 returning findings with band and evidence
string. Wire into the AUR review path only, gated by ecosystem. Ship the
tokenizer fuzz target first, then rules in three batches (checksum/source,
execution/network, metadata/indirection), each with unit fixtures plus the
shared 100-file benign corpus. Any rule that fires on the corpus stays INFO
until tuned.

## Sources
- PKGBUILD(5) man page, https://man.archlinux.org/man/PKGBUILD
- ArchWiki PKGBUILD, https://wiki.archlinux.org/title/PKGBUILD
- GNU Bash manual, Shell Expansions, https://www.gnu.org/software/bash/manual/html_node/Shell-Expansions.html
- GNU Bash manual, Quoting, https://www.gnu.org/software/bash/manual/html_node/Quoting.html
- ShellCheck repo, https://github.com/koalaman/shellcheck
- flash shell parser in Rust, https://github.com/raphamorim/flash
- Bash Pitfalls catalog, https://mywiki.wooledge.org/BashPitfalls
- This repo: src/heuristic.rs fold-then-match, src/manifest.rs SRCINFO bounds
- FOSS Linux AUR June 2026 incident writeup and yay v13 Lua hook shapes

## Adversarial Verification
- Sources verified: man page, ArchWiki, GNU Bash manual sections, and repo
  paths above all resolve and say what is claimed. No papers, no numbers to
  check.
- Logical coherence: VCS `pkgver()` exception and SKIP-plus-key pairing are
  the two spots a reviewer could call fail-open. Both are scoped narrowly
  above with reasoning.
- Omissions: full POSIX arithmetic and process substitution are out of scope
  by design. Anything using them that we cannot fold fails closed.
- Status: GREEN
