# Review card + prompt research

Phase 1 dependency research for Blueline: table rendering, ANSI color, the
interactive verdict prompt, real-world review-card precedents, JSON/TTY duality,
and Unicode/locale pitfalls. Goal of the report: a concrete, fail-closed,
YAGNI-sized dependency set and an exact interactive contract that never lets an
install proceed without an explicit human approve.

Context anchors: ARCHITECTURE.md pins "Review card: `comfy-table`" and
"Interactive prompt: `inquire` or custom `[a]/[h]/[d]`". The README wedge shows
the target card (two-column label/value list, a verdict band, then
`[a]pprove · [h]old · [d]iff`). Phase 0 already ships `OutputFormat`
(text/json), so the JSON degrade path is a Phase 0 seam, not new design.

---

## 1. Rust table rendering: comfy-table vs tabled vs hand-rolled ANSI

### comfy-table

- Current version **8.0.0**, published **2026-08-05**; 91.2M total downloads,
  1147 reverse dependents; repo github.com/Nukesor/comfy-table
  (https://crates.io/crates/comfy-table, https://github.com/Nukesor/comfy-table/releases).
- Maintenance: the author labels the project "finished" (feature-complete) but
  "still receives regular version bumps for its few dependencies", reviews and
  merges approved PRs, and releases on request
  (https://docs.rs/comfy-table/latest/comfy_table/). v7.2.x shipped perf fixes
  and a border-styling fix in 2026 (https://github.com/Nukesor/comfy-table/releases).
- v8.0.0 (2026-08-05) is an API break: the `TableComponent` enum, the `modifiers`
  module, `Table::apply_modifier`, and `Table::load_preset` are gone. Presets in
  `comfy_table::presets::*` are now `TableStyle` constants loaded via
  `Table::load_style`; style edits go through `Table::style_mut()`; rounded corners
  via `TableStyle::with_rounded_corners`. Truncation indicator is `…`. Formatting
  got ~34-70% faster (https://github.com/Nukesor/comfy-table/releases/tag/v8.0.0).
- Relevant features for a card:
  - `tty` feature (enabled by default) gives "automatic detection whether
    we're in a terminal environment. Only used when no explicit
    `Table::set_width` is provided" plus ANSI styling support
    (https://docs.rs/crate/comfy-table/latest).
  - Styling presets: `UTF8_FULL`, `UTF8_NO_BORDERS`, `ASCII_FULL`,
    `ASCII_NO_BORDERS`, `NOTHING`; rounded corners via
    `TableStyle::with_rounded_corners` (round-corner *modifiers* were removed in
    8.0.0) (https://docs.rs/comfy-table/latest/comfy_table/presets/index.html).
  - `ContentArrangement::Dynamic` wraps cell content to a target width; when no
    width is set and the program runs in a terminal, terminal size is used
    (https://docs.rs/comfy-table/latest/comfy_table/).
  - ANSI-aware width calculation switched to the `ansi-str` crate in 7.1.1 so
    embedded ANSI sequences (including OSC 8 hyperlinks) do not mis-measure
    column width (https://github.com/Nukesor/comfy-table/releases/tag/v7.1.1).
  - No `unsafe` in the library; a single `unsafe` sits in the crossterm
    dependency under the `tty` feature, which can be disabled
    (https://docs.rs/comfy-table/latest/comfy_table/).
- Feature flags (8.0.0): `tty` (default), `custom_styling` (off; pulls
  ansi-str + console; makes styling 30-50% slower), `reexport_crossterm`
  (https://docs.rs/crate/comfy-table/latest/features).

### tabled

- Current version **0.21.0**, published **2026-05-31**; 34.2M total downloads,
  770 dependents; repo github.com/zhiburt/tabled (https://crates.io/crates/tabled).
- Feature flags are default-heavy: `default = derive, macros, assert`; the
  derive macro and `assert` (snapshot-test helper) ship by default, and ANSI
  support requires opting into the `ansi` feature
  (https://lib.rs/crates/tabled/features). The README is explicit: to work
  correctly with colored input and avoid mis-measured string widths you "should
  add the `ansi` feature to your `Cargo.toml`"
  (https://github.com/zhiburt/tabled).
- Maintenance: 37 releases, 20 of them breaking; the changelog shows steady
  activity through 2026 (https://github.com/zhiburt/tabled/blob/master/CHANGELOG.md).
  Version cadence and churn is much higher than comfy-table's (e.g. 0.17.0
  Nov 2024, 0.18.0 Feb 2025, 0.19.0 Apr 2025, 0.20.0 Jun 2025, 0.21.0 May 2026).
- It is the more powerful library (derives, `Table::kv`, settings engine,
  multiple output formats) but that power is not needed for a two-column card.

### Hand-rolled ANSI

Zero dependencies, full control, and trivially small for a fixed two-column
label/value list. The costs are real: you re-implement display-width measurement
(the reason tabled has an `ansi` feature and comfy-table moved to `ansi-str`),
wrapping at terminal width, and alignment. For a card whose values are
package names, version strings, and file paths (potentially CJK filenames),
width bugs are easy to introduce and easy to miss.

### Verdict

For "a small security card with a couple of fixed columns and a colored verdict
line", **comfy-table is the right choice and stays the ARCHITECTURE.md
decision**. It is maintained, tiny in surface area, gives the exact
width/wrap behavior a narrow-terminal card needs, and its presets cover both
the README card look (borderless two-column via `UTF8_NO_BORDERS`/`NOTHING`)
and an ASCII fallback. tabled's derive machinery, default `assert`/`macros`
features, and opt-in `ansi` feature are unjustified weight (YAGNI). Hand-rolling
is tempting for zero deps but pushes width/wrap correctness onto us, which is
exactly the kind of subtle bug a security tool should not own. Terminal width:
rely on comfy-table's dynamic arrangement on a TTY; pin an explicit width when
stdout is piped.

---

## 2. Terminal color/ANSI: anstyle/anstream vs colored vs owo-colors

### The ecosystem standard: anstyle + anstream

- `anstream` (1.x) is a stdout/stderr wrapper that "adapts ANSI escape codes to
  the underlying Write's capabilities": strips colors for non-terminals,
  respects `NO_COLOR` and `CLICOLOR`, and on Windows falls back to the wincon
  API where `ENABLE_VIRTUAL_TERMINAL_PROCESSING` is unsupported
  (https://docs.rs/anstream/latest/anstream/struct.AutoStream.html).
- `anstyle-query` exposes the low-level checks: `no_color()`, `is_ci()`,
  `term_supports_color()`, `truecolor()`, `clicolor()`
  (https://docs.rs/anstyle-query/latest/anstyle_query/).
- This is where clap's maintainer (epage) moved the ecosystem: clap deferred to
  "ANSI escape codes as our external stable API", letting users style via
  owo-colors/color-print while `anstream` decides pass-through/strip/wincon
  (https://github.com/clap-rs/clap/pull/4765). Cargo itself migrated from
  termcolor to anstream, citing the decoupled styling API and faster stripping
  (https://github.com/rust-lang/cargo/issues/12627).

### owo-colors

- Current **4.3.0**, published **2026-02-22**; zero-allocation, dependency-free
  by default, MSRV 1.81 (https://crates.io/crates/owo-colors/4.3.0).
- With the `supports-colors` feature it "checks if it's a tty, checks if it's
  running in CI", and is "Overridable by `NO_COLOR`/`FORCE_COLOR` environment
  variables" plus a programmatic `set_override`; the `if_supports_color(...)`
  API gates styling per stream (https://github.com/owo-colors/owo-colors).
- It is a documented drop-in replacement for `colored`
  (https://docs.rs/crate/owo-colors/latest/source/README.md).

### colored

- Current **3.1.1**, published **2026-01-16**; MSRV 1.80; license **MPL-2.0**
  (rest of the stack is MIT/Apache); color gating via a `no-color` feature
  (https://crates.io/crates/colored). It is the most-downloaded of the three
  (211M) but the least interesting for us: global state, no zero-alloc claim,
  and owo-colors is explicitly the drop-in replacement.

### Verdict

The least-bloat option for "a few colored lines" is **owo-colors with the
`supports-colors` feature** (or none at all in v1, see section 3): it respects
NO_COLOR, detects non-TTY, detects CI, is zero-alloc, and matches how clap's
own output already behaves. `anstream` is not needed in Phase 1 because we
degrade to JSON on non-TTY (no human text to strip) and comfy-table + owo-colors
already gate styling on TTY/NO_COLOR; revisit anstream if a later phase ever
prints styled text to a pipe. `colored`'s MPL-2.0 license and global control
state are two small reasons not to reach for it when owo-colors exists.

---

## 3. Interactive prompts: inquire vs dialoguer vs hand-rolled readline

### inquire

- Current **0.9.4**, published **2026-02-24** (0.9.0 landed 2025-09-16), MIT,
  crossterm backend by default with termion/console as alternates
  (https://crates.io/crates/inquire, https://github.com/mikaelmello/inquire).
- Error model is explicit and terminal-aware:
  `InquireError::{NotTTY, OperationCanceled, OperationInterrupted, IO, ...}`.
  `NotTTY` fires "when enabling raw mode on the terminal in order to listen to
  input events is not possible"; `OperationInterrupted` is Ctrl+C and is
  returned only on the crossterm/termion backends (on console, Ctrl+C triggers
  SIGINT) (https://docs.rs/inquire/latest/inquire/error/enum.InquireError.html).
- Key bindings are standardized: Enter submits, Esc cancels, Ctrl+C interrupts;
  cancel and interrupt are deliberately different concepts
  (https://github.com/mikaelmello/inquire/blob/main/KEY_BINDINGS.md).
- 0.9.4 also fixed termion crashing on piped input and IO errors not being
  mapped to `NotTTY` (https://github.com/mikaelmello/inquire/blob/main/CHANGELOG.md).
- Gap for Blueline: every prompt type submits with Enter. There is no
  built-in single-keypress submit; `Select` is arrow-key + Enter. `Confirm`
  supports `with_default(false)` for an explicit "(y/N)" default-deny binary
  (https://docs.rs/inquire/latest/inquire/struct.Confirm.html), but that only
  covers approve/hold, not the three-way `[a]/[h]/[d]`.

### dialoguer

- Current **0.12.0**, published **2025-08-23** (0.11.0 was 2023-09-21, a ~2
  year gap), MIT, console-rs org, features `editor`, `password`, `completion`,
  `fuzzy-select`, `history` (https://crates.io/crates/dialoguer).
- `Confirm` renders `(y/N)`-style with a default and submits on Enter; input
  dialogs render on stderr (https://docs.rs/dialoguer/latest/dialoguer/struct.Input.html).
- Known sharp edges: Ctrl+C handling requires a workaround (`ctrlc` handler to
  suppress SIGINT, plus manual cursor restore) because dialoguer hides the
  cursor and does not reliably restore it on interrupt
  (https://github.com/console-rs/dialoguer/issues/294,
  https://github.com/console-rs/dialoguer/issues/22). Same single-key gap as
  inquire: selection and confirm both submit on Enter.

### Hand-rolled single-key readline

The `[a]pprove · [h]old · [d]iff` contract in the README is a single-keypress
verdict. Neither inquire nor dialoguer exposes that out of the box; both are
Enter-to-submit. A hand-rolled reader is ~60 lines: `enable_raw_mode`, loop
`crossterm::event::read()`, match `KeyCode`, restore mode in an RAII guard.
In raw mode, Ctrl+C arrives as a key event rather than a SIGINT, so the
handler is fully in our control. crossterm is already in the dependency tree
via comfy-table's `tty` feature, so this adds no new crate. This is the option
ARCHITECTURE.md explicitly allows ("`inquire` or custom `[a]/[h]/[d]`").

### Non-TTY stdin, Ctrl-C, EOF, and default-deny

- Non-TTY stdin (piped/CI): `std::io::IsTerminal::is_terminal()` (stable in
  std since Rust 1.70) is the gate (https://doc.rust-lang.org/std/io/trait.IsTerminal.html).
  inquire surfaces this as `NotTTY`; the correct fail-closed behavior is: do
  not prompt at all, emit the JSON verdict with a denied decision, exit non-zero.
- Ctrl+C mid-review: must not silently allow. npm's own npx aborts the install
  prompt with `npm ERR! canceled` (https://stackoverflow.com/questions/79679498),
  npq aborts with a `USER_ABORT` exit code 1 (https://github.com/lirantal/npq/blob/main/docs/feature/auto-continue.md),
  and sudo/gh simply die without running the action. The invariant: install
  proceeds on exactly one input, the explicit approve key.
- EOF (Ctrl+D) on a TTY: treat as a canceled review, deny, no install.
- Default-deny: the prompt has no default at all. Bare Enter and unknown keys
  repeat the prompt; any timeout (if one is ever added) must resolve to deny,
  never to allow. npq's 15-second countdown that auto-continues on warnings is
  the anti-pattern to invert (see section 4).

### Verdict

**Hand-rolled single-key prompt on crossterm**, gated by
`stdin().is_terminal()` and `TERM != dumb`. It is the only option that
implements the exact three-way single-key card, gives us total ownership of
Ctrl+C/Ctrl+D/non-TTY fail-closed semantics, and adds no new dependency
(crossterm already arrives via comfy-table). inquire is the runner-up but would
force Enter-to-submit or two stacked prompts, and it is a second raw-mode
owner; dialoguer additionally drags in the Ctrl+C cursor-restore workaround
hobby. Reserve inquire as the Phase 3+ answer if MCP/ci ever needs richer
inputs.

---

## 4. Real-world precedent for review-card CLIs

### npm audit and audit-ci (passive, threshold-gated)

`npm audit` reports after install, exits non-zero by default when any
vulnerability is found, and `--audit-level` tunes the failure threshold; it is
the CI-era default (https://docs.npmjs.com/cli/v10/commands/npm-audit/).
`audit-ci` wraps it for CI with threshold flags (`--high`), an allowlist, and
`--output-format text|json`; its `--pass-enoaudit` defaults to **false** "to
reduce the risk of merging in a vulnerable package", an explicit fail-closed
default (https://www.npmjs.com/package/audit-ci). Both are non-interactive:
they gate builds, they do not sit in front of a human at an install line.

### npx (the dangerous precedent to invert)

`npx` prompts `Need to install the following packages: ... Ok to proceed? (y)`
with an uppercase Y default, and when stdin is not a TTY or CI is detected it
assumes `--yes` (skips the prompt and installs, printing a warning)
(https://github.com/npm/cli/issues/1935). For a supply-chain gate this is
exactly backwards: default-allow plus auto-allow when unattended. Blueline must
be the mirror image: default-deny, and piped/unattended must refuse rather than
assume yes.

### npq (closest analogue, with a cautionary default)

npq audits a package pre-install and prompts before handing off to npm. Its
default, however, is a 15-second countdown that auto-continues the install when
only warnings are found; `NPQ_DISABLE_AUTO_CONTINUE` or
`--disable-auto-continue` replaces it with an explicit `(y/N)` prompt. Ctrl+C
during the countdown aborts cleanly with exit code 1 (USER_ABORT). Hard
failures (errors, provenance regressions) prompt with a default "no"
(https://github.com/lirantal/npq/blob/main/docs/feature/auto-continue.md,
https://github.com/lirantal/npq/blob/main/docs/feature/provenance.md).
Independent writeups describe the interactive flow as "not a hands-off CI gate"
and note there is no documented flag that auto-fails every flagged package
(https://blog.openreplay.com/npm-package-security-checks-npq/). Lessons for
Blueline: (1) the countdown-to-allow default is a trust-compromise, invert it;
(2) Ctrl+C cleanup with exit code 1 and no stack trace is the right UX;
(3) prompts are for humans, CI needs a different (refusal/JSON) path.

### socket (the fail-closed flag pattern)

Socket's CLI wraps npm/pnpm/yarn and prompts only for packages it alerts on;
its commands take `--interactive` and `--no-interactive` where the non-flag
default "defaults them to cancel/no", and most commands support `--json` and
`--markdown` so results can be piped (https://docs.socket.dev/docs/socket-scan,
https://docs.socket.dev/docs/socket-cli). `socket scan report` returns a
`{healthy: bool}` verdict that the exit code reflects. This is the cleanest
existing template for "prompt on a TTY, deny-by-default without one".

### gh (the no-prompt error pattern)

gh "already does the right thing in non-TTY contexts: it skips the pager,
strips ANSI color, and errors out fast with a helpful message instead of
prompting (e.g. `must provide --title and --body when not running
interactively`)" (https://github.com/cli/cli/blob/c14cbaa2/skills/gh/SKILL.md).
It honors `NO_COLOR`/`CLICOLOR_FORCE`, and `GH_FORCE_TTY` exists as an explicit
opt-out for harnesses that want TTY-style rendering when piped
(https://cli.github.com/manual/gh_help_environment).

### git (the TERM=dumb color precedent)

git decides "is terminal dumb" by checking `$TERM != dumb` before deciding on
ANSI color (https://github.com/rails/thor/pull/710 references
https://github.com/git/git/blob/0d0ac3826a3bbb9247e39e12623bbcfdd722f24c/editor.c#L11-L15).
That same check is the right guard for box-drawing characters (section 6).

### What good ones do that bad ones don't

Good review gates: prompt only when a human is present (stdin TTY); default to
deny/cancel/no; make the bypass flag explicit and opinionated; emit a stable
machine-readable verdict (JSON) with an exit code that reflects it; make Ctrl+C
a clean abort with no side effects. Bad ones: default-allow prompts (npx's
`(y)`, npq's countdown) and hang-forever-on-pipe behavior that blocks CI or
auto-resolves to the permissive answer.

---

## 5. JSON + TTY duality

The CLI Spec makes this a first-class principle: "Emit JSON when piped,
human-friendly output in a terminal, support `--output` for format selection"
and "text output MUST carry no ANSI or color codes when stdout is not a TTY"
(https://clispec.dev/). Its recommended Rust pattern is an `OutputConfig` with
`--output auto|json|...` where `auto` resolves via `stdout().is_terminal()`,
and an explicit flag always wins over TTY detection
(https://clispec.dev/guide/rust/). Principle 4 adds the refusal rule that
matters most here: a command that would prompt on a TTY must, without a TTY,
"refuse and exit non-zero with a structured error naming the bypass flag. It
must never proceed silently" (https://clispec.dev/). clig.dev states the same
interactivity rule: only prompt if stdin is a TTY; otherwise error and tell the
user which flag to pass (https://clig.dev/).

Precedents in the ecosystem: `npm audit --json` emits one JSON object and its
text form exits non-zero on findings (https://docs.npmjs.com/cli/v10/commands/npm-audit/);
gh's `--json field,...` produces clean JSON with no ANSI when piped, and
`--jq`/`--template` shape it (https://cli.github.com/manual/gh_help_formatting);
socket's `--json` is "a raw dump you can pipe into jq"
(https://docs.socket.dev/docs/socket-cli).

For Blueline this is mostly a Phase 0 seam: `OutputFormat` already exists and
`Verdict` is one JSON schema that feeds CLI card, CI comment, and MCP
(ARCHITECTURE.md D7). The Phase 1 contract is:

- `--output auto` (default): TTY on stdin + stdout -> human card on stdout and
  interactive verdict on stderr; otherwise -> single JSON verdict object on
  stdout.
- `--output json`: always JSON, never prompt, regardless of TTY.
- `--output text`: force human card; if stdin is not a TTY, still no prompt,
  emit the card (plain, no ANSI) and exit with a denied decision.
- The JSON object carries the verdict, the decision (deny unless approved on a
  TTY), and the reason; exit code mirrors the decision. Piped use is deny by
  construction, which satisfies "machine-consumable verdicts in CI" without a
  permissive default.

---

## 6. Locale/Unicode pitfalls: box-drawing on Windows, dumb terminals, embedded terminals

- `TERM=dumb`: treat as non-interactive. Git's `is_terminal`-style color check
  keys off `TERM != dumb` (git editor.c, cited in
  https://github.com/rails/thor/pull/710). GitHub's TUI foundations go further:
  "Terminals reporting `TERM=dumb` should also be treated as non-interactive"
  and, for non-TTY environments, "default to no color, don't assume terminal
  width, and provide ASCII fallbacks for Unicode icons"
  (https://github.com/github/TUIKit/blob/main/docs/foundations.md).
- Windows: pre-Windows-10 conhost had almost no ANSI/VT support; Windows 10
  added comprehensive VT support to conhost and Windows Terminal, but the old
  GDI-based console text renderer could not font-fallback, so exotic glyphs
  rendered poorly (https://devblogs.microsoft.com/commandline/windows-command-line-inside-the-windows-console/).
  In practice modern Windows 10+ conhost and Windows Terminal render UTF-8 box
  drawing fine (Consolas/Cascadia have the glyphs), but the historical surface
  is exactly why a plain-ASCII preset must exist and be reachable.
- Terminal detection is genuinely unreliable; `$TERM` is "a compatibility hint,
  not a capability oracle", and the recommended stance is layered detection
  with graceful degradation rather than trusting any single signal
  (https://terminfo.dev/fundamentals/term-detection).
- Embedded terminals (VS Code integrated terminal, GitHub Codespaces web
  terminal) are real PTYs that fully support VT sequences and box drawing; they
  present as ordinary TTYs with `TERM=xterm-256color`-style values, so they need
  no special-casing beyond the standard is_terminal + TERM-dumb checks. They are
  narrow (often < 100 cols), which comfy-table's dynamic wrapping handles.
- Safe subset for v1: use UTF-8 box drawing only when stdout is a TTY and
  `TERM != dumb`; otherwise fall back to comfy-table's `ASCII_*` preset. The
  README card is effectively borderless (two-column label/value), so the
  simplest robust choice is `UTF8_NO_BORDERS`/`ASCII_NO_BORDERS` (or `NOTHING`)
  rather than full box drawing; reserve `UTF8_FULL` for the diff/verdict
  framing later. Since non-TTY degrades to JSON, "dumb" only matters for a
  TTY that lacks color, where ASCII preset + no-color styling is the fallback.

---

## Recommendations for Blueline

### Dependencies (the whole Phase 1 addition)

- **`comfy-table` 8.0.0** (default features; `tty` is fine, we need it for
  width detection). Two columns (label, value), `ContentArrangement::Dynamic`,
  preset chosen at runtime via `Table::load_style`: `UTF8_NO_BORDERS` on a
  color-capable TTY, `ASCII_NO_BORDERS` otherwise. Do not enable `custom_styling`;
  we will not embed our own ANSI inside cells in v1. Explicit width when stdout
  is piped; auto width on TTY. (https://crates.io/crates/comfy-table)
- **`owo-colors` 4.3.0 with `supports-colors`** for the verdict band line and
  the prompt hint. Zero-alloc, honors NO_COLOR/CI/non-TTY, drop-in compatible
  if we later swap. Keep cells uncolored; color only the verdict text outside
  the table. (https://crates.io/crates/owo-colors/4.3.0)
- **No prompt crate.** Hand-rolled single-key reader on **crossterm** (already
  in the tree via comfy-table's `tty` feature): `enable_raw_mode` in an RAII
  guard, loop on `event::read()`, match key. Do not add `inquire` or
  `dialoguer` in Phase 1; both are Enter-to-submit and dialoguer adds a
  Ctrl+C cursor-restore workaround (https://github.com/console-rs/dialoguer/issues/294).
  ARCHITECTURE.md explicitly permits "custom `[a]/[h]/[d]`".
- **std only** for capability checks: `std::io::IsTerminal` (stable 1.70) for
  stdin/stdout gating, and `TERM` env for the dumb check. No new crate for
  `NO_COLOR`: `supports-color` (via owo-colors) reads it.

### Interactive contract (exact)

Preconditions for entering the prompt: `stdin.is_terminal() == true` AND
`TERM != "dumb"`. The card prints to stdout; the prompt renders on stderr
(dialoguer precedent, and keeps stdout clean for JSON).

- `a` -> APPROVE. The only path that returns a positive verdict, and therefore
  the only path that can reach `npm install --ignore-scripts`.
- `h` -> HOLD. Abort with a non-zero exit, persist the decision to the
  `known_clean` store as a hold override if the store supports it in Phase 1.
- `d` -> DIFF. Open the file diff view for the current delta, then return to
  the same prompt (no decision taken by viewing).
- Any other key (including bare Enter): ignore, re-render the hint line, stay
  in the loop. No default.
- `Ctrl+C` (raw-mode key event): restore terminal, exit non-zero (fail closed,
  no install), matching npq's clean USER_ABORT UX.
- `Ctrl+D` / EOF on stdin: same as cancel, deny, exit non-zero.
- Timeout: none in Phase 1. If one is ever added, it must resolve to deny.
- `TERM=dumb` or non-TTY stdin: do not prompt. `--output auto` -> JSON verdict,
  decision deny, exit non-zero. Never auto-approve (the npx/npq anti-pattern).

### Card layout that survives narrow + dumb terminals

Keep the README wedge shape, rendered as a borderless two-column comfy-table
plus a standalone verdict line:

```
BLUELINE REVIEW CARD

package:    express
version:    4.21.2
previous:   4.21.1 (last known-clean)

delta:      +3 files, -1 file
size:       +1.2 KB
author:     expressjs (verified)
permissions: no new binaries
install script: none

changed:    lib/router/index.js (3 lines)
            lib/router/layer.js (1 line, comment only)
            package.json (version bump)

verdict:    LOW RISK

[a]pprove · [h]old · [d]iff
```

Rules: label column fixed width ~12, value column dynamic and wrapping; set an
explicit table width (min(table size, ~100)) so no line exceeds 80 columns;
values that exceed the width wrap rather than truncate (never hide a security
signal); color only the verdict band via `if_supports_color`, nothing else;
UTF-8 box drawing avoided entirely in v1 (borderless preset), ASCII fallback
is therefore automatic and dumb-terminal safe; CJK package/file names measure
correctly because comfy-table uses ansi-str/unicode-width.

### YAGNI check

This is the smallest thing that works: two new crates (comfy-table already
decided by ARCHITECTURE.md, owo-colors), no prompt library, no ANSI stream
adapter, no custom width code. Everything else (tabled's derives, anstream,
inquire/dialoguer, JSON-on-stdout coloring, diff view, CI command) is Phase 3+
or explicitly deferred.

---

## Sources

- comfy-table 8.0.0 (2026-08-05): https://crates.io/crates/comfy-table,
  https://github.com/Nukesor/comfy-table/releases,
  https://docs.rs/comfy-table/latest/comfy_table/,
  https://docs.rs/comfy-table/latest/comfy_table/presets/index.html,
  https://docs.rs/crate/comfy-table/latest/features,
  https://github.com/Nukesor/comfy-table/releases/tag/v7.1.1
- tabled 0.21.0 (2026-05-31): https://crates.io/crates/tabled,
  https://lib.rs/crates/tabled/features, https://github.com/zhiburt/tabled,
  https://github.com/zhiburt/tabled/blob/master/CHANGELOG.md
- anstream/anstyle-query: https://docs.rs/anstream/latest/anstream/struct.AutoStream.html,
  https://docs.rs/anstyle-query/latest/anstyle_query/,
  clap migration: https://github.com/clap-rs/clap/pull/4765,
  cargo migration: https://github.com/rust-lang/cargo/issues/12627
- owo-colors 4.3.0 (2026-02-22): https://crates.io/crates/owo-colors/4.3.0,
  https://github.com/owo-colors/owo-colors
- colored 3.1.1 (2026-01-16): https://crates.io/crates/colored
- inquire 0.9.4 (2026-02-24): https://crates.io/crates/inquire,
  https://docs.rs/inquire/latest/inquire/error/enum.InquireError.html,
  https://github.com/mikaelmello/inquire/blob/main/KEY_BINDINGS.md,
  https://github.com/mikaelmello/inquire/blob/main/CHANGELOG.md,
  https://docs.rs/inquire/latest/inquire/struct.Confirm.html
- dialoguer 0.12.0 (2025-08-23): https://crates.io/crates/dialoguer,
  https://github.com/console-rs/dialoguer/issues/294,
  https://github.com/console-rs/dialoguer/issues/22
- std::io::IsTerminal: https://doc.rust-lang.org/std/io/trait.IsTerminal.html
- CLI Spec: https://clispec.dev/, https://clispec.dev/guide/rust/
- clig.dev (12-factor CLI): https://clig.dev/
- npm audit: https://docs.npmjs.com/cli/v10/commands/npm-audit/
- audit-ci: https://www.npmjs.com/package/audit-ci
- npx non-TTY behavior: https://github.com/npm/cli/issues/1935,
  https://github.com/nuke-build/nuke/issues/1353
- npq: https://github.com/lirantal/npq/blob/main/docs/feature/auto-continue.md,
  https://github.com/lirantal/npq/blob/main/docs/feature/provenance.md,
  https://blog.openreplay.com/npm-package-security-checks-npq/
- socket: https://docs.socket.dev/docs/socket-cli,
  https://docs.socket.dev/docs/socket-scan
- gh: https://cli.github.com/manual/gh_help_environment,
  https://cli.github.com/manual/gh_help_formatting,
  https://github.com/cli/cli/blob/c14cbaa2/skills/gh/SKILL.md
- git TERM=dumb check: https://github.com/rails/thor/pull/710,
  https://github.com/git/git/blob/0d0ac3826a3bbb9247e39e12623bbcfdd722f24c/editor.c#L11-L15
- Windows console/VT history: https://devblogs.microsoft.com/commandline/windows-command-line-inside-the-windows-console/
- Terminal detection reality: https://terminfo.dev/fundamentals/term-detection
- TUIKit TTY/non-interactive guidance: https://github.com/github/TUIKit/blob/main/docs/foundations.md

---

## Adversarial self-check

- **Is skipping inquire defensible given ARCHITECTURE.md?** Yes: it says
  "`inquire` or custom `[a]/[h]/[d]`", and no prompt crate implements
  single-keypress submission. The hand-rolled reader is the only way to honor
  the README's exact contract, and crossterm is already present via
  comfy-table. Flagged as a deviation from "add inquire" in case the team
  prefers a stock library and accepts Enter-to-submit.
- **Could a hand-rolled raw-mode loop leave the terminal broken on panic?**
  Mitigated by an RAII guard that restores mode on drop; the guard is the
  standard pattern, and panic-during-prompt leaves the process aborting before
  any install path, which is fail-closed. Should be covered by a unit test
  using a PTY harness in Phase 1.
- **Comfy-table styling vs NO_COLOR:** comfy-table's cell styling keys off its
  own TTY detection and does not read NO_COLOR. Mitigation: v1 colors no cells,
  only the standalone verdict line via owo-colors `if_supports_color`, which
  honors NO_COLOR. If cell highlighting is added later it must be gated by the
  same decision or routed through anstream.
- **Dumb terminal + real TTY:** a `TERM=dumb` TTY still has a working key
  channel; we choose to refuse to prompt anyway, matching git and TUIKit. This
  errs toward "no install", which is the correct side to err on.
- **Ctrl+C semantics in raw mode:** crossterm in raw mode surfaces Ctrl+C as a
  key event, so the default SIGINT handler is bypassed while raw; the RAII
  guard restores cooked mode on the way out. The critical invariant holds by
  construction: no code path reaches `npm install --ignore-scripts` except an
  explicit `a` keypress.
- **Piped stdout but interactive stdin:** the card is plain (no ANSI) when
  stdout is not a TTY, per CLI Spec Principle 1, while the prompt on stderr
  still works because stdin is a TTY. JSON verdict is chosen by stdin TTY
  state, not stdout, so `blueline review pkg | tee log` stays interactive and
  human-decidable.
- **Version/license drift risk:** all cited versions are current as of
  2026-08-13; tabled's 0.20.0 docs.rs page is stale (0.21.0 released a month
  later) and was not relied on. colored is MPL-2.0, avoided. comfy-table
  declares itself "finished", meaning low feature growth but also low churn;
  its dependency bumps continue (7.2.x in 2026).
- **Do any findings overfit to popularity over fitness?** The tabled pick is
  rejected on fitness (default derive/assert weight, opt-in ansi, breaking
  cadence), not on downloads. owo-colors is picked over anstream on YAGNI for
  the exact "few colored lines" case; anstream remains the documented upgrade
  path if Phase 3 prints styled text to pipes.
