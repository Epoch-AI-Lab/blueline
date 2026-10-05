# Render

`src/render.rs`. The human face: review card, JSON output, and the sanitizers
every other surface calls before printing untrusted strings. Protects the
property that **untrusted text can never forge terminal output** — no escape
sequences, no line breaks, no BiDi reordering.

## Sub-features
- `render_text` / `render_json` / `render_text_to_string`.
- `sanitize_terminal` / `sanitize_for_terminal` / `sanitize_single_line`.
- `is_dangerous_unicode`.
- Card sections: header, Integrity, Ecosystem, Verdict, Delta, Install Scripts,
  trust-source rows, Recursive Reviews, Security Findings.
- Markdown cell escaping (used by `ci.rs`).

## How to get to it (user POV)
```sh
blueline review demo@1.0.0                          # card on a TTY
blueline review demo@1.0.0 | jq .                   # JSON when piped (Auto)
blueline review demo@1.0.0 --output text            # force the card
blueline review demo@1.0.0 --output json | jq .band
```

## Driving it
`Output::resolve(stdout_is_tty)` (in `cli.rs`): `Auto` is `Text` on a TTY and
`Json` otherwise. Explicit `--output` always wins.

Render caps, both disclosed rather than silent:
`MAX_RENDERED_CHILDREN = 8`, `MAX_RENDERED_CHILD_FINDINGS = 3`, overflowing to
`… and N more recursive review(s) (see JSON verdict)`.

Sanitizer behaviour:
- `sanitize_for_terminal` / `sanitize_terminal` — byte-identical; `sanitize_terminal`
  is a pure alias. Keeps `\n` and `\t`.
- `sanitize_single_line` — same, but maps `\n \r \t U+000B U+000C U+0085
  U+2028 U+2029` to a single space.
- Both strip `\x1b[`-CSI (through the first `0x40..=0x7E` byte),
  `\x1b]`/`P`/`_`/`^`/`X` OSC/DCS/APC/PM/SOS (through BEL or ESC-backslash),
  and a bare 2-byte `\x1bX`.
- `is_dangerous_unicode` (dropped silently): `U+061C`, `U+200B..=U+200F`,
  `U+202A..=U+202E`, `U+2066..=U+2069`, `U+FEFF`.

Findings tag column is fixed-width 10 chars, and **`Low` renders as `[INFO]`,
not `[LOW]`**.

## Gotchas
- **The escape-sequence parser is copy-pasted between the two sanitizers.**
  Fixing an introducer or terminator in one and not the other silently
  unbalances the property for `ci.rs`, `mcp.rs`, and `review.rs`, which all call
  in.
- **All five introducer chars `] P _ ^ X` must stay in the same match arm.**
  `sanitizes_dcs_apc_pm_sos_and_st_terminators` covers DCS+ST, APC+BEL, PM+ST,
  SOS+BEL, and the 2-byte form, and includes a payload with backslashes so a
  lone `\` must not terminate the sequence early.
- **OSC-8 hyperlinks are a named case.** `\x1b]8;;url\x07Click Me\x1b]8;;\x07`
  must yield exactly `"Click Me"` in both sanitizers.
- **BiDi controls are *deleted*, not replaced with a space.** The
  Trojan-Source test asserts `"legit\u{202E}txt.exe\u{202D}end"` →
  `"legittxt.exeend"`. A space substitution would break the `.exe` extension
  check downstream.
- **`U+2028`/`U+2029` belong in the space-mapping arm of
  `sanitize_single_line`, not the strip arm.**
- **`is_dangerous_unicode` is not the same list as heuristic's
  `is_ignorable_js_char`.** The render list omits `U+00AD`, `U+2060`, `U+180E`;
  the heuristic list omits `U+061C`. Do not unify them without re-running both
  suites.
- **JSON purity is a test, not a convention.** Under `OutputFormat::Json` the
  `Approved … (--yes)` line is suppressed and the prompt is gated; any new
  `println!` must sit behind the same guard or
  `regression_pure_json_output_with_yes_and_clean_exit` (which does
  `serde_json::from_str(stdout.trim())`) fails.
- **Integrity is always rendered Green.** There is no conditional color for a
  mismatch — a mismatched digest never reaches the card anyway.
- **`install` bypasses this lane's format selection entirely** (it always calls
  `render_text`, and has no `--output` flag).
- `R02_NEW_INSTALL_SCRIPT` exists only as a hard-coded `Finding` in a
  `render.rs` **test**; it is not a production rule id. Do not "fix" that
  string — it exercises the renderer, not the engine.