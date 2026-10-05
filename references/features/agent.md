# Agent Lane

`src/agent.rs`. `agent review` and `agent gate` — the agent-native, never
interactive enforcement path. Protects the property that **an agent can learn a
verdict but can never grant trust**, and that a hook decision is always an
explicit allow/deny, never an error the host can mistake for success.

## Sub-features
- `agent::run` — `agent review`, JSON verdict, exit 0/2.
- `agent::gate` / `agent::decide` / `emit_decision` — the hook binding.
- `read_hook_command_from` / `hook_stdin_limit` / `hook_stdin_too_large`.
- `detect_agent_identity` / `identity_for_audit`.
- `warn_on_ignored_env_policy`.
- `GateFormat { Plain, Claude, Cursor }`, `truncate_command`.

## How to get to it (user POV)
```sh
blueline agent review express@4.21.2                       # one line of JSON, exit 0 or 2
blueline agent gate --command 'npm install evil-pkg'       # exit 2 on deny
blueline agent gate --command 'npm install lodash' --format claude
echo '{"command":"npm install lodash"}' | blueline agent gate
echo '{"tool_input":{"command":"npm install lodash"}}' | blueline agent gate  # Claude Code PreToolUse
```

## Driving it
Exit codes, all measured:

| Outcome | Code |
|---|---|
| `agent review`, band `LOW` | `0` |
| `agent review`, band above `LOW` | `2` |
| `agent gate` allow | `0` |
| `agent gate` deny — **including every error path** | `2` |
| policy/store/spec failure in `agent review` | `1` |

`MAX_HOOK_STDIN_BYTES = 64 * 1024`; the reader takes `MAX + 1` and refuses
`len > 65536`. Exactly 65536 is accepted whole.

Decision JSON shapes:
- `claude`: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"|"deny","permissionDecisionReason":"<reason>"}}`
- `cursor`: `{"permission":"allow"|"deny","user_message":"<reason>"}`

Manager routing (`child_ecosystem`): `pip`→PyPI, `cargo`→crates.io,
`yay`/`paru`→AUR, everything else→npm.

Agent identity (env **names** only, never values), priority order:
`CLAUDECODE`/`CLAUDE_CODE_ENTRYPOINT` → `"claude-code"`;
`CURSOR_AGENT`/`CURSOR_TRACE_ID` → `"cursor"`;
`CODEX_SANDBOX`/`CODEX_SANDBOX_NETWORK_DISABLED` → `"codex"`; else
`"unknown-agent"`. Audit `decided_by` = `format!("agent:{}", id)`.

Redirect-capable env disclosure, prefixes (case-insensitive):
`npm_config_`, `pip_`, `cargo_` — reported by **name only**, sorted and deduped,
as a non-blocking note in the reason and the audit trail.

## Gotchas
- **Every gate error path denies with exit 2, never 1.** The whole `decide` call
  is wrapped so any error becomes
  `GateDecision { allow: false, reason: "blueline gate failed closed: …" }`.
  CHANGELOG is explicit about why: "hook hosts treat non-2 exits as non-blocking,
  so a hostile stdin payload sized to break the UTF-8 read, a corrupt store, or
  an unreadable policy previously let the command run ungated." Do not add a bare
  `bail!` that escapes to `main`.
- **`agent review` never mutates `known_clean`.** No `mark_clean`, no
  `record_verified`. The audit note is the literal
  `"agent mode; no interactive approval; known_clean untouched"`.
- **`Policy::load_for_agent` ignores `BLUELINE_POLICY`.** Use `--policy`. See
  the policy lane; this is a deliberate security boundary, not a bug.
- **Both stdin shapes are read by field, not by event.** It tries
  `value["command"]` (Cursor `beforeShellExecution`) then
  `value["tool_input"]["command"]` (Claude Code PreToolUse). `hook_event_name`
  is never inspected. Non-JSON input is treated as a raw command line.
- **The allow-with-no-refs case is deliberate:** `ls -la` (verified, exit 0)
  allows with reason "no named package-manager install found in the command; the
  manifest's dependencies are policed by `blueline ci`".
- **Redirect/override denials require a manager token on the line.**
  `PIP_INDEX_URL=https://evil.example echo hi` is *allowed*; add `pip install`
  and it denies.
- **Audit rows are written for every evaluated ref, allow or deny**, plus a
  final `agent_gate_summary` row. `recall export-candidates` filters on
  `action ∈ {hold, agent_gate, agent_review}` or `verdict ∈ {BLOCK, HIGH}`, so
  denials surface as curation candidates.
- **`truncate_command` boundary is exact:** 200 chars passes unchanged with no
  ellipsis; 201 chars becomes exactly 201 chars (200 + `…`, 203 bytes) after
  `sanitize_single_line`. Pinned by
  `command_truncation_boundary_is_exactly_200_chars`.
- **A bare absolute manager path is scanned, not denied** (`/usr/bin/npm`), but a
  *quoted or escaped* one is denied. That asymmetry is deliberate and pinned.
- `warn_on_ignored_env_policy`'s `bool` return is discarded (`let _ =`) at both
  call sites — a warning only.