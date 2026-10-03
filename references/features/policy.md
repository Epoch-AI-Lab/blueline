# Policy

`src/policy.rs`. D10 policy-as-code. Owns every `blueline.toml` key, its
default, its validation, and the two loaders whose difference is a security
boundary. Protects the property that **the agent entry points ignore ambient
`BLUELINE_POLICY`** — a hook inherits the repo as cwd and its environment.

## Sub-features
- `Policy` — nine tables, all `#[serde(default)]`.
- `load_with_env` / `load_or_default` / `load_for_agent`.
- `validate()` — six fail-closed checks.
- Matchers: `is_script_allowed`, `allows_unreviewed_baseline`,
  `is_package_blocked`, `is_maintainer_blocked`, `glob_match`.
- `parse_band_str` lives in `ci.rs`, not here.

## How to get to it (user POV)
```sh
blueline --policy ./blueline.toml review demo@1.0.0
BLUELINE_POLICY=/abs/path/blueline.toml blueline review demo@1.0.0
blueline review demo@1.0.0          # falls back to ./blueline.toml, ./.blueline.toml, config dir
```
```toml
[thresholds]
max_low_score = 19; max_medium_score = 49; block_score = 80
[policy]
require_provenance = false; block_unreviewed_scripts = true
allow_git_dependencies = false; check_advisories = true; fail_closed_network = false
[advisories]
block_on_malware = true; block_on_critical_cve = true
cache_ttl_hours_clean = 12; cache_ttl_hours_vulnerable = 1
[provenance]
require_provenance = false; require_signatures = false
allowed_builders = []; allowed_repositories = []
[[allowlist.packages]]
name = "demo"; ecosystem = "npm"; allowed_scripts = ["postinstall"]
allow_unreviewed_baseline = false
[blocklist]
packages = ["evil-*"]; maintainers = []
[ci]
fail_on = "high"; max_evaluations = 100; include_dev = true
[recursion]
max_depth = 3; max_child_reviews = 8; child_block_band = "HIGH"
[recall]
max_age_hours = 48; block_on_stale = false
```

## Driving it
Load order, exact priority (`load_with_env`):
1. explicit `--policy <path>` (env never consulted)
2. `BLUELINE_POLICY` — **only** in `load_or_default`
3. `./blueline.toml`
4. `./.blueline.toml`
5. `dirs::config_dir()/blueline/config.toml`
6. `Policy::default()`

**No parent-directory walk, no git-root discovery.** `MAX_POLICY_FILE_SIZE = 64 KiB`,
checked on `metadata.len()` (stat only — no re-check after read).

`validate()` rejects: `max_low > max_medium` (**equality allowed**),
`max_medium >= block_score` (**strict**), `block > 100`, `max_depth > 16`,
`max_child_reviews > 256`, `max_age_hours == 0 || > 24*365`.

Glob semantics (`glob_match`, hand-rolled, no library): `"*"` matches all;
`"*mid*"` → `contains(mid)`; `"pre*"` → `starts_with`; `"*suf"` → `ends_with`;
otherwise exact `==` (**case-sensitive**). No `?`, no `[...]`, no escaping.

## Gotchas
- **`load_for_agent` silently ignores `BLUELINE_POLICY`.** It is
  `load_with_env(custom_path, || None)`. The doc comment: *"a hook fires with
  the repository as its working directory and inherits ambient env, so honoring
  the variable would let any process that exports it steer the gate."* It
  eprints a warning (`warn_on_ignored_env_policy`) whose `bool` return is
  discarded at both call sites — a warning only, never a behavior change.
  Shims compensate by translating `BLUELINE_POLICY` into an explicit `--policy`.
  **MCP uses `load_or_default` and therefore DOES honor the env var** — the only
  surface that does.
- **No `deny_unknown_fields` anywhere.** A typo'd key (`block_on_malwares`)
  is silently dropped and the default applies. For `block_on_critical_cve`,
  `fail_closed_network`, `block_on_stale`, and `require_signatures` that
  default is the fail-open one.
- **Malformed or unreadable always fails closed.** A `BLUELINE_POLICY` that is
  set but unreadable is `Err`, not a fallback to defaults
  (`blueline_policy_env_scopes_policy_loading_fail_closed`).
- **`Policy::escalate_band` is the only score-to-band rule in the engine.** It
  takes the band the findings already earned as `current` and escalates on
  `thresholds` without ever downgrading it. Both scoring paths
  (`evaluate_with_trust`, `apply_extra_findings`) route through it.
- **`is_maintainer_blocked` is `#[allow(dead_code)]`** — exact trim+lowercase
  match, *not* glob. `blocklist.maintainers` has no production effect.
  `R10_MAINTAINER_TRANSITION` uses registry authorship, not this list.
- **Allowlist `name` and `allowed_scripts` are exact string equality, no glob.**
  `"@scope/*"` grants nothing for `allows_unreviewed_baseline`.
- **Absent `ecosystem` means "matches every ecosystem"** (`Option::is_none_or`).
  A single `packages = ["*"]` blocklists everything everywhere; nothing rejects
  an over-broad rule. An unknown ecosystem *string* in TOML does fail closed at
  parse time (`Ecosystem` is `rename_all = "lowercase"`).
- **`allow_unreviewed_baseline` zeroes risk.** R06/R07 become `Low` (0 points),
  so `--yes` auto-approves a first sighting. It does *not* suppress content
  heuristics — which is why the repo's own `blueline.toml` is 934 lines of
  per-crate rules.
- **Two `require_provenance` fields exist** (`[policy]` and `[provenance]`) and
  are OR'd in `heuristic.rs`. Setting only one is ambiguous; set both.
- **`allowed_builders`, `allowlist[].max_risk`, and `allowlist[].integrity` are
  dead knobs.** `max_risk` is only ever constructed as `None` in tests.
- **`recursion.child_block_band` compares with `>=`**, so lowering it to
  `MEDIUM` rolls up medium children (`child_block_band_policy_lowering_rolls_up_medium_children`).
- **`glob_match("**")` is `true`** (`contains("")`), and `a*b*c` degrades to an
  `a*` prefix match. Replacing this with `globset`/`glob` silently changes
  blocking semantics.
- **An env-probing test must re-exec the test binary.** `std::env::set_var` is
  `unsafe` and forbidden in edition 2024, so
  `env_policy_present_reads_process_environment` spawns itself with
  `--exact --ignored policy::tests::probe_env_policy_present_when_{set,unset}`.
  Name a probe exactly and mark it `#[ignore]`, or `cargo test` runs it and fails.