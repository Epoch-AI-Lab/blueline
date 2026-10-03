# CLI Surface

`src/cli.rs`, `src/main.rs`, `src/lib.rs`. Owns argument parsing, the
`--registry`/`--index` → four-base-URL derivation, and the exit-code contract
every surface inherits. Touching it changes what every other lane receives.

## Sub-features
- `Cli` / `Command` / `AgentAction` / `RecallAction` / `ShimAction`: clap types.
- `trim_pkg`: rejects empty specs and anything starting with `-`.
- `RegistryBases::from_flags` + `registry_base_for`: derives all four bases once.
- `Output::resolve(isatty)`: `Auto` is Text on a TTY, JSON otherwise.
- `run()` in `main.rs`: the single `anyhow` boundary; `{e:#}` prints the chain.

## How to get to it (user POV)
```sh
blueline --help                 # verified: review install ci mcp agent recall shim
blueline review express@4.21.2
blueline --ecosystem pypi review requests==2.31.0
blueline --registry http://127.0.0.1:8080 review demo@1.0.0
blueline --policy ./blueline.toml review demo@1.0.0
```

## Driving it
Global flags (available on every subcommand, verified via `--help`):
`--registry <REGISTRY>` (default `https://registry.npmjs.org`),
`--ecosystem <npm|cargo|pypi|aur>` (default `npm`),
`--index <INDEX>` (default `https://index.crates.io`), `--policy <POLICY>`.

```sh
blueline review <PKG> [--output auto|text|json] [-y|--yes]
blueline install <PKG> [NPM_ARGS]... [-y|--yes]
blueline ci [--base <ref>] [--lockfile <path>] [--format auto|text|markdown|json]
            [--fail-on low|medium|high|block] [--output-file <path>]
blueline mcp
blueline agent review <PKG>
blueline agent gate [--command <line>] [--format plain|claude|cursor]
blueline recall sync --url <URL>
blueline recall serve [--port <N>] --snapshot <PATH>
blueline recall export-candidates --out <PATH> [--limit <N>]
blueline shim install|uninstall [MANAGERS]... [--dir <PATH>]
```

Exit codes, all measured against `target/debug/blueline`:

| Situation | Code |
|---|---|
| clap parse error (unknown flag, `-x`) | **2** |
| Engine error: `git show` failure, missing lockfile, policy load failure | **1** |
| `ci` band reached `--fail-on` threshold | **1** |
| `review`/`install`/`agent review` BLOCK or non-LOW | **2** |
| `agent gate` deny (including *every* error path) | **2** |
| `agent gate` allow | **0** |
| `shim install` refusal (unknown manager, no real binary) | **1** |

## Gotchas
- **Exit 2 is overloaded.** clap's usage error and a BLOCK verdict both exit 2.
  Do not write a CI wrapper that treats `2` as "verdict blocked" without also
  checking that stdout carries a verdict document.
- **`--registry` moves three bases, not one.** `registry_base_for` routes
  `--registry` to PyPI and AUR when it differs from the npm default, and
  `--index` wins for PyPI when it is set. `--registry` against a mirror silently
  repoints `pip`/`yay` gate reviews too.
- **`install` takes trailing args verbatim** (`trailing_var_arg`,
  `allow_hyphen_values`). `blueline install pkg --force` forwards `--force`;
  `executor::validate_extra_args` is the only filter.
- **`--yes` fails closed upward, never down.** `--yes` approves *only*
  `VerdictBand::Low`; anything else prints a refusal and exits 2.
- `install` has **no `--output` flag** and always renders the text card, even
  under a pipe. Do not assume `--output json` parity with `review`.