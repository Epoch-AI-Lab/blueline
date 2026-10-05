# Executor

`src/executor.rs`. Decision D11: on approve, install proceeds with
`npm install --ignore-scripts` — the package's lifecycle scripts are never
executed. Protects the property that **user-supplied extra args cannot
override network, security, or script-isolation flags**, and that no shell is
ever involved.

## Sub-features
- `build_install_command` / `install_with_ignore_scripts`.
- `validate_extra_args` + `normalize_key`.
- Two blocked-flag groups (29 network/security/config keys, 3 script-isolation).
- Environment blocklist scrub.

## How to get to it (user POV)
```sh
blueline install express@4.21.2 -y
blueline install express@4.21.2 --save-dev --save-exact
blueline install express@4.21.2 --registry https://evil.example   # refused, exit 1
blueline install express@4.21.2 --ignore-scripts=false            # refused, exit 1
blueline install express@4.21.2 -- --registry https://evil.example # refused
```

## Driving it
Constructed argv, pinned by `build_install_command_constructs_proper_args`:
```
["install", "--ignore-scripts", "--registry", <base>, "--", <pkg.trim()>]
```
with `extra_args` spliced between `--registry <base>` and `--`.

Interpreter selection: if `npm_execpath` is set and ends in `.js`/`.cjs`/`.mjs`,
run `Command::new(env "NODE" or "node")` with the execpath as argv[1]; otherwise
`Command::new(execpath)`; else `Command::new("npm")`.

Env scrub (a **blocklist** over `std::env::vars()`, lowercased per key):
removes every key starting `npm_config_` plus `node_options` and
`node_extra_ca_certs`. Nothing is allowlisted and nothing new is set; the
registry travels as the `--registry` flag.

Exit propagation: unix `exit(code)`, else `exit(128 + sig)`, else `exit(1)`;
non-unix `exit(code.unwrap_or(1))`.

## Gotchas
- **The module has no `unsafe`, no shell, and no captured output.** `Command` is
  invoked with an argv array — there is no shell-escaping surface. All three
  `Stdio`s are `inherit()`.
- **There is no "postinstall surfacing" here.** `--ignore-scripts` means
  lifecycle scripts never run at all; nothing is captured, parsed, or re-emitted.
  The `postinstall` *disclosure* lives in the heuristic (`R01_LIFECYCLE_SCRIPT_*`)
  and the install-reference lane, not here.
- **`normalize_key` is: `trim_start_matches('-')`, delete every `-` and `_`,
  ASCII-lowercase.** That is why `--no_ignore_scripts`, `-no-ignore-scripts`,
  `--ignoreScripts`, and `--ca_file` all collapse onto one key. Any new blocked
  flag inherits this normalization for free — and any *bypass* that uses an
  unusual separator is also caught.
- **Any extra arg not starting with `-` is rejected** as
  `forbidden positional argument`. That is what stops `express@4.21.2` or
  `http://evil.example/payload.tgz` from displacing the reviewed package.
- **Group 1 (29 keys, "cannot override network, security or configuration
  options")**: `userconfig, globalconfig, config, prefix, nodeoptions, loader,
  experimentalloader, import, scriptshell, shell, onloadscript,
  scriptsprependnodepath, registry, proxy, httpsproxy, httpproxy, noproxy,
  strictssl, nostrictssl, ca, cafile, cert, key, extracacerts, extracacert,
  initmodule, auth, authtoken`.
- **Group 2 (3 keys, "cannot override script isolation")**: `noignorescripts`,
  `ignorescripts`, `foregroundscripts`.
- **`--cache` and `--tag` are NOT in this blocklist**, even though the agent
  gate's scanner denies both. Two layers, two different lists — a gap, not an
  oversight, but do not assume one layer covers the other.
- **`validate_extra_args` runs twice**: once in `review::install` and again in
  `build_install_command`. Keep both; the second is the enforcement point.
- **The cargo/PyPI/AUR install refusals are in `review.rs`, not here**, each a
  `std::process::exit(2)` with its own rationale. This module only ever sees the
  npm lane.
- **Proptests cover the spelling space exhaustively**:
  `rejects_all_ignore_scripts_false_permutations` over
  `dashes in "[-]{1,3}" × sep in "[-_]" × val in "false|0|no|off" ×
  delimiter in "[= ]"` and `rejects_all_forbidden_flag_variations` over
  1–3 dashes × 14 flag spellings × `=value` or ` value`. Both use
  `failure_persistence: None`, so failures are not reproducible from disk.
- **The working directory is never set** — the install inherits blueline's cwd.