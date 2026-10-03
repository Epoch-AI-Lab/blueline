# Shim

`src/shim.rs`. Generates fail-closed bash shims for eleven package managers
that route every invocation through `blueline agent gate` before the real
binary runs. Explicitly a **backstop for the interactive terminal**, never the
primary agent gate (hooks and MCP are).

## Sub-features
- `install` / `uninstall` / `default_dir`.
- `find_on_path(name, exclude_dir)` — real-binary resolution at install time.
- `is_executable_file` — ONE function with `cfg` branches inside.
- `assert_bakeable(path, what)` — refuse rather than escape.
- The generated bash template.
- `SHIM_MANAGERS`.

## How to get to it (user POV)
```sh
blueline shim install npm npx pnpm yarn bun bunx pip pip3 cargo yay paru
# installed npm shim: /root/.local/share/blueline/shims/npm (real: /usr/bin/npm)
# export PATH="/root/.local/share/blueline/shims:$PATH"
blueline shim install npm --dir ~/.local/bin
blueline shim uninstall npm npx

BLUELINE_REGISTRY=https://npm.internal blueline shim install pnpm
BLUELINE_INDEX=https://internal/crates blueline shim install cargo
BLUELINE_POLICY=/abs/blueline.toml blueline shim install pip
```

## Driving it
`SHIM_MANAGERS: [&str; 11] = ["npm","npx","pnpm","yarn","bun","bunx","pip","pip3","cargo","yay","paru"]`.
Anything else: `unknown shim manager \`{m}\`; known: …`, **exit 1**.

Default dir: `$BLUELINE_DATA_DIR/shims`, else `dirs::data_dir()/blueline/shims`.
Shims are written mode `0o755` (unix).

Per-manager registry override (each shim passes **only its own**):
- `npm npx pnpm yarn bun bunx` → `--registry "${BLUELINE_REGISTRY:-https://registry.npmjs.org}"`
- `cargo` → `--index "${BLUELINE_INDEX:-https://index.crates.io}"`
- `pip pip3 yay paru` → no registry override

All managers: `if [ -n "${BLUELINE_POLICY:-}" ]; then args+=(--policy "$BLUELINE_POLICY"); fi`.

## Gotchas
- **The template rebuilds the command with `printf %q` per argument** and execs
  the real binary with the **original `"$@"`, not the rebuilt `cmd`**. Only the
  gate sees the reconstructed line. `shim_installs_gates_and_uninstalls` asserts
  the original args reach the real binary.
- **`is_executable_file` is one function with `#[cfg(unix)]` / `#[cfg(not(unix))]`
  blocks inside, on purpose** (CHANGELOG: it was two functions and a mutation
  survivor). unix = `is_file() && mode & 0o111 != 0`. **non-unix =
  `path.is_file()` only** — no extension check, so on Windows any file in a PATH
  directory passes. Do not merge it with `diff.rs::check_is_executable`, whose
  Windows arm is a different 4-entry extension list.
- **`assert_bakeable` refuses on `"`, `$`, backtick, `\`** rather than escaping.
  Paths are baked into double-quoted bash assignments (`BLUELINE="…"`,
  `REAL="…"`), so a `$` would execute arbitrary code at *every* shim call.
  Applied to `current_exe()` and to each resolved real binary.
- **`find_on_path` skips the shim directory**, so a shim can never delegate to
  another shim or to itself. Not found ⇒
  `"no real \`{name}\` binary found on PATH (excluding the shim directory);
  refusing to write a shim that cannot exec anything"`.
- **The pip/pip3 shim pre-filter is LOOSER than the gate's own rule.** It exits
  2 on any pip flag except `-q`/`--quiet` (including harmless `--no-deps`),
  while `install_ref::pip_non_registry_shape` denies only the 8 `DANGEROUS`
  entries. A shimmed `pip install --no-deps x` never reaches `agent gate`.
  `shim_script_is_fail_closed_and_execs_real_binary` asserts the block is
  **absent** from the npm shim.
- **`BLUELINE_REGISTRY` is wired to *blueline*, not to the managers.** pnpm,
  yarn, and bun have independent registry configuration the shim does not
  touch, so a shimmed `pnpm install` can still fetch from a different registry
  than the one reviewed. This is an unmitigated coverage hole, not a bug fix.
- **The module doc lists ten managers and omits `pip3`** — a stale comment. The
  array has eleven and `all_shim_managers_cover_every_scanned_manager` pins it.
- **Documented bypasses** (README "What shims cannot stop"): absolute binary
  paths (`/usr/bin/npm`), `command npm`, `env -i`, direct
  `node .../npm-cli.js`, npx resolving from an existing `node_modules/.bin`, PATH
  reordering, repo-committable hook config, exported redirect env (disclosed, not
  denied), and unshimmed near-synonyms — `python -m pip` and `uv pip` have no
  shim.
- **`uninstall` on an absent shim succeeds** (`NotFound` is not an error), but a
  directory at the shim path *is* an error.
- **Shim install failures exit 1, not 2** (no hook host is involved) —
  `shim_install_refuses_unknown_manager_and_missing_real_binary` asserts it.