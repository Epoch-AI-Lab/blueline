# Node shim research: zero-scripts optional-deps layout for `@blueline/cli`, a `spawnSync` launcher with verbatim exit-code passthrough, and `npm_execpath` delegation for the `--ignore-scripts` install

Research for Phase 1, the distribution wedge: the Node shim that makes `blueline` runnable via npx while keeping the tool's core guarantee that lifecycle scripts never execute. `ARCHITECTURE.md` §1 specifies an npm package `@blueline/cli` whose `bin` is a JS launcher that resolves platform-specific optional dependencies (`@blueline/binary-{linux,darwin,win}-{x64,arm64}`), with Node providing only npx ergonomics and PATH registration; the Rust binary stays directly installable via `cargo install`. The hard constraint is that Blueline wraps `npm install --ignore-scripts`, so any install-time download in the shim's own package would defeat the tool's purpose: a postinstall downloader is a disqualifying footgun. The precedent set is esbuild's PR #1621, which moved esbuild off a postinstall downloader and onto `optionalDependencies` platform packages, and the shim design below follows esbuild, oxlint, rolldown, biome, and tailwindcss to that exact shape.

## 1. Per-platform optional dependencies: exact-pinned platform packages and the `--ignore-scripts` constraint

The ecosystem-wide pattern for shipping native binaries through npm is now platform packages listed in the meta package's `optionalDependencies`, resolved at runtime, with no install-time download:

- **esbuild.** PR #1621 moved esbuild off the old postinstall downloader onto `optionalDependencies`. `esbuild@0.25.0`'s package.json pins every platform package to the exact version (`"@esbuild/linux-x64": "0.25.0"`) and still carries a `postinstall: node install.js`, but that script is now a shim-optimization/version-check plus a fallback for the `--no-optional` case, not the binary delivery mechanism. The esbuild docs state the install works with `--ignore-scripts` alone and only breaks when `--ignore-scripts` is combined with `--no-optional`. The platform packages themselves (`@esbuild/darwin-arm64`, etc.) carry `os`, `cpu`, `engines`, and `preferUnplugged` fields and no `bin` field. [esbuild PR #1621](https://github.com/evanw/esbuild/pull/1621), [esbuild@0.25.0 package.json](https://unpkg.com/esbuild@0.25.0/package.json), [esbuild getting started](https://esbuild.github.io/getting-started/), [node-install.ts](https://github.com/evanw/esbuild/blob/main/lib/npm/node-install.ts).
- **oxlint.** `oxlint@1.45.0` has no `scripts` field at all, only `optionalDependencies` on `@oxlint/binding-*`. This is the zero-scripts ideal for Blueline: NAPI-RS generated the binding packages, and there is nothing to run at install time. [oxlint@1.45.0 package.json](https://unpkg.com/oxlint@1.45.0/package.json).
- **rolldown.** PR #654 hard-coded `@rolldown/binding-*` into `optionalDependencies` rather than generating ranges, exactly the exact-pin discipline Blueline should copy. [rolldown PR #654](https://github.com/rolldown/rolldown/pull/654).
- **biome.** The `@biomejs/biome` meta package lists 8 `@biomejs/cli-*` optional deps and resolves the binary at runtime from them; no download at install. [@biomejs/biome launcher `bin/biome`](https://github.com/biomejs/biome/blob/main/packages/%40biomejs/biome/bin/biome), [generate-bin-path.ts](https://github.com/biomejs/biome/blob/main/packages/%40biomejs/biome/src/generate-bin-path.ts).
- **tailwindcss.** The oxide bindings (`@tailwindcss/oxide-*`) load via `@neon-rs/load`. Tailwind PR #17929 added a postinstall fallback that runs only when the binding is missing, as a workaround for the npm optional-deps bug (npm/cli#4828); it skips itself on `publish` user-agents and local builds. [tailwind PR #17929](https://github.com/tailwindlabs/tailwindcss/pull/17929), [npm/cli issue #4828](https://github.com/npm/cli/issues/4828).

The takeaway for Blueline: the `optionalDependencies` layout works under `--ignore-scripts`, and every implementation with a postinstall uses it as a repair/optimization shim, never as the delivery mechanism. Tailwind's fallback exists only to work around npm/cli#4828 (see section 3) and is exactly the kind of code Blueline must not copy, because a postinstall in Blueline's own package is the one attack surface the tool exists to review. Zero-scripts is both sufficient and the only defensible choice.

## 2. npx ergonomics: scoped-package bin resolution, arg pass-through, and the `@blueline/cli` naming consequence

npx's contract with a package's `bin` field is the whole ergonomic story:

- **Scoped packages resolve their `bin`.** The npx v10 docs demonstrate `npx @npmcli/arborist --version`, which is a scoped package with a single bin entry. For packages with a single `bin`, or a `bin` matching the unscoped package name, npm's bin-guessing heuristic also works (documented in the npm-exec v8 docs). [npx v10 docs](https://docs.npmjs.com/cli/v10/commands/npx), [npm-exec v8 docs](https://docs.npmjs.com/cli/v8/commands/npm-exec).
- **Positional args after the package name pass through untouched**, and the package is cached in npx's `_npx` folder rather than a global install, so there is no global `blueline` binary to conflict with a `cargo install`ed one. npx prompts before downloading unless `--yes`/`--no` is passed, which is fine for a review desk (an explicit confirmation to download a security tool is a feature). [npx v10 docs](https://docs.npmjs.com/cli/v10/commands/npx).
- **`npx blueline` would resolve a package literally named `blueline`**, so the ergonomic command is `npx @blueline/cli install ...`, not `npx blueline`. Users who want bare `blueline` should install the CLI once (`npm i -g @blueline/cli`) or `cargo install blueline`; npx stays the no-install path.
- **Empirical validation:** oxc's own release smoke test runs `npx oxfmt@<version> ./test.js` and `npx oxlint@<version> ./test.js` across windows, ubuntu, alpine (musl) and macOS runners, which proves the optional-deps + npx pattern end to end on the exact matrix Blueline needs. [oxc release_apps.yml](https://github.com/oxc-project/oxc/blob/main/.github/workflows/release_apps.yml).

For the review flow itself, npm's programmatic API was removed in npm v8.0.0, and npm's own guidance is to treat the CLI as an opaque program and drive it from a child process instead ([npm/npm#11130](https://github.com/npm/npm/pull/11130)). That is what Blueline must do, and npm exposes two environment variables that make the delegation robust: `npm_execpath` (the npm that is currently running, including when invoked via npx) and `npm_config_user_agent`, both set for scripts and npm exec. [npm/npm#11130](https://github.com/npm/npm/pull/11130), [npm scripts docs](https://docs.npmjs.com/cli/v10/using-npm/scripts).

## 3. Cross-platform binary resolution at runtime: platform map, `require.resolve`, musl detection, and the npm optional-deps bug

The launcher must map the running platform to a package that npm installed, then run its binary. Three reference implementations:

- **Biome's `generateBinPath()`**: builds a `platform` key from `process.platform`/`process.arch`, detects musl on Linux, and returns `require.resolve(\`${pkg}/biome\`)`. It throws a clear error when no optional dep matched, which is the fail-closed behavior Blueline needs. [generate-bin-path.ts](https://github.com/biomejs/biome/blob/main/packages/%40biomejs/biome/src/generate-bin-path.ts).
- **esbuild's `node-platform.ts`**: maps `platform arch libc` (e.g. `"linux x64 LE"`) to a package name, then `require.resolve`s it, with an `ESBUILD_BINARY_PATH` environment override. No musl split, because Go binaries are statically linked. [node-platform.ts](https://github.com/evanw/esbuild/blob/main/lib/npm/node-platform.ts).
- **oxlint's `bindings.js`** (NAPI-RS generated): uses `createRequire` for resolution and runs an `isMusl()` ladder (checking ldd output, `process.report`, then a child process) to pick the right binding, with a version check gated behind `NAPI_RS_ENFORCE_VERSION_CHECK`. [bindings.js](https://github.com/oxc-project/oxc/blob/main/apps/oxlint/src-js/bindings.js).

The environment override (`ESBUILD_BINARY_PATH`, and a `BLUELINE_BINARY` equivalent) is worth copying: it lets developers and tests force a specific binary without re-installing, and lets Blueline verify a locally built binary against the npm layout.

**The one real footgun is npm/cli#4828**: npm sometimes silently fails to install optional dependencies, and the failure mode is a hard-to-debug `Cannot find native binding` at first run. The oxc issue shows it (`Cannot find native binding. npm has a bug related to optional dependencies (https://github.com/npm/cli/issues/4828)`), and the rolldown/vite discussion shows the same error for `@rolldown/binding`. [oxc issue #19276](https://github.com/oxc-project/oxc/issues/19276), [vite discussion #21846](https://github.com/vitejs/vite/discussions/21846). Mitigations used in the wild: Tailwind's postinstall repair fallback (rejected for Blueline, section 1), and every other implementation printing the offending npm bug URL when resolution fails. Blueline should adopt the second: on resolution failure, error out loud with the install command to retry and a pointer to npm/cli#4828. That is the fail-closed move, and it never runs a script.

## 4. Signals and exit codes: `spawnSync` with inherited stdio and verbatim status passthrough

Blueline's launcher is a wrapper, so its exit code must be the child's exit code, exactly:

- **Biome's `bin/biome`** is the canonical pattern: `spawnSync(binPath, process.argv.slice(2), { shell: false, stdio: "inherit" })` then `process.exitCode = spawn.status ?? undefined`. `shell: false` avoids shell injection on the args; `stdio: "inherit"` keeps the TTY and, because Node spawns the child in the same process group, lets Ctrl-C and SIGTERM reach the Rust process normally. [biome `bin/biome`](https://github.com/biomejs/biome/blob/main/packages/%40biomejs/biome/bin/biome).
- **npq** (the closest prior-art tool, which also delegates to npm) uses the async `spawn(fn, args, { cwd, stdio: "inherit" })` and propagates with `exit(code, signal)`. [npq](https://github.com/lirantal/npq).
- **Node's `spawnSync` returns `{ status, signal, error }`**: `status` is the child's exit code, `signal` is non-null when the child was killed by a signal, and `error` covers spawn failures (e.g. binary not found or not executable). `process.exitCode = status` propagates the code verbatim; when the child died by signal, `util.convertProcessSignalToExitCode()` (Node 20.17+) turns the signal into the conventional 128+N exit code so scripts and CI see a number. [child_process.spawnSync](https://nodejs.org/api/child_process.html#child_process_child_process_spawnsync_command_args_options), [util.convertProcessSignalToExitCode](https://nodejs.org/api/util.html#util_util_convertprocesssignaltoexitcode_signal).

The design consequence: the launcher must never re-map the child's exit code through its own error model. `spawnSync` with `stdio: "inherit"` and verbatim passthrough means a review verdict (and its exit code) reaches the shell byte-for-byte, and a spawn failure (missing platform package) is itself an error with a non-zero code.

## 5. Packaging Rust binaries to npm: the release pipelines that work

Three reference release pipelines cover the full matrix Blueline needs, and their shapes converge:

- **esbuild** (Go, but the npm mechanics are the model): a RUNBOOK plus a `publish.yml` workflow that builds all platform packages and publishes them; the docs document the version-bump process and a `make platform-all` build path. [esbuild RUNBOOK](https://github.com/evanw/esbuild/blob/main/RUNBOOK.md), [esbuild publish.yml](https://github.com/evanw/esbuild/blob/main/.github/workflows/publish.yml).
- **oxc** (`release_apps.yml`): a build matrix with native macOS and Windows runners for `apple-darwin` and `pc-windows-msvc` targets, Ubuntu runners using `cross` for most targets and `cargo-zigbuild` (via `goto-bus-stop/setup-zig`) for musl, pinned `taiki-e/install-action` for the toolchain, `napi create-npm-dirs` to generate the per-platform package directories, and trusted publishing (`--provenance`, no publish token) with an alpine container smoke test among others. [oxc release_apps.yml](https://github.com/oxc-project/oxc/blob/main/.github/workflows/release_apps.yml), [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild).
- **biome** (`release_cli.yml`): native `cargo build` per target with `RUSTFLAGS="-C strip=symbols -C codegen-units=1"` (stripped, single-codegen-unit binaries), `musl-tools` for the Linux musl targets, and a separate `build-gnu` job that compiles the glibc Linux binaries inside a Debian bullseye (11) Docker image to establish a glibc floor for old distros. A `generate-packages.mjs` script synthesizes the platform package.jsons, and the publish job loops `npm publish` over every `packages/@biomejs/*` directory with `--access public`. [biome release_cli.yml](https://github.com/biomejs/biome/blob/main/.github/workflows/release_cli.yml), [generate-packages.mjs](https://github.com/biomejs/biome/blob/main/packages/%40biomejs/biome/scripts/generate-packages.mjs).

The published platform packages share a common shape regardless of generator: `os`, `cpu` (and `libc` where musl is split), `engines`, `preferUnplugged: true`, no `bin`, and the binary at a fixed package-relative path. Everything ships in the tarball; nothing is fetched at install time.

## 6. `cargo install` coexistence: two first-party install paths that must not collide

Blueline ships two ways: `cargo install blueline` and `npm i -g @blueline/cli` (or npx). They coexist cleanly because:

- The Rust package is `blueline` and the npm package is `@blueline/cli`; the names live in different namespaces, so neither registry conflicts with the other. Both install a binary literally named `blueline`, and both are first-party, version-lockstep artifacts of the same `Cargo.toml` (currently `blueline` v0.2.0), so whichever `blueline` wins on `PATH` is the same tool.
- **The only real conflict is `cargo install` binary-name collisions**: cargo refuses to overwrite an existing binary of the same name unless `--force`, and it tracks installed packages in `~/.cargo/.crates.toml`. A second, unrelated crate that also ships a `blueline` binary would trigger that refusal, but Blueline's own two install paths never do, because npm places the binary in its own prefix (`~/.npm`-global or the npx cache) rather than `~/.cargo/bin`. [cargo install docs](https://doc.rust-lang.org/cargo/commands/cargo-install.html).
- PATH order decides which binary runs when both are installed; that is normal tooling behavior (same as having both a Homebrew and a source-built git) and worth one line in the README, not an engineering problem.

## Recommendations for Blueline

**Package layout (zero-scripts, exact pins).**
- Meta package `@blueline/cli`, version locked to `Cargo.toml` (v0.2.0). No `scripts` field at all, mirroring oxlint; `bin: { "blueline": "bin/blueline.js" }`; `optionalDependencies` with exact pins, one per shipped target: `@blueline/binary-linux-x64-gnu`, `-linux-x64-musl`, `-linux-arm64-gnu`, `-linux-arm64-musl`, `-darwin-x64`, `-darwin-arm64`, `-win32-x64`, `-win32-arm64`, each `"0.2.0"` verbatim (rolldown's hard-coded-pin approach).
- Each `@blueline/binary-*` package: no `bin`, `os`, `cpu`, `libc` (on the Linux packages), `preferUnplugged: true`, binary at `blueline` (or `blueline.exe`). Generate these package.jsons from a script, biome-style, so the launcher path and the pins stay in one place.
- Accept the esbuild counter-example: a static musl build of the Rust binary would run on both musl and glibc Linux and drop the gnu/musl split entirely. Blueline's SQLite dependency currently ties the binary to a specific libc, so start with the full 8-package matrix and revisit only if the dependency set ever goes fully static.

**Launcher (`bin/blueline.js`).**
- Resolve via a biome-style platform map: `process.platform`/`process.arch` plus a musl check on Linux, then `require.resolve(\`@blueline/binary-.../blueline\`)`. Honor a `BLUELINE_BINARY` env override first (esbuild's `ESBUILD_BINARY_PATH` pattern) so developers and tests can point at a locally built binary.
- Run `spawnSync(binPath, process.argv.slice(2), { shell: false, stdio: "inherit" })`; `process.exitCode = spawn.status ?? undefined`; on `spawn.signal`, `util.convertProcessSignalToExitCode(signal)`; on `spawn.error` (binary missing or not executable), print the npm install retry command and the npm/cli#4828 pointer, and exit non-zero. Fail closed, never fall back to guessing.
- No postinstall, no `install.js`, no repair fallback. `--ignore-scripts` must work, and the launcher must contain nothing that lifecycle scripts would ever have run.

**Rust executor (`src/`).**
- When the review flow must run the real install (with `--ignore-scripts`), exec npm via `$npm_execpath` (the npm that launched the tool, set by npx and scripts), falling back to `npm` on `PATH`, with inherited stdio and verbatim exit-code passthrough. This is npm's endorsed child-process delegation; the programmatic npm API was removed in npm v8.0.0 and no stable one exists to call.

**CI / release.**
- GH Actions matrix: native `macos-*` and `windows-*` runners for darwin and win32; Ubuntu runners with `cargo-zigbuild` via `setup-zig` for the four Linux gnu/musl targets. Trusted publishing (`--provenance`, no token), biome-style stripped builds (`-C strip=symbols -C codegen-units=1`), and a glibc-floor strategy for gnu Linux. Publish platform packages before the meta package, and smoke test with the exact user-facing command (`npx @blueline/cli --version`) on windows, ubuntu, and an alpine musl container, mirroring oxc's smoke matrix.

**YAGNI list (explicitly not building).**
- No `install.js` downloader or postinstall of any kind.
- No NAPI `.node` bindings or WASM fallback; Blueline is a plain binary and gains nothing from an ABI surface.
- No postinstall self-repair fallback à la Tailwind; the npm/cli#4828 workaround is a printed message, not code that runs.
- No per-platform `engines.node` split or dual-package trick; one launcher, one Node baseline.
- No extra npm packages beyond the 8 binaries plus the meta package; a reviewer tool should not need a dependency tree of its own.

## Sources

- https://github.com/evanw/esbuild/pull/1621
- https://unpkg.com/esbuild@0.25.0/package.json
- https://esbuild.github.io/getting-started/
- https://github.com/evanw/esbuild/blob/main/lib/npm/node-install.ts
- https://github.com/evanw/esbuild/blob/main/lib/npm/node-platform.ts
- https://github.com/evanw/esbuild/blob/main/RUNBOOK.md
- https://github.com/evanw/esbuild/blob/main/.github/workflows/publish.yml
- https://unpkg.com/oxlint@1.45.0/package.json
- https://github.com/oxc-project/oxc/blob/main/apps/oxlint/src-js/bindings.js
- https://github.com/oxc-project/oxc/issues/19276
- https://github.com/oxc-project/oxc/blob/main/.github/workflows/release_apps.yml
- https://github.com/rolldown/rolldown/pull/654
- https://github.com/vitejs/vite/discussions/21846
- https://github.com/biomejs/biome/blob/main/packages/%40biomejs/biome/bin/biome
- https://github.com/biomejs/biome/blob/main/packages/%40biomejs/biome/src/generate-bin-path.ts
- https://github.com/biomejs/biome/blob/main/packages/%40biomejs/biome/scripts/generate-packages.mjs
- https://github.com/biomejs/biome/blob/main/.github/workflows/release_cli.yml
- https://github.com/tailwindlabs/tailwindcss/pull/17929
- https://github.com/npm/cli/issues/4828
- https://github.com/npm/npm/pull/11130
- https://docs.npmjs.com/cli/v10/commands/npx
- https://docs.npmjs.com/cli/v8/commands/npm-exec
- https://docs.npmjs.com/cli/v10/using-npm/scripts
- https://nodejs.org/api/child_process.html#child_process_child_process_spawnsync_command_args_options
- https://nodejs.org/api/util.html#util_util_convertprocesssignaltoexitcode_signal
- https://github.com/lirantal/npq
- https://github.com/rust-cross/cargo-zigbuild
- https://doc.rust-lang.org/cargo/commands/cargo-install.html

## Adversarial self-check

- **esbuild's postinstall still exists.** `esbuild@0.25.0` does ship `postinstall: node install.js`, so my "zero-scripts" claim for esbuild is wrong if stated broadly. The accurate claim is that the postinstall is no longer the download mechanism (that moved to `optionalDependencies` in PR #1621); it is an optimization and a `--no-optional` fallback, and esbuild's docs confirm `--ignore-scripts` alone works. Blueline's zero-scripts stance is therefore stricter than esbuild's and safe; I verified the package.json but did not execute `install.js` to confirm its exact runtime behavior.
- **Musl detection robustness.** I verified oxlint's `isMusl()` ladder exists but did not run it; the ldd-based check is a heuristic and can misfire on exotic toolchains. Blueline's gnu/musl split depends on that check being right, so the launcher should treat a failed resolution as an error with the retry instructions, never guess.
- **npm/cli#4828 failure rate.** I verified the issue and the two linked user reports (oxc #19276, vite #21846) but have no measurement of how often npm 10/11 actually drops optional deps. The mitigation (clear error + retry command) is chosen because it is the only one that works under `--ignore-scripts`, not because the bug is common.
- **`~/.cargo/.crates.toml` location.** The cargo docs describe the installed-package registry and the `--force` overwrite rule; the exact `~/.cargo/.crates.toml` path is from my reading of cargo's behavior, not a doc quote, and it varies with `CARGO_HOME`.
- **Trusted publishing details.** I confirmed oxc publishes with `id-token: write` and `--provenance` and biome with `actions/attest-build-provenance` plus a tokenless flow, but I did not inspect either npm account's OIDC configuration, so "trusted publishing works here" is inferred from the workflow files, not verified on the registry side.
- **Glibc floor claim.** Biome's `build-gnu` job comment says Debian 11 (bullseye) is used "to support older versions of glibc"; I did not test the resulting binary on an old distro, so the floor is claimed from the workflow comment only.
- **NAPI specifics are context, not requirements.** oxc's `create-npm-dirs`/`pre-publish` tooling belongs to NAPI-RS's packaging model, which Blueline does not use; I cite it only because its matrix, zigbuild setup, smoke tests, and publish order are directly reusable. Blueline's own package generation is a small script, biome-style, not a NAPI pipeline.
