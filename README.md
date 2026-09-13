<p align="center"><img src="./brand_assets/logo.png" alt="Blueline" width="480"></p>

> Approve the change, not the download.

Blueline is a review step for package installs. It extracts the release tarball in an isolated sandbox, calculates what changed against your last verified version, and prompts for approval before anything touches your machine.

## The problem

Package managers treat installs as a transport problem. You ask for a package, they fetch the tarball, unpack it, and run whatever install scripts came with it. If an attacker pushed malicious code ten minutes ago, your machine executes it before you can look.

- 96% of developers use AI coding tools, but only 18% run security checks continuously (Checkmarx 2026).
- The TanStack router worm shipped malicious npm packages that carried valid SLSA L3 build provenance (Unit42).
- 46% of developers distrust AI output, and 96% do not fully trust its functional accuracy (Stack Overflow 2025).
- 41% of developers rank managing tech debt among their top five daily frustrations (Sonar State of Code 2026).

Autonomous agents install dependencies without reading them. Nobody audits the delta between 4.21.1 and 4.21.2 when an agent runs an install command in a loop.

## The review card

Blueline intercepts package installs and renders a summary card before extracting files to your project:

```bash
$ npx blueline install express@4.21.2

  BLUELINE REVIEW CARD
  ─────────────────────────────────────────
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

  verdict:    ▶ LOW RISK

  [a]pprove · [h]old · [d]iff
```

If a release exceeds risk thresholds, Blueline blocks the install and halts the workflow.

## Project status

- [x] Multi-registry support: npm, crates.io (`--ecosystem cargo`), PyPI (`--ecosystem pypi`), and AUR (`--ecosystem aur`, review-only)
- [x] Recursive review: an install reference inside a reviewed payload (npm lifecycle script, PKGBUILD `npm install` delivery, wheel `.data/scripts`) is itself reviewed — depth-capped, cycle-safe, and rolled up into the parent verdict
- [x] Recall / revocation index: local-first and self-hostable — serve a curated revocation snapshot, sync it, and any hit blocks; staleness is disclosed (and can BLOCK by policy)
- [x] Sandboxed archive extraction with path traversal, symlink, and decompression bomb guards
- [x] Package manifest parsing, cryptographic integrity (SHA-256 / SHA-512), and PEP 740 / SLSA provenance
- [x] SQLite store for verified baseline releases and audit logging
- [x] Lockfile CI scanning (`package-lock.json`, `Cargo.lock`, `requirements.txt`)
- [x] CLI review command (`blueline review <pkg@ver>` / `blueline --ecosystem pypi review <pkg==ver>`)
- [x] Line-level diff engine and static heuristic risk scoring
- [x] npm and npx wrapper shim (`@blueline/cli`)
- [x] GitHub Action PR check
- [x] Agent hook via Model Context Protocol (MCP)
- [ ] Revocation index and recall API

## Quickstart

Clone the repository and build the release binary:

```bash
git clone https://github.com/Epoch-AI-Lab/blueline.git
cd blueline
cargo build --release
./target/release/blueline review express@4.21.2
```

## AUR

Blueline reviews AUR packages but never builds them: `blueline install`
refuses `--ecosystem aur` because building a PKGBUILD runs its shell code.
Review with blueline, build with yay or paru.

```bash
blueline --ecosystem aur review yay@12.4.2-1
```

Threat model, plainly stated: the review covers the repo scripts only.
Downloaded upstream sources listed in `source=()` are not reviewed, and the
build step executes the PKGBUILD. Every AUR card carries that scope
disclosure. The stored approval is bound to the reviewed commit: the audit
log keeps the sha256 of the pinned commit's archive bytes, so a history
rewrite never passes as the same approval.

### yay gate hook

yay v13 runs `AURPreInstall` hooks before building. Drop this in your yay
`init.lua` to block the build unless blueline approves the version:

```lua
yay.create_autocmd("AURPreInstall", {
  desc = "gate the build on a blueline review",
  callback = function(event)
    for _, pkg in ipairs(event.data.packages) do
      local spec = event.match .. "@" .. pkg.version
      local ok = os.execute(
        "blueline --ecosystem aur review "
          .. string.format("%q", spec) .. " --yes --policy blueline.toml"
      )
      if ok ~= 0 then
        yay.abort(event.match .. ": blueline refused " .. spec)
      end
    end
  end,
})
```

Timing note: the review pins the newest commit for that version at review
time, while yay builds its own download. Re-run the review right before the
build and treat any version drift as a re-review signal.

### AUR in CI

`blueline ci` accepts a pin file with one `pkgbase@pkgver-pkgrel` per line,
blank lines and `#` comments allowed. Pipe your own tooling over
`pacman -Qqm` to produce it:

```bash
blueline --ecosystem aur ci --lockfile aur.lock --base origin/main
```

Policy rules take `ecosystem = "aur"` to scope allows and blocks to AUR,
or omit it to match every ecosystem.

## Agent enforcement

Autonomous agents install dependencies without reading them. Blueline ships
three enforcement surfaces, one per trust boundary:

- **`blueline agent review <pkg>`** — the agent's own call. Non-interactive
  and policy-bound: a single-line JSON verdict on stdout, exit `0` when the
  policy approves, `2` when it refuses, `1` on error. It never prompts and
  never marks a baseline clean — an agent can learn the verdict, not grant
  trust. Every decision lands in the local audit log as
  `agent:<identity>` (Claude Code, Cursor, or Codex CLI detected from the
  process environment; env names only, never values).
- **`blueline agent gate`** — the hook binding. It polices one command line
  (`--command "<cmd>"`, or the hook payload on stdin — Claude Code
  `PreToolUse` and Cursor `beforeShellExecution` shapes are both accepted),
  reviews every package the command names with the recursive engine (npm
  packages through npm, pip through PyPI, `cargo install` through
  crates.io, `yay`/`paru -S` through the AUR), and answers with exit codes
   or the product's native decision JSON. Any internal error denies —
   never allows. Best-effort obfuscation that hides a package-manager token
   entirely (indirect scripts, `python -m pip`, `pip3` without a shim) is
   outside the scanner's reach and disclosed below.
- **`blueline agent gate`** — registry-redirect handling. Inline assignments
  that would install from elsewhere than the reviewed registry
  (`PIP_INDEX_URL` / `PIP_EXTRA_INDEX_URL` / `PIP_CONFIG_FILE`, `NPM_CONFIG_*`,
  `CARGO_*`, `.npmrc` references, `--registry` / `--index-url` overrides)
  are denied outright: the review would vouch for bytes the install never
  fetches. The same families exported in the gate's process environment
  cannot be denied from the command line, so they are disclosed instead —
  the verdict reason carries a warning and the audit trail records the
  variable names (never values). Absolute manager paths (`/usr/bin/npm`,
  `/usr/local/bin/npx`, `/usr/bin/pip`, quoted variants) are scanned like
  their bare names, not treated as a bypass.

### Claude Code hook

Drop this in **user-level** `~/.claude/settings.json` (not the repo —
repo-committable hook config is itself an attack vector):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "blueline agent gate --format claude"
          }
        ]
      }
    ]
  }
}
```

The gate reads the tool-call JSON from stdin, scans the command with the
same parser the review engine uses, reviews the named packages, and denies
with `exit 2` (Claude Code's documented contract for policy hooks). A
dynamic target like `npm install $(cat deps.txt)` is denied — fail closed.
**Pin a user-level policy** with an explicit flag in the hook command —
`blueline agent gate --format claude --policy /path/to/blueline.toml`
(user-level config, not the repo: a hook fires with the repository as its
working directory, so a committed `blueline.toml` allowlist must never
govern the gate). `agent gate` and `agent review` ignore `BLUELINE_POLICY`
from the environment for the same reason — ambient env is attacker-shaped —
and warn on stderr when it is set but ignored. Every other subcommand
(`review`, `install`, `ci`, `mcp`) still honors `BLUELINE_POLICY` ahead of
the working-directory and user-config search paths.

### Cursor hook

`.cursor/hooks.json` (project) or `~/.cursor/hooks.json` (user):

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "blueline agent gate --format cursor",
        "timeout": 60,
        "failClosed": true
      }
    ]
  }
}
```

### Codex CLI

Codex has no hook process; its execpolicy is prefix-based and cannot run a
reviewer. The honest recipe is advisory: mark install verbs as `prompt` in
`~/.codex/rules/*.rules` and instruct the agent to route installs through
`blueline agent review` (or run them inside a blueline-shimmed shell):

```python
prefix_rule(pattern = ["npm", "install"], decision = "prompt",
            justification = "installs must be reviewed by blueline")
```

### PATH shims (interactive-terminal backstop)

```bash
blueline shim install npm npx pnpm yarn bun bunx pip pip3 cargo yay paru
export PATH="$HOME/.local/share/blueline/shims:$PATH"
```

Each shim rebuilds the invocation, runs it through `blueline agent gate`,
and only then execs the real package manager (resolved on PATH at install
time). If blueline errors or refuses, the install does not run. Scope a
shell with `BLUELINE_REGISTRY=<mirror>` and `BLUELINE_POLICY=<blueline.toml>`.

**What shims cannot stop** — stated plainly, because a gate that overstates
its coverage is security theater: absolute binary paths (`/usr/bin/npm`) —
scanned by the gate but invisible to a PATH shim, so prefer the hook —
`command npm`, `env -i`, direct `node .../npm-cli.js` invocation, npx
resolving from an existing `node_modules/.bin`, PATH reordering,
repo-committable hook config, exported registry-redirect environment
(`PIP_INDEX_URL`, `NPM_CONFIG_REGISTRY`, `CARGO_*` — disclosed by the gate,
not denied), and unshimmed near-synonyms (`pip3` is
shipped, but `python -m pip` and `uv pip` are not). Shims are
defense-in-depth for the terminal; hooks are the agent boundary;
`blueline ci` polices the manifest and lockfile where the real authority
lives. Unpinned specs are reviewed at their current default version —
re-review before the install if the window matters.

## Distribution

The CLI ships through npm (`@bluelinecli/cli`, `npx blueline`) with the
native binary delivered via platform packages for linux (x64 glibc/musl,
arm64), macOS (x64, arm64), and Windows (x64, arm64). Release binaries
are attested at release time with SLSA build provenance
(`actions/attest-build-provenance`) and a `SHA256SUMS` manifest; npm
publishes use `--provenance`. Packaging configs for the other channels
live in-repo: `packaging/homebrew/blueline.rb` (source build via cargo)
and `packaging/aur/` (PKGBUILD + .SRCINFO pinned to the signed GitHub
tag — reviewed with blueline's own PKGBUILD heuristics before it lands on
the AUR). Publishing to any registry is a manual, human-confirmed step.

We eat our own dog food: CI runs `blueline ci` against this repo's own
`package-lock.json` and `Cargo.lock` on every PR, and dependency deltas
are reviewed with the same verdicts customers get.

## Policy reference

- `BLUELINE_POLICY` scopes shells and hooks launched outside a project
  directory: `review`, `install`, `ci`, and `mcp` read it ahead of
  `./blueline.toml`, `./.blueline.toml`, and the user config. `agent gate`
  and `agent review` ignore it unless `--policy` names the file explicitly
  (ambient env is attacker-shaped at the hook boundary).
- Recall vs `check_advisories`: the curated recall index is consulted
  *before* the `check_advisories` policy switch, so setting
  `check_advisories = false` disables OSV/GHSA lookups but never silences
  a recall revocation — a hit still BLOCKs. Recall-index staleness
  (`R28_RECALL_STALE`) is disclosed independently of that switch: MEDIUM
  when the snapshot is older than `[recall] max_age_hours`, HIGH when it
  cannot be read at all, BLOCK when `block_on_stale` escalates it.

## Contributors

See [CONTRIBUTORS.md](./CONTRIBUTORS.md) for maintainers, contributors, and details on how to get involved.

## License

The CLI, diff engine, and CI checks are licensed under the MIT License. See [LICENSE](./LICENSE) for details.

