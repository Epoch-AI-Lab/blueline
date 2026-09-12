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
**Pin a user-level policy** by exporting `BLUELINE_POLICY=/path/to/blueline.toml`
for the hook's environment: a hook fires with the repository as its working
directory, so without it a malicious repo's committed `blueline.toml`
allowlist would govern the gate.

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
blueline shim install npm npx pip pip3 cargo yay paru
export PATH="$HOME/.local/share/blueline/shims:$PATH"
```

Each shim rebuilds the invocation, runs it through `blueline agent gate`,
and only then execs the real package manager (resolved on PATH at install
time). If blueline errors or refuses, the install does not run. Scope a
shell with `BLUELINE_REGISTRY=<mirror>` and `BLUELINE_POLICY=<blueline.toml>`.

**What shims cannot stop** — stated plainly, because a gate that overstates
its coverage is security theater: absolute binary paths (`/usr/bin/npm`),
`command npm`, `env -i`, direct `node .../npm-cli.js` invocation, npx
resolving from an existing `node_modules/.bin`, PATH reordering,
repo-committable hook config, and unshimmed near-synonyms (`pip3` is
shipped, but `python -m pip` and `uv pip` are not). Shims are
defense-in-depth for the terminal; hooks are the agent boundary;
`blueline ci` polices the manifest and lockfile where the real authority
lives. Unpinned specs are reviewed at their current default version —
re-review before the install if the window matters.

## Contributors

See [CONTRIBUTORS.md](./CONTRIBUTORS.md) for maintainers, contributors, and details on how to get involved.

## License

The CLI, diff engine, and CI checks are licensed under the MIT License. See [LICENSE](./LICENSE) for details.

