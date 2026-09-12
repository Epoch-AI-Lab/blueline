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

## Contributors

See [CONTRIBUTORS.md](./CONTRIBUTORS.md) for maintainers, contributors, and details on how to get involved.

## License

The CLI, diff engine, and CI checks are licensed under the MIT License. See [LICENSE](./LICENSE) for details.

