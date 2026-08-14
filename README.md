<p align="center"><img src="./brand_assets/logo.png" alt="Blueline" width="480"></p>

> Approve the change, not the download.

Blueline reviews package installs one line at a time. It shows what changed between releases and makes you approve it before anything downloads.

## Problem

- **96%** of devs use AI tools; only **18%** apply security continuously <cite>Checkmarx 2026</cite>
- The TanStack/router worm shipped a malicious npm package with **valid SLSA L3 provenance** <cite>Unit42</cite>
- **46%** distrust AI output; **96%** don't fully trust its functional accuracy <cite>Stack Overflow 2025</cite>
- **41%** place managing tech debt in their top-5 frustrations <cite>Sonar State of Code 2026</cite>

Every install is a failure point. Agents grab packages without reading them. Nothing should execute without a sign-off first.

## The review card

A drop-in CLI wrapper that prints one review card before any download:

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

If the change exceeds policy thresholds, Blueline blocks the install and routes it to a senior engineer for sign-off.

## Status

Building the review flow:
- [x] Diff rendering engine (Rust)
- [ ] npm/npx CLI wrapper
- [ ] GitHub Action + CI check
- [ ] MCP tool (agent hook)
- [ ] Revocation index + recall API

## License

The CLI, CI check, and diff engine are MIT-licensed. The hosted verdict model and recall index will be a paid service for orgs that want it. A trust tool that audits itself in secret is a contradiction.

## Try it

```bash
git clone https://github.com/Epoch-AI-Lab/blueline.git
cd blueline
cargo build --release
./target/release/blueline review express@4.21.2
```

## Contribute

- Language experts for the diff heuristic (what makes a change "risky"?)
- Security engineers who've reviewed real supply-chain incidents
- Anyone who's ever been burned by `npm install` and wants to fix it

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Sources

All figures are verbatim from the [Developer Workflow Bottlenecks](https://github.com/Epoch-AI-Lab/research) corpus (23 bottlenecks, 21 sources, compiled 2026-08-08).

---

*Never generate faster. Always verify sooner.*
