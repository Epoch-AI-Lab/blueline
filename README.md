<p align="center"><img src="./brand_assets/logo.png" alt="Blueline" width="480"></p>

> Approve the delta, not the download.

Blueline is a release-diff review desk for the package install line. It renders every release as a proof sheet and demands sign-off before the byte runs. Built for humans. Built for agents that install hallucinated packages in good faith.

## The problem

- **96%** of devs use AI tools; only **18%** apply security continuously <cite>Checkmarx 2026</cite>
- The TanStack/router worm shipped a malicious npm package with **valid SLSA L3 provenance** <cite>Unit42</cite>
- **46%** distrust AI output; **96%** don't fully trust its functional accuracy <cite>Stack Overflow 2025</cite>
- **41%** place managing tech debt in their top-5 frustrations <cite>Sonar State of Code 2026</cite>

The install line is the cheapest failure point in the agent era. Nothing executes until it has been judged.

## The wedge

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

If the delta exceeds policy thresholds, Blueline blocks the install and routes it to a senior engineer for sign-off.

## Status

We are building the wedge primitive:
- [x] Diff rendering engine (Rust)
- [ ] npm/npx CLI wrapper
- [ ] GitHub Action + CI check
- [ ] MCP tool (agent hook)
- [ ] Revocation index + recall API

## Open source

Blueline's CLI, CI check, and diff engine are MIT-licensed. The hosted verdict model and recall index will be a paid service for orgs that want it. A trust tool that audits itself in secret is a contradiction — the wedge stays open.

## Try it

```bash
git clone https://github.com/Epoch-AI-Lab/blueline.git
cd blueline
cargo build --release
./target/release/blueline review express@4.21.2
```

## Contribute

We need:
- Language experts for the diff heuristic (what makes a delta "risky"?)
- Security engineers who've reviewed real supply-chain incidents
- Anyone who's ever been burned by `npm install` and wants to fix it

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Cite the research

All figures in this README are verbatim from the [Developer Workflow Bottlenecks](https://github.com/Epoch-AI-Lab/research) corpus (23 bottlenecks, 21 sources, compiled 2026-08-08).

---

*Never generate faster. Always verify sooner.*
