# Phase 2 — Review Card, CLI Surface & JSON Schema Updates

**Subject:** Visual card layout, command line arguments, and JSON schema evolution for Phase 2.
**Compiled:** 2026-08-16 · **Status:** Technical Specification & Research

---

## 1. Terminal Card Rendering Updates

The Phase 1 review card ([render.rs](file:///home/kriday/Desktop/code/blueline/src/render.rs)) focuses on delta heuristics. Phase 2 extends the proof sheet to display intelligence from trust sources:

### 1.1 Updated Card Layout (ASCII Terminal)
```
┌────────────────────────────────────────────────────────────────────────────┐
│ BLUELINE RELEASE REVIEW: express@4.21.2                                   │
├────────────────────────────────────────────────────────────────────────────┤
│ Baseline:       express@4.21.1 (known clean from local store)              │
│ Verdict:        MEDIUM RISK (Score: 35/100)                                │
│ Action:         Manual Sign-off Required                                   │
├────────────────────────────────────────────────────────────────────────────┤
│ TRUST SOURCES & PROVENANCE                                                 │
│ • OSV / GHSA:   [CLEAN] 0 known advisories affecting 4.21.2                │
│ • Provenance:   [SLSA L3] Verified GitHub Actions Builder                  │
│ • Source Repo:  https://github.com/expressjs/express                       │
│ • Commit:       8f1a23c (tagged release v4.21.2)                           │
│ • Registry Sig: [VALID] Signed by npm Registry Key                         │
├────────────────────────────────────────────────────────────────────────────┤
│ HEURISTIC DELTA ANALYSIS                                                   │
│ • Files:        +2 added, -1 removed, ~4 modified                          │
│ • Obfuscation:  None detected                                              │
│ • Scripts:      No new lifecycle scripts added                             │
│ • Network:      [WARN] Introduced fetch() call in lib/telemetry.js         │
│ • Binaries:     None                                                       │
├────────────────────────────────────────────────────────────────────────────┤
│ Decision: [a]pprove · [h]old · [d]iff full delta · [o]sv details           │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Stable JSON Verdict Schema (v2)

The machine-readable JSON output emitted by `--output json` (or via piped stdout) is backward-compatible while providing typed trust fields:

```json
{
  "$schema": "https://blueline.security/schemas/verdict-v2.json",
  "schema_version": 2,
  "package": "express",
  "target_version": "4.21.2",
  "baseline_version": "4.21.1",
  "baseline_source": "store",
  "score": 35,
  "verdict": "Medium",
  "trust_sources": {
    "advisories": {
      "status": "clean",
      "count": 0,
      "hits": []
    },
    "provenance": {
      "status": "verified",
      "slsa_level": 3,
      "builder_id": "https://github.com/actions/runner",
      "source_repo": "https://github.com/expressjs/express",
      "commit_sha": "8f1a23c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
      "workflow_path": ".github/workflows/release.yml"
    },
    "registry_signature": {
      "status": "valid",
      "key_id": "SHA256:jl3BW1Uv80P05WOwuN2HPqQ62W7eRM6CDOhWYT558NN"
    }
  },
  "delta_summary": {
    "files_added": 2,
    "files_removed": 1,
    "files_modified": 4,
    "lines_added": 45,
    "lines_removed": 12,
    "has_install_scripts": false,
    "has_binary_files": false
  },
  "findings": [
    {
      "rule": "network_primitives",
      "severity": "medium",
      "file": "lib/telemetry.js",
      "line": 42,
      "description": "Introduced fetch() network call"
    }
  ]
}
```

---

## 3. CLI Argument Additions

New CLI flags to control Phase 2 behavior in `src/cli.rs`:

```
OPTIONS:
    --no-advisories          Skip querying OSV/GHSA vulnerability databases
    --strict-advisories      Fail closed (Block) if advisory database is unreachable
    --require-provenance     Enforce that target package must have valid SLSA provenance
    --policy <PATH>          Path to custom blueline.toml policy file
    --clear-advisory-cache   Evict all locally cached OSV advisory responses
```
