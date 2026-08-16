# Phase 2 — Trust Sources & Intelligence Research: Provenance & Attestations

**Subject:** npm Provenance (Sigstore / SLSA) & Registry Signatures Architecture for Blueline.
**Compiled:** 2026-08-16 · **Status:** Technical Specification & Research

---

## 1. Context & Threat Model

npm supports two cryptographic authenticity mechanisms:
1. **Registry Signatures:** ECDSA P-256 signatures over `${package.name}@${package.version}:${package.dist.integrity}` using npm's registry public key (`/-/npm/v1/keys`).
2. **Build Provenance Attestations:** Sigstore-backed in-toto / SLSA v0.2/v1.0 attestations linking the published tarball to a verifiable source repository, commit SHA, and GitHub Actions workflow.

### The Core Lesson: Provenance is Context, Never Complete Trust
The **2025 TanStack Supply Chain Incident** proved that malicious packages can carry valid, cryptographically sound SLSA Build Level 3 attestations if the maintainer's GitHub repository or CI workflow is compromised.

Therefore, Blueline's design rule (D9/D10) is:
> **Provenance is surfaced to the human reviewer for context, but never bypasses diff review or heuristic scoring.**

---

## 2. npm Attestation Protocol & Structure

### 2.1 Fetching Attestations
Attestations are fetched from the npm registry via:
- Endpoint: `GET https://registry.npmjs.org/-/npm/v1/attestations/<pkg>@<version>`
- Or extracted from `dist.attestations.url` in the packument.

### 2.2 Attestation Bundle Structure (Sigstore / in-toto)
```json
{
  "attestations": [
    {
      "url": "https://registry.npmjs.org/-/npm/v1/attestations/example@1.0.0",
      "predicateType": "https://slsa.dev/provenance/v0.2",
      "bundle": {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "verificationMaterial": {
          "x509CertificateChain": {
            "certificates": [{ "rawBytes": "..." }]
          },
          "tlogEntries": [{ "logIndex": "123456" }]
        },
        "dsseEnvelope": {
          "payload": "<base64 encoded in-toto statement>",
          "payloadType": "application/vnd.in-toto+json",
          "signatures": [{ "keyid": "", "sig": "..." }]
        }
      }
    }
  ]
}
```

### 2.3 Decoded in-toto / SLSA Statement
When the DSSE payload is base64-decoded, it contains:
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "pkg:npm/%40scope%2Fpkg@1.0.0",
      "digest": {
        "sha512": "..."
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": { "id": "https://github.com/actions/runner" },
    "buildType": "https://actions.github.com/workflow/v1",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/org/repo@refs/heads/main",
        "digest": { "sha1": "abcdef0123456789..." },
        "entryPoint": ".github/workflows/release.yml"
      }
    }
  }
}
```

---

## 3. Data Extraction & Display Model

Blueline parses the following verified metadata fields:
1. **Source Repository:** e.g., `github.com/facebook/react`
2. **Commit SHA:** e.g., `8f7a932b...`
3. **Workflow Path:** e.g., `.github/workflows/publish.yml`
4. **Builder / Host:** e.g., `GitHub Actions (Hosted)`
5. **Transparency Log (Rekor):** Log inclusion index verification.

### Review Card Display
In `render.rs`, the card adds an **Attestation & Origin** row:
```
┌────────────────────────────────────────────────────────┐
│ PROVENANCE & BUILD ORIGIN                              │
├────────────────────────────────────────────────────────┤
│ Provenance:     [VERIFIED SLSA Level 3]                │
│ Source Repo:    https://github.com/expressjs/express   │
│ Commit:         7ab3c49 (release v4.21.2)              │
│ Workflow:       .github/workflows/release.yml          │
│ Registry Sig:   [VALID] npm Inc. (Key: SHA256:abcd...) │
└────────────────────────────────────────────────────────┘
```

---

## 4. Policy Integration (`blueline.toml`)

Projects can enforce provenance policies in `blueline.toml`:
```toml
[policy.provenance]
# Fail closed if a release lacks valid SLSA provenance
require_provenance = false

# Restrict allowed source repositories for critical packages
[policy.provenance.repositories]
"express" = "https://github.com/expressjs/express"
"@scope/*" = "https://github.com/my-org/*"

# Block if builder is not standard GitHub Actions
allowed_builders = [
    "https://github.com/actions/runner",
    "https://slsa-framework.github.io/slsa-github-generator"
]
```

### Invariant Checks
1. **Digest Binding:** The subject digest in the SLSA statement MUST match the downloaded tarball's `sha512` integrity hash. Any mismatch is an immediate hard `Verdict::Block`.
2. **Repository Drift Detection:** If the baseline version was built from repo `A` and the new version claims repo `B`, flag a high-severity alert: `CRITICAL: Source repository changed from A to B`.
