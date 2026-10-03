# Provenance

`src/provenance.rs`. Surfaces sigstore/SLSA/in-toto attestations. Protects one
narrow property — **the in-toto subject digest must match the tarball we
actually fetched** — and explicitly does *not* claim signature verification.

## Sub-features
- `inspect_provenance` (npm) / `inspect_provenance_pypi` (PEP 740).
- `parse_attestation_payload` / `parse_pypi_provenance_json`.
- `ProvenanceStatus` / `ProvenanceReport`.
- Cache integration with `provenance_cache`.

## How to get to it (user POV)
```sh
blueline review express@4.21.2 --output json | jq '.trust_sources.provenance'
# {"status":"Missing","slsa_level":0,"registry_signature_present":true,…}
blueline --policy <(printf '[provenance]\nrequire_provenance = true\n') \
  review express@4.21.2
```

## Driving it
npm endpoint: `{base}/-/npm/v1/attestations/{pkg with '/'→%2f}@{version}`.
PyPI endpoint: `{base}/integrity/{pep503-name}/{version}/{filename}/provenance`.
Both take the base as a parameter — "threaded from the resolved registry, never
hardcoded". Do not reintroduce a literal `registry.npmjs.org`.

Timeout `3000 ms`, response cap `1 MiB` (inline literals, not named consts).
`User-Agent: blueline-security/0.1.0`.

Rule wiring (`heuristic.rs`):
- `P03_PROVENANCE_DIGEST_MISMATCH` → `Block`, on `status == FailedMismatch`.
  **Unconditional, no policy switch.**
- `P03_PROVENANCE_REQUIRED_MISSING` → `Block`, only when
  `[policy] require_provenance || [provenance] require_provenance` **and**
  `status != Verified`.
- `P03_SIGNATURE_REQUIRED_MISSING` → `Block`, when
  `[provenance] require_signatures && !registry_signature_present`.

## Gotchas
- **Exactly one thing is verified: the subject digest.** There is **no DSSE
  signature check** — `DsseEnvelope` only has `payload`, no `signatures` field,
  no Fulcio root, no Rekor entry. Anyone controlling the registry response can
  forge `Verified`. The PyPI message says so literally: `"PEP 740 attestation
  verified (crypto verification not performed)"`.
- **`slsa_level: 3` is a hardcoded literal.** `predicateType` is never read (the
  `InTotoStatement` struct has no such field), so a
  `slsa.dev/provenance/v0.2` statement still reports Level 3. Never write
  "sigstore-verified" anywhere.
- **An empty `subject: []` must fail closed.** `#[serde(default)] subject:
  Vec<InTotoSubject>` plus `statement.subject.iter().any(...)` means an empty
  array yields `FailedMismatch`, not `Verified`. That is exactly what
  `empty_subject_attestation_fails_closed` pins. Rewriting it as
  `subject.first().map_or(true, …)` or `is_empty() => Verified` reintroduces the
  bypass fixed in 0.1.0.
- **The algorithm key must match exactly.** A `sha256` subject against a
  `sha512` `Checksum` is a mismatch. The comparison is `eq_ignore_ascii_case`;
  switching it to `==` produces spurious `FailedMismatch` → `Block` on any
  uppercase-hex registry.
- **`subject[].name` is never checked.** `pkg:npm/express@4.21.2` is decorative.
- **The first parseable payload wins, including a `FailedMismatch`** — an
  early-bad / late-good bundle reports mismatch.
- **`ProvenanceStatus::Unverified` is dead.** `ProvenanceReport::unverified()`
  returns `status: Missing`, so `render.rs`'s `Unverified` arm is unreachable.
  Observably you only see `Verified`, `Missing`, `FailedMismatch`.
- **A base64/JSON parse error on the PyPI endpoint is indistinguishable from
  "no attestation"** (`Missing`), except by the `"Provenance unverified: "`
  message prefix.
- **The provenance cache has no TTL and no checksum in its key.** A cache hit
  returns `Verified` without touching `expected_integrity` — so the same
  `name@version` with a *different* tarball reads back the old `Verified` and
  skips the digest check entirely. `verified_at` is stored and never compared.
  This is the sharpest asymmetry with the advisory cache, which at least expires.
- **Cargo and AUR pass `None` for provenance** in `review.rs`, so
  `trust_sources.provenance` is absent for those ecosystems.
- **`[provenance] allowed_builders` is a dead knob** — never read anywhere.
  Only `allowed_repositories` is consulted, via `P03_UNAUTHORIZED_BUILD_REPO`.
- **`is_repo_allowed` matches on path boundaries only**: exact
  `eq_ignore_ascii_case`, or `strip_suffix(pattern)` where the remainder ends
  with `'/'` or `':'`. `enforces_repository_boundary_matching` pins rejection of
  `github.com/org/app-malicious`, `github.com/attacker-org/app`, and
  `github.com/attacker/org/app`. A `None` `source_repo` is a *silent pass*.