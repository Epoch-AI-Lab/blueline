# Error Types

The `BluelineError` enum — eleven variants, one per refusal category, plus the
`{e:#}` chain-printing discipline. It is the file that makes "fail closed on
doubt" *nameable*: every parse, extract, verify, or store boundary returns one
of these instead of guessing. 39 lines. Read it once.

## Sub-features

- `InvalidPackageSpec` — the spec itself is malformed.
- `Network` / `Manifest` / `NotFound` — registry transport and shape.
- `Extraction` / `ExtractionLimit` — archive unpacking, split so limits are
  distinguishable from corrupt input.
- `Verification` — integrity or attestation mismatch.
- `Store` / `Policy` / `Advisory` / `Provenance` — the four subsystems.

## How to get to it (user POV)

Every variant's `Display` is what a user sees, printed by `main()` as
`error: {e:#}`. Trigger examples:

```sh
./target/debug/blueline review 'no-such-pkg-xyz'      # NotFound
./target/debug/blueline review ''                      # clap rejects before this
./target/debug/blueline review --policy /nope.toml x    # Policy
```

## Driving it

No flags. `src/error.rs` is 39 lines and has no `#[cfg(test)]` module.

## Gotchas

**`{e:#}` at the `main()` boundary is mandatory, not cosmetic.** `main.rs`
prints `error: {e:#}`, the alternate form, so the whole `anyhow` context chain
renders. Change it to `{e}` and every user-facing error loses its cause. AGENTS.md
calls this out explicitly.

**`InvalidJson` uses a manual `From` instead of `#[from]` — on purpose.**
`lockfile.rs:22-24` and its test `invalid_json_has_no_source_chain` document it:
the `Display` already embeds the `serde_json` detail, and `#[from]` would *also*
attach it as `source()`, so `{e:#}` would print the detail twice. The same
reasoning is why some boundary errors carry wrapped inner text in their own
`String` rather than a nested source.

**`NotFound` is distinct from `Network` on purpose.** CHANGELOG 0.3.0 records
the fix: registry 404s must say "package not found in registry" instead of
surfacing as a generic network error. If you collapse these, that UX regression
returns.

**`ExtractionLimit` is separate from `Extraction` so caps are auditable.** Every
size/count/ratio bound raises `ExtractionLimit`, including non-archive bounds:
`registry::http_util::download_bounded` raises it for an oversized HTTP body, and
`registry::aur` raises it for git stdout exceeding its cap. A byte cap is not an
archive problem.

**`Verification` covers integrity *and* attestation.** `dist.integrity` sha512
mismatch, cargo `cksum` sha256 mismatch, PyPI sha256 mismatch, AUR resolve-time
sha256, provenance digest mismatch, and `registry_signature_present` refusal all
land here. Note the distinction: `provenance.rs` reports *status* in its own
`ProvenanceReport` (surfaced as findings), and only its hard refusals raise
`Verification`.

**`Advisory` and `Provenance` are used for lookup failure, not for hits.** A
malware hit is a *finding* in the heuristic (see
[heuristic](heuristic.md) rules 2-4), not an error. `Advisory`/`Provenance`
mean "I could not ask the question", which under `fail_closed_network` becomes a
refusal rather than a clean result.

**The doc comment is aspirational.** It says "the `blueline` binary maps these
into `anyhow` contexts; CI/MCP surfaces (later phases) can branch on the
variants." No caller branches on a variant — `main` prints `{e:#}` and exits 1.
Do not add a branch without deciding what CI should do about it.

**`main()` exits 1 for every error.** There is no exit-2 path outside
`agent review`/`agent gate`, which return their own codes from inside
[agent](agent.md). So a CI-gate failure and an operational crash are
indistinguishable by exit code — only the message differs.

**No variant exists for a policy violation.** `blocklist` hits become
`P01_PACKAGE_BLOCKED` findings and a BLOCK band, not an error. A blocked package
still produces a full renderable verdict. Do not "simplify" this into an early
return; CI reports depend on getting a verdict for blocked packages.