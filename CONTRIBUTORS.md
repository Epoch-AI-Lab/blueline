# Contributors and guidelines

Blueline is maintained by Epoch AI Lab and community contributors.

## Maintainers

- Kriday Dave ([@kridaydave](https://github.com/kridaydave)) - Epoch AI Lab

## Core contributors

- Kriday Dave ([@kridaydave](https://github.com/kridaydave))

## Ground rules

Blueline is a security fail-closed CLI that parses untrusted third-party packages. A bug in extraction or verification is a security vulnerability. Keep these rules in mind before opening a pull request:

### 1. Fail closed on any doubt
Never guess what untrusted tarball bytes or manifests mean. If an archive entry has suspicious paths, symlinks, abnormal permissions, or corrupted headers, error out immediately.

### 2. Zero unsafe code
The repository compiles with `#![forbid(unsafe_code)]`. Pull requests introducing unsafe blocks will be rejected.

### 3. No unwrap on untrusted inputs
Never use `.unwrap()` or `.expect()` on data parsed from package registries, tarballs, or user configurations. Modules must return structured errors with `thiserror`, chained into `anyhow` at the CLI boundary.

### 4. Ask before adding dependencies
Dependencies expand our attack surface. Open an issue to discuss any new crate before adding it to `Cargo.toml`.

### 5. Passing CI is mandatory
Every pull request must pass the standard checks locally:
- `cargo fmt --all --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --all-targets --locked`

CI also runs mutation testing with `cargo-mutants` and supply-chain auditing with `cargo-audit`. Tests must cover both happy paths and malicious boundary cases.

## Contribution areas

We welcome contributions in:
- Risk scoring heuristics for package release diffs
- Registry adapters for PyPI, crates.io, and RubyGems
- Sandbox extraction hardening and archive bomb defenses
- Real-world supply-chain attack reproduction fixtures

## Getting listed

Add your name and GitHub profile link to the contributors list above in the pull request that ships your merged contribution.
