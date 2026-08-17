# Phase 3 Research: CI Hardening, Cargo-Deny & Untrusted Parsing Fuzzing

**Topic:** Automated supply chain defense, license validation, advisory checking, and `cargo-fuzz` property testing.  
**Compiled:** 2026-08-17 · **Status:** Implementation Research (CDRes Mode 4)

---

## 1. The Task & Scope

Elevate Blueline's internal CI and security guarantees to the top-tier standard required for a security CLI parsing hostile archives:
1. **`cargo-deny` Integration:**
   - Policy file `deny.toml` at repository root.
   - Enforce acceptable open-source licenses (MIT, Apache-2.0, BSD-3-Clause, ISC, Unicode-DFS-2016).
   - Detect banned crates, duplicate dependencies, and RUSTSEC advisories.
2. **`cargo-fuzz` Fuzzing Suite (`fuzz/` crate):**
   - Independent sub-crate (`fuzz/Cargo.toml`) utilizing `libfuzzer-sys`.
   - Continuous property fuzzing on `extract::safe_extract` (feeding malformed/hostile tar.gz streams) and `manifest::read_package_json` (feeding malformed JSON tokens, recursion attacks, huge keys).
   - Verification assertion: parser/extractor NEVER panics, never violates directory boundaries, and enforces memory caps.

---

## 2. Common Gotchas

1. **Nightly Toolchain Requirement for `cargo-fuzz`:**
   - *Gotcha:* `cargo-fuzz` requires `rustc` nightly with libFuzzer sanitizers. The main Blueline repository is pinned to stable Rust (`rust-toolchain.toml`).
   - *Source:* `cargo-fuzz` documentation.
   - *Mitigation:* Pin nightly inside `fuzz/rust-toolchain.toml` or execute fuzzing in a dedicated CI job (`dtolnay/rust-toolchain@nightly`) so main development remains locked to stable.

2. **`cargo-deny` License Whitelist Maintenance:**
   - *Gotcha:* Transitive dependencies in Rust often introduce permissive variants (e.g. `CC0-1.0`, `Zlib`, `Apache-2.0 WITH LLVM-exception`). A strict whitelist that is too narrow breaks CI builds on routine dependency updates.
   - *Source:* `cargo-deny` configuration guide.
   - *Mitigation:* Seed `deny.toml` from a comprehensive permissive license set and run `cargo deny check licenses` across the entire dependency graph.

3. **Fuzzing Seed Corpus Management:**
   - *Gotcha:* Fuzzing from a blank slate takes longer to explore deep decompression code paths.
   - *Mitigation:* Seed the `fuzz/corpus/safe_extract` directory with valid minimal tar.gz archives (single file, deep tree, binary payload, malicious paths) from `tests/fixtures`.

---

## 3. Best Practices

- **License policy (`deny.toml`):**
  ```toml
  [licenses]
  allow = [
      "MIT",
      "Apache-2.0",
      "BSD-2-Clause",
      "BSD-3-Clause",
      "ISC",
      "Unicode-DFS-2016",
      "CC0-1.0"
  ]
  confidence-threshold = 0.8
  ```
- **Fuzz target design (`fuzz/fuzz_targets/safe_extract.rs`):**
  ```rust
  #![no_main]
  use libfuzzer_sys::fuzz_target;
  use blueline::extract::{safe_extract, ExtractLimits};

  fuzz_target!(|data: &[u8]| {
      let temp = tempfile::tempdir().unwrap();
      let limits = ExtractLimits::default();
      // Must not panic under any hostile byte stream
      let _ = safe_extract(data, temp.path(), &limits);
  });
  ```

---

## Adversarial Verification
- Dependency isolation: Fuzzing crate dependencies do not bleed into the production release binary.
- Policy stability: `cargo deny check` verified against current `Cargo.lock`.
- Status: GREEN
