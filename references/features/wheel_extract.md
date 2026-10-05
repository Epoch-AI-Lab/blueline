# Wheel Extract

`src/wheel_extract.rs` is one line:

```rust
pub use crate::extract::safe_extract_wheel;
```

That is the entire file. It exists so callers can name the wheel path without
knowing it lives in [extract](extract.md), and so `lib.rs` can declare a
`wheel_extract` module. There is no logic, no state, and no tests here.

**All behaviour, all bounds, and all gotchas are in
[extract](extract.md) under "Wheel path (`safe_extract_wheel`)".** Do not
duplicate them.

## Sub-features

- Nothing. A single `pub use` re-export.

## How to get to it (user POV)

None. No CLI flag reaches it. It runs inside PyPI reviews, after the sha256
check and before the diff.

## Driving it

```sh
./target/debug/blueline --ecosystem pypi review <package>@<version>
```

## Gotchas

**Prefer reading `extract::safe_extract_wheel` directly if you are changing
behaviour.** A grep that finds the function here will mislead you — the body is
400 lines away in `extract.rs`, under `mod wheel_tests`' jurisdiction.

**Mutation scope includes this file (`src/**/*.rs`) but there is nothing to
mutate.** A "test coverage" argument based on this file's existence is wrong;
the coverage lives in `extract.rs`'s 20 `wheel_tests`.

**It is a `pub use`, not a wrapper.** Adding a doc comment or a bound here
changes the public re-export surface without changing behaviour — and there is
no test that would notice.

**The wheel path is strictly stricter than the tar path.** If you are comparing
the two, the wheel path adds: NUL-in-raw-name, `encrypted()`, a compression
allowlist (`Stored | Deflated` only), `enclosed_name()`, duplicate normalized
keys, `is_symlink()`, a non-zero-size directory check, and a *second* total-byte
cap enforced against actual inflated bytes during the read loop. See
[extract](extract.md).