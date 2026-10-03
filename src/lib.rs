#![forbid(unsafe_code)]
// Activated by `disallowed-methods` in clippy.toml. Tests are exempt via
// `allow-unwrap-in-tests`; `expect_used` is deliberately not denied
// crate-wide — see the comment in clippy.toml.
#![deny(clippy::unwrap_used)]

pub mod advisory;
pub mod agent;
pub mod baseline;
pub mod ci;
pub mod cli;
pub mod diff;
pub mod error;
pub mod executor;
pub mod extract;
pub mod heuristic;
pub mod install_ref;
pub mod lockfile;
pub mod manifest;
pub mod mcp;
pub mod pkgbuild;
pub mod policy;
pub mod provenance;
pub mod recall;
pub mod recursive;
pub mod registry;
pub mod render;
pub mod review;
pub mod shim;
pub mod store;
pub mod verdict;
pub mod version;
pub mod wheel_extract;
