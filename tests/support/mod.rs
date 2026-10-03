//! Reproducible attack-scenario harness for the blueline CLI.
//!
//! Every integration test in `tests/` used to hand-roll its own fixture
//! registry: bind loopback, answer `/{name}` with a packument, answer
//! `/{name}/-/{name}-{version}.tgz` with a tarball, hash it with sha512, and
//! point the CLI at the result. This module factors that scaffolding into one
//! composable API so `tests/scenarios.rs` can state *what the attack is* and
//! nothing else:
//!
//! - [`ReleaseBuilder`] composes a release under attack (manifest fields,
//!   lifecycle scripts, hostile tar entries, a forged integrity advertisement)
//!   into a [`Release`].
//! - [`Registry`] serves a set of releases over loopback HTTP and records every
//!   request and every peer address it saw.
//! - [`AurRegistry`] serves the AUR RPC endpoint plus a bare git repo over
//!   smart HTTP, which is how AUR releases are actually reviewed.
//! - [`RecallService`] serves a curated revocation snapshot.
//! - [`Cli`] runs the real binary against any of those, and [`Run`] reads the
//!   result back as a typed [`Verdict`].
//!
//! Hermeticity is structural, not conventional: every listener binds
//! `127.0.0.1:0`, every connection's peer address is checked and recorded, and
//! `scenario_harness_never_opens_a_non_loopback_socket` in `scenarios.rs`
//! fails if any of it is not true.

// This module is a harness, not production code: it is deliberately broader
// than the scenarios that consume it today, because the next attack scenario
// should be able to compose a new archive shape or a new verdict accessor
// instead of hand-rolling a second registry. `-D warnings` would otherwise
// make that breadth a build failure and push the code back into copy-paste.
// The allow is scoped to this module and its submodules only.
#![allow(dead_code)]

mod aur;
mod cli;
mod registry;
mod tarball;

// Re-exported as one flat surface so a scenario reads as a statement about the
// attack, not a tour of the module tree. Not every scenario needs every type;
// that is the harness's job, not the scenario's.
#[allow(unused_imports)]
pub use aur::{AurRegistry, AurRevision};
#[allow(unused_imports)]
pub use cli::{Band, Cli, Run, Verdict};
#[allow(unused_imports)]
pub use registry::{RecallService, Registry};
#[allow(unused_imports)]
pub use tarball::{
    Entry, EntryKind, Release, ReleaseBuilder, gzip, pad_to_512, pax_record, raw_header, sha512_sri,
};

use std::path::{Path, PathBuf};

/// Process exit code for a held/blocked verdict (`agent review` BLOCK, and
/// `review --yes` refusing anything above LOW).
pub const EXIT_BLOCKED: i32 = 2;

/// Process exit code for an engine refusal that never produced a verdict:
/// integrity mismatch, refused extraction, bad policy.
pub const EXIT_ERROR: i32 = 1;

/// An empty directory the harness owns, used to prove that a hostile archive
/// escaped nothing: the scenario names the probe path it wants an attack to
/// write, and [`Probe::assert_untouched`] checks the directory is still empty
/// after the engine ran.
///
/// A `TempDir` alone is not enough — the point is the *specific* directory an
/// absolute-path or `..` entry would land in, so the assertion is about
/// attacker-chosen coordinates rather than "the tempdir looks clean".
#[derive(Debug)]
pub struct Probe {
    dir: tempfile::TempDir,
}

impl Default for Probe {
    fn default() -> Probe {
        Probe::new()
    }
}

impl Probe {
    pub fn new() -> Probe {
        Probe {
            dir: tempfile::tempdir().expect("create escape probe dir"),
        }
    }

    /// Absolute path of the probe directory, for embedding in a raw tar entry.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Absolute path of a file inside the probe directory that must never
    /// come into existence.
    pub fn sentinel(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The probe must still be empty: nothing the archive named was written.
    pub fn assert_untouched(&self) {
        let leftovers: Vec<_> = std::fs::read_dir(self.path())
            .expect("read probe dir")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        assert!(
            leftovers.is_empty(),
            "the archive escaped its sandbox: probe {} now holds {leftovers:?}",
            self.path().display()
        );
    }
}
