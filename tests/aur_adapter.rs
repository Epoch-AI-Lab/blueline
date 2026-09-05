//! End-to-end AUR adapter CLI test. The adapter's git/archive behavior is
//! covered by unit tests with local git fixtures in `src/registry/aur.rs`;
//! this file only proves the CLI entry point fails closed cleanly when the
//! configured AUR base is unreachable.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn review_fails_closed_cleanly_when_aur_base_is_unreachable() {
    let isolated = tempfile::tempdir().unwrap();
    Command::cargo_bin("blueline")
        .unwrap()
        .env("BLUELINE_DATA_DIR", isolated.path())
        .args([
            "--ecosystem",
            "aur",
            "--registry",
            "http://127.0.0.1:1",
            "review",
            "ghost-package@1.0.0-1",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("AUR"));
}
