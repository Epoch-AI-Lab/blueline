//! End-to-end AUR CLI surface tests. `install` refuses AUR before any
//! network use (building a PKGBUILD executes its shell script), and `ci`
//! rejects the ecosystem (no AUR lockfile format exists to diff). Adapter
//! behavior lives in `src/registry/aur.rs` unit tests and
//! `tests/aur_adapter.rs`.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn install_refuses_aur_before_any_network_use() {
    Command::cargo_bin("blueline")
        .unwrap()
        .args(["--ecosystem", "aur", "install", "yay@12.4.2-1", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "blueline install refuses AUR packages",
        ))
        .stderr(predicate::str::contains("executes its PKGBUILD"));
}

#[test]
fn ci_rejects_aur_ecosystem() {
    let isolated = tempfile::tempdir().unwrap();
    Command::cargo_bin("blueline")
        .unwrap()
        .env("BLUELINE_DATA_DIR", isolated.path())
        .args([
            "--ecosystem",
            "aur",
            "ci",
            "--lockfile",
            "package-lock.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("AUR CI scanning is not supported"));
}
