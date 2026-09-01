//! End-to-end AUR CLI surface tests. PR1 scope: `--ecosystem aur` is
//! accepted, `install` refuses AUR before any network use, and `review`
//! fails closed while the AUR adapter is still under construction.

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
fn review_fails_closed_while_adapter_is_unbuilt() {
    let isolated = tempfile::tempdir().unwrap();
    Command::cargo_bin("blueline")
        .unwrap()
        .env("BLUELINE_DATA_DIR", isolated.path())
        .args(["--ecosystem", "aur", "review", "yay@12.4.2-1", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "AUR reviews are not supported yet",
        ));
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
