//! End-to-end AUR CLI surface tests. `install` refuses AUR before any
//! network use (building a PKGBUILD executes its shell script), and `ci`
//! rejects the ecosystem (no AUR lockfile format exists to diff). Adapter
//! behavior lives in `src/registry/aur.rs` unit tests and
//! `tests/aur_adapter.rs`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;

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

struct AurReviewFixture {
    base: String,
    _server: std::thread::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

fn fixture_git(dir: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_fixture_pkg(repo: &Path, pkgver: &str, keys: &str) {
    std::fs::write(
        repo.join("PKGBUILD"),
        format!(
            "pkgname=demopkg\npkgver={pkgver}\npkgrel=1\narch=('any')\n\
             source=(https://good.example/demopkg-{pkgver}.tar.gz)\n\
             sha256sums=(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n\
             validpgpkeys=({keys})\nbuild() {{\n make\n}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        repo.join(".SRCINFO"),
        format!("pkgbase = demopkg\n\tpkgver = {pkgver}\n\tpkgrel = 1\n"),
    )
    .unwrap();
}

/// Offline end-to-end AUR review: loopback RPC plus a bare git repo served
/// over dumb HTTP from the same base (one `--registry`). Two commits,
/// 1.0-1 then 1.1-1, differing only in `validpgpkeys`, so reviewing 1.1-1
/// must surface the R19 pair finding on top of the R07 unreviewed-baseline
/// finding and the R00 scope disclosure.
fn spawn_aur_review_fixture() -> AurReviewFixture {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    fixture_git(&work, &["init", "--quiet", "-b", "master"]);
    fixture_git(&work, &["config", "user.email", "alice@example.com"]);
    fixture_git(&work, &["config", "user.name", "Fixture"]);
    fixture_git(&work, &["config", "commit.gpgsign", "false"]);
    write_fixture_pkg(&work, "1.0", "AAA");
    fixture_git(&work, &["add", "-A"]);
    fixture_git(&work, &["commit", "--quiet", "-m", "demopkg 1.0-1"]);
    write_fixture_pkg(&work, "1.1", "BBB");
    fixture_git(&work, &["add", "-A"]);
    fixture_git(&work, &["commit", "--quiet", "-m", "demopkg 1.1-1"]);
    let bare = dir.path().join("demopkg.git");
    fixture_git(
        dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            work.to_str().unwrap(),
            bare.to_str().unwrap(),
        ],
    );
    fixture_git(&bare, &["update-server-info"]);

    let rpc = serde_json::json!({
        "version": 5,
        "type": "multiinfo",
        "resultcount": 1,
        "results": [{
            "ID": 1,
            "Name": "demopkg",
            "PackageBaseID": 1,
            "PackageBase": "demopkg",
            "Version": "1.1-1",
            "Description": "fixture",
            "Maintainer": "alice"
        }]
    })
    .to_string();
    let rpc = Arc::new(rpc);
    let bare = Arc::new(bare);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let rpc = rpc.clone();
            let bare = bare.clone();
            std::thread::spawn(move || serve_aur(&mut stream, &rpc, &bare));
        }
    });
    AurReviewFixture {
        base,
        _server: handle,
        _dir: dir,
    }
}

/// Single-commit variant: reviewing 1.0-1 has no baseline, so pair
/// rules must stay silent while target checks and disclosure still run.
fn spawn_aur_first_sighting_fixture() -> AurReviewFixture {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    fixture_git(&work, &["init", "--quiet", "-b", "master"]);
    fixture_git(&work, &["config", "user.email", "alice@example.com"]);
    fixture_git(&work, &["config", "user.name", "Fixture"]);
    fixture_git(&work, &["config", "commit.gpgsign", "false"]);
    write_fixture_pkg(&work, "1.0", "AAA");
    fixture_git(&work, &["add", "-A"]);
    fixture_git(&work, &["commit", "--quiet", "-m", "demopkg 1.0-1"]);
    let bare = dir.path().join("demopkg.git");
    fixture_git(
        dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            work.to_str().unwrap(),
            bare.to_str().unwrap(),
        ],
    );
    fixture_git(&bare, &["update-server-info"]);

    let rpc = serde_json::json!({
        "version": 5,
        "type": "multiinfo",
        "resultcount": 1,
        "results": [{
            "ID": 1,
            "Name": "demopkg",
            "PackageBaseID": 1,
            "PackageBase": "demopkg",
            "Version": "1.0-1",
            "Description": "fixture",
            "Maintainer": "alice"
        }]
    })
    .to_string();
    let rpc = Arc::new(rpc);
    let bare = Arc::new(bare);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let rpc = rpc.clone();
            let bare = bare.clone();
            std::thread::spawn(move || serve_aur(&mut stream, &rpc, &bare));
        }
    });
    AurReviewFixture {
        base,
        _server: handle,
        _dir: dir,
    }
}

fn serve_aur(stream: &mut TcpStream, rpc: &str, bare: &Path) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 65_536 {
                    return;
                }
            }
        }
    }
    let req = String::from_utf8_lossy(&buf);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/");
    let (status, ctype, body) = if path.starts_with("/rpc/v5/info") {
        ("200 OK", "application/json", rpc.as_bytes().to_vec())
    } else if let Some(rel) = path
        .split('?')
        .next()
        .and_then(|p| p.strip_prefix("/demopkg.git/"))
    {
        match std::fs::read(bare.join(rel)) {
            Ok(bytes) => ("200 OK", "application/octet-stream", bytes),
            Err(_) => ("404 Not Found", "text/plain", b"nope".to_vec()),
        }
    } else {
        ("404 Not Found", "text/plain", b"nope".to_vec())
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
}

fn review_json(fixture: &AurReviewFixture) -> serde_json::Value {
    let data_dir = tempfile::tempdir().unwrap();
    let output = Command::cargo_bin("blueline")
        .unwrap()
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .args([
            "--ecosystem",
            "aur",
            "--registry",
            &fixture.base,
            "review",
            "demopkg@1.1-1",
            "--output",
            "json",
            "--yes",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    serde_json::from_str(&String::from_utf8(output).unwrap()).expect("valid json")
}

fn rule_present(json: &serde_json::Value, rule: &str) -> bool {
    json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["rule_id"] == rule)
}

/// Pins the AUR findings gate: flipping it drops every pkgbuild finding.
#[test]
fn aur_review_surfaces_pkgbuild_findings() {
    let fixture = spawn_aur_review_fixture();
    let json = review_json(&fixture);
    assert_eq!(json["baseline_version"], "1.0-1");
    assert!(
        rule_present(&json, "R00_PKGBUILD_SCOPE"),
        "AUR review must carry pkgbuild findings: {json}"
    );
}

/// Pins first-sighting behavior: no baseline means no pair findings, but
/// target checks and the scope disclosure still run.
#[test]
fn aur_first_sighting_skips_pair_rules() {
    let fixture = spawn_aur_first_sighting_fixture();
    let data_dir = tempfile::tempdir().unwrap();
    let output = Command::cargo_bin("blueline")
        .unwrap()
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .args([
            "--ecosystem",
            "aur",
            "--registry",
            &fixture.base,
            "review",
            "demopkg@1.0-1",
            "--output",
            "json",
            "--yes",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8(output).unwrap()).expect("valid json");
    assert!(rule_present(&json, "R00_PKGBUILD_SCOPE"));
    assert!(!rule_present(&json, "R19_VALIDPGPKEYS_CHANGE"));
    assert!(!rule_present(&json, "R12_SOURCE_URL_DRIFT"));
}

/// Pins baseline PKGBUILD capture: without it the R12/R19 pair rules starve.
#[test]
fn aur_review_surfaces_baseline_pair_findings() {
    let fixture = spawn_aur_review_fixture();
    let json = review_json(&fixture);
    assert!(
        rule_present(&json, "R19_VALIDPGPKEYS_CHANGE"),
        "key change 1.0-1 -> 1.1-1 must surface: {json}"
    );
}
