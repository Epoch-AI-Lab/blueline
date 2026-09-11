//! End-to-end AUR CLI surface tests. `install` refuses AUR before any
//! network use (building a PKGBUILD executes its shell script), and `ci`
//! accepts a pin file of `pkgbase@pkgver-pkgrel` lines to diff. Adapter
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

fn init_aur_ci_repo(dir: &Path, base_content: &str, head_content: &str) {
    fixture_git(dir, &["init", "--quiet", "-b", "main"]);
    fixture_git(dir, &["config", "user.email", "alice@example.com"]);
    fixture_git(dir, &["config", "user.name", "Fixture"]);
    fixture_git(dir, &["config", "commit.gpgsign", "false"]);
    std::fs::write(dir.join("aur.lock"), base_content).unwrap();
    fixture_git(dir, &["add", "-A"]);
    fixture_git(dir, &["commit", "--quiet", "-m", "base pins"]);
    std::fs::write(dir.join("aur.lock"), head_content).unwrap();
}

#[test]
fn ci_aur_passes_when_pins_are_unchanged() {
    let repo = tempfile::tempdir().unwrap();
    init_aur_ci_repo(repo.path(), "demopkg@1.0-1\n", "demopkg@1.0-1\n");
    let isolated = tempfile::tempdir().unwrap();
    Command::cargo_bin("blueline")
        .unwrap()
        .current_dir(repo.path())
        .env("BLUELINE_DATA_DIR", isolated.path())
        .args([
            "--ecosystem",
            "aur",
            "ci",
            "--lockfile",
            "aur.lock",
            "--base",
            "HEAD",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASSED"));
}

#[test]
fn ci_aur_rejects_malformed_pin_file() {
    let repo = tempfile::tempdir().unwrap();
    init_aur_ci_repo(repo.path(), "demopkg@1.0-1\n", "demopkg@1.0-1\nnot a pin\n");
    let isolated = tempfile::tempdir().unwrap();
    Command::cargo_bin("blueline")
        .unwrap()
        .current_dir(repo.path())
        .env("BLUELINE_DATA_DIR", isolated.path())
        .args([
            "--ecosystem",
            "aur",
            "ci",
            "--lockfile",
            "aur.lock",
            "--base",
            "HEAD",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("line 2"));
}

#[test]
fn ci_aur_evaluates_added_pin() {
    let fixture = spawn_aur_review_fixture();
    let repo = tempfile::tempdir().unwrap();
    init_aur_ci_repo(repo.path(), "# pins\n", "demopkg@1.1-1\n");
    let isolated = tempfile::tempdir().unwrap();
    Command::cargo_bin("blueline")
        .unwrap()
        .current_dir(repo.path())
        .env("BLUELINE_DATA_DIR", isolated.path())
        .args([
            "--ecosystem",
            "aur",
            "--registry",
            &fixture.base,
            "ci",
            "--lockfile",
            "aur.lock",
            "--base",
            "HEAD",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("demopkg"))
        .stdout(predicate::str::contains("1.1-1"));
}

#[test]
fn ci_aur_evaluates_upgraded_pin() {
    let fixture = spawn_aur_review_fixture();
    let repo = tempfile::tempdir().unwrap();
    init_aur_ci_repo(repo.path(), "demopkg@1.0-1\n", "demopkg@1.1-1\n");
    let isolated = tempfile::tempdir().unwrap();
    Command::cargo_bin("blueline")
        .unwrap()
        .current_dir(repo.path())
        .env("BLUELINE_DATA_DIR", isolated.path())
        .args([
            "--ecosystem",
            "aur",
            "--registry",
            &fixture.base,
            "ci",
            "--lockfile",
            "aur.lock",
            "--base",
            "HEAD",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("demopkg"))
        .stdout(predicate::str::contains("1.0-1"));
}

#[test]
fn ci_aur_missing_base_reviews_head_pins() {
    let repo = tempfile::tempdir().unwrap();
    fixture_git(repo.path(), &["init", "--quiet", "-b", "main"]);
    fixture_git(repo.path(), &["config", "user.email", "alice@example.com"]);
    fixture_git(repo.path(), &["config", "user.name", "Fixture"]);
    fixture_git(repo.path(), &["config", "commit.gpgsign", "false"]);
    std::fs::write(repo.path().join("other.txt"), "unrelated\n").unwrap();
    fixture_git(repo.path(), &["add", "-A"]);
    fixture_git(repo.path(), &["commit", "--quiet", "-m", "no pins yet"]);
    std::fs::write(repo.path().join("aur.lock"), "# none yet\n").unwrap();
    let isolated = tempfile::tempdir().unwrap();
    Command::cargo_bin("blueline")
        .unwrap()
        .current_dir(repo.path())
        .env("BLUELINE_DATA_DIR", isolated.path())
        .args([
            "--ecosystem",
            "aur",
            "ci",
            "--lockfile",
            "aur.lock",
            "--base",
            "HEAD",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASSED"));
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
/// over smart HTTP (`git upload-pack --stateless-rpc`, the protocol real AUR
/// uses — shallow clones are impossible over dumb HTTP) from the same base
/// (one `--registry`). Two commits,
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

/// Read one HTTP request off the stream: headers through the blank line,
/// then the full `Content-Length` body. Returns (body offset, buffer).
fn read_http_request(stream: &mut TcpStream) -> Option<(usize, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 65_536 {
            return None;
        }
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let headers = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let content_length: usize = headers
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + content_length {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Some((head_end, buf))
}

/// One stateless `git upload-pack` round: feed the request body on stdin,
/// return the response bytes. `--advertise-refs` serves the info/refs GET.
fn upload_pack(bare: &Path, advertise: bool, body: &[u8]) -> Option<Vec<u8>> {
    let mut args = vec!["upload-pack", "--stateless-rpc"];
    if advertise {
        args.push("--advertise-refs");
    }
    let mut child = std::process::Command::new("git")
        .args(&args)
        .arg(".")
        .current_dir(bare)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(body).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

fn serve_aur(stream: &mut TcpStream, rpc: &str, bare: &Path) {
    let Some((head_end, req)) = read_http_request(stream) else {
        return;
    };
    let request = String::from_utf8_lossy(&req);
    let path = request
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let is_gzip = request[..head_end]
        .to_ascii_lowercase()
        .contains("content-encoding: gzip");
    let body = req[head_end..].to_vec();
    let (status, ctype, out) = if path.starts_with("/rpc/v5/info") {
        ("200 OK", "application/json", rpc.as_bytes().to_vec())
    } else if path.split('?').next() == Some("/demopkg.git/info/refs") {
        match upload_pack(bare, true, b"") {
            Some(adv) => {
                // Smart-HTTP advertisement: the service pkt-line the client
                // expects before upload-pack's ref advertisement.
                let mut body = b"001e# service=git-upload-pack\n0000".to_vec();
                body.extend_from_slice(&adv);
                (
                    "200 OK",
                    "application/x-git-upload-pack-advertisement",
                    body,
                )
            }
            None => (
                "500 Internal Server Error",
                "text/plain",
                b"upload-pack failed".to_vec(),
            ),
        }
    } else if path == "/demopkg.git/git-upload-pack" {
        let mut body = body;
        if is_gzip {
            let mut plain = Vec::new();
            if std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&body[..]), &mut plain)
                .is_err()
            {
                return;
            }
            body = plain;
        }
        match upload_pack(bare, false, &body) {
            Some(out) => ("200 OK", "application/x-git-upload-pack", out),
            None => (
                "500 Internal Server Error",
                "text/plain",
                b"upload-pack failed".to_vec(),
            ),
        }
    } else {
        ("404 Not Found", "text/plain", b"nope".to_vec())
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        out.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&out);
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
