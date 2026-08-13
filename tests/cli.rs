use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use assert_cmd::Command;
use base64::Engine;
use predicates::prelude::*;
use sha2::{Digest, Sha512};

struct Fixture {
    base: String,
    _server: std::thread::JoinHandle<()>,
}

/// Mini HTTP/1.1 server: answers the packument at `/express` and the tarball
/// at `/express/-/express-<version>.tgz`. No external network.
///
/// The server binds first so the packument can embed the real base URL.
fn spawn_fixture<F>(pack_fn: F, tarball: Vec<u8>) -> Fixture
where
    F: FnOnce(&str) -> String + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let pack = Arc::new(pack_fn(&base));
    let tar = Arc::new(tarball);
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let pack = pack.clone();
            let tar = tar.clone();
            std::thread::spawn(move || serve(&mut stream, &pack, &tar));
        }
    });
    Fixture {
        base,
        _server: handle,
    }
}

fn serve(stream: &mut TcpStream, pack: &str, tar: &[u8]) {
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
    let (body, ctype) = if path.ends_with(".tgz") {
        (tar.to_vec(), "application/octet-stream")
    } else {
        (pack.as_bytes().to_vec(), "application/json")
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
}

fn make_tarball() -> Vec<u8> {
    make_tarball_with(b"module.exports = {};")
}

fn make_tarball_with(code: &[u8]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let pkg_json = br#"{
        "name": "express",
        "version": "4.21.2",
        "scripts": { "preinstall": "echo hi", "postinstall": "node install.js" },
        "dependencies": { "cookie": "0.7.1" }
    }"#;
    let mut h = tar::Header::new_gnu();
    h.set_size(pkg_json.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder
        .append_data(&mut h, "package/package.json", &pkg_json[..])
        .unwrap();

    let mut h2 = tar::Header::new_gnu();
    h2.set_size(code.len() as u64);
    h2.set_mode(0o644);
    h2.set_cksum();
    builder
        .append_data(&mut h2, "package/lib/index.js", code)
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap()
}

fn sha512_b64(data: &[u8]) -> String {
    let digest = Sha512::digest(data);
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

fn packument(base: &str, version: &str, integrity: &str) -> String {
    serde_json::json!({
        "name": "express",
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": "express",
                "version": version,
                "dist": {
                    "tarball": format!("{base}/express/-/express-{version}.tgz"),
                    "integrity": integrity,
                    "shasum": "0".repeat(40)
                }
            }
        }
    })
    .to_string()
}

fn blueline() -> Command {
    Command::cargo_bin("blueline").unwrap()
}

#[test]
fn help_lists_review_subcommand() {
    blueline()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("review").and(predicate::str::contains("--registry")));
}

#[test]
fn review_requires_version() {
    blueline()
        .args(["review", "express"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("expected `<name>@<version>`"));
}

#[test]
fn full_flow_json_output() {
    let tarball = make_tarball();
    let integrity = sha512_b64(&tarball);
    let pack_integrity = integrity.clone();
    let fixture = spawn_fixture(
        move |base| packument(base, "4.21.2", &pack_integrity),
        tarball,
    );

    let data_dir = tempfile::tempdir().unwrap();
    let output = blueline()
        .args([
            "review",
            "express@4.21.2",
            "--registry",
            &fixture.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let output = String::from_utf8(output).unwrap();

    let json: serde_json::Value = serde_json::from_str(&output).expect("stdout must be valid JSON");
    assert_eq!(json["name"], "express");
    assert_eq!(json["version"], "4.21.2");
    assert_eq!(json["integrity"], "verified (sha512)");
    assert_eq!(json["files"], 2);
    assert_eq!(json["lifecycle_scripts"].as_array().unwrap().len(), 2);
    assert_eq!(json["baseline"], "verified; no clean verdict yet");

    // The witness record exists and is explicitly unclean: a review must not
    // bless the version it merely looked at.
    let db_path = data_dir.path().join("baseline.db");
    assert!(db_path.exists(), "baseline.db must exist");
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let (name, version, integrity_row, clean): (String, String, String, i64) = conn
        .query_row(
            "SELECT name, version, integrity, clean FROM known_clean WHERE name = 'express'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(name, "express");
    assert_eq!(version, "4.21.2");
    assert_eq!(integrity_row, integrity);
    assert_eq!(clean, 0, "review records evidence, never a clean blessing");
}

#[test]
fn text_output_lists_install_scripts() {
    let tarball = make_tarball();
    let integrity = sha512_b64(&tarball);
    let fixture = spawn_fixture(move |base| packument(base, "4.21.2", &integrity), tarball);

    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args([
            "review",
            "express@4.21.2",
            "--registry",
            &fixture.base,
            "--output",
            "text",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("reviewed express@4.21.2")
                .and(predicate::str::contains(
                    "integrity:      verified (sha512)",
                ))
                .and(predicate::str::contains(
                    "install script: preinstall, postinstall",
                ))
                .and(predicate::str::contains(
                    "baseline:       verified; no clean verdict yet",
                )),
        );
}

#[test]
fn tampered_tarball_fails_closed() {
    let tarball = make_tarball();
    // The registry claims an integrity that does NOT match the served bytes.
    let forged_integrity =
        "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    let fixture = spawn_fixture(
        move |base| packument(base, "4.21.2", &forged_integrity),
        tarball,
    );

    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args(["review", "express@4.21.2", "--registry", &fixture.base])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("integrity verification failed"));
}

#[test]
fn republished_tarball_same_version_fails_closed() {
    let tarball_a = make_tarball();
    let tarball_b = make_tarball_with(b"module.exports = 2;");
    let integrity_a = sha512_b64(&tarball_a);
    let integrity_b = sha512_b64(&tarball_b);
    assert_ne!(integrity_a, integrity_b, "fixtures must differ");

    let data_dir = tempfile::tempdir().unwrap();

    // First review witnesses 4.21.2 with tarball A.
    let fixture_a = spawn_fixture(
        move |base| packument(base, "4.21.2", &integrity_a),
        tarball_a,
    );
    blueline()
        .args(["review", "express@4.21.2", "--registry", &fixture_a.base])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .success();

    // The registry now serves the same version string with different bytes.
    let fixture_b = spawn_fixture(
        move |base| packument(base, "4.21.2", &integrity_b),
        tarball_b,
    );
    blueline()
        .args(["review", "express@4.21.2", "--registry", &fixture_b.base])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("integrity changed"));
}
