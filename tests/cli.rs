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
fn help_lists_review_and_install_subcommands() {
    blueline().arg("--help").assert().success().stdout(
        predicate::str::contains("review")
            .and(predicate::str::contains("install"))
            .and(predicate::str::contains("--registry")),
    );
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
        .code(2)
        .get_output()
        .stdout
        .clone();
    let output = String::from_utf8(output).unwrap();

    let json: serde_json::Value = serde_json::from_str(&output).expect("stdout must be valid JSON");
    assert_eq!(json["name"], "express");
    assert_eq!(json["target_version"], "4.21.2");
    assert_eq!(json["integrity"], "verified (sha512)");
    assert_eq!(json["band"], "BLOCK");
    assert!(json["risk_score"].as_u64().unwrap() >= 50);
    assert_eq!(json["diff_summary"]["files_added"], 2);

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
        .code(2)
        .stdout(
            predicate::str::contains("BLUELINE REVIEW: express@4.21.2")
                .and(predicate::str::contains("verified (sha512)"))
                .and(predicate::str::contains("BLOCK"))
                .and(predicate::str::contains("preinstall"))
                .and(predicate::str::contains("postinstall")),
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
        .code(2);

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

#[test]
fn reviews_delta_against_predecessor_baseline() {
    let tarball_v1 = make_tarball_with(b"module.exports = { version: 1 };");
    let tarball_v2 =
        make_tarball_with(b"module.exports = { version: 2 };\nconsole.log('updated');\n");
    let integ_v1 = sha512_b64(&tarball_v1);
    let integ_v2 = sha512_b64(&tarball_v2);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());

    let pack = serde_json::json!({
        "name": "express",
        "dist-tags": { "latest": "4.21.2" },
        "versions": {
            "4.21.1": {
                "name": "express",
                "version": "4.21.1",
                "dist": {
                    "tarball": format!("{base}/express/-/express-4.21.1.tgz"),
                    "integrity": integ_v1,
                    "shasum": "0".repeat(40)
                }
            },
            "4.21.2": {
                "name": "express",
                "version": "4.21.2",
                "dist": {
                    "tarball": format!("{base}/express/-/express-4.21.2.tgz"),
                    "integrity": integ_v2,
                    "shasum": "0".repeat(40)
                }
            }
        }
    })
    .to_string();

    let pack = Arc::new(pack);
    let tar_v1 = Arc::new(tarball_v1);
    let tar_v2 = Arc::new(tarball_v2);

    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let pack = pack.clone();
            let tar1 = tar_v1.clone();
            let tar2 = tar_v2.clone();
            std::thread::spawn(move || {
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
                let (body, ctype) = if path.contains("4.21.1.tgz") {
                    (tar1.to_vec(), "application/octet-stream")
                } else if path.contains("4.21.2.tgz") {
                    (tar2.to_vec(), "application/octet-stream")
                } else {
                    (pack.as_bytes().to_vec(), "application/json")
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            });
        }
    });

    let data_dir = tempfile::tempdir().unwrap();
    let output = blueline()
        .args([
            "review",
            "express@4.21.2",
            "--registry",
            &base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let output = String::from_utf8(output).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).expect("valid json");
    assert_eq!(json["name"], "express");
    assert_eq!(json["target_version"], "4.21.2");
    assert_eq!(json["baseline_version"], "4.21.1");
    assert_eq!(json["diff_summary"]["files_modified"], 1);
    assert_eq!(json["diff_summary"]["files_added"], 0);

    drop(handle);
}

#[test]
fn install_delegates_to_npm_with_ignore_scripts() {
    let temp_dir = tempfile::tempdir().unwrap();
    let log_file = temp_dir.path().join("npm_args.log");
    let mock_npm = temp_dir.path().join("mock-npm.sh");
    std::fs::write(
        &mock_npm,
        format!(
            "#!/bin/sh\necho \"$@\" > \"{}\"\nexit 0\n",
            log_file.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&mock_npm, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let pkg_json = br#"{"name":"safe-pkg","version":"1.0.0"}"#;
    let mut h = tar::Header::new_gnu();
    h.set_size(pkg_json.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder
        .append_data(&mut h, "package/package.json", &pkg_json[..])
        .unwrap();
    let tarball = builder.into_inner().unwrap().finish().unwrap();
    let integrity = sha512_b64(&tarball);
    let pack_integrity = integrity.clone();
    let fixture_integrity = pack_integrity.clone();
    let fixture = spawn_fixture(
        move |base| {
            serde_json::json!({
                "name": "safe-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "0.9.0": {
                        "name": "safe-pkg",
                        "version": "0.9.0",
                        "dist": {
                            "tarball": format!("{base}/safe-pkg/-/safe-pkg-1.0.0.tgz"),
                            "integrity": fixture_integrity,
                            "shasum": "0".repeat(40)
                        }
                    },
                    "1.0.0": {
                        "name": "safe-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base}/safe-pkg/-/safe-pkg-1.0.0.tgz"),
                            "integrity": fixture_integrity,
                            "shasum": "0".repeat(40)
                        }
                    }
                }
            })
            .to_string()
        },
        tarball,
    );

    let data_dir = tempfile::tempdir().unwrap();
    let db_path = data_dir.path().join("baseline.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 2;
         CREATE TABLE IF NOT EXISTS known_clean (
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            integrity TEXT NOT NULL,
            reviewed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            clean INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (name, version)
         ) STRICT;",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO known_clean (name, version, integrity, clean) VALUES ('safe-pkg', '0.9.0', ?1, 1)",
        [&pack_integrity],
    )
    .unwrap();
    blueline()
        .args([
            "install",
            "safe-pkg",
            "--registry",
            &fixture.base,
            "--",
            "--save-dev",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .env("npm_execpath", mock_npm.to_str().unwrap())
        .assert()
        .success();

    let logged_args = std::fs::read_to_string(&log_file).unwrap();
    assert!(
        logged_args.contains("install --ignore-scripts")
            && logged_args.contains("--registry")
            && logged_args.contains(&fixture.base)
            && logged_args.contains("safe-pkg@1.0.0")
            && logged_args.contains("--save-dev"),
        "npm must receive install --ignore-scripts, registry, and extra args, got: {logged_args}"
    );
}

#[test]
fn install_blocks_unapproved_in_non_interactive_mode() {
    let tarball = make_tarball();
    let integrity = sha512_b64(&tarball);
    let fixture = spawn_fixture(move |base| packument(base, "4.21.2", &integrity), tarball);

    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args(["install", "express@4.21.2", "--registry", &fixture.base])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("installation blocked"));
}

#[test]
fn node_shim_launches_binary_via_override() {
    let bin_path = assert_cmd::cargo::cargo_bin("blueline");
    let launcher_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("packages/blueline/bin/blueline.js");

    let mut cmd = std::process::Command::new("node");
    cmd.arg(launcher_path)
        .arg("--version")
        .env("BLUELINE_BINARY", bin_path);

    let output = cmd.output().expect("running node shim");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("blueline"));
}

#[test]
fn install_rejects_forbidden_override_flags() {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let pkg_json = br#"{"name":"safe-pkg-override","version":"1.0.0"}"#;
    let mut h = tar::Header::new_gnu();
    h.set_size(pkg_json.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder
        .append_data(&mut h, "package/package.json", &pkg_json[..])
        .unwrap();
    let tarball = builder.into_inner().unwrap().finish().unwrap();
    let integrity = sha512_b64(&tarball);
    let pack_integrity = integrity.clone();
    let db_integrity = integrity.clone();
    let fixture = spawn_fixture(
        move |base| {
            serde_json::json!({
                "name": "safe-pkg-override",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "0.9.0": {
                        "name": "safe-pkg-override",
                        "version": "0.9.0",
                        "dist": {
                            "tarball": format!("{base}/safe-pkg-override/-/safe-pkg-override-1.0.0.tgz"),
                            "integrity": pack_integrity,
                            "shasum": "0".repeat(40)
                        }
                    },
                    "1.0.0": {
                        "name": "safe-pkg-override",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base}/safe-pkg-override/-/safe-pkg-override-1.0.0.tgz"),
                            "integrity": pack_integrity,
                            "shasum": "0".repeat(40)
                        }
                    }
                }
            })
            .to_string()
        },
        tarball,
    );

    let data_dir = tempfile::tempdir().unwrap();
    let db_path = data_dir.path().join("baseline.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 2;
         CREATE TABLE IF NOT EXISTS known_clean (
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            integrity TEXT NOT NULL,
            reviewed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            clean INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (name, version)
         ) STRICT;",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO known_clean (name, version, integrity, clean) VALUES ('safe-pkg-override', '0.9.0', ?1, 1)",
        [&db_integrity],
    )
    .unwrap();
    for flag in [
        "--no-ignore-scripts",
        "--ignore-scripts=false",
        "--foreground-scripts",
        "--script-shell=/bin/sh",
    ] {
        blueline()
            .args([
                "install",
                "safe-pkg-override",
                "--registry",
                &fixture.base,
                "--",
                flag,
            ])
            .env("BLUELINE_DATA_DIR", data_dir.path())
            .assert()
            .failure()
            .stderr(predicate::str::contains("forbidden flag"));
    }
}

#[test]
fn review_handles_whitespace_padded_spec() {
    let tarball = make_tarball();
    let integrity = sha512_b64(&tarball);
    let fixture = spawn_fixture(move |base| packument(base, "4.21.2", &integrity), tarball);

    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args([
            "review",
            "  express@4.21.2  ",
            "--registry",
            &fixture.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2);
}

#[test]
fn regression_large_file_opaque_detection() {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let pkg_json = br#"{"name":"large-pkg","version":"1.0.0"}"#;
    let mut h = tar::Header::new_gnu();
    h.set_size(pkg_json.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder
        .append_data(&mut h, "package/package.json", &pkg_json[..])
        .unwrap();

    let large_bytes = vec![b'A'; 11 * 1024 * 1024]; // 11 MiB > 10 MiB cap
    let mut h2 = tar::Header::new_gnu();
    h2.set_size(large_bytes.len() as u64);
    h2.set_mode(0o644);
    h2.set_cksum();
    builder
        .append_data(&mut h2, "package/big_data.txt", &large_bytes[..])
        .unwrap();
    let tarball = builder.into_inner().unwrap().finish().unwrap();
    let integrity = sha512_b64(&tarball);

    let fixture = spawn_fixture(
        move |base| {
            serde_json::json!({
                "name": "large-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "large-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base}/large-pkg/-/large-pkg-1.0.0.tgz"),
                            "integrity": integrity,
                            "shasum": "0".repeat(40)
                        }
                    }
                }
            })
            .to_string()
        },
        tarball,
    );

    let data_dir = tempfile::tempdir().unwrap();
    let output = blueline()
        .args([
            "review",
            "large-pkg@1.0.0",
            "--registry",
            &fixture.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let output = String::from_utf8(output).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).expect("valid json");
    assert_eq!(json["band"], "HIGH");
    assert!(
        json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "R02_OPAQUE_LARGE_FILE_ADDED")
    );
}

#[test]
fn regression_unreviewed_predecessor_baseline_warning() {
    let tarball = make_tarball_with(b"module.exports = { clean: true };");
    let integrity = sha512_b64(&tarball);

    let fixture = spawn_fixture(
        move |base| {
            serde_json::json!({
                "name": "pred-pkg",
                "dist-tags": { "latest": "1.1.0" },
                "versions": {
                    "1.0.0": {
                        "name": "pred-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base}/pred-pkg/-/pred-pkg-1.0.0.tgz"),
                            "integrity": integrity,
                            "shasum": "0".repeat(40)
                        }
                    },
                    "1.1.0": {
                        "name": "pred-pkg",
                        "version": "1.1.0",
                        "dist": {
                            "tarball": format!("{base}/pred-pkg/-/pred-pkg-1.1.0.tgz"),
                            "integrity": integrity,
                            "shasum": "0".repeat(40)
                        }
                    }
                }
            })
            .to_string()
        },
        tarball,
    );

    let data_dir = tempfile::tempdir().unwrap();
    let output = blueline()
        .args([
            "review",
            "pred-pkg@1.1.0",
            "--registry",
            &fixture.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let output = String::from_utf8(output).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).expect("valid json");
    assert_eq!(json["baseline_version"], "1.0.0");
    assert_eq!(json["band"], "MEDIUM");
    assert!(
        json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "R07_UNREVIEWED_PREDECESSOR_BASELINE")
    );
}

#[test]
fn regression_terminal_sanitization() {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let pkg_json = b"{\n  \"name\": \"ansi-pkg\",\n  \"version\": \"1.0.0\",\n  \"scripts\": { \"postinstall\\u001b[2J\": \"echo pwned\" }\n}";
    let mut h = tar::Header::new_gnu();
    h.set_size(pkg_json.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder
        .append_data(&mut h, "package/package.json", &pkg_json[..])
        .unwrap();
    let tarball = builder.into_inner().unwrap().finish().unwrap();
    let integrity = sha512_b64(&tarball);

    let fixture = spawn_fixture(
        move |base| {
            serde_json::json!({
                "name": "ansi-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "ansi-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base}/ansi-pkg/-/ansi-pkg-1.0.0.tgz"),
                            "integrity": integrity,
                            "shasum": "0".repeat(40)
                        }
                    }
                }
            })
            .to_string()
        },
        tarball,
    );

    let data_dir = tempfile::tempdir().unwrap();
    let output = blueline()
        .args([
            "review",
            "ansi-pkg@1.0.0",
            "--registry",
            &fixture.base,
            "--output",
            "text",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let output = String::from_utf8(output).unwrap();
    assert!(!output.contains("\x1b[2J"));
    assert!(!output.contains('\r'));
}

#[test]
fn regression_non_interactive_review_fail_closed_and_success() {
    let safe_tarball = make_tarball_with(b"module.exports = {};");
    let safe_integrity = sha512_b64(&safe_tarball);
    let fixture_safe = spawn_fixture(
        move |base| {
            serde_json::json!({
                "name": "safe-pass-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "0.9.0": {
                        "name": "safe-pass-pkg",
                        "version": "0.9.0",
                        "dist": {
                            "tarball": format!("{base}/safe-pass-pkg/-/safe-pass-pkg-1.0.0.tgz"),
                            "integrity": safe_integrity,
                            "shasum": "0".repeat(40)
                        }
                    },
                    "1.0.0": {
                        "name": "safe-pass-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base}/safe-pass-pkg/-/safe-pass-pkg-1.0.0.tgz"),
                            "integrity": safe_integrity,
                            "shasum": "0".repeat(40)
                        }
                    }
                }
            })
            .to_string()
        },
        safe_tarball,
    );

    let data_dir = tempfile::tempdir().unwrap();
    // Review 0.9.0 to initialize store and record baseline witness
    blueline()
        .args([
            "review",
            "safe-pass-pkg@0.9.0",
            "--registry",
            &fixture_safe.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2);

    let db_path = data_dir.path().join("baseline.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute(
        "UPDATE known_clean SET clean = 1 WHERE name = 'safe-pass-pkg' AND version = '0.9.0'",
        [],
    )
    .unwrap();
    drop(conn);

    // Low risk review with approved baseline succeeds with exit code 0
    blueline()
        .args([
            "review",
            "safe-pass-pkg@1.0.0",
            "--registry",
            &fixture_safe.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .success();

    // High risk review (e.g. lifecycle scripts) fails closed with exit code 2
    let script_tarball = make_tarball();
    let script_integ = sha512_b64(&script_tarball);
    let fixture_bad = spawn_fixture(
        move |base| packument(base, "4.21.2", &script_integ),
        script_tarball,
    );

    blueline()
        .args([
            "review",
            "express@4.21.2",
            "--registry",
            &fixture_bad.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2);
}

#[test]
fn regression_sqlite_busy_timeout() {
    let data_dir = tempfile::tempdir().unwrap();
    let db_path = data_dir.path().join("baseline.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);
         INSERT INTO schema_migrations (version) VALUES (2);
         CREATE TABLE IF NOT EXISTS known_clean (
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            integrity TEXT NOT NULL,
            reviewed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            clean INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (name, version)
        ) STRICT;
        INSERT INTO known_clean (name, version, integrity, clean) VALUES ('pkg', '1.0.0', 'sha512-test', 1);",
    ).unwrap();

    let conn2 = rusqlite::Connection::open(&db_path).unwrap();
    conn2
        .busy_timeout(std::time::Duration::from_millis(5000))
        .unwrap();

    let count: i64 = conn2
        .query_row("SELECT COUNT(*) FROM known_clean", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn regression_leading_hyphen_package_spec_rejected() {
    blueline()
        .args(["review", "-badpkg@1.0.0"])
        .assert()
        .failure();

    blueline()
        .args(["install", "--", "--badpkg"])
        .assert()
        .failure();
}

#[test]
fn regression_forwarded_flags_underscore_and_config_injection_blocked() {
    let variations = [
        vec!["install", "express@4.21.2", "--", "--ignore_scripts=false"],
        vec!["install", "express@4.21.2", "--", "--ignoreScripts=false"],
        vec![
            "install",
            "express@4.21.2",
            "--",
            "--userconfig=/tmp/evil.npmrc",
        ],
        vec![
            "install",
            "express@4.21.2",
            "--",
            "--node-options=--require /tmp/pwn.js",
        ],
        vec!["install", "express@4.21.2", "--", "--prefix=/tmp/evil"],
        vec![
            "install",
            "express@4.21.2",
            "--",
            "--script-shell",
            "/bin/sh",
        ],
    ];

    for args in variations {
        blueline().args(&args).assert().failure();
    }
}

#[test]
fn regression_policy_missing_file_fails_closed() {
    blueline()
        .args([
            "review",
            "express@4.21.2",
            "--policy",
            "nonexistent_policy_file.toml",
        ])
        .assert()
        .failure();
}

#[test]
fn regression_policy_blocks_package_via_cli() {
    let tarball = make_tarball();
    let integrity = sha512_b64(&tarball);
    let pack_integrity = integrity.clone();
    let fix = spawn_fixture(
        move |base| packument(base, "4.21.2", &pack_integrity),
        tarball,
    );

    let temp_policy = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        temp_policy.path(),
        r#"
[blocklist]
packages = ["express"]
"#,
    )
    .unwrap();

    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args([
            "review",
            "express@4.21.2",
            "--registry",
            &fix.base,
            "--policy",
            temp_policy.path().to_str().unwrap(),
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2)
        .stdout(predicates::str::contains(r#""band":"BLOCK""#))
        .stdout(predicates::str::contains("P01_PACKAGE_BLOCKED"));
}

fn make_custom_layout_tarball(prefix: &str) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let pkg_json = br#"{
        "name": "express",
        "version": "4.21.2"
    }"#;
    let mut h = tar::Header::new_gnu();
    h.set_size(pkg_json.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder
        .append_data(&mut h, format!("{prefix}/package.json"), &pkg_json[..])
        .unwrap();

    let code = b"module.exports = {};";
    let mut h2 = tar::Header::new_gnu();
    h2.set_size(code.len() as u64);
    h2.set_mode(0o644);
    h2.set_cksum();
    builder
        .append_data(&mut h2, format!("{prefix}/index.js"), &code[..])
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap()
}

#[test]
fn regression_single_directory_package_layout() {
    let tarball = make_custom_layout_tarball("lodash");
    let integrity = sha512_b64(&tarball);
    let pack_integrity = integrity.clone();
    let fix = spawn_fixture(
        move |base| packument(base, "4.21.2", &pack_integrity),
        tarball,
    );

    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args([
            "review",
            "express@4.21.2",
            "--registry",
            &fix.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2)
        .stdout(predicates::str::contains(r#""name":"express""#))
        .stdout(predicates::str::contains(r#""files_added":2"#));
}

#[test]
fn regression_json_output_emits_valid_json_without_prompt() {
    let tarball = make_tarball();
    let integrity = sha512_b64(&tarball);
    let pack_integrity = integrity.clone();
    let fix = spawn_fixture(
        move |base| packument(base, "4.21.2", &pack_integrity),
        tarball,
    );

    let data_dir = tempfile::tempdir().unwrap();
    let output = blueline()
        .args([
            "review",
            "express@4.21.2",
            "--registry",
            &fix.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .get_output()
        .stdout
        .clone();

    let stdout_str = String::from_utf8(output).unwrap();
    assert!(!stdout_str.contains("[a]pprove · [h]old · [d]iff"));
    let json_val: serde_json::Value =
        serde_json::from_str(&stdout_str).expect("stdout should be valid JSON");
    assert_eq!(json_val["name"], "express");
    assert_eq!(json_val["target_version"], "4.21.2");
}

#[test]
fn ci_and_mcp_subcommands_appear_in_help() {
    blueline()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("ci"))
        .stdout(predicates::str::contains("mcp"));
}

#[test]
fn mcp_stdio_handles_initialize_and_tools_list() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let bin_path = assert_cmd::cargo::cargo_bin("blueline");
    let mut child = Command::new(bin_path)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();

    // 1. Send initialize
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line).unwrap();

    let init_resp: serde_json::Value = serde_json::from_str(&line).expect("valid JSON response");
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "blueline");

    // 2. Send tools/list
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    line.clear();
    std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
    let tools_resp: serde_json::Value = serde_json::from_str(&line).expect("valid JSON response");
    assert_eq!(tools_resp["id"], 2);
    let tools = tools_resp["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|t| t["name"] == "review_install"));

    drop(stdin);
    let _ = child.wait();
}
