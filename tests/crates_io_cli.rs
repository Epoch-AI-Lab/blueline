//! End-to-end cargo-adapter tests: a local fixture HTTP server plays the
//! crates.io sparse index (config.json, NDJSON, `.crate` downloads) and the
//! real binary reviews against it. No external network.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use assert_cmd::Command;
use flate2::Compression;
use predicates::prelude::*;
use sha2::{Digest, Sha256};

struct Fixture {
    base: String,
    _handle: std::thread::JoinHandle<()>,
}

struct Routes {
    config: String,
    index_rel: String,
    ndjson: String,
    /// download path (no leading slash) -> `.crate` bytes
    downloads: BTreeMap<String, Vec<u8>>,
}

impl Fixture {
    fn spawn<F>(make_routes: F) -> Fixture
    where
        F: FnOnce(&str) -> Routes + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let routes = std::sync::Arc::new(make_routes(&base));
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let routes = routes.clone();
                std::thread::spawn(move || serve(stream, &routes));
            }
        });
        Fixture {
            base,
            _handle: handle,
        }
    }
}

fn serve(mut stream: TcpStream, routes: &Routes) {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .trim_start_matches('/')
        .to_string();

    let (ctype, body): (&str, Vec<u8>) = if path == "config.json" {
        ("application/json", routes.config.as_bytes().to_vec())
    } else if path == routes.index_rel {
        ("text/plain", routes.ndjson.as_bytes().to_vec())
    } else if let Some(bytes) = routes.downloads.get(&path) {
        ("application/octet-stream", bytes.clone())
    } else {
        ("text/plain", b"not found".to_vec())
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
}

/// Build a gzipped tar shaped like a packed `.crate`: one top-level
/// `{root_name}/` holding a Cargo.toml and a source file.
fn make_crate_bytes(root_name: &str) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let manifest = format!("[package]\nname = \"{root_name}\"\nedition = \"2021\"\n");
    append_file(
        &mut builder,
        &format!("{root_name}/Cargo.toml"),
        manifest.as_bytes(),
        false,
    );
    append_file(
        &mut builder,
        &format!("{root_name}/src/lib.rs"),
        b"pub fn f() {}\n",
        false,
    );
    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap()
}

fn append_file(
    builder: &mut tar::Builder<flate2::write::GzEncoder<Vec<u8>>>,
    path: &str,
    data: &[u8],
    executable: bool,
) {
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(if executable { 0o755 } else { 0o644 });
    h.set_cksum();
    builder.append_data(&mut h, path, data).unwrap();
}

/// Append an entry whose path skips tar-rs's own `..` validation, so the
/// malicious archive reaches blueline's extraction guard intact.
fn append_unsafe_path(
    builder: &mut tar::Builder<flate2::write::GzEncoder<Vec<u8>>>,
    path: &str,
    data: &[u8],
) {
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    let name = h.as_gnu_mut().unwrap();
    name.name[..path.len()].copy_from_slice(path.as_bytes());
    h.set_cksum();
    builder.append(&h, data).unwrap();
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn sparse_index_rel(canonical: &str) -> String {
    match canonical.len() {
        1 => format!("1/{canonical}"),
        2 => format!("2/{canonical}"),
        3 => format!("3/{}/{}", &canonical[..1], canonical),
        n => format!(
            "{}/{}/{}",
            &canonical[0..2],
            &canonical[2..4],
            &canonical[..n]
        ),
    }
}

fn index_row(name: &str, version: &str, cksum: &str, yanked: bool) -> String {
    format!(
        r#"{{"name":"{name}","vers":"{version}","cksum":"{cksum}","yanked":{yanked},"features":{{}}}}"#
    )
}

fn blueline() -> Command {
    Command::cargo_bin("blueline").unwrap()
}

#[test]
fn help_advertises_ecosystem_and_index_flags() {
    blueline()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--ecosystem").and(predicate::str::contains("--index")));
}

#[test]
fn install_refuses_cargo_before_any_network_use() {
    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args(["--ecosystem", "cargo", "install", "serde@1.0.210"])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("build.rs"))
        .stderr(predicate::str::contains("refuses cargo"));
}

#[test]
fn review_cargo_first_sighting_renders_ecosystem_and_sha256() {
    let name = "serde-json";
    let version = "1.0.210";
    let crate_bytes = make_crate_bytes(&format!("{name}-{version}"));
    let cksum = sha256_hex(&crate_bytes);

    let fixture = Fixture::spawn(move |base| Routes {
        config: format!(r#"{{"dl":"{base}","api":"{base}"}}"#),
        index_rel: sparse_index_rel(name),
        ndjson: format!("{}\n", index_row(name, version, &cksum, false)),
        downloads: BTreeMap::from([(format!("{name}/{version}/download"), crate_bytes)]),
    });

    let data_dir = tempfile::tempdir().unwrap();
    let output = blueline()
        .args([
            "--ecosystem",
            "cargo",
            "review",
            &format!("{name}@{version}"),
            "--index",
            &fixture.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .code(2) // FirstSighting -> MEDIUM, refused without --yes on a pipe
        .get_output()
        .stdout
        .clone();
    let output = String::from_utf8(output).unwrap();

    let verdict: serde_json::Value =
        serde_json::from_str(output.trim()).expect("stdout must be pure JSON");
    assert_eq!(verdict["ecosystem"], "cargo");
    assert_eq!(verdict["name"], "serde-json");
    assert_eq!(verdict["target_version"], "1.0.210");
    let integrity = verdict["integrity"].as_str().unwrap();
    assert!(
        integrity.starts_with("sha256:") && integrity.len() == "sha256:".len() + 64,
        "integrity must display as sha256:<hex>, got {integrity}"
    );
    assert_eq!(verdict["band"], "MEDIUM");
    assert!(
        verdict["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "R06_FIRST_SIGHTING")
    );
}

#[test]
fn review_cargo_skips_yanked_predecessor_and_emits_r08() {
    let name = "yanker";
    let target = "1.0.2";
    // Immediate prior (1.0.1) is yanked; the diff anchor falls back to 1.0.0.
    let c0 = make_crate_bytes(&format!("{name}-1.0.0"));
    let c1 = make_crate_bytes(&format!("{name}-1.0.1"));
    let c2 = make_crate_bytes(&format!("{name}-{target}"));

    let fixture = Fixture::spawn(move |base| Routes {
        config: format!(r#"{{"dl":"{base}","api":"{base}"}}"#),
        index_rel: sparse_index_rel(name),
        ndjson: [
            index_row(name, "1.0.0", &sha256_hex(&c0), false),
            index_row(name, "1.0.1", &sha256_hex(&c1), true),
            index_row(name, target, &sha256_hex(&c2), false),
        ]
        .join("\n")
            + "\n",
        downloads: BTreeMap::from([
            (format!("{name}/1.0.0/download"), c0),
            (format!("{name}/1.0.1/download"), c1),
            (format!("{name}/{target}/download"), c2),
        ]),
    });

    let data_dir = tempfile::tempdir().unwrap();
    let output = blueline()
        .args([
            "--ecosystem",
            "cargo",
            "review",
            &format!("{name}@{target}"),
            "--index",
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
    let verdict: serde_json::Value =
        serde_json::from_str(String::from_utf8(output).unwrap().trim()).unwrap();

    assert_eq!(verdict["baseline_version"], "1.0.0");
    assert!(
        verdict["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "R08_YANKED_PREDECESSOR" && f["severity"] == "MEDIUM"),
        "expected an R08 finding, got {:?}",
        verdict["findings"]
    );
}

#[test]
fn review_cargo_rejects_checksum_mismatch() {
    let name = "badsum";
    let version = "0.1.0";
    let crate_bytes = make_crate_bytes(name);
    let wrong_cksum = "b".repeat(64);

    let fixture = Fixture::spawn(move |base| Routes {
        config: format!(r#"{{"dl":"{base}"}}"#),
        index_rel: sparse_index_rel(name),
        ndjson: format!("{}\n", index_row(name, version, &wrong_cksum, false)),
        downloads: BTreeMap::from([(format!("{name}/{version}/download"), crate_bytes)]),
    });

    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args([
            "--ecosystem",
            "cargo",
            "review",
            &format!("{name}@{version}"),
            "--index",
            &fixture.base,
            "--output",
            "json",
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("sha256 mismatch"));
}

#[test]
fn review_cargo_rejects_wrong_root_directory() {
    let name = "roothijack";
    let version = "2.0.0";
    // Valid checksum, but the archive unpacks to a different root name.
    let crate_bytes = make_crate_bytes("totally-other-2.0.0");

    let fixture = Fixture::spawn(move |base| Routes {
        config: format!(r#"{{"dl":"{base}"}}"#),
        index_rel: sparse_index_rel(name),
        ndjson: format!(
            "{}\n",
            index_row(name, version, &sha256_hex(&crate_bytes), false)
        ),
        downloads: BTreeMap::from([(format!("{name}/{version}/download"), crate_bytes)]),
    });

    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args([
            "--ecosystem",
            "cargo",
            "review",
            &format!("{name}@{version}"),
            "--index",
            &fixture.base,
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("root mismatch"));
}

#[test]
fn review_cargo_rejects_traversal_entries() {
    let name = "climber";
    let version = "1.0.0";
    let root = format!("{name}-{version}");
    let encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let manifest = format!("[package]\nname = \"{name}\"\nedition = \"2021\"\n");
    append_file(
        &mut builder,
        &format!("{root}/Cargo.toml"),
        manifest.as_bytes(),
        false,
    );
    append_file(
        &mut builder,
        &format!("{root}/src/lib.rs"),
        b"pub fn f() {}\n",
        false,
    );
    append_unsafe_path(&mut builder, "../../escaped.txt", b"pwned");
    let encoder = builder.into_inner().unwrap();
    let crate_bytes = encoder.finish().unwrap();

    let fixture = Fixture::spawn(move |base| Routes {
        config: format!(r#"{{"dl":"{base}"}}"#),
        index_rel: sparse_index_rel(name),
        ndjson: format!(
            "{}\n",
            index_row(name, version, &sha256_hex(&crate_bytes), false)
        ),
        downloads: BTreeMap::from([(format!("{name}/{version}/download"), crate_bytes)]),
    });

    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args([
            "--ecosystem",
            "cargo",
            "review",
            &format!("{name}@{version}"),
            "--index",
            &fixture.base,
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to extract"));
}

#[test]
fn review_cargo_rejects_symlink_entries() {
    let name = "linker";
    let version = "1.0.0";
    let encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let manifest = format!("[package]\nname = \"{name}\"\n");
    let manifest_path = format!("{name}-{version}/Cargo.toml");
    append_file(&mut builder, &manifest_path, manifest.as_bytes(), false);
    let mut h = tar::Header::new_gnu();
    h.set_size(0);
    h.set_mode(0o777);
    h.set_entry_type(tar::EntryType::Symlink);
    h.set_cksum();
    builder
        .append_data(
            &mut h,
            format!("{name}-{version}/evil-link"),
            b"/etc/passwd".as_slice(),
        )
        .unwrap();
    let encoder = builder.into_inner().unwrap();
    let crate_bytes = encoder.finish().unwrap();

    let fixture = Fixture::spawn(move |base| Routes {
        config: format!(r#"{{"dl":"{base}"}}"#),
        index_rel: sparse_index_rel(name),
        ndjson: format!(
            "{}\n",
            index_row(name, version, &sha256_hex(&crate_bytes), false)
        ),
        downloads: BTreeMap::from([(format!("{name}/{version}/download"), crate_bytes)]),
    });

    let data_dir = tempfile::tempdir().unwrap();
    blueline()
        .args([
            "--ecosystem",
            "cargo",
            "review",
            &format!("{name}@{version}"),
            "--index",
            &fixture.base,
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to extract"));
}
