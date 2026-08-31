//! End-to-end PyPI adapter tests: local fixture HTTP server serves Simple API JSON
//! and wheel zip downloads. No external network.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use assert_cmd::Command;
use predicates::prelude::*;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;

struct Fixture {
    base: String,
    _handle: std::thread::JoinHandle<()>,
}

struct Routes {
    simple_json: String,
    simple_path: String,
    /// download path -> wheel zip bytes
    downloads: BTreeMap<String, Vec<u8>>,
    provenance_path: Option<String>,
    provenance_json: Option<String>,
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

    let (ctype, body): (&str, Vec<u8>) = if path == routes.simple_path.trim_start_matches('/') {
        (
            "application/vnd.pypi.simple.v1+json",
            routes.simple_json.as_bytes().to_vec(),
        )
    } else if let Some(prov_path) = &routes.provenance_path
        && path == prov_path.trim_start_matches('/')
    {
        (
            "application/json",
            routes
                .provenance_json
                .as_deref()
                .unwrap_or("{}")
                .as_bytes()
                .to_vec(),
        )
    } else if let Some(bytes) = routes.downloads.get(&path) {
        ("application/octet-stream", bytes.clone())
    } else {
        let not_found = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
        let _ = stream.write_all(not_found);
        return;
    };

    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
}

fn make_wheel_bytes(pkg_name: &str, version: &str) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);
        zip.start_file(format!("{pkg_name}/__init__.py"), opts)
            .unwrap();
        zip.write_all(b"__version__ = '1.0.0'\n").unwrap();
        zip.start_file(format!("{pkg_name}-{version}.dist-info/METADATA"), opts)
            .unwrap();
        zip.write_all(
            format!("Metadata-Version: 2.1\nName: {pkg_name}\nVersion: {version}\n").as_bytes(),
        )
        .unwrap();
        zip.finish().unwrap();
    }
    buf.into_inner()
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

#[test]
fn install_refuses_pypi_before_any_network_use() {
    Command::cargo_bin("blueline")
        .unwrap()
        .args(["--ecosystem", "pypi", "install", "requests==2.31.0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refuses PyPI packages"));
}

#[test]
fn review_pypi_first_sighting_renders_ecosystem_and_sha256() {
    let name = "demo-pkg";
    let version = "1.0.0";
    let whl_filename = format!("{name}-{version}-py3-none-any.whl");
    let wheel_bytes = make_wheel_bytes("demo_pkg", version);
    let whl_sha = sha256_hex(&wheel_bytes);
    let served_sha = whl_sha.clone();

    let server = Fixture::spawn(move |base| {
        let simple_json = format!(
            r#"{{
                "name": "{name}",
                "versions": ["{version}"],
                "files": [
                    {{
                        "filename": "{whl_filename}",
                        "url": "{base}/packages/{whl_filename}",
                        "hashes": {{
                            "sha256": "{served_sha}"
                        }},
                        "yanked": false
                    }}
                ]
            }}"#
        );
        let mut downloads = BTreeMap::new();
        downloads.insert(format!("packages/{whl_filename}"), wheel_bytes);
        Routes {
            simple_json,
            simple_path: format!("simple/{name}/"),
            downloads,
            provenance_path: None,
            provenance_json: None,
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let output = Command::cargo_bin("blueline")
        .unwrap()
        .env("HOME", dir.path())
        .args([
            "--ecosystem",
            "pypi",
            "--index",
            &server.base,
            "review",
            &format!("{name}=={version}"),
            "--output",
            "json",
        ])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let verdict: serde_json::Value =
        serde_json::from_str(&String::from_utf8(output).unwrap()).unwrap();
    assert_eq!(verdict["ecosystem"], "pypi");
    assert_eq!(verdict["name"], name);
    assert_eq!(verdict["target_version"], version);
    assert_eq!(verdict["integrity"], format!("sha256:{whl_sha}"));
    assert_eq!(verdict["band"], "MEDIUM");
}

#[test]
fn review_pypi_rejects_checksum_mismatch() {
    let name = "bad-hash";
    let version = "1.0.0";
    let whl_filename = format!("{name}-{version}-py3-none-any.whl");
    let wheel_bytes = make_wheel_bytes("bad_hash", version);

    let server = Fixture::spawn(move |base| {
        let simple_json = format!(
            r#"{{
                "name": "{name}",
                "versions": ["{version}"],
                "files": [
                    {{
                        "filename": "{whl_filename}",
                        "url": "{base}/packages/{whl_filename}",
                        "hashes": {{
                            "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
                        }},
                        "yanked": false
                    }}
                ]
            }}"#
        );
        let mut downloads = BTreeMap::new();
        downloads.insert(format!("packages/{whl_filename}"), wheel_bytes);
        Routes {
            simple_json,
            simple_path: format!("simple/{name}/"),
            downloads,
            provenance_path: None,
            provenance_json: None,
        }
    });

    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("blueline")
        .unwrap()
        .env("HOME", dir.path())
        .args([
            "--ecosystem",
            "pypi",
            "--index",
            &server.base,
            "review",
            &format!("{name}@{version}"),
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("sha256 mismatch"));
}

#[test]
fn ci_pypi_lockfile_hash_verification() {
    let name = "demo-lock";
    let version = "1.0.0";
    let whl_filename = format!("{name}-{version}-py3-none-any.whl");
    let wheel_bytes = make_wheel_bytes("demo_lock", version);
    let whl_sha = sha256_hex(&wheel_bytes);
    let served_sha = whl_sha.clone();

    let server = Fixture::spawn(move |base| {
        let simple_json = format!(
            r#"{{
                "name": "{name}",
                "versions": ["{version}"],
                "files": [
                    {{
                        "filename": "{whl_filename}",
                        "url": "{base}/packages/{whl_filename}",
                        "hashes": {{
                            "sha256": "{served_sha}"
                        }},
                        "yanked": false
                    }}
                ]
            }}"#
        );
        let mut downloads = BTreeMap::new();
        downloads.insert(format!("packages/{whl_filename}"), wheel_bytes);
        Routes {
            simple_json,
            simple_path: format!("simple/{name}/"),
            downloads,
            provenance_path: None,
            provenance_json: None,
        }
    });

    let dir = tempfile::tempdir().unwrap();

    // Mismatched hash
    let lockfile_mismatch = format!(
        "{name}=={version} --hash sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
    );
    let req_bad_path = dir.path().join("requirements_bad.txt");
    std::fs::write(&req_bad_path, lockfile_mismatch).unwrap();

    Command::cargo_bin("blueline")
        .unwrap()
        .env("HOME", dir.path())
        .args([
            "--ecosystem",
            "pypi",
            "--index",
            &server.base,
            "ci",
            "--lockfile",
            req_bad_path.to_str().unwrap(),
            "--fail-on",
            "high",
            "--base",
            "HEAD",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("BLOCK"));

    // Matching hash
    let lockfile_matching = format!("{name}=={version} --hash sha256:{whl_sha}\n");
    let req_ok_path = dir.path().join("requirements_ok.txt");
    std::fs::write(&req_ok_path, lockfile_matching).unwrap();

    Command::cargo_bin("blueline")
        .unwrap()
        .env("HOME", dir.path())
        .args([
            "--ecosystem",
            "pypi",
            "--index",
            &server.base,
            "ci",
            "--lockfile",
            req_ok_path.to_str().unwrap(),
            "--fail-on",
            "block",
            "--base",
            "HEAD",
        ])
        .assert()
        .success();
}
