//! End-to-end agent-mode tests: `blueline agent review` (policy-bound,
//! never prompts, exit codes) and `blueline agent gate` (the hook binding)
//! through the real CLI binary against a local fixture registry.

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
        .trim_start_matches('/')
        .to_string();
    let body: Vec<u8> = if let Some((pack, _)) = packages.get(&path) {
        pack.as_bytes().to_vec()
    } else {
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() == 3 {
            let tgz = segments[2].strip_suffix(".tgz").unwrap_or(segments[2]);
            match tgz.rsplit_once('-') {
                Some((name, _)) => match packages.get(name) {
                    Some((_, tar)) => tar.clone(),
                    None => return,
                },
                None => return,
            }
        } else {
            return;
        }
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

fn spawn_two_packages() -> (Fixture, std::path::PathBuf, std::path::PathBuf) {
    // `ok` is script-free; `risky` adds a postinstall (R01 BLOCK).
    let ok_json = r#"{"name":"ok","version":"1.0.0"}"#;
    let ok_tar = tarball_with(ok_json, &[]);
    let risky_json =
        r#"{"name":"risky","version":"1.0.0","scripts":{"postinstall":"node setup.js"}}"#;
    let risky_tar = tarball_with(
        risky_json,
        &[("package/setup.js", b"console.log(1);" as &[u8])],
    );
    let fixture = spawn_fixture(move |base| {
        let mut packages = HashMap::new();
        packages.insert(
            "ok".to_string(),
            (packument("ok", base, "1.0.0", &sha512_b64(&ok_tar)), ok_tar),
        );
        packages.insert(
            "risky".to_string(),
            (
                packument("risky", base, "1.0.0", &sha512_b64(&risky_tar)),
                risky_tar,
            ),
        );
        packages
    });
    (
        fixture,
        std::path::PathBuf::new(),
        std::path::PathBuf::new(),
    )
}

fn agent(args: &[&str]) -> (i32, String, String) {
    let temp = tempfile::tempdir().unwrap();
    let policy_dir = tempfile::tempdir().unwrap();
    let policy_path = policy_dir.path().join("blueline.toml");
    std::fs::write(
        &policy_path,
        "[[allowlist.packages]]\nname = \"ok\"\nallow_unreviewed_baseline = true\n",
    )
    .unwrap();
    let output = Command::cargo_bin("blueline")
        .unwrap()
        .args(args)
        .arg("--policy")
        .arg(policy_path)
        .env("BLUELINE_DATA_DIR", temp.path())
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn agent_review_blocks_risky_and_passes_clean() {
    let (fixture, _, _) = spawn_two_packages();

    let (code, stdout, _) = agent(&[
        "agent",
        "review",
        "risky@1.0.0",
        "--registry",
        &fixture.base,
    ]);
    assert_eq!(code, 2, "risky must exit 2: {stdout}");
    let verdict: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap())
        .unwrap_or_else(|e| panic!("single-line JSON verdict expected: {e}; {stdout}"));
    assert_eq!(verdict["band"], "BLOCK");
    assert_eq!(verdict["name"], "risky");

    let (code, stdout, _) = agent(&["agent", "review", "ok@1.0.0", "--registry", &fixture.base]);
    assert_eq!(code, 0, "clean must exit 0: {stdout}");
    let verdict: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(verdict["band"], "LOW");
}

#[test]
fn agent_gate_uses_exit_codes_and_native_decision_shapes() {
    let (fixture, _, _) = spawn_two_packages();
    let base = fixture.base.clone();

    // Named install of the clean package: allow.
    let (code, _, _) = agent(&[
        "agent",
        "gate",
        "--command",
        "npm install ok@1.0.0",
        "--registry",
        &base,
    ]);
    assert_eq!(code, 0);

    // Named install of the risky package: deny.
    let (code, _, stderr) = agent(&[
        "agent",
        "gate",
        "--command",
        "npm install risky@1.0.0",
        "--registry",
        &base,
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("blueline refused"), "{stderr}");
    assert!(
        stderr.contains("risky@1.0.0"),
        "denial must name the refused spec: {stderr}"
    );

    // Dynamic target: fail closed.
    let (code, _, stderr) = agent(&[
        "agent",
        "gate",
        "--command",
        "npm install $(cat deps.txt)",
        "--registry",
        &base,
    ]);
    assert_eq!(code, 2, "dynamic target must deny: {stderr}");

    // Bare install: allowed, manifest deps are CI's lane.
    let (code, _, _) = agent(&["agent", "gate", "--command", "npm ci", "--registry", &base]);
    assert_eq!(code, 0);

    // Claude Code shape.
    let (code, stdout, _) = agent(&[
        "agent",
        "gate",
        "--command",
        "npm install risky@1.0.0",
        "--registry",
        &base,
        "--format",
        "claude",
    ]);
    assert_eq!(code, 2);
    let decision: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        decision["hookSpecificOutput"]["hookEventName"],
        "PreToolUse"
    );

    // Cursor shape.
    let (code, stdout, _) = agent(&[
        "agent",
        "gate",
        "--command",
        "npm install ok@1.0.0",
        "--registry",
        &base,
        "--format",
        "cursor",
    ]);
    assert_eq!(code, 0);
    let decision: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(decision["permission"], "allow");

    // Hook stdin (Claude PreToolUse payload) is accepted instead of --command.
    let temp = tempfile::tempdir().unwrap();
    let output = Command::cargo_bin("blueline")
        .unwrap()
        .args(["agent", "gate", "--registry", &base])
        .env("BLUELINE_DATA_DIR", temp.path())
        .write_stdin(
            r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"npm install risky@1.0.0"}}"#
                .as_bytes(),
        )
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "hook stdin must reach the gate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gate_refuses_a_registry_override_without_touching_the_registry() {
    // A registry the gate cannot reach stands in for any side effect of
    // resolving the operand. If the shape denial short-circuits, the refusal
    // is still the shape reason rather than a network failure, and the store
    // gains no evidence row for a command that never ran.
    let data_dir = tempfile::tempdir().unwrap();
    let dead_registry = "http://127.0.0.1:1";
    let output = Command::cargo_bin("blueline")
        .unwrap()
        .args([
            "agent",
            "gate",
            "--command",
            "npm install risky@1.0.0 --registry=http://elsewhere.test",
            "--registry",
            dead_registry,
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unreviewable invocation shape"),
        "must refuse on shape alone, not on a failed lookup: {stderr}"
    );
    assert!(
        !stderr.contains("registry lookup failed"),
        "the operand must not be resolved at all: {stderr}"
    );

    let conn = rusqlite::Connection::open(data_dir.path().join("baseline.db")).unwrap();
    let known: i64 = conn
        .query_row("SELECT count(*) FROM known_clean", [], |r| r.get(0))
        .unwrap();
    assert_eq!(known, 0, "a refused command must not record evidence");
}
