//! End-to-end recall index tests: serve a curated revocation snapshot,
//! sync it, prove a revoked release is BLOCKed through the real CLI with
//! the R09 malware roll-up, prove staleness is disclosed (and escalates
//! per policy), and prove the curation export works.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Stdio};
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

fn tarball_with(json: &str) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let mut h = tar::Header::new_gnu();
    h.set_size(json.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder
        .append_data(&mut h, "package/package.json", json.as_bytes())
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

struct RecallServer {
    url: String,
    child: Child,
}

impl Drop for RecallServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_recall_server(index: &std::path::Path) -> RecallServer {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_blueline"))
        .args([
            "recall",
            "serve",
            "--port",
            "0",
            "--snapshot",
            index.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("serve banner");
    let port: u16 = line
        .trim()
        .split("http://127.0.0.1:")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("cannot parse serve banner: {line}"));
    RecallServer {
        url: format!("http://127.0.0.1:{port}"),
        child,
    }
}

fn blueline(data_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("blueline").unwrap();
    cmd.env("BLUELINE_DATA_DIR", data_dir);
    cmd
}

fn curated_index(now: i64) -> String {
    serde_json::json!({
        "schema": 1,
        "generated_at": now,
        "sequence": 42,
        "revocations": [{
            "ecosystem": "npm",
            "name": "evil-pkg",
            "versions": ["1.0.0"],
            "all_versions": false,
            "reason": "backdoored postinstall, human-verified",
            "id": "BL-2026-0001"
        }]
    })
    .to_string()
}

#[test]
fn recall_index_hit_blocks_a_clean_looking_release() {
    let work = tempfile::tempdir().unwrap();
    let index_path = work.path().join("revocations.json");
    std::fs::write(&index_path, curated_index(now_secs())).unwrap();
    let server = spawn_recall_server(&index_path);

    let data_dir = tempfile::tempdir().unwrap();
    // Sync from the service.
    let out = blueline(data_dir.path())
        .args(["recall", "sync", "--url", &server.url])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The package itself is perfectly clean — the index is what blocks it.
    let json = r#"{"name":"evil-pkg","version":"1.0.0"}"#;
    let tar = tarball_with(json);
    let fixture = spawn_fixture(move |base| {
        let mut packages = HashMap::new();
        packages.insert(
            "evil-pkg".to_string(),
            (packument("evil-pkg", base, "1.0.0", &sha512_b64(&tar)), tar),
        );
        packages
    });
    let out = blueline(data_dir.path())
        .args([
            "review",
            "evil-pkg@1.0.0",
            "--registry",
            &fixture.base,
            "--output",
            "json",
            "--yes",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        out.status.code(),
        Some(2),
        "recall hit must block: {stdout}"
    );
    let verdict: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(verdict["band"], "BLOCK");
    assert_eq!(
        verdict["trust_sources"]["advisories"]["source"],
        "blueline-recall"
    );
    assert!(
        verdict["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "R09_ADVISORY_MALWARE"),
        "revocation hit must roll up as malware: {stdout}"
    );

    // Backward sequence sync is refused fail closed.
    let stale_index = curated_index(now_secs()).replace("\"sequence\":42", "\"sequence\":41");
    let old_dir = tempfile::tempdir().unwrap();
    let old_index = old_dir.path().join("revocations.json");
    std::fs::write(&old_index, stale_index).unwrap();
    let old_server = spawn_recall_server(&old_index);
    let out = blueline(data_dir.path())
        .args(["recall", "sync", "--url", &old_server.url])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "backward sequence must refuse: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn backward_sequence_is_refused_without_write_and_equal_sequence_is_idempotent() {
    let work = tempfile::tempdir().unwrap();
    let index_path = work.path().join("revocations.json");
    std::fs::write(&index_path, curated_index(now_secs())).unwrap();
    let server = spawn_recall_server(&index_path);

    let data_dir = tempfile::tempdir().unwrap();
    let out = blueline(data_dir.path())
        .args(["recall", "sync", "--url", &server.url])
        .output()
        .unwrap();
    assert!(out.status.success());
    let snapshot_path = data_dir.path().join("recall_snapshot.json");
    let synced_bytes = std::fs::read(&snapshot_path).unwrap();

    // Backward sequence: refused, and the stored snapshot is untouched.
    let stale_index = curated_index(now_secs()).replace("\"sequence\":42", "\"sequence\":41");
    let old_dir = tempfile::tempdir().unwrap();
    let old_index = old_dir.path().join("revocations.json");
    std::fs::write(&old_index, stale_index).unwrap();
    let old_server = spawn_recall_server(&old_index);
    let out = blueline(data_dir.path())
        .args(["recall", "sync", "--url", &old_server.url])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let reread = std::fs::read(&snapshot_path).unwrap();
    assert_eq!(
        reread, synced_bytes,
        "refused sync must not partially write"
    );
    let stored: serde_json::Value = serde_json::from_slice(&reread).unwrap();
    assert_eq!(stored["snapshot"]["sequence"], 42);

    // Equal sequence: accepted and byte-identical (idempotent re-sync).
    let out = blueline(data_dir.path())
        .args(["recall", "sync", "--url", &server.url])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "equal sequence must re-sync cleanly: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&snapshot_path).unwrap()).unwrap();
    assert_eq!(stored["snapshot"]["sequence"], 42);
}

#[test]
fn stale_index_is_disclosed_and_escalates_per_policy() {
    let data_dir = tempfile::tempdir().unwrap();
    let snapshot_path = data_dir.path().join("recall_snapshot.json");
    let synced = serde_json::json!({
        "fetched_at": now_secs() - 100 * 3600,
        "url": "http://127.0.0.1:1",
        "snapshot": {
            "schema": 1,
            "generated_at": now_secs() - 200 * 3600,
            "sequence": 9,
            "revocations": []
        }
    });
    std::fs::write(&snapshot_path, synced.to_string()).unwrap();

    let json = r#"{"name":"clean","version":"1.0.0"}"#;
    let tar = tarball_with(json);
    let fixture = spawn_fixture(move |base| {
        let mut packages = HashMap::new();
        packages.insert(
            "clean".to_string(),
            (packument("clean", base, "1.0.0", &sha512_b64(&tar)), tar),
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

    let out = blueline(data_dir.path())
        .args([
            "review",
            "clean@1.0.0",
            "--registry",
            &fixture.base,
            "--output",
            "json",
            "--yes",
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let verdict: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    let stale = verdict["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "R28_RECALL_STALE")
        .expect("stale index must be disclosed")
        .clone();
    assert_eq!(stale["severity"], "MEDIUM");

    // block_on_stale escalates the whole verdict to BLOCK.
    let strict_dir = tempfile::tempdir().unwrap();
    let strict_policy = strict_dir.path().join("blueline.toml");
    std::fs::write(
        &strict_policy,
        "[[allowlist.packages]]\nname = \"clean\"\nallow_unreviewed_baseline = true\n\n[recall]\nblock_on_stale = true\n",
    )
    .unwrap();
    let out = blueline(data_dir.path())
        .args([
            "review",
            "clean@1.0.0",
            "--registry",
            &fixture.base,
            "--output",
            "json",
            "--yes",
            "--policy",
            strict_policy.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let verdict: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(verdict["band"], "BLOCK", "{stdout}");
}

#[test]
fn corrupt_snapshot_is_disclosed_high_and_blocks_low() {
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        data_dir.path().join("recall_snapshot.json"),
        "{ not valid json",
    )
    .unwrap();

    let json = r#"{"name":"clean","version":"1.0.0"}"#;
    let tar = tarball_with(json);
    let fixture = spawn_fixture(move |base| {
        let mut packages = HashMap::new();
        packages.insert(
            "clean".to_string(),
            (packument("clean", base, "1.0.0", &sha512_b64(&tar)), tar),
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

    let out = blueline(data_dir.path())
        .args([
            "review",
            "clean@1.0.0",
            "--registry",
            &fixture.base,
            "--output",
            "json",
            "--yes",
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let verdict: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    let corrupt = verdict["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "R28_RECALL_STALE")
        .expect("corrupt index must be disclosed as R28")
        .clone();
    assert_eq!(corrupt["severity"], "HIGH", "{corrupt:?}");
    assert_ne!(
        verdict["band"], "LOW",
        "a blind revocation index is never LOW: {stdout}"
    );
}

#[test]
fn audit_export_candidates_lists_denials_for_curation() {
    let data_dir = tempfile::tempdir().unwrap();
    // An agent-gate denial writes the audit row the curator would review.
    let gate_out = blueline(data_dir.path())
        .args([
            "agent",
            "gate",
            "--command",
            "npm install risky-thing@1.0.0",
        ])
        .output()
        .unwrap();
    let code = gate_out.status.code().unwrap_or(-1);
    assert_eq!(code, 2, "unresolvable spec must deny");

    let out_path = data_dir.path().join("candidates.json");
    let out = blueline(data_dir.path())
        .args([
            "recall",
            "export-candidates",
            "--out",
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let candidates: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let entries = candidates.as_array().unwrap();
    assert!(
        entries.iter().any(|e| {
            e["action"] == "agent_gate_summary"
                && e["verdict"] == "HIGH"
                && e["notes"]
                    .as_str()
                    .is_some_and(|n| n.contains("risky-thing"))
        }),
        "the gate summary denial must be a curation candidate: {entries:?}"
    );
}
