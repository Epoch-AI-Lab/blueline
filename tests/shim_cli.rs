//! End-to-end PATH-shim tests: install the generated shim, run a real
//! `npm install` through it against a fixture registry (denied for a
//! risky package, allowed with the real binary exec'd for a clean one),
//! then uninstall. Fail-closed behavior is proven without any real npm.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
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

fn spawn_two_packages() -> Fixture {
    let ok_json = r#"{"name":"ok","version":"1.0.0"}"#;
    let ok_tar = tarball_with(ok_json, &[]);
    let risky_json =
        r#"{"name":"risky","version":"1.0.0","scripts":{"postinstall":"node setup.js"}}"#;
    let risky_tar = tarball_with(
        risky_json,
        &[("package/setup.js", b"console.log(1);" as &[u8])],
    );
    spawn_fixture(move |base| {
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
    })
}

fn write_fake_real_npm(dir: &Path, log: &Path) -> PathBufHelper {
    let bin_dir = dir.join("realbin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let npm = bin_dir.join("npm");
    let script = format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}\n", log.display());
    std::fs::write(&npm, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&npm, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    PathBufHelper(bin_dir)
}

struct PathBufHelper(std::path::PathBuf);

#[test]
fn shim_installs_gates_and_uninstalls() {
    let fixture = spawn_two_packages();
    let work = tempfile::tempdir().unwrap();
    let shim_dir = work.path().join("shims");
    let log = work.path().join("npm-calls.log");
    let helper = write_fake_real_npm(work.path(), &log);

    let policy_dir = tempfile::tempdir().unwrap();
    let policy_path = policy_dir.path().join("blueline.toml");
    std::fs::write(
        &policy_path,
        "[[allowlist.packages]]\nname = \"ok\"\nallow_unreviewed_baseline = true\n",
    )
    .unwrap();

    // Install.
    let data_dir = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("blueline")
        .unwrap()
        .args([
            "shim",
            "install",
            "npm",
            "--dir",
            shim_dir.to_str().unwrap(),
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .env(
            "PATH",
            format!("{}:{}", helper.0.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shim = shim_dir.join("npm");
    assert!(shim.is_file(), "shim script must exist");

    // Denied: the risky package never reaches the real npm.
    let out = Command::new(&shim)
        .args(["install", "risky@1.0.0"])
        .env("BLUELINE_REGISTRY", &fixture.base)
        .env("BLUELINE_POLICY", &policy_path)
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .env(
            "PATH",
            format!("{}:{}", helper.0.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "risky install must be blocked: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !log.exists(),
        "the real npm must not run when the review blocks"
    );

    // Allowed: clean package passes the gate and reaches the fake real npm.
    let out = Command::new(&shim)
        .args(["install", "ok@1.0.0"])
        .env("BLUELINE_REGISTRY", &fixture.base)
        .env("BLUELINE_POLICY", &policy_path)
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .env(
            "PATH",
            format!("{}:{}", helper.0.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "clean install must pass: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let logged = std::fs::read_to_string(&log).unwrap();
    assert!(
        logged.contains("ok@1.0.0"),
        "the real npm must receive the original args: {logged}"
    );

    // Uninstall removes the shim.
    let out = Command::cargo_bin("blueline")
        .unwrap()
        .args([
            "shim",
            "uninstall",
            "npm",
            "--dir",
            shim_dir.to_str().unwrap(),
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!shim.exists());
}

#[test]
fn shim_install_refuses_unknown_manager_and_missing_real_binary() {
    let work = tempfile::tempdir().unwrap();
    let shim_dir = work.path().join("shims");
    let data_dir = tempfile::tempdir().unwrap();

    let out = Command::cargo_bin("blueline")
        .unwrap()
        .args([
            "shim",
            "install",
            "definitely-not-a-manager",
            "--dir",
            shim_dir.to_str().unwrap(),
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    // No real `npm` on the (emptied) PATH: fail closed, no shim written.
    let out = Command::cargo_bin("blueline")
        .unwrap()
        .args([
            "shim",
            "install",
            "npm",
            "--dir",
            shim_dir.to_str().unwrap(),
        ])
        .env("BLUELINE_DATA_DIR", data_dir.path())
        .env("PATH", "")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "missing real binary must fail closed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!shim_dir.join("npm").exists());
}
