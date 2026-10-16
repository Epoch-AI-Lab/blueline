//! The AUR CI lane runs through the shared parallel `evaluate_candidates`
//! driver, so its report must follow pin-file order no matter which review
//! finishes first. The first pin's RPC answer is delayed on purpose: a lane
//! that emitted items as they finished would put `aaa-slow` last.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;

use assert_cmd::Command;

const SLOW: &str = "aaa-slow";
const FAST: [&str; 3] = ["bbb-fast", "ccc-fast", "ddd-fast"];
const SLOW_DELAY_MS: u64 = 1500;

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

fn write_fixture_pkg(repo: &Path, pkgbase: &str) {
    std::fs::write(
        repo.join("PKGBUILD"),
        format!(
            "pkgname={pkgbase}\npkgver=1.0\npkgrel=1\narch=('any')\n\
             source=(https://good.example/{pkgbase}-1.0.tar.gz)\n\
             sha256sums=(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n\
             validpgpkeys=(AAA)\nbuild() {{\n make\n}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        repo.join(".SRCINFO"),
        format!("pkgbase = {pkgbase}\n\tpkgver = 1.0\n\tpkgrel = 1\n"),
    )
    .unwrap();
}

struct MultiPackageFixture {
    base: String,
    _server: std::thread::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

/// Loopback AUR serving one single-commit repo per package in `names`,
/// over smart HTTP like the real archive. Only the RPC side is delayed,
/// and only for the slow package: its whole review still finishes last,
/// so the report order has to come from the candidate index, not the clock.
fn spawn_multi_package_fixture(names: &[&str]) -> MultiPackageFixture {
    let dir = tempfile::tempdir().unwrap();
    for name in names {
        let work = dir.path().join(format!("work-{name}"));
        std::fs::create_dir_all(&work).unwrap();
        fixture_git(&work, &["init", "--quiet", "-b", "master"]);
        fixture_git(&work, &["config", "user.email", "alice@example.com"]);
        fixture_git(&work, &["config", "user.name", "Fixture"]);
        fixture_git(&work, &["config", "commit.gpgsign", "false"]);
        write_fixture_pkg(&work, name);
        fixture_git(&work, &["add", "-A"]);
        fixture_git(
            &work,
            &["commit", "--quiet", "-m", &format!("{name} 1.0-1")],
        );
        let bare = dir.path().join(format!("{name}.git"));
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
    }

    let serve_dir = Arc::new(dir.path().to_path_buf());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let serve_dir = serve_dir.clone();
            std::thread::spawn(move || serve_aur(&mut stream, &serve_dir));
        }
    });
    MultiPackageFixture {
        base,
        _server: handle,
        _dir: dir,
    }
}

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

fn serve_aur(stream: &mut TcpStream, serve_dir: &Path) {
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

    let bare_for = |pkg: &str| {
        let bare = serve_dir.join(format!("{pkg}.git"));
        bare.is_dir().then_some(bare)
    };

    // Git appends `?service=git-upload-pack` to the refs advertisement, so
    // route on the path with the query stripped, like the real client does.
    let route = path.split('?').next().unwrap_or("").to_string();
    let (status, ctype, out) = if let Some(name) = path.strip_prefix("/rpc/v5/info?arg%5B%5D=") {
        let name = name.split('&').next().unwrap_or("").to_string();
        if name == SLOW {
            std::thread::sleep(std::time::Duration::from_millis(SLOW_DELAY_MS));
        }
        let Some(_) = bare_for(&name) else {
            let head = "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(b"nope");
            return;
        };
        let rpc = serde_json::json!({
            "version": 5,
            "type": "multiinfo",
            "resultcount": 1,
            "results": [{
                "ID": 1,
                "Name": name,
                "PackageBaseID": 1,
                "PackageBase": name,
                "Version": "1.0-1",
                "Description": "fixture",
                "Maintainer": "alice"
            }]
        })
        .to_string();
        ("200 OK", "application/json", rpc.into_bytes())
    } else if let Some(pkg) = route
        .strip_prefix('/')
        .and_then(|p| p.strip_suffix(".git/info/refs"))
    {
        match bare_for(pkg).and_then(|bare| upload_pack(&bare, true, b"")) {
            Some(adv) => {
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
    } else if let Some(pkg) = route
        .strip_prefix('/')
        .and_then(|p| p.strip_suffix(".git/git-upload-pack"))
    {
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
        match bare_for(pkg).and_then(|bare| upload_pack(&bare, false, &body)) {
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

#[test]
fn aur_ci_reports_pins_in_pin_file_order() {
    let mut names = vec![SLOW];
    names.extend(FAST);
    let fixture = spawn_multi_package_fixture(&names);

    let repo = tempfile::tempdir().unwrap();
    fixture_git(repo.path(), &["init", "--quiet", "-b", "main"]);
    fixture_git(repo.path(), &["config", "user.email", "alice@example.com"]);
    fixture_git(repo.path(), &["config", "user.name", "Fixture"]);
    fixture_git(repo.path(), &["config", "commit.gpgsign", "false"]);
    std::fs::write(repo.path().join("aur.lock"), "# none yet\n").unwrap();
    fixture_git(repo.path(), &["add", "-A"]);
    fixture_git(repo.path(), &["commit", "--quiet", "-m", "base pins"]);
    let head_pins = names
        .iter()
        .map(|n| format!("{n}@1.0-1"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(repo.path().join("aur.lock"), &head_pins).unwrap();

    let isolated = tempfile::tempdir().unwrap();
    let output = Command::cargo_bin("blueline")
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
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value =
        serde_json::from_str(&String::from_utf8(output).unwrap()).expect("valid json");
    let got: Vec<&str> = report["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|i| i["name"].as_str().expect("item name"))
        .collect();
    assert_eq!(
        got, names,
        "items must follow pin-file order, not finish order"
    );
}
