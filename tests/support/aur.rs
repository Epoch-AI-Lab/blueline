//! AUR fixture: the RPC metadata endpoint plus a bare git repository served
//! over smart HTTP, which is how blueline actually reviews an AUR release.
//! Building an AUR PKGBUILD executes shell, so the AUR lane reads the repo
//! statically; a scenario must therefore give it a real repository.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

/// One PKGBUILD revision committed to the fixture repository.
pub struct AurRevision {
    pub version: String,
    pub pkgbuild: String,
    pub srcinfo: String,
}

impl AurRevision {
    /// `pkgbase` must match the name the registry resolves, or the engine
    /// refuses the review (it cross-checks the two).
    pub fn new(pkgbase: &str, version: &str, pkgbuild: &str) -> AurRevision {
        AurRevision {
            version: version.to_string(),
            pkgbuild: pkgbuild.to_string(),
            srcinfo: format!(
                "pkgbase = {pkgbase}\n\tpkgver = {version}\n\tpkgrel = 1\n\tarch = x86_64\n"
            ),
        }
    }
}

/// Serves `/rpc/v5/info`, `/{name}.git/info/refs`, and
/// `/{name}.git/git-upload-pack` off one loopback listener, so a scenario
/// passes a single `--registry` base just like the npm lane.
pub struct AurRegistry {
    base: String,
    addr: SocketAddr,
    observations: Arc<Mutex<Vec<SocketAddr>>>,
    _dir: tempfile::TempDir,
    _server: std::thread::JoinHandle<()>,
}

impl AurRegistry {
    /// Build a repository from ordered revisions (oldest first; the last one
    /// is the release under review and the previous one becomes the baseline).
    pub fn serve(name: &str, revisions: &[AurRevision]) -> AurRegistry {
        assert!(
            !revisions.is_empty(),
            "an AUR fixture needs at least one revision"
        );
        let dir = tempfile::tempdir().expect("create AUR fixture dir");
        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).expect("create AUR fixture worktree");
        git(&work, &["init", "--quiet", "-b", "master"]);
        git(&work, &["config", "user.email", "fixture@example.invalid"]);
        git(&work, &["config", "user.name", "Scenario Fixture"]);
        git(&work, &["config", "commit.gpgsign", "false"]);

        for revision in revisions {
            std::fs::write(work.join("PKGBUILD"), &revision.pkgbuild)
                .expect("write fixture PKGBUILD");
            std::fs::write(work.join(".SRCINFO"), &revision.srcinfo)
                .expect("write fixture .SRCINFO");
            git(&work, &["add", "-A"]);
            git(
                &work,
                &[
                    "commit",
                    "--quiet",
                    "-m",
                    &format!("{} {}", name, revision.version),
                ],
            );
        }

        let bare = dir.path().join(format!("{name}.git"));
        git(
            dir.path(),
            &[
                "clone",
                "--quiet",
                "--bare",
                work.to_str().expect("worktree path is UTF-8"),
                bare.to_str().expect("bare repo path is UTF-8"),
            ],
        );
        git(&bare, &["update-server-info"]);

        let latest = revisions
            .last()
            .expect("revisions is non-empty")
            .version
            .clone();
        let rpc = serde_json::json!({
            "version": 5,
            "type": "multiinfo",
            "resultcount": 1,
            "results": [{
                "ID": 1,
                "Name": name,
                "PackageBaseID": 1,
                "PackageBase": name,
                "Version": latest,
                "Description": "scenario fixture",
                "Maintainer": "fixture"
            }]
        })
        .to_string();
        let rpc = Arc::new(rpc);
        let bare: Arc<PathBuf> = Arc::new(bare);
        let repo_name = name.to_string();

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback AUR fixture");
        let addr = listener
            .local_addr()
            .expect("read AUR fixture local address");
        assert!(
            addr.ip().is_loopback(),
            "AUR fixture bound a non-loopback address: {addr}"
        );
        let base = format!("http://{addr}");
        let observations = Arc::new(Mutex::new(Vec::new()));

        let server_rpc = rpc.clone();
        let server_bare = bare.clone();
        let server_name = repo_name.clone();
        let server_observations = observations.clone();
        let server = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let rpc = server_rpc.clone();
                let bare = server_bare.clone();
                let name = server_name.clone();
                let observations = server_observations.clone();
                std::thread::spawn(move || serve(&mut stream, &rpc, &bare, &name, &observations));
            }
        });

        AurRegistry {
            base,
            addr,
            observations,
            _dir: dir,
            _server: server,
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn non_loopback_peers(&self) -> Vec<SocketAddr> {
        self.observations
            .lock()
            .expect("AUR fixture log poisoned")
            .iter()
            .filter(|addr| !addr.ip().is_loopback())
            .copied()
            .collect()
    }
}

fn git(dir: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("spawn git {args:?} in {}: {e}", dir.display()));
    assert!(
        output.status.success(),
        "git {args:?} failed in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Read one HTTP request: headers through the blank line, then the full
/// `Content-Length` body.
fn read_request(stream: &mut TcpStream) -> Option<(usize, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 65_536 {
            return None;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let headers = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let content_length: usize = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some((head_end, buf))
}

/// One stateless `git upload-pack` round: feed the request body on stdin,
/// return the response bytes. `--advertise-refs` serves the `info/refs` GET.
fn upload_pack(bare: &Path, advertise: bool, body: &[u8]) -> Option<Vec<u8>> {
    let mut args = vec!["upload-pack", "--stateless-rpc"];
    if advertise {
        args.push("--advertise-refs");
    }
    let mut child = std::process::Command::new("git")
        .args(&args)
        .arg(".")
        .current_dir(bare)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(body).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

fn serve(
    stream: &mut TcpStream,
    rpc: &str,
    bare: &Path,
    name: &str,
    observations: &Arc<Mutex<Vec<SocketAddr>>>,
) {
    if let Ok(peer) = stream.peer_addr() {
        observations
            .lock()
            .expect("AUR fixture log poisoned")
            .push(peer);
    }
    let Some((head_end, request)) = read_request(stream) else {
        return;
    };
    let head = String::from_utf8_lossy(&request[..head_end]).to_ascii_lowercase();
    let request_line = String::from_utf8_lossy(&request);
    let path = request_line
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let mut body = request[head_end..].to_vec();
    if head.contains("content-encoding: gzip") {
        let mut plain = Vec::new();
        if flate2::read::GzDecoder::new(&body[..])
            .read_to_end(&mut plain)
            .is_err()
        {
            return;
        }
        body = plain;
    }

    let advertise_path = format!("/{name}.git/info/refs");
    let upload_path = format!("/{name}.git/git-upload-pack");
    let (status, content_type, out) = if path.starts_with("/rpc/v5/info") {
        ("200 OK", "application/json", rpc.as_bytes().to_vec())
    } else if path.split('?').next() == Some(advertise_path.as_str()) {
        match upload_pack(bare, true, b"") {
            Some(advertisement) => {
                // Smart HTTP: the service pkt-line the client expects before
                // upload-pack's ref advertisement.
                let mut out = b"001e# service=git-upload-pack\n0000".to_vec();
                out.extend_from_slice(&advertisement);
                ("200 OK", "application/x-git-upload-pack-advertisement", out)
            }
            None => (
                "500 Internal Server Error",
                "text/plain",
                b"upload-pack failed".to_vec(),
            ),
        }
    } else if path == upload_path {
        match upload_pack(bare, false, &body) {
            Some(out) => ("200 OK", "application/x-git-upload-pack", out),
            None => (
                "500 Internal Server Error",
                "text/plain",
                b"upload-pack failed".to_vec(),
            ),
        }
    } else {
        ("404 Not Found", "text/plain", b"not found".to_vec())
    };

    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        out.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&out);
}
