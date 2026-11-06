//! Shared AUR git/smart-HTTP fixture helpers for the AUR CLI tests. One
//! copy so `tests/aur_cli.rs` and `tests/aur_ci_parallel.rs` cannot drift.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

pub fn fixture_git(dir: &Path, args: &[&str]) {
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

pub fn read_http_request(stream: &mut TcpStream) -> Option<(usize, Vec<u8>)> {
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

pub fn upload_pack(bare: &Path, advertise: bool, body: &[u8]) -> Option<Vec<u8>> {
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
