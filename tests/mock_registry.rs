//! Shared raw-HTTP mock registry for the CLI integration tests (agent,
//! recall, shim). Each test binary includes this as its own module; items
//! unused by one binary would otherwise fail `-D warnings`, so this module
//! opts out of dead-code analysis instead of pushing the fixture back into
//! copy-paste.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use base64::Engine as _;
use sha2::{Digest, Sha512};

pub struct Fixture {
    pub base: String,
    pub _server: std::thread::JoinHandle<()>,
}

/// Mini HTTP/1.1 registry serving two packages: packuments at `/{name}`
/// and tarballs at `/{name}/-/{name}-{version}.tgz`. No external network.
///
/// The server binds first so the packument can embed the real base URL.
pub fn spawn_fixture<F>(build: F) -> Fixture
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

pub fn serve(stream: &mut TcpStream, packages: &Arc<HashMap<String, (String, Vec<u8>)>>) {
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

pub fn tarball_with(json: &str, extra: &[(&str, &[u8])]) -> Vec<u8> {
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

pub fn sha512_b64(data: &[u8]) -> String {
    let digest = Sha512::digest(data);
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

pub fn packument(name: &str, base: &str, version: &str, integrity: &str) -> String {
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
