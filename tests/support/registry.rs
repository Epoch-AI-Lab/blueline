//! Loopback fixture servers: an npm-shaped package registry and a recall
//! snapshot service. Both bind `127.0.0.1:0` and nothing else; both record
//! what they served and who asked, so a scenario can prove that a hostile
//! tarball was fetched but never scored, and prove hermeticity by assertion.

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};

use super::tarball::{Release, TAR_SEGMENT};

#[derive(Default)]
struct Routes {
    packuments: BTreeMap<String, Vec<u8>>,
    tarballs: BTreeMap<String, Vec<u8>>,
}

#[derive(Default)]
struct Observations {
    requests: Vec<String>,
    peers: Vec<SocketAddr>,
}

/// A package registry on loopback: packuments at `/{name}`, tarballs at
/// `/{name}/-/{name}-{version}.tgz`, 404 for anything else.
pub struct Registry {
    base: String,
    addr: SocketAddr,
    observations: Arc<Mutex<Observations>>,
    _server: std::thread::JoinHandle<()>,
}

impl Registry {
    pub fn serve(releases: Vec<Release>) -> Registry {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture registry");
        let addr = listener
            .local_addr()
            .expect("read fixture registry local address");
        assert!(
            addr.ip().is_loopback(),
            "fixture registry bound a non-loopback address: {addr}"
        );
        let base = format!("http://{addr}");
        let routes = Arc::new(build_routes(&releases, &base));
        let observations = Arc::new(Mutex::new(Observations::default()));

        let server_routes = routes.clone();
        let server_observations = observations.clone();
        let server = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let routes = server_routes.clone();
                let observations = server_observations.clone();
                std::thread::spawn(move || serve(&mut stream, &routes, &observations));
            }
        });

        Registry {
            base,
            addr,
            observations,
            _server: server,
        }
    }

    /// The `--registry` value a scenario hands to the CLI.
    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every request line the registry answered, as `"GET /path"`.
    pub fn requests(&self) -> Vec<String> {
        self.observations
            .lock()
            .expect("registry log poisoned")
            .requests
            .clone()
    }

    /// Whether any request path contained `needle`. Use it to prove a
    /// tarball really was downloaded before a later stage refused it.
    pub fn requested(&self, needle: &str) -> bool {
        self.requests().iter().any(|r| r.contains(needle))
    }

    /// Peer addresses of every accepted connection. A scenario asserting
    /// this is empty proves the engine spoke to loopback and nothing else.
    pub fn peers(&self) -> Vec<SocketAddr> {
        self.observations
            .lock()
            .expect("registry log poisoned")
            .peers
            .clone()
    }

    pub fn non_loopback_peers(&self) -> Vec<SocketAddr> {
        self.peers()
            .into_iter()
            .filter(|addr| !addr.ip().is_loopback())
            .collect()
    }
}

fn build_routes(releases: &[Release], base: &str) -> Routes {
    let mut routes = Routes::default();
    for release in releases {
        let previous = routes.tarballs.insert(
            tarball_path(release.name(), release.version()),
            release.tarball().to_vec(),
        );
        assert!(
            previous.is_none(),
            "two releases share name {} version {}: a fixture cannot serve both",
            release.name(),
            release.version()
        );
    }

    let names: std::collections::BTreeSet<&str> = releases.iter().map(Release::name).collect();
    for name in names {
        let mut versions: Vec<&Release> = releases.iter().filter(|r| r.name() == name).collect();
        versions.sort_by_key(|r| {
            semver::Version::parse(r.version())
                .unwrap_or_else(|e| panic!("fixture version `{}` is not semver: {e}", r.version()))
        });
        let latest = versions
            .last()
            .expect("a packument needs at least one version")
            .version();
        let mut version_map = serde_json::Map::new();
        for release in &versions {
            version_map.insert(
                release.version().to_string(),
                release.version_document(base),
            );
        }
        let document = serde_json::json!({
            "name": name,
            "dist-tags": { "latest": latest },
            "versions": version_map,
        });
        routes.packuments.insert(
            name.to_string(),
            serde_json::to_vec(&document).expect("serialize fixture packument"),
        );
    }
    routes
}

fn tarball_path(name: &str, version: &str) -> String {
    format!("/{name}/{TAR_SEGMENT}/{name}-{version}.tgz")
}

fn serve(stream: &mut TcpStream, routes: &Arc<Routes>, observations: &Arc<Mutex<Observations>>) {
    if let Ok(peer) = stream.peer_addr() {
        observations
            .lock()
            .expect("registry log poisoned")
            .peers
            .push(peer);
    }
    let Some((method, path)) = read_request_line(stream) else {
        return;
    };
    observations
        .lock()
        .expect("registry log poisoned")
        .requests
        .push(format!("{method} {path}"));

    let key = path.trim_start_matches('/');
    let body = routes
        .tarballs
        .get(&path)
        .or_else(|| routes.packuments.get(key))
        .cloned();
    match body {
        Some(body) => respond(stream, "200 OK", "application/json", &body),
        None => respond(stream, "404 Not Found", "text/plain", b"not found"),
    }
}

fn read_request_line(stream: &mut TcpStream) -> Option<(String, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let mut parts = head.split_whitespace();
            let method = parts.next()?.to_string();
            let path = parts.next()?.to_string();
            return Some((method, path));
        }
        if buf.len() > 65_536 {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

/// A curated revocation snapshot served by the real `blueline recall serve`
/// subprocess, exactly as an operator would run it.
pub struct RecallService {
    url: String,
    child: Child,
}

impl RecallService {
    pub fn serve(snapshot: &Path) -> RecallService {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_blueline"))
            .args([
                "recall",
                "serve",
                "--port",
                "0",
                "--snapshot",
                snapshot.to_str().expect("snapshot path is valid UTF-8"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn `blueline recall serve`");

        let stdout = child.stdout.take().expect("recall serve stdout");
        let mut banner = String::new();
        std::io::BufReader::new(stdout)
            .read_line(&mut banner)
            .expect("recall serve banner");
        let port: u16 = banner
            .trim()
            .split("http://127.0.0.1:")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("cannot parse recall serve banner: {banner}"));
        RecallService {
            url: format!("http://127.0.0.1:{port}"),
            child,
        }
    }

    /// The `--url` value for `blueline recall sync`.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for RecallService {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
