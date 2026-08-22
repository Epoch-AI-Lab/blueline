use std::collections::BTreeMap;
use std::io::Read;

use serde::Deserialize;
use sha2::{Digest, Sha512};
use ureq::Agent;

use crate::error::BluelineError;
use crate::registry::http_util::{RegistryLimits, download_bounded};
use crate::registry::{Checksum, ChecksumAlg, Ecosystem, Package, Registry, Release};

/// Abbreviated packument (corgi) media type — small enough to be sane
/// for large packages like express.
const CORGI_ACCEPT: &str = "application/vnd.npm.install-v1+json";
const USER_AGENT: &str = concat!("blueline/", env!("CARGO_PKG_VERSION"));

pub struct NpmRegistry {
    agent: Agent,
    base: String,
    limits: RegistryLimits,
}

impl NpmRegistry {
    pub fn new(base: &str) -> Self {
        Self::with_limits(base, RegistryLimits::default())
    }

    pub fn with_limits(base: &str, limits: RegistryLimits) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(90))
            .user_agent(USER_AGENT)
            .redirects(0) // Do not follow redirects automatically without SSRF validation
            .build();
        Self {
            agent,
            base: base.trim_end_matches('/').to_string(),
            limits,
        }
    }

    fn packument(&self, name: &str) -> Result<Packument, BluelineError> {
        validate_package_name(name)?;
        // Scoped packages must have the slash percent-encoded in the path.
        let encoded = name.replace('/', "%2f");
        let url = format!("{}/{}", self.base, encoded);
        let resp = self
            .agent
            .get(&url)
            .set("accept", CORGI_ACCEPT)
            .call()
            .map_err(|e| BluelineError::Network(format!("GET {url}: {e}")))?;

        let mut body = String::new();
        let mut reader = resp.into_reader().take(self.limits.max_packument_bytes + 1);
        reader
            .read_to_string(&mut body)
            .map_err(|e| BluelineError::Network(format!("reading {url}: {e}")))?;

        if body.len() as u64 > self.limits.max_packument_bytes {
            return Err(BluelineError::Manifest(
                name.to_string(),
                format!(
                    "packument exceeds maximum cap of {} bytes",
                    self.limits.max_packument_bytes
                ),
            ));
        }

        let packument: Packument = serde_json::from_str(&body).map_err(|e| {
            BluelineError::Manifest(name.to_string(), format!("corrupt packument JSON: {e}"))
        })?;
        validate_package_name(&packument.name)?;
        Ok(packument)
    }

    /// Stream-download the tarball, hashing as we go, then fail closed unless
    /// the sha512 matches the registry's `dist.integrity`.
    fn fetch_url_verified(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError> {
        let bytes = download_bounded(
            &self.agent,
            &self.base,
            &pkg.tarball_url,
            self.limits.max_tarball_bytes,
            self.limits.max_redirects,
        )
        .map_err(|e| match e {
            BluelineError::ExtractionLimit(_) => BluelineError::ExtractionLimit(format!(
                "tarball exceeds maximum size cap of {} bytes",
                self.limits.max_tarball_bytes
            )),
            other => other,
        })?;

        let mut hasher = Sha512::new();
        hasher.update(&bytes);
        let computed = Checksum {
            alg: ChecksumAlg::Sha512,
            value_hex: hex_encode(&hasher.finalize()),
        };
        match &pkg.integrity {
            Some(expected) if expected.alg == ChecksumAlg::Sha512 => {
                if !expected.value_hex.eq_ignore_ascii_case(&computed.value_hex) {
                    return Err(BluelineError::Verification(format!(
                        "{}@{}: tarball sha512 mismatch (expected {}, got {})",
                        pkg.name,
                        pkg.version,
                        expected.to_sri(),
                        computed.to_sri()
                    )));
                }
            }
            Some(expected) => {
                return Err(BluelineError::Verification(format!(
                    "{}@{}: unsupported dist.integrity algorithm `{}`, expected sha512",
                    pkg.name,
                    pkg.version,
                    expected.alg.name()
                )));
            }
            None => {
                return Err(BluelineError::Verification(format!(
                    "{}@{}: registry provided no dist.integrity; refusing to trust unverifiable bytes",
                    pkg.name, pkg.version
                )));
            }
        }
        Ok(bytes)
    }

    /// Normalize the packument's raw `dist.integrity` string into a typed
    /// checksum. Fail closed when nothing sha512-shaped can be decoded.
    fn normalize_integrity(
        &self,
        pkg_name: &str,
        version: &str,
        raw: &Option<String>,
    ) -> Result<Option<Checksum>, BluelineError> {
        match raw {
            None => Ok(None),
            Some(s) => Checksum::parse(s)
                .map(Some)
                .map_err(|_| {
                    BluelineError::Verification(format!(
                        "{pkg_name}@{version}: unsupported dist.integrity `{s}`, expected `sha512-<base64>`"
                    ))
                }),
        }
    }
}

impl Registry for NpmRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn resolve(&self, name: &str, version: &str) -> Result<Package, BluelineError> {
        let packument = self.packument(name)?;
        let meta = packument.versions.get(version).ok_or_else(|| {
            BluelineError::Manifest(
                name.to_string(),
                format!(
                    "no version `{version}` (have: {})",
                    summarize_versions(&packument)
                ),
            )
        })?;
        if meta.name != name || meta.version != version {
            return Err(BluelineError::Manifest(
                name.to_string(),
                format!(
                    "registry metadata mismatch: expected {name}@{version}, got {}@{}",
                    meta.name, meta.version
                ),
            ));
        }
        crate::registry::http_util::validate_download_url(&self.base, &meta.dist.tarball)?;
        validate_package_name(&meta.name)?;
        Ok(Package {
            name: meta.name.clone(),
            version: meta.version.clone(),
            tarball_url: meta.dist.tarball.clone(),
            integrity: self.normalize_integrity(name, version, &meta.dist.integrity)?,
        })
    }

    fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError> {
        self.fetch_url_verified(pkg)
    }

    fn list_versions(&self, name: &str) -> Result<Vec<semver::Version>, BluelineError> {
        let mut versions: Vec<semver::Version> = self
            .packument(name)?
            .versions
            .keys()
            .filter_map(|v| semver::Version::parse(v).ok())
            .collect();
        versions.sort();
        Ok(versions)
    }

    fn list_releases(&self, name: &str) -> Result<Vec<Release>, BluelineError> {
        let releases = self.list_versions(name)?;
        // npm's corgi packument does not expose yanked or publish time.
        Ok(releases
            .into_iter()
            .map(|v| Release {
                version: v.to_string(),
                yanked: false,
                publish_time: None,
            })
            .collect())
    }

    fn default_version(&self, name: &str) -> Result<Option<String>, BluelineError> {
        let packument = self.packument(name)?;
        if let Some(latest) = packument.dist_tags.get("latest") {
            return Ok(Some(latest.clone()));
        }
        let mut versions: Vec<semver::Version> = packument
            .versions
            .keys()
            .filter_map(|v| semver::Version::parse(v).ok())
            .collect();
        versions.sort();
        Ok(versions
            .iter()
            .rfind(|v| v.pre.is_empty())
            .or_else(|| versions.last())
            .map(|v| v.to_string()))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_valid_name_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.starts_with('.')
        && !s.starts_with('_')
        && s.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.'
        })
}

fn validate_package_name(name: &str) -> Result<(), BluelineError> {
    if name.is_empty() || name.len() > 214 {
        return Err(BluelineError::Manifest(
            name.to_string(),
            "invalid package name: empty or exceeds 214 characters".to_string(),
        ));
    }
    if name.contains('\\')
        || name.contains('?')
        || name.contains('#')
        || name.contains('&')
        || name.contains('%')
        || name.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(BluelineError::Manifest(
            name.to_string(),
            "invalid package name: contains forbidden characters".to_string(),
        ));
    }

    let is_valid = if let Some(stripped) = name.strip_prefix('@') {
        if let Some((scope, rest)) = stripped.split_once('/') {
            is_valid_name_segment(scope) && is_valid_name_segment(rest) && !rest.contains('/')
        } else {
            false
        }
    } else {
        is_valid_name_segment(name) && !name.contains('/')
    };

    if !is_valid {
        return Err(BluelineError::Manifest(
            name.to_string(),
            "invalid package name format".to_string(),
        ));
    }
    Ok(())
}

fn summarize_versions(packument: &Packument) -> String {
    let mut semvers: Vec<semver::Version> = packument
        .versions
        .keys()
        .filter_map(|v| semver::Version::parse(v).ok())
        .collect();
    semvers.sort();
    semvers
        .iter()
        .rev()
        .take(8)
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Deserialize)]
struct Packument {
    #[allow(dead_code)]
    name: String,
    #[serde(rename = "dist-tags")]
    dist_tags: BTreeMap<String, String>,
    versions: BTreeMap<String, VersionMeta>,
}

#[derive(Debug, Deserialize)]
struct VersionMeta {
    name: String,
    version: String,
    dist: Dist,
}

#[derive(Debug, Deserialize)]
struct Dist {
    tarball: String,
    integrity: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// sha512 SRI of the bytes "tarball-content".
    const TEST_SRI: &str = "sha512-dWJ6JIJkmHG8N3fH1b/hbpmBQ7wKIpEw3zsVl2873OtFXh9QhR1KUU3uojohuIJ/xd+hb1R0q/57C8sMt4tstQ==";

    #[test]
    fn list_versions_orders_and_limits() {
        let versions: BTreeMap<String, VersionMeta> =
            ["1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0", "10.0.0"]
                .iter()
                .map(|v| {
                    let vm = VersionMeta {
                        name: "p".into(),
                        version: v.to_string(),
                        dist: Dist {
                            tarball: String::new(),
                            integrity: None,
                        },
                    };
                    (v.to_string(), vm)
                })
                .collect();
        let pm = Packument {
            name: "p".into(),
            dist_tags: BTreeMap::new(),
            versions,
        };
        // Semver precedence in descending order capped at 8
        assert_eq!(
            summarize_versions(&pm),
            "10.0.0, 2.0.0, 1.10.0, 1.2.0, 1.0.1, 1.0.0"
        );
    }

    #[test]
    fn validates_package_names() {
        assert!(validate_package_name("express").is_ok());
        assert!(validate_package_name("@scope/pkg").is_ok());
        assert!(validate_package_name("lodash.debounce").is_ok());
        assert!(validate_package_name("my-package-123_x").is_ok());

        assert!(validate_package_name("").is_err());
        assert!(validate_package_name("../evil").is_err());
        assert!(validate_package_name("evil/..").is_err());
        assert!(validate_package_name("a/../b").is_err());
        assert!(validate_package_name("./a").is_err());
        assert!(validate_package_name("/a").is_err());
        assert!(validate_package_name("a/").is_err());
        assert!(validate_package_name("a//b").is_err());
        assert!(validate_package_name("a\\b").is_err());
        assert!(validate_package_name("a\0b").is_err());
        assert!(validate_package_name("a\nb").is_err());
    }

    #[test]
    fn validates_package_names_rejects_query_and_specials() {
        assert!(validate_package_name("express?foo=bar").is_err());
        assert!(validate_package_name("express#anchor").is_err());
        assert!(validate_package_name("express&cmd=1").is_err());
        assert!(validate_package_name("express%2fother").is_err());
        assert!(validate_package_name("@scope/pkg/extra").is_err());
        assert!(validate_package_name("@/pkg").is_err());
        assert!(validate_package_name("@scope/").is_err());
        assert!(validate_package_name(".pkg").is_err());
        assert!(validate_package_name("_pkg").is_err());
        assert!(validate_package_name("@.scope/pkg").is_err());
        assert!(validate_package_name("@_scope/pkg").is_err());
        assert!(validate_package_name("@scope/.pkg").is_err());
        assert!(validate_package_name("@scope/_pkg").is_err());

        // Test length boundaries: 214 is max allowed by npm, 215 is rejected
        let len214 = "a".repeat(214);
        assert!(validate_package_name(&len214).is_ok());
        let len215 = "a".repeat(215);
        assert!(validate_package_name(&len215).is_err());

        // Test individual forbidden characters in name and scope with exact error message
        let forbidden = ['\\', '?', '#', '&', '%', '\0', '\n', '\r', '\t', ' '];
        for c in forbidden {
            let err = validate_package_name(&format!("pkg{c}")).unwrap_err();
            assert!(err.to_string().contains("contains forbidden characters"));
            assert!(validate_package_name(&format!("@scope/pkg{c}")).is_err());
            assert!(validate_package_name(&format!("@scope{c}/pkg")).is_err());
        }
    }

    #[test]
    fn mock_http_resolve_and_dist_tags() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        let handle = std::thread::spawn(move || {
            // Exactly 5 requests: testpkg default_version, testpkg releases,
            // testpkg resolve, mismatchname, mismatchver
            for _ in 0..5 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    if req.contains("GET /testpkg ") {
                        let body = r#"{"name":"testpkg","dist-tags":{"latest":"2.1.0"},"versions":{"2.1.0":{"name":"testpkg","version":"2.1.0","dist":{"tarball":"http://127.0.0.1:1/pkg.tgz","integrity":"sha512-dWJ6JIJkmHG8N3fH1b/hbpmBQ7wKIpEw3zsVl2873OtFXh9QhR1KUU3uojohuIJ/xd+hb1R0q/57C8sMt4tstQ=="}}}}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("GET /mismatchname ") {
                        let body = r#"{"name":"otherpkg","dist-tags":{},"versions":{"1.0.0":{"name":"otherpkg","version":"1.0.0","dist":{"tarball":"http://127.0.0.1:1/pkg.tgz","integrity":null}}}}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("GET /mismatchver ") {
                        let body = r#"{"name":"mismatchver","dist-tags":{},"versions":{"1.0.0":{"name":"mismatchver","version":"2.0.0","dist":{"tarball":"http://127.0.0.1:1/pkg.tgz","integrity":null}}}}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                }
            }
        });

        let reg = NpmRegistry::new(&base);
        let tag = reg.default_version("testpkg").unwrap();
        assert_eq!(tag, Some("2.1.0".into()));

        let releases = reg.list_releases("testpkg").unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].version, "2.1.0");
        assert!(!releases[0].yanked);
        assert_eq!(releases[0].publish_time, None);
        assert_eq!(reg.ecosystem(), Ecosystem::Npm);

        let pkg = reg.resolve("testpkg", "2.1.0").unwrap();
        assert_eq!(pkg.name, "testpkg");
        assert_eq!(pkg.version, "2.1.0");
        assert_eq!(pkg.integrity, Some(Checksum::parse(TEST_SRI).unwrap()));

        let err_name = reg.resolve("mismatchname", "1.0.0").unwrap_err();
        assert!(err_name.to_string().contains("registry metadata mismatch"));

        let err_ver = reg.resolve("mismatchver", "1.0.0").unwrap_err();
        assert!(err_ver.to_string().contains("registry metadata mismatch"));

        let _ = handle.join();
    }

    #[test]
    fn mock_http_redirect_handling() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        let payload = b"tarball-content";
        let mut hasher = sha2::Sha512::new();
        hasher.update(payload);
        let hash = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        let integrity = format!("sha512-{hash}");

        let handle = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_millis(600) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.contains("GET /redirect1 ") {
                        let resp = format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/final.tgz\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("GET /final.tgz ") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            payload.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.write_all(payload);
                    } else if req.contains("GET /loop ") {
                        let resp = format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        });

        let reg = NpmRegistry::new(&base);

        // 1 redirect succeeds and fetches tarball bytes
        let pkg_ok = Package {
            name: "test".into(),
            version: "1.0.0".into(),
            tarball_url: format!("{base}/redirect1"),
            integrity: Some(Checksum::parse(&integrity).unwrap()),
        };
        let bytes = reg.fetch_url_verified(&pkg_ok).unwrap();
        assert_eq!(bytes, payload);

        // 6 redirects exceeds MAX_REDIRECTS (5) and errors out
        let pkg_loop = Package {
            name: "test".into(),
            version: "1.0.0".into(),
            tarball_url: format!("{base}/loop"),
            integrity: Some(Checksum::parse(TEST_SRI).unwrap()),
        };
        let err = reg.fetch_url_verified(&pkg_loop).unwrap_err();
        assert!(err.to_string().contains("too many redirects"));

        let _ = handle.join();
    }

    #[test]
    fn packument_and_tarball_size_above_false_equivalent_cap() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        // Build a tarball of 6000 bytes (above 512 + 1024 + 1024 = 2560 bytes)
        let payload = vec![b'a'; 6000];
        let mut hasher = sha2::Sha512::new();
        hasher.update(&payload);
        let hash = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        let integrity = format!("sha512-{hash}");

        let handle = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_millis(600) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    if req.contains("GET /bigpkg ") {
                        // Packument of 6000 bytes (above 64 + 1024 + 1024 = 2112 bytes)
                        let padding = "a".repeat(5000);
                        let body = format!(
                            r#"{{"name":"bigpkg","description":"{padding}","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"bigpkg","version":"1.0.0","dist":{{"tarball":"http://127.0.0.1:{port}/big.tgz","integrity":"{integrity}"}}}}}}}}"#
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("GET /big.tgz ") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            payload.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.write_all(&payload);
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        });

        let reg = NpmRegistry::new(&base);
        let pkg = reg.resolve("bigpkg", "1.0.0").unwrap();
        assert_eq!(pkg.name, "bigpkg");

        let tarball_bytes = reg.fetch_tarball(&pkg).unwrap();
        assert_eq!(tarball_bytes.len(), 6000);

        let _ = handle.join();
    }

    #[test]
    fn packument_exact_limits_boundary() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        let body_exact = r#"{"name":"exactpkg","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"exactpkg","version":"1.0.0","dist":{"tarball":"http://127.0.0.1:1/p.tgz","integrity":null}}}}"#;
        let exact_len = body_exact.len();
        let body_over = format!("{body_exact} ");

        let handle = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_millis(600) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    if req.contains("GET /exactpkg ") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body_exact.len(),
                            body_exact
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("GET /overpkg ") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body_over.len(),
                            body_over
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        });

        let reg_exact = NpmRegistry::with_limits(
            &base,
            RegistryLimits {
                max_packument_bytes: exact_len as u64,
                ..RegistryLimits::default()
            },
        );
        let pkg = reg_exact.resolve("exactpkg", "1.0.0").unwrap();
        assert_eq!(pkg.name, "exactpkg");

        // Over cap: over body length is exact_len + 1 with limit exact_len
        let err = reg_exact.resolve("overpkg", "1.0.0").unwrap_err();
        assert!(err.to_string().contains("packument exceeds maximum cap"));

        let _ = handle.join();
    }

    #[test]
    fn tarball_exact_limits_boundary() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        let exact_payload = vec![b'x'; 50];
        let mut hasher = sha2::Sha512::new();
        hasher.update(&exact_payload);
        let hash = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        let exact_integrity = format!("sha512-{hash}");

        let over_payload = vec![b'y'; 51];
        let mut hasher2 = sha2::Sha512::new();
        hasher2.update(&over_payload);
        let hash2 = base64::engine::general_purpose::STANDARD.encode(hasher2.finalize());
        let over_integrity = format!("sha512-{hash2}");

        let handle = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_millis(600) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    if req.contains("GET /exact.tgz ") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            exact_payload.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.write_all(&exact_payload);
                    } else if req.contains("GET /over.tgz ") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            over_payload.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.write_all(&over_payload);
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        });

        let reg = NpmRegistry::with_limits(
            &base,
            RegistryLimits {
                max_tarball_bytes: 50,
                ..RegistryLimits::default()
            },
        );

        let pkg_exact = Package {
            name: "exact".into(),
            version: "1.0.0".into(),
            tarball_url: format!("{base}/exact.tgz"),
            integrity: Some(Checksum::parse(&exact_integrity).unwrap()),
        };
        let bytes = reg.fetch_url_verified(&pkg_exact).unwrap();
        assert_eq!(bytes.len(), 50);

        let pkg_over = Package {
            name: "over".into(),
            version: "1.0.0".into(),
            tarball_url: format!("{base}/over.tgz"),
            integrity: Some(Checksum::parse(&over_integrity).unwrap()),
        };
        let err = reg.fetch_url_verified(&pkg_over).unwrap_err();
        assert!(err.to_string().contains("tarball exceeds maximum size cap"));

        let _ = handle.join();
    }

    #[test]
    fn redirect_exact_limits_boundary() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        let payload = b"ok";
        let mut hasher = sha2::Sha512::new();
        hasher.update(payload);
        let hash = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        let integrity = format!("sha512-{hash}");

        let handle = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_millis(600) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    if req.contains("GET /r1 ") {
                        let resp = format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/r2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("GET /r2 ") {
                        let resp = format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/ok.tgz\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("GET /ok.tgz ") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            payload.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.write_all(payload);
                    } else if req.contains("GET /over1 ") {
                        let resp = format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/over2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("GET /over2 ") {
                        let resp = format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/over3\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("GET /over3 ") {
                        let resp = format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/over4\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        });

        let reg = NpmRegistry::with_limits(
            &base,
            RegistryLimits {
                max_redirects: 2,
                ..RegistryLimits::default()
            },
        );

        // Exactly 2 redirects: succeeds
        let pkg_ok = Package {
            name: "test".into(),
            version: "1.0.0".into(),
            tarball_url: format!("{base}/r1"),
            integrity: Some(Checksum::parse(&integrity).unwrap()),
        };
        let bytes = reg.fetch_url_verified(&pkg_ok).unwrap();
        assert_eq!(bytes, payload);

        // 3 redirects: exceeds max_redirects (2) and fails
        let pkg_over = Package {
            name: "test".into(),
            version: "1.0.0".into(),
            tarball_url: format!("{base}/over1"),
            integrity: Some(Checksum::parse(TEST_SRI).unwrap()),
        };
        let err = reg.fetch_url_verified(&pkg_over).unwrap_err();
        assert!(err.to_string().contains("too many redirects"));

        let _ = handle.join();
    }
}
