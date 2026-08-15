use std::collections::BTreeMap;
use std::io::Read;

use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha512};
use ureq::Agent;

use crate::error::BluelineError;
use crate::registry::{Package, Registry};

/// Abbreviated packument (corgi) media type — small enough to be sane
/// for large packages like express.
const CORGI_ACCEPT: &str = "application/vnd.npm.install-v1+json";
const USER_AGENT: &str = concat!("blueline/", env!("CARGO_PKG_VERSION"));
const SRI_PREFIX: &str = "sha512-";

#[derive(Debug, Clone, Copy)]
pub struct RegistryLimits {
    pub max_packument_bytes: u64,
    pub max_tarball_bytes: u64,
    pub max_redirects: usize,
}

impl Default for RegistryLimits {
    fn default() -> Self {
        Self {
            max_packument_bytes: 64 * 1024 * 1024,
            max_tarball_bytes: 512 * 1024 * 1024,
            max_redirects: 5,
        }
    }
}

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

    fn validate_tarball_url(&self, tarball_url: &str) -> Result<(), BluelineError> {
        let (tarball_scheme, tarball_host) =
            parse_url_scheme_and_host(tarball_url).map_err(|e| {
                BluelineError::Network(format!("invalid tarball URL `{tarball_url}`: {e}"))
            })?;

        let (base_scheme, base_host) = parse_url_scheme_and_host(&self.base).map_err(|e| {
            BluelineError::Network(format!("invalid registry base URL `{}`: {e}", self.base))
        })?;

        if base_scheme == "https" {
            if tarball_scheme != "https" {
                return Err(BluelineError::Network(format!(
                    "insecure tarball scheme `{tarball_scheme}` in `{tarball_url}`; registry base requires HTTPS"
                )));
            }
        } else if base_scheme == "http" {
            match tarball_scheme.as_str() {
                "http" | "https" => {}
                _ => {
                    return Err(BluelineError::Network(format!(
                        "unsupported tarball scheme `{tarball_scheme}` in `{tarball_url}`"
                    )));
                }
            }
        } else {
            return Err(BluelineError::Network(format!(
                "unsupported registry base scheme `{base_scheme}` in `{}`",
                self.base
            )));
        }

        if is_private_or_local_host(&tarball_host) && base_host != tarball_host {
            return Err(BluelineError::Network(format!(
                "tarball URL `{tarball_url}` targets private/local host `{tarball_host}`, which does not match registry base host `{base_host}`"
            )));
        }

        Ok(())
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
        let mut current_url = pkg.tarball_url.clone();
        let mut redirects_followed = 0;

        let resp = loop {
            self.validate_tarball_url(&current_url)?;
            let res = self.agent.get(&current_url).call();
            match res {
                Ok(response) if (301..=308).contains(&response.status()) => {
                    redirects_followed += 1;
                    if redirects_followed > self.limits.max_redirects {
                        return Err(BluelineError::Network(format!(
                            "too many redirects downloading {}",
                            pkg.tarball_url
                        )));
                    }
                    let location = response.header("location").ok_or_else(|| {
                        BluelineError::Network(format!(
                            "redirect {} missing Location header for {current_url}",
                            response.status()
                        ))
                    })?;
                    current_url = location.to_string();
                }
                Ok(response) => break response,
                Err(e) => {
                    return Err(BluelineError::Network(format!(
                        "GET {}: {e}",
                        pkg.tarball_url
                    )));
                }
            }
        };

        let mut bytes = Vec::new();
        let mut reader = resp.into_reader().take(self.limits.max_tarball_bytes + 1);
        reader
            .read_to_end(&mut bytes)
            .map_err(|e| BluelineError::Network(format!("downloading {}: {e}", pkg.tarball_url)))?;

        if bytes.len() as u64 > self.limits.max_tarball_bytes {
            return Err(BluelineError::ExtractionLimit(format!(
                "tarball exceeds maximum size cap of {} bytes",
                self.limits.max_tarball_bytes
            )));
        }

        let mut hasher = Sha512::new();
        hasher.update(&bytes);
        let digest = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        match pkg.integrity.as_deref() {
            Some(expected) => {
                let expected_b64 = expected
                    .strip_prefix(SRI_PREFIX)
                    .ok_or_else(|| {
                        BluelineError::Verification(format!(
                            "{}@{}: unsupported dist.integrity `{expected}`, expected `{SRI_PREFIX}<base64>`",
                            pkg.name, pkg.version
                        ))
                    })?
                    .trim();
                if digest != expected_b64 {
                    return Err(BluelineError::Verification(format!(
                        "{}@{}: tarball sha512 mismatch (expected {expected}, got {SRI_PREFIX}{digest})",
                        pkg.name, pkg.version
                    )));
                }
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
}

impl Registry for NpmRegistry {
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
        self.validate_tarball_url(&meta.dist.tarball)?;
        validate_package_name(&meta.name)?;
        Ok(Package {
            name: meta.name.clone(),
            version: meta.version.clone(),
            tarball_url: meta.dist.tarball.clone(),
            integrity: meta.dist.integrity.clone(),
        })
    }

    fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError> {
        self.fetch_url_verified(pkg)
    }

    fn list_versions(&self, name: &str) -> Result<Vec<semver::Version>, BluelineError> {
        let packument = self.packument(name)?;
        let mut versions: Vec<semver::Version> = packument
            .versions
            .keys()
            .filter_map(|v| semver::Version::parse(v).ok())
            .collect();
        versions.sort();
        Ok(versions)
    }

    fn resolve_dist_tag(&self, name: &str, tag: &str) -> Result<Option<String>, BluelineError> {
        let packument = self.packument(name)?;
        Ok(packument.dist_tags.get(tag).cloned())
    }
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

fn parse_url_scheme_and_host(raw_url: &str) -> Result<(String, String), String> {
    let (scheme, rest) = raw_url
        .split_once("://")
        .ok_or_else(|| format!("URL `{raw_url}` is missing `://` scheme separator"))?;
    let scheme = scheme.to_lowercase();
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(format!("URL `{raw_url}` has empty host"));
    }
    let host_port = if let Some((_, hp)) = authority.rsplit_once('@') {
        hp
    } else {
        authority
    };
    let host = if host_port.starts_with('[') {
        let closing = host_port
            .find(']')
            .ok_or_else(|| format!("URL `{raw_url}` has unmatched `[` in IPv6 address"))?;
        &host_port[1..closing]
    } else if let Some((h, _port)) = host_port.split_once(':') {
        h
    } else {
        host_port
    };
    if host.is_empty() {
        return Err(format!("URL `{raw_url}` has empty host"));
    }
    Ok((scheme, host.to_lowercase()))
}

fn is_private_v4(v4: std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback()
        || v4.is_link_local()
        || v4.is_private()
        || v4.is_unspecified()
        || v4.is_broadcast()
        // CGNAT RFC 6598 (100.64.0.0/10)
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
}

fn is_private_or_local_host(host: &str) -> bool {
    if host == "localhost"
        || host.ends_with(".localhost")
        || host == "metadata.google.internal"
        || host == "instance-data"
    {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => is_private_v4(v4),
            std::net::IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    is_private_v4(v4)
                } else {
                    v6.is_loopback()
                        || v6.is_unspecified()
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                        || (v6.segments()[0] & 0xfe00) == 0xfc00
                }
            }
        }
    } else {
        false
    }
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
    fn validates_tarball_url_ssrf_and_schemes() {
        let reg = NpmRegistry::new("https://registry.npmjs.org");

        // Public https is valid
        assert!(
            reg.validate_tarball_url("https://registry.npmjs.org/express/-/express-4.21.2.tgz")
                .is_ok()
        );
        assert!(
            reg.validate_tarball_url("https://cdn.example.com/express.tgz")
                .is_ok()
        );

        // Insecure http rejected when base is https
        assert!(
            reg.validate_tarball_url("http://registry.npmjs.org/express.tgz")
                .is_err()
        );

        // Localhost / Loopback rejected
        assert!(
            reg.validate_tarball_url("https://127.0.0.1/express.tgz")
                .is_err()
        );
        assert!(
            reg.validate_tarball_url("https://localhost/express.tgz")
                .is_err()
        );
        assert!(
            reg.validate_tarball_url("https://[::1]/express.tgz")
                .is_err()
        );

        // Cloud metadata rejected
        assert!(
            reg.validate_tarball_url("https://169.254.169.254/latest/meta-data")
                .is_err()
        );
        assert!(
            reg.validate_tarball_url("https://metadata.google.internal/computeMetadata")
                .is_err()
        );

        // RFC 1918 private IPs rejected
        assert!(
            reg.validate_tarball_url("https://10.0.0.1/tarball.tgz")
                .is_err()
        );
        assert!(
            reg.validate_tarball_url("https://192.168.1.50/tarball.tgz")
                .is_err()
        );
        assert!(
            reg.validate_tarball_url("https://172.16.0.10/tarball.tgz")
                .is_err()
        );

        // Local registry allows matching local host
        let local_reg = NpmRegistry::new("http://127.0.0.1:8080");
        assert!(
            local_reg
                .validate_tarball_url("http://127.0.0.1:8080/express/-/express-1.0.0.tgz")
                .is_ok()
        );
        assert!(
            local_reg
                .validate_tarball_url("https://127.0.0.1:8080/express/-/express-1.0.0.tgz")
                .is_ok()
        );
        assert!(
            local_reg
                .validate_tarball_url("ftp://127.0.0.1:8080/express/-/express-1.0.0.tgz")
                .is_err()
        );
        assert!(
            local_reg
                .validate_tarball_url("file:///etc/passwd")
                .is_err()
        );
        let ftp_reg = NpmRegistry::new("ftp://127.0.0.1:8080");
        assert!(
            ftp_reg
                .validate_tarball_url("ftp://127.0.0.1:8080/pkg.tgz")
                .is_err()
        );
        // But local registry cannot be bounced to metadata
        assert!(
            local_reg
                .validate_tarball_url("http://169.254.169.254/latest/meta-data")
                .is_err()
        );
    }

    #[test]
    fn is_private_or_local_host_covers_all_ranges() {
        assert!(is_private_or_local_host("localhost"));
        assert!(is_private_or_local_host("foo.localhost"));
        assert!(is_private_or_local_host("metadata.google.internal"));
        assert!(is_private_or_local_host("instance-data"));
        assert!(is_private_or_local_host("127.0.0.1"));
        assert!(is_private_or_local_host("169.254.169.254"));
        assert!(is_private_or_local_host("10.0.0.1"));
        assert!(is_private_or_local_host("172.16.0.1"));
        assert!(is_private_or_local_host("192.168.1.1"));
        assert!(is_private_or_local_host("0.0.0.0"));
        assert!(is_private_or_local_host("255.255.255.255"));
        assert!(is_private_or_local_host("::1"));
        assert!(is_private_or_local_host("::"));
        assert!(is_private_or_local_host("fe80::1"));
        assert!(is_private_or_local_host("fc00::1"));
        assert!(is_private_or_local_host("::ffff:127.0.0.1"));
        assert!(is_private_or_local_host("::ffff:169.254.169.254"));
        assert!(is_private_or_local_host("::ffff:10.0.0.1"));
        assert!(is_private_or_local_host("100.64.0.1"));
        assert!(is_private_or_local_host("100.127.255.254"));

        assert!(!is_private_or_local_host("registry.npmjs.org"));
        assert!(!is_private_or_local_host("8.8.8.8"));
        assert!(!is_private_or_local_host("1.1.1.1"));
        assert!(!is_private_or_local_host("100.63.255.255"));
        assert!(!is_private_or_local_host("100.128.0.1"));
        assert!(!is_private_or_local_host("2607:f8b0:4005:805::200e"));
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
            // Exactly 4 requests: testpkg dist-tag, testpkg resolve, mismatchname, mismatchver
            for _ in 0..4 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    if req.contains("GET /testpkg ") {
                        let body = r#"{"name":"testpkg","dist-tags":{"latest":"2.1.0"},"versions":{"2.1.0":{"name":"testpkg","version":"2.1.0","dist":{"tarball":"http://127.0.0.1:1/pkg.tgz","integrity":"sha512-test"}}}}"#;
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
        let tag = reg.resolve_dist_tag("testpkg", "latest").unwrap();
        assert_eq!(tag, Some("2.1.0".into()));

        let pkg = reg.resolve("testpkg", "2.1.0").unwrap();
        assert_eq!(pkg.name, "testpkg");
        assert_eq!(pkg.version, "2.1.0");

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
            // Request 1 & 2: successful redirect (1 redirect)
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/final.tgz\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes());
            }
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(payload);
            }

            // Next 6 requests: loop of 6 redirects
            for _ in 0..6 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        });

        let reg = NpmRegistry::new(&base);

        // 1 redirect succeeds and fetches tarball bytes
        let pkg_ok = Package {
            name: "test".into(),
            version: "1.0.0".into(),
            tarball_url: format!("{base}/redirect1"),
            integrity: Some(integrity),
        };
        let bytes = reg.fetch_url_verified(&pkg_ok).unwrap();
        assert_eq!(bytes, payload);

        // 6 redirects exceeds MAX_REDIRECTS (5) and errors out
        let pkg_loop = Package {
            name: "test".into(),
            version: "1.0.0".into(),
            tarball_url: format!("{base}/loop"),
            integrity: Some("sha512-test".into()),
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
            for _ in 0..2 {
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
            for _ in 0..2 {
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
            for _ in 0..2 {
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
            integrity: Some(exact_integrity),
        };
        let bytes = reg.fetch_url_verified(&pkg_exact).unwrap();
        assert_eq!(bytes.len(), 50);

        let pkg_over = Package {
            name: "over".into(),
            version: "1.0.0".into(),
            tarball_url: format!("{base}/over.tgz"),
            integrity: Some(over_integrity),
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
            // Test 1: Exactly 2 redirects -> /r1 -> /r2 -> /ok.tgz (3 requests)
            for i in 1..=2 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let target = if i == 1 {
                        format!("http://127.0.0.1:{port}/r2")
                    } else {
                        format!("http://127.0.0.1:{port}/ok.tgz")
                    };
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(payload);
            }

            // Test 2: 3 redirects with limit 2 -> /over1 -> /over2 -> /over3 (3 redirects = 3 302 responses)
            for i in 1..=3 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let target = format!("http://127.0.0.1:{port}/over{}", i + 1);
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(resp.as_bytes());
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
            integrity: Some(integrity),
        };
        let bytes = reg.fetch_url_verified(&pkg_ok).unwrap();
        assert_eq!(bytes, payload);

        // 3 redirects: exceeds max_redirects (2) and fails
        let pkg_over = Package {
            name: "test".into(),
            version: "1.0.0".into(),
            tarball_url: format!("{base}/over1"),
            integrity: Some("sha512-test".into()),
        };
        let err = reg.fetch_url_verified(&pkg_over).unwrap_err();
        assert!(err.to_string().contains("too many redirects"));

        let _ = handle.join();
    }
}
