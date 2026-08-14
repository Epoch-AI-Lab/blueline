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
const MAX_PACKUMENT_BYTES: u64 = 33_554_432;
const MAX_TARBALL_BYTES: usize = 268_435_456;

pub struct NpmRegistry {
    agent: Agent,
    base: String,
}

impl NpmRegistry {
    pub fn new(base: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(90))
            .user_agent(USER_AGENT)
            .redirects(10)
            .build();
        Self {
            agent,
            base: base.trim_end_matches('/').to_string(),
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
            if tarball_scheme != "http" && tarball_scheme != "https" {
                return Err(BluelineError::Network(format!(
                    "unsupported tarball scheme `{tarball_scheme}` in `{tarball_url}`"
                )));
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
        resp.into_reader()
            .take(MAX_PACKUMENT_BYTES)
            .read_to_string(&mut body)
            .map_err(|e| BluelineError::Network(format!("reading {url}: {e}")))?;
        let packument: Packument = serde_json::from_str(&body).map_err(|e| {
            BluelineError::Manifest(name.to_string(), format!("invalid packument JSON: {e}"))
        })?;
        validate_package_name(&packument.name)?;
        Ok(packument)
    }

    /// Stream-download the tarball, hashing as we go, then fail closed unless
    /// the sha512 matches the registry's `dist.integrity`.
    fn fetch_url_verified(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError> {
        self.validate_tarball_url(&pkg.tarball_url)?;
        let resp = self
            .agent
            .get(&pkg.tarball_url)
            .call()
            .map_err(|e| BluelineError::Network(format!("GET {}: {e}", pkg.tarball_url)))?;
        let mut reader = resp.into_reader();
        let mut hasher = Sha512::new();
        let mut buf = [0u8; 65536];
        let mut bytes = Vec::new();
        loop {
            let n = reader.read(&mut buf).map_err(|e| {
                BluelineError::Network(format!("downloading {}: {e}", pkg.tarball_url))
            })?;
            if n == 0 {
                break;
            }
            if bytes.len().saturating_add(n) > MAX_TARBALL_BYTES {
                return Err(BluelineError::ExtractionLimit(format!(
                    "tarball download exceeded maximum allowed size of {MAX_TARBALL_BYTES} bytes"
                )));
            }
            hasher.update(&buf[..n]);
            bytes.extend_from_slice(&buf[..n]);
        }

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
}

fn validate_package_name(name: &str) -> Result<(), BluelineError> {
    if name.is_empty() || name.chars().any(|c| c.is_control()) {
        return Err(BluelineError::Manifest(
            name.to_string(),
            "invalid package name: empty or contains control characters".to_string(),
        ));
    }
    if name.contains('\\')
        || name
            .split('/')
            .any(|part| part == "." || part == ".." || part.is_empty())
    {
        return Err(BluelineError::Manifest(
            name.to_string(),
            "invalid package name: contains path traversal or invalid segments".to_string(),
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
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_private()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
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
    #[allow(dead_code)]
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
        assert!(is_private_or_local_host("fd00::1"));

        assert!(!is_private_or_local_host("registry.npmjs.org"));
        assert!(!is_private_or_local_host("8.8.8.8"));
        assert!(!is_private_or_local_host("1.1.1.1"));
        assert!(!is_private_or_local_host("2607:f8b0:4005:805::200e"));
    }
}
