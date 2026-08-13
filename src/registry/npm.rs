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

    fn packument(&self, name: &str) -> Result<Packument, BluelineError> {
        // Scoped packages must have the slash percent-encoded in the path.
        let encoded = name.replace('/', "%2f");
        let url = format!("{}/{}", self.base, encoded);
        let resp = self
            .agent
            .get(&url)
            .set("accept", CORGI_ACCEPT)
            .call()
            .map_err(|e| BluelineError::Network(format!("GET {url}: {e}")))?;
        let body = resp
            .into_string()
            .map_err(|e| BluelineError::Network(format!("reading {url}: {e}")))?;
        serde_json::from_str(&body).map_err(|e| {
            BluelineError::Manifest(name.to_string(), format!("invalid packument JSON: {e}"))
        })
    }

    /// Stream-download the tarball, hashing as we go, then fail closed unless
    /// the sha512 matches the registry's `dist.integrity`.
    fn fetch_url_verified(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError> {
        let resp = self
            .agent
            .get(&pkg.tarball_url)
            .call()
            .map_err(|e| BluelineError::Network(format!("GET {}: {e}", pkg.tarball_url)))?;
        let mut reader = resp.into_reader();
        let mut hasher = Sha512::new();
        let mut buf = [0u8; 64 * 1024];
        let mut bytes = Vec::new();
        loop {
            let n = reader.read(&mut buf).map_err(|e| {
                BluelineError::Network(format!("downloading {}: {e}", pkg.tarball_url))
            })?;
            if n == 0 {
                break;
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
                    list_versions(&packument)
                ),
            )
        })?;
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
}

fn list_versions(packument: &Packument) -> String {
    let mut keys: Vec<&String> = packument.versions.keys().collect();
    keys.sort();
    keys.iter()
        .rev()
        .take(8)
        .map(|v| v.as_str())
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
