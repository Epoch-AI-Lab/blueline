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
    /// Packuments already fetched in this process, keyed by package name. A
    /// review resolves the target and then asks for its signature block, and
    /// the packument can be tens of megabytes against a fail-closed 64 MiB cap,
    /// so the second call is a second full download of a document already in
    /// hand. The lifetime is one review, which is also the window in which a
    /// stale packument could matter.
    ///
    /// Byte-bounded for the same reason the tarball memo in `ReviewContext` is:
    /// a recursive review walks a dependency graph, and without a ceiling the
    /// memo is the one place the walk's own memory grows without bound. A
    /// packument over the ceiling is simply not cached, which costs a refetch
    /// and nothing else.
    packuments: std::sync::Mutex<PackumentMemo>,
}

impl NpmRegistry {
    pub fn new(base: &str) -> Self {
        Self::with_limits(base, RegistryLimits::default())
    }

    pub fn with_limits(base: &str, limits: RegistryLimits) -> Self {
        let agent = super::http_util::registry_agent(USER_AGENT, base);
        Self {
            agent,
            base: base.trim_end_matches('/').to_string(),
            limits,
            packuments: std::sync::Mutex::new(PackumentMemo::default()),
        }
    }

    /// Fetch the packument once per process. A poisoned lock means some other
    /// thread panicked holding it, and this adapter has no other state to
    /// corrupt, so the document is simply fetched again rather than erroring.
    fn packument(&self, name: &str) -> Result<Packument, BluelineError> {
        validate_package_name(name)?;
        if let Ok(cache) = self.packuments.lock()
            && let Some(hit) = cache.by_name.get(name)
        {
            return Ok(hit.clone());
        }
        let fetched = self.fetch_packument(name)?;
        if let Ok(mut cache) = self.packuments.lock() {
            cache.insert(name.to_string(), &fetched);
        }
        Ok(fetched)
    }

    fn fetch_packument(&self, name: &str) -> Result<Packument, BluelineError> {
        validate_package_name(name)?;
        // Scoped packages must have the slash percent-encoded in the path.
        let encoded = name.replace('/', "%2f");
        let url = format!("{}/{}", self.base, encoded);
        let resp = match self.agent.get(&url).set("accept", CORGI_ACCEPT).call() {
            Ok(resp) => resp,
            Err(ureq::Error::Status(404, _)) => {
                return Err(BluelineError::NotFound(name.to_string()));
            }
            Err(e) => return Err(BluelineError::Network(format!("GET {url}: {e}"))),
        };

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

    /// npm publishes the signature block on the release's own `dist`, so it
    /// is read back for the exact version under review and not for whatever
    /// `latest` points at. An unreadable packument yields `None`, which the
    /// signature policy treats as absent.
    fn release_signatures(&self, pkg: &Package) -> Option<serde_json::Value> {
        let packument = self.packument(&pkg.name).ok()?;
        packument
            .versions
            .get(&pkg.version)
            .and_then(|meta| meta.dist.signatures.clone())
    }
}

/// Ceiling on one memoised packument, and on the memo as a whole. Mirrors the
/// tarball memo in `ReviewContext`: a single document is capped, and the total
/// is capped, and a walk that would exceed the total starts over rather than
/// growing.
const MAX_MEMOISED_PACKUMENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MEMOISED_PACKUMENT_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Rough serialised size of a packument, for the memo ceiling only. Not a
/// security bound -- the fetch itself is already byte-capped separately.
fn packument_size_estimate(p: &Packument) -> u64 {
    let versions: u64 = p
        .versions
        .values()
        .map(|v| {
            // The signature block is retained as a raw `serde_json::Value`, so
            // it counts toward the ceiling even though nothing here reads its
            // shape. Omitting it made a packument carrying a 32 MiB block
            // measure 1050 bytes, and a 64 MiB ceiling that does not bind is
            // worse than no ceiling: it looks like a bound.
            let signatures = v
                .dist
                .signatures
                .as_ref()
                .and_then(|sig| serde_json::to_string(sig).ok())
                .map_or(0, |s| s.len() as u64);
            512 + v.dist.tarball.len() as u64 + signatures
        })
        .sum();
    p.name.len() as u64 + 512 + versions
}

#[derive(Default)]
struct PackumentMemo {
    by_name: std::collections::HashMap<String, Packument>,
    bytes: u64,
}

impl PackumentMemo {
    /// The whole ceiling policy, in one place so a test can exercise the
    /// production logic rather than a copy of it. A document over the per-entry
    /// ceiling is not stored; a store that would pass the total restarts rather
    /// than grows.
    fn insert(&mut self, name: String, p: &Packument) {
        Self::insert_within(
            &mut self.by_name,
            &mut self.bytes,
            name,
            p,
            MAX_MEMOISED_PACKUMENT_BYTES,
            MAX_MEMOISED_PACKUMENT_TOTAL_BYTES,
        );
    }

    /// The policy with the two ceilings supplied, so the *comparison* can be
    /// pinned.
    ///
    /// The per-document test is `size > ceiling`, and the only input that
    /// separates `>` from `>=` is a packument estimating to exactly the ceiling
    /// — 64 MiB of fixture to assert one byte of comparison. Handing the
    /// ceilings in makes that a rounding argument instead, and the same shape
    /// `stale_band_for` and `reap_if_aged` use on the recall side.
    #[allow(clippy::too_many_arguments)]
    fn insert_within(
        by_name: &mut std::collections::HashMap<String, Packument>,
        bytes: &mut u64,
        name: String,
        p: &Packument,
        per_document: u64,
        total: u64,
    ) {
        let size = packument_size_estimate(p);
        if size > per_document {
            return;
        }
        if *bytes + size > total {
            by_name.clear();
            *bytes = 0;
        }
        *bytes += size;
        by_name.insert(name, p.clone());
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

pub fn validate_package_name(name: &str) -> Result<(), BluelineError> {
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

#[derive(Debug, Deserialize, Clone)]
struct Packument {
    name: String,
    #[serde(rename = "dist-tags")]
    dist_tags: BTreeMap<String, String>,
    versions: BTreeMap<String, VersionMeta>,
}

#[derive(Debug, Deserialize, Clone)]
struct VersionMeta {
    name: String,
    version: String,
    dist: Dist,
}

#[derive(Debug, Deserialize, Clone)]
struct Dist {
    tarball: String,
    integrity: Option<String>,
    /// The registry's signature block for this artifact, when it publishes
    /// one. Kept as raw JSON because the provenance engine only reads
    /// presence and key id, and a stricter shape here would refuse a packument
    /// over a field the check does not use.
    signatures: Option<serde_json::Value>,
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
                            signatures: None,
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
            // Exactly 3 requests: testpkg once, then mismatchname and
            // mismatchver. The packument is memoised per registry, so
            // default_version, list_releases and resolve share one fetch rather
            // than making three. A fourth request would not be served, and the
            // loop below would then block on accept().
            for _ in 0..3 {
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

    /// The three npm calls a review makes for one package -- default version,
    /// release list, resolve -- share a single packument fetch, and so does the
    /// signature lookup that follows them.
    #[test]
    fn a_packument_is_fetched_once_per_package() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let handle = std::thread::spawn(move || {
            // Poll rather than block on accept: with the packument memoised
            // there is no second request to serve, so a blocking accept() would
            // wait forever instead of letting the thread finish and the count
            // be asserted. Exit after a stretch with no connection.
            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut idle = 0u32;
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        idle = 0;
                        let mut buf = [0u8; 1024];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        if !req.contains("GET /counted ") {
                            break;
                        }
                        counter.fetch_add(1, Ordering::SeqCst);
                        let body = r#"{"name":"counted","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"counted","version":"1.0.0","dist":{"tarball":"http://127.0.0.1:1/pkg.tgz","integrity":null,"signatures":[{"keyid":"k","sig":"s"}]}}}}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        idle += 1;
                        if idle > 200 {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let reg = NpmRegistry::new(&base);
        assert_eq!(
            reg.default_version("counted").unwrap(),
            Some("1.0.0".into())
        );
        assert_eq!(reg.list_releases("counted").unwrap().len(), 1);
        let pkg = reg.resolve("counted", "1.0.0").unwrap();
        assert!(
            reg.release_signatures(&pkg).is_some(),
            "the signature block must be readable"
        );
        let _ = handle.join();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "four npm calls for one package must share one packument fetch"
        );
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

    /// The signature block the registry publishes next to the artifact was
    /// never deserialized, so `[provenance] require_signatures` gated on a
    /// value that was hard-wired absent and could never be satisfied on this
    /// lane. It is read for the exact version under review.
    #[test]
    fn release_signatures_reads_the_blocks_for_the_resolved_version_only() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        let handle = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_millis(600) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.contains("GET /signed ") {
                        let body = format!(
                            r#"{{"name":"signed","dist-tags":{{"latest":"2.0.0"}},"versions":{{"1.0.0":{{"name":"signed","version":"1.0.0","dist":{{"tarball":"http://127.0.0.1:{port}/one.tgz","integrity":null,"signatures":[{{"keyid":"SHA256:one","sig":"c2lnMQ=="}}]}}}},"2.0.0":{{"name":"signed","version":"2.0.0","dist":{{"tarball":"http://127.0.0.1:{port}/two.tgz","integrity":null}}}}}}}}"#
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        });

        let reg = NpmRegistry::new(&base);
        let signed = reg.resolve("signed", "1.0.0").unwrap();
        let sigs = reg
            .release_signatures(&signed)
            .expect("1.0.0 publishes a signature block");
        assert_eq!(
            sigs,
            serde_json::json!([{ "keyid": "SHA256:one", "sig": "c2lnMQ==" }])
        );
        // The block belongs to 1.0.0. Reading `latest` instead would vouch for
        // a different release than the one under review.
        let unsigned = reg.resolve("signed", "2.0.0").unwrap();
        assert_eq!(reg.release_signatures(&unsigned), None);

        let _ = handle.join();
    }

    /// The `[blocklist] maintainers` key is enforced through
    /// `Registry::release_author`, and on the npm lane that seam supplies
    /// nothing — so the key is a no-signal here, not a pass. This pins that,
    /// including the case that makes the naive wiring wrong: the adapter asks
    /// for the *abbreviated* packument (`application/vnd.npm.install-v1+json`),
    /// which does not publish a `maintainers` member at all. Its top-level keys
    /// are `name`, `dist-tags`, `modified` and `versions`; a
    /// `maintainers` array only appears in the full packument. Deserializing
    /// one and returning it would therefore compile, pass a mock, and be
    /// `None` against every real registry — a check wired to nothing.
    ///
    /// Even with the member in hand, npm's value is a *list*: `express`
    /// declares 5 identities, `typescript` 7, `react` 2, and some are bots
    /// (`react-bot`, `typescript-bot`) rather than people. The seam carries one
    /// `Option<String>` and P04 compares that one string, so a selection rule
    /// would silently check one of N and leave the rest unchecked while the
    /// card claimed the identity was checked. Wiring this needs a seam that
    /// carries the whole list (`Registry` + `Policy::is_maintainer_blocked`),
    /// and a decision about the 2.4x-10.5x larger full-packument body that
    /// carries it; see `CHANGELOG.md` and `ARCHITECTURE.md`.
    #[test]
    fn the_npm_lane_contributes_no_blocklist_identity() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        let handle = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_millis(600) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.contains("GET /orgpkg ") {
                        // As generous as the wire gets: the member the
                        // abbreviated format never publishes, carrying several
                        // identities including a bot.
                        let body = format!(
                            r#"{{"name":"orgpkg","maintainers":[{{"name":"alice","email":"alice@example.com"}},{{"name":"mallory","email":"mallory@example.com"}},{{"name":"orgpkg-bot","email":"bot@example.com"}}],"dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"orgpkg","version":"1.0.0","dist":{{"tarball":"http://127.0.0.1:{port}/o.tgz","integrity":null}}}}}}}}"#
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        });

        let reg = NpmRegistry::new(&base);
        let pkg = reg.resolve("orgpkg", "1.0.0").unwrap();
        assert_eq!(
            reg.release_author(&pkg),
            None,
            "the npm lane supplies no publishing identity, so `[blocklist] maintainers` \
             is inert here: no P04, no card line, no warning"
        );

        let _ = handle.join();
    }

    #[test]
    fn packument_404_reports_not_found() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");

        let handle = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_millis(600) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.contains("GET /ghost ") {
                        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = stream.write_all(resp.as_bytes());
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        });

        let reg = NpmRegistry::new(&base);

        // A 404 must read as "package not found in registry" (distinct from an
        // outage) so a lockfile pointing at a ghost package is tamper evidence.
        let err = reg.list_releases("ghost").unwrap_err();
        assert!(err.to_string().contains("package not found in registry"));

        let _ = handle.join();
    }
    /// The memo has to bind, or it is decoration. Two ceilings: one document,
    /// and the memo as a whole. A packument over the first is not cached at
    /// all; exceeding the second clears what is held, so a recursive review
    /// cannot grow the memo without limit.
    #[test]
    fn the_packument_memo_is_bounded_and_the_estimate_is_not_a_fig_leaf() {
        let big = "x".repeat(2 * 1024 * 1024);
        let mut versions = BTreeMap::new();
        for i in 0..64 {
            versions.insert(
                format!("1.0.{i}"),
                VersionMeta {
                    name: "memo".into(),
                    version: format!("1.0.{i}"),
                    dist: Dist {
                        tarball: "https://example.invalid/p.tgz".into(),
                        integrity: None,
                        signatures: Some(serde_json::json!([big, big])),
                    },
                },
            );
        }
        let p = Packument {
            name: "memo".into(),
            dist_tags: BTreeMap::new(),
            versions,
        };
        let size = packument_size_estimate(&p);
        assert!(
            size > 200 * 1024 * 1024,
            "a packument carrying 256 MiB of signature blocks must not estimate to {size} bytes"
        );

        // Over the per-document ceiling: not cached.
        assert!(
            size > MAX_MEMOISED_PACKUMENT_BYTES,
            "this fixture must exceed the single-document ceiling"
        );

        // Under the per-document ceiling but over the total: cleared, not grown.
        // Calls the production `insert`, not a copy of the policy, so deleting
        // the ceiling in the real code fails here.
        let mut memo = PackumentMemo::default();
        let small = Packument {
            name: "memo".into(),
            dist_tags: BTreeMap::new(),
            versions: BTreeMap::from([(
                "1.0.0".to_string(),
                VersionMeta {
                    name: "memo".into(),
                    version: "1.0.0".into(),
                    dist: Dist {
                        tarball: "https://example.invalid/p.tgz".into(),
                        integrity: None,
                        signatures: None,
                    },
                },
            )]),
        };
        let small_size = packument_size_estimate(&small);
        assert!(small_size <= MAX_MEMOISED_PACKUMENT_BYTES);

        memo.insert("stale".into(), &small);
        assert!(memo.by_name.contains_key("stale"));
        // Fill the accounting right up to the ceiling without inserting a
        // document, which is what a long walk of small ones does.
        memo.bytes = MAX_MEMOISED_PACKUMENT_TOTAL_BYTES;
        memo.insert("memo".into(), &small);
        assert!(
            !memo.by_name.contains_key("stale"),
            "a memo past its total ceiling must drop what it held"
        );
        assert_eq!(
            memo.bytes, small_size,
            "the total must restart at the new entry, not accumulate"
        );
        assert!(memo.by_name.contains_key("memo"));

        // An over-ceiling document is refused outright, even when there is room.
        let mut roomy = PackumentMemo::default();
        roomy.insert("toobig".into(), &p);
        assert!(
            !roomy.by_name.contains_key("toobig"),
            "a document over the per-entry ceiling must not be stored"
        );
        assert_eq!(roomy.bytes, 0);
    }

    /// The two ceilings, asserted as values.
    ///
    /// Every test of the memo so far has compared an estimate against these
    /// constants with `>`, which is why six arithmetic mutants across the two
    /// lines survived: `64 * 1024` and `64 + 1024` are both "large", so a
    /// ceiling that no longer means 64 MiB still refused the 256 MiB fixture and
    /// still passed. A ceiling that is wrong in the *permissive* direction is
    /// the dangerous one -- it looks like a bound and is not -- so the number
    /// itself is the thing worth pinning.
    #[test]
    fn the_packument_memo_ceilings_are_the_documented_sizes() {
        assert_eq!(MAX_MEMOISED_PACKUMENT_BYTES, 64 * 1024 * 1024);
        assert_eq!(MAX_MEMOISED_PACKUMENT_BYTES, 67_108_864);
        assert_eq!(MAX_MEMOISED_PACKUMENT_TOTAL_BYTES, 256 * 1024 * 1024);
        assert_eq!(MAX_MEMOISED_PACKUMENT_TOTAL_BYTES, 268_435_456);
        // The memo as a whole is allowed to be larger than any one document.
        assert_eq!(
            MAX_MEMOISED_PACKUMENT_TOTAL_BYTES - MAX_MEMOISED_PACKUMENT_BYTES,
            192 * 1024 * 1024
        );
    }

    /// The estimate, exactly, on a packument small enough to reason about.
    ///
    /// ```text
    /// name("memo", 4) + 512
    ///   + per version: 512 + tarball.len() + signatures
    /// ```
    ///
    /// One version with no signatures and a 29-byte tarball URL is
    /// `4 + 512 + 512 + 29 = 1057`. Each of the five `+` operators in the
    /// expression can be mutated to `*` or `-`, and every one of those changes
    /// this number, so asserting the total rather than a range is what kills
    /// them. A second version pins that the per-version terms are *summed* over
    /// versions rather than taken from one.
    #[test]
    fn the_packument_estimate_is_exact() {
        let one = Packument {
            name: "memo".into(),
            dist_tags: BTreeMap::new(),
            versions: BTreeMap::from([(
                "1.0.0".to_string(),
                VersionMeta {
                    name: "memo".into(),
                    version: "1.0.0".into(),
                    dist: Dist {
                        tarball: "https://example.invalid/p.tgz".into(),
                        integrity: None,
                        signatures: None,
                    },
                },
            )]),
        };
        assert_eq!(
            packument_size_estimate(&one),
            4 + 512 + (512 + "https://example.invalid/p.tgz".len() as u64),
            "one unsigned version"
        );
        assert_eq!(packument_size_estimate(&one), 1057);

        // Two versions: the per-version term is summed, not overwritten.
        let mut two = one.clone();
        two.versions.insert(
            "1.0.1".to_string(),
            VersionMeta {
                name: "memo".into(),
                version: "1.0.1".into(),
                dist: Dist {
                    tarball: "https://example.invalid/q.tgz".into(),
                    integrity: None,
                    signatures: None,
                },
            },
        );
        assert_eq!(
            packument_size_estimate(&two),
            1057 + 512 + "https://example.invalid/q.tgz".len() as u64,
            "a second version adds its own 512 plus its tarball length"
        );

        // The signature block is counted, because it is retained as raw JSON.
        // Dropping this term is what let a 32 MiB block measure 1050 bytes.
        let mut signed = one.clone();
        signed.versions.get_mut("1.0.0").unwrap().dist.signatures =
            Some(serde_json::json!({"keyid": "k", "sig": "s"}));
        let sig_len = serde_json::to_string(&serde_json::json!({"keyid": "k", "sig": "s"}))
            .unwrap()
            .len() as u64;
        assert_eq!(
            packument_size_estimate(&signed),
            1057 + sig_len,
            "a retained signature block must count toward the ceiling"
        );

        // An absent packument still costs its name and the two fixed terms, so
        // the estimate is never zero for a real document.
        let empty = Packument {
            name: String::new(),
            dist_tags: BTreeMap::new(),
            versions: BTreeMap::new(),
        };
        assert_eq!(packument_size_estimate(&empty), 512);
    }

    /// The per-document comparison is strict, pinned with the ceilings handed
    /// in. A document estimating to exactly the ceiling is stored; one byte more
    /// is refused. The `insert` path with the real 64 MiB ceiling cannot express
    /// this without a 64 MiB fixture, and the mutation it catches -- `>` becoming
    /// `>=` -- would let an over-ceiling document sit in the memo whenever the
    /// estimate landed exactly on the bound.
    #[test]
    fn the_per_document_ceiling_is_strict() {
        let doc = Packument {
            name: "memo".into(),
            dist_tags: BTreeMap::new(),
            versions: BTreeMap::from([(
                "1.0.0".to_string(),
                VersionMeta {
                    name: "memo".into(),
                    version: "1.0.0".into(),
                    dist: Dist {
                        tarball: "https://example.invalid/p.tgz".into(),
                        integrity: None,
                        signatures: None,
                    },
                },
            )]),
        };
        let size = packument_size_estimate(&doc);

        let mut by_name = std::collections::HashMap::new();
        let mut bytes = 0u64;
        PackumentMemo::insert_within(
            &mut by_name,
            &mut bytes,
            "memo".into(),
            &doc,
            size,
            u64::MAX,
        );
        assert!(
            by_name.contains_key("memo"),
            "a document exactly at the ceiling must be stored: {size}"
        );
        assert_eq!(bytes, size);

        let mut by_name = std::collections::HashMap::new();
        let mut bytes = 0u64;
        PackumentMemo::insert_within(
            &mut by_name,
            &mut bytes,
            "memo".into(),
            &doc,
            size - 1,
            u64::MAX,
        );
        assert!(
            !by_name.contains_key("memo"),
            "one byte over the ceiling must not be stored"
        );
        assert_eq!(bytes, 0, "a refused document must not be accounted for");
    }

    /// The whole-memo ceiling, on its exact boundary.
    ///
    /// `the_per_document_ceiling_is_strict` passes `u64::MAX` as the total, so
    /// the running sum and its comparison were never exercised: a `>` that could
    /// not be reached, and an arithmetic operator on a value too large to
    /// overflow.
    ///
    /// Two boundaries, because the two mutants are separable in different ways:
    ///
    /// * a total of exactly `bytes + size` must **not** restart. A `>` relaxed to
    ///   `>=` discards a memo that is exactly full, which turns a full cache
    ///   into a permanently empty one as the walk proceeds.
    /// * at that same total the sum is 2 × `size`, and a sum replaced by a
    ///   product is astronomically larger, so the product form restarts where the
    ///   sum does not. `size` is at least 1025 for any real packument, which is
    ///   what makes `2 * size` and `size * size` land on opposite sides.
    #[test]
    fn the_whole_memo_ceiling_is_strict_and_adds_rather_than_multiplies() {
        let doc = Packument {
            name: "memo".into(),
            dist_tags: BTreeMap::new(),
            versions: BTreeMap::from([(
                "1.0.0".to_string(),
                VersionMeta {
                    name: "memo".into(),
                    version: "1.0.0".into(),
                    dist: Dist {
                        tarball: "https://example.invalid/p.tgz".into(),
                        integrity: None,
                        signatures: None,
                    },
                },
            )]),
        };
        let size = packument_size_estimate(&doc);

        // Fill the memo to exactly `size`, then offer one more document with a
        // total of exactly `size + size`.
        let mut by_name = std::collections::HashMap::new();
        let mut bytes = 0u64;
        PackumentMemo::insert_within(
            &mut by_name,
            &mut bytes,
            "first".into(),
            &doc,
            u64::MAX,
            u64::MAX,
        );
        assert_eq!(bytes, size);
        assert_eq!(by_name.len(), 1);

        PackumentMemo::insert_within(
            &mut by_name,
            &mut bytes,
            "second".into(),
            &doc,
            u64::MAX,
            size * 2,
        );
        assert!(
            by_name.contains_key("first") && by_name.contains_key("second"),
            "a memo exactly at the total must be kept, not restarted: {:?}",
            by_name.keys()
        );
        assert_eq!(bytes, size * 2);

        // One byte below the total, the next document does not fit, and the
        // memo restarts rather than growing.
        let mut by_name = std::collections::HashMap::new();
        let mut bytes = 0u64;
        PackumentMemo::insert_within(
            &mut by_name,
            &mut bytes,
            "first".into(),
            &doc,
            u64::MAX,
            u64::MAX,
        );
        PackumentMemo::insert_within(
            &mut by_name,
            &mut bytes,
            "second".into(),
            &doc,
            u64::MAX,
            size * 2 - 1,
        );
        assert_eq!(
            by_name.len(),
            1,
            "an over-total document restarts the memo rather than growing it"
        );
        assert!(
            by_name.contains_key("second"),
            "the document that triggered the restart is still kept"
        );
        assert_eq!(bytes, size, "the accounting restarts from the new document");
    }
}
