use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use ureq::Agent;

use crate::error::BluelineError;
use crate::registry::http_util::{RegistryLimits, download_bounded, validate_download_url};
use crate::registry::{Checksum, ChecksumAlg, Ecosystem, Package, Registry, Release, hex_encode};

const USER_AGENT: &str = concat!("blueline/", env!("CARGO_PKG_VERSION"));

/// crates.io sparse-index registry client.
///
/// Speaks the cargo sparse protocol (`config.json`, NDJSON index paths,
/// `.crate` downloads). Every response is size-capped and parsed fail-closed;
/// artifact bytes are sha256-verified against the index `cksum` before any
/// caller can extract them.
pub struct CratesIoRegistry {
    agent: Agent,
    base: String,
    limits: RegistryLimits,
}

impl CratesIoRegistry {
    pub fn new(base: &str) -> Self {
        Self::with_limits(base, RegistryLimits::default())
    }

    pub fn with_limits(base: &str, limits: RegistryLimits) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(90))
            .user_agent(USER_AGENT)
            .redirects(0)
            .build();
        Self {
            agent,
            base: base.trim_end_matches('/').to_string(),
            limits,
        }
    }

    /// Fetch and validate `{base}/config.json`. Fail closed when the endpoint
    /// demands authentication or publishes no usable download base.
    fn config(&self) -> Result<IndexConfig, BluelineError> {
        let url = format!("{}/config.json", self.base);
        let body = self.get_capped_string(&url)?;
        let config: IndexConfig = serde_json::from_str(&body).map_err(|e| {
            BluelineError::Manifest(
                "config.json".to_string(),
                format!("corrupt registry config JSON: {e}"),
            )
        })?;
        if config.auth_required == Some(true) {
            return Err(BluelineError::Manifest(
                "config.json".to_string(),
                "registry requires authentication (`auth-required`: true); refusing".to_string(),
            ));
        }
        match normalize_base(config.dl.as_deref().unwrap_or_default()) {
            Some(_) => Ok(config),
            None => Err(BluelineError::Manifest(
                "config.json".to_string(),
                format!(
                    "registry config has no usable `dl` download URL (`{}`)",
                    config.dl.as_deref().unwrap_or("<missing>")
                ),
            )),
        }
    }

    fn get_capped_string(&self, url: &str) -> Result<String, BluelineError> {
        let resp = match self
            .agent
            .get(url)
            .set("accept", "application/json, text/plain")
            .call()
        {
            Ok(resp) => resp,
            Err(ureq::Error::Status(404, _)) => {
                return Err(BluelineError::Manifest(
                    url.to_string(),
                    "not found on this registry".to_string(),
                ));
            }
            Err(e) => return Err(BluelineError::Network(format!("GET {url}: {e}"))),
        };

        let mut body = String::new();
        let mut reader = resp.into_reader().take(self.limits.max_packument_bytes + 1);
        reader
            .read_to_string(&mut body)
            .map_err(|e| BluelineError::Network(format!("reading {url}: {e}")))?;
        if body.len() as u64 > self.limits.max_packument_bytes {
            return Err(BluelineError::ExtractionLimit(format!(
                "response from {url} exceeds maximum cap of {} bytes",
                self.limits.max_packument_bytes
            )));
        }
        Ok(body)
    }

    /// Fetch and parse the sparse-index NDJSON for a canonical crate name.
    fn index_entries(&self, canonical: &str) -> Result<Vec<IndexEntry>, BluelineError> {
        let rel = sparse_index_path(canonical)?;
        let url = format!("{}/{rel}", self.base);
        let body = self.get_capped_string(&url)?;
        let (entries, notes) = parse_index_ndjson(&body)
            .map_err(|e| BluelineError::Manifest(canonical.to_string(), e.to_string()))?;
        for note in notes {
            eprintln!("blueline: `{canonical}` index note: {note}");
        }
        for entry in &entries {
            if entry.name != canonical {
                return Err(BluelineError::Manifest(
                    canonical.to_string(),
                    format!(
                        "registry metadata mismatch: index entry reports name `{}`",
                        entry.name
                    ),
                ));
            }
        }
        Ok(entries)
    }

    fn releases_sorted(&self, canonical: &str) -> Result<Vec<Release>, BluelineError> {
        let entries = self.index_entries(canonical)?;
        let mut releases = Vec::with_capacity(entries.len());
        for entry in entries {
            // Unreachable in practice: parse_index_ndjson already validated
            // every recognized row's `vers`.
            let version = semver::Version::parse(&entry.vers).map_err(|_| {
                BluelineError::Manifest(
                    canonical.to_string(),
                    format!("invalid version `{}` served by registry", entry.vers),
                )
            })?;
            releases.push((
                version.clone(),
                Release {
                    version: version.to_string(),
                    yanked: entry.yanked.unwrap_or(false),
                    publish_time: None,
                },
            ));
        }
        releases.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(releases.into_iter().map(|(_, r)| r).collect())
    }

    /// Stream-download the `.crate` artifact and fail closed unless its sha256
    /// matches the index checksum. Bytes leave this function only verified.
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
                ".crate download exceeds maximum size cap of {} bytes",
                self.limits.max_tarball_bytes
            )),
            other => other,
        })?;

        let expected = pkg.integrity.as_ref().ok_or_else(|| {
            BluelineError::Verification(format!(
                "{}@{}: registry provided no checksum; refusing to trust unverifiable bytes",
                pkg.name, pkg.version
            ))
        })?;
        if expected.alg != ChecksumAlg::Sha256 {
            return Err(BluelineError::Verification(format!(
                "{}@{}: checksum algorithm `{}` is not sha256; crates.io artifacts verify with sha256",
                pkg.name,
                pkg.version,
                expected.alg.name()
            )));
        }

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let computed = hex_encode(&hasher.finalize());
        if computed != expected.value_hex {
            return Err(BluelineError::Verification(format!(
                "{}@{}: .crate sha256 mismatch (expected {}, got sha256:{computed})",
                pkg.name,
                pkg.version,
                expected.to_display()
            )));
        }
        Ok(bytes)
    }

    fn resolve_package(&self, name: &str, version: &str) -> Result<Package, BluelineError> {
        validate_crate_name(name)?;
        semver::Version::parse(version).map_err(|_| {
            BluelineError::InvalidPackageSpec(format!("{name}@{version}: invalid semver"))
        })?;
        let canonical = canonical_crate_name(name);
        let entries = self.index_entries(&canonical)?;

        let entry = entries.iter().find(|e| e.vers == version).ok_or_else(|| {
            BluelineError::Manifest(
                canonical.clone(),
                format!(
                    "no version `{version}` (have: {})",
                    summarize_versions(&entries)
                ),
            )
        })?;

        let checksum = Checksum::parse(&entry.cksum).map_err(|_| {
            BluelineError::Verification(format!(
                "{canonical}@{version}: unusable checksum `{}`; refusing unverifiable bytes",
                entry.cksum
            ))
        })?;
        if checksum.alg != ChecksumAlg::Sha256 {
            return Err(BluelineError::Verification(format!(
                "{canonical}@{version}: checksum algorithm `{}` is not sha256",
                checksum.alg.name()
            )));
        }

        let config = self.config()?;
        let dl = normalize_base(config.dl.as_deref().unwrap_or_default()).ok_or_else(|| {
            BluelineError::Manifest(
                "config.json".to_string(),
                "registry config has no usable `dl` download URL".to_string(),
            )
        })?;
        let tarball_url = format!("{dl}/{canonical}/{version}/download");
        validate_download_url(&self.base, &tarball_url)?;

        Ok(Package {
            name: canonical,
            version: version.to_string(),
            tarball_url,
            integrity: Some(checksum),
        })
    }
}

impl Registry for CratesIoRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn resolve(&self, name: &str, version: &str) -> Result<Package, BluelineError> {
        self.resolve_package(name, version)
    }

    fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError> {
        self.fetch_url_verified(pkg)
    }

    fn list_versions(&self, name: &str) -> Result<Vec<semver::Version>, BluelineError> {
        validate_crate_name(name)?;
        let canonical = canonical_crate_name(name);
        let mut versions: Vec<semver::Version> = self
            .index_entries(&canonical)?
            .iter()
            .filter_map(|e| semver::Version::parse(&e.vers).ok())
            .collect();
        versions.sort();
        Ok(versions)
    }

    fn list_releases(&self, name: &str) -> Result<Vec<Release>, BluelineError> {
        validate_crate_name(name)?;
        let canonical = canonical_crate_name(name);
        self.releases_sorted(&canonical)
    }

    fn default_version(&self, name: &str) -> Result<Option<String>, BluelineError> {
        validate_crate_name(name)?;
        let canonical = canonical_crate_name(name);
        let releases = self.releases_sorted(&canonical)?;
        let live: Vec<&Release> = releases.iter().filter(|r| !r.yanked).collect();
        let highest = |stable_only: bool| -> Option<String> {
            live.iter()
                .filter_map(|r| semver::Version::parse(&r.version).ok())
                .filter(|v| !stable_only || v.pre.is_empty())
                .max()
                .map(|v| v.to_string())
        };
        Ok(highest(true).or_else(|| highest(false)))
    }
}

#[derive(Debug, Deserialize)]
struct IndexConfig {
    dl: Option<String>,
    #[serde(rename = "auth-required")]
    auth_required: Option<bool>,
}

/// One row of the sparse-index NDJSON stream.
#[derive(Debug, Deserialize)]
pub struct IndexEntry {
    pub name: String,
    pub vers: String,
    pub cksum: String,
    pub yanked: Option<bool>,
}

/// Sparse-index storage path for an already-canonical crate name:
/// `1/{a}`, `2/{ab}`, `3/{a}/{abc}`, `{c1}{c2}/{c3}{c4}/{name}`.
fn sparse_index_path(canonical: &str) -> Result<String, BluelineError> {
    if canonical.is_empty() || canonical.len() > 64 {
        return Err(BluelineError::InvalidPackageSpec(format!(
            "`{canonical}` cannot be mapped to an index path"
        )));
    }
    let path = match canonical.len() {
        1 => format!("1/{canonical}"),
        2 => format!("2/{canonical}"),
        3 => format!("3/{}/{}", &canonical[..1], canonical),
        n => format!(
            "{}/{}/{}",
            &canonical[0..2],
            &canonical[2..4],
            &canonical[..n]
        ),
    };
    Ok(path)
}

/// Lowercase the name and fold `_` to `-`, matching cargo's canonical form.
pub fn canonical_crate_name(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// Crate names are ASCII alphanumeric plus `-` and `_`, at most 64 chars.
pub fn validate_crate_name(name: &str) -> Result<(), BluelineError> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        return Err(BluelineError::InvalidPackageSpec(format!(
            "`{name}` is not a valid crate name (ASCII letters, digits, `-`, `_`; max 64 chars)"
        )));
    }
    Ok(())
}

/// Parse one sparse-index response body. Fail-closed rules:
/// - malformed JSON lines are errors;
/// - rows carrying an unknown schema marker `v > 2` are skipped with a note;
/// - recognized rows with unparsable `vers` are errors;
/// - missing `yanked` defaults to false.
fn parse_index_ndjson(body: &str) -> Result<(Vec<IndexEntry>, Vec<String>), BluelineError> {
    let mut entries = Vec::new();
    let mut notes = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let raw: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            BluelineError::Manifest(
                "index".to_string(),
                format!("malformed NDJSON on line {}: {e}", idx + 1),
            )
        })?;

        let schema = raw.get("v").and_then(|v| v.as_u64());
        if schema.is_some_and(|v| v > 2) {
            notes.push(format!(
                "skipped line {} with unsupported schema v={}",
                idx + 1,
                schema.unwrap_or_default()
            ));
            continue;
        }

        let entry: IndexEntry = serde_json::from_value(raw).map_err(|e| {
            BluelineError::Manifest(
                "index".to_string(),
                format!("unusable index row on line {}: {e}", idx + 1),
            )
        })?;
        if semver::Version::parse(&entry.vers).is_err() {
            return Err(BluelineError::Manifest(
                "index".to_string(),
                format!(
                    "line {} reports invalid version `{}`; refusing ambiguous index",
                    idx + 1,
                    entry.vers
                ),
            ));
        }
        entries.push(entry);
    }
    Ok((entries, notes))
}

/// Post-extraction structural check for a packed `.crate`: exactly one
/// top-level directory named `{canonical}-{version}`, nothing else beside it.
pub fn verify_single_root(
    root: &Path,
    canonical: &str,
    version: &str,
) -> Result<PathBuf, BluelineError> {
    let expected = format!("{canonical}-{version}");
    let mut names = Vec::new();
    let rd = std::fs::read_dir(root)
        .map_err(|e| BluelineError::Extraction(format!("reading extracted root: {e}")))?;
    for item in rd {
        let item = item
            .map_err(|e| BluelineError::Extraction(format!("reading extracted root entry: {e}")))?;
        names.push(item.file_name().to_string_lossy().into_owned());
    }
    if names.len() != 1 {
        return Err(BluelineError::Extraction(format!(
            ".crate must contain exactly one top-level directory named `{expected}`, found {} root entries",
            names.len()
        )));
    }
    let only = names.remove(0);
    let is_dir = std::fs::metadata(root.join(&only))
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if !is_dir || only != expected {
        return Err(BluelineError::Extraction(format!(
            ".crate root mismatch: expected single top-level directory `{expected}`, found `{only}`"
        )));
    }
    Ok(root.join(expected))
}

fn normalize_base(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn summarize_versions(entries: &[IndexEntry]) -> String {
    let mut vers: Vec<semver::Version> = entries
        .iter()
        .filter_map(|e| semver::Version::parse(&e.vers).ok())
        .collect();
    vers.sort();
    vers.iter()
        .rev()
        .take(8)
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;

    const GOOD_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn maps_sparse_index_paths() {
        assert_eq!(sparse_index_path("a").unwrap(), "1/a");
        assert_eq!(sparse_index_path("ab").unwrap(), "2/ab");
        assert_eq!(sparse_index_path("abc").unwrap(), "3/a/abc");
        assert_eq!(sparse_index_path("abcd").unwrap(), "ab/cd/abcd");
        assert_eq!(sparse_index_path("serde-json").unwrap(), "se/rd/serde-json");
        assert!(sparse_index_path("").is_err());
        let long = "a".repeat(65);
        assert!(sparse_index_path(&long).is_err());
    }

    #[test]
    fn canonicalizes_names() {
        assert_eq!(canonical_crate_name("Serde_JSON"), "serde-json");
        assert_eq!(canonical_crate_name("tokio"), "tokio");
        assert_eq!(canonical_crate_name("MiXeD_CaSe"), "mixed-case");
    }

    #[test]
    fn validates_crate_names() {
        assert!(validate_crate_name("serde").is_ok());
        assert!(validate_crate_name("serde_json").is_ok());
        assert!(validate_crate_name("My-Crate_42").is_ok());

        assert!(validate_crate_name("").is_err());
        assert!(validate_crate_name("../evil").is_err());
        assert!(validate_crate_name("has/slash").is_err());
        assert!(validate_crate_name("has.dot").is_err());
        assert!(validate_crate_name("sp ace").is_err());
        assert!(validate_crate_name("unicode_\u{00fc}").is_err());
        let ok_len = "a".repeat(64);
        assert!(validate_crate_name(&ok_len).is_ok());
        let over_len = "a".repeat(65);
        assert!(validate_crate_name(&over_len).is_err());
    }

    fn row(vers: &str, extra: &str) -> String {
        format!(r#"{{"name":"p","vers":"{vers}","cksum":"{GOOD_SHA256}","features":{{}}{extra}}}"#)
    }

    #[test]
    fn parses_ndjson_fail_closed() {
        // Missing yanked defaults to false (None here); blank lines ignored.
        let body = format!("{}\n{}\n\n", row("0.9.0", ""), row("1.0.0", ""));
        let (entries, notes) = parse_index_ndjson(&body).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].yanked, None);
        assert!(notes.is_empty());

        // Unknown schema row is skipped with a note.
        let body = format!(
            "{}\n{}",
            row("1.0.0", ""),
            r#"{"name":"p","vers":"9.9.9","cksum":"aa","v":3}"#
        );
        let (entries, notes) = parse_index_ndjson(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].vers, "1.0.0");
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("unsupported schema"));

        // Bad vers on a recognized row fails the whole index.
        let bad = r#"{"name":"p","vers":"NOT_SEMVER","cksum":"aa"}"#;
        assert!(parse_index_ndjson(bad).is_err());
        let mixed = format!("{}\n{}", row("1.0.0", ""), bad);
        assert!(parse_index_ndjson(&mixed).is_err());

        // Malformed JSON line fails closed.
        assert!(parse_index_ndjson("{not json}\n").is_err());

        // Missing required fields fail closed.
        assert!(parse_index_ndjson(r#"{"name":"p","vers":"1.0.0"}"#).is_err());

        // Empty / blank-only bodies are empty indexes.
        let (entries, _) = parse_index_ndjson("\n\n").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn single_root_structural_check() {
        let dir = tempfile::tempdir().unwrap();

        let good = dir.path().join("good");
        std::fs::create_dir_all(good.join("serde-json-1.0.210/src")).unwrap();
        assert_eq!(
            verify_single_root(&good, "serde-json", "1.0.210").unwrap(),
            good.join("serde-json-1.0.210")
        );

        let wrong = dir.path().join("wrong");
        std::fs::create_dir_all(wrong.join("evil-pkg-1.0.210")).unwrap();
        let err = verify_single_root(&wrong, "serde-json", "1.0.210").unwrap_err();
        assert!(err.to_string().contains("root mismatch"));

        let multi = dir.path().join("multi");
        std::fs::create_dir_all(multi.join("serde-json-1.0.210")).unwrap();
        std::fs::create_dir_all(multi.join("extra-dir")).unwrap();
        assert!(verify_single_root(&multi, "serde-json", "1.0.210").is_err());

        let stray = dir.path().join("stray");
        std::fs::create_dir_all(stray.join("serde-json-1.0.210")).unwrap();
        std::fs::write(stray.join("README"), "hi").unwrap();
        assert!(verify_single_root(&stray, "serde-json", "1.0.210").is_err());
    }

    /// Minimal HTTP fixture serving config.json, one NDJSON index document,
    /// and one `.crate` download. No external network. The listener binds
    /// first so route bodies can embed the real base URL.
    struct Fixture {
        base: String,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    struct FixtureRoutes {
        config: String,
        index_rel: String,
        ndjson: String,
        download_rel: String,
        crate_bytes: Vec<u8>,
    }

    impl Fixture {
        fn spawn<F: FnOnce(&str) -> FixtureRoutes>(make_routes: F) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let routes = Arc::new(make_routes(&base));
            let handle = std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let routes = routes.clone();
                    std::thread::spawn(move || {
                        serve(stream, &routes);
                    });
                }
            });
            Fixture {
                base,
                handle: Some(handle),
            }
        }
    }

    fn serve(mut stream: std::net::TcpStream, routes: &FixtureRoutes) {
        use std::io::{Read, Write};

        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let path = req
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/")
            .trim_start_matches('/')
            .to_string();

        let (ctype, body): (&str, Vec<u8>) = if path == "config.json" {
            ("application/json", routes.config.as_bytes().to_vec())
        } else if path == routes.index_rel {
            ("text/plain", routes.ndjson.as_bytes().to_vec())
        } else if path == routes.download_rel {
            ("application/octet-stream", routes.crate_bytes.clone())
        } else {
            ("text/plain", b"not found".to_vec())
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&body);
    }

    fn make_crate_bytes(root_name: &str) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let manifest = format!("[package]\nname = \"{root_name}\"\nedition = \"2021\"\n");
        let mut h = tar::Header::new_gnu();
        h.set_size(manifest.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        builder
            .append_data(
                &mut h,
                format!("{root_name}/Cargo.toml"),
                manifest.as_bytes(),
            )
            .unwrap();
        let code = "pub fn f() {}\n";
        let mut h2 = tar::Header::new_gnu();
        h2.set_size(code.len() as u64);
        h2.set_mode(0o644);
        h2.set_cksum();
        builder
            .append_data(&mut h2, format!("{root_name}/src/lib.rs"), code.as_bytes())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn sha256_hex(data: &[u8]) -> String {
        let digest = Sha256::digest(data);
        hex_encode(&digest)
    }

    /// Standard happy-path fixture for `name` at `version`, downloading bytes
    /// whose sha256 matches the served `cksum`.
    fn happy_fixture(name: &str, version: &str, crate_bytes: Vec<u8>) -> Fixture {
        let canonical = canonical_crate_name(name);
        let index_rel = sparse_index_path(&canonical).unwrap();
        let download_rel = format!("{canonical}/{version}/download");
        Fixture::spawn(move |base| {
            let cksum = sha256_hex(&crate_bytes);
            FixtureRoutes {
                config: format!(r#"{{"dl":"{base}","api":"{base}"}}"#),
                index_rel,
                ndjson: format!(
                    r#"{{"name":"{canonical}","vers":"{version}","cksum":"{cksum}","yanked":false,"features":{{}}}}
"#
                ),
                download_rel,
                crate_bytes,
            }
        })
    }

    #[test]
    fn mock_http_resolve_list_and_download() {
        let name = "serde-json";
        let version = "1.0.210";
        let crate_bytes = make_crate_bytes(name);
        let mut server = happy_fixture(name, version, crate_bytes.clone());

        let reg = CratesIoRegistry::new(&server.base);
        assert_eq!(reg.ecosystem(), Ecosystem::Cargo);

        let releases = reg.list_releases(name).unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].version, version);
        assert!(!releases[0].yanked);
        assert_eq!(releases[0].publish_time, None);
        assert_eq!(reg.default_version(name).unwrap().as_deref(), Some(version));

        let versions = reg.list_versions(name).unwrap();
        assert_eq!(versions.len(), 1);

        let pkg = reg.resolve(name, version).unwrap();
        assert_eq!(pkg.name, "serde-json");
        assert_eq!(
            pkg.integrity,
            Some(Checksum::parse(&sha256_hex(&crate_bytes)).unwrap())
        );
        assert!(pkg.tarball_url.contains("/serde-json/1.0.210/download"));

        let bytes = reg.fetch_tarball(&pkg).unwrap();
        assert_eq!(bytes, crate_bytes);

        // Detach the fixture's accept loop; it exits with the process.
        drop(server.handle.take());
    }

    #[test]
    fn rejects_checksum_mismatch_before_any_extract() {
        let name = "badsum";
        let version = "0.1.0";
        let crate_bytes = make_crate_bytes(name);
        let canonical = canonical_crate_name(name);
        let index_rel = sparse_index_path(&canonical).unwrap();
        let download_rel = format!("{canonical}/{version}/download");
        let server = Fixture::spawn(move |base| {
            let config = format!(r#"{{"dl":"{base}"}}"#);
            let ndjson =
                format!(r#"{{"name":"{canonical}","vers":"{version}","cksum":"{GOOD_SHA256}"}}"#);
            FixtureRoutes {
                config,
                index_rel,
                ndjson,
                download_rel,
                crate_bytes,
            }
        });

        let reg = CratesIoRegistry::new(&server.base);
        let pkg = reg.resolve(name, version).unwrap();
        let err = reg.fetch_tarball(&pkg).unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"));
    }

    #[test]
    fn rejects_auth_required_config() {
        let name = "authed";
        let version = "1.0.0";
        let canonical = canonical_crate_name(name);
        let index_rel = sparse_index_path(&canonical).unwrap();
        let download_rel = format!("{canonical}/{version}/download");
        let server = Fixture::spawn(move |base| {
            let config = format!(r#"{{"dl":"{base}","auth-required":true}}"#);
            let ndjson =
                format!(r#"{{"name":"{canonical}","vers":"{version}","cksum":"{GOOD_SHA256}"}}"#);
            FixtureRoutes {
                config,
                index_rel,
                ndjson,
                download_rel,
                crate_bytes: vec![],
            }
        });

        let reg = CratesIoRegistry::new(&server.base);
        let err = reg.resolve(name, version).unwrap_err();
        assert!(err.to_string().contains("requires authentication"));
    }

    #[test]
    fn rejects_entry_name_mismatch() {
        let name = "mismatcher";
        let version = "1.0.0";
        let canonical = canonical_crate_name(name);
        let index_rel = sparse_index_path(&canonical).unwrap();
        let download_rel = format!("{canonical}/{version}/download");
        let server = Fixture::spawn(move |base| {
            let config = format!(r#"{{"dl":"{base}"}}"#);
            let ndjson =
                format!(r#"{{"name":"totally-other","vers":"{version}","cksum":"{GOOD_SHA256}"}}"#);
            FixtureRoutes {
                config,
                index_rel,
                ndjson,
                download_rel,
                crate_bytes: vec![],
            }
        });

        let reg = CratesIoRegistry::new(&server.base);
        let err = reg.resolve(name, version).unwrap_err();
        assert!(err.to_string().contains("metadata mismatch"));
    }

    #[test]
    fn underscore_names_resolve_through_canonical_paths() {
        let name = "my_crate";
        let version = "2.0.1";
        let canonical = canonical_crate_name(name);
        let crate_bytes = make_crate_bytes(&canonical);
        let server = happy_fixture(name, version, crate_bytes);

        let reg = CratesIoRegistry::new(&server.base);
        let pkg = reg.resolve(name, version).unwrap();
        assert_eq!(pkg.name, "my-crate");
        assert_eq!(reg.default_version(name).unwrap().as_deref(), Some(version));
    }
}
