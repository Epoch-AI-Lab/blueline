use crate::error::BluelineError;
use crate::registry::http_util::{RegistryLimits, download_bounded, validate_download_url};
use crate::registry::{Checksum, ChecksumAlg, Ecosystem, Package, Registry, Release, hex_encode};
use crate::version::{Pep440Version, VersionInfo, canonicalize_name, validate_pypi_name};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use ureq::Agent;
const USER_AGENT: &str = concat!("blueline/", env!("CARGO_PKG_VERSION"));
const SIMPLE_ACCEPT: &str = "application/vnd.pypi.simple.v1+json";
pub struct PyPIRegistry {
    agent: Agent,
    base: String,
    limits: RegistryLimits,
}
impl PyPIRegistry {
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
    fn fetch_simple(&self, n: &str) -> Result<SimpleResponse, BluelineError> {
        if !validate_pypi_name(n) {
            return Err(BluelineError::InvalidPackageSpec(format!(
                "`{n}` invalid PyPI name"
            )));
        }
        let url = format!("{}/simple/{n}/", self.base);
        let resp = match self.agent.get(&url).set("accept", SIMPLE_ACCEPT).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => {
                return Err(BluelineError::Manifest(n.to_string(), "not found".into()));
            }
            Err(e) => return Err(BluelineError::Network(format!("GET {url}: {e}"))),
        };
        if resp
            .header("content-type")
            .is_some_and(|ct| !ct.to_ascii_lowercase().contains("json"))
        {
            return Err(BluelineError::Manifest(
                n.to_string(),
                "bad content-type".into(),
            ));
        }
        let mut body = String::new();
        resp.into_reader()
            .take(self.limits.max_packument_bytes + 1)
            .read_to_string(&mut body)
            .map_err(|e| BluelineError::Network(format!("{e}")))?;
        if body.len() as u64 > self.limits.max_packument_bytes {
            return Err(BluelineError::ExtractionLimit(format!(
                "cap {}",
                self.limits.max_packument_bytes
            )));
        }
        serde_json::from_str(&body)
            .map_err(|e| BluelineError::Manifest(n.to_string(), format!("bad json: {e}")))
    }
    fn releases_sorted(&self, n: &str) -> Result<Vec<Release>, BluelineError> {
        let s = self.fetch_simple(n)?;
        let mut m: BTreeMap<String, Vec<&SimpleFile>> = BTreeMap::new();
        for f in &s.files {
            let v =
                extract_version_from_filename(&f.filename).unwrap_or_else(|| f.filename.clone());
            m.entry(v).or_default().push(f);
        }
        for v in &s.versions {
            m.entry(v.clone()).or_default();
        }
        let mut out: Vec<(Pep440Version, Release)> = Vec::new();
        for (ver, files) in m {
            let Ok(pv) = Pep440Version::parse(&ver) else {
                continue;
            };
            let yanked = files.iter().any(|f| f.yanked.is_yanked());
            let pt = files
                .iter()
                .filter_map(|f| f.upload_time.as_deref().and_then(parse_upload_time))
                .max();
            out.push((
                pv,
                Release {
                    version: ver,
                    yanked,
                    publish_time: pt,
                },
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out.into_iter().map(|(_, r)| r).collect())
    }
    fn resolve_package(&self, name: &str, version: &str) -> Result<Package, BluelineError> {
        if !validate_pypi_name(name) {
            return Err(BluelineError::InvalidPackageSpec(format!(
                "`{name}` invalid"
            )));
        }
        Pep440Version::parse(version)
            .map_err(|_| BluelineError::InvalidPackageSpec(format!("{name}=={version} invalid")))?;
        let norm = canonicalize_name(name);
        let s = self.fetch_simple(&norm)?;
        let cand: Vec<&SimpleFile> = s
            .files
            .iter()
            .filter(|f| extract_version_from_filename(&f.filename).as_deref() == Some(version))
            .collect();
        if cand.is_empty() {
            return Err(BluelineError::Manifest(norm, format!("no {version}")));
        }
        let non: Vec<&SimpleFile> = cand
            .iter()
            .copied()
            .filter(|f| !f.yanked.is_yanked())
            .collect();
        let pool = if non.is_empty() { cand } else { non };
        let chosen = select_wheel(&pool)
            .or_else(|| pool.first().copied())
            .ok_or_else(|| BluelineError::Manifest(norm.clone(), "no files".to_string()))?;
        let sha = chosen
            .hashes
            .get("sha256")
            .ok_or_else(|| BluelineError::Verification("no sha256".to_string()))?;
        let csum = Checksum::parse(&format!("sha256:{sha}"))
            .map_err(|e| BluelineError::Verification(format!("bad sha256: {e}")))?;
        validate_download_url(&self.base, &chosen.url)?;
        Ok(Package {
            name: s.name,
            version: version.to_string(),
            tarball_url: chosen.url.clone(),
            integrity: Some(csum),
        })
    }
    fn fetch_url_verified(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError> {
        let b = download_bounded(
            &self.agent,
            &self.base,
            &pkg.tarball_url,
            self.limits.max_tarball_bytes,
            self.limits.max_redirects,
        )
        .map_err(|e| match e {
            BluelineError::ExtractionLimit(_) => {
                BluelineError::ExtractionLimit(format!("cap {}", self.limits.max_tarball_bytes))
            }
            other => other,
        })?;
        let exp = pkg
            .integrity
            .as_ref()
            .ok_or_else(|| BluelineError::Verification("no checksum".to_string()))?;
        if exp.alg != ChecksumAlg::Sha256 {
            return Err(BluelineError::Verification("not sha256".to_string()));
        }
        let mut h = Sha256::new();
        h.update(&b);
        let comp = hex_encode(&h.finalize());
        if comp != exp.value_hex {
            return Err(BluelineError::Verification(format!(
                "sha256 mismatch {} vs {comp}",
                exp.to_display()
            )));
        }
        Ok(b)
    }
}
impl Registry for PyPIRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPi
    }
    fn resolve(&self, name: &str, version: &str) -> Result<Package, BluelineError> {
        self.resolve_package(name, version)
    }
    fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError> {
        self.fetch_url_verified(pkg)
    }
    fn list_versions(&self, name: &str) -> Result<Vec<semver::Version>, BluelineError> {
        let mut v: Vec<semver::Version> = self
            .list_releases(name)?
            .into_iter()
            .filter_map(|r| {
                semver::Version::parse(&r.version).ok().or_else(|| {
                    Pep440Version::parse(&r.version)
                        .ok()
                        .and_then(|p| semver::Version::parse(&p.canonical()).ok())
                })
            })
            .collect();
        v.sort();
        Ok(v)
    }
    fn list_releases(&self, name: &str) -> Result<Vec<Release>, BluelineError> {
        self.releases_sorted(&canonicalize_name(name))
    }
    fn default_version(&self, name: &str) -> Result<Option<String>, BluelineError> {
        let rel = self.releases_sorted(&canonicalize_name(name))?;
        let live: Vec<&Release> = rel.iter().filter(|r| !r.yanked).collect();
        let src: Vec<&Release> = if live.is_empty() {
            rel.iter().collect()
        } else {
            live
        };
        let best = |stable: bool| {
            src.iter()
                .filter_map(|r| {
                    Pep440Version::parse(&r.version)
                        .ok()
                        .map(|pv| (pv, &r.version))
                })
                .filter(|(pv, _)| !stable || !pv.is_prerelease())
                .max_by(|a, b| a.0.cmp(&b.0))
                .map(|(_, v)| v.clone())
        };
        Ok(best(true).or_else(|| best(false)))
    }
}
#[derive(Debug, Deserialize)]
struct SimpleResponse {
    name: String,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    files: Vec<SimpleFile>,
    #[allow(dead_code)]
    #[serde(default)]
    meta: Option<serde_json::Value>,
}
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SimpleFile {
    filename: String,
    url: String,
    #[serde(default)]
    hashes: BTreeMap<String, String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default, rename = "upload-time")]
    upload_time: Option<String>,
    #[serde(default)]
    yanked: YankedField,
    #[serde(default)]
    provenance: Option<String>,
}
#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
enum YankedField {
    #[default]
    NotYanked,
    Bool(bool),
    Reason(String),
}
#[allow(dead_code)]
impl YankedField {
    fn is_yanked(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Reason(s) => !s.is_empty(),
            _ => false,
        }
    }
    fn yanked_reason(&self) -> Option<&str> {
        match self {
            Self::Reason(s) if !s.is_empty() => Some(s),
            Self::Bool(true) => Some("yanked"),
            _ => None,
        }
    }
}
fn select_wheel<'a>(c: &[&'a SimpleFile]) -> Option<&'a SimpleFile> {
    if let Some(u) = c.iter().find(|f| f.filename.ends_with("-py3-none-any.whl")) {
        return Some(*u);
    }
    c.iter()
        .filter(|f| f.filename.ends_with(".whl"))
        .min_by_key(|f| &f.filename)
        .copied()
        .or_else(|| c.iter().min_by_key(|f| &f.filename).copied())
}
fn extract_version_from_filename(n: &str) -> Option<String> {
    if let Some(s) = n.strip_suffix(".whl") {
        let p: Vec<&str> = s.split('-').collect();
        if p.len() < 5 {
            return None;
        }
        Some(p[p.len() - 4].to_string())
    } else {
        let s = n
            .strip_suffix(".tar.gz")
            .or_else(|| n.strip_suffix(".zip"))?;
        s.rsplit('-').next().map(|s| s.to_string())
    }
}
#[rustfmt::skip]
fn parse_upload_time(s: &str) -> Option<i64> { let s = s.trim().strip_suffix('Z').unwrap_or(s.trim()); let s = s.split('.').next().unwrap_or(s); let (d, t) = s.split_once('T')?; let mut d = d.split('-'); let y:i64=d.next()?.parse().ok()?; let m:i64=d.next()?.parse().ok()?; let day:i64=d.next()?.parse().ok()?; let mut t=t.split(':'); let hh:i64=t.next()?.parse().ok()?; let mm:i64=t.next()?.parse().ok()?; let ss:i64=t.next()?.parse().ok()?; if !(1..=12).contains(&m)||!(1..=31).contains(&day){return None;} let a=(14-m)/12; let yy=y+4800-a; let mo=m+12*a-3; let jdn=day+(153*mo+2)/5+365*yy+yy/4-yy/100+yy/400-32045; Some((jdn-2440588)*86400+hh*3600+mm*60+ss) }
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::Arc;

    #[test]
    fn yanked_field_is_yanked() {
        for (s, e) in [
            ("false", false),
            ("true", true),
            ("\"reason\"", true),
            ("\"\"", false),
        ] {
            let f: YankedField = serde_json::from_str(s).unwrap();
            assert_eq!(f.is_yanked(), e);
        }
    }

    #[test]
    fn yanked_field_reasons() {
        assert_eq!(YankedField::NotYanked.yanked_reason(), None);
        assert_eq!(YankedField::Bool(false).yanked_reason(), None);
        assert_eq!(YankedField::Bool(true).yanked_reason(), Some("yanked"));
        assert_eq!(
            YankedField::Reason("security bug".into()).yanked_reason(),
            Some("security bug")
        );
        assert_eq!(YankedField::Reason("".into()).yanked_reason(), None);
    }

    #[test]
    fn select_prefers_universal() {
        let mk = |n: &str| SimpleFile {
            filename: n.into(),
            url: "https://e.com/a.whl".into(),
            hashes: BTreeMap::new(),
            size: None,
            upload_time: None,
            yanked: YankedField::NotYanked,
            provenance: None,
        };
        let a = mk("pkg-1.0-cp311-cp311-linux_x86_64.whl");
        let b = mk("pkg-1.0-py3-none-any.whl");
        assert_eq!(select_wheel(&[&a, &b]).unwrap().filename, b.filename);
    }

    #[test]
    fn parse_upload_time_iso8601() {
        assert_eq!(
            parse_upload_time("2024-01-17T16:53:12.779164Z"),
            Some(1705510392)
        );
        assert_eq!(parse_upload_time("2024-01-17T16:53:12Z"), Some(1705510392));
        assert_eq!(parse_upload_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_upload_time("2024-03-15T12:00:00Z"), Some(1710504000));
        assert_eq!(parse_upload_time("2024-07-20T08:30:00Z"), Some(1721464200));
        assert_eq!(parse_upload_time("2024-11-05T18:45:15Z"), Some(1730832315));
        assert_eq!(parse_upload_time("2024-02-29T23:59:59Z"), Some(1709251199));
        assert!(parse_upload_time("not-a-time").is_none());
        assert!(parse_upload_time("2024-00-17T16:53:12Z").is_none());
        assert!(parse_upload_time("2024-13-17T16:53:12Z").is_none());
        assert!(parse_upload_time("2024-01-00T16:53:12Z").is_none());
        assert!(parse_upload_time("2024-01-32T16:53:12Z").is_none());
    }

    #[test]
    fn extracts_version_from_hyphenated_names() {
        for (f, e) in [
            ("scikit-learn-1.4.0-py3-none-any.whl", Some("1.4.0")),
            ("my-package-1.0-py3-none-any.whl", Some("1.0")),
            ("scikit-learn-1.4.0.tar.gz", Some("1.4.0")),
            ("pkg-2.28.1.zip", Some("2.28.1")),
            ("pkg-1.0-cp311.whl", None),
            ("pkg-1.0.whl", None),
            ("pkg.whl", None),
        ] {
            assert_eq!(extract_version_from_filename(f), e.map(|s| s.to_string()));
        }
        assert!(extract_version_from_filename("notawheel").is_none());
    }

    struct MockPyPIServer {
        base: String,
        _handle: std::thread::JoinHandle<()>,
    }

    impl MockPyPIServer {
        fn spawn<F: Fn(&str) -> (String, Vec<u8>) + Send + Sync + 'static>(handler: F) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let handler = Arc::new(handler);
            let handle = std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let h = handler.clone();
                    std::thread::spawn(move || {
                        let mut stream = stream;
                        let mut buf = [0u8; 4096];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let path = req
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("/");
                        let (ctype, body) = h(path);
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(&body);
                    });
                }
            });
            Self {
                base,
                _handle: handle,
            }
        }
    }

    #[test]
    fn pypi_packument_exact_limits_boundary() {
        let max_bytes = 1024u64;
        let server = MockPyPIServer::spawn(move |path| {
            if path == "/simple/pkg-exact/" {
                let base = "{\"name\":\"pkg-exact\",\"files\":[],\"versions\":[]}";
                let padding = " ".repeat(max_bytes as usize - base.len());
                let body = format!("{base}{padding}");
                (SIMPLE_ACCEPT.to_string(), body.into_bytes())
            } else if path == "/simple/pkg-over/" {
                let base = "{\"name\":\"pkg-over\",\"files\":[],\"versions\":[]}";
                let padding = " ".repeat(max_bytes as usize + 1 - base.len());
                let body = format!("{base}{padding}");
                (SIMPLE_ACCEPT.to_string(), body.into_bytes())
            } else {
                ("text/plain".into(), b"not found".to_vec())
            }
        });

        let reg = PyPIRegistry::with_limits(
            &server.base,
            RegistryLimits {
                max_packument_bytes: max_bytes,
                max_tarball_bytes: 512,
                ..RegistryLimits::default()
            },
        );

        assert!(reg.fetch_simple("pkg-exact").is_ok());
        let err = reg.fetch_simple("pkg-over").unwrap_err();
        assert!(matches!(err, BluelineError::ExtractionLimit(_)));
    }

    #[test]
    fn pypi_releases_and_default_version_selection() {
        let server = MockPyPIServer::spawn(|path| {
            if path == "/simple/demo/" {
                let json = serde_json::json!({
                    "name": "demo",
                    "versions": ["1.0.0", "1.1.0", "2.0.0a1", "2.0.0"],
                    "files": [
                        {
                            "filename": "demo-1.0.0-py3-none-any.whl",
                            "url": "http://127.0.0.1/demo-1.0.0.whl",
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": false,
                            "upload-time": "2024-01-01T00:00:00Z"
                        },
                        {
                            "filename": "demo-1.1.0-py3-none-any.whl",
                            "url": "http://127.0.0.1/demo-1.1.0.whl",
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": false,
                            "upload-time": "2024-02-01T00:00:00Z"
                        },
                        {
                            "filename": "demo-2.0.0a1-py3-none-any.whl",
                            "url": "http://127.0.0.1/demo-2.0.0a1.whl",
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": false,
                            "upload-time": "2024-03-01T00:00:00Z"
                        },
                        {
                            "filename": "demo-2.0.0-py3-none-any.whl",
                            "url": "http://127.0.0.1/demo-2.0.0.whl",
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": "critical security bug",
                            "upload-time": "2024-04-01T00:00:00Z"
                        }
                    ]
                });
                (
                    SIMPLE_ACCEPT.to_string(),
                    serde_json::to_vec(&json).unwrap(),
                )
            } else if path == "/simple/only-pre/" {
                let json = serde_json::json!({
                    "name": "only-pre",
                    "versions": ["1.0.0a1"],
                    "files": [
                        {
                            "filename": "only-pre-1.0.0a1-py3-none-any.whl",
                            "url": "http://127.0.0.1/only-pre-1.0.0a1.whl",
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": false
                        }
                    ]
                });
                (
                    SIMPLE_ACCEPT.to_string(),
                    serde_json::to_vec(&json).unwrap(),
                )
            } else if path == "/simple/empty/" {
                let json = serde_json::json!({
                    "name": "empty",
                    "versions": [],
                    "files": []
                });
                (
                    SIMPLE_ACCEPT.to_string(),
                    serde_json::to_vec(&json).unwrap(),
                )
            } else if path == "/simple/dual-files/" {
                let json = serde_json::json!({
                    "name": "dual-files",
                    "versions": ["1.0.0"],
                    "files": [
                        {
                            "filename": "dual-files-1.0.0-cp311-cp311-linux_x86_64.whl",
                            "url": "http://127.0.0.1/yanked.whl",
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": true
                        },
                        {
                            "filename": "dual-files-1.0.0-py3-none-any.whl",
                            "url": "http://127.0.0.1/good.whl",
                            "hashes": {"sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
                            "yanked": false
                        }
                    ]
                });
                (
                    SIMPLE_ACCEPT.to_string(),
                    serde_json::to_vec(&json).unwrap(),
                )
            } else {
                ("text/plain".into(), b"not found".to_vec())
            }
        });

        let reg = PyPIRegistry::new(&server.base);

        let releases = reg.list_releases("demo").unwrap();
        assert_eq!(releases.len(), 4);
        assert_eq!(releases[0].version, "1.0.0");
        assert!(!releases[0].yanked);
        assert_eq!(releases[0].publish_time, Some(1704067200));
        assert!(releases[3].yanked);

        let versions = reg.list_versions("demo").unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0], semver::Version::new(1, 0, 0));
        assert_eq!(versions[1], semver::Version::new(1, 1, 0));
        assert_eq!(versions[2], semver::Version::new(2, 0, 0));

        assert_eq!(reg.default_version("demo").unwrap(), Some("1.1.0".into()));
        assert_eq!(
            reg.default_version("only-pre").unwrap(),
            Some("1.0.0a1".into())
        );
        assert_eq!(reg.default_version("empty").unwrap(), None);

        let pkg = reg.resolve("dual-files", "1.0.0").unwrap();
        assert_eq!(pkg.tarball_url, "http://127.0.0.1/good.whl");
        assert_eq!(
            pkg.integrity.unwrap().to_display(),
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        );

        assert!(reg.resolve("invalid!name", "1.0.0").is_err());
        assert!(reg.resolve("demo", "invalid-ver!").is_err());
    }
}
