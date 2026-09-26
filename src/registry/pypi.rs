use crate::error::BluelineError;
use crate::registry::http_util::{RegistryLimits, download_bounded, validate_download_url};
use crate::registry::{Checksum, ChecksumAlg, Ecosystem, Package, Registry, Release, hex_encode};
use crate::version::{Pep440Version, VersionInfo, canonicalize_name, validate_pypi_name};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use ureq::Agent;
const USER_AGENT: &str = concat!("blueline/", env!("CARGO_PKG_VERSION"));
const SIMPLE_ACCEPT: &str = "application/vnd.pypi.simple.v1+json";

/// How many Simple API pages one logical read will walk before refusing.
/// PEP 691 paginates with `meta.next`, and the walk is bounded so a registry
/// that offers an endless chain cannot spin the review.
const MAX_SIMPLE_PAGES: usize = 16;

/// One PyPI release as the Simple API describes it. `Registry::Release` has
/// nowhere to put a PEP 592 yanked reason, so the reason lives here and a
/// caller that renders it reads it from this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyPiRelease {
    pub version: String,
    pub yanked: bool,
    /// Why the registry withdrew the release, when it says. `"yanked"` stands
    /// in for the boolean form, which carries no cause of its own.
    pub yanked_reason: Option<String>,
    /// Unix epoch seconds, when the registry publishes it.
    pub publish_time: Option<i64>,
}

impl From<PyPiRelease> for Release {
    fn from(r: PyPiRelease) -> Self {
        Release {
            version: r.version,
            yanked: r.yanked,
            publish_time: r.publish_time,
        }
    }
}

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
        let agent = super::http_util::registry_agent(USER_AGENT, base);
        Self {
            agent,
            base: base.trim_end_matches('/').to_string(),
            limits,
        }
    }
    /// Every file and version the registry has for `n`: page one, then every
    /// page `meta.next` points at.
    ///
    /// A paginated index read as one page is a silent lie — the release list
    /// stops early, the baseline anchor is picked from a prefix, and a
    /// release whose live artifact is on a later page looks withdrawn because
    /// the only file that arrived was the yanked one. So the walk is bounded
    /// and fails: a chain that outlives `MAX_SIMPLE_PAGES` is an error, never
    /// a short list.
    fn fetch_simple_index(&self, n: &str) -> Result<SimpleIndex, BluelineError> {
        if !validate_pypi_name(n) {
            return Err(BluelineError::InvalidPackageSpec(format!(
                "`{n}` invalid PyPI name"
            )));
        }
        let url = format!("{}/simple/{n}/", self.base);
        // One budget across the whole walk, so a paginated index cannot
        // multiply the per-response cap by the page count.
        let mut budget = self.limits.max_packument_bytes;
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut pages = 1usize;

        let body = self.get_simple_body(&url, n, budget)?;
        budget = budget.saturating_sub(body.len() as u64);
        let first: SimpleResponse = serde_json::from_str(&body)
            .map_err(|e| BluelineError::Manifest(n.to_string(), format!("bad json: {e}")))?;
        let mut next = first
            .meta
            .and_then(|m| m.next)
            .filter(|u| !u.trim().is_empty());
        let mut index = SimpleIndex {
            name: first.name,
            versions: first.versions,
            files: first.files,
        };

        while let Some(next_url) = next {
            if pages >= MAX_SIMPLE_PAGES {
                return Err(BluelineError::Manifest(
                    n.to_string(),
                    format!(
                        "simple index still paginated after {MAX_SIMPLE_PAGES} pages; refusing a truncated release list"
                    ),
                ));
            }
            if !visited.insert(next_url.clone()) {
                return Err(BluelineError::Manifest(
                    n.to_string(),
                    format!("simple index pagination loops back to `{next_url}`"),
                ));
            }
            self.validate_page_url(&next_url)?;
            let body = self.get_simple_body(&next_url, n, budget)?;
            budget = budget.saturating_sub(body.len() as u64);
            let page: SimpleResponse = serde_json::from_str(&body)
                .map_err(|e| BluelineError::Manifest(n.to_string(), format!("bad json: {e}")))?;
            next = page
                .meta
                .and_then(|m| m.next)
                .filter(|u| !u.trim().is_empty());
            index.versions.extend(page.versions);
            index.files.extend(page.files);
            pages += 1;
        }

        Ok(index)
    }
    /// A `meta.next` is a URL off untrusted data. It gets the same SSRF
    /// treatment as a file URL, and must stay on the configured base: the base
    /// is the trust anchor, and an index that points its own continuation at
    /// some other host is a redirect this tool did not agree to.
    fn validate_page_url(&self, url: &str) -> Result<(), BluelineError> {
        validate_download_url(&self.base, url)?;
        let (page_scheme, page_host) =
            super::http_util::parse_url_scheme_and_host(url).map_err(|e| {
                BluelineError::Network(format!("invalid simple index page URL `{url}`: {e}"))
            })?;
        let (base_scheme, base_host) = super::http_util::parse_url_scheme_and_host(&self.base)
            .map_err(|e| {
                BluelineError::Network(format!("invalid registry base URL `{}`: {e}", self.base))
            })?;
        if page_scheme != base_scheme || page_host != base_host {
            return Err(BluelineError::Network(format!(
                "simple index page `{url}` leaves registry base `{}`; refusing",
                self.base
            )));
        }
        Ok(())
    }
    fn get_simple_body(&self, url: &str, n: &str, max_bytes: u64) -> Result<String, BluelineError> {
        let resp = match self.agent.get(url).set("accept", SIMPLE_ACCEPT).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => {
                return Err(BluelineError::NotFound(n.to_string()));
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
            .take(max_bytes + 1)
            .read_to_string(&mut body)
            .map_err(|e| BluelineError::Network(format!("{e}")))?;
        if body.len() as u64 > max_bytes {
            return Err(BluelineError::ExtractionLimit(format!("cap {max_bytes}")));
        }
        Ok(body)
    }
    fn releases_sorted(&self, n: &str) -> Result<Vec<PyPiRelease>, BluelineError> {
        let s = self.fetch_simple_index(n)?;
        let mut m: BTreeMap<String, Vec<&SimpleFile>> = BTreeMap::new();
        for f in &s.files {
            let v =
                extract_version_from_filename(&f.filename).unwrap_or_else(|| f.filename.clone());
            m.entry(v).or_default().push(f);
        }
        for v in &s.versions {
            m.entry(v.clone()).or_default();
        }
        let mut out: Vec<(Pep440Version, PyPiRelease)> = Vec::new();
        for (ver, files) in m {
            let Ok(pv) = Pep440Version::parse(&ver) else {
                continue;
            };
            let pt = files
                .iter()
                .filter_map(|f| f.upload_time.as_deref().and_then(parse_upload_time))
                .max();
            // A release is withdrawn when any of its artifacts is; the reason
            // is the one the withdrawing artifact gives. `yanked_reason` is
            // `Some` exactly when `is_yanked` is true, so the two cannot drift.
            let withdrawn = files.iter().find(|f| f.yanked.is_yanked());
            out.push((
                pv,
                PyPiRelease {
                    version: ver,
                    yanked: withdrawn.is_some(),
                    yanked_reason: withdrawn
                        .and_then(|f| f.yanked.yanked_reason())
                        .map(String::from),
                    publish_time: pt,
                },
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out.into_iter().map(|(_, r)| r).collect())
    }
    /// Release list with the PEP 592 yanked reason preserved. The
    /// `Registry::list_releases` seam drops the reason, so this is what a
    /// caller that renders *why* a release was withdrawn reads.
    pub fn list_releases_with_reasons(
        &self,
        name: &str,
    ) -> Result<Vec<PyPiRelease>, BluelineError> {
        self.releases_sorted(&canonicalize_name(name))
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
        let s = self.fetch_simple_index(&norm)?;
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
        Ok(self
            .releases_sorted(&canonicalize_name(name))?
            .into_iter()
            .map(Release::from)
            .collect())
    }
    fn default_version(&self, name: &str) -> Result<Option<String>, BluelineError> {
        let rel = self.releases_sorted(&canonicalize_name(name))?;
        let live: Vec<&PyPiRelease> = rel.iter().filter(|r| !r.yanked).collect();
        let src: Vec<&PyPiRelease> = if live.is_empty() {
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
/// The full Simple API read for one package, across every page.
#[derive(Debug)]
struct SimpleIndex {
    name: String,
    versions: Vec<String>,
    files: Vec<SimpleFile>,
}

#[derive(Debug, Deserialize)]
struct SimpleResponse {
    name: String,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    files: Vec<SimpleFile>,
    #[serde(default)]
    meta: Option<SimpleMeta>,
}

/// PEP 691 response metadata. `next` is the pagination marker: when it is
/// present the page is a prefix of the index, which is why it is read rather
/// than dropped (see `fetch_simple_index`). `api-version` is deliberately not
/// modeled — nothing acts on it, and a member nothing reads is the same defect
/// as the marker was.
#[derive(Debug, Deserialize)]
struct SimpleMeta {
    #[serde(default)]
    next: Option<String>,
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
impl YankedField {
    fn is_yanked(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Reason(s) => !s.is_empty(),
            _ => false,
        }
    }
    /// The PEP 592 withdrawal reason. `Some` exactly when `is_yanked` is true,
    /// with the boolean form's own spelling standing in for the cause it does
    /// not carry.
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

    /// The PEP 592 yanked reason was read off the index and dropped: the
    /// release list carried only the boolean, so the one field that says *why*
    /// a release was withdrawn never reached a caller.
    #[test]
    fn yanked_release_exposes_the_registry_reason() {
        let server = MockPyPIServer::spawn(|path, _base| {
            if path == "/simple/demo/" {
                let json = serde_json::json!({
                    "name": "demo",
                    "versions": ["1.0.0", "2.0.0", "3.0.0"],
                    "files": [
                        {
                            "filename": "demo-1.0.0-py3-none-any.whl",
                            "url": "http://127.0.0.1/demo-1.0.0.whl",
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": false
                        },
                        {
                            "filename": "demo-2.0.0-py3-none-any.whl",
                            "url": "http://127.0.0.1/demo-2.0.0.whl",
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": "critical vulnerability, no upgrade path"
                        },
                        {
                            "filename": "demo-3.0.0-py3-none-any.whl",
                            "url": "http://127.0.0.1/demo-3.0.0.whl",
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": true
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
        let releases = reg.list_releases_with_reasons("demo").unwrap();
        assert_eq!(releases.len(), 3);

        let by_version = |v: &str| -> PyPiRelease {
            releases
                .iter()
                .find(|r| r.version == v)
                .cloned()
                .expect("release listed")
        };

        let live = by_version("1.0.0");
        assert!(!live.yanked);
        assert_eq!(live.yanked_reason, None);

        let withdrawn = by_version("2.0.0");
        assert!(withdrawn.yanked);
        assert_eq!(
            withdrawn.yanked_reason.as_deref(),
            Some("critical vulnerability, no upgrade path")
        );

        // The boolean form has no reason of its own, so the record says which
        // form the registry used rather than inventing a cause.
        let boolean = by_version("3.0.0");
        assert!(boolean.yanked);
        assert_eq!(boolean.yanked_reason.as_deref(), Some("yanked"));

        // `yanked` and `yanked_reason` are one fact, not two.
        for r in &releases {
            assert_eq!(r.yanked, r.yanked_reason.is_some(), "{}", r.version);
        }
    }

    /// PEP 691 paginates with `meta.next`. The marker was deserialized and
    /// never read, so a truncated page was indistinguishable from a complete
    /// one — a release list that stopped early silently picked the wrong
    /// baseline anchor, and could make a live artifact look yanked because the
    /// surviving file was the withdrawn one.
    #[test]
    fn paginated_simple_index_is_walked_rather_than_truncated() {
        let server = MockPyPIServer::spawn(|path, base| {
            let page =
                |next: Option<String>, files: serde_json::Value, versions: serde_json::Value| {
                    let mut meta = serde_json::json!({"api-version": "1.1"});
                    if let Some(n) = next {
                        meta["next"] = serde_json::json!(n);
                    }
                    (
                        SIMPLE_ACCEPT.to_string(),
                        serde_json::to_vec(&serde_json::json!({
                            "name": "paged",
                            "meta": meta,
                            "versions": versions,
                            "files": files
                        }))
                        .unwrap(),
                    )
                };
            let file = |filename: &str, yanked: serde_json::Value| {
                serde_json::json!({
                    "filename": filename,
                    "url": format!("{base}/{filename}"),
                    "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                    "yanked": yanked
                })
            };
            let next = |n: u32| Some(format!("{base}/simple/paged/?page={n}"));

            match path {
                "/simple/paged/" => page(
                    next(2),
                    serde_json::json!([file(
                        "paged-1.0.0-py3-none-any.whl",
                        serde_json::json!(false)
                    )]),
                    serde_json::json!(["1.0.0"]),
                ),
                "/simple/paged/?page=2" => page(
                    next(3),
                    serde_json::json!([file(
                        "paged-1.1.0-py3-none-any.whl",
                        serde_json::json!(false)
                    )]),
                    serde_json::json!(["1.1.0"]),
                ),
                // The last page is the one that has to arrive: the withdrawn
                // platform wheel, the live universal wheel, and the reason.
                "/simple/paged/?page=3" => page(
                    None,
                    serde_json::json!([
                        file(
                            "paged-1.2.0-cp311-cp311-linux_x86_64.whl",
                            serde_json::json!("broken wheel")
                        ),
                        file("paged-1.2.0-py3-none-any.whl", serde_json::json!(false)),
                    ]),
                    serde_json::json!(["1.2.0"]),
                ),
                _ => ("text/plain".into(), b"not found".to_vec()),
            }
        });

        let reg = PyPIRegistry::new(&server.base);

        // Every page contributes, in version order.
        let releases = reg.list_releases("paged").unwrap();
        let versions: Vec<&str> = releases.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(versions, vec!["1.0.0", "1.1.0", "1.2.0"]);

        // A release with a withdrawn artifact among its files is withdrawn,
        // and the reason comes off the last page.
        let with_reasons = reg.list_releases_with_reasons("paged").unwrap();
        let v12 = with_reasons.iter().find(|r| r.version == "1.2.0").unwrap();
        assert!(v12.yanked);
        assert_eq!(v12.yanked_reason.as_deref(), Some("broken wheel"));
        assert_eq!(reg.default_version("paged").unwrap(), Some("1.1.0".into()));

        // The live artifact of the withdrawn release is still chosen, and it is
        // only visible if the walk reached the last page at all.
        let pkg = reg.resolve("paged", "1.2.0").unwrap();
        assert_eq!(
            pkg.tarball_url,
            format!("{}/paged-1.2.0-py3-none-any.whl", server.base)
        );
    }

    /// A `meta.next` the registry should not be pointing at is refused rather
    /// than followed: it is a URL off untrusted data, and the base is the trust
    /// anchor.
    #[test]
    fn pagination_is_refused_when_the_next_link_leaves_the_registry() {
        for next in [
            "http://169.254.169.254/simple/paged/?page=2",
            "https://cdn.example.com/simple/paged/?page=2",
            "file:///etc/passwd",
        ] {
            let next = next.to_string();
            let server = MockPyPIServer::spawn(move |path, _base| {
                if path == "/simple/paged/" {
                    let json = serde_json::json!({
                        "name": "paged",
                        "meta": {"api-version": "1.1", "next": next},
                        "versions": ["1.0.0"],
                        "files": [{
                            "filename": "paged-1.0.0-py3-none-any.whl",
                            "url": "http://127.0.0.1/paged-1.0.0.whl",
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": false
                        }]
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
            assert!(
                reg.list_releases("paged").is_err(),
                "`next` pointing off the registry must be refused, not followed"
            );
        }
    }

    /// Walking `meta.next` forever is bounded: a chain longer than the page cap
    /// is refused. Returning the pages read so far would be exactly the
    /// truncated list this walk exists to refuse.
    #[test]
    fn pagination_stops_at_the_page_cap_instead_of_reading_a_prefix() {
        let server = MockPyPIServer::spawn(|path, base| {
            let page = |n: usize| {
                (
                    SIMPLE_ACCEPT.to_string(),
                    serde_json::to_vec(&serde_json::json!({
                        "name": "deep",
                        "meta": {"next": format!("{base}/simple/deep/?page={}", n + 1)},
                        "versions": [format!("1.0.{n}")],
                        "files": [{
                            "filename": format!("deep-1.0.{n}-py3-none-any.whl"),
                            "url": format!("{base}/deep-1.0.{n}.whl"),
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": false
                        }]
                    }))
                    .unwrap(),
                )
            };
            if path == "/simple/deep/" {
                return page(0);
            }
            match path.strip_prefix("/simple/deep/?page=") {
                Some(n) => match n.parse::<usize>() {
                    Ok(n) if n <= MAX_SIMPLE_PAGES + 1 => page(n),
                    _ => ("text/plain".into(), b"not found".to_vec()),
                },
                None => ("text/plain".into(), b"not found".to_vec()),
            }
        });

        let reg = PyPIRegistry::new(&server.base);
        let err = reg.list_releases("deep").unwrap_err();
        assert!(
            matches!(&err, BluelineError::Manifest(_, msg) if msg.contains("paginated")),
            "{err}"
        );
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
        /// The handler is also given the base URL, because a fixture that
        /// hands out a `meta.next` link has to spell the ephemeral port the
        /// listener actually bound: the agent exempts the base authority from
        /// its SSRF resolver, and a link to the same host on a different port
        /// is refused like any other private target.
        fn spawn<F: Fn(&str, &str) -> (String, Vec<u8>) + Send + Sync + 'static>(
            handler: F,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let handler = Arc::new(handler);
            let base_in_thread = Arc::new(base.clone());
            let handle = std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let h = handler.clone();
                    let base = base_in_thread.clone();
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
                        let (ctype, body) = h(path, &base);
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
        let server = MockPyPIServer::spawn(move |path, _base| {
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

        assert!(reg.fetch_simple_index("pkg-exact").is_ok());
        let err = reg.fetch_simple_index("pkg-over").unwrap_err();
        assert!(matches!(err, BluelineError::ExtractionLimit(_)));
    }

    #[test]
    fn pypi_releases_and_default_version_selection() {
        let server = MockPyPIServer::spawn(|path, _base| {
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
