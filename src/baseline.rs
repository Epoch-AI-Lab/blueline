use crate::error::BluelineError;
use crate::registry::{Checksum, Package, Registry, Release, releases_with_reasons};
use crate::store::BaselineStore;
use crate::version::VersionInfo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineResolution {
    /// Found an approved release from the local SQLite store (clean = 1).
    LocalApproved(Package),
    /// Found the immediate prior release from the registry version list.
    RegistryPredecessor(Package),
    /// No prior version exists (first sighting / initial publication).
    FirstSighting,
}

/// Result of baseline resolution: which anchor to diff against, plus lifecycle
/// signals observed while consulting registry history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineSelection {
    pub resolution: BaselineResolution,
    /// The release immediately preceding the target is yanked. Supply-chain
    /// signal regardless of which anchor won (feeds R08_YANKED_PREDECESSOR).
    pub prior_release_yanked: bool,
    /// Why the registry withdrew that prior release, when it says. `None` is
    /// the registry publishing no reason, not an unknown one.
    pub prior_yanked_reason: Option<String>,
    /// The target release itself is yanked on the registry (feeds R09_YANKED_TARGET).
    pub target_release_yanked: bool,
    /// Why the registry withdrew the target, when it says.
    pub target_yanked_reason: Option<String>,
}

impl BaselineResolution {
    pub fn package(&self) -> Option<&Package> {
        match self {
            BaselineResolution::LocalApproved(p) | BaselineResolution::RegistryPredecessor(p) => {
                Some(p)
            }
            BaselineResolution::FirstSighting => None,
        }
    }
}

pub fn resolve_baseline<V: VersionInfo>(
    name: &str,
    target_ver: &V,
    registry: &dyn Registry,
    store: &BaselineStore,
) -> Result<BaselineSelection, BluelineError> {
    let (all_releases, yanked_reasons) = releases_with_reasons(registry, name)?;
    let target_release = all_releases
        .iter()
        .find(|r| V::parse(&r.version).ok().as_ref() == Some(target_ver));
    let target_release_yanked = target_release.is_some_and(|r| r.yanked);
    let target_yanked_reason = target_release
        .filter(|r| r.yanked)
        .and_then(|r| yanked_reasons.get(&r.version))
        .map(String::from);

    let mut eligible: Vec<(V, Release)> = all_releases
        .into_iter()
        .filter_map(|r| V::parse(&r.version).ok().map(|v| (v, r)))
        .filter(|(v, _)| v.baseline_eligible_for(target_ver))
        .collect();
    eligible.sort_by(|a, b| a.0.cmp(&b.0));
    let prior = eligible.last();
    let prior_release_yanked = prior.is_some_and(|(_, r)| r.yanked);
    let prior_yanked_reason = prior
        .filter(|(_, r)| r.yanked)
        .and_then(|(_, r)| yanked_reasons.get(&r.version))
        .map(String::from);

    let selection = |resolution| BaselineSelection {
        resolution,
        prior_release_yanked,
        target_release_yanked,
        prior_yanked_reason: prior_yanked_reason.clone(),
        target_yanked_reason: target_yanked_reason.clone(),
    };

    let clean_versions = store.list_clean_versions::<V>(registry.ecosystem(), name)?;

    for (clean_ver, stored_integrity) in clean_versions {
        if clean_ver.baseline_eligible_for(target_ver) {
            // Compare normalized checksums so legacy SRI rows and new display
            // forms are judged by content, not by spelling.
            let stored_checksum = Checksum::parse(&stored_integrity);
            match registry.resolve(name, &clean_ver.canonical()) {
                Ok(pkg) => match (&pkg.integrity, &stored_checksum) {
                    (Some(reg_integ), Ok(stored)) if *reg_integ == *stored => {
                        return Ok(selection(BaselineResolution::LocalApproved(pkg)));
                    }
                    (Some(reg_integ), _) => {
                        return Err(BluelineError::Verification(format!(
                            "stored clean baseline for {name}@{} had integrity `{stored_integrity}`, but registry reported `{}`; refusing to trust tampered baseline",
                            clean_ver.canonical(),
                            reg_integ.to_display()
                        )));
                    }
                    (None, _) => {
                        return Err(BluelineError::Verification(format!(
                            "stored clean baseline for {name}@{} had integrity `{stored_integrity}`, but registry reported no integrity; refusing to trust unverified baseline",
                            clean_ver.canonical()
                        )));
                    }
                },
                Err(BluelineError::Manifest(_, _)) => {
                    // A version-level Manifest error here means this specific
                    // stored-clean version is yanked/missing from the registry,
                    // so we keep looking at older clean versions. A package-wide
                    // 404 (the whole package removed) is gated earlier at
                    // `releases_with_reasons(..)?` above and fails closed there
                    // — it must never reach this loop, so do NOT reinterpret
                    // Manifest as a benign "skip the candidate" for a missing
                    // package.
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    // Predecessor = highest NON-YANKED eligible release. All-yanked history
    // degrades to FirstSighting (with the R08 warning carried alongside).
    let predecessor_version = eligible
        .iter()
        .rev()
        .find(|(_, r)| !r.yanked)
        .map(|(_, r)| r.version.clone());

    if let Some(pred_str) = predecessor_version {
        let pkg = registry.resolve(name, &pred_str)?;
        return Ok(selection(BaselineResolution::RegistryPredecessor(pkg)));
    }

    Ok(selection(BaselineResolution::FirstSighting))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Checksum, ChecksumAlg, Ecosystem, Release};
    use sha2::{Digest, Sha512};

    /// Deterministic valid sha512 checksum derived from the version string.
    fn checksum_for(tag: &str) -> Checksum {
        let mut hasher = Sha512::new();
        hasher.update(tag.as_bytes());
        Checksum {
            alg: ChecksumAlg::Sha512,
            value_hex: format!("{:x}", hasher.finalize()),
        }
    }

    struct MockRegistry {
        versions: Vec<String>,
        yanked_versions: Vec<String>,
        integrity_override: Option<Option<Checksum>>,
    }

    impl MockRegistry {
        fn new(versions: Vec<String>) -> Self {
            Self {
                versions,
                yanked_versions: Vec::new(),
                integrity_override: None,
            }
        }

        fn with_yanked(versions: Vec<String>, yanked_versions: Vec<String>) -> Self {
            Self {
                versions,
                yanked_versions,
                integrity_override: None,
            }
        }
    }

    impl Registry for MockRegistry {
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::Npm
        }

        fn resolve(&self, name: &str, version: &str) -> Result<Package, BluelineError> {
            if self.versions.contains(&version.to_string()) {
                let integrity = match &self.integrity_override {
                    Some(custom) => custom.clone(),
                    None => Some(checksum_for(version)),
                };
                Ok(Package {
                    name: name.to_string(),
                    version: version.to_string(),
                    tarball_url: format!("https://example.com/{name}-{version}.tgz"),
                    integrity,
                })
            } else {
                Err(BluelineError::Manifest(
                    name.to_string(),
                    format!("unknown version {version}"),
                ))
            }
        }

        fn fetch_tarball(&self, _pkg: &Package) -> Result<Vec<u8>, BluelineError> {
            Ok(vec![])
        }

        fn list_versions(&self, _name: &str) -> Result<Vec<semver::Version>, BluelineError> {
            let mut v: Vec<_> = self
                .versions
                .iter()
                .filter_map(|s| semver::Version::parse(s).ok())
                .collect();
            v.sort();
            Ok(v)
        }

        fn list_releases(&self, name: &str) -> Result<Vec<Release>, BluelineError> {
            let mut releases: Vec<Release> = self
                .versions
                .iter()
                .map(|v| Release {
                    yanked: self.yanked_versions.contains(v),
                    version: v.clone(),
                    publish_time: None,
                })
                .collect();
            releases.sort_by(|a, b| {
                let av = crate::version::Pep440Version::parse(&a.version)
                    .ok()
                    .map(|v| v.canonical());
                let bv = crate::version::Pep440Version::parse(&b.version)
                    .ok()
                    .map(|v| v.canonical());
                av.cmp(&bv)
            });
            let _ = name;
            Ok(releases)
        }

        fn default_version(&self, _name: &str) -> Result<Option<String>, BluelineError> {
            Ok(self.versions.last().cloned())
        }
    }

    #[test]
    fn resolves_local_approved_baseline_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified(Ecosystem::Npm, "pkg", "1.0.0", &checksum_for("1.0.0"))
            .unwrap();
        store
            .record_verified(Ecosystem::Npm, "pkg", "1.1.0", &checksum_for("1.1.0"))
            .unwrap();
        store
            .mark_clean(Ecosystem::Npm, "pkg", "1.0.0", &checksum_for("1.0.0"))
            .unwrap();

        let registry = MockRegistry::new(vec!["1.0.0".into(), "1.1.0".into(), "1.2.0".into()]);

        let target = semver::Version::parse("1.2.0").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        assert!(matches!(
            res.resolution,
            BaselineResolution::LocalApproved(ref p) if p.version == "1.0.0"
        ));
        assert!(!res.prior_release_yanked);
    }

    #[test]
    fn falls_back_to_registry_predecessor() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();

        let registry = MockRegistry::new(vec!["1.0.0".into(), "1.1.0".into(), "1.2.0".into()]);

        let target = semver::Version::parse("1.2.0").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        assert!(matches!(
            res.resolution,
            BaselineResolution::RegistryPredecessor(ref p) if p.version == "1.1.0"
        ));
    }

    #[test]
    fn detects_first_sighting() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();

        let registry = MockRegistry::new(vec!["1.0.0".into()]);

        let target = semver::Version::parse("1.0.0").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        assert_eq!(res.resolution, BaselineResolution::FirstSighting);
        assert!(!res.prior_release_yanked);
    }

    #[test]
    fn skips_yanked_immediate_prior_and_flags_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();

        // 1.1.0 (the immediate prior) is yanked; 1.0.0 remains as anchor.
        let registry = MockRegistry::with_yanked(
            vec!["1.0.0".into(), "1.1.0".into(), "1.2.0".into()],
            vec!["1.1.0".into()],
        );

        let target = semver::Version::parse("1.2.0").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        assert!(matches!(
            res.resolution,
            BaselineResolution::RegistryPredecessor(ref p) if p.version == "1.0.0"
        ));
        assert!(res.prior_release_yanked);
    }

    #[test]
    fn all_yanked_history_degrades_to_first_sighting_with_warning() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();

        let registry = MockRegistry::with_yanked(
            vec!["1.0.0".into(), "1.1.0".into(), "1.2.0".into()],
            vec!["1.0.0".into(), "1.1.0".into()],
        );

        let target = semver::Version::parse("1.2.0").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        assert_eq!(res.resolution, BaselineResolution::FirstSighting);
        assert!(res.prior_release_yanked);
    }

    #[test]
    fn non_yanked_target_keeps_clean_flag_when_prior_is_live() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();

        let registry =
            MockRegistry::with_yanked(vec!["1.0.0".into(), "1.1.0".into()], vec!["9.9.9".into()]);

        let target = semver::Version::parse("1.1.0").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        assert!(matches!(
            res.resolution,
            BaselineResolution::RegistryPredecessor(ref p) if p.version == "1.0.0"
        ));
        assert!(!res.prior_release_yanked);
    }

    #[test]
    fn rejects_tampered_approved_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified(Ecosystem::Npm, "pkg", "1.0.0", &checksum_for("authentic"))
            .unwrap();
        store
            .mark_clean(Ecosystem::Npm, "pkg", "1.0.0", &checksum_for("authentic"))
            .unwrap();

        // Registry serves a tampered integrity for 1.0.0
        let mut registry = MockRegistry::new(vec!["1.0.0".into(), "1.1.0".into()]);
        registry.integrity_override = Some(Some(checksum_for("tampered")));

        let target = semver::Version::parse("1.1.0").unwrap();
        let err = resolve_baseline("pkg", &target, &registry, &store).unwrap_err();
        assert!(err.to_string().contains("tampered baseline"));
    }

    #[test]
    fn rejects_missing_integrity_on_stored_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified(Ecosystem::Npm, "pkg", "1.0.0", &checksum_for("authentic"))
            .unwrap();
        store
            .mark_clean(Ecosystem::Npm, "pkg", "1.0.0", &checksum_for("authentic"))
            .unwrap();

        let mut registry = MockRegistry::new(vec!["1.0.0".into(), "1.1.0".into()]);
        registry.integrity_override = Some(None);

        let target = semver::Version::parse("1.1.0").unwrap();
        let err = resolve_baseline("pkg", &target, &registry, &store).unwrap_err();
        assert!(err.to_string().contains("reported no integrity"));
    }

    #[test]
    fn pep440_baseline_skips_prerelease_for_stable_target() {
        use crate::version::Pep440Version;
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        let registry = MockRegistry::new(vec!["1.0".into(), "1.0a1".into(), "1.0.1".into()]);
        let target = Pep440Version::parse("1.0.1").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        match res.resolution {
            BaselineResolution::RegistryPredecessor(p) => assert_eq!(p.version, "1.0"),
            other => panic!("expected predecessor 1.0, got {other:?}"),
        }
    }

    #[test]
    fn pep440_baseline_allows_prerelease_for_prerelease_target() {
        use crate::version::Pep440Version;
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        let registry = MockRegistry::new(vec!["1.0".into(), "1.0a1".into()]);
        let target = Pep440Version::parse("1.0a2").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        match res.resolution {
            BaselineResolution::RegistryPredecessor(p) => assert_eq!(p.version, "1.0a1"),
            other => panic!("expected predecessor 1.0a1, got {other:?}"),
        }
    }

    #[test]
    fn baseline_detects_target_and_prior_yanked() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        let mut registry = MockRegistry::new(vec!["1.0.0".into(), "1.1.0".into(), "1.2.0".into()]);
        registry.yanked_versions = vec!["1.1.0".into(), "1.2.0".into()];
        let target = semver::Version::parse("1.2.0").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        assert!(res.target_release_yanked);
        assert!(res.prior_release_yanked);
        // This registry publishes no reason, so there is none to report: a
        // withdrawn release must not inherit a cause nobody stated.
        assert_eq!(res.prior_yanked_reason, None);
        assert_eq!(res.target_yanked_reason, None);

        let target_stable = semver::Version::parse("1.0.0").unwrap();
        let res2 = resolve_baseline("pkg", &target_stable, &registry, &store).unwrap();
        assert!(!res2.target_release_yanked);
        assert!(!res2.prior_release_yanked);
        assert_eq!(res2.prior_yanked_reason, None);
        assert_eq!(res2.target_yanked_reason, None);
    }

    /// A release that is not withdrawn never carries a reason: a reason next
    /// to a live release would read as a cause for a withdrawal that did not
    /// happen. This is the default state for every registry that publishes no
    /// reason at all, npm among them.
    #[test]
    fn a_live_release_never_carries_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        let server = MockSimpleIndex::spawn("live", &[]);
        let registry = crate::registry::pypi::PyPIRegistry::new(&server.base);
        let target = crate::version::Pep440Version::parse("1.0.0").unwrap();
        let res = resolve_baseline("live", &target, &registry, &store).unwrap();
        assert!(!res.prior_release_yanked);
        assert!(!res.target_release_yanked);
        assert_eq!(res.prior_yanked_reason, None);
        assert_eq!(res.target_yanked_reason, None);
    }

    /// The reason the registry published for the withdrawn predecessor and for
    /// the withdrawn target, filled at the same sites that set the booleans.
    /// Before this, a reviewer saw "yanked" and nothing about why.
    #[test]
    fn registry_stated_yanked_reasons_reach_the_selection() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        let server = MockSimpleIndex::spawn("demo", &["1.1.0 broken wheel", "1.2.0 security bug"]);
        let registry = crate::registry::pypi::PyPIRegistry::new(&server.base);
        let target = crate::version::Pep440Version::parse("1.2.0").unwrap();
        let res = resolve_baseline("demo", &target, &registry, &store).unwrap();

        assert!(res.prior_release_yanked);
        assert_eq!(res.prior_yanked_reason.as_deref(), Some("broken wheel"));
        assert!(res.target_release_yanked);
        assert_eq!(res.target_yanked_reason.as_deref(), Some("security bug"));
        // The anchor is the highest non-yanked release, which is not the one
        // the reason belongs to.
        match &res.resolution {
            BaselineResolution::RegistryPredecessor(p) => assert_eq!(p.version, "1.0.0"),
            other => panic!("expected predecessor 1.0.0, got {other:?}"),
        }
    }

    /// Serves a PEP 691 Simple index for one package: `1.0.0` live, and each
    /// `yanked` argument naming a version to withdraw with that reason. Only
    /// the index is needed — baseline resolution resolves a predecessor
    /// without downloading it.
    struct MockSimpleIndex {
        base: String,
        _handle: std::thread::JoinHandle<()>,
    }

    impl MockSimpleIndex {
        fn spawn(name: &str, yanked: &[&str]) -> Self {
            use std::io::{Read, Write};
            use std::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let name = name.to_string();
            let yanked: Vec<String> = yanked.iter().map(|s| s.to_string()).collect();
            let handle = std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let (name, yanked) = (name.clone(), yanked.clone());
                    std::thread::spawn(move || {
                        let mut stream = stream;
                        let mut buf = [0u8; 4096];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let path = String::from_utf8_lossy(&buf[..n])
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("/")
                            .to_string();
                        let mut versions = vec!["1.0.0".to_string()];
                        let mut files = vec![serde_json::json!({
                            "filename": format!("{name}-1.0.0.tar.gz"),
                            "url": format!("http://example.invalid/{name}-1.0.0.tar.gz"),
                            "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                            "yanked": false,
                        })];
                        for entry in &yanked {
                            let (version, reason) = entry.split_once(' ').unwrap();
                            versions.push(version.to_string());
                            files.push(serde_json::json!({
                                "filename": format!("{name}-{version}.tar.gz"),
                                "url": format!("http://example.invalid/{name}-{version}.tar.gz"),
                                "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                                "yanked": reason,
                            }));
                        }
                        let body = if path == format!("/simple/{name}/") {
                            serde_json::json!({
                                "name": name,
                                "versions": versions,
                                "files": files,
                            })
                            .to_string()
                        } else {
                            "not found".to_string()
                        };
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.pypi.simple.v1+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(body.as_bytes());
                    });
                }
            });
            Self {
                base,
                _handle: handle,
            }
        }
    }
}
