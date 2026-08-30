use crate::error::BluelineError;
use crate::registry::{Checksum, Package, Registry, Release};
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

    #[allow(dead_code)]
    pub fn display_summary(&self) -> String {
        match self {
            BaselineResolution::LocalApproved(p) => format!("{} (approved locally)", p.version),
            BaselineResolution::RegistryPredecessor(p) => {
                format!("{} (registry predecessor; unreviewed)", p.version)
            }
            BaselineResolution::FirstSighting => {
                "none (first sighting / initial release)".to_string()
            }
        }
    }
}

pub fn resolve_baseline<R: Registry, V: VersionInfo>(
    name: &str,
    target_ver: &V,
    registry: &R,
    store: &BaselineStore,
) -> Result<BaselineSelection, BluelineError> {
    let mut eligible: Vec<(V, Release)> = registry
        .list_releases(name)?
        .into_iter()
        .filter_map(|r| V::parse(&r.version).ok().map(|v| (v, r)))
        .filter(|(v, _)| v.baseline_eligible_for(target_ver))
        .collect();
    eligible.sort_by(|a, b| a.0.cmp(&b.0));
    let prior_release_yanked = eligible.last().is_some_and(|(_, r)| r.yanked);

    let clean_versions = store.list_clean_versions::<V>(registry.ecosystem(), name)?;

    for (clean_ver, stored_integrity) in clean_versions {
        if clean_ver.baseline_eligible_for(target_ver) {
            // Compare normalized checksums so legacy SRI rows and new display
            // forms are judged by content, not by spelling.
            let stored_checksum = Checksum::parse(&stored_integrity);
            match registry.resolve(name, &clean_ver.canonical()) {
                Ok(pkg) => match (&pkg.integrity, &stored_checksum) {
                    (Some(reg_integ), Ok(stored)) if *reg_integ == *stored => {
                        return Ok(BaselineSelection {
                            resolution: BaselineResolution::LocalApproved(pkg),
                            prior_release_yanked,
                        });
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
                    // `list_releases(name)?` above and fails closed there — it
                    // must never reach this loop, so do NOT reinterpret Manifest
                    // as a benign "skip the candidate" for a missing package.
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
        return Ok(BaselineSelection {
            resolution: BaselineResolution::RegistryPredecessor(pkg),
            prior_release_yanked,
        });
    }

    Ok(BaselineSelection {
        resolution: BaselineResolution::FirstSighting,
        prior_release_yanked,
    })
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
}
