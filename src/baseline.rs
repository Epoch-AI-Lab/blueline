use crate::error::BluelineError;
use crate::registry::{Package, Registry};
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
) -> Result<BaselineResolution, BluelineError> {
    let clean_versions = store.list_clean_versions::<V>(name)?;

    for (clean_ver, stored_integrity) in clean_versions {
        if clean_ver.baseline_eligible_for(target_ver) {
            match registry.resolve(name, &clean_ver.canonical()) {
                Ok(pkg) => match &pkg.integrity {
                    Some(reg_integ) if reg_integ == &stored_integrity => {
                        return Ok(BaselineResolution::LocalApproved(pkg));
                    }
                    Some(reg_integ) => {
                        return Err(BluelineError::Verification(format!(
                            "stored clean baseline for {name}@{} had integrity `{stored_integrity}`, but registry reported `{reg_integ}`; refusing to trust tampered baseline",
                            clean_ver.canonical()
                        )));
                    }
                    None => {
                        return Err(BluelineError::Verification(format!(
                            "stored clean baseline for {name}@{} had integrity `{stored_integrity}`, but registry reported no integrity; refusing to trust unverified baseline",
                            clean_ver.canonical()
                        )));
                    }
                },
                Err(BluelineError::Manifest(_, _)) => {
                    // Version yanked/missing from registry; continue looking for older clean versions
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    let reg_versions = registry.list_versions(name)?;
    let target_semver = semver::Version::parse(&target_ver.canonical()).map_err(|e| {
        BluelineError::InvalidPackageSpec(format!(
            "version `{}` is not comparable for baseline selection: {e}",
            target_ver.canonical()
        ))
    })?;
    let predecessor = reg_versions
        .into_iter()
        .filter(|v| *v < target_semver && (target_semver.pre.is_empty() || v.pre.is_empty()))
        .max();

    if let Some(pred_ver) = predecessor {
        let pkg = registry.resolve(name, &pred_ver.to_string())?;
        return Ok(BaselineResolution::RegistryPredecessor(pkg));
    }

    Ok(BaselineResolution::FirstSighting)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRegistry {
        versions: Vec<String>,
        integrity_override: Option<Option<String>>,
    }

    impl MockRegistry {
        fn new(versions: Vec<String>) -> Self {
            Self {
                versions,
                integrity_override: None,
            }
        }
    }

    impl Registry for MockRegistry {
        fn resolve(&self, name: &str, version: &str) -> Result<Package, BluelineError> {
            if self.versions.contains(&version.to_string()) {
                let integrity = match &self.integrity_override {
                    Some(custom) => custom.clone(),
                    None => Some(format!("sha512-{version}")),
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

        fn resolve_dist_tag(
            &self,
            _name: &str,
            _tag: &str,
        ) -> Result<Option<String>, BluelineError> {
            Ok(self.versions.last().cloned())
        }
    }

    #[test]
    fn resolves_local_approved_baseline_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified("pkg", "1.0.0", "sha512-1.0.0")
            .unwrap();
        store
            .record_verified("pkg", "1.1.0", "sha512-1.1.0")
            .unwrap();
        store.mark_clean("pkg", "1.0.0", "sha512-1.0.0").unwrap();

        let registry = MockRegistry::new(vec!["1.0.0".into(), "1.1.0".into(), "1.2.0".into()]);

        let target = semver::Version::parse("1.2.0").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        assert!(matches!(res, BaselineResolution::LocalApproved(p) if p.version == "1.0.0"));
    }

    #[test]
    fn falls_back_to_registry_predecessor() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();

        let registry = MockRegistry::new(vec!["1.0.0".into(), "1.1.0".into(), "1.2.0".into()]);

        let target = semver::Version::parse("1.2.0").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        assert!(matches!(res, BaselineResolution::RegistryPredecessor(p) if p.version == "1.1.0"));
    }

    #[test]
    fn detects_first_sighting() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();

        let registry = MockRegistry::new(vec!["1.0.0".into()]);

        let target = semver::Version::parse("1.0.0").unwrap();
        let res = resolve_baseline("pkg", &target, &registry, &store).unwrap();
        assert_eq!(res, BaselineResolution::FirstSighting);
    }

    #[test]
    fn rejects_tampered_approved_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified("pkg", "1.0.0", "sha512-authentic")
            .unwrap();
        store
            .mark_clean("pkg", "1.0.0", "sha512-authentic")
            .unwrap();

        // Registry serves a tampered integrity for 1.0.0
        let registry = MockRegistry::new(vec!["1.0.0".into(), "1.1.0".into()]);

        let target = semver::Version::parse("1.1.0").unwrap();
        let err = resolve_baseline("pkg", &target, &registry, &store).unwrap_err();
        assert!(err.to_string().contains("tampered baseline"));
    }

    #[test]
    fn rejects_missing_integrity_on_stored_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified("pkg", "1.0.0", "sha512-authentic")
            .unwrap();
        store
            .mark_clean("pkg", "1.0.0", "sha512-authentic")
            .unwrap();

        let mut registry = MockRegistry::new(vec!["1.0.0".into(), "1.1.0".into()]);
        registry.integrity_override = Some(None);

        let target = semver::Version::parse("1.1.0").unwrap();
        let err = resolve_baseline("pkg", &target, &registry, &store).unwrap_err();
        assert!(err.to_string().contains("reported no integrity"));
    }
}
