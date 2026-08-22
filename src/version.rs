use crate::error::BluelineError;

/// Seam over version ordering so ecosystems with different version grammars
/// (semver today, PEP 440 later) plug into baseline selection and the store
/// without the engine knowing their details.
pub trait VersionInfo: Clone + PartialEq + Eq + Ord + std::fmt::Debug + Sized {
    /// Strict parse. Fail closed on anything the grammar does not accept.
    fn parse(raw: &str) -> Result<Self, BluelineError>;

    /// Canonical string form used when re-resolving against a registry.
    fn canonical(&self) -> String;

    /// True when this version is a pre-release.
    fn is_prerelease(&self) -> bool;

    /// Whether `self` may serve as the reviewed baseline for `target`:
    /// strictly older, and stable unless the target itself is a pre-release.
    fn baseline_eligible_for(&self, target: &Self) -> bool {
        self < target && (target.is_prerelease() || !self.is_prerelease())
    }
}

impl VersionInfo for semver::Version {
    fn parse(raw: &str) -> Result<Self, BluelineError> {
        semver::Version::parse(raw)
            .map_err(|e| BluelineError::InvalidPackageSpec(format!("`{raw}`: invalid semver: {e}")))
    }

    fn canonical(&self) -> String {
        self.to_string()
    }

    fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> semver::Version {
        <semver::Version as VersionInfo>::parse(s).unwrap()
    }

    #[test]
    fn parse_fails_closed_on_non_semver() {
        assert!(<semver::Version as VersionInfo>::parse("not-a-version").is_err());
        assert!(<semver::Version as VersionInfo>::parse("1.0").is_err());
        assert!(<semver::Version as VersionInfo>::parse("1.0.0").is_ok());
    }

    #[test]
    fn canonical_round_trips_semver() {
        let parsed = <semver::Version as VersionInfo>::parse("1.2.3-alpha.1+build").unwrap();
        assert_eq!(parsed.canonical(), "1.2.3-alpha.1+build");
    }

    #[test]
    fn prerelease_detection() {
        assert!(!v("1.0.0").is_prerelease());
        assert!(v("1.0.0-rc.1").is_prerelease());
    }

    #[test]
    fn baseline_eligibility_matches_baseline_rules() {
        // Stable target: only stable predecessors are eligible.
        assert!(v("1.9.0").baseline_eligible_for(&v("2.0.0")));
        assert!(!v("2.0.0").baseline_eligible_for(&v("2.0.0")));
        assert!(!v("2.1.0").baseline_eligible_for(&v("2.0.0")));
        assert!(
            !v("1.9.0-rc.1").baseline_eligible_for(&v("2.0.0")),
            "predecessor pre-releases are not eligible for a stable target"
        );

        // Pre-release target: any older version is eligible.
        assert!(v("1.9.0-rc.1").baseline_eligible_for(&v("2.0.0-beta.1")));
        assert!(v("1.9.0").baseline_eligible_for(&v("2.0.0-beta.1")));
    }
}
