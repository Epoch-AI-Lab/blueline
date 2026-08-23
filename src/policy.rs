use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::BluelineError;
use crate::registry::Ecosystem;
use crate::verdict::VerdictBand;

/// Maximum size allowed for a policy configuration file (64 KB).
pub const MAX_POLICY_FILE_SIZE: u64 = 64 * 1024;

/// Complete policy configuration loaded from `blueline.toml` or defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub thresholds: ThresholdsConfig,
    pub policy: GeneralPolicyConfig,
    pub advisories: AdvisoriesPolicyConfig,
    pub provenance: ProvenancePolicyConfig,
    pub allowlist: AllowlistConfig,
    pub blocklist: BlocklistConfig,
    pub ci: CiPolicyConfig,
}

impl Policy {
    /// Load policy from a specific file path or search standard candidate locations.
    /// Fails closed if an existing file cannot be read or contains invalid syntax.
    pub fn load_or_default(custom_path: Option<&Path>) -> Result<Self, BluelineError> {
        if let Some(path) = custom_path {
            return Self::from_file(path);
        }

        // Search candidate paths in priority order:
        // 1. Current working directory: `./blueline.toml`
        // 2. Hidden current working directory: `./.blueline.toml`
        // 3. User config directory: `~/.config/blueline/config.toml` (or OS equivalent)
        let candidates = [
            PathBuf::from("blueline.toml"),
            PathBuf::from(".blueline.toml"),
            dirs::config_dir()
                .map(|p| p.join("blueline").join("config.toml"))
                .unwrap_or_else(|| PathBuf::from("blueline-nonexistent.toml")),
        ];

        for candidate in candidates {
            if candidate.exists() {
                return Self::from_file(&candidate);
            }
        }

        Ok(Self::default())
    }

    /// Load and validate policy from a specific file path.
    pub fn from_file(path: &Path) -> Result<Self, BluelineError> {
        let metadata = std::fs::metadata(path).map_err(|e| {
            BluelineError::Policy(format!(
                "failed to stat policy file `{}`: {e}",
                path.display()
            ))
        })?;

        if metadata.len() > MAX_POLICY_FILE_SIZE {
            return Err(BluelineError::Policy(format!(
                "policy file `{}` exceeds max size limit of {} bytes (got {} bytes)",
                path.display(),
                MAX_POLICY_FILE_SIZE,
                metadata.len()
            )));
        }

        let mut file = File::open(path).map_err(|e| {
            BluelineError::Policy(format!(
                "failed to open policy file `{}`: {e}",
                path.display()
            ))
        })?;

        let mut content = String::new();
        file.read_to_string(&mut content).map_err(|e| {
            BluelineError::Policy(format!(
                "failed to read policy file `{}`: {e}",
                path.display()
            ))
        })?;

        Self::from_toml_str(&content)
    }

    /// Parse and validate policy from a TOML string.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, BluelineError> {
        let policy: Policy = toml::from_str(toml_str)
            .map_err(|e| BluelineError::Policy(format!("invalid policy TOML: {e}")))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Validate internal policy consistency and invariants.
    pub fn validate(&self) -> Result<(), BluelineError> {
        if self.thresholds.max_low_score > self.thresholds.max_medium_score {
            return Err(BluelineError::Policy(format!(
                "invalid thresholds: max_low_score ({}) cannot exceed max_medium_score ({})",
                self.thresholds.max_low_score, self.thresholds.max_medium_score
            )));
        }

        if self.thresholds.max_medium_score >= self.thresholds.block_score {
            return Err(BluelineError::Policy(format!(
                "invalid thresholds: max_medium_score ({}) must be strictly less than block_score ({})",
                self.thresholds.max_medium_score, self.thresholds.block_score
            )));
        }

        if self.thresholds.block_score > 100 {
            return Err(BluelineError::Policy(format!(
                "invalid thresholds: block_score ({}) cannot exceed 100",
                self.thresholds.block_score
            )));
        }

        Ok(())
    }

    /// Determine the verdict band given an accumulated score and hard block flag.
    #[allow(dead_code)]
    pub fn calculate_band(&self, score: u32, has_block_latch: bool) -> VerdictBand {
        if has_block_latch || score >= self.thresholds.block_score {
            VerdictBand::Block
        } else if score > self.thresholds.max_medium_score {
            VerdictBand::High
        } else if score > self.thresholds.max_low_score {
            VerdictBand::Medium
        } else {
            VerdictBand::Low
        }
    }

    /// Check if a package name matches any blocked package pattern for the
    /// given ecosystem. Rules without an `ecosystem` field match all.
    pub fn is_package_blocked(&self, name: &str, ecosystem: Ecosystem) -> bool {
        self.blocklist.packages.iter().any(|rule| {
            rule.ecosystem.is_none_or(|rule_eco| rule_eco == ecosystem)
                && glob_match(&rule.pattern, name)
        })
    }

    /// Check if a maintainer email is on the blocklist.
    #[allow(dead_code)]
    pub fn is_maintainer_blocked(&self, email: &str) -> bool {
        let email_trimmed = email.trim().to_lowercase();
        self.blocklist
            .maintainers
            .iter()
            .any(|b| b.trim().to_lowercase() == email_trimmed)
    }

    /// Check if a lifecycle script is explicitly permitted for a package in
    /// the given ecosystem. Rules without an `ecosystem` field match all.
    pub fn is_script_allowed(
        &self,
        package_name: &str,
        script_name: &str,
        ecosystem: Ecosystem,
    ) -> bool {
        self.allowlist.packages.iter().any(|rule| {
            rule.name == package_name
                && rule.ecosystem.is_none_or(|rule_eco| rule_eco == ecosystem)
                && rule.allowed_scripts.iter().any(|s| s == script_name)
        })
    }

    /// Check if a package is explicitly declared trusted to onboard without an
    /// approved baseline. Exact name match (no globs), matching
    /// `is_script_allowed`; a pattern like `@scope/*` grants nothing. Rules
    /// without an `ecosystem` field match all.
    pub fn allows_unreviewed_baseline(&self, package_name: &str, ecosystem: Ecosystem) -> bool {
        self.allowlist.packages.iter().any(|r| {
            r.allow_unreviewed_baseline
                && r.name == package_name
                && r.ecosystem.is_none_or(|rule_eco| rule_eco == ecosystem)
        })
    }
}

/// Threshold configurations for mapping numeric risk scores to verdict bands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ThresholdsConfig {
    /// Maximum score for VerdictBand::Low (default 19).
    pub max_low_score: u32,
    /// Maximum score for VerdictBand::Medium (default 49).
    pub max_medium_score: u32,
    /// Score threshold that triggers automatic VerdictBand::Block (default 80).
    pub block_score: u32,
}

impl Default for ThresholdsConfig {
    fn default() -> Self {
        Self {
            max_low_score: 19,
            max_medium_score: 49,
            block_score: 80,
        }
    }
}

/// General security policy flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralPolicyConfig {
    /// Require valid Sigstore/SLSA build attestations (default false).
    pub require_provenance: bool,
    /// Block on newly added lifecycle scripts when no baseline approval exists (default true).
    pub block_unreviewed_scripts: bool,
    /// Allow non-registry git/http dependencies without blocking (default false).
    pub allow_git_dependencies: bool,
    /// Query and check OSV vulnerability advisories (default true).
    pub check_advisories: bool,
    /// Fail closed if advisory or registry network calls fail (default false).
    pub fail_closed_network: bool,
}

impl Default for GeneralPolicyConfig {
    fn default() -> Self {
        Self {
            require_provenance: false,
            block_unreviewed_scripts: true,
            allow_git_dependencies: false,
            check_advisories: true,
            fail_closed_network: false,
        }
    }
}

/// Advisory policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdvisoriesPolicyConfig {
    pub block_on_malware: bool,
    pub block_on_critical_cve: bool,
    pub cache_ttl_hours_clean: u64,
    pub cache_ttl_hours_vulnerable: u64,
}

impl Default for AdvisoriesPolicyConfig {
    fn default() -> Self {
        Self {
            block_on_malware: true,
            block_on_critical_cve: true,
            cache_ttl_hours_clean: 12,
            cache_ttl_hours_vulnerable: 1,
        }
    }
}

impl AdvisoriesPolicyConfig {
    pub fn clean_cache_ttl_secs(&self) -> i64 {
        (self.cache_ttl_hours_clean.saturating_mul(3600)) as i64
    }

    pub fn vulnerable_cache_ttl_secs(&self) -> i64 {
        (self.cache_ttl_hours_vulnerable.saturating_mul(3600)) as i64
    }
}

/// Provenance and attestation policy configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProvenancePolicyConfig {
    pub require_provenance: bool,
    pub require_signatures: bool,
    pub allowed_builders: Vec<String>,
    pub allowed_repositories: Vec<String>,
}

/// CI policy configuration for pull requests and lockfile scanning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CiPolicyConfig {
    /// Minimum verdict band that triggers a non-zero exit code (default: "high").
    pub fail_on: String,
    /// Maximum number of packages to evaluate before failing closed (default: 100).
    pub max_evaluations: usize,
    /// Whether to evaluate devDependencies (default: true).
    pub include_dev: bool,
}

impl Default for CiPolicyConfig {
    fn default() -> Self {
        Self {
            fail_on: "high".to_string(),
            max_evaluations: 100,
            include_dev: true,
        }
    }
}

/// Allowlist configuration for verified packages and lifecycle scripts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowlistConfig {
    pub packages: Vec<PackageAllowRule>,
}

/// Specific package allowlist rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageAllowRule {
    pub name: String,
    /// Restrict the rule to one ecosystem; absent means it applies to all.
    #[serde(default)]
    pub ecosystem: Option<Ecosystem>,
    #[serde(default)]
    pub allowed_scripts: Vec<String>,
    #[serde(default)]
    pub max_risk: Option<VerdictBand>,
    #[serde(default)]
    pub integrity: Option<String>,
    /// Trust this package enough to onboard it without an approved baseline.
    /// First-sighting and unreviewed-predecessor findings stay visible but no
    /// longer contribute risk. Content heuristics still apply in full.
    #[serde(default)]
    pub allow_unreviewed_baseline: bool,
}

/// Specific package blocklist rule. TOML accepts either a plain glob string
/// (`"evil-*"`, matching every ecosystem) or a table
/// (`{ pattern = "evil-*", ecosystem = "npm" }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageBlockRule {
    #[serde(alias = "name")]
    pub pattern: String,
    /// Restrict the block to one ecosystem; absent means all ecosystems.
    #[serde(default)]
    pub ecosystem: Option<Ecosystem>,
}

/// A blocklist entry as written in TOML: plain string or detailed table.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawBlockPackage {
    Glob(String),
    Detailed(PackageBlockRule),
}

impl From<RawBlockPackage> for PackageBlockRule {
    fn from(raw: RawBlockPackage) -> Self {
        match raw {
            RawBlockPackage::Glob(pattern) => Self {
                pattern,
                ecosystem: None,
            },
            RawBlockPackage::Detailed(rule) => rule,
        }
    }
}

/// Blocklist configuration for banned packages and maintainers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlocklistConfig {
    #[serde(deserialize_with = "deserialize_block_packages")]
    pub packages: Vec<PackageBlockRule>,
    pub maintainers: Vec<String>,
}

fn deserialize_block_packages<'de, D>(deserializer: D) -> Result<Vec<PackageBlockRule>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Vec<RawBlockPackage> = Deserialize::deserialize(deserializer)?;
    Ok(raw.into_iter().map(PackageBlockRule::from).collect())
}

/// Minimal, memory-safe wildcard pattern matching (`*` support).
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        if let Some(suffix) = prefix.strip_prefix('*') {
            return text.contains(suffix);
        }
        return text.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return text.ends_with(suffix);
    }
    pattern == text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_has_sane_values() {
        let p = Policy::default();
        assert_eq!(p.thresholds.max_low_score, 19);
        assert_eq!(p.thresholds.max_medium_score, 49);
        assert_eq!(p.thresholds.block_score, 80);
        assert!(!p.policy.require_provenance);
        assert!(p.policy.block_unreviewed_scripts);
        assert!(!p.policy.allow_git_dependencies);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn parses_valid_toml_policy() {
        let toml_content = r#"
[thresholds]
max_low_score = 15
max_medium_score = 40
block_score = 75

[policy]
require_provenance = true
block_unreviewed_scripts = true
allow_git_dependencies = false

[[allowlist.packages]]
name = "esbuild"
allowed_scripts = ["postinstall"]
max_risk = "MEDIUM"

[blocklist]
packages = ["evil-*", "@badscope/*"]
maintainers = ["badactor@example.com"]
"#;

        let policy = Policy::from_toml_str(toml_content).unwrap();
        assert_eq!(policy.thresholds.max_low_score, 15);
        assert_eq!(policy.thresholds.max_medium_score, 40);
        assert_eq!(policy.thresholds.block_score, 75);
        assert!(policy.policy.require_provenance);

        assert!(policy.is_script_allowed("esbuild", "postinstall", Ecosystem::Npm));
        assert!(!policy.is_script_allowed("esbuild", "preinstall", Ecosystem::Npm));
        assert!(!policy.is_script_allowed("sharp", "postinstall", Ecosystem::Npm));

        assert!(policy.is_package_blocked("evil-pkg", Ecosystem::Npm));
        assert!(
            policy.is_package_blocked("evil-pkg", Ecosystem::Cargo),
            "rules without an ecosystem match every ecosystem"
        );
        assert!(policy.is_package_blocked("@badscope/lib", Ecosystem::Npm));
        assert!(!policy.is_package_blocked("good-pkg", Ecosystem::Npm));

        assert!(policy.is_maintainer_blocked("badactor@example.com"));
        assert!(!policy.is_maintainer_blocked("gooddev@example.com"));
    }

    #[test]
    fn rejects_invalid_thresholds() {
        let invalid_low_high = r#"
[thresholds]
max_low_score = 50
max_medium_score = 40
"#;
        assert!(Policy::from_toml_str(invalid_low_high).is_err());

        let invalid_med_block = r#"
[thresholds]
max_low_score = 20
max_medium_score = 80
block_score = 80
"#;
        assert!(Policy::from_toml_str(invalid_med_block).is_err());

        let invalid_block_over_100 = r#"
[thresholds]
block_score = 101
"#;
        assert!(Policy::from_toml_str(invalid_block_over_100).is_err());
    }

    #[test]
    fn calculates_bands_correctly() {
        let p = Policy::default();
        assert_eq!(p.calculate_band(0, false), VerdictBand::Low);
        assert_eq!(p.calculate_band(19, false), VerdictBand::Low);
        assert_eq!(p.calculate_band(20, false), VerdictBand::Medium);
        assert_eq!(p.calculate_band(49, false), VerdictBand::Medium);
        assert_eq!(p.calculate_band(50, false), VerdictBand::High);
        assert_eq!(p.calculate_band(79, false), VerdictBand::High);
        assert_eq!(p.calculate_band(80, false), VerdictBand::Block);
        assert_eq!(p.calculate_band(100, false), VerdictBand::Block);
        assert_eq!(p.calculate_band(5, true), VerdictBand::Block);
    }

    #[test]
    fn glob_matching_patterns() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("evil-*", "evil-pkg"));
        assert!(glob_match("evil-*", "evil-"));
        assert!(!glob_match("evil-*", "good-evil-pkg"));
        assert!(glob_match("*-bad", "pkg-bad"));
        assert!(!glob_match("*-bad", "pkg-bad-not"));
        assert!(glob_match("*middle*", "some-middle-name"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exact-not"));
    }

    #[test]
    fn parses_allow_unreviewed_baseline_rule() {
        let toml_content = r#"
[[allowlist.packages]]
name = "internal-tool"
allow_unreviewed_baseline = true

[[allowlist.packages]]
name = "other-pkg"
"#;
        let policy = Policy::from_toml_str(toml_content).unwrap();
        assert!(policy.allows_unreviewed_baseline("internal-tool", Ecosystem::Npm));
        assert!(!policy.allows_unreviewed_baseline("other-pkg", Ecosystem::Npm));
        assert!(!policy.allows_unreviewed_baseline("internal-tool-jr", Ecosystem::Npm));
        assert!(!Policy::default().allows_unreviewed_baseline("internal-tool", Ecosystem::Npm));
    }

    #[test]
    fn parses_ecosystem_scoped_rules_and_back_compat_strings() {
        let toml_content = r#"
[[allowlist.packages]]
name = "internal-crate"
ecosystem = "cargo"
allow_unreviewed_baseline = true

[blocklist]
packages = ["evil-*", { pattern = "@badscope/*", ecosystem = "npm" }]
maintainers = []
"#;
        let policy = Policy::from_toml_str(toml_content).unwrap();

        // Scoped allow rule applies only to its ecosystem.
        assert!(policy.allows_unreviewed_baseline("internal-crate", Ecosystem::Cargo));
        assert!(!policy.allows_unreviewed_baseline("internal-crate", Ecosystem::Npm));
        assert!(!policy.allows_unreviewed_baseline("internal-crate", Ecosystem::PyPi));

        // Plain-string blocklist entries still parse and match all ecosystems;
        // detailed entries are scoped.
        assert!(policy.is_package_blocked("evil-thing", Ecosystem::PyPi));
        assert!(policy.is_package_blocked("@badscope/lib", Ecosystem::Npm));
        assert!(!policy.is_package_blocked("@badscope/lib", Ecosystem::Cargo));

        // Unknown ecosystem values fail closed at parse time.
        let bad = r#"
[[allowlist.packages]]
name = "x"
ecosystem = "rubygems"
"#;
        assert!(Policy::from_toml_str(bad).is_err());
    }
}
