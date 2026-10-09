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
    pub recursion: RecursionPolicyConfig,
    pub recall: RecallPolicyConfig,
}

impl Policy {
    /// Load policy from a specific file path or search standard candidate locations.
    /// Fails closed if an existing file cannot be read or contains invalid syntax.
    /// The `BLUELINE_POLICY` environment variable scopes shells and hooks
    /// launched outside a project directory (shims and agent hooks set and
    /// honor it); a set-but-unreadable path fails closed.
    pub fn load_or_default(custom_path: Option<&Path>) -> Result<Self, BluelineError> {
        Self::load_with_env(custom_path, || std::env::var("BLUELINE_POLICY").ok())
    }

    /// Agent entry points (`agent gate`, `agent review`) load policy through
    /// this constructor: `BLUELINE_POLICY` from the environment is ignored
    /// unless an explicit `--policy` flag names the file. A hook fires with
    /// the repository as its working directory and inherits ambient env, so
    /// honoring the variable would let any process that exports it steer
    /// the gate. Shims pass `--policy` explicitly, so scoped shells keep
    /// working; callers warn on stderr when ambient env is ignored.
    pub fn load_for_agent(custom_path: Option<&Path>) -> Result<Self, BluelineError> {
        Self::load_with_env(custom_path, || None)
    }

    /// True when `BLUELINE_POLICY` is set in the process environment, used
    /// by agent entry points to warn that the ambient value is ignored.
    pub fn env_policy_present() -> bool {
        std::env::var("BLUELINE_POLICY").is_ok()
    }

    fn load_with_env(
        custom_path: Option<&Path>,
        env: impl Fn() -> Option<String>,
    ) -> Result<Self, BluelineError> {
        if let Some(path) = custom_path {
            return Self::from_file(path);
        }
        if let Some(path) = env() {
            return Self::from_file(Path::new(&path));
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
        // A typo here used to fall back to HIGH, so `fail_on = "blockk"`
        // quietly weakened a gate instead of refusing the policy. The CLI flag
        // already refused the same typo; the policy key did not.
        if crate::verdict::VerdictBand::parse(&self.ci.fail_on).is_none() {
            return Err(BluelineError::Policy(format!(
                "invalid ci policy: fail_on ({}) is not one of low, medium, high, block",
                self.ci.fail_on
            )));
        }
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

        if self.recursion.max_depth > 16 {
            return Err(BluelineError::Policy(format!(
                "invalid recursion policy: max_depth ({}) exceeds the cap of 16",
                self.recursion.max_depth
            )));
        }

        if self.recall.max_age_hours == 0 || self.recall.max_age_hours > 24 * 365 {
            return Err(BluelineError::Policy(format!(
                "invalid recall policy: max_age_hours ({}) out of range",
                self.recall.max_age_hours
            )));
        }

        if self.recursion.max_child_reviews > 256 {
            return Err(BluelineError::Policy(format!(
                "invalid recursion policy: max_child_reviews ({}) exceeds the cap of 256",
                self.recursion.max_child_reviews
            )));
        }

        self.reject_unimplemented_keys()?;

        Ok(())
    }

    /// Refuse policy keys that parse but govern nothing.
    ///
    /// These are `serde` fields, so before this check they were accepted and
    /// ignored: a user who blocklisted a maintainer or pinned a package's
    /// integrity got a config that read as active protection and was not. In a
    /// tool that fails closed, a silently-ignored security control is worse
    /// than a rejected one, because the operator has no way to notice. Erroring
    /// here is the only point where the key is still visible; once the field is
    /// gone, serde would drop it without a word.
    fn reject_unimplemented_keys(&self) -> Result<(), BluelineError> {
        // `require_signatures` gates on `registry_signature_present`, which is
        // built from whether `dist.signatures` is a non-empty array. Nothing
        // compares the tarball against the signature, and `dist.shasum` is not
        // even parsed, so the key is satisfied by a registry publishing *any*
        // block. Verified registry signatures need a Sigstore verification path
        // this project has not approved as a dependency, so rather than leave a
        // key that reads as verification and is not, refuse it at load.
        if self.provenance.require_signatures {
            return Err(BluelineError::Policy(
                "provenance.require_signatures is not implemented and would otherwise be \
                 silently satisfied by the *presence* of a registry signature block rather \
                 than by verifying it. blueline does not check the tarball against that \
                 signature and does not parse dist.shasum, so a forged block satisfies this \
                 key. Remove it; dist.integrity (sha512) is the check that actually runs \
                 before extraction."
                    .into(),
            ));
        }

        // `blocklist.maintainers` is deliberately absent from this check. It
        // used to be refused here because nothing read it, which was true
        // before `P04_MAINTAINER_BLOCKED` existed and is false now: AUR
        // resolves a per-release commit author and the rule consumes it. Where
        // a registry supplies no identity the rule cannot be applied, and that
        // is reported per review as `P04_MAINTAINER_UNEVALUABLE` rather than
        // turned into a load-time error, because the policy is loaded without
        // ecosystem context and the answer differs per lane.
        for (i, rule) in self.allowlist.packages.iter().enumerate() {
            if rule.max_risk.is_some() {
                return Err(BluelineError::Policy(format!(
                    "allowlist.packages[{i}].max_risk (rule `{}`) is not implemented and would \
                     otherwise be silently ignored. Risk bands come from the heuristic engine and \
                     cannot be pinned per package. Remove the key.",
                    rule.name
                )));
            }
            if rule.integrity.is_some() {
                return Err(BluelineError::Policy(format!(
                    "allowlist.packages[{i}].integrity (rule `{}`) is not implemented and would \
                     otherwise be silently ignored. Integrity is verified per release against the \
                     registry's own dist.integrity and cannot be pinned per package. Remove the key.",
                    rule.name
                )));
            }
        }

        Ok(())
    }

    /// Escalate the band a set of findings already earned when the accumulated
    /// score crosses a policy threshold.
    ///
    /// Never downgrades. A band earned by a specific finding outranks the band
    /// the score alone would imply, so a BLOCK finding stays BLOCK even when its
    /// score lands in the HIGH range. This is the only score-to-band rule in the
    /// engine; `heuristic::evaluate_with_trust` and
    /// `heuristic::apply_extra_findings` both route through it.
    pub fn escalate_band(&self, score: u32, current: VerdictBand) -> VerdictBand {
        let from_score = if score >= self.thresholds.block_score {
            VerdictBand::Block
        } else if score > self.thresholds.max_medium_score {
            VerdictBand::High
        } else if score > self.thresholds.max_low_score {
            VerdictBand::Medium
        } else {
            VerdictBand::Low
        };
        current.max(from_score)
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
    ///
    /// Reported, not enforced as a blanket block. A release with no published
    /// provenance is disclosed and its verdict held; a release whose published
    /// provenance cannot be verified is refused. Nothing short of a signature
    /// check is presented as satisfying this key, so the report never overstates
    /// what was proven.
    pub require_provenance: bool,
    /// Block on newly added lifecycle scripts when no baseline approval exists (default true).
    pub block_unreviewed_scripts: bool,
    /// Refuse a review whose extraction could not be confined by the kernel,
    /// instead of disclosing it and continuing.
    ///
    /// Off by default, and that default is the honest one. Unavailability is
    /// the normal case on macOS, Windows and any kernel without Landlock, so
    /// refusing by default would make the tool unusable on four of six shipped
    /// platforms for a check the operator never asked for. Turning it on is how
    /// an operator says "refuse rather than tell me".
    pub require_sandbox: bool,
    /// Lower the band of non-registry (git/http/ssh/`npm:`/`file:`/`link:`)
    /// dependency findings from HIGH to MEDIUM. The findings stay visible; they
    /// are never suppressed (default false).
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
            require_sandbox: false,
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
    /// Same rule as `GeneralPolicyConfig::require_provenance`, and honoured
    /// identically: either key turns the requirement on. Named here as well so a
    /// policy can group it with the other provenance keys.
    pub require_provenance: bool,
    /// Require a *verified* npm registry signature on every release.
    ///
    /// Refused at load. The npm lane reads `dist.signatures` for presence and
    /// never checks the bytes against it, so this key used to read as a
    /// verification requirement while a forged signature block satisfied it —
    /// the operator's protection was the registry's willingness to publish a
    /// block. A key that cannot fail closed must be refused rather than
    /// honoured, because `require_signatures = true` in a file is a claim that
    /// signatures are checked and nothing in this codebase can check them.
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
    /// Permit requirements.txt options that redirect pip away from the
    /// reviewed graph (`--index-url`, `-r`, `-c`, ...). Off by default,
    /// because blueline models only pinned `name==version` lines and cannot
    /// follow an alternative index, an extra requirements file, or a
    /// constraints file. On, they are disclosed rather than refused.
    pub allow_requirements_options: bool,
}

impl Default for CiPolicyConfig {
    fn default() -> Self {
        Self {
            fail_on: "high".to_string(),
            max_evaluations: 100,
            include_dev: true,
            allow_requirements_options: false,
        }
    }
}

/// Recursive-review policy: caps on second-order review fan-out and the
/// band at which a referenced package's finding escalates the parent
/// verdict. Ambiguity resolves to block (fail closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RecursionPolicyConfig {
    /// Maximum review depth for referenced installs (root review is depth
    /// 0; default 3). Exceeding the cap emits R25_RECURSION_DEPTH (HIGH).
    pub max_depth: u32,
    /// Maximum child reviews per top-level evaluation (default 8); bounds
    /// fan-out cost for CI. Exceeding the budget emits R25_RECURSION_DEPTH.
    pub max_child_reviews: u32,
    /// Band at or above which a referenced package's finding escalates the
    /// parent verdict via R27_SECOND_ORDER (default HIGH; TOML values are
    /// the uppercase band names, e.g. `child_block_band = "HIGH"`).
    pub child_block_band: VerdictBand,
}

impl Default for RecursionPolicyConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_child_reviews: 8,
            child_block_band: VerdictBand::High,
        }
    }
}

/// Recall-index policy: how far past its fetch time the synced revocation
/// snapshot may drift before it is disclosed (R28), and whether that
/// staleness escalates to BLOCK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RecallPolicyConfig {
    pub max_age_hours: u64,
    pub block_on_stale: bool,
}

impl Default for RecallPolicyConfig {
    fn default() -> Self {
        Self {
            max_age_hours: 48,
            block_on_stale: false,
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

[blocklist]
packages = ["evil-*", "@badscope/*"]
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
    }

    #[test]
    fn accepts_an_empty_maintainers_blocklist() {
        // Present but empty is not a claim about anything, so it still parses.
        // Only a populated list is a security claim the tool cannot honor.
        let policy = Policy::from_toml_str(
            r#"
[blocklist]
maintainers = []
"#,
        )
        .unwrap();
        assert!(policy.blocklist.maintainers.is_empty());
    }

    /// A populated maintainer blocklist loads rather than being refused.
    ///
    /// This test used to assert the opposite, and the reason it changed is the
    /// whole point: the key was refused because nothing read it, which was true
    /// while `is_maintainer_blocked` had no caller and false once
    /// `P04_MAINTAINER_BLOCKED` started calling it. AUR resolves a per-release
    /// commit author and that identity reaches the rule, so refusing the key
    /// would forbid a protection that works.
    ///
    /// The lane where it cannot work is not expressible here, because a policy
    /// is loaded without ecosystem context. That case is reported per review as
    /// `P04_MAINTAINER_UNEVALUABLE` in `heuristic.rs`.
    #[test]
    fn accepts_a_populated_maintainers_blocklist() {
        let policy = Policy::from_toml_str(
            r#"
[blocklist]
maintainers = ["badactor@example.com"]
"#,
        )
        .expect(
            "the key is enforced by P04 wherever the registry supplies an identity, so \
             refusing it at load would forbid a protection that works",
        );

        assert_eq!(
            policy.blocklist.maintainers,
            vec!["badactor@example.com".to_string()],
            "the list must survive the load intact or the rule has nothing to match"
        );
        assert!(
            policy.is_maintainer_blocked("badactor@example.com"),
            "a loaded entry must actually be matchable, or the key is decorative again"
        );
    }

    /// The whole point of the key is that it cannot be satisfied by a forged
    /// block, and it cannot, so it is refused.
    #[test]
    fn rejects_require_signatures() {
        let err = Policy::from_toml_str(
            r#"
[provenance]
require_signatures = true
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("require_signatures"), "got: {err}");
        assert!(
            err.contains("presence"),
            "the error must name what the key actually checked, got: {err}"
        );
        assert!(
            err.contains("dist.integrity"),
            "the error must name the check that does run, got: {err}"
        );
    }

    /// `require_sandbox` sits in `GeneralPolicyConfig`, but the TOML table is
    /// named after the *field* (`policy`), not the struct. `Policy` has no
    /// `deny_unknown_fields`, so `[general]` loads cleanly and leaves the flag at
    /// its default. An operator who wrote it expecting fail-closed refusals got
    /// an unconfined extraction and a LOW disclosure instead.
    #[test]
    fn require_sandbox_lives_under_the_policy_table() {
        let right = Policy::from_toml_str("[policy]\nrequire_sandbox = true\n").expect("loads");
        assert!(
            right.policy.require_sandbox,
            "`[policy] require_sandbox = true` must set the flag"
        );

        let wrong = Policy::from_toml_str("[general]\nrequire_sandbox = true\n").expect("loads");
        assert!(
            !wrong.policy.require_sandbox,
            "`[general]` must not be what an operator writes; if this ever passes, the \
             documented table name is wrong again"
        );
    }

    /// `require_provenance` sits in the same table and is honoured per status,
    /// so refusing the sibling key must not refuse this one.
    #[test]
    fn accepts_require_provenance_alongside_a_refused_require_signatures() {
        Policy::from_toml_str(
            r#"
[provenance]
require_provenance = true
"#,
        )
        .expect("require_provenance is enforced per status and is not the key being refused");
    }

    /// The default leaves the key off, so an ordinary policy still loads.
    #[test]
    fn accepts_a_policy_that_never_mentions_signatures() {
        Policy::from_toml_str(
            r#"
[provenance]
allowed_repositories = ["https://github.com/vercel/next.js"]
"#,
        )
        .expect("the key is off by default, so this is an ordinary policy");
    }

    /// An empty `blueline.toml` on disk is the common case and must not trip
    /// the refusal, which is why the check reads the flag rather than the
    /// table's presence.
    #[test]
    fn accepts_the_repository_blueline_toml_it_ships_with() {
        let shipped = concat!(env!("CARGO_MANIFEST_DIR"), "/blueline.toml");
        Policy::from_file(std::path::Path::new(shipped))
            .unwrap_or_else(|e| panic!("the shipped policy must load: {e}"));
    }

    #[test]
    fn rejects_an_allowlist_max_risk_pin() {
        let err = Policy::from_toml_str(
            r#"
[[allowlist.packages]]
name = "esbuild"
max_risk = "MEDIUM"
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("max_risk"), "got: {err}");
        assert!(
            err.contains("esbuild"),
            "the error must name the rule, got: {err}"
        );
        assert!(
            err.contains("heuristic engine"),
            "the error must say why it cannot be pinned, got: {err}"
        );
    }

    #[test]
    fn rejects_an_allowlist_integrity_pin() {
        let err = Policy::from_toml_str(
            r#"
[[allowlist.packages]]
name = "esbuild"
integrity = "sha512-deadbeef"
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("integrity"), "got: {err}");
        assert!(
            err.contains("esbuild"),
            "the error must name the rule, got: {err}"
        );
        assert!(
            err.contains("dist.integrity"),
            "the error must name the integrity check that does exist, got: {err}"
        );
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
    fn escalates_bands_at_the_policy_threshold_boundaries() {
        let p = Policy::default();
        let from_low = |score| p.escalate_band(score, VerdictBand::Low);
        assert_eq!(from_low(0), VerdictBand::Low);
        assert_eq!(from_low(19), VerdictBand::Low);
        assert_eq!(from_low(20), VerdictBand::Medium);
        assert_eq!(from_low(49), VerdictBand::Medium);
        assert_eq!(from_low(50), VerdictBand::High);
        assert_eq!(from_low(79), VerdictBand::High);
        assert_eq!(from_low(80), VerdictBand::Block);
        assert_eq!(from_low(100), VerdictBand::Block);
    }

    #[test]
    fn escalate_band_never_downgrades_a_band_a_finding_already_earned() {
        let p = Policy::default();
        // Score 50 alone means High, but a BLOCK finding outranks it.
        assert_eq!(p.escalate_band(50, VerdictBand::Block), VerdictBand::Block);
        // Score 0 must not walk a finding-earned band back down to Low.
        assert_eq!(p.escalate_band(0, VerdictBand::Block), VerdictBand::Block);
        assert_eq!(p.escalate_band(0, VerdictBand::High), VerdictBand::High);
        assert_eq!(p.escalate_band(0, VerdictBand::Medium), VerdictBand::Medium);
        // Score in the MEDIUM range must not demote an earned High.
        assert_eq!(p.escalate_band(20, VerdictBand::High), VerdictBand::High);
        // Escalation still applies on top of an earned band.
        assert_eq!(p.escalate_band(80, VerdictBand::Medium), VerdictBand::Block);
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
    fn rejects_an_unparseable_ci_fail_on() {
        for bad in ["blockk", "", "medium-high", "  "] {
            let toml = format!("[ci]\nfail_on = \"{bad}\"\n");
            assert!(
                Policy::from_toml_str(&toml).is_err(),
                "fail_on = {bad:?} must be refused rather than silently weakened"
            );
        }
    }

    #[test]
    fn accepts_ci_fail_on_case_and_whitespace_insensitively() {
        for good in ["low", "HIGH", "  Block  ", "Medium"] {
            let toml = format!("[ci]\nfail_on = \"{good}\"\n");
            assert!(
                Policy::from_toml_str(&toml).is_ok(),
                "fail_on = {good:?} must stay valid"
            );
        }
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

    #[test]
    fn recursion_policy_caps_fail_closed() {
        let ok = Policy::from_toml_str("[recursion]\nmax_depth = 16\n").unwrap();
        assert_eq!(ok.recursion.max_depth, 16);
        assert!(Policy::from_toml_str("[recursion]\nmax_depth = 17\n").is_err());
        let ok = Policy::from_toml_str("[recursion]\nmax_child_reviews = 256\n").unwrap();
        assert_eq!(ok.recursion.max_child_reviews, 256);
        assert!(Policy::from_toml_str("[recursion]\nmax_child_reviews = 257\n").is_err());
    }

    #[test]
    fn recursion_child_block_band_parses_from_toml() {
        let policy = Policy::from_toml_str("[recursion]\nchild_block_band = \"HIGH\"\n").unwrap();
        assert_eq!(policy.recursion.child_block_band, VerdictBand::High);
        let policy = Policy::from_toml_str("[recursion]\nchild_block_band = \"MEDIUM\"\n").unwrap();
        assert_eq!(policy.recursion.child_block_band, VerdictBand::Medium);
    }
    #[test]
    fn blueline_policy_env_scopes_policy_loading_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scoped.toml");
        std::fs::write(
            &path,
            "[[allowlist.packages]]\nname = \"ok\"\nallow_unreviewed_baseline = true\n",
        )
        .unwrap();
        let scoped = || Some(path.display().to_string());
        let policy = Policy::load_with_env(None, scoped).unwrap();
        assert!(policy.allows_unreviewed_baseline("ok", crate::registry::Ecosystem::Npm));

        let missing = || Some(dir.path().join("missing.toml").display().to_string());
        assert!(
            Policy::load_with_env(None, missing).is_err(),
            "a set-but-unreadable BLUELINE_POLICY must fail closed"
        );

        // An explicit --policy path wins over the environment.
        let other = dir.path().join("other.toml");
        std::fs::write(&other, "").unwrap();
        assert!(Policy::load_with_env(Some(&other), scoped).is_ok());
    }

    #[test]
    fn env_policy_present_reads_process_environment() {
        // `std::env::set_var` is `unsafe` (and forbidden) in edition 2024,
        // so each outcome runs in a child harness with a scrubbed/set env.
        fn run_probe(name: &str, set: bool) -> std::process::Output {
            let exe = std::env::current_exe().unwrap();
            let mut cmd = std::process::Command::new(exe);
            cmd.args(["--exact", "--ignored", name]);
            if set {
                cmd.env(
                    "BLUELINE_POLICY",
                    "/tmp/blueline-policy-presence-probe.toml",
                );
            } else {
                cmd.env_remove("BLUELINE_POLICY");
            }
            cmd.output().unwrap()
        }
        let out = run_probe("policy::tests::probe_env_policy_present_when_set", true);
        assert!(
            out.status.success(),
            "set BLUELINE_POLICY must read present: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let out = run_probe("policy::tests::probe_env_policy_present_when_unset", false);
        assert!(
            out.status.success(),
            "unset BLUELINE_POLICY must read absent: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    #[ignore]
    fn probe_env_policy_present_when_set() {
        assert!(Policy::env_policy_present());
    }

    #[test]
    #[ignore]
    fn probe_env_policy_present_when_unset() {
        assert!(!Policy::env_policy_present());
    }

    #[test]
    fn recall_max_age_hours_bounds() {
        let with_max_age = |hours: u64| Policy {
            recall: RecallPolicyConfig {
                max_age_hours: hours,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(with_max_age(0).validate().is_err());
        assert!(with_max_age(1).validate().is_ok());
        assert!(with_max_age(24 * 365).validate().is_ok());
        assert!(with_max_age(24 * 365 + 1).validate().is_err());
    }
}
