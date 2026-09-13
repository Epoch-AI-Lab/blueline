//! Recursive review: a reviewed payload that references another install
//! (npm lifecycle script, PKGBUILD npm/bun delivery, wheel .data/scripts)
//! pipes that referenced package through the same review engine. Depth
//! caps, cycle detection, and the child-review budget all fail closed —
//! a cap is disclosed as a HIGH finding on the card, never a silent skip.

use crate::cli::RegistryBases;
use crate::install_ref::{InstallRef, RefManager, RefOrigin};
use crate::policy::Policy;
use crate::registry::{Ecosystem, Package, Registry};
use crate::store::BaselineStore;
use crate::verdict::{ChildReview, Finding, VerdictBand};
use crate::version::VersionInfo;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// Bound on tarball bytes memoized per review session (clone-on-overflow,
/// matching the AUR clone-cache discipline).
const MAX_TARBALL_MEMO_BYTES: usize = 256 * 1024 * 1024;

/// Identity of a reviewed release: the cycle-detection key and the memo key.
type ReviewKey = (Ecosystem, String, String);
type TarballMemo = HashMap<ReviewKey, Rc<[u8]>>;

pub struct ReviewContext {
    max_depth: u32,
    max_child_reviews: u32,
    child_block_band: VerdictBand,
    /// Current review path: cycle detection AND the delivery chain, with
    /// the root package first and the package being evaluated last.
    stack: Vec<ReviewKey>,
    chain: Vec<String>,
    child_reviews: u32,
    completed: HashMap<ReviewKey, ChildReview>,
    /// (ecosystem, canonical name) → the key of its completed review, so a
    /// repeated reference to the same package reuses the cached review even
    /// when the budget is spent (a reuse costs nothing; a fresh review
    /// would count against fan-out).
    completed_names: HashMap<(Ecosystem, String), ReviewKey>,
    registries: RefCell<HashMap<Ecosystem, Rc<dyn Registry>>>,
    tarballs: RefCell<TarballMemo>,
    memo_bytes: std::cell::Cell<usize>,
    pub bases: RegistryBases,
}

impl ReviewContext {
    pub fn new(policy: &Policy, bases: RegistryBases) -> Self {
        Self {
            max_depth: policy.recursion.max_depth,
            max_child_reviews: policy.recursion.max_child_reviews,
            child_block_band: policy.recursion.child_block_band,
            stack: Vec::new(),
            chain: Vec::new(),
            child_reviews: 0,
            completed: HashMap::new(),
            completed_names: HashMap::new(),
            registries: RefCell::new(HashMap::new()),
            tarballs: RefCell::new(HashMap::new()),
            memo_bytes: std::cell::Cell::new(0),
            bases,
        }
    }

    #[cfg(test)]
    pub fn inject_registry(&mut self, ecosystem: Ecosystem, registry: Rc<dyn Registry>) {
        self.registries.borrow_mut().insert(ecosystem, registry);
    }

    pub fn child_block_band(&self) -> VerdictBand {
        self.child_block_band
    }

    pub(crate) fn registry(&self, ecosystem: Ecosystem) -> Rc<dyn Registry> {
        let mut map = self.registries.borrow_mut();
        if let Some(existing) = map.get(&ecosystem) {
            return existing.clone();
        }
        let registry = registry_for(ecosystem, self.bases.for_ecosystem(ecosystem));
        map.insert(ecosystem, registry.clone());
        registry
    }

    /// Fetch a tarball through the session memo so a package referenced by
    /// several reviews (baseline, target, child) is downloaded once.
    pub fn fetch_tarball(
        &self,
        registry: &dyn Registry,
        pkg: &Package,
    ) -> Result<Rc<[u8]>, crate::error::BluelineError> {
        let key = (registry.ecosystem(), pkg.name.clone(), pkg.version.clone());
        if let Some(bytes) = self.tarballs.borrow().get(&key) {
            return Ok(bytes.clone());
        }
        let bytes: Rc<[u8]> = registry.fetch_tarball(pkg)?.into();
        if self.memo_bytes.get() + bytes.len() > MAX_TARBALL_MEMO_BYTES {
            self.tarballs.borrow_mut().clear();
            self.memo_bytes.set(0);
        }
        self.memo_bytes.set(self.memo_bytes.get() + bytes.len());
        self.tarballs.borrow_mut().insert(key, bytes.clone());
        Ok(bytes)
    }

    /// Enter the scope of a package evaluation: pushes the cycle-detection
    /// key and the delivery-chain label. The caller pops both after the
    /// evaluation (including its own children) completes.
    pub fn enter_scope(&mut self, ecosystem: Ecosystem, name: &str, version: &str, root: bool) {
        self.stack.push((
            ecosystem,
            crate::version::canonicalize_for_ecosystem(ecosystem, name),
            version.to_string(),
        ));
        let label = if root {
            format!("{name}@{version}")
        } else {
            format!("{}:{}@{}", ecosystem.key(), name, version)
        };
        self.chain.push(label);
    }

    pub fn exit_scope(&mut self) {
        self.stack.pop();
        self.chain.pop();
    }

    /// Review every resolvable install reference. Returns the completed
    /// child reviews plus findings for what could NOT be reviewed: cap
    /// overruns (R25), cycles (R26), and failed child reviews (R24).
    /// Resolvable-spec references already carry their own R24 finding for
    /// the delivery line itself.
    pub fn review_children(
        &mut self,
        refs: &[InstallRef],
        store: &BaselineStore,
        policy: &Policy,
    ) -> (Vec<ChildReview>, Vec<Finding>) {
        let mut children = Vec::new();
        let mut findings = Vec::new();
        // The depth cap is constant across this call's references; check it
        // once so a hostile payload cannot spend network round-trips on
        // resolution that can never be reviewed.
        let child_depth = self.stack.len() as u32;
        if child_depth > self.max_depth {
            for r in refs.iter().filter(|r| r.registry_spec().is_some()) {
                findings.push(depth_cap_finding(
                    &self.chain,
                    &self.dropped_key(r),
                    &depth_cause(child_depth, self.max_depth),
                ));
            }
            return (children, findings);
        }
        for r in refs {
            let Some((name, version_part)) = r.registry_spec() else {
                continue;
            };
            let child_eco = child_ecosystem(r.manager);
            let chain = self.chain.clone();
            // A repeated reference to an already-reviewed package reuses
            // the cached review without re-resolving, budget or not.
            let canon_name = crate::version::canonicalize_for_ecosystem(child_eco, name);
            if let Some(stored_key) = self.completed_names.get(&(child_eco, canon_name.clone())) {
                let same_version = match version_part {
                    Some(v) => stored_key.2 == v,
                    // An unpinned reference floats with the registry: it may
                    // only reuse the cached review when the resolved latest
                    // equals the stored version. Never assume that here —
                    // resolution below either reuses the exact completed
                    // review or reviews the new latest.
                    None => false,
                };
                if same_version && let Some(cached) = self.completed.get(stored_key) {
                    let mut child = cached.clone();
                    let mut chain = chain;
                    chain.push(format!("{}:{}@{}", child_eco.key(), name, stored_key.2));
                    child.chain = chain;
                    children.push(child);
                    continue;
                }
            }
            // Budget check precedes resolution so an exhausted fan-out never
            // spends a registry lookup it cannot act on.
            if self.child_reviews >= self.max_child_reviews {
                findings.push(depth_cap_finding(
                    &chain,
                    &self.dropped_key(r),
                    &budget_cause(self.child_reviews, self.max_child_reviews),
                ));
                continue;
            }
            let version = match self.resolve_child_version(child_eco, name, version_part, &chain, r)
            {
                Ok(version) => version,
                Err(finding) => {
                    findings.push(finding);
                    continue;
                }
            };
            let key = (child_eco, canon_name, version.clone());
            // Chain through the child: used for every outcome once the
            // referenced release is identified.
            let mut chain = self.chain.clone();
            chain.push(format!("{}:{}@{}", child_eco.key(), name, version));
            if self
                .stack
                .iter()
                .any(|k| k.0 == key.0 && k.1 == key.1 && k.2 == key.2)
            {
                findings.push(cycle_finding(&chain, &key));
                continue;
            }
            // A completed child costs nothing to reuse: attach the cached
            // review even when the budget is spent.
            if let Some(cached) = self.completed.get(&key) {
                let mut child = cached.clone();
                child.chain = chain;
                children.push(child);
                continue;
            }
            self.child_reviews += 1;
            self.enter_scope(child_eco, name, &version, false);
            let chain = self.chain.clone();
            let result =
                crate::review::evaluate_scoped(name, &version, child_eco, store, policy, self);
            self.exit_scope();
            match result {
                Ok((verdict, _, _, _)) => {
                    let child = ChildReview {
                        chain,
                        name: name.to_string(),
                        version,
                        ecosystem: child_eco,
                        band: verdict.band,
                        risk_score: verdict.risk_score,
                        findings: verdict.findings,
                    };
                    self.completed_names
                        .insert((child_eco, key.1.clone()), key.clone());
                    self.completed.insert(key, child.clone());
                    children.push(child);
                }
                Err(e) => findings.push(child_review_failed_finding(
                    &chain, child_eco, name, &version, &e,
                )),
            }
        }
        (children, findings)
    }

    /// Identity placeholder for a reference whose target was never resolved
    /// (cap hit before resolution): the raw spec, not a guessed version.
    fn dropped_key(&self, r: &InstallRef) -> ReviewKey {
        let child_eco = child_ecosystem(r.manager);
        let (name, _) = r.registry_spec().unwrap_or(("", None));
        (
            child_eco,
            crate::version::canonicalize_for_ecosystem(child_eco, name),
            String::new(),
        )
    }

    fn resolve_child_version(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: Option<&str>,
        chain: &[String],
        r: &InstallRef,
    ) -> Result<String, Finding> {
        let unresolvable = |detail: String| Finding {
            rule_id: "R24_LIFECYCLE_INSTALL_REF".to_string(),
            severity: VerdictBand::Medium,
            title: "Referenced install could not be resolved".to_string(),
            description: format!(
                "delivered via: {}; {} install of `{}`: {detail}",
                chain.join(" → "),
                r.manager.label(),
                if r.spec.is_empty() {
                    "<unresolvable>"
                } else {
                    &r.spec
                }
            ),
        };
        match version {
            Some(v) if is_exact_version(ecosystem, v) => Ok(v.to_string()),
            Some(v) => Err(unresolvable(format!(
                "`{v}` is not an exact version; ranges cannot be pinned for review"
            ))),
            None => match self.registry(ecosystem).default_version(name) {
                Ok(Some(default)) => Ok(default),
                Ok(None) => Err(unresolvable(format!(
                    "no versions found for `{name}` in the registry"
                ))),
                Err(e) => Err(unresolvable(format!("registry lookup failed: {e:#}"))),
            },
        }
    }
}

fn is_exact_version(ecosystem: Ecosystem, version: &str) -> bool {
    match ecosystem {
        Ecosystem::Npm | Ecosystem::Cargo => semver::Version::parse(version).is_ok(),
        Ecosystem::PyPi => crate::version::Pep440Version::parse(version).is_ok(),
        Ecosystem::Aur => crate::version::AurVersionInfo::parse(version).is_ok(),
    }
}

/// A child evaluation that failed because the referenced package does not
/// exist (registry 404) is a disclosed unresolvable reference (MEDIUM);
/// any other failure is fail-closed HIGH — the target could not be
/// reviewed and nothing is assumed about it.
fn child_review_failed_finding(
    chain: &[String],
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    e: &anyhow::Error,
) -> Finding {
    let not_found = e
        .chain()
        .filter_map(|c| c.downcast_ref::<crate::error::BluelineError>())
        .any(|b| matches!(b, crate::error::BluelineError::NotFound(_)));
    let (severity, title) = if not_found {
        (
            VerdictBand::Medium,
            "Referenced install could not be resolved",
        )
    } else {
        (VerdictBand::High, "Recursive review failed")
    };
    Finding {
        rule_id: "R24_LIFECYCLE_INSTALL_REF".to_string(),
        severity,
        title: title.to_string(),
        description: format!(
            "delivered via: {}; recursive review of {}:{}@{} failed: {e:#}",
            chain.join(" → "),
            ecosystem.key(),
            name,
            version
        ),
    }
}

fn depth_cap_finding(chain: &[String], key: &ReviewKey, cause: &str) -> Finding {
    Finding {
        rule_id: "R25_RECURSION_DEPTH".to_string(),
        severity: VerdictBand::High,
        title: "Recursion cap reached".to_string(),
        description: format!(
            "delivered via: {}; referenced install {}:{}@{} was NOT reviewed: \
             {}. Fail closed: the un-reviewed reference is disclosed, never silent.",
            chain.join(" → "),
            key.0.key(),
            key.1,
            key.2,
            cause,
        ),
    }
}

fn depth_cause(depth: u32, max_depth: u32) -> String {
    format!("child depth {depth} exceeds the configured max_depth {max_depth}")
}

fn budget_cause(reviews: u32, max_reviews: u32) -> String {
    format!("child budget {reviews}/{max_reviews} exhausted")
}

fn cycle_finding(chain: &[String], key: &(Ecosystem, String, String)) -> Finding {
    Finding {
        rule_id: "R26_RECURSION_CYCLE".to_string(),
        severity: VerdictBand::High,
        title: "Install-reference cycle".to_string(),
        description: format!(
            "delivered via: {}; {}:{}@{} references a package already on the review \
             path (A → B → A); the loop is cut here, fail closed",
            chain.join(" → "),
            key.0.key(),
            key.1,
            key.2,
        ),
    }
}

/// R24 findings for the delivery lines themselves: every statically visible
/// install reference is disclosed, with the band reflecting how well the
/// target can be pinned and reviewed.
pub fn install_ref_findings(refs: &[InstallRef]) -> Vec<Finding> {
    refs.iter()
        .map(|r| {
            let location = match &r.origin {
                RefOrigin::NpmLifecycle { script } => format!("`{script}` lifecycle script"),
                RefOrigin::Pkgbuild { function } => format!("PKGBUILD `{function}()`"),
                RefOrigin::WheelDataScript { path } => format!("wheel script `{path}`"),
                RefOrigin::CommandLine => "command line".to_string(),
            };
            let invocation = format!(
                "{} install of `{}`",
                r.manager.label(),
                if r.spec.is_empty() {
                    "<unresolvable>"
                } else {
                    &r.spec
                }
            );
            if !r.parseable {
                return Finding {
                    rule_id: "R24_LIFECYCLE_INSTALL_REF".to_string(),
                    severity: VerdictBand::Medium,
                    title: "Install reference with unresolvable target".to_string(),
                    description: format!(
                        "{location}: {invocation}; the target is dynamic or unreadable, \
                         so it cannot be reviewed statically"
                    ),
                };
            }
            if let Some((name, version)) = r.registry_spec() {
                let pinning = match version {
                    Some(v) => format!("pinned to {v}"),
                    None => "UNPINNED — the payload can change after this review".to_string(),
                };
                let severity = if r.pinned {
                    VerdictBand::High
                } else {
                    VerdictBand::Medium
                };
                return Finding {
                    rule_id: "R24_LIFECYCLE_INSTALL_REF".to_string(),
                    severity,
                    title: "Second-order install reference".to_string(),
                    description: format!(
                        "{location}: {invocation} ({pinning}); the referenced package \
                         `{name}` is reviewed recursively and rolled up into this verdict"
                    ),
                };
            }
            Finding {
                rule_id: "R24_LIFECYCLE_INSTALL_REF".to_string(),
                severity: VerdictBand::High,
                title: "Non-registry install reference".to_string(),
                description: format!(
                    "{location}: {invocation}; git/URL/path references are NOT recursively \
                     reviewed — the payload they execute is unreviewed"
                ),
            }
        })
        .collect()
}

/// Roll-up: a child finding at or above the policy threshold escalates the
/// parent verdict, so a HIGH finding in a referenced package can BLOCK the
/// parent.
pub fn second_order_finding(child: &ChildReview) -> Finding {
    let worst = child
        .findings
        .iter()
        .max_by_key(|f| f.severity)
        .map(|f| format!("[{}] {}: {}", f.severity, f.rule_id, f.title))
        .unwrap_or_else(|| "no findings recorded".to_string());
    Finding {
        rule_id: "R27_SECOND_ORDER".to_string(),
        severity: child.band,
        title: "Second-order finding in referenced package".to_string(),
        description: format!(
            "delivered via: {}; {}:{}@{} reviewed at band {} (score {}) with {} finding(s); \
             worst: {worst}",
            child.chain.join(" → "),
            child.ecosystem.key(),
            child.name,
            child.version,
            child.band,
            child.risk_score,
            child.findings.len(),
        ),
    }
}

/// Which registry a referenced install resolves against. Delegates to the
/// manager's own mapping so the gate and the recursive reviewer can never
/// disagree about where a `cargo install` or `yay -S` lands.
pub(crate) fn child_ecosystem(manager: RefManager) -> Ecosystem {
    manager.ecosystem()
}

/// Registry factory shared by the review context and one-off spec
/// resolution: AUR parents deliver through npm, pip invocations in wheel
/// scripts resolve in PyPI.
pub(crate) fn registry_for(ecosystem: Ecosystem, base: &str) -> Rc<dyn Registry> {
    match ecosystem {
        Ecosystem::Npm => Rc::new(crate::registry::npm::NpmRegistry::new(base)),
        Ecosystem::Cargo => Rc::new(crate::registry::cratesio::CratesIoRegistry::new(base)),
        Ecosystem::PyPi => Rc::new(crate::registry::pypi::PyPIRegistry::new(base)),
        Ecosystem::Aur => Rc::new(crate::registry::aur::AurRegistry::new(base)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Package, Release};

    struct FakeRegistry {
        ecosystem: Ecosystem,
        payloads: std::collections::HashMap<(String, String), Vec<u8>>,
    }

    impl crate::registry::Registry for FakeRegistry {
        fn ecosystem(&self) -> Ecosystem {
            self.ecosystem
        }

        fn resolve(
            &self,
            name: &str,
            version: &str,
        ) -> Result<Package, crate::error::BluelineError> {
            Ok(Package {
                name: name.to_string(),
                version: version.to_string(),
                tarball_url: String::new(),
                integrity: None,
            })
        }

        fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, crate::error::BluelineError> {
            match self.payloads.get(&(pkg.name.clone(), pkg.version.clone())) {
                Some(bytes) => Ok(bytes.clone()),
                None => Err(crate::error::BluelineError::NotFound(pkg.name.clone())),
            }
        }

        fn list_versions(
            &self,
            _name: &str,
        ) -> Result<Vec<semver::Version>, crate::error::BluelineError> {
            Ok(Vec::new())
        }

        fn list_releases(&self, _name: &str) -> Result<Vec<Release>, crate::error::BluelineError> {
            Ok(Vec::new())
        }

        fn default_version(&self, _: &str) -> Result<Option<String>, crate::error::BluelineError> {
            Ok(None)
        }
    }

    fn test_context() -> ReviewContext {
        ReviewContext::new(
            &Policy::default(),
            crate::cli::RegistryBases {
                npm: String::new(),
                cargo: String::new(),
                pypi: String::new(),
                aur: String::new(),
            },
        )
    }

    fn test_package(name: &str, version: &str) -> Package {
        Package {
            name: name.to_string(),
            version: version.to_string(),
            tarball_url: String::new(),
            integrity: None,
        }
    }

    #[test]
    fn child_ecosystem_routes_cargo_and_aur_helpers() {
        assert_eq!(child_ecosystem(RefManager::Cargo), Ecosystem::Cargo);
        assert_eq!(child_ecosystem(RefManager::Yay), Ecosystem::Aur);
        assert_eq!(child_ecosystem(RefManager::Paru), Ecosystem::Aur);
        assert_eq!(child_ecosystem(RefManager::Pip), Ecosystem::PyPi);
        assert_eq!(child_ecosystem(RefManager::Npm), Ecosystem::Npm);
        assert_eq!(child_ecosystem(RefManager::Npx), Ecosystem::Npm);
    }

    #[test]
    fn dropped_key_uses_the_child_registry() {
        let ctx = ReviewContext::new(
            &Policy::default(),
            crate::cli::RegistryBases {
                npm: String::new(),
                cargo: String::new(),
                pypi: String::new(),
                aur: String::new(),
            },
        );
        for (manager, ecosystem) in [
            (RefManager::Cargo, Ecosystem::Cargo),
            (RefManager::Yay, Ecosystem::Aur),
            (RefManager::Paru, Ecosystem::Aur),
            (RefManager::Pip, Ecosystem::PyPi),
            (RefManager::Npm, Ecosystem::Npm),
        ] {
            let r = crate::install_ref::raw_ref(RefOrigin::CommandLine, manager, "some-pkg");
            let key = ctx.dropped_key(&r);
            assert_eq!(key.0, ecosystem, "{manager:?} must drop into {ecosystem:?}");
        }
    }

    #[test]
    fn tarball_memo_cap_is_exactly_256mib() {
        assert_eq!(MAX_TARBALL_MEMO_BYTES, 268_435_456);
        assert_eq!(MAX_TARBALL_MEMO_BYTES, 256 * 1024 * 1024);
    }

    #[test]
    fn tarball_fetch_at_exact_cap_keeps_memo() {
        let ctx = test_context();
        let mut payloads = std::collections::HashMap::new();
        payloads.insert(("seed".to_string(), "1.0.0".to_string()), vec![1u8; 5]);
        payloads.insert(("exact".to_string(), "1.0.0".to_string()), vec![2u8; 5]);
        let registry = FakeRegistry {
            ecosystem: Ecosystem::Npm,
            payloads,
        };
        ctx.fetch_tarball(&registry, &test_package("seed", "1.0.0"))
            .expect("seed fetch must succeed");
        ctx.memo_bytes.set(MAX_TARBALL_MEMO_BYTES - 5);
        let bytes = ctx
            .fetch_tarball(&registry, &test_package("exact", "1.0.0"))
            .expect("exactly-MAX fetch must succeed");
        assert_eq!(bytes.len(), 5);
        assert_eq!(ctx.memo_bytes.get(), MAX_TARBALL_MEMO_BYTES);
        assert!(ctx.tarballs.borrow().contains_key(&(
            Ecosystem::Npm,
            "seed".to_string(),
            "1.0.0".to_string()
        )));
        assert!(ctx.tarballs.borrow().contains_key(&(
            Ecosystem::Npm,
            "exact".to_string(),
            "1.0.0".to_string()
        )));
    }

    #[test]
    fn tarball_fetch_one_past_cap_clears_memo() {
        let ctx = test_context();
        let mut payloads = std::collections::HashMap::new();
        payloads.insert(("seed".to_string(), "1.0.0".to_string()), vec![1u8; 5]);
        payloads.insert(("over".to_string(), "1.0.0".to_string()), vec![2u8; 6]);
        let registry = FakeRegistry {
            ecosystem: Ecosystem::Npm,
            payloads,
        };
        ctx.fetch_tarball(&registry, &test_package("seed", "1.0.0"))
            .expect("seed fetch must succeed");
        ctx.memo_bytes.set(MAX_TARBALL_MEMO_BYTES - 5);
        let bytes = ctx
            .fetch_tarball(&registry, &test_package("over", "1.0.0"))
            .expect("overflow fetch must still return bytes");
        assert_eq!(bytes.len(), 6);
        assert_eq!(ctx.memo_bytes.get(), 6);
        assert_eq!(ctx.tarballs.borrow().len(), 1);
        assert!(ctx.tarballs.borrow().contains_key(&(
            Ecosystem::Npm,
            "over".to_string(),
            "1.0.0".to_string()
        )));
    }

    #[test]
    fn depth_cause_names_depth_and_limit() {
        let cause = depth_cause(5, 3);
        assert!(!cause.is_empty());
        assert_ne!(cause, "xyzzy");
        assert!(cause.contains('5'), "cause must name the depth: {cause}");
        assert!(cause.contains('3'), "cause must name max_depth: {cause}");
        assert!(cause.contains("max_depth"));
    }

    #[test]
    fn budget_cause_names_reviews_and_limit() {
        let cause = budget_cause(8, 8);
        assert!(!cause.is_empty());
        assert_ne!(cause, "xyzzy");
        assert!(cause.contains('8'), "cause must name the budget: {cause}");
        assert!(cause.contains("budget"));
    }
}
