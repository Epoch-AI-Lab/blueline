use std::io::{IsTerminal, Write};

use crate::baseline::{BaselineSelection, resolve_baseline};
use crate::cli::{Output, OutputFormat};
use crate::diff::compute_delta;
use crate::extract::{ExtractionLimits, safe_extract};
use crate::heuristic::evaluate_with_trust;
use crate::manifest::{read_package_json, read_packed_cargo_toml};
use crate::policy::Policy;
use crate::registry::cratesio::CratesIoRegistry;
use crate::registry::npm::NpmRegistry;
use crate::registry::pypi::PyPIRegistry;
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

fn make_registry(ecosystem: Ecosystem, registry_base: &str) -> anyhow::Result<Box<dyn Registry>> {
    match ecosystem {
        Ecosystem::Npm => Ok(Box::new(NpmRegistry::new(registry_base))),
        Ecosystem::Cargo => Ok(Box::new(CratesIoRegistry::new(registry_base))),
        Ecosystem::PyPi => Ok(Box::new(PyPIRegistry::new(registry_base))),
    }
}

/// Evaluates a package specification against its baseline, computing delta,
/// OSV advisories, and Sigstore provenance to produce a final Verdict and Delta.
pub fn evaluate_package(
    name: &str,
    version_str: &str,
    ecosystem: Ecosystem,
    registry_base: &str,
    store: &BaselineStore,
    policy: &Policy,
) -> anyhow::Result<(
    crate::verdict::Verdict,
    crate::diff::Delta,
    crate::registry::Checksum,
    Option<UnreviewedBaseline>,
)> {
    match ecosystem {
        Ecosystem::Npm => evaluate_with_registry::<NpmRegistry, semver::Version>(
            NpmRegistry::new(registry_base),
            name,
            version_str,
            registry_base,
            store,
            policy,
        ),
        Ecosystem::Cargo => evaluate_with_registry::<CratesIoRegistry, semver::Version>(
            CratesIoRegistry::new(registry_base),
            name,
            version_str,
            registry_base,
            store,
            policy,
        ),
        Ecosystem::PyPi => evaluate_with_registry::<PyPIRegistry, crate::version::Pep440Version>(
            PyPIRegistry::new(registry_base),
            name,
            version_str,
            registry_base,
            store,
            policy,
        ),
    }
}

fn evaluate_with_registry<R: Registry, V: VersionInfo>(
    registry: R,
    name: &str,
    version_str: &str,
    registry_base: &str,
    store: &BaselineStore,
    policy: &Policy,
) -> anyhow::Result<(
    crate::verdict::Verdict,
    crate::diff::Delta,
    crate::registry::Checksum,
    Option<UnreviewedBaseline>,
)> {
    let target_ver = V::parse(version_str)
        .map_err(|e| anyhow::anyhow!("invalid version for `{version_str}`: {e}"))?;

    let ecosystem = registry.ecosystem();
    let target_pkg = registry.resolve(name, version_str)?;

    let target_tarball = registry.fetch_tarball(&target_pkg)?;

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

    let baseline_res: BaselineSelection = resolve_baseline(name, &target_ver, &registry, store)
        .map_err(|e| anyhow::anyhow!("baseline resolution: {e}"))?;

    let delta = if let Some(base_pkg) = baseline_res.resolution.package() {
        let base_tarball = registry.fetch_tarball(base_pkg)?;
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

        compute_delta(
            Some(&base_root),
            Some(&base_manifest),
            Some(&base_pkg.version),
            &target_root,
            &target_manifest,
            &target_pkg.version,
        )?
    } else {
        compute_delta(
            None,
            None,
            None,
            &target_root,
            &target_manifest,
            &target_pkg.version,
        )?
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

    let advisories = crate::advisory::fetch_advisories(
        &target_pkg.name,
        &target_pkg.version,
        ecosystem,
        Some(store),
        policy,
    )
    .unwrap_or_else(|e| crate::advisory::AdvisoryReport::unverified(&e.to_string()));

    let provenance = match ecosystem {
        Ecosystem::Npm => Some(crate::provenance::inspect_provenance(
            &target_pkg.name,
            &target_pkg.version,
            &checksum,
            None,
            registry_base,
            Some(store),
            policy,
        )),
        Ecosystem::PyPi => {
            let filename = target_pkg
                .tarball_url
                .rsplit('/')
                .next()
                .unwrap_or(&target_pkg.name);
            Some(crate::provenance::inspect_provenance_pypi(
                &target_pkg.name,
                &target_pkg.version,
                filename,
                &checksum,
                registry_base,
                Some(store),
                policy,
            ))
        }
        Ecosystem::Cargo => None,
    };

    let verdict = evaluate_with_trust(
        &target_pkg.name,
        ecosystem,
        &checksum.to_display(),
        &delta,
        is_unreviewed,
        baseline_res.prior_release_yanked,
        policy,
        Some(&advisories),
        provenance.as_ref(),
    );

    Ok((verdict, delta, checksum, unreviewed_baseline))
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
/// directory named `{canonical-name}-{version}`.
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
        Ecosystem::PyPi => {
            let candidate = root.join("METADATA");
            if candidate.exists() {
                let raw = std::fs::read_to_string(&candidate).unwrap_or_default();
                let mut deps = std::collections::BTreeMap::new();
                for line in raw.lines() {
                    if let Some(rest) = line.strip_prefix("Requires-Dist:") {
                        let dep = rest.trim().split(';').next().unwrap_or("").trim();
                        if !dep.is_empty() {
                            let name = dep.split_whitespace().next().unwrap_or(dep).to_string();
                            deps.insert(name.clone(), dep.to_string());
                        }
                    }
                }
                crate::manifest::PackageJson {
                    name: canonical_name.to_string(),
                    version: version.to_string(),
                    gypfile: None,
                    scripts: std::collections::BTreeMap::new(),
                    dependencies: deps,
                    ..Default::default()
                }
            } else {
                crate::manifest::PackageJson {
                    name: canonical_name.to_string(),
                    version: version.to_string(),
                    ..Default::default()
                }
            }
        }
    };
    Ok((root, manifest))
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
        Some(format!(
            "hint: baseline `{name}@{base}` was never approved locally. Approve it when prompted during an interactive `blueline review`, or run `blueline review {name}@{base}` directly."
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
    registry_base: &str,
    output: Output,
    policy_path: Option<&std::path::Path>,
    yes: bool,
) -> anyhow::Result<()> {
    let policy = Policy::load_or_default(policy_path)?;
    let registry = make_registry(ecosystem, registry_base)?;
    let (name, version_str) = parse_spec_flexible(pkg_spec, registry.as_ref())?;
    let store = BaselineStore::open()?;

    let (verdict, delta, checksum, unreviewed_baseline) = evaluate_package(
        &name,
        &version_str,
        ecosystem,
        registry_base,
        &store,
        &policy,
    )?;

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
            store.mark_clean(ecosystem, &name, &version_str, &checksum)?;
            let _ = store.record_audit_log(
                ecosystem,
                &name,
                &version_str,
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
            &name,
            &version_str,
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
    registry_base: &str,
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

    crate::executor::validate_extra_args(npm_args)?;
    let policy = Policy::load_or_default(policy_path)?;
    let registry = make_registry(ecosystem, registry_base)?;
    let (name, version_str) = parse_spec_flexible(pkg_spec, registry.as_ref())?;
    let store = BaselineStore::open()?;

    let (verdict, delta, checksum, unreviewed_baseline) = evaluate_package(
        &name,
        &version_str,
        ecosystem,
        registry_base,
        &store,
        &policy,
    )?;
    render_text(&verdict, &delta);

    let is_interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let approved = if yes {
        if verdict.band == crate::verdict::VerdictBand::Low {
            store.mark_clean(ecosystem, &name, &version_str, &checksum)?;
            let _ = store.record_audit_log(
                ecosystem,
                &name,
                &version_str,
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
            &name,
            &version_str,
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
        crate::executor::install_with_ignore_scripts(&install_spec, registry_base, npm_args)?;
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
pub fn parse_spec(spec: &str) -> anyhow::Result<(String, String)> {
    if let Some((name, version)) = spec.split_once("==") {
        if name.is_empty() || version.is_empty() || name.contains('@') || version.contains('@') {
            return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
        }
        if name.contains('[')
            || name.contains(']')
            || version.contains('[')
            || version.contains(' ')
        {
            return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
        }
        if crate::version::Pep440Version::parse(version).is_err()
            && semver::Version::parse(version).is_err()
        {
            return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
        }
        return Ok((name.to_string(), version.to_string()));
    }
    let mut parts = spec.rsplitn(2, '@');
    let version = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if name.is_empty() || version.is_empty() {
        return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
    }
    if semver::Version::parse(version).is_err()
        && crate::version::Pep440Version::parse(version).is_err()
    {
        return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
    }
    Ok((name.to_string(), version.to_string()))
}

/// Flexible parser for install: `<name>` or `<name>@<version>`.
/// If version is omitted, resolves the registry's default version
/// (`dist-tags.latest` for npm, falling back to latest stable semver release).
fn parse_spec_flexible(spec: &str, registry: &dyn Registry) -> anyhow::Result<(String, String)> {
    let has_version_sep = spec.contains("==")
        || if let Some(rest) = spec.strip_prefix('@') {
            rest.contains('@')
        } else {
            spec.contains('@')
        };

    if has_version_sep {
        parse_spec(spec)
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

    #[test]
    fn parses_plain_spec() {
        assert_eq!(
            parse_spec("express@4.21.2").unwrap(),
            ("express".into(), "4.21.2".into())
        );
    }

    #[test]
    fn parses_scoped_spec() {
        assert_eq!(
            parse_spec("@scope/pkg@1.2.3").unwrap(),
            ("@scope/pkg".into(), "1.2.3".into())
        );
    }

    #[test]
    fn rejects_missing_at() {
        assert!(parse_spec("express").is_err());
    }

    #[test]
    fn rejects_bad_semver() {
        assert!(parse_spec("express@latest").is_err());
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
            parse_spec("requests==2.28.1").unwrap(),
            ("requests".into(), "2.28.1".into())
        );
        assert_eq!(
            parse_spec("my-package==1.0a1").unwrap(),
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
    }
}
