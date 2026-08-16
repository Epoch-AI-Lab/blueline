use std::io::{IsTerminal, Write};

use crate::baseline::resolve_baseline;
use crate::cli::{Output, OutputFormat};
use crate::diff::compute_delta;
use crate::extract::{ExtractionLimits, safe_extract};
use crate::heuristic::evaluate_with_trust;
use crate::manifest::read_package_json;
use crate::policy::Policy;
use crate::registry::Registry;
use crate::registry::npm::NpmRegistry;
use crate::render::{render_json, render_text};
use crate::store::BaselineStore;

pub fn run(
    pkg_spec: &str,
    registry_base: &str,
    output: Output,
    policy_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let policy = Policy::load_or_default(policy_path)?;
    let (name, version_str) = parse_spec(pkg_spec)?;
    let target_semver = semver::Version::parse(&version_str)
        .map_err(|e| anyhow::anyhow!("invalid semver for `{version_str}`: {e}"))?;

    let registry = NpmRegistry::new(registry_base);
    let target_pkg = registry.resolve(&name, &version_str)?;

    // fetch_tarball verifies sha512 against dist.integrity and fails closed
    // on any mismatch, so the bytes below are integrity-verified.
    let target_tarball = registry.fetch_tarball(&target_pkg)?;

    let target_temp = tempfile::tempdir().map_err(|e| anyhow::anyhow!("creating temp dir: {e}"))?;
    safe_extract(
        &target_tarball,
        target_temp.path(),
        &ExtractionLimits::default(),
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to extract {}@{}: {e}",
            target_pkg.name,
            target_pkg.version
        )
    })?;

    let target_manifest_path = package_json_path(target_temp.path());
    let target_manifest = read_package_json(&target_manifest_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to parse package.json for {}@{}: {e}",
            target_pkg.name,
            target_pkg.version
        )
    })?;

    let store = BaselineStore::open().map_err(|e| anyhow::anyhow!("baseline store: {e}"))?;
    let integrity = target_pkg.integrity.clone().unwrap_or_default();
    store
        .record_verified(&target_pkg.name, &target_pkg.version, &integrity)
        .map_err(|e| anyhow::anyhow!("baseline store: {e}"))?;

    let baseline_res = resolve_baseline(&name, &target_semver, &registry, &store)
        .map_err(|e| anyhow::anyhow!("baseline resolution: {e}"))?;

    let delta = if let Some(base_pkg) = baseline_res.package() {
        let base_tarball = registry.fetch_tarball(base_pkg)?;
        let base_temp =
            tempfile::tempdir().map_err(|e| anyhow::anyhow!("creating temp dir: {e}"))?;
        safe_extract(
            &base_tarball,
            base_temp.path(),
            &ExtractionLimits::default(),
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to extract baseline {}@{}: {e}",
                base_pkg.name,
                base_pkg.version
            )
        })?;
        let base_manifest_path = package_json_path(base_temp.path());
        let base_manifest = read_package_json(&base_manifest_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to parse package.json for baseline {}@{}: {e}",
                base_pkg.name,
                base_pkg.version
            )
        })?;

        compute_delta(
            Some(base_temp.path()),
            Some(&base_manifest),
            Some(&base_pkg.version),
            target_temp.path(),
            &target_manifest,
            &target_pkg.version,
        )?
    } else {
        compute_delta(
            None,
            None,
            None,
            target_temp.path(),
            &target_manifest,
            &target_pkg.version,
        )?
    };

    let is_unreviewed = matches!(
        baseline_res,
        crate::baseline::BaselineResolution::RegistryPredecessor(_)
    );

    let advisories = crate::advisory::fetch_advisories(
        &target_pkg.name,
        &target_pkg.version,
        Some(&store),
        &policy,
    )
    .unwrap_or_else(|e| crate::advisory::AdvisoryReport::unverified(&e.to_string()));

    let provenance = crate::provenance::inspect_provenance(
        &target_pkg.name,
        &target_pkg.version,
        &integrity,
        None,
        Some(&store),
        &policy,
    );

    let verdict = evaluate_with_trust(
        &target_pkg.name,
        "verified (sha512)",
        &delta,
        is_unreviewed,
        &policy,
        Some(&advisories),
        Some(&provenance),
    );

    match output.resolve(std::io::stdout().is_terminal()) {
        OutputFormat::Json => {
            render_json(&verdict)?;
        }
        OutputFormat::Text => {
            render_text(&verdict, &delta);
        }
    }

    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        interactive_prompt(
            &store,
            &target_pkg.name,
            &target_pkg.version,
            &integrity,
            &delta,
        )?;
    } else if verdict.band != crate::verdict::VerdictBand::Low {
        std::process::exit(2);
    }

    Ok(())
}

pub fn install(
    pkg_spec: &str,
    registry_base: &str,
    npm_args: &[String],
    policy_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    crate::executor::validate_extra_args(npm_args)?;
    let policy = Policy::load_or_default(policy_path)?;
    let registry = NpmRegistry::new(registry_base);
    let (name, version_str) = parse_spec_flexible(pkg_spec, &registry)?;
    let target_semver = semver::Version::parse(&version_str)
        .map_err(|e| anyhow::anyhow!("invalid semver for `{version_str}`: {e}"))?;

    let target_pkg = registry.resolve(&name, &version_str)?;
    let target_tarball = registry.fetch_tarball(&target_pkg)?;

    let target_temp = tempfile::tempdir().map_err(|e| anyhow::anyhow!("creating temp dir: {e}"))?;
    safe_extract(
        &target_tarball,
        target_temp.path(),
        &ExtractionLimits::default(),
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to extract {}@{}: {e}",
            target_pkg.name,
            target_pkg.version
        )
    })?;

    let target_manifest_path = package_json_path(target_temp.path());
    let target_manifest = read_package_json(&target_manifest_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to parse package.json for {}@{}: {e}",
            target_pkg.name,
            target_pkg.version
        )
    })?;

    let store = BaselineStore::open().map_err(|e| anyhow::anyhow!("baseline store: {e}"))?;
    let integrity = target_pkg.integrity.clone().unwrap_or_default();
    store
        .record_verified(&target_pkg.name, &target_pkg.version, &integrity)
        .map_err(|e| anyhow::anyhow!("baseline store: {e}"))?;

    let baseline_res = resolve_baseline(&name, &target_semver, &registry, &store)
        .map_err(|e| anyhow::anyhow!("baseline resolution: {e}"))?;

    let delta = if let Some(base_pkg) = baseline_res.package() {
        let base_tarball = registry.fetch_tarball(base_pkg)?;
        let base_temp =
            tempfile::tempdir().map_err(|e| anyhow::anyhow!("creating temp dir: {e}"))?;
        safe_extract(
            &base_tarball,
            base_temp.path(),
            &ExtractionLimits::default(),
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to extract baseline {}@{}: {e}",
                base_pkg.name,
                base_pkg.version
            )
        })?;
        let base_manifest_path = package_json_path(base_temp.path());
        let base_manifest = read_package_json(&base_manifest_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to parse package.json for baseline {}@{}: {e}",
                base_pkg.name,
                base_pkg.version
            )
        })?;

        compute_delta(
            Some(base_temp.path()),
            Some(&base_manifest),
            Some(&base_pkg.version),
            target_temp.path(),
            &target_manifest,
            &target_pkg.version,
        )?
    } else {
        compute_delta(
            None,
            None,
            None,
            target_temp.path(),
            &target_manifest,
            &target_pkg.version,
        )?
    };

    let is_unreviewed = matches!(
        baseline_res,
        crate::baseline::BaselineResolution::RegistryPredecessor(_)
    );

    let advisories = crate::advisory::fetch_advisories(
        &target_pkg.name,
        &target_pkg.version,
        Some(&store),
        &policy,
    )
    .unwrap_or_else(|e| crate::advisory::AdvisoryReport::unverified(&e.to_string()));

    let provenance = crate::provenance::inspect_provenance(
        &target_pkg.name,
        &target_pkg.version,
        &integrity,
        None,
        Some(&store),
        &policy,
    );

    let verdict = evaluate_with_trust(
        &target_pkg.name,
        "verified (sha512)",
        &delta,
        is_unreviewed,
        &policy,
        Some(&advisories),
        Some(&provenance),
    );
    render_text(&verdict, &delta);

    let is_interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let approved = if is_interactive {
        interactive_prompt(
            &store,
            &target_pkg.name,
            &target_pkg.version,
            &integrity,
            &delta,
        )?
    } else {
        verdict.band == crate::verdict::VerdictBand::Low
    };

    if approved {
        let install_spec = format!("{name}@{version_str}");
        crate::executor::install_with_ignore_scripts(&install_spec, registry_base, npm_args)?;
        Ok(())
    } else {
        eprintln!(
            "Held {}@{}; installation blocked.",
            target_pkg.name, target_pkg.version
        );
        std::process::exit(2);
    }
}

fn interactive_prompt(
    store: &BaselineStore,
    name: &str,
    version: &str,
    integrity: &str,
    delta: &crate::diff::Delta,
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
                store.mark_clean(name, version, integrity)?;
                let _ = store.record_audit_log(
                    name, version, integrity, "approve", 0, "approved", "user", None,
                );
                println!(
                    "Approved {}@{} and marked clean in baseline store.",
                    name, version
                );
                return Ok(true);
            }
            "h" | "hold" => {
                let _ = store
                    .record_audit_log(name, version, integrity, "hold", 0, "held", "user", None);
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

/// `<name>@<version>` → (name, version). Scoped names (`@scope/pkg@1.0.0`)
/// split from the right so the scope's leading `@` stays with the name.
fn parse_spec(spec: &str) -> anyhow::Result<(String, String)> {
    let mut parts = spec.rsplitn(2, '@');
    let version = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if name.is_empty() || version.is_empty() {
        return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
    }
    if semver::Version::parse(version).is_err() {
        return Err(crate::error::BluelineError::InvalidPackageSpec(spec.to_string()).into());
    }
    Ok((name.to_string(), version.to_string()))
}

/// Flexible parser for install: `<name>` or `<name>@<version>`.
/// If version is omitted, resolves `dist-tags.latest` or falls back to latest stable semver release.
fn parse_spec_flexible(spec: &str, registry: &dyn Registry) -> anyhow::Result<(String, String)> {
    let has_version_sep = if let Some(rest) = spec.strip_prefix('@') {
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
        if let Ok(Some(latest_tag)) = registry.resolve_dist_tag(name, "latest") {
            return Ok((name.to_string(), latest_tag));
        }
        let versions = registry.list_versions(name)?;
        let latest = versions
            .iter()
            .rfind(|v| v.pre.is_empty())
            .or_else(|| versions.last())
            .ok_or_else(|| anyhow::anyhow!("no versions found for `{name}`"))?;
        Ok((name.to_string(), latest.to_string()))
    }
}

/// npm tarballs nest every file under a `package/` prefix.
fn package_json_path(root: &std::path::Path) -> std::path::PathBuf {
    let nested = root.join("package/package.json");
    if nested.exists() {
        nested
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
}
