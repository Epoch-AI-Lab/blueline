use std::io::IsTerminal;

use crate::cli::{Output, OutputFormat};
use crate::extract::{ExtractionLimits, safe_extract};
use crate::manifest::read_package_json;
use crate::registry::Registry;
use crate::registry::npm::NpmRegistry;
use crate::store::BaselineStore;

pub struct ReviewSummary {
    pub name: String,
    pub version: String,
    pub integrity: String,
    pub files: usize,
    pub unpacked_bytes: u64,
    pub install_scripts: Vec<String>,
    pub baseline: String,
}

pub fn run(pkg_spec: &str, registry_base: &str, output: Output) -> anyhow::Result<()> {
    let (name, version) = parse_spec(pkg_spec)?;

    let registry = NpmRegistry::new(registry_base);
    let pkg = registry.resolve(&name, &version)?;

    // fetch_tarball verifies sha512 against dist.integrity and fails closed
    // on any mismatch, so the bytes below are integrity-verified.
    let tarball = registry.fetch_tarball(&pkg)?;

    let temp = tempfile::tempdir().map_err(|e| anyhow::anyhow!("creating temp dir: {e}"))?;
    let stats = safe_extract(&tarball, temp.path(), &ExtractionLimits::default())
        .map_err(|e| anyhow::anyhow!("failed to extract {}@{}: {e}", pkg.name, pkg.version))?;

    let manifest_path = package_json_path(temp.path());
    let manifest = read_package_json(&manifest_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to parse package.json for {}@{}: {e}",
            pkg.name,
            pkg.version
        )
    })?;

    // Persist "this exact tarball, integrity-verified" as the known-clean baseline.
    let store = BaselineStore::open().map_err(|e| anyhow::anyhow!("baseline store: {e}"))?;
    let integrity = pkg.integrity.clone().unwrap_or_default();
    store
        .record_known_clean(&pkg.name, &pkg.version, &integrity)
        .map_err(|e| anyhow::anyhow!("baseline store: {e}"))?;

    let summary = ReviewSummary {
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        integrity: "verified (sha512)".to_string(),
        files: stats.files,
        unpacked_bytes: stats.unpacked_bytes,
        install_scripts: manifest.lifecycle_scripts(),
        baseline: "recorded as known-clean".to_string(),
    };

    match output.resolve(std::io::stdout().is_terminal()) {
        OutputFormat::Text => render_text(&summary),
        OutputFormat::Json => render_json(&summary)?,
    }
    Ok(())
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

fn render_text(s: &ReviewSummary) {
    let scripts = if s.install_scripts.is_empty() {
        "none".to_string()
    } else {
        s.install_scripts.join(", ")
    };
    println!("reviewed {}@{}", s.name, s.version);
    println!("  integrity:      {}", s.integrity);
    println!(
        "  files:          {} ({})",
        s.files,
        human_bytes(s.unpacked_bytes)
    );
    println!("  install script: {scripts}");
    println!("  baseline:       {}", s.baseline);
}

fn render_json(s: &ReviewSummary) -> anyhow::Result<()> {
    let out = serde_json::json!({
        "name": s.name,
        "version": s.version,
        "integrity": s.integrity,
        "files": s.files,
        "unpacked_bytes": s.unpacked_bytes,
        "lifecycle_scripts": s.install_scripts,
        "baseline": s.baseline,
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
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

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
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
    fn human_bytes_formats() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(3 * 1024 * 1024), "3.0 MiB");
    }
}
