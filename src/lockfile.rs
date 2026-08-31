use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::version::VersionInfo;

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("failed to parse lockfile JSON: {0}")]
    InvalidJson(serde_json::Error),

    #[error("failed to parse Cargo.lock TOML: {0}")]
    InvalidToml(String),

    #[error("lockfile is missing mandatory field: {0}")]
    MissingField(&'static str),

    #[error("invalid lockfile data: {0}")]
    InvalidData(String),
}

// Manual From instead of #[from]: the Display already embeds the serde_json
// detail, and thiserror's #[from] would also attach it as `source()`, which
// makes `{e:#}` in main print the detail twice.
impl From<serde_json::Error> for LockfileError {
    fn from(e: serde_json::Error) -> Self {
        LockfileError::InvalidJson(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    pub integrity: Option<String>,
    pub resolved: Option<String>,
    pub is_dev: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageUpgrade {
    pub name: String,
    pub old_version: String,
    pub new_version: String,
    pub old_integrity: Option<String>,
    pub new_integrity: Option<String>,
    pub resolved: Option<String>,
    pub is_dev: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileDelta {
    pub added: Vec<PackageEntry>,
    pub upgraded: Vec<PackageUpgrade>,
    pub removed: Vec<PackageEntry>,
    pub unchanged_count: usize,
}

impl LockfileDelta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.upgraded.is_empty() && self.removed.is_empty()
    }

    pub fn total_changed(&self) -> usize {
        self.added.len() + self.upgraded.len() + self.removed.len()
    }
}

#[derive(Deserialize)]
struct RawLockfile {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<u32>,
    packages: Option<BTreeMap<String, RawPackageV3>>,
    dependencies: Option<BTreeMap<String, RawDependencyV1>>,
}

#[derive(Deserialize)]
struct RawPackageV3 {
    name: Option<String>,
    version: Option<String>,
    integrity: Option<String>,
    resolved: Option<String>,
    dev: Option<bool>,
}

#[derive(Deserialize)]
struct RawDependencyV1 {
    version: Option<String>,
    integrity: Option<String>,
    resolved: Option<String>,
    dev: Option<bool>,
    dependencies: Option<BTreeMap<String, RawDependencyV1>>,
}

pub fn parse_lockfile_packages(
    json_content: &str,
) -> Result<BTreeMap<String, PackageEntry>, LockfileError> {
    let raw: RawLockfile = serde_json::from_str(json_content)?;
    let mut packages = BTreeMap::new();

    if let Some(raw_packages) = raw.packages {
        // v2 / v3 format
        for (path, pkg) in raw_packages {
            // Skip root package represented by empty string or "."
            if path.is_empty() || path == "." {
                continue;
            }

            let Some(version) = pkg.version else {
                continue;
            };

            let name = if let Some(pkg_name) = pkg.name {
                pkg_name
            } else {
                extract_package_name_from_path(&path)
            };

            if name.is_empty() {
                continue;
            }

            let entry = PackageEntry {
                name: name.clone(),
                version,
                integrity: pkg.integrity,
                resolved: pkg.resolved,
                is_dev: pkg.dev.unwrap_or(false),
            };

            // Key by normalized path in node_modules tree to handle nested deps
            let normalized_key = normalize_node_modules_path(&path);
            packages.insert(normalized_key, entry);
        }
    } else if let Some(raw_dependencies) = raw.dependencies {
        // v1 format
        walk_v1_dependencies("", &raw_dependencies, &mut packages, 0);
    } else {
        // Lockfile with neither packages nor dependencies (empty or invalid)
        if raw.lockfile_version.is_none() {
            return Err(LockfileError::MissingField("lockfileVersion"));
        }
    }

    Ok(packages)
}

const MAX_LOCKFILE_RECURSION_DEPTH: usize = 32;

fn walk_v1_dependencies(
    prefix: &str,
    deps: &BTreeMap<String, RawDependencyV1>,
    out: &mut BTreeMap<String, PackageEntry>,
    depth: usize,
) {
    if depth > MAX_LOCKFILE_RECURSION_DEPTH {
        return;
    }

    for (name, dep) in deps {
        let Some(version) = &dep.version else {
            continue;
        };

        let path_key = if prefix.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{prefix}/node_modules/{name}")
        };

        let entry = PackageEntry {
            name: name.clone(),
            version: version.clone(),
            integrity: dep.integrity.clone(),
            resolved: dep.resolved.clone(),
            is_dev: dep.dev.unwrap_or(false),
        };

        out.insert(path_key.clone(), entry);

        if let Some(nested) = &dep.dependencies {
            walk_v1_dependencies(&path_key, nested, out, depth + 1);
        }
    }
}

fn extract_package_name_from_path(path: &str) -> String {
    let name_part = path.rsplit("node_modules/").next().unwrap_or(path);
    name_part.trim_end_matches('/').to_string()
}

fn normalize_node_modules_path(path: &str) -> String {
    path.trim_start_matches("./")
        .trim_end_matches('/')
        .to_string()
}

const MAX_CARGO_LOCK_BYTES: usize = 10 * 1024 * 1024;

#[derive(Deserialize)]
struct CargoLockFile {
    package: Option<Vec<CargoPackage>>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
}

pub fn parse_cargo_lock_packages(
    toml_content: &str,
) -> Result<BTreeMap<String, PackageEntry>, LockfileError> {
    if toml_content.len() > MAX_CARGO_LOCK_BYTES {
        return Err(LockfileError::InvalidData(format!(
            "Cargo.lock exceeds maximum size of {} bytes (got {})",
            MAX_CARGO_LOCK_BYTES,
            toml_content.len()
        )));
    }

    let parsed: CargoLockFile =
        toml::from_str(toml_content).map_err(|e| LockfileError::InvalidToml(e.to_string()))?;

    let packages = parsed.package.unwrap_or_default();
    let mut out = BTreeMap::new();

    for pkg in packages {
        let name = pkg.name.ok_or_else(|| {
            LockfileError::InvalidData("cargo package missing mandatory field: name".to_string())
        })?;
        let version = pkg.version.ok_or_else(|| {
            LockfileError::InvalidData("cargo package missing mandatory field: version".to_string())
        })?;

        if name.is_empty() || version.is_empty() {
            return Err(LockfileError::InvalidData(
                "cargo package has empty name or version".to_string(),
            ));
        }

        let integrity = match pkg.checksum {
            Some(c) => {
                let hex = c.to_lowercase();
                if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    return Err(LockfileError::InvalidData(format!(
                        "invalid cargo checksum for {name}@{version}: expected 64 hex chars, got `{c}`",
                    )));
                }
                Some(format!("sha256:{hex}"))
            }
            None => None,
        };
        let resolved = pkg.source.clone();

        let entry = PackageEntry {
            name: name.clone(),
            version: version.clone(),
            integrity,
            resolved,
            is_dev: false,
        };

        let key = format!("cargo/{}@{}", name, version);
        if let Some(prev) = out.get(&key)
            && prev != &entry
        {
            return Err(LockfileError::InvalidData(format!(
                "duplicate cargo package entry for {key} with differing data",
            )));
        }
        out.insert(key, entry);
    }

    Ok(out)
}

const MAX_REQUIREMENTS_TXT_BYTES: usize = 10 * 1024 * 1024;

/// Parse a pinned requirements.txt file (PEP 508 / pip requirements format).
/// Fail-closed rules:
/// - Size cap 10 MiB.
/// - Unpinned specifications (e.g. `foo>=1.0`, `bar`, `baz~=2.0`, `qux!=1.1`) fail closed
///   with line-numbered errors listing every unpinned line.
/// - Valid lines must have exact pinned version `name == version` (or `name==version`).
/// - Optional `--hash=sha256:<hex>` is parsed and validated (64 hex characters).
/// - Comments (`#...`), blank lines, and options like `--index-url`, `--extra-index-url`, `-r` are skipped.
pub fn parse_requirements_txt_packages(
    content: &str,
) -> Result<BTreeMap<String, PackageEntry>, LockfileError> {
    if content.len() > MAX_REQUIREMENTS_TXT_BYTES {
        return Err(LockfileError::InvalidData(format!(
            "requirements.txt exceeds maximum size of {} bytes (got {})",
            MAX_REQUIREMENTS_TXT_BYTES,
            content.len()
        )));
    }

    let mut packages = BTreeMap::new();
    let mut unpinned_errors = Vec::new();

    // Process line continuations (lines ending in `\`)
    let mut raw_lines = Vec::new();
    let mut current_line = String::new();
    let mut start_line_num = 1;

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();
        if let Some(without_slash) = trimmed.strip_suffix('\\') {
            if current_line.is_empty() {
                start_line_num = line_num;
            }
            current_line.push_str(without_slash.trim_end());
            current_line.push(' ');
        } else {
            if current_line.is_empty() {
                start_line_num = line_num;
                raw_lines.push((start_line_num, trimmed.to_string()));
            } else {
                current_line.push_str(trimmed);
                raw_lines.push((start_line_num, current_line.clone()));
                current_line.clear();
            }
        }
    }
    if !current_line.is_empty() {
        raw_lines.push((start_line_num, current_line));
    }

    for (line_num, raw_line) in raw_lines {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let code_part = match line.split_once('#') {
            Some((before, _)) => before.trim(),
            None => line,
        };
        if code_part.is_empty() {
            continue;
        }

        // Skip standalone flags: -i, --index-url, --extra-index-url, -r, --requirement, -f, --find-links, etc.
        if code_part.starts_with('-') && !code_part.starts_with("--hash") {
            continue;
        }

        let tokens: Vec<&str> = code_part.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        let mut hashes = Vec::new();
        let mut spec_tokens = Vec::new();

        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i];
            if let Some(h) = tok.strip_prefix("--hash=") {
                let h_clean = h.strip_prefix("sha256:").unwrap_or(h).trim();
                hashes.push(h_clean.to_string());
                i += 1;
            } else if tok == "--hash" {
                if i + 1 < tokens.len() {
                    let next = tokens[i + 1];
                    let h_clean = next.strip_prefix("sha256:").unwrap_or(next).trim();
                    hashes.push(h_clean.to_string());
                    i += 2;
                } else {
                    return Err(LockfileError::InvalidData(format!(
                        "line {line_num}: `--hash` option missing hash value"
                    )));
                }
            } else {
                spec_tokens.push(tok);
                i += 1;
            }
        }

        let spec = spec_tokens.join("");
        if spec.is_empty() {
            continue;
        }

        // Separate environment marker `; ...` before range checking the requirement
        let (req_spec, _marker) = match spec.split_once(';') {
            Some((before, after)) => (before.trim(), Some(after.trim())),
            None => (spec.as_str(), None),
        };

        if req_spec.is_empty() {
            continue;
        }

        let has_range_op = req_spec.contains(">=")
            || req_spec.contains("<=")
            || req_spec.contains('>')
            || req_spec.contains('<')
            || req_spec.contains("~=")
            || req_spec.contains("!=")
            || req_spec.contains("===")
            || req_spec.contains('@');

        if has_range_op {
            unpinned_errors.push(format!("  line {line_num}: unpinned range `{req_spec}`"));
            continue;
        }

        if let Some((name_part, ver_part)) = req_spec.split_once("==") {
            let raw_name = name_part.trim();
            let ver = ver_part.trim();

            if raw_name.is_empty() || ver.is_empty() {
                unpinned_errors.push(format!(
                    "  line {line_num}: invalid requirement `{req_spec}`"
                ));
                continue;
            }

            // Extract base package name and extras if present: `foo[extra1,extra2]`
            let name = if let Some((base, extras_part)) = raw_name.split_once('[') {
                if !extras_part.ends_with(']') {
                    return Err(LockfileError::InvalidData(format!(
                        "line {line_num}: unclosed extras bracket in `{raw_name}`"
                    )));
                }
                base.trim()
            } else {
                raw_name
            };

            if !crate::version::validate_pypi_name(name) {
                return Err(LockfileError::InvalidData(format!(
                    "line {line_num}: invalid PyPI package name `{name}`"
                )));
            }

            if crate::version::Pep440Version::parse(ver).is_err() {
                return Err(LockfileError::InvalidData(format!(
                    "line {line_num}: invalid PEP 440 version `{ver}` in `{req_spec}`"
                )));
            }

            let mut formatted_hashes = Vec::new();
            for h in hashes {
                let hex = h.to_lowercase();
                if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(LockfileError::InvalidData(format!(
                        "line {line_num}: invalid sha256 hash length (expected 64 hex chars, got `{h}`)"
                    )));
                }
                formatted_hashes.push(format!("sha256:{hex}"));
            }
            let integrity = if formatted_hashes.is_empty() {
                None
            } else {
                Some(formatted_hashes.join(" "))
            };

            let canon_name = crate::version::canonicalize_name(name);
            packages.insert(
                canon_name,
                PackageEntry {
                    name: name.to_string(),
                    version: ver.to_string(),
                    integrity,
                    resolved: None,
                    is_dev: false,
                },
            );
        } else {
            unpinned_errors.push(format!(
                "  line {line_num}: unpinned package `{spec}` (must use `name==version`)"
            ));
        }
    }

    if !unpinned_errors.is_empty() {
        return Err(LockfileError::InvalidData(format!(
            "requirements.txt contains unpinned dependencies (all packages must be pinned with `==`):\n{}",
            unpinned_errors.join("\n")
        )));
    }

    Ok(packages)
}

pub fn compute_delta_from_maps(
    base_pkgs: &BTreeMap<String, PackageEntry>,
    head_pkgs: &BTreeMap<String, PackageEntry>,
) -> LockfileDelta {
    let mut added = Vec::new();
    let mut upgraded = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged_count = 0;

    let mut base_iter = base_pkgs.iter().peekable();
    let mut head_iter = head_pkgs.iter().peekable();

    loop {
        match (base_iter.peek(), head_iter.peek()) {
            (Some(&(b_key, b_val)), Some(&(h_key, h_val))) => match b_key.cmp(h_key) {
                std::cmp::Ordering::Less => {
                    removed.push((*b_val).clone());
                    base_iter.next();
                }
                std::cmp::Ordering::Greater => {
                    added.push((*h_val).clone());
                    head_iter.next();
                }
                std::cmp::Ordering::Equal => {
                    if b_val.version != h_val.version || b_val.integrity != h_val.integrity {
                        upgraded.push(PackageUpgrade {
                            name: h_val.name.clone(),
                            old_version: b_val.version.clone(),
                            new_version: h_val.version.clone(),
                            old_integrity: b_val.integrity.clone(),
                            new_integrity: h_val.integrity.clone(),
                            resolved: h_val.resolved.clone(),
                            is_dev: h_val.is_dev,
                        });
                    } else {
                        unchanged_count += 1;
                    }
                    base_iter.next();
                    head_iter.next();
                }
            },
            (Some(&(_, b_val)), None) => {
                removed.push((*b_val).clone());
                base_iter.next();
            }
            (None, Some(&(_, h_val))) => {
                added.push((*h_val).clone());
                head_iter.next();
            }
            (None, None) => break,
        }
    }

    LockfileDelta {
        added,
        upgraded,
        removed,
        unchanged_count,
    }
}

pub fn compute_lockfile_delta(
    base_json: &str,
    head_json: &str,
) -> Result<LockfileDelta, LockfileError> {
    let base_pkgs = parse_lockfile_packages(base_json)?;
    let head_pkgs = parse_lockfile_packages(head_json)?;
    Ok(compute_delta_from_maps(&base_pkgs, &head_pkgs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_json_has_no_source_chain() {
        use std::error::Error;
        // The Display already embeds the serde detail; a `source()` would
        // make `{e:#}` in main print the detail twice.
        let err =
            LockfileError::from(serde_json::from_str::<serde_json::Value>("{{{{").unwrap_err());
        assert!(err.source().is_none(), "source must be None: {err:#}");
    }

    #[test]
    fn parses_v3_lockfile() {
        let json = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-app",
                    "version": "1.0.0"
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
                    "dev": false
                },
                "node_modules/@scope/pkg": {
                    "version": "2.0.0",
                    "integrity": "sha512-test",
                    "dev": true
                }
            }
        }"#;

        let pkgs = parse_lockfile_packages(json).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs.get("node_modules/lodash").unwrap().name, "lodash");
        assert_eq!(pkgs.get("node_modules/lodash").unwrap().version, "4.17.21");
        assert!(!pkgs.get("node_modules/lodash").unwrap().is_dev);

        assert_eq!(
            pkgs.get("node_modules/@scope/pkg").unwrap().name,
            "@scope/pkg"
        );
        assert_eq!(
            pkgs.get("node_modules/@scope/pkg").unwrap().version,
            "2.0.0"
        );
        assert!(pkgs.get("node_modules/@scope/pkg").unwrap().is_dev);
    }

    #[test]
    fn parses_v1_lockfile() {
        let json = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "integrity": "sha512-expresshash",
                    "dev": false,
                    "dependencies": {
                        "accepts": {
                            "version": "1.3.8",
                            "integrity": "sha512-acceptshash"
                        }
                    }
                }
            }
        }"#;

        let pkgs = parse_lockfile_packages(json).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs.get("node_modules/express").unwrap().version, "4.18.2");
        assert_eq!(
            pkgs.get("node_modules/express/node_modules/accepts")
                .unwrap()
                .version,
            "1.3.8"
        );
    }

    #[test]
    fn computes_delta_across_lockfiles() {
        let base_json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/unchanged": { "version": "1.0.0", "integrity": "sha512-same" },
                "node_modules/upgraded": { "version": "1.0.0", "integrity": "sha512-old" },
                "node_modules/removed": { "version": "0.9.0", "integrity": "sha512-del" }
            }
        }"#;

        let head_json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/unchanged": { "version": "1.0.0", "integrity": "sha512-same" },
                "node_modules/upgraded": { "version": "1.1.0", "integrity": "sha512-new" },
                "node_modules/added": { "version": "2.0.0", "integrity": "sha512-add", "dev": true }
            }
        }"#;

        let delta = compute_lockfile_delta(base_json, head_json).unwrap();
        assert_eq!(delta.unchanged_count, 1);
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.added[0].name, "added");
        assert_eq!(delta.added[0].version, "2.0.0");
        assert!(delta.added[0].is_dev);

        assert_eq!(delta.upgraded.len(), 1);
        assert_eq!(delta.upgraded[0].name, "upgraded");
        assert_eq!(delta.upgraded[0].old_version, "1.0.0");
        assert_eq!(delta.upgraded[0].new_version, "1.1.0");

        assert_eq!(delta.removed.len(), 1);
        assert_eq!(delta.removed[0].name, "removed");
        assert_eq!(delta.total_changed(), 3);
    }

    #[test]
    fn v1_recursion_depth_limit_enforced() {
        // Build a deeply nested structure exceeding MAX_LOCKFILE_RECURSION_DEPTH (32)
        let mut curr = serde_json::json!({
            "version": "1.0.0"
        });

        for i in 0..35 {
            curr = serde_json::json!({
                "version": "1.0.0",
                "dependencies": {
                    format!("dep-{}", i): curr
                }
            });
        }

        let root = serde_json::json!({
            "lockfileVersion": 1,
            "dependencies": {
                "dep-root": curr
            }
        });

        let json = serde_json::to_string(&root).unwrap();
        let pkgs = parse_lockfile_packages(&json).unwrap();
        // Should parse up to the limit (33 levels including root: depth 0 to 32)
        assert_eq!(pkgs.len(), MAX_LOCKFILE_RECURSION_DEPTH + 1);
    }

    #[test]
    fn delta_is_empty_and_integrity_only_upgrade() {
        let empty_delta = LockfileDelta {
            added: Vec::new(),
            upgraded: Vec::new(),
            removed: Vec::new(),
            unchanged_count: 5,
        };
        assert!(empty_delta.is_empty());

        let mut delta_with_add = empty_delta.clone();
        delta_with_add.added.push(PackageEntry {
            name: "pkg".into(),
            version: "1.0.0".into(),
            integrity: None,
            resolved: None,
            is_dev: false,
        });
        assert!(!delta_with_add.is_empty());

        let mut delta_with_up = empty_delta.clone();
        delta_with_up.upgraded.push(PackageUpgrade {
            name: "pkg".into(),
            old_version: "1.0.0".into(),
            new_version: "1.0.0".into(),
            old_integrity: Some("sha512-old".into()),
            new_integrity: Some("sha512-new".into()),
            resolved: None,
            is_dev: false,
        });
        assert!(!delta_with_up.is_empty());

        let mut delta_with_rem = empty_delta.clone();
        delta_with_rem.removed.push(PackageEntry {
            name: "pkg".into(),
            version: "1.0.0".into(),
            integrity: None,
            resolved: None,
            is_dev: false,
        });
        assert!(!delta_with_rem.is_empty());

        let base_json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/tampered": { "version": "1.0.0", "integrity": "sha512-old" }
            }
        }"#;
        let head_json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/tampered": { "version": "1.0.0", "integrity": "sha512-new" }
            }
        }"#;
        let delta = compute_lockfile_delta(base_json, head_json).unwrap();
        assert_eq!(delta.upgraded.len(), 1);
        assert_eq!(delta.upgraded[0].name, "tampered");
        assert_eq!(
            delta.upgraded[0].old_integrity.as_deref(),
            Some("sha512-old")
        );
        assert_eq!(
            delta.upgraded[0].new_integrity.as_deref(),
            Some("sha512-new")
        );
    }

    #[test]
    fn parses_cargo_lock_registry_dep() {
        let toml = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
"#;
        let pkgs = parse_cargo_lock_packages(toml).unwrap();
        assert_eq!(pkgs.len(), 1);
        let entry = pkgs.get("cargo/serde@1.0.210").unwrap();
        assert_eq!(entry.name, "serde");
        assert_eq!(entry.version, "1.0.210");
        assert_eq!(
            entry.integrity.as_deref(),
            Some("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        );
        assert_eq!(
            entry.resolved.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert!(!entry.is_dev);
    }

    #[test]
    fn parses_cargo_lock_git_and_path_deps() {
        let toml = r#"
version = 4

[[package]]
name = "my-git-dep"
version = "0.1.0"
source = "git+https://github.com/example/repo#abc123"

[[package]]
name = "my-path-dep"
version = "0.2.0"

[[package]]
name = "regular"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
"#;
        let pkgs = parse_cargo_lock_packages(toml).unwrap();
        assert_eq!(pkgs.len(), 3);

        let git = pkgs.get("cargo/my-git-dep@0.1.0").unwrap();
        assert_eq!(git.integrity, None);
        assert_eq!(
            git.resolved.as_deref(),
            Some("git+https://github.com/example/repo#abc123")
        );

        let path = pkgs.get("cargo/my-path-dep@0.2.0").unwrap();
        assert_eq!(path.integrity, None);
        assert_eq!(path.resolved, None);

        let reg = pkgs.get("cargo/regular@1.0.0").unwrap();
        assert_eq!(
            reg.integrity.as_deref(),
            Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        );
        assert!(reg.resolved.is_some());
    }

    #[test]
    fn cargo_lock_delta_via_parse_pair() {
        let base_toml = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

[[package]]
name = "unchanged"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

[[package]]
name = "removed"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
"#;

        let head_toml = r#"
version = 4

[[package]]
name = "serde"
version = "1.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"

[[package]]
name = "unchanged"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

[[package]]
name = "added"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
"#;

        let base = parse_cargo_lock_packages(base_toml).unwrap();
        let head = parse_cargo_lock_packages(head_toml).unwrap();
        let delta = compute_delta_from_maps(&base, &head);

        // With `cargo/name@version` keys, a version bump is not an `upgraded` but
        // a `removed` old key + `added` new key. Both are still evaluated in CI.
        assert_eq!(delta.added.len(), 2, "serde 1.1.0 + added");
        assert_eq!(delta.removed.len(), 2, "serde 1.0.0 + removed");
        assert_eq!(delta.upgraded.len(), 0);
        assert_eq!(delta.unchanged_count, 1);
        assert!(
            delta
                .added
                .iter()
                .any(|e| e.name == "serde" && e.version == "1.1.0")
        );
        assert!(delta.added.iter().any(|e| e.name == "added"));

        // Integrity-only change on same key is an `upgraded`.
        let base2 = parse_cargo_lock_packages(
            r#"
version = 4
[[package]]
name = "tampered"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#,
        )
        .unwrap();
        let head2 = parse_cargo_lock_packages(
            r#"
version = 4
[[package]]
name = "tampered"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
        )
        .unwrap();
        let delta2 = compute_delta_from_maps(&base2, &head2);
        assert_eq!(delta2.upgraded.len(), 1);
        assert_eq!(delta2.upgraded[0].name, "tampered");
        assert_eq!(delta2.unchanged_count, 0);
    }

    #[test]
    fn cargo_lock_invalid_toml_fails_closed() {
        let bad = "[[package\nname = \"oops\"";
        let err = parse_cargo_lock_packages(bad).unwrap_err();
        assert!(
            matches!(err, LockfileError::InvalidToml(_)),
            "malformed TOML must be InvalidToml, got {err:?}"
        );

        let empty_pkg = r#"
version = 4

[[package]]
name = "no-version"
"#;
        let err2 = parse_cargo_lock_packages(empty_pkg).unwrap_err();
        match err2 {
            LockfileError::InvalidData(_) => {}
            other => panic!("expected InvalidData for missing version, got {other:?}"),
        }

        // Empty name or empty version must fail closed (|| vs && mutant).
        let empty_name = r#"
version = 4
[[package]]
name = ""
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#;
        assert!(matches!(
            parse_cargo_lock_packages(empty_name).unwrap_err(),
            LockfileError::InvalidData(_)
        ));
        let empty_version = r#"
version = 4
[[package]]
name = "x"
version = ""
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#;
        assert!(matches!(
            parse_cargo_lock_packages(empty_version).unwrap_err(),
            LockfileError::InvalidData(_)
        ));

        // Size cap: > MAX fails, == MAX passes. Kills *→+ and >→>= mutants.
        assert_eq!(
            MAX_CARGO_LOCK_BYTES, 10_485_760,
            "MAX must be 10 MiB; hard literal kills *→+ mutants"
        );
        let header = "version = 4\n";
        let mut at_limit_toml = String::with_capacity(MAX_CARGO_LOCK_BYTES);
        at_limit_toml.push_str(header);
        let remaining = MAX_CARGO_LOCK_BYTES - at_limit_toml.len() - 2;
        at_limit_toml.push('#');
        at_limit_toml.push_str(&"a".repeat(remaining));
        at_limit_toml.push('\n');
        assert_eq!(at_limit_toml.len(), MAX_CARGO_LOCK_BYTES);
        let at_limit_res = parse_cargo_lock_packages(&at_limit_toml);
        assert!(
            at_limit_res.is_ok(),
            "exactly MAX bytes must not be rejected by size cap (> vs >= mutant), got {at_limit_res:?}"
        );
        let oversized = format!("{at_limit_toml}a");
        assert_eq!(oversized.len(), MAX_CARGO_LOCK_BYTES + 1);
        let err3 = parse_cargo_lock_packages(&oversized).unwrap_err();
        match err3 {
            LockfileError::InvalidData(msg) => assert!(msg.contains("exceeds maximum size")),
            other => panic!("expected InvalidData for oversized, got {other:?}"),
        }

        // Checksum validation: wrong length vs bad hex must each fail (|| vs &&).
        let bad_len = r#"
version = 4
[[package]]
name = "bad"
version = "1.0.0"
checksum = "AAA"
"#;
        assert!(matches!(
            parse_cargo_lock_packages(bad_len).unwrap_err(),
            LockfileError::InvalidData(_)
        ));
        let bad_hex = "g".repeat(64);
        let bad_hex_toml = format!(
            "version = 4\n[[package]]\nname = \"bad\"\nversion = \"1.0.0\"\nchecksum = \"{bad_hex}\"\n"
        );
        assert!(matches!(
            parse_cargo_lock_packages(&bad_hex_toml).unwrap_err(),
            LockfileError::InvalidData(_)
        ));

        // Duplicate with differing data must fail ( != vs == mutant).
        let dup_diff = r#"
version = 4
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#;
        assert!(matches!(
            parse_cargo_lock_packages(dup_diff).unwrap_err(),
            LockfileError::InvalidData(_)
        ));
        // Same duplicate with identical data is ok (last wins).
        let dup_same = r#"
version = 4
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#;
        assert!(parse_cargo_lock_packages(dup_same).is_ok());
    }

    #[test]
    fn parses_pinned_requirements_txt_with_hashes() {
        let content = r#"
# Core dependencies
requests==2.31.0 \
    --hash=sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

Flask==3.0.0 --hash sha256:1111111111111111111111111111111111111111111111111111111111111111
urllib3==2.1.0 # trailing comment
"#;
        let pkgs = parse_requirements_txt_packages(content).unwrap();
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs["requests"].version, "2.31.0");
        assert_eq!(
            pkgs["requests"].integrity.as_deref(),
            Some("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        );
        assert_eq!(pkgs["flask"].name, "Flask");
        assert_eq!(pkgs["flask"].version, "3.0.0");
        assert_eq!(pkgs["urllib3"].integrity, None);
    }

    #[test]
    fn rejects_unpinned_requirements_with_line_numbers() {
        let content = "requests>=2.0.0\nflask==3.0.0\npytest~=7.0\nblack\n";
        let err = parse_requirements_txt_packages(content)
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 1: unpinned range `requests>=2.0.0`"));
        assert!(err.contains("line 3: unpinned range `pytest~=7.0`"));
        assert!(err.contains("line 4: unpinned package `black`"));
    }

    #[test]
    fn requirements_txt_flags_and_edge_cases() {
        let content = r#"
# Flags to ignore
-i https://pypi.org/simple
--extra-index-url https://example.com/pypi
-r base.txt
--requirement other.txt
-f /path/to/wheels

# Empty lines and comments with whitespace
   # leading space comment
   
requests==2.31.0 \
    --hash sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 \
    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111
"#;
        let pkgs = parse_requirements_txt_packages(content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs["requests"].version, "2.31.0");

        // Trailing line continuation with no trailing newline
        let no_nl = "urllib3==2.1.0 \\\n  --hash sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let pkgs2 = parse_requirements_txt_packages(no_nl).unwrap();
        assert_eq!(pkgs2["urllib3"].version, "2.1.0");

        // Missing hash value after `--hash`
        let missing_hash = "requests==2.31.0 --hash";
        let err = parse_requirements_txt_packages(missing_hash).unwrap_err();
        assert!(
            matches!(err, LockfileError::InvalidData(msg) if msg.contains("missing hash value"))
        );

        // Exact MAX_REQUIREMENTS_TXT_BYTES size boundary test
        let header = "requests==2.31.0\n";
        let mut at_limit = String::with_capacity(MAX_REQUIREMENTS_TXT_BYTES);
        at_limit.push_str(header);
        let remaining = MAX_REQUIREMENTS_TXT_BYTES - at_limit.len() - 2;
        at_limit.push('#');
        at_limit.push_str(&"a".repeat(remaining));
        at_limit.push('\n');
        assert_eq!(at_limit.len(), MAX_REQUIREMENTS_TXT_BYTES);
        assert!(parse_requirements_txt_packages(&at_limit).is_ok());

        let over_limit = format!("{at_limit}a");
        assert_eq!(over_limit.len(), MAX_REQUIREMENTS_TXT_BYTES + 1);
        let err_over = parse_requirements_txt_packages(&over_limit).unwrap_err();
        assert!(
            matches!(err_over, LockfileError::InvalidData(msg) if msg.contains("exceeds maximum size"))
        );

        assert_eq!(MAX_REQUIREMENTS_TXT_BYTES, 10 * 1024 * 1024);

        let blanks_and_comments =
            "\n\n# comment 1\n   # comment 2\n\nflask==3.0.0\n\n# trailing comment\n";
        let parsed = parse_requirements_txt_packages(blanks_and_comments).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed["flask"].version, "3.0.0");
    }
}
