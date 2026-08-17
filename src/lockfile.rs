use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("failed to parse lockfile JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("lockfile is missing mandatory field: {0}")]
    MissingField(&'static str),

    #[error("invalid lockfile data: {0}")]
    InvalidData(String),
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
        walk_v1_dependencies("", &raw_dependencies, &mut packages);
    } else {
        // Lockfile with neither packages nor dependencies (empty or invalid)
        if raw.lockfile_version.is_none() {
            return Err(LockfileError::MissingField("lockfileVersion"));
        }
    }

    Ok(packages)
}

fn walk_v1_dependencies(
    prefix: &str,
    deps: &BTreeMap<String, RawDependencyV1>,
    out: &mut BTreeMap<String, PackageEntry>,
) {
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
            walk_v1_dependencies(&path_key, nested, out);
        }
    }
}

fn extract_package_name_from_path(path: &str) -> String {
    let parts: Vec<&str> = path
        .split("node_modules/")
        .filter(|s| !s.is_empty())
        .collect();
    if let Some(last) = parts.last() {
        // Strip trailing slash if present
        last.trim_end_matches('/').to_string()
    } else {
        path.to_string()
    }
}

fn normalize_node_modules_path(path: &str) -> String {
    path.trim_start_matches("./")
        .trim_end_matches('/')
        .to_string()
}

pub fn compute_lockfile_delta(
    base_json: &str,
    head_json: &str,
) -> Result<LockfileDelta, LockfileError> {
    let base_pkgs = parse_lockfile_packages(base_json)?;
    let head_pkgs = parse_lockfile_packages(head_json)?;

    let mut added = Vec::new();
    let mut upgraded = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged_count = 0;

    let all_keys: BTreeSet<&String> = base_pkgs.keys().chain(head_pkgs.keys()).collect();

    for key in all_keys {
        match (base_pkgs.get(key), head_pkgs.get(key)) {
            (None, Some(new_entry)) => {
                added.push(new_entry.clone());
            }
            (Some(old_entry), None) => {
                removed.push(old_entry.clone());
            }
            (Some(old_entry), Some(new_entry)) => {
                if old_entry.version != new_entry.version
                    || old_entry.integrity != new_entry.integrity
                {
                    upgraded.push(PackageUpgrade {
                        name: new_entry.name.clone(),
                        old_version: old_entry.version.clone(),
                        new_version: new_entry.version.clone(),
                        old_integrity: old_entry.integrity.clone(),
                        new_integrity: new_entry.integrity.clone(),
                        resolved: new_entry.resolved.clone(),
                        is_dev: new_entry.is_dev,
                    });
                } else {
                    unchanged_count += 1;
                }
            }
            (None, None) => unreachable!(),
        }
    }

    Ok(LockfileDelta {
        added,
        upgraded,
        removed,
        unchanged_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
