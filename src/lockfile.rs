use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("failed to parse lockfile JSON: {0}")]
    InvalidJson(serde_json::Error),

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

    let mut base_iter = base_pkgs.iter().peekable();
    let mut head_iter = head_pkgs.iter().peekable();

    loop {
        match (base_iter.peek(), head_iter.peek()) {
            (Some(&(b_key, b_val)), Some(&(h_key, h_val))) => match b_key.cmp(h_key) {
                std::cmp::Ordering::Less => {
                    removed.push(b_val.clone());
                    base_iter.next();
                }
                std::cmp::Ordering::Greater => {
                    added.push(h_val.clone());
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
                removed.push(b_val.clone());
                base_iter.next();
            }
            (None, Some(&(_, h_val))) => {
                added.push(h_val.clone());
                head_iter.next();
            }
            (None, None) => break,
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
}
