use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::BluelineError;

/// Cap on the extracted package.json before parsing (untrusted input).
const MAX_MANIFEST_BYTES: u64 = 10 * 1024 * 1024;

/// npm lifecycle scripts that execute during `npm install`.
const LIFECYCLE_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Typed view of the extracted `package.json`. The `scripts` / dependency
/// fields are attack surface — parsed strictly, never executed. The unused
/// fields feed the Phase 1 heuristic (maintainer/dep/script delta); they are
/// parsed now so the type is stable and validated.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct PackageJson {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub scripts: BTreeMap<String, String>,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub peer_dependencies: BTreeMap<String, String>,
}

impl PackageJson {
    /// Lifecycle scripts that would run on a plain `npm install`.
    pub fn lifecycle_scripts(&self) -> Vec<String> {
        LIFECYCLE_SCRIPTS
            .iter()
            .filter(|key| self.scripts.contains_key(**key))
            .map(|key| key.to_string())
            .collect()
    }
}

pub fn read_package_json(path: &Path) -> Result<PackageJson, BluelineError> {
    let metadata = fs::metadata(path)
        .map_err(|e| BluelineError::Manifest(format!("{:?}", path), format!("cannot stat: {e}")))?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(BluelineError::Manifest(
            format!("{:?}", path),
            format!(
                "manifest is {} bytes, exceeding cap {MAX_MANIFEST_BYTES}",
                metadata.len()
            ),
        ));
    }
    let bytes = fs::read(path)
        .map_err(|e| BluelineError::Manifest(format!("{:?}", path), format!("cannot read: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| BluelineError::Manifest(format!("{:?}", path), format!("invalid JSON: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_manifest() {
        let m: PackageJson = serde_json::from_str(r#"{"name":"x","version":"1.0.0"}"#).unwrap();
        assert_eq!(m.name, "x");
        assert_eq!(m.version, "1.0.0");
        assert!(m.scripts.is_empty());
        assert!(m.lifecycle_scripts().is_empty());
    }

    #[test]
    fn flags_lifecycle_scripts() {
        let m: PackageJson =
            serde_json::from_str(r#"{"scripts":{"preinstall":"a","postinstall":"b","test":"c"}}"#)
                .unwrap();
        assert_eq!(m.lifecycle_scripts(), vec!["preinstall", "postinstall"]);
    }

    #[test]
    fn ignores_unknown_fields() {
        let m: PackageJson =
            serde_json::from_str(r#"{"name":"x","whatever":{"deep":[1,2,3]}}"#).unwrap();
        assert_eq!(m.name, "x");
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(serde_json::from_str::<PackageJson>(r#"{"name":"unclosed"#).is_err());
    }

    #[test]
    fn read_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        fs::write(&path, r#"{"version":"9.9.9"}"#).unwrap();
        let m = read_package_json(&path).unwrap();
        assert_eq!(m.version, "9.9.9");
    }

    #[test]
    fn read_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_package_json(&dir.path().join("nope.json")).unwrap_err();
        assert!(matches!(err, BluelineError::Manifest(_, _)));
    }
}
