use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::BluelineError;

/// Cap on the extracted package.json before parsing (untrusted input).
const MAX_MANIFEST_BYTES: u64 = 10 * 1024 * 1024;

/// npm lifecycle scripts that execute during `npm install` or build.
const LIFECYCLE_SCRIPTS: [&str; 22] = [
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
    "prepack",
    "postpack",
    "prepublish",
    "prepublishOnly",
    "preshrinkwrap",
    "shrinkwrap",
    "postshrinkwrap",
    "preversion",
    "version",
    "postversion",
    "prestop",
    "stop",
    "poststop",
    "prerestart",
    "restart",
    "postrestart",
];

/// Typed view of the extracted `package.json`. The `scripts` / dependency
/// fields are attack surface — parsed strictly, never executed. The unused
/// fields feed the Phase 1 heuristic (maintainer/dep/script delta); they are
/// parsed now so the type is stable and validated.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct PackageJson {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub gypfile: Option<bool>,
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
    use std::io::Read;
    let display_path = path.display().to_string();
    let file = fs::File::open(path)
        .map_err(|e| BluelineError::Manifest(display_path.clone(), format!("cannot open: {e}")))?;
    let mut bytes = Vec::new();
    let mut handle = file.take(MAX_MANIFEST_BYTES + 1);
    handle
        .read_to_end(&mut bytes)
        .map_err(|e| BluelineError::Manifest(display_path.clone(), format!("cannot read: {e}")))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(BluelineError::Manifest(
            display_path,
            format!("manifest exceeds cap of {MAX_MANIFEST_BYTES} bytes"),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| BluelineError::Manifest(display_path, format!("invalid JSON: {e}")))
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
        let m: PackageJson = serde_json::from_str(
            r#"{"scripts":{"preinstall":"a","postinstall":"b","prepublishOnly":"c","prepare":"d","test":"e"}}"#,
        )
        .unwrap();
        assert_eq!(
            m.lifecycle_scripts(),
            vec!["preinstall", "postinstall", "prepare", "prepublishOnly"]
        );
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

    #[test]
    fn accepts_small_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        // Above the false-equivalent cap (10 + 1024 + 1024) but below the real one.
        let body = format!(
            "{{\"name\":\"x\",\"description\":\"{}\"}}",
            "a".repeat(4000)
        );
        fs::write(&path, &body).unwrap();
        assert!(read_package_json(&path).is_ok());
    }

    #[test]
    fn rejects_above_manifest_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        let n = 10 * 1024 * 1024 - 7;
        let body = format!("{{\"x\":\"{}\"}}", "a".repeat(n));
        assert_eq!(body.len(), 10 * 1024 * 1024 + 1);
        fs::write(&path, &body).unwrap();
        let err = read_package_json(&path).unwrap_err();
        assert!(err.to_string().contains("manifest exceeds cap"));
    }

    #[test]
    fn accepts_at_manifest_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        let n = 10 * 1024 * 1024 - 8;
        let body = format!("{{\"x\":\"{}\"}}", "a".repeat(n));
        assert_eq!(body.len(), 10 * 1024 * 1024);
        fs::write(&path, &body).unwrap();
        assert!(read_package_json(&path).is_ok());
    }
}
