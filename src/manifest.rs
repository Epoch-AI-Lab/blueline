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

/// Minimal typed view of a packed `Cargo.toml` (the file cargo-package writes
/// into a `.crate`). Only build/execution attack surface is kept; everything
/// else is ignored. Dependency requirement values may be plain strings or
/// detail tables (`{ version = "1", features = [...] }`); both are accepted.
#[derive(Debug, Default, Deserialize)]
pub struct PackedCargoToml {
    #[serde(default)]
    pub package: BTreeMap<String, toml::Value>,
    #[serde(default, rename = "bin")]
    pub bins: Vec<CargoBinTarget>,
    #[serde(default)]
    pub dependencies: BTreeMap<String, toml::Value>,
    #[serde(default, rename = "dev-dependencies")]
    pub dev_dependencies: BTreeMap<String, toml::Value>,
    #[serde(default, rename = "build-dependencies")]
    pub build_dependencies: BTreeMap<String, toml::Value>,
    #[serde(default)]
    pub features: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CargoBinTarget {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

impl PackedCargoToml {
    /// A `[package]` string field (`name`, `version`, ...), when present.
    pub fn package_field(&self, key: &str) -> Option<String> {
        self.package.get(key).and_then(|v| match v {
            toml::Value::String(s) => Some(s.clone()),
            _ => None,
        })
    }

    /// Custom build script (`[package] build`): executes during `cargo build`.
    pub fn build(&self) -> Option<String> {
        self.package_field("build")
    }

    /// Native library linkage declaration (`[package] links`).
    pub fn links(&self) -> Option<String> {
        self.package_field("links")
    }

    /// Declared `[[bin]]` target names (targets without an explicit `name`
    /// are omitted but still counted in `bins.len()`).
    pub fn bin_names(&self) -> Vec<String> {
        self.bins.iter().filter_map(|b| b.name.clone()).collect()
    }

    /// Project the cargo manifest onto the npm-shaped delta engine so the
    /// existing diff/heuristic machinery works unchanged. `[dependencies]`
    /// drive runtime dependency deltas; dev/build dependencies surface through
    /// the peer/optional slots (approximation — see PR notes). Cargo has no
    /// npm-style lifecycle scripts, so `scripts` stays empty.
    pub fn manifest_view(&self) -> PackageJson {
        let map_deps = |m: &BTreeMap<String, toml::Value>| -> BTreeMap<String, String> {
            m.iter()
                .map(|(k, v)| (k.clone(), dep_req_display(v)))
                .collect()
        };
        PackageJson {
            name: self.package_field("name").unwrap_or_default(),
            version: self.package_field("version").unwrap_or_default(),
            gypfile: Some(
                self.build().is_some() || self.links().is_some() || !self.bins.is_empty(),
            ),
            scripts: BTreeMap::new(),
            dependencies: map_deps(&self.dependencies),
            optional_dependencies: map_deps(&self.build_dependencies),
            peer_dependencies: map_deps(&self.dev_dependencies),
        }
    }
}

fn dep_req_display(req: &toml::Value) -> String {
    match req {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(t) => t
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| "(table)".to_string()),
        _ => "(table)".to_string(),
    }
}

/// Read and parse a packed `Cargo.toml` from an extracted `.crate`, under the
/// same size cap as every other untrusted manifest.
pub fn read_packed_cargo_toml(path: &Path) -> Result<PackedCargoToml, BluelineError> {
    let display_path = path.display().to_string();
    let raw = fs::read_to_string(path).map_err(|e| {
        BluelineError::Manifest(
            display_path.clone(),
            format!("cannot read packed Cargo.toml: {e}"),
        )
    })?;
    if raw.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(BluelineError::Manifest(
            display_path,
            format!("manifest exceeds cap of {MAX_MANIFEST_BYTES} bytes"),
        ));
    }
    toml::from_str(&raw)
        .map_err(|e| BluelineError::Manifest(display_path, format!("invalid TOML: {e}")))
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

    fn cargo_example() -> &'static str {
        r#"
[package]
name = "serde-json"
version = "1.0.210"
build = "custom-build.rs"
links = "zlib"

[[bin]]
name = "cli-tool"

[[bin]]
path = "src/main.rs"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
log = "0.4"

[dev-dependencies]
tempfile = "3"

[build-dependencies]
cc = "1.0"

[features]
default = ["std"]
std = []
"#
    }

    #[test]
    fn parses_packed_cargo_toml_surface() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        fs::write(&path, cargo_example()).unwrap();
        let m = read_packed_cargo_toml(&path).unwrap();

        assert_eq!(m.package_field("name").as_deref(), Some("serde-json"));
        assert_eq!(m.build().as_deref(), Some("custom-build.rs"));
        assert_eq!(m.links().as_deref(), Some("zlib"));
        assert_eq!(m.bins.len(), 2);
        assert_eq!(m.bin_names(), vec!["cli-tool".to_string()]);
        assert!(m.dependencies.contains_key("serde"));
        assert!(m.dev_dependencies.contains_key("tempfile"));
        assert!(m.build_dependencies.contains_key("cc"));
        assert_eq!(m.features.get("default"), Some(&vec!["std".to_string()]));
    }

    #[test]
    fn projects_cargo_manifest_onto_npm_view() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        fs::write(&path, cargo_example()).unwrap();
        let view = read_packed_cargo_toml(&path).unwrap().manifest_view();

        assert_eq!(view.name, "serde-json");
        assert_eq!(view.version, "1.0.210");
        assert!(view.scripts.is_empty());
        assert_eq!(
            view.dependencies.get("serde").map(String::as_str),
            Some("1.0")
        );
        assert_eq!(
            view.dependencies.get("log").map(String::as_str),
            Some("0.4")
        );
        assert!(view.peer_dependencies.contains_key("tempfile"));
        assert!(view.optional_dependencies.contains_key("cc"));
        assert_eq!(view.gypfile, Some(true));
    }

    #[test]
    fn plain_dependency_strings_survive_projection() {
        let m: PackedCargoToml =
            toml::from_str("[package]\nname=\"x\"\n\n[dependencies]\nlog = \"0.4\"\n").unwrap();
        assert_eq!(
            m.manifest_view()
                .dependencies
                .get("log")
                .map(String::as_str),
            Some("0.4")
        );
    }

    #[test]
    fn rejects_invalid_cargo_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        fs::write(&path, "[package\nbroken").unwrap();
        assert!(read_packed_cargo_toml(&path).is_err());
    }

    #[test]
    fn missing_cargo_toml_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_packed_cargo_toml(&dir.path().join("nope.toml")).is_err());
    }
}
