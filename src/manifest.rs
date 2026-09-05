use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::BluelineError;
use crate::version::VersionInfo;

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

/// Byte cap on `.SRCINFO` files before parsing (untrusted input).
pub const SRCINFO_MAX_BYTES: u64 = 1024 * 1024;

/// Line cap on `.SRCINFO` files; a generated `.SRCINFO` never approaches this.
const MAX_SRCINFO_LINES: usize = 64 * 1024;

/// Static parse of a generated `.SRCINFO` (the output of
/// `makepkg --printsrcinfo`, never produced by executing a PKGBUILD here).
/// Only `key = value` lines, blank separators, and the unindented
/// `pkgbase =` / `pkgname =` section headers of the generated format are
/// accepted; everything else fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrcInfo {
    pub pkgbase: String,
    /// Validated `epoch:pkgver-pkgrel` identity in canonical form.
    pub version: String,
    /// `depends` + `makedepends` merged across all sections: dep name →
    /// the full dependency expression as written.
    pub deps: BTreeMap<String, String>,
}

pub fn read_aur_srcinfo(path: &Path) -> Result<PackageJson, BluelineError> {
    use std::io::Read;
    let display_path = path.display().to_string();
    let file = fs::File::open(path)
        .map_err(|e| BluelineError::Manifest(display_path.clone(), format!("cannot open: {e}")))?;
    let mut bytes = Vec::new();
    file.take(SRCINFO_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| BluelineError::Manifest(display_path.clone(), format!("cannot read: {e}")))?;
    if bytes.len() as u64 > SRCINFO_MAX_BYTES {
        return Err(BluelineError::Manifest(
            display_path,
            format!(".SRCINFO exceeds cap of {SRCINFO_MAX_BYTES} bytes"),
        ));
    }
    let raw = String::from_utf8(bytes).map_err(|_| {
        BluelineError::Manifest(display_path.clone(), ".SRCINFO is not valid UTF-8".into())
    })?;
    let src = parse_aur_srcinfo(&raw).map_err(|mut e| {
        if let BluelineError::Manifest(_, msg) = &mut e {
            *msg = format!("{display_path}: {msg}");
        }
        e
    })?;
    Ok(PackageJson {
        name: src.pkgbase,
        version: src.version,
        dependencies: src.deps,
        ..Default::default()
    })
}

/// Parse `.SRCINFO` content as untrusted text. The PKGBUILD is never sourced
/// and `makepkg` is never invoked; this reader understands only the flat
/// generated key-value shape.
pub fn parse_aur_srcinfo(raw: &str) -> Result<SrcInfo, BluelineError> {
    if raw.len() as u64 > SRCINFO_MAX_BYTES {
        return Err(BluelineError::Manifest(
            ".SRCINFO".to_string(),
            format!("exceeds cap of {SRCINFO_MAX_BYTES} bytes"),
        ));
    }
    let line_count = raw.lines().count();
    if line_count > MAX_SRCINFO_LINES {
        return Err(BluelineError::Manifest(
            ".SRCINFO".to_string(),
            format!("exceeds cap of {MAX_SRCINFO_LINES} lines"),
        ));
    }

    let mut pkgbase: Option<String> = None;
    let mut pkgver: Option<String> = None;
    let mut pkgrel: Option<String> = None;
    let mut epoch: Option<String> = None;
    let mut deps: BTreeMap<String, String> = BTreeMap::new();

    for (idx, line) in raw.lines().enumerate() {
        let lineno = idx + 1;
        if line.trim().is_empty() {
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let (key, value) = split_srcinfo_pair(line, lineno)?;
        if !indented {
            // Unindented lines are section headers in the generated format.
            match key.as_str() {
                "pkgbase" => {
                    if pkgbase.is_some() {
                        return Err(BluelineError::Manifest(
                            ".SRCINFO".to_string(),
                            format!("line {lineno}: duplicate pkgbase section"),
                        ));
                    }
                    if !crate::registry::aur::validate_aur_name(&value) {
                        return Err(BluelineError::Manifest(
                            ".SRCINFO".to_string(),
                            format!("line {lineno}: invalid pkgbase `{value}`"),
                        ));
                    }
                    pkgbase = Some(value);
                }
                "pkgname" => {
                    if !crate::registry::aur::validate_aur_name(&value) {
                        return Err(BluelineError::Manifest(
                            ".SRCINFO".to_string(),
                            format!("line {lineno}: invalid pkgname `{value}`"),
                        ));
                    }
                }
                other => {
                    return Err(BluelineError::Manifest(
                        ".SRCINFO".to_string(),
                        format!("line {lineno}: unexpected unindented key `{other}`"),
                    ));
                }
            }
            continue;
        }
        match key.as_str() {
            "pkgver" | "pkgrel" | "epoch" => {
                let slot = match key.as_str() {
                    "pkgver" => &mut pkgver,
                    "pkgrel" => &mut pkgrel,
                    _ => &mut epoch,
                };
                if slot.is_some() {
                    return Err(BluelineError::Manifest(
                        ".SRCINFO".to_string(),
                        format!("line {lineno}: duplicate `{}` key", key),
                    ));
                }
                *slot = Some(value);
            }
            "depends" | "makedepends" => {
                let name = dep_name(&value).ok_or_else(|| {
                    BluelineError::Manifest(
                        ".SRCINFO".to_string(),
                        format!("line {lineno}: dependency `{value}` has no package name"),
                    )
                })?;
                deps.insert(name, value);
            }
            _ => {}
        }
    }

    let pkgbase = pkgbase.ok_or_else(|| {
        BluelineError::Manifest(".SRCINFO".to_string(), "no pkgbase section".to_string())
    })?;
    let pkgver = pkgver.ok_or_else(|| {
        BluelineError::Manifest(".SRCINFO".to_string(), "missing pkgver".to_string())
    })?;
    let raw_version = match (epoch.as_deref(), pkgrel.as_deref()) {
        (Some(e), Some(r)) => format!("{e}:{pkgver}-{r}"),
        (Some(e), None) => format!("{e}:{pkgver}"),
        (None, Some(r)) => format!("{pkgver}-{r}"),
        (None, None) => pkgver,
    };
    let version = crate::version::AurVersionInfo::parse(&raw_version)
        .map_err(|e| {
            BluelineError::Manifest(
                ".SRCINFO".to_string(),
                format!("invalid pkgver/pkgrel/epoch: {e}"),
            )
        })?
        .canonical();

    Ok(SrcInfo {
        pkgbase,
        version,
        deps,
    })
}

/// Split a `.SRCINFO` line into its `key = value` pair. The generated format
/// uses a single ` = ` separator; anything else fails closed.
fn split_srcinfo_pair(line: &str, lineno: usize) -> Result<(String, String), BluelineError> {
    let fail = |msg: String| {
        BluelineError::Manifest(".SRCINFO".to_string(), format!("line {lineno}: {msg}"))
    };
    let body = line.trim_start();
    let (key, value) = body
        .split_once('=')
        .ok_or_else(|| fail(format!("expected `key = value`, got `{}`", line.trim_end())))?;
    let key = key.trim();
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(fail(format!("invalid key `{key}`")));
    }
    Ok((key.to_string(), value.trim().to_string()))
}

/// The package name of an AUR dependency expression
/// (`go>=1.21`, `sqlite3`, `mesa=24.0`): everything before the first
/// version-relation character.
fn dep_name(dep: &str) -> Option<String> {
    let name = dep.split(['<', '>', '=']).next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
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
    fn gypfile_flags_any_single_signal() {
        let gyp = |body: &str| {
            let m: PackedCargoToml =
                toml::from_str(&format!("[package]\nname=\"x\"\n{body}")).unwrap();
            m.manifest_view().gypfile
        };
        // Each signal alone must set the flag; the disjunction must not
        // degrade into requiring all three at once.
        assert_eq!(gyp("build = \"b.rs\""), Some(true));
        assert_eq!(gyp("links = \"z\""), Some(true));
        assert_eq!(gyp("\n[[bin]]\nname = \"cli\""), Some(true));
        assert_eq!(gyp(""), Some(false));
    }

    #[test]
    fn accepts_manifest_at_exact_size_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        let head = b"[package]\nname = \"x\"\n#";
        let mut body = head.to_vec();
        body.resize(MAX_MANIFEST_BYTES as usize, b'#');
        assert_eq!(body.len() as u64, MAX_MANIFEST_BYTES);
        fs::write(&path, &body).unwrap();
        assert!(read_packed_cargo_toml(&path).is_ok());
    }

    #[test]
    fn rejects_manifest_over_size_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        let body = vec![b'#'; MAX_MANIFEST_BYTES as usize + 1];
        assert_ne!(body.len() as u64, MAX_MANIFEST_BYTES);
        fs::write(&path, &body).unwrap();
        let err = read_packed_cargo_toml(&path).unwrap_err().to_string();
        assert!(err.contains("exceeds cap"), "unexpected error: {err}");
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

    fn sample_srcinfo() -> String {
        "pkgbase = yay\n\tpkgdesc = Yet another yogurt\n\tpkgver = 12.4.2\n\tpkgrel = 1\n\tarch = x86_64\n\tdepends = go>=1.21\n\tdepends = pacman\n\tmakedepends = git\n\npkgname = yay\n\tdepends = pacman>=6.1\n\tlicense = GPL3\n".to_string()
    }

    #[test]
    fn parses_srcinfo_version_and_merged_deps() {
        let src = parse_aur_srcinfo(&sample_srcinfo()).unwrap();
        assert_eq!(src.pkgbase, "yay");
        assert_eq!(src.version, "12.4.2-1");
        assert_eq!(src.deps.len(), 3);
        assert_eq!(src.deps["go"], "go>=1.21");
        assert_eq!(src.deps["pacman"], "pacman>=6.1");
        assert_eq!(src.deps["git"], "git");

        let view = read_aur_srcinfo_view(&sample_srcinfo());
        assert_eq!(view.name, "yay");
        assert_eq!(view.version, "12.4.2-1");
        assert_eq!(view.dependencies.len(), 3);
    }

    fn read_aur_srcinfo_view(raw: &str) -> PackageJson {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".SRCINFO");
        fs::write(&path, raw).unwrap();
        read_aur_srcinfo(&path).unwrap()
    }

    #[test]
    fn srcinfo_epoch_is_part_of_the_identity() {
        let raw = "pkgbase = demo\n\tpkgver = 1.0\n\tpkgrel = 2\n\tepoch = 3\n";
        let src = parse_aur_srcinfo(raw).unwrap();
        assert_eq!(src.version, "3:1.0-2");
    }

    #[test]
    fn srcinfo_without_pkgrel_parses() {
        let raw = "pkgbase = demo\n\tpkgver = 1.0\n";
        assert_eq!(parse_aur_srcinfo(raw).unwrap().version, "1.0");
    }

    #[test]
    fn srcinfo_fails_closed_on_missing_required_keys() {
        assert!(parse_aur_srcinfo("pkgver = 1.0\n").is_err());
        assert!(parse_aur_srcinfo("pkgbase = demo\n").is_err());
        assert!(parse_aur_srcinfo("").is_err());
    }

    #[test]
    fn srcinfo_fails_closed_on_duplicate_pkgbase_and_keys() {
        let dup_base = "pkgbase = demo\n\tpkgver = 1.0-1\npkgbase = demo\n";
        assert!(
            parse_aur_srcinfo(dup_base)
                .unwrap_err()
                .to_string()
                .contains("duplicate pkgbase")
        );

        let dup_ver = "pkgbase = demo\n\tpkgver = 1.0-1\n\tpkgver = 2.0-1\n";
        assert!(parse_aur_srcinfo(dup_ver).is_err());
    }

    #[test]
    fn srcinfo_fails_closed_on_unrecognized_shapes() {
        // Not a key = value line at all.
        assert!(parse_aur_srcinfo("pkgbase = demo\n\tbroken\n").is_err());
        // Comments are not part of the generated format.
        assert!(parse_aur_srcinfo("# comment\npkgbase = demo\n\tpkgver = 1.0-1\n").is_err());
        // Unindented keys other than pkgbase/pkgname are not generated output.
        assert!(parse_aur_srcinfo("pkgbase = demo\npkgver = 1.0-1\n").is_err());
        // Invalid names in section headers.
        assert!(parse_aur_srcinfo("pkgbase = ../evil\n\tpkgver = 1.0-1\n").is_err());
        // Garbage pkgver is rejected through the version grammar.
        assert!(parse_aur_srcinfo("pkgbase = demo\n\tpkgver = not/valid-1\n").is_err());
        // Empty key or empty dependency name.
        assert!(parse_aur_srcinfo("pkgbase = demo\n\t = 1.0-1\n").is_err());
        assert!(parse_aur_srcinfo("pkgbase = demo\n\tdepends = >=1.0\n").is_err());
    }

    #[test]
    fn srcinfo_fails_closed_over_line_cap() {
        let raw = format!(
            "pkgbase = demo\n\tpkgver = 1.0-1\n{}",
            "x = y\n".repeat(64 * 1024)
        );
        let err = parse_aur_srcinfo(&raw).unwrap_err().to_string();
        assert!(err.contains("65536 lines"), "unexpected error: {err}");
    }

    #[test]
    fn srcinfo_fails_closed_over_byte_cap() {
        let raw = " ".repeat(SRCINFO_MAX_BYTES as usize + 1);
        assert!(parse_aur_srcinfo(&raw).is_err());
    }

    #[test]
    fn srcinfo_byte_cap_boundary_is_exact() {
        // Padded to exactly the byte cap; the cap itself must parse.
        let mut raw = String::from("pkgbase = demo\n\tpkgver = 1.0\n\tx = ");
        raw.push_str(&"p".repeat(SRCINFO_MAX_BYTES as usize - raw.len() - 13));
        raw.push_str("\n\tpkgrel = 1\n");
        assert_eq!(raw.len() as u64, SRCINFO_MAX_BYTES);
        assert_eq!(parse_aur_srcinfo(&raw).unwrap().version, "1.0-1");

        let err = parse_aur_srcinfo(&format!("{raw}x"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds cap"), "unexpected error: {err}");
    }

    #[test]
    fn srcinfo_line_cap_boundary_is_exact() {
        let mut raw = String::from("pkgbase = demo\n\tpkgver = 1.0\n\tpkgrel = 1\n");
        for _ in 3..MAX_SRCINFO_LINES {
            raw.push_str("\tx = 1\n");
        }
        assert_eq!(raw.lines().count(), MAX_SRCINFO_LINES);
        assert_eq!(parse_aur_srcinfo(&raw).unwrap().version, "1.0-1");
    }

    #[test]
    fn srcinfo_errors_carry_one_based_line_numbers() {
        let err = parse_aur_srcinfo("junk = 1\n\tpkgver = 1.0-1\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 1:"), "unexpected error: {err}");
    }

    #[test]
    fn srcinfo_key_grammar_accepts_underscores_and_rejects_empty() {
        assert!(split_srcinfo_pair("make_depends = git", 1).is_ok());
        let err = split_srcinfo_pair(" = git", 1).unwrap_err().to_string();
        assert!(err.contains("invalid key"), "unexpected error: {err}");
    }

    #[test]
    fn read_aur_srcinfo_reports_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_aur_srcinfo(&dir.path().join(".SRCINFO")),
            Err(BluelineError::Manifest(_, _))
        ));
    }

    #[test]
    fn read_aur_srcinfo_byte_cap_boundary_is_exact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".SRCINFO");
        // Exactly at the cap; the final byte completes `pkgrel`, so a
        // truncated read cannot silently succeed.
        let mut exact = String::from("pkgbase = demo\n\tpkgver = 1.0\n\tx = ");
        exact.push_str(&"p".repeat(SRCINFO_MAX_BYTES as usize - exact.len() - 12));
        exact.push_str("\n\tpkgrel = 1");
        assert_eq!(exact.len() as u64, SRCINFO_MAX_BYTES);
        fs::write(&path, &exact).unwrap();
        assert_eq!(read_aur_srcinfo(&path).unwrap().version, "1.0-1");

        fs::write(&path, format!("{exact}x")).unwrap();
        let err = read_aur_srcinfo(&path).unwrap_err().to_string();
        assert!(err.contains("exceeds cap"), "unexpected error: {err}");
    }
}
