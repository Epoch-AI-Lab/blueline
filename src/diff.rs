use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::error::BluelineError;
use crate::manifest::PackageJson;

const MAX_DIFF_FILE_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB cap for line diffing

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKind {
    Text,
    Binary,
    OpaqueTooLarge,
}

#[derive(Debug, Clone)]
pub struct FileChange {
    pub relative_path: String,
    pub kind: FileKind,
    pub lines_added: usize,
    pub lines_deleted: usize,
    pub is_executable: bool,
    pub unified_diff: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Delta {
    pub baseline_version: Option<String>,
    pub target_version: String,
    pub files_added: Vec<FileChange>,
    pub files_removed: Vec<FileChange>,
    pub files_modified: Vec<FileChange>,
    pub total_lines_added: usize,
    pub total_lines_deleted: usize,
    pub new_executables: Vec<String>,
    pub new_binaries: Vec<String>,
    pub modified_binaries: Vec<String>,
    pub new_lifecycle_scripts: Vec<String>,
    pub modified_lifecycle_scripts: Vec<String>,
    pub new_dependencies: Vec<(String, String)>,
    pub modified_dependencies: Vec<(String, String, String)>,
    #[allow(dead_code)]
    pub removed_dependencies: Vec<String>,
    #[allow(dead_code)]
    pub binding_gyp_added: bool,
}

impl Delta {
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.files_added.is_empty()
            && self.files_removed.is_empty()
            && self.files_modified.is_empty()
    }
}

pub fn compute_delta(
    baseline_root: Option<&Path>,
    baseline_manifest: Option<&PackageJson>,
    baseline_version: Option<&str>,
    target_root: &Path,
    target_manifest: &PackageJson,
    target_version: &str,
) -> Result<Delta, BluelineError> {
    let target_base = find_package_prefix(target_root);
    let target_files = scan_tree(&target_base)?;

    let mut files_added = Vec::new();
    let mut files_removed = Vec::new();
    let mut files_modified = Vec::new();
    let mut total_lines_added = 0;
    let mut total_lines_deleted = 0;
    let mut new_executables = Vec::new();
    let mut new_binaries = Vec::new();
    let mut modified_binaries = Vec::new();

    if let Some(base_root) = baseline_root {
        let base_base = find_package_prefix(base_root);
        let base_files = scan_tree(&base_base)?;

        let all_paths: BTreeSet<String> = base_files
            .keys()
            .chain(target_files.keys())
            .cloned()
            .collect();

        for rel_path in all_paths {
            let in_base = base_files.get(&rel_path);
            let in_target = target_files.get(&rel_path);

            match (in_base, in_target) {
                (None, Some(target_meta)) => {
                    let target_full = target_base.join(&rel_path);
                    let change =
                        diff_single_file(None, Some(&target_full), &rel_path, target_meta)?;
                    if change.is_executable || is_executable_extension(&rel_path) {
                        new_executables.push(rel_path.clone());
                    }
                    if change.kind == FileKind::Binary || change.kind == FileKind::OpaqueTooLarge {
                        new_binaries.push(rel_path.clone());
                    }
                    total_lines_added += change.lines_added;
                    files_added.push(change);
                }
                (Some(base_meta), None) => {
                    let base_full = base_base.join(&rel_path);
                    let change = diff_single_file(Some(&base_full), None, &rel_path, base_meta)?;
                    total_lines_deleted += change.lines_deleted;
                    files_removed.push(change);
                }
                (Some(base_meta), Some(target_meta)) => {
                    let base_full = base_base.join(&rel_path);
                    let target_full = target_base.join(&rel_path);

                    if base_meta.hash != target_meta.hash {
                        let change = diff_single_file(
                            Some(&base_full),
                            Some(&target_full),
                            &rel_path,
                            target_meta,
                        )?;
                        if !base_meta.is_executable && target_meta.is_executable {
                            new_executables.push(rel_path.clone());
                        }
                        if base_meta.kind == FileKind::Binary
                            && target_meta.kind == FileKind::Binary
                        {
                            modified_binaries.push(rel_path.clone());
                        }
                        if (base_meta.kind != FileKind::Binary
                            && target_meta.kind == FileKind::Binary)
                            || (base_meta.kind != FileKind::OpaqueTooLarge
                                && target_meta.kind == FileKind::OpaqueTooLarge)
                        {
                            new_binaries.push(rel_path.clone());
                        }
                        total_lines_added += change.lines_added;
                        total_lines_deleted += change.lines_deleted;
                        files_modified.push(change);
                    }
                }
                (None, None) => unreachable!(),
            }
        }
    } else {
        // First sighting: all target files are added
        for (rel_path, target_meta) in target_files {
            let target_full = target_base.join(&rel_path);
            let change = diff_single_file(None, Some(&target_full), &rel_path, &target_meta)?;
            if change.is_executable || is_executable_extension(&rel_path) {
                new_executables.push(rel_path.clone());
            }
            if change.kind == FileKind::Binary || change.kind == FileKind::OpaqueTooLarge {
                new_binaries.push(rel_path.clone());
            }
            total_lines_added += change.lines_added;
            files_added.push(change);
        }
    }

    // Manifest deltas
    let target_lifecycle = target_manifest.lifecycle_scripts();
    let mut new_lifecycle_scripts = Vec::new();
    let mut modified_lifecycle_scripts = Vec::new();

    if let Some(base_m) = baseline_manifest {
        let base_scripts = &base_m.scripts;
        for script_name in &target_lifecycle {
            if let Some(base_cmd) = base_scripts.get(script_name) {
                if let Some(target_cmd) = target_manifest.scripts.get(script_name)
                    && base_cmd != target_cmd
                {
                    modified_lifecycle_scripts.push(script_name.clone());
                }
            } else {
                new_lifecycle_scripts.push(script_name.clone());
            }
        }
    } else {
        new_lifecycle_scripts = target_lifecycle;
    }

    let mut new_dependencies = Vec::new();
    let mut modified_dependencies = Vec::new();
    let mut removed_dependencies = Vec::new();

    let target_deps = collect_all_dependencies(target_manifest);
    if let Some(base_m) = baseline_manifest {
        let base_deps = collect_all_dependencies(base_m);
        for (dep, ver) in &target_deps {
            if let Some(base_ver) = base_deps.get(dep) {
                if base_ver != ver {
                    modified_dependencies.push((dep.clone(), base_ver.clone(), ver.clone()));
                }
            } else {
                new_dependencies.push((dep.clone(), ver.clone()));
            }
        }
        for dep in base_deps.keys() {
            if !target_deps.contains_key(dep) {
                removed_dependencies.push(dep.clone());
            }
        }
    } else {
        for (dep, ver) in &target_deps {
            new_dependencies.push((dep.clone(), ver.clone()));
        }
    }

    let binding_gyp_added = files_added.iter().any(|f| {
        f.relative_path.eq_ignore_ascii_case("binding.gyp")
            || Path::new(&f.relative_path)
                .file_name()
                .map(|n| n.to_string_lossy().eq_ignore_ascii_case("binding.gyp"))
                .unwrap_or(false)
    }) || target_manifest.gypfile == Some(true);

    Ok(Delta {
        baseline_version: baseline_version.map(|s| s.to_string()),
        target_version: target_version.to_string(),
        files_added,
        files_removed,
        files_modified,
        total_lines_added,
        total_lines_deleted,
        new_executables,
        new_binaries,
        modified_binaries,
        new_lifecycle_scripts,
        modified_lifecycle_scripts,
        new_dependencies,
        modified_dependencies,
        removed_dependencies,
        binding_gyp_added,
    })
}

fn collect_all_dependencies(manifest: &PackageJson) -> BTreeMap<String, String> {
    let mut all = BTreeMap::new();
    for (k, v) in &manifest.dependencies {
        all.insert(k.clone(), v.clone());
    }
    for (k, v) in &manifest.optional_dependencies {
        all.entry(k.clone()).or_insert_with(|| v.clone());
    }
    for (k, v) in &manifest.peer_dependencies {
        all.entry(k.clone()).or_insert_with(|| v.clone());
    }
    all
}

#[derive(Debug, Clone)]
struct DiskFileMeta {
    #[allow(dead_code)]
    size: u64,
    hash: [u8; 32],
    kind: FileKind,
    is_executable: bool,
}

fn scan_tree(root: &Path) -> Result<BTreeMap<String, DiskFileMeta>, BluelineError> {
    let mut files = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|e| BluelineError::Extraction(format!("scanning tree: {e}")))?;
        if entry.file_type().is_file() {
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .map_err(|e| BluelineError::Extraction(format!("path strip error: {e}")))?
                .to_string_lossy()
                .to_string();

            let bytes = fs::read(path).map_err(|e| {
                BluelineError::Extraction(format!("reading {}: {e}", path.display()))
            })?;
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let hash = hasher.finalize().into();

            let kind = classify_bytes(&bytes);
            let is_executable = check_is_executable(path);

            files.insert(
                rel,
                DiskFileMeta {
                    size: bytes.len() as u64,
                    hash,
                    kind,
                    is_executable,
                },
            );
        }
    }
    Ok(files)
}

fn classify_bytes(bytes: &[u8]) -> FileKind {
    if bytes.len() as u64 > MAX_DIFF_FILE_BYTES {
        return FileKind::OpaqueTooLarge;
    }
    if bytes.contains(&0) {
        return FileKind::Binary;
    }
    if std::str::from_utf8(bytes).is_err() {
        return FileKind::Binary;
    }
    FileKind::Text
}

fn diff_single_file(
    old_path: Option<&Path>,
    new_path: Option<&Path>,
    rel_path: &str,
    target_meta: &DiskFileMeta,
) -> Result<FileChange, BluelineError> {
    let kind = target_meta.kind.clone();
    if kind != FileKind::Text {
        return Ok(FileChange {
            relative_path: rel_path.to_string(),
            kind,
            lines_added: 0,
            lines_deleted: 0,
            is_executable: target_meta.is_executable,
            unified_diff: None,
        });
    }

    let old_bytes = match old_path {
        Some(p) => fs::read(p).map_err(|e| BluelineError::Extraction(format!("read old: {e}")))?,
        None => Vec::new(),
    };
    let new_bytes = match new_path {
        Some(p) => fs::read(p).map_err(|e| BluelineError::Extraction(format!("read new: {e}")))?,
        None => Vec::new(),
    };

    let old_str = std::str::from_utf8(&old_bytes).unwrap_or("");
    let new_str = std::str::from_utf8(&new_bytes).unwrap_or("");

    let diff = similar::TextDiff::from_lines(old_str, new_str);
    let mut lines_added = 0;
    let mut lines_deleted = 0;

    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Insert => lines_added += 1,
            similar::ChangeTag::Delete => lines_deleted += 1,
            similar::ChangeTag::Equal => {}
        }
    }

    let unified = diff
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{rel_path}"), &format!("b/{rel_path}"))
        .to_string();

    Ok(FileChange {
        relative_path: rel_path.to_string(),
        kind: FileKind::Text,
        lines_added,
        lines_deleted,
        is_executable: target_meta.is_executable,
        unified_diff: if unified.trim().is_empty() {
            None
        } else {
            Some(unified)
        },
    })
}

fn find_package_prefix(root: &Path) -> PathBuf {
    let nested = root.join("package");
    if nested.is_dir() {
        let has_siblings = fs::read_dir(root)
            .map(|mut r| {
                r.any(|e| {
                    e.map(|entry| entry.file_name() != "package")
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        if !has_siblings {
            return nested;
        }
    }
    root.to_path_buf()
}

fn check_is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            return meta.permissions().mode() & 0o111 != 0;
        }
    }
    #[cfg(not(unix))]
    {
        if let Some(ext) = path.extension() {
            let ext_s = ext.to_string_lossy().to_lowercase();
            return matches!(ext_s.as_str(), "exe" | "cmd" | "bat" | "sh");
        }
    }
    false
}

fn is_executable_extension(path_str: &str) -> bool {
    let path = Path::new(path_str);
    if let Some(ext) = path.extension() {
        let ext_s = ext.to_string_lossy().to_lowercase();
        matches!(
            ext_s.as_str(),
            "exe" | "dll" | "so" | "dylib" | "node" | "sh" | "bat" | "cmd" | "ps1" | "vbs" | "bin"
        )
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_file_added_removed_modified() {
        let old_dir = tempfile::tempdir().unwrap();
        let new_dir = tempfile::tempdir().unwrap();

        fs::write(old_dir.path().join("deleted.txt"), "goodbye\n").unwrap();
        fs::write(old_dir.path().join("modified.txt"), "hello\nworld\n").unwrap();
        fs::write(old_dir.path().join("same.txt"), "unchanged\n").unwrap();

        fs::write(new_dir.path().join("modified.txt"), "hello\nbrave\nworld\n").unwrap();
        fs::write(new_dir.path().join("same.txt"), "unchanged\n").unwrap();
        fs::write(new_dir.path().join("added.txt"), "welcome\n").unwrap();

        let base_m = PackageJson {
            name: "test".into(),
            version: "1.0.0".into(),
            gypfile: None,
            scripts: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
        };
        let target_m = PackageJson {
            name: "test".into(),
            version: "1.1.0".into(),
            gypfile: None,
            scripts: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
        };

        let delta = compute_delta(
            Some(old_dir.path()),
            Some(&base_m),
            Some("1.0.0"),
            new_dir.path(),
            &target_m,
            "1.1.0",
        )
        .unwrap();

        assert_eq!(delta.files_added.len(), 1);
        assert_eq!(delta.files_added[0].relative_path, "added.txt");
        assert_eq!(delta.files_removed.len(), 1);
        assert_eq!(delta.files_removed[0].relative_path, "deleted.txt");
        assert_eq!(delta.files_modified.len(), 1);
        assert_eq!(delta.files_modified[0].relative_path, "modified.txt");
        assert!(delta.total_lines_added >= 2);
    }

    #[test]
    fn detects_binary_files() {
        let new_dir = tempfile::tempdir().unwrap();
        let bin_bytes = vec![0x7f, b'E', b'L', b'F', 0, 1, 2, 3];
        fs::write(new_dir.path().join("binary.node"), &bin_bytes).unwrap();

        let target_m = PackageJson {
            name: "test".into(),
            version: "1.0.0".into(),
            gypfile: None,
            scripts: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
        };

        let delta = compute_delta(None, None, None, new_dir.path(), &target_m, "1.0.0").unwrap();

        assert_eq!(delta.files_added.len(), 1);
        assert_eq!(delta.files_added[0].kind, FileKind::Binary);
        assert!(delta.new_binaries.contains(&"binary.node".to_string()));
        assert!(delta.new_executables.contains(&"binary.node".to_string()));
    }

    #[test]
    fn scans_entire_file_for_nul_byte() {
        // NUL byte placed past 8192 bytes
        let mut data = vec![b'a'; 10000];
        data[9000] = 0;
        assert_eq!(classify_bytes(&data), FileKind::Binary);
    }

    #[test]
    fn diffs_optional_and_peer_dependencies() {
        let old_dir = tempfile::tempdir().unwrap();
        let new_dir = tempfile::tempdir().unwrap();

        let base_m = PackageJson {
            name: "test".into(),
            version: "1.0.0".into(),
            gypfile: None,
            scripts: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
        };
        let mut target_m = PackageJson {
            name: "test".into(),
            version: "1.1.0".into(),
            gypfile: None,
            scripts: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
        };
        target_m
            .optional_dependencies
            .insert("opt-dep".into(), "^1.0.0".into());
        target_m
            .peer_dependencies
            .insert("peer-dep".into(), "ssh://git@evil.com".into());

        let delta = compute_delta(
            Some(old_dir.path()),
            Some(&base_m),
            Some("1.0.0"),
            new_dir.path(),
            &target_m,
            "1.1.0",
        )
        .unwrap();

        assert_eq!(delta.new_dependencies.len(), 2);
        assert!(
            delta
                .new_dependencies
                .contains(&("opt-dep".into(), "^1.0.0".into()))
        );
        assert!(
            delta
                .new_dependencies
                .contains(&("peer-dep".into(), "ssh://git@evil.com".into()))
        );
    }

    #[test]
    fn detects_binding_gyp_addition() {
        let new_dir = tempfile::tempdir().unwrap();
        fs::write(new_dir.path().join("binding.gyp"), "{}").unwrap();

        let target_m = PackageJson {
            name: "test".into(),
            version: "1.0.0".into(),
            gypfile: None,
            scripts: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
        };

        let delta = compute_delta(None, None, None, new_dir.path(), &target_m, "1.0.0").unwrap();
        assert!(delta.binding_gyp_added);
    }

    #[test]
    fn detects_gypfile_in_manifest() {
        let new_dir = tempfile::tempdir().unwrap();

        let target_m = PackageJson {
            name: "test".into(),
            version: "1.0.0".into(),
            gypfile: Some(true),
            scripts: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
        };

        let delta = compute_delta(None, None, None, new_dir.path(), &target_m, "1.0.0").unwrap();
        assert!(delta.binding_gyp_added);
    }
}
