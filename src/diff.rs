use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::error::BluelineError;
use crate::manifest::PackageJson;

const MAX_DIFF_FILE_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB cap for line diffing

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FileKind {
    #[default]
    Text,
    Binary,
    OpaqueTooLarge,
}

#[derive(Debug, Clone, Default)]
pub struct FileChange {
    pub relative_path: String,
    pub kind: FileKind,
    pub lines_added: usize,
    pub lines_deleted: usize,
    pub is_executable: bool,
    pub unified_diff: Option<String>,
}

#[derive(Debug, Clone, Default)]
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
    pub removed_dependencies: Vec<(String, String)>,
    pub binding_gyp_added: bool,
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

        let mut base_iter = base_files.iter().peekable();
        let mut target_iter = target_files.iter().peekable();

        loop {
            match (base_iter.peek(), target_iter.peek()) {
                (Some(&(b_path, _)), Some(&(t_path, _))) => match b_path.cmp(t_path) {
                    std::cmp::Ordering::Less => {
                        // peek() returned Some above and nothing advanced this
                        // iterator since; None here is a logic bug, not input.
                        #[allow(clippy::unwrap_used)]
                        let (rel_path, base_meta) = base_iter.next().unwrap();
                        let base_full = base_base.join(rel_path);
                        let change = diff_single_file(Some(&base_full), None, rel_path, base_meta)?;
                        total_lines_deleted += change.lines_deleted;
                        files_removed.push(change);
                    }
                    std::cmp::Ordering::Greater => {
                        // peek() returned Some above and nothing advanced this
                        // iterator since; None here is a logic bug, not input.
                        #[allow(clippy::unwrap_used)]
                        let (rel_path, target_meta) = target_iter.next().unwrap();
                        let target_full = target_base.join(rel_path);
                        let change =
                            diff_single_file(None, Some(&target_full), rel_path, target_meta)?;
                        if change.is_executable
                            || is_executable_extension(&rel_path.to_string_lossy())
                        {
                            new_executables.push(rel_display_at(rel_path));
                        }
                        if change.kind == FileKind::Binary
                            || change.kind == FileKind::OpaqueTooLarge
                        {
                            new_binaries.push(rel_display_at(rel_path));
                        }
                        total_lines_added += change.lines_added;
                        files_added.push(change);
                    }
                    std::cmp::Ordering::Equal => {
                        // Both iterators peeked Some above and neither has been
                        // advanced since; None here is a logic bug, not input.
                        #[allow(clippy::unwrap_used)]
                        let (rel_path, base_meta) = base_iter.next().unwrap();
                        #[allow(clippy::unwrap_used)]
                        let (_, target_meta) = target_iter.next().unwrap();

                        if base_meta.hash != target_meta.hash {
                            let base_full = base_base.join(rel_path);
                            let target_full = target_base.join(rel_path);
                            let change = diff_single_file(
                                Some(&base_full),
                                Some(&target_full),
                                rel_path,
                                target_meta,
                            )?;
                            if !base_meta.is_executable && target_meta.is_executable {
                                new_executables.push(rel_display_at(rel_path));
                            }
                            if base_meta.kind == FileKind::Binary
                                && target_meta.kind == FileKind::Binary
                            {
                                modified_binaries.push(rel_display_at(rel_path));
                            }
                            if (base_meta.kind != FileKind::Binary
                                && target_meta.kind == FileKind::Binary)
                                || (base_meta.kind != FileKind::OpaqueTooLarge
                                    && target_meta.kind == FileKind::OpaqueTooLarge)
                            {
                                new_binaries.push(rel_display_at(rel_path));
                            }
                            total_lines_added += change.lines_added;
                            total_lines_deleted += change.lines_deleted;
                            files_modified.push(change);
                        }
                    }
                },
                (Some(_), None) => {
                    // peek() returned Some above and nothing advanced this
                    // iterator since; None here is a logic bug, not input.
                    #[allow(clippy::unwrap_used)]
                    let (rel_path, base_meta) = base_iter.next().unwrap();
                    let base_full = base_base.join(rel_path);
                    let change = diff_single_file(Some(&base_full), None, rel_path, base_meta)?;
                    total_lines_deleted += change.lines_deleted;
                    files_removed.push(change);
                }
                (None, Some(_)) => {
                    // peek() returned Some above and nothing advanced this
                    // iterator since; None here is a logic bug, not input.
                    #[allow(clippy::unwrap_used)]
                    let (rel_path, target_meta) = target_iter.next().unwrap();
                    let target_full = target_base.join(rel_path);
                    let change = diff_single_file(None, Some(&target_full), rel_path, target_meta)?;
                    if change.is_executable || is_executable_extension(&rel_path.to_string_lossy())
                    {
                        new_executables.push(rel_display_at(rel_path));
                    }
                    if change.kind == FileKind::Binary || change.kind == FileKind::OpaqueTooLarge {
                        new_binaries.push(rel_display_at(rel_path));
                    }
                    total_lines_added += change.lines_added;
                    files_added.push(change);
                }
                (None, None) => break,
            }
        }
    } else {
        // First sighting: all target files are added
        for (rel_path, target_meta) in target_files {
            let display = rel_display_at(&rel_path);
            let target_full = target_base.join(&rel_path);
            let change = diff_single_file(None, Some(&target_full), &rel_path, &target_meta)?;
            if change.is_executable || is_executable_extension(&rel_path.to_string_lossy()) {
                new_executables.push(display.clone());
            }
            if change.kind == FileKind::Binary || change.kind == FileKind::OpaqueTooLarge {
                new_binaries.push(display);
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
        for (dep, ver) in &base_deps {
            if !target_deps.contains_key(dep) {
                removed_dependencies.push((dep.clone(), ver.clone()));
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
    }) || (target_manifest.gypfile == Some(true)
        && baseline_manifest.is_none_or(|b| b.gypfile != Some(true)));

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
    hash: [u8; 32],
    kind: FileKind,
    is_executable: bool,
}

/// Keyed by `PathBuf`, not a lossy string. Two entries differing only in
/// invalid UTF-8 bytes collapse to the same replacement character, and the
/// merged string was then joined back onto the root to read the file, so a
/// non-UTF-8 name aborted the whole review with "No such file or directory".
fn scan_tree(root: &Path) -> Result<BTreeMap<PathBuf, DiskFileMeta>, BluelineError> {
    let mut files = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|e| BluelineError::Extraction(format!("scanning tree: {e}")))?;
        if entry.file_type().is_file() {
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .map_err(|e| BluelineError::Extraction(format!("path strip error: {e}")))?
                .to_path_buf();

            files.insert(rel, scan_file(path)?);
        }
    }
    Ok(files)
}

/// Window used to read each file. Large enough that syscall overhead is noise,
/// small enough that peak memory is set by this rather than by the package.
const SCAN_CHUNK_BYTES: usize = 64 * 1024;

/// Longest UTF-8 sequence, so a code point split across two reads can be
/// carried over whole.
const UTF8_MAX_SEQ: usize = 4;

/// Sequence length implied by a UTF-8 lead byte, or `None` if the byte cannot
/// start a valid sequence.
fn seq_len(lead: u8) -> Option<usize> {
    match lead {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

/// Incremental UTF-8 validity check.
///
/// `from_utf8` rejects a sequence that is merely truncated by the end of the
/// buffer, so the tail of a chunk has to be carried into the next one before it
/// can be judged. The carry is at most `UTF8_MAX_SEQ - 1` bytes, and a valid
/// result on the carried bytes means those bytes are settled, so the carry
/// never grows without bound.
#[derive(Default)]
struct Utf8Scan {
    valid: bool,
    pending: [u8; UTF8_MAX_SEQ],
    pending_len: usize,
}

impl Utf8Scan {
    fn feed(&mut self, chunk: &[u8]) {
        if !self.valid {
            return;
        }
        let mut rest = chunk;

        if self.pending_len > 0 {
            // Complete the carried sequence by its actual length, taken from the
            // lead byte. Padding to a fixed four bytes would steal the lead of
            // the next character whenever the split sequence is shorter, and
            // from_utf8 would then reject the carry as malformed.
            let expected = match seq_len(self.pending[0]) {
                Some(n) => n,
                None => {
                    self.valid = false;
                    return;
                }
            };
            let take = (expected - self.pending_len).min(rest.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&rest[..take]);
            self.pending_len += take;
            rest = &rest[take..];
            if self.pending_len < expected {
                // Still short of a full sequence. Nothing new is judgeable yet.
                return;
            }
            if std::str::from_utf8(&self.pending[..expected]).is_err() {
                self.valid = false;
                return;
            }
            self.pending_len = 0;
        }

        match std::str::from_utf8(rest) {
            Ok(_) => {}
            Err(e) => match e.error_len() {
                Some(_) => self.valid = false,
                None => {
                    let tail = rest.len() - e.valid_up_to();
                    self.pending[..tail].copy_from_slice(&rest[rest.len() - tail..]);
                    self.pending_len = tail;
                }
            },
        }
    }

    /// Judge whatever carry is left once the file is exhausted.
    ///
    /// A sequence still incomplete at EOF is malformed input, not a truncation
    /// of a longer buffer: there are no further bytes to complete it with.
    /// Judging it here is what keeps a file that ends mid-code-point from
    /// reading as text.
    fn finish(&mut self) {
        if self.pending_len > 0 {
            self.valid = false;
        }
    }
}

/// Read one file once and keep only what the comparison needs.
///
/// The previous shape was `fs::read` followed by a hash and a classify over the
/// whole buffer. None of the three questions need the buffer: the size is a
/// running count, the digest is incremental by construction, and "is this
/// text" is a NUL scan plus a UTF-8 check. A fixed window answers all three, so
/// peak memory stops scaling with the largest file in the package. Every byte
/// still reaches the hasher, because the digest is what decides whether a file
/// is compared at all.
fn scan_file(path: &Path) -> Result<DiskFileMeta, BluelineError> {
    let read_err =
        |e: std::io::Error| BluelineError::Extraction(format!("reading {}: {e}", path.display()));
    let mut file = fs::File::open(path).map_err(read_err)?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; SCAN_CHUNK_BYTES];
    let mut utf8 = Utf8Scan {
        valid: true,
        ..Default::default()
    };
    let mut len: u64 = 0;
    let mut has_nul = false;

    loop {
        let n = file.read(&mut buf).map_err(read_err)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        hasher.update(chunk);
        len += n as u64;
        // Past the cap the file is opaque whatever its bytes look like, so the
        // two scans stop. The hash keeps going: it decides the comparison.
        if len <= MAX_DIFF_FILE_BYTES {
            if !has_nul {
                has_nul = chunk.contains(&0);
            }
            utf8.feed(chunk);
        }
    }
    utf8.finish();

    let hash = hasher.finalize().into();
    let kind = classify_bytes(len, has_nul, utf8.valid);
    Ok(DiskFileMeta {
        hash,
        kind,
        is_executable: check_is_executable(path),
    })
}

fn classify_bytes(len: u64, has_nul: bool, utf8_valid: bool) -> FileKind {
    if len > MAX_DIFF_FILE_BYTES {
        return FileKind::OpaqueTooLarge;
    }
    if has_nul || !utf8_valid {
        return FileKind::Binary;
    }
    FileKind::Text
}

/// Display form of a relative path, for the string-typed report fields.
fn rel_display_at(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn diff_single_file(
    old_path: Option<&Path>,
    new_path: Option<&Path>,
    rel_path: &Path,
    target_meta: &DiskFileMeta,
) -> Result<FileChange, BluelineError> {
    let rel_display = rel_path.to_string_lossy().into_owned();
    let rel_path = rel_display.as_str();
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

    let old_str = std::str::from_utf8(&old_bytes).map_err(|e| {
        BluelineError::Extraction(format!(
            "diffing {rel_path}: baseline bytes are not UTF-8 ({e}); a text-classified \
             file that does not decode cannot be line-diffed, and coercing it to \
             an empty string scored a real change as all-add or all-delete"
        ))
    })?;
    let new_str = std::str::from_utf8(&new_bytes).map_err(|e| {
        BluelineError::Extraction(format!(
            "diffing {rel_path}: payload bytes are not UTF-8 ({e}); a text-classified \
             file that does not decode cannot be line-diffed, and coercing it to \
             an empty string scored a real change as all-add or all-delete"
        ))
    })?;

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

    let unified_diff = if lines_added == 0 && lines_deleted == 0 {
        None
    } else {
        let unified = diff
            .unified_diff()
            .context_radius(3)
            .header(&format!("a/{rel_path}"), &format!("b/{rel_path}"))
            .to_string();
        if unified.trim().is_empty() {
            None
        } else {
            Some(unified)
        }
    };

    Ok(FileChange {
        relative_path: rel_path.to_string(),
        kind: FileKind::Text,
        lines_added,
        lines_deleted,
        is_executable: target_meta.is_executable,
        unified_diff,
    })
}

pub(crate) fn find_package_prefix(root: &Path) -> PathBuf {
    if let Ok(entries) = fs::read_dir(root).and_then(|r| r.collect::<Result<Vec<_>, _>>())
        && entries.len() == 1
    {
        let entry = &entries[0];
        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            return entry.path();
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
    fn seq_len_maps_every_utf8_lead_byte_class() {
        // Each arm is the load-bearing half of the chunk-boundary carry: it
        // decides how many bytes a split sequence still needs. Deleting an arm
        // silently mis-classifies every file whose split lands on that class,
        // so pin all four plus the two rejection ranges.
        assert_eq!(seq_len(b'a'), Some(1)); // 0x00..=0x7f
        assert_eq!(seq_len(0x7f), Some(1));
        assert_eq!(seq_len(0xc2), Some(2)); // 0xc2..=0xdf
        assert_eq!(seq_len(0xdf), Some(2));
        assert_eq!(seq_len(0xe0), Some(3)); // 0xe0..=0xef
        assert_eq!(seq_len(0xef), Some(3));
        assert_eq!(seq_len(0xf0), Some(4)); // 0xf0..=0xf4
        assert_eq!(seq_len(0xf4), Some(4));
        // Not valid lead bytes: continuation bytes and the two overlong ranges.
        assert_eq!(seq_len(0x80), None);
        assert_eq!(seq_len(0xbf), None);
        assert_eq!(seq_len(0xc0), None);
        assert_eq!(seq_len(0xc1), None);
        assert_eq!(seq_len(0xf5), None);
        assert_eq!(seq_len(0xff), None);
    }

    #[test]
    fn the_scan_window_is_sixty_four_kibibytes() {
        // The window is the memory bound, and `64 * 1024` vs `64 + 1024` is a
        // one-token swap the digest test cannot see. Pin the value so the
        // bound the comment promises is the bound that ships.
        assert_eq!(SCAN_CHUNK_BYTES, 64 * 1024);
    }

    #[test]
    fn classify_bytes_draws_the_opaque_boundary_above_the_cap_only() {
        // `len > cap` vs `len >= cap` is an off-by-one at the exact boundary.
        // A file exactly at the cap is still line-diffable, so it must stay
        // Text; only one byte past it is opaque.
        assert_eq!(
            classify_bytes(MAX_DIFF_FILE_BYTES, false, true),
            FileKind::Text,
            "a file exactly at the cap must still be diffable"
        );
        assert_eq!(
            classify_bytes(MAX_DIFF_FILE_BYTES + 1, false, true),
            FileKind::OpaqueTooLarge,
            "one byte past the cap is opaque"
        );
    }

    #[test]
    fn a_carry_completes_only_once_the_whole_sequence_arrives() {
        // The `pending_len < expected` guard is what keeps a half-arrived
        // sequence from being judged before its bytes exist. Flipping it to
        // `>` would judge an empty carry as complete and a full one as
        // incomplete, so drive both sides of the boundary.
        //
        // `valid` starts true, exactly as `scan_file` initialises it; the
        // `Default` derive would start it false and every feed would no-op.
        let new_scan = || Utf8Scan {
            valid: true,
            ..Default::default()
        };
        // A four-byte sequence delivered one byte at a time into the SAME
        // scan: incomplete at every step but the last, and never judged until
        // the fourth byte. This is the case the `pending_len < expected` guard
        // protects — a partial carry meeting a follow-up feed that is still
        // too short must not be judged. Flipping the guard to `>` would skip
        // the early return and judge the half-filled carry as malformed.
        let mut drip = new_scan();
        for (i, byte) in [0xf0u8, 0x9f, 0x98, 0x80].iter().enumerate() {
            drip.feed(&[*byte]);
            if i < 3 {
                assert!(
                    drip.valid,
                    "after {i} byte(s) the carry is incomplete, not invalid"
                );
            }
        }
        assert!(
            drip.valid,
            "the completed four-byte sequence is valid UTF-8"
        );

        // The completed sequence judges valid, and so does the same sequence
        // split across two feeds.
        let mut scan = new_scan();
        scan.feed(&[0xf0, 0x9f]);
        assert!(scan.valid, "a two-byte carry is not yet judgeable");
        scan.feed(&[0x98, 0x80]);
        assert!(
            scan.valid,
            "the completed four-byte sequence is valid UTF-8"
        );

        // A genuinely malformed lead byte is rejected as soon as it is the
        // carry's first byte, which is what `seq_len` returning `None` drives.
        let mut bad = new_scan();
        bad.feed(&[0xff]);
        assert!(!bad.valid, "0xff cannot start a UTF-8 sequence");
    }

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
        // NUL byte placed past 8192 bytes, and past the read window, so only a
        // scan that keeps going to the end of the file can see it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("late-nul.bin");
        let mut data = vec![b'a'; SCAN_CHUNK_BYTES * 3];
        data[SCAN_CHUNK_BYTES + 17] = 0;
        fs::write(&path, &data).unwrap();

        assert_eq!(scan_file(&path).unwrap().kind, FileKind::Binary);
    }

    #[test]
    fn chunked_reads_agree_with_a_single_read_on_the_classification() {
        // A multi-byte code point straddling the window boundary is the case
        // most likely to be misjudged by an incremental check, so pin every
        // offset of a four-byte sequence against the whole-buffer answer.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("edge.txt");
        let euro = "€".repeat(SCAN_CHUNK_BYTES);
        for pad in 0..8usize {
            let mut data = vec![b'a'; pad];
            data.extend_from_slice(euro.as_bytes());
            fs::write(&path, &data).unwrap();
            assert_eq!(
                scan_file(&path).unwrap().kind,
                FileKind::Text,
                "misclassified with {pad} bytes of padding"
            );
        }

        fs::write(&path, b"\xff\xfe not utf8").unwrap();
        assert_eq!(scan_file(&path).unwrap().kind, FileKind::Binary);

        // A file that ends mid-code-point has no further bytes to complete the
        // sequence with, so the leftover carry is malformed, not truncated.
        for truncated in [&[0xc2][..], &[0xe2, 0x82][..], &[0xf0, 0x9f, 0x98][..]] {
            fs::write(&path, truncated).unwrap();
            assert_eq!(scan_file(&path).unwrap().kind, FileKind::Binary);
        }

        let mut oversize = vec![b'a'; MAX_DIFF_FILE_BYTES as usize + 1];
        oversize[MAX_DIFF_FILE_BYTES as usize / 2] = 0;
        fs::write(&path, &oversize).unwrap();
        assert_eq!(scan_file(&path).unwrap().kind, FileKind::OpaqueTooLarge);
    }

    #[test]
    fn the_windowed_digest_equals_the_whole_file_digest() {
        // The hash decides whether a file is compared at all
        // (`if base_meta.hash != target_meta.hash`), so a digest that covered
        // fewer bytes than it read would make base and target agree on a
        // changed file and silently skip the comparison. Every byte must
        // reach the hasher, so pin the digest against the whole-buffer
        // answer across sizes that cross the window boundary at every offset
        // of one, plus a zero-byte file and an exact multiple of the window.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("digest.bin");

        let mut sizes = vec![0usize];
        for base in [SCAN_CHUNK_BYTES - 1, SCAN_CHUNK_BYTES, SCAN_CHUNK_BYTES + 1] {
            sizes.extend([base, base * 2, base * 2 + 1]);
        }
        for size in sizes {
            let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            fs::write(&path, &bytes).unwrap();
            let scanned = scan_file(&path).unwrap();
            let expected: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(
                scanned.hash, expected,
                "digest differs from the whole-buffer hash at {size} bytes"
            );
        }
    }

    #[test]
    fn a_text_classified_file_that_does_not_decode_is_refused_not_coerced() {
        // scan_tree classifies invalid UTF-8 as Binary, so this is the
        // meta-vs-bytes disagreement path: a file stamped Text whose bytes
        // do not decode. Coercing the side to "" made a real change read
        // as all-add or all-delete, which silently mis-scores the verdict.
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = b"console.log('install')\n".to_vec();
        bytes.push(0xff); // lone continuation byte: not valid UTF-8
        let payload = dir.path().join("index.js");
        fs::write(&payload, &bytes).unwrap();
        let rel = Path::new("index.js");
        let meta = DiskFileMeta {
            hash: [0u8; 32],
            kind: FileKind::Text,
            is_executable: false,
        };

        let err = diff_single_file(None, Some(&payload), rel, &meta).unwrap_err();
        assert!(
            err.to_string().contains("payload bytes are not UTF-8"),
            "{err}"
        );

        let baseline = dir.path().join("baseline.js");
        fs::write(&baseline, &bytes).unwrap();
        let err = diff_single_file(Some(&baseline), Some(&payload), rel, &meta).unwrap_err();
        assert!(
            err.to_string().contains("baseline bytes are not UTF-8"),
            "{err}"
        );
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
    #[cfg(unix)]
    fn non_utf8_filename_is_reviewed_rather_than_fatal() {
        use std::os::unix::ffi::OsStrExt;
        let base = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        // A name that is not valid UTF-8. validate_entry_path only rejects NUL,
        // so this reaches the diff layer through normal extraction.
        let odd = std::ffi::OsStr::from_bytes(b"p\xffayload.sh");
        std::fs::write(target.path().join(odd), b"console.log(1)\n").unwrap();
        let empty = PackageJson::default();
        let delta = compute_delta(
            Some(base.path()),
            None,
            None,
            target.path(),
            &empty,
            "1.0.0",
        )
        .expect("a non-UTF-8 filename must not abort the review");
        assert_eq!(delta.files_added.len(), 1);
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

    #[test]
    fn find_package_prefix_handles_custom_single_directory_and_flat_roots() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(find_package_prefix(dir.path()), dir.path());

        let custom_dir = dir.path().join("lodash");
        fs::create_dir(&custom_dir).unwrap();
        assert_eq!(find_package_prefix(dir.path()), custom_dir);

        fs::write(dir.path().join("extra.txt"), "hello").unwrap();
        assert_eq!(find_package_prefix(dir.path()), dir.path());
    }

    /// The executable and binary classification, on the *merge* path.
    ///
    /// `compute_delta` has two independent implementations of this
    /// classification: a sorted merge when a baseline tree is supplied, and a
    /// one-sided walk when it is not. `detects_binary_files` passes
    /// `baseline_root: None`, so it only ever reached the second — which is why
    /// every mutant in the merge arm survived while its twin in the one-sided
    /// arm was already covered.
    ///
    /// Each assertion below is the one input that separates a mutation from the
    /// code as written:
    ///
    /// * `added-exec-mode` is executable by mode with an unremarkable name, so
    ///   it is in `new_executables` only while the test is an `||`. Under `&&`
    ///   it needs both signals and drops out.
    /// * `hook.sh` is the other half: an exec extension with no exec bit.
    /// * `both-exec` is executable in the baseline *and* the target, so it is a
    ///   modified file that gained nothing and must not be reported as a new
    ///   executable. Deleting the `!` on the baseline's `is_executable` turns
    ///   the guard into "executable in both" and reports it.
    /// * `text-to-big` crosses into `OpaqueTooLarge` by growing past 2 MiB, so
    ///   it is neither binary before nor binary after, and only the
    ///   "became opaque" arm can put it in `new_binaries`.
    /// * `bin-to-bin` is binary on both sides, which is the only way into
    ///   `modified_binaries`.
    #[test]
    fn the_merge_path_classifies_executables_and_binaries() {
        use std::os::unix::fs::PermissionsExt;

        fn manifest(version: &str) -> PackageJson {
            PackageJson {
                name: "test".into(),
                version: version.into(),
                gypfile: None,
                scripts: BTreeMap::new(),
                dependencies: BTreeMap::new(),
                optional_dependencies: BTreeMap::new(),
                peer_dependencies: BTreeMap::new(),
            }
        }

        fn set_mode(dir: &std::path::Path, name: &str, mode: u32) {
            fs::set_permissions(dir.join(name), fs::Permissions::from_mode(mode)).unwrap();
        }

        let old_dir = tempfile::tempdir().unwrap();
        let new_dir = tempfile::tempdir().unwrap();

        // Modified files.
        fs::write(old_dir.path().join("both-exec"), "old\n").unwrap();
        set_mode(old_dir.path(), "both-exec", 0o755);
        fs::write(new_dir.path().join("both-exec"), "new\n").unwrap();
        set_mode(new_dir.path(), "both-exec", 0o755);

        fs::write(old_dir.path().join("gains-exec"), "old\n").unwrap();
        set_mode(old_dir.path(), "gains-exec", 0o644);
        fs::write(new_dir.path().join("gains-exec"), "new\n").unwrap();
        set_mode(new_dir.path(), "gains-exec", 0o755);

        // Binary on both sides: the only route into `modified_binaries`.
        fs::write(old_dir.path().join("bin-to-bin"), [1u8, 0, 2, 3]).unwrap();
        fs::write(new_dir.path().join("bin-to-bin"), [9u8, 0, 8, 7]).unwrap();

        // Grows past MAX_DIFF_FILE_BYTES, so it is opaque rather than binary.
        let big = "a".repeat((MAX_DIFF_FILE_BYTES + 1024) as usize);
        fs::write(old_dir.path().join("text-to-big"), "small\n").unwrap();
        fs::write(new_dir.path().join("text-to-big"), &big).unwrap();

        // Added files, one signal each.
        fs::write(new_dir.path().join("added-exec-mode"), "hi\n").unwrap();
        set_mode(new_dir.path(), "added-exec-mode", 0o755);
        fs::write(new_dir.path().join("hook.sh"), "hi\n").unwrap();
        set_mode(new_dir.path(), "hook.sh", 0o644);

        // Added, and opaque rather than binary. This is the only shape that
        // separates the two arms of the `new_binaries` test in the `(None,
        // Some(_))` merge arm, and that arm is reachable only with a baseline --
        // the one-sided walk has its own copy of the check further down.
        fs::write(new_dir.path().join("added-opaque"), &big).unwrap();

        // Added, opaque, and named so it sorts *after* every baseline entry.
        // That is what routes it through the `(None, Some(_))` arm rather than
        // the `Greater` one: the merge compares the two sorted streams, so a
        // file that sorts before the next baseline entry is classified as
        // `Greater` and one that sorts after all of them is classified only once
        // the baseline iterator is exhausted. The two arms carry their own copy
        // of the check, so an added file only reaches one of them by name.
        fs::write(new_dir.path().join("zzz-opaque"), &big).unwrap();

        // Added, executable, and named so it sorts after every baseline entry,
        // for the executable check in the same `(None, Some(_))` arm.
        fs::write(new_dir.path().join("zzz-exec"), "hi\n").unwrap();
        set_mode(new_dir.path(), "zzz-exec", 0o755);

        // Added and genuinely *binary* -- a NUL byte, which is what makes
        // `classify_bytes` call it Binary rather than OpaqueTooLarge. The
        // opaque file above covers the other arm of the `||`; only a real
        // binary tells a `==` from a `!=` here, because an opaque file satisfies
        // "kind is not Binary" as readily as "kind is Binary".
        fs::write(new_dir.path().join("zzz-binary"), [1u8, 0, 2, 3]).unwrap();

        // Removed.
        fs::write(old_dir.path().join("gone"), "bye\n").unwrap();

        let base_m = manifest("1.0.0");
        let target_m = manifest("1.1.0");
        let delta = compute_delta(
            Some(old_dir.path()),
            Some(&base_m),
            Some("1.0.0"),
            new_dir.path(),
            &target_m,
            "1.1.0",
        )
        .unwrap();

        for want in ["gains-exec", "added-exec-mode", "hook.sh", "zzz-exec"] {
            assert!(
                delta.new_executables.iter().any(|p| p == want),
                "`{want}` must be reported as a new executable, got {:?}",
                delta.new_executables
            );
        }
        assert!(
            !delta.new_executables.iter().any(|p| p == "both-exec"),
            "a file executable in both trees gained nothing: {:?}",
            delta.new_executables
        );

        assert!(
            delta.modified_binaries.iter().any(|p| p == "bin-to-bin"),
            "binary before and after is a modified binary, got {:?}",
            delta.modified_binaries
        );
        assert!(
            delta.new_binaries.iter().any(|p| p == "text-to-big"),
            "a file that becomes opaque is a new binary, got {:?}",
            delta.new_binaries
        );
        for want in ["added-opaque", "zzz-opaque", "zzz-binary"] {
            assert!(
                delta.new_binaries.iter().any(|p| p == want),
                "an added non-text file is a new binary: `{want}`, got {:?}",
                delta.new_binaries
            );
        }
        assert!(
            delta
                .files_removed
                .iter()
                .any(|c| c.relative_path == "gone"),
            "the removed file must still be reported"
        );
    }

    /// An added file that is opaque rather than binary. `classify_bytes` tests
    /// the size cap *before* the NUL scan, so a file over 2 MiB is
    /// `OpaqueTooLarge` and never `Binary` — which is the only way to tell the
    /// two arms of the `new_binaries` test apart. `detects_binary_files` adds a
    /// 4-byte `.node` file, where both sides of the `||` are false, so it passes
    /// whether the operator is `||` or `&&`.
    #[test]
    fn an_added_opaque_file_counts_as_a_new_binary() {
        let new_dir = tempfile::tempdir().unwrap();
        let big = "a".repeat((MAX_DIFF_FILE_BYTES + 1024) as usize);
        fs::write(new_dir.path().join("huge.txt"), &big).unwrap();

        let m = PackageJson {
            name: "test".into(),
            version: "1.0.0".into(),
            gypfile: None,
            scripts: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
        };
        let delta = compute_delta(None, None, None, new_dir.path(), &m, "1.0.0").unwrap();

        assert_eq!(delta.files_added[0].kind, FileKind::OpaqueTooLarge);
        assert!(
            delta.new_binaries.contains(&"huge.txt".to_string()),
            "an opaque file is not scannable, so it counts as a new binary: {:?}",
            delta.new_binaries
        );
    }
}
