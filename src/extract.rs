use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path};

use crate::error::BluelineError;

const DEFAULT_MAX_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES: usize = 100_000;
const DEFAULT_MAX_ENTRY_BYTES: u64 = 128 * 1024 * 1024;

/// Hard caps applied while unpacking an untrusted tarball (bomb guard).
#[derive(Debug, Clone)]
pub struct ExtractionLimits {
    pub max_unpacked_bytes: u64,
    pub max_entries: usize,
    pub max_entry_bytes: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_unpacked_bytes: DEFAULT_MAX_UNPACKED_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_entry_bytes: DEFAULT_MAX_ENTRY_BYTES,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ExtractStats {
    pub files: usize,
    pub dirs: usize,
    pub unpacked_bytes: u64,
}

/// Extract a gzipped tarball into `dest` under hard bounds.
///
/// Safety invariants:
/// - only regular files and directories are unpacked (symlinks, hardlinks,
///   device nodes, FIFOs, sockets are rejected);
/// - absolute paths, `..` traversal, and drive prefixes are rejected;
/// - total unpacked size, per-entry size, and entry count are capped;
/// - setuid/setgid bits are stripped after unpacking.
pub fn safe_extract(
    tarball: &[u8],
    dest: &Path,
    limits: &ExtractionLimits,
) -> Result<ExtractStats, BluelineError> {
    let decoder = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|e| BluelineError::Extraction(format!("reading tar stream: {e}")))?;

    let mut stats = ExtractStats::default();
    let mut seen = 0usize;

    for entry in entries {
        seen += 1;
        if seen > limits.max_entries {
            return Err(BluelineError::ExtractionLimit(format!(
                "entry count exceeded ({seen}/{})",
                limits.max_entries
            )));
        }

        let mut entry =
            entry.map_err(|e| BluelineError::Extraction(format!("reading tar entry: {e}")))?;

        let entry_type = entry.header().entry_type();
        let size = entry.size();

        // Metadata entries (GNU long names, pax extensions) carry headers in the stream.
        // Cap their size and count them towards total unpacked bytes to prevent tar bombs.
        if entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_global_extensions()
            || entry_type.is_pax_local_extensions()
        {
            const MAX_METADATA_ENTRY_BYTES: u64 = 64 * 1024;
            if size > MAX_METADATA_ENTRY_BYTES {
                return Err(BluelineError::ExtractionLimit(format!(
                    "metadata entry exceeds cap of {MAX_METADATA_ENTRY_BYTES} bytes"
                )));
            }
            if stats.unpacked_bytes.saturating_add(size) > limits.max_unpacked_bytes {
                return Err(BluelineError::ExtractionLimit(format!(
                    "total unpacked size would exceed cap {}",
                    limits.max_unpacked_bytes
                )));
            }
            stats.unpacked_bytes += size;
            continue;
        }

        if !entry_type.is_file() && !entry_type.is_dir() {
            return Err(BluelineError::ExtractionLimit(format!(
                "unsupported entry type {entry_type:?} (symlinks/hardlinks/special files are rejected)"
            )));
        }

        let path = entry
            .path()
            .map_err(|e| BluelineError::Extraction(format!("unreadable entry path: {e}")))?
            .to_path_buf();
        validate_entry_path(&path).map_err(BluelineError::Extraction)?;

        if entry_type.is_file() {
            if size > limits.max_entry_bytes {
                return Err(BluelineError::ExtractionLimit(format!(
                    "entry `{}` is {size} bytes, exceeding per-entry cap {}",
                    path.display(),
                    limits.max_entry_bytes
                )));
            }
            if stats.unpacked_bytes.saturating_add(size) > limits.max_unpacked_bytes {
                return Err(BluelineError::ExtractionLimit(format!(
                    "total unpacked size would exceed cap {}",
                    limits.max_unpacked_bytes
                )));
            }
        }

        entry.unpack_in(dest).map_err(|e| {
            BluelineError::Extraction(format!("unpacking `{}`: {e}", path.display()))
        })?;

        strip_special_bits(&dest.join(&path));
        if entry_type.is_file() {
            stats.files += 1;
            stats.unpacked_bytes += size;
        } else {
            stats.dirs += 1;
        }
    }

    Ok(stats)
}

pub fn safe_extract_wheel(
    bytes: &[u8],
    dest: &Path,
    limits: &ExtractionLimits,
) -> Result<ExtractStats, BluelineError> {
    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| BluelineError::Extraction(format!("reading zip archive: {e}")))?;

    let len = archive.len();
    if len > limits.max_entries {
        return Err(BluelineError::ExtractionLimit(format!(
            "entry count {len} exceeds cap {}",
            limits.max_entries
        )));
    }

    let mut stats = ExtractStats::default();
    let mut seen: HashSet<String> = HashSet::with_capacity(len);

    for idx in 0..len {
        if stats.files + stats.dirs >= limits.max_entries {
            return Err(BluelineError::ExtractionLimit(format!(
                "entry count exceeded ({}/{})",
                stats.files + stats.dirs + 1,
                limits.max_entries
            )));
        }

        let mut file = archive
            .by_index(idx)
            .map_err(|e| BluelineError::Extraction(format!("reading zip entry {idx}: {e}")))?;

        let raw_name = file.name().to_string();

        if raw_name.as_bytes().contains(&0) {
            return Err(BluelineError::Extraction(format!(
                "entry `{raw_name}` contains NUL byte"
            )));
        }

        if file.encrypted() {
            return Err(BluelineError::Extraction(format!(
                "encrypted entry `{raw_name}` rejected"
            )));
        }

        match file.compression() {
            zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated => {}
            other => {
                return Err(BluelineError::Extraction(format!(
                    "unsupported compression {other:?} for entry `{raw_name}`"
                )));
            }
        }

        let is_dir = raw_name.ends_with('/');

        let enclosed = file.enclosed_name();
        let Some(enclosed_path) = enclosed else {
            return Err(BluelineError::Extraction(format!(
                "entry `{raw_name}` fails enclosed_name check (absolute or traversal)"
            )));
        };

        validate_entry_path(&enclosed_path).map_err(BluelineError::Extraction)?;

        let normalized_key = enclosed_path
            .components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .collect::<std::path::PathBuf>()
            .to_string_lossy()
            .into_owned();
        if !seen.insert(normalized_key.clone()) {
            return Err(BluelineError::Extraction(format!(
                "duplicate entry `{raw_name}` (normalized `{normalized_key}`)"
            )));
        }

        let is_symlink = file.is_symlink();
        let symlink_via_mode = file.unix_mode().is_some_and(|m| (m & 0o170000) == 0o120000);
        if is_symlink || symlink_via_mode {
            return Err(BluelineError::Extraction(format!(
                "symlink entry `{raw_name}` rejected"
            )));
        }

        let declared_size = file.size();

        if is_dir {
            if declared_size != 0 {
                return Err(BluelineError::Extraction(format!(
                    "directory entry `{raw_name}` has non-zero size {declared_size}"
                )));
            }
            let out_path = dest.join(&enclosed_path);
            fs::create_dir_all(&out_path).map_err(|e| {
                BluelineError::Extraction(format!("creating dir `{}`: {e}", out_path.display()))
            })?;
            set_dir_perm(&out_path);
            stats.dirs += 1;
            continue;
        }

        if declared_size > limits.max_entry_bytes {
            return Err(BluelineError::ExtractionLimit(format!(
                "entry `{raw_name}` is {declared_size} bytes, exceeding per-entry cap {}",
                limits.max_entry_bytes
            )));
        }
        if stats.unpacked_bytes.saturating_add(declared_size) > limits.max_unpacked_bytes {
            return Err(BluelineError::ExtractionLimit(format!(
                "total unpacked size would exceed cap {}",
                limits.max_unpacked_bytes
            )));
        }

        let out_path = dest.join(&enclosed_path);
        if let Some(parent) = out_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                BluelineError::Extraction(format!(
                    "creating parent dir `{}`: {e}",
                    parent.display()
                ))
            })?;
        }

        let mut out_file = fs::File::create(&out_path).map_err(|e| {
            BluelineError::Extraction(format!("creating file `{}`: {e}", out_path.display()))
        })?;

        let mut actual_written: u64 = 0;
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf).map_err(|e| {
                BluelineError::Extraction(format!("reading zip entry `{raw_name}`: {e}"))
            })?;
            if n == 0 {
                break;
            }
            if actual_written + n as u64 > limits.max_entry_bytes {
                return Err(BluelineError::ExtractionLimit(format!(
                    "entry `{raw_name}` exceeds per-entry cap {} during inflate",
                    limits.max_entry_bytes
                )));
            }
            if stats.unpacked_bytes + actual_written + n as u64 > limits.max_unpacked_bytes {
                return Err(BluelineError::ExtractionLimit(format!(
                    "total unpacked size would exceed cap {}",
                    limits.max_unpacked_bytes
                )));
            }
            out_file.write_all(&buf[..n]).map_err(|e| {
                BluelineError::Extraction(format!("writing file `{}`: {e}", out_path.display()))
            })?;
            actual_written += n as u64;
        }

        if actual_written != declared_size {
            return Err(BluelineError::Extraction(format!(
                "entry `{raw_name}` size mismatch: declared {declared_size} vs actual {actual_written}"
            )));
        }

        set_file_perm(&out_path);
        stats.files += 1;
        stats.unpacked_bytes += actual_written;
    }

    Ok(stats)
}

const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$",
    "CONOUT$", "CLOCK$",
];

pub fn validate_entry_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("empty entry path".to_string());
    }
    if path.is_absolute() {
        return Err(format!("absolute entry path `{}` rejected", path.display()));
    }
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.contains(&0) {
        return Err(format!(
            "entry path `{}` containing NUL byte rejected",
            path.display()
        ));
    }
    if bytes.contains(&b'\\') {
        return Err(format!(
            "entry path `{}` containing backslash rejected",
            path.display()
        ));
    }
    if bytes.contains(&b':') {
        return Err(format!(
            "entry path `{}` containing colon rejected",
            path.display()
        ));
    }
    let mut has_normal = false;
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err(format!(
                    "parent traversal in entry path `{}` rejected",
                    path.display()
                ));
            }
            Component::RootDir => {
                return Err(format!(
                    "root directory component in entry path `{}` rejected",
                    path.display()
                ));
            }
            Component::Prefix(_) => {
                return Err(format!(
                    "drive prefix in entry path `{}` rejected",
                    path.display()
                ));
            }
            Component::Normal(os_name) => {
                has_normal = true;
                let name = os_name.to_string_lossy();
                let stem = name.split('.').next().unwrap_or(&name);
                if WINDOWS_RESERVED_NAMES
                    .iter()
                    .any(|&r| r.eq_ignore_ascii_case(stem))
                {
                    return Err(format!(
                        "reserved device name `{}` in entry path `{}` rejected",
                        name,
                        path.display()
                    ));
                }
            }
            Component::CurDir => {}
        }
    }
    if !has_normal {
        return Err(format!(
            "entry path `{}` resolving to current directory rejected",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_perm(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_perm(_path: &Path, _mode: u32) {}

/// Strip setuid/setgid/sticky from unpacked files and directories (they must never run here).
/// Ensures directories retain owner read/write/execute permissions so tempdir deletion succeeds.
#[cfg(unix)]
fn strip_special_bits(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = fs::symlink_metadata(path) {
        if md.is_symlink() {
            return;
        }
        let mut perm = md.permissions();
        let mut mode = perm.mode() & 0o777;
        if md.is_dir() {
            mode |= 0o700;
        }
        perm.set_mode(mode);
        let _ = fs::set_permissions(path, perm);
    }
}

#[cfg(not(unix))]
fn strip_special_bits(_path: &Path) {}

#[cfg(unix)]
fn set_file_perm(path: &Path) {
    set_perm(path, 0o644);
}

#[cfg(not(unix))]
fn set_file_perm(_path: &Path) {}

#[cfg(unix)]
fn set_dir_perm(path: &Path) {
    set_perm(path, 0o755);
}

#[cfg(not(unix))]
fn set_dir_perm(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    /// Hand-crafted raw tar bytes. `typeflag`: 0x30 regular, 0x32 symlink,
    /// 0x31 hardlink, 0x35 directory. The tar *builder* refuses such paths,
    /// so malicious archives are written by hand — as they arrive on the wire.
    fn raw_header(name: &str, typeflag: u8, size: u64, linkname: &str, mode: u32) -> Vec<u8> {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(format!("{:07o}\x00", mode).as_bytes());
        h[108..116].copy_from_slice(b"0000000\x00");
        h[116..124].copy_from_slice(b"0000000\x00");
        h[124..136].copy_from_slice(format!("{:011o}\x00", size).as_bytes());
        h[136..148].copy_from_slice(b"00000000000\x00");
        h[156] = typeflag;
        h[157..157 + linkname.len()].copy_from_slice(linkname.as_bytes());
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        let chksum = format!("{:06o}\x00 ", sum);
        h[148..156].copy_from_slice(chksum.as_bytes());
        h.to_vec()
    }

    fn raw_tarball(entries: &[(String, u8, &str)]) -> Vec<u8> {
        use std::io::Write;

        let mut out = Vec::new();
        for (name, typeflag, linkname) in entries {
            let mut data = [0u8; 1];
            let size = if *typeflag == 0x30 {
                data[0] = b'x';
                1
            } else {
                0
            };
            out.extend_from_slice(&raw_header(name, *typeflag, size, linkname, 0o644));
            if size == 1 {
                out.extend_from_slice(&data);
            }
        }
        out.extend_from_slice(&[0u8; 1024]);
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&out).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn extracts_plain_files() {
        let tarball = make_tarball(&[
            ("package.json", b"{}"),
            ("lib/index.js", b"module.exports = 1;"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let stats = safe_extract(&tarball, dir.path(), &ExtractionLimits::default()).unwrap();
        assert_eq!(stats.files, 2);
        assert_eq!(stats.unpacked_bytes, 21);
        assert!(dir.path().join("lib/index.js").exists());
    }

    #[test]
    fn rejects_parent_traversal() {
        let tarball = raw_tarball(&[("../evil".into(), 0x30, "")]);
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract(&tarball, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("traversal"));
    }

    #[test]
    fn rejects_absolute_paths() {
        let tarball = raw_tarball(&[("/etc/cron.d/evil".into(), 0x30, "")]);
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract(&tarball, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn rejects_symlinks() {
        let tarball = raw_tarball(&[("link".into(), 0x32, "/etc/passwd")]);
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract(&tarball, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("unsupported entry type"));
    }

    #[test]
    fn rejects_hardlinks() {
        let tarball = raw_tarball(&[("hard".into(), 0x31, "target")]);
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract(&tarball, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("unsupported entry type"));
    }

    #[test]
    fn rejects_colons_and_reserved_dos_names() {
        let dir = tempfile::tempdir().unwrap();

        let tarball_colon = make_tarball(&[("foo:bar.js", b"console.log(1);")]);
        let err =
            safe_extract(&tarball_colon, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("colon"));

        let tarball_aux = make_tarball(&[("aux.json", b"{}")]);
        let err = safe_extract(&tarball_aux, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("reserved device name"));

        let tarball_com1 = make_tarball(&[("dir/com1.js", b"")]);
        let err =
            safe_extract(&tarball_com1, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("reserved device name"));

        let tarball_conin = make_tarball(&[("conin$.txt", b"")]);
        let err =
            safe_extract(&tarball_conin, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("reserved device name"));

        let tarball_conout = make_tarball(&[("dir/conout$.dat", b"")]);
        let err =
            safe_extract(&tarball_conout, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("reserved device name"));

        let tarball_clock = make_tarball(&[("clock$.txt", b"")]);
        let err =
            safe_extract(&tarball_clock, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("reserved device name"));
    }

    #[test]
    fn caps_entry_count() {
        let entries: Vec<(&str, &[u8])> = (0..5)
            .map(|i| {
                let name: &'static mut str = Box::leak(format!("f{i}").into_boxed_str());
                let name: &'static str = name;
                (name, &b"x"[..])
            })
            .collect();
        let tarball = make_tarball(&entries);
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_entries: 2,
            ..ExtractionLimits::default()
        };
        let err = safe_extract(&tarball, dir.path(), &limits).unwrap_err();
        assert!(matches!(err, BluelineError::ExtractionLimit(_)));
    }

    #[test]
    fn caps_total_unpacked_bytes() {
        let tarball = make_tarball(&[("big", &[0u8; 1024])]);
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_unpacked_bytes: 512,
            ..ExtractionLimits::default()
        };
        let err = safe_extract(&tarball, dir.path(), &limits).unwrap_err();
        assert!(matches!(err, BluelineError::ExtractionLimit(_)));
    }

    #[test]
    fn caps_per_entry_bytes() {
        let tarball = make_tarball(&[("big", &[0u8; 4096])]);
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_entry_bytes: 1024,
            ..ExtractionLimits::default()
        };
        let err = safe_extract(&tarball, dir.path(), &limits).unwrap_err();
        assert!(matches!(err, BluelineError::ExtractionLimit(_)));
    }

    #[test]
    fn defaults_are_sane() {
        let d = ExtractionLimits::default();
        assert_eq!(d.max_unpacked_bytes, 512 * 1024 * 1024);
        assert_eq!(d.max_entries, 100_000);
        assert_eq!(d.max_entry_bytes, 128 * 1024 * 1024);
    }

    #[test]
    fn skips_metadata_entries() {
        // GNU long-name / long-link and pax extension entries carry no
        // payload and must be skipped, never extracted or rejected.
        for (name, typeflag) in [
            ("longname", 0x4c_u8),
            ("longlink", 0x4b_u8),
            ("paxglobal", 0x67_u8),
            ("paxlocal", 0x78_u8),
        ] {
            let tarball = raw_tarball(&[(name.to_string(), typeflag, "")]);
            let dir = tempfile::tempdir().unwrap();
            let stats = safe_extract(&tarball, dir.path(), &ExtractionLimits::default()).unwrap();
            assert_eq!(stats.files, 0, "metadata entry {name} must be skipped");
        }
    }

    #[test]
    fn entry_count_at_boundary() {
        let entries: Vec<(&str, &[u8])> = (0..2)
            .map(|i| {
                let name: &'static str = Box::leak(format!("f{i}").into_boxed_str());
                (name, &b"x"[..])
            })
            .collect();
        let tarball = make_tarball(&entries);
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_entries: 2,
            ..ExtractionLimits::default()
        };
        let stats = safe_extract(&tarball, dir.path(), &limits).unwrap();
        assert_eq!(stats.files, 2, "exactly max_entries files must extract");
    }

    #[test]
    fn per_entry_size_at_boundary() {
        let tarball = make_tarball(&[("big", &[0u8; 1024])]);
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_entry_bytes: 1024,
            ..ExtractionLimits::default()
        };
        let stats = safe_extract(&tarball, dir.path(), &limits).unwrap();
        assert_eq!(
            stats.files, 1,
            "entry at exactly the per-entry cap must extract"
        );
    }

    #[test]
    fn total_size_at_boundary() {
        let tarball = make_tarball(&[("big", &[0u8; 512])]);
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_unpacked_bytes: 512,
            ..ExtractionLimits::default()
        };
        let stats = safe_extract(&tarball, dir.path(), &limits).unwrap();
        assert_eq!(
            stats.unpacked_bytes, 512,
            "total at exactly the cap must extract"
        );
    }

    #[test]
    fn counts_directories() {
        let tarball = raw_tarball(&[("sub".into(), 0x35, ""), ("file2".into(), 0x30, "")]);
        let dir = tempfile::tempdir().unwrap();
        let stats = safe_extract(&tarball, dir.path(), &ExtractionLimits::default()).unwrap();
        assert_eq!(stats.dirs, 1);
        assert_eq!(stats.files, 1);
    }

    #[cfg(unix)]
    #[test]
    fn strips_setuid_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evil");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap();
        strip_special_bits(&path);
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "permission bits preserved");
        assert_eq!(mode & 0o4000, 0, "setuid bit must be stripped");
    }

    #[cfg(unix)]
    #[test]
    fn strips_special_bits_on_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evildir");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o2755)).unwrap();
        strip_special_bits(&path);
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "directory permission bits preserved");
        assert_eq!(
            mode & 0o2000,
            0,
            "setgid bit must be stripped from directory"
        );
    }

    #[test]
    fn rejects_backslash_in_path() {
        let tarball = raw_tarball(&[(r"foo\bar".into(), 0x30, "")]);
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract(&tarball, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("backslash"));
    }

    #[test]
    fn rejects_root_dir_component() {
        let err = validate_entry_path(Path::new("/root/foo")).unwrap_err();
        assert!(err.contains("absolute") || err.contains("root directory"));
    }

    #[test]
    fn metadata_entries_counted_against_limit() {
        let entries = vec![
            ("meta1".to_string(), 0x4c_u8, ""),
            ("meta2".to_string(), 0x4c_u8, ""),
            ("meta3".to_string(), 0x4c_u8, ""),
        ];
        let tarball = raw_tarball(&entries);
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_entries: 2,
            ..ExtractionLimits::default()
        };
        let err = safe_extract(&tarball, dir.path(), &limits).unwrap_err();
        assert!(matches!(err, BluelineError::ExtractionLimit(_)));
    }

    fn raw_tarball_with_payload(entries: &[(String, u8, Vec<u8>)]) -> Vec<u8> {
        use std::io::Write;
        let mut out = Vec::new();
        for (name, typeflag, data) in entries {
            let size = data.len() as u64;
            out.extend_from_slice(&raw_header(name, *typeflag, size, "", 0o644));
            out.extend_from_slice(data);
            let pad = (512 - (data.len() % 512)) % 512;
            out.extend_from_slice(&vec![0u8; pad]);
        }
        out.extend_from_slice(&[0u8; 1024]);
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&out).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn metadata_entry_size_limits() {
        let dir = tempfile::tempdir().unwrap();
        // Exact metadata cap 64 KiB succeeds
        let valid_meta = raw_tarball_with_payload(&[
            ("././@LongLink".into(), 0x4c, vec![b'a'; 64 * 1024]),
            ("file.txt".into(), 0x30, vec![b'x'; 1]),
        ]);
        let stats = safe_extract(&valid_meta, dir.path(), &ExtractionLimits::default()).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.unpacked_bytes, (64 * 1024) + 1);

        // 64 KiB + 1 fails
        let invalid_meta = raw_tarball_with_payload(&[(
            "././@LongLink".into(),
            0x4c,
            vec![b'a'; (64 * 1024) + 1],
        )]);
        let err =
            safe_extract(&invalid_meta, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("metadata entry exceeds cap"));
    }

    #[test]
    fn metadata_entry_accounts_for_total_unpacked_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_unpacked_bytes: 200,
            ..ExtractionLimits::default()
        };

        // Exactly at cap: 100 metadata bytes + 100 file bytes = 200 bytes total
        let exact_tarball = raw_tarball_with_payload(&[
            ("././@LongLink".into(), 0x4c, vec![b'a'; 100]),
            ("file.txt".into(), 0x30, vec![b'x'; 100]),
        ]);
        let stats = safe_extract(&exact_tarball, dir.path(), &limits).unwrap();
        assert_eq!(stats.unpacked_bytes, 200);

        // Exceeds total unpacked bytes: 100 metadata bytes + 101 file bytes = 201 bytes
        let exceed_tarball = raw_tarball_with_payload(&[
            ("././@LongLink".into(), 0x4c, vec![b'a'; 100]),
            ("file.txt".into(), 0x30, vec![b'x'; 101]),
        ]);
        let err = safe_extract(&exceed_tarball, dir.path(), &limits).unwrap_err();
        assert!(
            err.to_string()
                .contains("total unpacked size would exceed cap")
        );
    }

    #[test]
    fn metadata_entry_accounts_for_total_unpacked_bytes_alone() {
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_unpacked_bytes: 200,
            ..ExtractionLimits::default()
        };

        // Exactly at cap for metadata entry alone: 200 metadata bytes
        let exact_meta_alone =
            raw_tarball_with_payload(&[("././@LongLink".into(), 0x4c, vec![b'a'; 200])]);
        let stats = safe_extract(&exact_meta_alone, dir.path(), &limits).unwrap();
        assert_eq!(stats.unpacked_bytes, 200);

        // Exceeds total unpacked bytes for metadata entry alone: 201 bytes
        let exceed_meta_alone =
            raw_tarball_with_payload(&[("././@LongLink".into(), 0x4c, vec![b'a'; 201])]);
        let err = safe_extract(&exceed_meta_alone, dir.path(), &limits).unwrap_err();
        assert!(
            err.to_string()
                .contains("total unpacked size would exceed cap")
        );
    }
}

#[cfg(test)]
mod wheel_tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn make_wheel(entries: &[(&str, &[u8], zip::CompressionMethod)]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut zw = zip::ZipWriter::new(&mut buf);
        for (name, data, method) in entries {
            let opts = SimpleFileOptions::default().compression_method(*method);
            if name.ends_with('/') {
                zw.add_directory(*name, opts).unwrap();
            } else {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(data).unwrap();
            }
        }
        zw.finish().unwrap();
        buf.into_inner()
    }

    #[allow(dead_code)]
    fn make_wheel_with_unix_mode(
        entries: &[(&str, &[u8], zip::CompressionMethod, u32)],
    ) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut zw = zip::ZipWriter::new(&mut buf);
        for (name, data, method, mode) in entries {
            let opts = SimpleFileOptions::default()
                .compression_method(*method)
                .unix_permissions(*mode);
            if name.ends_with('/') {
                zw.add_directory(*name, opts).unwrap();
            } else {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(data).unwrap();
            }
        }
        zw.finish().unwrap();
        buf.into_inner()
    }

    #[test]
    fn extracts_plain_files() {
        let bytes = make_wheel(&[
            (
                "pkg-1.0.dist-info/METADATA",
                b"Name: pkg",
                zip::CompressionMethod::Stored,
            ),
            (
                "pkg/module.py",
                b"print(1)",
                zip::CompressionMethod::Deflated,
            ),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let stats = safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap();
        assert_eq!(stats.files, 2);
        assert!(dir.path().join("pkg/module.py").exists());
    }

    #[test]
    fn rejects_encrypted() {
        let mut bytes = make_wheel(&[("secret.txt", b"hi", zip::CompressionMethod::Stored)]);
        for i in 0..bytes.len().saturating_sub(4) {
            if bytes[i..i + 4] == [0x50, 0x4b, 0x03, 0x04] && i + 6 < bytes.len() {
                bytes[i + 6] |= 0x01;
            } else if bytes[i..i + 4] == [0x50, 0x4b, 0x01, 0x02] && i + 8 < bytes.len() {
                bytes[i + 8] |= 0x01;
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("encrypted") || msg.contains("password"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unsupported_compression() {
        let bytes_stored = make_wheel(&[("a.txt", b"hi", zip::CompressionMethod::Stored)]);
        let mut mutated = bytes_stored.clone();
        let mut count = 0;
        for i in 0..mutated.len().saturating_sub(4) {
            if mutated[i..i + 4] == [0x50, 0x4b, 0x03, 0x04]
                && i + 10 < mutated.len()
                && mutated[i + 8] == 0
                && mutated[i + 9] == 0
            {
                mutated[i + 8] = 12;
                mutated[i + 9] = 0;
                count += 1;
            } else if mutated[i..i + 4] == [0x50, 0x4b, 0x01, 0x02]
                && i + 12 < mutated.len()
                && mutated[i + 10] == 0
                && mutated[i + 11] == 0
            {
                mutated[i + 10] = 12;
                mutated[i + 11] = 0;
                count += 1;
            }
        }
        assert!(count >= 2, "failed to patch compression");
        let dir = tempfile::tempdir().unwrap();
        let err =
            safe_extract_wheel(&mutated, dir.path(), &ExtractionLimits::default()).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("unsupported") && (msg.contains("compression") || msg.contains("method")),
            "{err}"
        );
    }

    #[test]
    fn rejects_traversal_via_enclosed() {
        let bytes = make_wheel(&[("../evil.txt", b"hi", zip::CompressionMethod::Stored)]);
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("enclosed_name"), "{err}");
    }

    #[test]
    fn rejects_absolute_path() {
        let bytes = make_wheel(&[("/etc/evil", b"hi", zip::CompressionMethod::Stored)]);
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("enclosed_name"), "{err}");
    }

    #[test]
    fn rejects_symlink_via_mode() {
        let mut bytes = make_wheel(&[("link", b"target", zip::CompressionMethod::Stored)]);
        for i in 0..bytes.len().saturating_sub(4) {
            if bytes[i..i + 4] == [0x50, 0x4b, 0x01, 0x02] && i + 42 < bytes.len() {
                let mode: u32 = 0o120777;
                let attrs = mode << 16;
                bytes[i + 38] = (attrs & 0xFF) as u8;
                bytes[i + 39] = ((attrs >> 8) & 0xFF) as u8;
                bytes[i + 40] = ((attrs >> 16) & 0xFF) as u8;
                bytes[i + 41] = ((attrs >> 24) & 0xFF) as u8;
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn rejects_duplicate_names() {
        let mut buf = Cursor::new(Vec::new());
        let mut zw = zip::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zw.start_file("dup.txt", opts).unwrap();
        zw.write_all(b"a").unwrap();
        let second = zw.start_file("dup.txt", opts);
        if second.is_err() {
            return;
        }
        zw.write_all(b"b").unwrap();
        let finish = zw.finish();
        if finish.is_err() {
            return;
        }
        let bytes = buf.into_inner();
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn rejects_normalized_duplicate_paths() {
        let bytes = {
            let mut buf = Cursor::new(Vec::new());
            let mut zw = zip::ZipWriter::new(&mut buf);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zw.start_file("a.txt", opts).unwrap();
            zw.write_all(b"first").unwrap();
            zw.start_file("./a.txt", opts).unwrap();
            zw.write_all(b"second").unwrap();
            zw.finish().unwrap();
            buf.into_inner()
        };
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn rejects_backslash_and_colon_via_validate() {
        for name in ["foo\\bar.txt", "foo:bar.txt"] {
            let bytes = make_wheel(&[(name, b"hi", zip::CompressionMethod::Stored)]);
            let dir = tempfile::tempdir().unwrap();
            let err =
                safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap_err();
            assert!(
                err.to_string().contains(name)
                    || err.to_string().contains("backslash")
                    || err.to_string().contains("colon"),
                "{err} for {name}"
            );
        }
    }

    #[test]
    fn rejects_windows_reserved() {
        let bytes = make_wheel(&[("CON.txt", b"hi", zip::CompressionMethod::Stored)]);
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    #[test]
    fn rejects_nul_byte() {
        let name = "a\0b.txt";
        let bytes = make_wheel(&[(name, b"hi", zip::CompressionMethod::Stored)]);
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("NUL"), "{err}");
    }

    #[test]
    fn enforces_max_entries() {
        let bytes = make_wheel(&[
            ("a.txt", b"a", zip::CompressionMethod::Stored),
            ("b.txt", b"b", zip::CompressionMethod::Stored),
            ("c.txt", b"c", zip::CompressionMethod::Stored),
        ]);
        let limits = ExtractionLimits {
            max_entries: 2,
            ..ExtractionLimits::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &limits).unwrap_err();
        assert!(matches!(err, BluelineError::ExtractionLimit(_)), "{err}");
    }

    #[test]
    fn enforces_max_entry_bytes_declared() {
        let bytes = make_wheel(&[("big.bin", &[0u8; 1024], zip::CompressionMethod::Stored)]);
        let limits = ExtractionLimits {
            max_entry_bytes: 512,
            ..ExtractionLimits::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &limits).unwrap_err();
        assert!(matches!(err, BluelineError::ExtractionLimit(_)), "{err}");
    }

    #[test]
    fn enforces_max_unpacked_during_stream() {
        let bytes = make_wheel(&[
            ("a.bin", &[0u8; 600], zip::CompressionMethod::Stored),
            ("b.bin", &[0u8; 600], zip::CompressionMethod::Stored),
        ]);
        let limits = ExtractionLimits {
            max_unpacked_bytes: 1000,
            ..ExtractionLimits::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let err = safe_extract_wheel(&bytes, dir.path(), &limits).unwrap_err();
        assert!(matches!(err, BluelineError::ExtractionLimit(_)), "{err}");
    }

    #[test]
    fn handles_directories() {
        let bytes = make_wheel(&[
            ("mydir/", b"", zip::CompressionMethod::Stored),
            ("mydir/file.txt", b"hi", zip::CompressionMethod::Stored),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let stats = safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap();
        assert_eq!(stats.dirs, 1);
        assert_eq!(stats.files, 1);
        assert!(dir.path().join("mydir/file.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn file_perms_are_644() {
        use std::os::unix::fs::PermissionsExt;
        let bytes = make_wheel(&[("a.txt", b"hi", zip::CompressionMethod::Stored)]);
        let dir = tempfile::tempdir().unwrap();
        safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap();
        let mode = fs::metadata(dir.path().join("a.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn dir_perms_are_755() {
        use std::os::unix::fs::PermissionsExt;
        let bytes = make_wheel(&[("mydir/", b"", zip::CompressionMethod::Stored)]);
        let dir = tempfile::tempdir().unwrap();
        safe_extract_wheel(&bytes, dir.path(), &ExtractionLimits::default()).unwrap();
        let mode = fs::metadata(dir.path().join("mydir"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn wheel_exact_limits_and_mode_tests() {
        // Exact entry count
        let limits_entries = ExtractionLimits {
            max_entries: 2,
            ..ExtractionLimits::default()
        };
        let b2 = make_wheel(&[
            ("a.txt", b"a", zip::CompressionMethod::Stored),
            ("b.txt", b"b", zip::CompressionMethod::Stored),
        ]);
        let dir = tempfile::tempdir().unwrap();
        assert!(safe_extract_wheel(&b2, dir.path(), &limits_entries).is_ok());

        let b3 = make_wheel(&[
            ("a.txt", b"a", zip::CompressionMethod::Stored),
            ("b.txt", b"b", zip::CompressionMethod::Stored),
            ("c.txt", b"c", zip::CompressionMethod::Stored),
        ]);
        assert!(matches!(
            safe_extract_wheel(&b3, dir.path(), &limits_entries).unwrap_err(),
            BluelineError::ExtractionLimit(_)
        ));

        // Exact declared entry bytes
        let limits_entry_bytes = ExtractionLimits {
            max_entry_bytes: 100,
            ..ExtractionLimits::default()
        };
        let b_exact = make_wheel(&[("exact.bin", &[0u8; 100], zip::CompressionMethod::Stored)]);
        let dir2 = tempfile::tempdir().unwrap();
        assert!(safe_extract_wheel(&b_exact, dir2.path(), &limits_entry_bytes).is_ok());

        let b_over = make_wheel(&[("over.bin", &[0u8; 101], zip::CompressionMethod::Stored)]);
        assert!(matches!(
            safe_extract_wheel(&b_over, dir2.path(), &limits_entry_bytes).unwrap_err(),
            BluelineError::ExtractionLimit(_)
        ));

        // Exact total unpacked bytes
        let limits_total = ExtractionLimits {
            max_entry_bytes: 100,
            max_unpacked_bytes: 200,
            ..ExtractionLimits::default()
        };
        let b_tot_exact = make_wheel(&[
            ("a.bin", &[0u8; 100], zip::CompressionMethod::Stored),
            ("b.bin", &[0u8; 100], zip::CompressionMethod::Stored),
        ]);
        let dir3 = tempfile::tempdir().unwrap();
        assert!(safe_extract_wheel(&b_tot_exact, dir3.path(), &limits_total).is_ok());

        let b_tot_over = make_wheel(&[
            ("a.bin", &[0u8; 100], zip::CompressionMethod::Stored),
            ("b.bin", &[0u8; 100], zip::CompressionMethod::Stored),
            ("c.bin", &[0u8; 1], zip::CompressionMethod::Stored),
        ]);
        assert!(matches!(
            safe_extract_wheel(&b_tot_over, dir3.path(), &limits_total).unwrap_err(),
            BluelineError::ExtractionLimit(_)
        ));

        // Mixed files and dirs exceeding max_entries
        let b_mixed = make_wheel(&[
            ("mydir/", b"", zip::CompressionMethod::Stored),
            ("mydir/a.txt", b"a", zip::CompressionMethod::Stored),
            ("mydir/b.txt", b"b", zip::CompressionMethod::Stored),
        ]);
        let limits_mixed = ExtractionLimits {
            max_entries: 2,
            ..ExtractionLimits::default()
        };
        let dir_mixed = tempfile::tempdir().unwrap();
        let err_mixed = safe_extract_wheel(&b_mixed, dir_mixed.path(), &limits_mixed).unwrap_err();
        assert!(matches!(err_mixed, BluelineError::ExtractionLimit(_)));

        // Symlink via unix mode
        let mut sym_wheel = make_wheel(&[("link.txt", b"target", zip::CompressionMethod::Stored)]);
        for i in 0..sym_wheel.len().saturating_sub(4) {
            if sym_wheel[i..i + 4] == [0x50, 0x4b, 0x01, 0x02] && i + 42 <= sym_wheel.len() {
                sym_wheel[i + 5] = 3; // System::Unix
                let mode: u32 = 0o120644;
                let attrs = mode << 16;
                sym_wheel[i + 38] = (attrs & 0xFF) as u8;
                sym_wheel[i + 39] = ((attrs >> 8) & 0xFF) as u8;
                sym_wheel[i + 40] = ((attrs >> 16) & 0xFF) as u8;
                sym_wheel[i + 41] = ((attrs >> 24) & 0xFF) as u8;
            }
        }
        let dir4 = tempfile::tempdir().unwrap();
        let err =
            safe_extract_wheel(&sym_wheel, dir4.path(), &ExtractionLimits::default()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn test_set_perm_helpers() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fpath = dir.path().join("test.txt");
        fs::write(&fpath, b"hello").unwrap();
        fs::set_permissions(&fpath, fs::Permissions::from_mode(0o777)).unwrap();
        set_file_perm(&fpath);
        let f_mode = fs::metadata(&fpath).unwrap().permissions().mode() & 0o777;
        assert_eq!(f_mode, 0o644);

        let dpath = dir.path().join("subdir");
        fs::create_dir(&dpath).unwrap();
        fs::set_permissions(&dpath, fs::Permissions::from_mode(0o700)).unwrap();
        set_dir_perm(&dpath);
        let d_mode = fs::metadata(&dpath).unwrap().permissions().mode() & 0o777;
        assert_eq!(d_mode, 0o755);

        set_perm(&fpath, 0o600);
        let p_mode = fs::metadata(&fpath).unwrap().permissions().mode() & 0o777;
        assert_eq!(p_mode, 0o600);
    }
}
