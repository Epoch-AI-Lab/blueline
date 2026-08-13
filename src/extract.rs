use std::fs;
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
        let mut entry =
            entry.map_err(|e| BluelineError::Extraction(format!("reading tar entry: {e}")))?;

        let entry_type = entry.header().entry_type();
        // Metadata entries (GNU long names, pax extensions) carry no payload.
        if entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_global_extensions()
            || entry_type.is_pax_local_extensions()
        {
            continue;
        }
        if !entry_type.is_file() && !entry_type.is_dir() {
            return Err(BluelineError::ExtractionLimit(format!(
                "unsupported entry type {entry_type:?} (symlinks/hardlinks/special files are rejected)"
            )));
        }

        seen += 1;
        if seen > limits.max_entries {
            return Err(BluelineError::ExtractionLimit(format!(
                "entry count exceeded ({seen}/{})",
                limits.max_entries
            )));
        }

        let path = entry
            .path()
            .map_err(|e| BluelineError::Extraction(format!("unreadable entry path: {e}")))?
            .to_path_buf();
        validate_entry_path(&path).map_err(BluelineError::Extraction)?;

        let size = entry.size();
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

        if entry_type.is_file() {
            stats.files += 1;
            stats.unpacked_bytes += size;
            strip_special_bits(&dest.join(&path));
        } else {
            stats.dirs += 1;
        }
    }

    Ok(stats)
}

fn validate_entry_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("empty entry path".to_string());
    }
    if path.is_absolute() {
        return Err(format!("absolute entry path `{}` rejected", path.display()));
    }
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err(format!(
                    "parent traversal in entry path `{}` rejected",
                    path.display()
                ));
            }
            Component::Prefix(_) => {
                return Err(format!(
                    "drive prefix in entry path `{}` rejected",
                    path.display()
                ));
            }
            Component::RootDir | Component::CurDir | Component::Normal(_) => {}
        }
    }
    Ok(())
}

/// Strip setuid/setgid/sticky from unpacked files (they must never run here).
#[cfg(unix)]
fn strip_special_bits(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = fs::metadata(path) {
        let mut perm = md.permissions();
        perm.set_mode(perm.mode() & 0o777);
        let _ = fs::set_permissions(path, perm);
    }
}

#[cfg(not(unix))]
fn strip_special_bits(_path: &Path) {}

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
    fn raw_tarball(entries: &[(String, u8, &str)]) -> Vec<u8> {
        use std::io::Write;

        fn raw_header(name: &str, typeflag: u8, size: u64, linkname: &str) -> Vec<u8> {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..108].copy_from_slice(b"0000644\x00");
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

        let mut out = Vec::new();
        for (name, typeflag, linkname) in entries {
            let mut data = [0u8; 1];
            let size = if *typeflag == 0x30 {
                data[0] = b'x';
                1
            } else {
                0
            };
            out.extend_from_slice(&raw_header(name, *typeflag, size, linkname));
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
}
