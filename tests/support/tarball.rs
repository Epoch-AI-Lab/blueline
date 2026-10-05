//! Tar fixtures for the scenario harness.
//!
//! Archives are written as raw ustar bytes rather than through `tar::Builder`.
//! That is deliberate: the builder refuses the shapes this harness exists to
//! serve (absolute paths, `..` components, symlinks, hardlinks, entries whose
//! payload is hundreds of megabytes of zeros), and those are exactly the
//! shapes an attacker puts on the wire.

use std::io::Write;

use base64::Engine;
use serde_json::{Map, Value};
use sha2::{Digest, Sha512};

/// ustar entry types this harness serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Hardlink,
}

impl EntryKind {
    fn typeflag(self) -> u8 {
        match self {
            EntryKind::File => b'0',
            EntryKind::Dir => b'5',
            EntryKind::Symlink => b'2',
            EntryKind::Hardlink => b'1',
        }
    }
}

#[derive(Debug, Clone)]
enum Payload {
    Bytes(Vec<u8>),
    /// `len` zero bytes, streamed a chunk at a time. A decompression bomb
    /// fixture must declare and really carry its bytes without the harness
    /// allocating hundreds of megabytes to build it.
    Zeroes {
        len: u64,
        chunk: Vec<u8>,
    },
}

const ZERO_CHUNK: usize = 1 << 20;

/// One tar entry: a path (which may be hostile), a type, an optional link
/// target, and a payload.
#[derive(Debug, Clone)]
pub struct Entry {
    path: String,
    kind: EntryKind,
    link_target: String,
    mode: u32,
    payload: Payload,
}

impl Entry {
    pub fn file(path: &str, contents: &[u8]) -> Entry {
        Entry {
            path: path.to_string(),
            kind: EntryKind::File,
            link_target: String::new(),
            mode: 0o644,
            payload: Payload::Bytes(contents.to_vec()),
        }
    }

    pub fn dir(path: &str) -> Entry {
        Entry {
            path: path.to_string(),
            kind: EntryKind::Dir,
            link_target: String::new(),
            mode: 0o755,
            payload: Payload::Bytes(Vec::new()),
        }
    }

    /// A symlink entry: the archive-level escape primitive, since a link can
    /// name a target outside the extraction root without any `..` in a path.
    pub fn symlink(path: &str, target: &str) -> Entry {
        Entry {
            path: path.to_string(),
            kind: EntryKind::Symlink,
            link_target: target.to_string(),
            mode: 0o777,
            payload: Payload::Bytes(Vec::new()),
        }
    }

    /// A hardlink entry pointing at another archive member.
    pub fn hardlink(path: &str, target: &str) -> Entry {
        Entry {
            path: path.to_string(),
            kind: EntryKind::Hardlink,
            link_target: target.to_string(),
            mode: 0o644,
            payload: Payload::Bytes(Vec::new()),
        }
    }

    /// A file entry of `len` real zero bytes — a decompression bomb, carried
    /// honestly (the declared size and the payload agree) and built without
    /// allocating it.
    pub fn zeroes(path: &str, len: u64) -> Entry {
        Entry {
            path: path.to_string(),
            kind: EntryKind::File,
            link_target: String::new(),
            mode: 0o644,
            payload: Payload::Zeroes {
                len,
                chunk: vec![0u8; ZERO_CHUNK.min(len.max(1) as usize)],
            },
        }
    }

    pub fn with_mode(mut self, mode: u32) -> Entry {
        self.mode = mode;
        self
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn kind(&self) -> EntryKind {
        self.kind
    }
}

/// Gzip a raw tar stream: the shape every npm tarball arrives in.
pub fn archive(entries: &[Entry]) -> Vec<u8> {
    let mut tar: Vec<u8> = Vec::new();
    for entry in entries {
        let size = match &entry.payload {
            Payload::Bytes(b) => b.len() as u64,
            Payload::Zeroes { len, .. } => *len,
        };
        let link = match entry.kind {
            EntryKind::Symlink | EntryKind::Hardlink => entry.link_target.as_str(),
            _ => "",
        };
        tar.extend_from_slice(&ustar_header(
            &entry.path,
            entry.kind,
            size,
            link,
            entry.mode,
        ));
        match &entry.payload {
            Payload::Bytes(bytes) => {
                tar.extend_from_slice(bytes);
                pad_to_block(&mut tar, bytes.len() as u64);
            }
            Payload::Zeroes { len, chunk } => {
                let mut written: u64 = 0;
                while written < *len {
                    let take = chunk.len().min((*len - written) as usize);
                    tar.extend_from_slice(&chunk[..take]);
                    written += take as u64;
                }
                pad_to_block(&mut tar, *len);
            }
        }
    }
    tar.extend_from_slice(&[0u8; 1024]);

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar).expect("gzip fixture tarball");
    encoder.finish().expect("finish gzip fixture tarball")
}

/// Zero padding to the next 512-byte boundary.
pub fn pad_to_512(len: usize) -> Vec<u8> {
    vec![0u8; (512 - len % 512) % 512]
}

fn pad_to_block(buf: &mut Vec<u8>, written: u64) {
    buf.extend_from_slice(&pad_to_512(written as usize));
}

/// A raw ustar header with an explicit typeflag, for the archive shapes
/// `Entry` cannot express: GNU long name (`L`) and long link (`K`) records,
/// and pax extended headers (`x`, `g`).
pub fn raw_header(name: &str, typeflag: u8, size: u64, link_target: &str) -> Vec<u8> {
    ustar_header_raw(name, typeflag, size, link_target, 0o644)
}

/// A pax extended-header record: `"<len> <key>=<value>\n"`, where `len`
/// counts its own digits, so the length has to be solved for.
pub fn pax_record(key: &str, value: &str) -> String {
    let mut len = key.len() + value.len() + 3;
    loop {
        let candidate = format!("{len} {key}={value}\n");
        if candidate.len() == len {
            return candidate;
        }
        len = candidate.len();
    }
}

/// Raw ustar header. `prefix` splitting is deliberately not implemented: a
/// scenario that needs a name longer than the 100-byte field panics here
/// rather than silently producing an archive the engine reads differently.
fn ustar_header(name: &str, kind: EntryKind, size: u64, link_target: &str, mode: u32) -> Vec<u8> {
    ustar_header_raw(name, kind.typeflag(), size, link_target, mode)
}

fn ustar_header_raw(name: &str, typeflag: u8, size: u64, link_target: &str, mode: u32) -> Vec<u8> {
    assert!(
        name.len() <= 100,
        "entry name `{name}` exceeds the 100-byte ustar name field the fixture writer supports"
    );
    assert!(
        link_target.len() <= 100,
        "link target `{link_target}` exceeds the 100-byte ustar linkname field"
    );
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[157..157 + link_target.len()].copy_from_slice(link_target.as_bytes());
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let sum: u64 = header.iter().map(|&b| u64::from(b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    header.to_vec()
}

/// Gzip raw tar bytes: the wire shape of every npm tarball. Paired with
/// [`raw_header`] for archive shapes a builder cannot express.
pub fn gzip(raw: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(raw).expect("gzip fixture tarball");
    encoder.finish().expect("finish gzip fixture tarball")
}

/// Subresource-integrity string npm publishes in `dist.integrity`.
pub fn sha512_sri(bytes: &[u8]) -> String {
    let digest = Sha512::digest(bytes);
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

#[derive(Debug, Clone)]
enum Integrity {
    /// Advertise the digest of the bytes actually served.
    Computed,
    /// Advertise something else entirely.
    Fixed(String),
    /// Advertise no integrity at all.
    Absent,
}

/// One release as a registry will publish it: a name, a version, tarball
/// bytes, and the integrity the registry claims for them.
#[derive(Debug, Clone)]
pub struct Release {
    name: String,
    version: String,
    tarball: Vec<u8>,
    integrity: Integrity,
}

impl Release {
    /// `name@version`, the spec `blueline review` takes.
    pub fn spec(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn tarball(&self) -> &[u8] {
        &self.tarball
    }

    pub fn integrity(&self) -> Option<String> {
        match &self.integrity {
            Integrity::Computed => Some(sha512_sri(&self.tarball)),
            Integrity::Fixed(s) => Some(s.clone()),
            Integrity::Absent => None,
        }
    }

    /// The `versions[<version>]` document this release contributes to a
    /// packument served at `base`.
    pub fn version_document(&self, base: &str) -> Value {
        serde_json::json!({
            "name": self.name,
            "version": self.version,
            "dist": {
                "tarball": format!("{base}/{}/{}/{}-{}.tgz", self.name, TAR_SEGMENT, self.name, self.version),
                "integrity": self.integrity(),
                "shasum": "0".repeat(40),
            }
        })
    }
}

/// npm's tarball path segment between the package name and the file name.
pub const TAR_SEGMENT: &str = "-";

/// Composes a release under attack. The manifest is a JSON object the
/// scenario edits directly; the tarball is `package/package.json` plus
/// whatever entries the scenario asks for, hostile or not.
#[derive(Debug, Clone)]
pub struct ReleaseBuilder {
    name: String,
    version: String,
    manifest: Map<String, Value>,
    entries: Vec<Entry>,
    integrity: Integrity,
    raw: Option<Vec<u8>>,
}

impl ReleaseBuilder {
    pub fn npm(name: &str, version: &str) -> ReleaseBuilder {
        let mut manifest = Map::new();
        manifest.insert("name".to_string(), Value::String(name.to_string()));
        manifest.insert("version".to_string(), Value::String(version.to_string()));
        ReleaseBuilder {
            name: name.to_string(),
            version: version.to_string(),
            manifest,
            entries: Vec::new(),
            integrity: Integrity::Computed,
            raw: None,
        }
    }

    /// Replace the whole `package.json`.
    pub fn manifest(mut self, manifest: Value) -> ReleaseBuilder {
        let object = manifest
            .as_object()
            .expect("manifest must be a JSON object")
            .clone();
        self.manifest = object;
        self
    }

    /// Set one top-level manifest field (`scripts`, `dependencies`, …).
    pub fn field(mut self, key: &str, value: Value) -> ReleaseBuilder {
        self.manifest.insert(key.to_string(), value);
        self
    }

    /// Add a lifecycle script — the canonical npm install-time attack.
    pub fn script(self, name: &str, command: &str) -> ReleaseBuilder {
        let mut scripts = self
            .manifest
            .get("scripts")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        scripts.insert(name.to_string(), Value::String(command.to_string()));
        self.field("scripts", Value::Object(scripts))
    }

    pub fn dependency(self, name: &str, range: &str) -> ReleaseBuilder {
        let mut deps = self
            .manifest
            .get("dependencies")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        deps.insert(name.to_string(), Value::String(range.to_string()));
        self.field("dependencies", Value::Object(deps))
    }

    pub fn entry(mut self, entry: Entry) -> ReleaseBuilder {
        self.entries.push(entry);
        self
    }

    pub fn file(self, path: &str, contents: &[u8]) -> ReleaseBuilder {
        self.entry(Entry::file(path, contents))
    }

    /// Advertise an integrity string that is not the digest of the served
    /// bytes: the swapped-tarball attack.
    pub fn advertise_integrity(mut self, sri: &str) -> ReleaseBuilder {
        self.integrity = Integrity::Fixed(sri.to_string());
        self
    }

    /// Advertise the digest of some other tarball while serving this one's
    /// bytes. The pair is a tampered release that passes every byte the
    /// registry can vouch for, if the engine only checks what it was told.
    pub fn advertise_digest_of(mut self, other: &[u8]) -> ReleaseBuilder {
        self.integrity = Integrity::Fixed(sha512_sri(other));
        self
    }

    /// Publish no integrity at all.
    pub fn publish_without_integrity(mut self) -> ReleaseBuilder {
        self.integrity = Integrity::Absent;
        self
    }

    /// Publish tarball bytes exactly as given, advertising `integrity`. The
    /// escape hatch for archive shapes a builder cannot express.
    pub fn for_bytes(
        name: &str,
        version: &str,
        tarball: Vec<u8>,
        integrity: String,
    ) -> ReleaseBuilder {
        let mut manifest = Map::new();
        manifest.insert("name".to_string(), Value::String(name.to_string()));
        manifest.insert("version".to_string(), Value::String(version.to_string()));
        ReleaseBuilder {
            name: name.to_string(),
            version: version.to_string(),
            manifest,
            entries: Vec::new(),
            integrity: Integrity::Fixed(integrity),
            raw: Some(tarball),
        }
    }

    pub fn build(self) -> Release {
        let mut manifest = self.manifest;
        manifest.insert("name".to_string(), Value::String(self.name.clone()));
        manifest.insert("version".to_string(), Value::String(self.version.clone()));
        let tarball = match self.raw {
            Some(bytes) => bytes,
            None => {
                let json = serde_json::to_vec(&Value::Object(manifest))
                    .expect("serialize fixture manifest");
                let mut entries = vec![Entry::file("package/package.json", &json)];
                entries.extend(self.entries);
                archive(&entries)
            }
        };
        Release {
            name: self.name,
            version: self.version,
            tarball,
            integrity: self.integrity,
        }
    }
}
