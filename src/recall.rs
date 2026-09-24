//! Local-first recall / revocation index: a curated, human-verified list
//! of revoked package versions, served by `blueline recall serve`, synced
//! by `blueline recall sync` into a JSON file under the data directory
//! (the SQLite store is untouched — the snapshot is rebuilt wholesale on
//! every sync), and folded into the advisory engine so a hit is a
//! BLOCK-class finding. Motivating window: OSV/GHSA classify new malware
//! on the order of days; a team-curated index closes that gap.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::BluelineError;
use crate::registry::Ecosystem;
use crate::version::VersionInfo;

pub const SNAPSHOT_SCHEMA: u64 = 1;
/// Bounds on hostile served bytes: a snapshot is a bounded document, not a
/// stream.
const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_TEXT_BYTES: usize = 512;
/// Clock skew allowance when validating generated_at.
const TIMESTAMP_SKEW_SECS: i64 = 300;
const HTTP_READ_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revocation {
    pub ecosystem: Ecosystem,
    pub name: String,
    /// Exact revoked versions; ignored when `all_versions` is set.
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub all_versions: bool,
    pub reason: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema: u64,
    /// Epoch seconds when the curator generated the snapshot.
    pub generated_at: i64,
    /// Monotonic per-index revision; syncs that move it backward are refused.
    pub sequence: u64,
    pub revocations: Vec<Revocation>,
}

/// Does `name` satisfy the package-name grammar of its own ecosystem? A recall
/// entry that names something no registry in that ecosystem could ever serve is
/// a curation error, and accepting it would let a path-shaped name sit in an
/// index that reviewers treat as authoritative.
fn name_matches_grammar(ecosystem: Ecosystem, name: &str) -> bool {
    match ecosystem {
        Ecosystem::Npm => crate::registry::npm::validate_package_name(name).is_ok(),
        Ecosystem::Cargo => crate::registry::cratesio::validate_crate_name(name).is_ok(),
        Ecosystem::PyPi => crate::version::validate_pypi_name(name),
        Ecosystem::Aur => crate::registry::aur::validate_aur_name(name),
    }
}

/// What the client persists after a successful sync: the snapshot plus the
/// client-side facts the snapshot itself cannot attest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncedSnapshot {
    pub fetched_at: i64,
    pub url: String,
    pub snapshot: Snapshot,
}

/// Per-process snapshot cache: reviews evaluate many packages (CI, recursive
/// children) and re-validating the snapshot per lookup is wasted work. The
/// cache is keyed by modification timestamp so a re-sync in the same
/// process is picked up.
static SNAPSHOT_CACHE: std::sync::OnceLock<(std::time::SystemTime, Option<SyncedSnapshot>)> =
    std::sync::OnceLock::new();

fn cached_load(path: &Path) -> Result<Option<SyncedSnapshot>, BluelineError> {
    let mtime = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(std::time::UNIX_EPOCH);
    match SNAPSHOT_CACHE.get() {
        Some((cached_at, cached)) if *cached_at == mtime => return Ok(cached.clone()),
        _ => {}
    }
    let loaded = load_at(path)?;
    let _ = SNAPSHOT_CACHE.set((mtime, loaded.clone()));
    Ok(loaded)
}

/// Injectable reader used by `load` and tests: missing file is an absent
/// index, anything present is parsed and validated fail closed.
pub(crate) fn load_at(path: &Path) -> Result<Option<SyncedSnapshot>, BluelineError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(BluelineError::Advisory(format!(
                "reading recall snapshot {}: {e}",
                path.display()
            )));
        }
    };
    if text.len() > MAX_SNAPSHOT_BYTES {
        return Err(BluelineError::Advisory(format!(
            "recall snapshot {} exceeds {MAX_SNAPSHOT_BYTES} bytes",
            path.display()
        )));
    }
    let synced: SyncedSnapshot = serde_json::from_str(&text).map_err(|e| {
        BluelineError::Advisory(format!("parsing recall snapshot {}: {e}", path.display()))
    })?;
    synced.snapshot.validate()?;
    Ok(Some(synced))
}

pub fn snapshot_path() -> Result<PathBuf, BluelineError> {
    if let Ok(dir) = std::env::var("BLUELINE_DATA_DIR") {
        return Ok(Path::new(&dir).join("recall_snapshot.json"));
    }
    let base = dirs::data_dir().ok_or_else(|| {
        BluelineError::Store("could not determine the platform data directory".into())
    })?;
    Ok(base.join("blueline").join("recall_snapshot.json"))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Snapshot {
    /// Fail-closed validation: an invalid snapshot is refused whole, never
    /// partially trusted.
    pub fn validate(&self) -> Result<(), BluelineError> {
        if self.schema != SNAPSHOT_SCHEMA {
            return Err(BluelineError::Advisory(format!(
                "recall snapshot schema {} is not {}",
                self.schema, SNAPSHOT_SCHEMA
            )));
        }
        if self.revocations.len() > MAX_ENTRIES {
            return Err(BluelineError::Advisory(format!(
                "recall snapshot carries {} entries; cap is {MAX_ENTRIES}",
                self.revocations.len()
            )));
        }
        let now = now_secs();
        if self.generated_at > now + TIMESTAMP_SKEW_SECS {
            return Err(BluelineError::Advisory(
                "recall snapshot generated_at lies in the future".into(),
            ));
        }
        for rev in &self.revocations {
            if !name_matches_grammar(rev.ecosystem, &rev.name) {
                return Err(BluelineError::Advisory(format!(
                    "recall entry `{}`: `{}` is not a valid {} package name",
                    rev.id,
                    rev.name,
                    rev.ecosystem.key()
                )));
            }
            if rev.reason.is_empty() || rev.reason.len() > MAX_TEXT_BYTES {
                return Err(BluelineError::Advisory(format!(
                    "recall entry `{}`: reason missing or over {MAX_TEXT_BYTES} bytes",
                    rev.id
                )));
            }
            if rev.id.is_empty() || rev.id.len() > MAX_TEXT_BYTES {
                return Err(BluelineError::Advisory(
                    "recall entry id missing or oversized".into(),
                ));
            }
            if rev.all_versions {
                if !rev.versions.is_empty() {
                    return Err(BluelineError::Advisory(format!(
                        "recall entry `{}`: all_versions with a version list is ambiguous",
                        rev.id
                    )));
                }
                continue;
            }
            if rev.versions.is_empty() {
                return Err(BluelineError::Advisory(format!(
                    "recall entry `{}`: no versions and all_versions unset",
                    rev.id
                )));
            }
            for version in &rev.versions {
                let valid = match rev.ecosystem {
                    Ecosystem::Npm | Ecosystem::Cargo => semver::Version::parse(version).is_ok(),
                    Ecosystem::PyPi => crate::version::Pep440Version::parse(version).is_ok(),
                    Ecosystem::Aur => crate::version::AurVersionInfo::parse(version).is_ok(),
                };
                if !valid {
                    return Err(BluelineError::Advisory(format!(
                        "recall entry `{}`: version `{version}` is not valid for {}",
                        rev.id,
                        rev.ecosystem.key()
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn lookup(&self, ecosystem: Ecosystem, name: &str, version: &str) -> Option<&Revocation> {
        self.revocations.iter().find(|rev| {
            rev.ecosystem == ecosystem
                && names_match(ecosystem, &rev.name, name)
                && (rev.all_versions
                    || rev
                        .versions
                        .iter()
                        .any(|v| versions_match(ecosystem, v, version)))
        })
    }
}

/// Name identity for revocation matching: PEP 503 canonicalization on both
/// sides for PyPI (a revocation for `foo-bar` fires on `Foo_Bar`), exact
/// match elsewhere where separators are significant.
fn names_match(ecosystem: Ecosystem, indexed: &str, queried: &str) -> bool {
    match ecosystem {
        Ecosystem::PyPi => {
            crate::version::canonicalize_name(indexed) == crate::version::canonicalize_name(queried)
        }
        _ => indexed == queried,
    }
}

/// Version identity for revocation matching: parsed-and-compared per
/// ecosystem grammar so `1.0` fires on `1.0.0` (PEP 440 zero-padding).
/// Strict semver has no distinct-but-equal forms, so npm/cargo matching
/// is exact via the identity fast path above. Unparseable input falls
/// back to exact match rather than failing open.
fn versions_match(ecosystem: Ecosystem, indexed: &str, queried: &str) -> bool {
    if indexed == queried {
        return true;
    }
    match ecosystem {
        Ecosystem::Npm | Ecosystem::Cargo => false,
        Ecosystem::PyPi => {
            match (
                crate::version::Pep440Version::parse(indexed),
                crate::version::Pep440Version::parse(queried),
            ) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            }
        }
        Ecosystem::Aur => {
            match (
                crate::version::AurVersionInfo::parse(indexed),
                crate::version::AurVersionInfo::parse(queried),
            ) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            }
        }
    }
}

impl SyncedSnapshot {
    /// Load and validate the synced snapshot from the data directory.
    /// Absent → None (no index installed). Corrupt → refused with the
    /// error; the caller must treat that as "no index" WITH disclosure,
    /// never as trusted.
    pub fn load() -> Result<Option<Self>, BluelineError> {
        cached_load(&snapshot_path()?)
    }

    /// Epoch seconds past the snapshot's fetch time (client-side staleness).
    pub fn age_secs(&self) -> i64 {
        (now_secs() - self.fetched_at).max(0)
    }
}

/// Staleness band for the synced snapshot per policy: None when absent or
/// fresh; Some(Medium) when stale, Some(Block) with block_on_stale. A
/// corrupt snapshot is an Err the caller must disclose (R28), never skip.
pub fn stale_band(
    policy: &crate::policy::Policy,
) -> Result<Option<crate::verdict::VerdictBand>, BluelineError> {
    stale_band_at(policy, &snapshot_path()?)
}

pub(crate) fn stale_band_at(
    policy: &crate::policy::Policy,
    path: &Path,
) -> Result<Option<crate::verdict::VerdictBand>, BluelineError> {
    let Some(synced) = load_at(path)? else {
        return Ok(None);
    };
    let max_age_secs = (policy.recall.max_age_hours as i64).saturating_mul(3600);
    if synced.age_secs() > max_age_secs {
        return Ok(Some(if policy.recall.block_on_stale {
            crate::verdict::VerdictBand::Block
        } else {
            crate::verdict::VerdictBand::Medium
        }));
    }
    Ok(None)
}

/// Look up a package in the synced snapshot. Missing index → Ok(None).
pub fn lookup(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<Option<Revocation>, BluelineError> {
    let Some(synced) = SyncedSnapshot::load()? else {
        return Ok(None);
    };
    Ok(synced.snapshot.lookup(ecosystem, name, version).cloned())
}

/// Sync the snapshot from a recall service: bounded fetch, fail-closed
/// validation, monotonic sequence check, atomic write. Sequence moves
/// backward → refused.
pub fn sync(url: &str) -> anyhow::Result<SyncedSnapshot> {
    let url = format!("{}/revocations.json", url.trim_end_matches('/'));
    let agent = ureq::AgentBuilder::new()
        .timeout_read(std::time::Duration::from_secs(HTTP_READ_TIMEOUT_SECS))
        .build();
    let resp = agent
        .get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("GET {url}: {e}"))?;
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_SNAPSHOT_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|e| anyhow::anyhow!("reading {url}: {e}"))?;
    if body.len() > MAX_SNAPSHOT_BYTES {
        anyhow::bail!("recall snapshot from {url} exceeds {MAX_SNAPSHOT_BYTES} bytes");
    }
    let snapshot: Snapshot = serde_json::from_slice(&body)
        .map_err(|e| anyhow::anyhow!("parsing recall snapshot from {url}: {e}"))?;
    snapshot.validate()?;
    let synced = SyncedSnapshot {
        fetched_at: now_secs(),
        url: url.clone(),
        snapshot,
    };
    if let Some(existing) = SyncedSnapshot::load()?
        && synced.snapshot.sequence < existing.snapshot.sequence
    {
        anyhow::bail!(
            "refusing to sync: sequence {} is older than the stored sequence {}",
            synced.snapshot.sequence,
            existing.snapshot.sequence
        );
    }
    let path = snapshot_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("creating {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    std::fs::write(&tmp, serde_json::to_string_pretty(&synced)?)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| anyhow::anyhow!("renaming into {}: {e}", path.display()))?;
    Ok(synced)
}

fn index_size_within_cap(len: usize) -> bool {
    len <= MAX_SNAPSHOT_BYTES
}

/// Serve a curated index file over a minimal HTTP server. The file is
/// validated once at startup and the served bytes are exactly the file
/// bytes; the server never mutates anything.
pub fn serve(port: u16, index: &Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(index)
        .map_err(|e| anyhow::anyhow!("reading index {}: {e}", index.display()))?;
    if !index_size_within_cap(bytes.len()) {
        anyhow::bail!(
            "index {} exceeds {MAX_SNAPSHOT_BYTES} bytes",
            index.display()
        );
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|e| {
        anyhow::anyhow!(
            "index {} is not a valid recall snapshot: {e}; refusing to serve",
            index.display()
        )
    })?;
    snapshot.validate()?;
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| anyhow::anyhow!("binding 127.0.0.1:{port}: {e}"))?;
    let actual = listener.local_addr()?.port();
    println!("recall index serving on http://127.0.0.1:{actual}/revocations.json");
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let bytes = bytes.clone();
        std::thread::spawn(move || {
            let _ = stream
                .set_read_timeout(Some(std::time::Duration::from_secs(HTTP_READ_TIMEOUT_SECS)));
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/");
            let (status, body): (&str, Vec<u8>) = match path {
                "/revocations.json" => ("200 OK", bytes),
                "/health" => ("200 OK", b"ok".to_vec()),
                _ => ("404 Not Found", b"not found".to_vec()),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_snapshot() -> Snapshot {
        Snapshot {
            schema: SNAPSHOT_SCHEMA,
            generated_at: now_secs() - 60,
            sequence: 7,
            revocations: vec![Revocation {
                ecosystem: Ecosystem::Npm,
                name: "evil-pkg".into(),
                versions: vec!["1.0.0".into(), "1.0.1".into()],
                all_versions: false,
                reason: "backdoored postinstall (human-verified)".into(),
                id: "BL-2026-0001".into(),
            }],
        }
    }

    #[test]
    fn validates_a_good_snapshot() {
        valid_snapshot().validate().unwrap();
    }

    #[test]
    fn rejects_wrong_schema_future_clock_and_bad_versions() {
        let mut snap = valid_snapshot();
        snap.schema = 99;
        assert!(snap.validate().is_err());
        let mut snap = valid_snapshot();
        snap.generated_at = now_secs() + 10_000;
        assert!(snap.validate().is_err());
        let mut snap = valid_snapshot();
        snap.revocations[0].versions = vec!["not-a-version".into()];
        assert!(snap.validate().is_err());
    }

    #[test]
    fn rejects_all_versions_with_list_and_missing_versions() {
        let mut snap = valid_snapshot();
        snap.revocations[0].all_versions = true;
        assert!(snap.validate().is_err());
        let mut snap = valid_snapshot();
        snap.revocations[0].versions.clear();
        assert!(snap.validate().is_err());
    }

    #[test]
    fn lookup_normalizes_pypi_names_and_versions() {
        let snap = Snapshot {
            schema: SNAPSHOT_SCHEMA,
            generated_at: now_secs() - 60,
            sequence: 7,
            revocations: vec![Revocation {
                ecosystem: Ecosystem::PyPi,
                name: "foo-bar".into(),
                versions: vec!["1.0".into()],
                all_versions: false,
                reason: "revoked".into(),
                id: "BL-2026-0002".into(),
            }],
        };
        assert!(snap.lookup(Ecosystem::PyPi, "Foo_Bar", "1.0.0").is_some());
        assert!(snap.lookup(Ecosystem::PyPi, "foo.bar", "1.0").is_some());
        assert!(snap.lookup(Ecosystem::PyPi, "foo-bar", "2.0").is_none());
        assert!(snap.lookup(Ecosystem::Npm, "Foo_Bar", "1.0.0").is_none());
        let npm_snap = Snapshot {
            schema: SNAPSHOT_SCHEMA,
            generated_at: now_secs() - 60,
            sequence: 7,
            revocations: vec![Revocation {
                ecosystem: Ecosystem::Npm,
                name: "foo_bar".into(),
                versions: vec!["1.0.0".into()],
                all_versions: false,
                reason: "revoked".into(),
                id: "BL-2026-0003".into(),
            }],
        };
        assert!(
            npm_snap
                .lookup(Ecosystem::Npm, "foo_bar", "1.0.0")
                .is_some()
        );
        assert!(
            npm_snap
                .lookup(Ecosystem::Npm, "foo-bar", "1.0.0")
                .is_none()
        );
    }

    #[test]
    fn lookup_matches_ecosystem_name_and_versions() {
        let snap = valid_snapshot();
        assert!(snap.lookup(Ecosystem::Npm, "evil-pkg", "1.0.1").is_some());
        assert!(snap.lookup(Ecosystem::Npm, "evil-pkg", "1.0.2").is_none());
        assert!(snap.lookup(Ecosystem::PyPi, "evil-pkg", "1.0.0").is_none());
        let mut all = valid_snapshot();
        all.revocations[0].all_versions = true;
        all.revocations[0].versions.clear();
        assert!(all.lookup(Ecosystem::Npm, "evil-pkg", "9.9.9").is_some());
    }

    #[test]
    fn stale_band_follows_policy_window_and_escalation() {
        let mut policy = crate::policy::Policy::default();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recall_snapshot.json");

        // Absent index: never stale.
        assert!(stale_band_at(&policy, &path).unwrap().is_none());

        // Fresh snapshot: not stale.
        let synced = SyncedSnapshot {
            fetched_at: now_secs(),
            url: "http://127.0.0.1:1".into(),
            snapshot: valid_snapshot(),
        };
        std::fs::write(&path, serde_json::to_string(&synced).unwrap()).unwrap();
        assert!(stale_band_at(&policy, &path).unwrap().is_none());

        // Stale past the window: MEDIUM by default, BLOCK on escalation.
        let synced = SyncedSnapshot {
            fetched_at: now_secs() - 100 * 3600,
            url: synced.url,
            snapshot: synced.snapshot,
        };
        std::fs::write(&path, serde_json::to_string(&synced).unwrap()).unwrap();
        assert_eq!(
            stale_band_at(&policy, &path).unwrap(),
            Some(crate::verdict::VerdictBand::Medium)
        );
        policy.recall.block_on_stale = true;
        assert_eq!(
            stale_band_at(&policy, &path).unwrap(),
            Some(crate::verdict::VerdictBand::Block)
        );

        // Corrupt snapshot: an Err the caller must disclose.
        std::fs::write(&path, "not json").unwrap();
        assert!(stale_band_at(&policy, &path).is_err());
    }

    #[test]
    fn load_treats_missing_file_as_absent_index() {
        // Path-injected load: the same reader the env-based path uses.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recall_snapshot.json");
        assert!(!path.exists());
        let result = crate::recall::load_at(&path);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn snapshot_size_consts_are_exact() {
        assert_eq!(MAX_SNAPSHOT_BYTES, 8 * 1024 * 1024);
        assert_eq!(MAX_SNAPSHOT_BYTES, 8_388_608);
        assert_eq!(MAX_ENTRIES, 10_000);
        assert_eq!(MAX_TEXT_BYTES, 512);
        assert_eq!(TIMESTAMP_SKEW_SECS, 300);
    }

    fn synced_tagged(sequence: u64, tag: &str) -> SyncedSnapshot {
        SyncedSnapshot {
            fetched_at: 1_700_000_000,
            url: format!("http://127.0.0.1:1/{tag}"),
            snapshot: Snapshot {
                schema: SNAPSHOT_SCHEMA,
                generated_at: 1_700_000_000,
                sequence,
                revocations: Vec::new(),
            },
        }
    }

    fn big_snapshot(sequence: u64) -> Snapshot {
        Snapshot {
            schema: SNAPSHOT_SCHEMA,
            generated_at: 1_700_000_000,
            sequence,
            revocations: (0..6000)
                .map(|i| Revocation {
                    ecosystem: Ecosystem::Npm,
                    name: format!("bulk-pkg-{i}"),
                    versions: vec!["1.0.0".into()],
                    all_versions: false,
                    reason: "bulk".into(),
                    id: format!("BLK-{i:05}"),
                })
                .collect(),
        }
    }

    fn synced_padded_to_bytes(total_len: usize, sequence: u64) -> SyncedSnapshot {
        let mut synced = SyncedSnapshot {
            fetched_at: 1_700_000_000,
            url: "http://127.0.0.1:1/pad".into(),
            snapshot: big_snapshot(sequence),
        };
        let base_len = serde_json::to_string(&synced).unwrap().len();
        assert!(base_len < total_len, "fixture must fit under the cap");
        synced.url.push_str(&"a".repeat(total_len - base_len));
        assert_eq!(serde_json::to_string(&synced).unwrap().len(), total_len);
        synced
    }

    fn snapshot_padded_to_bytes(total_len: usize, sequence: u64) -> Snapshot {
        fn entry(reason_len: usize) -> Revocation {
            Revocation {
                ecosystem: Ecosystem::Npm,
                name: "a".repeat(214),
                versions: (0..20).map(|i| format!("1.0.{i}")).collect(),
                all_versions: false,
                reason: "r".repeat(reason_len),
                id: "b".repeat(512),
            }
        }
        let mut count = 6000usize;
        for _ in 0..100 {
            let probe = Snapshot {
                schema: SNAPSHOT_SCHEMA,
                generated_at: 1_700_000_000,
                sequence,
                revocations: (0..count).map(|_| entry(1)).collect(),
            };
            let size = serde_json::to_string(&probe).unwrap().len();
            let extra = total_len as i64 - size as i64;
            let capacity = (count * 511) as i64;
            if extra >= 0 && extra <= capacity {
                let mut remaining = extra as usize;
                let mut revocations = Vec::with_capacity(count);
                for _ in 0..count {
                    let add = remaining.min(511);
                    revocations.push(entry(1 + add));
                    remaining -= add;
                }
                assert_eq!(remaining, 0);
                let snap = Snapshot {
                    schema: SNAPSHOT_SCHEMA,
                    generated_at: 1_700_000_000,
                    sequence,
                    revocations,
                };
                assert_eq!(serde_json::to_string(&snap).unwrap().len(), total_len);
                snap.validate().unwrap();
                return snap;
            }
            if extra < 0 {
                count = count * 3 / 4;
            } else {
                count += 500;
            }
            assert!(
                (100..MAX_ENTRIES).contains(&count),
                "padding must stay a valid snapshot"
            );
        }
        panic!("could not pad snapshot to {total_len} bytes");
    }

    #[test]
    fn cached_load_hits_on_same_mtime_and_misses_on_change() {
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recall_snapshot.json");

        fn set_mtime(path: &std::path::Path, mtime: std::time::SystemTime) {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(mtime)
                .unwrap();
        }

        // A miss always rereads the file: anchor the mtime away from any
        // cached entry, future-dated so even a concurrent population of the
        // process-global cache cannot collide with it.
        let probe_a = synced_tagged(11, "phase-a");
        std::fs::write(&path, serde_json::to_string(&probe_a).unwrap()).unwrap();
        let anchor = match SNAPSHOT_CACHE.get() {
            Some((cached_at, _)) => *cached_at + Duration::from_secs(60),
            None => std::time::SystemTime::now() + Duration::from_secs(60),
        };
        set_mtime(&path, anchor);
        assert_eq!(cached_load(&path).unwrap(), Some(probe_a));

        // The cache is definitely populated now (set-once: pre-existing or
        // stored by the miss above), so rewinding the mtime to the cached
        // entry must return the cached snapshot without rereading the file.
        let (cached_at, cached) = SNAPSHOT_CACHE.get().cloned().unwrap();
        let probe_b = synced_tagged(12, "phase-b");
        assert_ne!(cached, Some(probe_b.clone()));
        std::fs::write(&path, serde_json::to_string(&probe_b).unwrap()).unwrap();
        set_mtime(&path, cached_at);
        assert_eq!(cached_load(&path).unwrap(), cached);

        // A changed mtime reloads: the fresh file wins over the cache.
        let probe_c = synced_tagged(13, "phase-c");
        std::fs::write(&path, serde_json::to_string(&probe_c).unwrap()).unwrap();
        set_mtime(&path, cached_at + Duration::from_secs(60));
        assert_eq!(cached_load(&path).unwrap(), Some(probe_c));
    }

    #[test]
    fn load_at_distinguishes_absent_index_from_unreadable_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("recall_snapshot.json");
        assert!(matches!(load_at(&missing), Ok(None)));
        let err = load_at(dir.path()).unwrap_err();
        assert!(err.to_string().contains("reading recall snapshot"));
    }

    #[test]
    fn load_at_enforces_byte_cap_at_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recall_snapshot.json");
        let exact = synced_padded_to_bytes(MAX_SNAPSHOT_BYTES, 21);
        std::fs::write(&path, serde_json::to_string(&exact).unwrap()).unwrap();
        assert_eq!(load_at(&path).unwrap(), Some(exact));
        let over = synced_padded_to_bytes(MAX_SNAPSHOT_BYTES + 1, 22);
        std::fs::write(&path, serde_json::to_string(&over).unwrap()).unwrap();
        let err = load_at(&path).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err:#}");
    }

    #[test]
    fn validate_enforces_entry_count_cap_at_boundary() {
        let rev = valid_snapshot().revocations.pop().unwrap();
        let mut at_cap = valid_snapshot();
        at_cap.revocations = vec![rev.clone(); MAX_ENTRIES];
        assert!(at_cap.validate().is_ok());
        let mut over = valid_snapshot();
        over.revocations = vec![rev; MAX_ENTRIES + 1];
        assert!(over.validate().is_err());
    }

    #[test]
    fn validate_accepts_generated_at_at_skew_boundary() {
        let mut at_skew = valid_snapshot();
        at_skew.generated_at = now_secs() + TIMESTAMP_SKEW_SECS;
        assert!(at_skew.validate().is_ok());
        let mut past_skew = valid_snapshot();
        past_skew.generated_at = now_secs() + TIMESTAMP_SKEW_SECS + 1;
        assert!(past_skew.validate().is_err());
    }

    #[test]
    fn validate_enforces_name_length_at_boundary() {
        let mut empty = valid_snapshot();
        empty.revocations[0].name.clear();
        assert!(empty.validate().is_err());
        let mut at_cap = valid_snapshot();
        at_cap.revocations[0].name = "a".repeat(214);
        assert!(at_cap.validate().is_ok());
        let mut over = valid_snapshot();
        over.revocations[0].name = "a".repeat(215);
        assert!(over.validate().is_err());
    }

    #[test]
    fn validate_applies_the_ecosystems_own_name_grammar() {
        // A path-shaped name is not a package name in any ecosystem; the old
        // character-class check let it through because `/` and `.` are legal
        // in npm scoped names.
        for name in ["../etc", "a/b/c", "..", "@/x", "x@", "a b", "a\\b"] {
            let mut snap = valid_snapshot();
            snap.revocations[0].name = name.to_string();
            assert!(
                snap.validate().is_err(),
                "npm entry `{name}` must be refused"
            );
        }
        // A name legal in npm but not in cargo must not sneak through under
        // the cargo key, and the scoped form stays legal under npm.
        let mut scoped = valid_snapshot();
        scoped.revocations[0].name = "@scope/pkg".to_string();
        assert!(scoped.validate().is_ok());
        let mut cargo_scoped = scoped.clone();
        cargo_scoped.revocations[0].ecosystem = Ecosystem::Cargo;
        assert!(cargo_scoped.validate().is_err());
    }

    #[test]
    fn validate_accepts_names_legal_in_their_own_ecosystem() {
        for (eco, name) in [
            (Ecosystem::Npm, "lodash"),
            (Ecosystem::Npm, "some.pkg_name"),
            (Ecosystem::Cargo, "serde-json"),
            (Ecosystem::PyPi, "zope.interface"),
            (Ecosystem::Aur, "yay"),
        ] {
            let mut snap = valid_snapshot();
            snap.revocations[0].ecosystem = eco;
            snap.revocations[0].name = name.to_string();
            assert!(
                snap.validate().is_ok(),
                "{name:?} must be legal under {eco:?}"
            );
        }
    }

    #[test]
    fn validate_enforces_reason_length_at_boundary() {
        let mut empty = valid_snapshot();
        empty.revocations[0].reason.clear();
        assert!(empty.validate().is_err());
        let mut at_cap = valid_snapshot();
        at_cap.revocations[0].reason = "r".repeat(MAX_TEXT_BYTES);
        assert!(at_cap.validate().is_ok());
        let mut over = valid_snapshot();
        over.revocations[0].reason = "r".repeat(MAX_TEXT_BYTES + 1);
        assert!(over.validate().is_err());
    }

    #[test]
    fn validate_enforces_id_length_at_boundary() {
        let mut empty = valid_snapshot();
        empty.revocations[0].id.clear();
        assert!(empty.validate().is_err());
        let mut at_cap = valid_snapshot();
        at_cap.revocations[0].id = "b".repeat(MAX_TEXT_BYTES);
        assert!(at_cap.validate().is_ok());
        let mut over = valid_snapshot();
        over.revocations[0].id = "b".repeat(MAX_TEXT_BYTES + 1);
        assert!(over.validate().is_err());
    }

    #[test]
    fn versions_match_equivalence_and_fallback() {
        assert!(versions_match(Ecosystem::Aur, "1.0-1", "1.0-1"));
        assert!(versions_match(Ecosystem::Aur, "1.0", "1.0-1"));
        assert!(!versions_match(Ecosystem::Aur, "1.0-1", "2.0-1"));
        assert!(versions_match(Ecosystem::PyPi, "1.0", "1.0.0"));
        assert!(versions_match(Ecosystem::PyPi, "2024.1", "2024.1.0"));
        assert!(!versions_match(Ecosystem::PyPi, "1.0", "2.0"));
        assert!(versions_match(Ecosystem::Aur, "!!!", "!!!"));
        assert!(!versions_match(Ecosystem::Aur, "!!!a", "!!!b"));
        assert!(!versions_match(
            Ecosystem::Npm,
            "not-a-version",
            "also-not-a-version"
        ));
        assert!(!versions_match(Ecosystem::PyPi, "1.0", "1.0a1"));
        assert!(versions_match(Ecosystem::Npm, "1.0.0", "1.0.0"));
        assert!(versions_match(Ecosystem::Cargo, "1.0.0", "1.0.0"));
        assert!(!versions_match(Ecosystem::Npm, "1.0.0+a", "1.0.0+b"));
        assert!(!versions_match(Ecosystem::Npm, "1.0.0", "1.0.1"));
        assert!(!versions_match(Ecosystem::Cargo, "1.0.0", "2.0.0"));
    }

    #[test]
    fn index_cap_boundary_is_exact() {
        assert_eq!(MAX_SNAPSHOT_BYTES, 8 * 1024 * 1024);
        assert!(index_size_within_cap(0));
        assert!(index_size_within_cap(MAX_SNAPSHOT_BYTES - 1));
        assert!(index_size_within_cap(MAX_SNAPSHOT_BYTES));
        assert!(!index_size_within_cap(MAX_SNAPSHOT_BYTES + 1));
    }

    #[test]
    fn stale_band_pins_max_age_boundary() {
        let policy = crate::policy::Policy::default();
        let max_age_secs = (policy.recall.max_age_hours as i64).saturating_mul(3600);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recall_snapshot.json");
        let snap = valid_snapshot();
        let write_at = |fetched_at: i64| {
            let synced = SyncedSnapshot {
                fetched_at,
                url: "http://127.0.0.1:1".into(),
                snapshot: snap.clone(),
            };
            std::fs::write(&path, serde_json::to_string(&synced).unwrap()).unwrap();
        };
        let mut fresh_at_cap = false;
        for _ in 0..8 {
            write_at(now_secs() - max_age_secs);
            if stale_band_at(&policy, &path).unwrap().is_none() {
                fresh_at_cap = true;
                break;
            }
        }
        assert!(fresh_at_cap, "age exactly max_age_secs must be fresh");
        write_at(now_secs() - max_age_secs - 1);
        assert_eq!(
            stale_band_at(&policy, &path).unwrap(),
            Some(crate::verdict::VerdictBand::Medium)
        );
        write_at(now_secs() - max_age_secs + 1);
        assert!(stale_band_at(&policy, &path).unwrap().is_none());
    }

    fn blueline_cmd(data_dir: &std::path::Path) -> assert_cmd::Command {
        let mut cmd = assert_cmd::Command::cargo_bin("blueline").unwrap();
        cmd.env("BLUELINE_DATA_DIR", data_dir);
        cmd
    }

    fn serve_recall_once(body: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let handle = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(15) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 8192];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]).to_string();
                        let path = req
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("/");
                        if path == "/revocations.json" {
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(head.as_bytes());
                            let _ = stream.write_all(&body);
                            return;
                        }
                        let _ = stream.write_all(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found",
                        );
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                }
            }
        });
        (format!("http://127.0.0.1:{port}"), handle)
    }

    fn recall_snapshot(sequence: u64, generated_at: i64) -> Snapshot {
        Snapshot {
            schema: SNAPSHOT_SCHEMA,
            generated_at,
            sequence,
            revocations: Vec::new(),
        }
    }

    #[test]
    fn sync_refuses_sequence_rollback_without_touching_file() {
        let data_dir = tempfile::tempdir().unwrap();
        let snapshot_path = data_dir.path().join("recall_snapshot.json");
        let (seed_url, seed_handle) =
            serve_recall_once(serde_json::to_vec(&recall_snapshot(42, 1_700_000_000)).unwrap());
        let out = blueline_cmd(data_dir.path())
            .args(["recall", "sync", "--url", &seed_url])
            .output()
            .unwrap();
        seed_handle.join().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stored_bytes = std::fs::read(&snapshot_path).unwrap();

        let (old_url, old_handle) =
            serve_recall_once(serde_json::to_vec(&recall_snapshot(41, 1_700_000_000)).unwrap());
        let out = blueline_cmd(data_dir.path())
            .args(["recall", "sync", "--url", &old_url])
            .output()
            .unwrap();
        old_handle.join().unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("older than the stored sequence"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read(&snapshot_path).unwrap(), stored_bytes);
    }

    #[test]
    fn sync_accepts_equal_sequence_idempotently() {
        let data_dir = tempfile::tempdir().unwrap();
        let snapshot_path = data_dir.path().join("recall_snapshot.json");
        let (seed_url, seed_handle) =
            serve_recall_once(serde_json::to_vec(&recall_snapshot(42, 1_700_000_000)).unwrap());
        let out = blueline_cmd(data_dir.path())
            .args(["recall", "sync", "--url", &seed_url])
            .output()
            .unwrap();
        seed_handle.join().unwrap();
        assert!(out.status.success());

        let (url, handle) =
            serve_recall_once(serde_json::to_vec(&recall_snapshot(42, 1_700_000_001)).unwrap());
        let out = blueline_cmd(data_dir.path())
            .args(["recall", "sync", "--url", &format!("{url}///")])
            .output()
            .unwrap();
        handle.join().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stored: SyncedSnapshot =
            serde_json::from_slice(&std::fs::read(&snapshot_path).unwrap()).unwrap();
        assert_eq!(stored.snapshot.sequence, 42);
        assert_eq!(stored.snapshot.generated_at, 1_700_000_001);
    }

    #[test]
    fn sync_enforces_snapshot_byte_cap_at_boundary() {
        let data_dir = tempfile::tempdir().unwrap();
        let exact = snapshot_padded_to_bytes(MAX_SNAPSHOT_BYTES, 31);
        let (url, handle) = serve_recall_once(serde_json::to_vec(&exact).unwrap());
        let out = blueline_cmd(data_dir.path())
            .args(["recall", "sync", "--url", &url])
            .output()
            .unwrap();
        handle.join().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stored: SyncedSnapshot = serde_json::from_slice(
            &std::fs::read(data_dir.path().join("recall_snapshot.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(stored.snapshot.sequence, 31);

        let data_dir = tempfile::tempdir().unwrap();
        let over = snapshot_padded_to_bytes(MAX_SNAPSHOT_BYTES + 1, 32);
        let (url, handle) = serve_recall_once(serde_json::to_vec(&over).unwrap());
        let out = blueline_cmd(data_dir.path())
            .args(["recall", "sync", "--url", &url])
            .output()
            .unwrap();
        handle.join().unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("exceeds"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn serve_refuses_oversized_index_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let index_path = dir.path().join("index.json");
        let over = snapshot_padded_to_bytes(MAX_SNAPSHOT_BYTES + 1, 51);
        std::fs::write(&index_path, serde_json::to_vec(&over).unwrap()).unwrap();
        let bin = assert_cmd::cargo::cargo_bin("blueline");
        let mut child = std::process::Command::new(bin)
            .env("BLUELINE_DATA_DIR", dir.path())
            .args([
                "recall",
                "serve",
                "--port",
                "0",
                "--snapshot",
                index_path.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let out = loop {
            match child.try_wait().expect("serve child must be waitable") {
                Some(_) => {
                    break child
                        .wait_with_output()
                        .expect("serve output must be readable");
                }
                None if std::time::Instant::now() > deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("oversized index hung serve instead of refusing at startup");
                }
                None => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        };
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("exceeds"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn serve_serves_at_cap_snapshot_with_health_endpoint() {
        use std::io::{BufRead, BufReader, Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let index_path = dir.path().join("index.json");
        let snap = snapshot_padded_to_bytes(MAX_SNAPSHOT_BYTES, 52);
        std::fs::write(&index_path, serde_json::to_vec(&snap).unwrap()).unwrap();
        let bin = assert_cmd::cargo::cargo_bin("blueline");
        let mut child = std::process::Command::new(bin)
            .args([
                "recall",
                "serve",
                "--port",
                "0",
                "--snapshot",
                index_path.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut banner = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut banner)
            .unwrap();
        let port: u16 = banner
            .trim()
            .split("http://127.0.0.1:")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("cannot parse serve banner: {banner}"));
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let _ = child.kill();
        let _ = child.wait();
        let response = String::from_utf8_lossy(&response).to_string();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.ends_with("ok"), "{response}");
    }
}
