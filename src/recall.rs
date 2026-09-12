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

/// What the client persists after a successful sync: the snapshot plus the
/// client-side facts the snapshot itself cannot attest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncedSnapshot {
    pub fetched_at: i64,
    pub url: String,
    pub snapshot: Snapshot,
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
            if rev.name.is_empty() || rev.name.len() > 214 {
                return Err(BluelineError::Advisory(format!(
                    "recall entry `{}`: invalid package name length",
                    rev.id
                )));
            }
            if !rev
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '@'))
            {
                return Err(BluelineError::Advisory(format!(
                    "recall entry `{}`: invalid package name characters",
                    rev.id
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
                && rev.name == name
                && (rev.all_versions || rev.versions.iter().any(|v| v == version))
        })
    }
}

impl SyncedSnapshot {
    /// Load and validate the synced snapshot from the data directory.
    /// Absent → None (no index installed). Corrupt → refused with the
    /// error; the caller must treat that as "no index" WITH disclosure,
    /// never as trusted.
    pub fn load() -> Result<Option<Self>, BluelineError> {
        load_at(&snapshot_path()?)
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
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(&synced)?)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| anyhow::anyhow!("renaming into {}: {e}", path.display()))?;
    Ok(synced)
}

/// Serve a curated index file over a minimal HTTP server. The file is
/// validated once at startup and the served bytes are exactly the file
/// bytes; the server never mutates anything.
pub fn serve(port: u16, index: &Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(index)
        .map_err(|e| anyhow::anyhow!("reading index {}: {e}", index.display()))?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
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
}
