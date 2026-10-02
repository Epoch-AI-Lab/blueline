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
/// Redirect hops a snapshot fetch will follow. A recall service is an operator-
/// configured origin that serves one document, so two hops is generous for the
/// legitimate shapes (a trailing-slash correction plus a versioned-path move)
/// while keeping the chain short enough to reason about.
const MAX_REDIRECTS: usize = 2;

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
        // npm folds case on publish, and packages published before that rule
        // still carry capitals. Curators write the name they know, so compare
        // case-insensitively rather than refusing the whole index over one
        // legacy spelling.
        Ecosystem::Npm => {
            crate::registry::npm::validate_package_name(&name.to_ascii_lowercase()).is_ok()
        }
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
/// children) and re-validating a snapshot that can carry 10 000 entries per
/// lookup is wasted work.
///
/// A `OnceLock` cannot do this job. `set` fails once the cell is occupied and
/// the result was discarded, so the cache froze at the first snapshot it ever
/// saw. That stayed correct, because a stamp miss falls through to a fresh
/// read, but the cache stopped hitting the moment the file changed, which is
/// the only case it exists for. It was also keyed on mtime alone, so two
/// snapshot paths sharing a timestamp served each other's index.
///
/// Keyed on the full path plus `(mtime, len, ino)`. The length closes the
/// same-second collision a coarse filesystem clock would otherwise allow, and
/// the inode catches a replacement that preserves both, which `cp -p`,
/// `rsync --times` and a tar or git extraction all do. The value is an `Arc`
/// so populating the cache does not need a second deep copy; a *hit* still
/// clones the snapshot out of it, because the callers want an owned value.
type CacheKey = (std::path::PathBuf, Stamp);
static SNAPSHOT_CACHE: std::sync::Mutex<
    Option<(CacheKey, std::sync::Arc<Option<SyncedSnapshot>>)>,
> = std::sync::Mutex::new(None);

type Stamp = (std::time::SystemTime, u64, u64);

fn stamp(path: &Path) -> Stamp {
    let Ok(m) = std::fs::metadata(path) else {
        return (std::time::UNIX_EPOCH, 0, 0);
    };
    #[cfg(unix)]
    let ino = {
        use std::os::unix::fs::MetadataExt;
        m.ino()
    };
    #[cfg(not(unix))]
    let ino = 0;
    (m.modified().unwrap_or(std::time::UNIX_EPOCH), m.len(), ino)
}

fn cached_load(path: &Path) -> Result<Option<SyncedSnapshot>, BluelineError> {
    let key = (path.to_path_buf(), stamp(path));
    let hit = SNAPSHOT_CACHE
        .lock()
        .map_err(|_| BluelineError::Advisory("recall snapshot cache poisoned".into()))?
        .clone();
    if let Some((cached_key, value)) = hit
        && cached_key == key
    {
        return Ok(value.as_ref().clone());
    }
    let loaded = load_at(path)?;
    let mut guard = SNAPSHOT_CACHE
        .lock()
        .map_err(|_| BluelineError::Advisory("recall snapshot cache poisoned".into()))?;
    *guard = Some((key, std::sync::Arc::new(loaded.clone())));
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
        // PEP 503 for PyPI, ASCII case folding for npm and crates.io. Both
        // registries fold case on publish, so a curator who writes `React` or
        // `Serde` means the same package the reviewer queries. Without this
        // the entry validates and then never fires, which is the worst shape
        // a revocation can have: present, trusted, inert.
        Ecosystem::PyPi => {
            crate::version::canonicalize_name(indexed) == crate::version::canonicalize_name(queried)
        }
        Ecosystem::Npm | Ecosystem::Cargo => indexed.eq_ignore_ascii_case(queried),
        Ecosystem::Aur => indexed == queried,
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
        self.age_secs_at(now_secs())
    }

    fn age_secs_at(&self, now: i64) -> i64 {
        (now - self.fetched_at).max(0)
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
    let Some(synced) = cached_load(path)? else {
        return Ok(None);
    };
    Ok(stale_band_for(
        &synced,
        recall_max_age_secs(policy),
        policy.recall.block_on_stale,
        now_secs(),
    ))
}

fn recall_max_age_secs(policy: &crate::policy::Policy) -> i64 {
    (policy.recall.max_age_hours as i64).saturating_mul(3600)
}

/// The staleness decision with the clock handed in. A review asks this at a
/// moment it does not choose, so pinning the boundary through the filesystem
/// and a wall clock is a coin flip on second granularity: the arithmetic lives
/// here, where a test can put the age exactly on the cap.
fn stale_band_for(
    synced: &SyncedSnapshot,
    max_age_secs: i64,
    block_on_stale: bool,
    now: i64,
) -> Option<crate::verdict::VerdictBand> {
    if synced.age_secs_at(now) > max_age_secs {
        return Some(if block_on_stale {
            crate::verdict::VerdictBand::Block
        } else {
            crate::verdict::VerdictBand::Medium
        });
    }
    None
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
    sync_within(url, LOCK_WAIT)
}

/// Follow the snapshot fetch's redirect chain, one hop at a time.
///
/// The agent has `redirects(0)`, so every hop is a request this function makes
/// explicitly and every hop goes back through the same validating resolver
/// rather than being followed blindly. Two rules bound what a hop may do:
///
/// * At most `MAX_REDIRECTS` hops, so the chain stays short and terminates.
/// * A hop may change path, or upgrade `http` to `https`, but it may not change
///   *host* — and it may not downgrade `https` to `http` even on the same host,
///   because that hands the operator's configured origin a request they did not
///   intend to make in cleartext.
///
/// A cross-host hop is refused rather than followed. The commonest real cause is
/// a base URL pointing at a web front end instead of the file host, so the
/// error names that case rather than leaving the operator to guess.
fn follow_redirects(agent: &ureq::Agent, url: &str) -> Result<ureq::Response, anyhow::Error> {
    let mut current = url.to_string();
    for hop in 0..=MAX_REDIRECTS {
        let resp = agent
            .get(&current)
            .call()
            .map_err(|e| anyhow::anyhow!("GET {current}: {e}"))?;
        let status = resp.status();
        if !(301..=308).contains(&status) {
            return Ok(resp);
        }
        if hop == MAX_REDIRECTS {
            anyhow::bail!(
                "recall snapshot fetch exceeded {MAX_REDIRECTS} redirects starting at {url}; \
                 point the recall URL at the file host that serves {}/revocations.json directly",
                base_of(url)
            );
        }
        let location = resp.header("location").ok_or_else(|| {
            anyhow::anyhow!(
                "recall snapshot fetch got {status} from {current} with no Location header"
            )
        })?;
        let next = crate::registry::http_util::resolve_redirect_url(&current, location)
            .map_err(|e| anyhow::anyhow!("resolving redirect from {current}: {e}"))?;
        check_hop(&current, &next, url)?;
        current = next;
    }
    unreachable!("the loop returns or bails on its final iteration")
}

/// The scheme and host of a URL, for comparing two hops.
fn scheme_host(raw: &str) -> Result<(String, String), anyhow::Error> {
    crate::registry::http_util::parse_url_scheme_and_host(raw)
        .map_err(|e| anyhow::anyhow!("parsing {raw}: {e}"))
}

/// The origin of the configured URL, minus the snapshot path, for error text.
fn base_of(url: &str) -> String {
    url.split_once("/revocations.json")
        .map(|(base, _)| base)
        .unwrap_or(url)
        .to_string()
}

/// Refuse a hop that leaves the origin, or that downgrades to cleartext.
fn check_hop(from: &str, to: &str, configured: &str) -> Result<(), anyhow::Error> {
    let (from_scheme, from_host) = scheme_host(from)?;
    let (to_scheme, to_host) = scheme_host(to)?;

    if to_host != from_host {
        anyhow::bail!(
            "recall snapshot redirect from {from} to {to} changes host, which is refused. \
             If the recall URL is a web front end, point it at the file host that serves the \
             snapshot directly, e.g. a GitHub repo's \
             `https://raw.githubusercontent.com/OWNER/REPO/BRANCH` page rather than \
             `https://github.com/OWNER/REPO`."
        );
    }
    if from_scheme == "https" && to_scheme != "https" {
        anyhow::bail!(
            "recall snapshot redirect from {from} to {to} downgrades HTTPS to cleartext, \
             which is refused. Fix the redirect at {}, or configure the https URL directly.",
            base_of(configured)
        );
    }
    Ok(())
}

/// `lock_wait` is a parameter only so the tests can exercise the contended path
/// in milliseconds. Production always passes `LOCK_WAIT`.
fn sync_within(url: &str, lock_wait: std::time::Duration) -> anyhow::Result<SyncedSnapshot> {
    let url = format!("{}/revocations.json", url.trim_end_matches('/'));
    // The shared registry agent, not a bare `AgentBuilder`. The SSRF properties
    // are the point: `redirects(0)` and a resolver that validates every address
    // against the host the operator configured. A bare builder defaults to
    // following 5 redirects to any host, which is how the two provenance fetches
    // ended up reachable from a recall URL pointing anywhere. The total budget
    // also replaces the per-read one that was here: a peer that dribbles a byte
    // every few seconds stays inside a per-read ceiling forever, because each
    // individual read is small.
    let agent = crate::registry::http_util::registry_agent_with_timeout(
        "blueline-security/recall",
        &url,
        std::time::Duration::from_secs(HTTP_READ_TIMEOUT_SECS),
    );
    let resp = follow_redirects(&agent, &url)?;
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
    let path = snapshot_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| anyhow::anyhow!("creating {}: {e}", parent.display()))?;

    // The lock spans the read-compare-write, which means the comparison has to
    // happen *inside* it. Comparing first and locking after looks equivalent and
    // is not: two syncs that both read sequence 4, both pass a `5 < 4` check,
    // and then land out of order, leaving 5 on disk after 6 was already there.
    // Nothing else reads `sequence`, so every later review would then trust the
    // rolled-back index and the revocations published at 6 would be invisible.
    let _lock = SyncLock::acquire_within(parent, lock_wait)?;
    if let Some(existing) = SyncedSnapshot::load()?
        && synced.snapshot.sequence < existing.snapshot.sequence
    {
        anyhow::bail!(
            "refusing to sync: sequence {} is older than the stored sequence {}",
            synced.snapshot.sequence,
            existing.snapshot.sequence
        );
    }

    // A tempfile rather than a name derived from the pid. The old name was
    // fully predictable and `fs::write` follows a symlink, so a planted link
    // in a shared data directory turned a sync into an arbitrary-file
    // overwrite. `tempfile` is already a dependency and creates with O_EXCL.
    let mut tmp = tempfile::Builder::new()
        .prefix(".recall_snapshot.")
        .tempfile_in(parent)
        .map_err(|e| anyhow::anyhow!("creating a temp file in {}: {e}", parent.display()))?;
    tmp.write_all(serde_json::to_string_pretty(&synced)?.as_bytes())
        .map_err(|e| anyhow::anyhow!("writing the snapshot: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| anyhow::anyhow!("flushing the snapshot: {e}"))?;
    tmp.persist(&path)
        .map_err(|e| anyhow::anyhow!("renaming into {}: {}", path.display(), e.error))?;
    Ok(synced)
}

/// Advisory lock for the sync read-compare-write, built on `create_new` so it
/// needs no new dependency. Removed on drop, including on an error path.
struct SyncLock(PathBuf);

/// How long a sync waits for a peer before refusing. Generous enough for the
/// 8 MiB worst case plus its `fsync` on a loaded disk, short enough that a
/// wedged peer does not hang a review indefinitely.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// A lock file older than this was left by a process that died: `Drop` does
/// not run on SIGKILL or an abort, so without reaping one crash would make
/// every later sync wait out the full timeout and then fail forever.
const LOCK_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(300);

impl SyncLock {
    #[cfg(test)]
    fn acquire(parent: &Path) -> anyhow::Result<Self> {
        Self::acquire_within(parent, LOCK_WAIT)
    }

    /// `wait` is a parameter only so the tests can exercise the timeout path
    /// in milliseconds. Production always passes `LOCK_WAIT`.
    fn acquire_within(parent: &Path, wait: std::time::Duration) -> anyhow::Result<Self> {
        let path = parent.join("recall_snapshot.lock");
        let deadline = std::time::Instant::now() + wait;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(SyncLock(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(anyhow::anyhow!("creating {}: {e}", path.display())),
            }
            if Self::reap_if_stale(&path) {
                // Reaped, so try to take it immediately -- but a reap that keeps
                // succeeding must not buy unbounded retries. `continue` here skips
                // the deadline test below, so a peer that recreates the lock the
                // instant it is removed would spin forever and turn a bounded wait
                // into a hang. Re-checked before looping, so the wait stays bounded
                // however the reap goes.
                if std::time::Instant::now() >= deadline {
                    anyhow::bail!(
                        "another blueline recall sync holds {}; refusing to race it",
                        path.display()
                    );
                }
                continue;
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "another blueline recall sync holds {}; refusing to race it",
                    path.display()
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Remove a lock left behind by a dead holder. `Drop` cannot cover a
    /// SIGKILL, an abort, or a power loss, and a lock that is never released
    /// bricks the sync path permanently. Only a lock older than
    /// `LOCK_STALE_AFTER` is reaped, so a slow-but-alive holder is never
    /// stolen from. Removing a lock is itself racy — two waiters may both reap
    /// and both proceed — so the create above stays `create_new` and the worst
    /// case is two writers racing, which the sequence check under the lock
    /// still catches.
    fn reap_if_stale(path: &Path) -> bool {
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        let Ok(modified) = meta.modified() else {
            return false;
        };
        let age = std::time::SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        Self::reap_if_aged(path, age)
    }

    /// The comparison, with the age handed in. A lock is stolen once its age
    /// *reaches* the threshold: the bound is inclusive, so a lock exactly
    /// `LOCK_STALE_AFTER` old is reaped and only a younger one is left alone.
    /// The comparison is what decides that, and it is not reachable through the
    /// filesystem — reading a file's mtime and comparing it to `now` always
    /// straddles the instant the test set — so the arithmetic lives here where a
    /// test can sit exactly on it.
    fn reap_if_aged(path: &Path, age: std::time::Duration) -> bool {
        if age < LOCK_STALE_AFTER {
            return false;
        }
        std::fs::remove_file(path).is_ok()
    }
}

impl Drop for SyncLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
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

    /// A redirect chain the fetch is allowed to follow: same host, path only.
    ///
    /// Control for the refusal tests below. Without it, a `check_hop` that
    /// refused *everything* would make them pass for the wrong reason, which is
    /// the same trap the provenance redirect fixture had to guard against.
    #[test]
    fn a_same_host_path_redirect_is_followed() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // One hop: /start redirects to /moved, which serves the body.
            for stream in listener.incoming().take(2).flatten() {
                let mut stream = stream;
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let req = String::from_utf8_lossy(&buf);
                let (head, body): (&str, &[u8]) = if req.contains("/moved") {
                    (
                        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
                        b"hello",
                    )
                } else {
                    (
                        "HTTP/1.1 302 Found\r\nLocation: /moved\r\nContent-Length: 0\r\n\
                         Connection: close\r\n\r\n",
                        b"",
                    )
                };
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            }
        });

        let agent = crate::registry::http_util::registry_agent_with_timeout(
            "blueline-security/recall-test",
            &format!("http://127.0.0.1:{port}"),
            std::time::Duration::from_secs(10),
        );
        let resp = follow_redirects(&agent, &format!("http://127.0.0.1:{port}/start"))
            .expect("a same-host path redirect must be followed");
        assert_eq!(resp.status(), 200);
    }

    /// The origin the error text points the operator back to.
    ///
    /// Pinned on its own because it is load-bearing in two messages and neither
    /// of them is easy to read: the cap message and the downgrade message both
    /// tell the operator to fix the redirect "at" this base, so a `base_of` that
    /// returned an empty or wrong origin would send them to fix nothing. The
    /// last two cases matter because the helper is what keeps a non-snapshot URL
    /// whole rather than truncating it at a separator it does not carry.
    #[test]
    fn the_reported_base_is_the_origin_without_the_snapshot_path() {
        assert_eq!(
            base_of("https://recall.example/revocations.json"),
            "https://recall.example"
        );
        assert_eq!(
            base_of("https://recall.example/api/v2/revocations.json"),
            "https://recall.example/api/v2"
        );
        assert_eq!(
            base_of("http://127.0.0.1:8080/revocations.json"),
            "http://127.0.0.1:8080"
        );
        // No snapshot path at all: the whole URL stands, rather than a prefix of
        // it cut at a separator that is not there.
        assert_eq!(base_of("https://recall.example"), "https://recall.example");
    }

    /// The two messages that name the base must actually carry it.
    ///
    /// This is the test that failed under mutation: `base_of` was unconstrained,
    /// because the cross-host message does not use it and the other two only
    /// asserted the refusal, never the host the operator is told to fix. Both
    /// messages are useless without the origin in them.
    #[test]
    fn the_refusal_messages_name_the_origin_to_fix() {
        let from = "https://recall.example/revocations.json";

        let downgrade = check_hop(from, "http://recall.example/revocations.json", from)
            .map_err(|e| format!("{e:#}"))
            .expect_err("a downgrade must be refused");
        assert!(
            downgrade.contains("https://recall.example"),
            "the downgrade message must name the origin to fix: {downgrade}"
        );
    }

    /// A hop to a different host is refused, and the error names the mistake.
    ///
    /// The likeliest real cause is a recall URL pointing at a web front end that
    /// redirects to a file host, so the message has to name that shape — an
    /// operator who only sees "changes host" cannot tell what to fix.
    #[test]
    fn a_cross_host_redirect_is_refused_with_the_likely_cause_named() {
        let from = "https://recall.example/revocations.json";
        let to = "https://raw.githubusercontent.com/owner/repo/main/revocations.json";
        let err = check_hop(from, to, from)
            .map_err(|e| format!("{e:#}"))
            .unwrap_err();
        assert!(err.contains("changes host"), "must say why: {err}");
        assert!(
            err.contains("raw.githubusercontent.com"),
            "must name the file-host form the operator probably wants: {err}"
        );
        assert!(
            err.contains("github.com/OWNER/REPO"),
            "must contrast it with the front-end form that causes this: {err}"
        );
    }

    /// A same-host hop is fine; the two things that are not are a changed host
    /// and an https-to-http downgrade. The downgrade matters independently: a
    /// chain that stays on one host can still move the request into cleartext.
    #[test]
    fn only_a_downgrade_is_refused_among_same_host_hops() {
        let from = "https://recall.example/revocations.json";
        assert!(
            check_hop(from, "https://recall.example/v2/revocations.json", from).is_ok(),
            "a same-host path change on https must be allowed"
        );
        assert!(
            check_hop(from, "http://recall.example/revocations.json", from).is_err(),
            "an https to http downgrade must be refused even on the same host"
        );
        assert!(
            check_hop(
                "http://recall.example/revocations.json",
                "https://recall.example/revocations.json",
                from
            )
            .is_ok(),
            "an http to https upgrade must be allowed"
        );
    }

    /// The hop cap has to be enforced, not merely configured.
    ///
    /// An unbounded chain against an operator-configured origin is a hang, and
    /// the cap is the only thing that bounds it, so this pins the count rather
    /// than the constant.
    #[test]
    fn a_chain_longer_than_the_hop_cap_is_refused() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Redirect forever; only the cap can stop this.
        std::thread::spawn(move || {
            for stream in listener.incoming().take(8).flatten() {
                let mut stream = stream;
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\
                      Connection: close\r\n\r\n",
                );
                let _ = stream.flush();
            }
        });

        let agent = crate::registry::http_util::registry_agent_with_timeout(
            "blueline-security/recall-test",
            &format!("http://127.0.0.1:{port}"),
            std::time::Duration::from_secs(10),
        );
        let err = follow_redirects(&agent, &format!("http://127.0.0.1:{port}/start"))
            .map(|_| ())
            .map_err(|e| format!("{e:#}"))
            .expect_err("an endless redirect chain must be refused");
        assert!(
            err.contains(&format!("{MAX_REDIRECTS} redirects")),
            "the refusal must name the cap it hit: {err}"
        );
        // The cap message tells the operator to point the URL at the file host
        // directly, so it has to carry the origin it was talking to.
        assert!(
            err.contains(&format!("http://127.0.0.1:{port}")),
            "the cap message must name the origin it gave up on: {err}"
        );
    }

    /// The lock wait the tests use for the contended path. The production
    /// default is `LOCK_WAIT` and is pinned to 30 s in
    /// `sync_lock_times_out_loudly_rather_than_proceeding`; the timeout being
    /// tested is the refusal, not the patience behind it, so paying 30 s of it
    /// per test buys nothing.
    const TEST_LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(200);

    /// The snapshot cache holds one process-wide entry, so a concurrent review
    /// can evict the entry a cache test just primed and turn an observed hit
    /// into an ordinary miss. Re-priming is cheap; the attempts bound a cache
    /// that never hits.
    const CACHE_HIT_ATTEMPTS: usize = 32;

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

        // One path per phase. `stale_band_at` reads through the process-wide
        // snapshot cache, whose key is `(path, mtime, len, ino)`, and these
        // fixtures differ only in `fetched_at`, so consecutive ones serialize to
        // the *same length* on the same inode. Two writes inside one filesystem
        // timestamp tick therefore landed on one cache key, and the second
        // phase was served the first phase's snapshot. That is what made this
        // test fail about 1 run in 12 with `left: None` -- a stale hit, not a
        // wrong band. Distinct paths remove the collision without depending on
        // the filesystem's timestamp granularity, which is what varies.
        //
        // The band ladder is what this test is about; the cache has its own
        // tests, and `stale_band_for` takes the clock as a parameter for the
        // same reason.
        let phase = |name: &str| dir.path().join(name);
        let fresh_path = phase("fresh.json");
        let stale_path = phase("stale.json");
        let corrupt_path = phase("corrupt.json");

        // Absent index: never stale.
        assert!(
            stale_band_at(&policy, &phase("absent.json"))
                .unwrap()
                .is_none()
        );

        // Fresh snapshot: not stale.
        let synced = SyncedSnapshot {
            fetched_at: now_secs(),
            url: "http://127.0.0.1:1".into(),
            snapshot: valid_snapshot(),
        };
        std::fs::write(&fresh_path, serde_json::to_string(&synced).unwrap()).unwrap();
        assert!(stale_band_at(&policy, &fresh_path).unwrap().is_none());

        // Stale past the window: MEDIUM by default, BLOCK on escalation.
        let synced = SyncedSnapshot {
            fetched_at: now_secs() - 100 * 3600,
            url: synced.url,
            snapshot: synced.snapshot,
        };
        std::fs::write(&stale_path, serde_json::to_string(&synced).unwrap()).unwrap();
        assert_eq!(
            stale_band_at(&policy, &stale_path).unwrap(),
            Some(crate::verdict::VerdictBand::Medium)
        );
        policy.recall.block_on_stale = true;
        assert_eq!(
            stale_band_at(&policy, &stale_path).unwrap(),
            Some(crate::verdict::VerdictBand::Block)
        );

        // Corrupt snapshot: an Err the caller must disclose.
        std::fs::write(&corrupt_path, "not json").unwrap();
        assert!(stale_band_at(&policy, &corrupt_path).is_err());
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

    fn far_future() -> std::time::SystemTime {
        std::time::SystemTime::now() + std::time::Duration::from_secs(3600)
    }

    fn set_mtime(path: &std::path::Path, mtime: std::time::SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
    }

    #[test]
    fn cached_load_hits_on_same_mtime_and_misses_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recall_snapshot.json");

        // A miss always rereads, whatever the cache holds.
        let probe_b = synced_tagged(12, "phase-b");
        std::fs::write(&path, serde_json::to_string(&probe_b).unwrap()).unwrap();
        set_mtime(&path, far_future());
        assert_eq!(cached_load(&path).unwrap(), Some(probe_b));

        // A rewrite with the same timestamp but different content is picked
        // up, because the stamp carries the length as well. This is the case
        // a timestamp-only key gets wrong on a coarse clock.
        let probe_c = synced_tagged(13, "phase-c-a");
        std::fs::write(&path, serde_json::to_string(&probe_c).unwrap()).unwrap();
        let pinned = far_future();
        set_mtime(&path, pinned);
        assert_eq!(cached_load(&path).unwrap(), Some(probe_c.clone()));
        let probe_d = synced_tagged(14, "phase-d-longer-content");
        std::fs::write(&path, serde_json::to_string(&probe_d).unwrap()).unwrap();
        set_mtime(&path, pinned);
        assert_eq!(
            cached_load(&path).unwrap(),
            Some(probe_d),
            "a same-mtime rewrite with different content must be reloaded"
        );

        // The hit, which is the half an assertion about the returned value
        // cannot see: a hit and a re-read of an unchanged file return the same
        // thing. The only way to tell them apart is to make the bytes on disk
        // disagree with what a read would return and check the CACHED value
        // comes back. The stamp is (mtime, len, ino), so a same-length rewrite
        // with the mtime rewound lands exactly on the cached key -- and
        // `fs::write` keeps the inode, so the whole key is preserved.
        //
        // The cache is one process-wide slot, so a review loading any other
        // snapshot in between evicts this entry and the hit degrades to an
        // ordinary miss, which is a correct outcome rather than a defect. The
        // loop re-primes on that; a cache that never hits serves the on-disk
        // bytes every time and runs out of attempts.
        let cached = synced_tagged(15, "hit-01");
        let on_disk = synced_tagged(15, "hit-02");
        assert_eq!(
            serde_json::to_string(&on_disk).unwrap().len(),
            serde_json::to_string(&cached).unwrap().len(),
            "the rewrite must keep the length or the stamp moves on its own"
        );
        let mut served = None;
        for _ in 0..CACHE_HIT_ATTEMPTS {
            std::fs::write(&path, serde_json::to_string(&cached).unwrap()).unwrap();
            set_mtime(&path, pinned);
            cached_load(&path).unwrap();
            std::fs::write(&path, serde_json::to_string(&on_disk).unwrap()).unwrap();
            set_mtime(&path, pinned);
            served = cached_load(&path).unwrap();
            if served == Some(cached.clone()) {
                break;
            }
        }
        assert_eq!(
            served,
            Some(cached),
            "an unchanged (mtime, len, ino) must be served from the cache, not \
             reread -- the file holds a different index of identical length"
        );
    }

    /// What the process-wide cache currently holds, so a test can tell a miss
    /// it caused from a miss another review caused by evicting the entry.
    fn cache_entry() -> Option<CacheKey> {
        SNAPSHOT_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|(key, _)| key.clone())
    }

    /// The stamp's inode half is the only thing standing between a review and a
    /// replacement that preserves everything else: `cp -p`, `rsync --times` and
    /// a tar or git extraction all hand over identical content length and
    /// mtime from a different file. Nothing else in the suite moves the inode
    /// -- `fs::write` keeps it -- so the test has to.
    #[test]
    #[cfg(unix)]
    fn cache_misses_when_a_replacement_keeps_mtime_and_length_but_not_the_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recall_snapshot.json");
        let pinned = far_future();
        let original = synced_tagged(61, "inode-original");
        let replacement = synced_tagged(62, "inode-replaced");
        assert_eq!(
            serde_json::to_string(&replacement).unwrap().len(),
            serde_json::to_string(&original).unwrap().len(),
            "the replacement must be a different index of exactly the same length"
        );

        let mut served = None;
        for _ in 0..CACHE_HIT_ATTEMPTS {
            std::fs::write(&path, serde_json::to_string(&original).unwrap()).unwrap();
            set_mtime(&path, pinned);
            assert_eq!(cached_load(&path).unwrap(), Some(original.clone()));
            let before = stamp(&path);
            if cache_entry() != Some((path.clone(), before)) {
                // Another review loaded a snapshot in between and evicted the
                // primed entry; without it there is nothing to catch, so prime
                // again rather than conclude the stamp reloaded by accident.
                continue;
            }

            // The replacement is a different file, so it has a different inode;
            // `rename` over the target is what a `cp -p` restore or a package
            // extraction does. The length and the mtime are copied onto it, so
            // a timestamp-and-length key alone cannot see the swap.
            let incoming = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
            std::fs::write(
                incoming.path(),
                serde_json::to_string(&replacement).unwrap(),
            )
            .unwrap();
            incoming.persist(&path).unwrap();
            set_mtime(&path, pinned);

            let after = stamp(&path);
            assert_eq!(before.0, after.0, "the mtime must be preserved");
            assert_eq!(before.1, after.1, "the length must be preserved");
            assert_ne!(before.2, after.2, "the inode must have changed");
            served = cached_load(&path).unwrap();
            break;
        }
        assert_eq!(
            served,
            Some(replacement),
            "a replaced file carrying the old mtime and length must be reloaded; \
             the stamp's inode half is what catches it"
        );
    }

    /// Two snapshot paths must not share a cache entry even when they carry
    /// the same timestamp. Serving another data directory's index here would
    /// be a trust bug, not a performance one.
    #[test]
    fn cache_is_keyed_by_path_not_only_by_timestamp() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let path_a = a.path().join("recall_snapshot.json");
        let path_b = b.path().join("recall_snapshot.json");
        let snap_a = synced_tagged(21, "dir-a");
        let snap_b = synced_tagged(22, "dir-b");
        std::fs::write(&path_a, serde_json::to_string(&snap_a).unwrap()).unwrap();
        std::fs::write(&path_b, serde_json::to_string(&snap_b).unwrap()).unwrap();
        // Identical mtime on both.
        let pinned = far_future();
        set_mtime(&path_a, pinned);
        set_mtime(&path_b, pinned);
        assert_eq!(cached_load(&path_a).unwrap(), Some(snap_a));
        assert_eq!(
            cached_load(&path_b).unwrap(),
            Some(snap_b),
            "a second data directory must not serve the first one's index"
        );
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
    fn validate_accepts_legacy_capitalised_npm_names() {
        // npm folded case on publish, but pre-rule packages still carry
        // capitals and curators write the name they know. One such entry must
        // not take the whole index down with it.
        for name in ["React", "MyPackage", "@scope/Pkg", "ExPRESS"] {
            let mut snap = valid_snapshot();
            snap.revocations[0].ecosystem = Ecosystem::Npm;
            snap.revocations[0].name = name.to_string();
            assert!(snap.validate().is_ok(), "npm entry `{name}` must load");
        }
    }

    #[test]
    fn validate_still_rejects_shaped_names_after_case_folding() {
        for name in ["../ETC", "A/B/C", "@/x", "..", "a b"] {
            let mut snap = valid_snapshot();
            snap.revocations[0].ecosystem = Ecosystem::Npm;
            snap.revocations[0].name = name.to_string();
            assert!(
                snap.validate().is_err(),
                "npm entry `{name}` must still be refused"
            );
        }
    }

    #[test]
    fn names_match_folds_case_where_the_registry_folds_it() {
        // npm and crates.io both lowercase on publish, so a curator's
        // capitalised spelling must still fire against the queried name.
        assert!(names_match(Ecosystem::Npm, "React", "react"));
        assert!(names_match(Ecosystem::Npm, "@Scope/Pkg", "@scope/pkg"));
        assert!(names_match(Ecosystem::Cargo, "Serde", "serde"));
        // AUR pkgbases are case sensitive.
        assert!(!names_match(Ecosystem::Aur, "Yay", "yay"));
        // A genuinely different name must not match.
        assert!(!names_match(Ecosystem::Npm, "react-dom", "react"));
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
        let max_age_secs = recall_max_age_secs(&policy);
        let fetched_at = 1_700_000_000;
        let synced = SyncedSnapshot {
            fetched_at,
            url: "http://127.0.0.1:1".into(),
            snapshot: valid_snapshot(),
        };
        // The cap itself is fresh, one second past is stale, one second short is
        // fresh. Pinned on the arithmetic with the clock handed in: doing this
        // through the filesystem needed a retry loop to escape a same-second
        // stamp collision, because a write that straddles a second boundary
        // ages the snapshot by one and reads one second staler than it is.
        assert_eq!(
            stale_band_for(&synced, max_age_secs, false, fetched_at + max_age_secs),
            None,
            "age exactly max_age_secs must be fresh"
        );
        assert_eq!(
            stale_band_for(&synced, max_age_secs, false, fetched_at + max_age_secs - 1),
            None
        );
        assert_eq!(
            stale_band_for(&synced, max_age_secs, false, fetched_at + max_age_secs + 1),
            Some(crate::verdict::VerdictBand::Medium)
        );
        assert_eq!(
            stale_band_for(&synced, max_age_secs, true, fetched_at + max_age_secs + 1),
            Some(crate::verdict::VerdictBand::Block),
            "the escalation is on the same boundary as the band"
        );
        // A zero window still holds the exact instant it was fetched, and a
        // snapshot stamped ahead of the clock never reads as stale.
        assert_eq!(stale_band_for(&synced, 0, false, fetched_at), None);
        assert_eq!(
            stale_band_for(&synced, 0, false, fetched_at + 1),
            Some(crate::verdict::VerdictBand::Medium)
        );
        assert_eq!(stale_band_for(&synced, 0, false, fetched_at - 60), None);
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

    /// The temp name used to be `recall_snapshot.json.tmp-<pid>`, a fully
    /// predictable path, and `fs::write` follows a symlink. A link planted in
    /// the data directory turned a sync into an arbitrary-file overwrite.
    ///
    /// This runs the sync in a re-executed child, because the vulnerable name
    /// is derived from the pid of whichever process syncs. A test that plants
    /// the link from the parent plants a name the child never uses, so it
    /// passes against the code it is meant to catch.
    #[test]
    fn sync_does_not_follow_a_planted_symlink_in_the_data_directory() {
        let data_dir = tempfile::tempdir().unwrap();
        std::fs::write(data_dir.path().join("victim.txt"), b"original").unwrap();
        let (url, handle) =
            serve_recall_once(serde_json::to_vec(&recall_snapshot(42, 1_700_000_000)).unwrap());
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "sync_child_planted_symlink", "--nocapture"])
            .env("BLUELINE_DATA_DIR", data_dir.path())
            .env("BLUELINE_TEST_URL", &url)
            .output()
            .unwrap();
        handle.join().unwrap();
        assert!(
            out.status.success(),
            "child sync failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(data_dir.path().join("victim.txt")).unwrap(),
            "original",
            "a sync followed a planted symlink and overwrote its target"
        );
        assert!(
            data_dir.path().join("recall_snapshot.json").is_file(),
            "the snapshot itself must still be written"
        );
    }

    /// Child half of the rollback race, re-executed as its own process so the
    /// lock contention is between two real syncs. Exits 0 when the sync landed
    /// and 1 when it refused, so the parent's assertion is on the decision the
    /// sync made rather than on a panic.
    #[test]
    #[ignore = "re-executed by the_sequence_check_runs_inside_the_lock_not_before_it"]
    fn sync_child_for_rollback_race() {
        let Ok(url) = std::env::var("BLUELINE_TEST_URL") else {
            return;
        };
        if sync(&url).is_err() {
            std::process::exit(1);
        }
    }

    /// Child half of the symlink test above, re-executed as its own process so
    /// the planted name matches the pid that actually syncs.
    #[test]
    #[ignore = "re-executed by sync_does_not_follow_a_planted_symlink"]
    fn sync_child_planted_symlink() {
        let Ok(url) = std::env::var("BLUELINE_TEST_URL") else {
            return;
        };
        let data = std::path::PathBuf::from(std::env::var("BLUELINE_DATA_DIR").unwrap());
        let victim = data.join("victim.txt");
        std::fs::write(&victim, b"original").unwrap();
        let planted = data
            .join("recall_snapshot.json")
            .with_extension(format!("json.tmp-{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        sync(&url).unwrap();
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "original",
            "the sync followed a planted symlink and overwrote its target"
        );
    }

    /// Two syncs that both pass the sequence check must not be able to write
    /// out of order. The lock spans the whole read-compare-write, so the second
    /// writer sees the first one's sequence and refuses.
    #[test]
    fn sync_locks_the_compare_and_write() {
        let data_dir = tempfile::tempdir().unwrap();
        let held = SyncLock::acquire(data_dir.path()).unwrap();
        assert!(
            data_dir.path().join("recall_snapshot.lock").exists(),
            "the lock file must be visible to another process"
        );

        let (url, handle) =
            serve_recall_once(serde_json::to_vec(&recall_snapshot(42, 1_700_000_000)).unwrap());
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "sync_child_contended_lock", "--nocapture"])
            .env("BLUELINE_DATA_DIR", data_dir.path())
            .env("BLUELINE_TEST_URL", &url)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        handle.join().unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("refusing to race"),
            "a contended sync must fail loudly, got: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        drop(held);
        assert!(
            !data_dir.path().join("recall_snapshot.lock").exists(),
            "the lock must be released on drop, including the error path"
        );
    }

    /// Child half of the contended-lock test, re-executed as its own process so
    /// the lock is held by a different process than the one syncing. It waits
    /// `TEST_LOCK_WAIT` rather than the production `LOCK_WAIT` for the same
    /// reason the in-process test does: the wait under test is a refusal, and
    /// refusing in 200 ms says exactly what refusing in 30 s says.
    #[test]
    #[ignore = "re-executed by sync_locks_the_compare_and_write"]
    fn sync_child_contended_lock() {
        let Ok(url) = std::env::var("BLUELINE_TEST_URL") else {
            return;
        };
        if let Err(e) = sync_within(&url, TEST_LOCK_WAIT) {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    }

    #[test]
    fn sync_lock_times_out_loudly_rather_than_proceeding() {
        // Production's patience is pinned here so lowering it in the tests
        // cannot quietly lower it for users.
        assert_eq!(LOCK_WAIT, std::time::Duration::from_secs(30));

        let data_dir = tempfile::tempdir().unwrap();
        let _held = SyncLock::acquire(data_dir.path()).unwrap();
        let Err(err) = SyncLock::acquire_within(data_dir.path(), TEST_LOCK_WAIT) else {
            panic!("a held lock must not be acquirable");
        };
        assert!(
            err.to_string().contains("refusing to race"),
            "a contended lock must fail loudly, got {err}"
        );
        // The refusal through `sync` itself needs a child process: `sync`
        // resolves its path from the environment, so in-process it would lock
        // and write the real data directory rather than the temp one.
        // `sync_locks_the_compare_and_write` is that half.
    }
    /// The rollback this branch claimed to fix. Two syncs that both read the
    /// stored sequence before either writes: comparing first and locking
    /// afterwards lets the older snapshot land last, and `sequence` is read
    /// nowhere else, so every later review then trusts a rolled-back index.
    ///
    /// The ordering is forced with the lock itself. The parent holds the lock,
    /// so a child that compares *before* locking has already read the stored
    /// value and is now stuck in its retry loop holding a stale answer; a child
    /// that locks first has not compared at all. The parent then writes a newer
    /// sequence as a finished peer would, and releases. Only the second
    /// implementation can still see the newer sequence.
    #[test]
    fn the_sequence_check_runs_inside_the_lock_not_before_it() {
        let data_dir = tempfile::tempdir().unwrap();
        let snapshot_path = data_dir.path().join("recall_snapshot.json");
        let (seed_url, seed_handle) =
            serve_recall_once(serde_json::to_vec(&recall_snapshot(4, 1_700_000_000)).unwrap());
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

        let held = SyncLock::acquire(data_dir.path()).unwrap();

        // This child fetches sequence 5 while the parent holds the lock.
        let (older_url, older_handle) =
            serve_recall_once(serde_json::to_vec(&recall_snapshot(5, 1_700_000_000)).unwrap());
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "sync_child_for_rollback_race", "--nocapture"])
            .env("BLUELINE_DATA_DIR", data_dir.path())
            .env("BLUELINE_TEST_URL", &older_url)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        older_handle.join().unwrap();

        // Long enough for the child to fetch, compare, and settle into its lock
        // retry loop. Generous on purpose: a short wait would let the child
        // reach the lock late enough to read the new sequence regardless of
        // which implementation it is, and the test would pass either way.
        std::thread::sleep(std::time::Duration::from_millis(600));

        // A finished peer lands sequence 9 while the lock is still held.
        std::fs::write(
            &snapshot_path,
            serde_json::to_vec(&synced_tagged(9, "peer")).unwrap(),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        drop(held);

        let out = child.wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(1),
            "a sync to sequence 5 must refuse once a peer stored sequence 9, \
             got: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&snapshot_path).unwrap()).unwrap();
        assert_eq!(
            stored["snapshot"]["sequence"], 9,
            "the stored sequence must not roll back to 5"
        );
    }

    /// A lock file left by a process that died is reaped. `Drop` does not run
    /// on SIGKILL or an abort, so without reaping one crash would make every
    /// later sync wait out the full timeout and then fail forever.
    #[test]
    fn a_stale_lock_from_a_dead_holder_is_reaped() {
        let data_dir = tempfile::tempdir().unwrap();
        let lock = data_dir.path().join("recall_snapshot.lock");
        std::fs::write(&lock, b"").unwrap();
        assert!(
            !SyncLock::reap_if_stale(&lock),
            "a fresh lock file must not be stolen from a live holder"
        );
        let old =
            std::time::SystemTime::now() - (LOCK_STALE_AFTER + std::time::Duration::from_secs(60));
        std::fs::File::options()
            .write(true)
            .open(&lock)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(
            SyncLock::reap_if_stale(&lock),
            "a dead holder's lock must be reaped"
        );

        // The property that matters is on the acquire path, not the helper: a
        // stale lock left by a dead sync must not make every later sync wait
        // out the full timeout and then fail. Asserted through `acquire` with no
        // manual reaping first, so removing the call inside it fails here --
        // which takes the full lock deadline to do, but only in the mutated
        // build.
        let lock2 = data_dir.path().join("recall_snapshot.lock");
        std::fs::write(&lock2, b"").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&lock2)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let acquired = SyncLock::acquire(data_dir.path());
        assert!(
            acquired.is_ok(),
            "a stale lock must not block acquisition: {:?}",
            acquired.err()
        );
    }

    /// The hours-to-seconds conversion, pinned against the constant rather than
    /// against itself.
    ///
    /// `stale_band_pins_max_age_boundary` derived *both* sides of its boundary
    /// from `recall_max_age_secs(&policy)`, so it would have passed with the
    /// conversion returning 0, 1, or anything at all: both the cap and the
    /// ages under test moved together. That is the one way an assertion about a
    /// conversion can be vacuous, and it is why the constant is written out
    /// here. A window that silently became zero would make every snapshot over
    /// zero seconds old stale, and one that became 48x too large would disable
    /// staleness disclosure entirely.
    #[test]
    fn the_recall_window_converts_hours_to_seconds() {
        let cases: [(u64, i64); 4] = [(1, 3_600), (2, 7_200), (24, 86_400), (48, 172_800)];
        for (hours, secs) in cases {
            let mut policy = crate::policy::Policy::default();
            policy.recall.max_age_hours = hours;
            assert_eq!(
                recall_max_age_secs(&policy),
                secs,
                "max_age_hours = {hours} must be {secs} seconds"
            );
        }
    }

    /// `age_secs` is the public accessor and the only place the real clock is
    /// read, and every other test hands `stale_band_for` a clock it chose. A
    /// constant here would have gone unnoticed, including a negative one.
    ///
    /// The window is a few seconds wide rather than exact: this genuinely reads
    /// `SystemTime::now()`, and pinning it to the second would make it a
    /// coin flip on where the test's own execution lands.
    #[test]
    fn age_secs_measures_against_the_wall_clock() {
        let hour_ago = now_secs() - 3_600;
        let synced = SyncedSnapshot {
            fetched_at: hour_ago,
            url: "http://127.0.0.1:1".into(),
            snapshot: valid_snapshot(),
        };
        let age = synced.age_secs();
        assert!(
            (3_600..=3_610).contains(&age),
            "a snapshot fetched an hour ago must read about an hour old, got {age}"
        );

        // A clock that has gone backwards reads as fresh rather than negative:
        // a future stamp is a fault to disclose, not an age to subtract.
        let ahead = SyncedSnapshot {
            fetched_at: now_secs() + 600,
            url: "http://127.0.0.1:1".into(),
            snapshot: valid_snapshot(),
        };
        assert_eq!(ahead.age_secs(), 0);
    }

    /// A lock that is released while the caller is still inside its wait window
    /// must be acquired, not refused.
    ///
    /// This is the pair of mutants that a contended-lock test cannot see. Both
    /// the deadline expression and the comparison that consults it can be
    /// broken in a direction that makes the *refusal* fire immediately, and the
    /// existing timeout test still passes — a lock that is held forever and a
    /// lock that is held for 60ms both produce "refusing to race". Only a
    /// holder that lets go distinguishes them: a deadline computed in the past,
    /// or a comparison that bails while the deadline is still ahead, turns a
    /// successful acquisition into an error.
    #[test]
    fn a_lock_released_inside_the_wait_window_is_acquired() {
        let data_dir = tempfile::tempdir().unwrap();
        let parent = data_dir.path().to_path_buf();
        let held = SyncLock::acquire(&parent).unwrap();

        let releaser = {
            let parent = parent.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(60));
                drop(held);
                // Keep the directory alive until the waiter is done with it.
                drop(parent);
            })
        };

        let got = SyncLock::acquire_within(&parent, std::time::Duration::from_millis(5_000))
            .map(|_| ())
            .map_err(|e| format!("{e:#}"));
        releaser.join().unwrap();

        assert!(
            got.is_ok(),
            "a lock freed inside the wait window must be acquired, not refused: {got:?}"
        );
    }

    /// An error opening the lock that is *not* "it already exists" must be
    /// reported as itself.
    ///
    /// The `AlreadyExists` arm is what lets the loop retry. Widening it to every
    /// error turns a permanent, immediately detectable fault — a path whose
    /// parent is a regular file, so the open fails `ENOTDIR` — into a spin
    /// until the deadline and then the generic "refusing to race", which names
    /// a lock contention that never happened and hides the real cause. Asserted
    /// on the message so a caller can tell the two apart.
    #[test]
    fn an_unopenable_lock_path_reports_its_own_error() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("a-regular-file");
        std::fs::write(&not_a_dir, b"not a directory").unwrap();

        let err = SyncLock::acquire_within(&not_a_dir, TEST_LOCK_WAIT)
            .map(|_| ())
            .expect_err("opening a lock under a regular file cannot succeed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("creating"),
            "the real failure must be reported, not retried into a timeout: {msg}"
        );
        assert!(
            !msg.contains("refusing to race"),
            "this is not lock contention and must not be reported as such: {msg}"
        );
    }

    /// The reap branch must respect the deadline, or a reap that always succeeds
    /// spins forever.
    ///
    /// The reap arm used to `continue` past the deadline test, so a peer whose
    /// lock is reapable never reached a bound: every iteration removed the lock,
    /// looped, and hit the next one. No sleep, no deadline, no exit — a 30 second
    /// bounded wait becomes a hang on the sync path, with no error to show.
    /// Mutation shard 22 hit this and ran to the 300s per-mutant timeout.
    ///
    /// A wait of zero makes the assertion deterministic instead of racy, which a
    /// competing-recreator test could not be. The deadline has already passed on
    /// entry, so the reap must bail immediately:
    ///
    /// * with the check, the reap succeeds and the now-expired deadline refuses.
    /// * without it, the reap succeeds and the loop's next `create_new` finds a
    ///   free path, so the call returns `Ok` having waited no time at all.
    ///
    /// So `Ok` here is not "won the lock", it is the bug.
    #[test]
    fn a_reap_that_always_succeeds_still_honours_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().to_path_buf();
        let lock_path = parent.join("recall_snapshot.lock");
        let held = SyncLock::acquire(&parent).unwrap();
        drop(held);

        // Old enough that every reap succeeds, which is the condition that turns
        // the missing check into an unbounded loop.
        let old =
            std::time::SystemTime::now() - LOCK_STALE_AFTER - std::time::Duration::from_secs(1);
        filetime_reset(&lock_path, old);

        let got = SyncLock::acquire_within(&parent, std::time::Duration::ZERO)
            .map(|_| ())
            .map_err(|e| format!("{e:#}"));
        let _ = std::fs::remove_file(&lock_path);

        assert!(
            got.is_err(),
            "an expired deadline must refuse even when the reap succeeds; returning \
             Ok means the reap branch skipped the deadline check and would spin \
             against a peer that keeps re-creating its lock: {got:?}"
        );
        assert!(
            got.as_ref().unwrap_err().contains("refusing to race"),
            "the bound must be reported as the contention it is: {got:?}"
        );
    }

    /// Set a file's mtime, so a lock can be made old enough to reap. Shells out
    /// to `touch` because the stdlib has no portable setter, and the one caller
    /// is a file-age test on a platform that has one.
    fn filetime_reset(path: &Path, when: std::time::SystemTime) {
        let secs = when
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = std::process::Command::new("touch")
            .arg("-d")
            .arg(format!("@{secs}"))
            .arg(path)
            .status();
    }

    /// The reap threshold, sitting exactly on it.
    ///
    /// Through the filesystem this boundary is unreachable: setting a file's
    /// mtime and then reading it always lands on the far side of the instant the
    /// test chose, so a filesystem test can only ever check "clearly fresh" or
    /// "clearly stale". That is why `reap_if_aged` takes the age.
    #[test]
    fn a_lock_exactly_at_the_stale_threshold_is_not_reaped() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("recall_snapshot.lock");

        // A real file, because the removal has to succeed for the reap to report
        // itself; a lock that is never created is reaped vacuously.
        std::fs::write(&lock, b"").unwrap();
        assert!(
            SyncLock::reap_if_aged(&lock, LOCK_STALE_AFTER),
            "the threshold is inclusive: a lock that has reached it is reaped"
        );
        assert!(
            !SyncLock::reap_if_aged(&lock, LOCK_STALE_AFTER - std::time::Duration::from_nanos(1)),
            "one nanosecond short of the threshold must be left alone"
        );
        assert!(
            !SyncLock::reap_if_aged(&lock, std::time::Duration::ZERO),
            "a brand new lock is not stale"
        );
    }
}
