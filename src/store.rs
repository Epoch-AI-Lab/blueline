use std::fs;
use std::path::Path;

use rusqlite_migration::{M, Migrations};

use crate::error::BluelineError;
use crate::registry::{Checksum, Ecosystem};

const MIGRATIONS: &[&str] = &[
    "
    CREATE TABLE known_clean (
        name        TEXT NOT NULL,
        version     TEXT NOT NULL,
        integrity   TEXT NOT NULL,
        reviewed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        PRIMARY KEY (name, version)
    ) STRICT;
    ",
    "
    ALTER TABLE known_clean ADD COLUMN clean INTEGER NOT NULL DEFAULT 0;
    ",
    "
    CREATE TABLE advisory_cache (
        package               TEXT NOT NULL,
        version               TEXT NOT NULL,
        advisories_json       TEXT NOT NULL,
        hit_count             INTEGER NOT NULL DEFAULT 0,
        has_blocking_advisory INTEGER NOT NULL DEFAULT 0,
        fetched_at            INTEGER NOT NULL,
        expires_at            INTEGER NOT NULL,
        PRIMARY KEY (package, version)
    ) STRICT;

    CREATE INDEX idx_advisory_cache_expiry ON advisory_cache(expires_at);

    CREATE TABLE provenance_cache (
        package          TEXT NOT NULL,
        version          TEXT NOT NULL,
        builder_id       TEXT,
        source_repo      TEXT,
        commit_sha       TEXT,
        workflow_path    TEXT,
        slsa_level       INTEGER NOT NULL DEFAULT 0,
        signature_valid  INTEGER NOT NULL DEFAULT 0,
        verified_at      INTEGER NOT NULL,
        PRIMARY KEY (package, version)
    ) STRICT;

    CREATE TABLE audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        package    TEXT NOT NULL,
        version    TEXT NOT NULL,
        integrity  TEXT NOT NULL,
        action     TEXT NOT NULL,
        score      INTEGER NOT NULL,
        verdict    TEXT NOT NULL,
        decided_by TEXT NOT NULL,
        notes      TEXT,
        decided_at INTEGER NOT NULL
    ) STRICT;

    CREATE INDEX idx_audit_pkg_ver ON audit_log(package, version);
    ",
    // v3: multi-registry. Every row gains an ecosystem dimension; pre-existing
    // rows are npm-scoped. PKs must be rebuilt, so the three keyed tables are
    // swapped via `_new` copies. audit_log has no composite key, so a plain
    // column addition suffices there.
    "
    ALTER TABLE audit_log ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'npm';

    CREATE TABLE known_clean_new (
        ecosystem   TEXT NOT NULL,
        name        TEXT NOT NULL,
        version     TEXT NOT NULL,
        integrity   TEXT NOT NULL,
        clean       INTEGER NOT NULL DEFAULT 0,
        reviewed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        PRIMARY KEY (ecosystem, name, version)
    ) STRICT;

    INSERT INTO known_clean_new (ecosystem, name, version, integrity, clean, reviewed_at)
        SELECT 'npm', name, version, integrity, clean, reviewed_at FROM known_clean;

    DROP TABLE known_clean;
    ALTER TABLE known_clean_new RENAME TO known_clean;

    CREATE TABLE advisory_cache_new (
        ecosystem             TEXT NOT NULL,
        package               TEXT NOT NULL,
        version               TEXT NOT NULL,
        advisories_json       TEXT NOT NULL,
        hit_count             INTEGER NOT NULL DEFAULT 0,
        has_blocking_advisory INTEGER NOT NULL DEFAULT 0,
        fetched_at            INTEGER NOT NULL,
        expires_at            INTEGER NOT NULL,
        PRIMARY KEY (ecosystem, package, version)
    ) STRICT;

    INSERT INTO advisory_cache_new (
            ecosystem, package, version, advisories_json, hit_count,
            has_blocking_advisory, fetched_at, expires_at)
        SELECT 'npm', package, version, advisories_json, hit_count,
               has_blocking_advisory, fetched_at, expires_at
        FROM advisory_cache;

    DROP TABLE advisory_cache;
    ALTER TABLE advisory_cache_new RENAME TO advisory_cache;

    CREATE INDEX idx_advisory_cache_expiry ON advisory_cache(expires_at);

    CREATE TABLE provenance_cache_new (
        ecosystem        TEXT NOT NULL,
        package          TEXT NOT NULL,
        version          TEXT NOT NULL,
        builder_id       TEXT,
        source_repo      TEXT,
        commit_sha       TEXT,
        workflow_path    TEXT,
        slsa_level       INTEGER NOT NULL DEFAULT 0,
        signature_valid  INTEGER NOT NULL DEFAULT 0,
        verified_at      INTEGER NOT NULL,
        PRIMARY KEY (ecosystem, package, version)
    ) STRICT;

    INSERT INTO provenance_cache_new (
            ecosystem, package, version, builder_id, source_repo, commit_sha,
            workflow_path, slsa_level, signature_valid, verified_at)
        SELECT 'npm', package, version, builder_id, source_repo, commit_sha,
               workflow_path, slsa_level, signature_valid, verified_at
        FROM provenance_cache;

    DROP TABLE provenance_cache;
    ALTER TABLE provenance_cache_new RENAME TO provenance_cache;
    ",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedAdvisories {
    pub advisories_json: String,
    pub hit_count: usize,
    pub has_blocking: bool,
    pub fetched_at: i64,
    pub expires_at: i64,
    pub is_expired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedProvenance {
    pub builder_id: Option<String>,
    pub source_repo: Option<String>,
    pub commit_sha: Option<String>,
    pub workflow_path: Option<String>,
    pub slsa_level: u32,
    pub signature_valid: bool,
    pub verified_at: i64,
}

/// SQLite store for the review baseline. A row records that `name@version`
/// was integrity-verified, with `clean = 0` the default: only a verdict
/// (Phase 1) may mark a version clean, so merely running a review never
/// blesses a release.
pub struct BaselineStore {
    conn: rusqlite::Connection,
}

impl BaselineStore {
    pub fn open() -> Result<Self, BluelineError> {
        Self::open_at(&default_db_path()?)
    }

    pub fn open_at(path: &Path) -> Result<Self, BluelineError> {
        if let Some(parent) = path.parent() {
            #[cfg(unix)]
            {
                if let Ok(meta) = fs::symlink_metadata(parent)
                    && meta.file_type().is_symlink()
                {
                    return Err(BluelineError::Store(
                        "data directory cannot be a symbolic link".into(),
                    ));
                }
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                builder.mode(0o700);
                builder.create(parent).map_err(|e| {
                    BluelineError::Store(format!("creating {}: {e}", parent.display()))
                })?;
                if let Ok(meta) = fs::symlink_metadata(parent) {
                    if meta.file_type().is_symlink() {
                        return Err(BluelineError::Store(
                            "data directory cannot be a symbolic link".into(),
                        ));
                    }
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = meta.permissions();
                    perms.set_mode(0o700);
                    let _ = fs::set_permissions(parent, perms);
                }
            }
            #[cfg(not(unix))]
            {
                fs::create_dir_all(parent).map_err(|e| {
                    BluelineError::Store(format!("creating {}: {e}", parent.display()))
                })?;
            }
        }

        #[cfg(unix)]
        {
            if let Ok(meta) = fs::symlink_metadata(path)
                && meta.file_type().is_symlink()
            {
                return Err(BluelineError::Store(
                    "database path cannot be a symbolic link".into(),
                ));
            }
            use std::os::unix::fs::OpenOptionsExt;
            let _ = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path);
        }

        let mut conn = rusqlite::Connection::open(path)
            .map_err(|e| BluelineError::Store(format!("opening {}: {e}", path.display())))?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))
            .map_err(|e| BluelineError::Store(format!("setting busy timeout: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::symlink_metadata(path) {
                if meta.file_type().is_symlink() {
                    return Err(BluelineError::Store(
                        "database path cannot be a symbolic link".into(),
                    ));
                }
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = fs::set_permissions(path, perms);
            }
        }

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| BluelineError::Store(format!("enabling WAL: {e}")))?;

        let migrations = Migrations::new(MIGRATIONS.iter().map(|sql| M::up(sql)).collect());
        migrations
            .to_latest(&mut conn)
            .map_err(|e| BluelineError::Store(format!("applying migrations: {e}")))?;

        Ok(Self { conn })
    }

    /// Record that `name@version` was integrity-verified. This is evidence,
    /// not a judgment: `clean` stays 0. Re-recording the identical checksum
    /// is idempotent and refreshes the timestamp; re-recording a DIFFERENT
    /// checksum for the same version fails closed, because a republished
    /// tarball under the same version string must not silently overwrite what
    /// was witnessed before. Comparison is on normalized digest content, so
    /// legacy SRI rows and new display-form rows are judged alike.
    pub fn record_verified(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        checksum: &Checksum,
    ) -> Result<(), BluelineError> {
        let stored = self.stored_integrity(ecosystem, name, version)?;
        match stored {
            Some(existing) => {
                let existing = Checksum::parse(&existing).map_err(|_| {
                    BluelineError::Store(format!(
                        "integrity changed for {name}@{version}: the stored record no longer matches this \
                         tarball; refusing to overwrite it"
                    ))
                })?;
                if existing != *checksum {
                    return Err(BluelineError::Store(format!(
                        "integrity changed for {name}@{version}: the stored record no longer matches this \
                         tarball; refusing to overwrite it"
                    )));
                }
                self.conn
                    .prepare_cached(
                        "UPDATE known_clean
                         SET reviewed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                         WHERE ecosystem = ?1 AND name = ?2 AND version = ?3",
                    )
                    .map_err(|e| BluelineError::Store(format!("preparing refresh: {e}")))?
                    .execute(rusqlite::params![ecosystem.key(), name, version])
                    .map_err(|e| {
                        BluelineError::Store(format!("recording {name}@{version}: {e}"))
                    })?;
                Ok(())
            }
            None => {
                self.conn
                    .prepare_cached(
                        "INSERT INTO known_clean (ecosystem, name, version, integrity)
                         VALUES (?1, ?2, ?3, ?4)",
                    )
                    .map_err(|e| BluelineError::Store(format!("preparing upsert: {e}")))?
                    .execute(rusqlite::params![
                        ecosystem.key(),
                        name,
                        version,
                        checksum.to_display()
                    ])
                    .map_err(|e| {
                        BluelineError::Store(format!("recording {name}@{version}: {e}"))
                    })?;
                Ok(())
            }
        }
    }

    fn stored_integrity(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<Option<String>, BluelineError> {
        use rusqlite::OptionalExtension;
        self.conn
            .prepare_cached(
                "SELECT integrity FROM known_clean
                 WHERE ecosystem = ?1 AND name = ?2 AND version = ?3",
            )
            .map_err(|e| BluelineError::Store(format!("preparing select: {e}")))?
            .query_row(rusqlite::params![ecosystem.key(), name, version], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| BluelineError::Store(format!("reading {name}@{version}: {e}")))
    }

    /// Mark a verified version as clean (user approved). The witness checksum
    /// must match the stored record's normalized digest.
    pub fn mark_clean(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        checksum: &Checksum,
    ) -> Result<(), BluelineError> {
        let stored = self.stored_integrity(ecosystem, name, version)?;
        let matches = stored
            .as_deref()
            .and_then(|s| Checksum::parse(s).ok())
            .is_some_and(|existing| existing == *checksum);
        if !matches {
            return Err(BluelineError::Store(format!(
                "cannot mark clean {name}@{version}: record missing or integrity mismatch"
            )));
        }
        let affected = self
            .conn
            .prepare_cached(
                "UPDATE known_clean
                 SET clean = 1, reviewed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                 WHERE ecosystem = ?1 AND name = ?2 AND version = ?3",
            )
            .map_err(|e| BluelineError::Store(format!("preparing mark_clean: {e}")))?
            .execute(rusqlite::params![ecosystem.key(), name, version])
            .map_err(|e| BluelineError::Store(format!("marking clean {name}@{version}: {e}")))?;
        if affected == 0 {
            return Err(BluelineError::Store(format!(
                "cannot mark clean {name}@{version}: record missing or integrity mismatch"
            )));
        }
        Ok(())
    }

    /// Retrieve all versions marked clean for a package, sorted descending.
    pub fn list_clean_versions<V: crate::version::VersionInfo>(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<(V, String)>, BluelineError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT version, integrity FROM known_clean
                 WHERE ecosystem = ?1 AND name = ?2 AND clean = 1",
            )
            .map_err(|e| BluelineError::Store(format!("preparing select clean: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![ecosystem.key(), name], |row| {
                let ver_str: String = row.get(0)?;
                let integrity: String = row.get(1)?;
                Ok((ver_str, integrity))
            })
            .map_err(|e| {
                BluelineError::Store(format!("querying clean versions for {name}: {e}"))
            })?;
        let mut versions = Vec::new();
        for row in rows {
            let (v_str, integ) = row
                .map_err(|e| BluelineError::Store(format!("reading clean row for {name}: {e}")))?;
            if let Ok(v) = V::parse(&v_str) {
                versions.push((v, integ));
            }
        }
        versions.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(versions)
    }

    #[cfg(test)]
    pub fn known_clean(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<Option<String>, BluelineError> {
        use rusqlite::OptionalExtension;
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT integrity FROM known_clean
                 WHERE ecosystem = ?1 AND name = ?2 AND version = ?3",
            )
            .map_err(|e| BluelineError::Store(format!("preparing select: {e}")))?;
        stmt.query_row(rusqlite::params![ecosystem.key(), name, version], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|e| BluelineError::Store(format!("reading {name}@{version}: {e}")))
    }

    /// Retrieve cached advisories for `package@version` if present.
    pub fn get_cached_advisories(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        version: &str,
    ) -> Result<Option<CachedAdvisories>, BluelineError> {
        use rusqlite::OptionalExtension;
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT advisories_json, hit_count, has_blocking_advisory, fetched_at, expires_at
                 FROM advisory_cache WHERE ecosystem = ?1 AND package = ?2 AND version = ?3",
            )
            .map_err(|e| BluelineError::Store(format!("preparing get_cached_advisories: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        stmt.query_row(
            rusqlite::params![ecosystem.key(), package, version],
            |row| {
                let json: String = row.get(0)?;
                let hit_count: i64 = row.get(1)?;
                let has_blocking: i64 = row.get(2)?;
                let fetched_at: i64 = row.get(3)?;
                let expires_at: i64 = row.get(4)?;
                Ok(CachedAdvisories {
                    advisories_json: json,
                    hit_count: hit_count.max(0) as usize,
                    has_blocking: has_blocking != 0,
                    fetched_at,
                    expires_at,
                    is_expired: now >= expires_at,
                })
            },
        )
        .optional()
        .map_err(|e| {
            BluelineError::Store(format!(
                "reading cached advisories for {package}@{version}: {e}"
            ))
        })
    }

    /// Cache advisory results for `package@version` with a specified TTL in seconds.
    #[allow(clippy::too_many_arguments)]
    pub fn put_cached_advisories(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        version: &str,
        advisories_json: &str,
        hit_count: usize,
        has_blocking: bool,
        ttl_secs: i64,
    ) -> Result<(), BluelineError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let expires_at = now.saturating_add(ttl_secs);

        self.conn
            .prepare_cached(
                "INSERT INTO advisory_cache (ecosystem, package, version, advisories_json, hit_count, has_blocking_advisory, fetched_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(ecosystem, package, version) DO UPDATE SET
                     advisories_json = excluded.advisories_json,
                     hit_count = excluded.hit_count,
                     has_blocking_advisory = excluded.has_blocking_advisory,
                     fetched_at = excluded.fetched_at,
                     expires_at = excluded.expires_at",
            )
            .map_err(|e| BluelineError::Store(format!("preparing put_cached_advisories: {e}")))?
            .execute(rusqlite::params![
                ecosystem.key(),
                package,
                version,
                advisories_json,
                hit_count as i64,
                if has_blocking { 1 } else { 0 },
                now,
                expires_at,
            ])
            .map_err(|e| {
                BluelineError::Store(format!("storing advisories for {package}@{version}: {e}"))
            })?;

        Ok(())
    }

    /// Clear all cached advisories. Returns the number of deleted cache rows.
    #[allow(dead_code)]
    pub fn clear_advisory_cache(&self) -> Result<usize, BluelineError> {
        let count = self
            .conn
            .execute("DELETE FROM advisory_cache", [])
            .map_err(|e| BluelineError::Store(format!("clearing advisory cache: {e}")))?;
        Ok(count)
    }

    /// Cache verified provenance and registry signatures for `package@version`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_provenance(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        version: &str,
        builder_id: Option<&str>,
        source_repo: Option<&str>,
        commit_sha: Option<&str>,
        workflow_path: Option<&str>,
        slsa_level: u32,
        signature_valid: bool,
    ) -> Result<(), BluelineError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.conn
            .prepare_cached(
                "INSERT INTO provenance_cache (ecosystem, package, version, builder_id, source_repo, commit_sha, workflow_path, slsa_level, signature_valid, verified_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(ecosystem, package, version) DO UPDATE SET
                     builder_id = excluded.builder_id,
                     source_repo = excluded.source_repo,
                     commit_sha = excluded.commit_sha,
                     workflow_path = excluded.workflow_path,
                     slsa_level = excluded.slsa_level,
                     signature_valid = excluded.signature_valid,
                     verified_at = excluded.verified_at",
            )
            .map_err(|e| BluelineError::Store(format!("preparing record_provenance: {e}")))?
            .execute(rusqlite::params![
                ecosystem.key(),
                package,
                version,
                builder_id,
                source_repo,
                commit_sha,
                workflow_path,
                slsa_level as i64,
                if signature_valid { 1 } else { 0 },
                now,
            ])
            .map_err(|e| {
                BluelineError::Store(format!("storing provenance for {package}@{version}: {e}"))
            })?;

        Ok(())
    }

    /// Retrieve cached provenance metadata for `package@version`.
    pub fn get_cached_provenance(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        version: &str,
    ) -> Result<Option<CachedProvenance>, BluelineError> {
        use rusqlite::OptionalExtension;
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT builder_id, source_repo, commit_sha, workflow_path, slsa_level, signature_valid, verified_at
                 FROM provenance_cache WHERE ecosystem = ?1 AND package = ?2 AND version = ?3",
            )
            .map_err(|e| BluelineError::Store(format!("preparing get_cached_provenance: {e}")))?;

        stmt.query_row(
            rusqlite::params![ecosystem.key(), package, version],
            |row| {
                let builder_id: Option<String> = row.get(0)?;
                let source_repo: Option<String> = row.get(1)?;
                let commit_sha: Option<String> = row.get(2)?;
                let workflow_path: Option<String> = row.get(3)?;
                let slsa_level: i64 = row.get(4)?;
                let signature_valid: i64 = row.get(5)?;
                let verified_at: i64 = row.get(6)?;
                Ok(CachedProvenance {
                    builder_id,
                    source_repo,
                    commit_sha,
                    workflow_path,
                    slsa_level: slsa_level.max(0) as u32,
                    signature_valid: signature_valid != 0,
                    verified_at,
                })
            },
        )
        .optional()
        .map_err(|e| {
            BluelineError::Store(format!(
                "reading cached provenance for {package}@{version}: {e}"
            ))
        })
    }

    /// Record an audit decision (e.g. approve, hold, block) into the audit trail.
    #[allow(clippy::too_many_arguments)]
    pub fn record_audit_log(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        version: &str,
        integrity: &str,
        action: &str,
        score: u32,
        verdict: &str,
        decided_by: &str,
        notes: Option<&str>,
    ) -> Result<(), BluelineError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.conn
            .prepare_cached(
                "INSERT INTO audit_log (ecosystem, package, version, integrity, action, score, verdict, decided_by, notes, decided_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )
            .map_err(|e| BluelineError::Store(format!("preparing record_audit_log: {e}")))?
            .execute(rusqlite::params![
                ecosystem.key(),
                package,
                version,
                integrity,
                action,
                score as i64,
                verdict,
                decided_by,
                notes,
                now,
            ])
            .map_err(|e| {
                BluelineError::Store(format!(
                    "recording audit log for {package}@{version}: {e}"
                ))
            })?;

        Ok(())
    }
}

fn default_db_path() -> Result<std::path::PathBuf, BluelineError> {
    if let Ok(dir) = std::env::var("BLUELINE_DATA_DIR") {
        return Ok(Path::new(&dir).join("baseline.db"));
    }
    let base = dirs::data_dir().ok_or_else(|| {
        BluelineError::Store(
            "could not determine the platform data directory (set BLUELINE_DATA_DIR)".into(),
        )
    })?;
    Ok(base.join("blueline").join("baseline.db"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ChecksumAlg;
    use sha2::{Digest, Sha512};

    fn ck(tag: &str) -> Checksum {
        let mut hasher = Sha512::new();
        hasher.update(tag.as_bytes());
        Checksum {
            alg: ChecksumAlg::Sha512,
            value_hex: format!("{:x}", hasher.finalize()),
        }
    }

    #[test]
    fn records_verified_witness_as_unclean() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified(Ecosystem::Npm, "express", "4.21.2", &ck("abc"))
            .unwrap();
        assert_eq!(
            store
                .known_clean(Ecosystem::Npm, "express", "4.21.2")
                .unwrap()
                .as_deref(),
            Some(ck("abc").to_display().as_str())
        );
        assert_eq!(
            store
                .known_clean(Ecosystem::Npm, "express", "4.21.1")
                .unwrap(),
            None
        );
        let unclean: i64 = {
            let conn = rusqlite::Connection::open(dir.path().join("t.db")).unwrap();
            conn.query_row(
                "SELECT COUNT(*) FROM known_clean
                 WHERE ecosystem = 'npm' AND name = 'express' AND version = '4.21.2' AND clean = 0",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(unclean, 1, "a review records evidence, never clean=1");
    }

    #[test]
    fn re_record_with_same_integrity_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified(Ecosystem::Npm, "pkg", "1.0.0", &ck("one"))
            .unwrap();
        // Same digest content in a different accepted spelling is still idempotent.
        store
            .record_verified(
                Ecosystem::Npm,
                "pkg",
                "1.0.0",
                &Checksum::parse(&ck("one").to_sri()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store
                .known_clean(Ecosystem::Npm, "pkg", "1.0.0")
                .unwrap()
                .as_deref(),
            Some(ck("one").to_display().as_str())
        );
        let count: i64 = {
            let conn = rusqlite::Connection::open(dir.path().join("t.db")).unwrap();
            conn.query_row("SELECT COUNT(*) FROM known_clean", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count, 1);
    }

    #[test]
    fn integrity_change_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified(Ecosystem::Npm, "pkg", "1.0.0", &ck("one"))
            .unwrap();
        let err = store
            .record_verified(Ecosystem::Npm, "pkg", "1.0.0", &ck("two"))
            .unwrap_err();
        assert!(err.to_string().contains("integrity changed"));
        assert_eq!(
            store
                .known_clean(Ecosystem::Npm, "pkg", "1.0.0")
                .unwrap()
                .as_deref(),
            Some(ck("one").to_display().as_str()),
            "the stored record must survive a rejected rewrite"
        );
    }

    #[test]
    fn ecosystems_are_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified(Ecosystem::Npm, "pkg", "1.0.0", &ck("npm"))
            .unwrap();
        // The same name@version under another ecosystem is an independent row.
        store
            .record_verified(Ecosystem::Cargo, "pkg", "1.0.0", &ck("cargo"))
            .unwrap();
        assert_eq!(
            store.known_clean(Ecosystem::Npm, "pkg", "1.0.0").unwrap(),
            Some(ck("npm").to_display())
        );
        assert_eq!(
            store.known_clean(Ecosystem::Cargo, "pkg", "1.0.0").unwrap(),
            Some(ck("cargo").to_display())
        );

        // Approving cargo must not bless the npm row.
        store
            .mark_clean(Ecosystem::Cargo, "pkg", "1.0.0", &ck("cargo"))
            .unwrap();
        assert_eq!(
            store
                .list_clean_versions::<semver::Version>(Ecosystem::Npm, "pkg")
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            store
                .list_clean_versions::<semver::Version>(Ecosystem::Cargo, "pkg")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn migration_v2_to_v3_scopes_old_rows_to_npm() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t.db");
        let legacy_checksum = ck("legacy");

        // Build a legacy v2 database (first three migrations only).
        {
            let mut conn = rusqlite::Connection::open(&db_path).unwrap();
            let migrations =
                Migrations::new(MIGRATIONS.iter().take(3).map(|sql| M::up(sql)).collect());
            migrations.to_latest(&mut conn).unwrap();
            conn.execute(
                "INSERT INTO known_clean (name, version, integrity, clean) VALUES ('legacy', '1.0.0', ?1, 1)",
                rusqlite::params![legacy_checksum.to_sri()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO advisory_cache (package, version, advisories_json, fetched_at, expires_at)
                 VALUES ('legacy', '1.0.0', '{}', 0, 9223372036854775807)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO provenance_cache (package, version, verified_at) VALUES ('legacy', '1.0.0', 42)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO audit_log (package, version, integrity, action, score, verdict, decided_by, decided_at)
                 VALUES ('legacy', '1.0.0', 'sha512-YWJjZA==', 'approve', 0, 'LOW', 'user', 7)",
                [],
            )
            .unwrap();
        }

        // Reopening runs the v3 migration; legacy rows must survive npm-scoped.
        let store = BaselineStore::open_at(&db_path).unwrap();

        let clean = store
            .list_clean_versions::<semver::Version>(Ecosystem::Npm, "legacy")
            .unwrap();
        assert_eq!(clean.len(), 1);
        assert_eq!(clean[0].0.to_string(), "1.0.0");
        // The legacy SRI value survives verbatim and normalizes to the same content.
        assert_eq!(clean[0].1, legacy_checksum.to_sri());
        assert_eq!(Checksum::parse(&clean[0].1).unwrap(), legacy_checksum);

        assert!(
            store
                .get_cached_advisories(Ecosystem::Npm, "legacy", "1.0.0")
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get_cached_provenance(Ecosystem::Npm, "legacy", "1.0.0")
                .unwrap()
                .is_some()
        );

        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            let audit_eco: String = conn
                .query_row(
                    "SELECT ecosystem FROM audit_log WHERE package = 'legacy'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(audit_eco, "npm");
        }

        // The rebuilt PK admits a non-npm row at the same name@version.
        store
            .record_verified(Ecosystem::PyPi, "legacy", "1.0.0", &ck("pypi"))
            .unwrap();

        // Tamper guard compares normalized content across accepted spellings:
        // same digest in display form is idempotent against the legacy SRI row...
        store
            .record_verified(Ecosystem::Npm, "legacy", "1.0.0", &legacy_checksum)
            .unwrap();
        // ...and a genuinely different digest still fails closed.
        assert!(
            store
                .record_verified(
                    Ecosystem::Npm,
                    "legacy",
                    "1.0.0",
                    &Checksum {
                        alg: ChecksumAlg::Sha512,
                        value_hex: format!("{:x}", Sha512::digest(b"tampered")),
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn migration_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        BaselineStore::open_at(&path).unwrap();
        BaselineStore::open_at(&path).unwrap();
    }

    #[test]
    fn mark_clean_and_list_clean_versions() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified(Ecosystem::Npm, "pkg", "1.0.0", &ck("v1"))
            .unwrap();
        store
            .record_verified(Ecosystem::Npm, "pkg", "1.1.0", &ck("v2"))
            .unwrap();
        store
            .record_verified(Ecosystem::Npm, "pkg", "2.0.0", &ck("v3"))
            .unwrap();

        assert!(
            store
                .list_clean_versions::<semver::Version>(Ecosystem::Npm, "pkg")
                .unwrap()
                .is_empty()
        );

        store
            .mark_clean(Ecosystem::Npm, "pkg", "1.0.0", &ck("v1"))
            .unwrap();
        store
            .mark_clean(Ecosystem::Npm, "pkg", "2.0.0", &ck("v3"))
            .unwrap();

        let clean = store
            .list_clean_versions::<semver::Version>(Ecosystem::Npm, "pkg")
            .unwrap();
        assert_eq!(clean.len(), 2);
        assert_eq!(clean[0].0, semver::Version::parse("2.0.0").unwrap());
        assert_eq!(Checksum::parse(&clean[0].1).unwrap(), ck("v3"));
        assert_eq!(clean[1].0, semver::Version::parse("1.0.0").unwrap());
        assert_eq!(Checksum::parse(&clean[1].1).unwrap(), ck("v1"));

        // Marking unrecorded version errors
        assert!(
            store
                .mark_clean(Ecosystem::Npm, "pkg", "3.0.0", &ck("v4"))
                .is_err()
        );
        // Marking with mismatched integrity errors
        assert!(
            store
                .mark_clean(Ecosystem::Npm, "pkg", "1.0.0", &ck("wrong"))
                .is_err()
        );
    }

    #[test]
    #[cfg(unix)]
    fn enforces_unix_file_and_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let db_dir = dir.path().join("secure_subdir");
        let db_path = db_dir.join("t.db");
        let _store = BaselineStore::open_at(&db_path).unwrap();

        let dir_meta = fs::metadata(&db_dir).unwrap();
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);

        let file_meta = fs::metadata(&db_path).unwrap();
        assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn advisory_cache_roundtrip_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();

        assert!(
            store
                .get_cached_advisories(Ecosystem::Npm, "pkg", "1.0.0")
                .unwrap()
                .is_none()
        );

        store
            .put_cached_advisories(
                Ecosystem::Npm,
                "pkg",
                "1.0.0",
                r#"{"vulns":[]}"#,
                0,
                false,
                3600,
            )
            .unwrap();

        let cached = store
            .get_cached_advisories(Ecosystem::Npm, "pkg", "1.0.0")
            .unwrap()
            .unwrap();
        assert_eq!(cached.advisories_json, r#"{"vulns":[]}"#);
        assert_eq!(cached.hit_count, 0);
        assert!(!cached.has_blocking);
        assert!(!cached.is_expired);

        // Test expired advisory cache entry
        store
            .put_cached_advisories(
                Ecosystem::Npm,
                "pkg",
                "2.0.0",
                r#"{"vulns":[]}"#,
                1,
                true,
                -10,
            )
            .unwrap();
        let expired = store
            .get_cached_advisories(Ecosystem::Npm, "pkg", "2.0.0")
            .unwrap()
            .unwrap();
        assert!(expired.is_expired);
        assert_eq!(expired.hit_count, 1);
        assert!(expired.has_blocking);

        // Test clearing cache
        let cleared = store.clear_advisory_cache().unwrap();
        assert_eq!(cleared, 2);
        assert!(
            store
                .get_cached_advisories(Ecosystem::Npm, "pkg", "1.0.0")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_cached_advisories(Ecosystem::Npm, "pkg", "2.0.0")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn provenance_cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();

        assert!(
            store
                .get_cached_provenance(Ecosystem::Npm, "pkg", "1.0.0")
                .unwrap()
                .is_none()
        );

        store
            .record_provenance(
                Ecosystem::Npm,
                "pkg",
                "1.0.0",
                Some("https://github.com/actions/runner"),
                Some("https://github.com/org/repo"),
                Some("abc123sha"),
                Some(".github/workflows/release.yml"),
                3,
                true,
            )
            .unwrap();

        let prov = store
            .get_cached_provenance(Ecosystem::Npm, "pkg", "1.0.0")
            .unwrap()
            .unwrap();
        assert_eq!(
            prov.builder_id.as_deref(),
            Some("https://github.com/actions/runner")
        );
        assert_eq!(
            prov.source_repo.as_deref(),
            Some("https://github.com/org/repo")
        );
        assert_eq!(prov.commit_sha.as_deref(), Some("abc123sha"));
        assert_eq!(
            prov.workflow_path.as_deref(),
            Some(".github/workflows/release.yml")
        );
        assert_eq!(prov.slsa_level, 3);
        assert!(prov.signature_valid);
    }

    #[test]
    fn audit_log_recording() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t.db");
        let store = BaselineStore::open_at(&db_path).unwrap();

        store
            .record_audit_log(
                Ecosystem::Npm,
                "pkg",
                "1.0.0",
                &ck("test").to_display(),
                "approve",
                15,
                "LOW",
                "ci-bot",
                Some("Reviewed zero dangerous deltas"),
            )
            .unwrap();

        // Verify direct row insertion in SQLite
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let (pkg, ver, integrity, action, score, verdict, decided_by, notes): (
            String,
            String,
            String,
            String,
            i64,
            String,
            String,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT package, version, integrity, action, score, verdict, decided_by, notes FROM audit_log WHERE package = 'pkg'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
            )
            .unwrap();

        assert_eq!(pkg, "pkg");
        assert_eq!(ver, "1.0.0");
        assert_eq!(integrity, ck("test").to_display());
        assert_eq!(action, "approve");
        assert_eq!(score, 15);
        assert_eq!(verdict, "LOW");
        assert_eq!(decided_by, "ci-bot");
        assert_eq!(notes.as_deref(), Some("Reviewed zero dangerous deltas"));
    }

    mod proptest_invariants {
        use super::*;
        use crate::registry::ChecksumAlg;
        use proptest::collection;
        use proptest::prelude::*;
        use sha2::{Digest, Sha512};
        use std::collections::BTreeMap;

        fn ck(tag: &str) -> Checksum {
            let mut hasher = Sha512::new();
            hasher.update(tag.as_bytes());
            Checksum {
                alg: ChecksumAlg::Sha512,
                value_hex: format!("{:x}", hasher.finalize()),
            }
        }

        // K distinct (name, version) keys plus a sequence of actions that
        // reference them. Each action re-verifies a key with either its true
        // integrity (must succeed, idempotent) or a different one (must fail
        // closed and never overwrite the stored record).
        #[allow(clippy::type_complexity)]
        fn keys_and_actions() -> impl Strategy<Value = (Vec<(String, String)>, Vec<(usize, bool)>)>
        {
            (1usize..=5).prop_flat_map(|k| {
                collection::btree_set("[a-z]{1,8}", k..=k)
                    .prop_map(|names| {
                        names
                            .into_iter()
                            .map(|n| (n, "1.0.0".to_string()))
                            .collect::<Vec<_>>()
                    })
                    .prop_flat_map(move |keys| {
                        let nk = keys.len();
                        collection::vec((0..nk, any::<bool>()), 1..=12)
                            .prop_map(move |acts| (keys.clone(), acts))
                    })
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                failure_persistence: None,
                cases: 64,
                ..ProptestConfig::default()
            })]
            #[test]
            fn verification_never_blesses_or_overwrites(
                (keys, actions) in keys_and_actions(),
            ) {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("t.db");
                let store = BaselineStore::open_at(&path).unwrap();

                // Per key index: a "true" integrity and a conflicting one.
                let good: Vec<Checksum> =
                    (0..keys.len()).map(|i| ck(&format!("good-{i}"))).collect();
                let bad: Vec<Checksum> =
                    (0..keys.len()).map(|i| ck(&format!("bad-{i}"))).collect();

                // key -> the integrity the store is currently expected to hold.
                let mut committed: BTreeMap<(String, String), Checksum> = BTreeMap::new();

                for (ki, use_bad) in actions {
                    let key = keys[ki].clone();
                    let checksum = if use_bad { bad[ki].clone() } else { good[ki].clone() };
                    let expected_ok = match committed.get(&key) {
                        None => true,
                        Some(v) => v == &checksum,
                    };
                    let result = store.record_verified(Ecosystem::Npm, &key.0, &key.1, &checksum);
                    if expected_ok {
                        prop_assert!(
                            result.is_ok(),
                            "expected success for {}@{} with {}",
                            key.0,
                            key.1,
                            checksum.to_display()
                        );
                        committed.insert(key, checksum);
                    } else {
                        prop_assert!(
                            result.is_err(),
                            "integrity conflict must fail closed for {}@{}",
                            key.0,
                            key.1
                        );
                    }
                }

                // Invariant after the whole sequence: every committed row is
                // exactly what we wrote, and nothing was ever blessed clean.
                let conn = rusqlite::Connection::open(&path).unwrap();
                for (key, checksum) in &committed {
                    let (stored, clean): (String, i64) = conn
                        .query_row(
                            "SELECT integrity, clean FROM known_clean
                             WHERE ecosystem = 'npm' AND name = ?1 AND version = ?2",
                            rusqlite::params![key.0, key.1],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .unwrap();
                    prop_assert_eq!(
                        stored,
                        checksum.to_display(),
                        "integrity must stay immutable for a given version"
                    );
                    prop_assert_eq!(clean, 0, "a review is evidence, never clean=1");
                }
            }
        }
    }
}
