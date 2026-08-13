use std::fs;
use std::path::Path;

use rusqlite_migration::{M, Migrations};

use crate::error::BluelineError;

const MIGRATIONS: &[&str] = &["
CREATE TABLE known_clean (
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    integrity   TEXT NOT NULL,
    reviewed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (name, version)
) STRICT;
"];

/// SQLite store for the "known-clean" baseline. Schema grows when Phase 2
/// (overrides, policy) lands — nothing is persisted here that isn't read.
pub struct BaselineStore {
    conn: rusqlite::Connection,
}

impl BaselineStore {
    pub fn open() -> Result<Self, BluelineError> {
        Self::open_at(&default_db_path()?)
    }

    pub fn open_at(path: &Path) -> Result<Self, BluelineError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| BluelineError::Store(format!("creating {}: {e}", parent.display())))?;
        }
        let mut conn = rusqlite::Connection::open(path)
            .map_err(|e| BluelineError::Store(format!("opening {}: {e}", path.display())))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| BluelineError::Store(format!("enabling WAL: {e}")))?;

        let migrations = Migrations::new(MIGRATIONS.iter().map(|sql| M::up(sql)).collect());
        migrations
            .to_latest(&mut conn)
            .map_err(|e| BluelineError::Store(format!("applying migrations: {e}")))?;

        Ok(Self { conn })
    }

    pub fn record_known_clean(
        &self,
        name: &str,
        version: &str,
        integrity: &str,
    ) -> Result<(), BluelineError> {
        self.conn
            .prepare_cached(
                "INSERT INTO known_clean (name, version, integrity) VALUES (?1, ?2, ?3)
                 ON CONFLICT(name, version) DO UPDATE SET
                     integrity = excluded.integrity,
                     reviewed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            )
            .map_err(|e| BluelineError::Store(format!("preparing upsert: {e}")))?
            .execute(rusqlite::params![name, version, integrity])
            .map_err(|e| BluelineError::Store(format!("recording {name}@{version}: {e}")))?;
        Ok(())
    }

    #[cfg(test)]
    pub fn known_clean(&self, name: &str, version: &str) -> Result<Option<String>, BluelineError> {
        use rusqlite::OptionalExtension;
        let mut stmt = self
            .conn
            .prepare_cached("SELECT integrity FROM known_clean WHERE name = ?1 AND version = ?2")
            .map_err(|e| BluelineError::Store(format!("preparing select: {e}")))?;
        stmt.query_row(rusqlite::params![name, version], |row| row.get(0))
            .optional()
            .map_err(|e| BluelineError::Store(format!("reading {name}@{version}: {e}")))
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

    #[test]
    fn records_and_reads_known_clean() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_known_clean("express", "4.21.2", "sha512-abc")
            .unwrap();
        assert_eq!(
            store.known_clean("express", "4.21.2").unwrap().as_deref(),
            Some("sha512-abc")
        );
        assert_eq!(store.known_clean("express", "4.21.1").unwrap(), None);
    }

    #[test]
    fn upsert_refreshes_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_known_clean("pkg", "1.0.0", "sha512-one")
            .unwrap();
        store
            .record_known_clean("pkg", "1.0.0", "sha512-two")
            .unwrap();
        assert_eq!(
            store.known_clean("pkg", "1.0.0").unwrap().as_deref(),
            Some("sha512-two")
        );
        let count: i64 = {
            let conn = rusqlite::Connection::open(dir.path().join("t.db")).unwrap();
            conn.query_row("SELECT COUNT(*) FROM known_clean", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count, 1);
    }

    #[test]
    fn migration_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        BaselineStore::open_at(&path).unwrap();
        BaselineStore::open_at(&path).unwrap();
    }
}
