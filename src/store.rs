use std::fs;
use std::path::Path;

use rusqlite_migration::{M, Migrations};

use crate::error::BluelineError;

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
];

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

    /// Record that `name@version` was integrity-verified. This is evidence,
    /// not a judgment: `clean` stays 0. Re-recording the identical integrity
    /// is idempotent and refreshes the timestamp; re-recording a DIFFERENT
    /// integrity for the same version fails closed, because a republished
    /// tarball under the same version string must not silently overwrite what
    /// was witnessed before.
    pub fn record_verified(
        &self,
        name: &str,
        version: &str,
        integrity: &str,
    ) -> Result<(), BluelineError> {
        let affected = self
            .conn
            .prepare_cached(
                "INSERT INTO known_clean (name, version, integrity) VALUES (?1, ?2, ?3)
                 ON CONFLICT(name, version) DO UPDATE SET
                     integrity = excluded.integrity,
                     reviewed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                 WHERE known_clean.integrity = excluded.integrity",
            )
            .map_err(|e| BluelineError::Store(format!("preparing upsert: {e}")))?
            .execute(rusqlite::params![name, version, integrity])
            .map_err(|e| BluelineError::Store(format!("recording {name}@{version}: {e}")))?;
        if affected == 0 {
            return Err(BluelineError::Store(format!(
                "integrity changed for {name}@{version}: the stored record no longer matches this \
                 tarball; refusing to overwrite it"
            )));
        }
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
    fn records_verified_witness_as_unclean() {
        let dir = tempfile::tempdir().unwrap();
        let store = BaselineStore::open_at(&dir.path().join("t.db")).unwrap();
        store
            .record_verified("express", "4.21.2", "sha512-abc")
            .unwrap();
        assert_eq!(
            store.known_clean("express", "4.21.2").unwrap().as_deref(),
            Some("sha512-abc")
        );
        assert_eq!(store.known_clean("express", "4.21.1").unwrap(), None);
        let unclean: i64 = {
            let conn = rusqlite::Connection::open(dir.path().join("t.db")).unwrap();
            conn.query_row(
                "SELECT COUNT(*) FROM known_clean
                 WHERE name = 'express' AND version = '4.21.2' AND clean = 0",
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
        store.record_verified("pkg", "1.0.0", "sha512-one").unwrap();
        store.record_verified("pkg", "1.0.0", "sha512-one").unwrap();
        assert_eq!(
            store.known_clean("pkg", "1.0.0").unwrap().as_deref(),
            Some("sha512-one")
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
        store.record_verified("pkg", "1.0.0", "sha512-one").unwrap();
        let err = store
            .record_verified("pkg", "1.0.0", "sha512-two")
            .unwrap_err();
        assert!(err.to_string().contains("integrity changed"));
        assert_eq!(
            store.known_clean("pkg", "1.0.0").unwrap().as_deref(),
            Some("sha512-one"),
            "the stored record must survive a rejected rewrite"
        );
    }

    #[test]
    fn migration_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        BaselineStore::open_at(&path).unwrap();
        BaselineStore::open_at(&path).unwrap();
    }

    mod proptest_invariants {
        use super::*;
        use proptest::collection;
        use proptest::prelude::*;
        use std::collections::BTreeMap;

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
                let good: Vec<String> =
                    (0..keys.len()).map(|i| format!("sha512-good-{i}")).collect();
                let bad: Vec<String> =
                    (0..keys.len()).map(|i| format!("sha512-bad-{i}")).collect();

                // key -> the integrity the store is currently expected to hold.
                let mut committed: BTreeMap<(String, String), String> = BTreeMap::new();

                for (ki, use_bad) in actions {
                    let key = keys[ki].clone();
                    let integrity = if use_bad { bad[ki].clone() } else { good[ki].clone() };
                    let expected_ok = match committed.get(&key) {
                        None => true,
                        Some(v) => v == &integrity,
                    };
                    let result = store.record_verified(&key.0, &key.1, &integrity);
                    if expected_ok {
                        prop_assert!(
                            result.is_ok(),
                            "expected success for {}@{} with {integrity}",
                            key.0,
                            key.1
                        );
                        committed.insert(key, integrity);
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
                for (key, integrity) in &committed {
                    let (stored, clean): (String, i64) = conn
                        .query_row(
                            "SELECT integrity, clean FROM known_clean
                             WHERE name = ?1 AND version = ?2",
                            rusqlite::params![key.0, key.1],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .unwrap();
                    prop_assert_eq!(
                        &stored, integrity,
                        "integrity must stay immutable for a given version"
                    );
                    prop_assert_eq!(clean, 0, "a review is evidence, never clean=1");
                }
            }
        }
    }
}
