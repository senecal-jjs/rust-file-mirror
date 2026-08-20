use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

use crate::hash::ContentHash;
use crate::scanner::{HashCache, LocalEntry};
use crate::{Error, Result};

pub const STATE_DIR: &str = ".mirror";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub mtime_ns: i64,
    pub content_hash: ContentHash,
    pub last_synced_hash: Option<ContentHash>,
}

pub type Baseline = BTreeMap<String, FileRecord>;
pub type ManifestGeneration = u64;

impl HashCache for Baseline {
    fn cached(&self, path: &str, size: u64, mtime_ns: i64) -> Option<ContentHash> {
        let record = self.get(path)?;
        (record.size == size && record.mtime_ns == mtime_ns).then_some(record.content_hash)
    }
}

pub struct State {
    conn: Connection,
}

impl State {
    pub fn open(root: &Path) -> Result<Self> {
        let dir = root.join(STATE_DIR);

        std::fs::create_dir_all(&dir).map_err(|source| Error::Io {
            path: dir.clone(),
            source,
        })?;

        let conn = Connection::open(dir.join("state.db")).map_err(sql)?;

        // journal_mode returns a row, so pragma_update would error here
        conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))
            .map_err(sql)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(sql)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(sql)?;

        let state = Self { conn };
        state.migrate()?;
        Ok(state)
    }

    /// Sets latest file status after a confirmed upload or download
    pub fn confirm_sync(
        &mut self,
        path: &str,
        size: u64,
        mtime_ns: i64,
        content_hash: ContentHash,
    ) -> Result<()> {
        // INSERT ... ON CONFLICT UPDATE, same shape as record_scan's statement,
        // but also setting last_synced_hash = content_hash
        let tx = self.conn.transaction().map_err(sql)?;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO files (path, size, mtime_ns, content_hash, updated_at, last_synced_hash)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(path) DO UPDATE SET
                         size         = excluded.size,
                         mtime_ns     = excluded.mtime_ns,
                         content_hash = excluded.content_hash,
                         updated_at   = excluded.updated_at,
                         last_synced_hash = excluded.last_synced_hash"
                )
                .map_err(sql)?;

            let now = now_unix();

            stmt.execute(params![
                path,
                i64::try_from(size).unwrap_or(i64::MAX),
                mtime_ns,
                content_hash.to_string(),
                now,
                content_hash.to_string(),
            ])
            .map_err(sql)?;
        }

        tx.commit().map_err(sql)?;
        Ok(())
    }

    /// Clears a file's baseline row once both sides agree it's gone — the reconcile
    /// engine treats absence from the baseline as "never existed here".
    pub fn remove(&mut self, path: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM files WHERE path = ?1", params![path])
            .map_err(sql)?;

        Ok(())
    }

    /// The highest manifest generation this device has ever seen — 0 if none yet
    /// (a fresh device, or a vault whose manifest has never been written).
    pub fn highest_manifest_generation(&self) -> Result<ManifestGeneration> {
        let raw: Option<i64> = self
            .conn
            .query_row(
                "SELECT gen FROM manifest_generation WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;

        Ok(raw
            .map(|value| ManifestGeneration::try_from(value).unwrap_or(0))
            .unwrap_or(0))
    }

    /// Records the highest manifest generation this device has confirmed — either
    /// one it just wrote, or one it read and accepted from another device. Callers
    /// are responsible for never calling this with a value lower than what's already
    /// recorded; that check is the actual rollback protection, not this setter.
    pub fn record_manifest_generation(&mut self, generation: ManifestGeneration) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO manifest_generation (id, gen) VALUES (0, ?1)
                 ON CONFLICT(id) DO UPDATE SET gen = excluded.gen",
                params![i64::try_from(generation).unwrap_or(i64::MAX)],
            )
            .map_err(sql)?;

        Ok(())
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sql)?;

        if version < 1 {
            self.conn
                .execute_batch(
                    "BEGIN;
                     CREATE TABLE files (
                         path             TEXT PRIMARY KEY,
                         size             INTEGER NOT NULL,
                         mtime_ns         INTEGER NOT NULL,
                         content_hash     TEXT NOT NULL,
                         last_synced_hash TEXT,
                         updated_at       INTEGER NOT NULL
                     );
                     CREATE TABLE manifest_generation (
                         id  INTEGER PRIMARY KEY CHECK (id = 0),
                         gen INTEGER NOT NULL
                     );
                     PRAGMA user_version = 1;
                     COMMIT;",
                )
                .map_err(sql)?;
        }

        Ok(())
    }

    pub fn baseline(&self) -> Result<Baseline> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, size, mtime_ns, content_hash, last_synced_hash FROM files")
            .map_err(sql)?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(sql)?;

        let mut baseline = Baseline::new();

        for row in rows {
            let (path, size, mtime_ns, content_hash, last_synced) = row.map_err(sql)?;

            let record = FileRecord {
                path: path.clone(),
                size: u64::try_from(size).unwrap_or_default(),
                mtime_ns,
                content_hash: ContentHash::from_hex(&content_hash)?,
                last_synced_hash: last_synced
                    .map(|hex| ContentHash::from_hex(&hex))
                    .transpose()?,
            };

            baseline.insert(path, record);
        }

        Ok(baseline)
    }

    /// Records observed files. Deliberately leaves `last_synced_hash` untouched — only a
    /// confirmed transfer may advance it.
    pub fn record_scan(&mut self, entries: &[LocalEntry]) -> Result<()> {
        let tx = self.conn.transaction().map_err(sql)?;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO files (path, size, mtime_ns, content_hash, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(path) DO UPDATE SET
                         size         = excluded.size,
                         mtime_ns     = excluded.mtime_ns,
                         content_hash = excluded.content_hash,
                         updated_at   = excluded.updated_at",
                )
                .map_err(sql)?;

            let now = now_unix();

            for entry in entries {
                stmt.execute(params![
                    entry.path,
                    i64::try_from(entry.size).unwrap_or(i64::MAX),
                    entry.mtime_ns,
                    entry.hash.to_string(),
                    now,
                ])
                .map_err(sql)?;
            }
        }

        tx.commit().map_err(sql)?;
        Ok(())
    }
}

fn sql(e: rusqlite::Error) -> Error {
    Error::State(e.to_string())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_generation_defaults_to_zero_then_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();

        assert_eq!(state.highest_manifest_generation().unwrap(), 0);

        state.record_manifest_generation(5).unwrap();
        assert_eq!(state.highest_manifest_generation().unwrap(), 5);

        // A later write overwrites, it doesn't accumulate a second row.
        state.record_manifest_generation(6).unwrap();
        assert_eq!(state.highest_manifest_generation().unwrap(), 6);
    }

    fn hash(byte: u8) -> ContentHash {
        ContentHash::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn entry(path: &str, size: u64, mtime_ns: i64, h: ContentHash) -> LocalEntry {
        LocalEntry {
            path: path.to_string(),
            size,
            mtime_ns,
            hash: h,
        }
    }

    #[test]
    fn remove_clears_the_baseline_row() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();

        state
            .record_scan(&[entry("a.txt", 3, 42, hash(0xab))])
            .unwrap();
        state.remove("a.txt").unwrap();

        assert!(!state.baseline().unwrap().contains_key("a.txt"));
    }

    #[test]
    fn round_trips_records() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();

        state
            .record_scan(&[entry("a.txt", 3, 42, hash(0xab))])
            .unwrap();

        let baseline = state.baseline().unwrap();
        let record = &baseline["a.txt"];

        assert_eq!(record.size, 3);
        assert_eq!(record.mtime_ns, 42);
        assert_eq!(record.content_hash, hash(0xab));
        assert_eq!(record.last_synced_hash, None);
    }

    #[test]
    fn cache_hits_only_when_size_and_mtime_match() {
        let mut baseline = Baseline::new();
        baseline.insert(
            "a.txt".to_string(),
            FileRecord {
                path: "a.txt".to_string(),
                size: 3,
                mtime_ns: 42,
                content_hash: hash(0xab),
                last_synced_hash: None,
            },
        );

        assert_eq!(baseline.cached("a.txt", 3, 42), Some(hash(0xab)));
        assert_eq!(baseline.cached("a.txt", 4, 42), None);
        assert_eq!(baseline.cached("a.txt", 3, 43), None);
        assert_eq!(baseline.cached("missing", 3, 42), None);
    }
}
