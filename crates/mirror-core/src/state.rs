use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gethostname::gethostname;
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedUploadPart {
    pub part_number: i32,
    pub etag: String,
    pub checksum_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingUpload {
    pub path: PathBuf,
    pub upload_id: String,
    pub part_size: usize,
    /// The local file's content hash when this upload started — compare against
    /// the current local hash to decide whether to resume or abort-and-restart.
    pub content_hash: ContentHash,
    pub nonce: Vec<u8>,
    /// Ordered by part_number — whatever's already confirmed by S3, so a resume
    /// knows which parts it can skip re-uploading.
    pub completed_parts: Vec<CompletedUploadPart>,
}

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
        // Off by default per connection — needed so deleting an `uploads` row cascades
        // to its `upload_parts` rows instead of leaving them orphaned.
        conn.pragma_update(None, "foreign_keys", "ON")
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

    /// Records that a multipart upload has begun for `path`, so an interrupted sync
    /// can resume it later instead of restarting the whole file. Overwrites any
    /// prior row for the same path — callers are responsible for having already
    /// resolved (resumed or aborted) whatever upload that row was tracking.
    pub fn record_upload_start(
        &mut self,
        path: &str,
        upload_id: &str,
        part_size: usize,
        content_hash: ContentHash,
        nonce: &[u8],
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO uploads (path, upload_id, part_size, content_hash, nonce, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(path) DO UPDATE SET
                     upload_id    = excluded.upload_id,
                     part_size    = excluded.part_size,
                     content_hash = excluded.content_hash,
                     nonce        = excluded.nonce,
                     created_at   = excluded.created_at",
                params![
                    path,
                    upload_id,
                    i64::try_from(part_size).unwrap_or(i64::MAX),
                    content_hash.to_string(),
                    nonce,
                    now_unix(),
                ],
            )
            .map_err(sql)?;

        Ok(())
    }

    /// Records one confirmed part of an in-progress multipart upload, so a
    /// resumed upload knows which parts it can skip re-uploading.
    pub fn record_upload_part(
        &mut self,
        path: &str,
        part_number: i32,
        etag: &str,
        checksum_sha256: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO upload_parts (path, part_number, etag, checksum_sha256)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(path, part_number) DO UPDATE SET
                     etag            = excluded.etag,
                     checksum_sha256 = excluded.checksum_sha256",
                params![path, part_number, etag, checksum_sha256],
            )
            .map_err(sql)?;

        Ok(())
    }

    /// Clears all tracking for `path`'s multipart upload — call once it's completed
    /// or aborted, since neither case needs to be resumed anymore. `upload_parts`
    /// rows are removed automatically via `ON DELETE CASCADE` now that `open` turns
    /// foreign key enforcement on for the connection.
    pub fn clear_upload(&mut self, path: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM uploads WHERE path = ?1", params![path])
            .map_err(sql)?;

        Ok(())
    }

    /// Every multipart upload still tracked — left behind by a sync that got
    /// interrupted before it could call `clear_upload`. Doesn't judge whether any
    /// of them are actually resumable (that needs the current local file's hash,
    /// which this has no access to) — callers compare `content_hash` against a
    /// fresh scan themselves and decide resume vs. abort-and-restart per upload.
    pub fn pending_uploads(&self) -> Result<Vec<PendingUpload>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, upload_id, part_size, content_hash, nonce FROM uploads")
            .map_err(sql)?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })
            .map_err(sql)?;

        let mut uploads = Vec::new();

        for row in rows {
            let (path, upload_id, part_size, content_hash, nonce) = row.map_err(sql)?;
            let completed_parts = self.completed_upload_parts(&path)?;

            uploads.push(PendingUpload {
                path: PathBuf::from(path),
                upload_id,
                part_size: usize::try_from(part_size).unwrap_or_default(),
                content_hash: ContentHash::from_hex(&content_hash)?,
                nonce,
                completed_parts,
            });
        }

        Ok(uploads)
    }

    fn completed_upload_parts(&self, path: &str) -> Result<Vec<CompletedUploadPart>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT part_number, etag, checksum_sha256 FROM upload_parts
                 WHERE path = ?1 ORDER BY part_number",
            )
            .map_err(sql)?;

        let rows = stmt
            .query_map(params![path], |row| {
                Ok(CompletedUploadPart {
                    part_number: row.get(0)?,
                    etag: row.get(1)?,
                    checksum_sha256: row.get(2)?,
                })
            })
            .map_err(sql)?;

        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(sql)
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

    pub fn record_lamport(&mut self, clock: u64) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO device_lamport (id, lamport_clock) VALUES (0, ?1)
                    ON CONFLICT(id) DO UPDATE SET lamport_clock = excluded.lamport_clock",
                params![i64::try_from(clock).unwrap_or(i64::MAX)],
            )
            .map_err(sql)?;

        Ok(())
    }

    pub fn get_latest_lamport(&self) -> Result<u64> {
        let raw: Option<i64> = self
            .conn
            .query_row(
                "SELECT lamport_clock FROM device_lamport WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;

        let lamport = raw.ok_or(Error::State("failed to fetch lamport clock".to_string()))?;

        Ok(u64::try_from(lamport).unwrap_or(0))
    }

    pub fn device_name(&self) -> Result<String> {
        let raw = self
            .conn
            .query_row(
                "SELECT device_name FROM device_lamport WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;

        let name = raw.ok_or(Error::State("failed to fetch device name".to_string()))?;

        Ok(name)
    }

    pub fn device_id(&self) -> Result<String> {
        let name = self
            .conn
            .query_row(
                "SELECT device_id FROM device_lamport WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .map_err(sql)?;

        Ok(name)
    }

    pub fn latest_delta_cursor(&self, root: &str) -> Result<Option<String>> {
        let cursor = self
            .conn
            .query_row(
                "SELECT cursor FROM delta_cursors WHERE root = ?1",
                [root],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;

        Ok(cursor)
    }

    pub fn set_delta_cursor(&mut self, root: &str, cursor: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO delta_cursors (root, cursor) VALUES (?1, ?2)
                    ON CONFLICT(root) DO UPDATE SET cursor = excluded.cursor",
                params![root, cursor],
            )
            .map_err(sql)?;
        
        Ok(())
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sql)?;

        // Register a custom SQL function named "generate_uuid"
        self.conn
            .create_scalar_function(
                "generate_uuid",
                0,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                |_ctx| Ok(Uuid::new_v4().to_string()),
            )
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

        if version < 2 {
            self.conn
                .execute_batch(
                    "BEGIN;
                     CREATE TABLE uploads (
                         path         TEXT PRIMARY KEY,
                         upload_id    TEXT NOT NULL,
                         part_size    INTEGER NOT NULL,
                         -- The file's content hash when this upload started — compared
                         -- against the current local hash on resume to detect whether the
                         -- file changed underneath the interrupted upload.
                         content_hash TEXT NOT NULL,
                         -- StreamingEncryptor's 19-byte STREAM nonce. Resuming has to reuse
                         -- this exact nonce, not a fresh one — parts already uploaded were
                         -- encrypted under it, and STREAM ties every frame in a sequence to
                         -- one shared nonce.
                         nonce        BLOB NOT NULL,
                         created_at   INTEGER NOT NULL
                     );
                     -- One row per part already confirmed by S3. path+part_number is only
                     -- unique within a single upload, not globally, hence the composite key.
                     -- ON DELETE CASCADE only takes effect if the connection has run
                     -- `PRAGMA foreign_keys = ON` — sqlite leaves it off by default.
                     CREATE TABLE upload_parts (
                         path            TEXT NOT NULL REFERENCES uploads(path) ON DELETE CASCADE,
                         part_number     INTEGER NOT NULL,
                         etag            TEXT NOT NULL,
                         checksum_sha256 TEXT NOT NULL,
                         PRIMARY KEY (path, part_number)
                     );
                     PRAGMA user_version = 2;
                     COMMIT;",
                )
                .map_err(sql)?;
        }

        if version < 3 {
            let hostname_os: String = gethostname()
                .into_string()
                .unwrap_or(uuid::Uuid::new_v4().to_string());

            let device_id = uuid::Uuid::new_v4().to_string();

            self.conn
                .execute_batch(
                    "BEGIN;
                    CREATE TABLE device_lamport (
                        id INTEGER PRIMARY KEY CHECK (id = 0),
                        device_id TEXT NOT NULL DEFAULT (generate_uuid()),
                        device_name TEXT,
                        lamport_clock INTEGER NOT NULL DEFAULT 0    
                    );
                    CREATE TABLE delta_cursors (
                        root TEXT PRIMARY KEY,
                        cursor TEXT NOT NULL
                    );
                    PRAGMA user_version = 3;
                    COMMIT;",
                )
                .map_err(sql)?;

            self.conn
                .execute(
                    "INSERT INTO device_lamport (id, device_id, device_name, lamport_clock) VALUES (0, ?1, ?2, 0)",
                    params![device_id, hostname_os],
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
    fn set_and_get_delta_cursor() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();
        let root = "rfm/";

        assert_eq!(state.latest_delta_cursor(root).unwrap().is_none(), true);

        state.set_delta_cursor(root, "rfm/delta001.delta").unwrap();
        
        let cursor = state.latest_delta_cursor(root).unwrap().unwrap();

        assert_eq!(cursor, "rfm/delta001.delta");
    }

    #[test]
    fn get_device_name_id_lamport() {
        let tmp = tempfile::tempdir().unwrap();
        let state = State::open(tmp.path()).unwrap();

        state.device_name().unwrap();

        assert!(!state.device_id().unwrap().trim().is_empty());
        assert_eq!(state.get_latest_lamport().unwrap(), 0);
    }

    #[test]
    fn record_lamport() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();

        assert!(!state.device_id().unwrap().trim().is_empty());
        state.record_lamport(2).unwrap();
        assert_eq!(state.get_latest_lamport().unwrap(), 2);
    }

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

    #[test]
    fn pending_uploads_round_trips_with_their_completed_parts() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();

        state
            .record_upload_start("a.txt", "upload-1", 8 * 1024 * 1024, hash(0xab), &[7u8; 19])
            .unwrap();
        state
            .record_upload_part("a.txt", 2, "etag-2", "checksum-2")
            .unwrap();
        state
            .record_upload_part("a.txt", 1, "etag-1", "checksum-1")
            .unwrap();

        // A second, unrelated in-progress upload, to prove parts don't bleed
        // across paths.
        state
            .record_upload_start("b.txt", "upload-2", 5 * 1024 * 1024, hash(0xcd), &[9u8; 19])
            .unwrap();

        let mut pending = state.pending_uploads().unwrap();
        pending.sort_by(|a, b| a.path.cmp(&b.path));

        assert_eq!(pending.len(), 2);

        let a = &pending[0];
        assert_eq!(a.path.to_str().unwrap(), "a.txt");
        assert_eq!(a.upload_id, "upload-1");
        assert_eq!(a.part_size, 8 * 1024 * 1024);
        assert_eq!(a.content_hash, hash(0xab));
        assert_eq!(a.nonce, vec![7u8; 19]);
        // Recorded out of order above — pending_uploads must still return them
        // sorted by part_number, since resume logic depends on that ordering.
        assert_eq!(
            a.completed_parts,
            vec![
                CompletedUploadPart {
                    part_number: 1,
                    etag: "etag-1".to_string(),
                    checksum_sha256: "checksum-1".to_string(),
                },
                CompletedUploadPart {
                    part_number: 2,
                    etag: "etag-2".to_string(),
                    checksum_sha256: "checksum-2".to_string(),
                },
            ]
        );

        let b = &pending[1];
        assert_eq!(b.path.to_str().unwrap(), "b.txt");
        assert!(b.completed_parts.is_empty());

        // clear_upload removes the row and, via ON DELETE CASCADE, its parts too.
        state.clear_upload("a.txt").unwrap();
        let pending = state.pending_uploads().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].path.to_str().unwrap(), "b.txt");
    }
}
