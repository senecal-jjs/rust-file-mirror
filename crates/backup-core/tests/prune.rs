//! Forgetting snapshots and reclaiming space, checked by verifying and restoring
//! what survives.

use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use backup_core::Error;
use backup_core::archiver::{self, Options as BackupOptions};
use backup_core::chunker::ChunkerConfig;
use backup_core::compress::Compression;
use backup_core::crypto::{Id, Keys};
use backup_core::lock::{Lock, STALE_AFTER};
use backup_core::pack::BlobType;
use backup_core::prune::{ORPHAN_GRACE, prune};
use backup_core::repo::{InitOptions, Repository};
use backup_core::restorer;
use backup_core::snapshot::Snapshot;
use backup_core::verify::{self, Options as VerifyOptions};
use mirror_core::store::ObjectStore;
use mirror_core::store::memory::MemoryStore;
use rand::{Rng, SeedableRng};
use secrecy::SecretBox;

const PREFIX: &str = "rfm/";
const BASE: &str = "rfm/backup/";

fn keys() -> Keys {
    Keys::derive(&SecretBox::new(Box::new([8; 32])))
}

fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    bytes
}

struct Fixture {
    store: Arc<MemoryStore>,
    src: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let store = Arc::new(MemoryStore::new());
        let options = InitOptions {
            chunker: ChunkerConfig {
                min_size: 2048,
                avg_size: 8192,
                max_size: 32768,
            },
            compression: Compression::Zstd,
        };
        Repository::init(Arc::clone(&store), PREFIX, keys(), options, None)
            .await
            .unwrap();
        Self {
            store,
            src: tempfile::tempdir().unwrap(),
        }
    }

    /// A fresh handle, as each command opens one.
    async fn repo(&self) -> Arc<Repository<MemoryStore>> {
        let mut repo = Repository::open(Arc::clone(&self.store), PREFIX, keys(), None)
            .await
            .unwrap();
        repo.set_pack_target(64 * 1024);
        Arc::new(repo)
    }

    fn write(&self, rel: &str, data: &[u8]) {
        fs::write(self.src.path().join(rel), data).unwrap();
    }

    async fn backup(&self) -> Snapshot {
        archiver::backup(
            self.repo().await,
            &[self.src.path().to_path_buf()],
            BackupOptions::default(),
        )
        .await
        .unwrap()
    }

    async fn count(&self, dir: &str) -> usize {
        self.store
            .list(&format!("{BASE}{dir}"), None)
            .await
            .unwrap()
            .len()
    }

    async fn assert_healthy(&self) -> verify::Report {
        let report = verify::verify(
            &*self.repo().await,
            VerifyOptions {
                read_data: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(report.ok(), "{:?}", report.problems);
        report
    }

    /// Restores `snapshot` and returns the restored copy of the source directory.
    async fn restore(&self, snapshot: &Snapshot) -> (tempfile::TempDir, std::path::PathBuf) {
        let dst = tempfile::tempdir().unwrap();
        restorer::restore(self.repo().await, snapshot, dst.path(), Default::default())
            .await
            .unwrap();
        let inside = std::path::absolute(self.src.path()).unwrap();
        let path = dst.path().join(inside.strip_prefix("/").unwrap());
        (dst, path)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn forgetting_a_snapshot_frees_what_only_it_used() {
    let f = Fixture::new().await;
    let shared = random_bytes(150_000, 1);
    let old = random_bytes(300_000, 2);
    let new = random_bytes(300_000, 3);
    f.write("shared", &shared);
    f.write("changing", &old);
    let first = f.backup().await;
    f.write("changing", &new);
    let second = f.backup().await;
    let packs_before = f.count("packs/").await;

    let report = prune(&*f.repo().await, &[first.id], false).await.unwrap();
    assert_eq!(report.snapshots_forgotten, 1);
    assert!(report.packs_deleted > 0, "{report:?}");
    // Both files were chunked at once, so their chunks share packs; repacking is
    // what frees the old version from those.
    assert!(report.packs_repacked > 0, "{report:?}");
    assert!(
        report.bytes_freed > 250_000,
        "most of the old version's 300 KB: {report:?}"
    );
    assert!(report.bytes_unused_in_kept_packs < 50_000, "{report:?}");
    assert!(f.count("packs/").await <= packs_before, "{report:?}");
    assert_eq!(f.count("snapshots/").await, 1);
    assert_eq!(f.count("indexes/").await, 1, "one consolidated index");
    assert_eq!(f.count("locks/").await, 0);

    let health = f.assert_healthy().await;
    assert!(health.orphan_packs.is_empty());
    let (_dst, restored) = f.restore(&second).await;
    assert_eq!(fs::read(restored.join("shared")).unwrap(), shared);
    assert_eq!(fs::read(restored.join("changing")).unwrap(), new);

    // And the next backup still deduplicates against what survived.
    let third = f.backup().await;
    assert_eq!(third.stats.bytes_added, 0);

    // A second prune with nothing to forget has nothing to do.
    let indexes = f.count("indexes/").await;
    let again = prune(&*f.repo().await, &[], false).await.unwrap();
    assert_eq!(
        (
            again.packs_deleted,
            again.packs_repacked,
            again.index_objects_replaced
        ),
        (0, 0, 0)
    );
    assert_eq!(f.count("indexes/").await, indexes);
}

#[tokio::test(flavor = "multi_thread")]
async fn dry_run_changes_nothing() {
    let f = Fixture::new().await;
    f.write("a", &random_bytes(200_000, 4));
    let first = f.backup().await;
    f.write("a", &random_bytes(200_000, 5));
    f.backup().await;
    let before = (
        f.count("packs/").await,
        f.count("snapshots/").await,
        f.count("indexes/").await,
    );

    let report = prune(&*f.repo().await, &[first.id], true).await.unwrap();
    assert!(report.dry_run && report.packs_deleted > 0);
    assert_eq!(
        (
            f.count("packs/").await,
            f.count("snapshots/").await,
            f.count("indexes/").await
        ),
        before
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn orphans_are_kept_for_a_while_then_cleaned_and_stale_locks_removed() {
    let f = Fixture::new().await;
    f.write("a", &random_bytes(100_000, 6));
    let only = f.backup().await;

    // An interrupted run: packs uploaded, never indexed.
    {
        let repo = f.repo().await;
        for i in 0..3 {
            repo.save_blob(BlobType::Data, &random_bytes(40_000, 100 + i))
                .await
                .unwrap();
        }
    }
    // A crashed process's lock, long expired.
    let abandoned = Lock::acquire(Arc::clone(&f.store), BASE, &keys(), false)
        .await
        .unwrap();
    let lock_key = f.store.list(&format!("{BASE}locks/"), None).await.unwrap()[0]
        .key
        .clone();
    drop(abandoned);
    f.store.set_modified_at(
        &lock_key,
        SystemTime::now() - STALE_AFTER - Duration::from_secs(60),
    );

    let orphans = f.assert_healthy().await.orphan_packs;
    assert!(!orphans.is_empty());

    // Recent orphans are kept for the next backup to adopt.
    let report = prune(&*f.repo().await, &[], false).await.unwrap();
    assert_eq!(
        (report.packs_deleted, report.orphans_kept),
        (0, orphans.len())
    );
    assert_eq!(report.stale_locks_removed, 1);
    assert_eq!(f.count("locks/").await, 0);
    assert_eq!(f.assert_healthy().await.orphan_packs, orphans);

    // Once past the grace period, they go.
    for id in &orphans {
        let key = format!("{BASE}{}", backup_core::pack::object_name(id));
        f.store.set_modified_at(
            &key,
            SystemTime::now() - ORPHAN_GRACE - Duration::from_secs(60),
        );
    }
    let report = prune(&*f.repo().await, &[], false).await.unwrap();
    assert_eq!(
        (report.packs_deleted, report.orphans_kept),
        (orphans.len(), 0)
    );
    assert!(f.assert_healthy().await.orphan_packs.is_empty());
    let (_dst, restored) = f.restore(&only).await;
    assert_eq!(
        fs::read(restored.join("a")).unwrap(),
        random_bytes(100_000, 6)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn prune_waits_for_a_running_backup() {
    let f = Fixture::new().await;
    f.write("a", b"a");
    let snap = f.backup().await;
    let running = Lock::acquire(Arc::clone(&f.store), BASE, &keys(), false)
        .await
        .unwrap();
    assert!(matches!(
        prune(&*f.repo().await, &[snap.id], false).await,
        Err(Error::Locked(_))
    ));
    assert_eq!(f.count("snapshots/").await, 1);
    running.release().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_snapshot_is_an_error() {
    let f = Fixture::new().await;
    f.write("a", b"a");
    f.backup().await;
    assert!(matches!(
        prune(&*f.repo().await, &[Id::random()], false).await,
        Err(Error::SnapshotNotFound(_))
    ));
    assert_eq!(f.count("locks/").await, 0);
}

/// Pruning a damaged repository could delete the wrong things; it refuses.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_repository_is_not_pruned() {
    let f = Fixture::new().await;
    f.write("a", &random_bytes(50_000, 7));
    f.backup().await;
    for object in f
        .store
        .list(&format!("{BASE}indexes/"), None)
        .await
        .unwrap()
    {
        f.store.delete(&object.key).await.unwrap();
    }
    let packs = f.count("packs/").await;
    assert!(matches!(
        prune(&*f.repo().await, &[], false).await,
        Err(Error::Incomplete(_))
    ));
    assert_eq!(f.count("packs/").await, packs, "nothing deleted");
}

/// The repository handle predates a backup that finished before the prune took its
/// lock: prune reads fresh state, so that backup's data is kept.
#[tokio::test(flavor = "multi_thread")]
async fn prune_uses_state_read_under_its_lock() {
    let f = Fixture::new().await;
    f.write("a", &random_bytes(80_000, 8));
    let first = f.backup().await;
    let stale_handle = f.repo().await;

    f.write("b", &random_bytes(80_000, 9));
    let second = f.backup().await;

    prune(&*stale_handle, &[first.id], false).await.unwrap();
    f.assert_healthy().await;
    let (_dst, restored) = f.restore(&second).await;
    assert_eq!(
        fs::read(restored.join("b")).unwrap(),
        random_bytes(80_000, 9)
    );
}
