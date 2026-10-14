//! Backups cut off partway, then resumed: the next run adopts what was uploaded
//! and skips what was finished.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use backup_core::archiver::{self, Options};
use backup_core::chunker::ChunkerConfig;
use backup_core::compress::Compression;
use backup_core::crypto::{Id, Keys};
use backup_core::repo::{InitOptions, Repository};
use backup_core::snapshot::Snapshot;
use backup_core::verify::{self, Options as VerifyOptions};
use backup_core::{Error, journal, restorer};
use mirror_core::store::ObjectStore;
use mirror_core::store::memory::MemoryStore;
use rand::{Rng, SeedableRng};
use secrecy::SecretBox;

const PREFIX: &str = "rfm/";
const BASE: &str = "rfm/backup/";
const FILES: u64 = 40;
const FILE_SIZE: usize = 40_000;

fn keys() -> Keys {
    Keys::derive(&SecretBox::new(Box::new([6; 32])))
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
    /// `None` runs without a local cache, so without a journal.
    cache: Option<tempfile::TempDir>,
}

impl Fixture {
    async fn new(with_cache: bool) -> Self {
        let f = Self {
            store: Arc::new(MemoryStore::new()),
            src: tempfile::tempdir().unwrap(),
            cache: with_cache.then(|| tempfile::tempdir().unwrap()),
        };
        let options = InitOptions {
            chunker: ChunkerConfig {
                min_size: 2048,
                avg_size: 8192,
                max_size: 32768,
            },
            compression: Compression::None,
        };
        Repository::init(Arc::clone(&f.store), PREFIX, keys(), options, f.cache_dir())
            .await
            .unwrap();
        for i in 0..FILES {
            fs::write(
                f.src.path().join(format!("f{i:02}")),
                random_bytes(FILE_SIZE, i),
            )
            .unwrap();
        }
        f
    }

    fn cache_dir(&self) -> Option<&std::path::Path> {
        self.cache.as_ref().map(|c| c.path())
    }

    /// A fresh handle each time, as each backup is a new process.
    async fn repo(&self) -> Arc<Repository<MemoryStore>> {
        let mut repo = Repository::open(Arc::clone(&self.store), PREFIX, keys(), self.cache_dir())
            .await
            .unwrap();
        repo.set_pack_target(64 * 1024);
        Arc::new(repo)
    }

    fn options(&self) -> Options {
        Options {
            concurrency: 1,
            ..Options::default()
        }
    }

    async fn backup(&self, options: Options) -> backup_core::Result<Snapshot> {
        archiver::backup(self.repo().await, &[self.src.path().to_path_buf()], options).await
    }

    /// Runs a backup that loses its connection after `after` files.
    async fn interrupted_backup(&self, after: u64) {
        let store = Arc::clone(&self.store);
        let tripped = Arc::new(AtomicBool::new(false));
        let options = Options {
            progress: Some(Arc::new(move |p: &archiver::Progress| {
                if p.files_processed >= after && !tripped.swap(true, Ordering::Relaxed) {
                    store.fail_puts_under(Some(&format!("{BASE}packs/")));
                }
            })),
            ..self.options()
        };
        let err = self.backup(options).await.unwrap_err();
        assert!(matches!(err, Error::RunFailed(_)), "{err}");
        self.store.fail_puts_under(None);
        assert_eq!(self.count("snapshots/").await, 0);
        assert_eq!(self.count("indexes/").await, 0);
    }

    async fn count(&self, dir: &str) -> usize {
        self.store
            .list(&format!("{BASE}{dir}"), None)
            .await
            .unwrap()
            .len()
    }

    async fn pack_ids(&self) -> Vec<Id> {
        let mut ids: Vec<Id> = self
            .store
            .list(&format!("{BASE}packs/"), None)
            .await
            .unwrap()
            .iter()
            .map(|m| m.key.rsplit('/').next().unwrap().parse().unwrap())
            .collect();
        ids.sort();
        ids
    }

    /// The snapshot is complete, consistent, and restores every file exactly.
    async fn assert_restores(&self, snapshot: &Snapshot) {
        let repo = self.repo().await;
        let report = verify::verify(
            &*repo,
            VerifyOptions {
                read_data: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(report.ok(), "{:?}", report.problems);
        assert!(
            report.orphan_packs.is_empty(),
            "adopted packs are indexed now"
        );

        let dst = tempfile::tempdir().unwrap();
        restorer::restore(repo, snapshot, dst.path(), Default::default())
            .await
            .unwrap();
        let inside = std::path::absolute(self.src.path()).unwrap();
        let restored = dst.path().join(inside.strip_prefix("/").unwrap());
        for entry in fs::read_dir(self.src.path()).unwrap() {
            let name = entry.unwrap().file_name();
            assert_eq!(
                fs::read(restored.join(&name)).unwrap(),
                fs::read(self.src.path().join(&name)).unwrap(),
                "{name:?}"
            );
        }
    }

    fn journal_path(&self) -> Option<PathBuf> {
        let cache = self.cache.as_ref()?;
        let repo_dir = fs::read_dir(cache.path()).unwrap().next()?.unwrap().path();
        let dir = repo_dir.join("journal");
        fs::read_dir(dir).ok()?.next().map(|e| e.unwrap().path())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_backup_adopts_uploads_and_skips_finished_files() {
    let f = Fixture::new(true).await;
    f.interrupted_backup(25).await;
    let left_behind = f.count("packs/").await;
    assert!(left_behind > 0);
    assert!(
        f.journal_path().is_some(),
        "the interrupted run kept a journal"
    );

    let snap = f.backup(f.options()).await.unwrap();
    let total = FILES * FILE_SIZE as u64;
    assert_eq!(snap.stats.packs_adopted, left_behind as u64);
    assert!(snap.stats.files_resumed >= 15, "{:?}", snap.stats);
    assert!(
        snap.stats.bytes_added < total * 6 / 10,
        "most of the interrupted run's uploads were reused: {:?}",
        snap.stats
    );
    assert_eq!(snap.stats.files_new + snap.stats.files_resumed, FILES);
    assert!(
        f.journal_path().is_none(),
        "removed once the snapshot is saved"
    );
    f.assert_restores(&snap).await;
}

/// Without a cache there's no journal, but uploads are still adopted.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_journal_uploads_are_still_reused() {
    let f = Fixture::new(false).await;
    f.interrupted_backup(25).await;
    let snap = f.backup(f.options()).await.unwrap();
    assert!(snap.stats.packs_adopted > 0);
    assert_eq!(snap.stats.files_resumed, 0, "every file is read again");
    assert!(
        snap.stats.bytes_added < FILES * FILE_SIZE as u64 * 6 / 10,
        "{:?}",
        snap.stats
    );
    f.assert_restores(&snap).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_changed_since_the_interruption_is_read_again() {
    let f = Fixture::new(true).await;
    f.interrupted_backup(25).await;
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(f.src.path().join("f00"), b"changed after the interruption").unwrap();

    let snap = f.backup(f.options()).await.unwrap();
    assert!(snap.stats.files_resumed > 0);
    f.assert_restores(&snap).await;
}

/// A journal entry whose chunks are gone (here, one of the uploaded packs was
/// lost) is dropped rather than trusted, and its file read again.
#[tokio::test(flavor = "multi_thread")]
async fn journal_entries_for_missing_chunks_are_ignored() {
    let f = Fixture::new(true).await;
    f.interrupted_backup(25).await;
    let lost = f.pack_ids().await[0];
    f.store
        .delete(&format!("{BASE}{}", backup_core::pack::object_name(&lost)))
        .await
        .unwrap();

    let snap = f.backup(f.options()).await.unwrap();
    assert!(
        snap.stats.files_new > FILES - 25,
        "files with lost chunks were read again: {:?}",
        snap.stats
    );
    f.assert_restores(&snap).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn resume_can_be_turned_off() {
    let f = Fixture::new(true).await;
    f.interrupted_backup(25).await;
    let snap = f
        .backup(Options {
            resume: false,
            ..f.options()
        })
        .await
        .unwrap();
    assert_eq!(snap.stats.files_resumed, 0);
    assert!(
        snap.stats.packs_adopted > 0,
        "adopting uploads is always safe"
    );
    f.assert_restores(&snap).await;
}

/// Something under packs/ that isn't a genuine pack of this repository is left
/// alone, and doesn't stop the backup.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_leftover_pack_is_skipped() {
    let f = Fixture::new(true).await;
    let bogus = Id::random();
    f.store
        .put_bytes(
            &format!("{BASE}{}", backup_core::pack::object_name(&bogus)),
            b"not a pack at all",
        )
        .await
        .unwrap();

    let snap = f.backup(f.options()).await.unwrap();
    assert_eq!(snap.stats.packs_adopted, 0);
    assert_eq!(snap.stats.files_new, FILES);
    let report = verify::verify(&*f.repo().await, VerifyOptions::default())
        .await
        .unwrap();
    assert!(report.ok());
    assert_eq!(
        report.orphan_packs,
        vec![bogus],
        "still there for prune to clean up"
    );
    let _ = journal::path_for;
}
