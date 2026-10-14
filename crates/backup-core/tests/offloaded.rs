//! Mirror placeholders backed up as the files they stand for.

use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use backup_core::archiver::{self, Offloaded, OffloadedSource, Options};
use backup_core::chunker::ChunkerConfig;
use backup_core::compress::Compression;
use backup_core::crypto::Keys;
use backup_core::repo::{InitOptions, Repository};
use backup_core::restorer;
use backup_core::snapshot::Snapshot;
use backup_core::{Error, Result};
use mirror_core::hash::hash_bytes;
use mirror_core::placeholder::{self, StubMeta};
use mirror_core::store::memory::MemoryStore;
use rand::{Rng, SeedableRng};
use secrecy::SecretBox;

const PREFIX: &str = "rfm/";

/// Stands in for the mirror's bucket: object key → plaintext, counting opens.
#[derive(Default)]
struct FakeRemote {
    objects: Mutex<HashMap<String, Vec<u8>>>,
    opens: AtomicUsize,
}

impl FakeRemote {
    fn put(&self, key: &str, data: &[u8]) {
        self.objects
            .lock()
            .unwrap()
            .insert(key.into(), data.to_vec());
    }

    fn opens(&self) -> usize {
        self.opens.load(Ordering::Relaxed)
    }
}

impl OffloadedSource for FakeRemote {
    fn open(&self, stub: &StubMeta) -> Result<Box<dyn Read + Send>> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        let data = self.objects.lock().unwrap().get(&stub.object_key).cloned();
        match data {
            Some(data) => Ok(Box::new(Cursor::new(data))),
            None => Err(Error::Invalid(format!(
                "no remote object {}",
                stub.object_key
            ))),
        }
    }
}

struct Fixture {
    repo: Arc<Repository<MemoryStore>>,
    remote: Arc<FakeRemote>,
    root: tempfile::TempDir,
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
        let keys = Keys::derive(&SecretBox::new(Box::new([4; 32])));
        let repo = Repository::init(store, PREFIX, keys, options, None)
            .await
            .unwrap();
        Self {
            repo: Arc::new(repo),
            remote: Arc::new(FakeRemote::default()),
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    /// Offloads `rel` the way the mirror does: the content goes to the "bucket",
    /// a placeholder recording it (and its mode and mtime) replaces the file.
    fn offload(&self, rel: &str) -> StubMeta {
        let data = fs::read(self.path(rel)).unwrap();
        let meta = fs::metadata(self.path(rel)).unwrap();
        let key = format!("data/{rel}");
        self.remote.put(&key, &data);
        let mtime = meta
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let stub = StubMeta::new(rel, data.len() as u64, hash_bytes(&data), &key, 0)
            .with_mtime_ns(mtime.as_nanos() as i64)
            .with_mode(meta.mode());
        placeholder::write(self.root.path(), &stub).unwrap();
        fs::remove_file(self.path(rel)).unwrap();
        stub
    }

    /// A file that arrived from another device already offloaded: never local.
    fn arrive_offloaded(&self, rel: &str, data: &[u8]) -> StubMeta {
        let key = format!("data/{rel}");
        self.remote.put(&key, data);
        let stub = StubMeta::new(rel, data.len() as u64, hash_bytes(data), &key, 0);
        placeholder::write(self.root.path(), &stub).unwrap();
        stub
    }

    async fn backup(&self) -> Snapshot {
        let parent = self.repo.list_snapshots().await.unwrap().into_iter().next();
        let options = Options {
            parent,
            offloaded: Offloaded::Include(self.remote.clone()),
            ..Options::default()
        };
        archiver::backup(
            Arc::clone(&self.repo),
            &[self.root.path().to_path_buf()],
            options,
        )
        .await
        .unwrap()
    }

    /// Restores `snapshot`, returning the restored root.
    async fn restore(&self, snapshot: &Snapshot) -> (tempfile::TempDir, PathBuf) {
        let dst = tempfile::tempdir().unwrap();
        restorer::restore(
            Arc::clone(&self.repo),
            snapshot,
            dst.path(),
            Default::default(),
        )
        .await
        .unwrap();
        let inside = std::path::absolute(self.root.path()).unwrap();
        let root = dst.path().join(inside.strip_prefix("/").unwrap());
        (dst, root)
    }
}

fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    bytes
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// The common case: backed up while local, offloaded, backed up again. The
/// content is already in the repository, so nothing is downloaded.
#[tokio::test(flavor = "multi_thread")]
async fn content_backed_up_before_offloading_is_reused() {
    let f = Fixture::new().await;
    let data = random_bytes(200_000, 1);
    fs::write(f.path("photo.jpg"), &data).unwrap();
    fs::set_permissions(f.path("photo.jpg"), fs::Permissions::from_mode(0o600)).unwrap();
    let mtime = fs::metadata(f.path("photo.jpg"))
        .unwrap()
        .modified()
        .unwrap();
    f.backup().await;

    f.offload("photo.jpg");
    let snap = f.backup().await;
    assert_eq!(f.remote.opens(), 0, "nothing downloaded");
    assert_eq!(snap.stats.offloaded_reused, 1);
    assert_eq!(snap.stats.bytes_added, 0);

    let (_dst, restored) = f.restore(&snap).await;
    assert_eq!(fs::read(restored.join("photo.jpg")).unwrap(), data);
    assert!(
        !restored.join("photo.jpg.rfm").exists(),
        "stored under its real name"
    );
    assert_eq!(mode(&restored.join("photo.jpg")), 0o600);
    assert_eq!(
        fs::metadata(restored.join("photo.jpg"))
            .unwrap()
            .modified()
            .unwrap(),
        mtime
    );

    // And again: still nothing to download.
    let again = f.backup().await;
    assert_eq!((f.remote.opens(), again.stats.offloaded_reused), (0, 1));
}

/// Moved and then offloaded: matched by content, not path.
#[tokio::test(flavor = "multi_thread")]
async fn reuse_matches_by_content_across_renames() {
    let f = Fixture::new().await;
    let data = random_bytes(50_000, 2);
    fs::write(f.path("old-name.bin"), &data).unwrap();
    f.backup().await;
    fs::rename(f.path("old-name.bin"), f.path("new-name.bin")).unwrap();
    f.offload("new-name.bin");

    let snap = f.backup().await;
    assert_eq!((f.remote.opens(), snap.stats.offloaded_reused), (0, 1));
}

/// Never local on this device: fetched once, verified, then reused.
#[tokio::test(flavor = "multi_thread")]
async fn content_never_backed_up_is_fetched_once() {
    let f = Fixture::new().await;
    let data = random_bytes(300_000, 3);
    f.arrive_offloaded("from-elsewhere.mov", &data);
    fs::write(f.path("empty-arrival"), b"").unwrap();
    f.offload("empty-arrival");

    let snap = f.backup().await;
    assert_eq!(snap.stats.offloaded_downloaded, 2);
    assert_eq!(snap.stats.offloaded_bytes_downloaded, data.len() as u64);
    assert!(snap.stats.bytes_added > 250_000);

    let (_dst, restored) = f.restore(&snap).await;
    assert_eq!(fs::read(restored.join("from-elsewhere.mov")).unwrap(), data);
    assert_eq!(fs::read(restored.join("empty-arrival")).unwrap(), b"");
    // Nothing recorded the mode of a file that was never here.
    assert_eq!(mode(&restored.join("from-elsewhere.mov")), 0o644);

    let again = f.backup().await;
    assert_eq!(
        f.remote.opens(),
        2,
        "the second run reuses what the first fetched"
    );
    assert_eq!(again.stats.offloaded_reused, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn mismatched_or_missing_content_is_skipped_not_stored() {
    let f = Fixture::new().await;
    fs::write(f.path("fine.txt"), b"fine").unwrap();
    // The bucket holds something other than what the placeholder describes.
    let stub = f.arrive_offloaded("tampered.bin", b"the real thing");
    f.remote.put(&stub.object_key, b"something else!");
    // And a placeholder whose object is gone.
    let gone = f.arrive_offloaded("gone.bin", b"was here");
    f.remote.objects.lock().unwrap().remove(&gone.object_key);

    let snap = f.backup().await;
    assert_eq!(snap.stats.offloaded_skipped, 2);
    assert_eq!(snap.stats.offloaded_downloaded, 0);
    let (_dst, restored) = f.restore(&snap).await;
    assert!(restored.join("fine.txt").exists());
    assert!(!restored.join("tampered.bin").exists());
    assert!(!restored.join("gone.bin").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_placeholder_beside_its_real_file_defers_to_the_file() {
    let f = Fixture::new().await;
    f.arrive_offloaded("both.txt", b"remote version");
    fs::write(f.path("both.txt"), b"local version").unwrap();

    let snap = f.backup().await;
    assert_eq!(snap.stats.offloaded_skipped, 1);
    assert_eq!(f.remote.opens(), 0);
    let (_dst, restored) = f.restore(&snap).await;
    assert_eq!(
        fs::read(restored.join("both.txt")).unwrap(),
        b"local version"
    );
}

/// After hydration the file is local again, with a new inode and ctime: it's read
/// rather than trusted to match the offloaded record.
#[tokio::test(flavor = "multi_thread")]
async fn a_hydrated_file_is_read_again() {
    let f = Fixture::new().await;
    let data = random_bytes(40_000, 4);
    f.arrive_offloaded("doc.pdf", &data);
    f.backup().await;

    fs::remove_file(f.path("doc.pdf.rfm")).unwrap();
    fs::write(f.path("doc.pdf"), &data).unwrap();
    let snap = f.backup().await;
    assert_eq!(snap.stats.files_changed + snap.stats.files_new, 1);
    assert_eq!(snap.stats.files_unmodified, 0);
    assert_eq!(
        snap.stats.bytes_added, 0,
        "same content: chunks deduplicate"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn skip_and_as_files_modes() {
    let f = Fixture::new().await;
    let stub = f.arrive_offloaded("a.bin", b"remote content");

    let skipped = archiver::backup(
        Arc::clone(&f.repo),
        &[f.root.path().to_path_buf()],
        Options {
            offloaded: Offloaded::Skip,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(skipped.stats.offloaded_skipped, 1);

    let as_files = archiver::backup(
        Arc::clone(&f.repo),
        &[f.root.path().to_path_buf()],
        Options::default(),
    )
    .await
    .unwrap();
    let (_dst, restored) = f.restore(&as_files).await;
    let restored_stub = placeholder::read(&restored.join("a.bin.rfm")).unwrap();
    assert_eq!(
        restored_stub.hash, stub.hash,
        "outside a mirror, a placeholder is just a file"
    );
    assert_eq!(f.remote.opens(), 0);
}
