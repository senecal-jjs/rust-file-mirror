//! Backup → restore round trips, plus the ways a restore must refuse to write
//! outside its target or clobber what's there.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use backup_core::archiver::{self, Options as BackupOptions};
use backup_core::chunker::ChunkerConfig;
use backup_core::compress::Compression;
use backup_core::crypto::{Id, Keys};
use backup_core::pack::BlobType;
use backup_core::repo::{InitOptions, Repository};
use backup_core::restorer::{self, Options};
use backup_core::snapshot::Snapshot;
use backup_core::{Error, Result};
use mirror_core::store::memory::MemoryStore;
use rand::{Rng, SeedableRng};
use secrecy::SecretBox;

const PREFIX: &str = "rfm/";

struct Fixture {
    store: Arc<MemoryStore>,
    repo: Arc<Repository<MemoryStore>>,
    src: tempfile::TempDir,
    dst: tempfile::TempDir,
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
        let keys = Keys::derive(&SecretBox::new(Box::new([3; 32])));
        let mut repo = Repository::init(Arc::clone(&store), PREFIX, keys, options)
            .await
            .unwrap();
        repo.set_pack_target(128 * 1024);
        Self {
            store,
            repo: Arc::new(repo),
            src: tempfile::tempdir().unwrap(),
            dst: tempfile::tempdir().unwrap(),
        }
    }

    fn write(&self, rel: &str, contents: &[u8]) -> PathBuf {
        let path = self.src.path().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }

    async fn backup(&self) -> Snapshot {
        archiver::backup(
            Arc::clone(&self.repo),
            &[self.src.path().to_path_buf()],
            BackupOptions::default(),
        )
        .await
        .unwrap()
    }

    async fn restore(&self, snapshot: &Snapshot, options: Options) -> Result<restorer::Stats> {
        restorer::restore(Arc::clone(&self.repo), snapshot, self.dst.path(), options).await
    }

    /// Where the backed-up source lands inside the restore target.
    fn restored(&self, rel: &str) -> PathBuf {
        let src = std::path::absolute(self.src.path()).unwrap();
        let inside = src.strip_prefix("/").unwrap();
        if rel.is_empty() {
            self.dst.path().join(inside)
        } else {
            self.dst.path().join(inside).join(rel)
        }
    }

    /// The restore-target path of the source root's parent, for building hostile
    /// layouts in the target before restoring.
    fn restored_root(&self) -> PathBuf {
        self.restored("")
    }
}

fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    bytes
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn mtime(path: &Path) -> std::time::SystemTime {
    fs::symlink_metadata(path).unwrap().modified().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn round_trip_restores_content_and_metadata() {
    let f = Fixture::new().await;
    let big = random_bytes(500_000, 1);
    let shared = random_bytes(40_000, 2);
    f.write("a.txt", b"hello");
    f.write("empty", b"");
    f.write("dir/big.bin", &big);
    f.write("dir/copy1", &shared);
    f.write("other/copy2", &shared);
    fs::create_dir_all(f.src.path().join("empty-dir/nested")).unwrap();
    symlink("../a.txt", f.src.path().join("dir/link")).unwrap();
    fs::set_permissions(
        f.src.path().join("a.txt"),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    fs::set_permissions(f.src.path().join("dir"), fs::Permissions::from_mode(0o750)).unwrap();
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::File::options()
        .write(true)
        .open(f.src.path().join("a.txt"))
        .unwrap()
        .set_modified(old)
        .unwrap();
    fs::File::open(f.src.path().join("dir"))
        .unwrap()
        .set_modified(old)
        .unwrap();

    let snap = f.backup().await;
    let stats = f.restore(&snap, Options::default()).await.unwrap();

    assert_eq!(fs::read(f.restored("a.txt")).unwrap(), b"hello");
    assert_eq!(fs::read(f.restored("empty")).unwrap(), b"");
    assert_eq!(fs::read(f.restored("dir/big.bin")).unwrap(), big);
    assert_eq!(fs::read(f.restored("dir/copy1")).unwrap(), shared);
    assert_eq!(fs::read(f.restored("other/copy2")).unwrap(), shared);
    assert!(f.restored("empty-dir/nested").is_dir());
    assert_eq!(
        fs::read_link(f.restored("dir/link")).unwrap(),
        PathBuf::from("../a.txt")
    );

    assert_eq!(mode(&f.restored("a.txt")), 0o640);
    assert_eq!(mode(&f.restored("dir")), 0o750);
    assert_eq!(mtime(&f.restored("a.txt")), old);
    assert_eq!(
        mtime(&f.restored("dir")),
        old,
        "directory times survive writing their children"
    );
    assert_eq!(stats.files, 5);
    assert_eq!(stats.symlinks, 1);
    assert_eq!(stats.bytes, 5 + 500_000 + 2 * 40_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn special_mode_bits_are_restored() {
    let f = Fixture::new().await;
    let exe = f.write("tool", b"#!/bin/sh\n");
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o4755)).unwrap();
    let shared = f.src.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();

    let snap = f.backup().await;
    f.restore(&snap, Options::default()).await.unwrap();
    assert_eq!(mode(&f.restored("tool")), 0o4755);
    assert_eq!(mode(&f.restored("shared")), 0o1777);
}

#[tokio::test(flavor = "multi_thread")]
async fn hardlinks_are_recreated() {
    let f = Fixture::new().await;
    let original = f.write("one", b"linked content");
    fs::hard_link(&original, f.src.path().join("two")).unwrap();

    let snap = f.backup().await;
    let stats = f.restore(&snap, Options::default()).await.unwrap();
    let (a, b) = (
        fs::metadata(f.restored("one")).unwrap(),
        fs::metadata(f.restored("two")).unwrap(),
    );
    assert_eq!(a.ino(), b.ino());
    assert_eq!(fs::read(f.restored("two")).unwrap(), b"linked content");
    assert_eq!((stats.files, stats.hardlinks), (1, 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_to_overwrite_by_default() {
    let f = Fixture::new().await;
    f.write("a.txt", b"from backup");
    let snap = f.backup().await;

    fs::create_dir_all(f.restored_root()).unwrap();
    fs::write(f.restored("a.txt"), b"precious").unwrap();
    let err = f.restore(&snap, Options::default()).await.unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    assert_eq!(fs::read(f.restored("a.txt")).unwrap(), b"precious");

    f.restore(
        &snap,
        Options {
            overwrite: true,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(fs::read(f.restored("a.txt")).unwrap(), b"from backup");
}

#[tokio::test(flavor = "multi_thread")]
async fn excluded_directory_excludes_its_contents() {
    let f = Fixture::new().await;
    f.write("keep/a", b"a");
    f.write("build.d/deep/b", b"b");
    let snap = f.backup().await;

    f.restore(
        &snap,
        Options {
            exclude: vec!["*.d".into()],
            ..Options::default()
        },
    )
    .await
    .unwrap();
    assert!(f.restored("keep/a").exists());
    assert!(!f.restored("build.d").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn include_restores_matches_and_only_the_directories_leading_to_them() {
    let f = Fixture::new().await;
    f.write("docs/report.pdf", b"pdf");
    f.write("docs/notes.txt", b"txt");
    f.write("music/song.mp3", b"mp3");
    f.write("photos/2024/a.jpg", b"jpg");
    fs::create_dir_all(f.src.path().join("photos/empty")).unwrap();
    let snap = f.backup().await;

    f.restore(
        &snap,
        Options {
            include: vec!["*.pdf".into(), "photos".into()],
            ..Options::default()
        },
    )
    .await
    .unwrap();
    assert!(f.restored("docs/report.pdf").exists());
    assert!(!f.restored("docs/notes.txt").exists());
    assert!(
        !f.restored("music").exists(),
        "no directory leads to a match"
    );
    assert!(
        f.restored("photos/2024/a.jpg").exists(),
        "an included directory brings its contents"
    );
    assert!(
        f.restored("photos/empty").is_dir(),
        "including empty directories"
    );
}

/// A symlink planted at a directory's position in the target must never be
/// followed: without overwrite the restore stops, with it the link is replaced by
/// a real directory. Either way nothing is written to where it pointed.
#[tokio::test(flavor = "multi_thread")]
async fn symlinked_directory_in_the_target_is_never_followed() {
    let f = Fixture::new().await;
    f.write("dir/file", b"payload");
    let snap = f.backup().await;

    let outside = tempfile::tempdir().unwrap();
    fs::create_dir_all(f.restored_root()).unwrap();
    symlink(outside.path(), f.restored("dir")).unwrap();

    assert!(f.restore(&snap, Options::default()).await.is_err());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);

    f.restore(
        &snap,
        Options {
            overwrite: true,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    assert!(
        !fs::symlink_metadata(f.restored("dir"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(f.restored("dir/file")).unwrap(), b"payload");
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn symlink_at_a_file_position_is_replaced_not_written_through() {
    let f = Fixture::new().await;
    f.write("file", b"restored");
    let snap = f.backup().await;

    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    fs::write(&victim, b"untouched").unwrap();
    fs::create_dir_all(f.restored_root()).unwrap();
    symlink(&victim, f.restored("file")).unwrap();

    assert!(f.restore(&snap, Options::default()).await.is_err());
    f.restore(
        &snap,
        Options {
            overwrite: true,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    assert_eq!(fs::read(f.restored("file")).unwrap(), b"restored");
}

/// A target directory that already exists but resolves outside the target (an
/// ancestor of the restored path replaced by a symlink) is caught by the resolved
/// containment check.
#[tokio::test(flavor = "multi_thread")]
async fn ancestor_symlink_escaping_the_target_is_rejected() {
    let f = Fixture::new().await;
    f.write("x", b"x");
    let snap = f.backup().await;

    let outside = tempfile::tempdir().unwrap();
    let first = std::path::absolute(f.src.path()).unwrap();
    let first = first.components().nth(1).unwrap().as_os_str().to_owned();
    symlink(outside.path(), f.dst.path().join(&first)).unwrap();

    let err = f
        .restore(
            &snap,
            Options {
                overwrite: false,
                ..Options::default()
            },
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("already exists") || err.to_string().contains("outside"),
        "{err}"
    );
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

/// A tree blob naming `..`, sealed with the right key (so it authenticates): the
/// restore must refuse rather than write outside the target.
#[tokio::test(flavor = "multi_thread")]
async fn hostile_tree_names_are_rejected() {
    let f = Fixture::new().await;
    let data = f.repo.save_blob(BlobType::Data, b"evil").await.unwrap().0;
    let tree = format!(
        r#"{{"nodes":[{{"name":"..","type":"file","mode":420,"uid":0,"gid":0,"size":4,"mtime":"2024-01-01T00:00:00Z","content":["{data}"]}}]}}"#
    );
    let (tree_id, _) = f
        .repo
        .save_blob(BlobType::Tree, tree.as_bytes())
        .await
        .unwrap();
    f.repo.flush().await.unwrap();

    let snap = Snapshot {
        id: Id::default(),
        time: chrono::Utc::now(),
        hostname: String::new(),
        username: String::new(),
        paths: vec!["/x".into()],
        tags: vec![],
        tree: tree_id,
        parent: None,
        stats: Default::default(),
    };
    let err = f.restore(&snap, Options::default()).await.unwrap_err();
    assert!(matches!(err, Error::Format(_)), "{err}");
    assert!(
        !f.dst
            .path()
            .parent()
            .unwrap()
            .join("..")
            .join("evil")
            .exists()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_chunk_is_reported_as_an_incomplete_repository() {
    let f = Fixture::new().await;
    f.write("a", &random_bytes(10_000, 3));
    let snap = f.backup().await;

    // A fresh handle whose index has lost every object.
    for object in
        mirror_core::store::ObjectStore::list(f.store.as_ref(), "rfm/backup/indexes/", None)
            .await
            .unwrap()
    {
        mirror_core::store::ObjectStore::delete(f.store.as_ref(), &object.key)
            .await
            .unwrap();
    }
    let keys = Keys::derive(&SecretBox::new(Box::new([3; 32])));
    let repo = Arc::new(
        Repository::open(Arc::clone(&f.store), PREFIX, keys)
            .await
            .unwrap(),
    );
    let err = restorer::restore(repo, &snap, f.dst.path(), Options::default())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::UnknownBlob(_) | Error::Incomplete(_)),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn many_files_restore_with_progress() {
    let f = Fixture::new().await;
    for i in 0..300 {
        f.write(
            &format!("d{}/f{i}", i % 7),
            format!("content {i}").as_bytes(),
        );
    }
    let snap = f.backup().await;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_in = Arc::clone(&calls);
    let stats = f
        .restore(
            &snap,
            Options {
                progress: Some(Arc::new(move |_| {
                    calls_in.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                })),
                ..Options::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(stats.files, 300);
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 300);
    assert_eq!(fs::read(f.restored("d5/f299")).unwrap(), b"content 299");
}
