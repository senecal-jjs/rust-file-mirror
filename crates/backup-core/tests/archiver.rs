//! End-to-end backups against the in-memory store, checked by reading the saved
//! snapshot back through the repository.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use backup_core::archiver::{self, Decision, Options};
use backup_core::chunker::ChunkerConfig;
use backup_core::compress::Compression;
use backup_core::crypto::Keys;
use backup_core::filter::{Excludes, MirrorFilter};
use backup_core::repo::{InitOptions, Repository};
use backup_core::snapshot::{NodeType, Snapshot};
use backup_core::{Error, Result};
use mirror_core::store::ObjectStore;
use mirror_core::store::memory::MemoryStore;
use rand::{Rng, SeedableRng};
use secrecy::SecretBox;

const PREFIX: &str = "rfm/";

/// Small chunks so a few megabytes exercise content-defined chunking properly.
const SMALL_CHUNKS: ChunkerConfig = ChunkerConfig {
    min_size: 2 * 1024,
    avg_size: 8 * 1024,
    max_size: 32 * 1024,
};

fn keys() -> Keys {
    Keys::derive(&SecretBox::new(Box::new([7; 32])))
}

struct Fixture {
    store: Arc<MemoryStore>,
    repo: Arc<Repository<MemoryStore>>,
    dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let store = Arc::new(MemoryStore::new());
        let options = InitOptions {
            chunker: SMALL_CHUNKS,
            compression: Compression::Zstd,
        };
        let mut repo = Repository::init(Arc::clone(&store), PREFIX, keys(), options, None)
            .await
            .unwrap();
        repo.set_pack_target(256 * 1024);
        Self {
            store,
            repo: Arc::new(repo),
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, rel: &str, contents: &[u8]) {
        let path = self.root().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// A fresh repository handle, as a new process would open it.
    async fn reopen(&mut self) {
        let mut repo = Repository::open(Arc::clone(&self.store), PREFIX, keys(), None)
            .await
            .unwrap();
        repo.set_pack_target(256 * 1024);
        self.repo = Arc::new(repo);
    }

    async fn backup(&self, options: Options) -> Result<Snapshot> {
        archiver::backup(
            Arc::clone(&self.repo),
            &[self.root().to_path_buf()],
            options,
        )
        .await
    }

    /// Backs up with the latest snapshot as parent, the way the CLI will.
    async fn backup_incremental(&self) -> Snapshot {
        let parent = self.repo.list_snapshots().await.unwrap().into_iter().next();
        self.backup(Options {
            parent,
            ..Options::default()
        })
        .await
        .unwrap()
    }

    async fn objects(&self, dir: &str) -> usize {
        self.store
            .list(&format!("{PREFIX}backup/{dir}"), None)
            .await
            .unwrap()
            .len()
    }

    /// The tree ID the snapshot recorded for the backed-up root itself.
    async fn root_subtree(&self, snapshot: &Snapshot) -> backup_core::crypto::Id {
        let mut id = snapshot.tree;
        for part in clean(self.root()).iter().skip(1) {
            let tree = self.repo.load_tree(&id).await.unwrap();
            id = tree.find(part.to_str().unwrap()).unwrap().subtree.unwrap();
        }
        id
    }

    /// Everything under the backed-up root, as the snapshot recorded it.
    async fn contents(&self, snapshot: &Snapshot) -> BTreeMap<String, Entry> {
        let tree = self
            .repo
            .load_tree(&self.root_subtree(snapshot).await)
            .await
            .unwrap();
        let mut out = BTreeMap::new();
        self.collect(tree, String::new(), &mut out).await;
        out
    }

    fn collect<'a>(
        &'a self,
        tree: backup_core::snapshot::Tree,
        prefix: String,
        out: &'a mut BTreeMap<String, Entry>,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            for node in tree.nodes {
                let rel = format!("{prefix}{}", node.name);
                match node.node_type {
                    NodeType::File => {
                        let mut data = Vec::new();
                        for id in &node.content {
                            data.extend(self.repo.load_blob(id).await.unwrap());
                        }
                        assert_eq!(data.len() as u64, node.size, "{rel}");
                        out.insert(rel, Entry::File(data, node.mode));
                    }
                    NodeType::Symlink => {
                        out.insert(rel, Entry::Symlink(node.link_target.unwrap()));
                    }
                    NodeType::Dir => {
                        let sub = self.repo.load_tree(&node.subtree.unwrap()).await.unwrap();
                        out.insert(rel.clone(), Entry::Dir);
                        self.collect(sub, format!("{rel}/"), out).await;
                    }
                }
            }
        })
    }
}

fn clean(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    File(Vec<u8>, u32),
    Dir,
    Symlink(String),
}

fn file(data: &[u8]) -> Entry {
    Entry::File(data.to_vec(), 0o644)
}

fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    bytes
}

/// Sets permissions explicitly so tests don't depend on the umask.
fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn backup_round_trip() {
    let f = Fixture::new().await;
    let big = random_bytes(300_000, 1);
    f.write("a.txt", b"hello");
    f.write("empty", b"");
    f.write("nested/deep/b.bin", &big);
    f.write("script.sh", b"#!/bin/sh\n");
    fs::create_dir(f.root().join("empty-dir")).unwrap();
    symlink("nested/deep/b.bin", f.root().join("link")).unwrap();
    for rel in ["a.txt", "empty", "nested/deep/b.bin"] {
        chmod(&f.root().join(rel), 0o644);
    }
    chmod(&f.root().join("script.sh"), 0o755);

    let snap = f.backup(Options::default()).await.unwrap();

    let expected = BTreeMap::from([
        ("a.txt".into(), file(b"hello")),
        ("empty".into(), file(b"")),
        ("empty-dir".into(), Entry::Dir),
        ("link".into(), Entry::Symlink("nested/deep/b.bin".into())),
        ("nested".into(), Entry::Dir),
        ("nested/deep".into(), Entry::Dir),
        ("nested/deep/b.bin".into(), file(&big)),
        (
            "script.sh".into(),
            Entry::File(b"#!/bin/sh\n".to_vec(), 0o755),
        ),
    ]);
    assert_eq!(f.contents(&snap).await, expected);
    assert_eq!(snap.stats.files_new, 4, "symlinks and dirs are not files");
    assert_eq!(
        snap.stats.dirs_processed, 4,
        "root, empty-dir, nested, nested/deep"
    );
    assert_eq!(
        snap.paths,
        vec![clean(f.root()).to_str().unwrap().to_string()]
    );
    assert!(snap.stats.bytes_added > 0);

    // Readable by a fresh process.
    let mut f = f;
    f.reopen().await;
    let reloaded = f.repo.find_snapshot("latest").await.unwrap();
    assert_eq!(reloaded, snap);
    assert_eq!(f.contents(&reloaded).await, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn walk_lists_every_entry_with_absolute_paths() {
    let f = Fixture::new().await;
    f.write("a", b"1");
    f.write("d/b", b"22");
    let snap = f.backup(Options::default()).await.unwrap();
    let root = clean(f.root()).to_str().unwrap().to_string();

    let entries = f.repo.walk(snap.tree).await.unwrap();
    let paths: Vec<_> = entries.iter().map(|(p, _)| p.as_str()).collect();
    assert!(paths.contains(&root.as_str()));
    let below: Vec<_> = paths
        .iter()
        .filter_map(|p| p.strip_prefix(&format!("{root}/")))
        .collect();
    assert_eq!(below, ["a", "d", "d/b"]);
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted);
}

#[tokio::test(flavor = "multi_thread")]
async fn second_backup_reads_and_uploads_nothing() {
    let mut f = Fixture::new().await;
    for i in 0..20 {
        f.write(&format!("dir{}/file{i}", i % 3), &random_bytes(20_000, i));
    }
    let first = f.backup(Options::default()).await.unwrap();
    let packs = f.objects("packs/").await;
    let indexes = f.objects("indexes/").await;

    f.reopen().await;
    let second = f.backup_incremental().await;
    assert_eq!(second.parent, Some(first.id));
    assert_eq!(second.stats.files_unmodified, 20);
    assert_eq!((second.stats.files_new, second.stats.files_changed), (0, 0));
    assert_eq!(second.stats.bytes_added, 0);
    assert_eq!(
        second.stats.chunks_new + second.stats.chunks_duplicate,
        0,
        "no file was read"
    );
    assert_eq!(
        f.root_subtree(&second).await,
        f.root_subtree(&first).await,
        "an unchanged directory produces an identical tree"
    );
    // The synthetic directories above the root carry their real metadata, which
    // other processes change (here, other tests creating temp dirs), so at most
    // a few tiny ancestor trees are new: one small pack and one index.
    assert!(f.objects("packs/").await <= packs + 1);
    assert!(f.objects("indexes/").await <= indexes + 1);
    assert_eq!(f.objects("snapshots/").await, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn incremental_uploads_only_the_change() {
    let f = Fixture::new().await;
    let original = random_bytes(2 * 1024 * 1024, 2);
    f.write("big.bin", &original);
    f.backup(Options::default()).await.unwrap();

    let mut edited = original.clone();
    edited.splice(1_000_000..1_000_000, random_bytes(1024, 3));
    f.write("big.bin", &edited);

    let snap = f.backup_incremental().await;
    assert_eq!(snap.stats.files_changed, 1);
    assert!(
        snap.stats.bytes_added < 4 * SMALL_CHUNKS.max_size as u64,
        "{} bytes uploaded for a 1 KiB insert",
        snap.stats.bytes_added
    );
    assert!(snap.stats.chunks_duplicate > 100);
    assert_eq!(f.contents(&snap).await["big.bin"], file(&edited));
}

/// Same size, and the old mtime put back: only ctime (and here also inode) can
/// tell. The fast path must not reuse stale chunks.
#[tokio::test(flavor = "multi_thread")]
async fn change_with_preserved_size_and_mtime_is_detected() {
    let f = Fixture::new().await;
    let path = f.root().join("f.txt");
    f.write("f.txt", b"version one");
    chmod(&path, 0o644);
    let mtime = fs::metadata(&path).unwrap().modified().unwrap();
    f.backup(Options::default()).await.unwrap();

    std::thread::sleep(std::time::Duration::from_millis(20));
    f.write("f.txt", b"version two");
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);

    let snap = f.backup_incremental().await;
    assert_eq!(snap.stats.files_changed, 1);
    assert_eq!(f.contents(&snap).await["f.txt"], file(b"version two"));
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_content_is_stored_once() {
    let f = Fixture::new().await;
    let data = random_bytes(200_000, 4);
    f.write("one", &data);
    f.backup(Options::default()).await.unwrap();

    f.write("copy/two", &data);
    f.write("copy/three", &data);
    let snap = f.backup_incremental().await;
    assert_eq!(snap.stats.files_new, 2);
    assert_eq!(snap.stats.bytes_added, 0);
    let contents = f.contents(&snap).await;
    assert_eq!(contents["copy/two"], contents["one"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn deleted_file_disappears_from_the_next_snapshot() {
    let f = Fixture::new().await;
    f.write("keep", b"k");
    f.write("gone", b"g");
    let first = f.backup(Options::default()).await.unwrap();
    fs::remove_file(f.root().join("gone")).unwrap();
    let second = f.backup_incremental().await;

    assert!(
        f.contents(&first).await.contains_key("gone"),
        "history keeps it"
    );
    assert!(!f.contents(&second).await.contains_key("gone"));
}

#[tokio::test(flavor = "multi_thread")]
async fn excludes_skip_matching_entries() {
    let f = Fixture::new().await;
    f.write("keep.txt", b"k");
    f.write("debug.log", b"l");
    f.write("sub/trace.log", b"l");
    f.write("node_modules/pkg/index.js", b"x");
    f.write("cache/blob", b"c");
    let cache = clean(f.root()).join("cache");
    let excludes = Excludes::new(&[
        "*.log".into(),
        "node_modules".into(),
        cache.to_str().unwrap().into(),
    ])
    .unwrap();

    let snap = f
        .backup(Options {
            filters: vec![Arc::new(excludes)],
            ..Options::default()
        })
        .await
        .unwrap();
    let names: Vec<_> = f.contents(&snap).await.into_keys().collect();
    assert_eq!(names, ["keep.txt", "sub"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn mirror_root_backup_skips_state_ignored_files_and_placeholders() {
    let f = Fixture::new().await;
    f.write(".mirror/state.db", b"state");
    f.write(".mirror/passphrase", b"secret");
    f.write(".mirrorignore", b"*.tmp\n");
    f.write("doc.txt", b"d");
    f.write("scratch.tmp", b"t");
    f.write(
        "real.rfm",
        b"a real file that only happens to use the suffix",
    );
    // A genuine placeholder, written the way the mirror writes them.
    let stub = mirror_core::placeholder::StubMeta::new(
        "photo.jpg",
        1234,
        mirror_core::hash::hash_bytes(b"x"),
        "rfm/data/k",
        1,
    );
    mirror_core::placeholder::write(f.root(), &stub).unwrap();

    let snap = f
        .backup(Options {
            filters: vec![Arc::new(MirrorFilter::new(
                clean(f.root()),
                ".mirrorignore",
            ))],
            skip_placeholders: true,
            ..Options::default()
        })
        .await
        .unwrap();
    let names: Vec<_> = f.contents(&snap).await.into_keys().collect();
    assert_eq!(names, [".mirrorignore", "doc.txt", "real.rfm"]);
    assert_eq!(snap.stats.placeholders_skipped, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn unreadable_files_are_skipped_by_default() {
    if unsafe { libc_geteuid() } == 0 {
        return; // root can read anything
    }
    let f = Fixture::new().await;
    f.write("ok.txt", b"fine");
    f.write("secret.txt", b"nope");
    f.write("locked/inner.txt", b"nope");
    chmod(&f.root().join("secret.txt"), 0o000);
    chmod(&f.root().join("locked"), 0o000);

    let snap = f.backup(Options::default()).await;
    chmod(&f.root().join("locked"), 0o755);
    let snap = snap.unwrap();

    let contents = f.contents(&snap).await;
    assert!(contents.contains_key("ok.txt"));
    assert!(!contents.contains_key("secret.txt"));
    assert_eq!(
        contents["locked"],
        Entry::Dir,
        "unreadable dir recorded empty"
    );
    assert!(!contents.contains_key("locked/inner.txt"));
    assert_eq!(snap.stats.files_skipped, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn on_error_can_abort_the_run() {
    if unsafe { libc_geteuid() } == 0 {
        return;
    }
    let f = Fixture::new().await;
    f.write("secret.txt", b"nope");
    chmod(&f.root().join("secret.txt"), 0o000);

    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_in = Arc::clone(&seen);
    let result = f
        .backup(Options {
            on_error: Some(Arc::new(move |path: &Path, _: &Error| {
                seen_in.lock().unwrap().push(path.to_path_buf());
                Decision::Abort
            })),
            ..Options::default()
        })
        .await;
    assert!(result.is_err());
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert_eq!(f.objects("snapshots/").await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn many_small_files() {
    let f = Fixture::new().await;
    for i in 0..500 {
        f.write(&format!("d{}/f{i}", i % 10), format!("file {i}").as_bytes());
    }
    let snap = f.backup(Options::default()).await.unwrap();
    assert_eq!(snap.stats.files_new, 500);
    let contents = f.contents(&snap).await;
    assert_eq!(contents["d7/f337"], file(b"file 337"));
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_missing_and_empty_paths() {
    let f = Fixture::new().await;
    let missing = f.root().join("does-not-exist");
    assert!(
        archiver::backup(Arc::clone(&f.repo), &[missing], Options::default())
            .await
            .is_err()
    );
    assert!(
        archiver::backup(Arc::clone(&f.repo), &[], Options::default())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_and_multiple_paths() {
    let f = Fixture::new().await;
    f.write("a/one", b"1");
    f.write("a/b/two", b"2");
    f.write("c/three", b"3");
    let (a, ab, c) = (f.root().join("a"), f.root().join("a/b"), f.root().join("c"));

    let snap = archiver::backup(
        Arc::clone(&f.repo),
        &[ab, c.clone(), a.clone()],
        Options::default(),
    )
    .await
    .unwrap();
    let mut want = [clean(&a), clean(&c)];
    want.sort();
    let want: Vec<_> = want
        .iter()
        .map(|p| p.to_str().unwrap().to_string())
        .collect();
    assert_eq!(snap.paths, want, "a/b is covered by a");

    // Only the requested children appear under the root directory.
    let names: Vec<_> = f.contents(&snap).await.into_keys().collect();
    assert_eq!(names, ["a", "a/b", "a/b/two", "a/one", "c", "c/three"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_symlink_given_as_a_path_is_stored_as_a_symlink() {
    let f = Fixture::new().await;
    f.write("target/file", b"x");
    symlink("target", f.root().join("link")).unwrap();
    let snap = archiver::backup(
        Arc::clone(&f.repo),
        &[f.root().join("link")],
        Options::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        f.contents(&snap).await["link"],
        Entry::Symlink("target".into())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_pack_upload_produces_no_snapshot() {
    let f = Fixture::new().await;
    for i in 0..10 {
        f.write(&format!("f{i}"), &random_bytes(100_000, 10 + i));
    }
    f.store
        .fail_puts_under(Some(&format!("{PREFIX}backup/packs/")));

    // A repository failure is never a skippable source error: the policy must not
    // even be asked about it. (The repository's sticky failure would still stop a
    // snapshot, but the archiver shouldn't rely on that backstop.)
    let consulted = Arc::new(AtomicUsize::new(0));
    let consulted_in = Arc::clone(&consulted);
    let err = f
        .backup(Options {
            on_error: Some(Arc::new(move |_: &Path, _: &Error| {
                consulted_in.fetch_add(1, Ordering::Relaxed);
                Decision::Skip
            })),
            ..Options::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::RunFailed(_)), "{err}");
    assert_eq!(consulted.load(Ordering::Relaxed), 0);
    assert_eq!(f.objects("snapshots/").await, 0);
    assert_eq!(f.objects("indexes/").await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn backups_hold_a_shared_lock_and_wait_for_a_prune() {
    let f = Fixture::new().await;
    f.write("a", b"a");

    // While a prune holds the repository, backups refuse to start.
    let prune = backup_core::lock::Lock::acquire(
        Arc::clone(&f.store),
        &format!("{PREFIX}backup/"),
        &keys(),
        true,
    )
    .await
    .unwrap();
    assert!(matches!(
        f.backup(Options::default()).await,
        Err(Error::Locked(_))
    ));
    prune.release().await.unwrap();

    // Locks are released after success and after failure alike.
    f.backup(Options::default()).await.unwrap();
    assert_eq!(f.objects("locks/").await, 0);
    f.store
        .fail_puts_under(Some(&format!("{PREFIX}backup/packs/")));
    f.write("b", &random_bytes(300_000, 9));
    assert!(f.backup(Options::default()).await.is_err());
    f.store.fail_puts_under(None);
    assert_eq!(f.objects("locks/").await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancellation_stops_the_run() {
    let f = Fixture::new().await;
    for i in 0..50 {
        f.write(&format!("f{i}"), &random_bytes(50_000, 100 + i));
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_in = Arc::clone(&cancel);
    let result = f
        .backup(Options {
            concurrency: 1,
            cancel: Some(Arc::clone(&cancel)),
            progress: Some(Arc::new(move |_| cancel_in.store(true, Ordering::Relaxed))),
            ..Options::default()
        })
        .await;
    assert!(matches!(result, Err(Error::Cancelled)), "{result:?}");
    assert_eq!(f.objects("snapshots/").await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn progress_is_reported_for_every_file_from_many_threads() {
    let f = Fixture::new().await;
    for i in 0..100 {
        f.write(&format!("d{}/f{i}", i % 4), &random_bytes(5_000, 200 + i));
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(Mutex::new(0u64));
    let (calls_in, max_in) = (Arc::clone(&calls), Arc::clone(&max_seen));

    let snap = f
        .backup(Options {
            concurrency: 8,
            progress: Some(Arc::new(move |p| {
                calls_in.fetch_add(1, Ordering::Relaxed);
                let mut max = max_in.lock().unwrap();
                *max = (*max).max(p.files_processed);
            })),
            ..Options::default()
        })
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 100);
    assert_eq!(*max_seen.lock().unwrap(), 100);
    assert_eq!(snap.stats.files_new, 100);
}

/// The archiver also works on a current-thread runtime (file workers run on
/// blocking threads and drive the repository through the handle).
#[tokio::test]
async fn works_on_a_current_thread_runtime() {
    let f = Fixture::new().await;
    f.write("a", &random_bytes(100_000, 5));
    let snap = f.backup(Options::default()).await.unwrap();
    assert_eq!(snap.stats.files_new, 1);
    assert_eq!(
        f.contents(&snap).await["a"],
        file(&random_bytes(100_000, 5))
    );
}

unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}
