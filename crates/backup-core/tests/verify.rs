//! Verification against healthy and deliberately damaged repositories.

use std::fs;
use std::sync::Arc;

use backup_core::archiver::{self, Options as BackupOptions};
use backup_core::chunker::ChunkerConfig;
use backup_core::compress::Compression;
use backup_core::crypto::Keys;
use backup_core::pack::BlobType;
use backup_core::repo::{InitOptions, Repository};
use backup_core::verify::{Options, Report, verify};
use mirror_core::store::ObjectStore;
use mirror_core::store::memory::MemoryStore;
use rand::{Rng, SeedableRng};
use secrecy::SecretBox;

const PREFIX: &str = "rfm/";
const BASE: &str = "rfm/backup/";

fn keys() -> Keys {
    Keys::derive(&SecretBox::new(Box::new([5; 32])))
}

async fn open(store: &Arc<MemoryStore>) -> Repository<MemoryStore> {
    let mut repo = Repository::open(Arc::clone(store), PREFIX, keys(), None)
        .await
        .unwrap();
    repo.set_pack_target(64 * 1024);
    repo
}

/// A repository holding one backup of a few files, spread over several packs.
async fn backed_up() -> Arc<MemoryStore> {
    let store = Arc::new(MemoryStore::new());
    let options = InitOptions {
        chunker: ChunkerConfig {
            min_size: 2048,
            avg_size: 8192,
            max_size: 32768,
        },
        compression: Compression::Zstd,
    };
    let mut repo = Repository::init(Arc::clone(&store), PREFIX, keys(), options, None)
        .await
        .unwrap();
    repo.set_pack_target(64 * 1024);

    let src = tempfile::tempdir().unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(9);
    for i in 0..6 {
        let mut data = vec![0u8; 50_000];
        rng.fill(&mut data[..]);
        fs::write(src.path().join(format!("f{i}")), data).unwrap();
    }
    archiver::backup(
        Arc::new(repo),
        &[src.path().to_path_buf()],
        BackupOptions::default(),
    )
    .await
    .unwrap();
    store
}

async fn packs(store: &MemoryStore) -> Vec<String> {
    store
        .list(&format!("{BASE}packs/"), None)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.key)
        .collect()
}

async fn check(store: &Arc<MemoryStore>, read_data: bool) -> Report {
    verify(
        &open(store).await,
        Options {
            read_data,
            ..Options::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn healthy_repository_passes_both_levels() {
    let store = backed_up().await;
    let structural = check(&store, false).await;
    assert!(structural.ok(), "{:?}", structural.problems);
    assert_eq!(structural.snapshots_checked, 1);
    assert!(structural.trees_checked > 1);
    assert!(structural.blobs_referenced > 20);
    assert!(structural.packs_in_storage > 1);
    assert_eq!(structural.packs_referenced, structural.packs_in_storage);
    assert!(structural.orphan_packs.is_empty());
    assert_eq!(structural.bytes_read, 0, "metadata only");

    let full = check(&store, true).await;
    assert!(full.ok(), "{:?}", full.problems);
    assert!(full.bytes_read > 300_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_repository_passes() {
    let store = Arc::new(MemoryStore::new());
    Repository::init(
        Arc::clone(&store),
        PREFIX,
        keys(),
        InitOptions::default(),
        None,
    )
    .await
    .unwrap();
    let report = check(&store, true).await;
    assert!(report.ok());
    assert_eq!((report.snapshots_checked, report.packs_in_storage), (0, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_pack_is_detected() {
    let store = backed_up().await;
    let victim = packs(&store).await.remove(0);
    store.delete(&victim).await.unwrap();

    let report = check(&store, false).await;
    assert!(!report.ok());
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("missing from storage")),
        "{:?}",
        report.problems
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn truncated_pack_is_detected_structurally() {
    let store = backed_up().await;
    let victim = packs(&store).await.remove(0);
    let data = store.get(&victim).await.unwrap();
    store
        .put_bytes(&victim, &data[..data.len() / 2])
        .await
        .unwrap();

    let report = check(&store, false).await;
    assert!(
        report.problems.iter().any(|p| p.contains("which is only")),
        "{:?}",
        report.problems
    );
}

/// A flipped byte inside a blob: same size, so only reading the data finds it.
#[tokio::test(flavor = "multi_thread")]
async fn silent_corruption_needs_read_data() {
    let store = backed_up().await;
    let victim = packs(&store).await.remove(0);
    let mut data = store.get(&victim).await.unwrap();
    data[100] ^= 0x01;
    store.put_bytes(&victim, &data).await.unwrap();

    assert!(
        check(&store, false).await.ok(),
        "structural checks can't see it"
    );
    let full = check(&store, true).await;
    assert!(!full.ok());
    assert!(
        full.problems
            .iter()
            .any(|p| p.contains("decryption failed")),
        "{:?}",
        full.problems
    );
}

/// An interrupted run (packs uploaded, never flushed) leaves orphans: reported,
/// but not a problem.
#[tokio::test(flavor = "multi_thread")]
async fn orphan_packs_are_reported_but_harmless() {
    let store = backed_up().await;
    let before = packs(&store).await.len();
    {
        let repo = open(&store).await;
        let mut rng = rand::rngs::StdRng::seed_from_u64(77);
        for _ in 0..3 {
            let mut data = vec![0u8; 40_000];
            rng.fill(&mut data[..]);
            repo.save_blob(BlobType::Data, &data).await.unwrap();
        }
        // Dropped without flush.
    }
    let orphans = packs(&store).await.len() - before;
    assert!(orphans > 0);

    let report = check(&store, true).await;
    assert!(report.ok(), "{:?}", report.problems);
    assert_eq!(report.orphan_packs.len(), orphans);
}

#[tokio::test(flavor = "multi_thread")]
async fn lost_index_is_detected() {
    let store = backed_up().await;
    for object in store.list(&format!("{BASE}indexes/"), None).await.unwrap() {
        store.delete(&object.key).await.unwrap();
    }
    let report = check(&store, false).await;
    assert!(!report.ok());
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("cannot read the directory tree")),
        "{:?}",
        report.problems
    );
}
