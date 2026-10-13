//! A sync pass compacts the remote log once enough deltas are old enough to prune.

use std::sync::Arc;
use std::time::Duration;

use mirror_core::store::ObjectStore;
use mirror_core::store::memory::MemoryStore;
use mirror_core::sync::{Compaction, SyncOptions};
use tempfile::TempDir;

mod common;
use common::{Device, test_keys, tree_hashes};

const PREFIX: &str = "compact/";

fn devices(count: usize) -> (Vec<TempDir>, Vec<Device<MemoryStore>>) {
    let store = Arc::new(MemoryStore::new());
    let dirs: Vec<TempDir> = (0..count).map(|_| tempfile::tempdir().unwrap()).collect();
    let devices = dirs
        .iter()
        .map(|dir| Device {
            root: dir.path().to_path_buf(),
            store: Arc::clone(&store),
        })
        .collect();

    (dirs, devices)
}

fn compacting(threshold: usize, grace: Duration) -> SyncOptions {
    SyncOptions {
        compaction: Some(Compaction {
            threshold,
            grace,
            object_retention: grace,
        }),
        ..SyncOptions::default()
    }
}

async fn count(store: &MemoryStore, prefix: &str) -> usize {
    store.list(prefix, None).await.unwrap().len()
}

#[tokio::test]
async fn compacts_once_threshold_reached() {
    let (_dirs, devices) = devices(2);
    let (a, b) = (&devices[0], &devices[1]);
    let keys = Arc::new(test_keys());
    let options = compacting(2, Duration::ZERO);

    std::fs::write(a.root.join("one.txt"), "one").unwrap();
    let first = a.sync_with(PREFIX, Arc::clone(&keys), &options).await;
    assert_eq!(first.compacted, 0, "log was empty when the pass listed it");

    std::fs::write(a.root.join("two.txt"), "two").unwrap();
    let second = a.sync_with(PREFIX, Arc::clone(&keys), &options).await;
    assert_eq!(second.compacted, 0, "one delta is below the threshold");

    let third = a.sync_with(PREFIX, Arc::clone(&keys), &options).await;
    assert_eq!(third.compacted, 2);
    assert_eq!(count(&a.store, &format!("{PREFIX}log/")).await, 0);
    assert_eq!(count(&a.store, &format!("{PREFIX}snapshot")).await, 1);

    // A device that never saw the deltas still converges from the snapshot.
    b.sync_with(PREFIX, Arc::clone(&keys), &SyncOptions::default())
        .await;
    assert_eq!(tree_hashes(&a.root), tree_hashes(&b.root));
}

#[tokio::test]
async fn leaves_deltas_inside_grace_alone() {
    let (_dirs, devices) = devices(1);
    let a = &devices[0];
    let keys = Arc::new(test_keys());
    let options = compacting(1, Duration::from_secs(3600));

    std::fs::write(a.root.join("one.txt"), "one").unwrap();
    a.sync_with(PREFIX, Arc::clone(&keys), &options).await;
    let outcome = a.sync_with(PREFIX, Arc::clone(&keys), &options).await;

    assert_eq!(outcome.compacted, 0);
    assert_eq!(count(&a.store, &format!("{PREFIX}log/")).await, 1);
    assert_eq!(count(&a.store, &format!("{PREFIX}snapshot")).await, 0);
}

#[tokio::test]
async fn never_compacts_without_compaction_options() {
    let (_dirs, devices) = devices(1);
    let a = &devices[0];
    let keys = Arc::new(test_keys());

    for name in ["one.txt", "two.txt", "three.txt"] {
        std::fs::write(a.root.join(name), name).unwrap();
        let outcome = a
            .sync_with(PREFIX, Arc::clone(&keys), &SyncOptions::default())
            .await;
        assert_eq!(outcome.compacted, 0);
    }

    assert_eq!(count(&a.store, &format!("{PREFIX}log/")).await, 3);
}
