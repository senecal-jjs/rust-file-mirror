//! Online-only files: eviction and hydration are device-local, never look like a
//! delete, and never lose a version.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mirror_core::residency::{Mode, Policy};
use mirror_core::state::State;
use mirror_core::store::ObjectStore;
use mirror_core::store::memory::MemoryStore;
use mirror_core::sync::{SpaceTarget, SyncOptions};
use tempfile::TempDir;

mod common;
use common::{Device, settle, sync_read, sync_write, test_keys, tree_hashes};

const PREFIX: &str = "offline/";

struct Fixture {
    _dirs: Vec<TempDir>,
    devices: Vec<Device<MemoryStore>>,
    store: Arc<MemoryStore>,
    keys: Arc<mirror_core::crypto::key::DerivedSubKeys>,
}

fn fixture(count: usize) -> Fixture {
    let store = Arc::new(MemoryStore::new());
    let dirs: Vec<TempDir> = (0..count).map(|_| tempfile::tempdir().unwrap()).collect();
    let devices = dirs
        .iter()
        .map(|dir| Device {
            root: dir.path().to_path_buf(),
            store: Arc::clone(&store),
        })
        .collect();

    Fixture {
        _dirs: dirs,
        devices,
        store,
        keys: Arc::new(test_keys()),
    }
}

impl Fixture {
    async fn keys_in_bucket(&self) -> Vec<String> {
        self.store
            .list(PREFIX, None)
            .await
            .unwrap()
            .into_iter()
            .map(|meta| meta.key)
            .collect()
    }

    async fn settle(&self) {
        settle(&self.devices, PREFIX, &self.keys).await;
    }
}

fn is_evicted(root: &Path, path: &str) -> bool {
    State::open(root).unwrap().baseline().unwrap()[path].is_evicted()
}

fn stub(root: &Path, path: &str) -> std::path::PathBuf {
    root.join(format!("{path}.rfm"))
}

#[tokio::test]
async fn evict_then_hydrate_round_trips_without_touching_the_bucket() {
    let fx = fixture(2);
    let (a, b) = (&fx.devices[0], &fx.devices[1]);
    std::fs::write(a.root.join("big.bin"), vec![7u8; 100_000]).unwrap();
    fx.settle().await;

    let before = fx.keys_in_bucket().await;
    let outcome = a.evict(PREFIX, Arc::clone(&fx.keys), "big.bin").await;

    assert_eq!(outcome.evicted, 1);
    assert!(outcome.bytes_freed > 0);
    assert!(!a.root.join("big.bin").exists());
    assert!(stub(&a.root, "big.bin").exists());
    assert!(is_evicted(&a.root, "big.bin"));

    // Other devices and the bucket never notice.
    fx.settle().await;
    assert_eq!(fx.keys_in_bucket().await, before);
    assert!(b.root.join("big.bin").exists());

    let outcome = a.hydrate(PREFIX, Arc::clone(&fx.keys), "big.bin").await;
    assert_eq!(outcome.hydrated, 1);
    assert_eq!(
        std::fs::read(a.root.join("big.bin")).unwrap(),
        vec![7u8; 100_000]
    );
    assert!(!stub(&a.root, "big.bin").exists());
    assert!(!is_evicted(&a.root, "big.bin"));
    assert_eq!(tree_hashes(&a.root), tree_hashes(&b.root));
}

#[tokio::test]
async fn deleting_a_placeholder_deletes_the_file_but_keeps_the_object() {
    let fx = fixture(2);
    let (a, b) = (&fx.devices[0], &fx.devices[1]);
    std::fs::write(a.root.join("f.txt"), b"hello").unwrap();
    fx.settle().await;
    a.evict(PREFIX, Arc::clone(&fx.keys), "f.txt").await;

    let data_before: Vec<String> = fx
        .keys_in_bucket()
        .await
        .into_iter()
        .filter(|key| key.contains("/data/"))
        .collect();

    std::fs::remove_file(stub(&a.root, "f.txt")).unwrap();
    fx.settle().await;

    assert!(!b.root.join("f.txt").exists());
    assert!(
        !State::open(&a.root)
            .unwrap()
            .baseline()
            .unwrap()
            .contains_key("f.txt")
    );
    // Tombstone only: GC, not the delete, reclaims the bytes.
    for key in data_before {
        assert!(
            fx.store.head(&key).await.unwrap().is_some(),
            "{key} deleted"
        );
    }
}

#[tokio::test]
async fn remote_edit_updates_the_placeholder_without_downloading() {
    let fx = fixture(2);
    let (a, b) = (&fx.devices[0], &fx.devices[1]);
    std::fs::write(a.root.join("f.txt"), b"v1").unwrap();
    fx.settle().await;
    a.evict(PREFIX, Arc::clone(&fx.keys), "f.txt").await;

    std::fs::write(b.root.join("f.txt"), b"v2").unwrap();
    b.sync(PREFIX, Arc::clone(&fx.keys)).await;
    let outcome = a
        .sync_with(PREFIX, Arc::clone(&fx.keys), &SyncOptions::default())
        .await;

    assert_eq!(outcome.placeholders, 1);
    assert_eq!(outcome.downloads + outcome.hydrated, 0);
    assert!(!a.root.join("f.txt").exists());
    let meta = mirror_core::placeholder::read(&stub(&a.root, "f.txt")).unwrap();
    assert_eq!(
        meta.content_hash(),
        Some(mirror_core::hash::hash_bytes(b"v2"))
    );

    a.hydrate(PREFIX, Arc::clone(&fx.keys), "f.txt").await;
    assert_eq!(std::fs::read(a.root.join("f.txt")).unwrap(), b"v2");
}

#[tokio::test]
async fn online_only_device_receives_placeholders_and_pins_control_residency() {
    let fx = fixture(2);
    let (a, b) = (&fx.devices[0], &fx.devices[1]);
    std::fs::write(a.root.join("one.txt"), b"one").unwrap();
    std::fs::write(a.root.join("two.txt"), b"two").unwrap();
    a.sync(PREFIX, Arc::clone(&fx.keys)).await;

    let online_only = SyncOptions {
        policy: Policy::new(&[], &[], &[], true).unwrap(),
        ..SyncOptions::default()
    };
    let outcome = b
        .sync_with(PREFIX, Arc::clone(&fx.keys), &online_only)
        .await;

    assert_eq!(outcome.placeholders, 2);
    assert_eq!(outcome.downloads, 0);
    assert!(tree_hashes(&b.root).is_empty());
    assert!(stub(&b.root, "one.txt").exists());

    // Pinning local hydrates on the next pass.
    let pinned = SyncOptions {
        policy: Policy::new(&[("one.txt".to_string(), Mode::Local)], &[], &[], true).unwrap(),
        ..SyncOptions::default()
    };
    b.sync_with(PREFIX, Arc::clone(&fx.keys), &pinned).await;
    assert_eq!(std::fs::read(b.root.join("one.txt")).unwrap(), b"one");
    assert!(!b.root.join("two.txt").exists());

    // Pinning online-only evicts once past the grace period.
    let evicting = SyncOptions {
        policy: Policy::new(&[("one.txt".to_string(), Mode::OnlineOnly)], &[], &[], true).unwrap(),
        evict_grace: Duration::ZERO,
        ..SyncOptions::default()
    };
    let outcome = b.sync_with(PREFIX, Arc::clone(&fx.keys), &evicting).await;
    assert_eq!(outcome.evicted, 1);
    assert!(!b.root.join("one.txt").exists());
}

#[tokio::test]
async fn moved_placeholder_is_relocated_and_the_old_path_deleted() {
    let fx = fixture(2);
    let (a, b) = (&fx.devices[0], &fx.devices[1]);
    std::fs::write(a.root.join("old.txt"), b"contents").unwrap();
    fx.settle().await;
    a.evict(PREFIX, Arc::clone(&fx.keys), "old.txt").await;

    std::fs::rename(stub(&a.root, "old.txt"), stub(&a.root, "new.txt")).unwrap();
    let outcome = a
        .sync_with(PREFIX, Arc::clone(&fx.keys), &SyncOptions::default())
        .await;

    assert_eq!(outcome.relocated, 1);
    assert_eq!(outcome.deletes_remote, 1);
    assert!(is_evicted(&a.root, "new.txt"));
    let meta = mirror_core::placeholder::read(&stub(&a.root, "new.txt")).unwrap();
    assert_eq!(meta.path, "new.txt");

    fx.settle().await;
    assert!(!b.root.join("old.txt").exists());
    assert_eq!(std::fs::read(b.root.join("new.txt")).unwrap(), b"contents");
}

#[tokio::test]
async fn space_pressure_evicts_auto_files() {
    let fx = fixture(1);
    let a = &fx.devices[0];
    std::fs::write(a.root.join("a.bin"), vec![1u8; 10_000]).unwrap();
    std::fs::write(a.root.join("b.bin"), vec![2u8; 10_000]).unwrap();
    a.sync(PREFIX, Arc::clone(&fx.keys)).await;

    let options = SyncOptions {
        space: Some(SpaceTarget {
            min_free: u64::MAX,
            target_free: u64::MAX,
        }),
        evict_grace: Duration::ZERO,
        ..SyncOptions::default()
    };
    let outcome = a.sync_with(PREFIX, Arc::clone(&fx.keys), &options).await;

    assert_eq!(outcome.evicted, 2);
    assert!(tree_hashes(&a.root).is_empty());
}

/// Plan §6: the loser of a concurrent edit had already evicted its version. Its
/// bytes survive under their own object key and come back as a conflicted copy.
#[tokio::test]
async fn evicted_conflict_loser_is_relocated_not_lost() {
    let fx = fixture(2);
    let (a, b) = (&fx.devices[0], &fx.devices[1]);
    std::fs::write(a.root.join("f.txt"), b"v1").unwrap();
    fx.settle().await;
    // Every pass advances a device's Lamport clock, so B wins the coming conflict.
    for _ in 0..3 {
        b.sync(PREFIX, Arc::clone(&fx.keys)).await;
    }

    // Both edit and read the log before either writes.
    std::fs::write(a.root.join("f.txt"), b"from-a").unwrap();
    std::fs::write(b.root.join("f.txt"), b"from-b").unwrap();
    let pending_a = sync_read(&a.root, fx.store.as_ref(), PREFIX, &fx.keys).await;
    let pending_b = sync_read(&b.root, fx.store.as_ref(), PREFIX, &fx.keys).await;
    sync_write(
        pending_a,
        &a.root,
        Arc::clone(&fx.store),
        PREFIX,
        Arc::clone(&fx.keys),
    )
    .await;

    // A evicts its version before B's competing write lands.
    let outcome = a.evict(PREFIX, Arc::clone(&fx.keys), "f.txt").await;
    assert_eq!(outcome.evicted, 1);
    sync_write(
        pending_b,
        &b.root,
        Arc::clone(&fx.store),
        PREFIX,
        Arc::clone(&fx.keys),
    )
    .await;

    let outcome = a
        .sync_with(PREFIX, Arc::clone(&fx.keys), &SyncOptions::default())
        .await;
    assert_eq!(outcome.relocated, 1, "the evicted loser must be relocated");

    fx.settle().await;
    for device in &fx.devices {
        let evicted: BTreeSet<String> = State::open(&device.root)
            .unwrap()
            .baseline()
            .unwrap()
            .into_values()
            .filter(|record| record.is_evicted())
            .map(|record| record.path)
            .collect();
        let options = SyncOptions {
            hydrate: evicted,
            ..SyncOptions::default()
        };
        device
            .sync_with(PREFIX, Arc::clone(&fx.keys), &options)
            .await;
    }
    fx.settle().await;

    let tree = tree_hashes(&a.root);
    assert_eq!(tree, tree_hashes(&b.root));

    let contents: BTreeSet<Vec<u8>> = tree
        .keys()
        .map(|path| std::fs::read(a.root.join(path)).unwrap())
        .collect();
    assert_eq!(
        contents,
        BTreeSet::from([b"from-a".to_vec(), b"from-b".to_vec()]),
        "both concurrent versions must survive; tree = {tree:?}"
    );
}
