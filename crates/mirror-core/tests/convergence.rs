//! Crown-jewel convergence simulation (plan §6.1). Random operation sequences
//! across several devices sharing one in-memory bucket, applied in the arbitrary
//! interleavings proptest explores, must always settle to byte-identical trees.
//! This is the property the whole delta-log/merge design exists to guarantee.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mirror_core::state::State;
use mirror_core::store::ObjectStore;
use mirror_core::store::memory::MemoryStore;
use mirror_core::sync::SyncOptions;
use proptest::collection::vec;
use proptest::prelude::*;
use tempfile::TempDir;
use tokio::runtime::Runtime;

mod common;
use common::{Device, settle, test_keys, tree_hashes};

fn placeholder_files(root: &Path) -> Vec<String> {
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".rfm"))
        .collect()
}

const DEVICES: usize = 3;
/// Few enough paths that random writes frequently collide on the same one,
/// which is what actually exercises conflict handling instead of unrelated files.
const PATHS: usize = 3;

#[derive(Debug, Clone)]
enum Op {
    /// Create or overwrite a file locally on one device (not yet synced).
    Write {
        device: usize,
        path: usize,
        content: u8,
    },
    Delete {
        device: usize,
        path: usize,
    },
    /// A single sync pass for one device — the interleaving of these is what
    /// creates concurrent-edit windows and remote conflicts.
    Sync {
        device: usize,
    },

    /// Fold the delta log into a fresh snapshot and prune the folded deltas.
    Compact {
        device: usize,
    },

    /// Drop one device's local bytes for a path, keeping a placeholder.
    Evict {
        device: usize,
        path: usize,
    },

    Hydrate {
        device: usize,
        path: usize,
    },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..DEVICES, 0..PATHS, 0u8..4)
            .prop_map(|(device, path, content)| Op::Write { device, path, content }),
        1 => (0..DEVICES, 0..PATHS).prop_map(|(device, path)| Op::Delete { device, path }),
        3 => (0..DEVICES).prop_map(|device| Op::Sync { device }),
        1 => (0..DEVICES).prop_map(|device| Op::Compact { device }),
        1 => (0..DEVICES, 0..PATHS).prop_map(|(device, path)| Op::Evict { device, path }),
        1 => (0..DEVICES, 0..PATHS).prop_map(|(device, path)| Op::Hydrate { device, path })
    ]
}

fn path_name(idx: usize) -> String {
    format!("f{idx}.bin")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whatever sequence of local edits and partial syncs happens, once every
    /// device syncs to quiescence they all hold an identical set of files with
    /// identical contents.
    #[test]
    fn devices_converge(ops in vec(op_strategy(), 0..16)) {
        let runtime = Runtime::new().unwrap();

        runtime.block_on(async move {
            let prefix = "sim/";
            let enc_keys = Arc::new(test_keys());
            let store = Arc::new(MemoryStore::new());

            let dirs: Vec<TempDir> = (0..DEVICES).map(|_| tempfile::tempdir().unwrap()).collect();
            let devices: Vec<Device<MemoryStore>> = dirs
                .iter()
                .map(|dir| Device {
                    root: dir.path().to_path_buf(),
                    store: Arc::clone(&store),
                })
                .collect();

            for op in &ops {
                match *op {
                    Op::Write { device, path, content } => {
                        std::fs::write(devices[device].root.join(path_name(path)), [content; 8])
                            .unwrap();
                    }
                    Op::Delete { device, path } => {
                        // Deleting an evicted file means deleting its placeholder.
                        let root = &devices[device].root;
                        let _ = std::fs::remove_file(root.join(path_name(path)));
                        let _ = std::fs::remove_file(root.join(format!("{}.rfm", path_name(path))));
                    }
                    Op::Evict { device, path } => {
                        devices[device].evict(prefix, Arc::clone(&enc_keys), &path_name(path)).await;
                    }
                    Op::Hydrate { device, path } => {
                        devices[device].hydrate(prefix, Arc::clone(&enc_keys), &path_name(path)).await;
                    }
                    Op::Sync { device } => {
                        devices[device].sync(prefix, Arc::clone(&enc_keys)).await;
                    }
                    Op::Compact { device } => {
                        // Zero grace so every delta folded into the new snapshot
                        // is actually pruned — otherwise the delete path is never
                        // exercised under the fast test clock.
                        devices[device]
                            .compact(prefix, Arc::clone(&enc_keys), Duration::ZERO)
                            .await;

                        let remaining = store
                            .list(&format!("{prefix}log/"), None)
                            .await
                            .expect("list log");
                        prop_assert!(
                            remaining.is_empty(),
                            "compaction left {} delta(s) in the log; ops = {:?}",
                            remaining.len(),
                            ops
                        );
                    }
                }
            }

            settle(&devices, prefix, &enc_keys).await;

            // Eviction is device-local: once every placeholder is hydrated, the
            // logical trees must match exactly.
            for device in &devices {
                let evicted: BTreeSet<String> = State::open(&device.root)
                    .unwrap()
                    .baseline()
                    .unwrap()
                    .into_values()
                    .filter(|record| record.is_evicted())
                    .map(|record| record.path)
                    .collect();
                let options = SyncOptions { hydrate: evicted, ..SyncOptions::default() };
                device.sync_with(prefix, Arc::clone(&enc_keys), &options).await;
            }
            settle(&devices, prefix, &enc_keys).await;

            for device in &devices {
                let leftover = placeholder_files(&device.root);
                prop_assert!(leftover.is_empty(), "placeholders left after hydrating: {:?}; ops = {:?}", leftover, ops);
            }

            let reference = tree_hashes(&devices[0].root);
            for device in &devices[1..] {
                prop_assert_eq!(
                    tree_hashes(&device.root),
                    reference.clone(),
                    "devices diverged after settling; ops = {:?}",
                    ops
                );
            }

            Ok(())
        })?;
    }
}
