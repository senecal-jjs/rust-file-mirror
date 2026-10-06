//! Shared, store-agnostic test harness. Drives a full per-device sync cycle
//! (read remote → merge → scan → reconcile → apply → write) against any
//! `ObjectStore`, so the same code exercises the real `S3Store` (MinIO) and the
//! in-memory `MemoryStore` (fast, in-process, multi-device convergence proptests).
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mirror_core::apply::apply;
use mirror_core::crypto::key::DerivedSubKeys;
use mirror_core::engine::Plan;
use mirror_core::hash::ContentHash;
use mirror_core::indicator::PrintReporter;
use mirror_core::manifest::{self, Manifest};
use mirror_core::scanner::{LocalEntry, Scanner};
use mirror_core::state::State;
use mirror_core::store::ObjectStore;
use mirror_core::sync::{PassPlan, SyncOptions, SyncOutcome, plan_pass};
use rand::Rng;
use secrecy::SecretBox;

/// Everything a sync works out before it writes anything to the remote. Split
/// out from the write half so a test can interleave two devices — both reading
/// the log before either writes to it — which is the only window in which a
/// genuine remote conflict can form.
pub struct PendingSync {
    pub state: State,
    pub manifest: Manifest,
    pub plan: Plan,
    pub entries: Vec<LocalEntry>,
    pub remote_lamport: u64,
}

pub async fn sync_read<S: ObjectStore>(
    root: &Path,
    store: &S,
    prefix: &str,
    enc_keys: &DerivedSubKeys,
) -> PendingSync {
    let mut state = State::open(root).expect("open state");
    // The same read half the real sync uses: merge, preserve conflict losers, scan,
    // and reconcile (placeholders included).
    let PassPlan {
        plan,
        manifest,
        scan,
        remote_lamport,
    } = plan_pass(
        store,
        root,
        prefix,
        ".mirrorignore",
        enc_keys,
        &mut state,
        &SyncOptions::default(),
    )
    .await
    .expect("plan pass");

    PendingSync {
        state,
        manifest,
        plan,
        entries: scan.entries,
        remote_lamport,
    }
}

pub async fn sync_write<S: ObjectStore + 'static>(
    mut pending: PendingSync,
    root: &Path,
    store: Arc<S>,
    prefix: &str,
    enc_keys: Arc<DerivedSubKeys>,
) {
    apply(
        &pending.plan,
        store,
        root.to_path_buf(),
        prefix.to_string(),
        &mut pending.state,
        &mut pending.manifest,
        enc_keys,
        Arc::new(PrintReporter {}),
        &pending.remote_lamport,
    )
    .await
    .expect("apply plan");

    pending
        .state
        .record_scan(&pending.entries)
        .expect("record scan");
}

pub async fn sync_once<S: ObjectStore + 'static>(
    root: &Path,
    store: Arc<S>,
    prefix: &str,
    enc_keys: Arc<DerivedSubKeys>,
) {
    let pending = sync_read(root, store.as_ref(), prefix, &enc_keys).await;
    sync_write(pending, root, store, prefix, enc_keys).await;
}

/// One device in a multi-device simulation: its own local tree and state DB,
/// sharing one backing store (bucket prefix) with every other device.
pub struct Device<S: ObjectStore + 'static> {
    pub root: PathBuf,
    pub store: Arc<S>,
}

impl<S: ObjectStore + 'static> Device<S> {
    pub async fn sync(&self, prefix: &str, enc_keys: Arc<DerivedSubKeys>) {
        sync_once(&self.root, Arc::clone(&self.store), prefix, enc_keys).await;
    }

    pub async fn compact(&self, prefix: &str, enc_keys: Arc<DerivedSubKeys>, grace: Duration) {
        let mut state = State::open(&self.root).expect("open state");
        manifest::compact(
            self.store.as_ref(),
            &enc_keys.manifest_key,
            prefix,
            &mut state,
            grace,
            grace,
        )
        .await
        .expect("compact");
    }

    /// A full `sync_once` pass, with residency options (hydrate/evict requests, pins).
    pub async fn sync_with(
        &self,
        prefix: &str,
        enc_keys: Arc<DerivedSubKeys>,
        options: &SyncOptions,
    ) -> SyncOutcome {
        let mut state = State::open(&self.root).expect("open state");
        mirror_core::sync::sync_once(
            Arc::clone(&self.store),
            &self.root,
            prefix,
            ".mirrorignore",
            enc_keys,
            &mut state,
            Arc::new(PrintReporter {}),
            options,
        )
        .await
        .expect("sync pass")
    }

    pub async fn evict(
        &self,
        prefix: &str,
        enc_keys: Arc<DerivedSubKeys>,
        path: &str,
    ) -> SyncOutcome {
        let options = SyncOptions {
            evict: BTreeSet::from([path.to_string()]),
            ..SyncOptions::default()
        };
        self.sync_with(prefix, enc_keys, &options).await
    }

    pub async fn hydrate(
        &self,
        prefix: &str,
        enc_keys: Arc<DerivedSubKeys>,
        path: &str,
    ) -> SyncOutcome {
        let options = SyncOptions {
            hydrate: BTreeSet::from([path.to_string()]),
            ..SyncOptions::default()
        };
        self.sync_with(prefix, enc_keys, &options).await
    }
}

/// Round-robin syncs every device until a full pass produces no plan actions on
/// any device — the fixed point. Panics if that doesn't happen within a bound,
/// which is itself a genuine non-convergence bug rather than a slow test.
pub async fn settle<S: ObjectStore + 'static>(
    devices: &[Device<S>],
    prefix: &str,
    enc_keys: &Arc<DerivedSubKeys>,
) {
    const MAX_ROUNDS: usize = 40;

    for _ in 0..MAX_ROUNDS {
        let mut changed = false;
        for device in devices {
            let pending = sync_read(&device.root, device.store.as_ref(), prefix, enc_keys).await;
            if !pending.plan.is_empty() {
                changed = true;
            }
            sync_write(
                pending,
                &device.root,
                Arc::clone(&device.store),
                prefix,
                Arc::clone(enc_keys),
            )
            .await;
        }
        if !changed {
            return;
        }
    }

    panic!("devices did not converge within {MAX_ROUNDS} settle rounds");
}

/// The set of files under `root` as `relative_path -> content hash`, using the
/// same walk/exclusions the real scanner uses. This is the canonical form two
/// devices must agree on to be "converged" — mtimes and object keys are ignored.
pub fn tree_hashes(root: &Path) -> BTreeMap<String, ContentHash> {
    Scanner::new(root, ".mirrorignore")
        .scan(&())
        .expect("scan tree")
        .into_iter()
        .map(|entry| (entry.path, entry.hash))
        .collect()
}

/// Random subkeys — a real vault derives these from a passphrase, but tests only
/// need every device to share the *same* set, so random-but-shared is enough.
pub fn test_keys() -> DerivedSubKeys {
    let random = || {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        SecretBox::new(Box::new(bytes))
    };

    DerivedSubKeys {
        content_key: random(),
        name_key: random(),
        manifest_key: random(),
        keycheck_bytes: random(),
    }
}

/// The single `… (conflicted copy …)` file in `root`, whatever timestamp and
/// device name it ended up carrying.
pub fn find_conflicted_copy(root: &Path) -> PathBuf {
    let mut found: Vec<_> = std::fs::read_dir(root)
        .expect("read root")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("conflicted copy"))
        })
        .collect();

    assert_eq!(
        found.len(),
        1,
        "expected exactly one conflicted copy in {root:?}"
    );
    found.pop().unwrap()
}
