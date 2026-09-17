use std::{
    cmp::max,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::sync::Semaphore;

use crate::{
    Error,
    apply::{
        conflict::conflict,
        delete_local::delete_local,
        delete_remote::delete_remote,
        download::{DownloadResult, download},
        upload::{UploadResult, upload},
    },
    crypto::key::DerivedSubKeys,
    engine::{ActionKind, Plan},
    error::Result,
    hash::ContentHash,
    indicator::ProgressReporter,
    manifest::{self, DeltaEntry, Manifest},
    state::State,
    store::ObjectStore,
    util::time::unix_timestamp,
};

enum ActionOutcome {
    Upload(Option<UploadResult>),
    Download(DownloadResult),
}

/// A baseline mutation deferred until its delta is durably logged, so the local
/// baseline can never claim a sync the remote log doesn't record.
enum BaselineOp {
    Confirm {
        path: String,
        size: u64,
        mtime_ns: i64,
        hash: ContentHash,
    },
    Remove {
        path: String,
    },
}

/// One durable commit step: write the batch's delta object, then — only after it
/// is durable — apply the batch's baseline updates. A crash or error can lose
/// progress but never leave the baseline ahead of the log (which `reconcile`
/// would read as a remote delete and destroy the local file).
async fn flush<S: ObjectStore>(
    store: &S,
    state: &mut State,
    prefix: &str,
    lamport: u64,
    seq: &mut u32,
    deltas: &mut Vec<DeltaEntry>,
    ops: &mut Vec<BaselineOp>,
) -> Result<()> {
    if !deltas.is_empty() {
        manifest::log_delta(store, state, prefix, deltas, &lamport, *seq).await?;
        *seq += 1;
        deltas.clear();
    }

    for op in ops.drain(..) {
        match op {
            BaselineOp::Confirm {
                path,
                size,
                mtime_ns,
                hash,
            } => state.confirm_sync(&path, size, mtime_ns, hash)?,
            BaselineOp::Remove { path } => state.remove(&path)?,
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn apply<S: ObjectStore + 'static>(
    plan: &Plan,
    store: Arc<S>,
    root: PathBuf,
    prefix: String,
    state: &mut State,
    manifest: &mut Manifest,
    enc_keys: Arc<DerivedSubKeys>,
    reporter: Arc<dyn ProgressReporter>,
    remote_lamport: &u64,
) -> Result<()> {
    const MAX_CONCURRENT_TRANSFERS: usize = 8;
    // Deltas are flushed (and baselines confirmed) in batches of this size so a
    // failure part-way through a huge copy only costs the last partial batch.
    const FLUSH_BATCH: usize = 25;

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TRANSFERS));
    let mut tasks = tokio::task::JoinSet::new();
    let mut deltas: Vec<DeltaEntry> = Vec::new();
    let mut batch_ops: Vec<BaselineOp> = Vec::new();
    let mut flush_seq: u32 = 0;
    let local_lamport = state.get_latest_lamport()?;
    let lamport = max(remote_lamport, &local_lamport) + 1;

    for action in &plan.actions {
        match action.kind {
            ActionKind::Download => {
                let entry = manifest
                    .get(&action.path)
                    .ok_or_else(|| {
                        Error::Store(format!("no remote manifest entry for {}", action.path))
                    })?
                    .clone(); // owned — the borrow from `manifest` can't cross into a 'static task
                let store = Arc::clone(&store);
                let enc_keys = Arc::clone(&enc_keys);
                let action = action.clone();
                let root = root.to_path_buf();
                let prefix = prefix.to_string();
                let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
                let reporter = Arc::clone(&reporter);

                tasks.spawn(async move {
                    let _permit = permit;
                    let result = download(
                        store.as_ref(),
                        &root,
                        &prefix,
                        &entry,
                        &action,
                        &enc_keys.content_key,
                        reporter.as_ref(),
                    )
                    .await
                    .map(ActionOutcome::Download);
                    (action, result)
                });
            }
            ActionKind::Upload => {
                let store = Arc::clone(&store);
                let enc_keys = Arc::clone(&enc_keys);
                let action = action.clone();
                let root = root.to_path_buf();
                let prefix = prefix.to_string();
                let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
                let reporter = Arc::clone(&reporter);

                tasks.spawn(async move {
                    let _permit = permit; // held for the task's lifetime, released on drop
                    let upload_result = upload(
                        store.as_ref(),
                        &root,
                        &action,
                        &enc_keys,
                        &prefix,
                        reporter.as_ref(),
                    )
                    .await
                    .map(ActionOutcome::Upload);

                    (action, upload_result)
                });
            }
            _ => {}
        }
    }

    while let Some(joined) = tasks.join_next().await {
        let (action, result) = joined.expect("task panicked");

        match result {
            // A single failed transfer must not abort the whole batch: skip it —
            // its baseline stays untouched, so the next pass simply retries it.
            Err(e) => {
                tracing::warn!(path = %action.path, error = %e, "transfer failed; will retry next sync");
            }
            Ok(ActionOutcome::Upload(None)) => {} // file changed mid-hash, deferred
            Ok(ActionOutcome::Upload(Some(r))) => {
                // What this device believed was current for this path before its
                // own edit — the merge rule compares an incoming delta's base_hash
                // against this.
                let base_hash = manifest.get(&action.path).map(|e| e.plaintext_hash);
                let mtime_utc = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let entry = DeltaEntry {
                    path: action.path.clone(),
                    object_key: r.object_key,
                    plaintext_hash: r.content_hash,
                    size: r.size,
                    mtime_utc,
                    deleted: false,
                    deleted_at: 0,
                    lamport,
                    device_id: state.device_id()?,
                    base_hash,
                };

                manifest.insert(action.path.clone(), entry.clone());
                deltas.push(entry);
                batch_ops.push(BaselineOp::Confirm {
                    path: action.path.clone(),
                    size: r.size,
                    mtime_ns: r.mtime_ns,
                    hash: r.content_hash,
                });
                reporter.action_completed(&action.path, action.kind);
            }
            Ok(ActionOutcome::Download(r)) => {
                batch_ops.push(BaselineOp::Confirm {
                    path: action.path.clone(),
                    size: r.size,
                    mtime_ns: r.mtime_ns,
                    hash: r.content_hash,
                });
                reporter.action_completed(&action.path, action.kind);
            }
        }

        if batch_ops.len() >= FLUSH_BATCH {
            flush(
                store.as_ref(),
                state,
                &prefix,
                lamport,
                &mut flush_seq,
                &mut deltas,
                &mut batch_ops,
            )
            .await?;
        }
    }

    // Deletes go last so an interrupted sync leaves extra data rather than missing data.
    for action in &plan.actions {
        match action.kind {
            ActionKind::DeleteLocal => {
                delete_local(&root, action).await?;
                batch_ops.push(BaselineOp::Remove {
                    path: action.path.clone(),
                });
                reporter.action_completed(&action.path, action.kind);
            }
            ActionKind::DeleteRemote => {
                let entry = manifest.get(&action.path);
                if let Some(entry) = entry {
                    deltas.push(DeltaEntry {
                        path: action.path.clone(),
                        object_key: entry.object_key.clone(),
                        plaintext_hash: entry.plaintext_hash,
                        size: entry.size,
                        mtime_utc: entry.mtime_utc,
                        deleted: true,
                        deleted_at: unix_timestamp(),
                        lamport,
                        device_id: state.device_id()?,
                        base_hash: Some(entry.plaintext_hash),
                    });
                }
                delete_remote(store.as_ref(), &prefix, entry).await?;
                manifest.remove_entry(&action.path);
                batch_ops.push(BaselineOp::Remove {
                    path: action.path.clone(),
                });
                reporter.action_completed(&action.path, action.kind);
            }
            ActionKind::Conflict => {
                conflict(&root, action, state)?;
                reporter.action_completed(&action.path, action.kind);
            }
            _ => {}
        }

        if batch_ops.len() >= FLUSH_BATCH {
            flush(
                store.as_ref(),
                state,
                &prefix,
                lamport,
                &mut flush_seq,
                &mut deltas,
                &mut batch_ops,
            )
            .await?;
        }
    }

    // Final partial batch.
    flush(
        store.as_ref(),
        state,
        &prefix,
        lamport,
        &mut flush_seq,
        &mut deltas,
        &mut batch_ops,
    )
    .await?;

    state.record_lamport(lamport)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::{Rng, rng};
    use secrecy::SecretBox;
    use std::path::Path;

    use super::*;
    use crate::{
        crypto::{
            content::{decrypt, encrypt},
            filename,
        },
        engine::{Action, reconcile},
        hash,
        indicator::PrintReporter,
        manifest::{self, MergeResult},
        scanner::Scanner,
        store::memory::MemoryStore,
    };

    #[tokio::test]
    async fn download_writes_file_and_confirms_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let store = MemoryStore::new();
        let src = root.join("src.txt");
        std::fs::write(&src, b"hello").unwrap();

        let mut content_enc_key = [0u8; 32];
        rng().fill(&mut content_enc_key);
        let content_enc_key = SecretBox::new(Box::new(content_enc_key));

        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        // download decrypts whatever it fetches, so the store needs to actually
        // hold ciphertext produced under the same key — not the raw plaintext.
        let content_hash = hash::hash_file(&src).unwrap();
        let ciphertext = tmp.path().join("ciphertext.bin");
        let object_key = filename::object_key(&name_enc_key, src.to_str().unwrap()).unwrap();
        let prefix = "rfm/";
        let store_key = format!("{prefix}{}", object_key);

        encrypt(&content_enc_key, &src, &ciphertext, "a.txt").unwrap();
        store.put(&store_key, &ciphertext).await.unwrap();

        let mut state = State::open(root).unwrap();
        let entry = DeltaEntry {
            path: "a.txt".to_string(),
            object_key,
            plaintext_hash: content_hash,
            size: 5,
            mtime_utc: 0,
            deleted: false,
            deleted_at: 0,
            lamport: 0,
            device_id: "test-device".to_string(),
            base_hash: None,
        };
        let action = Action {
            path: "a.txt".to_string(),
            kind: ActionKind::Download,
        };

        let reporter = PrintReporter {};

        // download() no longer touches state itself — the caller (here, standing
        // in for apply()'s own Download arm) applies the returned outcome.
        let result = download(
            &store,
            root,
            "rfm/",
            &entry,
            &action,
            &content_enc_key,
            Arc::new(reporter).as_ref(),
        )
        .await
        .unwrap();

        state
            .confirm_sync(
                &action.path,
                result.size,
                result.mtime_ns,
                result.content_hash,
            )
            .unwrap();

        assert_eq!(
            std::fs::read(root.join("a.txt")).unwrap(),
            b"hello".to_vec()
        );

        let baseline = state.baseline().unwrap();
        assert_eq!(
            baseline["a.txt"].last_synced_hash,
            Some(entry.plaintext_hash)
        );
    }

    #[tokio::test]
    async fn upload_puts_file_and_confirms_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.txt"), b"hello").unwrap();

        let store = MemoryStore::new();
        let mut state = State::open(root).unwrap();
        let action = Action {
            path: "a.txt".to_string(),
            kind: ActionKind::Upload,
        };

        let mut content_enc_key = [0u8; 32];
        rng().fill(&mut content_enc_key);
        let content_enc_key = SecretBox::new(Box::new(content_enc_key));

        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        let enc_keys = DerivedSubKeys {
            content_key: content_enc_key,
            name_key: name_enc_key,
            manifest_key: SecretBox::new(Box::new([0u8; 32])),
            keycheck_bytes: SecretBox::new(Box::new([0u8; 32])),
        };

        let mut manifest = Manifest::new();
        let prefix = "rfm/";
        let reporter = PrintReporter {};

        // upload() no longer touches manifest/state itself — it just reports what
        // happened, so the caller (here, standing in for apply()'s own Upload arm)
        // is responsible for applying that outcome.
        let result = upload(
            &store,
            root,
            &action,
            &enc_keys,
            prefix,
            Arc::new(reporter).as_ref(),
        )
        .await
        .unwrap()
        .expect("file existed and was hashable, so upload should produce a result");

        manifest.insert(
            action.path.clone(),
            DeltaEntry {
                path: action.path.clone(),
                object_key: result.object_key,
                plaintext_hash: result.content_hash,
                size: result.size,
                mtime_utc: 0,
                deleted: false,
                deleted_at: 0,
                lamport: 0,
                device_id: "test-device".to_string(),
                base_hash: None,
            },
        );

        state
            .confirm_sync(
                &action.path,
                result.size,
                result.mtime_ns,
                result.content_hash,
            )
            .unwrap();

        // What's stored is ciphertext, not the plaintext bytes — round-trip it back
        // through decrypt to confirm the upload actually encrypted correctly.
        let object_key = manifest.get("a.txt").unwrap().object_key.clone();
        let store_key = format!("{prefix}{object_key}");
        let ciphertext = store.get(&store_key).await.unwrap();
        assert_ne!(ciphertext, b"hello".to_vec());

        let ciphertext_path = tmp.path().join("ciphertext.bin");
        std::fs::write(&ciphertext_path, &ciphertext).unwrap();
        let decrypted_path = tmp.path().join("decrypted.txt");
        decrypt(
            &enc_keys.content_key,
            &ciphertext_path,
            &decrypted_path,
            "a.txt",
        )
        .unwrap();

        assert_eq!(std::fs::read(decrypted_path).unwrap(), b"hello".to_vec());

        let baseline = state.baseline().unwrap();
        assert!(baseline["a.txt"].last_synced_hash.is_some());
    }

    #[tokio::test]
    async fn delete_local_is_idempotent_on_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let action = Action {
            path: "missing.txt".to_string(),
            kind: ActionKind::DeleteLocal,
        };

        delete_local(root, &action).await.unwrap();
        delete_local(root, &action).await.unwrap();
    }

    #[tokio::test]
    async fn delete_remote_is_idempotent_on_missing_key() {
        let store = MemoryStore::new();
        let action = Action {
            path: "missing.txt".to_string(),
            kind: ActionKind::DeleteRemote,
        };
        let mut manifest = Manifest::new();
        let store_key = format!("rfm/{}", action.path);

        manifest.insert(
            store_key,
            DeltaEntry {
                path: action.path.clone(),
                object_key: "doesnt matter".to_string(),
                plaintext_hash: hash::hash_bytes(&[0u8; 32]),
                size: 0,
                mtime_utc: 0,
                deleted: false,
                deleted_at: 0,
                lamport: 0,
                device_id: "test-device".to_string(),
                base_hash: None,
            },
        );

        delete_remote(&store, "rfm/", manifest.get(&action.path))
            .await
            .unwrap();
        delete_remote(&store, "rfm/", manifest.get(&action.path))
            .await
            .unwrap();
    }

    fn test_keys() -> DerivedSubKeys {
        let random = || {
            let mut k = [0u8; 32];
            rng().fill(&mut k);
            SecretBox::new(Box::new(k))
        };
        DerivedSubKeys {
            content_key: random(),
            name_key: random(),
            manifest_key: random(),
            keycheck_bytes: random(),
        }
    }

    /// Regression for the verified data-loss bug: one upload failing part-way
    /// through a batch must never leave the baseline claiming a sync the delta log
    /// doesn't record (which `reconcile` would later read as a remote delete).
    #[tokio::test]
    async fn one_failed_upload_never_leaves_baseline_ahead_of_the_log() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for name in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(root.join(name), format!("contents of {name}")).unwrap();
        }

        let enc_keys = Arc::new(test_keys());
        let prefix = "rfm/".to_string();
        let store = Arc::new(MemoryStore::new());

        // Make only b.txt's content upload fail.
        let b_key = format!(
            "{prefix}{}",
            filename::object_key(&enc_keys.name_key, "b.txt").unwrap()
        );
        store.fail_put_for(b_key);

        let mut state = State::open(root).unwrap();
        let baseline = state.baseline().unwrap();
        let entries = Scanner::new(root, ".mirrorignore").scan(&baseline).unwrap();
        let mut manifest = Manifest::new();
        let plan = reconcile(&entries, &baseline, &manifest);

        apply(
            &plan,
            Arc::clone(&store),
            root.to_path_buf(),
            prefix.clone(),
            &mut state,
            &mut manifest,
            Arc::clone(&enc_keys),
            Arc::new(PrintReporter {}),
            &0,
        )
        .await
        .expect("a single failed upload must not fail the whole apply");

        // The failed file left no baseline row; the succeeded ones did.
        let baseline = state.baseline().unwrap();
        assert!(baseline.contains_key("a.txt"));
        assert!(baseline.contains_key("c.txt"));
        assert!(
            !baseline.contains_key("b.txt"),
            "a failed upload must not be confirmed in the baseline"
        );

        // The log records exactly the confirmed files — baseline never leads it.
        let delta_log = manifest::read_deltas(store.as_ref(), &prefix)
            .await
            .unwrap();
        let merged = manifest::merge_deltas(&Manifest::new(), &delta_log.deltas).manifest;
        assert!(merged.contains_key("a.txt"));
        assert!(merged.contains_key("c.txt"));
        assert!(!merged.contains_key("b.txt"));

        // The data-loss check: re-reconciling must not delete any local file, and
        // must re-plan the failed upload.
        let baseline = state.baseline().unwrap();
        let entries = Scanner::new(root, ".mirrorignore").scan(&baseline).unwrap();
        let plan = reconcile(&entries, &baseline, &merged);
        assert_eq!(
            plan.count(ActionKind::DeleteLocal),
            0,
            "a partial-batch failure must never turn into a local delete"
        );
        assert!(
            plan.actions
                .iter()
                .any(|a| a.path == "b.txt" && a.kind == ActionKind::Upload),
            "the failed upload should be retried"
        );
    }

    /// Phase 1's stated exit criteria, as a test: sync a tree, mutate, re-sync;
    /// a second empty root converges to an identical tree via a shared `MemoryStore`.
    #[tokio::test]
    async fn round_trip_two_devices_converge() {
        async fn sync_once(
            root: &Path,
            store: Arc<MemoryStore>,
            prefix: &str,
            enc_keys: Arc<DerivedSubKeys>,
        ) {
            let mut state = State::open(root).unwrap();
            let baseline = state.baseline().unwrap();

            let scanner = Scanner::new(root, ".mirrorignore");
            let entries = scanner.scan(&baseline).unwrap();

            let snapshot =
                manifest::from_store(store.as_ref(), &enc_keys.manifest_key, prefix, &mut state)
                    .await
                    .unwrap();
            let delta_log = manifest::read_deltas(store.as_ref(), prefix).await.unwrap();
            let MergeResult {
                mut manifest,
                conflicts,
                remote_lamport,
            } = manifest::merge_deltas(&snapshot.manifest, &delta_log.deltas);
            let plan = reconcile(&entries, &baseline, &manifest);
            let reporter = PrintReporter {};

            for conflict in conflicts {
                println!("WARN: conflict at {}", conflict.winner.path);
            }

            apply(
                &plan,
                store,
                root.to_path_buf(),
                prefix.to_string(),
                &mut state,
                &mut manifest,
                enc_keys,
                Arc::new(reporter),
                &remote_lamport,
            )
            .await
            .unwrap();
            state.record_scan(&entries).unwrap();
        }

        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        let store = Arc::new(MemoryStore::new());
        let prefix = "rfm/";

        // Both "devices" share one derived key, same as two machines deriving the
        // same content key from the same passphrase — a fresh key per sync_once
        // call would mean root_a and root_b can never decrypt each other's uploads.
        let mut content_enc_key = [0u8; 32];
        rng().fill(&mut content_enc_key);
        let content_enc_key = SecretBox::new(Box::new(content_enc_key));

        let mut manifest_enc_key = [0u8; 32];
        rng().fill(&mut manifest_enc_key);
        let manifest_enc_key = SecretBox::new(Box::new(manifest_enc_key));

        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        let mut keycheck_bytes = [0u8; 32];
        rng().fill(&mut keycheck_bytes);
        let keycheck_bytes = SecretBox::new(Box::new(keycheck_bytes));

        std::fs::write(root_a.path().join("a.txt"), b"one").unwrap();
        std::fs::write(root_a.path().join("b.txt"), b"two").unwrap();

        let enc_keys = Arc::new(DerivedSubKeys {
            content_key: content_enc_key,
            name_key: name_enc_key,
            manifest_key: manifest_enc_key,
            keycheck_bytes,
        });

        sync_once(
            root_a.path(),
            Arc::clone(&store),
            prefix,
            Arc::clone(&enc_keys),
        )
        .await; // uploads a.txt, b.txt
        sync_once(
            root_b.path(),
            Arc::clone(&store),
            prefix,
            Arc::clone(&enc_keys),
        )
        .await; // downloads both

        assert_eq!(
            std::fs::read(root_b.path().join("a.txt")).unwrap(),
            b"one".to_vec()
        );
        assert_eq!(
            std::fs::read(root_b.path().join("b.txt")).unwrap(),
            b"two".to_vec()
        );

        // mutate on A, both sides re-sync, B picks up the change
        std::fs::write(root_a.path().join("a.txt"), b"one-changed").unwrap();
        sync_once(
            root_a.path(),
            Arc::clone(&store),
            prefix,
            Arc::clone(&enc_keys),
        )
        .await;
        sync_once(
            root_b.path(),
            Arc::clone(&store),
            prefix,
            Arc::clone(&enc_keys),
        )
        .await;

        assert_eq!(
            std::fs::read(root_b.path().join("a.txt")).unwrap(),
            b"one-changed".to_vec()
        );

        // delete on A, both sides re-sync, B loses it too
        std::fs::remove_file(root_a.path().join("b.txt")).unwrap();
        sync_once(
            root_a.path(),
            Arc::clone(&store),
            prefix,
            Arc::clone(&enc_keys),
        )
        .await;
        sync_once(
            root_b.path(),
            Arc::clone(&store),
            prefix,
            Arc::clone(&enc_keys),
        )
        .await;

        assert!(!root_b.path().join("b.txt").exists());
    }
}
