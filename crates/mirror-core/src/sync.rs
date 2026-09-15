//! One full sync pass, store-agnostic. This is the single orchestration the CLI
//! `sync` command and the background daemon both drive: read the remote log,
//! merge it, reconcile against the local tree, finish any interrupted uploads,
//! apply the plan, and record the new baseline. Kept generic over `ObjectStore`
//! so it runs against the real `S3Store` and the in-memory test store alike.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::apply::apply;
use crate::apply::remote_conflict::preserve_conflict_losers;
use crate::apply::upload::resume_upload;
use crate::crypto::filename;
use crate::crypto::key::DerivedSubKeys;
use crate::engine::{ActionKind, reconcile};
use crate::indicator::ProgressReporter;
use crate::manifest::{self, DeltaEntry, Manifest, MergeResult, merge_deltas, read_deltas};
use crate::scanner::Scanner;
use crate::state::State;
use crate::store::ObjectStore;
use crate::util::file::hash_stable;
use crate::{Error, Result};

/// What a sync pass ended up doing, so callers can report it.
#[derive(Debug, Default, Clone, Copy)]
pub struct SyncOutcome {
    pub uploads: usize,
    pub downloads: usize,
    pub deletes_local: usize,
    pub deletes_remote: usize,
    pub conflicts: usize,
}

impl SyncOutcome {
    pub fn is_noop(&self) -> bool {
        self.uploads == 0
            && self.downloads == 0
            && self.deletes_local == 0
            && self.deletes_remote == 0
            && self.conflicts == 0
    }
}

/// Runs one complete sync pass against an already-connected store, with keys and
/// state supplied by the caller (the daemon holds these across many passes).
#[allow(clippy::too_many_arguments)]
pub async fn sync_once<S: ObjectStore + 'static>(
    store: Arc<S>,
    root: &Path,
    prefix: &str,
    ignore_file: &str,
    enc_keys: Arc<DerivedSubKeys>,
    state: &mut State,
    reporter: Arc<dyn ProgressReporter>,
) -> Result<SyncOutcome> {
    let snapshot =
        manifest::from_store(store.as_ref(), &enc_keys.manifest_key, prefix, state).await?;
    let delta_log = read_deltas(store.as_ref(), prefix).await?;
    let MergeResult {
        mut manifest,
        conflicts,
        remote_lamport,
    } = merge_deltas(&snapshot.manifest, &delta_log.deltas);

    // Must run before the scan so it sees this device's losing files under their
    // new conflicted-copy names.
    preserve_conflict_losers(&conflicts, root, state)?;

    let baseline = state.baseline()?;
    let entries = Scanner::new(root, ignore_file).scan(&baseline)?;
    let mut plan = reconcile(&entries, &baseline, &manifest);

    let resumed = resume_uploads(
        state,
        store.as_ref(),
        &mut manifest,
        &enc_keys,
        root,
        prefix,
    )
    .await?;

    // A resumed upload is already fully on the remote, but the plan was built
    // before it finished — drop its now-redundant Upload action.
    plan.actions
        .retain(|action| !(action.kind == ActionKind::Upload && resumed.contains(&action.path)));

    let outcome = SyncOutcome {
        uploads: plan.count(ActionKind::Upload),
        downloads: plan.count(ActionKind::Download),
        deletes_local: plan.count(ActionKind::DeleteLocal),
        deletes_remote: plan.count(ActionKind::DeleteRemote),
        conflicts: plan.count(ActionKind::Conflict),
    };

    apply(
        &plan,
        Arc::clone(&store),
        root.to_path_buf(),
        prefix.to_string(),
        state,
        &mut manifest,
        Arc::clone(&enc_keys),
        reporter,
        &remote_lamport,
    )
    .await?;

    state.record_scan(&entries)?;

    Ok(outcome)
}

/// Finishes every multipart upload an interrupted sync left behind, returning the
/// paths that completed so the caller can drop their redundant `Upload` actions.
async fn resume_uploads<S: ObjectStore>(
    state: &mut State,
    store: &S,
    manifest: &mut Manifest,
    enc_keys: &DerivedSubKeys,
    root: &Path,
    prefix: &str,
) -> Result<Vec<String>> {
    let uploads = state.pending_uploads()?;
    let mut resumed = Vec::new();

    for upload in uploads {
        let path_str = upload
            .path
            .to_str()
            .ok_or_else(|| {
                Error::State(format!(
                    "non-UTF8 path in pending upload: {:?}",
                    upload.path
                ))
            })?
            .to_string();
        let local_path = root.join(&upload.path);

        match hash_stable(&local_path)? {
            Some(stats) if stats.2 == upload.content_hash => {
                let result =
                    resume_upload(store, &upload, stats, enc_keys, root, prefix, state).await?;

                // What this device believed was current for this path before its
                // own edit — the merge rule compares an incoming delta's base_hash
                // against this.
                let base_hash = manifest.get(&path_str).map(|e| e.plaintext_hash);
                let mtime_utc = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                manifest.insert(
                    path_str.clone(),
                    DeltaEntry {
                        path: path_str.clone(),
                        object_key: result.object_key,
                        plaintext_hash: result.content_hash,
                        size: result.size,
                        mtime_utc,
                        deleted: false,
                        deleted_at: 0,
                        lamport: state.get_latest_lamport()?,
                        device_id: state.device_id()?,
                        base_hash,
                    },
                );
                state.confirm_sync(&path_str, result.size, result.mtime_ns, result.content_hash)?;
                resumed.push(path_str);
            }
            // The file changed or vanished since the interrupted upload started, so
            // the stale multipart can't be resumed safely — drop tracking and abort
            // it so it doesn't accrue storage charges.
            _ => {
                state.clear_upload(&path_str)?;
                let object_key = filename::object_key(&enc_keys.name_key, &path_str)?;
                let store_key = format!("{prefix}{object_key}");
                store
                    .abort_multipart_upload(&store_key, &upload.upload_id)
                    .await?;
            }
        }
    }

    Ok(resumed)
}
