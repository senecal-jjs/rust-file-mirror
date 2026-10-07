//! One full sync pass, store-agnostic. This is the single orchestration the CLI
//! `sync` command and the background daemon both drive: read the remote log,
//! merge it, reconcile against the local tree, finish any interrupted uploads,
//! apply the plan, and record the new baseline. Kept generic over `ObjectStore`
//! so it runs against the real `S3Store` and the in-memory test store alike.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::apply::apply;
use crate::apply::evict::{
    self, EvictOutcome, Skip, pending_upload_paths, plan_policy_evictions, plan_space_evictions,
    space_candidates,
};
use crate::apply::remote_conflict::preserve_conflict_losers;
use crate::apply::upload::resume_upload;
use crate::config::OfflineConfig;
use crate::crypto::filename;
use crate::crypto::key::DerivedSubKeys;
use crate::engine::{Action, ActionKind, Plan, ResidencyView, reconcile_with};
use crate::indicator::ProgressReporter;
use crate::manifest::{self, DeltaEntry, Manifest, MergeResult, merge_deltas, read_deltas};
use crate::placeholder;
use crate::residency::Policy;
use crate::scanner::{ScanResult, Scanner};
use crate::state::State;
use crate::store::ObjectStore;
use crate::util::file::hash_stable;
use crate::{Error, Result};

/// Upper bound on files auto-evicted per pass, so one pass can't churn the whole tree.
const MAX_AUTO_EVICTIONS_PER_PASS: usize = 1000;

/// What a sync pass ended up doing, so callers can report it.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SyncOutcome {
    pub uploads: usize,
    pub downloads: usize,
    pub deletes_local: usize,
    pub deletes_remote: usize,
    pub conflicts: usize,
    pub hydrated: usize,
    pub placeholders: usize,
    pub relocated: usize,
    pub evicted: usize,
    pub bytes_freed: u64,
    /// Eviction candidates left in place, and why.
    pub not_evicted: Vec<(String, Skip)>,
}

impl SyncOutcome {
    pub fn is_noop(&self) -> bool {
        self.uploads == 0
            && self.downloads == 0
            && self.deletes_local == 0
            && self.deletes_remote == 0
            && self.conflicts == 0
            && self.hydrated == 0
            && self.placeholders == 0
            && self.relocated == 0
            && self.evicted == 0
    }
}

/// Free-space thresholds for automatic eviction.
#[derive(Debug, Clone, Copy)]
pub struct SpaceTarget {
    pub min_free: u64,
    pub target_free: u64,
}

/// Device-local residency settings for one pass.
#[derive(Default)]
pub struct SyncOptions {
    pub policy: Policy,
    /// Placeholders to hydrate this pass.
    pub hydrate: BTreeSet<String>,
    /// Files to evict after this pass. Explicit requests skip the grace period.
    pub evict: BTreeSet<String>,
    /// Policy-driven eviction waits this long after a file's last confirmed sync.
    pub evict_grace: Duration,
    pub evict_min_size: u64,
    pub verify_before_evict: bool,
    pub space: Option<SpaceTarget>,
}

impl SyncOptions {
    pub fn from_config(config: &OfflineConfig, state: &State) -> Result<Self> {
        Ok(Self {
            policy: config.policy(&state.pins()?)?,
            evict_grace: config.evict_grace(),
            evict_min_size: config.evict_min_size,
            verify_before_evict: config.verify_before_evict,
            space: config.auto_evict.then_some(SpaceTarget {
                min_free: config.min_free_space,
                target_free: config.target_free_space,
            }),
            ..Self::default()
        })
    }
}

/// Everything a pass works out before it writes anything.
pub struct PassPlan {
    pub plan: Plan,
    pub manifest: Manifest,
    pub scan: ScanResult,
    pub remote_lamport: u64,
}

/// Reads and merges the remote log, preserves conflict losers, scans, and reconciles.
/// Only local side effects: renaming conflict losers aside and dropping stale placeholders.
pub async fn plan_pass<S: ObjectStore>(
    store: &S,
    root: &Path,
    prefix: &str,
    ignore_file: &str,
    enc_keys: &DerivedSubKeys,
    state: &mut State,
    options: &SyncOptions,
) -> Result<PassPlan> {
    let snapshot = manifest::from_store(store, &enc_keys.manifest_key, prefix, state).await?;
    let delta_log = read_deltas(store, prefix).await?;
    let MergeResult {
        manifest,
        conflicts,
        remote_lamport,
    } = merge_deltas(&snapshot.manifest, &delta_log.deltas);

    // Must run before the scan so it sees this device's losing files under their
    // new conflicted-copy names.
    let preserved = preserve_conflict_losers(&conflicts, root, state)?;

    let baseline = state.baseline()?;
    let mut scan = Scanner::new(root, ignore_file).scan_all(&baseline)?;

    // A real file wins over its own placeholder (e.g. after an interrupted eviction).
    let real: BTreeSet<&str> = scan.entries.iter().map(|e| e.path.as_str()).collect();
    let stale: Vec<String> = scan
        .placeholders
        .iter()
        .filter(|(path, meta)| real.contains(path.as_str()) && meta.path == **path)
        .map(|(path, _)| path.clone())
        .collect();
    for path in stale {
        placeholder::remove(root, &path)?;
        scan.placeholders.remove(&path);
    }

    let view = ResidencyView {
        placeholders: &scan.placeholders,
        policy: &options.policy,
        hydrate: &options.hydrate,
    };
    let mut plan = reconcile_with(&scan.entries, &baseline, &manifest, &view);

    for (to, loser) in preserved.relocations {
        // Advance the loser's own path only once its bytes are relocated; a hydrate
        // would advance it unconditionally.
        for action in &mut plan.actions {
            if action.path == loser.path && action.kind == ActionKind::Hydrate {
                action.kind = ActionKind::UpdatePlaceholder;
            }
        }
        plan.actions.push(Action {
            path: to.clone(),
            kind: ActionKind::Relocate,
        });
        plan.relocations.insert(to, loser);
    }
    plan.actions
        .sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.path.cmp(&b.path)));

    Ok(PassPlan {
        plan,
        manifest,
        scan,
        remote_lamport,
    })
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
    options: &SyncOptions,
) -> Result<SyncOutcome> {
    let PassPlan {
        mut plan,
        mut manifest,
        scan,
        remote_lamport,
    } = plan_pass(
        store.as_ref(),
        root,
        prefix,
        ignore_file,
        &enc_keys,
        state,
        options,
    )
    .await?;

    let resumed = resume_uploads(
        state,
        store.as_ref(),
        &mut manifest,
        &enc_keys,
        root,
        prefix,
        remote_lamport,
    )
    .await?;

    // A resumed upload is already fully on the remote, but the plan was built
    // before it finished — drop its now-redundant Upload action.
    plan.actions
        .retain(|action| !(action.kind == ActionKind::Upload && resumed.contains(&action.path)));

    let mut outcome = SyncOutcome {
        uploads: plan.count(ActionKind::Upload),
        downloads: plan.count(ActionKind::Download),
        deletes_local: plan.count(ActionKind::DeleteLocal),
        deletes_remote: plan.count(ActionKind::DeleteRemote),
        conflicts: plan.count(ActionKind::Conflict),
        hydrated: plan.count(ActionKind::Hydrate),
        placeholders: plan.count(ActionKind::CreatePlaceholder)
            + plan.count(ActionKind::UpdatePlaceholder),
        relocated: plan.count(ActionKind::Relocate),
        ..SyncOutcome::default()
    };

    apply(
        &plan,
        Arc::clone(&store),
        root.to_path_buf(),
        prefix.to_string(),
        state,
        &mut manifest,
        Arc::clone(&enc_keys),
        Arc::clone(&reporter),
        &remote_lamport,
    )
    .await?;

    state.record_scan(&scan.entries)?;

    let evicted = evict_pass(
        store.as_ref(),
        root,
        prefix,
        state,
        &manifest,
        &enc_keys,
        reporter.as_ref(),
        options,
    )
    .await?;

    outcome.evicted = evicted.evicted.len();
    outcome.bytes_freed = evicted.bytes_freed;
    outcome.not_evicted = evicted.skipped;

    Ok(outcome)
}

/// Runs after the pass's own baseline updates, so it only ever evicts files this
/// pass has confirmed are in sync.
#[allow(clippy::too_many_arguments)]
async fn evict_pass<S: ObjectStore>(
    store: &S,
    root: &Path,
    prefix: &str,
    state: &mut State,
    manifest: &Manifest,
    enc_keys: &DerivedSubKeys,
    reporter: &dyn ProgressReporter,
    options: &SyncOptions,
) -> Result<EvictOutcome> {
    let baseline = state.baseline()?;
    let pending = pending_upload_paths(state)?;
    let now = i64::try_from(crate::util::time::unix_timestamp()).unwrap_or(i64::MAX);

    let mut paths = options.evict.clone();
    paths.extend(plan_policy_evictions(
        &baseline,
        manifest,
        &pending,
        &options.policy,
        options.evict_grace,
        now,
    ));

    if let Some(space) = options.space {
        let available = fs2::available_space(root).map_err(|source| Error::Io {
            path: root.to_path_buf(),
            source,
        })?;

        if available < space.min_free {
            let candidates = space_candidates(
                root,
                &baseline,
                manifest,
                &pending,
                &options.policy,
                options.evict_grace,
                options.evict_min_size,
                now,
            )
            .into_iter()
            .filter(|candidate| !paths.contains(&candidate.path))
            .collect();

            paths.extend(plan_space_evictions(
                candidates,
                space.target_free.saturating_sub(available),
                MAX_AUTO_EVICTIONS_PER_PASS,
            ));
        }
    }

    if paths.is_empty() {
        return Ok(EvictOutcome::default());
    }

    evict::evict(
        store,
        root,
        prefix,
        state,
        manifest,
        &paths,
        enc_keys,
        options.verify_before_evict,
        reporter,
    )
    .await
}

/// Finishes every multipart upload an interrupted sync left behind, returning the
/// paths that completed so the caller can drop their redundant `Upload` actions.
/// Like `apply`, it logs the deltas before confirming any baseline.
async fn resume_uploads<S: ObjectStore>(
    state: &mut State,
    store: &S,
    manifest: &mut Manifest,
    enc_keys: &DerivedSubKeys,
    root: &Path,
    prefix: &str,
    remote_lamport: u64,
) -> Result<Vec<String>> {
    let uploads = state.pending_uploads()?;
    let lamport = remote_lamport.max(state.get_latest_lamport()?) + 1;
    let mut completed = Vec::new();

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

        // A vanished or unreadable file can't be resumed either.
        match hash_stable(&local_path).ok().flatten() {
            Some(stats) if stats.2 == upload.content_hash => {
                let result =
                    match resume_upload(store, &upload, stats, enc_keys, root, prefix, state).await
                    {
                        Ok(result) => result,
                        // The remote multipart is gone or its parts don't match.
                        // resume_upload already cleared the local record, so skip it —
                        // reconcile will re-plan a fresh upload next.
                        Err(Error::UploadGone(msg)) => {
                            tracing::warn!(path = %path_str, "{msg}; re-uploading from scratch");
                            continue;
                        }
                        Err(e) => return Err(e),
                    };

                // What this device believed was current for this path before its
                // own edit — the merge rule compares an incoming delta's base_hash
                // against this.
                let base_hash = manifest.get(&path_str).map(|e| e.plaintext_hash);
                let mtime_utc = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let entry = DeltaEntry {
                    path: path_str.clone(),
                    object_key: result.object_key.clone(),
                    plaintext_hash: result.content_hash,
                    size: result.size,
                    mtime_utc,
                    deleted: false,
                    deleted_at: 0,
                    lamport,
                    device_id: state.device_id()?,
                    base_hash,
                };
                completed.push((entry, result));
            }
            // The file changed or vanished since the interrupted upload started, so
            // the stale multipart can't be resumed safely — drop tracking and abort
            // it so it doesn't accrue storage charges.
            _ => {
                state.clear_upload(&path_str)?;
                let object_key =
                    filename::object_key(&enc_keys.name_key, &path_str, &upload.content_hash)?;
                let store_key = format!("{prefix}{object_key}");
                store
                    .abort_multipart_upload(&store_key, &upload.upload_id)
                    .await?;
            }
        }
    }

    if completed.is_empty() {
        return Ok(Vec::new());
    }

    let deltas: Vec<DeltaEntry> = completed.iter().map(|(entry, _)| entry.clone()).collect();
    manifest::log_delta(store, state, prefix, &deltas, &lamport, 0).await?;
    // Claim this lamport so `apply`'s own delta keys can't collide with this one.
    state.record_lamport(lamport)?;

    let mut resumed = Vec::new();
    for (entry, result) in completed {
        state.confirm_sync(
            &entry.path,
            result.size,
            result.mtime_ns,
            result.content_hash,
        )?;
        resumed.push(entry.path.clone());
        manifest.insert(entry.path.clone(), entry);
    }

    Ok(resumed)
}
