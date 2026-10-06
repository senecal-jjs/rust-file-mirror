//! Device-local eviction: replace a synced file's bytes with a placeholder. Planning
//! is pure; `evict` does the IO in an order where every crash point is recoverable
//! (a real file always wins over its placeholder).

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use crate::{
    Error, Result,
    apply::{download::fetch_verified, safe_join},
    crypto::{content::ciphertext_len, key::DerivedSubKeys},
    indicator::ProgressReporter,
    manifest::Manifest,
    placeholder::{self, StubMeta},
    residency::{Mode, Policy},
    state::{Baseline, FileRecord, State},
    store::ObjectStore,
    util::{
        file::{file_stat, hash_stable},
        time::unix_timestamp,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    NotTracked,
    AlreadyEvicted,
    /// Local bytes or the remote differ from the last confirmed sync.
    NotSynced,
    PendingUpload,
    /// The remote object is missing, the wrong size, or failed verification.
    RemoteUnverified,
    /// The file changed while being evicted; it was put back.
    Changed,
}

impl std::fmt::Display for Skip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Self::NotTracked => "not tracked",
            Self::AlreadyEvicted => "already online-only",
            Self::NotSynced => "not in sync",
            Self::PendingUpload => "upload pending",
            Self::RemoteUnverified => "remote copy unverified",
            Self::Changed => "changed during eviction",
        })
    }
}

#[derive(Debug, Default)]
pub struct EvictOutcome {
    pub evicted: Vec<String>,
    pub bytes_freed: u64,
    pub skipped: Vec<(String, Skip)>,
}

/// Pure safety check: the local bytes, the baseline and the remote all agree.
pub fn eligible(
    record: Option<&FileRecord>,
    manifest: &Manifest,
    pending_uploads: &BTreeSet<String>,
) -> std::result::Result<(), Skip> {
    let record = record.ok_or(Skip::NotTracked)?;

    if record.is_evicted() {
        return Err(Skip::AlreadyEvicted);
    }
    if record.last_synced_hash != Some(record.content_hash) {
        return Err(Skip::NotSynced);
    }
    if pending_uploads.contains(&record.path) {
        return Err(Skip::PendingUpload);
    }

    match manifest.get(&record.path) {
        Some(entry) if !entry.deleted && entry.plaintext_hash == record.content_hash => Ok(()),
        _ => Err(Skip::NotSynced),
    }
}

fn past_grace(record: &FileRecord, grace: Duration, now_secs: i64) -> bool {
    // Rows from before sync times were tracked are long settled.
    record.synced_at.is_none_or(|synced| {
        now_secs.saturating_sub(synced) >= i64::try_from(grace.as_secs()).unwrap_or(i64::MAX)
    })
}

/// Files pinned online-only that are safe to evict now.
pub fn plan_policy_evictions(
    baseline: &Baseline,
    manifest: &Manifest,
    pending_uploads: &BTreeSet<String>,
    policy: &Policy,
    grace: Duration,
    now_secs: i64,
) -> Vec<String> {
    baseline
        .values()
        .filter(|record| policy.mode(&record.path) == Mode::OnlineOnly)
        .filter(|record| eligible(Some(record), manifest, pending_uploads).is_ok())
        .filter(|record| past_grace(record, grace, now_secs))
        .map(|record| record.path.clone())
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: String,
    /// Bytes actually freed (allocated blocks, not logical size).
    pub bytes: u64,
    /// Unix seconds of the most recent known use.
    pub last_used: i64,
}

/// Least-recently-used first, until `bytes_needed` would be freed or `max_files` reached.
pub fn plan_space_evictions(
    mut candidates: Vec<Candidate>,
    bytes_needed: u64,
    max_files: usize,
) -> Vec<String> {
    candidates.sort_by(|a, b| a.last_used.cmp(&b.last_used).then(a.path.cmp(&b.path)));

    let mut freed = 0u64;
    let mut picked = Vec::new();

    for candidate in candidates {
        if freed >= bytes_needed || picked.len() >= max_files {
            break;
        }
        freed += candidate.bytes;
        picked.push(candidate.path);
    }

    picked
}

/// `Auto` files eligible for space-driven eviction, with their on-disk cost and last use.
#[allow(clippy::too_many_arguments)]
pub fn space_candidates(
    root: &Path,
    baseline: &Baseline,
    manifest: &Manifest,
    pending_uploads: &BTreeSet<String>,
    policy: &Policy,
    grace: Duration,
    min_size: u64,
    now_secs: i64,
) -> Vec<Candidate> {
    baseline
        .values()
        .filter(|record| policy.mode(&record.path) == Mode::Auto && record.size >= min_size)
        .filter(|record| eligible(Some(record), manifest, pending_uploads).is_ok())
        .filter(|record| past_grace(record, grace, now_secs))
        .filter_map(|record| {
            let meta = std::fs::metadata(root.join(&record.path)).ok()?;
            let secs = |time: std::io::Result<std::time::SystemTime>| {
                time.ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            };
            let last_used = secs(meta.accessed())
                .max(secs(meta.modified()))
                .max(record.last_hydrated_at.unwrap_or(0));

            Some(Candidate {
                path: record.path.clone(),
                bytes: allocated_bytes(&meta),
                last_used,
            })
        })
        .collect()
}

#[cfg(unix)]
fn allocated_bytes(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.blocks() * 512
}

#[cfg(not(unix))]
fn allocated_bytes(meta: &std::fs::Metadata) -> u64 {
    meta.len()
}

pub fn pending_upload_paths(state: &State) -> Result<BTreeSet<String>> {
    Ok(state
        .pending_uploads()?
        .into_iter()
        .filter_map(|upload| upload.path.to_str().map(str::to_string))
        .collect())
}

#[allow(clippy::too_many_arguments)]
pub async fn evict<S: ObjectStore>(
    store: &S,
    root: &Path,
    prefix: &str,
    state: &mut State,
    manifest: &Manifest,
    paths: &BTreeSet<String>,
    enc_keys: &DerivedSubKeys,
    verify: bool,
    reporter: &dyn ProgressReporter,
) -> Result<EvictOutcome> {
    let baseline = state.baseline()?;
    let pending = pending_upload_paths(state)?;
    let mut outcome = EvictOutcome::default();

    for path in paths {
        match evict_one(
            store,
            root,
            prefix,
            state,
            manifest,
            baseline.get(path),
            &pending,
            enc_keys,
            verify,
            reporter,
        )
        .await?
        {
            Ok(freed) => {
                outcome.evicted.push(path.clone());
                outcome.bytes_freed += freed;
            }
            Err(skip) => outcome.skipped.push((path.clone(), skip)),
        }
    }

    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
async fn evict_one<S: ObjectStore>(
    store: &S,
    root: &Path,
    prefix: &str,
    state: &mut State,
    manifest: &Manifest,
    record: Option<&FileRecord>,
    pending: &BTreeSet<String>,
    enc_keys: &DerivedSubKeys,
    verify: bool,
    reporter: &dyn ProgressReporter,
) -> Result<std::result::Result<u64, Skip>> {
    if let Err(skip) = eligible(record, manifest, pending) {
        return Ok(Err(skip));
    }
    let record = record.expect("eligible implies a record");
    let entry = &manifest[&record.path];
    let local = safe_join(root, &record.path)?;

    let Some((size, mtime_ns, hash)) = hash_stable(&local)? else {
        return Ok(Err(Skip::Changed));
    };
    if hash != entry.plaintext_hash {
        return Ok(Err(Skip::NotSynced));
    }

    let store_key = format!("{prefix}{}", entry.object_key);
    let remote_ok = store
        .head(&store_key)
        .await?
        .is_some_and(|meta| meta.size == ciphertext_len(entry.size));
    if !remote_ok {
        return Ok(Err(Skip::RemoteUnverified));
    }
    if verify
        && fetch_verified(
            store,
            root,
            prefix,
            entry,
            &record.path,
            &enc_keys.content_key,
            reporter,
        )
        .await
        .is_err()
    {
        return Ok(Err(Skip::RemoteUnverified));
    }

    let freed = std::fs::metadata(&local)
        .map(|meta| allocated_bytes(&meta))
        .unwrap_or(size);

    state.mark_evicted(&record.path)?;
    placeholder::write(
        root,
        &StubMeta::new(
            &record.path,
            size,
            hash,
            &entry.object_key,
            unix_timestamp(),
        ),
    )?;

    // Move aside first, so a writer racing with us is detected by the re-stat.
    let aside = root
        .join(".mirror/tmp")
        .join(format!("evicting-{}", uuid::Uuid::new_v4().simple()));
    std::fs::rename(&local, &aside).map_err(|source| Error::Io {
        path: local.clone(),
        source,
    })?;

    let after = file_stat(&aside)?;
    if after.size != size || after.mtime_ns != mtime_ns {
        std::fs::rename(&aside, &local).map_err(|source| Error::Io {
            path: aside.clone(),
            source,
        })?;
        placeholder::remove(root, &record.path)?;
        state.mark_local(&record.path)?;
        return Ok(Err(Skip::Changed));
    }

    std::fs::remove_file(&aside).map_err(|source| Error::Io {
        path: aside.clone(),
        source,
    })?;

    if let Some(parent) = local.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all(); // best effort
    }

    Ok(Ok(freed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{ContentHash, hash_bytes};
    use crate::manifest::DeltaEntry;
    use crate::state::Residency;

    fn entry(path: &str, hash: ContentHash) -> DeltaEntry {
        DeltaEntry {
            path: path.to_string(),
            object_key: format!("data/{path}"),
            plaintext_hash: hash,
            size: 1,
            mtime_utc: 0,
            deleted: false,
            deleted_at: 0,
            lamport: 1,
            device_id: "d".to_string(),
            base_hash: None,
        }
    }

    #[test]
    fn eligibility_requires_full_agreement() {
        let h1 = hash_bytes(b"1");
        let h2 = hash_bytes(b"2");
        let manifest = Manifest::from([("f".to_string(), entry("f", h1))]);
        let none = BTreeSet::new();
        let synced = FileRecord::synced("f", 1, h1);

        assert_eq!(eligible(Some(&synced), &manifest, &none), Ok(()));
        assert_eq!(eligible(None, &manifest, &none), Err(Skip::NotTracked));

        let edited = FileRecord {
            content_hash: h2,
            ..synced.clone()
        };
        assert_eq!(
            eligible(Some(&edited), &manifest, &none),
            Err(Skip::NotSynced)
        );

        let evicted = FileRecord {
            residency: Residency::Evicted,
            ..synced.clone()
        };
        assert_eq!(
            eligible(Some(&evicted), &manifest, &none),
            Err(Skip::AlreadyEvicted)
        );

        let pending = BTreeSet::from(["f".to_string()]);
        assert_eq!(
            eligible(Some(&synced), &manifest, &pending),
            Err(Skip::PendingUpload)
        );

        let moved_on = Manifest::from([("f".to_string(), entry("f", h2))]);
        assert_eq!(
            eligible(Some(&synced), &moved_on, &none),
            Err(Skip::NotSynced)
        );
    }

    #[test]
    fn policy_evictions_respect_pins_and_grace() {
        let h = hash_bytes(b"1");
        let manifest = Manifest::from([
            ("archive/a".to_string(), entry("archive/a", h)),
            ("archive/b".to_string(), entry("archive/b", h)),
            ("keep".to_string(), entry("keep", h)),
        ]);
        let mut baseline = Baseline::new();
        for path in ["archive/a", "archive/b", "keep"] {
            let mut record = FileRecord::synced(path, 1, h);
            record.synced_at = Some(if path == "archive/b" { 990 } else { 0 });
            baseline.insert(path.to_string(), record);
        }
        let policy = Policy::new(&[], &[], &["archive/**".to_string()], false).unwrap();

        let planned = plan_policy_evictions(
            &baseline,
            &manifest,
            &BTreeSet::new(),
            &policy,
            Duration::from_secs(60),
            1000,
        );

        assert_eq!(planned, vec!["archive/a".to_string()]);
    }

    #[test]
    fn space_evictions_take_least_recently_used_until_enough_is_freed() {
        let c = |path: &str, bytes, last_used| Candidate {
            path: path.to_string(),
            bytes,
            last_used,
        };
        let candidates = vec![c("new", 100, 30), c("old", 100, 10), c("mid", 100, 20)];

        assert_eq!(
            plan_space_evictions(candidates.clone(), 150, 10),
            vec!["old".to_string(), "mid".to_string()]
        );
        assert_eq!(
            plan_space_evictions(candidates.clone(), 0, 10),
            Vec::<String>::new()
        );
        assert_eq!(
            plan_space_evictions(candidates, 1000, 1),
            vec!["old".to_string()]
        );
    }
}
