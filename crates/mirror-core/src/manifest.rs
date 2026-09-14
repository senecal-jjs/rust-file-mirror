use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use std::{io::Write, path::Path};

use futures_util::future::join_all;
use regex::Regex;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::crypto::content::encrypt;
use crate::hash::ContentHash;
use crate::state::State;
use crate::store::ObjectMeta;
use crate::{Error, Result, crypto::content::decrypt, store::ObjectStore};

/// Deltas and superseded snapshots younger than this are kept so a device that
/// is mid-read isn't left with a dangling range. Tests inject `Duration::ZERO`
/// to force pruning.
pub const DEFAULT_COMPACTION_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DeltaEntry {
    pub path: String,
    pub object_key: String,
    pub plaintext_hash: ContentHash,
    pub size: u64,
    pub mtime_utc: u64,
    pub deleted: bool,
    pub deleted_at: u64,
    pub lamport: u64,
    pub device_id: String,
    pub base_hash: Option<ContentHash>,
}

pub type Manifest = BTreeMap<String, DeltaEntry>;

fn to_json_bytes(deltas: &[DeltaEntry]) -> Result<Vec<u8>> {
    serde_json::to_vec(deltas).map_err(|e| {
        Error::Store(format!(
            "Failed to serialize deltas. Error: {}, Deltas {:?}",
            e, deltas
        ))
    })
}

fn from_json_bytes(bytes: &[u8]) -> Result<Vec<DeltaEntry>> {
    let manifest = serde_json::from_slice(bytes).map_err(|source| {
        Error::Store(format!(
            "Failed to deserialize manifest from bytes. Error: {}",
            source
        ))
    })?;

    Ok(manifest)
}

fn from_json_path(bytes_path: &Path) -> Result<Vec<DeltaEntry>> {
    let bytes = std::fs::read(bytes_path).map_err(|source| Error::Io {
        path: bytes_path.to_path_buf(),
        source,
    })?;

    from_json_bytes(&bytes)
}

pub struct RemoteConflict {
    pub winner: DeltaEntry,
    pub loser: DeltaEntry,
}

pub struct MergeResult {
    pub manifest: Manifest,
    pub conflicts: Vec<RemoteConflict>,
    pub remote_lamport: u64,
}

pub async fn compact<S: ObjectStore>(
    store: &S,
    manifest_enc_key: &SecretBox<[u8; 32]>,
    prefix: &str,
    state: &mut State,
    grace: Duration,
) -> Result<()> {
    let snapshot = from_store(store, manifest_enc_key, prefix, state).await?;
    let delta_log = read_deltas(store, prefix).await?;
    let merge_result = merge_deltas(&snapshot.manifest, &delta_log.deltas);

    // save new snapshot
    to_store(
        &merge_result.manifest,
        store,
        manifest_enc_key,
        prefix,
        state,
    )
    .await?;

    // fetch and verify snapshot matches, updated manifest
    let latest = from_store(store, manifest_enc_key, prefix, state).await?;

    if merge_result.manifest == latest.manifest {
        for delta_meta in delta_log.metas {
            if let Some(last_modified) = delta_meta.last_modified
                && older_than_grace(last_modified, grace)
            {
                store.delete(&delta_meta.key).await?;
            }
        }

        // key will exist unless there was no previous snapshot
        if let Some(snapshot_object_key) = snapshot.object_key
            && let Some(snapshot_modified_at) = snapshot.modified_at
            && older_than_grace(snapshot_modified_at, grace)
        {
            store.delete(&snapshot_object_key).await?;
        }

        Ok(())
    } else {
        Err(Error::Store(
            "compaction failed due to manifest mis-match".to_string(),
        ))
    }
}

/// Total-order key deciding which of two competing entries for a path wins the
/// merge. `(lamport, device_id)` is the causal order from plan §4.3; the trailing
/// fields only break a degenerate tie deterministically so the merge stays
/// commutative even on malformed input.
#[allow(clippy::type_complexity)]
fn winner_key(
    d: &DeltaEntry,
) -> (
    u64,
    &str,
    &[u8; 32],
    Option<&[u8; 32]>,
    bool,
    u64,
    u64,
    u64,
    &str,
) {
    (
        d.lamport,
        &d.device_id,
        d.plaintext_hash.as_bytes(),
        d.base_hash.as_ref().map(|h| h.as_bytes()),
        d.deleted,
        d.deleted_at,
        d.size,
        d.mtime_utc,
        &d.object_key,
    )
}

pub fn merge_deltas(snapshot: &Manifest, deltas: &[DeltaEntry]) -> MergeResult {
    let mut manifest = snapshot.clone();
    let mut conflicts: Vec<RemoteConflict> = Vec::new();
    let mut lamport = snapshot
        .values()
        .max_by(|x, y| x.lamport.cmp(&y.lamport))
        .map_or(0, |d| d.lamport);

    for delta in deltas {
        // Clone out so the immutable borrow of `manifest` ends before we mutate it.
        match manifest.get(&delta.path).cloned() {
            None => {
                manifest.insert(delta.path.clone(), delta.clone());
            }
            Some(existing) => {
                // The winner is always the causally-latest entry under a total
                // order: (lamport, device_id) as plan §4.3 specifies, then every
                // remaining field so that even a degenerate pair sharing a
                // (lamport, device_id) — which correct clients never emit for one
                // path — still resolves to a single deterministic winner. Picking
                // the max — never anything order-sensitive like fast-forward-accept
                // — is what makes the merge commutative and idempotent: replaying
                // the same deltas in any order, or more than once, yields the same
                // manifest.
                let delta_wins = winner_key(delta) > winner_key(&existing);

                // A conflict is two concurrent writes of *different* content:
                // same content converges, and a delta that descended from the
                // other's content (base_hash matches) is a linear edit, not a
                // fork. base_hash only classifies the conflict — it never decides
                // the winner.
                let same_content = delta.plaintext_hash == existing.plaintext_hash;
                let delta_descends_existing = delta.base_hash == Some(existing.plaintext_hash);
                let existing_descends_delta = existing.base_hash == Some(delta.plaintext_hash);
                let is_conflict =
                    !same_content && !delta_descends_existing && !existing_descends_delta;

                if is_conflict {
                    let conflict = if delta_wins {
                        RemoteConflict {
                            winner: delta.clone(),
                            loser: existing.clone(),
                        }
                    } else {
                        RemoteConflict {
                            winner: existing.clone(),
                            loser: delta.clone(),
                        }
                    };
                    conflicts.push(conflict);
                }

                if delta_wins {
                    manifest.insert(delta.path.clone(), delta.clone());
                }
            }
        }

        if delta.lamport > lamport {
            lamport = delta.lamport
        }
    }

    MergeResult {
        manifest,
        conflicts,
        remote_lamport: lamport,
    }
}

pub async fn log_delta(
    store: &impl ObjectStore,
    state: &mut State,
    prefix: &str,
    log: &[DeltaEntry],
    lamport: &u64,
) -> Result<String> {
    let log_bytes = to_json_bytes(log)?;
    let device_id = state.device_id()?;
    // 20 is max number of digits a u64 an hold
    let formatted_lamport = format!("lamport:{:020}", lamport);
    let store_key = format!("{prefix}log/{}-{}.delta", formatted_lamport, device_id);

    store.put_bytes(&store_key, &log_bytes).await?;

    Ok(store_key)
}

pub struct DeltaLog {
    pub deltas: Vec<DeltaEntry>,
    pub metas: Vec<ObjectMeta>,
}

pub async fn read_deltas(store: &impl ObjectStore, prefix: &str) -> Result<DeltaLog> {
    // read all until compaction in place
    let metas = store.list(format!("{prefix}log/").as_str(), None).await?;
    let results: Vec<Result<Vec<u8>>> =
        join_all(metas.iter().map(|meta| store.get(&meta.key))).await;
    let objects: Vec<Vec<u8>> = results.into_iter().collect::<Result<Vec<_>>>()?;
    let deltas: Vec<Vec<DeltaEntry>> = objects
        .into_iter()
        .map(|object| from_json_bytes(&object))
        .collect::<Result<Vec<_>>>()?;

    Ok(DeltaLog {
        deltas: deltas.into_iter().flatten().collect(),
        metas,
    })
}

pub async fn to_store(
    manifest: &Manifest,
    store: &impl ObjectStore,
    manifest_enc_key: &SecretBox<[u8; 32]>,
    prefix: &str,
    state: &mut State,
) -> Result<()> {
    let snapshot_prefix = format!("{}snapshot", prefix);
    let latest_key = store.list(&snapshot_prefix, None).await?;

    let highest_gen: u64 = if let Some(latest_key) = latest_key.last() {
        extract_generation(&latest_key.key)?
    } else {
        state.highest_manifest_generation()?
    };

    // Every write is one generation past whatever this device has last confirmed —
    // either its own last write, or the highest it has read and accepted from
    // another device.
    let generation = highest_gen + 1;
    let manifest_store_key = format!("{prefix}snapshot/generation{:020}.snap", generation);
    let deltas: Vec<DeltaEntry> = manifest.values().cloned().collect();
    let manifest_bytes = to_json_bytes(&deltas)?;

    // encrypt manifest
    let tmp_dir = PathBuf::from(".mirror/tmp");

    std::fs::create_dir_all(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let mut tmp_input_file = NamedTempFile::new_in(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    tmp_input_file
        .write_all(&manifest_bytes)
        .map_err(|source| Error::Io {
            path: tmp_dir.clone(),
            source,
        })?;

    let tmp_output_file = NamedTempFile::new_in(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    // AAD binds the object identity *and* the generation, so a ciphertext can't be
    // relabeled with a different generation number and still authenticate.
    let associated_data = manifest_store_key.to_string();

    encrypt(
        manifest_enc_key,
        tmp_input_file.path(),
        tmp_output_file.path(),
        &associated_data,
    )?;

    // The generation travels as a plaintext 8-byte prefix ahead of the ciphertext —
    // same idea as the nonce prefix inside it. from_store has to read this before it
    // can even know what AAD to attempt decryption with.
    let encrypted_bytes = std::fs::read(tmp_output_file.path()).map_err(|source| Error::Io {
        path: tmp_output_file.path().to_path_buf(),
        source,
    })?;

    store
        .put_bytes(&manifest_store_key, &encrypted_bytes)
        .await?;

    state.record_manifest_generation(generation)?;

    Ok(())
}

pub struct Snapshot {
    pub manifest: Manifest,
    pub object_key: Option<String>,
    pub modified_at: Option<SystemTime>,
}

pub async fn from_store<S: ObjectStore>(
    store: &S,
    manifest_enc_key: &SecretBox<[u8; 32]>,
    prefix: &str,
    state: &mut State,
) -> Result<Snapshot> {
    // let manifest_store_key = format!("{prefix}{MANIFEST_OBJECT_NAME}");
    let snapshot_prefix = format!("{}snapshot", prefix);
    let object_metas = store.list(&snapshot_prefix, None).await?;

    if let Some(object_meta) = object_metas.last() {
        let encrypted_manifest = store.get(&object_meta.key).await?;
        let highest_remote_gen = extract_generation(&object_meta.key)?;
        let highest_local_gen = state.highest_manifest_generation()?;

        if highest_remote_gen < highest_local_gen {
            return Err(Error::Store(format!(
                "manifest generation {highest_remote_gen} is older than the last one this device has \
                seen ({highest_local_gen}) — refusing a possible rollback"
            )));
        }

        // decrypt manifest
        let tmp_dir = PathBuf::from(".mirror/tmp");

        std::fs::create_dir_all(&tmp_dir).map_err(|source| Error::Io {
            path: tmp_dir.clone(),
            source,
        })?;

        let mut tmp_input_file = NamedTempFile::new_in(&tmp_dir).map_err(|source| Error::Io {
            path: tmp_dir.clone(),
            source,
        })?;

        tmp_input_file
            .write_all(&encrypted_manifest)
            .map_err(|source| Error::Io {
                path: tmp_dir.clone(),
                source,
            })?;

        let tmp_output_file = NamedTempFile::new_in(&tmp_dir).map_err(|source| Error::Io {
            path: tmp_dir.clone(),
            source,
        })?;

        let associated_data = object_meta.key.to_string();

        decrypt(
            manifest_enc_key,
            tmp_input_file.path(),
            tmp_output_file.path(),
            &associated_data,
        )?;

        let manifest: Manifest = from_json_path(tmp_output_file.path())?
            .into_iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect();

        if highest_remote_gen > highest_local_gen {
            state.record_manifest_generation(highest_remote_gen)?;
        }

        Ok(Snapshot {
            manifest,
            object_key: Some(object_meta.key.clone()),
            modified_at: object_meta.last_modified,
        })
    } else {
        Ok(Snapshot {
            manifest: Manifest::new(),
            object_key: None,
            modified_at: Some(SystemTime::now()),
        })
    }
}

fn extract_generation(key: &str) -> Result<u64> {
    let re = Regex::new(r"generation(\d+)").unwrap();
    let caps = re.captures(key).ok_or(Error::Store(
        "failed to capture regex expression for manifest gen".to_string(),
    ))?;
    let generation_str = &caps[1];
    let generation: u64 = generation_str
        .parse()
        .map_err(|_| Error::Store("failed to parse generation int from string".to_string()))?;

    Ok(generation)
}

fn older_than_grace(modified_at: SystemTime, grace: Duration) -> bool {
    SystemTime::now()
        .duration_since(modified_at)
        .is_ok_and(|elapsed| elapsed >= grace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::MemoryStore;

    fn key() -> SecretBox<[u8; 32]> {
        SecretBox::new(Box::new([7u8; 32]))
    }

    #[tokio::test]
    async fn from_store_rejects_a_rolled_back_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();
        let store = MemoryStore::new();
        let enc_key = key();
        let prefix = "rfm/";

        // Write generation 1, and hang on to exactly what got stored.
        to_store(&Manifest::new(), &store, &enc_key, prefix, &mut state)
            .await
            .unwrap();

        // Advance to generation 2 for real — this device now knows about it.
        to_store(&Manifest::new(), &store, &enc_key, prefix, &mut state)
            .await
            .unwrap();

        // Simulate an attacker (or a restored backup) deleting a newer snapshot
        store
            .delete(format!("{prefix}snapshot/generation00000000000000000002.snap").as_str())
            .await
            .unwrap();

        let result = from_store(&store, &enc_key, prefix, &mut state).await;

        assert!(result.is_err(), "a rolled-back generation must be refused");
    }

    #[tokio::test]
    async fn from_store_accepts_generation_advancing() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();
        let store = MemoryStore::new();
        let enc_key = key();
        let prefix = "rfm/";

        to_store(&Manifest::new(), &store, &enc_key, prefix, &mut state)
            .await
            .unwrap();
        to_store(&Manifest::new(), &store, &enc_key, prefix, &mut state)
            .await
            .unwrap();

        // A second device, seeing this for the first time, should accept it and
        // adopt its generation — not treat it as a rollback.
        let mut fresh_device_state = State::open(tempfile::tempdir().unwrap().path()).unwrap();
        let result = from_store(&store, &enc_key, prefix, &mut fresh_device_state).await;

        assert!(result.is_ok());
        assert_eq!(fresh_device_state.highest_manifest_generation().unwrap(), 2);
    }

    fn delta_entry(
        path: &str,
        content: &[u8],
        lamport: u64,
        device: &str,
        base: Option<&[u8]>,
        deleted: bool,
    ) -> DeltaEntry {
        DeltaEntry {
            path: path.to_string(),
            object_key: format!("ab/cd/{path}"),
            plaintext_hash: crate::hash::hash_bytes(content),
            size: content.len() as u64,
            mtime_utc: 0,
            deleted,
            deleted_at: if deleted { 1 } else { 0 },
            lamport,
            device_id: device.to_string(),
            base_hash: base.map(crate::hash::hash_bytes),
        }
    }

    async fn write_log(
        store: &MemoryStore,
        prefix: &str,
        lamport: u64,
        device: &str,
        entries: &[DeltaEntry],
    ) {
        let bytes = to_json_bytes(entries).unwrap();
        let store_key = format!("{prefix}log/lamport:{:020}-{}.delta", lamport, device);
        store.put_bytes(&store_key, &bytes).await.unwrap();
    }

    #[tokio::test]
    async fn compact_folds_deltas_into_a_new_snapshot_and_removes_the_previous() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();
        let store = MemoryStore::new();
        let enc_key = key();
        let prefix = "rfm/";

        // Seed generation 1 with a single file "a".
        let a0 = delta_entry("a", b"a-v0", 1, "dev1", None, false);
        let mut m0 = Manifest::new();
        m0.insert(a0.path.clone(), a0.clone());
        to_store(&m0, &store, &enc_key, prefix, &mut state)
            .await
            .unwrap();

        // Log: fast-forward "a" off v0, and create "b".
        let a1 = delta_entry("a", b"a-v1", 2, "dev1", Some(b"a-v0"), false);
        let b0 = delta_entry("b", b"b-v0", 3, "dev2", None, false);
        write_log(&store, prefix, 3, "dev2", &[a1.clone(), b0.clone()]).await;

        let expected = merge_deltas(&m0, &[a1, b0]).manifest;

        compact(
            &store,
            &enc_key,
            prefix,
            &mut state,
            DEFAULT_COMPACTION_GRACE,
        )
        .await
        .unwrap();

        // two snapshots remain due to grace period.
        let snapshots = store
            .list(&format!("{prefix}snapshot"), None)
            .await
            .unwrap();
        assert!(snapshots[1].key.contains("generation00000000000000000002"));

        // A fresh device reconstructs the fully-merged manifest from that snapshot alone.
        let mut fresh = State::open(tempfile::tempdir().unwrap().path()).unwrap();
        let reread = from_store(&store, &enc_key, prefix, &mut fresh)
            .await
            .unwrap();
        assert_eq!(reread.manifest, expected);
    }

    #[tokio::test]
    async fn compact_with_no_prior_snapshot_writes_generation_one() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();
        let store = MemoryStore::new();
        let enc_key = key();
        let prefix = "rfm/";

        let a = delta_entry("a", b"a", 1, "dev1", None, false);
        let b = delta_entry("b", b"b", 2, "dev1", None, false);
        write_log(&store, prefix, 2, "dev1", &[a.clone(), b.clone()]).await;

        let expected = merge_deltas(&Manifest::new(), &[a, b]).manifest;

        compact(
            &store,
            &enc_key,
            prefix,
            &mut state,
            DEFAULT_COMPACTION_GRACE,
        )
        .await
        .unwrap();

        assert_eq!(state.highest_manifest_generation().unwrap(), 1);

        let mut fresh = State::open(tempfile::tempdir().unwrap().path()).unwrap();
        let reread = from_store(&store, &enc_key, prefix, &mut fresh)
            .await
            .unwrap();
        assert_eq!(reread.manifest, expected);
    }

    #[tokio::test]
    async fn compact_preserves_tombstones() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();
        let store = MemoryStore::new();
        let enc_key = key();
        let prefix = "rfm/";

        // Generation 1 has a live "a".
        let a0 = delta_entry("a", b"a-v0", 1, "dev1", None, false);
        let mut m0 = Manifest::new();
        m0.insert(a0.path.clone(), a0.clone());
        to_store(&m0, &store, &enc_key, prefix, &mut state)
            .await
            .unwrap();

        // A delete tombstone that fast-forwards off v0.
        let tomb = delta_entry("a", b"a-v0", 2, "dev1", Some(b"a-v0"), true);
        write_log(&store, prefix, 2, "dev1", &[tomb]).await;

        compact(
            &store,
            &enc_key,
            prefix,
            &mut state,
            DEFAULT_COMPACTION_GRACE,
        )
        .await
        .unwrap();

        // The tombstone must survive compaction — an offline device still needs
        // to learn the deletion, so it can't be dropped from the snapshot.
        let mut fresh = State::open(tempfile::tempdir().unwrap().path()).unwrap();
        let reread = from_store(&store, &enc_key, prefix, &mut fresh)
            .await
            .unwrap();
        assert!(reread.manifest.get("a").unwrap().deleted);
    }

    #[tokio::test]
    async fn compact_is_idempotent_on_manifest_content() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();
        let store = MemoryStore::new();
        let enc_key = key();
        let prefix = "rfm/";

        let a = delta_entry("a", b"a", 1, "dev1", None, false);
        let b = delta_entry("b", b"b", 2, "dev2", None, false);
        write_log(&store, prefix, 2, "dev2", &[a.clone(), b.clone()]).await;

        let expected = merge_deltas(&Manifest::new(), &[a, b]).manifest;

        compact(
            &store,
            &enc_key,
            prefix,
            &mut state,
            DEFAULT_COMPACTION_GRACE,
        )
        .await
        .unwrap();
        compact(
            &store,
            &enc_key,
            prefix,
            &mut state,
            DEFAULT_COMPACTION_GRACE,
        )
        .await
        .unwrap();

        let mut fresh = State::open(tempfile::tempdir().unwrap().path()).unwrap();
        let reread = from_store(&store, &enc_key, prefix, &mut fresh)
            .await
            .unwrap();
        assert_eq!(reread.manifest, expected);
    }

    #[tokio::test]
    async fn compact_with_zero_grace_prunes_the_log_and_old_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = State::open(tmp.path()).unwrap();
        let store = MemoryStore::new();
        let enc_key = key();
        let prefix = "rfm/";

        // Generation 1 with "a", then a log that edits "a" and creates "b".
        let a0 = delta_entry("a", b"a-v0", 1, "dev1", None, false);
        let mut m0 = Manifest::new();
        m0.insert(a0.path.clone(), a0.clone());
        to_store(&m0, &store, &enc_key, prefix, &mut state)
            .await
            .unwrap();

        let a1 = delta_entry("a", b"a-v1", 2, "dev1", Some(b"a-v0"), false);
        let b0 = delta_entry("b", b"b-v0", 3, "dev2", None, false);
        write_log(&store, prefix, 3, "dev2", &[a1.clone(), b0.clone()]).await;

        let expected = merge_deltas(&m0, &[a1, b0]).manifest;

        compact(
            &store,
            &enc_key,
            prefix,
            &mut state,
            std::time::Duration::ZERO,
        )
        .await
        .unwrap();

        // Zero grace: every folded delta and the superseded snapshot are pruned.
        let logs = store.list(&format!("{prefix}log/"), None).await.unwrap();
        assert!(logs.is_empty(), "folded deltas should be pruned");
        let snapshots = store
            .list(&format!("{prefix}snapshot"), None)
            .await
            .unwrap();
        assert_eq!(snapshots.len(), 1, "only the newest snapshot should remain");

        // The single remaining snapshot still reconstructs the full manifest.
        let mut fresh = State::open(tempfile::tempdir().unwrap().path()).unwrap();
        let reread = from_store(&store, &enc_key, prefix, &mut fresh)
            .await
            .unwrap();
        assert_eq!(reread.manifest, expected);
    }
}
