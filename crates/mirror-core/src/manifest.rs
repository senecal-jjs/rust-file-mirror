use std::collections::BTreeMap;
use std::path::PathBuf;
use std::{io::Write, path::Path};

use futures_util::future::join_all;
use regex::Regex;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::crypto::content::encrypt;
use crate::hash::ContentHash;
use crate::state::State;
use crate::{Error, Result, crypto::content::decrypt, store::ObjectStore};

#[derive(Serialize, Deserialize, Debug, Clone)]
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

pub fn merge_deltas(snapshot: &Manifest, deltas: &[DeltaEntry]) -> MergeResult {
    let mut manifest = snapshot.clone();
    let mut conflicts: Vec<RemoteConflict> = Vec::new();
    let mut lamport = snapshot
        .values()
        .max_by(|x, y| x.lamport.cmp(&y.lamport))
        .map_or(0, |d| d.lamport);

    for delta in deltas {
        let existing = manifest.get(&delta.path);

        if let Some(existing) = existing {
            if delta.base_hash == Some(existing.plaintext_hash) {
                // fast-forward: the writer saw the current state, accept it
                manifest.insert(delta.path.clone(), delta.clone());
            } else if delta.plaintext_hash == existing.plaintext_hash {
                // converge: same content reached independently, keep the lower (lamport, device_id)
                if (delta.lamport, &delta.device_id) < (existing.lamport, &existing.device_id) {
                    manifest.insert(delta.path.clone(), delta.clone());
                }
            } else {
                // conflict: record it, leave `existing` in place, don't touch `manifest` here
                let conflict = if (delta.lamport, &delta.device_id)
                    < (existing.lamport, &existing.device_id)
                {
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
        } else {
            manifest.insert(delta.path.clone(), delta.clone());
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

pub async fn read_deltas(store: &impl ObjectStore, prefix: &str) -> Result<Vec<DeltaEntry>> {
    // read all until compaction in place
    let metas = store.list(format!("{prefix}log/").as_str(), None).await?;
    let results: Vec<Result<Vec<u8>>> =
        join_all(metas.iter().map(|meta| store.get(&meta.key))).await;
    let objects: Vec<Vec<u8>> = results.into_iter().collect::<Result<Vec<_>>>()?;
    let deltas: Vec<Vec<DeltaEntry>> = objects
        .into_iter()
        .map(|object| from_json_bytes(&object))
        .collect::<Result<Vec<_>>>()?;

    Ok(deltas.into_iter().flatten().collect())
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

pub async fn from_store<S: ObjectStore>(
    store: &S,
    manifest_enc_key: &SecretBox<[u8; 32]>,
    prefix: &str,
    state: &mut State,
) -> Result<Manifest> {
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

        Ok(manifest)
    } else {
        Ok(Manifest::new())
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
}
