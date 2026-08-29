use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;
use std::{io::Write, path::Path};

use regex::Regex;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::crypto::content::encrypt;
use crate::hash::ContentHash;
use crate::state::State;
use crate::{Error, Result, crypto::content::decrypt, store::ObjectStore};

/// What the bucket currently holds. Phase 4 adds tombstones and lamport clocks;
/// for now abscense means deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub content_hash: ContentHash,
    pub object_key: String,
}

/// Maps HMAC -> plaintext path
pub type Manifest = BTreeMap<String, ManifestEntry>;

fn to_json_bytes(manifest: &BTreeMap<String, ManifestEntry>) -> Result<Vec<u8>> {
    serde_json::to_vec(manifest).map_err(|e| {
        Error::Store(format!(
            "Failed to serialize manifest. Error: {}, Manifest {:?}",
            e, manifest
        ))
    })
}

fn from_json_bytes(bytes_path: &Path) -> Result<Manifest> {
    let input = File::open(bytes_path).map_err(|source| Error::Io {
        path: bytes_path.to_path_buf(),
        source,
    })?;

    let buf_reader = std::io::BufReader::new(input);

    let manifest = serde_json::from_reader(buf_reader).map_err(|source| {
        Error::Store(format!(
            "Failed to deserialize manifest from file. Error: {}",
            source
        ))
    })?;

    Ok(manifest)
}

pub async fn to_store(
    manifest: &Manifest,
    store: &impl ObjectStore,
    manifest_enc_key: &SecretBox<[u8; 32]>,
    prefix: &str,
    state: &mut State,
) -> Result<()> {
    let snapshot_prefix = format!("{}snapshot", prefix);
    let latest_key = store.list(&snapshot_prefix).await?;

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

    let manifest_bytes = to_json_bytes(manifest)?;

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
    let object_metas = store.list(&snapshot_prefix).await?;

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

        let manifest = from_json_bytes(tmp_output_file.path())?;

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
