use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;
use std::{io::Write, path::Path};

use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::crypto::content::encrypt;
use crate::hash::ContentHash;
use crate::state::State;
use crate::{Error, Result, crypto::content::decrypt, store::ObjectStore};

const MANIFEST_OBJECT_NAME: &str = "manifest.bin";

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
    let manifest_bytes = to_json_bytes(manifest)?;
    let manifest_store_key = format!("{prefix}{MANIFEST_OBJECT_NAME}");

    // Every write is one generation past whatever this device has last confirmed —
    // either its own last write, or the highest it has read and accepted from
    // another device.
    let generation = state.highest_manifest_generation()? + 1;

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
    let associated_data = format!("{manifest_store_key}:{generation}");

    encrypt(
        manifest_enc_key,
        tmp_input_file.path(),
        tmp_output_file.path(),
        &associated_data,
    )?;

    // The generation travels as a plaintext 8-byte prefix ahead of the ciphertext —
    // same idea as the nonce prefix inside it. from_store has to read this before it
    // can even know what AAD to attempt decryption with.
    let encrypted_bytes =
        std::fs::read(tmp_output_file.path()).map_err(|source| Error::Io {
            path: tmp_output_file.path().to_path_buf(),
            source,
        })?;

    let mut payload = generation.to_be_bytes().to_vec();
    payload.extend_from_slice(&encrypted_bytes);

    store.put_bytes(&manifest_store_key, &payload).await?;

    state.record_manifest_generation(generation)?;

    Ok(())
}

pub async fn from_store<S: ObjectStore>(
    store: &S,
    manifest_enc_key: &SecretBox<[u8; 32]>,
    prefix: &str,
    state: &mut State,
) -> Result<Manifest> {
    let manifest_store_key = format!("{prefix}{MANIFEST_OBJECT_NAME}");

    if store.head(&manifest_store_key).await?.is_none() {
        return Ok(Manifest::new());
    }

    let payload = store.get(&manifest_store_key).await?;

    if payload.len() < 8 {
        return Err(Error::Store(format!(
            "manifest object {manifest_store_key} is too short to hold a generation prefix"
        )));
    }

    let (generation_bytes, encrypted_manifest) = payload.split_at(8);
    let generation = u64::from_be_bytes(generation_bytes.try_into().unwrap());

    // The actual rollback protection: refuse anything older than what this device
    // has already confirmed, whether that came from its own writes or a previous read.
    let highest = state.highest_manifest_generation()?;

    if generation < highest {
        return Err(Error::Store(format!(
            "manifest generation {generation} is older than the last one this device has \
             seen ({highest}) — refusing a possible rollback"
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
        .write_all(encrypted_manifest)
        .map_err(|source| Error::Io {
            path: tmp_dir.clone(),
            source,
        })?;

    let tmp_output_file = NamedTempFile::new_in(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let associated_data = format!("{manifest_store_key}:{generation}");

    decrypt(
        manifest_enc_key,
        tmp_input_file.path(),
        tmp_output_file.path(),
        &associated_data,
    )?;

    let manifest = from_json_bytes(tmp_output_file.path())?;

    if generation > highest {
        state.record_manifest_generation(generation)?;
    }

    Ok(manifest)
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
        let manifest_key = format!("{prefix}{MANIFEST_OBJECT_NAME}");
        let generation_1_bytes = store.get(&manifest_key).await.unwrap();

        // Advance to generation 2 for real — this device now knows about it.
        to_store(&Manifest::new(), &store, &enc_key, prefix, &mut state)
            .await
            .unwrap();

        // Simulate an attacker (or a restored backup) replacing the object with
        // the older generation-1 bytes.
        store
            .put_bytes(&manifest_key, &generation_1_bytes)
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
