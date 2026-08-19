use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;
use std::{io::Write, path::Path};

use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::crypto::content::encrypt;
use crate::hash::ContentHash;
use crate::{Error, Result, crypto::content::decrypt, store::ObjectStore};

const MANIFEST_OBJECT_NAME: &str = "manifest.bin";

/// What the bucket currently holds. Phase 4 adds tombstones and lamport clocks;
/// for now abscense means deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub content_hash: ContentHash,
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
) -> Result<()> {
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

    let manifest_store_key = format!("{prefix}{MANIFEST_OBJECT_NAME}");

    encrypt(
        manifest_enc_key,
        tmp_input_file.path(),
        tmp_output_file.path(),
        &manifest_store_key,
    )?;

    store
        .put(&manifest_store_key, tmp_output_file.path())
        .await?;

    Ok(())
}

pub async fn from_store<S: ObjectStore>(
    store: &S,
    manifest_enc_key: &SecretBox<[u8; 32]>,
    prefix: &str,
) -> Result<Manifest> {
    let manifest_store_key = format!("{prefix}{MANIFEST_OBJECT_NAME}");
    let encrypted_manifest = store.get(&manifest_store_key).await?;

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

    decrypt(
        manifest_enc_key,
        tmp_input_file.path(),
        tmp_output_file.path(),
        &manifest_store_key,
    )?;

    let manifest = from_json_bytes(tmp_output_file.path())?;

    Ok(manifest)
}
