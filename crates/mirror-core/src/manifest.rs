use std::collections::BTreeMap;

use serde::Serialize;

use crate::{
    Error, Result,
    hash::{self, ContentHash},
    store::ObjectStore,
};

/// What the bucket currently holds. Phase 4 adds tombstones and lamport clocks;
/// for now abscense means deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestEntry {
    pub path: String,
    pub content_hash: ContentHash,
    pub size: u64,
}

pub type Manifest = BTreeMap<String, ManifestEntry>;

pub fn to_json(manifest: &BTreeMap<String, ManifestEntry>) -> Result<Vec<u8>> {
    serde_json::to_vec(manifest).map_err(|e| {
        Error::Store(format!(
            "Failed to serialize manifest. Error: {}, Manifest {:?}",
            e, manifest
        ))
    })
}

pub async fn from_store<S: ObjectStore>(store: &S, prefix: &str) -> Result<Manifest> {
    let mut manifest = Manifest::new();

    for meta in store.list(prefix).await? {
        // strip prefix -> local-relative path, download+hash, insert ManifestEntry

        let data = store.get(&meta.key).await?;
        let path = meta.key.strip_prefix(prefix).ok_or(Error::Store(
            format!("Cannot strip prefix {} from key {}", prefix, meta.key).to_string(),
        ))?;
        let content_hash = hash::hash_bytes(&data);

        manifest.insert(
            path.to_string(),
            ManifestEntry {
                path: path.to_string(),
                content_hash,
                size: data.len() as u64,
            },
        );
    }

    Ok(manifest)
}
