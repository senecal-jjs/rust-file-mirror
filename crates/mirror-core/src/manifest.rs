use std::collections::BTreeMap;

use serde::Serialize;

use crate::{
    Error, Result, crypto::vault::VAULT_OBJECT_NAME, hash::ContentHash, store::ObjectStore,
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

/// Builds the remote manifest from listed objects' metadata alone — no bodies are
/// downloaded. Content is encrypted with a fresh random nonce on every upload, so
/// hashing a downloaded object's bytes would no longer reflect the plaintext (the
/// same content re-uploaded produces different ciphertext every time); `put`/
/// `put_bytes` instead carry the plaintext BLAKE3 hash as object metadata, and
/// `head` is what can actually return it.
pub async fn from_store<S: ObjectStore>(store: &S, prefix: &str) -> Result<Manifest> {
    let mut manifest = Manifest::new();

    for meta in store.list(prefix).await? {
        let path = meta.key.strip_prefix(prefix).ok_or_else(|| {
            Error::Store(format!(
                "cannot strip prefix {prefix} from key {}",
                meta.key
            ))
        })?;

        // The vault header lives under the same prefix but isn't synced content —
        // it's written via put_bytes with its own encryption scheme, not something
        // reconcile should ever plan a download/upload/conflict for.
        if path == VAULT_OBJECT_NAME {
            continue;
        }

        let Some(head) = store.head(&meta.key).await? else {
            // Listed a moment ago, gone now (e.g. a concurrent delete elsewhere) —
            // treat it the same as if it had never been listed at all.
            continue;
        };

        let Some(content_hash) = head.content_hash else {
            return Err(Error::Store(format!(
                "object {} has no content-hash metadata — not written by this client?",
                meta.key
            )));
        };

        manifest.insert(
            path.to_string(),
            ManifestEntry {
                path: path.to_string(),
                content_hash,
                size: head.size,
            },
        );
    }

    Ok(manifest)
}
