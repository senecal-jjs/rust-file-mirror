use std::collections::BTreeMap;

use serde::Serialize;

use crate::{Error, Result, hash::ContentHash};

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