use std::collections::BTreeMap;

use crate::hash::ContentHash;

/// What the bucket currently holds. Phase 4 adds tombstones and lamport clocks;
/// for now abscense means deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub path: String,
    pub content_hash: ContentHash,
    pub size: u64,
}

pub type Manifest = BTreeMap<String, ManifestEntry>;
