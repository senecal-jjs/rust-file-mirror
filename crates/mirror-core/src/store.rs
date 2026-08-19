use std::path::Path;

use crate::{error::Result, hash::ContentHash};

pub mod memory;
pub mod s3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    /// Plaintext BLAKE3 hash carried as object metadata (set on `put`/`put_bytes`).
    /// Only ever populated by `head` — a real S3 `list_objects_v2` can't return
    /// custom metadata, so `list` always leaves this `None`.
    pub content_hash: Option<ContentHash>,
}

pub trait ObjectStore: Send + Sync {
    fn put(&self, key: &str, path: &Path) -> impl std::future::Future<Output = Result<()>> + Send;
    fn put_bytes(
        &self,
        key: &str,
        bytes: &[u8],
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn get(&self, key: &str) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
    fn head(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Option<ObjectMeta>>> + Send;
    fn delete(&self, key: &str) -> impl std::future::Future<Output = Result<()>> + Send;
    fn list(
        &self,
        prefix: &str,
    ) -> impl std::future::Future<Output = Result<Vec<ObjectMeta>>> + Send;
}
