use std::{cmp::max, path::Path, time::SystemTime};

use crate::{error::Result, hash::ContentHash, state::CompletedUploadPart};

pub mod memory;
pub mod s3;

/// STREAM's BE32 construction reserves 5 of XChaCha20's 24 nonce bytes for its own
/// per-chunk counter + last-block flag — callers supply the remaining 19, which
/// `StreamingEncryptor` prepends to every object it writes.
pub const NONCE_SIZE: usize = 19;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    /// Plaintext BLAKE3 hash carried as object metadata (set on `put`/`put_bytes`).
    /// Only ever populated by `head` — a real S3 `list_objects_v2` can't return
    /// custom metadata, so `list` always leaves this `None`.
    pub content_hash: Option<ContentHash>,
    pub last_modified: Option<SystemTime>,
}

pub trait ObjectStore: Send + Sync {
    type PartSink: PartSink;
    type PartSource: PartSource;

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
        start_after: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Vec<ObjectMeta>>> + Send;

    /// For objects too large to hand over as one `put`/`put_bytes` call — or, per
    /// what we're actually building, not yet materialized as a single buffer
    /// because they're coming off StreamingEncryptor one part at a time.
    fn begin_put(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Self::PartSink>> + Send;

    fn resume_put(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        completed_parts: Vec<CompletedUploadPart>,
    ) -> impl std::future::Future<Output = Result<Self::PartSink>> + Send;

    /// For objects too large to fetch as one `get` call. The nonce (always exactly
    /// `NONCE_SIZE` bytes — that's the whole reason this isn't a generic
    /// "download with a header of arbitrary size" abstraction) comes back via
    /// `PartSource::get_nonce`; the remaining ciphertext streams through `next`.
    fn begin_download(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Self::PartSource>> + Send;
}

pub struct PartRecord {
    pub part_number: i32,
    pub etag: String,
    pub checksum_sha256: String,
}

pub trait PartSink: Send {
    fn write_part(
        &mut self,
        bytes: &[u8],
    ) -> impl std::future::Future<Output = Result<PartRecord>> + Send;

    /// Terminal, by value — same reasoning as StreamingEncryptor/Decryptor's
    /// finalizers: once the object is complete, the type system (not a runtime
    /// flag) should make the sink unusable.
    fn finish(self) -> impl std::future::Future<Output = Result<()>> + Send;

    fn get_part_number(&self) -> i32;

    fn abort(self) -> impl std::future::Future<Output = Result<()>> + Send;

    fn upload_id(&self) -> &str;
}

pub trait PartSource: Send {
    fn next(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> + Send;
    fn get_nonce(&self) -> [u8; NONCE_SIZE];
}

pub fn get_chunk_size(file_len: u64) -> usize {
    const MIN_S3_PART_SIZE: u64 = 5 * 1024 * 1024; // 5 MB
    const MAX_S3_PARTS: u64 = 10_000;
    const TARGET_PART_SIZE: u64 = 8 * 1024 * 1024; // 8 MB baseline

    if file_len <= MIN_S3_PART_SIZE {
        return MIN_S3_PART_SIZE as usize;
    }

    // Math: Divide length by 10,000 and add 1 to safely handle any remainders
    // without crossing the hard 10,000 part ceiling.
    let required_min_by_limit = (file_len / MAX_S3_PARTS) + 1;

    // Pick the largest value among your ideal target, the 5MB floor,
    // and the strictly required minimum size based on the 10k ceiling.
    max(
        TARGET_PART_SIZE as usize,
        max(MIN_S3_PART_SIZE as usize, required_min_by_limit as usize),
    )
}
