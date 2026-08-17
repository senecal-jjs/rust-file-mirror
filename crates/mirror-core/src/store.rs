use std::path::Path;

use crate::error::Result;

pub mod memory;
pub mod s3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
}

pub trait ObjectStore: Send + Sync {
    fn put(&self, key: &str, path: &Path) -> impl std::future::Future<Output = Result<()>> + Send;
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
