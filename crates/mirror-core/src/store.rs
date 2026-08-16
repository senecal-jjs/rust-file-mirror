use std::path::Path;

use crate::error::Result;

pub mod s3;
pub mod memory;

pub struct ObjectMeta {
  pub key: String,
  pub size: u64
}

pub trait ObjectStore: Send + Sync {
  async fn put(&self, key: &str, path: &Path) -> Result<()>;
  async fn get(&self, key: &str) -> Result<Vec<u8>>;
  async fn head(&self, key: &str) -> Result<Option<ObjectMeta>>;
  async fn delete(&self, key: &str) -> Result<()>;
  async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>>;
}