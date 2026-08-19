use std::{collections::HashMap, sync::Mutex};

use crate::{
    Error,
    hash::ContentHash,
    store::{ObjectMeta, ObjectStore},
};

pub struct MemoryStore {
    entries: Mutex<HashMap<String, MemoryStoreEntry>>,
}

#[derive(Clone)]
pub struct MemoryStoreEntry {
    content_hash: ContentHash,
    bytes: Vec<u8>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStore for MemoryStore {
    async fn put(
        &self,
        key: &str,
        path: &std::path::Path,
        content_hash: ContentHash,
    ) -> crate::Result<()> {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| Error::Store(format!("{}", e)))?;

        let mut map = self.entries.lock().expect("lock poisoned");

        map.insert(
            key.to_string(),
            MemoryStoreEntry {
                content_hash,
                bytes,
            },
        );

        Ok(())
    }

    async fn put_bytes(
        &self,
        key: &str,
        bytes: &[u8],
        content_hash: ContentHash,
    ) -> crate::Result<()> {
        let mut map = self.entries.lock().expect("lock poisoned");

        map.insert(
            key.to_string(),
            MemoryStoreEntry {
                content_hash,
                bytes: bytes.to_vec(),
            },
        );

        Ok(())
    }

    async fn get(&self, key: &str) -> crate::Result<Vec<u8>> {
        let map = self.entries.lock().expect("lock poisoned");

        map.get(key)
            .map(|entry| entry.bytes.clone())
            .ok_or(Error::Store(format!("Failed to fetch {}", key)))
    }

    async fn head(&self, key: &str) -> crate::Result<Option<super::ObjectMeta>> {
        let map = self.entries.lock().expect("lock poisoned");

        Ok(map.get(key).map(|entry| ObjectMeta {
            key: key.to_string(),
            size: entry.bytes.len() as u64,
            content_hash: Some(entry.content_hash),
        }))
    }

    async fn delete(&self, key: &str) -> crate::Result<()> {
        let mut map = self.entries.lock().expect("lock poisoned");

        map.remove(key);

        Ok(())
    }

    async fn list(&self, prefix: &str) -> crate::Result<Vec<super::ObjectMeta>> {
        let map = self.entries.lock().expect("lock poisoned");

        Ok(map
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, entry)| ObjectMeta {
                key: key.clone(),
                size: entry.bytes.len() as u64,
                // Real S3's list_objects_v2 can't return custom metadata either —
                // deliberately withheld here too, so code tested against MemoryStore
                // can't accidentally rely on something the real backend can't give it.
                content_hash: None,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::store::ObjectStore;

    #[tokio::test]
    async fn round_trip_records() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("a.txt");

        std::fs::write(&file, b"Hello").unwrap();

        let content_hash = crate::hash::hash_file(&file).unwrap();
        let store = MemoryStore::new();

        store
            .put("/prefix/temp.txt", &file, content_hash)
            .await
            .unwrap();

        assert_eq!(
            b"Hello".to_vec(),
            store.get("/prefix/temp.txt").await.unwrap()
        );

        assert_eq!(
            ObjectMeta {
                key: "/prefix/temp.txt".to_string(),
                size: 5,
                content_hash: Some(content_hash),
            },
            store
                .head("/prefix/temp.txt")
                .await
                .unwrap()
                .expect("object does not exist"),
        );

        let obj_list = store.list("/prefix").await.unwrap();

        assert_eq!(1, obj_list.len());
        assert_eq!(
            ObjectMeta {
                key: "/prefix/temp.txt".to_string(),
                size: 5,
                content_hash: None,
            },
            obj_list.first().unwrap().clone(),
        );

        store.delete("/prefix/temp.txt").await.unwrap();

        assert!(matches!(
            store.get("/prefix/temp.txt").await.unwrap_err(),
            Error::Store(_)
        ))
    }
}
