use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{
    Error,
    store::{NONCE_SIZE, ObjectMeta, ObjectStore, PartSink, PartSource},
};

pub struct MemoryStore {
    entries: Arc<Mutex<HashMap<String, MemoryStoreEntry>>>,
}

#[derive(Clone)]
pub struct MemoryStoreEntry {
    bytes: Vec<u8>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MemoryPartSink {
    pub part_number: i32,
    data: Vec<u8>,
    key: String,
    entries: Arc<Mutex<HashMap<String, MemoryStoreEntry>>>,
}

impl PartSink for MemoryPartSink {
    async fn write_part(&mut self, bytes: &[u8]) -> crate::Result<()> {
        self.data.append(&mut bytes.to_vec());
        self.part_number += 1;
        Ok(())
    }

    async fn finish(self) -> crate::Result<()> {
        let mut map = self.entries.lock().expect("lock poisoned");
        map.insert(self.key, MemoryStoreEntry { bytes: self.data });
        Ok(())
    }

    fn get_part_number(&self) -> i32 {
        self.part_number
    }

    async fn abort(self) -> crate::Result<()> {
        Ok(())
    }
}

/// `MemoryStore` already holds every object's bytes in full, so there's no real
/// network chunking to simulate — `next` just hands back whatever's left after
/// the nonce, once, then reports done. That's still enough to exercise
/// `StreamingDecryptor` being fed a chunk of arbitrary (here: total) size.
pub struct MemoryPartSource {
    nonce: [u8; NONCE_SIZE],
    body: Option<Vec<u8>>,
}

impl PartSource for MemoryPartSource {
    async fn next(&mut self) -> crate::Result<Option<Vec<u8>>> {
        Ok(self.body.take())
    }

    fn get_nonce(&self) -> [u8; NONCE_SIZE] {
        self.nonce
    }
}

impl ObjectStore for MemoryStore {
    type PartSink = MemoryPartSink;
    type PartSource = MemoryPartSource;

    async fn begin_put(&self, key: &str) -> crate::Result<Self::PartSink> {
        Ok(MemoryPartSink {
            part_number: 1,
            data: Vec::new(),
            key: key.to_string(),
            entries: Arc::clone(&self.entries),
        })
    }

    async fn begin_download(&self, key: &str) -> crate::Result<Self::PartSource> {
        let bytes = {
            let map = self.entries.lock().expect("lock poisoned");

            map.get(key)
                .map(|entry| entry.bytes.clone())
                .ok_or(Error::Store(format!("Failed to fetch {}", key)))?
        };

        if bytes.len() < NONCE_SIZE {
            return Err(Error::Store(format!(
                "object {key} is too short to hold a {NONCE_SIZE}-byte nonce (got {} bytes)",
                bytes.len()
            )));
        }

        let (nonce, body) = bytes.split_at(NONCE_SIZE);

        Ok(MemoryPartSource {
            nonce: nonce.try_into().expect("checked length above"),
            body: Some(body.to_vec()),
        })
    }

    async fn put(&self, key: &str, path: &std::path::Path) -> crate::Result<()> {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| Error::Store(format!("{}", e)))?;

        let mut map = self.entries.lock().expect("lock poisoned");

        map.insert(key.to_string(), MemoryStoreEntry { bytes });

        Ok(())
    }

    async fn put_bytes(&self, key: &str, bytes: &[u8]) -> crate::Result<()> {
        let mut map = self.entries.lock().expect("lock poisoned");

        map.insert(
            key.to_string(),
            MemoryStoreEntry {
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
            content_hash: None,
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

        let store = MemoryStore::new();

        store.put("/prefix/temp.txt", &file).await.unwrap();

        assert_eq!(
            b"Hello".to_vec(),
            store.get("/prefix/temp.txt").await.unwrap()
        );

        assert_eq!(
            ObjectMeta {
                key: "/prefix/temp.txt".to_string(),
                size: 5,
                content_hash: None,
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
