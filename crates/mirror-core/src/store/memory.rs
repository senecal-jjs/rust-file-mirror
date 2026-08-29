use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use uuid::Uuid;

use crate::{
    Error,
    state::CompletedUploadPart,
    store::{NONCE_SIZE, ObjectMeta, ObjectStore, PartRecord, PartSink, PartSource},
};

pub struct MemoryStore {
    entries: Arc<Mutex<HashMap<String, MemoryStoreEntry>>>,
    // Bytes written so far for each key with an open (not yet finished or
    // aborted) multipart upload, keyed by object key rather than owned by any
    // one `MemoryPartSink` — that's what lets `resume_put` pick up parts a
    // previous, "interrupted" sink already wrote instead of starting over.
    in_progress: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

#[derive(Clone)]
pub struct MemoryStoreEntry {
    bytes: Vec<u8>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            in_progress: Arc::new(Mutex::new(HashMap::new())),
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
    key: String,
    entries: Arc<Mutex<HashMap<String, MemoryStoreEntry>>>,
    in_progress: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    pub upload_id: String,
}

impl PartSink for MemoryPartSink {
    fn upload_id(&self) -> &str {
        &self.upload_id
    }

    async fn write_part(&mut self, bytes: &[u8]) -> crate::Result<PartRecord> {
        self.in_progress
            .lock()
            .expect("lock poisoned")
            .get_mut(&self.key)
            .expect("begin_put/resume_put always seed this key first")
            .extend_from_slice(bytes);

        self.part_number += 1;

        Ok(PartRecord {
            part_number: self.part_number - 1,
            etag: format!("etag-{}", self.part_number - 1),
            checksum_sha256: format!("checksum-{}", self.part_number - 1),
        })
    }

    async fn finish(self) -> crate::Result<()> {
        let bytes = self
            .in_progress
            .lock()
            .expect("lock poisoned")
            .remove(&self.key)
            .unwrap_or_default();

        self.entries
            .lock()
            .expect("lock poisoned")
            .insert(self.key, MemoryStoreEntry { bytes });

        Ok(())
    }

    fn get_part_number(&self) -> i32 {
        self.part_number
    }

    async fn abort(self) -> crate::Result<()> {
        self.in_progress
            .lock()
            .expect("lock poisoned")
            .remove(&self.key);

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

    async fn resume_put(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        // Ignored: unlike S3, there's no separate remote to have kept these parts'
        // bytes for us — `in_progress` already has them under `key`, left there by
        // whatever `MemoryPartSink` wrote them before being interrupted (or, for a
        // real crash-recovery test, dropped via `std::mem::forget` instead of
        // `finish`/`abort`, the same way the live MinIO resume tests do it).
        _completed_parts: Vec<CompletedUploadPart>,
    ) -> crate::Result<Self::PartSink> {
        self.in_progress
            .lock()
            .expect("lock poisoned")
            .entry(key.to_string())
            .or_default();

        Ok(MemoryPartSink {
            part_number,
            key: key.to_string(),
            entries: Arc::clone(&self.entries),
            in_progress: Arc::clone(&self.in_progress),
            upload_id: upload_id.to_string(),
        })
    }

    async fn begin_put(&self, key: &str) -> crate::Result<Self::PartSink> {
        self.in_progress
            .lock()
            .expect("lock poisoned")
            .insert(key.to_string(), Vec::new());

        Ok(MemoryPartSink {
            part_number: 1,
            key: key.to_string(),
            entries: Arc::clone(&self.entries),
            in_progress: Arc::clone(&self.in_progress),
            upload_id: Uuid::new_v4().simple().to_string(),
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
        let mut objects: Vec<ObjectMeta> = map
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
            .collect();

        objects.sort_by(|a, b| a.key.cmp(&b.key));

        Ok(objects)
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

    #[tokio::test]
    async fn resume_put_picks_up_bytes_written_before_a_simulated_interruption() {
        let store = MemoryStore::new();

        let mut sink = store.begin_put("key").await.unwrap();
        let upload_id = sink.upload_id().to_string();
        sink.write_part(b"hello, ").await.unwrap();

        // Simulate a crash: neither finish() nor abort() ever runs, so this
        // part's bytes are never cleaned out of `in_progress` — the same trick
        // the live MinIO resume tests use, since a real `kill -9` never gives
        // Drop a chance to run either.
        std::mem::forget(sink);

        let mut resumed = store
            .resume_put("key", &upload_id, 2, Vec::new())
            .await
            .unwrap();
        resumed.write_part(b"world!").await.unwrap();
        resumed.finish().await.unwrap();

        assert_eq!(store.get("key").await.unwrap(), b"hello, world!".to_vec());
    }

    #[tokio::test]
    async fn abort_after_resume_discards_everything_written_so_far() {
        let store = MemoryStore::new();

        let mut sink = store.begin_put("key").await.unwrap();
        let upload_id = sink.upload_id().to_string();
        sink.write_part(b"partial").await.unwrap();
        std::mem::forget(sink);

        let resumed = store
            .resume_put("key", &upload_id, 2, Vec::new())
            .await
            .unwrap();
        resumed.abort().await.unwrap();

        // Nothing should have been left behind — the object was never finished.
        assert!(matches!(
            store.get("key").await.unwrap_err(),
            Error::Store(_)
        ));
    }
}
