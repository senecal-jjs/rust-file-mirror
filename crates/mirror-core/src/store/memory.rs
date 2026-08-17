use std::{collections::HashMap, sync::Mutex};

use crate::{
    Error,
    store::{ObjectMeta, ObjectStore},
};

pub struct MemoryStore {
    entries: Mutex<HashMap<String, Vec<u8>>>,
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
    async fn put(&self, key: &str, path: &std::path::Path) -> crate::Result<()> {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| Error::Store(format!("{}", e)))?;

        let mut map = self.entries.lock().expect("lock poisoned");

        map.insert(key.to_string(), bytes);

        Ok(())
    }

    async fn get(&self, key: &str) -> crate::Result<Vec<u8>> {
        let map = self.entries.lock().expect("lock poisoned");

        map.get(key)
            .cloned()
            .ok_or(Error::Store(format!("Failed to fetch {}", key)))
    }

    async fn head(&self, key: &str) -> crate::Result<Option<super::ObjectMeta>> {
        let map = self.entries.lock().expect("lock poisoned");

        Ok(map.get(key).map(|v| ObjectMeta {
            key: key.to_string(),
            size: v.len() as u64,
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
            .map(|(key, bytes)| ObjectMeta {
                key: key.clone(),
                size: bytes.len() as u64,
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
