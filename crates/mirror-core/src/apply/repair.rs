//! Finds content objects that can't hold what the manifest says they do (missing,
//! or the wrong length for the recorded size) and, when asked, re-uploads them from
//! a local copy that still matches the recorded hash. The object key is derived from
//! path and hash, so a repair overwrites the bad object in place and the manifest
//! needs no change.

use std::path::Path;

use futures_util::stream::{self, StreamExt};

use crate::Result;
use crate::apply::safe_join;
use crate::apply::upload::upload_file;
use crate::crypto::content::ciphertext_len;
use crate::crypto::filename;
use crate::crypto::key::DerivedSubKeys;
use crate::indicator::ProgressReporter;
use crate::manifest::{DeltaEntry, Manifest};
use crate::store::ObjectStore;
use crate::util::file::hash_stable;

const MAX_CONCURRENT_HEADS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteProblem {
    Missing,
    WrongSize { actual: u64, expected: u64 },
}

impl std::fmt::Display for RemoteProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "missing"),
            Self::WrongSize { actual, expected } => {
                write!(f, "wrong size ({actual} bytes, expected {expected})")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repair {
    Repaired,
    /// Only a placeholder (or nothing) here; another device may still have the bytes.
    NoLocalCopy,
    /// The local file has changed since it was synced, so it can't stand in.
    LocalDiffers,
    Failed(String),
}

impl std::fmt::Display for Repair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repaired => write!(f, "repaired from local copy"),
            Self::NoLocalCopy => write!(f, "no local copy on this device"),
            Self::LocalDiffers => write!(f, "local copy differs from the synced version"),
            Self::Failed(reason) => write!(f, "repair failed: {reason}"),
        }
    }
}

#[derive(Debug)]
pub struct BadObject {
    pub path: String,
    pub problem: RemoteProblem,
    /// `None` when only checking.
    pub repair: Option<Repair>,
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub checked: usize,
    pub bad: Vec<BadObject>,
}

/// Checks every live entry's object by HEAD. This catches truncated and missing
/// objects, not same-length corruption; that needs a full download.
pub async fn verify_remote<S: ObjectStore>(
    store: &S,
    manifest: &Manifest,
    root: &Path,
    prefix: &str,
    enc_keys: &DerivedSubKeys,
    reporter: &dyn ProgressReporter,
    repair: bool,
) -> Result<VerifyReport> {
    let live: Vec<&DeltaEntry> = manifest.values().filter(|entry| !entry.deleted).collect();
    let mut report = VerifyReport {
        checked: live.len(),
        ..VerifyReport::default()
    };

    let mut stage = reporter.stage("verifying remote objects");
    let heads: Vec<_> = live
        .iter()
        .map(|entry| async move {
            let head = store.head(&format!("{prefix}{}", entry.object_key)).await;
            (*entry, head)
        })
        .collect();
    let mut results = stream::iter(heads).buffered(MAX_CONCURRENT_HEADS);
    let mut problems = Vec::new();
    let mut done = 0;

    while let Some((entry, head)) = results.next().await {
        done += 1;
        stage.update(&format!("{done}/{}", live.len()));

        let expected = ciphertext_len(entry.size);
        let problem = match head? {
            None => RemoteProblem::Missing,
            Some(meta) if meta.size != expected => RemoteProblem::WrongSize {
                actual: meta.size,
                expected,
            },
            Some(_) => continue,
        };
        problems.push((entry, problem));
    }
    stage.finish(&format!("{} checked, {} bad", live.len(), problems.len()));

    for (entry, problem) in problems {
        let repair = if repair {
            Some(repair_one(store, entry, root, prefix, enc_keys, reporter).await)
        } else {
            None
        };

        report.bad.push(BadObject {
            path: entry.path.clone(),
            problem,
            repair,
        });
    }

    Ok(report)
}

async fn repair_one<S: ObjectStore>(
    store: &S,
    entry: &DeltaEntry,
    root: &Path,
    prefix: &str,
    enc_keys: &DerivedSubKeys,
    reporter: &dyn ProgressReporter,
) -> Repair {
    let attempt = async {
        let local = safe_join(root, &entry.path)?;
        if !local.is_file() {
            return Ok(Repair::NoLocalCopy);
        }

        let Some(stats) = hash_stable(&local)? else {
            return Ok(Repair::Failed("file kept changing while hashing".into()));
        };
        if stats.2 != entry.plaintext_hash {
            return Ok(Repair::LocalDiffers);
        }

        // Uploading under any other key would leave the manifest pointing at the
        // bad object and add a stray one.
        let key = filename::object_key(&enc_keys.name_key, &entry.path, &stats.2)?;
        if key != entry.object_key {
            return Ok(Repair::Failed(
                "manifest object key doesn't match path and hash".into(),
            ));
        }

        upload_file(
            store,
            &local,
            &entry.path,
            stats,
            enc_keys,
            prefix,
            reporter,
            Some(root),
        )
        .await?;

        let expected = ciphertext_len(entry.size);
        Ok(match store.head(&format!("{prefix}{key}")).await? {
            Some(meta) if meta.size == expected => Repair::Repaired,
            Some(meta) => Repair::Failed(format!("still {} bytes after upload", meta.size)),
            None => Repair::Failed("object missing after upload".into()),
        })
    };

    attempt
        .await
        .unwrap_or_else(|e: crate::Error| Repair::Failed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::content::decrypt_bytes;
    use crate::hash::hash_bytes;
    use crate::indicator::PrintReporter;
    use crate::store::memory::MemoryStore;
    use rand::{Rng, rng};
    use secrecy::SecretBox;

    fn test_keys() -> DerivedSubKeys {
        let random = || {
            let mut k = [0u8; 32];
            rng().fill(&mut k);
            SecretBox::new(Box::new(k))
        };
        DerivedSubKeys {
            content_key: random(),
            name_key: random(),
            manifest_key: random(),
            keycheck_bytes: random(),
        }
    }

    async fn uploaded(
        store: &MemoryStore,
        root: &Path,
        name: &str,
        content: &[u8],
        keys: &DerivedSubKeys,
    ) -> DeltaEntry {
        let path = root.join(name);
        std::fs::write(&path, content).unwrap();
        let stats = hash_stable(&path).unwrap().unwrap();
        let result = upload_file(store, &path, name, stats, keys, "p/", &PrintReporter, None)
            .await
            .unwrap();

        DeltaEntry {
            path: name.to_string(),
            size: content.len() as u64,
            plaintext_hash: hash_bytes(content),
            object_key: result.object_key,
            mtime_utc: 0,
            deleted: false,
            deleted_at: 0,
            lamport: 1,
            device_id: "test".to_string(),
            base_hash: None,
        }
    }

    #[tokio::test]
    async fn finds_truncated_objects_and_repairs_from_matching_local_copies() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let keys = test_keys();
        let store = MemoryStore::new();

        let good = uploaded(&store, root, "good.txt", b"fine", &keys).await;
        let fixable = uploaded(&store, root, "fixable.txt", b"repair me", &keys).await;
        let changed = uploaded(&store, root, "changed.txt", b"original", &keys).await;
        let gone = uploaded(&store, root, "gone.txt", b"evicted", &keys).await;

        for entry in [&fixable, &changed, &gone] {
            let key = format!("p/{}", entry.object_key);
            let mut bytes = store.get(&key).await.unwrap();
            bytes.truncate(bytes.len() - 1);
            store.put_bytes(&key, &bytes).await.unwrap();
        }
        std::fs::write(root.join("changed.txt"), b"edited since").unwrap();
        std::fs::remove_file(root.join("gone.txt")).unwrap();

        let manifest: Manifest = [&good, &fixable, &changed, &gone]
            .into_iter()
            .map(|entry| (entry.path.clone(), entry.clone()))
            .collect();

        let checked = verify_remote(&store, &manifest, root, "p/", &keys, &PrintReporter, false)
            .await
            .unwrap();
        assert_eq!(checked.checked, 4);
        assert_eq!(checked.bad.len(), 3);
        assert!(checked.bad.iter().all(|bad| bad.repair.is_none()));

        let repaired = verify_remote(&store, &manifest, root, "p/", &keys, &PrintReporter, true)
            .await
            .unwrap();
        let outcome = |path: &str| {
            repaired
                .bad
                .iter()
                .find(|bad| bad.path == path)
                .and_then(|bad| bad.repair.clone())
        };
        assert_eq!(outcome("fixable.txt"), Some(Repair::Repaired));
        assert_eq!(outcome("changed.txt"), Some(Repair::LocalDiffers));
        assert_eq!(outcome("gone.txt"), Some(Repair::NoLocalCopy));

        let object = store
            .get(&format!("p/{}", fixable.object_key))
            .await
            .unwrap();
        assert_eq!(
            decrypt_bytes(&keys.content_key, &object, "fixable.txt").unwrap(),
            b"repair me"
        );

        let after = verify_remote(&store, &manifest, root, "p/", &keys, &PrintReporter, false)
            .await
            .unwrap();
        assert_eq!(after.bad.len(), 2);
    }
}
