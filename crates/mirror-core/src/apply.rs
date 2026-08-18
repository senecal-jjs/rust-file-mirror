use std::{
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

use crate::{
    Error,
    engine::{Action, ActionKind, Plan},
    error::Result,
    hash::{self},
    manifest::{Manifest, ManifestEntry},
    state::State,
    store::ObjectStore,
    util::file::{file_stat, hash_stable},
};

pub async fn apply<S: ObjectStore>(
    plan: &Plan,
    store: &S,
    root: &Path,
    prefix: &str,
    state: &mut State,
    remote: &Manifest,
) -> Result<()> {
    for action in &plan.actions {
        match action.kind {
            ActionKind::Download => {
                let entry = remote.get(&action.path).ok_or_else(|| {
                    Error::Store(format!("no remote manifest entry for {}", action.path))
                })?;

                download(store, root, state, prefix, entry, action).await?
            }
            ActionKind::Upload => upload(store, root, action, prefix, state).await?,
            ActionKind::DeleteLocal => delete_local(root, action, state).await?,
            ActionKind::DeleteRemote => delete_remote(store, action, prefix, state).await?,
            ActionKind::Conflict => conflict(action)?,
        }
    }

    Ok(())
}

async fn delete_local(root: &Path, action: &Action, state: &mut State) -> Result<()> {
    let local_path = root.join(&action.path);

    // Idempotent: if it's already gone, the desired end state is already reached.
    if let Err(source) = std::fs::remove_file(&local_path)
        && source.kind() != ErrorKind::NotFound
    {
        return Err(Error::Io {
            path: local_path,
            source,
        });
    }

    state.remove(&action.path)?;

    println!("Applied {:<14} {}", action.kind, action.path);

    Ok(())
}

async fn delete_remote<S: ObjectStore>(
    store: &S,
    action: &Action,
    prefix: &str,
    state: &mut State,
) -> Result<()> {
    let key = format!("{prefix}{}", action.path);

    store.delete(&key).await?;
    state.remove(&action.path)?;

    println!("Applied {:<14} {}", action.kind, action.path);

    Ok(())
}

/// Phase 1 doesn't resolve conflicts — that's phase 4's job, once devices can tell
/// causal history apart. For now, leave both sides untouched and surface it; touching
/// either the local file, the remote object, or the baseline here would be a guess.
fn conflict(action: &Action) -> Result<()> {
    tracing::warn!(
        path = %action.path,
        "conflict: local and remote both changed; leaving untouched"
    );

    println!("On conflict do nothing {:<14} {}", action.kind, action.path);

    Ok(())
}

async fn upload<S: ObjectStore>(
    store: &S,
    root: &Path,
    action: &Action,
    prefix: &str,
    state: &mut State,
) -> Result<()> {
    let local_path = root.join(&action.path);
    let key = format!("{prefix}{}", action.path);

    let Some(stats) = hash_stable(&local_path)? else {
        tracing::warn!(path = %local_path.display(), "file changed while hashing; deferring");
        return Ok(()); // skip this action, next sync pass will pick it up
    };

    store.put(&key, &local_path).await?;

    state.confirm_sync(&action.path, stats.0, stats.1, stats.2)?;

    println!("Applied {:<14} {}", action.kind, action.path);

    Ok(())
}

async fn download<S: ObjectStore>(
    store: &S,
    root: &Path,
    state: &mut State,
    prefix: &str,
    manifest_entry: &ManifestEntry,
    action: &Action,
) -> Result<()> {
    let tmp_dir = root.join(".mirror/tmp");

    std::fs::create_dir_all(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let mut tmp_file = NamedTempFile::new_in(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let key = format!("{prefix}{}", manifest_entry.path);
    let data = store.get(&key).await?;

    tmp_file.write_all(&data).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let blake3_hash = hash::hash_file(tmp_file.path())?;

    if blake3_hash != manifest_entry.content_hash {
        return Err(Error::Store(format!(
            "Manifest hash {} does not match tmp file hash {}",
            manifest_entry.content_hash, blake3_hash
        )));
    }

    tmp_file.as_file().sync_all().map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let durable_path = safe_join(root, &manifest_entry.path)?;

    tmp_file
        .persist(&durable_path)
        .map_err(|source| Error::Io {
            path: durable_path.clone(),
            source: source.error,
        })?;

    // After the rename succeeds, stat the file (same as the scanner does) and write that (size, mtime_ns, content_hash)
    // into State as the new baseline, with last_synced_hash set — this is the "preserve mtime" concern: record whatever
    // mtime the filesystem actually assigned after your write, not a guess, so the next scan's stat matches what you just
    // recorded and doesn't look like a spurious local change.
    let file_stats = file_stat(&durable_path)?;

    state.confirm_sync(
        &manifest_entry.path,
        file_stats.size,
        file_stats.mtime_ns,
        blake3_hash,
    )?;

    println!("Applied {:<14} {}", action.kind, action.path);

    Ok(())
}

fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    for component in Path::new(rel).components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(Error::Store(format!(
                "unsafe path in manifest entry: {rel:?}"
            )));
        }
    }

    Ok(root.join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{engine::reconcile, manifest, scanner::Scanner, store::memory::MemoryStore};

    #[tokio::test]
    async fn download_writes_file_and_confirms_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let store = MemoryStore::new();
        let src = root.join("src.txt");
        std::fs::write(&src, b"hello").unwrap();
        store.put("rfm/a.txt", &src).await.unwrap();

        let mut state = State::open(root).unwrap();
        let entry = ManifestEntry {
            path: "a.txt".to_string(),
            content_hash: hash::hash_file(&src).unwrap(),
            size: 5,
        };
        let action = Action {
            path: "a.txt".to_string(),
            kind: ActionKind::Download,
        };

        download(&store, root, &mut state, "rfm/", &entry, &action)
            .await
            .unwrap();

        assert_eq!(
            std::fs::read(root.join("a.txt")).unwrap(),
            b"hello".to_vec()
        );

        let baseline = state.baseline().unwrap();
        assert_eq!(baseline["a.txt"].last_synced_hash, Some(entry.content_hash));
    }

    #[tokio::test]
    async fn upload_puts_file_and_confirms_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.txt"), b"hello").unwrap();

        let store = MemoryStore::new();
        let mut state = State::open(root).unwrap();
        let action = Action {
            path: "a.txt".to_string(),
            kind: ActionKind::Upload,
        };

        upload(&store, root, &action, "rfm/", &mut state)
            .await
            .unwrap();

        assert_eq!(store.get("rfm/a.txt").await.unwrap(), b"hello".to_vec());

        let baseline = state.baseline().unwrap();
        assert!(baseline["a.txt"].last_synced_hash.is_some());
    }

    #[tokio::test]
    async fn delete_local_is_idempotent_on_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut state = State::open(root).unwrap();
        let action = Action {
            path: "missing.txt".to_string(),
            kind: ActionKind::DeleteLocal,
        };

        delete_local(root, &action, &mut state).await.unwrap();
        delete_local(root, &action, &mut state).await.unwrap();
    }

    #[tokio::test]
    async fn delete_remote_is_idempotent_on_missing_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let store = MemoryStore::new();
        let mut state = State::open(root).unwrap();
        let action = Action {
            path: "missing.txt".to_string(),
            kind: ActionKind::DeleteRemote,
        };

        delete_remote(&store, &action, "rfm/", &mut state)
            .await
            .unwrap();
        delete_remote(&store, &action, "rfm/", &mut state)
            .await
            .unwrap();
    }

    #[test]
    fn safe_join_rejects_traversal_and_absolute_paths() {
        let root = Path::new("/safe/root");

        assert!(safe_join(root, "docs/notes.md").is_ok());
        assert!(safe_join(root, "../etc/passwd").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
        assert!(safe_join(root, "docs/../../etc/passwd").is_err());
    }

    /// Phase 1's stated exit criteria, as a test: sync a tree, mutate, re-sync;
    /// a second empty root converges to an identical tree via a shared `MemoryStore`.
    #[tokio::test]
    async fn round_trip_two_devices_converge() {
        async fn sync_once(root: &Path, store: &MemoryStore, prefix: &str) {
            let mut state = State::open(root).unwrap();
            let baseline = state.baseline().unwrap();

            let scanner = Scanner::new(root, ".mirrorignore");
            let entries = scanner.scan(&baseline).unwrap();

            let remote = manifest::from_store(store, prefix).await.unwrap();
            let plan = reconcile(&entries, &baseline, &remote);

            apply(&plan, store, root, prefix, &mut state, &remote)
                .await
                .unwrap();
            state.record_scan(&entries).unwrap();
        }

        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        let store = MemoryStore::new();
        let prefix = "rfm/";

        std::fs::write(root_a.path().join("a.txt"), b"one").unwrap();
        std::fs::write(root_a.path().join("b.txt"), b"two").unwrap();

        sync_once(root_a.path(), &store, prefix).await; // uploads a.txt, b.txt
        sync_once(root_b.path(), &store, prefix).await; // downloads both

        assert_eq!(
            std::fs::read(root_b.path().join("a.txt")).unwrap(),
            b"one".to_vec()
        );
        assert_eq!(
            std::fs::read(root_b.path().join("b.txt")).unwrap(),
            b"two".to_vec()
        );

        // mutate on A, both sides re-sync, B picks up the change
        std::fs::write(root_a.path().join("a.txt"), b"one-changed").unwrap();
        sync_once(root_a.path(), &store, prefix).await;
        sync_once(root_b.path(), &store, prefix).await;

        assert_eq!(
            std::fs::read(root_b.path().join("a.txt")).unwrap(),
            b"one-changed".to_vec()
        );

        // delete on A, both sides re-sync, B loses it too
        std::fs::remove_file(root_a.path().join("b.txt")).unwrap();
        sync_once(root_a.path(), &store, prefix).await;
        sync_once(root_b.path(), &store, prefix).await;

        assert!(!root_b.path().join("b.txt").exists());
    }
}
