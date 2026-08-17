use std::{
    io::Write,
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

                download(store, root, state, prefix, entry).await?
            }
            ActionKind::Upload => upload(store, root, action, prefix, state).await?,
            ActionKind::DeleteLocal => {}
            ActionKind::DeleteRemote => {}
            ActionKind::Conflict => {}
        }
    }

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

    Ok(())
}

async fn download<S: ObjectStore>(
    store: &S,
    root: &Path,
    state: &mut State,
    prefix: &str,
    manifest_entry: &ManifestEntry,
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
