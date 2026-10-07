use std::path::Path;

use crate::{
    Error, Result,
    apply::safe_join,
    manifest::{DeltaEntry, RemoteConflict},
    state::State,
    util::{
        file::{conflict_name, hash_stable, replace_name},
        time::utc_timestamp,
    },
};

#[derive(Debug, Default)]
pub struct PreservedConflicts {
    /// Conflicted-copy paths the loser's local bytes were renamed to.
    pub renamed: Vec<String>,
    /// Evicted losers: (conflicted-copy path, loser version) to re-encrypt remotely.
    pub relocations: Vec<(String, DeltaEntry)>,
}

/// Preserves this device's losing side of each remote conflict by renaming it
/// aside on local disk. Deliberately does nothing else — the renamed file is
/// just an ordinary new local file, so the scan picks it up and `reconcile`
/// plans a normal `Upload` for it. That's the plan's 4.5 design: "the conflicted
/// copy is then uploaded as an ordinary new file."
///
/// An evicted loser has no local bytes, but its version survives remotely under its
/// own object key, so it's returned as a relocation instead.
///
/// Must run before the scan (so the scanner sees the new name) and before any
/// download can overwrite the loser's bytes.
pub fn preserve_conflict_losers(
    conflicts: &[RemoteConflict],
    root: &Path,
    state: &mut State,
) -> Result<PreservedConflicts> {
    let device_id = state.device_id()?;
    let device_name = state.device_name()?;
    let baseline = state.baseline()?;
    let mut preserved = PreservedConflicts::default();

    for conflict in conflicts {
        // Only the losing device still holds the losing bytes; every other
        // device leaves this conflict for that device to resolve.
        if conflict.loser.device_id != device_id {
            continue;
        }

        let from = safe_join(root, &conflict.loser.path)?;

        // conflict_name returns a bare filename, so replace_name puts it back in
        // the original directory — otherwise nested files land at the root.
        let new_name = conflict_name(&conflict.loser.path, &utc_timestamp(), &device_name)?;
        let new_path = replace_name(Path::new(&conflict.loser.path), &new_name)?;
        let new_path = new_path.to_string_lossy().into_owned();

        if !from.exists() {
            // Only while the placeholder still stands for the loser's version; once it
            // advances to the winner this conflict has been handled.
            let evicted_loser = baseline.get(&conflict.loser.path).is_some_and(|record| {
                record.is_evicted()
                    && record.last_synced_hash == Some(conflict.loser.plaintext_hash)
            });

            if evicted_loser {
                preserved
                    .relocations
                    .push((new_path, conflict.loser.clone()));
            }
            continue;
        }

        tracing::info!(path = %conflict.loser.path, "resolving conflict");

        // These bytes are only the loser's if they still hash to what the delta
        // recorded — the file may well have been edited again since.
        let Some((_, _, hash)) = hash_stable(&from)? else {
            tracing::warn!(path = %from.display(), "loser changed while hashing; deferring");
            continue;
        };
        if hash != conflict.loser.plaintext_hash {
            tracing::warn!(path = %from.display(), "loser no longer matches its delta; deferring");
            continue;
        }

        let to = safe_join(root, &new_path)?;

        std::fs::rename(&from, &to).map_err(|source| Error::Io { path: from, source })?;

        // Without this the baseline still claims the original path exists
        // locally, so reconcile reads the rename as a local delete and raises a
        // *new*, spurious delete-vs-edit conflict against the winner.
        state.remove(&conflict.loser.path)?;

        preserved.renamed.push(new_path);
    }

    Ok(preserved)
}

// #[cfg(test)]
// mod tests {
//     use rand::{Rng, rng};

//     use super::*;
//     use crate::crypto::{content::StreamingDecryptor, filename};
//     use crate::store::NONCE_SIZE;
//     use crate::{hash, store::memory::MemoryStore};

// }
