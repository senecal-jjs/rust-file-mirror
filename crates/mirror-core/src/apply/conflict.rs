use std::path::Path;

use crate::{
    Error,
    apply::safe_join,
    engine::Action,
    error::Result,
    state::State,
    util::{
        file::{conflict_name, replace_name},
        time::utc_timestamp,
    },
};

/// Phase 1 doesn't resolve conflicts — that's phase 4's job, once devices can tell
/// causal history apart. For now, leave both sides untouched and surface it; touching
/// either the local file, the remote object, or the baseline here would be a guess.
pub(crate) fn conflict(root: &Path, action: &Action, state: &mut State) -> Result<()> {
    // conflict_name returns a bare filename, so replace_name puts it back in
    // the original directory — otherwise nested files land at the root.
    let from = root.join(&action.path);
    let device_name = state.device_name()?;
    let new_name = conflict_name(&action.path, &utc_timestamp(), &device_name)?;
    let new_path = replace_name(Path::new(&action.path), &new_name)?;
    let to = safe_join(root, new_path.to_str().unwrap())?;

    let rename = std::fs::rename(&from, &to).map_err(|source| Error::Io {
        path: from.clone(),
        source,
    });

    if rename.is_err() {
        tracing::warn!(path = %from.display(), "cannot rename missing file");
    }

    state.remove(&action.path)?;

    Ok(())
}
