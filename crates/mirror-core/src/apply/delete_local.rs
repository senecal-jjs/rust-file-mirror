use std::{io::ErrorKind, path::Path};

use crate::{Error, engine::Action, error::Result, state::State};

pub(crate) async fn delete_local(root: &Path, action: &Action, state: &mut State) -> Result<()> {
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
