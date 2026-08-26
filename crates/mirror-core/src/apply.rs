use std::path::{Path, PathBuf};

use crate::{Error, error::Result};

pub mod conflict;
pub mod delete_local;
pub mod delete_remote;
pub mod download;
pub mod execute;
pub mod upload;

pub use execute::apply;

pub(crate) const MAX_SINGLE_SHOT_PUT_SIZE: usize = 8 * 1024 * 1024; // 8 MB max single shot upload

pub(crate) fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
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

    #[test]
    fn safe_join_rejects_traversal_and_absolute_paths() {
        let root = Path::new("/safe/root");

        assert!(safe_join(root, "docs/notes.md").is_ok());
        assert!(safe_join(root, "../etc/passwd").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
        assert!(safe_join(root, "docs/../../etc/passwd").is_err());
    }
}
