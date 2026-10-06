//! Visible `<name>.rfm` placeholder files that stand in for evicted files.

use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::apply::safe_join;
use crate::hash::ContentHash;
use crate::{Error, Result};

/// Reserved suffix: a real file ending in it is never mirrored.
pub const SUFFIX: &str = ".rfm";
const FORMAT: u32 = 1;
/// Anything larger is not a placeholder and is never read into memory.
const MAX_STUB_LEN: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StubMeta {
    pub rfm: u32,
    pub path: String,
    pub size: u64,
    pub hash: String,
    pub object_key: String,
    pub evicted_at: u64,
}

impl StubMeta {
    pub fn new(
        path: &str,
        size: u64,
        hash: ContentHash,
        object_key: &str,
        evicted_at: u64,
    ) -> Self {
        Self {
            rfm: FORMAT,
            path: path.to_string(),
            size,
            hash: hash.to_string(),
            object_key: object_key.to_string(),
            evicted_at,
        }
    }

    pub fn content_hash(&self) -> Option<ContentHash> {
        ContentHash::from_hex(&self.hash).ok()
    }
}

/// Canonical relative path of the placeholder for `path`.
pub fn stub_rel(path: &str) -> String {
    format!("{path}{SUFFIX}")
}

pub fn stub_path(root: &Path, path: &str) -> Result<PathBuf> {
    safe_join(root, &stub_rel(path))
}

/// Parses a placeholder file; `None` if it isn't one.
pub fn read(file: &Path) -> Option<StubMeta> {
    let handle = std::fs::File::open(file).ok()?;
    let mut text = String::new();
    handle
        .take(MAX_STUB_LEN + 1)
        .read_to_string(&mut text)
        .ok()?;

    if text.len() as u64 > MAX_STUB_LEN {
        return None;
    }

    serde_json::from_str::<StubMeta>(text.trim())
        .ok()
        .filter(|meta| meta.rfm == FORMAT)
}

/// Atomically writes the placeholder for `meta.path` (tmp file + rename).
pub fn write(root: &Path, meta: &StubMeta) -> Result<()> {
    let target = stub_path(root, &meta.path)?;
    let tmp_dir = root.join(".mirror/tmp");

    for dir in [Some(tmp_dir.as_path()), target.parent()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(dir).map_err(|source| Error::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    }

    let mut tmp = NamedTempFile::new_in(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let mut bytes = serde_json::to_vec(meta)
        .map_err(|e| Error::Format(format!("failed to serialize placeholder: {e}")))?;
    bytes.push(b'\n');

    tmp.write_all(&bytes)
        .and_then(|()| tmp.as_file().sync_all())
        .map_err(|source| Error::Io {
            path: tmp_dir.clone(),
            source,
        })?;

    tmp.persist(&target).map_err(|source| Error::Io {
        path: target.clone(),
        source: source.error,
    })?;

    Ok(())
}

/// Removes the placeholder for `path`; a missing one is not an error.
pub fn remove(root: &Path, path: &str) -> Result<()> {
    let target = stub_path(root, path)?;

    match std::fs::remove_file(&target) {
        Err(source) if source.kind() != ErrorKind::NotFound => Err(Error::Io {
            path: target,
            source,
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_bytes;

    #[test]
    fn round_trips_and_rejects_non_placeholders() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let meta = StubMeta::new("docs/a.pdf", 5, hash_bytes(b"hello"), "data/ab/cd/x", 7);

        write(root, &meta).unwrap();
        let file = root.join("docs/a.pdf.rfm");

        assert_eq!(read(&file), Some(meta.clone()));
        assert_eq!(meta.content_hash(), Some(hash_bytes(b"hello")));

        std::fs::write(root.join("notes.rfm"), b"not json").unwrap();
        assert_eq!(read(&root.join("notes.rfm")), None);

        remove(root, "docs/a.pdf").unwrap();
        remove(root, "docs/a.pdf").unwrap();
        assert!(!file.exists());
    }
}
