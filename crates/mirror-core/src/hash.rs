use std::fmt;
use std::fs::File;
use std::path::Path;

use serde::Serialize;

use crate::{Error, Result};

/// BLAKE3 digest of a file's plaintext contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_hex(text: &str) -> Result<Self> {
        let hash =
            blake3::Hash::from_hex(text).map_err(|e| Error::Hash(format!("{text:?}: {e}")))?;
        Ok(Self(*hash.as_bytes()))
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        f.pad(&hex)
    }
}

pub fn hash_file(path: &Path) -> Result<ContentHash> {
    let file = File::open(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let mut hasher = blake3::Hasher::new();

    // memory mapping may be faster for hashing large files
    hasher.update_reader(&file).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    Ok(ContentHash(*hasher.finalize().as_bytes()))
}

pub fn hash_bytes(bytes: &[u8]) -> ContentHash {
    let mut hasher = blake3::Hasher::new();

    let hash = hasher.update(bytes).finalize();

    ContentHash(*hash.as_bytes())
}
