use std::path::Path;
use std::time::UNIX_EPOCH;

use crate::{Error, Result};

#[derive(Debug, PartialEq, Eq)]
pub struct FileStat {
    pub size: u64,
    pub mtime_ns: i64,
}

/// Size and mtime, the cheap identity used to detect change without reading contents.
pub fn file_stat(path: &Path) -> Result<FileStat> {
    let meta = path.metadata().map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let modified = meta.modified().map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let since_epoch = modified
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Scan(format!("mtime precedes unix epoch: {}", path.display())))?;

    Ok(FileStat {
        size: meta.len(),
        mtime_ns: i64::try_from(since_epoch.as_nanos()).unwrap_or(i64::MAX),
    })
}
