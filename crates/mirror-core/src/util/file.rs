use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use regex::Regex;

use crate::{
    Error, Result,
    hash::{ContentHash, hash_file},
};

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

const HASH_ATTEMPTS: usize = 3;

/// Hashes only if the file's stat is unchanged across the read; `Ok(None)` means it
/// kept moving and should be left for the next pass.
pub fn hash_stable(path: &Path) -> Result<Option<(u64, i64, ContentHash)>> {
    for _ in 0..HASH_ATTEMPTS {
        let before = file_stat(path)?;
        let hash = hash_file(path)?;
        let after = file_stat(path)?;

        if before == after {
            return Ok(Some((before.size, before.mtime_ns, hash)));
        }
    }

    Ok(None)
}

pub fn replace_name(path: &Path, name: &str) -> Result<PathBuf> {
    let canonical_path = path
        .to_str()
        .ok_or(Error::Format(format!("invalid path {}", path.display())))?;

    let split = canonical_path.rsplit_once("/");

    let root: &str;
    let filename: Option<&str>;

    if let Some(split) = split {
        root = split.0;
        filename = Some(split.1);
    } else {
        root = name;
        filename = None;
    };

    let new = if filename.is_some() {
        format!("{}/{}", root, name)
    } else {
        name.to_string()
    };

    Ok(PathBuf::from(new))
}

pub fn conflict_name(path: &str, timestamp: &str, device_name: &str) -> Result<String> {
    let name = path
        .split("/")
        .last()
        .ok_or(Error::Format(format!("invalid path format {}", path)))?;

    let split = name.rsplit_once(".");
    let stem: &str;
    let ext: Option<&str>;

    if let Some(split) = split {
        stem = split.0;
        ext = Some(split.1);
    } else {
        stem = name;
        ext = None;
    }

    // Already a conflicted copy — bump a trailing counter instead of nesting
    // a second full "(conflicted copy ...)" annotation on top of the first.
    let new_stem = if stem.contains(" (conflicted copy ") {
        let re = Regex::new(r"^(.*) \((\d+)\)$").unwrap();

        if let Some(caps) = re.captures(stem) {
            let base = &caps[1];
            let n: u32 = caps[2].parse().unwrap_or(1);
            format!("{base} ({})", n + 1)
        } else {
            format!("{stem} (2)")
        }
    } else {
        format!("{stem} (conflicted copy {timestamp} from {device_name})")
    };

    let cname = if let Some(ext) = ext {
        format!("{new_stem}.{ext}")
    } else {
        new_stem
    };

    Ok(cname)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::util::{file::conflict_name, file::replace_name};

    #[test]
    fn replace_file_name() {
        let original = PathBuf::from("/usr/bob/file1.txt");
        let replaced = replace_name(&original, "file2.txt").unwrap();

        assert_eq!("/usr/bob/file2.txt", replaced.to_str().unwrap());
    }

    #[test]
    fn replace_file_name_no_path() {
        let original = PathBuf::from("file1.txt");
        let replaced = replace_name(&original, "file2.txt").unwrap();

        assert_eq!("file2.txt", replaced.to_str().unwrap());
    }

    #[test]
    fn try_conflict_name() {
        let f1 = "/usr/bob/file1.txt";
        let timestamp = "2026-08-31T21-09-34Z";
        let cname = conflict_name(f1, timestamp, "bob's mac").unwrap();
        assert_eq!(
            "file1 (conflicted copy 2026-08-31T21-09-34Z from bob's mac).txt",
            cname
        );
    }
}
