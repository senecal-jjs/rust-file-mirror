use std::path::{Component, Path, PathBuf};

use ignore::WalkBuilder;
use unicode_normalization::UnicodeNormalization;

use crate::hash::ContentHash;
use crate::util::file::{file_stat, hash_stable};
use crate::{Error, Result};

/// A file discovered on disk, keyed by its canonical relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEntry {
    pub path: String,
    pub size: u64,
    pub mtime_ns: i64,
    pub hash: ContentHash,
}

const ALWAYS_EXCLUDE: &[&str] = &[".mirror", ".DS_Store", "Thumbs.db", "desktop.ini"];

/// Lets the scanner reuse a known hash when size and mtime are unchanged
pub trait HashCache {
    fn cached(&self, path: &str, size: u64, mtime_ns: i64) -> Option<ContentHash>;
}

/// Always hash.
impl HashCache for () {
    fn cached(&self, _path: &str, _size: u64, _mtime_ns: i64) -> Option<ContentHash> {
        None
    }
}

pub struct Scanner {
    root: PathBuf,
    ignore_file: String,
}

impl Scanner {
    pub fn new(root: impl Into<PathBuf>, ignore_file: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            ignore_file: ignore_file.into(),
        }
    }

    pub fn scan(&self, cache: &impl HashCache) -> Result<Vec<LocalEntry>> {
        let mut builder = WalkBuilder::new(&self.root);

        builder
            .hidden(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .parents(false)
            .follow_links(false)
            .filter_entry(|dent| {
                dent.file_name()
                    .to_str()
                    .is_none_or(|name| !ALWAYS_EXCLUDE.contains(&name))
            });

        builder.add_custom_ignore_filename(&self.ignore_file);

        let mut entries = Vec::new();

        for result in builder.build() {
            let dent = result.map_err(|e| Error::Scan(e.to_string()))?;

            if dent.depth() == 0 || !dent.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }

            let path = dent.path();
            let rel = canonical_relative(&self.root, path)?;
            let stats = file_stat(path)?;

            let (size, mtime_ns, hash) = match cache.cached(&rel, stats.size, stats.mtime_ns) {
                Some(hash) => (stats.size, stats.mtime_ns, hash),
                None => match hash_stable(path)? {
                    Some(triple) => triple,
                    None => {
                        tracing::warn!(path = %path.display(), "file changed while hashing; deferring");
                        continue;
                    }
                },
            };

            entries.push(LocalEntry {
                path: canonical_relative(&self.root, path)?,
                size,
                mtime_ns,
                hash,
            })
        }

        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }
}

/// Root-relative, '/'-separated, NFC-normalized. macOS hands back NFD, which would
/// otherwise hash differently than the same name on Linux.
fn canonical_relative(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| Error::Scan(format!("{} is outside {}", path.display(), root.display())))?;

    let mut parts = Vec::new();

    for component in rel.components() {
        match component {
            Component::Normal(os) => {
                let text = os
                    .to_str()
                    .ok_or_else(|| Error::Scan(format!("non-UTF-8 path: {}", path.display())))?;

                parts.push(text.nfc().collect::<String>());
            }
            _ => {
                return Err(Error::Scan(format!(
                    "unexpected path component in {}",
                    path.display()
                )));
            }
        }
    }

    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn respects_ignore_file_and_always_excluded_names() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        write(root, "a.txt", "one");
        write(root, "docs/notes.md", "two");
        write(root, "build/output.o", "junk");
        write(root, ".mirror/state.db", "state");
        write(root, ".DS_Store", "junk");
        write(root, ".mirrorignore", "build/\n");

        let entries = Scanner::new(root, ".mirrorignore").scan(&()).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();

        assert_eq!(paths, vec![".mirrorignore", "a.txt", "docs/notes.md"]);
    }

    #[test]
    fn identical_contents_hash_identically() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        write(root, "a.txt", "same");
        write(root, "b.txt", "same");
        write(root, "c.txt", "different");

        let entries = Scanner::new(root, ".mirrorignore").scan(&()).unwrap();

        assert_eq!(entries[0].hash, entries[1].hash);
        assert_ne!(entries[0].hash, entries[2].hash);
        assert_eq!(entries[0].hash.to_string().len(), 64);
    }
}
