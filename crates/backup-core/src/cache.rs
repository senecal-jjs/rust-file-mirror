//! A local copy of repository metadata, so repeat runs don't re-download it.
//!
//! Strictly an optimization: everything here can be rebuilt from the bucket,
//! deleting the directory only costs time, and a corrupt or unreadable entry is
//! ignored rather than reported. Nothing read from it is trusted until it has been
//! authenticated against the repository key at the point of use.
//!
//! Only immutable objects are cached, each named by an ID that never refers to
//! different contents, so there's nothing to invalidate.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::crypto::Id;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Sealed index objects: the biggest win, or every backup would download the
    /// whole index just to learn which chunks exist.
    Index,
    /// Sealed snapshot objects. Every command lists snapshots.
    Snapshot,
    /// Tree blob plaintexts, which the fast path walks every run. Checked against
    /// their keyed blob ID on use.
    Tree,
}

impl Kind {
    fn dir(&self) -> &'static str {
        match self {
            Self::Index => "index",
            Self::Snapshot => "snapshot",
            Self::Tree => "tree",
        }
    }
}

pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    /// Opens `<base>/<repo id>`, so several repositories can share one base.
    pub fn open(base: &Path, repo_id: &Id) -> Result<Self> {
        let dir = base.join(repo_id.to_string());
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, kind: Kind, id: &Id) -> PathBuf {
        self.dir.join(kind.dir()).join(id.to_string())
    }

    /// A miss and an unreadable entry look the same: either way the caller goes to
    /// the bucket.
    pub fn get(&self, kind: Kind, id: &Id) -> Option<Vec<u8>> {
        fs::read(self.path(kind, id)).ok()
    }

    /// Stores an entry through a temporary file, so a concurrent reader never sees
    /// a partial one. Failures only cost speed, so they're logged, not returned.
    pub fn put(&self, kind: Kind, id: &Id, data: &[u8]) {
        if let Err(e) = self.try_put(kind, id, data) {
            tracing::debug!(error = %e, "cache write failed");
        }
    }

    fn try_put(&self, kind: Kind, id: &Id, data: &[u8]) -> std::io::Result<()> {
        let dir = self.dir.join(kind.dir());
        fs::create_dir_all(&dir)?;
        let tmp = dir.join(format!(".tmp-{}", Id::random()));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(data)?;
            fs::rename(&tmp, self.path(kind, id))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    /// Drops one entry, e.g. after it failed to authenticate.
    pub fn remove(&self, kind: Kind, id: &Id) {
        let _ = fs::remove_file(self.path(kind, id));
    }

    pub fn clear(&self) -> Result<()> {
        match fs::remove_dir_all(&self.dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_remove_clear() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = Id::random();
        let cache = Cache::open(tmp.path(), &repo).unwrap();
        assert!(cache.dir().ends_with(repo.to_string()));

        let id = Id::random();
        assert_eq!(cache.get(Kind::Index, &id), None);
        cache.put(Kind::Index, &id, b"sealed");
        assert_eq!(cache.get(Kind::Index, &id).as_deref(), Some(&b"sealed"[..]));
        assert_eq!(
            cache.get(Kind::Tree, &id),
            None,
            "kinds are separate namespaces"
        );

        cache.put(Kind::Index, &id, b"replaced");
        assert_eq!(
            cache.get(Kind::Index, &id).as_deref(),
            Some(&b"replaced"[..])
        );
        let leftovers = fs::read_dir(cache.dir().join("index")).unwrap().count();
        assert_eq!(leftovers, 1, "no temporary files left behind");

        cache.remove(Kind::Index, &id);
        assert_eq!(cache.get(Kind::Index, &id), None);
        cache.put(Kind::Tree, &id, b"t");
        cache.clear().unwrap();
        assert!(!cache.dir().exists());
        cache.clear().unwrap();
    }

    #[test]
    fn entries_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::open(tmp.path(), &Id::random()).unwrap();
        let id = Id::random();
        cache.put(Kind::Snapshot, &id, b"x");
        let mode = fs::metadata(cache.dir().join("snapshot").join(id.to_string()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
