//! Deciding what a backup leaves out.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use mirror_core::scanner::ALWAYS_EXCLUDE;

use crate::error::{Error, Result};

pub trait Filter: Send + Sync {
    /// `path` is absolute; `is_dir` comes from `lstat`. An excluded directory is
    /// never descended into.
    fn excluded(&self, path: &Path, is_dir: bool) -> bool;
}

/// User exclude patterns. Each is a glob matched against the entry's name and its
/// full path (`*` doesn't cross `/`), so both `*.log` and `/var/cache/*` work; a
/// plain absolute path also excludes everything beneath it.
pub struct Excludes {
    globs: GlobSet,
    dirs: Vec<PathBuf>,
}

impl Excludes {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let mut globs = GlobSetBuilder::new();
        let mut dirs = Vec::new();
        for pattern in patterns {
            let glob = GlobBuilder::new(pattern)
                .literal_separator(true)
                .build()
                .map_err(|e| Error::Invalid(format!("exclude pattern {pattern:?}: {e}")))?;
            globs.add(glob);
            if pattern.starts_with('/') {
                dirs.push(PathBuf::from(pattern.trim_end_matches('/')));
            }
        }
        let globs = globs
            .build()
            .map_err(|e| Error::Invalid(format!("exclude patterns: {e}")))?;
        Ok(Self { globs, dirs })
    }
}

impl Filter for Excludes {
    fn excluded(&self, path: &Path, _is_dir: bool) -> bool {
        path.file_name()
            .is_some_and(|name| self.globs.is_match(name))
            || self.globs.is_match(path)
            || self.dirs.iter().any(|dir| path.starts_with(dir))
    }
}

/// What the mirror itself leaves out of `root`, so backing up a mirror root behaves
/// like the mirror: `.mirror/` (per-root state, including the saved passphrase), the
/// scanner's always-excluded names, and `ignore_file` rules at every level, with a
/// deeper file's rules winning over a shallower one's. Paths outside `root` pass.
pub struct MirrorFilter {
    root: PathBuf,
    ignore_file: String,
    /// Directory → its parsed ignore file, if it has one.
    loaded: Mutex<HashMap<PathBuf, Option<Arc<Gitignore>>>>,
}

impl MirrorFilter {
    pub fn new(root: impl Into<PathBuf>, ignore_file: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            ignore_file: ignore_file.into(),
            loaded: Mutex::new(HashMap::new()),
        }
    }

    fn rules(&self, dir: &Path) -> Option<Arc<Gitignore>> {
        let mut loaded = self.loaded.lock().expect("filter lock poisoned");
        loaded
            .entry(dir.to_path_buf())
            .or_insert_with(|| {
                let file = dir.join(&self.ignore_file);
                if !file.is_file() {
                    return None;
                }
                let mut builder = GitignoreBuilder::new(dir);
                if let Some(e) = builder.add(&file) {
                    tracing::warn!(file = %file.display(), error = %e, "unreadable ignore rules");
                }
                builder.build().ok().map(Arc::new)
            })
            .clone()
    }
}

impl Filter for MirrorFilter {
    fn excluded(&self, path: &Path, is_dir: bool) -> bool {
        let Ok(rel) = path.strip_prefix(&self.root) else {
            return false;
        };
        if rel.as_os_str().is_empty() {
            return false;
        }
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| ALWAYS_EXCLUDE.contains(&name))
        {
            return true;
        }

        // Deepest ignore file first: the first one with an opinion decides.
        for dir in path.ancestors().skip(1) {
            if let Some(rules) = self.rules(dir) {
                match rules.matched(path, is_dir) {
                    Match::Ignore(_) => return true,
                    Match::Whitelist(_) => return false,
                    Match::None => {}
                }
            }
            if dir == self.root {
                break;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn excludes_match_names_full_paths_and_directories() {
        let ex = Excludes::new(&[
            "*.log".into(),
            "/data/cache/*".into(),
            "/srv/tmp".into(),
            "node_modules".into(),
        ])
        .unwrap();
        assert!(ex.excluded(Path::new("/a/b/debug.log"), false));
        assert!(ex.excluded(Path::new("/data/cache/x"), false));
        assert!(
            !ex.excluded(Path::new("/data/cache/x/y"), false),
            "* doesn't cross /"
        );
        assert!(ex.excluded(Path::new("/srv/tmp"), true));
        assert!(ex.excluded(Path::new("/srv/tmp/deep/file"), false));
        assert!(!ex.excluded(Path::new("/srv/tmpfile"), false));
        assert!(ex.excluded(Path::new("/p/node_modules"), true));
        assert!(!ex.excluded(Path::new("/a/b/debug.txt"), false));
        assert!(Excludes::new(&["[".into()]).is_err());
    }

    #[test]
    fn mirror_filter_follows_the_mirrors_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("sub/keep")).unwrap();
        fs::write(root.join(".mirrorignore"), "*.tmp\nbuild/\n").unwrap();
        fs::write(
            root.join("sub/.mirrorignore"),
            "!important.tmp\nlocal.txt\n",
        )
        .unwrap();

        let f = MirrorFilter::new(root, ".mirrorignore");
        let ex = |rel: &str, is_dir| f.excluded(&root.join(rel), is_dir);

        assert!(ex(".mirror", true), "state dir");
        assert!(ex(".DS_Store", false));
        assert!(ex("sub/.DS_Store", false));
        assert!(ex("scratch.tmp", false));
        assert!(ex("build", true));
        assert!(!ex("build", false), "build/ only matches directories");
        assert!(ex("sub/other.tmp", false), "parent rules apply below");
        assert!(!ex("sub/important.tmp", false), "deeper whitelist wins");
        assert!(ex("sub/local.txt", false));
        assert!(!ex("local.txt", false), "deeper rules don't apply above");
        assert!(!ex("sub/keep", true));
        assert!(!ex(".mirrorignore", false));
        assert!(
            !f.excluded(Path::new("/elsewhere/x.tmp"), false),
            "outside root"
        );
        assert!(!f.excluded(root, true));
    }
}
