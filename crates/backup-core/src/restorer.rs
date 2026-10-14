//! The restore side: turning a snapshot back into files.
//!
//! # Read planning
//!
//! Fetching each chunk as files reference it would issue one request per chunk in
//! an order unrelated to how chunks sit in packs. Instead, every needed chunk is
//! collected first, grouped by pack, sorted by offset, and chunks within
//! `MERGE_GAP` of each other are fetched with one ranged read. A chunk shared by
//! many files is downloaded once.
//!
//! # Containment
//!
//! Nothing a snapshot names may be written outside the target, whether the
//! snapshot is hostile or the target holds symlinks someone planted:
//!
//! - tree names are validated on load (`Tree::decode`), so joined paths are
//!   lexically contained;
//! - directories are created one component at a time, never through a symlink;
//! - every directory written into is re-checked after resolving symlinks;
//! - files are opened with `O_NOFOLLOW`, and metadata is applied through the open
//!   handle, so a path swapped for a symlink mid-restore can't redirect anything.
//!
//! Anything already in the way is only replaced with `overwrite`; otherwise the
//! restore stops rather than touch something it didn't create.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, FileTimes, OpenOptions, Permissions};
use std::io::ErrorKind;
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use futures_util::{StreamExt, TryStreamExt, stream};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use mirror_core::store::ObjectStore;

use crate::crypto::Id;
use crate::error::{Error, Result};
use crate::pack::{self, Entry};
use crate::repo::Repository;
use crate::snapshot::{MODE_MASK, Node, NodeType, Snapshot};

pub const DEFAULT_CONCURRENCY: usize = 4;

/// The most unwanted bytes worth downloading to save a request: a few kilobytes
/// cost less than another round trip.
const MERGE_GAP: u64 = 64 * 1024;

pub type ProgressFn = Arc<dyn Fn(&Progress) + Send + Sync>;

#[derive(Debug, Clone)]
pub struct Progress {
    pub path: PathBuf,
    pub files_restored: u64,
    pub bytes_restored: u64,
}

#[derive(Default)]
pub struct Options {
    /// Globs matched against paths inside the snapshot (`home/me/a.txt`, with or
    /// without a leading `/`) and against entry names. When any are given, only
    /// matching entries are restored; a matching directory brings everything in it.
    pub include: Vec<String>,
    /// Same matching; an excluded directory excludes everything beneath it.
    pub exclude: Vec<String>,
    /// How many packs are read at once.
    pub concurrency: usize,
    /// Replace whatever already occupies a restored path.
    pub overwrite: bool,
    pub progress: Option<ProgressFn>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub hardlinks: u64,
    pub bytes: u64,
}

/// Globs plus "this exact path and everything below it".
struct PathMatcher {
    globs: GlobSet,
    literals: Vec<String>,
}

impl PathMatcher {
    fn new(patterns: &[String]) -> Result<Self> {
        let mut globs = GlobSetBuilder::new();
        let mut literals = Vec::new();
        for pattern in patterns {
            let pattern = pattern.trim_start_matches('/').trim_end_matches('/');
            let glob = GlobBuilder::new(pattern)
                .literal_separator(true)
                .build()
                .map_err(|e| Error::Invalid(format!("pattern {pattern:?}: {e}")))?;
            globs.add(glob);
            literals.push(pattern.to_string());
        }
        let globs = globs
            .build()
            .map_err(|e| Error::Invalid(format!("patterns: {e}")))?;
        Ok(Self { globs, literals })
    }

    fn is_empty(&self) -> bool {
        self.literals.is_empty()
    }

    /// `path` is relative to the snapshot root, `/`-separated.
    fn matches(&self, path: &str) -> bool {
        let name = path.rsplit('/').next().unwrap_or(path);
        self.globs.is_match(path)
            || self.globs.is_match(name)
            || self.literals.iter().any(|l| {
                path == l
                    || path
                        .strip_prefix(l.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
    }
}

/// What restoring a snapshot will do, worked out before touching the disk.
#[derive(Default)]
struct Plan {
    /// Directories, parents before children, and whether each was selected itself
    /// (restored even if empty) rather than only leading to something selected.
    dirs: Vec<(String, Node, bool)>,
    symlinks: Vec<(String, Node)>,
    files: Vec<(String, Node)>,
}

/// Restores `snapshot` under `target`, reproducing its absolute paths there: a
/// snapshot of `/home/me/docs` lands in `<target>/home/me/docs`.
pub async fn restore<S: ObjectStore + 'static>(
    repo: Arc<Repository<S>>,
    snapshot: &Snapshot,
    target: &Path,
    options: Options,
) -> Result<Stats> {
    let include = PathMatcher::new(&options.include)?;
    let exclude = PathMatcher::new(&options.exclude)?;

    let target = std::path::absolute(target)
        .map_err(|e| Error::Invalid(format!("{}: {e}", target.display())))?;
    fs::create_dir_all(&target)?;
    let restorer = Arc::new(Restorer {
        resolved_target: fs::canonicalize(&target)?,
        target,
        overwrite: options.overwrite,
        progress: options.progress.clone(),
        stats: Mutex::new(Stats::default()),
    });

    // Pass one: work out what to restore.
    let mut plan = Plan::default();
    plan_tree(
        &repo,
        snapshot.tree,
        String::new(),
        include.is_empty(),
        &include,
        &exclude,
        &mut plan,
    )
    .await?;
    let plan = prune_dirs(plan);

    // Pass two: the directory skeleton and symlinks, then every file's data.
    for (rel, _, _) in &plan.dirs {
        restorer.make_dir(rel)?;
    }
    for (rel, node) in &plan.symlinks {
        restorer.make_symlink(rel, node)?;
    }
    restorer
        .restore_files(&repo, plan.files, options.concurrency.max(1))
        .await?;

    // Pass three: directory metadata, deepest first, since writing into a
    // directory changes its timestamps.
    for (rel, node, _) in plan.dirs.iter().rev() {
        apply_metadata(&restorer.path(rel), node)?;
    }

    Ok(restorer.stats.lock().expect("stats lock poisoned").clone())
}

fn child_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// Collects what to restore. `included` says whether an ancestor directory already
/// matched the include filter (or there is none), which brings in all its contents.
fn plan_tree<'a, S: ObjectStore>(
    repo: &'a Repository<S>,
    tree: Id,
    dir: String,
    included: bool,
    include: &'a PathMatcher,
    exclude: &'a PathMatcher,
    plan: &'a mut Plan,
) -> futures_util::future::BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let tree = repo.load_tree(&tree).await?;
        for node in tree.nodes {
            let rel = child_path(&dir, &node.name);
            if exclude.matches(&rel) {
                continue;
            }
            let selected = included || include.matches(&rel);
            match node.node_type {
                NodeType::Dir => {
                    let subtree = node.subtree.expect("validated by Tree::decode");
                    plan.dirs.push((rel.clone(), node, selected));
                    plan_tree(repo, subtree, rel, selected, include, exclude, plan).await?;
                }
                NodeType::Symlink if selected => plan.symlinks.push((rel, node)),
                NodeType::File if selected => plan.files.push((rel, node)),
                _ => {}
            }
        }
        Ok(())
    })
}

/// Keeps only directories that were selected themselves or lead to something
/// that's being restored, so an include filter doesn't recreate the whole skeleton.
fn prune_dirs(mut plan: Plan) -> Plan {
    let mut needed = std::collections::HashSet::new();
    let selected_dirs = plan
        .dirs
        .iter()
        .filter(|(_, _, selected)| *selected)
        .map(|(rel, _, _)| rel);
    for rel in plan
        .files
        .iter()
        .chain(&plan.symlinks)
        .map(|(rel, _)| rel)
        .chain(selected_dirs)
    {
        let mut path = rel.as_str();
        while let Some((parent, _)) = path.rsplit_once('/') {
            needed.insert(parent.to_string());
            path = parent;
        }
    }
    plan.dirs
        .retain(|(rel, _, selected)| *selected || needed.contains(rel));
    plan
}

struct Restorer {
    target: PathBuf,
    /// The target with symlinks resolved, for containment checks.
    resolved_target: PathBuf,
    overwrite: bool,
    progress: Option<ProgressFn>,
    stats: Mutex<Stats>,
}

/// One chunk to fetch, and everywhere it has to be written.
struct BlobRead {
    entry: Entry,
    destinations: Vec<(usize, u64)>,
}

impl Restorer {
    fn path(&self, rel: &str) -> PathBuf {
        self.target.join(rel)
    }

    fn add_stats(&self, update: impl FnOnce(&mut Stats)) {
        update(&mut self.stats.lock().expect("stats lock poisoned"));
    }

    /// Confirms `dir` is inside the target once symlinks are resolved. Component-
    /// wise creation protects what this restore creates; this also covers
    /// directories that already existed.
    fn check_contained(&self, dir: &Path) -> Result<()> {
        let resolved = fs::canonicalize(dir)?;
        if !resolved.starts_with(&self.resolved_target) {
            return Err(Error::Invalid(format!(
                "{} resolves to {}, outside the restore target",
                dir.display(),
                resolved.display()
            )));
        }
        Ok(())
    }

    /// Removes whatever is at `path` (only with `overwrite`) to make way for a new
    /// entry. Never follows a symlink: the link itself is removed.
    fn clear(&self, path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
            Ok(_) if !self.overwrite => Err(Error::Invalid(format!(
                "{} already exists; pass --overwrite to replace it",
                path.display()
            ))),
            Ok(meta) if meta.is_dir() => Ok(fs::remove_dir_all(path)?),
            Ok(_) => Ok(fs::remove_file(path)?),
        }
    }

    /// Creates one directory without following a symlink in its place. Parents are
    /// always created first (the plan is ordered), so each call adds one component.
    fn make_dir(&self, rel: &str) -> Result<()> {
        let path = self.path(rel);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                // A symlink or file sits where the directory belongs.
                self.clear(&path)?;
                fs::create_dir(&path)?;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => fs::create_dir(&path)?,
            Err(e) => return Err(e.into()),
        }
        self.check_contained(&path)?;
        self.add_stats(|s| s.dirs += 1);
        Ok(())
    }

    fn make_symlink(&self, rel: &str, node: &Node) -> Result<()> {
        let path = self.path(rel);
        self.check_contained(path.parent().expect("rel is non-empty"))?;
        self.clear(&path)?;
        std::os::unix::fs::symlink(
            node.link_target
                .as_deref()
                .expect("validated by Tree::decode"),
            &path,
        )?;
        self.add_stats(|s| s.symlinks += 1);
        Ok(())
    }

    /// Creates an empty file to be filled at offsets. Closed straight away: holding
    /// every file open would need a descriptor per file in the snapshot.
    fn create_file(&self, path: &Path, size: u64) -> Result<()> {
        self.check_contained(path.parent().expect("rel is non-empty"))?;
        // Clearing an existing symlink matters: opening it, even with O_NOFOLLOW
        // failing safely, would otherwise block the restore with a confusing error.
        if fs::symlink_metadata(path).is_ok_and(|m| !m.is_file()) {
            self.clear(path)?;
        }

        let mut options = OpenOptions::new();
        options
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        if self.overwrite {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let file = options.open(path).map_err(|e| match e.kind() {
            ErrorKind::AlreadyExists => Error::Invalid(format!(
                "{} already exists; pass --overwrite to replace it",
                path.display()
            )),
            _ => Error::Invalid(format!("creating {}: {e}", path.display())),
        })?;
        file.set_len(size)?;
        Ok(())
    }

    async fn restore_files<S: ObjectStore + 'static>(
        self: &Arc<Self>,
        repo: &Arc<Repository<S>>,
        files: Vec<(String, Node)>,
        concurrency: usize,
    ) -> Result<()> {
        // Files sharing a device and inode were hardlinks: write the first, link the
        // rest to it once it's complete.
        let mut first_of_inode: HashMap<(u64, u64), PathBuf> = HashMap::new();
        let mut to_write = Vec::new();
        let mut links = Vec::new();
        for (rel, node) in files {
            let path = self.path(&rel);
            if node.is_hardlink() {
                match first_of_inode.get(&(node.device, node.inode)) {
                    Some(existing) => {
                        links.push((existing.clone(), path));
                        continue;
                    }
                    None => {
                        first_of_inode.insert((node.device, node.inode), path.clone());
                    }
                }
            }
            to_write.push((path, node));
        }

        for (path, node) in &to_write {
            self.create_file(path, node.size)?;
        }

        // Group every needed chunk by pack, keeping every place it's written.
        let index = repo.index();
        let mut by_pack: BTreeMap<Id, HashMap<Id, BlobRead>> = BTreeMap::new();
        for (file_index, (path, node)) in to_write.iter().enumerate() {
            let mut offset = 0;
            for chunk in &node.content {
                let location = index.lookup(chunk).ok_or_else(|| {
                    Error::Incomplete(format!(
                        "{} references chunk {}, which no index lists",
                        path.display(),
                        chunk.short()
                    ))
                })?;
                by_pack
                    .entry(location.pack_id)
                    .or_default()
                    .entry(*chunk)
                    .or_insert_with(|| BlobRead {
                        entry: location.entry,
                        destinations: Vec::new(),
                    })
                    .destinations
                    .push((file_index, offset));
                offset += u64::from(location.entry.plain_length);
            }
            if offset != node.size {
                return Err(Error::Format(format!(
                    "{}: chunks add up to {offset} bytes but the snapshot records {}",
                    path.display(),
                    node.size
                )));
            }
        }

        let paths: Arc<Vec<PathBuf>> = Arc::new(to_write.iter().map(|(p, _)| p.clone()).collect());
        let reads: Vec<_> = by_pack
            .into_iter()
            .map(|(pack_id, blobs)| self.read_pack(repo, pack_id, blobs, Arc::clone(&paths)))
            .collect();
        stream::iter(reads)
            .buffer_unordered(concurrency)
            .try_collect::<()>()
            .await?;

        for (path, node) in &to_write {
            apply_metadata(path, node)?;
            self.add_stats(|s| {
                s.files += 1;
                s.bytes += node.size;
            });
            self.report(path);
        }

        for (existing, path) in links {
            self.check_contained(path.parent().expect("rel is non-empty"))?;
            self.clear(&path)?;
            fs::hard_link(&existing, &path)?;
            self.add_stats(|s| s.hardlinks += 1);
        }
        Ok(())
    }

    /// Fetches the needed regions of one pack and writes the chunks out.
    async fn read_pack<S: ObjectStore + 'static>(
        self: &Arc<Self>,
        repo: &Arc<Repository<S>>,
        pack_id: Id,
        blobs: HashMap<Id, BlobRead>,
        paths: Arc<Vec<PathBuf>>,
    ) -> Result<()> {
        let mut reads: Vec<_> = blobs.into_values().collect();
        reads.sort_by_key(|r| r.entry.offset);
        let key = repo.object_key(&pack::object_name(&pack_id));

        for group in group_reads(reads) {
            let start = u64::from(group[0].entry.offset);
            let end = group
                .iter()
                .map(|r| r.entry.end())
                .max()
                .expect("groups are non-empty");
            let data = repo.store().get_range(&key, start, end - start).await?;

            let (repo, paths) = (Arc::clone(repo), Arc::clone(&paths));
            tokio::task::spawn_blocking(move || -> Result<()> {
                for read in group {
                    let at = (u64::from(read.entry.offset) - start) as usize;
                    let sealed = &data[at..at + read.entry.length as usize];
                    let plaintext = pack::decode_blob(repo.keys(), &read.entry, sealed)?;
                    for (file_index, offset) in read.destinations {
                        write_at(&paths[file_index], &plaintext, offset)?;
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| Error::Invalid(format!("restore task failed: {e}")))??;
        }
        Ok(())
    }

    fn report(&self, path: &Path) {
        if let Some(progress) = &self.progress {
            let stats = self.stats.lock().expect("stats lock poisoned").clone();
            progress(&Progress {
                path: path.to_path_buf(),
                files_restored: stats.files,
                bytes_restored: stats.bytes,
            });
        }
    }
}

/// Merges offset-sorted reads lying within `MERGE_GAP` of each other.
fn group_reads(reads: Vec<BlobRead>) -> Vec<Vec<BlobRead>> {
    let mut groups: Vec<Vec<BlobRead>> = Vec::new();
    let mut end = 0;
    for read in reads {
        let start = u64::from(read.entry.offset);
        match groups.last_mut() {
            Some(group) if start <= end + MERGE_GAP => {
                end = end.max(read.entry.end());
                group.push(read);
            }
            _ => {
                end = read.entry.end();
                groups.push(vec![read]);
            }
        }
    }
    groups
}

/// Writes one chunk into a file created earlier. `O_NOFOLLOW` keeps the write from
/// being redirected if the file was swapped for a symlink since.
fn write_at(path: &Path, data: &[u8], offset: u64) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Error::Invalid(format!("opening {}: {e}", path.display())))?;
    file.write_all_at(data, offset)
        .map_err(|e| Error::Invalid(format!("writing {}: {e}", path.display())))
}

/// Applies recorded ownership, permissions, and times through an open handle, so
/// nothing can be redirected through a symlink. Ownership is best effort (restoring
/// someone else's files without privileges is normal) and comes before the mode,
/// since changing owner clears setuid and setgid. Times come last, because writing
/// content updates them; access time isn't recorded, so it's set to the mtime.
/// Symlinks are left alone: their own metadata can't be set portably.
fn apply_metadata(path: &Path, node: &Node) -> Result<()> {
    if node.node_type == NodeType::Symlink {
        return Ok(());
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file: File = options
        .open(path)
        .map_err(|e| Error::Invalid(format!("opening {}: {e}", path.display())))?;

    let _ = std::os::unix::fs::fchown(&file, Some(node.uid), Some(node.gid));
    file.set_permissions(Permissions::from_mode(node.mode & MODE_MASK))
        .map_err(|e| Error::Invalid(format!("setting permissions on {}: {e}", path.display())))?;
    let mtime = SystemTime::from(node.mtime);
    file.set_times(FileTimes::new().set_accessed(mtime).set_modified(mtime))
        .map_err(|e| Error::Invalid(format!("setting times on {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::Compression;
    use crate::pack::BlobType;

    fn read(offset: u32, length: u32) -> BlobRead {
        BlobRead {
            entry: Entry {
                blob_type: BlobType::Data,
                compression: Compression::None,
                id: Id::random(),
                offset,
                length,
                plain_length: length,
            },
            destinations: vec![],
        }
    }

    fn shape(groups: &[Vec<BlobRead>]) -> Vec<Vec<u32>> {
        groups
            .iter()
            .map(|g| g.iter().map(|r| r.entry.offset).collect())
            .collect()
    }

    #[test]
    fn group_reads_merges_neighbours_within_the_gap() {
        let gap = MERGE_GAP as u32;
        let groups = group_reads(vec![
            read(0, 100),
            read(100, 100),             // adjacent
            read(200 + gap, 10),        // exactly at the gap: merged
            read(210 + 2 * gap + 1, 5), // one byte past: new group
            read(1_000_000, 1),
        ]);
        assert_eq!(
            shape(&groups),
            vec![
                vec![0, 100, 200 + gap],
                vec![210 + 2 * gap + 1],
                vec![1_000_000]
            ]
        );
        assert!(group_reads(vec![]).is_empty());
    }

    #[test]
    fn path_matcher_semantics() {
        let m =
            PathMatcher::new(&["*.pdf".into(), "/home/me/docs/".into(), "build.d".into()]).unwrap();
        assert!(m.matches("home/me/a.pdf"), "name glob");
        assert!(
            m.matches("home/me/docs"),
            "leading and trailing slashes ignored"
        );
        assert!(
            m.matches("home/me/docs/sub/x.txt"),
            "a literal covers what's beneath it"
        );
        assert!(!m.matches("home/me/docsx"));
        assert!(m.matches("src/build.d"));
        assert!(!m.matches("home/me/a.txt"));
        assert!(PathMatcher::new(&[]).unwrap().is_empty());
        assert!(PathMatcher::new(&["[".into()]).is_err());
    }
}
