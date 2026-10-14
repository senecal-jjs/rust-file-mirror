//! The backup side: walk the filesystem, decide what changed, chunk new data, and
//! assemble the trees that make up a snapshot.
//!
//! # What makes a run incremental
//!
//! - **Unchanged files are never read.** If a file's metadata matches the parent
//!   snapshot (`snapshot::same_content`), its chunk list is copied from the parent
//!   tree and the file is never opened.
//! - **Changed files cost only what changed.** New or modified files are chunked
//!   by content and each chunk is looked up before upload, so an edit to a huge
//!   file costs the bytes around the edit, and content that moved costs nothing.
//!
//! # Errors
//!
//! A file that can't be read is a local problem affecting that file alone, and the
//! default policy skips it. A failed write to the repository is different: by the
//! time it surfaces, blobs that files already in the tree reference may be missing,
//! so the whole run stops and no snapshot is written. The two are kept apart
//! throughout: only source errors ever reach the skip policy.
//!
//! # Ordering
//!
//! Trees are built bottom-up, so a directory's tree is saved only after every child
//! it names. The snapshot is written last, after `flush` has stored every pack and
//! the index.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, Metadata};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use mirror_core::placeholder;
use mirror_core::store::ObjectStore;
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::chunker;
use crate::crypto::Id;
use crate::error::{Error, Result};
use crate::filter::Filter;
use crate::pack::BlobType;
use crate::repo::Repository;
use crate::snapshot::{Node, NodeType, Snapshot, Stats, Tree, same_content};

pub const DEFAULT_CONCURRENCY: usize = 4;

/// What to do about a file that can't be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Skip,
    Abort,
}

pub type ErrorPolicy = Arc<dyn Fn(&Path, &Error) -> Decision + Send + Sync>;
pub type ProgressFn = Arc<dyn Fn(&Progress) + Send + Sync>;

#[derive(Debug, Clone)]
pub struct Progress {
    pub path: PathBuf,
    pub files_processed: u64,
    pub bytes_processed: u64,
    pub bytes_added: u64,
}

pub struct Options {
    /// Consulted for every entry below the requested paths (not the paths
    /// themselves). An excluded directory isn't descended into.
    pub filters: Vec<Arc<dyn Filter>>,
    /// Skip mirror placeholders (`*.rfm` stubs standing in for offloaded files):
    /// their content isn't local. Counted in `Stats::placeholders_skipped`.
    pub skip_placeholders: bool,
    /// The snapshot to compare against. Without one every file is read, though
    /// deduplication still avoids re-uploading known data.
    pub parent: Option<Snapshot>,
    pub hostname: String,
    pub username: String,
    pub tags: Vec<String>,
    /// How many files are read and chunked at once, across the whole walk.
    pub concurrency: usize,
    /// For unreadable files; the default skips them.
    pub on_error: Option<ErrorPolicy>,
    /// Called after each file, possibly from several threads at once.
    pub progress: Option<ProgressFn>,
    /// Set to stop the run; it then fails with `Error::Cancelled`.
    pub cancel: Option<Arc<AtomicBool>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            filters: Vec::new(),
            skip_placeholders: false,
            parent: None,
            hostname: gethostname::gethostname().to_string_lossy().into_owned(),
            username: std::env::var("USER").unwrap_or_default(),
            tags: Vec::new(),
            concurrency: DEFAULT_CONCURRENCY,
            on_error: None,
            progress: None,
            cancel: None,
        }
    }
}

/// Backs up `paths` into `repo` and returns the saved snapshot.
pub async fn backup<S: ObjectStore + 'static>(
    repo: Arc<Repository<S>>,
    paths: &[PathBuf],
    options: Options,
) -> Result<Snapshot> {
    if paths.is_empty() {
        return Err(Error::Invalid("no paths to back up".into()));
    }

    let mut cleaned = Vec::with_capacity(paths.len());
    for path in paths {
        let clean = clean_path(path)?;
        fs::symlink_metadata(&clean)
            .map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
        cleaned.push(clean);
    }
    cleaned.sort();
    let cleaned = remove_nested(cleaned);
    let path_strings = cleaned
        .iter()
        .map(|p| {
            p.to_str()
                .map(str::to_string)
                .ok_or_else(|| Error::Invalid(format!("{} is not valid UTF-8", p.display())))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut parent_files = HashMap::new();
    if let Some(parent) = &options.parent {
        load_parent(&repo, parent.tree, PathBuf::from("/"), &mut parent_files).await;
    }

    let run = Arc::new(Run {
        repo: Arc::clone(&repo),
        semaphore: Arc::new(Semaphore::new(options.concurrency.max(1))),
        cancel: options.cancel.clone().unwrap_or_default(),
        aborted: AtomicBool::new(false),
        stats: Mutex::new(Stats::default()),
        parent_files,
        handle: Handle::current(),
        options,
    });

    let mut trie = Trie::default();
    for path in &cleaned {
        trie.insert(path);
    }
    let root = Arc::clone(&run)
        .archive_trie(Arc::new(trie), PathBuf::from("/"))
        .await?;

    // Every pack and the index must be durable before the snapshot names them.
    repo.flush().await?;

    let options = &run.options;
    let mut snapshot = Snapshot {
        id: Id::default(),
        time: Utc::now(),
        hostname: options.hostname.clone(),
        username: options.username.clone(),
        paths: path_strings,
        tags: options.tags.clone(),
        tree: root,
        parent: options.parent.as_ref().map(|p| p.id),
        stats: run.stats.lock().expect("stats lock poisoned").clone(),
    };
    repo.save_snapshot(&mut snapshot).await?;
    Ok(snapshot)
}

/// An absolute path with `.` and `..` resolved lexically.
fn clean_path(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)
        .map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
    let mut out = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    Ok(out)
}

/// Drops paths an earlier (sorted) one already covers, so nothing is archived twice.
fn remove_nested(sorted: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::with_capacity(sorted.len());
    for path in sorted {
        if !out.last().is_some_and(|kept| path.starts_with(kept)) {
            out.push(path);
        }
    }
    out
}

/// Records every file in the parent snapshot by absolute path, for the fast path.
/// A parent that can't be read in full isn't fatal: affected files are just read
/// again, which is slower but still correct.
fn load_parent<'a, S: ObjectStore>(
    repo: &'a Repository<S>,
    tree: Id,
    dir: PathBuf,
    files: &'a mut HashMap<PathBuf, Node>,
) -> BoxFuture<'a, ()> {
    async move {
        let Ok(tree) = repo.load_tree(&tree).await else {
            return;
        };
        for node in tree.nodes {
            let path = dir.join(&node.name);
            match (node.node_type, node.subtree) {
                (NodeType::Dir, Some(subtree)) => load_parent(repo, subtree, path, files).await,
                (NodeType::File, _) => {
                    files.insert(path, node);
                }
                _ => {}
            }
        }
    }
    .boxed()
}

/// The directories above the requested paths.
#[derive(Default, Clone)]
struct Trie {
    children: BTreeMap<String, Arc<Trie>>,
    /// A requested path, whose real contents are archived.
    terminal: bool,
}

impl Trie {
    fn insert(&mut self, path: &Path) {
        let mut node = self;
        for part in path.components().filter_map(|c| match c {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        }) {
            node = Arc::make_mut(node.children.entry(part).or_default());
        }
        node.terminal = true;
    }
}

struct Run<S> {
    repo: Arc<Repository<S>>,
    options: Options,
    /// Bounds file work across the whole walk. One shared semaphore rather than one
    /// per directory, or a deep tree would run `concurrency × depth` files at once.
    semaphore: Arc<Semaphore>,
    /// The caller's cancellation.
    cancel: Arc<AtomicBool>,
    /// Set by the first fatal error, so every other worker stops rather than reading
    /// and uploading data no snapshot will reference.
    aborted: AtomicBool,
    stats: Mutex<Stats>,
    parent_files: HashMap<PathBuf, Node>,
    handle: Handle,
}

impl<S: ObjectStore + 'static> Run<S> {
    fn stopped(&self) -> bool {
        self.aborted.load(Ordering::Relaxed) || self.cancel.load(Ordering::Relaxed)
    }

    fn check(&self) -> Result<()> {
        if self.stopped() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }

    fn add_stats(&self, update: impl FnOnce(&mut Stats)) {
        update(&mut self.stats.lock().expect("stats lock poisoned"));
    }

    fn report(&self, path: &Path) {
        let Some(progress) = &self.options.progress else {
            return;
        };
        let snapshot = {
            let s = self.stats.lock().expect("stats lock poisoned");
            Progress {
                path: path.to_path_buf(),
                files_processed: s.files_new + s.files_changed + s.files_unmodified,
                bytes_processed: s.bytes_processed,
                bytes_added: s.bytes_added,
            }
        };
        progress(&snapshot);
    }

    /// Applies the error policy to a problem reading the source. `Ok(None)` skips
    /// the entry; an error ends the run.
    fn source_error(&self, path: &Path, error: Error) -> Result<Option<Node>> {
        let decision = self
            .options
            .on_error
            .as_ref()
            .map_or(Decision::Skip, |f| f(path, &error));
        match decision {
            Decision::Skip => {
                tracing::warn!(path = %path.display(), %error, "skipping");
                self.add_stats(|s| s.files_skipped += 1);
                Ok(None)
            }
            Decision::Abort => Err(Error::Invalid(format!("{}: {error}", path.display()))),
        }
    }

    async fn save_tree(&self, nodes: Vec<Node>) -> Result<Id> {
        self.repo.save_tree(&Tree::new(nodes)).await
    }

    /// An intermediate directory: real metadata, but only the children leading to a
    /// requested path.
    fn archive_trie(
        self: Arc<Self>,
        trie: Arc<Trie>,
        dir: PathBuf,
    ) -> BoxFuture<'static, Result<Id>> {
        async move {
            let mut nodes = Vec::new();
            for (name, child) in &trie.children {
                let path = dir.join(name);
                let node = if child.terminal {
                    // A requested path is recorded as it is, so backing up a symlink
                    // stores a symlink.
                    let meta = fs::symlink_metadata(&path)
                        .map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
                    Arc::clone(&self)
                        .archive_entry(path, name.clone(), meta)
                        .await?
                } else {
                    // Intermediate components are followed. On macOS /var is a
                    // symlink to /private/var, and backing up /var/log must treat
                    // "var" as the directory it leads to.
                    let meta = fs::metadata(&path)
                        .map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
                    let mut node = Node::from_metadata(&path, name, &meta)?;
                    node.subtree = Some(
                        Arc::clone(&self)
                            .archive_trie(Arc::clone(child), path)
                            .await?,
                    );
                    Some(node)
                };
                nodes.extend(node);
            }
            self.save_tree(nodes).await
        }
        .boxed()
    }

    /// Archives a real filesystem entry. `Ok(None)` means it was skipped.
    fn archive_entry(
        self: Arc<Self>,
        path: PathBuf,
        name: String,
        meta: Metadata,
    ) -> BoxFuture<'static, Result<Option<Node>>> {
        async move {
            self.check()?;
            let mut node = match Node::from_metadata(&path, &name, &meta) {
                Ok(node) => node,
                // Sockets, devices, FIFOs, and unreadable links land here.
                Err(e) => return self.source_error(&path, e),
            };

            match node.node_type {
                NodeType::Symlink => Ok(Some(node)),
                NodeType::Dir => {
                    node.subtree = Some(Arc::clone(&self).archive_dir(path).await?);
                    self.add_stats(|s| s.dirs_processed += 1);
                    Ok(Some(node))
                }
                NodeType::File => {
                    let permit = Arc::clone(&self.semaphore)
                        .acquire_owned()
                        .await
                        .expect("semaphore never closed");
                    let run = Arc::clone(&self);
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        run.archive_file(&path, node)
                    })
                    .await
                    .map_err(|e| Error::Invalid(format!("file task failed: {e}")))?
                }
            }
        }
        .boxed()
    }

    /// Archives a directory's children and returns its tree ID.
    fn archive_dir(self: Arc<Self>, dir: PathBuf) -> BoxFuture<'static, Result<Id>> {
        async move {
            let mut entries =
                match fs::read_dir(&dir).and_then(|rd| rd.collect::<std::io::Result<Vec<_>>>()) {
                    Ok(entries) => entries,
                    Err(e) => {
                        self.source_error(&dir, e.into())?;
                        // An unreadable directory is recorded as empty.
                        return self.save_tree(Vec::new()).await;
                    }
                };
            entries.sort_by_key(|e| e.file_name());

            let mut nodes = Vec::new();
            let mut files = JoinSet::new();
            let mut first_error: Option<Error> = None;

            // Keeps the first real error; a bare `Cancelled` from a worker that was
            // stopped because of it is never the one worth reporting.
            let record = |first: &mut Option<Error>, error: Error, run: &Self| {
                run.aborted.store(true, Ordering::Relaxed);
                if first.is_none() || matches!(first, Some(Error::Cancelled)) {
                    *first = Some(error);
                }
            };

            for entry in entries {
                // Collect files that already finished, so an error stops the walk
                // promptly instead of after every remaining entry is queued.
                while let Some(done) = files.try_join_next() {
                    match done
                        .map_err(|e| Error::Invalid(format!("file task failed: {e}")))
                        .and_then(|r| r)
                    {
                        Ok(node) => nodes.extend(node),
                        Err(e) => record(&mut first_error, e, &self),
                    }
                }
                if first_error.is_some() || self.stopped() {
                    break;
                }

                let path = entry.path();
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    if let Err(e) =
                        self.source_error(&path, Error::Invalid("name is not valid UTF-8".into()))
                    {
                        record(&mut first_error, e, &self);
                    }
                    continue;
                };
                let meta = match fs::symlink_metadata(&path) {
                    Ok(meta) => meta,
                    Err(e) => {
                        if let Err(e) = self.source_error(&path, e.into()) {
                            record(&mut first_error, e, &self);
                        }
                        continue;
                    }
                };

                if self
                    .options
                    .filters
                    .iter()
                    .any(|f| f.excluded(&path, meta.is_dir()))
                {
                    continue;
                }
                if self.options.skip_placeholders
                    && meta.is_file()
                    && name.ends_with(placeholder::SUFFIX)
                    && placeholder::read(&path).is_some()
                {
                    self.add_stats(|s| s.placeholders_skipped += 1);
                    continue;
                }

                if meta.is_file() {
                    // Files go to the worker pool; waiting for a permit here is what
                    // bounds the whole walk.
                    let permit = Arc::clone(&self.semaphore)
                        .acquire_owned()
                        .await
                        .expect("semaphore never closed");
                    let run = Arc::clone(&self);
                    files.spawn_blocking(move || {
                        let _permit = permit;
                        match Node::from_metadata(&path, &name, &meta) {
                            Ok(node) => run.archive_file(&path, node),
                            Err(e) => run.source_error(&path, e),
                        }
                    });
                } else {
                    // Directories recurse here, so the pool isn't tied up by tasks
                    // that only wait on their children.
                    match Arc::clone(&self).archive_entry(path, name, meta).await {
                        Ok(node) => nodes.extend(node),
                        Err(e) => record(&mut first_error, e, &self),
                    }
                }
            }

            // Every exit waits here: returning early would leave workers still
            // writing to the repository after the run reported its result.
            while let Some(done) = files.join_next().await {
                match done
                    .map_err(|e| Error::Invalid(format!("file task failed: {e}")))
                    .and_then(|r| r)
                {
                    Ok(node) => nodes.extend(node),
                    Err(e) => record(&mut first_error, e, &self),
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            self.check()?;
            self.save_tree(nodes).await
        }
        .boxed()
    }

    /// Fills in a file's content, reusing the parent's chunk list when unchanged.
    /// Runs on a blocking thread.
    fn archive_file(&self, path: &Path, mut node: Node) -> Result<Option<Node>> {
        let parent = self.parent_files.get(path);
        if let Some(old) = parent.filter(|old| same_content(old, &node)) {
            node.content = old.content.clone();
            self.add_stats(|s| {
                s.files_unmodified += 1;
                s.bytes_processed += node.size;
            });
            self.report(path);
            return Ok(Some(node));
        }

        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) => return self.source_error(path, e.into()),
        };
        let chunks = chunker::chunks(self.repo.config().chunker, file)?;

        let (mut content, mut total, mut added, mut new_chunks, mut duplicates) =
            (Vec::new(), 0u64, 0u64, 0u64, 0u64);
        for chunk in chunks {
            self.check()?;
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(e) => return self.source_error(path, e),
            };
            // A repository failure invalidates the run, not just this file.
            let (id, stored) = self
                .handle
                .block_on(self.repo.save_blob(BlobType::Data, &chunk))?;
            content.push(id);
            total += chunk.len() as u64;
            if stored {
                added += chunk.len() as u64;
                new_chunks += 1;
            } else {
                duplicates += 1;
            }
        }

        node.content = content;
        // The file may have changed size since it was statted; record what was read.
        node.size = total;
        self.add_stats(|s| {
            if parent.is_some() {
                s.files_changed += 1;
            } else {
                s.files_new += 1;
            }
            s.bytes_processed += total;
            s.bytes_added += added;
            s.chunks_new += new_chunks;
            s.chunks_duplicate += duplicates;
        });
        self.report(path);
        Ok(Some(node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_path_resolves_dots_lexically() {
        assert_eq!(
            clean_path(Path::new("/a/./b/../c/")).unwrap(),
            PathBuf::from("/a/c")
        );
        assert_eq!(clean_path(Path::new("/../..")).unwrap(), PathBuf::from("/"));
        assert!(clean_path(Path::new("rel")).unwrap().is_absolute());
    }

    #[test]
    fn remove_nested_keeps_only_outermost_paths() {
        let paths = ["/a", "/a/b", "/a/b/c", "/ab", "/b", "/b"]
            .map(PathBuf::from)
            .to_vec();
        assert_eq!(
            remove_nested(paths),
            ["/a", "/ab", "/b"].map(PathBuf::from).to_vec()
        );
    }
}
