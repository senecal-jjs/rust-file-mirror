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
//! # Offloaded files
//!
//! A mirror placeholder (`<name>.rfm`) stands in for a file whose content lives only
//! in the bucket. With `Offloaded::Include`, it's archived as that file, under its
//! real name: by reusing an earlier snapshot's chunks for the same content hash when
//! there are some (no download), and otherwise by streaming the content from an
//! `OffloadedSource` and checking it against the placeholder's hash.
//!
//! # Resuming
//!
//! A run that stops before saving its snapshot isn't wasted. The packs it uploaded
//! are adopted by the next run (`Repository::adopt_orphans`), and the files it
//! finished are in its resume journal (`journal`), so the next run of the same
//! paths skips them. What's redone is the pack that was being filled, and the files
//! whose chunks were in it.
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use mirror_core::placeholder::{self, StubMeta};
use mirror_core::store::ObjectStore;
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::chunker;
use crate::crypto::Id;
use crate::error::{Error, Result};
use crate::filter::Filter;
use crate::journal;
use crate::lock::Lock;
use crate::pack::BlobType;
use crate::repo::Repository;
use crate::snapshot::{MODE_MASK, Node, NodeType, Snapshot, Stats, Tree, same_content};

pub const DEFAULT_CONCURRENCY: usize = 4;

/// What to do about a file that can't be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Skip,
    Abort,
}

pub type ErrorPolicy = Arc<dyn Fn(&Path, &Error) -> Decision + Send + Sync>;

/// Supplies the content behind mirror placeholders.
pub trait OffloadedSource: Send + Sync {
    /// The plaintext `stub` stands for. Called on a blocking worker thread; the
    /// archiver checks what it reads against the stub's size and hash.
    fn open(&self, stub: &StubMeta) -> Result<Box<dyn Read + Send>>;
}

/// What to do with mirror placeholders (`*.rfm` files that parse as stubs).
#[derive(Clone, Default)]
pub enum Offloaded {
    /// No special treatment: they're backed up as the small files they are.
    #[default]
    AsFiles,
    /// Left out, and counted in `Stats::offloaded_skipped`.
    Skip,
    /// Backed up as the files they stand for (see the module docs).
    Include(Arc<dyn OffloadedSource>),
}
pub type ProgressFn = Arc<dyn Fn(&Progress) + Send + Sync>;
pub type ActivityFn = Arc<dyn Fn(Activity<'_>) + Send + Sync>;

/// What happened to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOutcome {
    New,
    Changed,
    /// Matched the parent snapshot; not read.
    Unchanged,
    /// Finished by an interrupted run; not read.
    Resumed,
    /// A placeholder whose content an earlier snapshot already held.
    OffloadedReused,
    /// A placeholder whose content was fetched from the bucket.
    OffloadedDownloaded,
}

/// A step of a run outside the per-file work, for showing progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// Looking for packs an interrupted run left, to reuse.
    CheckingForInterrupted,
    /// Reading the parent snapshot's directory trees, for the unchanged-file check.
    LoadingParent,
    /// An interrupted run's journal lists this many reusable files.
    Resuming(usize),
    /// Walking the paths and archiving files.
    Scanning,
    /// Uploading the last pack and this run's index.
    Finishing,
    SavingSnapshot,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CheckingForInterrupted => {
                f.write_str("checking for an interrupted backup to resume")
            }
            Self::LoadingParent => f.write_str("loading the previous snapshot"),
            Self::Resuming(files) => write!(
                f,
                "resuming: {files} files were finished by an interrupted backup"
            ),
            Self::Scanning => f.write_str("scanning files"),
            Self::Finishing => f.write_str("uploading the last pack and the index"),
            Self::SavingSnapshot => f.write_str("saving the snapshot"),
        }
    }
}

/// Fine-grained progress, so a long step never looks like a hang.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activity<'a> {
    Stage(Stage),
    /// A file being read: `done` of its `size` bytes so far. Sent when reading
    /// starts and after each chunk is stored.
    Reading {
        path: &'a Path,
        done: u64,
        size: u64,
    },
    /// Reading `path` ended, whether it finished, was skipped, or failed.
    ReadDone {
        path: &'a Path,
    },
}

#[derive(Debug, Clone)]
pub struct Progress {
    pub path: PathBuf,
    pub outcome: FileOutcome,
    /// The file's size.
    pub size: u64,
    /// Running totals for the run.
    pub files_processed: u64,
    pub bytes_processed: u64,
    pub bytes_added: u64,
}

pub struct Options {
    /// Consulted for every entry below the requested paths (not the paths
    /// themselves). An excluded directory isn't descended into.
    pub filters: Vec<Arc<dyn Filter>>,
    /// Mirror placeholders: as files, skipped, or as the content they stand for.
    pub offloaded: Offloaded,
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
    /// Stages and per-file read progress, possibly from several threads at once.
    pub activity: Option<ActivityFn>,
    /// Set to stop the run; it then fails with `Error::Cancelled`.
    pub cancel: Option<Arc<AtomicBool>>,
    /// Use the resume journal of an earlier unfinished run of these paths (see
    /// `journal`). Off for a run meant to read every file.
    pub resume: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            filters: Vec::new(),
            offloaded: Offloaded::AsFiles,
            parent: None,
            hostname: gethostname::gethostname().to_string_lossy().into_owned(),
            username: std::env::var("USER").unwrap_or_default(),
            tags: Vec::new(),
            concurrency: DEFAULT_CONCURRENCY,
            on_error: None,
            progress: None,
            activity: None,
            cancel: None,
            resume: true,
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

    let cleaned = normalize_paths(paths)?;
    for path in &cleaned {
        fs::symlink_metadata(path)
            .map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?;
    }
    let path_strings = path_strings(&cleaned)?;

    // Shared with other backups, exclusive of a prune; see `lock`.
    let lock = Lock::acquire(Arc::clone(repo.store()), repo.base(), repo.keys(), false).await?;
    let result = backup_locked(Arc::clone(&repo), cleaned, path_strings, options, &lock).await;
    if let Err(e) = lock.release().await {
        tracing::warn!(error = %e, "releasing the repository lock failed; it expires on its own");
    }
    result
}

async fn backup_locked<S: ObjectStore + 'static>(
    repo: Arc<Repository<S>>,
    cleaned: Vec<PathBuf>,
    path_strings: Vec<String>,
    options: Options,
    lock: &Lock<S>,
) -> Result<Snapshot> {
    let activity = options.activity.clone();
    let stage = move |stage: Stage| {
        if let Some(activity) = &activity {
            activity(Activity::Stage(stage));
        }
    };

    // Anything an interrupted run uploaded is already in the bucket; take it over
    // before deciding what's new.
    stage(Stage::CheckingForInterrupted);
    let packs_adopted = repo.adopt_orphans().await? as u64;

    let mut parent = ParentIndex::default();
    if let Some(snapshot) = &options.parent {
        stage(Stage::LoadingParent);
        load_parent(&repo, snapshot.tree, PathBuf::from("/"), &mut parent).await;
    }

    // What an unfinished run of these paths had done, as far as the repository
    // can vouch for it: an entry whose chunks didn't all reach the bucket is
    // dropped, and its file read again.
    let journal_path = repo
        .cache()
        .map(|cache| journal::path_for(cache, &path_strings));
    if let (true, Some(path)) = (options.resume, &journal_path) {
        for (file, node) in journal::load(path, repo.keys()) {
            if node.content.iter().all(|id| repo.index().has(id)) {
                if let Some(hash) = &node.content_hash {
                    parent.by_hash.insert(hash.clone(), node.clone());
                }
                parent.resumed.insert(file, node);
            }
        }
        if !parent.resumed.is_empty() {
            stage(Stage::Resuming(parent.resumed.len()));
        }
    }
    let journal = journal_path.as_deref().and_then(|path| {
        journal::Writer::open(path)
            .map_err(|e| tracing::warn!(error = %e, "no resume journal for this run"))
            .ok()
    });

    let run = Arc::new(Run {
        repo: Arc::clone(&repo),
        semaphore: Arc::new(Semaphore::new(options.concurrency.max(1))),
        cancel: options.cancel.clone().unwrap_or_default(),
        aborted: AtomicBool::new(false),
        stats: Mutex::new(Stats {
            packs_adopted,
            ..Stats::default()
        }),
        parent,
        journal,
        handle: Handle::current(),
        options,
    });

    stage(Stage::Scanning);
    let mut trie = Trie::default();
    for path in &cleaned {
        trie.insert(path);
    }
    let root = Arc::clone(&run)
        .archive_trie(Arc::new(trie), PathBuf::from("/"))
        .await?;

    // Every pack and the index must be durable before the snapshot names them.
    run.stage(Stage::Finishing);
    repo.flush().await?;
    // If a prune ran while this lock was lost, chunks this run reused may be gone.
    lock.ensure_held()?;

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
    run.stage(Stage::SavingSnapshot);
    repo.save_snapshot(&mut snapshot).await?;
    // Everything the journal described is in a snapshot now.
    if let Some(path) = &journal_path {
        journal::remove(path);
    }
    Ok(snapshot)
}

/// The paths a snapshot of `paths` records: absolute, lexically clean, sorted, and
/// without any already covered by another. Callers choosing a parent snapshot
/// compare against these.
pub fn normalize_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut cleaned = paths
        .iter()
        .map(|p| clean_path(p))
        .collect::<Result<Vec<_>>>()?;
    cleaned.sort();
    Ok(remove_nested(cleaned))
}

/// `normalize_paths` output as the strings a snapshot stores.
pub fn path_strings(paths: &[PathBuf]) -> Result<Vec<String>> {
    paths
        .iter()
        .map(|p| {
            p.to_str()
                .map(str::to_string)
                .ok_or_else(|| Error::Invalid(format!("{} is not valid UTF-8", p.display())))
        })
        .collect()
}

/// An absolute path with `.` and `..` resolved lexically: the form snapshots record.
pub fn clean_path(path: &Path) -> Result<PathBuf> {
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

/// The parent snapshot's files: by absolute path for the fast path, and by content
/// hash so a placeholder can reuse content backed up before it was offloaded (or
/// under another name).
#[derive(Default)]
struct ParentIndex {
    by_path: HashMap<PathBuf, Node>,
    by_hash: HashMap<String, Node>,
    /// Files an unfinished earlier run finished, from its journal; checked before
    /// `by_path`, since they're newer.
    resumed: HashMap<PathBuf, Node>,
}

/// Loads the parent snapshot's files. A parent that can't be read in full isn't
/// fatal: affected files are just read again, which is slower but still correct.
fn load_parent<'a, S: ObjectStore>(
    repo: &'a Repository<S>,
    tree: Id,
    dir: PathBuf,
    parent: &'a mut ParentIndex,
) -> BoxFuture<'a, ()> {
    async move {
        let Ok(tree) = repo.load_tree(&tree).await else {
            return;
        };
        for node in tree.nodes {
            let path = dir.join(&node.name);
            match (node.node_type, node.subtree) {
                (NodeType::Dir, Some(subtree)) => load_parent(repo, subtree, path, parent).await,
                (NodeType::File, _) => {
                    if let Some(hash) = &node.content_hash {
                        parent
                            .by_hash
                            .entry(hash.clone())
                            .or_insert_with(|| node.clone());
                    }
                    parent.by_path.insert(path, node);
                }
                _ => {}
            }
        }
    }
    .boxed()
}

/// A file's content once chunked and stored.
struct Chunked {
    content: Vec<Id>,
    hash: String,
    total: u64,
    added: u64,
    new_chunks: u64,
    duplicates: u64,
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
    parent: ParentIndex,
    journal: Option<journal::Writer>,
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

    fn report(&self, path: &Path, outcome: FileOutcome, size: u64) {
        let Some(progress) = &self.options.progress else {
            return;
        };
        let snapshot = {
            let s = self.stats.lock().expect("stats lock poisoned");
            Progress {
                path: path.to_path_buf(),
                outcome,
                size,
                files_processed: s.files_new
                    + s.files_changed
                    + s.files_unmodified
                    + s.files_resumed
                    + s.offloaded_reused
                    + s.offloaded_downloaded,
                bytes_processed: s.bytes_processed,
                bytes_added: s.bytes_added,
            }
        };
        progress(&snapshot);
    }

    fn stage(&self, stage: Stage) {
        if let Some(activity) = &self.options.activity {
            activity(Activity::Stage(stage));
        }
    }

    fn activity(&self, activity: Activity<'_>) {
        if let Some(callback) = &self.options.activity {
            callback(activity);
        }
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

    /// `source_error`, for a placeholder whose content couldn't be had: counted as
    /// an offloaded file skipped, not an unreadable one.
    fn offloaded_error(&self, path: &Path, error: Error) -> Result<Option<Node>> {
        let decision = self
            .options
            .on_error
            .as_ref()
            .map_or(Decision::Skip, |f| f(path, &error));
        match decision {
            Decision::Skip => {
                tracing::warn!(path = %path.display(), %error, "skipping offloaded file");
                self.add_stats(|s| s.offloaded_skipped += 1);
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

            // To notice a placeholder whose real file also exists.
            let names: HashSet<_> = entries.iter().map(|e| e.file_name()).collect();
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
                let stub = match (&self.options.offloaded, name.strip_suffix(placeholder::SUFFIX)) {
                    (Offloaded::AsFiles, _) | (_, None | Some("")) => None,
                    (_, Some(_)) if !meta.is_file() => None,
                    (_, Some(real)) => placeholder::read(&path).map(|stub| (real.to_string(), stub)),
                };
                if let Some((real, stub)) = stub {
                    let source = match &self.options.offloaded {
                        Offloaded::Include(source) => Arc::clone(source),
                        _ => {
                            self.add_stats(|s| s.offloaded_skipped += 1);
                            continue;
                        }
                    };
                    if names.contains(std::ffi::OsStr::new(&real)) {
                        // The mirror never leaves both; the real file is the truth.
                        tracing::warn!(path = %path.display(), "placeholder beside its real file; backing up the file");
                        self.add_stats(|s| s.offloaded_skipped += 1);
                        continue;
                    }
                    let permit = Arc::clone(&self.semaphore)
                        .acquire_owned()
                        .await
                        .expect("semaphore never closed");
                    let run = Arc::clone(&self);
                    files.spawn_blocking(move || {
                        let _permit = permit;
                        run.archive_offloaded(&path, &real, &meta, &stub, source.as_ref())
                    });
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
        if let Some(done) = self
            .parent
            .resumed
            .get(path)
            .filter(|done| same_content(done, &node))
        {
            node.content = done.content.clone();
            node.content_hash = done.content_hash.clone();
            self.add_stats(|s| {
                s.files_resumed += 1;
                s.bytes_processed += node.size;
            });
            self.report(path, FileOutcome::Resumed, node.size);
            return Ok(Some(node));
        }

        let parent = self.parent.by_path.get(path);
        if let Some(old) = parent.filter(|old| same_content(old, &node)) {
            node.content = old.content.clone();
            node.content_hash = old.content_hash.clone();
            self.add_stats(|s| {
                s.files_unmodified += 1;
                s.bytes_processed += node.size;
            });
            self.report(path, FileOutcome::Unchanged, node.size);
            return Ok(Some(node));
        }

        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) => return self.source_error(path, e.into()),
        };
        let chunked = match self.store_chunks(path, node.size, file)? {
            Ok(chunked) => chunked,
            Err(e) => return self.source_error(path, e),
        };

        // The file may have changed size since it was statted; record what was read.
        node.size = chunked.total;
        node.content_hash = Some(chunked.hash.clone());
        self.add_stats(|s| {
            if parent.is_some() {
                s.files_changed += 1;
            } else {
                s.files_new += 1;
            }
            self.count_chunked(s, &chunked);
        });
        node.content = chunked.content;
        self.record(path, &node);
        let outcome = if parent.is_some() {
            FileOutcome::Changed
        } else {
            FileOutcome::New
        };
        self.report(path, outcome, node.size);
        Ok(Some(node))
    }

    /// Notes a file this run has finished, for resuming if it doesn't complete.
    fn record(&self, path: &Path, node: &Node) {
        if let Some(journal) = &self.journal {
            journal.record(self.repo.keys(), path, node);
        }
    }

    /// Archives a placeholder as the file it stands for, named `real`. Runs on a
    /// blocking thread.
    fn archive_offloaded(
        &self,
        path: &Path,
        real: &str,
        meta: &Metadata,
        stub: &StubMeta,
        source: &dyn OffloadedSource,
    ) -> Result<Option<Node>> {
        self.check()?;
        let mut node = match Node::from_metadata(path, real, meta) {
            Ok(node) => node,
            Err(e) => return self.offloaded_error(path, e),
        };
        // The placeholder's own inode and ctime say nothing about the file.
        (node.inode, node.device, node.links, node.ctime) = (0, 0, 0, None);
        let stub_hash = stub.hash.to_ascii_lowercase();
        node.size = stub.size;
        node.offloaded = true;
        node.content_hash = Some(stub_hash.clone());

        // Content backed up before it was offloaded, if every chunk is still there.
        let reusable = self.parent.by_hash.get(&stub_hash).filter(|old| {
            old.size == stub.size && old.content.iter().all(|id| self.repo.index().has(id))
        });

        // Metadata: what the placeholder recorded, else what the earlier copy had,
        // else the placeholder file's mtime and a conventional mode.
        if let Some(ns) = stub.mtime_ns {
            node.mtime = chrono::DateTime::from_timestamp_nanos(ns);
        } else if let Some(old) = reusable {
            node.mtime = old.mtime;
        }
        node.mode = match (stub.mode, reusable) {
            (Some(mode), _) => mode & MODE_MASK,
            (None, Some(old)) => old.mode,
            (None, None) => 0o644,
        };

        if let Some(old) = reusable {
            node.content = old.content.clone();
            self.add_stats(|s| {
                s.offloaded_reused += 1;
                s.bytes_processed += stub.size;
            });
            self.report(path, FileOutcome::OffloadedReused, stub.size);
            return Ok(Some(node));
        }

        let reader = match source.open(stub) {
            Ok(reader) => reader,
            Err(e) => return self.offloaded_error(path, e),
        };
        let chunked = match self.store_chunks(path, stub.size, reader)? {
            Ok(chunked) => chunked,
            Err(e) => return self.offloaded_error(path, e),
        };
        // Chunks already stored for a mismatch stay unreferenced until a prune.
        if chunked.hash != stub_hash || chunked.total != stub.size {
            let error = Error::Corrupt(format!(
                "the content fetched for {} ({} bytes)",
                path.display(),
                chunked.total
            ));
            return self.offloaded_error(path, error);
        }

        self.add_stats(|s| {
            s.offloaded_downloaded += 1;
            s.offloaded_bytes_downloaded += chunked.total;
            self.count_chunked(s, &chunked);
        });
        node.content = chunked.content;
        self.record(&path.with_file_name(real), &node);
        self.report(path, FileOutcome::OffloadedDownloaded, stub.size);
        Ok(Some(node))
    }

    /// Chunks `reader` into the repository, hashing as it goes. The outer error is
    /// fatal (the repository); the inner one is about the source, for the caller's
    /// skip policy.
    fn store_chunks(
        &self,
        path: &Path,
        size: u64,
        reader: impl Read,
    ) -> Result<std::result::Result<Chunked, Error>> {
        // Says reading ended however this returns.
        struct Done<'a, S: ObjectStore + 'static>(&'a Run<S>, &'a Path);
        impl<S: ObjectStore + 'static> Drop for Done<'_, S> {
            fn drop(&mut self) {
                self.0.activity(Activity::ReadDone { path: self.1 });
            }
        }
        let _done = Done(self, path);
        self.activity(Activity::Reading {
            path,
            done: 0,
            size,
        });

        let chunks = chunker::chunks(self.repo.config().chunker, reader)?;
        let mut hasher = blake3::Hasher::new();
        let mut chunked = Chunked {
            content: Vec::new(),
            hash: String::new(),
            total: 0,
            added: 0,
            new_chunks: 0,
            duplicates: 0,
        };
        for chunk in chunks {
            self.check()?;
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(e) => return Ok(Err(e)),
            };
            hasher.update(&chunk);
            // A repository failure invalidates the run, not just this file.
            let (id, stored) = self
                .handle
                .block_on(self.repo.save_blob(BlobType::Data, &chunk))?;
            chunked.content.push(id);
            chunked.total += chunk.len() as u64;
            self.activity(Activity::Reading {
                path,
                done: chunked.total,
                size,
            });
            if stored {
                chunked.added += chunk.len() as u64;
                chunked.new_chunks += 1;
            } else {
                chunked.duplicates += 1;
            }
        }
        chunked.hash = hasher.finalize().to_hex().to_string();
        Ok(Ok(chunked))
    }

    fn count_chunked(&self, s: &mut Stats, chunked: &Chunked) {
        s.bytes_processed += chunked.total;
        s.bytes_added += chunked.added;
        s.chunks_new += chunked.new_chunks;
        s.chunks_duplicate += chunked.duplicates;
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
