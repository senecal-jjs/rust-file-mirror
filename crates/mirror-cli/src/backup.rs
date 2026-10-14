//! `rfm backup`: encrypted, deduplicated point-in-time snapshots in the same bucket
//! as the mirror, under the same vault passphrase.

use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use backup_core::archiver::{
    self, Decision, Offloaded, OffloadedSource, normalize_paths, path_strings,
};
use backup_core::crypto::Keys;
use backup_core::filter::{Excludes, Filter, MirrorFilter};
use backup_core::repo::{self, InitOptions, Repository};
use backup_core::snapshot::{self, Node, NodeType, Snapshot};
use backup_core::{prune, restorer, verify};
use chrono::Local;
use clap::Subcommand;
use indicatif::{ProgressBar, ProgressStyle};
use mirror_core::apply::download::{PlaintextStream, open_plaintext};
use mirror_core::config::{Config, KeepPolicy, OffloadedBackup};
use mirror_core::crypto::key::DerivedSubKeys;
use mirror_core::indicator::human_bytes;
use mirror_core::placeholder::StubMeta;
use mirror_core::store::ObjectStore;
use mirror_core::store::s3::{S3PartSource, S3Store};

#[derive(Subcommand)]
pub(crate) enum BackupCmd {
    /// Back up paths (the mirrored root by default) as a new snapshot
    Create {
        /// Files or directories; defaults to the mirrored root
        paths: Vec<PathBuf>,
        /// Leave out entries matching a glob (by name or full path); repeatable
        #[arg(long = "exclude", value_name = "GLOB")]
        excludes: Vec<String>,
        /// Label the snapshot; repeatable
        #[arg(long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// Also back up what the mirror's ignore rules leave out (`.mirror/` is always skipped)
        #[arg(long)]
        no_mirrorignore: bool,
        /// Read every file, instead of reusing unchanged ones from the last snapshot or
        /// finished ones from an interrupted backup
        #[arg(long)]
        full: bool,
        /// Leave offloaded files (placeholders) out instead of backing up their content
        #[arg(long)]
        skip_offloaded: bool,
        /// Print a line for every file as it's backed up
        #[arg(long, short)]
        verbose: bool,
    },

    /// List snapshots, or the files in one
    List {
        /// A snapshot ID, ID prefix, or `latest`
        snapshot: Option<String>,
    },

    /// Restore a snapshot into a directory
    Restore {
        /// A snapshot ID, ID prefix, or `latest`
        #[arg(default_value = "latest")]
        snapshot: String,
        /// Where to restore; original absolute paths are recreated beneath it
        #[arg(long)]
        target: PathBuf,
        /// Only restore entries matching a glob (by name or path in the snapshot); repeatable
        #[arg(long = "include", value_name = "GLOB")]
        includes: Vec<String>,
        /// Skip entries matching a glob; repeatable
        #[arg(long = "exclude", value_name = "GLOB")]
        excludes: Vec<String>,
        /// Replace files and links already in the target
        #[arg(long)]
        overwrite: bool,
    },

    /// Forget old snapshots by retention rules, and free the space only they used
    Prune {
        /// Keep the newest N snapshots
        #[arg(long, value_name = "N")]
        keep_last: Option<usize>,
        /// Keep the newest snapshot of each of the last N hours that have one
        #[arg(long, value_name = "N")]
        keep_hourly: Option<usize>,
        /// Same, per day
        #[arg(long, value_name = "N")]
        keep_daily: Option<usize>,
        /// Same, per week
        #[arg(long, value_name = "N")]
        keep_weekly: Option<usize>,
        /// Same, per month
        #[arg(long, value_name = "N")]
        keep_monthly: Option<usize>,
        /// Same, per year
        #[arg(long, value_name = "N")]
        keep_yearly: Option<usize>,
        /// Show what would be forgotten and freed without deleting anything
        #[arg(long)]
        dry_run: bool,
    },

    /// Check the backup repository is complete and readable
    Verify {
        /// Also download and check every byte (costs a full download)
        #[arg(long)]
        read_data: bool,
    },
}

pub(crate) async fn run(config_path: &Path, cmd: BackupCmd, no_cache: bool) -> Result<()> {
    let config = Config::load(config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    match cmd {
        BackupCmd::Create {
            paths,
            excludes,
            tags,
            no_mirrorignore,
            full,
            skip_offloaded,
            verbose,
        } => {
            let mut request = Request::from_config(&config);
            if !paths.is_empty() {
                request.paths = paths;
            }
            request.excludes.extend(excludes);
            request.tags = tags;
            request.mirrorignore &= !no_mirrorignore;
            request.full = full;
            request.offloaded &= !skip_offloaded;
            let display = crate::backup_progress::Display::new(real_root(&config)?, verbose);
            let (repo, mirror) =
                connect(&config, no_cache, true, &|step| display.early(step)).await?;
            create(&config, repo, &mirror, request, display).await
        }
        BackupCmd::Prune {
            keep_last,
            keep_hourly,
            keep_daily,
            keep_weekly,
            keep_monthly,
            keep_yearly,
            dry_run,
        } => {
            let flags = [
                keep_last,
                keep_hourly,
                keep_daily,
                keep_weekly,
                keep_monthly,
                keep_yearly,
            ];
            // Flags replace the configured rules entirely, rather than mixing with them.
            let policy = if flags.iter().any(Option::is_some) {
                KeepPolicy {
                    last: keep_last.unwrap_or(0),
                    hourly: keep_hourly.unwrap_or(0),
                    daily: keep_daily.unwrap_or(0),
                    weekly: keep_weekly.unwrap_or(0),
                    monthly: keep_monthly.unwrap_or(0),
                    yearly: keep_yearly.unwrap_or(0),
                }
            } else {
                config.backup.keep
            };
            anyhow::ensure!(
                !policy.is_empty(),
                "no retention rules: pass --keep-daily 7 (etc.), or set [backup.keep] in the config"
            );
            let repo = open(&config, no_cache, false).await?;
            prune_cmd(&repo, &policy, dry_run).await
        }
        BackupCmd::List { snapshot } => {
            let repo = open(&config, no_cache, false).await?;
            match snapshot {
                None => list_snapshots(&repo).await,
                Some(reference) => list_files(&repo, &reference).await,
            }
        }
        BackupCmd::Restore {
            snapshot,
            target,
            includes,
            excludes,
            overwrite,
        } => {
            let repo = open(&config, no_cache, false).await?;
            restore(repo, &snapshot, &target, includes, excludes, overwrite).await
        }
        BackupCmd::Verify { read_data } => {
            let repo = open(&config, no_cache, false).await?;
            verify(&repo, read_data).await
        }
    }
}

/// Where repository metadata is cached between runs.
fn cache_base() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("rfm").join("backup"))
}

/// Connects, unlocks the vault, and opens the repository (creating it on the first
/// `create`).
async fn open(config: &Config, no_cache: bool, create: bool) -> Result<Arc<Repository<S3Store>>> {
    Ok(connect(config, no_cache, create, &|_| {}).await?.0)
}

/// `open`, also keeping the mirror's store and keys for fetching offloaded files.
async fn connect(
    config: &Config,
    no_cache: bool,
    create: bool,
    step: &dyn Fn(&str),
) -> Result<(Arc<Repository<S3Store>>, Mirror)> {
    step(&format!("connecting to bucket {}", config.remote.bucket));
    let store = Arc::new(S3Store::connect(&config.remote).await?);
    store.check().await.context("checking bucket")?;
    step("unlocking the vault (deriving keys from the passphrase)");
    let enc_keys = Arc::new(crate::derive_enc_keys(config, &store).await?);
    step("opening the backup repository and loading its index");
    let repo = open_repo(config, Arc::clone(&store), &enc_keys, no_cache, create).await?;
    Ok((repo, Mirror { store, enc_keys }))
}

/// The mirror's side of the bucket: where offloaded files' content lives.
pub(crate) struct Mirror {
    pub store: Arc<S3Store>,
    pub enc_keys: Arc<DerivedSubKeys>,
}

/// Reads offloaded files' content from the mirror's objects, decrypting as it
/// streams. Runs on the archiver's blocking worker threads.
struct MirrorSource {
    store: Arc<S3Store>,
    enc_keys: Arc<DerivedSubKeys>,
    prefix: String,
    handle: tokio::runtime::Handle,
}

impl OffloadedSource for MirrorSource {
    fn open(&self, stub: &StubMeta) -> backup_core::Result<Box<dyn std::io::Read + Send>> {
        let key = format!("{}{}", self.prefix, stub.object_key);
        // Sealed for the file's logical path, which the placeholder records.
        let stream = self.handle.block_on(open_plaintext(
            self.store.as_ref(),
            &key,
            &stub.path,
            &self.enc_keys.content_key,
        ))?;
        Ok(Box::new(StreamReader {
            stream,
            handle: self.handle.clone(),
            buf: Vec::new(),
            pos: 0,
        }))
    }
}

/// A blocking `Read` over a plaintext stream.
struct StreamReader {
    stream: PlaintextStream<S3PartSource>,
    handle: tokio::runtime::Handle,
    buf: Vec<u8>,
    pos: usize,
}

impl std::io::Read for StreamReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos == self.buf.len() {
            match self
                .handle
                .block_on(self.stream.next())
                .map_err(std::io::Error::other)?
            {
                Some(next) => (self.buf, self.pos) = (next, 0),
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Opens the repository with keys already unlocked (the daemon holds them).
pub(crate) async fn open_repo(
    config: &Config,
    store: Arc<S3Store>,
    enc_keys: &DerivedSubKeys,
    no_cache: bool,
    create: bool,
) -> Result<Arc<Repository<S3Store>>> {
    let keys = Keys::derive(&enc_keys.backup_key);
    let cache = if no_cache { None } else { cache_base() };
    let prefix = &config.remote.prefix;
    let repo = if create {
        Repository::open_or_init(
            store,
            prefix,
            keys,
            InitOptions::default(),
            cache.as_deref(),
        )
        .await?
    } else {
        match Repository::open(store, prefix, keys, cache.as_deref()).await {
            Err(backup_core::Error::NotInitialized(_)) => {
                anyhow::bail!("no backups yet: run `rfm backup create` first")
            }
            other => other?,
        }
    };
    Ok(Arc::new(repo))
}

/// Holds `<root>/.mirror/backup.lock` for the run, so two backups from this device
/// (say, a scheduled one and a manual one) don't race. Backups from other devices
/// are kept apart from prunes by the repository's own lock.
fn lock(root: &Path) -> Result<std::fs::File> {
    let dir = root.join(".mirror");
    std::fs::create_dir_all(&dir)?;
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("backup.lock"))?;
    if fs2::FileExt::try_lock_exclusive(&file).is_err() {
        anyhow::bail!("another backup of {} is already running", root.display());
    }
    Ok(file)
}

fn spinner() -> Option<ProgressBar> {
    if !std::io::stderr().is_terminal() {
        return None;
    }
    let bar = ProgressBar::new_spinner();
    bar.set_style(ProgressStyle::with_template("{spinner} {msg}").expect("valid template"));
    bar.enable_steady_tick(Duration::from_millis(120));
    Some(bar)
}

/// Sets `flag` on Ctrl-C, so the run stops cleanly without writing a snapshot.
fn cancel_on_ctrl_c() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let set = Arc::clone(&flag);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            set.store(true, Ordering::Relaxed);
        }
    });
    flag
}

/// What to back up: `[backup]` config, plus any command-line overrides.
pub(crate) struct Request {
    /// The mirrored root when empty.
    pub paths: Vec<PathBuf>,
    pub excludes: Vec<String>,
    pub tags: Vec<String>,
    pub mirrorignore: bool,
    /// Read every file rather than trusting the last snapshot's metadata.
    pub full: bool,
    /// Back up offloaded files' content rather than leaving them out.
    pub offloaded: bool,
    /// Hold off idle sleep while the backup runs.
    pub keep_awake: bool,
}

impl Request {
    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            paths: config.backup.paths.clone(),
            excludes: config.backup.exclude.clone(),
            tags: Vec::new(),
            mirrorignore: config.backup.mirrorignore,
            full: false,
            offloaded: config.backup.offloaded == OffloadedBackup::Include,
            keep_awake: config.backup.keep_awake,
        }
    }

    /// The paths to archive. The root, whether by default or named, is given in its
    /// resolved form: a path that's a symlink is archived as a symlink, and a mirror
    /// root that's a link to the real folder (an external drive, say) must still be
    /// backed up as that folder.
    fn resolved_paths(&self, root: &Path) -> Vec<PathBuf> {
        if self.paths.is_empty() {
            return vec![root.to_path_buf()];
        }
        self.paths
            .iter()
            .map(|path| match std::fs::canonicalize(path) {
                Ok(real) if real == root => real,
                _ => path.clone(),
            })
            .collect()
    }
}

/// The mirror root with symlinks resolved, so filters and recorded paths agree with
/// what the walk sees.
fn real_root(config: &Config) -> Result<PathBuf> {
    let root = &config.local.root;
    std::fs::canonicalize(root).with_context(|| format!("resolving {}", root.display()))
}

/// Where a run reports to: a terminal for `rfm backup create`, the event hub for
/// the daemon.
pub(crate) struct Hooks {
    pub info: Arc<dyn Fn(String) + Send + Sync>,
    pub warn: Arc<dyn Fn(String) + Send + Sync>,
    pub progress: Option<archiver::ProgressFn>,
    pub activity: Option<archiver::ActivityFn>,
    pub cancel: Arc<AtomicBool>,
}

/// The most recent snapshot this request would build on, if any.
async fn parent_for(
    config: &Config,
    repo: &Repository<S3Store>,
    request: &Request,
) -> Result<Option<Snapshot>> {
    let root = real_root(config)?;
    let recorded = path_strings(&normalize_paths(&request.resolved_paths(&root))?)?;
    let snapshots = repo.list_snapshots().await?;
    let hostname = archiver::Options::default().hostname;
    Ok(snapshot::find_parent(&snapshots, &hostname, &recorded).cloned())
}

/// Whether a scheduled backup is due: no snapshot of these paths from this host
/// yet, or the latest is at least `interval` old. Judged from the bucket, so
/// restarts and sleep don't reset the schedule.
pub(crate) async fn is_due(
    config: &Config,
    repo: &Repository<S3Store>,
    interval: Duration,
) -> Result<bool> {
    let parent = parent_for(config, repo, &Request::from_config(config)).await?;
    Ok(parent.is_none_or(|p| {
        let age = chrono::Utc::now().signed_duration_since(p.time);
        age.to_std().is_ok_and(|age| age >= interval)
    }))
}

/// Takes one snapshot.
pub(crate) async fn create_snapshot(
    config: &Config,
    repo: Arc<Repository<S3Store>>,
    mirror: &Mirror,
    request: Request,
    hooks: Hooks,
) -> Result<Snapshot> {
    let root = real_root(config)?;
    let _lock = lock(&root)?;
    let _awake = request.keep_awake.then(crate::awake::KeepAwake::new);
    let paths = request.resolved_paths(&root);

    // `.mirror/` holds the saved passphrase and the mirror's state: never back it
    // up, whatever the other settings.
    let mut patterns = request.excludes.clone();
    patterns.push(root.join(".mirror").to_string_lossy().into_owned());
    let mut filters: Vec<Arc<dyn Filter>> = vec![Arc::new(Excludes::new(&patterns)?)];
    if request.mirrorignore {
        filters.push(Arc::new(MirrorFilter::new(
            &root,
            &config.local.ignore_file,
        )));
    }

    let parent = if request.full {
        None
    } else {
        (hooks.info)("· looking for the previous snapshot of these paths".into());
        parent_for(config, &repo, &request).await?
    };
    if let Some(parent) = &parent {
        (hooks.info)(format!("comparing against snapshot {}", parent.id.short()));
    }

    let offloaded = if request.offloaded {
        Offloaded::Include(Arc::new(MirrorSource {
            store: Arc::clone(&mirror.store),
            enc_keys: Arc::clone(&mirror.enc_keys),
            prefix: config.remote.prefix.clone(),
            handle: tokio::runtime::Handle::current(),
        }))
    } else {
        Offloaded::Skip
    };

    let warn = Arc::clone(&hooks.warn);
    let options = archiver::Options {
        filters,
        offloaded,
        tags: request.tags.clone(),
        parent,
        on_error: Some(Arc::new(move |path: &Path, error: &backup_core::Error| {
            warn(format!("skipping {}: {error}", path.display()));
            Decision::Skip
        })),
        progress: hooks.progress.clone(),
        activity: hooks.activity.clone(),
        cancel: Some(Arc::clone(&hooks.cancel)),
        // `--full` means read everything, including what an unfinished run did.
        resume: !request.full,
        ..archiver::Options::default()
    };

    match archiver::backup(repo, &paths, options).await {
        Err(backup_core::Error::Cancelled) if hooks.cancel.load(Ordering::Relaxed) => {
            anyhow::bail!("cancelled; no snapshot was written")
        }
        other => Ok(other?),
    }
}

async fn create(
    config: &Config,
    repo: Arc<Repository<S3Store>>,
    mirror: &Mirror,
    request: Request,
    mut display: crate::backup_progress::Display,
) -> Result<()> {
    display.start(Arc::clone(&repo));
    let printer = display.printer();
    let hooks = Hooks {
        info: Arc::clone(&printer),
        warn: printer,
        progress: Some(display.progress()),
        activity: Some(display.activity()),
        cancel: cancel_on_ctrl_c(),
    };

    let result = create_snapshot(config, Arc::clone(&repo), mirror, request, hooks).await;
    let elapsed = display.finish();
    let snapshot = result?;
    print!("{}", create_summary(&snapshot));
    println!("{}", upload_summary(repo.uploaded(), elapsed));
    Ok(())
}

/// "  uploaded 38 packs (612.0 MiB) in 4m 12s"
fn upload_summary((packs, bytes): (u64, u64), elapsed: Duration) -> String {
    format!(
        "  uploaded {packs} packs ({}) in {}",
        human_bytes(bytes),
        crate::backup_progress::duration(elapsed)
    )
}

/// Picks snapshots to forget by `policy` (days in local time), then prunes.
pub(crate) async fn prune_by_policy(
    repo: &Repository<S3Store>,
    policy: &KeepPolicy,
    dry_run: bool,
) -> Result<(prune::Selection, prune::Report)> {
    let snapshots = repo.list_snapshots().await?;
    let selection = prune::select(&snapshots, policy, &Local)?;
    let forget: Vec<_> = selection.forget.iter().map(|s| s.id).collect();
    let report = prune::prune(repo, &forget, dry_run).await?;
    Ok((selection, report))
}

async fn prune_cmd(repo: &Repository<S3Store>, policy: &KeepPolicy, dry_run: bool) -> Result<()> {
    let bar = spinner();
    if let Some(bar) = &bar {
        bar.set_message("pruning");
    }
    let result = prune_by_policy(repo, policy, dry_run).await;
    if let Some(bar) = &bar {
        bar.finish_and_clear();
    }
    let (selection, report) = result?;
    print!("{}", prune_summary(&selection, &report));
    Ok(())
}

fn prune_summary(selection: &prune::Selection, report: &prune::Report) -> String {
    let mut rows: Vec<(&Snapshot, String)> = selection
        .keep
        .iter()
        .map(|(s, why)| (s, format!("keep    ({})", why.join(", "))))
        .chain(selection.forget.iter().map(|s| (s, "forget".to_string())))
        .collect();
    rows.sort_by_key(|(s, _)| std::cmp::Reverse(s.time));

    let mut out = String::new();
    for (s, verdict) in rows {
        out += &format!(
            "{}  {}  {:<15}  {verdict}\n",
            s.id.short(),
            s.time.with_timezone(&Local).format("%Y-%m-%d %H:%M"),
            truncate(&s.hostname, 15),
        );
    }
    let verb = if report.dry_run {
        "would free"
    } else {
        "freed"
    };
    out += &format!(
        "{} {} snapshots; {verb} {} ({} packs removed, {} of them repacked)\n",
        if report.dry_run {
            "would forget"
        } else {
            "forgot"
        },
        report.snapshots_forgotten,
        human_bytes(report.bytes_freed),
        report.packs_deleted,
        report.packs_repacked
    );
    if report.packs_partly_used > 0 {
        out += &format!(
            "{} packs kept with {} no longer needed (below the repack threshold)\n",
            report.packs_partly_used,
            human_bytes(report.bytes_unused_in_kept_packs)
        );
    }
    if report.stale_locks_removed > 0 {
        out += &format!("removed {} abandoned locks\n", report.stale_locks_removed);
    }
    if report.orphans_kept > 0 {
        out += &format!(
            "kept {} recent packs from interrupted backups for the next backup to reuse\n",
            report.orphans_kept
        );
    }
    if report.dry_run {
        out += "dry run: nothing was deleted\n";
    }
    out
}

fn create_summary(snapshot: &Snapshot) -> String {
    let s = &snapshot.stats;
    let mut out = format!("snapshot {} saved\n", snapshot.id.short());
    out += &format!(
        "  files    {} new, {} changed, {} unchanged\n",
        s.files_new, s.files_changed, s.files_unmodified
    );
    if s.files_resumed + s.packs_adopted > 0 {
        out += &format!(
            "  resumed  {} files and {} packs from an interrupted backup\n",
            s.files_resumed, s.packs_adopted
        );
    }
    if s.offloaded_reused + s.offloaded_downloaded + s.offloaded_skipped > 0 {
        out += &format!(
            "  offloaded {} reused, {} downloaded ({}), {} skipped\n",
            s.offloaded_reused,
            s.offloaded_downloaded,
            human_bytes(s.offloaded_bytes_downloaded),
            s.offloaded_skipped
        );
    }
    if s.files_skipped > 0 {
        out += &format!("  skipped  {} unreadable\n", s.files_skipped);
    }
    // Unchanged files count toward the total without being read.
    out += &format!(
        "  data     {} total, {} new\n",
        human_bytes(s.bytes_processed),
        human_bytes(s.bytes_added)
    );
    out
}

async fn list_snapshots(repo: &Repository<S3Store>) -> Result<()> {
    let snapshots = repo.list_snapshots().await?;
    if snapshots.is_empty() {
        println!("no snapshots");
        return Ok(());
    }
    print!("{}", snapshot_table(&snapshots));
    Ok(())
}

fn snapshot_table(snapshots: &[Snapshot]) -> String {
    let mut out = format!(
        "{:<10}{:<18}{:<16}{:>11}  PATHS\n",
        "ID", "TIME", "HOST", "SIZE"
    );
    for s in snapshots {
        let mut paths = s.paths.join(" ");
        if !s.tags.is_empty() {
            paths += &format!("  [{}]", s.tags.join(", "));
        }
        out += &format!(
            "{:<10}{:<18}{:<16}{:>11}  {paths}\n",
            s.id.short(),
            s.time.with_timezone(&Local).format("%Y-%m-%d %H:%M"),
            truncate(&s.hostname, 15),
            human_bytes(s.stats.bytes_processed),
        );
    }
    out
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(max - 1).collect::<String>())
    }
}

async fn list_files(repo: &Repository<S3Store>, reference: &str) -> Result<()> {
    let snapshot = repo.find_snapshot(reference).await?;
    for (path, node) in repo.walk(snapshot.tree).await? {
        println!("{}", file_line(&path, &node));
    }
    Ok(())
}

fn file_line(path: &str, node: &Node) -> String {
    let size = match node.node_type {
        NodeType::File => human_bytes(node.size),
        _ => String::new(),
    };
    let target = match &node.link_target {
        Some(target) => format!(" -> {target}"),
        None if node.offloaded => "  (offloaded)".to_string(),
        None => String::new(),
    };
    format!(
        "{} {:>10}  {}  {path}{target}",
        mode_string(node),
        size,
        node.mtime.with_timezone(&Local).format("%Y-%m-%d %H:%M"),
    )
}

/// `ls -l` style: type, then rwx triplets with setuid/setgid/sticky folded in.
fn mode_string(node: &Node) -> String {
    let kind = match node.node_type {
        NodeType::Dir => 'd',
        NodeType::Symlink => 'l',
        NodeType::File => '-',
    };
    let m = node.mode;
    let bit = |mask: u32, c: char| if m & mask != 0 { c } else { '-' };
    let special = |exec: u32, special: u32, set: char| match (m & exec != 0, m & special != 0) {
        (true, true) => set,
        (false, true) => set.to_ascii_uppercase(),
        (true, false) => 'x',
        (false, false) => '-',
    };
    [
        kind,
        bit(0o400, 'r'),
        bit(0o200, 'w'),
        special(0o100, 0o4000, 's'),
        bit(0o040, 'r'),
        bit(0o020, 'w'),
        special(0o010, 0o2000, 's'),
        bit(0o004, 'r'),
        bit(0o002, 'w'),
        special(0o001, 0o1000, 't'),
    ]
    .iter()
    .collect()
}

async fn restore(
    repo: Arc<Repository<S3Store>>,
    reference: &str,
    target: &Path,
    include: Vec<String>,
    exclude: Vec<String>,
    overwrite: bool,
) -> Result<()> {
    let snapshot = repo.find_snapshot(reference).await?;
    let bar = spinner();
    let mut options = restorer::Options {
        include,
        exclude,
        overwrite,
        concurrency: restorer::DEFAULT_CONCURRENCY,
        progress: None,
    };
    if let Some(bar) = bar.clone() {
        options.progress = Some(Arc::new(move |p: &restorer::Progress| {
            bar.set_message(format!(
                "{} files, {}",
                p.files_restored,
                human_bytes(p.bytes_restored)
            ));
        }));
    }

    let result = restorer::restore(repo, &snapshot, target, options).await;
    if let Some(bar) = &bar {
        bar.finish_and_clear();
    }
    let stats = result?;
    println!(
        "restored snapshot {} into {}: {} files ({}), {} directories, {} symlinks, {} hardlinks",
        snapshot.id.short(),
        target.display(),
        stats.files,
        human_bytes(stats.bytes),
        stats.dirs,
        stats.symlinks,
        stats.hardlinks
    );
    Ok(())
}

async fn verify(repo: &Repository<S3Store>, read_data: bool) -> Result<()> {
    let bar = spinner();
    let progress_bar = bar.clone();
    let options = verify::Options {
        read_data,
        concurrency: verify::DEFAULT_CONCURRENCY,
        progress: progress_bar
            .map(|bar| Arc::new(move |stage: &str| bar.set_message(stage.to_string())) as _),
        ..verify::Options::default()
    };
    let result = verify::verify(repo, options).await;
    if let Some(bar) = &bar {
        bar.finish_and_clear();
    }
    let report = result?;
    print!("{}", verify_summary(&report, read_data));
    if !report.ok() {
        anyhow::bail!(
            "the backup repository has {} problem(s)",
            report.problems.len()
        );
    }
    Ok(())
}

fn verify_summary(report: &verify::Report, read_data: bool) -> String {
    let mut out = format!(
        "checked  {} snapshots, {} trees, {} chunk references, {} packs\n",
        report.snapshots_checked,
        report.trees_checked,
        report.blobs_referenced,
        report.packs_referenced
    );
    if read_data {
        out += &format!("read     {}\n", human_bytes(report.bytes_read));
    }
    if !report.orphan_packs.is_empty() {
        out += &format!(
            "orphans  {} unreferenced packs (left by interrupted backups; the next backup reuses them)\n",
            report.orphan_packs.len()
        );
    }
    if report.ok() {
        out += "ok       no problems found\n";
    }
    for problem in &report.problems {
        out += &format!("problem  {problem}\n");
    }
    out
}

/// One `rfm doctor` line about backups. Lists objects only, so it needs no
/// passphrase.
pub(crate) async fn doctor_line(store: &S3Store, prefix: &str) -> Result<String> {
    let base = repo::base(prefix);
    if store.head(&format!("{base}config")).await?.is_none() {
        return Ok("backup   none no repository yet (`rfm backup create` starts one)".into());
    }
    let snapshots = store
        .list(&format!("{base}{}", snapshot::DIR), None)
        .await?
        .len();
    Ok(format!("backup   ok   {snapshots} snapshots"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use backup_core::crypto::Id;
    use backup_core::snapshot::Stats;
    use chrono::{TimeZone, Utc};

    fn node(node_type: NodeType, mode: u32) -> Node {
        Node {
            name: "x".into(),
            node_type,
            mode,
            uid: 0,
            gid: 0,
            size: 2048,
            mtime: Utc.timestamp_opt(0, 0).unwrap(),
            ctime: None,
            link_target: None,
            content: vec![],
            subtree: None,
            device: 0,
            inode: 0,
            links: 0,
            content_hash: None,
            offloaded: false,
        }
    }

    #[test]
    fn a_root_named_through_a_symlink_resolves_to_the_real_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(tmp.path()).unwrap().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let other = tmp.path().join("other");
        std::fs::create_dir(&other).unwrap();

        let mut request = Request {
            paths: vec![],
            excludes: vec![],
            tags: vec![],
            mirrorignore: true,
            full: false,
            offloaded: true,
            keep_awake: true,
        };
        assert_eq!(request.resolved_paths(&real), [real.as_path()]);
        request.paths = vec![link.clone(), other.clone()];
        assert_eq!(request.resolved_paths(&real), [real.clone(), other]);
    }

    #[test]
    fn mode_strings_match_ls() {
        assert_eq!(mode_string(&node(NodeType::File, 0o644)), "-rw-r--r--");
        assert_eq!(mode_string(&node(NodeType::Dir, 0o755)), "drwxr-xr-x");
        assert_eq!(mode_string(&node(NodeType::File, 0o4755)), "-rwsr-xr-x");
        assert_eq!(mode_string(&node(NodeType::File, 0o2644)), "-rw-r-Sr--");
        assert_eq!(mode_string(&node(NodeType::Dir, 0o1777)), "drwxrwxrwt");
        assert_eq!(mode_string(&node(NodeType::Symlink, 0o777)), "lrwxrwxrwx");
    }

    #[test]
    fn create_summary_mentions_skips_only_when_there_are_any() {
        let mut snap = Snapshot {
            id: Id::default(),
            time: Utc::now(),
            hostname: "h".into(),
            username: String::new(),
            paths: vec!["/a".into()],
            tags: vec![],
            tree: Id::random(),
            parent: None,
            stats: Stats {
                files_new: 2,
                files_unmodified: 5,
                bytes_processed: 10 * 1024 * 1024,
                bytes_added: 1024,
                ..Stats::default()
            },
        };
        let text = create_summary(&snap);
        assert!(text.contains("2 new, 0 changed, 5 unchanged"));
        assert!(text.contains("10.0 MiB total, 1.0 KiB new"));
        assert!(!text.contains("skipped"));

        snap.stats.offloaded_reused = 4;
        snap.stats.offloaded_downloaded = 1;
        snap.stats.offloaded_bytes_downloaded = 2048;
        let text = create_summary(&snap);
        assert!(
            text.contains("offloaded 4 reused, 1 downloaded (2.0 KiB), 0 skipped"),
            "{text}"
        );
        assert!(!text.contains("unreadable"));
        assert!(
            !text.contains("resumed"),
            "only after an interrupted backup"
        );

        snap.stats.files_resumed = 12;
        snap.stats.packs_adopted = 3;
        assert!(
            create_summary(&snap)
                .contains("resumed  12 files and 3 packs from an interrupted backup")
        );
        assert_eq!(
            upload_summary((38, 612 * 1024 * 1024), Duration::from_secs(252)),
            "  uploaded 38 packs (612.0 MiB) in 4m 12s"
        );
    }

    #[test]
    fn snapshot_table_lists_newest_first_with_tags() {
        let snap = Snapshot {
            id: "ab12cd34".repeat(8).parse().unwrap(),
            time: Utc::now(),
            hostname: "a-very-long-hostname.local".into(),
            username: String::new(),
            paths: vec!["/home/me".into()],
            tags: vec!["nightly".into()],
            tree: Id::random(),
            parent: None,
            stats: Stats::default(),
        };
        let table = snapshot_table(&[snap]);
        let row = table.lines().nth(1).unwrap();
        assert!(row.starts_with("ab12cd34  "));
        assert!(row.contains("a-very-long-ho…"));
        assert!(row.ends_with("/home/me  [nightly]"));
    }

    #[test]
    fn prune_summary_lists_verdicts_and_totals() {
        let mut older = snap_at(1);
        older.hostname = "laptop".into();
        let newer = snap_at(2);
        let selection = prune::Selection {
            keep: vec![(newer.clone(), vec!["last", "daily"])],
            forget: vec![older.clone()],
        };
        let report = prune::Report {
            dry_run: true,
            snapshots_forgotten: 1,
            packs_deleted: 3,
            packs_repacked: 1,
            bytes_freed: 5 * 1024 * 1024,
            packs_partly_used: 2,
            bytes_unused_in_kept_packs: 1024,
            ..prune::Report::default()
        };
        let text = prune_summary(&selection, &report);
        let lines: Vec<_> = text.lines().collect();
        assert!(
            lines[0].starts_with(&newer.id.short()) && lines[0].ends_with("keep    (last, daily)")
        );
        assert!(lines[1].starts_with(&older.id.short()) && lines[1].ends_with("forget"));
        assert!(text.contains(
            "would forget 1 snapshots; would free 5.0 MiB (3 packs removed, 1 of them repacked)"
        ));
        assert!(text.contains("2 packs kept with 1.0 KiB no longer needed"));
        assert!(text.ends_with("dry run: nothing was deleted\n"));
    }

    fn snap_at(days: i64) -> Snapshot {
        Snapshot {
            id: Id::random(),
            time: Utc.timestamp_opt(days * 86_400, 0).unwrap(),
            hostname: "h".into(),
            username: String::new(),
            paths: vec!["/a".into()],
            tags: vec![],
            tree: Id::random(),
            parent: None,
            stats: Stats::default(),
        }
    }

    #[test]
    fn verify_summary_reports_problems_and_orphans() {
        let mut report = verify::Report {
            snapshots_checked: 2,
            ..verify::Report::default()
        };
        assert!(verify_summary(&report, false).contains("no problems found"));
        report.orphan_packs = vec![Id::random()];
        report.problems = vec!["pack x missing".into()];
        let text = verify_summary(&report, true);
        assert!(text.contains("1 unreferenced packs"));
        assert!(text.contains("problem  pack x missing"));
        assert!(!text.contains("no problems"));
    }

    #[test]
    fn file_lines_show_sizes_for_files_and_targets_for_links() {
        assert!(file_line("/a/f", &node(NodeType::File, 0o644)).contains("2.0 KiB"));
        let mut link = node(NodeType::Symlink, 0o777);
        link.link_target = Some("../t".into());
        let line = file_line("/a/l", &link);
        assert!(line.ends_with("/a/l -> ../t"));
        assert!(!line.contains("KiB"));

        let mut offloaded = node(NodeType::File, 0o644);
        offloaded.offloaded = true;
        assert!(file_line("/a/f", &offloaded).ends_with("/a/f  (offloaded)"));
    }
}
