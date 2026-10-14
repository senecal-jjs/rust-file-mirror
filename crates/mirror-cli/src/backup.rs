//! `rfm backup`: encrypted, deduplicated point-in-time snapshots in the same bucket
//! as the mirror, under the same vault passphrase.

use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use backup_core::archiver::{self, Decision, normalize_paths, path_strings};
use backup_core::crypto::Keys;
use backup_core::filter::{Excludes, Filter, MirrorFilter};
use backup_core::repo::{self, InitOptions, Repository};
use backup_core::snapshot::{self, Node, NodeType, Snapshot};
use backup_core::{restorer, verify};
use chrono::Local;
use clap::Subcommand;
use indicatif::{ProgressBar, ProgressStyle};
use mirror_core::config::Config;
use mirror_core::indicator::human_bytes;
use mirror_core::store::ObjectStore;
use mirror_core::store::s3::S3Store;

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
        /// Read every file instead of reusing unchanged ones from the last snapshot
        #[arg(long)]
        full: bool,
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
        } => {
            let repo = open(&config, no_cache, true).await?;
            create(&config, repo, paths, excludes, tags, no_mirrorignore, full).await
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
    let store = S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    let keys = Keys::derive(&crate::derive_enc_keys(config, &store).await?.backup_key);

    let cache = if no_cache { None } else { cache_base() };
    let store = Arc::new(store);
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
/// don't race (the mirror daemon uses its own lock, and can run alongside).
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

/// Prints through the spinner when there is one, so lines don't tear it.
fn warn(bar: Option<&ProgressBar>, message: &str) {
    match bar {
        Some(bar) => bar.suspend(|| eprintln!("{message}")),
        None => eprintln!("{message}"),
    }
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

async fn create(
    config: &Config,
    repo: Arc<Repository<S3Store>>,
    paths: Vec<PathBuf>,
    excludes: Vec<String>,
    tags: Vec<String>,
    no_mirrorignore: bool,
    full: bool,
) -> Result<()> {
    let root = archiver::clean_path(&config.local.root)?;
    let _lock = lock(&root)?;
    let paths = if paths.is_empty() {
        vec![root.clone()]
    } else {
        paths
    };

    // `.mirror/` holds the saved passphrase and the mirror's state: never back it
    // up, whatever the other settings.
    let state_dir = root.join(".mirror");
    let mut patterns = excludes;
    patterns.push(state_dir.to_string_lossy().into_owned());
    let mut filters: Vec<Arc<dyn Filter>> = vec![Arc::new(Excludes::new(&patterns)?)];
    if !no_mirrorignore {
        filters.push(Arc::new(MirrorFilter::new(
            &root,
            &config.local.ignore_file,
        )));
    }

    let mut options = archiver::Options {
        filters,
        skip_placeholders: true,
        tags,
        ..archiver::Options::default()
    };
    if !full {
        let recorded = path_strings(&normalize_paths(&paths)?)?;
        let snapshots = repo.list_snapshots().await?;
        options.parent = snapshot::find_parent(&snapshots, &options.hostname, &recorded).cloned();
    }
    if let Some(parent) = &options.parent {
        eprintln!("comparing against snapshot {}", parent.id.short());
    }

    let bar = spinner();
    let bar_for_errors = bar.clone();
    options.on_error = Some(Arc::new(move |path: &Path, error: &backup_core::Error| {
        warn(
            bar_for_errors.as_ref(),
            &format!("skipping {}: {error}", path.display()),
        );
        Decision::Skip
    }));
    if let Some(bar) = bar.clone() {
        options.progress = Some(Arc::new(move |p: &archiver::Progress| {
            bar.set_message(format!(
                "{} files, {} total, {} new",
                p.files_processed,
                human_bytes(p.bytes_processed),
                human_bytes(p.bytes_added)
            ));
        }));
    }
    let cancel = cancel_on_ctrl_c();
    options.cancel = Some(Arc::clone(&cancel));

    let result = archiver::backup(Arc::clone(&repo), &paths, options).await;
    if let Some(bar) = &bar {
        bar.finish_and_clear();
    }
    let snapshot = match result {
        Err(backup_core::Error::Cancelled) if cancel.load(Ordering::Relaxed) => {
            anyhow::bail!("cancelled; no snapshot was written")
        }
        other => other?,
    };

    print!("{}", create_summary(&snapshot));
    Ok(())
}

fn create_summary(snapshot: &Snapshot) -> String {
    let s = &snapshot.stats;
    let mut out = format!("snapshot {} saved\n", snapshot.id.short());
    out += &format!(
        "  files    {} new, {} changed, {} unchanged\n",
        s.files_new, s.files_changed, s.files_unmodified
    );
    if s.files_skipped + s.placeholders_skipped > 0 {
        out += &format!(
            "  skipped  {} unreadable, {} offloaded placeholders\n",
            s.files_skipped, s.placeholders_skipped
        );
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
            "orphans  {} unreferenced packs (left by interrupted backups; harmless)\n",
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
        }
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

        snap.stats.placeholders_skipped = 3;
        assert!(create_summary(&snap).contains("0 unreadable, 3 offloaded placeholders"));
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
    }
}
