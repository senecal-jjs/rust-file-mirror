use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::residency::{Mode, Policy};
use crate::{Error, Result};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub remote: Remote,
    pub local: Local,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(default)]
    pub offline: OfflineConfig,
    #[serde(default)]
    pub backup: BackupConfig,
}

/// `rfm backup` settings, and scheduled backups in `rfm watch`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BackupConfig {
    /// `rfm watch` backs up once the latest snapshot of these paths from this host
    /// is this many hours old. 0 turns scheduled backups off.
    #[serde(default)]
    pub interval_hours: u64,
    /// What to back up; the mirrored root when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<PathBuf>,
    /// Globs left out of every backup (by name or full path).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    /// Follow the mirror's ignore rules when backing up the root.
    #[serde(default = "default_true")]
    pub mirrorignore: bool,
    /// Whether offloaded files (placeholders) are backed up with their real
    /// content, fetched from the bucket when no earlier snapshot holds it.
    #[serde(default)]
    pub offloaded: OffloadedBackup,
    /// Which snapshots `rfm backup prune` keeps.
    #[serde(default)]
    pub keep: KeepPolicy,
    /// Prune by `keep` after each scheduled backup.
    #[serde(default)]
    pub auto_prune: bool,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            interval_hours: 0,
            paths: Vec::new(),
            exclude: Vec::new(),
            mirrorignore: true,
            offloaded: OffloadedBackup::default(),
            keep: KeepPolicy::default(),
            auto_prune: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OffloadedBackup {
    #[default]
    Include,
    Skip,
}

/// Snapshot retention, applied separately to each host and set of paths. A snapshot
/// survives if any rule keeps it: `last` keeps the newest N; the others keep the
/// newest snapshot in each of the N most recent hours, days, weeks, months, or years
/// that have one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeepPolicy {
    #[serde(default)]
    pub last: usize,
    #[serde(default)]
    pub hourly: usize,
    #[serde(default)]
    pub daily: usize,
    #[serde(default)]
    pub weekly: usize,
    #[serde(default)]
    pub monthly: usize,
    #[serde(default)]
    pub yearly: usize,
}

impl KeepPolicy {
    /// No rules at all, which would forget every snapshot.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Remote {
    pub bucket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub path_style: bool,
    /// Named AWS profile from ~/.aws/credentials; falls back to the default chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Local {
    pub root: PathBuf,
    #[serde(default = "default_ignore_file")]
    pub ignore_file: String,
}

#[derive(Debug, Deserialize)]
pub struct SyncConfig {
    /// How often the daemon lists the remote log for other devices' changes.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// How long the watcher coalesces a burst of local events before rescanning.
    #[serde(default = "default_debounce")]
    pub debounce_secs: u64,
    #[serde(default = "default_max_concurrent_transfers")]
    pub max_concurrent_transfers: usize,
    #[serde(default = "default_multipart_threshold")]
    pub multipart_threshold: u64,
    #[serde(default = "default_part_size")]
    pub part_size: u64,
    /// Minimum age of an unreferenced content object before compaction GC deletes it.
    #[serde(default = "default_object_retention")]
    pub object_retention_secs: u64,
    /// A sync compacts the remote log once this many deltas are old enough to prune;
    /// 0 leaves compaction to `rfm compact`.
    #[serde(default = "default_compact_threshold")]
    pub compact_threshold: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_poll_interval(),
            debounce_secs: default_debounce(),
            max_concurrent_transfers: default_max_concurrent_transfers(),
            multipart_threshold: default_multipart_threshold(),
            part_size: default_part_size(),
            object_retention_secs: default_object_retention(),
            compact_threshold: default_compact_threshold(),
        }
    }
}

impl SyncConfig {
    pub fn object_retention(&self) -> Duration {
        Duration::from_secs(self.object_retention_secs)
    }
}

/// How files this device has never had arrive, for paths with no explicit residency.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DefaultResidency {
    #[default]
    Local,
    OnlineOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct OfflineConfig {
    #[serde(default)]
    pub default_residency: DefaultResidency,
    /// Globs always kept local.
    #[serde(default)]
    pub local: Vec<String>,
    /// Globs kept only remotely once safely synced.
    #[serde(default)]
    pub online_only: Vec<String>,
    /// Automatic eviction skips files smaller than this many bytes.
    #[serde(default = "default_evict_min_size")]
    pub evict_min_size: u64,
    /// Policy-driven eviction waits this long after a file's last confirmed sync.
    #[serde(default = "default_evict_grace")]
    pub evict_grace_secs: u64,
    /// Download, decrypt and hash-check the remote copy before deleting local bytes.
    #[serde(default)]
    pub verify_before_evict: bool,
    #[serde(default)]
    pub auto_evict: bool,
    /// Auto-eviction starts below this many free bytes...
    #[serde(default = "default_min_free_space")]
    pub min_free_space: u64,
    /// ...and stops once this many are free.
    #[serde(default = "default_target_free_space")]
    pub target_free_space: u64,
}

impl Default for OfflineConfig {
    fn default() -> Self {
        Self {
            default_residency: DefaultResidency::default(),
            local: Vec::new(),
            online_only: Vec::new(),
            evict_min_size: default_evict_min_size(),
            evict_grace_secs: default_evict_grace(),
            verify_before_evict: false,
            auto_evict: false,
            min_free_space: default_min_free_space(),
            target_free_space: default_target_free_space(),
        }
    }
}

impl OfflineConfig {
    pub fn policy(&self, pins: &[(String, Mode)]) -> Result<Policy> {
        Policy::new(
            pins,
            &self.local,
            &self.online_only,
            self.default_residency == DefaultResidency::OnlineOnly,
        )
    }

    pub fn evict_grace(&self) -> Duration {
        Duration::from_secs(self.evict_grace_secs)
    }
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_prefix() -> String {
    "rfm/".to_string()
}

fn default_ignore_file() -> String {
    ".mirrorignore".to_string()
}

const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

fn default_poll_interval() -> u64 {
    60
}

fn default_debounce() -> u64 {
    2
}

fn default_max_concurrent_transfers() -> usize {
    8
}

fn default_multipart_threshold() -> u64 {
    8 * 1024 * 1024
}

fn default_part_size() -> u64 {
    8 * 1024 * 1024
}

const DAY_SECS: u64 = 24 * 60 * 60;
const MIN_OBJECT_RETENTION_SECS: u64 = 7 * DAY_SECS;
const GIB: u64 = 1024 * 1024 * 1024;

fn default_object_retention() -> u64 {
    30 * DAY_SECS
}

fn default_compact_threshold() -> usize {
    200
}

fn default_evict_min_size() -> u64 {
    1024 * 1024
}

fn default_evict_grace() -> u64 {
    15 * 60
}

fn default_min_free_space() -> u64 {
    20 * GIB
}

fn default_target_free_space() -> u64 {
    40 * GIB
}

/// Where `rfm init` writes the config, and where every rfm program looks for it
/// unless told otherwise (`--config` / `RFM_CONFIG`).
pub fn default_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".config/rfm/config.toml"))
        .unwrap_or_else(|| PathBuf::from("rfm.toml"))
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let config: Config = toml::from_str(&text).map_err(|e| Error::Config(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Writes `[remote]`, `[local]` and non-default `[offline]`/`[backup]` to `path`, creating
    /// parent dirs. `[sync]` is omitted so it keeps tracking the built-in defaults.
    pub fn save(&self, path: &Path) -> Result<()> {
        #[derive(Serialize)]
        struct Saved<'a> {
            remote: &'a Remote,
            local: &'a Local,
            #[serde(skip_serializing_if = "Option::is_none")]
            offline: Option<&'a OfflineConfig>,
            #[serde(skip_serializing_if = "Option::is_none")]
            backup: Option<&'a BackupConfig>,
        }

        let text = toml::to_string_pretty(&Saved {
            remote: &self.remote,
            local: &self.local,
            offline: (self.offline != OfflineConfig::default()).then_some(&self.offline),
            backup: (self.backup != BackupConfig::default()).then_some(&self.backup),
        })
        .map_err(|e| Error::Config(e.to_string()))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| Error::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        std::fs::write(path, text).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Reports every problem at once so a user fixes them in one pass.
    pub fn validate(&self) -> Result<()> {
        let mut problems = Vec::new();

        if self.remote.bucket.is_empty() {
            problems.push("remote.bucket must not be empty".to_string());
        }

        if !self.remote.prefix.ends_with('/') {
            problems.push(format!(
                "remote.prefix {:?} must end with '/'",
                self.remote.prefix
            ));
        }

        if !self.local.root.is_dir() {
            problems.push(format!(
                "local.root {} is not a directory",
                self.local.root.display()
            ));
        }

        // S3 rejects non-final multipart parts below 5 MiB, and a zero concurrency
        // or poll interval would wedge the daemon.
        if self.sync.part_size < MIN_PART_SIZE {
            problems.push(format!(
                "sync.part_size {} must be at least {MIN_PART_SIZE} (5 MiB)",
                self.sync.part_size
            ));
        }

        if self.sync.max_concurrent_transfers == 0 {
            problems.push("sync.max_concurrent_transfers must be at least 1".to_string());
        }

        if self.sync.poll_interval_secs == 0 {
            problems.push("sync.poll_interval_secs must be at least 1".to_string());
        }

        if self.sync.object_retention_secs < MIN_OBJECT_RETENTION_SECS {
            problems.push(format!(
                "sync.object_retention_secs must be at least {MIN_OBJECT_RETENTION_SECS} (7 days)"
            ));
        }

        let offline = &self.offline;

        if offline.target_free_space < offline.min_free_space {
            problems
                .push("offline.target_free_space must be >= offline.min_free_space".to_string());
        }

        if offline.evict_grace_secs < 2 * self.sync.poll_interval_secs {
            problems.push(
                "offline.evict_grace_secs must be at least 2 x sync.poll_interval_secs".to_string(),
            );
        }

        if self.sync.object_retention_secs <= offline.evict_grace_secs {
            problems.push(
                "sync.object_retention_secs must exceed offline.evict_grace_secs".to_string(),
            );
        }

        if let Err(e) = offline.policy(&[]) {
            problems.push(e.to_string());
        }

        if self.backup.auto_prune && self.backup.keep.is_empty() {
            problems.push("backup.auto_prune needs at least one backup.keep rule".to_string());
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(Error::Config(problems.join("; ")))
        }
    }
}

#[cfg(test)]
mod backup_config_tests {
    use super::*;

    /// A root that outlives every test (validation requires it to exist).
    fn root() -> &'static Path {
        static ROOT: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        ROOT.get_or_init(|| tempfile::tempdir().unwrap()).path()
    }

    fn parse(extra: &str) -> Result<Config> {
        let text = format!(
            "[remote]\nbucket = \"b\"\n[local]\nroot = {:?}\n{extra}",
            root().to_str().unwrap()
        );
        let config: Config = toml::from_str(&text).map_err(|e| Error::Config(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn backup_section_defaults_and_parses() {
        let config = parse("").unwrap();
        assert_eq!(config.backup, BackupConfig::default());
        assert!(config.backup.mirrorignore);
        assert_eq!(
            config.backup.interval_hours, 0,
            "scheduled backups are opt-in"
        );
        assert_eq!(config.backup.offloaded, OffloadedBackup::Include);
        let skip = parse("[backup]\noffloaded = \"skip\"\n").unwrap();
        assert_eq!(skip.backup.offloaded, OffloadedBackup::Skip);

        let config = parse(
            "[backup]\ninterval_hours = 24\nexclude = [\"*.iso\"]\nmirrorignore = false\n\
             auto_prune = true\n[backup.keep]\ndaily = 7\nweekly = 4\n",
        )
        .unwrap();
        assert_eq!(config.backup.interval_hours, 24);
        assert_eq!(config.backup.exclude, ["*.iso"]);
        assert!(!config.backup.mirrorignore);
        assert_eq!(
            config.backup.keep,
            KeepPolicy {
                daily: 7,
                weekly: 4,
                ..KeepPolicy::default()
            }
        );
    }

    #[test]
    fn auto_prune_needs_a_keep_rule() {
        let err = parse("[backup]\nauto_prune = true\n").unwrap_err();
        assert!(err.to_string().contains("backup.auto_prune"), "{err}");
    }

    #[test]
    fn save_keeps_a_non_default_backup_section() {
        let mut config = parse("[backup]\ninterval_hours = 12\n[backup.keep]\nlast = 3\n").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        config.save(&path).unwrap();
        let reloaded = Config::load(&path).unwrap();
        assert_eq!(reloaded.backup, config.backup);

        config.backup = BackupConfig::default();
        config.save(&path).unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("[backup]"));
    }
}
