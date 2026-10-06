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

    /// Writes `[remote]`, `[local]` and a non-default `[offline]` to `path`, creating
    /// parent dirs. `[sync]` is omitted so it keeps tracking the built-in defaults.
    pub fn save(&self, path: &Path) -> Result<()> {
        #[derive(Serialize)]
        struct Saved<'a> {
            remote: &'a Remote,
            local: &'a Local,
            #[serde(skip_serializing_if = "Option::is_none")]
            offline: Option<&'a OfflineConfig>,
        }

        let text = toml::to_string_pretty(&Saved {
            remote: &self.remote,
            local: &self.local,
            offline: (self.offline != OfflineConfig::default()).then_some(&self.offline),
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

        if problems.is_empty() {
            Ok(())
        } else {
            Err(Error::Config(problems.join("; ")))
        }
    }
}
