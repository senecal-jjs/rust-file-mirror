use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub remote: Remote,
    pub local: Local,
    #[serde(default)]
    pub sync: SyncConfig,
}

#[derive(Debug, Deserialize)]
pub struct Remote {
    pub bucket: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub path_style: bool,
}

#[derive(Debug, Deserialize)]
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
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_poll_interval(),
            debounce_secs: default_debounce(),
            max_concurrent_transfers: default_max_concurrent_transfers(),
            multipart_threshold: default_multipart_threshold(),
            part_size: default_part_size(),
        }
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

    fn validate(&self) -> Result<()> {
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

        if problems.is_empty() {
            Ok(())
        } else {
            Err(Error::Config(problems.join("; ")))
        }
    }
}
