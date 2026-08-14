use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub remote: Remote,
    pub local: Local,
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
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_prefix() -> String {
    "rfm/".to_string()
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

        if problems.is_empty() {
            Ok(())
        } else {
            Err(Error::Config(problems.join("; ")))
        }
    }
}
