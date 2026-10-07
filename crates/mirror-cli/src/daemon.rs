use std::time::SystemTime;

use anyhow::Error;
use mirror_core::{config::Config, sync::SyncOutcome};

use crate::events::{LastSync, Snapshot, Trigger};

pub struct DaemonStatus {
    bucket: String,
    root: String,
    poll_interval_secs: u64,
    syncing: Option<Trigger>,
    last: Option<LastSync>,
}

impl DaemonStatus {
    pub fn new(config: &Config) -> Self {
        Self {
            bucket: config.remote.bucket.clone(),
            root: config.local.root.display().to_string(),
            poll_interval_secs: config.sync.poll_interval_secs,
            syncing: None,
            last: None,
        }
    }

    pub fn started(&mut self, trigger: Trigger) {
        self.syncing = Some(trigger);
    }

    pub fn is_syncing(&self) -> bool {
        self.syncing.is_some()
    }

    pub fn record(&mut self, result: &Result<SyncOutcome, Error>) -> LastSync {
        let last = LastSync {
            at: SystemTime::now(),
            result: match result {
                Ok(o) => Ok(o.clone()),
                Err(e) => Err(format!("{e:#}")),
            },
        };
        self.syncing = None;
        self.last = Some(last.clone());
        last
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            bucket: self.bucket.clone(),
            root: self.root.clone(),
            poll_interval_secs: self.poll_interval_secs,
            syncing: self.syncing,
            last: self.last.clone(),
        }
    }

    pub fn render(&self) -> String {
        let mut text = match self.syncing {
            Some(trigger) => format!("syncing ({trigger})\n"),
            None => String::new(),
        };

        text.push_str(&match &self.last {
            Some(LastSync { result: Err(e), .. }) => format!("error: {e}\n"),
            Some(LastSync { result: Ok(o), .. }) => format!(
                "ok: {} up, {} down, {} conflict, {} hydrated, {} evicted ({} bytes freed)\n",
                o.uploads, o.downloads, o.conflicts, o.hydrated, o.evicted, o.bytes_freed
            ),
            None => "starting up\n".into(),
        });

        text
    }
}
