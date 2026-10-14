use std::time::SystemTime;

use anyhow::Error;
use mirror_core::{config::Config, sync::SyncOutcome};

use crate::events::{BackupSummary, LastBackup, LastSync, Snapshot, Trigger};

pub struct DaemonStatus {
    bucket: String,
    root: String,
    poll_interval_secs: u64,
    syncing: Option<Trigger>,
    last: Option<LastSync>,
    backup_interval_hours: u64,
    backing_up: bool,
    last_backup: Option<LastBackup>,
}

impl DaemonStatus {
    pub fn new(config: &Config) -> Self {
        Self {
            bucket: config.remote.bucket.clone(),
            root: config.local.root.display().to_string(),
            poll_interval_secs: config.sync.poll_interval_secs,
            syncing: None,
            last: None,
            backup_interval_hours: config.backup.interval_hours,
            backing_up: false,
            last_backup: None,
        }
    }

    pub fn backup_started(&mut self) {
        self.backing_up = true;
    }

    pub fn record_backup(&mut self, result: Result<BackupSummary, String>) -> LastBackup {
        let last = LastBackup {
            at: SystemTime::now(),
            result,
        };
        self.backing_up = false;
        self.last_backup = Some(last.clone());
        last
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
            backing_up: self.backing_up,
            last_backup: self.last_backup.clone(),
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

        text.push_str(&match (&self.last_backup, self.backing_up) {
            (_, true) => "backup: running\n".to_string(),
            (Some(LastBackup { result: Ok(s), .. }), _) => format!("backup: ok, {s}\n"),
            (Some(LastBackup { result: Err(e), .. }), _) => format!("backup: error: {e}\n"),
            (None, _) if self.backup_interval_hours > 0 => format!(
                "backup: every {}h, none yet since the daemon started\n",
                self.backup_interval_hours
            ),
            (None, _) => String::new(),
        });

        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(interval_hours: u64) -> DaemonStatus {
        DaemonStatus {
            bucket: "b".into(),
            root: "/r".into(),
            poll_interval_secs: 60,
            syncing: None,
            last: None,
            backup_interval_hours: interval_hours,
            backing_up: false,
            last_backup: None,
        }
    }

    #[test]
    fn render_reports_backups() {
        assert!(
            !status(0).render().contains("backup"),
            "nothing when backups aren't scheduled"
        );
        assert!(status(24).render().contains("backup: every 24h, none yet"));

        let mut s = status(24);
        s.backup_started();
        assert!(s.render().contains("backup: running"));
        assert!(s.snapshot().backing_up);

        s.record_backup(Ok(BackupSummary {
            snapshot: "ab12cd34".into(),
            files: 5,
            bytes_added: 0,
            pruned: None,
        }));
        assert!(
            s.render()
                .contains("backup: ok, snapshot ab12cd34: 5 files, 0 B new")
        );
        assert!(!s.snapshot().backing_up);

        s.record_backup(Err("bucket unreachable".into()));
        assert!(s.render().contains("backup: error: bucket unreachable"));
    }
}
