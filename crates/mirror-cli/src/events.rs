//! The daemon's event stream: what `watch` is doing, as it happens. One `Hub`
//! fans events out to the in-process TUI and to `rfm tui` clients on the control
//! socket; in plain (non-TUI) mode it also prints them, so the daemon log reads
//! the same as before.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use mirror_core::{
    engine::ActionKind,
    indicator::{FileTracker, PrintReporter, ProgressReporter},
};
use tokio::sync::broadcast;
use tracing_subscriber::fmt::MakeWriter;

use crate::ops::summary;

/// Byte progress is coalesced to at most one event per file per interval, so a
/// multipart transfer can't flood the channel (or a socket subscriber).
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Events a lagging subscriber can fall behind by before it starts skipping.
const CHANNEL_CAPACITY: usize = 4096;

// The wire types live in `mirror_core::control`, shared with other clients of the
// control socket (the menu bar app); re-exported here for the daemon's own use.
pub use mirror_core::control::{
    BackupSummary, LastBackup, LastSync, LogLevel, Snapshot, Trigger, UiEvent,
};

#[derive(Clone)]
pub struct Hub {
    tx: broadcast::Sender<UiEvent>,
    /// Plain mode: also print, matching the daemon's pre-TUI output.
    print: bool,
}

impl Hub {
    pub fn new(print: bool) -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx, print }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.tx.subscribe()
    }

    pub fn send(&self, event: UiEvent) {
        // Errors only when nobody is subscribed, which is the normal headless case.
        let _ = self.tx.send(event);
    }

    pub fn log(&self, level: LogLevel, msg: impl Into<String>) {
        let msg = msg.into();
        if self.print {
            match level {
                LogLevel::Info => println!("{msg}"),
                LogLevel::Warn | LogLevel::Error => eprintln!("{msg}"),
            }
        }
        self.send(UiEvent::Log { level, msg });
    }

    pub fn sync_finished(&self, last: LastSync) {
        if self.print {
            match &last.result {
                Ok(outcome) if !outcome.is_noop() => println!("{}", summary(outcome)),
                Ok(_) => {}
                Err(e) => eprintln!("sync failed: {e}"),
            }
        }
        self.send(UiEvent::SyncFinished(last));
    }

    pub fn backup_finished(&self, last: LastBackup) {
        if self.print {
            match &last.result {
                Ok(summary) => println!("backup: {summary}"),
                Err(e) => eprintln!("backup failed: {e}"),
            }
        }
        self.send(UiEvent::BackupFinished(last));
    }
}

/// Feeds core's progress callbacks into the hub. In plain mode it also drives a
/// `PrintReporter`, which keeps the daemon's per-file log lines.
pub struct HubReporter {
    hub: Hub,
    inner: Option<PrintReporter>,
    next_id: AtomicU64,
}

impl HubReporter {
    pub fn new(hub: Hub) -> Arc<Self> {
        Arc::new(Self {
            inner: hub.print.then_some(PrintReporter),
            hub,
            next_id: AtomicU64::new(0),
        })
    }
}

impl ProgressReporter for HubReporter {
    fn start_file(&self, path: &str, total_bytes: u64) -> Box<dyn FileTracker> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.hub.send(UiEvent::FileStarted {
            id,
            path: path.to_string(),
            total: total_bytes,
        });

        Box::new(HubTracker {
            hub: self.hub.clone(),
            id,
            done: 0,
            last_sent: Instant::now(),
            inner: self.inner.as_ref().map(|r| r.start_file(path, total_bytes)),
        })
    }

    fn action_completed(&self, path: &str, kind: ActionKind) {
        if let Some(inner) = &self.inner {
            inner.action_completed(path, kind);
        }
        self.hub.send(UiEvent::ActionCompleted {
            path: path.to_string(),
            kind,
        });
    }
}

struct HubTracker {
    hub: Hub,
    id: u64,
    done: u64,
    last_sent: Instant,
    inner: Option<Box<dyn FileTracker>>,
}

impl FileTracker for HubTracker {
    fn add_bytes(&mut self, bytes: u64) {
        self.done += bytes;
        if let Some(inner) = &mut self.inner {
            inner.add_bytes(bytes);
        }
        if self.last_sent.elapsed() >= PROGRESS_INTERVAL {
            self.last_sent = Instant::now();
            self.hub.send(UiEvent::FileProgress {
                id: self.id,
                done: self.done,
            });
        }
    }
}

impl Drop for HubTracker {
    fn drop(&mut self) {
        self.hub.send(UiEvent::FileProgress {
            id: self.id,
            done: self.done,
        });
        self.hub.send(UiEvent::FileFinished { id: self.id });
    }
}

/// A `tracing` writer for TUI mode, where anything on stderr would scribble over
/// the alternate screen: each formatted record becomes a `Log` event instead.
pub struct HubMakeWriter(pub Hub);

pub struct HubLogWriter {
    hub: Hub,
    level: LogLevel,
    buf: Vec<u8>,
}

impl io::Write for HubLogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for HubLogWriter {
    fn drop(&mut self) {
        let msg = String::from_utf8_lossy(&self.buf);
        let msg = msg.trim_end();
        if !msg.is_empty() {
            self.hub.send(UiEvent::Log {
                level: self.level,
                msg: msg.to_string(),
            });
        }
    }
}

impl HubMakeWriter {
    fn writer(&self, level: LogLevel) -> HubLogWriter {
        HubLogWriter {
            hub: self.0.clone(),
            level,
            buf: Vec::new(),
        }
    }
}

impl<'a> MakeWriter<'a> for HubMakeWriter {
    type Writer = HubLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.writer(LogLevel::Info)
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        self.writer(match *meta.level() {
            tracing::Level::ERROR => LogLevel::Error,
            tracing::Level::WARN => LogLevel::Warn,
            _ => LogLevel::Info,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_reports_final_progress_and_finish_on_drop() {
        let hub = Hub::new(false);
        let mut rx = hub.subscribe();
        let reporter = HubReporter::new(hub);

        let mut tracker = reporter.start_file("f", 10);
        tracker.add_bytes(4);
        tracker.add_bytes(6);
        drop(tracker);

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        assert!(matches!(
            events.first(),
            Some(UiEvent::FileStarted { total: 10, .. })
        ));
        assert!(matches!(
            events[events.len() - 2],
            UiEvent::FileProgress { done: 10, .. }
        ));
        assert!(matches!(events.last(), Some(UiEvent::FileFinished { .. })));
    }
}
