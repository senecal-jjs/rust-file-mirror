//! The daemon's event stream: what `watch` is doing, as it happens. One `Hub`
//! fans events out to the in-process TUI and to `rfm tui` clients on the control
//! socket; in plain (non-TUI) mode it also prints them, so the daemon log reads
//! the same as before.

use std::{
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use mirror_core::{
    engine::ActionKind,
    indicator::{FileTracker, PrintReporter, ProgressReporter},
    sync::SyncOutcome,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing_subscriber::fmt::MakeWriter;

use crate::ops::summary;

/// Byte progress is coalesced to at most one event per file per interval, so a
/// multipart transfer can't flood the channel (or a socket subscriber).
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Events a lagging subscriber can fall behind by before it starts skipping.
const CHANNEL_CAPACITY: usize = 4096;

/// Why a sync pass ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    Poll,
    FsChange,
    Manual,
    Residency,
}

impl fmt::Display for Trigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Poll => "poll",
            Self::FsChange => "file change",
            Self::Manual => "manual",
            Self::Residency => "evict/hydrate",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

/// The result of one finished sync pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastSync {
    pub at: SystemTime,
    pub result: Result<SyncOutcome, String>,
}

/// What a new subscriber needs to render before any live events arrive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub bucket: String,
    pub root: String,
    pub poll_interval_secs: u64,
    pub syncing: Option<Trigger>,
    pub last: Option<LastSync>,
}

/// One line of the `subscribe` wire protocol (JSON), and the TUI's input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum UiEvent {
    Hello(Snapshot),
    /// The poll interval ticked (a sync may or may not follow, if one is already queued).
    Polled,
    SyncStarted {
        trigger: Trigger,
    },
    SyncFinished(LastSync),
    FileStarted {
        id: u64,
        path: String,
        total: u64,
    },
    FileProgress {
        id: u64,
        done: u64,
    },
    FileFinished {
        id: u64,
    },
    ActionCompleted {
        path: String,
        kind: ActionKind,
    },
    Log {
        level: LogLevel,
        msg: String,
    },
}

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
    fn events_round_trip_as_json_lines() {
        let events = vec![
            UiEvent::Hello(Snapshot {
                bucket: "b".into(),
                root: "/r".into(),
                poll_interval_secs: 60,
                syncing: Some(Trigger::FsChange),
                last: Some(LastSync {
                    at: SystemTime::UNIX_EPOCH + Duration::from_secs(5),
                    result: Err("boom".into()),
                }),
            }),
            UiEvent::Polled,
            UiEvent::SyncFinished(LastSync {
                at: SystemTime::UNIX_EPOCH,
                result: Ok(SyncOutcome {
                    uploads: 2,
                    ..SyncOutcome::default()
                }),
            }),
            UiEvent::ActionCompleted {
                path: "a/b.txt".into(),
                kind: ActionKind::DeleteRemote,
            },
        ];

        for event in events {
            let line = serde_json::to_string(&event).unwrap();
            assert!(!line.contains('\n'), "one event per line: {line}");
            let back: UiEvent = serde_json::from_str(&line).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), line);
        }
    }

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
