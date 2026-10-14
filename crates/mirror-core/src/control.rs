//! The `rfm watch` control socket: its wire types, and a client.
//!
//! Each connection carries one newline-terminated command. `status`, `stop`,
//! `sync`, `backup`, and evict/hydrate requests get a text reply and the daemon
//! closes the connection. `subscribe` instead streams events as JSON lines,
//! starting with a `Hello` snapshot, until the client goes away.

use std::{
    fmt, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

/// How long a command waits for the daemon's reply. Every command answers at once
/// (work is queued, not awaited); a daemon that's shutting down may accept a
/// connection but never answer it.
const REPLY_TIMEOUT: Duration = Duration::from_secs(15);

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
};

use crate::{
    Error, Result, config::Config, engine::ActionKind, indicator::human_bytes, sync::SyncOutcome,
};

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
    pub result: std::result::Result<SyncOutcome, String>,
}

/// The result of one finished daemon backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastBackup {
    pub at: SystemTime,
    pub result: std::result::Result<BackupSummary, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSummary {
    /// The snapshot's short ID.
    pub snapshot: String,
    pub files: u64,
    pub bytes_added: u64,
    /// Snapshots forgotten by an automatic prune afterwards, if one ran.
    pub pruned: Option<usize>,
}

impl fmt::Display for BackupSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "snapshot {}: {} files, {} new",
            self.snapshot,
            self.files,
            human_bytes(self.bytes_added)
        )?;
        if let Some(pruned) = self.pruned {
            write!(f, ", {pruned} old snapshots pruned")?;
        }
        Ok(())
    }
}

/// What a new subscriber needs to render before any live events arrive. Fields
/// added later default when missing, so an older daemon's hello still parses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub bucket: String,
    pub root: String,
    pub poll_interval_secs: u64,
    pub syncing: Option<Trigger>,
    pub last: Option<LastSync>,
    #[serde(default)]
    pub backing_up: bool,
    #[serde(default)]
    pub last_backup: Option<LastBackup>,
}

/// One line of the `subscribe` stream.
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
    BackupStarted,
    BackupFinished(LastBackup),
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

pub fn socket_path(config: &Config) -> PathBuf {
    config.local.root.join(".mirror/daemon.sock")
}

/// A refused or missing socket means no daemon; anything else (a path too long
/// for a socket, say) is reported as it is.
async fn connect(socket: &Path) -> Result<UnixStream> {
    UnixStream::connect(socket)
        .await
        .map_err(|source| match source.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                Error::DaemonNotRunning(socket.display().to_string())
            }
            _ => Error::Io {
                path: socket.to_path_buf(),
                source,
            },
        })
}

fn io_error(socket: &Path) -> impl FnOnce(io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: socket.to_path_buf(),
        source,
    }
}

/// Sends one command and returns the daemon's whole reply.
pub async fn request(socket: &Path, command: &str) -> Result<String> {
    let mut stream = connect(socket).await?;
    stream
        .write_all(format!("{command}\n").as_bytes())
        .await
        .map_err(io_error(socket))?;
    let mut reply = String::new();
    tokio::time::timeout(REPLY_TIMEOUT, stream.read_to_string(&mut reply))
        .await
        .map_err(|_| Error::DaemonUnresponsive(socket.display().to_string()))?
        .map_err(io_error(socket))?;
    Ok(reply)
}

/// A live `subscribe` stream.
pub struct Subscription {
    lines: Lines<BufReader<OwnedReadHalf>>,
    /// Kept open: dropping the write half would half-close the socket.
    _write: OwnedWriteHalf,
}

/// Subscribes to the daemon's events, returning its hello snapshot and the stream
/// of what follows. A daemon that answers with anything but a hello predates
/// `subscribe`: `Error::DaemonIncompatible`.
pub async fn subscribe(socket: &Path) -> Result<(Snapshot, Subscription)> {
    let (read, mut write) = connect(socket).await?.into_split();
    write
        .write_all(b"subscribe\n")
        .await
        .map_err(io_error(socket))?;
    let mut lines = BufReader::new(read).lines();

    let first = tokio::time::timeout(REPLY_TIMEOUT, lines.next_line())
        .await
        .map_err(|_| Error::DaemonUnresponsive(socket.display().to_string()))?
        .map_err(io_error(socket))?
        .unwrap_or_default();
    match serde_json::from_str(&first) {
        Ok(UiEvent::Hello(snapshot)) => Ok((
            snapshot,
            Subscription {
                lines,
                _write: write,
            },
        )),
        _ => Err(Error::DaemonIncompatible(first.trim().to_string())),
    }
}

impl Subscription {
    /// The next event, or `None` once the daemon closes the stream. A line that
    /// doesn't parse (a newer daemon's event, say) comes back as a warning rather
    /// than ending the stream.
    pub async fn next(&mut self) -> Result<Option<UiEvent>> {
        let Some(line) = self.lines.next_line().await.map_err(|source| Error::Io {
            path: PathBuf::from("<daemon socket>"),
            source,
        })?
        else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_str(&line).unwrap_or_else(|e| {
            UiEvent::Log {
                level: LogLevel::Warn,
                msg: format!("unreadable event from daemon: {e}"),
            }
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::UnixListener;

    fn hello() -> UiEvent {
        UiEvent::Hello(Snapshot {
            bucket: "b".into(),
            root: "/r".into(),
            poll_interval_secs: 60,
            syncing: None,
            last: None,
            backing_up: false,
            last_backup: None,
        })
    }

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
                backing_up: true,
                last_backup: None,
            }),
            UiEvent::Polled,
            UiEvent::BackupStarted,
            UiEvent::BackupFinished(LastBackup {
                at: SystemTime::UNIX_EPOCH,
                result: Ok(BackupSummary {
                    snapshot: "ab12cd34".into(),
                    files: 3,
                    bytes_added: 2048,
                    pruned: Some(1),
                }),
            }),
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

    /// An older daemon's hello, without the backup fields, still parses.
    #[test]
    fn hello_from_an_older_daemon_parses() {
        let line = r#"{"event":"hello","bucket":"b","root":"/r","poll_interval_secs":60,"syncing":null,"last":null}"#;
        let UiEvent::Hello(snapshot) = serde_json::from_str(line).unwrap() else {
            panic!("not a hello");
        };
        assert!(!snapshot.backing_up && snapshot.last_backup.is_none());
    }

    #[test]
    fn backup_summary_reads_well() {
        let mut summary = BackupSummary {
            snapshot: "ab12cd34".into(),
            files: 10,
            bytes_added: 0,
            pruned: None,
        };
        assert_eq!(summary.to_string(), "snapshot ab12cd34: 10 files, 0 B new");
        summary.pruned = Some(2);
        assert!(summary.to_string().ends_with(", 2 old snapshots pruned"));
    }

    /// A fake daemon: answers each connection's first line with `reply(line)`.
    fn serve(socket: &Path, reply: fn(&str) -> Vec<String>) {
        let listener = UnixListener::bind(socket).unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                let line = lines.next_line().await.unwrap().unwrap_or_default();
                for out in reply(&line) {
                    write.write_all(out.as_bytes()).await.unwrap();
                }
            }
        });
    }

    #[tokio::test]
    async fn request_round_trips_a_command() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("d.sock");
        serve(&socket, |line| vec![format!("got {line}\n")]);
        assert_eq!(request(&socket, "sync").await.unwrap(), "got sync\n");
    }

    #[tokio::test]
    async fn subscribe_yields_the_hello_then_events() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("d.sock");
        serve(&socket, |line| {
            assert_eq!(line, "subscribe");
            [
                hello(),
                UiEvent::BackupStarted,
                UiEvent::SyncStarted {
                    trigger: Trigger::Manual,
                },
            ]
            .iter()
            .map(|e| serde_json::to_string(e).unwrap() + "\n")
            .chain(["{\"event\":\"from_the_future\"}\n".to_string()])
            .collect()
        });

        let (snapshot, mut events) = subscribe(&socket).await.unwrap();
        assert_eq!(snapshot.bucket, "b");
        assert!(matches!(
            events.next().await.unwrap(),
            Some(UiEvent::BackupStarted)
        ));
        assert!(matches!(
            events.next().await.unwrap(),
            Some(UiEvent::SyncStarted {
                trigger: Trigger::Manual
            })
        ));
        assert!(matches!(
            events.next().await.unwrap(),
            Some(UiEvent::Log {
                level: LogLevel::Warn,
                ..
            })
        ));
        assert!(
            events.next().await.unwrap().is_none(),
            "daemon closed the stream"
        );
    }

    #[tokio::test]
    async fn an_old_daemon_and_no_daemon_are_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("d.sock");
        assert!(matches!(
            subscribe(&socket).await,
            Err(Error::DaemonNotRunning(_))
        ));
        assert!(matches!(
            request(&socket, "status").await,
            Err(Error::DaemonNotRunning(_))
        ));

        serve(&socket, |_| vec!["unknown command\n".into()]);
        assert!(matches!(
            subscribe(&socket).await,
            Err(Error::DaemonIncompatible(reply)) if reply == "unknown command"
        ));
    }

    /// A daemon that takes the connection but never answers (one shutting down).
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_never_answers_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("d.sock");
        let _listener = UnixListener::bind(&socket).unwrap(); // never accepts
        assert!(matches!(
            request(&socket, "status").await,
            Err(Error::DaemonUnresponsive(_))
        ));
        assert!(matches!(
            subscribe(&socket).await,
            Err(Error::DaemonUnresponsive(_))
        ));
    }

    /// A socket file left by a crashed daemon refuses connections: not running.
    #[tokio::test]
    async fn a_stale_socket_counts_as_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("d.sock");
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        assert!(socket.exists());
        assert!(matches!(
            request(&socket, "status").await,
            Err(Error::DaemonNotRunning(_))
        ));
    }
}
