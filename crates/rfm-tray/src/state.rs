//! What the tray knows: a reducer over the daemon's events and connection changes.

use std::collections::{BTreeMap, VecDeque};
use std::time::SystemTime;

use mirror_core::control::{LastBackup, LastSync, Snapshot, Trigger, UiEvent};
use mirror_core::engine::ActionKind;

/// Completed actions kept for the Recent submenu.
pub const RECENT_CAP: usize = 8;

/// The state of the connection to the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connection {
    Connecting,
    Connected,
    NotRunning,
    /// The daemon answered, but predates `subscribe`; the reply is kept.
    Incompatible(String),
    /// No usable config (`rfm init` hasn't run, or the root is missing).
    Unconfigured(String),
    /// Anything else stopping a connection, such as a socket path too long.
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub path: String,
    pub total: u64,
    pub done: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recent {
    pub path: String,
    pub kind: ActionKind,
}

/// What the tray is told: daemon events, plus changes the subscriber notices.
#[derive(Debug, Clone)]
pub enum Input {
    Connected(Snapshot),
    Event(UiEvent),
    /// The connection ended or couldn't be made.
    Lost(Connection),
}

#[derive(Debug, Clone)]
pub struct TrayState {
    pub connection: Connection,
    /// The mirrored root, from the config; known even when the daemon isn't running.
    pub root: Option<String>,
    pub syncing: Option<(Trigger, SystemTime)>,
    pub last_sync: Option<LastSync>,
    pub backing_up: Option<SystemTime>,
    pub last_backup: Option<LastBackup>,
    pub transfers: BTreeMap<u64, Transfer>,
    /// Newest first.
    pub recent: VecDeque<Recent>,
    /// Whether `rfm service install` has set up the daemon's LaunchAgent.
    pub service_installed: bool,
}

impl TrayState {
    pub fn new(root: Option<String>) -> Self {
        Self {
            connection: Connection::Connecting,
            root,
            syncing: None,
            last_sync: None,
            backing_up: None,
            last_backup: None,
            transfers: BTreeMap::new(),
            recent: VecDeque::new(),
            service_installed: false,
        }
    }

    pub fn apply(&mut self, input: Input, now: SystemTime) {
        match input {
            Input::Connected(hello) => {
                self.connection = Connection::Connected;
                self.syncing = hello.syncing.map(|t| (t, now));
                self.last_sync = hello.last;
                self.backing_up = hello.backing_up.then_some(now);
                self.last_backup = hello.last_backup;
                self.root = Some(hello.root);
                // Anything in flight before a reconnect is stale.
                self.transfers.clear();
            }
            Input::Lost(connection) => {
                self.connection = connection;
                self.syncing = None;
                self.backing_up = None;
                self.transfers.clear();
            }
            Input::Event(event) => self.apply_event(event, now),
        }
    }

    fn apply_event(&mut self, event: UiEvent, now: SystemTime) {
        match event {
            UiEvent::Hello(hello) => self.apply(Input::Connected(hello), now),
            UiEvent::SyncStarted { trigger } => self.syncing = Some((trigger, now)),
            UiEvent::SyncFinished(last) => {
                self.syncing = None;
                // Trackers finish before their pass; leftovers are from skipped events.
                self.transfers.clear();
                self.last_sync = Some(last);
            }
            UiEvent::BackupStarted => self.backing_up = Some(now),
            UiEvent::BackupFinished(last) => {
                self.backing_up = None;
                self.last_backup = Some(last);
            }
            UiEvent::FileStarted { id, path, total } => {
                self.transfers.insert(
                    id,
                    Transfer {
                        path,
                        total,
                        done: 0,
                    },
                );
            }
            UiEvent::FileProgress { id, done } => {
                if let Some(transfer) = self.transfers.get_mut(&id) {
                    transfer.done = done;
                }
            }
            UiEvent::FileFinished { id } => {
                self.transfers.remove(&id);
            }
            UiEvent::ActionCompleted { path, kind } => {
                self.recent.push_front(Recent { path, kind });
                self.recent.truncate(RECENT_CAP);
            }
            UiEvent::Polled | UiEvent::Log { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirror_core::sync::SyncOutcome;
    use std::time::Duration;

    pub(crate) fn hello() -> Snapshot {
        Snapshot {
            bucket: "b".into(),
            root: "/Users/me/Mirror".into(),
            poll_interval_secs: 60,
            syncing: None,
            last: None,
            backing_up: false,
            last_backup: None,
        }
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn hello_seeds_state_and_events_update_it() {
        let mut s = TrayState::new(None);
        let mut h = hello();
        h.syncing = Some(Trigger::Poll);
        s.apply(Input::Connected(h), at(10));
        assert_eq!(s.connection, Connection::Connected);
        assert_eq!(s.syncing, Some((Trigger::Poll, at(10))));
        assert_eq!(s.root.as_deref(), Some("/Users/me/Mirror"));

        s.apply(
            Input::Event(UiEvent::FileStarted {
                id: 1,
                path: "a.bin".into(),
                total: 100,
            }),
            at(11),
        );
        s.apply(
            Input::Event(UiEvent::FileProgress { id: 1, done: 40 }),
            at(11),
        );
        assert_eq!(s.transfers[&1].done, 40);

        s.apply(
            Input::Event(UiEvent::SyncFinished(LastSync {
                at: at(12),
                result: Ok(SyncOutcome::default()),
            })),
            at(12),
        );
        assert!(s.syncing.is_none() && s.transfers.is_empty() && s.last_sync.is_some());
    }

    #[test]
    fn recent_keeps_the_newest_few() {
        let mut s = TrayState::new(None);
        for i in 0..RECENT_CAP + 3 {
            s.apply(
                Input::Event(UiEvent::ActionCompleted {
                    path: format!("f{i}"),
                    kind: ActionKind::Upload,
                }),
                at(0),
            );
        }
        assert_eq!(s.recent.len(), RECENT_CAP);
        assert_eq!(s.recent[0].path, format!("f{}", RECENT_CAP + 2));
    }

    #[test]
    fn losing_the_daemon_clears_what_was_in_flight_but_keeps_history() {
        let mut s = TrayState::new(None);
        s.apply(Input::Connected(hello()), at(0));
        s.apply(Input::Event(UiEvent::BackupStarted), at(1));
        s.apply(
            Input::Event(UiEvent::FileStarted {
                id: 1,
                path: "a".into(),
                total: 1,
            }),
            at(1),
        );
        s.apply(
            Input::Event(UiEvent::ActionCompleted {
                path: "a".into(),
                kind: ActionKind::Upload,
            }),
            at(1),
        );

        s.apply(Input::Lost(Connection::NotRunning), at(2));
        assert_eq!(s.connection, Connection::NotRunning);
        assert!(s.backing_up.is_none() && s.transfers.is_empty());
        assert_eq!(s.recent.len(), 1, "history outlives the connection");
        assert_eq!(s.root.as_deref(), Some("/Users/me/Mirror"));
    }
}
