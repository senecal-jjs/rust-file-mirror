//! Dashboard state: a pure reducer over `UiEvent`s plus key handling, so it can be
//! tested without a terminal.

use std::{
    collections::{BTreeMap, VecDeque},
    time::SystemTime,
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use mirror_core::engine::ActionKind;

use crate::{
    events::{LastSync, LogLevel, Snapshot, Trigger, UiEvent},
    ops::summary,
};

/// Activity lines kept for scrollback.
const ACTIVITY_CAP: usize = 500;
const PAGE: usize = 10;

/// Something the user asked the daemon to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAction {
    SyncNow,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    Quit,
    Action(UiAction),
}

pub struct Transfer {
    pub path: String,
    pub total: u64,
    pub done: u64,
}

pub enum EntryKind {
    Action(ActionKind, String),
    Log(LogLevel, String),
    Synced(String),
    Failed(String),
}

pub struct Entry {
    pub clock: String,
    pub kind: EntryKind,
}

#[derive(Default)]
pub struct Totals {
    pub uploads: usize,
    pub downloads: usize,
    pub bytes: u64,
}

pub struct App {
    pub snapshot: Option<Snapshot>,
    pub syncing: Option<(Trigger, SystemTime)>,
    pub last: Option<LastSync>,
    pub last_poll: Option<SystemTime>,
    pub transfers: BTreeMap<u64, Transfer>,
    pub activity: VecDeque<Entry>,
    /// Lines scrolled up from the newest entry; 0 follows new output.
    pub scroll: usize,
    pub connected: bool,
    pub totals: Totals,
    clock: fn(SystemTime) -> String,
}

impl Default for App {
    fn default() -> Self {
        Self::with_clock(local_clock)
    }
}

fn local_clock(at: SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(at)
        .format("%H:%M:%S")
        .to_string()
}

impl App {
    /// `clock` formats an entry's timestamp; tests pass a fixed-zone one.
    pub fn with_clock(clock: fn(SystemTime) -> String) -> Self {
        Self {
            snapshot: None,
            syncing: None,
            last: None,
            last_poll: None,
            transfers: BTreeMap::new(),
            activity: VecDeque::new(),
            scroll: 0,
            connected: true,
            totals: Totals::default(),
            clock,
        }
    }

    pub fn apply(&mut self, event: UiEvent) {
        self.apply_at(event, SystemTime::now());
    }

    pub fn apply_at(&mut self, event: UiEvent, now: SystemTime) {
        match event {
            UiEvent::Hello(snapshot) => {
                self.syncing = snapshot.syncing.map(|t| (t, now));
                self.last = snapshot.last.clone();
                self.snapshot = Some(snapshot);
            }
            UiEvent::Polled => self.last_poll = Some(now),
            UiEvent::SyncStarted { trigger } => self.syncing = Some((trigger, now)),
            UiEvent::SyncFinished(last) => {
                self.syncing = None;
                // Trackers always finish before their pass does; anything left is
                // from events skipped by a lagging subscription.
                self.transfers.clear();
                match &last.result {
                    Ok(outcome) if !outcome.is_noop() => {
                        self.push(EntryKind::Synced(summary(outcome)), now)
                    }
                    Ok(_) => {}
                    Err(e) => self.push(EntryKind::Failed(e.clone()), now),
                }
                self.last = Some(last);
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
                if let Some(transfer) = self.transfers.remove(&id) {
                    self.totals.bytes += transfer.done;
                }
            }
            UiEvent::ActionCompleted { path, kind } => {
                match kind {
                    ActionKind::Upload => self.totals.uploads += 1,
                    ActionKind::Download | ActionKind::Hydrate => self.totals.downloads += 1,
                    _ => {}
                }
                self.push(EntryKind::Action(kind, path), now);
            }
            UiEvent::Log { level, msg } => self.push(EntryKind::Log(level, msg), now),
        }
    }

    /// The event source closed: the daemon exited or the socket dropped.
    pub fn disconnected(&mut self, now: SystemTime) {
        self.connected = false;
        self.syncing = None;
        self.transfers.clear();
        self.push(
            EntryKind::Log(LogLevel::Error, "disconnected from the daemon".into()),
            now,
        );
    }

    fn push(&mut self, kind: EntryKind, now: SystemTime) {
        self.activity.push_back(Entry {
            clock: (self.clock)(now),
            kind,
        });
        if self.activity.len() > ACTIVITY_CAP {
            self.activity.pop_front();
        }
        // Keep a scrolled-back view pinned to the same lines.
        if self.scroll > 0 {
            self.scroll = (self.scroll + 1).min(self.max_scroll());
        }
    }

    fn max_scroll(&self) -> usize {
        self.activity.len().saturating_sub(1)
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Option<Input> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if ctrl => return Some(Input::Quit),
            KeyCode::Char('q') | KeyCode::Esc => return Some(Input::Quit),
            KeyCode::Char('s') if self.connected => return Some(Input::Action(UiAction::SyncNow)),
            KeyCode::Char('c') => {
                self.activity.clear();
                self.scroll = 0;
            }
            KeyCode::Up | KeyCode::Char('k') => self.scroll_by(1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_by(-1),
            KeyCode::PageUp => self.scroll_by(PAGE as isize),
            KeyCode::PageDown => self.scroll_by(-(PAGE as isize)),
            KeyCode::Home | KeyCode::Char('g') => self.scroll = self.max_scroll(),
            KeyCode::End | KeyCode::Char('G') => self.scroll = 0,
            _ => {}
        }
        None
    }

    fn scroll_by(&mut self, delta: isize) {
        self.scroll = self
            .scroll
            .saturating_add_signed(delta)
            .min(self.max_scroll());
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mirror_core::sync::SyncOutcome;

    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn log(msg: &str) -> UiEvent {
        UiEvent::Log {
            level: LogLevel::Info,
            msg: msg.into(),
        }
    }

    #[test]
    fn transfer_lifecycle_feeds_totals() {
        let mut app = App::default();
        app.apply(UiEvent::FileStarted {
            id: 1,
            path: "a".into(),
            total: 100,
        });
        app.apply(UiEvent::FileProgress { id: 1, done: 40 });
        assert_eq!(app.transfers[&1].done, 40);

        app.apply(UiEvent::FileProgress { id: 1, done: 100 });
        app.apply(UiEvent::FileFinished { id: 1 });
        app.apply(UiEvent::ActionCompleted {
            path: "a".into(),
            kind: ActionKind::Upload,
        });

        assert!(app.transfers.is_empty());
        assert_eq!(app.totals.bytes, 100);
        assert_eq!(app.totals.uploads, 1);
        assert_eq!(app.activity.len(), 1);
    }

    #[test]
    fn finishing_a_pass_clears_stale_transfers_and_records_errors() {
        let mut app = App::default();
        app.apply(UiEvent::SyncStarted {
            trigger: Trigger::Poll,
        });
        app.apply(UiEvent::FileStarted {
            id: 7,
            path: "orphan".into(),
            total: 1,
        });
        app.apply_at(
            UiEvent::SyncFinished(LastSync {
                at: at(10),
                result: Err("bucket unreachable".into()),
            }),
            at(10),
        );

        assert!(app.syncing.is_none());
        assert!(app.transfers.is_empty());
        assert!(matches!(
            app.activity.back().map(|e| &e.kind),
            Some(EntryKind::Failed(msg)) if msg == "bucket unreachable"
        ));
    }

    #[test]
    fn noop_passes_stay_out_of_the_activity_log() {
        let mut app = App::default();
        app.apply(UiEvent::SyncFinished(LastSync {
            at: at(0),
            result: Ok(SyncOutcome::default()),
        }));
        assert!(app.activity.is_empty());
        assert!(app.last.is_some());
    }

    #[test]
    fn activity_is_capped() {
        let mut app = App::default();
        for i in 0..ACTIVITY_CAP + 25 {
            app.apply(log(&i.to_string()));
        }
        assert_eq!(app.activity.len(), ACTIVITY_CAP);
        assert!(matches!(
            &app.activity.front().unwrap().kind,
            EntryKind::Log(_, msg) if msg == "25"
        ));
    }

    #[test]
    fn scrolled_view_stays_put_as_lines_arrive() {
        let mut app = App::default();
        for i in 0..20 {
            app.apply(log(&i.to_string()));
        }
        app.on_key(key(KeyCode::Up));
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.scroll, 2);

        app.apply(log("new"));
        assert_eq!(app.scroll, 3);

        app.on_key(key(KeyCode::End));
        assert_eq!(app.scroll, 0);
        app.apply(log("newer"));
        assert_eq!(app.scroll, 0, "an unscrolled view follows new output");

        app.on_key(key(KeyCode::PageUp));
        app.on_key(key(KeyCode::PageUp));
        app.on_key(key(KeyCode::PageUp));
        assert_eq!(
            app.scroll,
            app.activity.len() - 1,
            "clamped to the oldest line"
        );
    }

    #[test]
    fn keys_map_to_inputs() {
        let mut app = App::default();
        assert_eq!(app.on_key(key(KeyCode::Char('q'))), Some(Input::Quit));
        assert_eq!(
            app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Input::Quit)
        );
        assert_eq!(
            app.on_key(key(KeyCode::Char('s'))),
            Some(Input::Action(UiAction::SyncNow))
        );

        app.disconnected(at(0));
        assert_eq!(app.on_key(key(KeyCode::Char('s'))), None);
    }
}
