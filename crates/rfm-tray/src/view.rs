//! What the menu shows for a given state: a pure description the binary draws.

use std::time::{Duration, SystemTime};

use mirror_core::control::{LastBackup, LastSync};
use mirror_core::engine::ActionKind;
use mirror_core::indicator::human_bytes;

use crate::state::{Connection, Recent, TrayState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IconState {
    Idle,
    Busy,
    Error,
    Offline,
}

/// Something a menu item asks for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Command {
    Sync,
    Backup,
    OpenFolder,
    OpenDashboard,
    /// Run `rfm init` in Terminal.
    SetUp,
    /// Show a file from Recent in Finder; the path is relative to the root.
    Reveal(String),
    StartDaemon,
    StopDaemon,
    RestartDaemon,
    InstallService,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row {
    /// A line of status: shown, never clickable.
    Info(String),
    Separator,
    Action {
        command: Command,
        label: String,
        enabled: bool,
    },
    Submenu {
        label: String,
        items: Vec<Row>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuModel {
    pub icon: IconState,
    pub tooltip: String,
    pub rows: Vec<Row>,
}

/// A row's identity without its text: two models with the same shape differ only
/// in labels and enabled flags, so a drawn menu can be updated in place rather than
/// rebuilt (rebuilding an open menu would close it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    Info,
    Separator,
    Action(Command),
    Submenu(Vec<Shape>),
}

impl MenuModel {
    pub fn shape(&self) -> Vec<Shape> {
        fn shape(rows: &[Row]) -> Vec<Shape> {
            rows.iter()
                .map(|row| match row {
                    Row::Info(_) => Shape::Info,
                    Row::Separator => Shape::Separator,
                    Row::Action { command, .. } => Shape::Action(command.clone()),
                    Row::Submenu { items, .. } => Shape::Submenu(shape(items)),
                })
                .collect()
        }
        shape(&self.rows)
    }

    /// A plain-text rendering, for tests and debugging.
    pub fn to_text(&self) -> String {
        fn render(rows: &[Row], indent: &str, out: &mut String) {
            for row in rows {
                match row {
                    Row::Info(text) => out.push_str(&format!("{indent}{text}\n")),
                    Row::Separator => out.push_str(&format!("{indent}---\n")),
                    Row::Action { label, enabled, .. } => {
                        let mark = if *enabled { "" } else { " (disabled)" };
                        out.push_str(&format!("{indent}[{label}]{mark}\n"));
                    }
                    Row::Submenu { label, items } => {
                        out.push_str(&format!("{indent}{label} >\n"));
                        render(items, &format!("{indent}    "), out);
                    }
                }
            }
        }
        let mut out = format!("icon: {:?}\ntooltip: {}\n", self.icon, self.tooltip);
        render(&self.rows, "", &mut out);
        out
    }
}

/// "just now", "4 min ago", "3 h ago", "2 days ago".
pub fn ago(at: SystemTime, now: SystemTime) -> String {
    let secs = now.duration_since(at).unwrap_or_default().as_secs();
    match secs {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", secs / 60),
        3600..86_400 => format!("{} h ago", secs / 3600),
        _ => match secs / 86_400 {
            1 => "1 day ago".into(),
            days => format!("{days} days ago"),
        },
    }
}

/// How long something has been running: "12 s", "3 min", "1 h 5 min".
pub fn running_for(since: SystemTime, now: SystemTime) -> String {
    let secs = now
        .duration_since(since)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    match secs {
        0..60 => format!("{secs} s"),
        60..3600 => format!("{} min", secs / 60),
        _ => format!("{} h {} min", secs / 3600, secs % 3600 / 60),
    }
}

/// The first line of an error, cut to fit a menu.
fn short(error: &str) -> String {
    let line = error.lines().next().unwrap_or_default();
    if line.chars().count() > 70 {
        format!("{}…", line.chars().take(69).collect::<String>())
    } else {
        line.to_string()
    }
}

/// The end of a path, cut from the left to fit a menu.
fn tail(path: &str, max: usize) -> String {
    let count = path.chars().count();
    if count <= max {
        path.to_string()
    } else {
        format!(
            "…{}",
            path.chars().skip(count - (max - 1)).collect::<String>()
        )
    }
}

fn recent_row(item: &Recent) -> Row {
    let (mark, revealable) = match item.kind {
        ActionKind::Upload => ("↑", true),
        ActionKind::Download | ActionKind::Hydrate => ("↓", true),
        ActionKind::Conflict => ("⚠", true),
        ActionKind::Relocate => ("→", true),
        ActionKind::CreatePlaceholder | ActionKind::UpdatePlaceholder => ("☁", true),
        ActionKind::DeleteLocal | ActionKind::DeleteRemote => ("✕", false),
    };
    Row::Action {
        command: Command::Reveal(item.path.clone()),
        label: format!("{mark} {}", tail(&item.path, 40)),
        enabled: revealable,
    }
}

pub fn view(state: &TrayState, now: SystemTime) -> MenuModel {
    let connected = state.connection == Connection::Connected;
    let sync_failed = matches!(state.last_sync, Some(LastSync { result: Err(_), .. }));
    let backup_failed = matches!(state.last_backup, Some(LastBackup { result: Err(_), .. }));

    let (icon, status) = match &state.connection {
        Connection::Connecting => (IconState::Offline, "○ Connecting…".to_string()),
        Connection::NotRunning => (IconState::Offline, "○ Daemon not running".to_string()),
        Connection::Incompatible(_) => (
            IconState::Offline,
            "○ Daemon is older than this tray; restart it".to_string(),
        ),
        Connection::Unconfigured(_) => {
            (IconState::Offline, "○ Not set up: run rfm init".to_string())
        }
        Connection::Failed(error) => (
            IconState::Offline,
            format!("○ Can't reach the daemon: {}", short(error)),
        ),
        Connection::Connected => match (&state.syncing, state.backing_up) {
            (Some((trigger, since)), _) => (
                IconState::Busy,
                format!("● Syncing ({trigger}) · {}", running_for(*since, now)),
            ),
            (None, Some(since)) => (
                IconState::Busy,
                format!("● Backing up · {}", running_for(since, now)),
            ),
            (None, None) => match &state.last_sync {
                Some(LastSync { result: Err(_), .. }) => {
                    (IconState::Error, "● Last sync failed".to_string())
                }
                Some(LastSync { at, .. }) => (
                    if backup_failed {
                        IconState::Error
                    } else {
                        IconState::Idle
                    },
                    format!("● Up to date · synced {}", ago(*at, now)),
                ),
                None => (IconState::Idle, "● Starting up".to_string()),
            },
        },
    };

    let mut rows = vec![Row::Info(status.clone())];
    if let (true, Some(LastSync { result: Err(e), .. })) = (sync_failed, &state.last_sync) {
        rows.push(Row::Info(format!("   {}", short(e))));
    }
    if let Some(since) = state
        .backing_up
        .filter(|_| connected && state.syncing.is_some())
    {
        rows.push(Row::Info(format!(
            "   Backing up · {}",
            running_for(since, now)
        )));
    } else if let Some(last) = &state.last_backup {
        rows.push(Row::Info(match &last.result {
            Ok(summary) => format!(
                "   Backup: {} (snapshot {})",
                ago(last.at, now),
                summary.snapshot
            ),
            Err(e) => format!("   Backup failed {}: {}", ago(last.at, now), short(e)),
        }));
    }
    if connected && !state.transfers.is_empty() {
        let first = state.transfers.values().next().expect("non-empty");
        let progress = match first.total {
            0 => String::new(),
            total => format!(" {}%", first.done * 100 / total),
        };
        let more = match state.transfers.len() {
            1 => String::new(),
            n => format!(" (+{} more)", n - 1),
        };
        let name = first.path.rsplit('/').next().unwrap_or(&first.path);
        rows.push(Row::Info(format!(
            "   ⇅ {}{progress}{more} · {}",
            tail(name, 30),
            human_bytes(first.total)
        )));
    }

    rows.push(Row::Separator);
    let action = |command, label: &str, enabled| Row::Action {
        command,
        label: label.to_string(),
        enabled,
    };
    rows.push(action(Command::Sync, "Sync Now", connected));
    rows.push(action(Command::Backup, "Back Up Now", connected));
    rows.push(action(
        Command::OpenFolder,
        "Open Folder",
        state.root.is_some(),
    ));
    if matches!(state.connection, Connection::Unconfigured(_)) {
        rows.push(action(Command::SetUp, "Set Up in Terminal…", true));
    } else {
        rows.push(action(Command::OpenDashboard, "Open Dashboard", connected));
    }
    if !state.recent.is_empty() {
        rows.push(Row::Submenu {
            label: "Recent".into(),
            items: state.recent.iter().map(recent_row).collect(),
        });
    }

    rows.push(Row::Separator);
    match &state.connection {
        Connection::Connected => rows.push(action(Command::StopDaemon, "Stop Daemon", true)),
        Connection::Incompatible(_) => rows.push(action(
            Command::RestartDaemon,
            "Restart Daemon",
            state.service_installed,
        )),
        Connection::NotRunning | Connection::Failed(_) if state.service_installed => {
            rows.push(action(Command::StartDaemon, "Start Daemon", true))
        }
        Connection::NotRunning | Connection::Failed(_) => rows.push(action(
            Command::InstallService,
            "Install Background Service…",
            true,
        )),
        Connection::Connecting => rows.push(action(Command::StartDaemon, "Start Daemon", false)),
        Connection::Unconfigured(_) => {}
    }
    rows.push(action(Command::Quit, "Quit rfm Tray", true));

    MenuModel {
        icon,
        tooltip: format!("rfm: {}", status.trim_start_matches(['●', '○', ' '])),
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Input;
    use mirror_core::control::{BackupSummary, Snapshot, Trigger, UiEvent};
    use mirror_core::sync::SyncOutcome;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000 + secs)
    }

    fn hello() -> Snapshot {
        Snapshot {
            bucket: "b".into(),
            root: "/Users/me/Mirror".into(),
            poll_interval_secs: 60,
            syncing: None,
            last: Some(LastSync {
                at: at(0),
                result: Ok(SyncOutcome::default()),
            }),
            backing_up: false,
            last_backup: Some(LastBackup {
                at: at(0),
                result: Ok(BackupSummary {
                    snapshot: "ab12cd34".into(),
                    files: 3,
                    bytes_added: 0,
                    pruned: None,
                }),
            }),
        }
    }

    fn connected() -> TrayState {
        let mut s = TrayState::new(Some("/Users/me/Mirror".into()));
        s.service_installed = true;
        s.apply(Input::Connected(hello()), at(0));
        s
    }

    #[test]
    fn relative_times() {
        assert_eq!(ago(at(0), at(30)), "just now");
        assert_eq!(ago(at(0), at(4 * 60 + 5)), "4 min ago");
        assert_eq!(ago(at(0), at(3 * 3600)), "3 h ago");
        assert_eq!(ago(at(0), at(86_400 + 5)), "1 day ago");
        assert_eq!(ago(at(0), at(3 * 86_400)), "3 days ago");
        assert_eq!(
            ago(at(10), at(0)),
            "just now",
            "clock skew never goes negative"
        );
        assert_eq!(running_for(at(0), at(12)), "12 s");
        assert_eq!(running_for(at(0), at(3725)), "1 h 2 min");
    }

    #[test]
    fn idle() {
        insta::assert_snapshot!(view(&connected(), at(150)).to_text());
    }

    #[test]
    fn syncing_with_transfers_and_recent() {
        let mut s = connected();
        let events = [
            UiEvent::SyncStarted {
                trigger: Trigger::FsChange,
            },
            UiEvent::FileStarted {
                id: 1,
                path: "Photos/2026/very-long-directory-name/IMG_0042.jpg".into(),
                total: 4_000_000,
            },
            UiEvent::FileProgress {
                id: 1,
                done: 1_800_000,
            },
            UiEvent::FileStarted {
                id: 2,
                path: "b.txt".into(),
                total: 10,
            },
            UiEvent::ActionCompleted {
                path: "docs/report.pdf".into(),
                kind: ActionKind::Upload,
            },
            UiEvent::ActionCompleted {
                path: "old.txt".into(),
                kind: ActionKind::DeleteRemote,
            },
        ];
        for event in events {
            s.apply(Input::Event(event), at(100));
        }
        insta::assert_snapshot!(view(&s, at(112)).to_text());
    }

    #[test]
    fn failures() {
        let mut s = connected();
        s.apply(
            Input::Event(UiEvent::SyncFinished(LastSync {
                at: at(10),
                result: Err("object store error: dispatch failure\ncaused by: timeout".into()),
            })),
            at(10),
        );
        s.apply(
            Input::Event(UiEvent::BackupFinished(LastBackup {
                at: at(20),
                result: Err("bucket unreachable".into()),
            })),
            at(20),
        );
        insta::assert_snapshot!(view(&s, at(80)).to_text());
    }

    #[test]
    fn a_failed_backup_alone_still_marks_the_icon() {
        let mut s = connected();
        s.apply(
            Input::Event(UiEvent::BackupFinished(LastBackup {
                at: at(5),
                result: Err("x".into()),
            })),
            at(5),
        );
        assert_eq!(view(&s, at(6)).icon, IconState::Error);
    }

    #[test]
    fn not_running_offers_start_or_install() {
        let mut s = connected();
        s.apply(Input::Lost(Connection::NotRunning), at(5));
        insta::assert_snapshot!(view(&s, at(5)).to_text());
        s.service_installed = false;
        let model = view(&s, at(5));
        assert!(
            model
                .shape()
                .contains(&Shape::Action(Command::InstallService))
        );
        assert!(!model.shape().contains(&Shape::Action(Command::StartDaemon)));
    }

    #[test]
    fn unconfigured_and_incompatible() {
        let mut s = TrayState::new(None);
        s.apply(
            Input::Lost(Connection::Unconfigured(
                "no config at ~/.config/rfm/config.toml".into(),
            )),
            at(0),
        );
        insta::assert_snapshot!("unconfigured", view(&s, at(0)).to_text());

        let mut s = connected();
        s.apply(
            Input::Lost(Connection::Incompatible("unknown command".into())),
            at(0),
        );
        insta::assert_snapshot!("incompatible", view(&s, at(0)).to_text());
    }

    #[test]
    fn progress_and_time_change_text_not_shape() {
        let mut s = connected();
        s.apply(
            Input::Event(UiEvent::SyncStarted {
                trigger: Trigger::Poll,
            }),
            at(0),
        );
        s.apply(
            Input::Event(UiEvent::FileStarted {
                id: 1,
                path: "a".into(),
                total: 100,
            }),
            at(0),
        );
        let before = view(&s, at(1));
        s.apply(
            Input::Event(UiEvent::FileProgress { id: 1, done: 50 }),
            at(2),
        );
        let after = view(&s, at(30));
        assert_ne!(before, after);
        assert_eq!(
            before.shape(),
            after.shape(),
            "updated in place, not rebuilt"
        );

        s.apply(Input::Event(UiEvent::FileFinished { id: 1 }), at(31));
        assert_ne!(view(&s, at(31)).shape(), after.shape(), "a row went away");
    }
}
