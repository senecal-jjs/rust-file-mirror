//! Draws an `App`. `now` is passed in rather than read, so renders are
//! reproducible in snapshot tests.

use std::time::{Duration, SystemTime};

use mirror_core::engine::ActionKind;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, LineGauge, Paragraph},
};

use super::app::{App, EntryKind};
use crate::{
    events::{LastSync, LogLevel},
    ops::{human_bytes, summary},
};

/// Transfer rows shown before the rest collapse into "… and N more".
const MAX_TRANSFER_ROWS: usize = 8;

pub fn render(frame: &mut Frame, app: &App, now: SystemTime) {
    let rows = app.transfers.len().clamp(1, MAX_TRANSFER_ROWS) as u16;
    let [header, transfers, activity, footer] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(rows + 2),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .areas(frame.area());

    render_header(frame, header, app, now);
    render_transfers(frame, transfers, app);
    render_activity(frame, activity, app);
    render_footer(frame, footer, app);
}

fn render_header(frame: &mut Frame, area: Rect, app: &App, now: SystemTime) {
    let block = Block::bordered().title(" rfm ".bold());

    let location = match &app.snapshot {
        Some(s) => Line::from(vec![
            "bucket ".dark_gray(),
            Span::raw(s.bucket.clone()),
            "   root ".dark_gray(),
            Span::raw(s.root.clone()),
        ]),
        None => Line::from("connecting…".dark_gray()),
    };

    let mut status = vec![if !app.connected {
        "● disconnected".red().bold()
    } else if let Some((trigger, since)) = app.syncing {
        format!("● syncing ({trigger}) {}", elapsed(since, now))
            .yellow()
            .bold()
    } else if matches!(app.last, Some(LastSync { result: Err(_), .. })) {
        "● idle, last sync failed".red().bold()
    } else {
        "● idle".green().bold()
    }];

    if let Some(last) = &app.last {
        status.push(format!("   last sync {} ago", elapsed(last.at, now)).dark_gray());
    }
    if let (Some(polled), Some(s), true) = (app.last_poll, &app.snapshot, app.connected) {
        let next = polled + Duration::from_secs(s.poll_interval_secs);
        let left = next.duration_since(now).unwrap_or_default();
        status.push(format!("   next poll in {}", duration(left)).dark_gray());
    }

    frame.render_widget(
        Paragraph::new(vec![location, Line::from(status)]).block(block),
        area,
    );
}

fn render_transfers(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(format!(" transfers ({}) ", app.transfers.len()));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.transfers.is_empty() {
        frame.render_widget(Paragraph::new("no active transfers".dark_gray()), inner);
        return;
    }

    let overflow = app.transfers.len() > MAX_TRANSFER_ROWS;
    let shown = if overflow {
        MAX_TRANSFER_ROWS - 1
    } else {
        app.transfers.len()
    };
    let rows = Layout::vertical(vec![Constraint::Length(1); inner.height as usize]).split(inner);

    for (row, transfer) in rows.iter().zip(app.transfers.values().take(shown)) {
        let [path, gauge, bytes] = Layout::horizontal([
            Constraint::Percentage(45),
            Constraint::Fill(1),
            Constraint::Length(24),
        ])
        .spacing(1)
        .areas(*row);

        let ratio = if transfer.total == 0 {
            1.0
        } else {
            (transfer.done as f64 / transfer.total as f64).clamp(0.0, 1.0)
        };

        frame.render_widget(Paragraph::new(transfer.path.as_str()), path);
        frame.render_widget(
            LineGauge::default()
                .ratio(ratio)
                .filled_style(Style::new().fg(Color::Cyan))
                .unfilled_style(Style::new().fg(Color::DarkGray)),
            gauge,
        );
        frame.render_widget(
            Paragraph::new(format!(
                "{} / {}",
                human_bytes(transfer.done),
                human_bytes(transfer.total)
            ))
            .right_aligned()
            .dark_gray(),
            bytes,
        );
    }

    if overflow && let Some(row) = rows.get(shown) {
        frame.render_widget(
            Paragraph::new(format!("… and {} more", app.transfers.len() - shown).dark_gray()),
            *row,
        );
    }
}

fn render_activity(frame: &mut Frame, area: Rect, app: &App) {
    let mut title = vec![Span::raw(" activity ")];
    if app.scroll > 0 {
        title.push(format!("(↑ {}) ", app.scroll).yellow());
    }
    let block = Block::bordered().title(Line::from(title));
    let height = block.inner(area).height as usize;

    let end = app.activity.len().saturating_sub(app.scroll);
    let start = end.saturating_sub(height);
    let lines: Vec<Line> = app
        .activity
        .range(start..end)
        .map(|entry| {
            let (label, style, text) = match &entry.kind {
                EntryKind::Action(kind, path) => {
                    (kind.to_string(), action_style(*kind), path.as_str())
                }
                EntryKind::Log(level, msg) => {
                    let (label, style) = match level {
                        LogLevel::Info => ("info", Style::new().fg(Color::Gray)),
                        LogLevel::Warn => ("warn", Style::new().fg(Color::Yellow)),
                        LogLevel::Error => ("error", Style::new().fg(Color::Red)),
                    };
                    (label.to_string(), style, msg.as_str())
                }
                EntryKind::Synced(text) => (
                    "synced".to_string(),
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
                    text.as_str(),
                ),
                EntryKind::Failed(err) => (
                    "sync failed".to_string(),
                    Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                    err.as_str(),
                ),
            };
            Line::from(vec![
                Span::raw(format!("{} ", entry.clock)).dark_gray(),
                Span::styled(format!("{label:<18} "), style),
                Span::raw(text.to_string()),
            ])
        })
        .collect();

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn action_style(kind: ActionKind) -> Style {
    let color = match kind {
        ActionKind::Upload => Color::Cyan,
        ActionKind::Download | ActionKind::Hydrate => Color::Blue,
        ActionKind::DeleteLocal | ActionKind::DeleteRemote => Color::Red,
        ActionKind::Conflict => Color::Yellow,
        ActionKind::Relocate | ActionKind::CreatePlaceholder | ActionKind::UpdatePlaceholder => {
            Color::Magenta
        }
    };
    Style::new().fg(color)
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let last = match &app.last {
        Some(LastSync { result: Ok(o), .. }) if o.is_noop() => {
            Line::from(vec!["last ".dark_gray(), "up to date".into()])
        }
        Some(LastSync { result: Ok(o), .. }) => {
            Line::from(vec!["last ".dark_gray(), Span::raw(summary(o))])
        }
        Some(LastSync { result: Err(e), .. }) => {
            Line::from(vec!["last ".dark_gray(), format!("failed: {e}").red()])
        }
        None => Line::from("no sync yet".dark_gray()),
    };

    let totals = &app.totals;
    let mut hints = vec![
        format!(
            "session {} up · {} down · {} moved   ",
            totals.uploads,
            totals.downloads,
            human_bytes(totals.bytes)
        )
        .dark_gray(),
        "q".bold(),
        " quit  ".dark_gray(),
    ];
    if app.connected {
        hints.extend(["s".bold(), " sync now  ".dark_gray()]);
    }
    hints.extend([
        "↑↓".bold(),
        " scroll  ".dark_gray(),
        "c".bold(),
        " clear".dark_gray(),
    ]);

    frame.render_widget(Paragraph::new(vec![last, Line::from(hints)]), area);
}

fn elapsed(since: SystemTime, now: SystemTime) -> String {
    duration(now.duration_since(since).unwrap_or_default())
}

fn duration(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m {}s", secs / 60, secs % 60),
        _ => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    use mirror_core::sync::SyncOutcome;
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::events::{Snapshot, Trigger, UiEvent};

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn utc_clock(t: SystemTime) -> String {
        chrono::DateTime::<chrono::Utc>::from(t)
            .format("%H:%M:%S")
            .to_string()
    }

    fn draw(app: &App, now: SystemTime) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 22)).unwrap();
        terminal.draw(|f| render(f, app, now)).unwrap();
        terminal.backend().to_string()
    }

    fn busy_app() -> App {
        let mut app = App::with_clock(utc_clock);
        let events = [
            UiEvent::Hello(Snapshot {
                bucket: "my-bucket".into(),
                root: "/Users/me/Mirror".into(),
                poll_interval_secs: 60,
                syncing: None,
                last: None,
            }),
            UiEvent::Polled,
            UiEvent::SyncFinished(LastSync {
                at: at(0),
                result: Ok(SyncOutcome {
                    uploads: 1,
                    downloads: 1,
                    ..SyncOutcome::default()
                }),
            }),
            UiEvent::ActionCompleted {
                path: "notes/todo.md".into(),
                kind: ActionKind::Upload,
            },
            UiEvent::Log {
                level: LogLevel::Warn,
                msg: "transfer failed; will retry next sync path=big.iso".into(),
            },
            UiEvent::SyncStarted {
                trigger: Trigger::FsChange,
            },
            UiEvent::FileStarted {
                id: 1,
                path: "photos/2026/beach.jpg".into(),
                total: 4 * 1024 * 1024,
            },
            UiEvent::FileProgress {
                id: 1,
                done: 1024 * 1024,
            },
        ];
        for event in events {
            app.apply_at(event, at(0));
        }
        app
    }

    #[test]
    fn renders_a_sync_in_progress() {
        insta::assert_snapshot!(draw(&busy_app(), at(12)));
    }

    #[test]
    fn renders_idle_and_disconnected() {
        let mut app = busy_app();
        app.disconnected(at(30));
        insta::assert_snapshot!(draw(&app, at(30)));
    }

    #[test]
    fn collapses_overflowing_transfers() {
        let mut app = App::with_clock(utc_clock);
        for id in 0..12 {
            app.apply_at(
                UiEvent::FileStarted {
                    id,
                    path: format!("file-{id}"),
                    total: 10,
                },
                at(0),
            );
        }
        let screen = draw(&app, at(0));
        assert!(screen.contains("file-6"));
        assert!(!screen.contains("file-7"));
        assert!(screen.contains("… and 5 more"));
    }
}
