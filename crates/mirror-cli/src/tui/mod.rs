//! The live dashboard, used by `rfm watch --tui` (events from the in-process
//! hub) and `rfm tui` (events streamed from a daemon's control socket).

mod app;
mod ui;

use std::{future::Future, time::Duration};

use anyhow::Result;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures_util::StreamExt;
use tokio::sync::mpsc;

pub use app::UiAction;
use app::{App, Input};

use crate::events::UiEvent;

/// Redraw cadence; events between frames just update state.
const FRAME: Duration = Duration::from_millis(100);

/// Restores the terminal however `run` exits. Panics are covered separately by
/// the hook `ratatui::init` installs.
struct RestoreGuard;

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

/// Runs the dashboard until the user quits or `stop` resolves.
pub async fn run(
    mut events: mpsc::UnboundedReceiver<UiEvent>,
    on_action: impl Fn(UiAction) + Send + 'static,
    stop: impl Future<Output = ()> + Send,
) -> Result<()> {
    let mut terminal = ratatui::init();
    let _restore = RestoreGuard;

    let mut app = App::default();
    let mut keys = EventStream::new();
    let mut frame = tokio::time::interval(FRAME);
    frame.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(stop);

    loop {
        tokio::select! {
            _ = frame.tick() => {
                terminal.draw(|f| ui::render(f, &app, std::time::SystemTime::now()))?;
            }
            event = events.recv(), if app.connected => match event {
                Some(event) => app.apply(event),
                None => app.disconnected(std::time::SystemTime::now()),
            },
            key = keys.next() => match key {
                // Raw mode delivers Ctrl-C as a key, not SIGINT; `on_key` maps it to Quit.
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    match app.on_key(key) {
                        Some(Input::Quit) => break,
                        Some(Input::Action(action)) => on_action(action),
                        None => {}
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
                None => break,
            },
            _ = &mut stop => break,
        }
    }

    Ok(())
}
