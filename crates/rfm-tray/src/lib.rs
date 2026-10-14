//! `rfm-tray`: a menu bar app showing what `rfm watch` is doing and offering the
//! common commands. It's a client of the daemon's control socket, like `rfm tui`.
//!
//! Everything that decides what the menu says lives here, as pure functions of the
//! daemon's events (`state`, `view`), so it's testable without a display. The
//! binary only draws the result and runs commands.

pub mod icons;
pub mod state;
pub mod view;
