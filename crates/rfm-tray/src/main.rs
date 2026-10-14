//! `rfm-tray`: the rfm menu bar app. macOS only; see `app`.

#[cfg(target_os = "macos")]
mod app;

#[cfg(target_os = "macos")]
fn main() {
    app::main();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("rfm-tray only runs on macOS");
    std::process::exit(1);
}
