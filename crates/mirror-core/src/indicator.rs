use std::time::Instant;

use crate::engine::ActionKind;

pub trait FileTracker: Send {
    fn add_bytes(&mut self, bytes: u64);
}

/// One phase of a pass that isn't a transfer (reading the log, scanning, compacting).
/// Dropping it without `finish` abandons it silently, as on an error.
pub trait StageTracker: Send {
    /// Live detail for the running stage, such as the file being hashed.
    fn update(&mut self, _detail: &str) {}
    /// Closes the stage with a one-line summary.
    fn finish(self: Box<Self>, _summary: &str) {}
}

struct NoopStage;

impl StageTracker for NoopStage {}

pub trait ProgressReporter: Send + Sync {
    fn start_file(&self, path: &str, total_bytes: u64) -> Box<dyn FileTracker>;
    fn action_completed(&self, path: &str, kind: ActionKind);

    /// Without these, the stretches between transfers look like a hang.
    fn stage(&self, _name: &str) -> Box<dyn StageTracker> {
        Box::new(NoopStage)
    }
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;

    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub struct PrintTracker {
    path: String,
    total_bytes: u64,
    bytes_so_far: u64,
}

impl FileTracker for PrintTracker {
    fn add_bytes(&mut self, bytes: u64) {
        self.bytes_so_far += bytes;
        println!(
            "{}: +{} bytes (of {})",
            self.path, self.bytes_so_far, self.total_bytes
        );
    }
}

/// No shared state needed — unlike a real progress-bar reporter (which has to
/// coordinate multiple bars drawing to one terminal via something like
/// `MultiProgress`), each `PrintTracker` here is entirely self-contained, so
/// there's nothing for the reporter itself to hold onto between calls.
pub struct PrintReporter;

/// Prints the stage on entry and its summary on exit; per-file detail would flood a log.
struct PrintStage {
    name: String,
    started: Instant,
}

impl StageTracker for PrintStage {
    fn finish(self: Box<Self>, summary: &str) {
        println!(
            "{}: {summary} ({:.1}s)",
            self.name,
            self.started.elapsed().as_secs_f64()
        );
    }
}

impl ProgressReporter for PrintReporter {
    fn action_completed(&self, path: &str, kind: ActionKind) {
        println!("completed {} for {}", kind, path);
    }

    fn stage(&self, name: &str) -> Box<dyn StageTracker> {
        println!("{name}...");
        Box::new(PrintStage {
            name: name.to_string(),
            started: Instant::now(),
        })
    }

    fn start_file(&self, path: &str, total_bytes: u64) -> Box<dyn FileTracker> {
        Box::new(PrintTracker {
            path: path.to_string(),
            total_bytes,
            bytes_so_far: 0,
        })
    }
}
