use std::time::{Duration, Instant};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use mirror_core::indicator::{FileTracker, ProgressReporter, StageTracker};

pub struct VisualBarReporter {
    pub multi: MultiProgress,
}

pub struct VisualFileTracker {
    bar: ProgressBar,
}

impl FileTracker for VisualFileTracker {
    fn add_bytes(&mut self, bytes: u64) {
        self.bar.inc(bytes);
    }
}

impl Drop for VisualFileTracker {
    fn drop(&mut self) {
        self.bar.finish_and_clear();
    }
}

/// A spinner that keeps ticking while the stage works, so a slow stage still
/// visibly moves; replaced by a summary line when it finishes.
pub struct VisualStageTracker {
    multi: MultiProgress,
    spinner: ProgressBar,
    name: String,
    started: Instant,
}

impl StageTracker for VisualStageTracker {
    fn update(&mut self, detail: &str) {
        self.spinner.set_message(detail.to_string());
    }

    fn finish(self: Box<Self>, summary: &str) {
        let _ = self.multi.println(format!(
            "{}: {summary} ({:.1}s)",
            self.name,
            self.started.elapsed().as_secs_f64()
        ));
    }
}

impl Drop for VisualStageTracker {
    fn drop(&mut self) {
        self.spinner.finish_and_clear();
    }
}

impl ProgressReporter for VisualBarReporter {
    fn stage(&self, name: &str) -> Box<dyn StageTracker> {
        let spinner = self.multi.add(ProgressBar::new_spinner());
        spinner.set_style(
            ProgressStyle::with_template("{spinner} {prefix} [{elapsed}] {wide_msg}")
                .expect("valid template"),
        );
        spinner.set_prefix(name.to_string());
        spinner.enable_steady_tick(Duration::from_millis(120));

        Box::new(VisualStageTracker {
            multi: self.multi.clone(),
            spinner,
            name: name.to_string(),
            started: Instant::now(),
        })
    }

    fn action_completed(&self, path: &str, kind: mirror_core::engine::ActionKind) {
        // A bare println! here would interleave with whichever bars are still
        // actively redrawing for other in-flight files, corrupting the display —
        // MultiProgress::println is the version that prints cleanly above them.
        let _ = self.multi.println(format!("completed {kind} for {path}"));
    }

    fn start_file(&self, path: &str, total_bytes: u64) -> Box<dyn FileTracker> {
        let bar = self.multi.add(ProgressBar::new(total_bytes));
        bar.set_message(path.to_string());
        Box::new(VisualFileTracker { bar })
    }
}

// pub struct JsonReporter;

// pub struct JsonFileTracker {
//     path: String,
//     total_bytes: u64,
// }

// impl FileTracker for JsonFileTracker {
//     fn add_bytes(&mut self, bytes: u64) {
//         println!("{}: +{} bytes (of {})", self.path, bytes, self.total_bytes);
//     }
// }

// impl ProgressReporter for JsonReporter {
//     fn action_completed(&self, path: &str, kind: mirror_core::engine::ActionKind) {
//         println!("completed {} for {}", kind, path);
//     }

//     fn start_file(&self, path: &str, total_bytes: u64) -> Box<dyn FileTracker> {
//         Box::new(JsonFileTracker {
//             path: path.to_string(),
//             total_bytes,
//         })
//     }
// }
