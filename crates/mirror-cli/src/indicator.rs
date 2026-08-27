use indicatif::{MultiProgress, ProgressBar};
use mirror_core::indicator::{FileTracker, ProgressReporter};

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

impl ProgressReporter for VisualBarReporter {
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
