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
    type FileTracker = VisualFileTracker;

    fn action_completed(&self, path: &str, kind: mirror_core::engine::ActionKind) {
        println!("completed {} for {}", kind, path);
    }

    fn start_file(&self, path: &str, total_bytes: u64) -> Self::FileTracker {
        let bar = self.multi.add(ProgressBar::new(total_bytes));
        bar.set_message(path.to_string());
        VisualFileTracker { bar }
    }
}
