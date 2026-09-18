use crate::engine::ActionKind;

pub trait FileTracker: Send {
    fn add_bytes(&mut self, bytes: u64);
}

pub trait ProgressReporter: Send + Sync {
    fn start_file(&self, path: &str, total_bytes: u64) -> Box<dyn FileTracker>;
    fn action_completed(&self, path: &str, kind: ActionKind);
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

impl ProgressReporter for PrintReporter {
    fn action_completed(&self, path: &str, kind: ActionKind) {
        println!("completed {} for {}", kind, path);
    }

    fn start_file(&self, path: &str, total_bytes: u64) -> Box<dyn FileTracker> {
        Box::new(PrintTracker {
            path: path.to_string(),
            total_bytes,
            bytes_so_far: 0,
        })
    }
}
