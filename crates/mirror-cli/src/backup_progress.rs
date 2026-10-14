//! What `rfm backup create` shows while it runs, so a long step never looks like a
//! hang.
//!
//! On a terminal, two live lines redraw several times a second: running totals
//! (files, data read, new data, packs uploaded, elapsed time), and what's happening
//! right now (the file being read and how far along it is, or the current stage).
//! Each stage also leaves a line behind, so there's a trail of what was done.
//! Elsewhere (a log, a pipe), stages are printed as they happen and the totals
//! every `PLAIN_EVERY`. `--verbose` adds a line per file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use backup_core::archiver::{Activity, ActivityFn, FileOutcome, Progress, ProgressFn};
use backup_core::repo::Repository;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use mirror_core::indicator::human_bytes;
use mirror_core::store::s3::S3Store;
use tokio::task::JoinHandle;

/// How often the live lines redraw.
const REDRAW_EVERY: Duration = Duration::from_millis(200);
/// How often totals are printed when not on a terminal.
const PLAIN_EVERY: Duration = Duration::from_secs(15);

/// Everything the lines are drawn from.
#[derive(Default)]
struct State {
    stage: String,
    files: u64,
    bytes_read: u64,
    bytes_new: u64,
    /// Files being read now: bytes done of their size.
    reading: BTreeMap<PathBuf, (u64, u64)>,
}

pub(crate) struct Display {
    state: Arc<Mutex<State>>,
    lines: Option<(MultiProgress, ProgressBar, ProgressBar)>,
    root: PathBuf,
    verbose: bool,
    started: Instant,
    ticker: Option<JoinHandle<()>>,
}

impl Display {
    pub(crate) fn new(root: PathBuf, verbose: bool) -> Self {
        Self {
            state: Arc::default(),
            lines: None,
            root,
            verbose,
            started: Instant::now(),
            ticker: None,
        }
    }

    /// A step before the live lines start (connecting, unlocking the vault), as a
    /// plain line: a passphrase prompt may follow, and must not fight a spinner.
    pub(crate) fn early(&self, message: &str) {
        eprintln!("· {message}");
    }

    /// Starts the live lines (or the periodic plain ones) once the repository is
    /// open, since the upload counter comes from it.
    pub(crate) fn start(&mut self, repo: Arc<Repository<S3Store>>) {
        let state = Arc::clone(&self.state);
        let started = self.started;
        // Go by whether indicatif will actually draw (a terminal, and a `TERM` it
        // understands): when it won't, it also drops lines printed through it, so
        // anything else falls back to plain lines.
        let target = ProgressDrawTarget::stderr();
        if !target.is_hidden() {
            let multi = MultiProgress::with_draw_target(target);
            let style = ProgressStyle::with_template("{spinner} {msg}").expect("valid template");
            let main = multi.add(ProgressBar::new_spinner().with_style(style));
            let detail = multi.add(
                ProgressBar::new_spinner()
                    .with_style(ProgressStyle::with_template("  {msg}").expect("valid template")),
            );
            let (m, d, root) = (main.clone(), detail.clone(), self.root.clone());
            self.ticker = Some(tokio::spawn(async move {
                loop {
                    {
                        let state = state.lock().expect("display lock poisoned");
                        m.set_message(totals_line(&state, repo.uploaded(), started.elapsed()));
                        d.set_message(now_line(&state, &root));
                    }
                    m.tick();
                    tokio::time::sleep(REDRAW_EVERY).await;
                }
            }));
            self.lines = Some((multi, main, detail));
        } else {
            self.ticker = Some(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(PLAIN_EVERY).await;
                    let line = totals_line(
                        &state.lock().expect("display lock poisoned"),
                        repo.uploaded(),
                        started.elapsed(),
                    );
                    eprintln!("· {line}");
                }
            }));
        }
    }

    /// For `Hooks::info` and `Hooks::warn`.
    pub(crate) fn printer(&self) -> Arc<dyn Fn(String) + Send + Sync> {
        let multi = self.lines.as_ref().map(|(multi, _, _)| multi.clone());
        Arc::new(move |message: String| match &multi {
            Some(multi) => {
                let _ = multi.println(&message);
            }
            None => eprintln!("{message}"),
        })
    }

    pub(crate) fn progress(&self) -> ProgressFn {
        let state = Arc::clone(&self.state);
        let multi = self.lines.as_ref().map(|(multi, _, _)| multi.clone());
        let (verbose, root) = (self.verbose, self.root.clone());
        Arc::new(move |p: &Progress| {
            {
                let mut state = state.lock().expect("display lock poisoned");
                state.files = p.files_processed;
                state.bytes_read = p.bytes_processed;
                state.bytes_new = p.bytes_added;
            }
            if verbose {
                let line = file_line(p, &root);
                match &multi {
                    Some(multi) => {
                        let _ = multi.println(&line);
                    }
                    None => eprintln!("{line}"),
                }
            }
        })
    }

    pub(crate) fn activity(&self) -> ActivityFn {
        let state = Arc::clone(&self.state);
        let multi = self.lines.as_ref().map(|(multi, _, _)| multi.clone());
        Arc::new(move |activity: Activity<'_>| {
            let mut state = state.lock().expect("display lock poisoned");
            match activity {
                Activity::Stage(stage) => {
                    state.stage = stage.to_string();
                    let line = format!("· {stage}");
                    drop(state);
                    match &multi {
                        Some(multi) => {
                            let _ = multi.println(&line);
                        }
                        None => eprintln!("{line}"),
                    }
                }
                Activity::Reading { path, done, size } => {
                    state.reading.insert(path.to_path_buf(), (done, size));
                }
                Activity::ReadDone { path } => {
                    state.reading.remove(path);
                }
            }
        })
    }

    /// Clears the live lines and returns the elapsed time, for the summary.
    pub(crate) fn finish(mut self) -> Duration {
        if let Some(ticker) = self.ticker.take() {
            ticker.abort();
        }
        if let Some((_, main, detail)) = self.lines.take() {
            main.finish_and_clear();
            detail.finish_and_clear();
        }
        self.started.elapsed()
    }
}

/// "1,234 files · 12.3 GiB read · 2.1 GiB new · 38 packs uploaded (612.0 MiB) · 4m 12s"
///
/// "Read" includes files still being read, so it keeps moving through a large
/// file; "new" is only known once a file is done.
fn totals_line(state: &State, (packs, uploaded): (u64, u64), elapsed: Duration) -> String {
    let in_flight: u64 = state.reading.values().map(|(done, _)| done).sum();
    format!(
        "{} · {} read · {} new · {} uploaded ({}) · {}",
        plural(state.files, "file"),
        human_bytes(state.bytes_read + in_flight),
        human_bytes(state.bytes_new),
        plural(packs, "pack"),
        human_bytes(uploaded),
        duration(elapsed)
    )
}

/// "1 pack", "38 packs", "1,234 files".
fn plural(n: u64, noun: &str) -> String {
    let s = if n == 1 { "" } else { "s" };
    format!("{} {noun}{s}", thousands(n))
}

/// What's happening right now: the biggest file still being read, or the stage.
fn now_line(state: &State, root: &Path) -> String {
    let Some((path, (done, size))) = state
        .reading
        .iter()
        .max_by_key(|(_, (done, size))| size.saturating_sub(*done))
    else {
        return state.stage.clone();
    };
    let percent = match size {
        0 => 100,
        size => done * 100 / size,
    };
    let more = match state.reading.len() {
        1 => String::new(),
        n => format!(" (+{} more)", n - 1),
    };
    format!(
        "reading {}  {} of {} ({percent}%){more}",
        relative(path, root),
        human_bytes(*done),
        human_bytes(*size)
    )
}

/// One `--verbose` line: what happened to a file.
fn file_line(p: &Progress, root: &Path) -> String {
    let what = match p.outcome {
        FileOutcome::New => "new",
        FileOutcome::Changed => "changed",
        FileOutcome::Unchanged => "unchanged",
        FileOutcome::Resumed => "resumed",
        FileOutcome::OffloadedReused => "offloaded",
        FileOutcome::OffloadedDownloaded => "downloaded",
    };
    format!(
        "  {what:<10} {}  {}",
        relative(&p.path, root),
        human_bytes(p.size)
    )
}

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// "45s", "4m 12s", "1h 3m".
pub(crate) fn duration(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m {}s", secs / 60, secs % 60),
        _ => format!("{}h {}m", secs / 3600, secs % 3600 / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        State {
            stage: "scanning files".into(),
            files: 1234,
            bytes_read: 12 * 1024 * 1024 * 1024,
            bytes_new: 2048,
            reading: BTreeMap::new(),
        }
    }

    #[test]
    fn totals_read_well() {
        let line = totals_line(&state(), (38, 612 * 1024 * 1024), Duration::from_secs(252));
        assert_eq!(
            line,
            "1,234 files · 12.0 GiB read · 2.0 KiB new · 38 packs uploaded (612.0 MiB) · 4m 12s"
        );
    }

    #[test]
    fn totals_count_partial_reads_and_singulars() {
        let mut s = State {
            files: 1,
            ..State::default()
        };
        s.reading
            .insert(PathBuf::from("/r/big"), (3 * 1024 * 1024, 10 * 1024 * 1024));
        let line = totals_line(&s, (1, 1024), Duration::from_secs(5));
        assert_eq!(
            line,
            "1 file · 3.0 MiB read · 0 B new · 1 pack uploaded (1.0 KiB) · 5s"
        );
    }

    #[test]
    fn now_shows_the_biggest_remaining_read_or_the_stage() {
        let root = Path::new("/Users/me/Mirror");
        let mut s = state();
        assert_eq!(now_line(&s, root), "scanning files");

        s.reading.insert(root.join("small.txt"), (0, 10));
        s.reading
            .insert(root.join("videos/big.mov"), (1024 * 1024, 4 * 1024 * 1024));
        assert_eq!(
            now_line(&s, root),
            "reading videos/big.mov  1.0 MiB of 4.0 MiB (25%) (+1 more)"
        );

        s.reading.clear();
        s.reading.insert(PathBuf::from("/elsewhere/empty"), (0, 0));
        assert_eq!(
            now_line(&s, root),
            "reading /elsewhere/empty  0 B of 0 B (100%)"
        );
    }

    #[test]
    fn verbose_lines_name_the_outcome() {
        let p = Progress {
            path: PathBuf::from("/r/docs/a.pdf"),
            outcome: FileOutcome::Resumed,
            size: 2048,
            files_processed: 1,
            bytes_processed: 2048,
            bytes_added: 0,
        };
        assert_eq!(
            file_line(&p, Path::new("/r")),
            "  resumed    docs/a.pdf  2.0 KiB"
        );
    }

    #[test]
    fn numbers_and_durations() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(duration(Duration::from_secs(45)), "45s");
        assert_eq!(duration(Duration::from_secs(3 * 3600 + 120)), "3h 2m");
    }
}
