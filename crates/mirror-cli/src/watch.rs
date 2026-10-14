//! `rfm watch`: the daemon loop, the sync and backup workers it drives, and the
//! control socket protocol (`status`, `stop`, `sync`, `backup`, `subscribe`,
//! evict/hydrate).
//!
//! Sync passes run on a dedicated worker task that owns `State`, so the loop
//! itself never blocks on a sync: signals, the control socket and the TUI all
//! stay responsive while one is in flight. Backups run on their own worker, beside
//! syncs: they only read the root, and write under a separate bucket prefix.

use std::{
    fs::OpenOptions,
    io::IsTerminal,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use mirror_core::{
    config::Config, control, crypto::key::DerivedSubKeys, indicator::ProgressReporter,
    state::State, store::s3::S3Store,
};
use notify::EventKind;
use notify_debouncer_full::{DebounceEventResult, new_debouncer};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    signal::unix::{SignalKind, signal},
    sync::{Notify, broadcast, mpsc, oneshot},
    task::JoinHandle,
};

use crate::{
    backup,
    daemon::DaemonStatus,
    derive_enc_keys,
    events::{BackupSummary, Hub, HubReporter, LogLevel, Trigger, UiEvent},
    ops::{ResidencyRequest, residency_pass, residency_summary, run_sync},
    tui::{self, UiAction},
};

/// An evict/hydrate request from the control socket, and where to send its summary.
type ResidencyJob = (ResidencyRequest, oneshot::Sender<String>);

/// How often `rfm watch` checks whether a scheduled backup is due. The schedule
/// itself comes from the latest snapshot's time, so this only bounds how late a due
/// backup can start.
const BACKUP_CHECK_EVERY: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackupTrigger {
    /// Runs only if one is due.
    Scheduled,
    Manual,
}

pub(crate) use mirror_core::control::socket_path;

/// Sends one control command to a running daemon and returns its full reply.
pub(crate) async fn control_request(config: &Config, command: &str) -> Result<String> {
    Ok(control::request(&socket_path(config), command).await?)
}

/// Unlinks the control socket file when the daemon exits by any path.
struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub(crate) async fn watch(path: &Path, hub: Hub, tui: bool) -> Result<()> {
    if tui && !std::io::stdout().is_terminal() {
        anyhow::bail!("--tui needs an interactive terminal");
    }

    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    std::fs::create_dir_all(config.local.root.join(".mirror"))?;

    // held for the daemon's lifetime; drop releases the lock
    let lock_file = OpenOptions::new()
        .write(true) // Allow writing to the file
        .create(true) // Create the file if it doesn't exist!
        .truncate(false)
        .open(config.local.root.join(".mirror/daemon.lock"))?;

    let lock = fs2::FileExt::try_lock_exclusive(&lock_file);

    if lock.is_err() {
        anyhow::bail!(
            "failed to lock, another daemon may be running on root {}",
            config.local.root.display()
        );
    }

    let sock_path = socket_path(&config);

    // A leftover socket from a crashed daemon would make bind() fail with
    // "Address already in use" - safe to remove because the lock proves this is the only daemon
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path)?;
    std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;

    // Unlinks the socket on any exit path (return, `break`, or panic unwind).
    let _sock_guard = SocketGuard(sock_path);

    let store = S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    // Before the TUI takes over the terminal: this may prompt for the passphrase.
    let enc_keys = derive_enc_keys(&config, &store).await?;
    let state = State::open(&config.local.root)?;

    let config = Arc::new(config);
    let store = Arc::new(store);
    let enc_keys = Arc::new(enc_keys);
    let status = Arc::new(Mutex::new(DaemonStatus::new(&config)));
    let shutdown = Arc::new(Notify::new());

    // Capacity 1: while a sync runs, at most one more is queued and further
    // triggers coalesce into it.
    let (sync_tx, sync_rx) = mpsc::channel::<Trigger>(1);
    let (residency_tx, residency_rx) = mpsc::channel::<ResidencyJob>(8);
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    // Capacity 1 again: a backup asked for while one runs is queued, not stacked.
    let (backup_tx, backup_rx) = mpsc::channel::<BackupTrigger>(1);
    let backup_cancel = Arc::new(AtomicBool::new(false));
    let backup_shutdown = Arc::new(Notify::new());

    let backup_worker = tokio::spawn(
        BackupWorker {
            store: Arc::clone(&store),
            enc_keys: Arc::clone(&enc_keys),
            config: Arc::clone(&config),
            hub: hub.clone(),
            status: Arc::clone(&status),
            cancel: Arc::clone(&backup_cancel),
            shutdown: Arc::clone(&backup_shutdown),
        }
        .run(backup_rx),
    );
    // The first tick fires straight away, so a backup overdue at startup begins
    // promptly.
    let mut backup_check = (config.backup.interval_hours > 0).then(|| {
        let mut check = tokio::time::interval(BACKUP_CHECK_EVERY);
        check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        check
    });

    let worker = tokio::spawn(
        Worker {
            reporter: HubReporter::new(hub.clone()),
            store: Arc::clone(&store),
            enc_keys: Arc::clone(&enc_keys),
            config: Arc::clone(&config),
            state,
            hub: hub.clone(),
            status: Arc::clone(&status),
            shutdown: Arc::clone(&shutdown),
        }
        .run(sync_rx, residency_rx),
    );

    let mut interval = tokio::time::interval(Duration::from_secs(config.sync.poll_interval_secs));
    // After a suspend the interval would otherwise fire a burst of missed ticks at
    // once; Skip collapses them into a single catch-up tick.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_tick = SystemTime::now();
    let mut sigint = signal(SignalKind::interrupt())?; // Ctrl-C
    let mut sigterm = signal(SignalKind::terminate())?; // `kill`, launchd/systemd stop

    let contains_subpath = |subpath: &str, paths: Vec<PathBuf>| -> bool {
        paths
            .iter()
            .any(|p| p.components().any(|c| c.as_os_str() == subpath))
    };

    let fs_tx = sync_tx.clone();
    let watcher_hub = hub.clone();
    let mut debouncer = new_debouncer(
        Duration::from_secs(config.sync.debounce_secs),
        None,
        move |res: DebounceEventResult| match res {
            Ok(events) => {
                for event in events {
                    if matches!(
                        event.event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) && !contains_subpath(".mirror", event.event.paths)
                    {
                        let _ = fs_tx.try_send(Trigger::FsChange);
                    }
                }
            }
            Err(errors) => {
                for error in errors {
                    watcher_hub.log(LogLevel::Error, format!("Watcher error: {error:?}"));
                }
            }
        },
    )?;

    // RecursiveMode::Recursive means it also watches all folders inside this one.
    debouncer.watch(
        Path::new(&config.local.root),
        notify::RecursiveMode::Recursive,
    )?;

    let ctl = ControlCtx {
        status: Arc::clone(&status),
        hub: hub.clone(),
        sync_tx: sync_tx.clone(),
        backup_tx: backup_tx.clone(),
        residency_tx,
        stop_tx,
    };

    let mut ui = tui.then(|| {
        let (stop, stopped) = oneshot::channel::<()>();
        let events = forward_events(hub.subscribe(), UiEvent::Hello(ctl.snapshot()));
        let sync_tx = sync_tx.clone();
        let handle = tokio::spawn(tui::run(
            events,
            move |action| match action {
                UiAction::SyncNow => {
                    let _ = sync_tx.try_send(Trigger::Manual);
                }
            },
            async move {
                let _ = stopped.await;
            },
        ));
        (handle, stop)
    });

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // A wall-clock gap far larger than the poll interval means the host
                // was suspended; the sync below is a full reconcile regardless, so
                // this only surfaces it in the log.
                if let Ok(elapsed) = last_tick.elapsed()
                    && elapsed > Duration::from_secs(config.sync.poll_interval_secs * 5)
                {
                    hub.log(
                        LogLevel::Warn,
                        format!(
                            "resumed after ~{}s suspend; running a full reconcile",
                            elapsed.as_secs()
                        ),
                    );
                }
                last_tick = SystemTime::now();
                hub.send(UiEvent::Polled);
                let _ = sync_tx.try_send(Trigger::Poll);
            }
            _ = tick(&mut backup_check) => {
                let _ = backup_tx.try_send(BackupTrigger::Scheduled);
            }
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = stop_rx.recv() => break,
            ended = join_ui(&mut ui) => {
                ui = None;
                match ended {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => eprintln!("tui error: {e:#}"),
                    Err(e) => eprintln!("tui crashed: {e}"),
                }
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        tokio::spawn(handle_control(stream, ctl.clone()));
                    }
                    Err(e) => hub.log(LogLevel::Error, format!("control accept error: {e}")),
                }
            }
        }
    }

    // Restore the terminal before printing anything else.
    if let Some((handle, stop)) = ui.take() {
        let _ = stop.send(());
        let _ = handle.await;
    }

    // Stop new work; a sync already in flight is allowed to finish. A backup is
    // cancelled instead: it writes no snapshot, and the next one picks up the data
    // this one already uploaded.
    drop(debouncer);
    shutdown.notify_one();
    backup_cancel.store(true, Ordering::Relaxed);
    backup_shutdown.notify_one();
    drop(backup_tx);
    drop(ctl);
    if status.lock().unwrap().is_syncing() {
        eprintln!("waiting for the current sync to finish (Ctrl-C again to abort)");
    }

    tokio::select! {
        _ = async { let _ = tokio::join!(worker, backup_worker); } => {}
        _ = sigint.recv() => eprintln!("aborted; the next sync resumes where this one stopped"),
        _ = sigterm.recv() => {}
    }

    Ok(())
}

/// Ticks `check` if there is one; otherwise never resolves.
async fn tick(check: &mut Option<tokio::time::Interval>) {
    match check {
        Some(check) => {
            check.tick().await;
        }
        None => std::future::pending().await,
    }
}

async fn join_ui(
    ui: &mut Option<(JoinHandle<Result<()>>, oneshot::Sender<()>)>,
) -> Result<Result<()>, tokio::task::JoinError> {
    match ui {
        Some((handle, _)) => handle.await,
        None => std::future::pending().await,
    }
}

/// Bridges a hub subscription into the TUI's input, `hello` first. A subscriber
/// that falls too far behind skips ahead rather than stalling the daemon.
fn forward_events(
    mut rx: broadcast::Receiver<UiEvent>,
    hello: UiEvent,
) -> mpsc::UnboundedReceiver<UiEvent> {
    let (tx, out) = mpsc::unbounded_channel();
    let _ = tx.send(hello);

    tokio::spawn(async move {
        loop {
            let event = match rx.recv().await {
                Ok(event) => event,
                Err(broadcast::error::RecvError::Lagged(n)) => lagged(n),
                Err(broadcast::error::RecvError::Closed) => break,
            };
            if tx.send(event).is_err() {
                break; // the TUI is gone
            }
        }
    });

    out
}

fn lagged(n: u64) -> UiEvent {
    UiEvent::Log {
        level: LogLevel::Warn,
        msg: format!("display fell behind; skipped {n} events"),
    }
}

/// Owns everything a sync pass mutates, and runs passes one at a time.
struct Worker {
    store: Arc<S3Store>,
    config: Arc<Config>,
    enc_keys: Arc<DerivedSubKeys>,
    state: State,
    reporter: Arc<HubReporter>,
    hub: Hub,
    status: Arc<Mutex<DaemonStatus>>,
    shutdown: Arc<Notify>,
}

impl Worker {
    async fn run(
        mut self,
        mut syncs: mpsc::Receiver<Trigger>,
        mut residency: mpsc::Receiver<ResidencyJob>,
    ) {
        loop {
            tokio::select! {
                // Shutdown wins over queued work; a permit stored mid-sync is seen
                // as soon as that sync returns.
                biased;
                _ = self.shutdown.notified() => break,
                Some((request, reply)) = residency.recv() => {
                    let result = self.pass(Trigger::Residency, Some(&request)).await;
                    let text = match &result {
                        Ok(outcome) => residency_summary(outcome, &request),
                        Err(e) => format!("error: {e:#}\n"),
                    };
                    let _ = reply.send(text);
                }
                Some(trigger) = syncs.recv() => {
                    let _ = self.pass(trigger, None).await;
                }
                else => break,
            }
        }
    }

    async fn pass(
        &mut self,
        trigger: Trigger,
        request: Option<&ResidencyRequest>,
    ) -> Result<mirror_core::sync::SyncOutcome> {
        self.status.lock().unwrap().started(trigger);
        self.hub.send(UiEvent::SyncStarted { trigger });

        let reporter: Arc<dyn ProgressReporter> = self.reporter.clone();
        let result = match request {
            None => {
                run_sync(
                    &self.store,
                    &self.config,
                    &self.enc_keys,
                    &mut self.state,
                    &reporter,
                )
                .await
            }
            Some(request) => {
                residency_pass(
                    &self.store,
                    &self.config,
                    &self.enc_keys,
                    &mut self.state,
                    &reporter,
                    request,
                )
                .await
            }
        };

        let last = self.status.lock().unwrap().record(&result);
        self.hub.sync_finished(last);
        result
    }
}

/// Takes backups for the daemon, one at a time, beside the sync worker.
struct BackupWorker {
    store: Arc<S3Store>,
    enc_keys: Arc<DerivedSubKeys>,
    config: Arc<Config>,
    hub: Hub,
    status: Arc<Mutex<DaemonStatus>>,
    cancel: Arc<AtomicBool>,
    /// Ends the worker. Waiting for the trigger queue to close isn't enough:
    /// control connections hold senders for as long as they live.
    shutdown: Arc<Notify>,
}

impl BackupWorker {
    async fn run(self, mut triggers: mpsc::Receiver<BackupTrigger>) {
        loop {
            let trigger = tokio::select! {
                // A permit stored mid-backup is seen as soon as it returns.
                biased;
                _ = self.shutdown.notified() => break,
                trigger = triggers.recv() => match trigger {
                    Some(trigger) => trigger,
                    None => break,
                },
            };
            if let Err(e) = self.maybe_backup(trigger).await {
                self.hub
                    .log(LogLevel::Error, format!("backup check failed: {e:#}"));
            }
        }
    }

    /// Errors here are about deciding whether to run; a run's own failure is
    /// recorded as its result instead.
    async fn maybe_backup(&self, trigger: BackupTrigger) -> Result<()> {
        let config = &self.config;
        let repo =
            backup::open_repo(config, Arc::clone(&self.store), &self.enc_keys, false, true).await?;
        if trigger == BackupTrigger::Scheduled {
            let interval = Duration::from_secs(config.backup.interval_hours * 3600);
            if !backup::is_due(config, &repo, interval).await? {
                return Ok(());
            }
        }

        self.status.lock().unwrap().backup_started();
        self.hub.send(UiEvent::BackupStarted);
        let (info, warn) = (self.hub.clone(), self.hub.clone());
        let hooks = backup::Hooks {
            info: Arc::new(move |msg| info.log(LogLevel::Info, msg)),
            warn: Arc::new(move |msg| warn.log(LogLevel::Warn, msg)),
            progress: None,
            // The stages, so the daemon's log shows what a backup is doing.
            activity: Some({
                let hub = self.hub.clone();
                Arc::new(move |activity: backup_core::archiver::Activity<'_>| {
                    if let backup_core::archiver::Activity::Stage(stage) = activity {
                        hub.log(LogLevel::Info, format!("backup: {stage}"));
                    }
                })
            }),
            cancel: Arc::clone(&self.cancel),
        };

        let mirror = backup::Mirror {
            store: Arc::clone(&self.store),
            enc_keys: Arc::clone(&self.enc_keys),
        };
        let result = backup::create_snapshot(
            config,
            Arc::clone(&repo),
            &mirror,
            backup::Request::from_config(config),
            hooks,
        )
        .await
        .map(|snapshot| {
            let s = &snapshot.stats;
            BackupSummary {
                snapshot: snapshot.id.short(),
                files: s.files_new + s.files_changed + s.files_unmodified,
                bytes_added: s.bytes_added,
                pruned: None,
            }
        });
        let result = match result {
            Ok(mut summary) => {
                if config.backup.auto_prune {
                    match backup::prune_by_policy(&repo, &config.backup.keep, false).await {
                        Ok((_, report)) => summary.pruned = Some(report.snapshots_forgotten),
                        // The backup itself succeeded; a failed prune is retried next time.
                        Err(e) => self
                            .hub
                            .log(LogLevel::Warn, format!("prune after backup failed: {e:#}")),
                    }
                }
                Ok(summary)
            }
            Err(e) => Err(format!("{e:#}")),
        };

        let last = self.status.lock().unwrap().record_backup(result);
        self.hub.backup_finished(last);
        Ok(())
    }
}

/// What a control connection can see and do; cloned into each connection's task.
#[derive(Clone)]
struct ControlCtx {
    status: Arc<Mutex<DaemonStatus>>,
    hub: Hub,
    sync_tx: mpsc::Sender<Trigger>,
    backup_tx: mpsc::Sender<BackupTrigger>,
    residency_tx: mpsc::Sender<ResidencyJob>,
    stop_tx: mpsc::Sender<()>,
}

impl ControlCtx {
    fn snapshot(&self) -> crate::events::Snapshot {
        self.status.lock().unwrap().snapshot()
    }
}

async fn handle_control(stream: UnixStream, ctl: ControlCtx) {
    // Caps how many bytes a client can make us buffer.
    const MAX_REQUEST: u64 = 64 * 1024;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    // The timeout stops a client that connects and never sends a newline from
    // holding the connection open forever.
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        (&mut reader).take(MAX_REQUEST).read_line(&mut line),
    )
    .await;

    if !matches!(read, Ok(Ok(_))) {
        return; // timed out or errored, drop this client
    }

    let mut stream = reader.into_inner();
    let line = line.trim_end_matches(['\n', '\r']);

    let reply = match line {
        "stop" => {
            let _ = ctl.stop_tx.try_send(());
            "stopping\n".to_string()
        }
        "status" => ctl.status.lock().unwrap().render(),
        "sync" => match ctl.sync_tx.try_send(Trigger::Manual) {
            Ok(()) => "sync queued\n".to_string(),
            Err(mpsc::error::TrySendError::Full(_)) => "a sync is already queued\n".to_string(),
            Err(mpsc::error::TrySendError::Closed(_)) => "daemon is stopping\n".to_string(),
        },
        "backup" => match ctl.backup_tx.try_send(BackupTrigger::Manual) {
            Ok(()) => "backup queued\n".to_string(),
            Err(mpsc::error::TrySendError::Full(_)) => "a backup is already queued\n".to_string(),
            Err(mpsc::error::TrySendError::Closed(_)) => "daemon is stopping\n".to_string(),
        },
        "subscribe" => return subscribe(stream, ctl).await,
        _ => match ResidencyRequest::from_line(line) {
            Some(request) => {
                let (reply_tx, reply_rx) = oneshot::channel();
                if ctl.residency_tx.send((request, reply_tx)).await.is_err() {
                    "daemon is stopping\n".to_string()
                } else {
                    reply_rx
                        .await
                        .unwrap_or_else(|_| "daemon is stopping\n".to_string())
                }
            }
            None => "unknown command\n".to_string(),
        },
    };

    let _ = stream.write_all(reply.as_bytes()).await;
}

/// Streams events to an `rfm tui` client as JSON lines until it disconnects.
async fn subscribe(stream: UnixStream, ctl: ControlCtx) {
    // Subscribe before taking the snapshot, so nothing between the two is lost.
    let mut rx = ctl.hub.subscribe();
    let hello = UiEvent::Hello(ctl.snapshot());
    let (mut client, mut stream) = stream.into_split();

    if write_event(&mut stream, &hello).await.is_err() {
        return;
    }

    let mut scratch = [0u8; 64];
    loop {
        let event = tokio::select! {
            // A client that hangs up is noticed now, not at the next event, which
            // on a quiet daemon might never come.
            read = client.read(&mut scratch) => match read {
                Ok(0) | Err(_) => return,
                Ok(_) => continue,
            },
            event = rx.recv() => match event {
                Ok(event) => event,
                Err(broadcast::error::RecvError::Lagged(n)) => lagged(n),
                Err(broadcast::error::RecvError::Closed) => return,
            },
        };
        if write_event(&mut stream, &event).await.is_err() {
            return; // client went away
        }
    }
}

async fn write_event(
    stream: &mut tokio::net::unix::OwnedWriteHalf,
    event: &UiEvent,
) -> std::io::Result<()> {
    let mut line = serde_json::to_string(event).map_err(std::io::Error::other)?;
    line.push('\n');
    stream.write_all(line.as_bytes()).await
}

/// `rfm tui`: a dashboard attached to a running daemon over its control socket.
pub(crate) async fn attach(path: &Path) -> Result<()> {
    if !std::io::stdout().is_terminal() {
        anyhow::bail!("rfm tui needs an interactive terminal");
    }

    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;
    // Subscribing before taking over the terminal means an older daemon, or none,
    // fails with a readable message.
    let (hello, mut subscription) = control::subscribe(&socket_path(&config)).await?;

    let (tx, events) = mpsc::unbounded_channel();
    let _ = tx.send(UiEvent::Hello(hello));

    tokio::spawn(async move {
        while let Ok(Some(event)) = subscription.next().await {
            if tx.send(event).is_err() {
                break;
            }
        }
        // Dropping `tx` tells the TUI the daemon disconnected.
    });

    let config = Arc::new(config);
    tui::run(
        events,
        move |action| match action {
            UiAction::SyncNow => {
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let _ = control_request(&config, "sync").await;
                });
            }
        },
        std::future::pending(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &Path) -> Config {
        let path = root.join("config.toml");
        let text = format!(
            "[remote]\nbucket = \"b\"\n[local]\nroot = {:?}\n",
            root.to_str().unwrap()
        );
        std::fs::write(&path, text).unwrap();
        Config::load(&path).unwrap()
    }

    /// Regression: a subscriber that hung up used to leave its connection task
    /// waiting for the next event, holding the backup queue's sender, which kept
    /// `rfm watch` from finishing a stop on a quiet daemon.
    #[tokio::test]
    async fn a_departed_subscriber_releases_its_connection() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let (sync_tx, _sync_rx) = mpsc::channel(1);
        let (backup_tx, backup_rx) = mpsc::channel(1);
        let (residency_tx, _residency_rx) = mpsc::channel(1);
        let (stop_tx, _stop_rx) = mpsc::channel(1);
        let ctl = ControlCtx {
            status: Arc::new(Mutex::new(DaemonStatus::new(&config))),
            hub: Hub::new(false),
            sync_tx,
            backup_tx,
            residency_tx,
            stop_tx,
        };

        let (server, client) = UnixStream::pair().unwrap();
        let connection = tokio::spawn(handle_control(server, ctl.clone()));
        drop(ctl);

        let (read, mut write) = client.into_split();
        write.write_all(b"subscribe\n").await.unwrap();
        let mut lines = BufReader::new(read).lines();
        let hello = lines.next_line().await.unwrap().unwrap();
        assert!(hello.contains("\"hello\""));
        drop((lines, write));

        tokio::time::timeout(Duration::from_secs(5), connection)
            .await
            .expect("the connection task ends once its client hangs up")
            .unwrap();
        assert!(
            backup_rx.is_closed(),
            "no sender left to keep the backup worker alive"
        );
    }
}
