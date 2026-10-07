//! `rfm watch`: the daemon loop, the sync worker it drives, and the control
//! socket protocol (`status`, `stop`, `sync`, `subscribe`, evict/hydrate).
//!
//! Sync passes run on a dedicated worker task that owns `State`, so the loop
//! itself never blocks on a sync: signals, the control socket and the TUI all
//! stay responsive while one is in flight.

use std::{
    fs::OpenOptions,
    io::IsTerminal,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use mirror_core::{
    config::Config, crypto::key::DerivedSubKeys, indicator::ProgressReporter, state::State,
    store::s3::S3Store,
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
    daemon::DaemonStatus,
    derive_enc_keys,
    events::{Hub, HubReporter, LogLevel, Trigger, UiEvent},
    ops::{ResidencyRequest, residency_pass, residency_summary, run_sync},
    tui::{self, UiAction},
};

/// An evict/hydrate request from the control socket, and where to send its summary.
type ResidencyJob = (ResidencyRequest, oneshot::Sender<String>);

pub(crate) fn socket_path(config: &Config) -> PathBuf {
    config.local.root.join(".mirror/daemon.sock")
}

/// Sends one control command to a running daemon and returns its full reply.
pub(crate) async fn control_request(config: &Config, command: &str) -> Result<String> {
    let mut stream = UnixStream::connect(socket_path(config))
        .await
        .context("no daemon running (couldn't connect to control socket)")?;
    stream.write_all(format!("{command}\n").as_bytes()).await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
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
    let status = Arc::new(Mutex::new(DaemonStatus::new(&config)));
    let shutdown = Arc::new(Notify::new());

    // Capacity 1: while a sync runs, at most one more is queued and further
    // triggers coalesce into it.
    let (sync_tx, sync_rx) = mpsc::channel::<Trigger>(1);
    let (residency_tx, residency_rx) = mpsc::channel::<ResidencyJob>(8);
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);

    let worker = tokio::spawn(
        Worker {
            reporter: HubReporter::new(hub.clone()),
            store: Arc::new(store),
            enc_keys: Arc::new(enc_keys),
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

    // Stop new work; a sync already in flight is allowed to finish.
    drop(debouncer);
    shutdown.notify_one();
    if status.lock().unwrap().is_syncing() {
        eprintln!("waiting for the current sync to finish (Ctrl-C again to abort)");
    }

    tokio::select! {
        _ = worker => {}
        _ = sigint.recv() => eprintln!("aborted; the next sync resumes where this one stopped"),
        _ = sigterm.recv() => {}
    }

    Ok(())
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

/// What a control connection can see and do; cloned into each connection's task.
#[derive(Clone)]
struct ControlCtx {
    status: Arc<Mutex<DaemonStatus>>,
    hub: Hub,
    sync_tx: mpsc::Sender<Trigger>,
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
async fn subscribe(mut stream: UnixStream, ctl: ControlCtx) {
    // Subscribe before taking the snapshot, so nothing between the two is lost.
    let mut rx = ctl.hub.subscribe();
    let hello = UiEvent::Hello(ctl.snapshot());

    if write_event(&mut stream, &hello).await.is_err() {
        return;
    }

    loop {
        let event = match rx.recv().await {
            Ok(event) => event,
            Err(broadcast::error::RecvError::Lagged(n)) => lagged(n),
            Err(broadcast::error::RecvError::Closed) => return,
        };
        if write_event(&mut stream, &event).await.is_err() {
            return; // client went away
        }
    }
}

async fn write_event(stream: &mut UnixStream, event: &UiEvent) -> std::io::Result<()> {
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
    let stream = UnixStream::connect(socket_path(&config)).await.context(
        "no daemon running (couldn't connect to control socket); start one with `rfm watch`",
    )?;

    let (read, mut write) = stream.into_split();
    write.write_all(b"subscribe\n").await?;
    let mut lines = BufReader::new(read).lines();

    // Check the handshake before taking over the terminal, so an older daemon
    // fails with a readable message.
    let first = lines.next_line().await?.unwrap_or_default();
    let hello: UiEvent = serde_json::from_str(&first).map_err(|_| {
        anyhow::anyhow!(
            "the running daemon doesn't support `rfm tui` (it replied {:?}); restart it with this version of rfm",
            first.trim()
        )
    })?;

    let (tx, events) = mpsc::unbounded_channel();
    let _ = tx.send(hello);

    tokio::spawn(async move {
        // Keeps the write half open: dropping it would half-close the socket.
        let _write = write;
        while let Ok(Some(line)) = lines.next_line().await {
            let event = serde_json::from_str(&line).unwrap_or_else(|e| UiEvent::Log {
                level: LogLevel::Warn,
                msg: format!("unreadable event from daemon: {e}"),
            });
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
