mod daemon;
mod indicator;

use anyhow::{Context, Result};
use argon2::Params;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use clap::{Parser, Subcommand};
use indicatif::MultiProgress;
use mirror_core::{
    Error,
    apply::remote_conflict::preserve_conflict_losers,
    config::Config,
    crypto::{
        key::{DerivedSubKeys, derive_application_keys},
        keyring,
        vault::{self, VaultHeader},
    },
    engine::{ActionKind, Plan, reconcile},
    indicator::{PrintReporter, ProgressReporter},
    manifest::{self, MergeResult, merge_deltas, read_deltas},
    scanner::{LocalEntry, Scanner},
    state::State,
    store::{
        ObjectStore,
        s3::{self, S3Store},
    },
    sync::SyncOutcome,
};
use notify::EventKind;
use notify_debouncer_full::{DebounceEventResult, new_debouncer};
use rand::Rng;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::{self, IsTerminal, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};

use crate::{daemon::DaemonStatus, indicator::VisualBarReporter};

#[derive(Parser)]
#[command(name = "rfm", version, about = "Encrypted S3 file mirror")]
struct Cli {
    #[arg(long, global = true, env = "RFM_CONFIG", default_value = "rfm.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check configuration and bucket connectivity, and report orphaned multipart uploads
    Doctor {
        /// Abort orphaned multipart uploads older than the grace period, instead of just listing them
        #[arg(long)]
        abort_orphans: bool,
    },

    /// List files that would be synced
    Scan,

    /// Show local changes since the last snapshot
    Status,

    /// Record the current scan as the baseline (temporary scaffolding)
    Snapshot,

    /// Sync an action plan
    Sync,

    /// Initialize a vault
    Init,

    /// Unlock a vault
    Unlock,

    /// Run compaction on deltas, and generate a new manifest snapshot
    Compact,

    /// Run as background daemon
    Watch,

    Daemon {
        #[command(subcommand)]
        cmd: DaemonCmd,
    },
}

#[derive(Subcommand)]
enum DaemonCmd {
    Status,
    Stop,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("RFM_LOG"))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Doctor { abort_orphans } => doctor(&cli.config, abort_orphans).await,
        Command::Scan => scan(&cli.config),
        Command::Status => status(&cli.config).await,
        Command::Snapshot => snapshot(&cli.config),
        Command::Sync => sync(&cli.config).await,
        Command::Init => init(&cli.config).await,
        Command::Unlock => unlock(&cli.config).await,
        Command::Compact => compact(&cli.config).await,
        Command::Watch => watch(&cli.config).await,
        Command::Daemon { cmd } => daemon(&cli.config, cmd).await,
    }
}

async fn daemon(path: &Path, cmd: DaemonCmd) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;
    let sock = config.local.root.join(".mirror/daemon.sock");

    let mut stream = UnixStream::connect(&sock)
        .await
        .context("no daemon running (couldn't connect to control socket")?;

    let msg = match cmd {
        DaemonCmd::Status => "status\n",
        DaemonCmd::Stop => "stop\n",
    };

    stream.write_all(msg.as_bytes()).await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    print!("{response}");
    Ok(())
}

/// Unlinks the control socket file when the daemon exits by any path.
struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn watch(path: &Path) -> Result<()> {
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

    let sock_path = config.local.root.join(".mirror/daemon.sock");

    // A leftover socket from a crashed daemon would make bind() fail with
    // "Address already in use" - safe to remove because the lock proves this is the only daemon
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path)?;
    std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;

    // Unlinks the socket on any exit path (return, `break`, or panic unwind).
    let _sock_guard = SocketGuard(sock_path);

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let enc_keys = load_enc_keys(&config)?;
    let mut state = State::open(&config.local.root)?;
    let reporter: Arc<dyn ProgressReporter> = Arc::new(PrintReporter {});

    // Wrapped once; each sync pass gets a cheap refcount-bumping clone rather than
    // moving the originals out of the loop.
    let store = Arc::new(store);
    let enc_keys = Arc::new(enc_keys);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
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

    // 2. Initialize the debouncer with a callback function
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
                        let _ = tx.try_send(()).ok();
                    }
                }
            }
            Err(errors) => {
                for error in errors {
                    println!("Watcher error: {:?}", error);
                }
            }
        },
    )?;

    // 3. Tell the watcher which folder or file to monitor
    // RecursiveMode::Recursive means it also watches all folders inside this one.
    debouncer.watch(
        Path::new(&config.local.root),
        notify::RecursiveMode::Recursive,
    )?;

    let mut status = DaemonStatus::default();

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // A wall-clock gap far larger than the poll interval means the host
                // was suspended; the sync below is a full reconcile regardless, so
                // this only surfaces it in the log.
                if let Ok(elapsed) = last_tick.elapsed()
                    && elapsed > Duration::from_secs(config.sync.poll_interval_secs * 5)
                {
                    eprintln!(
                        "resumed after ~{}s suspend; running a full reconcile",
                        elapsed.as_secs()
                    );
                }
                last_tick = SystemTime::now();

                let result = run_sync(&store, &config, &enc_keys, &mut state, &reporter).await;
                status.record(&result);
                report(result);
            }
            _ = rx.recv() => {
                // drain the channel to prevent a queue pile up
                while rx.try_recv().is_ok() {};

                report(run_sync(&store, &config, &enc_keys, &mut state, &reporter).await);
            }
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,

            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        if handle_control(stream, &status).await {
                            break; // `stop` was received
                        }
                    }
                    Err(e) => eprintln!("control accept error: {e}")
                }
            }
        }
    }

    Ok(())
}

async fn handle_control(stream: UnixStream, status: &DaemonStatus) -> bool {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    // `.take(256)` caps how many bytes a client can make us buffer; the timeout
    // stops a client that connects and never sends a newline from wedging the loop.
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        (&mut reader).take(256).read_line(&mut line),
    )
    .await;

    if !matches!(read, Ok(Ok(_))) {
        return false; // timed out or errored, drop this client
    }

    let mut stream = reader.into_inner();

    match line.trim() {
        "stop" => {
            let _ = stream.write_all(b"stopping\n").await;
            true
        }
        "status" => {
            let _ = stream.write_all(status.render().as_bytes()).await;
            false
        }
        _ => {
            let _ = stream.write_all(b"unknown command\n").await;
            false
        }
    }
}

fn report(result: Result<SyncOutcome>) {
    match result {
        Ok(outcome) => {
            if !outcome.is_noop() {
                println!(
                    "{} upload, {} download, {} delete-remote, {} delete-local, {} conflict",
                    outcome.uploads,
                    outcome.downloads,
                    outcome.deletes_remote,
                    outcome.deletes_local,
                    outcome.conflicts,
                );
            }
        }
        Err(e) => eprintln!("sync failed: {e:#}"),
    }
}

async fn run_sync(
    store: &Arc<S3Store>,
    config: &Config,
    enc_keys: &Arc<DerivedSubKeys>,
    state: &mut State,
    reporter: &Arc<dyn ProgressReporter>,
) -> Result<SyncOutcome> {
    let outcome = mirror_core::sync::sync_once(
        Arc::clone(store),
        &config.local.root,
        &config.remote.prefix,
        &config.local.ignore_file,
        Arc::clone(enc_keys),
        state,
        Arc::clone(reporter),
    )
    .await?;

    Ok(outcome)
}

async fn compact(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let manifest_enc_key = keyring::load_from_keyring(
        format!(
            "{}/{}:manifest_key",
            config.remote.bucket, config.remote.prefix
        )
        .as_str(),
    )?;

    let mut state = State::open(&config.local.root)?;

    manifest::compact(
        &store,
        &manifest_enc_key,
        &config.remote.prefix,
        &mut state,
        manifest::DEFAULT_COMPACTION_GRACE,
    )
    .await?;

    Ok(())
}

async fn unlock(path: &Path) -> Result<()> {
    let vault_connection = connect_vault(path).await?;
    let passphrase = prompt_passphrase(false)?;
    let vault_header = vault::load(
        &vault_connection.store,
        &vault_connection.config.remote.prefix,
    )
    .await?
    .ok_or(Error::Config("no vault found".to_string()))?;

    let application_keys = derive_application_keys(
        passphrase,
        &vault_header.salt,
        Params::new(
            vault_header.m_cost,
            vault_header.t_cost,
            vault_header.p_cost,
            None,
        )
        .unwrap(),
    )?;

    let cipher_key = Key::try_from(application_keys.keycheck_bytes.expose_secret().as_ref())?;
    let cipher = ChaCha20Poly1305::new(&cipher_key);
    let nonce = Nonce::from(vault_header.key_check_nonce);

    if cipher
        .decrypt(&nonce, vault_header.key_check.as_ref())
        .is_err()
    {
        anyhow::bail!("passphrase incorrect");
    }

    keyring::store_to_keyring(
        application_keys.content_key,
        format!(
            "{}/{}:content_key",
            vault_connection.config.remote.bucket, vault_connection.config.remote.prefix
        )
        .as_str(),
    )?;
    keyring::store_to_keyring(
        application_keys.manifest_key,
        format!(
            "{}/{}:manifest_key",
            vault_connection.config.remote.bucket, vault_connection.config.remote.prefix
        )
        .as_str(),
    )?;
    keyring::store_to_keyring(
        application_keys.name_key,
        format!(
            "{}/{}:name_key",
            vault_connection.config.remote.bucket, vault_connection.config.remote.prefix
        )
        .as_str(),
    )?;

    println!("passphrase   ok");

    Ok(())
}

struct VaultConnection {
    pub config: Config,
    pub store: S3Store,
}

async fn connect_vault(path: &Path) -> Result<VaultConnection> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    Ok(VaultConnection { config, store })
}

fn prompt_passphrase(confirm_passphrase: bool) -> Result<SecretString> {
    let passphrase = match std::env::var("RFM_PASSPHRASE") {
        Ok(val) => {
            eprintln!("Loading passphrase from RFM_PASSPHRASE");
            SecretString::from(val)
        }
        Err(_) => {
            eprint!("Enter passphrase ");
            io::stderr().flush().unwrap();

            let mut raw_input = rpassword::read_password().context("reading passphrase")?;
            let p1 = SecretString::from(raw_input);

            if confirm_passphrase {
                eprint!("Confirm passphrase ");
                io::stderr().flush().unwrap();

                raw_input = rpassword::read_password().context("reading passphrase")?;
                let p2 = SecretString::from(raw_input);

                if p1.expose_secret() != p2.expose_secret() {
                    anyhow::bail!("passphrases do not match");
                }
            }

            p1
        }
    };

    Ok(passphrase)
}

async fn init(path: &Path) -> Result<()> {
    let vault_connection = connect_vault(path).await?;

    let key = format!("{}vault.json", vault_connection.config.remote.prefix);

    if vault::load(
        &vault_connection.store,
        &vault_connection.config.remote.prefix,
    )
    .await?
    .is_some()
    {
        anyhow::bail!("vault already exists at {key} — refusing to overwrite");
    }

    let passphrase = prompt_passphrase(true)?;

    // Generate salt
    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt);

    let custom_params = Params::new(
        65536, // Memory Cost (m): 64 MB of RAM
        3,     // Time Cost (t): 3 iterations over memory
        4,     // Parallelism (p): 4 concurrent threads
        None,  // Output length (defaults to 32 bytes)
    )
    .unwrap();

    let application_keys = derive_application_keys(passphrase, &salt, custom_params)?;
    let cipher_key = Key::try_from(application_keys.keycheck_bytes.expose_secret().as_ref())?;
    let cipher = ChaCha20Poly1305::new(&cipher_key);
    let payload = "file mirror".as_bytes();
    // Generate a cryptographically secure 96-bit (12-byte) unique Nonce
    // CRITICAL: Never reuse a nonce with the same key.
    let mut nonce = [0u8; 12];
    rand::rng().fill(&mut nonce);

    let key_check = cipher.encrypt(&nonce.into(), payload)?;

    let header = VaultHeader {
        format_version: 1,
        kdf: "argon2id".to_string(),
        // Placeholder cost params — 2.2 benchmarks these at init time and persists
        // the real values here so every device reproduces the same derived key.
        m_cost: 65536, // 64 MiB
        t_cost: 3,
        p_cost: 4,
        salt: salt.to_vec(),
        // Real value needs Argon2id + HKDF + the content AEAD (2.2/2.3), none of
        // which exist yet — an empty key_check means `unlock` can't verify a
        // passphrase yet, only `init` can create the vault.
        key_check_nonce: nonce,
        key_check,
    };

    vault::create(
        &vault_connection.store,
        &vault_connection.config.remote.prefix,
        header,
    )
    .await?;

    println!("vault    ok   {key}");
    println!();
    println!("WARNING: there is no recovery if the passphrase is lost.");

    Ok(())
}

/// Loads the three subkeys a sync needs from the OS keyring (populated by
/// `unlock`). The keycheck subkey is only used at vault time, so it's zeroed.
fn load_enc_keys(config: &Config) -> Result<DerivedSubKeys> {
    let subkey = |role: &str| {
        keyring::load_from_keyring(
            format!("{}/{}:{role}", config.remote.bucket, config.remote.prefix).as_str(),
        )
    };

    Ok(DerivedSubKeys {
        content_key: subkey("content_key")?,
        manifest_key: subkey("manifest_key")?,
        name_key: subkey("name_key")?,
        keycheck_bytes: SecretBox::new(Box::new([0u8; 32])),
    })
}

async fn sync(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let enc_keys = load_enc_keys(&config)?;
    let mut state = State::open(&config.local.root)?;

    let reporter: Arc<dyn ProgressReporter> = if std::io::stderr().is_terminal() {
        Arc::new(VisualBarReporter {
            multi: MultiProgress::new(),
        })
    } else {
        Arc::new(PrintReporter {})
    };

    let outcome = mirror_core::sync::sync_once(
        Arc::new(store),
        &config.local.root,
        &config.remote.prefix,
        &config.local.ignore_file,
        Arc::new(enc_keys),
        &mut state,
        reporter,
    )
    .await?;

    println!(
        "{} upload, {} download, {} delete-remote, {} delete-local, {} conflict",
        outcome.uploads,
        outcome.downloads,
        outcome.deletes_remote,
        outcome.deletes_local,
        outcome.conflicts,
    );

    Ok(())
}

/// Below this age, an untracked multipart upload is left alone rather than
/// flagged as an orphan — `rfm` is multi-device by design, so an upload this
/// device doesn't recognize may simply belong to another device that's still
/// actively uploading, not a crash this device needs to clean up after.
const ORPHAN_GRACE_PERIOD_SECS: i64 = 24 * 60 * 60;

async fn doctor(path: &Path, abort_orphans: bool) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    println!("config   ok   {}", path.display());

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let state = State::open(&config.local.root)?;
    let local_ids: HashSet<String> = state
        .pending_uploads()?
        .into_iter()
        .map(|pending| pending.upload_id)
        .collect();

    let remote_uploads = store.list_multipart_uploads().await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut orphans = Vec::new();

    for upload in remote_uploads {
        let (Some(key), Some(upload_id)) = (upload.key(), upload.upload_id()) else {
            eprintln!("uploads  warn  skipping a listing missing its key or upload id");
            continue;
        };

        if local_ids.contains(upload_id) {
            continue; // tracked by this device — not orphaned
        }

        // Missing `initiated` is treated the same as "too young": we'd rather
        // silently leave a truly-orphaned-but-unstamped upload alone than risk
        // aborting one that isn't actually orphaned at all.
        let age_secs = upload
            .initiated()
            .map_or(0, |initiated| now - initiated.secs());

        if age_secs < ORPHAN_GRACE_PERIOD_SECS {
            continue;
        }

        orphans.push((key.to_string(), upload_id.to_string(), age_secs));
    }

    if orphans.is_empty() {
        println!("uploads  ok   no orphaned multipart uploads found");
        return Ok(());
    }

    println!(
        "uploads  found {} orphaned multipart upload(s):",
        orphans.len()
    );
    for (key, upload_id, age_secs) in &orphans {
        println!("  {key}  upload_id={upload_id}  age={}h", age_secs / 3600);
    }

    if !abort_orphans {
        println!("\nrun with --abort-orphans to abort them");
        return Ok(());
    }

    let mut aborted = 0;
    let mut failed = 0;

    for (key, upload_id, _) in &orphans {
        match store.abort_multipart_upload(key, upload_id).await {
            Ok(()) => {
                println!("  aborted   {key} ({upload_id})");
                aborted += 1;
            }
            Err(e) => {
                eprintln!("  failed    {key} ({upload_id}): {e}");
                failed += 1;
            }
        }
    }

    println!(
        "\naborted {aborted} of {} orphaned upload(s){}",
        orphans.len(),
        if failed > 0 {
            format!(", {failed} failed")
        } else {
            String::new()
        }
    );

    Ok(())
}

fn scan(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let scanner = Scanner::new(&config.local.root, &config.local.ignore_file);
    let entries = scanner.scan(&())?;

    for entry in &entries {
        println!("{:>12} {:>10} {}", entry.hash, entry.size, entry.path);
    }

    println!("\n{} files", entries.len());

    Ok(())
}

async fn status(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;
    let plan_result = build_plan(&config).await?;

    if plan_result.plan.is_empty() {
        println!("up to date {} files", plan_result.local_entries.len());
        return Ok(());
    }

    for action in &plan_result.plan.actions {
        println!("{:<14} {}", action.kind, action.path);
    }

    println!(
        "\n{} upload, {} download, {} delete-remote, {} delete-local, {} conflict",
        plan_result.plan.count(ActionKind::Upload),
        plan_result.plan.count(ActionKind::Download),
        plan_result.plan.count(ActionKind::DeleteRemote),
        plan_result.plan.count(ActionKind::DeleteLocal),
        plan_result.plan.count(ActionKind::Conflict),
    );

    Ok(())
}

fn snapshot(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let mut state = State::open(&config.local.root)?;
    let baseline = state.baseline()?;

    let scanner = Scanner::new(&config.local.root, &config.local.ignore_file);
    let entries = scanner.scan(&baseline)?;

    state.record_scan(&entries)?;
    println!("recorded {} files", entries.len());
    Ok(())
}

struct PlanResult {
    pub plan: Plan,
    pub local_entries: Vec<LocalEntry>,
}

async fn build_plan(config: &Config) -> Result<PlanResult> {
    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let manifest_enc_key = keyring::load_from_keyring(
        format!(
            "{}/{}:manifest_key",
            config.remote.bucket, config.remote.prefix
        )
        .as_str(),
    )?;
    let mut state = State::open(&config.local.root)?;
    let snapshot =
        manifest::from_store(&store, &manifest_enc_key, &config.remote.prefix, &mut state).await?;
    let delta_log = read_deltas(&store, &config.remote.prefix).await?;
    let MergeResult {
        manifest,
        conflicts,
        ..
    } = merge_deltas(&snapshot.manifest, &delta_log.deltas);
    let _ = preserve_conflict_losers(&conflicts, &config.local.root, &mut state)?;

    let baseline = state.baseline()?;
    let scanner = Scanner::new(&config.local.root, &config.local.ignore_file);
    let entries = scanner.scan(&baseline)?;
    let plan = reconcile(&entries, &baseline, &manifest);

    Ok(PlanResult {
        plan,
        local_entries: entries,
    })
}
