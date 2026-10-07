mod daemon;
mod events;
mod indicator;
mod ops;
mod tui;
mod watch;

use anyhow::{Context, Result};
use argon2::Params;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use clap::{Parser, Subcommand};
use indicatif::MultiProgress;
use mirror_core::{
    config::{Config, DefaultResidency, Local, OfflineConfig, Remote, SyncConfig},
    crypto::{
        key::{DerivedSubKeys, derive_application_keys},
        vault::{self, VaultHeader},
    },
    engine::ActionKind,
    indicator::{PrintReporter, ProgressReporter},
    manifest,
    residency::{self, Mode},
    scanner::{ScanResult, Scanner},
    state::{Baseline, State},
    store::{
        ObjectStore,
        s3::{self, S3Store},
    },
    sync::{PassPlan, SyncOptions, plan_pass},
};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::{self, IsTerminal, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::{
    events::{Hub, HubMakeWriter},
    indicator::VisualBarReporter,
    ops::{ResidencyRequest, human_bytes, residency_pass, residency_summary, summary},
};

#[derive(Parser)]
#[command(name = "rfm", version, about = "Encrypted S3 file mirror")]
struct Cli {
    /// Config file path (defaults to ~/.config/rfm/config.toml, written by `rfm init`).
    #[arg(long, global = true, env = "RFM_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

/// Resolves the config path: `--config`/`RFM_CONFIG` if given, else the standard
/// per-user location that `rfm init` writes to.
fn default_config_path() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".config/rfm/config.toml"))
        .unwrap_or_else(|| PathBuf::from("rfm.toml"))
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

    /// Initialize a vault, or verify and save the passphrase on a device that
    /// already shares one
    Init(InitArgs),

    /// Run compaction on deltas, and generate a new manifest snapshot
    Compact,

    /// Run as background daemon
    Watch {
        /// Show a live dashboard instead of log lines (needs an interactive terminal)
        #[arg(long)]
        tui: bool,
    },

    /// Attach a live dashboard to a running `watch` daemon
    Tui,

    Daemon {
        #[command(subcommand)]
        cmd: DaemonCmd,
    },

    /// Free local space: keep only a placeholder, with the contents stored remotely
    Evict {
        /// Paths, directories or globs, relative to the mirrored root
        #[arg(required = true)]
        paths: Vec<String>,
        /// Download, decrypt and hash-check the remote copy before deleting local bytes
        #[arg(long)]
        verify: bool,
    },

    /// Download online-only files back into place
    Hydrate {
        /// Paths, directories or globs, relative to the mirrored root
        #[arg(required = true)]
        paths: Vec<String>,
    },

    /// Set a residency pin for a glob, or list pins when no glob is given
    Pin {
        pattern: Option<String>,
        /// Always keep local (hydrates on the next sync)
        #[arg(long, group = "mode")]
        local: bool,
        /// Keep only remotely once safely synced
        #[arg(long, group = "mode")]
        online_only: bool,
        /// Leave residency to manual and automatic eviction
        #[arg(long, group = "mode")]
        auto: bool,
    },

    /// Remove a residency pin
    Unpin { pattern: String },
}

#[derive(Subcommand)]
enum DaemonCmd {
    Status,
    Stop,
    /// Ask a running daemon to sync now
    Sync,
}

/// Values for `init`. Any omitted flag is prompted for interactively (or, when
/// not on a TTY, falls back to a default or errors if required).
#[derive(clap::Args)]
struct InitArgs {
    /// Re-run the config prompts even if a config file already exists
    #[arg(long)]
    reconfigure: bool,
    #[arg(long)]
    bucket: Option<String>,
    #[arg(long)]
    region: Option<String>,
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    path_style: Option<bool>,
    #[arg(long)]
    profile: Option<String>,
    #[arg(long)]
    root: Option<PathBuf>,
    /// New files from other devices arrive as placeholders instead of being downloaded
    #[arg(long)]
    online_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let hub = init_tracing(&cli.command);
    let config_path = cli.config.unwrap_or_else(default_config_path);

    match cli.command {
        Command::Doctor { abort_orphans } => doctor(&config_path, abort_orphans).await,
        Command::Scan => scan(&config_path),
        Command::Status => status(&config_path).await,
        Command::Snapshot => snapshot(&config_path),
        Command::Sync => sync(&config_path).await,
        Command::Init(args) => init(&config_path, args).await,
        Command::Compact => compact(&config_path).await,
        Command::Watch { tui } => watch::watch(&config_path, hub, tui).await,
        Command::Tui => watch::attach(&config_path).await,
        Command::Daemon { cmd } => daemon(&config_path, cmd).await,
        Command::Evict { paths, verify } => {
            residency_cmd(
                &config_path,
                ResidencyRequest {
                    hydrate: false,
                    verify,
                    patterns: paths,
                },
            )
            .await
        }
        Command::Hydrate { paths } => {
            residency_cmd(
                &config_path,
                ResidencyRequest {
                    hydrate: true,
                    verify: false,
                    patterns: paths,
                },
            )
            .await
        }
        Command::Pin {
            pattern,
            local,
            online_only,
            auto,
        } => {
            let mode = match (local, online_only, auto) {
                (true, _, _) => Some(Mode::Local),
                (_, true, _) => Some(Mode::OnlineOnly),
                (_, _, true) => Some(Mode::Auto),
                _ => None,
            };
            pin(&config_path, pattern, mode)
        }
        Command::Unpin { pattern } => unpin(&config_path, &pattern),
    }
}

/// Sets up logging for the command, returning the event hub `watch` should use.
/// Under a TUI anything written to stderr would corrupt the screen, so records
/// go to the dashboard (`watch --tui`) or nowhere (`rfm tui`) instead.
fn init_tracing(command: &Command) -> Hub {
    use tracing_subscriber::EnvFilter;

    let tui = matches!(command, Command::Watch { tui: true });
    let hub = Hub::new(!tui);

    match command {
        Command::Watch { tui: true } => tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_env("RFM_LOG")
                    .unwrap_or_else(|_| EnvFilter::new("mirror_core=info,mirror_cli=info")),
            )
            .with_writer(HubMakeWriter(hub.clone()))
            .with_ansi(false)
            .without_time()
            .with_level(false)
            .with_target(false)
            .init(),
        Command::Tui => tracing_subscriber::fmt().with_writer(std::io::sink).init(),
        _ => tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_env("RFM_LOG"))
            .init(),
    }

    hub
}

async fn daemon(path: &Path, cmd: DaemonCmd) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let command = match cmd {
        DaemonCmd::Status => "status",
        DaemonCmd::Stop => "stop",
        DaemonCmd::Sync => "sync",
    };

    print!("{}", watch::control_request(&config, command).await?);
    Ok(())
}

/// Runs an evict/hydrate request, through the daemon when one is running so a root
/// only ever has one writer.
async fn residency_cmd(path: &Path, mut request: ResidencyRequest) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;
    let root = &config.local.root;

    // Accept absolute paths (e.g. shell-completed) inside the root.
    for pattern in &mut request.patterns {
        if let Ok(rel) = Path::new(pattern.as_str()).strip_prefix(root) {
            *pattern = rel.to_string_lossy().into_owned();
        }
    }

    if let Ok(mut stream) = UnixStream::connect(watch::socket_path(&config)).await {
        stream.write_all(request.to_line().as_bytes()).await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        print!("{response}");
        return Ok(());
    }

    std::fs::create_dir_all(root.join(".mirror"))?;
    let lock_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(".mirror/daemon.lock"))?;
    if fs2::FileExt::try_lock_exclusive(&lock_file).is_err() {
        anyhow::bail!(
            "a daemon holds {} but isn't answering; try again",
            root.display()
        );
    }

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    let enc_keys = Arc::new(derive_enc_keys(&config, &store).await?);
    let mut state = State::open(root)?;
    let reporter = terminal_reporter();

    let outcome = residency_pass(
        &Arc::new(store),
        &config,
        &enc_keys,
        &mut state,
        &reporter,
        &request,
    )
    .await?;

    print!("{}", residency_summary(&outcome, &request));
    Ok(())
}

fn terminal_reporter() -> Arc<dyn ProgressReporter> {
    if std::io::stderr().is_terminal() {
        Arc::new(VisualBarReporter {
            multi: MultiProgress::new(),
        })
    } else {
        Arc::new(PrintReporter {})
    }
}

fn pin(path: &Path, pattern: Option<String>, mode: Option<Mode>) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;
    let mut state = State::open(&config.local.root)?;

    let Some(pattern) = pattern else {
        anyhow::ensure!(mode.is_none(), "give a glob to pin");

        for (pattern, mode) in state.pins()? {
            println!("{mode:<12} {pattern}  (pin)");
        }
        for pattern in &config.offline.local {
            println!("{:<12} {pattern}  (config)", Mode::Local);
        }
        for pattern in &config.offline.online_only {
            println!("{:<12} {pattern}  (config)", Mode::OnlineOnly);
        }
        return Ok(());
    };

    let mode = mode.context("choose one of --local, --online-only or --auto")?;
    // Reject a bad glob before storing it.
    residency::Policy::new(&[(pattern.clone(), mode)], &[], &[], false)?;
    state.add_pin(&pattern, mode)?;
    println!("pinned {pattern} {mode}; applies on the next sync");
    Ok(())
}

fn unpin(path: &Path, pattern: &str) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;
    let mut state = State::open(&config.local.root)?;

    if state.remove_pin(pattern)? {
        println!("unpinned {pattern}");
    } else {
        println!("no pin for {pattern}");
    }
    Ok(())
}

async fn compact(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let manifest_enc_key = derive_enc_keys(&config, &store).await?.manifest_key;

    let mut state = State::open(&config.local.root)?;

    manifest::compact(
        &store,
        &manifest_enc_key,
        &config.remote.prefix,
        &mut state,
        manifest::DEFAULT_COMPACTION_GRACE,
        config.sync.object_retention(),
    )
    .await?;

    Ok(())
}

/// Verifies a passphrase against the vault's `key_check`, failing closed on a
/// wrong passphrase before any real work happens.
fn verify_passphrase(keys: &DerivedSubKeys, header: &VaultHeader) -> Result<()> {
    let cipher_key = Key::try_from(keys.keycheck_bytes.expose_secret().as_ref())?;
    let cipher = ChaCha20Poly1305::new(&cipher_key);
    let nonce = Nonce::from(header.key_check_nonce);

    if cipher.decrypt(&nonce, header.key_check.as_ref()).is_err() {
        anyhow::bail!("passphrase incorrect");
    }

    Ok(())
}

/// Default per-root passphrase file, written by `init` and read by every later run.
fn passphrase_path(root: &Path) -> PathBuf {
    root.join(".mirror").join("passphrase")
}

fn read_passphrase_file(path: &Path) -> Result<SecretString> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading passphrase file {}", path.display()))?;
    // Tolerate a trailing newline (e.g. a hand-written `echo … > passphrase`).
    Ok(SecretString::from(
        raw.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

/// Writes the passphrase to `<root>/.mirror/passphrase` with 0600 perms, created
/// restrictively from the start rather than chmod-ed after a permissive open.
fn write_passphrase_file(root: &Path, passphrase: &SecretString) -> Result<()> {
    let dir = root.join(".mirror");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("passphrase");

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(passphrase.expose_secret().as_bytes())?;

    // Enforce 0600 even if the file already existed with looser permissions.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    Ok(())
}

/// Resolves the passphrase for an unattended run: env var, then env-pointed file,
/// then the default per-root file, then an interactive prompt if on a TTY.
fn resolve_passphrase(config: &Config) -> Result<SecretString> {
    if let Ok(val) = std::env::var("RFM_PASSPHRASE") {
        return Ok(SecretString::from(val));
    }

    if let Ok(file) = std::env::var("RFM_PASSPHRASE_FILE") {
        return read_passphrase_file(Path::new(&file));
    }

    let default_file = passphrase_path(&config.local.root);
    if default_file.exists() {
        return read_passphrase_file(&default_file);
    }

    if std::io::stderr().is_terminal() {
        return prompt_passphrase(false);
    }

    anyhow::bail!(
        "no passphrase available: set RFM_PASSPHRASE or RFM_PASSPHRASE_FILE, \
         or run `rfm init` to save one at {}",
        default_file.display()
    )
}

/// Re-derives the subkeys at startup from the vault header + resolved passphrase.
/// Replaces the old OS-keyring lookup so the daemon runs headless on Linux/macOS.
async fn derive_enc_keys(config: &Config, store: &S3Store) -> Result<DerivedSubKeys> {
    let header = vault::load(store, &config.remote.prefix)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no vault found — run `rfm init` first"))?;
    header.check_format()?;

    let passphrase = resolve_passphrase(config)?;
    let keys = derive_application_keys(
        passphrase,
        &header.salt,
        Params::new(header.m_cost, header.t_cost, header.p_cost, None).unwrap(),
    )?;
    verify_passphrase(&keys, &header)?;

    Ok(keys)
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

/// Prompts for a line with an optional default; loops until non-empty when there
/// is no default (a required field).
fn prompt_line(label: &str, default: Option<&str>) -> Result<String> {
    loop {
        match default {
            Some(d) => eprint!("{label} [{d}]: "),
            None => eprint!("{label}: "),
        }
        io::stderr().flush().ok();

        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let value = line.trim().to_string();

        if !value.is_empty() {
            return Ok(value);
        }
        match default {
            Some(d) => return Ok(d.to_string()),
            None => eprintln!("  a value is required"),
        }
    }
}

fn prompt_bool(label: &str, default: bool) -> Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    eprint!("{label} [{hint}]: ");
    io::stderr().flush().ok();

    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(match line.trim().to_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default,
    })
}

/// A required config value: flag wins, else prompt on a TTY, else the default, else error.
fn required_field(
    flag: Option<String>,
    label: &str,
    default: Option<&str>,
    interactive: bool,
) -> Result<String> {
    if let Some(value) = flag {
        return Ok(value);
    }
    if interactive {
        return prompt_line(label, default);
    }
    match default {
        Some(d) => Ok(d.to_string()),
        None => {
            anyhow::bail!("missing required value for \"{label}\" (not a TTY; pass it as a flag)")
        }
    }
}

/// An optional config value: flag wins, else prompt on a TTY (blank = none), else none.
fn optional_field(flag: Option<String>, label: &str, interactive: bool) -> Result<Option<String>> {
    if let Some(value) = flag {
        return Ok(Some(value));
    }
    if interactive {
        let value = prompt_line(label, Some("")).unwrap_or_default();
        return Ok((!value.is_empty()).then_some(value));
    }
    Ok(None)
}

/// Walks the user through the bucket + local settings and returns a validated config.
fn gather_config(args: &InitArgs) -> Result<Config> {
    let interactive = std::io::stderr().is_terminal();

    let bucket = required_field(args.bucket.clone(), "S3 bucket", None, interactive)?;
    let region = required_field(
        args.region.clone(),
        "AWS region",
        Some("us-east-1"),
        interactive,
    )?;

    let prefix = {
        let raw = required_field(args.prefix.clone(), "Key prefix", Some("rfm/"), interactive)?;
        // Config::validate requires a trailing slash — add it rather than reject.
        if raw.ends_with('/') {
            raw
        } else {
            format!("{raw}/")
        }
    };

    let endpoint = optional_field(
        args.endpoint.clone(),
        "S3 endpoint URL (blank for AWS)",
        interactive,
    )?;

    // MinIO and most S3-compatible stores need path-style; real S3 does not.
    let path_style = match args.path_style {
        Some(explicit) => explicit,
        None if interactive => prompt_bool(
            "Use path-style addressing (required for MinIO)",
            endpoint.is_some(),
        )?,
        None => endpoint.is_some(),
    };

    let profile = optional_field(
        args.profile.clone(),
        "AWS profile (blank for default credential chain)",
        interactive,
    )?;

    let root = match &args.root {
        Some(root) => root.clone(),
        None if interactive => PathBuf::from(prompt_line("Local folder to mirror", None)?),
        None => anyhow::bail!("missing required --root (not a TTY)"),
    };
    if !root.exists() {
        std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
        println!("created {}", root.display());
    }

    let config = Config {
        remote: Remote {
            bucket,
            endpoint,
            region,
            prefix,
            path_style,
            profile,
        },
        local: Local {
            root,
            ignore_file: ".mirrorignore".to_string(),
        },
        sync: SyncConfig::default(),
        offline: OfflineConfig {
            default_residency: if args.online_only {
                DefaultResidency::OnlineOnly
            } else {
                DefaultResidency::Local
            },
            ..OfflineConfig::default()
        },
    };
    config.validate()?;
    Ok(config)
}

async fn init(path: &Path, args: InitArgs) -> Result<()> {
    // Use an existing config unless asked to reconfigure; otherwise gather one.
    let config = if path.exists() && !args.reconfigure {
        println!("config   ok   {}", path.display());
        let config = Config::load(path)
            .with_context(|| format!("loading config from {}", path.display()))?;
        if args.online_only && config.offline.default_residency != DefaultResidency::OnlineOnly {
            println!(
                "note: config exists; add `[offline] default_residency = \"online-only\"` to {} \
                 or re-run with --reconfigure",
                path.display()
            );
        }
        config
    } else {
        let config = gather_config(&args)?;
        config.save(path)?;
        println!("config saved to {}", path.display());
        config
    };

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let prefix = &config.remote.prefix;
    let key = format!("{prefix}vault.json");

    match vault::load(&store, prefix).await? {
        // Vault already exists (e.g. a second device sharing the bucket): verify the
        // passphrase against it and save it locally — never recreate the vault.
        Some(header) => {
            header.check_format()?;
            let passphrase = prompt_passphrase(false)?;
            let keys = derive_application_keys(
                SecretString::from(passphrase.expose_secret().to_string()),
                &header.salt,
                Params::new(header.m_cost, header.t_cost, header.p_cost, None).unwrap(),
            )?;
            verify_passphrase(&keys, &header)?;
            write_passphrase_file(&config.local.root, &passphrase)?;

            println!("vault    ok   {key} (existing)");
            println!(
                "passphrase saved to {}",
                passphrase_path(&config.local.root).display()
            );
        }

        // No vault yet: create it, then save the passphrase locally.
        None => {
            let passphrase = prompt_passphrase(true)?;

            let mut salt = [0u8; 16];
            rand::rng().fill(&mut salt);

            let custom_params = Params::new(
                65536, // Memory Cost (m): 64 MB of RAM
                3,     // Time Cost (t): 3 iterations over memory
                4,     // Parallelism (p): 4 concurrent threads
                None,  // Output length (defaults to 32 bytes)
            )
            .unwrap();

            let application_keys = derive_application_keys(
                SecretString::from(passphrase.expose_secret().to_string()),
                &salt,
                custom_params,
            )?;
            let cipher_key =
                Key::try_from(application_keys.keycheck_bytes.expose_secret().as_ref())?;
            let cipher = ChaCha20Poly1305::new(&cipher_key);
            let payload = "file mirror".as_bytes();
            // Cryptographically secure 96-bit (12-byte) nonce; never reused with this key.
            let mut nonce = [0u8; 12];
            rand::rng().fill(&mut nonce);

            let key_check = cipher.encrypt(&nonce.into(), payload)?;

            let header = VaultHeader {
                format_version: vault::FORMAT_VERSION,
                kdf: "argon2id".to_string(),
                m_cost: 65536, // 64 MiB
                t_cost: 3,
                p_cost: 4,
                salt: salt.to_vec(),
                key_check_nonce: nonce,
                key_check,
            };

            vault::create(&store, prefix, header).await?;
            write_passphrase_file(&config.local.root, &passphrase)?;

            println!("vault    ok   {key}");
            println!(
                "passphrase saved to {}",
                passphrase_path(&config.local.root).display()
            );
            println!();
            println!("WARNING: there is no recovery if the passphrase is lost.");
        }
    }

    Ok(())
}

async fn sync(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let enc_keys = derive_enc_keys(&config, &store).await?;
    let mut state = State::open(&config.local.root)?;
    let options = SyncOptions::from_config(&config.offline, &state)?;

    let outcome = mirror_core::sync::sync_once(
        Arc::new(store),
        &config.local.root,
        &config.remote.prefix,
        &config.local.ignore_file,
        Arc::new(enc_keys),
        &mut state,
        terminal_reporter(),
        &options,
    )
    .await?;

    println!("{}", summary(&outcome));

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
    check_placeholders(&config, &state)?;

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
    let plan = &plan_result.pass.plan;

    if plan.is_empty() {
        println!("up to date {} files", plan_result.pass.scan.entries.len());
    } else {
        for action in &plan.actions {
            println!("{:<18} {}", action.kind, action.path);
        }

        println!(
            "\n{} upload, {} download, {} delete-remote, {} delete-local, {} conflict, \
             {} hydrate, {} placeholder, {} relocate",
            plan.count(ActionKind::Upload),
            plan.count(ActionKind::Download),
            plan.count(ActionKind::DeleteRemote),
            plan.count(ActionKind::DeleteLocal),
            plan.count(ActionKind::Conflict),
            plan.count(ActionKind::Hydrate),
            plan.count(ActionKind::CreatePlaceholder) + plan.count(ActionKind::UpdatePlaceholder),
            plan.count(ActionKind::Relocate),
        );
    }

    print_residency(&plan_result.baseline, &plan_result.pass.scan);

    Ok(())
}

fn print_residency(baseline: &Baseline, scan: &ScanResult) {
    let (evicted, local): (Vec<_>, Vec<_>) = baseline
        .values()
        .filter(|record| record.last_synced_hash.is_some())
        .partition(|record| record.is_evicted());
    let bytes = |records: &[&mirror_core::state::FileRecord]| -> u64 {
        records.iter().map(|record| record.size).sum()
    };

    println!(
        "\nlocal        {:>6} files  {}",
        local.len(),
        human_bytes(bytes(&local))
    );
    println!(
        "online-only  {:>6} files  {}",
        evicted.len(),
        human_bytes(bytes(&evicted))
    );

    for skipped in &scan.skipped {
        println!("skipped      {skipped}  (reserved .rfm suffix, not mirrored)");
    }
}

/// Placeholders that no synced file stands behind, or that were moved and await relocation.
fn check_placeholders(config: &Config, state: &State) -> Result<()> {
    let baseline = state.baseline()?;
    let scan = Scanner::new(&config.local.root, &config.local.ignore_file).scan_all(&baseline)?;
    let mut problems = 0;

    for (path, meta) in &scan.placeholders {
        if meta.path != *path {
            println!(
                "placeholders  moved   {path} (from {}; relocates on next sync)",
                meta.path
            );
            problems += 1;
        } else if !baseline.get(path).is_some_and(|record| record.is_evicted()) {
            println!("placeholders  orphan  {path} (adopted on next sync if still on the remote)");
            problems += 1;
        }
    }

    for skipped in &scan.skipped {
        println!("placeholders  skipped {skipped} (reserved .rfm suffix, not mirrored)");
        problems += 1;
    }

    if problems == 0 {
        println!("placeholders ok  {} online-only", scan.placeholders.len());
    }

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
    pub pass: PassPlan,
    pub baseline: Baseline,
}

async fn build_plan(config: &Config) -> Result<PlanResult> {
    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let enc_keys = derive_enc_keys(config, &store).await?;
    let mut state = State::open(&config.local.root)?;
    let options = SyncOptions::from_config(&config.offline, &state)?;
    let pass = plan_pass(
        &store,
        &config.local.root,
        &config.remote.prefix,
        &config.local.ignore_file,
        &enc_keys,
        &mut state,
        &options,
    )
    .await?;

    Ok(PlanResult {
        pass,
        baseline: state.baseline()?,
    })
}
