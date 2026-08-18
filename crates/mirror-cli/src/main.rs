use std::path::{Path, PathBuf};

use anyhow::{Context, Ok, Result};
use clap::{Parser, Subcommand};
use mirror_core::{
    apply::apply,
    config::Config,
    crypto::vault::{self, VaultHeader},
    engine::{ActionKind, Plan, reconcile},
    manifest::{self, Manifest},
    scanner::{LocalEntry, Scanner},
    state::State,
    store::s3::{self, S3Store},
};
use rand::Rng;

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
    /// Check configuration and bucket connectivity
    Doctor,

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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("RFM_LOG"))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Doctor => doctor(&cli.config).await,
        Command::Scan => scan(&cli.config),
        Command::Status => status(&cli.config).await,
        Command::Snapshot => snapshot(&cli.config),
        Command::Sync => sync(&cli.config).await,
        Command::Init => init(&cli.config).await,
    }
}

async fn init(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let key = format!("{}vault.json", config.remote.prefix);

    if vault::load(&store, &config.remote.prefix).await?.is_some() {
        anyhow::bail!("vault already exists at {key} — refusing to overwrite");
    }

    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt);

    let header = VaultHeader {
        format_version: 1,
        kdf: "argon2id".to_string(),
        // Placeholder cost params — 2.2 benchmarks these at init time and persists
        // the real values here so every device reproduces the same derived key.
        m_cost: 65536, // 64 MiB
        t_cost: 3,
        p_cost: 4,
        salt,
        // Real value needs Argon2id + HKDF + the content AEAD (2.2/2.3), none of
        // which exist yet — an empty key_check means `unlock` can't verify a
        // passphrase yet, only `init` can create the vault.
        key_check: Vec::new(),
    };

    vault::create(&store, &config.remote.prefix, header).await?;

    println!("vault    ok   {key}");
    println!();
    println!("WARNING: there is no recovery if the passphrase is lost.");

    Ok(())
}

async fn sync(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let (plan, remote, mut state, store, local_entries) = build_plan(&config).await?;

    for action in &plan.actions {
        println!("{:<14} {}", action.kind, action.path);
    }

    apply(
        &plan,
        &store,
        &config.local.root,
        &config.remote.prefix,
        &mut state,
        &remote,
    )
    .await?;

    state.record_scan(&local_entries)?;

    Ok(())
}

async fn doctor(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    println!("config   ok   {}", path.display());

    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

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

    let (plan, _, _, _, local_entries) = build_plan(&config).await?;

    if plan.is_empty() {
        println!("up to date {} files", local_entries.len());
        return Ok(());
    }

    for action in &plan.actions {
        println!("{:<14} {}", action.kind, action.path);
    }

    println!(
        "\n{} upload, {} download, {} delete-remote, {} delete-local, {} conflict",
        plan.count(ActionKind::Upload),
        plan.count(ActionKind::Download),
        plan.count(ActionKind::DeleteRemote),
        plan.count(ActionKind::DeleteLocal),
        plan.count(ActionKind::Conflict),
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

async fn build_plan(config: &Config) -> Result<(Plan, Manifest, State, S3Store, Vec<LocalEntry>)> {
    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let state = State::open(&config.local.root)?;
    let baseline = state.baseline()?;

    let scanner = Scanner::new(&config.local.root, &config.local.ignore_file);
    let entries = scanner.scan(&baseline)?;

    let remote = manifest::from_store(&store, &config.remote.prefix).await?;
    let plan = reconcile(&entries, &baseline, &remote);

    Ok((plan, remote, state, store, entries))
}
