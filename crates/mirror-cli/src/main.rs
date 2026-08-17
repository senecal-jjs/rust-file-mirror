use std::path::{Path, PathBuf};

use anyhow::{Context, Ok, Result};
use clap::{Parser, Subcommand};
use mirror_core::{
    config::Config, engine::ActionKind, engine::reconcile, manifest::Manifest, scanner::Scanner,
    state::State, store::s3,
};

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
        Command::Status => status(&cli.config),
        Command::Snapshot => snapshot(&cli.config),
    }
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

fn status(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let state = State::open(&config.local.root)?;
    let baseline = state.baseline()?;

    let scanner = Scanner::new(&config.local.root, &config.local.ignore_file);
    let entries = scanner.scan(&baseline)?;

    // Remote reads land in the next step; an empty manifest means "bucket is empty".
    let remote = Manifest::new();
    let plan = reconcile(&entries, &baseline, &remote);

    if plan.is_empty() {
        println!("up to date ({} files)", entries.len());
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
