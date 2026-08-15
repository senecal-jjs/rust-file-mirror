use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Ok, Result};
use clap::{Parser, Subcommand};
use mirror_core::{config::Config, scanner::Scanner, state::State, store::S3Store};

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

    let store = S3Store::connect(&config.remote).await?;
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

    let seen: BTreeSet<&str> = entries.iter().map(|e| e.path.as_str()).collect();

    let (mut added, mut modified, mut unchanged, mut deleted) = (0, 0, 0, 0);

    for entry in &entries {
        match baseline.get(&entry.path) {
            None => {
                println!("new      {}", entry.path);
                added += 1
            }
            Some(record) if record.content_hash != entry.hash => {
                println!("modified       {}", entry.path);
                modified += 1
            }
            Some(_) => unchanged += 1,
        }
    }

    for path in baseline.keys() {
        if !seen.contains(path.as_str()) {
            println!("deleted      {path}");
            deleted += 1
        }
    }

    println!("\n{added} new, {modified} modified, {deleted} deleted, {unchanged} unchanged");
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
