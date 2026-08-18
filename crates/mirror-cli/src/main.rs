use anyhow::{Context, Result};
use argon2::Params;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use clap::{Parser, Subcommand};
use mirror_core::{
    Error,
    apply::apply,
    config::Config,
    crypto::{
        key::derive_application_keys,
        vault::{self, VaultHeader},
    },
    engine::{ActionKind, Plan, reconcile},
    manifest::{self, Manifest},
    scanner::{LocalEntry, Scanner},
    state::State,
    store::s3::{self, S3Store},
};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
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

    /// Sync an action plan
    Sync,

    /// Initialize a vault
    Init,

    /// Unlock a vault
    Unlock,
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
        Command::Unlock => unlock(&cli.config).await,
    }
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
    let payload = "file mirror".as_bytes();
    let nonce = Nonce::from(vault_header.key_check_nonce);
    let key_check = cipher.encrypt(&nonce, payload)?;

    if key_check != vault_header.key_check {
        anyhow::bail!("passphrase incorrect");
    }

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

    let key = format!("{}vault.json", config.remote.prefix);

    if vault::load(&store, &config.remote.prefix).await?.is_some() {
        anyhow::bail!("vault already exists at {key} — refusing to overwrite");
    }

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
    // let config =
    //     Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    // let store = s3::S3Store::connect(&config.remote).await?;
    // store.check().await.context("checking bucket")?;
    // println!("bucket   ok   {}", config.remote.bucket);

    // let key = format!("{}vault.json", config.remote.prefix);

    // if vault::load(&store, &config.remote.prefix).await?.is_some() {
    //     anyhow::bail!("vault already exists at {key} — refusing to overwrite");
    // }

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

    println!(
        "vault    ok   {}vault.json",
        vault_connection.config.remote.prefix
    );
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
