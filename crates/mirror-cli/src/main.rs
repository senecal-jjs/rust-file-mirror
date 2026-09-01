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
    apply::{apply, execute::apply_remote_conflicts, upload::resume_upload},
    config::Config,
    crypto::{
        filename,
        key::{DerivedSubKeys, derive_application_keys},
        keyring,
        vault::{self, VaultHeader},
    },
    engine::{ActionKind, Plan, reconcile},
    indicator::{PrintReporter, ProgressReporter},
    manifest::{
        self, DeltaEntry, Manifest, MergeResult, RemoteConflict, merge_deltas, read_deltas,
    },
    scanner::{LocalEntry, Scanner},
    state::State,
    store::s3::{self, S3Store},
    util::file::hash_stable,
};
use rand::Rng;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::{
    collections::HashSet,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::indicator::VisualBarReporter;

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

/// Resumes every multipart upload left behind by an interrupted sync. Returns
/// the paths that were actually finished, so the caller can drop the redundant
/// `Upload` action a plan built before this ran would otherwise still contain
/// for each of them.
async fn resume_uploads(
    state: &mut State,
    store: &S3Store,
    manifest: &mut Manifest,
    enc_keys: &DerivedSubKeys,
    root: &Path,
    prefix: &str,
) -> Result<Vec<String>> {
    let uploads = state.pending_uploads()?;
    let mut resumed = Vec::new();

    for upload in uploads {
        let path_str = upload
            .path
            .to_str()
            .with_context(|| format!("non-UTF8 path in pending upload: {:?}", upload.path))?
            .to_string();
        let local_path = root.join(&upload.path);

        match hash_stable(&local_path)? {
            Some(stats) if stats.2 == upload.content_hash => {
                let result =
                    resume_upload(store, &upload, stats, enc_keys, root, prefix, state).await?;

                // What this device believed was current for this path before its
                // own edit — the merge rule's fast-forward check compares an
                // incoming delta's base_hash against this.
                let base_hash = manifest.get(&path_str).map(|e| e.plaintext_hash);
                let mtime_utc = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                manifest.insert(
                    path_str.clone(),
                    DeltaEntry {
                        path: path_str.clone(),
                        object_key: result.object_key,
                        plaintext_hash: result.content_hash,
                        size: result.size,
                        mtime_utc,
                        deleted: false,
                        deleted_at: 0,
                        lamport: state.get_latest_lamport()?,
                        device_id: state.device_id()?,
                        base_hash,
                    },
                );
                state.confirm_sync(&path_str, result.size, result.mtime_ns, result.content_hash)?;
                resumed.push(path_str);
            }
            // Either the file changed since the interrupted upload started (still
            // stable, just different content) or it's gone entirely — either way
            // the stale multipart upload can't be resumed safely. Drop tracking
            // and abort it so it doesn't sit there accruing storage charges.
            _ => {
                state.clear_upload(&path_str)?;
                let object_key = filename::object_key(&enc_keys.name_key, &path_str)?;
                let store_key = format!("{prefix}{object_key}");
                store
                    .abort_multipart_upload(&store_key, &upload.upload_id)
                    .await?;
            }
        }
    }

    Ok(resumed)
}

async fn sync(path: &Path) -> Result<()> {
    let config =
        Config::load(path).with_context(|| format!("loading config from {}", path.display()))?;

    let PlanResult {
        mut plan,
        mut manifest,
        mut state,
        store,
        local_entries,
        conflicts,
        remote_lamport,
    } = build_plan(&config).await?;

    for action in &plan.actions {
        println!("{:<14} {}", action.kind, action.path);
    }

    let content_enc_key = keyring::load_from_keyring(
        format!(
            "{}/{}:content_key",
            config.remote.bucket, config.remote.prefix
        )
        .as_str(),
    )?;

    let manifest_enc_key = keyring::load_from_keyring(
        format!(
            "{}/{}:manifest_key",
            config.remote.bucket, config.remote.prefix
        )
        .as_str(),
    )?;

    let name_enc_key = keyring::load_from_keyring(
        format!("{}/{}:name_key", config.remote.bucket, config.remote.prefix).as_str(),
    )?;

    let enc_keys = DerivedSubKeys {
        content_key: content_enc_key,
        manifest_key: manifest_enc_key,
        name_key: name_enc_key,
        keycheck_bytes: SecretBox::new(Box::new([0u8; 32])),
    };

    apply_remote_conflicts(
        &store,
        &mut manifest,
        &conflicts,
        &enc_keys.content_key,
        &enc_keys.name_key,
        config.local.root.clone(),
        config.remote.prefix.clone(),
        &mut state,
        &remote_lamport,
    )
    .await?;

    let resumed = resume_uploads(
        &mut state,
        &store,
        &mut manifest,
        &enc_keys,
        &config.local.root,
        &config.remote.prefix,
    )
    .await?;

    // Anything just finished by resume_uploads is already fully on the remote —
    // plan was built before that ran, so it still contains an Upload action for
    // each of them that would otherwise redundantly re-upload the whole file.
    plan.actions
        .retain(|action| !(action.kind == ActionKind::Upload && resumed.contains(&action.path)));

    let reporter: Arc<dyn ProgressReporter> = if std::io::stderr().is_terminal() {
        Arc::new(VisualBarReporter {
            multi: MultiProgress::new(),
        })
    } else {
        Arc::new(PrintReporter {})
    };

    apply(
        &plan,
        std::sync::Arc::new(store),
        config.local.root.clone(),
        config.remote.prefix.clone(),
        &mut state,
        &mut manifest,
        std::sync::Arc::new(enc_keys),
        reporter,
        &remote_lamport,
    )
    .await?;

    state.record_scan(&local_entries)?;

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
    pub manifest: Manifest,
    pub state: State,
    pub store: S3Store,
    pub local_entries: Vec<LocalEntry>,
    pub conflicts: Vec<RemoteConflict>,
    pub remote_lamport: u64,
}

async fn build_plan(config: &Config) -> Result<PlanResult> {
    let store = s3::S3Store::connect(&config.remote).await?;
    store.check().await.context("checking bucket")?;
    println!("bucket   ok   {}", config.remote.bucket);

    let mut state = State::open(&config.local.root)?;
    let baseline = state.baseline()?;

    let scanner = Scanner::new(&config.local.root, &config.local.ignore_file);
    let entries = scanner.scan(&baseline)?;

    let manifest_enc_key = keyring::load_from_keyring(
        format!(
            "{}/{}:manifest_key",
            config.remote.bucket, config.remote.prefix
        )
        .as_str(),
    )?;

    let snapshot =
        manifest::from_store(&store, &manifest_enc_key, &config.remote.prefix, &mut state).await?;
    let deltas = read_deltas(&store, &config.remote.prefix).await?;

    let MergeResult {
        manifest,
        conflicts,
        remote_lamport,
    } = merge_deltas(&snapshot, &deltas);

    let plan = reconcile(&entries, &baseline, &manifest);

    Ok(PlanResult {
        plan,
        manifest,
        state,
        store,
        local_entries: entries,
        conflicts,
        remote_lamport,
    })

    // Ok((plan, manifest, state, store, entries, conflicts))
}
