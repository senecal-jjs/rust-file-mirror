//! Sync passes and their human-readable summaries, shared by the one-shot
//! commands and the `watch` daemon.

use std::sync::Arc;

use anyhow::Result;
use mirror_core::{
    config::Config,
    crypto::key::DerivedSubKeys,
    indicator::ProgressReporter,
    residency,
    state::State,
    store::s3::S3Store,
    sync::{SyncOptions, SyncOutcome},
};

/// An evict/hydrate request, run directly or forwarded to a running daemon.
pub(crate) struct ResidencyRequest {
    pub(crate) hydrate: bool,
    pub(crate) verify: bool,
    pub(crate) patterns: Vec<String>,
}

impl ResidencyRequest {
    /// One tab-separated line: `evict|hydrate`, verify flag, then the patterns.
    pub(crate) fn to_line(&self) -> String {
        let verb = if self.hydrate { "hydrate" } else { "evict" };
        let mut fields = vec![verb.to_string(), u8::from(self.verify).to_string()];
        fields.extend(self.patterns.iter().cloned());
        format!("{}\n", fields.join("\t"))
    }

    pub(crate) fn from_line(line: &str) -> Option<Self> {
        let mut fields = line.split('\t');
        let hydrate = match fields.next()? {
            "hydrate" => true,
            "evict" => false,
            _ => return None,
        };
        let verify = fields.next()? == "1";
        let patterns: Vec<String> = fields
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();

        (!patterns.is_empty()).then_some(Self {
            hydrate,
            verify,
            patterns,
        })
    }
}

pub(crate) fn summary(outcome: &SyncOutcome) -> String {
    let mut text = format!(
        "{} upload, {} download, {} delete-remote, {} delete-local, {} conflict",
        outcome.uploads,
        outcome.downloads,
        outcome.deletes_remote,
        outcome.deletes_local,
        outcome.conflicts,
    );

    if outcome.hydrated + outcome.placeholders + outcome.relocated + outcome.evicted > 0 {
        text.push_str(&format!(
            ", {} hydrate, {} placeholder, {} relocate, {} evict ({} freed)",
            outcome.hydrated,
            outcome.placeholders,
            outcome.relocated,
            outcome.evicted,
            human_bytes(outcome.bytes_freed),
        ));
    }

    text
}

pub(crate) fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;

    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub(crate) fn residency_summary(outcome: &SyncOutcome, request: &ResidencyRequest) -> String {
    let mut text = if request.hydrate {
        format!("hydrated {} file(s)\n", outcome.hydrated)
    } else {
        format!(
            "evicted {} file(s), freed {}\n",
            outcome.evicted,
            human_bytes(outcome.bytes_freed)
        )
    };

    for (path, reason) in &outcome.not_evicted {
        text.push_str(&format!("  skipped  {path}: {reason}\n"));
    }

    text
}

pub(crate) async fn run_sync(
    store: &Arc<S3Store>,
    config: &Config,
    enc_keys: &Arc<DerivedSubKeys>,
    state: &mut State,
    reporter: &Arc<dyn ProgressReporter>,
) -> Result<SyncOutcome> {
    // Rebuilt every pass so `rfm pin` changes apply without restarting the daemon.
    let options = SyncOptions::from_config(&config.offline, state)?;
    run_sync_with(store, config, enc_keys, state, reporter, &options).await
}

pub(crate) async fn run_sync_with(
    store: &Arc<S3Store>,
    config: &Config,
    enc_keys: &Arc<DerivedSubKeys>,
    state: &mut State,
    reporter: &Arc<dyn ProgressReporter>,
    options: &SyncOptions,
) -> Result<SyncOutcome> {
    let outcome = mirror_core::sync::sync_once(
        Arc::clone(store),
        &config.local.root,
        &config.remote.prefix,
        &config.local.ignore_file,
        Arc::clone(enc_keys),
        state,
        Arc::clone(reporter),
        options,
    )
    .await?;

    Ok(outcome)
}

/// A sync pass that also evicts or hydrates the files `request` selects.
pub(crate) async fn residency_pass(
    store: &Arc<S3Store>,
    config: &Config,
    enc_keys: &Arc<DerivedSubKeys>,
    state: &mut State,
    reporter: &Arc<dyn ProgressReporter>,
    request: &ResidencyRequest,
) -> Result<SyncOutcome> {
    let baseline = state.baseline()?;
    let mut options = SyncOptions::from_config(&config.offline, state)?;
    let candidates = baseline
        .values()
        .filter(|record| record.is_evicted() == request.hydrate)
        .map(|record| record.path.as_str());
    let selected = residency::select(&request.patterns, candidates)?;

    if selected.is_empty() {
        anyhow::bail!(
            "no {} files match {}",
            if request.hydrate {
                "online-only"
            } else {
                "local"
            },
            request.patterns.join(" ")
        );
    }

    if request.hydrate {
        options.hydrate = selected;
    } else {
        options.evict = selected;
        options.verify_before_evict |= request.verify;
    }

    run_sync_with(store, config, enc_keys, state, reporter, &options).await
}
