use crate::{engine::Action, error::Result};

/// Phase 1 doesn't resolve conflicts — that's phase 4's job, once devices can tell
/// causal history apart. For now, leave both sides untouched and surface it; touching
/// either the local file, the remote object, or the baseline here would be a guess.
pub(crate) fn conflict(action: &Action) -> Result<()> {
    tracing::warn!(
        path = %action.path,
        "conflict: local and remote both changed; leaving untouched"
    );

    println!("On conflict do nothing {:<14} {}", action.kind, action.path);

    Ok(())
}
