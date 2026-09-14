//! Pure, IO-free property tests for `merge_deltas` — the heart of multi-device
//! convergence. These are fast (no store, no filesystem) and shrink to minimal
//! counterexamples, so they're the first line of defence for the merge rules in
//! plan §4.4: a device must reach the same merged manifest regardless of the
//! order it happens to read deltas in, and re-reading deltas it already folded
//! in must be a no-op.

use mirror_core::hash::{self, ContentHash};
use mirror_core::manifest::{DeltaEntry, Manifest, merge_deltas};
use proptest::prelude::*;

/// A tiny fixed universe of contents, so distinct deltas frequently collide on
/// the same path/hash and actually exercise the fast-forward / converge /
/// conflict branches instead of trivially inserting unrelated entries.
fn content_hash(idx: u8) -> ContentHash {
    hash::hash_bytes(&[idx])
}

/// One generated delta, described by just the fields `merge_deltas` reasons
/// about. Everything else is derived deterministically so the *same* logical
/// delta always produces a byte-identical `DeltaEntry` — required for the
/// order-independence comparison to be over full `DeltaEntry` equality.
#[derive(Debug, Clone)]
struct DeltaSpec {
    path: u8,
    hash: u8,
    base: Option<u8>,
    lamport: u64,
    device: u8,
    /// Sort key used to derive an arbitrary permutation of the delta list.
    perm: u64,
}

fn delta_from_spec(spec: &DeltaSpec) -> DeltaEntry {
    let path = format!("p{}", spec.path);
    DeltaEntry {
        object_key: format!("obj-{path}"),
        path,
        plaintext_hash: content_hash(spec.hash),
        size: u64::from(spec.hash),
        mtime_utc: spec.lamport,
        deleted: false,
        deleted_at: 0,
        lamport: spec.lamport,
        device_id: format!("d{}", spec.device),
        base_hash: spec.base.map(content_hash),
    }
}

fn spec_strategy() -> impl Strategy<Value = DeltaSpec> {
    (
        0u8..3, // path
        0u8..4, // hash
        proptest::option::of(0u8..4),
        0u64..6, // lamport
        0u8..3,  // device
        any::<u64>(),
    )
        .prop_map(|(path, hash, base, lamport, device, perm)| DeltaSpec {
            path,
            hash,
            base,
            lamport,
            device,
            perm,
        })
}

fn permute(specs: &[DeltaSpec]) -> Vec<DeltaEntry> {
    let mut ordered: Vec<&DeltaSpec> = specs.iter().collect();
    ordered.sort_by_key(|spec| spec.perm);
    ordered.into_iter().map(delta_from_spec).collect()
}

proptest! {
    /// Order independence: the merged manifest is a function of the *set* of
    /// deltas, not the order they were read. Two arbitrary permutations of the
    /// same deltas must fold to an identical manifest.
    #[test]
    fn merge_is_order_independent(specs in proptest::collection::vec(spec_strategy(), 0..12)) {
        let forward: Vec<DeltaEntry> = specs.iter().map(delta_from_spec).collect();
        let shuffled = permute(&specs);

        let a = merge_deltas(&Manifest::new(), &forward).manifest;
        let b = merge_deltas(&Manifest::new(), &shuffled).manifest;

        prop_assert_eq!(a, b);
    }

    /// Idempotence: re-reading deltas already folded in changes nothing. Folding
    /// the same deltas twice must equal folding them once.
    #[test]
    fn merge_is_idempotent(specs in proptest::collection::vec(spec_strategy(), 0..12)) {
        let deltas: Vec<DeltaEntry> = specs.iter().map(delta_from_spec).collect();

        let once = merge_deltas(&Manifest::new(), &deltas).manifest;

        let doubled: Vec<DeltaEntry> = deltas.iter().chain(deltas.iter()).cloned().collect();
        let twice = merge_deltas(&Manifest::new(), &doubled).manifest;

        prop_assert_eq!(once, twice);
    }

    /// Folding onto an existing snapshot is equivalent to folding the snapshot's
    /// own entries (as deltas) followed by the new deltas onto an empty base —
    /// the snapshot is just pre-folded history.
    #[test]
    fn snapshot_is_prefolded_history(
        base in proptest::collection::vec(spec_strategy(), 0..6),
        extra in proptest::collection::vec(spec_strategy(), 0..8),
    ) {
        let base_deltas: Vec<DeltaEntry> = base.iter().map(delta_from_spec).collect();
        let snapshot = merge_deltas(&Manifest::new(), &base_deltas).manifest;

        let extra_deltas: Vec<DeltaEntry> = extra.iter().map(delta_from_spec).collect();
        let via_snapshot = merge_deltas(&snapshot, &extra_deltas).manifest;

        let combined: Vec<DeltaEntry> = snapshot
            .values()
            .cloned()
            .chain(extra_deltas.iter().cloned())
            .collect();
        let via_deltas = merge_deltas(&Manifest::new(), &combined).manifest;

        prop_assert_eq!(via_snapshot, via_deltas);
    }
}
