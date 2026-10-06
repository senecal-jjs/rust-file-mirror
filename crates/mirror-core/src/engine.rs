use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;
use crate::manifest::{DeltaEntry, Manifest};
use crate::placeholder::StubMeta;
use crate::residency::{Mode, Policy};
use crate::scanner::LocalEntry;
use crate::state::{Baseline, FileRecord};

/// Variant order is execution order: transfers before deletes, so an interrupted
/// sync leaves extra data rather than missing data  
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActionKind {
    Download,
    /// Download into the place of a placeholder.
    Hydrate,
    /// Re-encrypt another path's version under this path; leaves a placeholder.
    Relocate,
    Upload,
    /// Metadata only: a new remote file arrives as a placeholder.
    CreatePlaceholder,
    /// Metadata only: a placeholder advances to the current remote version.
    UpdatePlaceholder,
    DeleteLocal,
    DeleteRemote,
    Conflict,
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Download => "download",
            Self::Hydrate => "hydrate",
            Self::Relocate => "relocate",
            Self::Upload => "upload",
            Self::CreatePlaceholder => "placeholder",
            Self::UpdatePlaceholder => "update-placeholder",
            Self::DeleteLocal => "delete-local",
            Self::DeleteRemote => "delete-remote",
            Self::Conflict => "conflict",
        };
        f.pad(text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub path: String,
    pub kind: ActionKind,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    pub actions: Vec<Action>,
    /// Source version for each `Relocate`, keyed by destination path.
    #[serde(default)]
    pub relocations: BTreeMap<String, DeltaEntry>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    pub fn count(&self, kind: ActionKind) -> usize {
        self.actions.iter().filter(|a| a.kind == kind).count()
    }
}

/// How one side moved relative to the last state both sides agreed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Unchanged,
    Created,
    Modified,
    Deleted,
}

fn classify(current: Option<ContentHash>, base: Option<ContentHash>) -> Change {
    match (current, base) {
        (None, None) => Change::Unchanged,
        (None, Some(_)) => Change::Deleted,
        (Some(_), None) => Change::Created,
        (Some(c), Some(b)) if c == b => Change::Unchanged,
        _ => Change::Modified,
    }
}

/// Device-local residency inputs. Never derived from, or written to, the remote log.
pub struct ResidencyView<'a> {
    /// Placeholders found by the scan, keyed by the path they stand in for.
    pub placeholders: &'a BTreeMap<String, StubMeta>,
    pub policy: &'a Policy,
    /// Placeholders explicitly asked to be hydrated this pass.
    pub hydrate: &'a BTreeSet<String>,
}

/// Pure: no IO, no clock, no randomness. Everything it needs is an argument.
pub fn reconcile(local: &[LocalEntry], baseline: &Baseline, remote: &Manifest) -> Plan {
    let view = ResidencyView {
        placeholders: &BTreeMap::new(),
        policy: &Policy::default(),
        hydrate: &BTreeSet::new(),
    };

    reconcile_with(local, baseline, remote, &view)
}

/// `reconcile`, plus placeholders and residency policy.
pub fn reconcile_with(
    local: &[LocalEntry],
    baseline: &Baseline,
    remote: &Manifest,
    view: &ResidencyView,
) -> Plan {
    let local: BTreeMap<&str, &LocalEntry> = local.iter().map(|e| (e.path.as_str(), e)).collect();

    let mut paths: BTreeSet<&str> = BTreeSet::new();
    paths.extend(local.keys().copied());
    paths.extend(baseline.keys().map(String::as_str));
    paths.extend(remote.keys().map(String::as_str));
    paths.extend(view.placeholders.keys().map(String::as_str));

    let mut actions = Vec::new();
    let mut relocations = BTreeMap::new();

    for path in paths {
        let record = baseline.get(path);
        let base = record.and_then(|r| r.last_synced_hash);
        let here = local.get(path).map(|e| e.hash);
        let there = remote.get(path).and_then(|e| {
            if e.deleted {
                None
            } else {
                Some(e.plaintext_hash)
            }
        });

        let there_change = classify(there, base);

        // A real file always wins over a placeholder or an evicted flag.
        let kind = if here.is_some() {
            decide(classify(here, base), there_change, here, there)
        } else if let Some(meta) = view.placeholders.get(path) {
            placeholder_action(
                path,
                meta,
                record,
                there_change,
                remote,
                view,
                &mut relocations,
            )
        } else if record.is_some_and(FileRecord::is_evicted) {
            // The user deleted the placeholder, which deletes the file.
            match there_change {
                Change::Unchanged => Some(ActionKind::DeleteRemote),
                // No local bytes exist to preserve, so the remote edit wins.
                Change::Created | Change::Modified => Some(ActionKind::Hydrate),
                Change::Deleted => Some(ActionKind::DeleteLocal),
            }
        } else {
            match decide(classify(None, base), there_change, None, there) {
                Some(ActionKind::Download) if view.policy.arrives_online_only(path) => {
                    Some(ActionKind::CreatePlaceholder)
                }
                other => other,
            }
        };

        if let Some(kind) = kind {
            actions.push(Action {
                path: path.to_string(),
                kind,
            });
        }
    }

    actions.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.path.cmp(&b.path)));

    Plan {
        actions,
        relocations,
    }
}

/// A placeholder with no real file beside it.
fn placeholder_action(
    path: &str,
    meta: &StubMeta,
    record: Option<&FileRecord>,
    there_change: Change,
    remote: &Manifest,
    view: &ResidencyView,
    relocations: &mut BTreeMap<String, DeltaEntry>,
) -> Option<ActionKind> {
    // Moved or copied from another path: re-encrypt that path's version under this one.
    if meta.path != path {
        let source = remote.get(&meta.path).filter(|e| !e.deleted)?;
        relocations.insert(path.to_string(), source.clone());
        return Some(ActionKind::Relocate);
    }

    let wants_local = view.hydrate.contains(path) || view.policy.mode(path) == Mode::Local;
    let refresh = if wants_local {
        ActionKind::Hydrate
    } else {
        ActionKind::UpdatePlaceholder
    };

    match (record.and_then(|r| r.last_synced_hash), there_change) {
        // Orphan placeholder (e.g. lost state DB): adopt it while the remote still has the file.
        (None, Change::Created) => Some(refresh),
        (None, _) => None,
        (Some(_), Change::Unchanged) => {
            if wants_local {
                Some(ActionKind::Hydrate)
            } else if record.is_some_and(FileRecord::is_evicted) {
                None
            } else {
                Some(ActionKind::UpdatePlaceholder)
            }
        }
        (Some(_), Change::Created | Change::Modified) => Some(refresh),
        (Some(_), Change::Deleted) => Some(ActionKind::DeleteLocal),
    }
}

fn decide(
    here: Change,
    there: Change,
    local_hash: Option<ContentHash>,
    remote_hash: Option<ContentHash>,
) -> Option<ActionKind> {
    use Change::{Created, Deleted, Modified, Unchanged};

    match (here, there) {
        (Unchanged, Unchanged) => None,
        (Unchanged, Created | Modified) => Some(ActionKind::Download),
        (Unchanged, Deleted) => Some(ActionKind::DeleteLocal),
        (Created | Modified, Unchanged) => Some(ActionKind::Upload),
        // Both moved. Identical content is convergence, not conflict
        (Created | Modified, Created | Modified) => {
            if local_hash == remote_hash {
                None
            } else {
                Some(ActionKind::Conflict)
            }
        }
        // Delete vs edit always resolves toward keeping data.
        (Created | Modified, Deleted) | (Deleted, Created | Modified) => Some(ActionKind::Conflict),
        // (Created | Modified, Deleted) => Some(ActionKind::Upload),
        // (Deleted, Created | Modified) => Some(ActionKind::Download),
        (Deleted, Unchanged) => Some(ActionKind::DeleteRemote),
        (Deleted, Deleted) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{manifest::DeltaEntry, state::FileRecord};

    fn h(byte: u8) -> ContentHash {
        ContentHash::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn local(hash: Option<ContentHash>) -> Vec<LocalEntry> {
        hash.into_iter()
            .map(|hash| LocalEntry {
                path: "f".to_string(),
                size: 1,
                mtime_ns: 0,
                hash,
            })
            .collect()
    }

    fn baseline(synced: Option<ContentHash>) -> Baseline {
        let mut map = Baseline::new();
        if let Some(hash) = synced {
            map.insert("f".to_string(), FileRecord::synced("f", 1, hash));
        }
        map
    }

    fn remote(hash: Option<ContentHash>) -> Manifest {
        let mut map = Manifest::new();
        if let Some(content_hash) = hash {
            map.insert(
                "f".to_string(),
                DeltaEntry {
                    path: "f".to_string(),
                    object_key: "doesn't matter".to_string(),
                    plaintext_hash: content_hash,
                    size: 1,
                    mtime_utc: 0,
                    deleted: false,
                    deleted_at: 0,
                    lamport: 0,
                    device_id: "test-device".to_string(),
                    base_hash: None,
                },
            );
        }
        map
    }

    /// (local, base, remote) -> expected action
    fn case(l: Option<u8>, b: Option<u8>, r: Option<u8>, expected: Option<ActionKind>) {
        let plan = reconcile(&local(l.map(h)), &baseline(b.map(h)), &remote(r.map(h)));
        let got = plan.actions.first().map(|a| a.kind);
        assert_eq!(got, expected, "local={l:?} base={b:?} remote={r:?}");
    }

    #[test]
    fn decision_matrix() {
        // nothing changed
        case(Some(1), Some(1), Some(1), None);

        // one-sided changes
        case(Some(2), Some(1), Some(1), Some(ActionKind::Upload));
        case(Some(1), Some(1), Some(2), Some(ActionKind::Download));
        case(Some(1), None, None, Some(ActionKind::Upload));
        case(None, None, Some(1), Some(ActionKind::Download));

        // deletes
        case(None, Some(1), Some(1), Some(ActionKind::DeleteRemote));
        case(Some(1), Some(1), None, Some(ActionKind::DeleteLocal));
        case(None, Some(1), None, None);

        // both sides moved
        case(Some(2), Some(1), Some(3), Some(ActionKind::Conflict));
        case(Some(2), Some(1), Some(2), None);
        case(Some(2), None, Some(3), Some(ActionKind::Conflict));
        case(Some(2), None, Some(2), None);

        // delete versus edit keeps data
        case(None, Some(1), Some(2), Some(ActionKind::Conflict));
        // case(None, Some(1), Some(2), Some(ActionKind::Download));
        case(Some(2), Some(1), None, Some(ActionKind::Conflict));
        // case(Some(2), Some(1), None, Some(ActionKind::Upload));
    }

    #[test]
    fn actions_are_ordered_transfers_before_deletes() {
        let mut baseline = Baseline::new();

        for (path, hash) in [("gone", h(1)), ("keep", h(2))] {
            baseline.insert(path.to_string(), FileRecord::synced(path, 1, hash));
        }

        let entries = vec![LocalEntry {
            path: "keep".to_string(),
            size: 1,
            mtime_ns: 0,
            hash: h(9),
        }];

        let mut remote = Manifest::new();

        remote.insert(
            "gone".to_string(),
            DeltaEntry {
                path: "gone".to_string(),
                object_key: "doesn't matter".to_string(),
                plaintext_hash: h(1),
                size: 1,
                mtime_utc: 0,
                deleted: false,
                deleted_at: 0,
                lamport: 0,
                device_id: "test-device".to_string(),
                base_hash: None,
            },
        );

        let plan = reconcile(&entries, &baseline, &remote);
        let kinds: Vec<_> = plan.actions.iter().map(|a| a.kind).collect();

        assert_eq!(kinds, vec![ActionKind::DeleteRemote, ActionKind::Conflict]);
    }

    #[derive(Clone, Copy)]
    enum Local {
        Real(u8),
        Stub,
        Gone,
    }

    /// Residency cases: (local, evicted baseline hash, remote, mode) -> expected action.
    fn residency_case(
        l: Local,
        b: Option<u8>,
        evicted: bool,
        r: Option<u8>,
        mode: Mode,
        expected: Option<ActionKind>,
    ) {
        let mut base = baseline(b.map(h));
        if evicted && let Some(record) = base.get_mut("f") {
            record.residency = crate::state::Residency::Evicted;
        }

        let (entries, placeholders) = match l {
            Local::Real(byte) => (local(Some(h(byte))), BTreeMap::new()),
            Local::Stub => {
                let meta = StubMeta::new("f", 1, h(b.unwrap_or(0)), "k", 0);
                (Vec::new(), BTreeMap::from([("f".to_string(), meta)]))
            }
            Local::Gone => (Vec::new(), BTreeMap::new()),
        };

        let policy = match mode {
            Mode::Auto => Policy::default(),
            other => Policy::new(&[("f".to_string(), other)], &[], &[], false).unwrap(),
        };
        let view = ResidencyView {
            placeholders: &placeholders,
            policy: &policy,
            hydrate: &BTreeSet::new(),
        };

        let plan = reconcile_with(&entries, &base, &remote(r.map(h)), &view);
        let got = plan.actions.first().map(|a| a.kind);
        assert_eq!(
            got, expected,
            "base={b:?} evicted={evicted} remote={r:?} mode={mode}"
        );
    }

    #[test]
    fn placeholder_matrix() {
        use ActionKind::*;
        use Local::*;

        // A placeholder counts as unchanged, never as a delete.
        residency_case(Stub, Some(1), true, Some(1), Mode::Auto, None);
        residency_case(
            Stub,
            Some(1),
            true,
            Some(2),
            Mode::Auto,
            Some(UpdatePlaceholder),
        );
        residency_case(Stub, Some(1), true, None, Mode::Auto, Some(DeleteLocal));

        // Pinned local hydrates.
        residency_case(Stub, Some(1), true, Some(1), Mode::Local, Some(Hydrate));
        residency_case(Stub, Some(1), true, Some(2), Mode::Local, Some(Hydrate));

        // Deleting the placeholder deletes the file, unless the remote moved on.
        residency_case(Gone, Some(1), true, Some(1), Mode::Auto, Some(DeleteRemote));
        residency_case(Gone, Some(1), true, Some(2), Mode::Auto, Some(Hydrate));
        residency_case(Gone, Some(1), true, None, Mode::Auto, Some(DeleteLocal));

        // A real file beside an evicted row wins and is reconciled normally.
        residency_case(Real(1), Some(1), true, Some(1), Mode::Auto, None);
        residency_case(Real(3), Some(1), true, Some(1), Mode::Auto, Some(Upload));

        // Orphan placeholder: adopted while the remote has the file.
        residency_case(
            Stub,
            None,
            false,
            Some(1),
            Mode::Auto,
            Some(UpdatePlaceholder),
        );
        residency_case(Stub, None, false, None, Mode::Auto, None);

        // New remote files on online-only paths arrive as placeholders.
        residency_case(
            Gone,
            None,
            false,
            Some(1),
            Mode::OnlineOnly,
            Some(CreatePlaceholder),
        );
        residency_case(Gone, None, false, Some(1), Mode::Auto, Some(Download));
    }

    #[test]
    fn moved_placeholder_relocates_and_old_path_is_deleted() {
        let mut base = Baseline::new();
        let mut old = FileRecord::synced("old", 1, h(1));
        old.residency = crate::state::Residency::Evicted;
        base.insert("old".to_string(), old);

        let mut entry = remote(Some(h(1))).remove("f").unwrap();
        entry.path = "old".to_string();
        let manifest = Manifest::from([("old".to_string(), entry.clone())]);

        let placeholders =
            BTreeMap::from([("new".to_string(), StubMeta::new("old", 1, h(1), "k", 0))]);
        let view = ResidencyView {
            placeholders: &placeholders,
            policy: &Policy::default(),
            hydrate: &BTreeSet::new(),
        };

        let plan = reconcile_with(&[], &base, &manifest, &view);
        let kinds: Vec<_> = plan
            .actions
            .iter()
            .map(|a| (a.path.as_str(), a.kind))
            .collect();

        assert_eq!(
            kinds,
            vec![
                ("new", ActionKind::Relocate),
                ("old", ActionKind::DeleteRemote)
            ]
        );
        assert_eq!(plan.relocations.get("new"), Some(&entry));
    }

    #[test]
    fn explicit_hydrate_request_hydrates_an_unchanged_placeholder() {
        let mut base = baseline(Some(h(1)));
        base.get_mut("f").unwrap().residency = crate::state::Residency::Evicted;
        let placeholders = BTreeMap::from([("f".to_string(), StubMeta::new("f", 1, h(1), "k", 0))]);
        let view = ResidencyView {
            placeholders: &placeholders,
            policy: &Policy::default(),
            hydrate: &BTreeSet::from(["f".to_string()]),
        };

        let plan = reconcile_with(&[], &base, &remote(Some(h(1))), &view);
        assert_eq!(plan.actions[0].kind, ActionKind::Hydrate);
    }
}
