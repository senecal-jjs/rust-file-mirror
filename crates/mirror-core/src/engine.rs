use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::hash::ContentHash;
use crate::manifest::Manifest;
use crate::scanner::LocalEntry;
use crate::state::Baseline;

/// Variant order is execution order: transfers before deletes, so an interrupted
/// sync leaves extra data rather than missing data  
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionKind {
    Download,
    Upload,
    DeleteLocal,
    DeleteRemote,
    Conflict,
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Download => "download",
            Self::Upload => "upload",
            Self::DeleteLocal => "delete-local",
            Self::DeleteRemote => "delete-remote",
            Self::Conflict => "conflict",
        };
        f.pad(text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub path: String,
    pub kind: ActionKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub actions: Vec<Action>,
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

/// Pure: no IO, no clock, no randomness. Everything it needs is an argument.
pub fn reconcile(local: &[LocalEntry], baseline: &Baseline, remote: &Manifest) -> Plan {
    let local: BTreeMap<&str, &LocalEntry> = local.iter().map(|e| (e.path.as_str(), e)).collect();

    let mut paths: BTreeSet<&str> = BTreeSet::new();
    paths.extend(local.keys().copied());
    paths.extend(baseline.keys().map(String::as_str));
    paths.extend(remote.keys().map(String::as_str));

    let mut actions = Vec::new();

    for path in paths {
        let base = baseline.get(path).and_then(|r| r.last_synced_hash);
        let here = local.get(path).map(|e| e.hash);
        let there = remote.get(path).map(|e| e.content_hash);

        let here_change = classify(here, base);
        let there_change = classify(there, base);

        if let Some(kind) = decide(here_change, there_change, here, there) {
            actions.push(Action {
                path: path.to_string(),
                kind,
            });
        }
    }

    actions.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.path.cmp(&b.path)));

    Plan { actions }
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
        (Deleted, Unchanged) => Some(ActionKind::DeleteRemote),
        (Deleted, Deleted) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ManifestEntry;
    use crate::state::FileRecord;

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
            map.insert(
                "f".to_string(),
                FileRecord {
                    path: "f".to_string(),
                    size: 1,
                    mtime_ns: 0,
                    content_hash: hash,
                    last_synced_hash: Some(hash),
                },
            );
        }
        map
    }

    fn remote(hash: Option<ContentHash>) -> Manifest {
        let mut map = Manifest::new();
        if let Some(content_hash) = hash {
            map.insert(
                "f".to_string(),
                ManifestEntry {
                    path: "f".to_string(),
                    content_hash,
                    size: 1,
                    object_key: "doesn't matter".to_string(),
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
        case(Some(2), Some(1), None, Some(ActionKind::Conflict));
    }

    #[test]
    fn actions_are_ordered_transfers_before_deletes() {
        let mut baseline = Baseline::new();

        for (path, hash) in [("gone", h(1)), ("keep", h(2))] {
            baseline.insert(
                path.to_string(),
                FileRecord {
                    path: path.to_string(),
                    size: 1,
                    mtime_ns: 0,
                    content_hash: hash,
                    last_synced_hash: Some(hash),
                },
            );
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
            ManifestEntry {
                path: "gone".to_string(),
                content_hash: h(1),
                size: 1,
                object_key: "doesn't matter".to_string(),
            },
        );

        let plan = reconcile(&entries, &baseline, &remote);
        let kinds: Vec<_> = plan.actions.iter().map(|a| a.kind).collect();

        assert_eq!(kinds, vec![ActionKind::DeleteRemote, ActionKind::Conflict]);
    }
}
