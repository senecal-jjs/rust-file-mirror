//! Forgetting old snapshots, and reclaiming the space only they used.
//!
//! # Choosing what to forget
//!
//! `select` applies a `KeepPolicy` to each host and set of paths separately, so
//! pruning one machine's nightly root backups never touches another's, or a weekly
//! backup of some other folder. A snapshot survives if any rule keeps it.
//!
//! # Reclaiming space
//!
//! Under an exclusive repository lock (so no backup is running anywhere; see
//! `lock`), `prune`:
//!
//! 1. deletes the forgotten snapshot objects;
//! 2. marks every blob the remaining snapshots reach (their trees and file chunks);
//! 3. writes one new index covering only packs still needed, then deletes the old
//!    index objects;
//! 4. deletes packs no remaining snapshot needs, including orphans from interrupted
//!    runs once they're older than `ORPHAN_GRACE` (until then the next backup may
//!    adopt them; see `Repository::adopt_orphans`).
//!
//! Backups chunk files in parallel, so a pack usually mixes blobs from several
//! files, and forgetting a snapshot leaves many packs only partly needed. A pack
//! whose unneeded share reaches `REPACK_THRESHOLD` is repacked: its needed blobs are
//! copied, still sealed, into new packs (uploaded before step 3), and the old pack
//! is deleted in step 4. Packs below the threshold are kept whole and reported.
//!
//! Each step leaves a consistent repository if it's the last one to run: a crash
//! only leaves unreferenced data, or duplicate copies, for the next prune.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{Datelike, TimeZone};
use futures_util::future::BoxFuture;
use mirror_core::config::KeepPolicy;
use mirror_core::store::ObjectStore;

use crate::cache::Kind;
use crate::crypto::Id;
use crate::error::{Error, Result};
use crate::index::{self, Index, PackEntries, list_ids};
use crate::lock::Lock;
use crate::pack::{self, SealedBlob, Writer};
use crate::repo::Repository;
use crate::snapshot::{self, NodeType, Snapshot, Tree};

/// Packs no index lists (an interrupted run's uploads) are kept this long, so the
/// next backup can adopt them rather than upload their contents again.
pub const ORPHAN_GRACE: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// A partly needed pack is rewritten once at least this share of it is unneeded.
pub const REPACK_THRESHOLD: f64 = 0.2;

/// Which snapshots survive, and why.
#[derive(Debug, Default)]
pub struct Selection {
    /// Newest first, each with the rules that kept it.
    pub keep: Vec<(Snapshot, Vec<&'static str>)>,
    /// Newest first.
    pub forget: Vec<Snapshot>,
}

/// Applies `policy` to `snapshots`, bucketing times in `tz` (so "daily" means the
/// caller's days). Each time rule keeps the newest snapshot in each of the N most
/// recent hours, days, weeks, months, or years that have one.
pub fn select<Tz>(snapshots: &[Snapshot], policy: &KeepPolicy, tz: &Tz) -> Result<Selection>
where
    Tz: TimeZone + 'static,
    Tz::Offset: std::fmt::Display,
{
    if policy.is_empty() {
        return Err(Error::Invalid(
            "no keep rules given; refusing to forget every snapshot".into(),
        ));
    }

    let mut groups: BTreeMap<(String, Vec<String>), Vec<&Snapshot>> = BTreeMap::new();
    for s in snapshots {
        let mut paths = s.paths.clone();
        paths.sort();
        groups
            .entry((s.hostname.clone(), paths))
            .or_default()
            .push(s);
    }

    type Bucket = Box<dyn Fn(&Snapshot) -> String>;
    let bucket = |format: &'static str| -> Bucket {
        let tz = tz.clone();
        Box::new(move |s: &Snapshot| s.time.with_timezone(&tz).format(format).to_string())
    };
    let rules: Vec<(&'static str, usize, Bucket)> = vec![
        (
            "last",
            policy.last,
            Box::new(|s: &Snapshot| s.id.to_string()),
        ),
        ("hourly", policy.hourly, bucket("%Y-%m-%d %H")),
        ("daily", policy.daily, bucket("%Y-%m-%d")),
        ("weekly", policy.weekly, {
            let tz = tz.clone();
            Box::new(move |s: &Snapshot| {
                let week = s.time.with_timezone(&tz).iso_week();
                format!("{}-{}", week.year(), week.week())
            })
        }),
        ("monthly", policy.monthly, bucket("%Y-%m")),
        ("yearly", policy.yearly, bucket("%Y")),
    ];

    let mut reasons: HashMap<Id, Vec<&'static str>> = HashMap::new();
    for mut group in groups.into_values() {
        group.sort_by(|a, b| b.time.cmp(&a.time).then(a.id.cmp(&b.id)));
        for (name, count, key) in &rules {
            let mut seen = HashSet::new();
            for s in &group {
                if seen.len() == *count {
                    break;
                }
                if seen.insert(key(s)) {
                    reasons.entry(s.id).or_default().push(name);
                }
            }
        }
    }

    let mut ordered: Vec<_> = snapshots.iter().collect();
    ordered.sort_by(|a, b| b.time.cmp(&a.time).then(a.id.cmp(&b.id)));
    let mut selection = Selection::default();
    for s in ordered {
        match reasons.remove(&s.id) {
            Some(why) => selection.keep.push((s.clone(), why)),
            None => selection.forget.push(s.clone()),
        }
    }
    Ok(selection)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub dry_run: bool,
    pub snapshots_forgotten: usize,
    pub packs_deleted: usize,
    pub bytes_freed: u64,
    /// Partly needed packs rewritten without their unneeded blobs (counted in
    /// `packs_deleted` too), and the bytes copied to do it.
    pub packs_repacked: usize,
    pub bytes_repacked: u64,
    /// Packs kept whole because some of their blobs are needed, and how many bytes
    /// in them aren't.
    pub packs_partly_used: usize,
    pub bytes_unused_in_kept_packs: u64,
    pub index_objects_replaced: usize,
    pub stale_locks_removed: usize,
    /// Recent packs no index lists, kept for the next backup to adopt.
    pub orphans_kept: usize,
}

/// Forgets `forget` and reclaims what only they used. With `dry_run`, works out
/// and reports the same without deleting anything (and without a lock).
pub async fn prune<S: ObjectStore + 'static>(
    repo: &Repository<S>,
    forget: &[Id],
    dry_run: bool,
) -> Result<Report> {
    if dry_run {
        return prune_locked(repo, forget, None).await;
    }
    let lock = Lock::acquire(
        std::sync::Arc::clone(repo.store()),
        repo.base(),
        repo.keys(),
        true,
    )
    .await?;
    let result = prune_locked(repo, forget, Some(&lock)).await;
    if let Err(e) = lock.release().await {
        tracing::warn!(error = %e, "releasing the repository lock failed; it expires on its own");
    }
    result
}

async fn prune_locked<S: ObjectStore + 'static>(
    repo: &Repository<S>,
    forget: &[Id],
    lock: Option<&Lock<S>>,
) -> Result<Report> {
    let store = repo.store().as_ref();
    let (base, keys, cache) = (repo.base(), repo.keys(), repo.cache());
    let mut report = Report {
        dry_run: lock.is_none(),
        ..Report::default()
    };
    if let Some(lock) = lock {
        report.stale_locks_removed = lock.remove_stale().await?;
    }

    // Fresh state, read under the lock: the caller's may predate a backup that has
    // finished since.
    let index = index::load(store, base, keys, cache).await?;
    let snapshots = snapshot::list(store, base, keys, cache).await?;
    let forget: HashSet<Id> = forget.iter().copied().collect();
    for id in &forget {
        if !snapshots.iter().any(|s| s.id == *id) {
            return Err(Error::SnapshotNotFound(format!(
                "no snapshot {}",
                id.short()
            )));
        }
    }
    let remaining: Vec<&Snapshot> = snapshots
        .iter()
        .filter(|s| !forget.contains(&s.id))
        .collect();
    report.snapshots_forgotten = forget.len();

    // Mark.
    let mut referenced = HashSet::new();
    for snapshot in &remaining {
        mark(repo, &index, snapshot.tree, &mut referenced).await?;
    }
    if let Some(missing) = referenced.iter().find(|id| !index.has(id)) {
        return Err(Error::Incomplete(format!(
            "a remaining snapshot references blob {}, which no index lists; run `rfm backup verify` \
             before pruning",
            missing.short()
        )));
    }

    // A pack is needed if a referenced blob's indexed location is in it.
    let mut by_pack: HashMap<Id, Vec<pack::Entry>> = HashMap::new();
    for location in index.locations() {
        by_pack
            .entry(location.pack_id)
            .or_default()
            .push(location.entry);
    }
    let stored = list_ids(store, base, "packs/").await?;
    let written: HashMap<Id, std::time::SystemTime> = store
        .list(&format!("{base}packs/"), None)
        .await?
        .into_iter()
        .filter_map(|meta| {
            Some((
                meta.key.rsplit('/').next()?.parse().ok()?,
                meta.last_modified?,
            ))
        })
        .collect();
    let now = std::time::SystemTime::now();
    let mut doomed = Vec::new();
    let mut kept = Vec::new();
    let mut repack = Vec::new();
    for (pack_id, size) in &stored {
        let Some(entries) = by_pack.remove(pack_id) else {
            // In no index: an interrupted run's. Recent ones wait to be adopted.
            let recent = written
                .get(pack_id)
                .is_none_or(|at| now.duration_since(*at).unwrap_or_default() < ORPHAN_GRACE);
            if recent {
                report.orphans_kept += 1;
            } else {
                doomed.push(*pack_id);
                report.bytes_freed += size;
            }
            continue;
        };
        let (needed, unneeded): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .partition(|e| referenced.contains(&e.id));
        let unused: u64 = unneeded.iter().map(|e| u64::from(e.length)).sum();
        let needed_bytes: u64 = needed.iter().map(|e| u64::from(e.length)).sum();
        if needed.is_empty() {
            doomed.push(*pack_id);
            report.bytes_freed += size;
        } else if unused as f64 >= REPACK_THRESHOLD * *size as f64 {
            report.packs_repacked += 1;
            report.bytes_repacked += needed_bytes;
            report.bytes_freed += size - needed_bytes;
            repack.push((*pack_id, needed));
        } else {
            if unused > 0 {
                report.packs_partly_used += 1;
                report.bytes_unused_in_kept_packs += unused;
            }
            let mut all = needed;
            all.extend(unneeded);
            kept.push(PackEntries {
                pack_id: *pack_id,
                entries: all,
            });
        }
    }
    report.packs_deleted = doomed.len() + repack.len();

    let Some(lock) = lock else {
        return Ok(report);
    };

    // Sweep, in an order where stopping after any step leaves a consistent
    // repository (see the module docs).
    lock.ensure_held()?;
    for id in &forget {
        store
            .delete(&format!("{base}{}", snapshot::object_name(id)))
            .await?;
        if let Some(cache) = cache {
            cache.remove(Kind::Snapshot, id);
        }
    }

    // New packs first: until the index changes they're harmless orphans.
    for (pack_id, needed) in &repack {
        kept.extend(copy_needed(repo, pack_id, needed).await?);
        doomed.push(*pack_id);
    }

    if !doomed.is_empty() {
        let old_indexes = index.source_ids();
        if !kept.is_empty() {
            index::save(store, base, keys, &kept, cache).await?;
        }
        lock.ensure_held()?;
        for id in &old_indexes {
            store
                .delete(&format!("{base}{}", index::object_name(id)))
                .await?;
            if let Some(cache) = cache {
                cache.remove(Kind::Index, id);
            }
        }
        report.index_objects_replaced = old_indexes.len();
        for pack_id in &doomed {
            store
                .delete(&format!("{base}{}", pack::object_name(pack_id)))
                .await?;
        }
    }
    Ok(report)
}

/// Copies `needed` blobs out of `pack_id` into new packs, checking each one decodes
/// first so corruption is never carried over. Returns the new packs' entries.
async fn copy_needed<S: ObjectStore>(
    repo: &Repository<S>,
    pack_id: &Id,
    needed: &[pack::Entry],
) -> Result<Vec<PackEntries>> {
    let data = repo
        .store()
        .get(&repo.object_key(&pack::object_name(pack_id)))
        .await?;
    let mut written = Vec::new();
    let mut writer = Writer::new(repo.config().compression);
    for entry in needed {
        let sealed = data
            .get(entry.offset as usize..entry.end() as usize)
            .ok_or_else(|| {
                Error::Format(format!(
                    "pack {} is shorter than its index says",
                    pack_id.short()
                ))
            })?;
        pack::decode_blob(repo.keys(), entry, sealed)?;
        writer.push(SealedBlob::from_entry(entry, sealed.to_vec()))?;
        if writer.size() >= pack::TARGET_SIZE {
            let full = std::mem::replace(&mut writer, Writer::new(repo.config().compression));
            written.push(upload(repo, full).await?);
        }
    }
    if writer.count() > 0 {
        written.push(upload(repo, writer).await?);
    }
    Ok(written)
}

async fn upload<S: ObjectStore>(repo: &Repository<S>, writer: Writer) -> Result<PackEntries> {
    let pack = writer.finish(repo.keys())?;
    repo.store()
        .put_bytes(&repo.object_key(&pack::object_name(&pack.id)), &pack.data)
        .await?;
    Ok(PackEntries {
        pack_id: pack.id,
        entries: pack.entries,
    })
}

/// Adds every blob reachable from `tree` (the trees themselves and file chunks) to
/// `referenced`. Reads through `index`, the freshly loaded one, rather than the
/// repository's own.
fn mark<'a, S: ObjectStore>(
    repo: &'a Repository<S>,
    index: &'a Index,
    tree: Id,
    referenced: &'a mut HashSet<Id>,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        if !referenced.insert(tree) {
            return Ok(()); // shared subtrees are walked once
        }
        let location = index
            .lookup(&tree)
            .ok_or_else(|| Error::Incomplete(format!("tree {} is in no index", tree.short())))?;
        let key = repo.object_key(&pack::object_name(&location.pack_id));
        let plaintext =
            pack::load_blob(repo.store().as_ref(), &key, repo.keys(), &location.entry).await?;
        for node in Tree::decode(&plaintext)?.nodes {
            match node.node_type {
                NodeType::Dir => {
                    let subtree = node.subtree.expect("validated by Tree::decode");
                    mark(repo, index, subtree, referenced).await?;
                }
                NodeType::File => referenced.extend(node.content),
                NodeType::Symlink => {}
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration, Utc};

    fn snap(at: &str, host: &str, paths: &[&str]) -> Snapshot {
        Snapshot {
            id: Id::random(),
            time: DateTime::parse_from_rfc3339(at)
                .unwrap()
                .with_timezone(&Utc),
            hostname: host.into(),
            username: String::new(),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            tags: vec![],
            tree: Id::random(),
            parent: None,
            stats: Default::default(),
        }
    }

    fn kept_times(selection: &Selection) -> Vec<String> {
        selection
            .keep
            .iter()
            .map(|(s, _)| s.time.format("%m-%d %H:%M").to_string())
            .collect()
    }

    #[test]
    fn empty_policy_is_refused() {
        assert!(
            select(
                &[snap("2026-01-01T00:00:00Z", "h", &["/a"])],
                &KeepPolicy::default(),
                &Utc
            )
            .is_err()
        );
    }

    #[test]
    fn keep_last() {
        let snaps: Vec<_> = (1..=5)
            .map(|d| snap(&format!("2026-01-0{d}T12:00:00Z"), "h", &["/a"]))
            .collect();
        let s = select(
            &snaps,
            &KeepPolicy {
                last: 2,
                ..Default::default()
            },
            &Utc,
        )
        .unwrap();
        assert_eq!(kept_times(&s), ["01-05 12:00", "01-04 12:00"]);
        assert_eq!(s.forget.len(), 3);
        assert_eq!(s.keep[0].1, ["last"]);
    }

    #[test]
    fn daily_keeps_the_newest_of_each_of_the_latest_days_that_have_one() {
        let snaps = vec![
            snap("2026-01-10T23:00:00Z", "h", &["/a"]),
            snap("2026-01-10T08:00:00Z", "h", &["/a"]),
            snap("2026-01-08T09:00:00Z", "h", &["/a"]), // a gap: the 9th has none
            snap("2026-01-07T09:00:00Z", "h", &["/a"]),
        ];
        let s = select(
            &snaps,
            &KeepPolicy {
                daily: 2,
                ..Default::default()
            },
            &Utc,
        )
        .unwrap();
        assert_eq!(kept_times(&s), ["01-10 23:00", "01-08 09:00"]);
    }

    #[test]
    fn days_follow_the_given_time_zone() {
        // 23:30 and 00:30 UTC are the same day at UTC-5.
        let snaps = vec![
            snap("2026-01-11T00:30:00Z", "h", &["/a"]),
            snap("2026-01-10T23:30:00Z", "h", &["/a"]),
        ];
        let policy = KeepPolicy {
            daily: 5,
            ..Default::default()
        };
        assert_eq!(select(&snaps, &policy, &Utc).unwrap().keep.len(), 2);
        let est = chrono::FixedOffset::west_opt(5 * 3600).unwrap();
        assert_eq!(select(&snaps, &policy, &est).unwrap().keep.len(), 1);
    }

    #[test]
    fn weekly_monthly_and_yearly_buckets() {
        let start = DateTime::parse_from_rfc3339("2026-12-31T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let snaps: Vec<_> = (0..400)
            .map(|d| {
                let mut s = snap("2026-01-01T00:00:00Z", "h", &["/a"]);
                s.time = start - Duration::days(d);
                s
            })
            .collect();
        let weekly = select(
            &snaps,
            &KeepPolicy {
                weekly: 4,
                ..Default::default()
            },
            &Utc,
        )
        .unwrap();
        assert_eq!(weekly.keep.len(), 4);
        let monthly = select(
            &snaps,
            &KeepPolicy {
                monthly: 3,
                ..Default::default()
            },
            &Utc,
        )
        .unwrap();
        assert_eq!(
            kept_times(&monthly),
            ["12-31 12:00", "11-30 12:00", "10-31 12:00"]
        );
        let yearly = select(
            &snaps,
            &KeepPolicy {
                yearly: 5,
                ..Default::default()
            },
            &Utc,
        )
        .unwrap();
        assert_eq!(yearly.keep.len(), 2, "400 days span 2026 and 2025");
    }

    #[test]
    fn rules_combine_and_record_every_reason() {
        let snaps: Vec<_> = (1..=4)
            .map(|d| snap(&format!("2026-01-0{d}T12:00:00Z"), "h", &["/a"]))
            .collect();
        let s = select(
            &snaps,
            &KeepPolicy {
                last: 1,
                daily: 2,
                ..Default::default()
            },
            &Utc,
        )
        .unwrap();
        assert_eq!(s.keep.len(), 2);
        assert_eq!(s.keep[0].1, ["last", "daily"]);
        assert_eq!(s.keep[1].1, ["daily"]);
    }

    #[test]
    fn hosts_and_path_sets_are_pruned_independently() {
        let snaps = vec![
            snap("2026-01-03T00:00:00Z", "laptop", &["/home"]),
            snap("2026-01-02T00:00:00Z", "laptop", &["/home"]),
            snap("2026-01-01T00:00:00Z", "laptop", &["/srv"]),
            snap("2025-06-01T00:00:00Z", "desktop", &["/home"]),
            snap("2025-05-01T00:00:00Z", "laptop", &["/b", "/a"]),
            snap("2025-04-01T00:00:00Z", "laptop", &["/a", "/b"]),
        ];
        let s = select(
            &snaps,
            &KeepPolicy {
                last: 1,
                ..Default::default()
            },
            &Utc,
        )
        .unwrap();
        let mut kept: Vec<_> = s
            .keep
            .iter()
            .map(|(s, _)| (s.hostname.as_str(), s.paths.join(",")))
            .collect();
        kept.sort();
        assert_eq!(
            kept,
            [
                ("desktop", "/home".into()),
                ("laptop", "/b,/a".into()),
                ("laptop", "/home".into()),
                ("laptop", "/srv".into())
            ]
        );
        assert_eq!(s.forget.len(), 2, "path order doesn't make a different set");
    }
}
