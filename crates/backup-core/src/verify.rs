//! Checking that a repository is consistent and its data restorable.
//!
//! Two levels, because they answer different questions at very different cost:
//!
//! - **Structural** (default): every chunk every snapshot references resolves
//!   through the index to a pack that exists and is big enough to hold it, and
//!   every tree can be read. Only metadata is read (a listing plus snapshot and
//!   tree blobs), so it's cheap enough to run after every backup. It catches what
//!   actually goes wrong: a missing pack, an interrupted upload, a snapshot written
//!   against an index that never landed.
//! - **Full** (`read_data`): additionally downloads every pack, checks the index
//!   against each pack's own header, and decrypts every blob and recomputes its
//!   keyed ID. A match proves the bytes are exactly what was backed up. This is the
//!   only way to find silent corruption, and it costs a full download.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use futures_util::{StreamExt, stream};
use mirror_core::store::ObjectStore;

use crate::crypto::Id;
use crate::error::Result;
use crate::index::list_ids;
use crate::pack::{self, Entry};
use crate::repo::Repository;
use crate::snapshot::{NodeType, Snapshot};

pub const DEFAULT_CONCURRENCY: usize = 4;

pub type ProgressFn = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Default)]
pub struct Options {
    pub read_data: bool,
    /// Limit the snapshot walk to these; all snapshots when `None`.
    pub snapshots: Option<Vec<Snapshot>>,
    /// Packs downloaded at once with `read_data`.
    pub concurrency: usize,
    /// A short description of each stage.
    pub progress: Option<ProgressFn>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub snapshots_checked: usize,
    pub trees_checked: usize,
    pub blobs_referenced: usize,
    pub packs_referenced: usize,
    pub packs_in_storage: usize,
    pub bytes_read: u64,
    /// Packs no index lists: usually what an interrupted backup leaves. Harmless,
    /// but wasted space.
    pub orphan_packs: Vec<Id>,
    /// Everything wrong with the repository.
    pub problems: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

pub async fn verify<S: ObjectStore + 'static>(
    repo: &Repository<S>,
    options: Options,
) -> Result<Report> {
    let progress = |stage: &str| {
        if let Some(progress) = &options.progress {
            progress(stage);
        }
    };
    let mut report = Report::default();

    // Inventory what's actually stored, with sizes, so index entries can be checked
    // without a request each.
    progress("listing packs");
    let pack_sizes: HashMap<Id, u64> = list_ids(repo.store().as_ref(), repo.base(), "packs/")
        .await?
        .into_iter()
        .collect();
    report.packs_in_storage = pack_sizes.len();

    progress("checking the index");
    let index = repo.index();
    let referenced: HashSet<Id> = index.pack_ids().into_iter().collect();
    report.packs_referenced = referenced.len();
    for pack_id in &referenced {
        if !pack_sizes.contains_key(pack_id) {
            report.problems.push(format!(
                "pack {} is listed in an index but missing from storage",
                pack_id.short()
            ));
        }
    }
    for location in index.locations() {
        if let Some(&size) = pack_sizes.get(&location.pack_id)
            && location.entry.end() > size
        {
            report.problems.push(format!(
                "chunk {} claims bytes up to {} of pack {}, which is only {size} bytes",
                location.entry.id.short(),
                location.entry.end(),
                location.pack_id.short()
            ));
        }
    }
    let mut orphans: Vec<_> = pack_sizes
        .keys()
        .filter(|id| !referenced.contains(id))
        .copied()
        .collect();
    orphans.sort();
    report.orphan_packs = orphans;

    let snapshots = match options.snapshots.clone() {
        Some(snapshots) => snapshots,
        None => repo.list_snapshots().await?,
    };
    let mut seen_trees = HashSet::new();
    for snapshot in &snapshots {
        progress(&format!("checking snapshot {}", snapshot.id.short()));
        report.snapshots_checked += 1;
        check_tree(
            repo,
            snapshot.tree,
            "/".into(),
            &mut seen_trees,
            &mut report,
        )
        .await;
    }
    report.trees_checked = seen_trees.len();

    if options.read_data {
        progress("reading and verifying every pack");
        read_all_packs(repo, &pack_sizes, options.concurrency.max(1), &mut report).await;
    }

    Ok(report)
}

/// Confirms a tree is readable and every chunk its files name is indexed, with
/// lengths adding up to the recorded size. Shared trees are checked once, which
/// keeps verification proportional to unique data.
fn check_tree<'a, S: ObjectStore>(
    repo: &'a Repository<S>,
    tree_id: Id,
    path: String,
    seen: &'a mut HashSet<Id>,
    report: &'a mut Report,
) -> futures_util::future::BoxFuture<'a, ()> {
    Box::pin(async move {
        if !seen.insert(tree_id) {
            return;
        }
        let tree = match repo.load_tree(&tree_id).await {
            Ok(tree) => tree,
            Err(e) => {
                report
                    .problems
                    .push(format!("cannot read the directory tree for {path}: {e}"));
                return;
            }
        };

        for node in tree.nodes {
            let child = format!("{path}{}", node.name);
            match node.node_type {
                NodeType::Dir => {
                    let subtree = node.subtree.expect("validated by Tree::decode");
                    check_tree(repo, subtree, format!("{child}/"), seen, report).await;
                }
                NodeType::File => {
                    let mut total = 0u64;
                    let mut complete = true;
                    for chunk in &node.content {
                        report.blobs_referenced += 1;
                        match repo.index().lookup(chunk) {
                            Some(location) => total += u64::from(location.entry.plain_length),
                            None => {
                                complete = false;
                                report.problems.push(format!(
                                    "file {child} references chunk {}, which no index lists",
                                    chunk.short()
                                ));
                            }
                        }
                    }
                    if complete && total != node.size {
                        report.problems.push(format!(
                            "file {child} records {} bytes but its chunks hold {total}",
                            node.size
                        ));
                    }
                }
                NodeType::Symlink => {}
            }
        }
    })
}

/// Downloads every pack and checks it against the index and its own contents.
async fn read_all_packs<S: ObjectStore + 'static>(
    repo: &Repository<S>,
    pack_sizes: &HashMap<Id, u64>,
    concurrency: usize,
    report: &mut Report,
) {
    // The index grouped by pack, to compare against each header.
    let mut indexed: HashMap<Id, HashMap<Id, Entry>> = HashMap::new();
    for location in repo.index().locations() {
        indexed
            .entry(location.pack_id)
            .or_default()
            .insert(location.entry.id, location.entry);
    }

    let ordered: BTreeMap<_, _> = pack_sizes.iter().collect();
    let results: Vec<_> = stream::iter(ordered.into_keys())
        .map(|pack_id| verify_pack(repo, *pack_id, indexed.get(pack_id)))
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let mut problems = Vec::new();
    for (pack_problems, bytes) in results {
        report.bytes_read += bytes;
        problems.extend(pack_problems);
    }
    // Concurrency makes the order arbitrary; sort for stable output.
    problems.sort();
    report.problems.extend(problems);
}

/// Returns problems found in one pack and how many bytes were read.
async fn verify_pack<S: ObjectStore>(
    repo: &Repository<S>,
    pack_id: Id,
    indexed: Option<&HashMap<Id, Entry>>,
) -> (Vec<String>, u64) {
    let short = pack_id.short();
    let data = match repo
        .store()
        .get(&repo.object_key(&pack::object_name(&pack_id)))
        .await
    {
        Ok(data) => data,
        Err(e) => return (vec![format!("pack {short}: cannot be read: {e}")], 0),
    };
    let bytes = data.len() as u64;

    let header = match pack::parse_header(repo.keys(), &pack_id, &data) {
        Ok(header) => header,
        Err(e) => {
            return (
                vec![format!("pack {short}: cannot read its header: {e}")],
                bytes,
            );
        }
    };

    // Restores read at the offsets the index gives; the checks below decode at the
    // offsets the header gives. They must agree, or a blob that verifies here could
    // still fail to restore.
    let mut problems = Vec::new();
    let empty = HashMap::new();
    let indexed = indexed.unwrap_or(&empty);
    let in_header: HashSet<Id> = header.iter().map(|e| e.id).collect();
    for entry in &header {
        if indexed.get(&entry.id).is_some_and(|want| want != entry) {
            problems.push(format!(
                "pack {short}: the index entry for blob {} doesn't match the pack header",
                entry.id.short()
            ));
        }
    }
    for id in indexed.keys().filter(|id| !in_header.contains(id)) {
        problems.push(format!(
            "pack {short}: the index lists blob {}, which the pack doesn't contain",
            id.short()
        ));
    }

    // `decode_blob` authenticates, decompresses, and recomputes the keyed ID.
    for entry in &header {
        let sealed = &data[entry.offset as usize..entry.end() as usize];
        if let Err(e) = pack::decode_blob(repo.keys(), entry, sealed) {
            problems.push(format!("pack {short}: {e}"));
        }
    }
    (problems, bytes)
}
