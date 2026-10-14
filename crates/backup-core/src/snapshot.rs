//! Backup metadata: directory trees and snapshot objects.
//!
//! # Trees
//!
//! A directory is a tree blob listing its immediate children. A file child lists
//! its content chunk IDs; a directory child names another tree blob. Trees live in
//! packs like file data, so they're encrypted, compressed, and deduplicated the same
//! way: an unchanged directory produces an identical tree blob and costs nothing to
//! store again. That makes determinism part of the format. Nodes are sorted by name
//! and times are UTC, so identical directory state always gives identical bytes.
//!
//! # Snapshots
//!
//! A snapshot names one backup run: when, which paths, and its root tree. It's
//! written last, after every pack and index it depends on, so a visible snapshot is
//! always complete.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};
use futures_util::{StreamExt, TryStreamExt, stream};
use mirror_core::store::ObjectStore;
use serde::{Deserialize, Serialize};

use crate::cache::{Cache, Kind};
use crate::crypto::{Id, KeyKind, Keys};
use crate::error::{Error, Result};
use crate::index::list_ids;

pub const DIR: &str = "snapshots/";

/// Permission bits plus setuid, setgid, and sticky. The file type is `NodeType`.
pub const MODE_MASK: u32 = 0o7777;

const LOAD_CONCURRENCY: usize = 8;

pub fn object_name(id: &Id) -> String {
    format!("{DIR}{id}")
}

fn aad(id: &Id) -> String {
    format!("rfm-backup:v1:snapshot:{id}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    File,
    Dir,
    Symlink,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// One entry in a directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub name: String,
    #[serde(rename = "type")]
    pub node_type: NodeType,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub size: u64,
    /// Restored onto extracted files, and compared by the fast path.
    pub mtime: DateTime<Utc>,
    /// Compared by the fast path only. Unlike mtime, ordinary programs can't set
    /// it, so it catches edits that put the old mtime back. Access time is
    /// deliberately not recorded: it changes whenever anything reads a file,
    /// including the backup itself, and would make every tree differ every run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctime: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
    /// A file's chunk IDs, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<Id>,
    /// A directory's tree blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtree: Option<Id>,
    /// Identify the file on its filesystem: to notice a path now naming a
    /// different file, and to recreate hardlinks.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub device: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub inode: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub links: u64,
}

fn unix_time(secs: i64, nanos: i64) -> Option<DateTime<Utc>> {
    (secs != 0 || nanos != 0)
        .then(|| Utc.timestamp_opt(secs, nanos as u32).single())
        .flatten()
}

impl Node {
    /// Describes a filesystem entry (from `symlink_metadata`). `content` and
    /// `subtree` are filled in once the file is chunked or the directory saved.
    pub fn from_metadata(path: &Path, name: &str, meta: &Metadata) -> Result<Self> {
        let file_type = meta.file_type();
        let (node_type, size, link_target) = if file_type.is_symlink() {
            let target = std::fs::read_link(path)?;
            let target = target.to_str().ok_or_else(|| {
                Error::Invalid(format!(
                    "symlink target of {} is not valid UTF-8",
                    path.display()
                ))
            })?;
            (NodeType::Symlink, 0, Some(target.to_string()))
        } else if file_type.is_dir() {
            (NodeType::Dir, 0, None)
        } else if file_type.is_file() {
            (NodeType::File, meta.len(), None)
        } else {
            // Sockets, devices, and FIFOs have no content worth backing up.
            return Err(Error::Invalid(format!(
                "{} is an unsupported file type",
                path.display()
            )));
        };

        Ok(Self {
            name: name.to_string(),
            node_type,
            mode: meta.mode() & MODE_MASK,
            uid: meta.uid(),
            gid: meta.gid(),
            size,
            mtime: unix_time(meta.mtime(), meta.mtime_nsec()).unwrap_or_default(),
            ctime: unix_time(meta.ctime(), meta.ctime_nsec()),
            link_target,
            content: Vec::new(),
            subtree: None,
            device: meta.dev(),
            inode: meta.ino(),
            links: meta.nlink(),
        })
    }

    pub fn is_hardlink(&self) -> bool {
        self.node_type == NodeType::File && self.links > 1 && self.inode != 0
    }
}

/// Whether a node from an earlier snapshot still describes the file on disk, so its
/// chunk list can be reused without reading the file. This is the heart of
/// incremental backup, and deliberately checks more than mtime: size (a new length
/// always means new content), ctime (catches a restored mtime), inode (catches a
/// path replaced by a different file, as editors do with write-and-rename), and
/// mode (so permission changes get recorded).
///
/// The remaining blind spot is a change within the timestamp resolution of the
/// file's own metadata, which is what `verify` and periodic full reads are for.
pub fn same_content(old: &Node, current: &Node) -> bool {
    old.node_type == NodeType::File
        && current.node_type == NodeType::File
        && old.size == current.size
        && old.mtime == current.mtime
        && old.mode == current.mode
        && (old.inode == 0 || current.inode == 0 || old.inode == current.inode)
        && (old.ctime.is_none() || current.ctime.is_none() || old.ctime == current.ctime)
}

/// One directory's children.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tree {
    pub nodes: Vec<Node>,
}

impl Tree {
    /// Puts nodes in the canonical order that deduplication depends on.
    pub fn new(mut nodes: Vec<Node>) -> Self {
        nodes.sort_by(|a, b| a.name.cmp(&b.name));
        Self { nodes }
    }

    pub fn find(&self, name: &str) -> Option<&Node> {
        self.nodes
            .binary_search_by(|n| n.name.as_str().cmp(name))
            .ok()
            .map(|i| &self.nodes[i])
    }

    /// The bytes depend only on the directory's contents, never on the order the
    /// filesystem listed entries or on the machine's time zone.
    pub fn encode(&self) -> Vec<u8> {
        let canonical = Self::new(self.nodes.clone());
        serde_json::to_vec(&canonical).expect("trees always serialize")
    }

    /// Parses and validates a tree blob. Names are checked here, once, so nothing
    /// downstream (restore especially) ever sees one that could escape its
    /// directory.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let tree: Self =
            serde_json::from_slice(data).map_err(|e| Error::Format(format!("tree: {e}")))?;

        for (i, node) in tree.nodes.iter().enumerate() {
            let name = &node.name;
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.contains('/')
                || name.contains('\0')
            {
                return Err(Error::Format(format!(
                    "tree: entry {i} has invalid name {name:?}"
                )));
            }
            if i > 0 && tree.nodes[i - 1].name >= *name {
                return Err(Error::Format(format!(
                    "tree: entry {name:?} is out of order or duplicated"
                )));
            }
            if node.node_type == NodeType::Dir && node.subtree.is_none() {
                return Err(Error::Format(format!(
                    "tree: directory {name:?} has no subtree"
                )));
            }
            if node.node_type == NodeType::Symlink && node.link_target.is_none() {
                return Err(Error::Format(format!(
                    "tree: symlink {name:?} has no target"
                )));
            }
        }
        Ok(tree)
    }
}

/// What a run did. Informational only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Stats {
    pub files_new: u64,
    pub files_changed: u64,
    pub files_unmodified: u64,
    pub dirs_processed: u64,
    /// Unreadable or unsupported entries skipped under the error policy.
    pub files_skipped: u64,
    /// Mirror placeholders for offloaded files, whose content isn't local.
    pub placeholders_skipped: u64,
    /// Size of every file considered, versus how much new data reached the bucket.
    /// The gap is what deduplication and the fast path saved.
    pub bytes_processed: u64,
    pub bytes_added: u64,
    pub chunks_new: u64,
    pub chunks_duplicate: u64,
}

/// One backup run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The object's name; assigned on save, not serialized.
    #[serde(skip)]
    pub id: Id,
    pub time: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// The absolute paths backed up.
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// The root directory: a synthetic tree reproducing the paths' absolute layout.
    pub tree: Id,
    /// The snapshot this run was compared against, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Id>,
    #[serde(default)]
    pub stats: Stats,
}

impl Snapshot {
    fn validate(&self) -> Result<()> {
        if self.paths.is_empty() {
            return Err(Error::Format("snapshot lists no paths".into()));
        }
        if self.tree == Id::default() {
            return Err(Error::Format("snapshot has no root tree".into()));
        }
        Ok(())
    }
}

/// Writes a snapshot object, assigning its ID. Must be a run's last write; callers
/// go through `Repository::save_snapshot`, which enforces that.
pub(crate) async fn save(
    store: &impl ObjectStore,
    base: &str,
    keys: &Keys,
    snapshot: &mut Snapshot,
    cache: Option<&Cache>,
) -> Result<Id> {
    snapshot.validate()?;
    let id = Id::random();
    let plaintext = serde_json::to_vec(snapshot)
        .map_err(|e| Error::Invalid(format!("encoding snapshot: {e}")))?;
    let sealed = keys.seal(KeyKind::Meta, &plaintext, &aad(&id))?;
    store
        .put_bytes(&format!("{base}{}", object_name(&id)), &sealed)
        .await?;
    if let Some(cache) = cache {
        cache.put(Kind::Snapshot, &id, &sealed);
    }
    snapshot.id = id;
    Ok(id)
}

fn open_object(keys: &Keys, id: &Id, sealed: &[u8]) -> Result<Snapshot> {
    let what = format!("snapshot {}", id.short());
    let plaintext = keys.open(KeyKind::Meta, sealed, &aad(id), &what)?;
    let mut snapshot: Snapshot =
        serde_json::from_slice(&plaintext).map_err(|e| Error::Format(format!("{what}: {e}")))?;
    snapshot.validate()?;
    snapshot.id = *id;
    Ok(snapshot)
}

/// Reads one snapshot, from the cache when it has an authentic copy.
pub async fn load(
    store: &impl ObjectStore,
    base: &str,
    keys: &Keys,
    id: &Id,
    cache: Option<&Cache>,
) -> Result<Snapshot> {
    if let Some(sealed) = cache.and_then(|c| c.get(Kind::Snapshot, id))
        && let Ok(snapshot) = open_object(keys, id, &sealed)
    {
        return Ok(snapshot);
    }
    let sealed = store.get(&format!("{base}{}", object_name(id))).await?;
    let snapshot = open_object(keys, id, &sealed)?;
    if let Some(cache) = cache {
        cache.put(Kind::Snapshot, id, &sealed);
    }
    Ok(snapshot)
}

/// Every snapshot, newest first.
pub async fn list(
    store: &impl ObjectStore,
    base: &str,
    keys: &Keys,
    cache: Option<&Cache>,
) -> Result<Vec<Snapshot>> {
    let ids = list_ids(store, base, DIR).await?;
    let mut snapshots: Vec<_> = stream::iter(
        ids.iter()
            .map(|(id, _)| load(store, base, keys, id, cache))
            .collect::<Vec<_>>(),
    )
    .buffered(LOAD_CONCURRENCY)
    .try_collect()
    .await?;
    snapshots.sort_by(|a, b| b.time.cmp(&a.time).then(a.id.cmp(&b.id)));
    Ok(snapshots)
}

/// Resolves a user's reference among `snapshots` (newest first): `latest`, a full
/// ID, or an unambiguous prefix of one.
pub fn find<'a>(snapshots: &'a [Snapshot], reference: &str) -> Result<&'a Snapshot> {
    if snapshots.is_empty() {
        return Err(Error::SnapshotNotFound(
            "the repository has no snapshots".into(),
        ));
    }
    if reference.is_empty() || reference == "latest" {
        return Ok(&snapshots[0]);
    }

    let reference = reference.to_ascii_lowercase();
    let mut matches = snapshots
        .iter()
        .filter(|s| s.id.to_string().starts_with(&reference));
    match (matches.next(), matches.next()) {
        (None, _) => Err(Error::SnapshotNotFound(format!(
            "no snapshot matches {reference:?}"
        ))),
        (Some(only), None) => Ok(only),
        (Some(_), Some(_)) => Err(Error::SnapshotNotFound(format!(
            "{reference:?} matches more than one snapshot; use more characters"
        ))),
    }
}

/// The most recent snapshot (from a newest-first list) covering the same paths on
/// the same host: the natural baseline for an incremental run.
pub fn find_parent<'a>(
    snapshots: &'a [Snapshot],
    hostname: &str,
    paths: &[String],
) -> Option<&'a Snapshot> {
    let mut want = paths.to_vec();
    want.sort();
    snapshots.iter().find(|s| {
        let mut got = s.paths.clone();
        got.sort();
        s.hostname == hostname && got == want
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_keys;
    use mirror_core::store::memory::MemoryStore;

    const BASE: &str = "rfm/backup/";

    fn file(name: &str, size: u64) -> Node {
        Node {
            name: name.into(),
            node_type: NodeType::File,
            mode: 0o644,
            uid: 501,
            gid: 20,
            size,
            mtime: Utc.timestamp_opt(1_700_000_000, 123_456_789).unwrap(),
            ctime: Some(Utc.timestamp_opt(1_700_000_001, 0).unwrap()),
            link_target: None,
            content: vec![Id::random()],
            subtree: None,
            device: 1,
            inode: 42,
            links: 1,
        }
    }

    fn dir(name: &str) -> Node {
        Node {
            node_type: NodeType::Dir,
            size: 0,
            content: vec![],
            subtree: Some(Id::random()),
            ..file(name, 0)
        }
    }

    fn snapshot(secs: i64, hostname: &str, paths: &[&str]) -> Snapshot {
        Snapshot {
            id: Id::default(),
            time: Utc.timestamp_opt(secs, 0).unwrap(),
            hostname: hostname.into(),
            username: "me".into(),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            tags: vec![],
            tree: Id::random(),
            parent: None,
            stats: Stats::default(),
        }
    }

    #[test]
    fn tree_round_trip_and_find() {
        let mut link = file("link", 0);
        link.node_type = NodeType::Symlink;
        link.link_target = Some("../target".into());
        link.content.clear();

        let tree = Tree::new(vec![file("b.txt", 10), dir("a"), link]);
        let decoded = Tree::decode(&tree.encode()).unwrap();
        assert_eq!(decoded, tree);
        assert_eq!(
            decoded
                .nodes
                .iter()
                .map(|n| n.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b.txt", "link"]
        );
        assert_eq!(decoded.find("b.txt").unwrap().size, 10);
        assert!(decoded.find("missing").is_none());
    }

    #[test]
    fn tree_encoding_is_deterministic() {
        let (a, b, c) = (file("a", 1), file("b", 2), dir("c"));
        let one = Tree {
            nodes: vec![c.clone(), a.clone(), b.clone()],
        };
        let two = Tree {
            nodes: vec![b, c, a],
        };
        assert_eq!(one.encode(), two.encode());
    }

    #[test]
    fn trees_do_not_record_access_time() {
        let json = String::from_utf8(Tree::new(vec![file("f", 1)]).encode()).unwrap();
        assert!(!json.contains("atime"));
    }

    #[test]
    fn decode_tree_rejects_malformed_input() {
        let encode = |nodes: Vec<Node>| serde_json::to_vec(&Tree { nodes }).unwrap();

        assert!(Tree::decode(b"not json").is_err());
        assert!(Tree::decode(br#"{"nodes":[null]}"#).is_err());
        for name in ["", ".", "..", "a/b", "a\0b"] {
            assert!(
                Tree::decode(&encode(vec![file(name, 1)])).is_err(),
                "{name:?} accepted"
            );
        }
        assert!(
            Tree::decode(&encode(vec![file("b", 1), file("a", 1)])).is_err(),
            "unsorted"
        );
        assert!(
            Tree::decode(&encode(vec![file("a", 1), file("a", 1)])).is_err(),
            "duplicate"
        );

        let mut no_subtree = dir("d");
        no_subtree.subtree = None;
        assert!(Tree::decode(&encode(vec![no_subtree])).is_err());

        let mut no_target = file("l", 0);
        no_target.node_type = NodeType::Symlink;
        assert!(Tree::decode(&encode(vec![no_target])).is_err());

        assert!(Tree::decode(br#"{"nodes":[{"name":"x","type":"fifo"}]}"#).is_err());
    }

    #[test]
    fn same_content() {
        let old = file("f", 100);
        assert!(super::same_content(&old, &old.clone()));

        let changes: Vec<fn(&mut Node)> = vec![
            |n| n.size += 1,
            |n| n.mtime += chrono::Duration::nanoseconds(1),
            |n| n.mode = 0o600,
            |n| n.inode += 1,
            |n| n.ctime = n.ctime.map(|t| t + chrono::Duration::seconds(1)),
            |n| n.node_type = NodeType::Symlink,
        ];
        for change in changes {
            let mut current = old.clone();
            change(&mut current);
            assert!(!super::same_content(&old, &current), "{current:?}");
        }

        // Missing inode or ctime on either side weakens the check rather than failing it.
        let mut unknown = old.clone();
        unknown.inode = 0;
        unknown.ctime = None;
        assert!(super::same_content(&old, &unknown));
        assert!(super::same_content(&unknown, &old));
    }

    #[test]
    fn node_from_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("f.txt");
        std::fs::write(&path, b"hello").unwrap();
        std::os::unix::fs::symlink("f.txt", tmp.path().join("l")).unwrap();

        let meta = std::fs::symlink_metadata(&path).unwrap();
        let node = Node::from_metadata(&path, "f.txt", &meta).unwrap();
        assert_eq!(
            (node.node_type, node.size, node.name.as_str()),
            (NodeType::File, 5, "f.txt")
        );
        assert_eq!(node.mode, meta.mode() & MODE_MASK);
        assert!(node.inode != 0 && node.ctime.is_some());
        assert_eq!(node.mtime, DateTime::<Utc>::from(meta.modified().unwrap()));

        let link = tmp.path().join("l");
        let node =
            Node::from_metadata(&link, "l", &std::fs::symlink_metadata(&link).unwrap()).unwrap();
        assert_eq!(
            (node.node_type, node.link_target.as_deref(), node.size),
            (NodeType::Symlink, Some("f.txt"), 0)
        );

        let node = Node::from_metadata(
            tmp.path(),
            "d",
            &std::fs::symlink_metadata(tmp.path()).unwrap(),
        )
        .unwrap();
        assert_eq!(node.node_type, NodeType::Dir);
    }

    #[tokio::test]
    async fn snapshot_save_load_and_wrong_key() {
        let (store, keys) = (MemoryStore::new(), test_keys());
        let mut snap = snapshot(1_700_000_000, "host", &["/a"]);
        snap.tags = vec!["nightly".into()];
        snap.parent = Some(Id::random());
        snap.stats.bytes_added = 7;

        let id = save(&store, BASE, &keys, &mut snap, None).await.unwrap();
        assert_eq!(snap.id, id);
        assert_eq!(load(&store, BASE, &keys, &id, None).await.unwrap(), snap);
        assert!(load(&store, BASE, &test_keys(), &id, None).await.is_err());
    }

    #[tokio::test]
    async fn snapshot_validation() {
        let (store, keys) = (MemoryStore::new(), test_keys());
        let mut no_paths = snapshot(1, "h", &[]);
        assert!(
            save(&store, BASE, &keys, &mut no_paths, None)
                .await
                .is_err()
        );
        let mut no_tree = snapshot(1, "h", &["/a"]);
        no_tree.tree = Id::default();
        assert!(save(&store, BASE, &keys, &mut no_tree, None).await.is_err());
    }

    #[tokio::test]
    async fn list_is_newest_first_and_find_resolves_references() {
        let (store, keys) = (MemoryStore::new(), test_keys());
        assert!(matches!(
            find(&[], "latest"),
            Err(Error::SnapshotNotFound(_))
        ));

        for secs in [100, 300, 200] {
            save(&store, BASE, &keys, &mut snapshot(secs, "h", &["/a"]), None)
                .await
                .unwrap();
        }
        let snapshots = list(&store, BASE, &keys, None).await.unwrap();
        let times: Vec<_> = snapshots.iter().map(|s| s.time.timestamp()).collect();
        assert_eq!(times, [300, 200, 100]);

        assert_eq!(find(&snapshots, "latest").unwrap().id, snapshots[0].id);
        assert_eq!(find(&snapshots, "").unwrap().id, snapshots[0].id);
        let target = &snapshots[1];
        assert_eq!(
            find(&snapshots, &target.id.to_string()).unwrap().id,
            target.id
        );
        assert_eq!(
            find(&snapshots, &target.id.to_string().to_uppercase()[..12])
                .unwrap()
                .id,
            target.id
        );
        assert!(find(&snapshots, "zzzz").is_err());

        // A prefix matching several is ambiguous; the empty-ish prefix "" is "latest".
        let first_chars: Vec<_> = snapshots.iter().map(|s| s.id.to_string()).collect();
        let shared = (0..16).map(|c| format!("{c:x}")).find(|p| {
            first_chars
                .iter()
                .filter(|id| id.starts_with(p.as_str()))
                .count()
                > 1
        });
        if let Some(prefix) = shared {
            assert!(find(&snapshots, &prefix).is_err());
        }
    }

    #[test]
    fn find_parent_matches_host_and_paths() {
        let snapshots = vec![
            snapshot(5, "other", &["/a", "/b"]),
            snapshot(4, "host", &["/a"]),
            snapshot(3, "host", &["/b", "/a"]),
            snapshot(2, "host", &["/a", "/b"]),
        ];
        let paths = vec!["/a".to_string(), "/b".to_string()];
        assert_eq!(
            find_parent(&snapshots, "host", &paths)
                .unwrap()
                .time
                .timestamp(),
            3
        );
        assert!(find_parent(&snapshots, "host", &["/c".into()]).is_none());
        assert!(find_parent(&snapshots, "nobody", &paths).is_none());
    }
}
