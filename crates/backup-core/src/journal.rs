//! The resume journal: which files an unfinished backup had finished, so the next
//! backup of the same paths can skip them.
//!
//! While a run archives, each file it reads is appended here with its node (its
//! metadata and chunk list). If the run never saves a snapshot (cancelled, a lost
//! connection, the Mac asleep too long), the next run of the same paths loads the
//! journal alongside its parent snapshot, so files finished last time pass the
//! unchanged-file check without being opened. Combined with adopting the packs an
//! interrupted run uploaded (`Repository::adopt_orphans`), a resumed backup redoes
//! almost nothing.
//!
//! Nothing here is trusted blindly. Each line carries a keyed hash, so a damaged or
//! altered line is dropped, and an entry is only used if every chunk it names is in
//! the index: chunks that were in a pack still being filled when the run stopped
//! never reached the bucket, and their files are read again. The journal lives in
//! the local cache and is deleted once a snapshot is saved.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::cache::Cache;
use crate::crypto::Keys;
use crate::snapshot::Node;

/// Separates the journal's keyed hashes from blob IDs made with the same key.
const MAC_CONTEXT: &[u8] = b"rfm-backup:v1:journal\0";

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    path: PathBuf,
    node: Node,
}

/// Where the journal for a backup of `paths` (as a snapshot records them) lives.
/// Each set of paths gets its own, like each gets its own parent snapshot.
pub fn path_for(cache: &Cache, paths: &[String]) -> PathBuf {
    let digest = blake3::hash(paths.join("\n").as_bytes()).to_hex();
    cache
        .dir()
        .join("journal")
        .join(format!("{}.jsonl", &digest[..16]))
}

fn mac(keys: &Keys, json: &[u8]) -> String {
    keys.blob_id(&[MAC_CONTEXT, json].concat()).to_string()
}

/// The entries of the journal at `path` that authenticate. A missing journal, and
/// any unreadable or truncated line (a crash mid-write), are simply nothing.
pub fn load(path: &Path, keys: &Keys) -> Vec<(PathBuf, Node)> {
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| {
            let (json, tag) = line.rsplit_once('\t')?;
            if mac(keys, json.as_bytes()) != tag {
                return None;
            }
            let entry: Entry = serde_json::from_str(json).ok()?;
            Some((entry.path, entry.node))
        })
        .collect()
}

pub fn remove(path: &Path) {
    let _ = fs::remove_file(path);
}

/// Appends entries as a run finishes files. Shared by the run's worker threads.
pub struct Writer {
    file: Mutex<File>,
}

impl Writer {
    /// Opens (creating if needed) the journal at `path` for appending: entries from
    /// earlier unfinished runs stay, since they may still be useful.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Records that `path` was archived as `node`. Failures only cost the ability to
    /// resume, so they're logged, not returned.
    pub fn record(&self, keys: &Keys, path: &Path, node: &Node) {
        let entry = Entry {
            path: path.to_path_buf(),
            node: node.clone(),
        };
        let json = serde_json::to_string(&entry).expect("journal entries serialize");
        let line = format!("{json}\t{}\n", mac(keys, json.as_bytes()));
        // One write per line, so a crash leaves at most one partial line.
        if let Err(e) = self
            .file
            .lock()
            .expect("journal lock poisoned")
            .write_all(line.as_bytes())
        {
            tracing::debug!(error = %e, "journal write failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Id, test_keys};
    use crate::snapshot::NodeType;
    use chrono::Utc;

    fn node(name: &str) -> Node {
        Node {
            name: name.into(),
            node_type: NodeType::File,
            mode: 0o644,
            uid: 501,
            gid: 20,
            size: 3,
            mtime: Utc::now(),
            ctime: Some(Utc::now()),
            link_target: None,
            content: vec![Id::random()],
            subtree: None,
            device: 1,
            inode: 7,
            links: 1,
            content_hash: Some("ab".into()),
            offloaded: false,
        }
    }

    #[test]
    fn entries_round_trip_and_accumulate() {
        let (dir, keys) = (tempfile::tempdir().unwrap(), test_keys());
        let path = dir.path().join("journal/x.jsonl");
        assert!(load(&path, &keys).is_empty(), "no journal yet");

        Writer::open(&path)
            .unwrap()
            .record(&keys, Path::new("/a/one"), &node("one"));
        Writer::open(&path)
            .unwrap()
            .record(&keys, Path::new("/a/two"), &node("two"));
        let entries = load(&path, &keys);
        let names: Vec<_> = entries
            .iter()
            .map(|(p, n)| (p.to_str().unwrap(), n.name.as_str()))
            .collect();
        assert_eq!(names, [("/a/one", "one"), ("/a/two", "two")]);

        remove(&path);
        assert!(load(&path, &keys).is_empty());
    }

    #[test]
    fn damaged_altered_or_foreign_lines_are_dropped() {
        let (dir, keys) = (tempfile::tempdir().unwrap(), test_keys());
        let path = dir.path().join("j.jsonl");
        let writer = Writer::open(&path).unwrap();
        writer.record(&keys, Path::new("/good"), &node("good"));
        writer.record(&keys, Path::new("/altered"), &node("altered"));
        writer.record(&test_keys(), Path::new("/foreign"), &node("foreign"));

        let text = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        lines[1] = lines[1].replace("\"size\":3", "\"size\":4");
        let truncated = lines[0][..lines[0].len() / 2].to_string();
        fs::write(&path, format!("{}\n{truncated}", lines.join("\n"))).unwrap();

        let entries = load(&path, &keys);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, PathBuf::from("/good"));
    }

    #[test]
    fn each_set_of_paths_gets_its_own_journal() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::open(dir.path(), &Id::random()).unwrap();
        let a = path_for(&cache, &["/a".into()]);
        assert_eq!(a, path_for(&cache, &["/a".into()]));
        assert_ne!(a, path_for(&cache, &["/a".into(), "/b".into()]));
        assert!(a.starts_with(cache.dir()));
    }
}
