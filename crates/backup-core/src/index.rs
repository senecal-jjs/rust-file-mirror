//! Maps blob IDs to the pack and byte range that hold them.
//!
//! A backup consults the index to decide whether a chunk is already stored; a
//! restore uses it to turn chunk IDs into ranged reads. Index objects are immutable
//! and additive: each backup run writes one object describing only the packs it
//! created, and readers merge every object they find. Nothing is ever rewritten, so
//! concurrent or interrupted runs can't corrupt what's already there.

use std::collections::HashMap;
use std::sync::RwLock;

use futures_util::{StreamExt, TryStreamExt, stream};
use mirror_core::store::ObjectStore;

use crate::crypto::{ID_SIZE, Id, KeyKind, Keys};
use crate::error::{Error, Result};
use crate::pack::{self, Entry, decode_entries, encode_entries};

const FORMAT_VERSION: u32 = 1;

/// Bounds how many index objects (or pack headers, when rebuilding) are fetched at
/// once. Every run adds an index object, so a cold load can have hundreds.
const LOAD_CONCURRENCY: usize = 8;

pub const DIR: &str = "indexes/";

pub fn object_name(id: &Id) -> String {
    format!("{DIR}{id}")
}

/// Binds a sealed index object to its own ID.
fn aad(id: &Id) -> String {
    format!("rfm-backup:v1:index:{id}")
}

/// Where a blob lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub pack_id: Id,
    pub entry: Entry,
}

/// The blobs stored in one pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackEntries {
    pub pack_id: Id,
    pub entries: Vec<Entry>,
}

/// A merged, in-memory view of index objects. Safe to share between tasks: the
/// archiver queries and extends it concurrently.
#[derive(Default)]
pub struct Index {
    inner: RwLock<Inner>,
}

#[derive(Default)]
struct Inner {
    blobs: HashMap<Id, Location>,
    /// Pack ID → how many blobs it holds.
    packs: HashMap<Id, usize>,
    /// The index objects this view was loaded from.
    sources: Vec<Id>,
}

impl Index {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records every blob in a pack. A blob that's already known keeps its existing
    /// location: duplicates come from concurrent runs storing the same new chunk,
    /// either copy is valid, and the other simply goes unreferenced.
    pub fn add_pack(&self, pack_id: Id, entries: &[Entry]) {
        let mut inner = self.inner.write().expect("index lock poisoned");
        *inner.packs.entry(pack_id).or_default() += entries.len();
        for entry in entries {
            inner.blobs.entry(entry.id).or_insert(Location {
                pack_id,
                entry: *entry,
            });
        }
    }

    pub fn lookup(&self, id: &Id) -> Option<Location> {
        self.inner
            .read()
            .expect("index lock poisoned")
            .blobs
            .get(id)
            .copied()
    }

    /// The hot path of an incremental backup: consulted once per chunk.
    pub fn has(&self, id: &Id) -> bool {
        self.inner
            .read()
            .expect("index lock poisoned")
            .blobs
            .contains_key(id)
    }

    /// Distinct blobs known.
    pub fn len(&self) -> usize {
        self.inner.read().expect("index lock poisoned").blobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn pack_ids(&self) -> Vec<Id> {
        let mut ids: Vec<_> = self
            .inner
            .read()
            .expect("index lock poisoned")
            .packs
            .keys()
            .copied()
            .collect();
        ids.sort();
        ids
    }

    pub fn source_ids(&self) -> Vec<Id> {
        self.inner
            .read()
            .expect("index lock poisoned")
            .sources
            .clone()
    }

    /// Every known blob location, in no particular order.
    pub fn locations(&self) -> Vec<Location> {
        self.inner
            .read()
            .expect("index lock poisoned")
            .blobs
            .values()
            .copied()
            .collect()
    }

    fn add_source(&self, id: Id) {
        self.inner
            .write()
            .expect("index lock poisoned")
            .sources
            .push(id);
    }
}

/// Serializes packs into an index object plaintext: version, pack count, then each
/// pack's ID followed by its entry list (the pack header encoding).
fn encode(packs: &[PackEntries]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&(packs.len() as u32).to_le_bytes());
    for p in packs {
        out.extend_from_slice(&p.pack_id.0);
        encode_entries(&p.entries, &mut out);
    }
    out
}

fn decode(data: &[u8]) -> Result<Vec<PackEntries>> {
    let bad = |msg: String| Error::Format(format!("index object: {msg}"));

    let (version, rest) = data
        .split_first_chunk::<4>()
        .ok_or_else(|| bad(format!("only {} bytes", data.len())))?;
    let version = u32::from_le_bytes(*version);
    if version != FORMAT_VERSION {
        return Err(bad(format!(
            "format version {version}, this build understands {FORMAT_VERSION}"
        )));
    }
    let (count, mut rest) = rest
        .split_first_chunk::<4>()
        .ok_or_else(|| bad(format!("only {} bytes", data.len())))?;
    let count = u32::from_le_bytes(*count) as usize;

    // The declared count is attacker-controlled. Every pack costs at least an ID and
    // an entry count, so the data itself bounds it, and checking that before
    // allocating stops a hostile object from requesting gigabytes.
    let max_packs = rest.len() / (ID_SIZE + 4);
    if count > max_packs {
        return Err(bad(format!(
            "declares {count} packs but only has room for {max_packs}"
        )));
    }

    let mut packs = Vec::with_capacity(count);
    for _ in 0..count {
        let (pack_id, after_id) = rest
            .split_first_chunk::<ID_SIZE>()
            .ok_or_else(|| bad("truncated pack ID".into()))?;
        let (entries, after_entries) = decode_entries(after_id)?;
        packs.push(PackEntries {
            pack_id: Id(*pack_id),
            entries,
        });
        rest = after_entries;
    }

    if !rest.is_empty() {
        return Err(bad(format!("{} trailing bytes", rest.len())));
    }
    Ok(packs)
}

/// Writes a new index object describing `packs` and returns its ID.
pub async fn save(
    store: &impl ObjectStore,
    base: &str,
    keys: &Keys,
    packs: &[PackEntries],
) -> Result<Id> {
    if packs.is_empty() {
        return Err(Error::Invalid("refusing to save an empty index".into()));
    }
    let id = Id::random();
    let sealed = keys.seal(KeyKind::Meta, &encode(packs), &aad(&id))?;
    store
        .put_bytes(&format!("{base}{}", object_name(&id)), &sealed)
        .await?;
    Ok(id)
}

/// Reads and decodes one index object.
pub async fn load_one(
    store: &impl ObjectStore,
    base: &str,
    keys: &Keys,
    id: &Id,
) -> Result<Vec<PackEntries>> {
    let sealed = store.get(&format!("{base}{}", object_name(id))).await?;
    let plaintext = keys.open(
        KeyKind::Meta,
        &sealed,
        &aad(id),
        &format!("index {}", id.short()),
    )?;
    decode(&plaintext).map_err(|e| Error::Format(format!("index {}: {e}", id.short())))
}

/// Lists the IDs of objects directly under `dir`, skipping names that aren't IDs:
/// those aren't objects we wrote, and shouldn't fail the whole run.
pub(crate) async fn list_ids(
    store: &impl ObjectStore,
    base: &str,
    dir: &str,
) -> Result<Vec<(Id, u64)>> {
    let prefix = format!("{base}{dir}");
    let mut ids: Vec<_> = store
        .list(&prefix, None)
        .await?
        .into_iter()
        .filter_map(|meta| {
            let name = meta.key.rsplit('/').next()?;
            Some((name.parse::<Id>().ok()?, meta.size))
        })
        .collect();
    ids.sort();
    Ok(ids)
}

/// Reads every index object and merges them. Objects are fetched concurrently but
/// merged in listing order, so the result doesn't depend on which finished first.
pub async fn load(store: &impl ObjectStore, base: &str, keys: &Keys) -> Result<Index> {
    let ids = list_ids(store, base, DIR).await?;

    let loaded: Vec<_> = stream::iter(ids.iter().map(|(id, _)| load_one(store, base, keys, id)))
        .buffered(LOAD_CONCURRENCY)
        .try_collect()
        .await?;

    let index = Index::new();
    for ((id, _), packs) in ids.iter().zip(loaded) {
        for p in packs {
            index.add_pack(p.pack_id, &p.entries);
        }
        index.add_source(*id);
    }
    Ok(index)
}

/// Reconstructs an index from the header of every pack. This is the recovery path
/// the tail header exists for: with every index object lost, the repository is
/// still readable, at one small ranged read per pack.
pub async fn rebuild(store: &impl ObjectStore, base: &str, keys: &Keys) -> Result<Index> {
    let packs = list_ids(store, base, "packs/").await?;

    let headers: Vec<_> = stream::iter(packs.iter().map(|(pack_id, size)| async move {
        let key = format!("{base}{}", pack::object_name(pack_id));
        pack::load_header_sized(store, &key, keys, pack_id, *size)
            .await
            .map_err(|e| {
                Error::Format(format!(
                    "rebuilding index from pack {}: {e}",
                    pack_id.short()
                ))
            })
    }))
    .buffered(LOAD_CONCURRENCY)
    .try_collect()
    .await?;

    let index = Index::new();
    for ((pack_id, _), entries) in packs.iter().zip(headers) {
        index.add_pack(*pack_id, &entries);
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::Compression;
    use crate::crypto::test_keys;
    use crate::pack::{BlobType, Writer};
    use mirror_core::store::memory::MemoryStore;
    use std::sync::Arc;

    const BASE: &str = "rfm/backup/";

    fn entry(id: Id, offset: u32) -> Entry {
        Entry {
            blob_type: BlobType::Data,
            compression: Compression::None,
            id,
            offset,
            length: 100,
            plain_length: 60,
        }
    }

    fn pack_entries(n: usize) -> PackEntries {
        PackEntries {
            pack_id: Id::random(),
            entries: (0..n)
                .map(|i| entry(Id::random(), i as u32 * 100))
                .collect(),
        }
    }

    #[test]
    fn add_and_lookup() {
        let index = Index::new();
        let p = pack_entries(3);
        index.add_pack(p.pack_id, &p.entries);

        assert_eq!(index.len(), 3);
        for e in &p.entries {
            assert!(index.has(&e.id));
            assert_eq!(
                index.lookup(&e.id),
                Some(Location {
                    pack_id: p.pack_id,
                    entry: *e
                })
            );
        }
        assert!(!index.has(&Id::random()));
        assert_eq!(index.pack_ids(), vec![p.pack_id]);
        assert_eq!(index.locations().len(), 3);
    }

    #[test]
    fn first_location_wins() {
        let index = Index::new();
        let blob = Id::random();
        let (first, second) = (Id::random(), Id::random());
        index.add_pack(first, &[entry(blob, 0)]);
        index.add_pack(second, &[entry(blob, 500)]);

        assert_eq!(index.lookup(&blob).unwrap().pack_id, first);
        assert_eq!(index.len(), 1);
        assert_eq!(index.pack_ids().len(), 2);
    }

    #[test]
    fn encode_decode_round_trip() {
        let packs = vec![pack_entries(3), pack_entries(0), pack_entries(1)];
        assert_eq!(decode(&encode(&packs)).unwrap(), packs);
        assert_eq!(decode(&encode(&[])).unwrap(), vec![]);
    }

    #[test]
    fn decode_rejects_malformed_input() {
        let good = encode(&[pack_entries(2)]);
        assert!(decode(&[]).is_err());
        assert!(decode(&good[..6]).is_err());
        assert!(decode(&good[..good.len() - 1]).is_err());

        let mut trailing = good.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());

        let mut wrong_version = good.clone();
        wrong_version[0] = 2;
        assert!(decode(&wrong_version).is_err());
    }

    /// Huge declared counts must fail on the length check, not by trying to
    /// allocate. If the check were missing, these would abort the test process.
    #[test]
    fn decode_rejects_hostile_counts_before_allocating() {
        let mut packs = FORMAT_VERSION.to_le_bytes().to_vec();
        packs.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&packs).is_err());

        let mut entries = FORMAT_VERSION.to_le_bytes().to_vec();
        entries.extend_from_slice(&1u32.to_le_bytes());
        entries.extend_from_slice(&[0u8; ID_SIZE]);
        entries.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&entries).is_err());
    }

    #[tokio::test]
    async fn save_and_load() {
        let (store, keys) = (MemoryStore::new(), test_keys());
        let packs = vec![pack_entries(2), pack_entries(1)];
        let id = save(&store, BASE, &keys, &packs).await.unwrap();

        assert_eq!(load_one(&store, BASE, &keys, &id).await.unwrap(), packs);

        let index = load(&store, BASE, &keys).await.unwrap();
        assert_eq!(index.len(), 3);
        assert_eq!(index.source_ids(), vec![id]);
    }

    #[tokio::test]
    async fn load_merges_multiple_objects_and_ignores_foreign_names() {
        let (store, keys) = (MemoryStore::new(), test_keys());
        let mut ids = Vec::new();
        for n in 1..=5 {
            ids.push(save(&store, BASE, &keys, &[pack_entries(n)]).await.unwrap());
        }
        store
            .put_bytes(&format!("{BASE}{DIR}not-an-id"), b"junk")
            .await
            .unwrap();

        let index = load(&store, BASE, &keys).await.unwrap();
        assert_eq!(index.len(), 15);
        assert_eq!(index.pack_ids().len(), 5);
        ids.sort();
        assert_eq!(index.source_ids(), ids);
    }

    #[tokio::test]
    async fn load_on_empty_repository() {
        let index = load(&MemoryStore::new(), BASE, &test_keys()).await.unwrap();
        assert!(index.is_empty());
    }

    #[tokio::test]
    async fn save_rejects_empty_input() {
        assert!(
            save(&MemoryStore::new(), BASE, &test_keys(), &[])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn index_is_unreadable_with_the_wrong_key() {
        let store = MemoryStore::new();
        let id = save(&store, BASE, &test_keys(), &[pack_entries(1)])
            .await
            .unwrap();
        assert!(load_one(&store, BASE, &test_keys(), &id).await.is_err());
        assert!(load(&store, BASE, &test_keys()).await.is_err());
    }

    #[tokio::test]
    async fn tampered_or_renamed_index_is_detected() {
        let (store, keys) = (MemoryStore::new(), test_keys());
        let id = save(&store, BASE, &keys, &[pack_entries(2)]).await.unwrap();
        let key = format!("{BASE}{}", object_name(&id));
        let sealed = store.get(&key).await.unwrap();

        let mut tampered = sealed.clone();
        tampered[30] ^= 1;
        store.put_bytes(&key, &tampered).await.unwrap();
        assert!(load_one(&store, BASE, &keys, &id).await.is_err());

        // Authentic bytes under a different name fail too: the AAD binds the ID.
        let other = Id::random();
        store
            .put_bytes(&format!("{BASE}{}", object_name(&other)), &sealed)
            .await
            .unwrap();
        assert!(load_one(&store, BASE, &keys, &other).await.is_err());
    }

    #[tokio::test]
    async fn rebuild_from_packs_matches_what_was_written() {
        let (store, keys) = (MemoryStore::new(), test_keys());
        let mut expected = Vec::new();
        for p in 0..3u32 {
            let mut writer = Writer::new(Compression::Zstd);
            for i in 0..4u32 {
                let plaintext = format!("pack {p} blob {i}").repeat(50);
                writer
                    .add(
                        &keys,
                        BlobType::Data,
                        keys.blob_id(plaintext.as_bytes()),
                        plaintext.as_bytes(),
                    )
                    .unwrap();
            }
            let pack = writer.finish(&keys).unwrap();
            store
                .put_bytes(
                    &format!("{BASE}{}", pack::object_name(&pack.id)),
                    &pack.data,
                )
                .await
                .unwrap();
            expected.push(pack);
        }

        let index = rebuild(&store, BASE, &keys).await.unwrap();
        assert_eq!(index.len(), 12);
        for pack in &expected {
            for e in &pack.entries {
                assert_eq!(
                    index.lookup(&e.id),
                    Some(Location {
                        pack_id: pack.id,
                        entry: *e
                    })
                );
            }
        }
    }

    #[tokio::test]
    async fn rebuild_on_empty_repository_and_with_a_corrupt_pack() {
        let (store, keys) = (MemoryStore::new(), test_keys());
        assert!(rebuild(&store, BASE, &keys).await.unwrap().is_empty());

        let id = Id::random();
        store
            .put_bytes(
                &format!("{BASE}{}", pack::object_name(&id)),
                b"not a pack at all",
            )
            .await
            .unwrap();
        assert!(rebuild(&store, BASE, &keys).await.is_err());
    }

    #[test]
    fn concurrent_access() {
        let index = Arc::new(Index::new());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let index = Arc::clone(&index);
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        let p = pack_entries(2);
                        index.add_pack(p.pack_id, &p.entries);
                        assert!(index.has(&p.entries[0].id));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(index.len(), 8 * 200 * 2);
    }
}
