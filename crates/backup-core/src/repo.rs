//! A backup repository: config, index, and the pack writer, tied together.
//!
//! Callers save and load blobs by content; the repository decides which pack a blob
//! lands in, when a pack is full, and how the index grows.
//!
//! # Write ordering
//!
//! A run writes packs, then one index object covering them (`flush`), then its
//! snapshot. A snapshot that's visible in the bucket therefore only ever references
//! data that's already durable; an interrupted run leaves unreferenced packs, never
//! a snapshot that can't be restored.
//!
//! The repository enforces this rather than trusting callers to. Once any write
//! fails, the failure is sticky: later saves, `flush`, and `ensure_writable` (which
//! snapshot writes call) all refuse, so a broken snapshot can't be published however
//! the original error was handled.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use mirror_core::store::ObjectStore;
use serde::{Deserialize, Serialize};

use crate::cache::{self, Cache};
use crate::chunker::ChunkerConfig;
use crate::compress::Compression;
use crate::crypto::{Id, KeyKind, Keys};
use crate::error::{Error, Result};
use crate::index::{self, Index, PackEntries};
use crate::pack::{self, BlobType, Pack, SealedBlob, Writer};
use crate::snapshot::{self, Node, NodeType, Snapshot, Tree};

const CONFIG_VERSION: u32 = 1;
const CONFIG_NAME: &str = "config";
const CONFIG_AAD: &str = "rfm-backup:v1:config";

/// Where a mirror prefix keeps its backup repository. The mirror's GC only touches
/// `<prefix>data/`, so nothing under here is ever collected by it.
pub fn base(prefix: &str) -> String {
    format!("{prefix}backup/")
}

/// The cache is only ever an optimization, so a repository opens without one if it
/// can't be created.
fn open_cache(base: Option<&Path>, repo_id: &Id) -> Option<Cache> {
    let base = base?;
    match Cache::open(base, repo_id) {
        Ok(cache) => Some(cache),
        Err(e) => {
            tracing::warn!(error = %e, "running without a metadata cache");
            None
        }
    }
}

/// Stored, sealed, at `<base>config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    pub id: Id,
    pub created: DateTime<Utc>,
    /// Chunk boundaries depend on these, so the stored values always win: backing
    /// up with different ones would silently stop deduplicating.
    pub chunker: ChunkerConfig,
    /// For new blobs. Each blob records its own, so this can change freely.
    pub compression: Compression,
}

/// Settings for a new repository.
#[derive(Debug, Clone, Copy)]
pub struct InitOptions {
    pub chunker: ChunkerConfig,
    pub compression: Compression,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            chunker: ChunkerConfig::default(),
            compression: Compression::Zstd,
        }
    }
}

pub struct Repository<S> {
    store: Arc<S>,
    base: String,
    keys: Keys,
    config: Config,
    index: Index,
    cache: Option<Cache>,
    pack_target: usize,
    state: Mutex<WriteState>,
}

#[derive(Default)]
struct WriteState {
    /// The pack being filled.
    writer: Option<Writer>,
    /// Blobs in finished packs that aren't uploaded and indexed yet. Without this, a
    /// blob saved while its pack is in flight is in neither the index nor the open
    /// pack, and gets stored twice.
    inflight: HashSet<Id>,
    /// Packs uploaded this run, for the index object `flush` writes.
    new_packs: Vec<PackEntries>,
    /// The first write failure this run. See the module docs.
    failed: Option<String>,
}

impl<S: ObjectStore> Repository<S> {
    /// Creates a repository under `prefix` (see `base`). With `cache_base`, metadata
    /// is cached locally under it (see `cache`).
    pub async fn init(
        store: Arc<S>,
        prefix: &str,
        keys: Keys,
        options: InitOptions,
        cache_base: Option<&Path>,
    ) -> Result<Self> {
        let base = base(prefix);
        let config_key = format!("{base}{CONFIG_NAME}");
        if store.head(&config_key).await?.is_some() {
            return Err(Error::AlreadyInitialized(base));
        }
        options.chunker.validate()?;

        let config = Config {
            version: CONFIG_VERSION,
            id: Id::random(),
            created: Utc::now(),
            chunker: options.chunker,
            compression: options.compression,
        };
        let plaintext = serde_json::to_vec(&config)
            .map_err(|e| Error::Invalid(format!("encoding repository config: {e}")))?;
        let sealed = keys.seal(KeyKind::Meta, &plaintext, CONFIG_AAD)?;
        store.put_bytes(&config_key, &sealed).await?;

        let cache = open_cache(cache_base, &config.id);
        Ok(Self::new(store, base, keys, config, Index::new(), cache))
    }

    /// Opens an existing repository and loads its index.
    pub async fn open(
        store: Arc<S>,
        prefix: &str,
        keys: Keys,
        cache_base: Option<&Path>,
    ) -> Result<Self> {
        let base = base(prefix);
        let config_key = format!("{base}{CONFIG_NAME}");
        if store.head(&config_key).await?.is_none() {
            return Err(Error::NotInitialized(base));
        }

        let sealed = store.get(&config_key).await?;
        let plaintext = keys.open(
            KeyKind::Meta,
            &sealed,
            CONFIG_AAD,
            "backup repository config",
        )?;
        let config: Config = serde_json::from_slice(&plaintext)
            .map_err(|e| Error::Format(format!("backup repository config: {e}")))?;
        if config.version != CONFIG_VERSION {
            return Err(Error::Format(format!(
                "backup repository format version {}, this build understands {CONFIG_VERSION}",
                config.version
            )));
        }
        config.chunker.validate()?;

        let cache = open_cache(cache_base, &config.id);
        let index = index::load(store.as_ref(), &base, &keys, cache.as_ref()).await?;
        Ok(Self::new(store, base, keys, config, index, cache))
    }

    /// Opens the repository, creating it first if there isn't one.
    pub async fn open_or_init(
        store: Arc<S>,
        prefix: &str,
        keys: Keys,
        options: InitOptions,
        cache_base: Option<&Path>,
    ) -> Result<Self> {
        if store
            .head(&format!("{}{CONFIG_NAME}", base(prefix)))
            .await?
            .is_some()
        {
            Self::open(store, prefix, keys, cache_base).await
        } else {
            Self::init(store, prefix, keys, options, cache_base).await
        }
    }

    fn new(
        store: Arc<S>,
        base: String,
        keys: Keys,
        config: Config,
        index: Index,
        cache: Option<Cache>,
    ) -> Self {
        Self {
            store,
            base,
            keys,
            config,
            index,
            cache,
            pack_target: pack::TARGET_SIZE,
            state: Mutex::new(WriteState::default()),
        }
    }

    /// Overrides the pack size to aim for; small values are useful in tests.
    pub fn set_pack_target(&mut self, bytes: usize) {
        self.pack_target = bytes;
    }

    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    /// The key prefix everything in this repository lives under.
    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    pub fn cache(&self) -> Option<&Cache> {
        self.cache.as_ref()
    }

    pub fn object_key(&self, name: &str) -> String {
        format!("{}{name}", self.base)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WriteState> {
        self.state.lock().expect("repository lock poisoned")
    }

    /// Whether `id` is stored, in the open pack, or on its way up.
    fn is_pending(state: &WriteState, id: &Id) -> bool {
        state.writer.as_ref().is_some_and(|w| w.has(id)) || state.inflight.contains(id)
    }

    /// Stores a blob unless the repository already has it. Returns its ID and whether
    /// this call stored it.
    ///
    /// New blobs fill an open pack, which is uploaded once it reaches the target
    /// size, so data streams to the bucket throughout a run rather than at the end.
    /// Safe to call from many tasks at once.
    pub async fn save_blob(&self, blob_type: BlobType, plaintext: &[u8]) -> Result<(Id, bool)> {
        let id = self.keys.blob_id(plaintext);
        if self.index.has(&id) {
            return Ok((id, false));
        }
        {
            let state = self.lock();
            if let Some(failed) = &state.failed {
                return Err(Error::RunFailed(failed.clone()));
            }
            if Self::is_pending(&state, &id) {
                return Ok((id, false));
            }
        }

        // The expensive part, done without the lock so other tasks keep filling the
        // pack. Losing a race below just discards this work.
        let sealed = SealedBlob::seal(
            &self.keys,
            self.config.compression,
            blob_type,
            id,
            plaintext,
        )?;

        let (added, full) = {
            let mut state = self.lock();
            if let Some(failed) = &state.failed {
                return Err(Error::RunFailed(failed.clone()));
            }
            if self.index.has(&id) || Self::is_pending(&state, &id) {
                return Ok((id, false));
            }

            let writer = state
                .writer
                .get_or_insert_with(|| Writer::new(self.config.compression));
            let added = writer.push(sealed)?;

            let full = if writer.size() >= self.pack_target {
                let writer = state.writer.take().expect("writer was just used");
                let pack = writer.finish(&self.keys)?;
                state.inflight.extend(pack.entries.iter().map(|e| e.id));
                Some(pack)
            } else {
                None
            };
            (added, full)
        };

        // Uploaded outside the lock so other tasks can keep filling the next pack.
        if let Some(pack) = full {
            self.upload_pack(pack).await?;
        }
        Ok((id, added))
    }

    /// Stores a finished pack and indexes its blobs. A failure can't be recovered
    /// within the run: files already added to the snapshot tree reference these
    /// blobs, so the run is marked failed.
    async fn upload_pack(&self, pack: Pack) -> Result<()> {
        let key = self.object_key(&pack::object_name(&pack.id));
        if let Err(e) = self.store.put_bytes(&key, &pack.data).await {
            let message = format!("uploading pack {}: {e}", pack.id.short());
            self.fail(message.clone());
            return Err(Error::RunFailed(message));
        }

        // Only now may the blobs count as stored. They enter the index before
        // leaving the in-flight set, so there's no moment they're in neither.
        self.index.add_pack(pack.id, &pack.entries);

        let mut state = self.lock();
        for entry in &pack.entries {
            state.inflight.remove(&entry.id);
        }
        state.new_packs.push(PackEntries {
            pack_id: pack.id,
            entries: pack.entries,
        });
        Ok(())
    }

    fn fail(&self, message: String) {
        self.lock().failed.get_or_insert(message);
    }

    /// The sticky write failure, if there's been one.
    pub fn failed(&self) -> Option<String> {
        self.lock().failed.clone()
    }

    /// Errors if a write has failed this run. Anything that publishes a snapshot
    /// must call this first.
    pub fn ensure_writable(&self) -> Result<()> {
        match self.failed() {
            Some(failed) => Err(Error::RunFailed(failed)),
            None => Ok(()),
        }
    }

    /// Finishes the open pack and writes one index object covering every pack
    /// uploaded this run. Must complete before the run's snapshot is saved, and only
    /// once every `save_blob` call has returned.
    pub async fn flush(&self) -> Result<()> {
        self.ensure_writable()?;

        let open = {
            let mut state = self.lock();
            let open = state.writer.take().filter(|w| w.count() > 0);
            match open.map(|w| w.finish(&self.keys)).transpose() {
                Ok(pack) => {
                    if let Some(pack) = &pack {
                        state.inflight.extend(pack.entries.iter().map(|e| e.id));
                    }
                    pack
                }
                Err(e) => {
                    let message = format!("finishing pack: {e}");
                    state.failed.get_or_insert(message.clone());
                    return Err(Error::RunFailed(message));
                }
            }
        };
        if let Some(pack) = open {
            self.upload_pack(pack).await?;
        }

        let packs = {
            let mut state = self.lock();
            if !state.inflight.is_empty() {
                // A pack is still uploading, so the index object would miss it.
                return Err(Error::Invalid(
                    "flush called while blobs are still being saved".into(),
                ));
            }
            std::mem::take(&mut state.new_packs)
        };
        // Nothing new is the normal outcome of backing up unchanged data.
        if packs.is_empty() {
            return Ok(());
        }

        if let Err(e) = index::save(
            self.store.as_ref(),
            &self.base,
            &self.keys,
            &packs,
            self.cache.as_ref(),
        )
        .await
        {
            let message = format!("writing index: {e}");
            self.fail(message.clone());
            return Err(Error::RunFailed(message));
        }
        Ok(())
    }

    /// Takes over packs an interrupted run left behind: stored, but in no index
    /// because that run never reached `flush`. Their blobs count as stored from now
    /// on, so this run doesn't upload them again, and this run's index covers them.
    /// Returns how many packs were adopted.
    ///
    /// Pack headers are authenticated, so only genuine packs of this repository are
    /// taken; one that doesn't check out is skipped with a warning. Call while
    /// holding the repository lock (backups do), so a prune can't be deleting them.
    pub async fn adopt_orphans(&self) -> Result<usize> {
        let indexed: HashSet<Id> = self.index.pack_ids().into_iter().collect();
        let mut adopted = 0;
        for (pack_id, size) in index::list_ids(self.store.as_ref(), &self.base, "packs/").await? {
            if indexed.contains(&pack_id) {
                continue;
            }
            let key = self.object_key(&pack::object_name(&pack_id));
            match pack::load_header_sized(self.store.as_ref(), &key, &self.keys, &pack_id, size)
                .await
            {
                Ok(entries) => {
                    self.index.add_pack(pack_id, &entries);
                    self.lock().new_packs.push(PackEntries { pack_id, entries });
                    adopted += 1;
                }
                Err(e) => {
                    tracing::warn!(pack = %pack_id.short(), error = %e, "not adopting an unreadable pack")
                }
            }
        }
        Ok(adopted)
    }

    /// Fetches a blob by ID with one ranged read.
    pub async fn load_blob(&self, id: &Id) -> Result<Vec<u8>> {
        let location = self
            .index
            .lookup(id)
            .ok_or_else(|| Error::UnknownBlob(id.short()))?;
        let key = self.object_key(&pack::object_name(&location.pack_id));
        pack::load_blob(self.store.as_ref(), &key, &self.keys, &location.entry).await
    }

    /// Stores a directory as a tree blob. Cached, since the next run's fast path
    /// walks it again.
    pub async fn save_tree(&self, tree: &Tree) -> Result<Id> {
        let plaintext = tree.encode();
        let id = self.save_blob(BlobType::Tree, &plaintext).await?.0;
        if let Some(cache) = &self.cache {
            cache.put(cache::Kind::Tree, &id, &plaintext);
        }
        Ok(id)
    }

    /// A cached tree is only used if it still matches the keyed ID that names it,
    /// the same check applied to blobs read from the bucket.
    pub async fn load_tree(&self, id: &Id) -> Result<Tree> {
        if let Some(cache) = &self.cache
            && let Some(plaintext) = cache.get(cache::Kind::Tree, id)
        {
            if self.keys.verify_blob_id(id, &plaintext) {
                return Tree::decode(&plaintext);
            }
            cache.remove(cache::Kind::Tree, id);
        }
        let plaintext = self.load_blob(id).await?;
        let tree = Tree::decode(&plaintext)?;
        if let Some(cache) = &self.cache {
            cache.put(cache::Kind::Tree, id, &plaintext);
        }
        Ok(tree)
    }

    /// Writes the run's snapshot. Only after `flush`, and never once a write has
    /// failed: this is the last line of defence against publishing a snapshot that
    /// references data the bucket doesn't have.
    pub async fn save_snapshot(&self, snapshot: &mut Snapshot) -> Result<Id> {
        self.ensure_writable()?;
        let unflushed = {
            let state = self.lock();
            state.writer.as_ref().is_some_and(|w| w.count() > 0)
                || !state.inflight.is_empty()
                || !state.new_packs.is_empty()
        };
        if unflushed {
            return Err(Error::Invalid("save_snapshot called before flush".into()));
        }
        snapshot::save(
            self.store.as_ref(),
            &self.base,
            &self.keys,
            snapshot,
            self.cache.as_ref(),
        )
        .await
    }

    pub async fn load_snapshot(&self, id: &Id) -> Result<Snapshot> {
        snapshot::load(
            self.store.as_ref(),
            &self.base,
            &self.keys,
            id,
            self.cache.as_ref(),
        )
        .await
    }

    /// Every snapshot, newest first.
    pub async fn list_snapshots(&self) -> Result<Vec<Snapshot>> {
        snapshot::list(
            self.store.as_ref(),
            &self.base,
            &self.keys,
            self.cache.as_ref(),
        )
        .await
    }

    /// Every entry beneath `tree`, as absolute `/`-joined paths, sorted.
    pub async fn walk(&self, tree: Id) -> Result<Vec<(String, Node)>> {
        let mut entries = Vec::new();
        let mut pending = vec![(tree, String::new())];
        while let Some((tree, dir)) = pending.pop() {
            for node in self.load_tree(&tree).await?.nodes {
                let path = format!("{dir}/{}", node.name);
                if let (NodeType::Dir, Some(subtree)) = (node.node_type, node.subtree) {
                    pending.push((subtree, path.clone()));
                }
                entries.push((path, node));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }

    /// Resolves `latest`, a full ID, or an unambiguous ID prefix.
    pub async fn find_snapshot(&self, reference: &str) -> Result<Snapshot> {
        let snapshots = self.list_snapshots().await?;
        snapshot::find(&snapshots, reference).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_keys;
    use mirror_core::store::memory::MemoryStore;
    use rand::Rng;
    use secrecy::SecretBox;
    use std::sync::Arc;

    const PREFIX: &str = "rfm/";

    /// The same key root every time a test re-derives, standing in for the vault.
    fn keys(root: u8) -> Keys {
        Keys::derive(&SecretBox::new(Box::new([root; 32])))
    }

    fn random_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        rand::rng().fill(&mut bytes[..]);
        bytes
    }

    /// The store is shared so tests can inspect it while the repository holds it.
    async fn init(store: &Arc<MemoryStore>) -> Repository<MemoryStore> {
        Repository::init(
            Arc::clone(store),
            PREFIX,
            keys(1),
            InitOptions::default(),
            None,
        )
        .await
        .unwrap()
    }

    async fn objects_under(store: &MemoryStore, dir: &str) -> usize {
        store
            .list(&format!("{}{dir}", base(PREFIX)), None)
            .await
            .unwrap()
            .len()
    }

    /// Every blob entry across every pack actually in the bucket, duplicates
    /// included (a rebuilt index would merge them and hide double stores).
    async fn stored_entries(store: &MemoryStore) -> usize {
        let base = base(PREFIX);
        let mut total = 0;
        for (pack_id, size) in index::list_ids(store, &base, "packs/").await.unwrap() {
            let key = format!("{base}{}", pack::object_name(&pack_id));
            total += pack::load_header_sized(store, &key, &keys(1), &pack_id, size)
                .await
                .unwrap()
                .len();
        }
        total
    }

    #[tokio::test]
    async fn init_and_open() {
        let store = Arc::new(MemoryStore::new());
        let config = init(&store).await.config().clone();
        assert_eq!(config.version, CONFIG_VERSION);
        assert_eq!(config.chunker, ChunkerConfig::default());
        assert_eq!(config.compression, Compression::Zstd);

        let reopened = Repository::open(Arc::clone(&store), PREFIX, keys(1), None)
            .await
            .unwrap();
        assert_eq!(reopened.config(), &config);
    }

    #[tokio::test]
    async fn init_refuses_to_overwrite_and_open_needs_a_repository() {
        let store = Arc::new(MemoryStore::new());
        assert!(matches!(
            Repository::open(Arc::clone(&store), PREFIX, keys(1), None).await,
            Err(Error::NotInitialized(_))
        ));
        init(&store).await;
        assert!(matches!(
            Repository::init(
                Arc::clone(&store),
                PREFIX,
                keys(1),
                InitOptions::default(),
                None
            )
            .await,
            Err(Error::AlreadyInitialized(_))
        ));
    }

    #[tokio::test]
    async fn open_or_init_creates_once() {
        let store = Arc::new(MemoryStore::new());
        let first = Repository::open_or_init(
            Arc::clone(&store),
            PREFIX,
            keys(1),
            InitOptions::default(),
            None,
        )
        .await
        .unwrap()
        .config()
        .id;
        let second = Repository::open_or_init(
            Arc::clone(&store),
            PREFIX,
            keys(1),
            InitOptions::default(),
            None,
        )
        .await
        .unwrap()
        .config()
        .id;
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn open_with_wrong_key_fails() {
        let store = Arc::new(MemoryStore::new());
        init(&store).await;
        assert!(matches!(
            Repository::open(Arc::clone(&store), PREFIX, keys(2), None).await,
            Err(Error::Decryption(_))
        ));
    }

    #[tokio::test]
    async fn stored_settings_win_and_invalid_ones_are_refused() {
        let store = Arc::new(MemoryStore::new());
        let options = InitOptions {
            chunker: ChunkerConfig {
                min_size: 4096,
                avg_size: 16384,
                max_size: 65536,
            },
            compression: Compression::None,
        };
        Repository::init(Arc::clone(&store), PREFIX, keys(1), options, None)
            .await
            .unwrap();

        let reopened = Repository::open_or_init(
            Arc::clone(&store),
            PREFIX,
            keys(1),
            InitOptions::default(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(reopened.config().chunker, options.chunker);
        assert_eq!(reopened.config().compression, Compression::None);

        let bad = InitOptions {
            chunker: ChunkerConfig {
                min_size: 1,
                ..options.chunker
            },
            ..options
        };
        assert!(
            Repository::init(Arc::new(MemoryStore::new()), PREFIX, keys(1), bad, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn save_and_load_blob() {
        let store = Arc::new(MemoryStore::new());
        let repo = init(&store).await;
        let data = random_bytes(10_000);
        let tree = b"{\"nodes\":[]}".to_vec();

        let (data_id, stored) = repo.save_blob(BlobType::Data, &data).await.unwrap();
        assert!(stored);
        let (tree_id, _) = repo.save_blob(BlobType::Tree, &tree).await.unwrap();
        repo.flush().await.unwrap();

        assert_eq!(repo.load_blob(&data_id).await.unwrap(), data);
        assert_eq!(repo.load_blob(&tree_id).await.unwrap(), tree);

        let reopened = Repository::open(Arc::clone(&store), PREFIX, keys(1), None)
            .await
            .unwrap();
        assert_eq!(reopened.load_blob(&data_id).await.unwrap(), data);
    }

    #[tokio::test]
    async fn load_blob_unknown_id() {
        let store = Arc::new(MemoryStore::new());
        let repo = init(&store).await;
        assert!(matches!(
            repo.load_blob(&Id::random()).await,
            Err(Error::UnknownBlob(_))
        ));
    }

    #[tokio::test]
    async fn deduplication_within_and_across_sessions() {
        let store = Arc::new(MemoryStore::new());
        let repo = init(&store).await;
        let data = random_bytes(5000);

        let (id, first) = repo.save_blob(BlobType::Data, &data).await.unwrap();
        let (again, second) = repo.save_blob(BlobType::Data, &data).await.unwrap();
        assert_eq!((id, first, second), (again, true, false));
        repo.flush().await.unwrap();
        assert_eq!(stored_entries(&store).await, 1);

        let reopened = Repository::open(Arc::clone(&store), PREFIX, keys(1), None)
            .await
            .unwrap();
        assert!(!reopened.save_blob(BlobType::Data, &data).await.unwrap().1);
        reopened.flush().await.unwrap();
        assert_eq!(
            objects_under(&store, index::DIR).await,
            1,
            "an unchanged run writes no index"
        );
        assert_eq!(objects_under(&store, "packs/").await, 1);
    }

    #[tokio::test]
    async fn pack_rollover_uploads_during_the_run() {
        let store = Arc::new(MemoryStore::new());
        let mut repo = init(&store).await;
        repo.set_pack_target(64 * 1024);

        for _ in 0..20 {
            repo.save_blob(BlobType::Data, &random_bytes(20_000))
                .await
                .unwrap();
        }
        // Full packs went up as they filled, well before flush.
        let before_flush = objects_under(&store, "packs/").await;
        assert!(before_flush >= 5, "{before_flush} packs before flush");

        repo.flush().await.unwrap();
        assert!(objects_under(&store, "packs/").await >= before_flush);
        assert_eq!(stored_entries(&store).await, 20);
    }

    #[tokio::test]
    async fn write_ordering_index_only_after_flush() {
        let store = Arc::new(MemoryStore::new());
        let mut repo = init(&store).await;
        repo.set_pack_target(16 * 1024);

        let blobs: Vec<_> = (0..6).map(|_| random_bytes(10_000)).collect();
        let mut ids = Vec::new();
        for blob in &blobs {
            ids.push(repo.save_blob(BlobType::Data, blob).await.unwrap().0);
        }
        assert!(objects_under(&store, "packs/").await > 0);
        assert_eq!(objects_under(&store, index::DIR).await, 0);

        // An interrupted run (no flush) leaves packs nothing references.
        let interrupted = Repository::open(Arc::clone(&store), PREFIX, keys(1), None)
            .await
            .unwrap();
        assert!(ids.iter().all(|id| !interrupted.index().has(id)));

        repo.flush().await.unwrap();
        assert_eq!(objects_under(&store, index::DIR).await, 1);
        let reopened = Repository::open(Arc::clone(&store), PREFIX, keys(1), None)
            .await
            .unwrap();
        for (id, blob) in ids.iter().zip(&blobs) {
            assert_eq!(&reopened.load_blob(id).await.unwrap(), blob);
        }
    }

    #[tokio::test]
    async fn flush_with_nothing_to_store_writes_nothing() {
        let store = Arc::new(MemoryStore::new());
        let repo = init(&store).await;
        repo.flush().await.unwrap();
        repo.flush().await.unwrap();
        assert_eq!(objects_under(&store, "").await, 1, "only the config");
    }

    #[tokio::test]
    async fn pack_upload_failure_is_sticky() {
        let store = Arc::new(MemoryStore::new());
        let mut repo = init(&store).await;
        repo.set_pack_target(8 * 1024);
        store.fail_puts_under(Some(&format!("{}packs/", base(PREFIX))));

        let err = repo
            .save_blob(BlobType::Data, &random_bytes(10_000))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RunFailed(_)), "{err}");

        // Even after the store recovers, nothing more is accepted this run.
        store.fail_puts_under(None);
        assert!(matches!(
            repo.save_blob(BlobType::Data, &random_bytes(100)).await,
            Err(Error::RunFailed(_))
        ));
        assert!(matches!(repo.flush().await, Err(Error::RunFailed(_))));
        assert!(repo.ensure_writable().is_err());
        assert!(repo.failed().is_some());
        assert_eq!(objects_under(&store, index::DIR).await, 0);
    }

    #[tokio::test]
    async fn index_write_failure_is_sticky() {
        let store = Arc::new(MemoryStore::new());
        let repo = init(&store).await;
        repo.save_blob(BlobType::Data, b"some data").await.unwrap();

        store.fail_puts_under(Some(&format!("{}{}", base(PREFIX), index::DIR)));
        assert!(matches!(repo.flush().await, Err(Error::RunFailed(_))));
        store.fail_puts_under(None);
        assert!(repo.ensure_writable().is_err());
        assert!(repo.flush().await.is_err());
    }

    /// Many tasks racing to save the same blobs, with packs small enough to be in
    /// flight constantly: each blob must still be stored exactly once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_saves_store_each_blob_once() {
        let store = Arc::new(MemoryStore::new());
        let mut repo = init(&store).await;
        repo.set_pack_target(4 * 1024);
        let repo = Arc::new(repo);
        let blobs: Arc<Vec<_>> = Arc::new((0..60).map(|_| random_bytes(2_000)).collect());

        let tasks: Vec<_> = (0..8)
            .map(|t| {
                let (repo, blobs) = (Arc::clone(&repo), Arc::clone(&blobs));
                tokio::spawn(async move {
                    let mut stored = 0;
                    for i in 0..blobs.len() {
                        let blob = &blobs[(i + t * 7) % blobs.len()];
                        stored += repo.save_blob(BlobType::Data, blob).await.unwrap().1 as usize;
                    }
                    stored
                })
            })
            .collect();
        let mut stored = 0;
        for task in tasks {
            stored += task.await.unwrap();
        }
        repo.flush().await.unwrap();

        assert_eq!(
            stored, 60,
            "each blob reported as newly stored exactly once"
        );
        assert_eq!(stored_entries(&store).await, 60);
        assert_eq!(repo.index().len(), 60);
    }

    #[tokio::test]
    async fn rebuilt_index_matches_stored_index() {
        let store = Arc::new(MemoryStore::new());
        let mut repo = init(&store).await;
        repo.set_pack_target(32 * 1024);
        for _ in 0..10 {
            repo.save_blob(BlobType::Data, &random_bytes(9_000))
                .await
                .unwrap();
        }
        repo.flush().await.unwrap();

        let stored = index::load(store.as_ref(), &base(PREFIX), &keys(1), None)
            .await
            .unwrap();
        let rebuilt = index::rebuild(store.as_ref(), &base(PREFIX), &keys(1))
            .await
            .unwrap();
        let sorted = |index: &Index| {
            let mut locations = index.locations();
            locations.sort_by_key(|l| l.entry.id);
            locations
        };
        assert_eq!(sorted(&stored), sorted(&rebuilt));
        assert_eq!(stored.pack_ids(), rebuilt.pack_ids());
    }

    #[tokio::test]
    async fn trees_and_snapshots() {
        let store = Arc::new(MemoryStore::new());
        let repo = init(&store).await;
        let tree = Tree::default();
        let tree_id = repo.save_tree(&tree).await.unwrap();
        // Identical trees deduplicate like any other blob.
        assert_eq!(repo.save_tree(&tree).await.unwrap(), tree_id);

        let mut snap = Snapshot {
            id: Id::default(),
            time: Utc::now(),
            hostname: "h".into(),
            username: String::new(),
            paths: vec!["/a".into()],
            tags: vec![],
            tree: tree_id,
            parent: None,
            stats: Default::default(),
        };
        assert!(
            repo.save_snapshot(&mut snap.clone()).await.is_err(),
            "unflushed packs"
        );
        repo.flush().await.unwrap();
        let id = repo.save_snapshot(&mut snap).await.unwrap();

        let reopened = Repository::open(Arc::clone(&store), PREFIX, keys(1), None)
            .await
            .unwrap();
        assert_eq!(reopened.load_tree(&tree_id).await.unwrap(), tree);
        assert!(reopened.walk(tree_id).await.unwrap().is_empty());
        assert_eq!(reopened.find_snapshot("latest").await.unwrap().id, id);
        assert_eq!(reopened.load_snapshot(&id).await.unwrap(), snap);
    }

    #[tokio::test]
    async fn no_snapshot_after_a_failed_write() {
        let store = Arc::new(MemoryStore::new());
        let repo = init(&store).await;
        let tree_id = repo.save_tree(&Tree::default()).await.unwrap();
        store.fail_puts_under(Some(&format!("{}packs/", base(PREFIX))));
        assert!(repo.flush().await.is_err());
        store.fail_puts_under(None);

        let mut snap = Snapshot {
            id: Id::default(),
            time: Utc::now(),
            hostname: String::new(),
            username: String::new(),
            paths: vec!["/a".into()],
            tags: vec![],
            tree: tree_id,
            parent: None,
            stats: Default::default(),
        };
        assert!(matches!(
            repo.save_snapshot(&mut snap).await,
            Err(Error::RunFailed(_))
        ));
        assert_eq!(objects_under(&store, snapshot::DIR).await, 0);
    }

    /// The bucket copy of every index object is damaged after the first run: a
    /// cached open still works, an uncached one can't, and a damaged cache entry is
    /// replaced from the bucket.
    #[tokio::test]
    async fn index_and_snapshot_caches_avoid_refetching() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(MemoryStore::new());
        let repo = Repository::init(
            Arc::clone(&store),
            PREFIX,
            keys(1),
            InitOptions::default(),
            Some(tmp.path()),
        )
        .await
        .unwrap();
        let (blob, _) = repo.save_blob(BlobType::Data, b"cached").await.unwrap();
        let tree = repo.save_tree(&Tree::default()).await.unwrap();
        repo.flush().await.unwrap();
        let mut snap = Snapshot {
            id: Id::default(),
            time: Utc::now(),
            hostname: String::new(),
            username: String::new(),
            paths: vec!["/a".into()],
            tags: vec![],
            tree,
            parent: None,
            stats: Default::default(),
        };
        let snap_id = repo.save_snapshot(&mut snap).await.unwrap();
        let cache_dir = repo.cache().unwrap().dir().to_path_buf();

        let index_key = store
            .list(&format!("{}{}", base(PREFIX), index::DIR), None)
            .await
            .unwrap()[0]
            .key
            .clone();
        let snapshot_key = format!("{}{}", base(PREFIX), snapshot::object_name(&snap_id));
        let index_bytes = store.get(&index_key).await.unwrap();
        store.put_bytes(&index_key, b"damaged").await.unwrap();
        store.put_bytes(&snapshot_key, b"damaged").await.unwrap();

        let cached = Repository::open(Arc::clone(&store), PREFIX, keys(1), Some(tmp.path()))
            .await
            .unwrap();
        assert!(cached.index().has(&blob));
        assert_eq!(cached.find_snapshot("latest").await.unwrap().id, snap_id);
        assert!(
            Repository::open(Arc::clone(&store), PREFIX, keys(1), None)
                .await
                .is_err()
        );

        // Now the reverse: a damaged cache entry and a healthy bucket.
        store.put_bytes(&index_key, &index_bytes).await.unwrap();
        let index_id = index_key.rsplit('/').next().unwrap();
        let cached_index = cache_dir.join("index").join(index_id);
        std::fs::write(&cached_index, b"garbage").unwrap();
        let reopened = Repository::open(Arc::clone(&store), PREFIX, keys(1), Some(tmp.path()))
            .await
            .unwrap();
        assert!(reopened.index().has(&blob));
        assert_eq!(
            std::fs::read(&cached_index).unwrap(),
            index_bytes,
            "repaired from the bucket"
        );
    }

    /// A cached tree that doesn't match its keyed ID (here, a different valid tree
    /// planted under its name) is ignored in favour of the bucket.
    #[tokio::test]
    async fn tree_cache_is_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(MemoryStore::new());
        let repo = Repository::init(
            Arc::clone(&store),
            PREFIX,
            keys(1),
            InitOptions::default(),
            Some(tmp.path()),
        )
        .await
        .unwrap();
        let real = Tree::default();
        let id = repo.save_tree(&real).await.unwrap();
        repo.flush().await.unwrap();

        let planted = Tree::new(vec![crate::snapshot::Node {
            name: "planted".into(),
            node_type: crate::snapshot::NodeType::Symlink,
            mode: 0o777,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: Utc::now(),
            ctime: None,
            link_target: Some("/etc".into()),
            content: vec![],
            subtree: None,
            device: 0,
            inode: 0,
            links: 0,
            content_hash: None,
            offloaded: false,
        }]);
        let path = repo
            .cache()
            .unwrap()
            .dir()
            .join("tree")
            .join(id.to_string());
        std::fs::write(&path, planted.encode()).unwrap();

        assert_eq!(repo.load_tree(&id).await.unwrap(), real);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            real.encode(),
            "bad entry replaced"
        );
    }

    #[test]
    fn test_keys_are_random() {
        assert_ne!(test_keys().blob_id(b"x"), test_keys().blob_id(b"x"));
    }
}
