//! Pack objects: many sealed blobs in one S3 object.
//!
//! S3 charges per request, and content-defined chunking yields about one chunk per
//! megabyte. Aggregating chunks into ~16 MiB packs cuts request counts by more than
//! an order of magnitude, at the cost of needing an index to find a chunk again.
//!
//! ```text
//! +---------------------+
//! | sealed blob 0       |  each sealed on its own, so one chunk costs one ranged GET
//! | sealed blob 1       |
//! | ...                 |
//! +---------------------+
//! | sealed header       |  entry per blob: type, compression, ID, offset, lengths
//! +---------------------+
//! | header length (u32) |
//! | magic "RFMB"        |  footer, fixed 12 bytes, little-endian
//! | version (u32)       |
//! +---------------------+
//! ```
//!
//! The header sits at the tail so packs describe themselves: reading the last few
//! kilobytes of an object recovers its blob list, and a lost index can be rebuilt
//! from the packs alone.

use std::collections::HashSet;

use mirror_core::store::ObjectStore;

use crate::compress::{Compression, compress, decompress};
use crate::crypto::{ID_SIZE, Id, KeyKind, Keys};
use crate::error::{Error, Result};

/// The pack size the repository aims for before starting a new one.
pub const TARGET_SIZE: usize = 16 << 20;

const MAGIC: &[u8; 4] = b"RFMB";
const FORMAT_VERSION: u32 = 1;
pub const FOOTER_SIZE: usize = 12;
/// type (1) + compression (1) + ID (32) + offset, length, plain length (3 × u32).
pub const ENTRY_SIZE: usize = 2 + ID_SIZE + 12;

/// Bounds the header a reader will decode, so a corrupt length field can't make it
/// allocate arbitrary memory.
pub const MAX_HEADER_SIZE: u32 = 64 << 20;

/// How much of a pack's tail to fetch when recovering its header. A 16 MiB pack of
/// megabyte chunks has a header well under a kilobyte (46 bytes an entry), so one
/// small read almost always gets the footer and the whole header; a pack of many
/// small blobs takes a second, exact one. Kept small because adopting or rebuilding
/// reads hundreds of these, and every extra kilobyte is downloaded hundreds of times.
const TAIL_READ_SIZE: u64 = 4 << 10;

/// The object name of a pack, relative to the backup repository's base.
pub fn object_name(id: &Id) -> String {
    let hex = id.to_string();
    format!("packs/{}/{hex}", &hex[..2])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlobType {
    /// File content.
    Data = 1,
    /// Directory metadata. Trees live in packs next to file data so they're
    /// deduplicated and encrypted the same way: an unchanged directory costs nothing
    /// to back up again.
    Tree = 2,
}

impl BlobType {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Data),
            2 => Some(Self::Tree),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Tree => "tree",
        }
    }

    /// Bulk content uses the data subkey; everything describing structure is
    /// metadata.
    fn key_kind(&self) -> KeyKind {
        match self {
            Self::Data => KeyKind::Data,
            Self::Tree => KeyKind::Meta,
        }
    }
}

/// One blob's placement inside a pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub blob_type: BlobType,
    pub compression: Compression,
    pub id: Id,
    /// Offset and length of the sealed bytes: exactly the range a restore fetches.
    pub offset: u32,
    pub length: u32,
    /// Size of the original, uncompressed blob.
    pub plain_length: u32,
}

impl Entry {
    pub fn end(&self) -> u64 {
        u64::from(self.offset) + u64::from(self.length)
    }
}

/// Binds a sealed blob to its identity: without it, a valid sealed blob could be
/// moved under a different entry and decrypt successfully as the wrong content.
fn blob_aad(blob_type: BlobType, id: &Id) -> String {
    format!("rfm-backup:v1:blob:{}:{id}", blob_type.as_str())
}

/// Binds a sealed header to its pack, so headers can't be swapped between packs.
fn header_aad(pack_id: &Id) -> String {
    format!("rfm-backup:v1:pack-header:{pack_id}")
}

/// Serializes an entry list: a u32 count, then fixed-size entries. Index objects use
/// the same encoding.
pub fn encode_entries(entries: &[Entry], out: &mut Vec<u8>) {
    out.reserve(4 + entries.len() * ENTRY_SIZE);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.push(e.blob_type as u8);
        out.push(e.compression as u8);
        out.extend_from_slice(&e.id.0);
        out.extend_from_slice(&e.offset.to_le_bytes());
        out.extend_from_slice(&e.length.to_le_bytes());
        out.extend_from_slice(&e.plain_length.to_le_bytes());
    }
}

/// Parses one `encode_entries` list off the front of `data`, returning the entries
/// and whatever follows them.
pub fn decode_entries(data: &[u8]) -> Result<(Vec<Entry>, &[u8])> {
    let bad = |msg: String| Error::Format(format!("entry list: {msg}"));

    let (count, rest) = data
        .split_first_chunk::<4>()
        .ok_or_else(|| bad(format!("only {} bytes", data.len())))?;
    let count = u32::from_le_bytes(*count) as usize;

    let body_len = count
        .checked_mul(ENTRY_SIZE)
        .filter(|&len| len <= rest.len())
        .ok_or_else(|| {
            bad(format!(
                "declares {count} entries but has {} bytes",
                rest.len()
            ))
        })?;
    let (body, rest) = rest.split_at(body_len);

    let u32_at = |raw: &[u8], at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
    let entries = body
        .chunks_exact(ENTRY_SIZE)
        .enumerate()
        .map(|(i, raw)| {
            Ok(Entry {
                blob_type: BlobType::from_byte(raw[0])
                    .ok_or_else(|| bad(format!("entry {i} has unknown blob type {}", raw[0])))?,
                compression: Compression::from_byte(raw[1])
                    .ok_or_else(|| bad(format!("entry {i} has unknown compression {}", raw[1])))?,
                id: Id::from_slice(&raw[2..2 + ID_SIZE])?,
                offset: u32_at(raw, 34),
                length: u32_at(raw, 38),
                plain_length: u32_at(raw, 42),
            })
        })
        .collect::<Result<_>>()?;

    Ok((entries, rest))
}

fn encode_footer(header_len: u32) -> [u8; FOOTER_SIZE] {
    let mut footer = [0u8; FOOTER_SIZE];
    footer[0..4].copy_from_slice(&header_len.to_le_bytes());
    footer[4..8].copy_from_slice(MAGIC);
    footer[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    footer
}

/// Returns the sealed header's length.
fn decode_footer(footer: &[u8]) -> Result<u32> {
    let footer: &[u8; FOOTER_SIZE] = footer
        .try_into()
        .map_err(|_| Error::Format(format!("pack footer of {} bytes", footer.len())))?;

    if &footer[4..8] != MAGIC {
        return Err(Error::Format(
            "pack: not a pack object, or it is truncated".into(),
        ));
    }
    let version = u32::from_le_bytes(footer[8..12].try_into().unwrap());
    if version != FORMAT_VERSION {
        return Err(Error::Format(format!(
            "pack: format version {version}, this build understands {FORMAT_VERSION}"
        )));
    }
    let header_len = u32::from_le_bytes(footer[0..4].try_into().unwrap());
    if header_len > MAX_HEADER_SIZE {
        return Err(Error::Format(format!(
            "pack: header claims {header_len} bytes, over the {MAX_HEADER_SIZE} byte limit"
        )));
    }
    Ok(header_len)
}

/// Assembles blobs into one pack in memory. Packs are tens of megabytes at most, so
/// buffering the whole object is cheap, and it lets the header follow the blobs
/// without seeking.
pub struct Writer {
    id: Id,
    compression: Compression,
    buf: Vec<u8>,
    entries: Vec<Entry>,
    seen: HashSet<Id>,
}

/// A blob compressed and sealed for a pack, not yet placed in one.
pub struct SealedBlob {
    blob_type: BlobType,
    compression: Compression,
    id: Id,
    plain_length: u32,
    sealed: Vec<u8>,
}

impl SealedBlob {
    pub fn seal(
        keys: &Keys,
        compression: Compression,
        blob_type: BlobType,
        id: Id,
        plaintext: &[u8],
    ) -> Result<Self> {
        let plain_length = u32::try_from(plaintext.len()).map_err(|_| {
            Error::Invalid(format!("blob of {} bytes is too large", plaintext.len()))
        })?;
        let (stored, compression) = compress(plaintext, compression)?;
        let sealed = keys.seal(blob_type.key_kind(), &stored, &blob_aad(blob_type, &id))?;

        Ok(Self {
            blob_type,
            compression,
            id,
            plain_length,
            sealed,
        })
    }

    pub fn id(&self) -> Id {
        self.id
    }

    /// A blob already sealed in another pack, for copying into a new one as is: the
    /// seal binds a blob to its own type and ID, not to the pack it's in, so it moves
    /// between packs without being re-encrypted.
    pub fn from_entry(entry: &Entry, sealed: Vec<u8>) -> Self {
        Self {
            blob_type: entry.blob_type,
            compression: entry.compression,
            id: entry.id,
            plain_length: entry.plain_length,
            sealed,
        }
    }
}

/// A finished pack, ready to upload.
#[derive(Debug)]
pub struct Pack {
    pub id: Id,
    pub data: Vec<u8>,
    pub entries: Vec<Entry>,
}

impl Writer {
    /// Each pack gets a random ID: it has to be known before the header is sealed,
    /// and no two packs hold the same blobs in practice, so content addressing would
    /// buy nothing here.
    pub fn new(compression: Compression) -> Self {
        Self {
            id: Id::random(),
            compression,
            buf: Vec::new(),
            entries: Vec::new(),
            seen: HashSet::new(),
        }
    }

    pub fn id(&self) -> Id {
        self.id
    }

    /// Bytes written so far, without the header and footer `finish` will add.
    pub fn size(&self) -> usize {
        self.buf.len()
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn has(&self, id: &Id) -> bool {
        self.seen.contains(id)
    }

    /// Compresses, seals, and appends a blob. Returns false, storing nothing, if the
    /// pack already holds `id`. The caller checks the repository index first: this
    /// only deduplicates within one pack.
    pub fn add(
        &mut self,
        keys: &Keys,
        blob_type: BlobType,
        id: Id,
        plaintext: &[u8],
    ) -> Result<bool> {
        if self.seen.contains(&id) {
            return Ok(false);
        }
        let sealed = SealedBlob::seal(keys, self.compression, blob_type, id, plaintext)?;
        self.push(sealed)
    }

    /// Appends a blob sealed ahead of time, so callers sharing one writer can do the
    /// expensive compression and encryption without holding it. Returns false if the
    /// pack already holds the blob.
    pub fn push(&mut self, blob: SealedBlob) -> Result<bool> {
        if self.seen.contains(&blob.id) {
            return Ok(false);
        }

        let offset = u32::try_from(self.buf.len())
            .ok()
            .filter(|offset| offset.checked_add(blob.sealed.len() as u32).is_some())
            .ok_or_else(|| Error::Invalid("pack has grown beyond the addressable size".into()))?;

        self.buf.extend_from_slice(&blob.sealed);
        self.entries.push(Entry {
            blob_type: blob.blob_type,
            compression: blob.compression,
            id: blob.id,
            offset,
            length: blob.sealed.len() as u32,
            plain_length: blob.plain_length,
        });
        self.seen.insert(blob.id);
        Ok(true)
    }

    /// Seals the header and appends it with the footer.
    pub fn finish(mut self, keys: &Keys) -> Result<Pack> {
        if self.entries.is_empty() {
            return Err(Error::Invalid("refusing to finish an empty pack".into()));
        }

        let mut header = Vec::new();
        encode_entries(&self.entries, &mut header);
        let sealed_header = keys.seal(KeyKind::Meta, &header, &header_aad(&self.id))?;
        let header_len = u32::try_from(sealed_header.len())
            .ok()
            .filter(|&len| len <= MAX_HEADER_SIZE)
            .ok_or_else(|| Error::Invalid("pack header exceeds the size limit".into()))?;

        self.buf.extend_from_slice(&sealed_header);
        self.buf.extend_from_slice(&encode_footer(header_len));

        Ok(Pack {
            id: self.id,
            data: self.buf,
            entries: self.entries,
        })
    }
}

/// Decrypts and parses a sealed header. `data_len` is the size of the blob region
/// (everything before the sealed header); every entry must lie inside it.
pub fn decode_header(
    keys: &Keys,
    pack_id: &Id,
    sealed: &[u8],
    data_len: u64,
) -> Result<Vec<Entry>> {
    let what = format!("pack {} header", pack_id.short());
    let plaintext = keys.open(KeyKind::Meta, sealed, &header_aad(pack_id), &what)?;

    let (entries, rest) = decode_entries(&plaintext)?;
    if !rest.is_empty() {
        return Err(Error::Format(format!(
            "{what}: {} trailing bytes",
            rest.len()
        )));
    }
    if let Some(e) = entries.iter().find(|e| e.end() > data_len) {
        return Err(Error::Format(format!(
            "{what}: blob {} ends at {} but the blob region is {data_len} bytes",
            e.id.short(),
            e.end()
        )));
    }
    Ok(entries)
}

/// Where the sealed header sits in a pack of `size` bytes, given its footer.
fn header_range(pack_id: &Id, footer: &[u8], size: u64) -> Result<(u64, u32)> {
    let header_len = decode_footer(footer)
        .map_err(|e| Error::Format(format!("pack {}: {e}", pack_id.short())))?;
    let start = size
        .checked_sub(FOOTER_SIZE as u64 + u64::from(header_len))
        .ok_or_else(|| {
            Error::Format(format!(
                "pack {} declares a {header_len} byte header but is only {size} bytes",
                pack_id.short()
            ))
        })?;
    Ok((start, header_len))
}

/// Recovers the header from a complete pack already in memory.
pub fn parse_header(keys: &Keys, pack_id: &Id, data: &[u8]) -> Result<Vec<Entry>> {
    if data.len() < FOOTER_SIZE {
        return Err(Error::Format(format!(
            "pack {} is only {} bytes",
            pack_id.short(),
            data.len()
        )));
    }
    let size = data.len() as u64;
    let (start, header_len) = header_range(pack_id, &data[data.len() - FOOTER_SIZE..], size)?;
    let start = start as usize;
    decode_header(
        keys,
        pack_id,
        &data[start..start + header_len as usize],
        start as u64,
    )
}

/// Reads a pack's header straight from storage, fetching only its tail.
pub async fn load_header(
    store: &impl ObjectStore,
    object_key: &str,
    keys: &Keys,
    pack_id: &Id,
) -> Result<Vec<Entry>> {
    let size = store
        .head(object_key)
        .await?
        .ok_or_else(|| Error::Format(format!("pack {} is missing", pack_id.short())))?
        .size;
    load_header_sized(store, object_key, keys, pack_id, size).await
}

/// `load_header` for a pack whose size is already known (say, from a listing),
/// saving the HEAD request.
pub async fn load_header_sized(
    store: &impl ObjectStore,
    object_key: &str,
    keys: &Keys,
    pack_id: &Id,
    size: u64,
) -> Result<Vec<Entry>> {
    if size < FOOTER_SIZE as u64 {
        return Err(Error::Format(format!(
            "pack {} is only {size} bytes",
            pack_id.short()
        )));
    }

    let read_len = TAIL_READ_SIZE.min(size);
    let tail = store
        .get_range(object_key, size - read_len, read_len)
        .await?;
    let (start, header_len) = header_range(pack_id, &tail[tail.len() - FOOTER_SIZE..], size)?;

    let sealed = if start >= size - read_len {
        let at = (start - (size - read_len)) as usize;
        tail[at..at + header_len as usize].to_vec()
    } else {
        store
            .get_range(object_key, start, u64::from(header_len))
            .await?
    };

    decode_header(keys, pack_id, &sealed, start)
}

/// Decrypts, decompresses, and verifies one blob read from a pack. The recomputed ID
/// must match, which catches silent storage corruption and an index pointing at the
/// wrong offset.
pub fn decode_blob(keys: &Keys, entry: &Entry, sealed: &[u8]) -> Result<Vec<u8>> {
    let what = format!("{} blob {}", entry.blob_type.as_str(), entry.id.short());
    if sealed.len() != entry.length as usize {
        return Err(Error::Format(format!(
            "{what}: {} bytes, but its entry says {}",
            sealed.len(),
            entry.length
        )));
    }

    let stored = keys.open(
        entry.blob_type.key_kind(),
        sealed,
        &blob_aad(entry.blob_type, &entry.id),
        &what,
    )?;
    let plaintext = decompress(stored, entry.compression, entry.plain_length as usize)?;

    if !keys.verify_blob_id(&entry.id, &plaintext) {
        return Err(Error::Corrupt(what));
    }
    Ok(plaintext)
}

/// Fetches and decodes a single blob with one ranged read.
pub async fn load_blob(
    store: &impl ObjectStore,
    object_key: &str,
    keys: &Keys,
    entry: &Entry,
) -> Result<Vec<u8>> {
    let sealed = store
        .get_range(object_key, u64::from(entry.offset), u64::from(entry.length))
        .await?;
    decode_blob(keys, entry, &sealed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_keys;
    use mirror_core::store::memory::MemoryStore;
    use rand::Rng;

    fn random_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        rand::rng().fill(&mut bytes[..]);
        bytes
    }

    /// Builds a pack from `blobs`, returning it with the blob plaintexts by ID.
    fn build(keys: &Keys, blobs: &[(BlobType, Vec<u8>)]) -> Pack {
        let mut writer = Writer::new(Compression::Zstd);
        for (blob_type, plaintext) in blobs {
            writer
                .add(keys, *blob_type, keys.blob_id(plaintext), plaintext)
                .unwrap();
        }
        writer.finish(keys).unwrap()
    }

    fn slice<'a>(pack: &'a Pack, entry: &Entry) -> &'a [u8] {
        &pack.data[entry.offset as usize..entry.end() as usize]
    }

    #[test]
    fn write_and_read_blobs() {
        let keys = test_keys();
        let blobs = vec![
            (BlobType::Data, random_bytes(100_000)),
            (BlobType::Data, b"compressible ".repeat(5000)),
            (BlobType::Data, Vec::new()),
            (BlobType::Tree, br#"{"nodes":[]}"#.to_vec()),
        ];
        let pack = build(&keys, &blobs);

        let header = parse_header(&keys, &pack.id, &pack.data).unwrap();
        assert_eq!(header, pack.entries);
        for ((blob_type, plaintext), entry) in blobs.iter().zip(&header) {
            assert_eq!(entry.blob_type, *blob_type);
            assert_eq!(entry.plain_length as usize, plaintext.len());
            assert_eq!(
                &decode_blob(&keys, entry, slice(&pack, entry)).unwrap(),
                plaintext
            );
        }
        assert_eq!(header[1].compression, Compression::Zstd);
        assert_eq!(header[0].compression, Compression::None);
    }

    #[tokio::test]
    async fn header_and_blobs_load_from_a_store() {
        let keys = test_keys();
        let blobs: Vec<_> = (0..20)
            .map(|i| (BlobType::Data, random_bytes(1000 * (i + 1))))
            .collect();
        let pack = build(&keys, &blobs);

        let store = MemoryStore::new();
        let key = format!("rfm/backup/{}", object_name(&pack.id));
        store.put_bytes(&key, &pack.data).await.unwrap();

        let header = load_header(&store, &key, &keys, &pack.id).await.unwrap();
        assert_eq!(header, pack.entries);
        for ((_, plaintext), entry) in blobs.iter().zip(&header) {
            assert_eq!(
                &load_blob(&store, &key, &keys, entry).await.unwrap(),
                plaintext
            );
        }
    }

    /// A header bigger than the tail read needs a second, exact request.
    #[tokio::test]
    async fn large_header_falls_back_to_a_second_read() {
        let keys = test_keys();
        let blobs: Vec<_> = (0..4000u32)
            .map(|i| (BlobType::Data, i.to_le_bytes().to_vec()))
            .collect();
        let pack = build(&keys, &blobs);
        assert!(pack.entries.len() * ENTRY_SIZE > TAIL_READ_SIZE as usize);

        let store = MemoryStore::new();
        store.put_bytes("p", &pack.data).await.unwrap();
        assert_eq!(
            load_header(&store, "p", &keys, &pack.id).await.unwrap(),
            pack.entries
        );
    }

    #[tokio::test]
    async fn load_header_on_missing_or_tiny_pack() {
        let keys = test_keys();
        let store = MemoryStore::new();
        assert!(
            load_header(&store, "missing", &keys, &Id::random())
                .await
                .is_err()
        );
        store.put_bytes("tiny", b"short").await.unwrap();
        assert!(
            load_header(&store, "tiny", &keys, &Id::random())
                .await
                .is_err()
        );
    }

    #[test]
    fn add_skips_duplicates_within_a_pack() {
        let keys = test_keys();
        let mut writer = Writer::new(Compression::Zstd);
        let id = keys.blob_id(b"dup");
        assert!(writer.add(&keys, BlobType::Data, id, b"dup").unwrap());
        let size = writer.size();
        assert!(!writer.add(&keys, BlobType::Data, id, b"dup").unwrap());
        assert_eq!((writer.size(), writer.count()), (size, 1));
        assert!(writer.has(&id));
    }

    #[test]
    fn compression_disabled_stores_verbatim() {
        let keys = test_keys();
        let mut writer = Writer::new(Compression::None);
        let plaintext = b"a".repeat(10_000);
        writer
            .add(&keys, BlobType::Data, keys.blob_id(&plaintext), &plaintext)
            .unwrap();
        let pack = writer.finish(&keys).unwrap();
        assert_eq!(pack.entries[0].compression, Compression::None);
    }

    #[test]
    fn blob_is_bound_to_its_identity() {
        let keys = test_keys();
        let pack = build(
            &keys,
            &[
                (BlobType::Data, b"one".to_vec()),
                (BlobType::Data, b"two".to_vec()),
            ],
        );
        let (a, b) = (pack.entries[0], pack.entries[1]);

        // b's bytes presented under a's entry (lengths match, so only AAD can catch it).
        let swapped = Entry {
            offset: b.offset,
            ..a
        };
        assert!(matches!(
            decode_blob(&keys, &swapped, slice(&pack, &b)),
            Err(Error::Decryption(_))
        ));

        // The same bytes relabeled with a different type.
        let retyped = Entry {
            blob_type: BlobType::Tree,
            ..a
        };
        assert!(decode_blob(&keys, &retyped, slice(&pack, &a)).is_err());
    }

    #[test]
    fn header_is_bound_to_its_pack() {
        let keys = test_keys();
        let pack = build(&keys, &[(BlobType::Data, b"x".to_vec())]);
        assert!(parse_header(&keys, &Id::random(), &pack.data).is_err());
    }

    #[test]
    fn corruption_is_detected_everywhere() {
        let keys = test_keys();
        let pack = build(&keys, &[(BlobType::Data, random_bytes(5000))]);
        let entry = pack.entries[0];

        let mut blob = slice(&pack, &entry).to_vec();
        blob[100] ^= 1;
        assert!(decode_blob(&keys, &entry, &blob).is_err());
        assert!(decode_blob(&keys, &entry, &slice(&pack, &entry)[1..]).is_err());

        let header_byte = pack.data.len() - FOOTER_SIZE - 5;
        let magic_byte = pack.data.len() - 7;
        let len_byte = pack.data.len() - FOOTER_SIZE;
        for i in [header_byte, magic_byte, len_byte] {
            let mut data = pack.data.clone();
            data[i] ^= 1;
            assert!(
                parse_header(&keys, &pack.id, &data).is_err(),
                "flip at {i} accepted"
            );
        }
        assert!(parse_header(&keys, &pack.id, &pack.data[..pack.data.len() - 1]).is_err());
    }

    /// A blob that authenticates but whose plaintext doesn't hash to its ID: only
    /// someone with the key can make one, but a buggy writer could too.
    #[test]
    fn content_not_matching_its_id_is_corrupt() {
        let keys = test_keys();
        let mut writer = Writer::new(Compression::None);
        writer
            .add(&keys, BlobType::Data, keys.blob_id(b"claimed"), b"actual")
            .unwrap();
        let pack = writer.finish(&keys).unwrap();
        let entry = pack.entries[0];
        assert!(matches!(
            decode_blob(&keys, &entry, slice(&pack, &entry)),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn wrong_key_cannot_read_pack() {
        let keys = test_keys();
        let pack = build(&keys, &[(BlobType::Data, b"secret".to_vec())]);
        let other = test_keys();
        assert!(parse_header(&other, &pack.id, &pack.data).is_err());
        assert!(decode_blob(&other, &pack.entries[0], slice(&pack, &pack.entries[0])).is_err());
    }

    #[test]
    fn pack_leaks_no_plaintext() {
        let keys = test_keys();
        let marker = b"VERY-RECOGNIZABLE-PLAINTEXT-MARKER".repeat(100);
        let pack = build(
            &keys,
            &[(BlobType::Data, marker.clone()), (BlobType::Tree, marker)],
        );
        let needle = b"RECOGNIZABLE";
        assert!(!pack.data.windows(needle.len()).any(|w| w == needle));
        let id = pack.entries[0].id;
        assert!(
            !pack.data.windows(ID_SIZE).any(|w| w == id.0),
            "blob IDs must not appear in clear"
        );
    }

    #[test]
    fn finish_rejects_empty_pack() {
        assert!(Writer::new(Compression::Zstd).finish(&test_keys()).is_err());
    }

    #[test]
    fn entry_codec_round_trips() {
        let entries: Vec<_> = (0..5u32)
            .map(|i| Entry {
                blob_type: if i % 2 == 0 {
                    BlobType::Data
                } else {
                    BlobType::Tree
                },
                compression: if i % 3 == 0 {
                    Compression::Zstd
                } else {
                    Compression::None
                },
                id: Id::random(),
                offset: i * 1000,
                length: i + 40,
                plain_length: u32::MAX - i,
            })
            .collect();
        let mut buf = Vec::new();
        encode_entries(&entries, &mut buf);
        buf.extend_from_slice(b"tail");
        assert_eq!(buf.len(), 4 + entries.len() * ENTRY_SIZE + 4);

        let (decoded, rest) = decode_entries(&buf).unwrap();
        assert_eq!((decoded, rest), (entries, &b"tail"[..]));
    }

    #[test]
    fn decode_entries_rejects_malformed_input() {
        let mut one = Vec::new();
        encode_entries(
            &[Entry {
                blob_type: BlobType::Data,
                compression: Compression::None,
                id: Id::random(),
                offset: 0,
                length: 1,
                plain_length: 1,
            }],
            &mut one,
        );

        assert!(decode_entries(&[]).is_err());
        assert!(decode_entries(&[1, 0]).is_err());
        assert!(decode_entries(&one[..one.len() - 1]).is_err());
        assert!(decode_entries(&[0xff, 0xff, 0xff, 0xff]).is_err());

        let mut bad_type = one.clone();
        bad_type[4] = 9;
        assert!(decode_entries(&bad_type).is_err());
        let mut bad_compression = one.clone();
        bad_compression[5] = 9;
        assert!(decode_entries(&bad_compression).is_err());
    }

    #[test]
    fn decode_footer_rejects_malformed_input() {
        assert_eq!(decode_footer(&encode_footer(123)).unwrap(), 123);
        assert!(decode_footer(&[0u8; 11]).is_err());

        let mut magic = encode_footer(1);
        magic[4] = b'X';
        assert!(decode_footer(&magic).is_err());

        let mut version = encode_footer(1);
        version[8] = 2;
        assert!(decode_footer(&version).is_err());

        assert!(decode_footer(&encode_footer(MAX_HEADER_SIZE + 1)).is_err());
    }

    /// An authentic header (sealed with the right key) whose entries point past the
    /// blob region: a writer bug, not tampering, but it must not reach a ranged read.
    #[test]
    fn entries_outside_the_blob_region_are_rejected() {
        let keys = test_keys();
        let pack_id = Id::random();
        let entries = [Entry {
            blob_type: BlobType::Data,
            compression: Compression::None,
            id: Id::random(),
            offset: 10,
            length: 100,
            plain_length: 50,
        }];
        let mut header = Vec::new();
        encode_entries(&entries, &mut header);
        let sealed = keys
            .seal(KeyKind::Meta, &header, &header_aad(&pack_id))
            .unwrap();

        assert!(decode_header(&keys, &pack_id, &sealed, 110).is_ok());
        assert!(decode_header(&keys, &pack_id, &sealed, 109).is_err());
    }

    #[test]
    fn object_name_shards_by_id_prefix() {
        let id: Id = format!("ab{}", "0".repeat(62)).parse().unwrap();
        assert_eq!(object_name(&id), format!("packs/ab/ab{}", "0".repeat(62)));
    }
}
