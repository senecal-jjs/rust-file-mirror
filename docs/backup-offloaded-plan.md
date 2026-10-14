# Plan: back up the real content of offloaded files

Today `rfm backup create` skips `*.rfm` placeholders and counts them, because the bytes
aren't on disk. A snapshot of a mirror root with offloaded files is therefore
incomplete, and the backups are weakest exactly where local disk is scarcest. This plan
makes snapshots hold each offloaded file's real content, under its real name, restorable
like any other file.

## What we have to work with

- **A placeholder** (`photo.jpg.rfm`, `mirror_core::placeholder::StubMeta`) records `path`,
  `size`, `hash` (plaintext BLAKE3), `object_key`, and `evicted_at`. It does **not**
  record the original mtime or permissions.
- **The remote copy** is `<prefix><object_key>`, sealed with the vault's `content_key`
  (XChaCha20-Poly1305 STREAM) with the file's logical path as AAD
  (`apply::download::fetch_verified`). The backup process already unlocks the vault, so
  it holds this key.
- **The mirror and backup use the same hash.** The stub's `hash` is the same plain
  BLAKE3 the archiver can compute while chunking.

## Approach: reuse when we can, stream when we must

Most offloaded files were local, and backed up, before they were offloaded. Their
content is already in the repository, so a placeholder only needs a way to find it. The
rest (files offloaded before their first backup, or files that arrived on this device
already offloaded) are streamed from the mirror's remote copy, decrypted in memory,
chunked, and stored like any other file.

### 1. Record each file's content hash in snapshots

- Add `content_hash: Option<String>` (plain BLAKE3, hex) to `snapshot::Node`. The
  archiver computes it with a `blake3::Hasher` fed by the chunks it already reads, at no
  extra I/O. The fast path copies it from the parent node with the chunk list.
- Add `offloaded: bool` (serde default `false`) so `rfm backup list` can mark files that
  were placeholders when backed up.
- Build a second map from the parent snapshot, `content_hash → (chunks, size, metadata)`,
  alongside the existing path map. Lookups by hash also catch files that were moved
  before they were offloaded.

Storing the plain hash inside trees exposes nothing new: trees are encrypted, and the
mirror already stores the same hash in its own encrypted manifest.

### 2. Archiver: treat a placeholder as the file it stands for

When the walk finds a verified stub `X.rfm` (it already checks with
`placeholder::read`):

1. **Name it `X`.** If a real `X` also exists (which the mirror shouldn't allow), the
   real file wins, with a warning.
2. **Reuse:** if the stub's hash is in the parent map, the node takes the parent's chunk
   list, mode, owner and mtime. Nothing is downloaded. This is the expected path on
   every run after the first.
3. **Fetch:** otherwise ask an `OffloadedSource` (below) for a reader of the plaintext,
   chunk it as usual, and check the BLAKE3 of what was read against the stub's hash. A
   mismatch, or a missing remote object, goes to the skip policy like an unreadable
   file: warn, count, carry on. Chunks already stored for it are left unreferenced for
   the next prune.
4. **Metadata for a fetched file** comes from the placeholder, which now records the
   original `mtime_ns` and `mode` (section 5). Placeholders written by older versions
   lack them, so the archiver falls back to the placeholder file's own mtime and to
   mode `0644`. Owner and group come from the placeholder file.

`backup-core` stays free of mirror keys and formats. The archiver takes a trait object:

```rust
pub trait OffloadedSource: Send + Sync {
    /// The plaintext behind a placeholder; read on a blocking worker thread.
    fn open(&self, stub: &StubMeta) -> Result<Box<dyn Read + Send>>;
}

pub struct Options {
    // replaces `skip_placeholders: bool`
    pub offloaded: Offloaded, // Skip | Include(Arc<dyn OffloadedSource>)
    // ...
}
```

### 3. Streaming the remote copy (mirror-core)

- Factor the decrypt loop out of `fetch_verified` into
  `apply::download::open_plaintext(store, prefix, object_key, aad_path, content_key)`.
  It returns an async stream of plaintext parts and works for both single-shot and
  multipart objects. `fetch_verified` then becomes "stream into a temp file and verify",
  with no change in behavior.
- The CLI's `OffloadedSource` wraps that stream in a blocking `Read`, the same
  `Handle::block_on` pattern the archiver uses for `save_blob`. Plaintext never touches
  disk, and memory stays bounded by one download part plus the chunker's buffer.
- Use `stub.path` as the AAD, because the object was sealed for the logical path.

### 4. Stats, output, config

- Replace `placeholders_skipped` with `offloaded_reused`, `offloaded_downloaded`,
  `offloaded_bytes_downloaded` and `offloaded_skipped`.
- Add a summary line: `offloaded  41 reused, 3 downloaded (212 MiB)`. Progress says
  which file is downloading.
- Config: `[backup] offloaded = "include" | "skip"`, defaulting to `include`, with a
  `--skip-offloaded` flag. There's no download cap.
- The daemon picks all of this up through `backup::Request`.

### 5. Placeholders record mode and mtime

`StubMeta` gains optional `mtime_ns` and `mode` fields (serde default, omitted when
unknown). Older versions still read new placeholders, since unknown fields are ignored,
and new versions read old ones as "unknown". `FORMAT` stays 1. Each place that writes a
placeholder fills in what it knows:

| Written by | mtime | mode |
|---|---|---|
| Offloading a local file (`apply::evict`) | the file's | the file's |
| Relocating a conflict loser (`execute`, `Relocate`) | the upload's | unknown |
| A file arriving already offloaded (`Create/UpdatePlaceholder`) | the manifest's `mtime_utc` | unknown |

### 6. Restore

Offloaded files restore as ordinary files with their real names and content. Restoring
them as placeholders (into a mirror root, to save space) is possible later but out of
scope here.

## Edge cases

| Case | Behavior |
|---|---|
| Hydrated during the backup | The walk sees either the stub or the real file; both give the same content. |
| Offloaded while being read | The read fails, the file is skipped with a warning, and the next run reuses or fetches it. |
| Remote object gone (stale stub) | Skipped with a warning suggesting `rfm sync`. |
| Placeholder moved by hand | Stored under its current location; decrypted using `stub.path` as AAD. |
| `.rfm` file outside the mirror root, or not a valid stub | Backed up as a normal file, as today. |
| Parent snapshot pruned | No reuse is possible, so the first run after that downloads. Retention keeps recent parents. |

## Phases

1. **Content hashes (backup-core only).** `Node.content_hash` and `offloaded`, a hasher
   in `archive_file`, the parent hash map. Tests: hashes match `mirror_core::hash`, and
   the fast path carries them over.
2. **Placeholders in the archiver.** The `OffloadedSource` trait, stub handling (rename,
   reuse, fetch, verify, skip), new stats. Tests use a fake source that counts opens:
   - a file backed up, then offloaded, then backed up again downloads nothing;
   - a file that was never local is fetched and restores byte-identical;
   - a hash mismatch and a missing object are skipped and counted;
   - a name collision prefers the real file.
3. **Mirror-core stream, placeholder metadata, and CLI.** `open_plaintext`, refactoring
   `fetch_verified` onto it, `StubMeta.mtime_ns`/`mode` at every write site, the CLI
   source, config, flags, summary, daemon.
   Tests: the existing download tests still pass; a MinIO integration test offloads a
   file with the real eviction path (`apply::evict`), backs up, restores and compares.
4. **Docs and smoke test.** README and plan updates. Then a real-binary run: `rfm evict`
   a file, `rfm backup create` (downloads once), `rfm backup create` again (reuses), and
   `rfm backup restore` with `diff -r`.

A possible later phase: a local `hash → chunks` cache built from every snapshot (they're
immutable, so it updates incrementally), so a file another device already backed up can
be reused instead of downloaded.

## Decisions

1. **Offloaded content is included by default**, with `offloaded = "skip"` or
   `--skip-offloaded` to opt out.
2. **There's no per-run download cap.**
3. **Placeholders record mode and mtime** from now on (section 5).

## Size

Roughly 600–900 lines including tests, mostly in `archiver.rs`, `download.rs` and the
CLI's backup module. There's no repository format version bump: the new node fields
are optional, and the first run after upgrading rewrites trees once, which is cheap.
