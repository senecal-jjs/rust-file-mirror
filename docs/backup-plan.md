# Plan: encrypted, deduplicating backups in rfm

Port the design of `cmd-line-backup` (gobackup) into rfm, so one tool and one S3 bucket
cover both live mirroring and point-in-time history. The mirror copies deletions and
overwrites to every device, so it is not a backup on its own. Snapshots close that gap.

## Decisions

- **Native format, no gobackup compatibility.** No gobackup repositories exist that need to
  stay readable, so we keep the design (FastCDC chunking, packs, additive indexes, tree
  blobs, write ordering) and use rfm's own crypto and serialization.
- **One passphrase.** The backup key is derived from the existing vault. `rfm init` stays
  the only setup step, and the daemon's stored passphrase covers backups too.
- **The Go tool is not maintained alongside this.** There's no format to freeze, so v1 can
  change freely until it ships.

## On-disk format (v1)

### Bucket layout

Everything lives under the existing remote prefix, next to the mirror's objects:

```
<prefix>vault.json                     existing, shared
<prefix>data/ log/ snapshot/           existing mirror objects
<prefix>backup/config                  repo config (sealed): version, repo id, chunker params, compression
<prefix>backup/packs/<ab>/<id>         ~16 MiB packs
<prefix>backup/indexes/<id>            chunk id -> pack + range, one per backup run
<prefix>backup/snapshots/<id>          one per backup run
```

The mirror's object GC only lists and deletes under `<prefix>data/`
(`manifest::collect_garbage`), so backup objects are safe from it. Unlike gobackup there is
no `keys/` directory, because the key comes from the vault.

### Keys

- Add `backup_key` to `DerivedSubKeys` in `crypto/key.rs`, expanded with info
  `rfm:v1:backup`. This is a separate HKDF expansion, so existing mirror keys and data are
  unaffected.
- Derive three subkeys from `backup_key` with BLAKE3 `derive_key` (contexts
  `rfm backup v1 blob id key`, `… data key` and `… metadata key`). Data and metadata stay
  separate, as in gobackup.

### Cryptography

| Purpose | gobackup | rfm backup |
|---|---|---|
| Object encryption | AES-256-GCM, per-object HKDF key, zero nonce | `crypto::content::encrypt_bytes`: XChaCha20-Poly1305 STREAM, random nonce |
| Chunk IDs | HMAC-SHA256 | keyed BLAKE3 (`blake3::keyed_hash`) |
| Binding | AEAD AAD = object identity | AAD string = `"rfm-backup:v1:<kind>:<id>"` |

XChaCha's 192-bit random nonce removes the 2^32-message ceiling that gobackup's per-object
key trick worked around, so encryption reuses the mirror's existing helper. That costs
about 16 bytes per 64 KiB frame plus a 19-byte nonce, roughly 0.03%. Keyed BLAKE3 keeps
the privacy property (nobody can test whether a known file is present without the key),
is much faster than HMAC-SHA256, and is already a dependency.

### Chunking, compression and serialization

- **Chunker:** the `fastcdc` crate's `v2020::StreamCDC` (normalized chunking) with
  min/avg/max set to 256 KiB / 1 MiB / 4 MiB. The parameters are recorded in
  `backup/config`, and the stored config always wins over defaults. Golden-vector tests
  pin the chunk boundaries, so a crate upgrade that changes them fails CI instead of
  silently breaking deduplication. This replaces porting `chunker.go` by hand.
- **Compression:** zstd per blob before encryption (the `zstd` crate), with a per-blob
  compression byte so it can be changed per repository.
- **Trees and snapshots:** serde_json with entries sorted by name and times as UTC. The
  output must be deterministic, or identical directories stop deduplicating.

### Packs

Same layout as gobackup: sealed blobs, then a sealed header, then a 12-byte footer
(header length, magic `RFMB`, version). Each header entry records type, compression, id
(32 bytes), offset, sealed length and plaintext length. The header bound and
truncated-footer checks carry over. Packs are written with one `put_bytes` call each,
never multipart.

## Integration with the mirror

- **Always exclude `<root>/.mirror/`.** It holds `state.db`, the daemon lock and the
  plaintext `passphrase` file. Backing it up would store the passphrase inside the data it
  protects. Reuse `scanner::ALWAYS_EXCLUDE`.
- **Placeholders (`*.rfm`):** skip them and report a count in the summary. A later
  `--hydrate` flag could fetch evicted content from `data/` just for the backup.
- **`.mirrorignore`:** honor it by default when backing up the mirror root.
  `--no-mirrorignore` turns that off; extra `--exclude` globs are added on top.
- **Default source:** with no paths given, `rfm backup create` backs up `local.root`.
- **Locking:** take a separate `<root>/.mirror/backup.lock`. Backup and sync can run at the
  same time because they use different prefixes.
- **Hostname:** `gethostname` (already a dependency) is used for parent snapshot
  selection, as in gobackup.
- **`rfm doctor`:** add a backup section that checks `backup/config` decrypts and reports
  the snapshot count. Backups never use multipart, so the orphan-upload check is
  unaffected.

## CLI

Grouped under `rfm backup`. The word "snapshot" already names both the mirror's manifest
generations and the existing scaffolding command, and a group avoids that clash.

```
rfm backup create [PATHS...] [--exclude GLOB]... [--tag TAG]
rfm backup list [--snapshot ID|latest --long]
rfm backup restore --snapshot ID|latest --target DIR [--include GLOB]... [--overwrite]
rfm backup verify [--read-data]
rfm backup prune --keep-last N --keep-daily N ...   (phase 6)
```

The first `backup create` writes `backup/config` if it doesn't exist yet. There's no
separate init step.

## Required change to `ObjectStore`

Add a ranged read, used by restore planning and verify:

```rust
fn get_range(&self, key: &str, offset: u64, len: u64)
    -> impl Future<Output = Result<Vec<u8>>> + Send;
```

Implement it for `S3Store` with a `Range: bytes=` header and a length check, and for
`MemoryStore` with a slice plus a bounds error.

## Phases

Each phase ends with passing tests and is mergeable on its own. Gobackup's test suite is
the checklist: port each relevant case alongside the code it covers.

### Phase 0: groundwork
- `get_range` on `ObjectStore`, S3 and memory, with tests (including an
  `s3_integration` case).
- `backup_key` in `DerivedSubKeys`.
- New crate `crates/backup-core` depending on `mirror-core`, with dependencies `fastcdc`,
  `zstd` and `blake3`.

### Phase 1: primitives
- `crypto`: subkeys, `seal`/`open` with AAD, keyed `BlobId`.
- `chunker`: `StreamCDC` wrapper with golden vectors.
- `pack`: writer and reader. Port `pack_test.go`: round trip, truncation, bad magic,
  oversize header, tampered blob, blob swapped between packs.

### Phase 2: index and repository
- `index`: binary serialization, merging many index objects, concurrent lookups.
- `repo`: config object, pack accumulation up to ~16 MiB, an in-flight set (a blob in a
  pack that is still uploading must not be stored twice), a **sticky failure** that blocks
  `flush` and `save_snapshot`, and write ordering packs → index → snapshot.
- Port `index_test.go` and `repo_test.go`.

### Phase 3: snapshots and archiver
- `snapshot`: `Node` (file/dir/symlink, mode, uid/gid, size, mtime, ctime, inode, chunk ids
  or subtree id), deterministic tree encoding, snapshot object.
- `archiver`: walk the source with `std::os::unix::fs::MetadataExt` (this replaces Go's
  build-tagged `stat_*.go`), the fast path against the parent tree, chunk → dedupe → save,
  bottom-up tree construction, warn-and-skip for unreadable files, abort on write failure.
  Concurrency is bounded by `sync.max_concurrent_transfers`.
- The mirror-specific excludes above.
- Port `archiver_test.go`, `failure_test.go` and `regression_test.go`, including the
  dedup measurements in the gobackup README (an inserted KiB uploads about 1.3 MiB, and a
  copied file uploads nothing).

### Phase 4: restore and verify
- `restorer`: gather needed blobs, group them by pack, sort by offset, merge reads within
  64 KiB, then issue `get_range` calls. Lexical path containment, directory creation that
  doesn't follow symlinks, a re-check after resolving symlinks, refusal to overwrite
  without `--overwrite`, include filters, and restored mode and mtime.
- gobackup has no dedicated restorer tests. Write direct ones here, especially for the
  path safety checks and a malicious tree.
- `verify`: a metadata check (every referenced blob resolves to a pack large enough to hold
  it, and unreferenced packs are reported), plus `--read-data` (decrypt and recompute every
  id). Port `verify_test.go`.

### Phase 5: cache and CLI
- Metadata cache in `dirs::cache_dir()/rfm/backup/<repo-id>/`, with entries authenticated
  before use. Port `cache_test.go`.
- `rfm backup create|list|restore|verify`, indicatif progress, summary output (new,
  reused, uploaded bytes, skipped placeholders), a `doctor` section, and README docs.

### Phase 6: daemon and retention
- `[backup]` config section: `schedule` (for example `interval_hours`), `paths`,
  `exclude`, and a retention policy.
- `rfm watch` runs scheduled backups. The TUI shows the last backup time and result.
- `rfm backup prune`: retention policy → delete snapshot objects → mark and sweep
  unreferenced packs and indexes (rewrite index objects that cover deleted packs). Use a
  grace period like the mirror's `object_retention_secs`, so a pack from a concurrent
  backup run isn't collected. gobackup never had GC, but the format already supports it
  because packs are immutable and content-addressed.

## Size estimate

Roughly 4–5k lines of Rust in `backup-core` plus a similar amount of tests. That's
smaller than the Go source, because `fastcdc` replaces the hand-written chunker and the
existing store, crypto and config code are reused.
