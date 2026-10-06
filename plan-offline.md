# Plan: Online-only files (local eviction)

Let a device drop a file's local bytes while keeping the file in the mirror. The encrypted object in the bucket becomes the only copy on that device. A small **placeholder** stays in the file's place, and the file can be **hydrated** (downloaded back) whenever needed. This is the same idea as Dropbox Smart Sync, OneDrive Files On-Demand, and iCloud "Optimize Storage".

> Terminology: "offline" is ambiguous. Dropbox uses it to mean *available offline*, which is the opposite of this feature. Internally the plan uses **evict / hydrate / residency**. The user-facing terms are **online-only** and **local**.

**Core rule:** eviction is **device-local**. It never reaches the delta log or the manifest, and other devices can't tell it happened. A file being evicted on one machine must never look like a deletion anywhere else.

**Decisions (2026-10-06):**
- Placeholders are **visible** (`name.ext.rfm`).
- Object keys become **versioned** now, as Phase O0, before any production data exists.
- **Automatic download on open is out of scope.** There will be no File Provider, FUSE, or Cloud Files integration. Hydration is always explicit, through the CLI or a pin.

---

## Why this is non-trivial in the current code

1. **A missing file looks like a deleted file.** `classify(None, Some(_)) => Deleted` in [engine.rs](crates/mirror-core/src/engine.rs#L64-L72) means `(Deleted, Unchanged) → DeleteRemote`. If you evict a file with today's engine, the next sync deletes it from the bucket. Residency has to be an engine input.
2. **The scanner only reports files that exist on disk.** [scanner.rs](crates/mirror-core/src/scanner.rs) returns `Vec<LocalEntry>`. Placeholders need their own representation, and the scanner must never upload them.
3. **Object keys are deterministic per path.** `object_key = HMAC(path)` ([filename.rs](crates/mirror-core/src/crypto/filename.rs#L38-L42)), so a newer upload of a path **overwrites** the older object. Eviction would remove the loser's last copy in a concurrent-edit race (§6). Phase O0 fixes this.
4. **The AAD binds ciphertext to its object key.** A moved placeholder therefore can't be re-pointed with a server-side copy. Its contents have to be re-encrypted under the new key (§O2.4).

---

## Phase O0 — Versioned object keys *(prerequisite)*

**Goal:** an upload never overwrites or destroys another version's bytes. Old versions are removed only by GC. **Exit criteria:** two devices upload different content for the same path at the same time, and both objects survive in the bucket until GC.

**O0.1 Key derivation.** `object_key(name_key, path, plaintext_hash) = "data/" + shard(base32(HMAC(k_name, "rfm:v2:obj\0" ‖ path ‖ \0 ‖ hash))[..26])`.
- Using the content hash rather than a random id keeps the key deterministic, so resuming an upload needs no new state: `uploads.content_hash` already pins it. Re-uploading identical content writes to the same key with equal plaintext, which is harmless.
- The `data/` prefix separates content from `log/`, `snapshot/`, and `vault.json`, so GC can list content objects directly. Today content sits directly under `{prefix}`.
- Readers keep using `DeltaEntry.object_key` and never recompute it. That already holds in [download.rs](crates/mirror-core/src/apply/download.rs#L47).
- Callers to update:
  - [upload.rs](crates/mirror-core/src/apply/upload.rs#L44) and [upload.rs](crates/mirror-core/src/apply/upload.rs#L142)
  - [sync.rs](crates/mirror-core/src/sync.rs#L189)
  - [execute.rs](crates/mirror-core/src/apply/execute.rs#L350)
  - the integration tests

**O0.2 Remote deletes become tombstone-only.** [delete_remote.rs](crates/mirror-core/src/apply/delete_remote.rs) stops calling `store.delete`. A `DeleteRemote` only writes a tombstone delta, and the bytes are reclaimed by GC. This matches plan1 §4.6 (trash/restore) and makes `trash restore` possible.

**O0.3 Object GC.** GC runs as part of `compact` ([manifest.rs](crates/mirror-core/src/manifest.rs#L79)), after the new snapshot has been verified:
1. Build the set of *referenced* keys: every `object_key` in the new snapshot (tombstoned entries included, until `trash purge`) plus every key in the deltas still in the log.
2. `list("{prefix}data/")`.
3. Delete only objects that are unreferenced **and** have `last_modified` older than `object_retention` (default 30 d).

The retention window covers in-flight uploads whose delta isn't written yet, and conflict losers whose devices haven't relocated them yet (§6). Like plan1 §4.7, GC is idempotent and fails open: a failed delete just retries on the next compaction.

**O0.4 Format bump.**
- Raise `vault.json` `format_version` to 2 ([vault.rs](crates/mirror-core/src/crypto/vault.rs#L14)).
- A v2 client refuses a v1 vault with a "re-init required" message. Existing buckets are dev-only, so no migration tool is needed. That mirrors how plan1 treats the Phase 1 plaintext format.
- Bump the HKDF info string for the name key to `rfm:v2:name`, so v1 and v2 keys can never collide.

**O0.5 Threat-model note.** A bucket observer now sees one new object per version instead of an overwrite. Storage grows until GC runs. Rewriting a path is visible either way, so nothing new leaks (plan1 §2.6).

---

## Phase O1 — Manual evict / hydrate *(depends on O0)*

**Goal:** `rfm evict <path>` frees space and `rfm hydrate <path>` restores the bytes. Syncing on any device never turns either action into a remote change. **Exit criteria:** evict a 1 GiB file, then sync on both devices. The bucket is unchanged, the other device is unchanged, and `hydrate` produces a byte-identical file.

### O1.1 Placeholder format
- On-disk name: `<name>.<ext>.rfm`, a **visible** sibling of the original path. Users can see that the file still exists, and deleting the placeholder deletes the file.
- Contents: one small JSON line (fits in one block): `{"rfm":1,"path":"a/b.pdf","size":N,"hash":"<blake3>","object_key":"data/…","evicted_at":T}`. The state DB is authoritative. The contents are there for detecting moves (§O2.4) and for rebuilding state if the DB is lost.
- The suffix is **reserved**. If a real file ends in `.rfm` but doesn't parse as a placeholder, it is reported as *skipped* in `status` (the same way skipped symlinks are reported) and is never silently mirrored.
- The placeholder name is built from the NFC-normalised canonical path, so macOS and Linux agree on it.

### O1.2 State (migration v4)
```sql
ALTER TABLE files ADD COLUMN residency        INTEGER NOT NULL DEFAULT 0; -- 0 local, 1 evicted
ALTER TABLE files ADD COLUMN evicted_at       INTEGER;
ALTER TABLE files ADD COLUMN last_hydrated_at INTEGER;
```
- Add `residency` to `FileRecord`. Expose `State::mark_evicted(path)` and `State::mark_local(path)`.
- `record_scan` sets `residency = 0` for every entry that is **present** on disk. If a real file shows up at the original path, it overrides the placeholder (see "real file wins" below).
- For evicted rows, `size`, `mtime_ns`, and `content_hash` keep the last confirmed values. `status` and the placeholder contents use these values.

### O1.3 Scanner
- Return `ScanResult { entries: Vec<LocalEntry>, placeholders: Vec<Placeholder> }`. `Placeholder { path /* original */, at /* actual location */, meta: Option<StubMeta> }`.
- A placeholder never becomes a `LocalEntry`, so it can never be hashed or uploaded.
- **Real file wins:** if both `foo.pdf` and `foo.pdf.rfm` exist, the real file is the local state and the placeholder is cleaned up afterwards. This one rule makes every crash point in evict and hydrate recoverable.

### O1.4 Engine (stays pure)
`reconcile(local, placeholders, baseline, remote, policy)`. For each path, local observation becomes three-state:

| Local observation | Treated as `here` |
|---|---|
| Real file with hash `h` | `Some(h)` (same as today; residency cleared) |
| Placeholder present and baseline `residency = evicted` | `Some(base)`, i.e. **Unchanged** |
| Nothing (placeholder deleted by the user) | `None`, i.e. **Deleted** (same as today) |

New `ActionKind` variants (enum order is execution order):

- `Hydrate`: download into place, then remove the placeholder.
- `UpdatePlaceholder`: metadata only. Rewrites the placeholder and advances the baseline. **No transfer.**
- `CreatePlaceholder`: metadata only (Phase O2).

`Evict` is **not** a reconcile action. It runs as a separate pass (§O1.6).

Truth table changes (every other cell is unchanged):

| Local | Remote | Today | With residency |
|---|---|---|---|
| Placeholder | Unchanged | — | none (or `Hydrate` if the path is pinned local) |
| Placeholder | Modified | — | `UpdatePlaceholder` (or `Hydrate` if pinned) |
| Placeholder | Deleted | — | `DeleteLocal` (removes the placeholder and the state row) |
| Placeholder deleted | Unchanged | — | `DeleteRemote` (deleting the placeholder deletes the file) |
| Placeholder deleted | Modified | `Conflict` | `Hydrate`. No local bytes exist to preserve, so the remote edit wins. The current `conflict()` would try to rename a file that isn't there. |

`ActionKind` ordering stays "transfers before deletes". The metadata actions run inline and don't take a transfer-semaphore permit.

### O1.5 Hydrate
- Reuse [download.rs](crates/mirror-core/src/apply/download.rs): tmp file → decrypt → verify against the **manifest's current** hash → fsync → persist. Then remove the placeholder, `mark_local`, and set `last_hydrated_at`.
- The hydrated bytes can be newer than the baseline because the remote overwrote the object. That's correct: the local side was Unchanged, so taking the remote version is a fast-forward. The baseline advances through `confirm_sync`.
- **Free-space precheck:** check `size + margin` before downloading, and fail with a clear message instead of ENOSPC halfway through.
- `rfm hydrate <path|glob>...` runs a scoped sync: it refreshes the manifest, plans only the selected paths, and applies. If the daemon is running, the request is sent to the daemon over its socket, so there is only ever one writer per root (Phase 5.4 lock).

### O1.6 Evict
Eviction is a **separate pass that runs after** `apply` + `record_scan`. That way it only sees files this pass has just confirmed as in sync. It is planned by a pure function, `plan_evictions(baseline, manifest, pending_uploads, policy, now) -> Vec<String>`.

**Eligibility.** All of the following must hold:
- local hash == `last_synced_hash` == manifest `plaintext_hash`, and the manifest entry is not deleted
- no row in `uploads` for the path (no pending or resumable multipart upload)
- confirmed for at least **`evict_grace`**. This is defense in depth (§6) and also stops evict→hydrate churn on files that were just edited.
- not pinned local
- `size >= evict_min_size` (the placeholder costs a block anyway)

**Remote check.** `head(object_key)` must return an object whose content-length equals the expected ciphertext size, computed from the plaintext size, header, and frame tags. This is cheap and catches missing objects. Optional `--verify` does a full download → decrypt → hash check first.

**Sequence.** The real-file-wins rule makes this crash-safe at every step:
1. `mark_evicted` (in a transaction)
2. write the placeholder atomically (tmp + rename)
3. rename the original to `.mirror/tmp/evicting-*`, then **re-stat** it. If size or mtime changed, a writer touched it: move it back, `mark_local`, and skip.
4. unlink, then fsync the parent directory

**Space accounting** uses `st_blocks` instead of `size`, because of sparse and compressed files. Note that APFS local snapshots can delay when freed space actually shows up.

### O1.7 CLI
- `rfm evict <path|glob>... [--dry-run] [--verify]`
- `rfm hydrate <path|glob>...`
- `rfm status` shows local vs online-only counts and bytes, plus skipped `.rfm` files
- New `SyncOutcome` counters for `Hydrate` and `UpdatePlaceholder`

---

## Phase O2 — Pins and online-only by default *(depends on O1)*

**Goal:** a new device can join with only metadata and pull bytes on demand. **Exit criteria:** `rfm init --online-only` on a fresh machine creates placeholders for a 100 GB tree while transferring nothing but manifests.

**O2.1 Residency policy.** Each path resolves to `Local | OnlineOnly | Auto`. Precedence, highest first:
1. explicit CLI pin (stored in the state table `pins(pattern PK, mode, created_at)`)
2. config globs
3. `default_residency`

`rfm pin <glob> --local|--online-only|--auto`, `rfm pin list`, `rfm unpin <glob>`. The policy is passed into `reconcile` and `plan_evictions` as a resolved lookup, so the engine stays pure.

**O2.2 `CreatePlaceholder`.** A new remote file `(None, Created)` on an online-only path gets a placeholder instead of a `Download`. This is where most of the space saving comes from.

**O2.3 Pin transitions.** Changing a pin to local triggers `Hydrate` on the next pass. Changing it to online-only makes the files eligible for eviction, still subject to the §O1.6 rules including grace.

**O2.4 Moved or renamed placeholders.** If a placeholder is found where its `meta.path` doesn't match its location, treat it as a move:
- new path: a `Relocate` action streams download → decrypt → re-encrypt under the new key → upload, entirely in memory, without hydrating to disk
- old path: `Deleted` → `DeleteRemote`, which runs after the transfer because of execution order

If the placeholder can't be parsed, fall back to hydrate-then-upload.

`Relocate` also handles an **evicted conflict loser** (§6). The loser's bytes are read from its version key and re-encrypted under the conflicted-copy path. The device then gets a placeholder at the conflicted name, not a hydrated file.

**O2.5 Orphan placeholders.** A placeholder with no state row (lost DB, or one copied in from elsewhere):
- if the manifest has `meta.path` with the same hash, adopt it as evicted
- otherwise report it in `doctor` and leave it alone

---

## Phase O3 — Automatic space management *(depends on O2 + Phase 5 daemon)*

**Goal:** the daemon keeps free disk space above a threshold without user involvement.

- **Trigger:** after each sync pass, and on a slower timer. Read available space with `fs2::available_space` (`mirror-core` forbids `unsafe`).
- **Policy:** when free space < `min_free_space`, evict `Auto` files in LRU order until free space ≥ `target_free_space`. The LRU key is `max(atime, last_hydrated_at, mtime)`. atime is only a hint (relatime/noatime), so recently hydrated files are protected explicitly.
- **Rate-limit** eviction per pass and log every eviction. Show the last eviction batch in `daemon status`.
- **Watcher integration:** suppress watcher events for placeholders and files the daemon itself creates or removes. A user deleting a placeholder **does** generate an event, which leads to a rescan and then `DeleteRemote`.

---

**Out of scope:** opening a placeholder in an app does not trigger a download. Hydration is always explicit, through `rfm hydrate` or a local pin.

---

## §6 Concurrent edits vs. eviction

**Scenario.** A and B both start a sync of `f` from base `v0`, and both read the log before either writes. A uploads `v1`, B uploads `v2`, and merge flags a conflict. The loser's `preserve_conflict_losers` renames its **local** bytes aside. If the loser has already **evicted** its version, it has no local bytes to rename.

**Resolution:**
- **O0 removes the data loss.** `v1` and `v2` live at different keys, so the loser's bytes are still in the bucket, kept by GC for at least `object_retention`.
- **`preserve_conflict_losers` gains an evicted branch.** If the loser path is evicted on this device, it emits a `Relocate` from the loser's `object_key` to the conflicted-copy path and leaves a placeholder there (§O2.4). Until O2 lands, it falls back to hydrating the loser's version to the conflicted-copy name, then uploading it.
- **`evict_grace`** (default 15 min, at least 2 × `poll_interval`) is now only defense in depth. It makes the race window close before eviction is possible.
- **Residual risk:** the loser device stays offline longer than `object_retention` and its conflict delta has been compacted away. Document it, and have `doctor` warn when a device's last sync is older than `object_retention / 2`.

---

## Configuration
Sizes are in bytes and durations in seconds, matching the existing `[sync]` keys.
```toml
[offline]
default_residency   = "local"        # "local" | "online-only"
local               = ["Documents/**"]
online_only         = ["Archive/**", "**/*.iso"]
evict_min_size      = 1048576        # 1 MiB
evict_grace_secs    = 900            # 15 min
verify_before_evict = false
auto_evict          = false
min_free_space      = 21474836480    # 20 GiB
target_free_space   = 42949672960    # 40 GiB

[sync]
object_retention_secs = 2592000      # 30 d; O0 GC: min age of an unreferenced object before deletion
```
Validate when loading:
- `target_free_space >= min_free_space`
- `evict_grace >= 2 × poll_interval`
- `object_retention >= 7d` and `object_retention > evict_grace`
- the globs compile

## Implementation notes (deviations from the plan above)
- **No HKDF bump for the name key.** The object-key HMAC input is already domain-separated (`rfm:v2:obj\0`), and v1 vaults are refused.
- **`Relocate` uses a temp file.** It goes through a verified temp file in `.mirror/tmp` and is not streamed purely in memory. The temp file is deleted as soon as the upload finishes.
- **Not implemented:**
  - suppressing watcher events from the daemon's own placeholder writes. The only cost is one extra no-op pass.
  - the `doctor` warning for a device whose last sync is older than `object_retention / 2`.
- **`rfm init --online-only` doesn't rewrite an existing config.** It prints the `[offline]` line to add instead, because `Config::save` would drop a custom `[sync]` section.
- **Explicit `rfm evict` skips `evict_grace` and `evict_min_size`.** It still enforces every safety check, including the remote head and size check.

---

## Testing
- **O0 key tests:**
  - the key changes when the hash changes
  - the key is stable for the same `(path, hash)`
  - v1 and v2 keys never collide
  - resuming an upload targets the same key
- **O0 GC tests:**
  - an object referenced by the snapshot or the log is never deleted
  - an unreferenced object younger than `object_retention` survives
  - a tombstoned path's object survives until `trash purge`
  - GC is idempotent
  - `MemoryStore` needs `last_modified` injection for this
- **Engine table tests:** every new cell in the §O1.4 table, plus the guarantee that a placeholder never produces `Upload` or `DeleteRemote` unless the user deleted it.
- **Convergence proptest:** in [tests/convergence.rs](crates/mirror-core/tests/convergence.rs), add `Evict(dev, file)` and `Hydrate(dev, file)` ops. Properties:
  - the **logical** tree (hydrated content) is identical on every device after quiescence
  - eviction never changes the manifest or delta log
  - every confirmed, non-superseded hash can still be fetched
- **Race test:** the §6 scenario with `evict_grace = 0`, using `MemoryStore` latency injection to force overlapping syncs. Both versions must still be recoverable, and the evicted loser must end up as a conflicted-copy placeholder.
- **Crash tests:** kill at each step of the evict sequence (§O1.6) and of hydrate. On restart there must be no lost file, no stray `DeleteRemote`, and the state must converge.
- **Integration (MinIO):** evict/hydrate round trip, `--verify`, and a moved placeholder (`Relocate`).

## Key files
- [crates/mirror-core/src/crypto/filename.rs](crates/mirror-core/src/crypto/filename.rs): `object_key(path, hash)`, `data/` prefix, v2 domain string
- [crates/mirror-core/src/crypto/vault.rs](crates/mirror-core/src/crypto/vault.rs): `format_version = 2`, reject v1
- [crates/mirror-core/src/apply/delete_remote.rs](crates/mirror-core/src/apply/delete_remote.rs): tombstone only, no object delete
- [crates/mirror-core/src/manifest.rs](crates/mirror-core/src/manifest.rs): object GC in `compact`
- [crates/mirror-core/src/apply/remote_conflict.rs](crates/mirror-core/src/apply/remote_conflict.rs): evicted-loser branch
- [crates/mirror-core/src/engine.rs](crates/mirror-core/src/engine.rs): residency-aware `reconcile`, new `ActionKind`s, `plan_evictions`
- [crates/mirror-core/src/scanner.rs](crates/mirror-core/src/scanner.rs): `ScanResult`, placeholder detection, reserved suffix
- [crates/mirror-core/src/state.rs](crates/mirror-core/src/state.rs): migration v4, `residency`, `pins`, `mark_evicted` / `mark_local`
- `crates/mirror-core/src/apply/{hydrate,evict,placeholder}.rs`: new; hydrate reuses `download.rs`
- [crates/mirror-core/src/sync.rs](crates/mirror-core/src/sync.rs): eviction pass after `record_scan`, scoped sync for `hydrate`
- [crates/mirror-core/src/config.rs](crates/mirror-core/src/config.rs): `[offline]` section and validation
- [crates/mirror-cli/src/main.rs](crates/mirror-cli/src/main.rs): `evict`, `hydrate`, `pin`, and the `status` additions

