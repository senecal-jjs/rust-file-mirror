# Plan: Encrypted S3 File Mirror CLI in Rust

Build `rfm`, a Rust CLI + daemon that bi-directionally mirrors a local folder to an S3-compatible bucket with client-side encryption of both file contents and path names. Multiple machines can share one bucket prefix. The key architectural bet: **no compare-and-swap is required** — devices coordinate through an append-only delta log (unique object keys per write, so zero contention) that is periodically compacted into snapshots. This works identically on AWS S3, MinIO, R2, and B2.

**Layout**: cargo workspace — `crates/mirror-core` (all logic, unit-testable) + `crates/mirror-cli` (binary `rfm`). An `ObjectStore` trait abstracts S3 so tests run against an in-memory fake, integration tests against MinIO in Docker.

---

## Phase 0 — Scaffolding

**Goal:** an installable binary that parses every command, loads config, connects to MinIO, and does nothing else. Exit criteria: `rfm doctor` reports a reachable bucket.

**0.1 Workspace skeleton** — Root `Cargo.toml` with `[workspace.dependencies]` so both crates pin identical versions. `rust-toolchain.toml` pinning stable + rustfmt + clippy. Release profile: thin LTO, `codegen-units = 1`, stripped, `panic = "abort"` on the binary only (core keeps unwind so tests can assert panics). `mirror-core` is `#![forbid(unsafe_code)]`.

**0.2 Dependencies**

| Concern | Crate |
|---|---|
| Async runtime | `tokio` (rt-multi-thread, fs, signal, sync, macros) |
| S3 | `aws-config`, `aws-sdk-s3`, `aws-smithy-types` |
| CLI | `clap` (derive, env), `clap_complete` |
| Serialization | `serde`, `serde_json`, `toml`, `postcard` (compact deltas) |
| Errors | `thiserror` (core), `anyhow` (cli) |
| Logging | `tracing`, `tracing-subscriber` |
| Hashing | `blake3` |
| Crypto | `chacha20poly1305` (stream), `argon2`, `hkdf`, `hmac`, `sha2`, `zeroize`, `rand` |
| State | `rusqlite` (bundled — no system SQLite dependency) |
| Walk / watch | `ignore`, `walkdir`, `notify`, `notify-debouncer-full` |
| Misc | `dirs`, `rpassword`, `indicatif`, `futures`, `bytes`, `data-encoding`, `uuid`, `humantime`, `tempfile`, `fs2`, `time` |
| Dev | `proptest`, `assert_cmd`, `insta`, `testcontainers`, `criterion` |

Pin `aws-sdk-s3` explicitly — it breaks often. Add `deny.toml` for licence/advisory drift.

**0.3 Configuration** — TOML at `~/.config/rust-file-mirror/config.toml`. Layered, later wins: defaults → file → `RFM_*` env → CLI flags.

- `[remote]` — `bucket`, `endpoint`, `region`, `prefix`, `path_style` (**true required for MinIO**), `credentials` (`environment` | `profile:<name>` | `static`)
- `[local]` — `root`, `ignore_file`, `follow_symlinks` (false), `preserve_mode` (false)
- `[sync]` — `poll_interval` 60 s, `debounce` 2 s, `max_concurrent_transfers` 8, `multipart_threshold`/`part_size` 8 MiB
- `[crypto]` — mirrors the remote vault header for offline validation
- `[device]` — `id` (UUIDv4), `name` (hostname)

Validate aggressively at load and report *all* problems at once: root exists, prefix ends in `/`, part size ≥ 5 MiB (S3 hard limit), concurrency ≥ 1.

**0.4 Errors and exit codes** — One `mirror_core::Error` enum: `Config`, `Io { path, source }`, `Store`, `Crypto`, `Manifest`, `Conflict`, `State`, `Interrupted`. Every IO variant carries the path — the most common complaint with sync tools is an error that doesn't say which file. Exit codes: 0 ok, 1 generic, 2 usage, 3 config, 4 auth, 5 network, 6 crypto/bad passphrase, 7 conflicts pending, 130 interrupted.

**0.5 Test environment** — `docker-compose.yml` with MinIO (9000/9001) plus an `mc` sidecar that waits for readiness, creates the bucket, and provisions a scoped key. `.env.example` + `justfile` (`up`, `down`, `test`, `it`, `lint`, `fmt`) so a clean clone works immediately.

**0.6 CI** — macOS + Linux matrix: fmt check, `clippy -D warnings`, tests; separate integration job with MinIO as a service container. `cargo-deny`/`cargo-audit` on a schedule.

**0.7 CLI surface** (stubbed now) — `init`, `unlock`, `status [--json]`, `sync [--dry-run]`, `push`, `pull`, `daemon start|stop|status|logs`, `watch`, `trash list|restore|purge`, `ignore list|add|check`, `doctor`, `config show [--redact]`, `completions`. Global: `--config`, `--root`, `-v`, `--quiet`, `--json`, `--yes`.

---

## Phase 1 — Walking-skeleton MVP *(depends on P0)*

**Goal:** plaintext, single-device, manual `sync` that is genuinely correct. No crypto, no multi-device, so the scan → diff → transfer → commit pipeline is validated in isolation. Exit criteria: sync a 10k-file tree, mutate, re-sync; a second empty root pulls an identical tree.

**1.1 Scanner** — `ignore::WalkBuilder` honouring `.mirrorignore` with full gitignore semantics (negation, directory-only, anchoring, nested files). Deliberately does **not** honour `.gitignore` — surprising for a backup tool. Always excluded: `.mirror/`, state DB + `-wal`/`-shm`, `.DS_Store`, `Thumbs.db`, editor swap files. Symlinks not followed but *recorded as skipped*, so data isn't silently missing.

Path normalisation is the subtle killer here: canonical form is the root-relative, `/`-separated path **Unicode-normalised to NFC**. macOS delivers NFD from APFS, so without this the same file derives two different object keys on macOS vs Linux. Also keep a case-folded index to detect `Readme.md` vs `README.md` collisions — distinct on Linux, colliding on macOS — and report them as conflicts rather than corrupting.

**1.2 Hashing** — BLAKE3 streaming with a 256 KiB buffer; `update_mmap_rayon` above ~16 MiB for multicore throughput. Only hash when `(size, mtime_ns, inode)` differs from baseline, making a no-op sync an IO-light stat walk. **Re-stat after hashing and discard if the file changed mid-read** — otherwise you commit a hash that never corresponded to any real on-disk state. Runs on `spawn_blocking` behind a semaphore so a huge tree can't exhaust the blocking pool.

**1.3 Local state (SQLite)** — WAL mode, `synchronous = NORMAL`, busy timeout. Table `files(path PK, size, mtime_ns, inode, plaintext_hash, last_synced_hash, object_key, lamport, deleted, updated_at)` plus a `meta` table. Migrations keyed on `PRAGMA user_version`, each in its own transaction.

`last_synced_hash` is the **baseline** and the most important column in the schema — it's what distinguishes "the file is gone locally" from "the file never existed here". Write it only *after* a transfer is durably confirmed, inside a per-file transaction. A crash then loses progress but never records a lie.

**1.4 Reconcile engine (the correctness core)** — A pure function: `reconcile(scan, baseline, remote) -> Plan`. No IO, no clock, no randomness — everything is passed in, so it's exhaustively table-testable. Classify each side as `Unchanged | Modified | Created | Deleted` against the baseline:

| Local ↓ / Remote → | Unchanged | Modified | Created | Deleted |
|---|---|---|---|---|
| **Unchanged** | Noop | Download | Download | DeleteLocal |
| **Modified** | Upload | same hash → Noop, else **Conflict** | — | **Conflict** (resurrect local) |
| **Created** | Upload | — | same hash → adopt, else **Conflict** | — |
| **Deleted** | DeleteRemote | **Conflict** (resurrect remote) | — | Noop, converge tombstone |

Two rules save enormous pain: when both sides changed, **compare content hashes first** — identical content is convergence, not conflict; and delete-vs-modify **always** resolves in favour of keeping data.

Action ordering matters: mkdir parents → downloads → uploads → local deletes → remote deletes → prune empty dirs. Deletes last means an interrupted sync leaves extra data rather than missing data.

**1.5 Transport (minimal)** — `ObjectStore` trait (`put`, `get`, `head`, `delete`, `list`) with `S3Store` and `MemoryStore` (injectable latency and failures). Single-shot put/get only in this phase. Configure the SDK's retry/timeout so it doesn't fight our own layer later.

**1.6 Apply loop** — Downloads stream to `.mirror/tmp` (same filesystem so rename is atomic), **verify BLAKE3 before rename**, fsync file, rename, fsync parent directory. Re-validate every remote path against traversal rules immediately before opening — not just at parse time. Preserve mtime so the next scan doesn't see a spurious change. `--dry-run` and `status` share the executor's plan code path, so the preview is exactly what runs.

---

## Phase 2 — Encryption *(depends on P1)*

**Goal:** nothing legible reaches the bucket — not contents, not filenames, not structure. Exit criteria: `mc ls --recursive` shows only opaque keys; a byte-flip in any object is detected on download.

**2.1 Vault header** — `<prefix>/vault.json`, stored **unencrypted** because it holds what's needed to derive the key: `format_version`, KDF algorithm + `m_cost`/`t_cost`/`p_cost` + 16-byte random salt, and a `key_check` (AEAD of a fixed string under a dedicated subkey) so `unlock` rejects a wrong passphrase instantly and unambiguously. `init` refuses to overwrite an existing vault and prints a prominent warning: **there is no recovery if the passphrase is lost.**

**2.2 Key derivation** — `master = Argon2id(passphrase, salt, params)` → 32 bytes, parameters around 64 MiB / t=3 / p=4, **benchmarked at init** to hit ~0.5–1 s locally then persisted so every device reproduces them. Subkeys via HKDF-SHA256 with versioned info strings `rfm:v1:{content,name,manifest,keycheck}` — domain separation means a weakness in one usage can't cross over. Passphrase from TTY (`rpassword`, confirmed at init) or `RFM_PASSPHRASE`; **never** from argv, which is world-readable in the process table and lands in shell history. Wrap keys in `Zeroizing`, hand-implement `Debug` as `[redacted]`, and unit-test that keys never appear in formatted output.

**2.3 Content encryption** — XChaCha20-Poly1305 via `aead::stream::EncryptorBE32`, 1 MiB frames. STREAM gives authenticated chunking with built-in resistance to truncation, reordering, and splicing — considerably safer than a hand-rolled chunk format. Layout: `magic("RFM1")` ‖ version ‖ scheme id ‖ 19-byte random nonce prefix ‖ frames (1 MiB + 16-byte tag each, last flagged).

**A fresh random nonce prefix per uploaded version, always** — nonce reuse under a reused key is catastrophic for ChaCha20, so never derive it from content or path. AAD binds the header *and the object key*, so ciphertext can't be relocated to another path and still authenticate. Empty files still get a header and one empty authenticated frame, making truncation-to-zero detectable. Decryption is streaming; a failing tag aborts and deletes the temp file.

**2.4 Filename encryption** — `object_key = shard(base32_nopad(HMAC-SHA256(k_name, canonical_path))[..26])`, sharded as `ab/cd/EFGH…` to spread keys across S3 partitions. Deterministic by design: two devices must derive the same key for the same path with zero coordination — this is the trade-off that makes coordination-free multi-device sync possible. Since the mapping is one-way, the plaintext→key direction exists **only in the encrypted manifest**, which is why manifest durability is a first-class concern (Phase 4 keeps snapshot history, not one mutable object). Directories aren't objects; structure is reconstructed from manifest paths.

**2.5 Manifest encryption** — Same STREAM construction under `k_manifest`, with generation number and object role bound as AAD, bounding rollback attacks. The client also refuses any generation lower than the highest recorded in local state.

**2.6 Threat model to document** — State plainly what a bucket-read observer still learns: object count, individual sizes (padded only to frame boundaries), timing/access patterns, and whether a given path was rewritten. Length-hiding padding and key rotation are explicitly deferred. `rfm` protects data at rest in the bucket; it does not protect a compromised client. Phase 1's plaintext format is developer-only and is **not** migrated.

---

## Phase 3 — Transfer robustness *(depends on P2; parallel with P4)*

**Goal:** large files, flaky networks, and interrupted runs stop being special cases. Exit criteria: a 5 GB file uploads with bounded memory, survives a mid-transfer network kill, and resumes.

**3.1 Multipart** — Above 8 MiB: `create_multipart_upload` → `upload_part` × N → `complete`. The encryptor streams directly into part buffers, so memory is `part_size × in_flight_parts` regardless of file size — never load a file into memory. Respect S3 limits (≥ 5 MiB non-final parts, ≤ 10 000 parts) by **auto-scaling part size for very large files** rather than failing at part 10 001. Send per-part checksums, verify the completed ETag where supported, and `abort_multipart_upload` from a cleanup guard so incomplete uploads don't accrue charges silently.

**3.2 Concurrency** — A global semaphore caps concurrent transfers; a second, smaller cap limits parts within one file so a single large file can't starve everything. Interleave small and large files so a queue of small files isn't stuck behind a multi-gigabyte upload.

**3.3 Retries** — Classify explicitly: retryable (5xx, `SlowDown`/throttling, timeouts, connection resets) vs terminal (403, 404 on a known key, bad credentials, decryption failure). Blindly retrying a 403 wastes time and trips rate limits. Exponential backoff with full jitter, per-operation attempt cap, overall deadline. Align or disable the SDK's own retry layer so the two don't multiply.

**3.4 Resumability** — An `uploads` table records `path`, `upload_id`, `part_size`, and completed `(part_number, etag)` rows. On startup, resume uploads whose local hash is unchanged; otherwise abort and restart. `doctor` lists and optionally aborts orphaned multipart uploads via `list_multipart_uploads`, including ones left by older versions.

**3.5 Progress** — `indicatif` per-file + aggregate bars, auto-disabled when stderr isn't a TTY or `--quiet`/`--json` is set. `--json` emits one event per line for scripting.

---

## Phase 4 — Multi-device convergence *(depends on P2)*

**Goal:** several machines share one prefix, converge without coordination, never silently lose an edit. Exit criteria: two devices editing the same file offline both end up with the original plus exactly one conflicted copy, trees identical.

**4.1 Why a delta log** — S3-compatible backends disagree on conditional writes: AWS supports `If-None-Match`/`If-Match`, MinIO and R2 partially, older clones not at all. Instead, **every write goes to a unique key, so writes never contend**; reads reconstruct state by merging. Strictly more portable, and crash-safe as a bonus since nothing is overwritten in place.

**4.2 Layout** — Deltas at `<prefix>/log/{lamport:020}-{device_id}.delta`, zero-padded so lexicographic listing order equals causal order. Snapshots at `<prefix>/snapshot/{generation:020}.snap`. Read path: newest snapshot, then `list_objects_v2` with `start_after` at that generation, merged in order. A regularly-syncing device reads a handful of tiny deltas; a device returning after months reads one snapshot plus the tail. Deltas are batched per sync pass, so a 1 000-file change is one object.

**4.3 Clocks and identity** — Each device has a UUID and a persisted Lamport counter. On read: `lamport = max(local, max_seen_remote) + 1`; ties break on device id, giving a total order every device computes identically. Wall-clock times are stored for display only, never ordering — cross-machine skew makes mtime ordering unreliable. `doctor` warns on skew by comparing against the S3 `Date` response header.

**4.4 Merge** — Entry: `path`, `object_key`, `plaintext_hash`, `size`, `mtime_utc`, `deleted`, `deleted_at`, `lamport`, `device_id`, `base_hash`. `base_hash` is what the writer believed was current before its edit — a one-slot causal history. Per path:

1. `incoming.base_hash == current.plaintext_hash` → writer saw current state, fast-forward.
2. `incoming.plaintext_hash == current.plaintext_hash` → same content reached independently, converge on the lower `(lamport, device_id)`.
3. Otherwise → **conflict**.

Merge must be commutative and idempotent — replaying deltas in any order yields the same result. That's the property Phase 6 verifies with `proptest`.

**4.5 Conflict resolution** — Winner (higher `(lamport, device_id)`) keeps the path; loser becomes `name (conflicted copy 2026-08-14T12-30-00Z from laptop).ext`, inserted **before the extension** so file associations survive. The conflicted copy is then uploaded as an ordinary new file, so *every* device receives both versions — that's what makes resolution deterministic rather than device-local. Guard against recursion: a file already matching the pattern gets a counter suffix instead of another conflict copy. Conflicts land in a `conflicts` table, appear in `status`, and set exit code 7 so scripts notice.

**4.6 Deletes, trash, GC** — Deletion writes a tombstone with `deleted_at`; the object is retained. Tombstones are what let an offline device learn about a deletion instead of re-uploading the file. `trash list` shows tombstones with time and device; `trash restore <path>` clears and re-downloads; `purge --older-than 30d` deletes objects behind expired tombstones, then compacts — conservatively, never touching an object still referenced by a live entry, and requiring `--yes`.

**4.7 Compaction** — Triggered above ~200 deltas or on a schedule. Safe sequence: write the new snapshot, **verify it reads back, then** delete superseded deltas — and only those older than a grace period, so a device mid-read isn't left with a dangling range. Deleting first would be unrecoverable. Compaction is idempotent; simultaneous compactors produce identical content and one object is simply redundant.

---

## Phase 5 — Daemon *(depends on P4)*

**Goal:** edits propagate within seconds. Exit criteria: 24 h run over a large tree with flat memory, correct across sleep/wake and network loss.

**5.1 Watching** — `notify` + `notify-debouncer-full` with a 2 s window, coalescing bursts (editors routinely write-rename-chmod several times per save). Map events to intent: create/modify → rescan that path; remove → candidate delete; rename → delete+create unless both halves land inside the debounce window.

**The watcher is a hint, never the source of truth** — events mark paths dirty and a scan confirms reality, which makes dropped or coalesced events harmless. Handle queue overflow explicitly by falling back to a full rescan; on Linux warn when the tree exceeds inotify watch limits; on macOS FSEvents reports directory-level recursive changes, which is precisely why confirm-by-scan is mandatory rather than optional. A periodic full rescan (hourly) catches the rest.

**5.2 Remote polling** — No push notifications from S3, so list the log prefix on an interval (60 s) with jitter to avoid a thundering herd when several devices start together. Usually one `list_objects_v2` with `start_after` returning nothing — very cheap.

**5.3 Sync loop** — Single-flight: if a sync is running, set a "rerun requested" flag rather than queueing. Unbounded queueing is how sync daemons enter death spirals. Exponential backoff on error with the failure surfaced in `daemon status`, not just logs. Detect suspend/resume via large wall-clock jumps and force a full reconcile, since post-sleep state is untrustworthy. Suppress watcher events for paths the daemon is itself writing, to avoid a feedback loop.

**5.4 Process management** — `rfm watch` runs foreground; ship a launchd plist (macOS) and systemd user unit (Linux) rather than self-daemonising — the OS handles restart, logging, and login integration better than a hand-rolled double-fork. `flock` on `.mirror/daemon.lock` holding the PID guarantees one instance per root, with stale-lock reclamation. A 0600 Unix socket at `.mirror/daemon.sock` serves `status`/`stop`; treat every request as untrusted input and keep the protocol minimal. Graceful SIGTERM/SIGINT: stop accepting work, finish or cleanly abort in-flight transfers, checkpoint, release the lock; a second signal forces exit. The derived key stays resident for the daemon's lifetime, prompted once, zeroized on shutdown.

**5.5 Logs** — `tracing` to a rotating file plus stderr in foreground, level via `RFM_LOG`, optional path redaction.

---

## Phase 6 — Hardening

**6.1 Property tests** — **Convergence** is the single highest-value test: generate random operation sequences across two or three simulated devices on a `MemoryStore`, apply in random interleavings, assert all devices reach byte-identical trees and manifests. Plus merge commutativity/idempotence, round-trip across size boundaries (0, 1, frame−1, frame, frame+1, threshold ±1, multi-GB), and path fuzzing (unicode, emoji, NFD, long names, reserved characters) that must round-trip or be rejected cleanly — never silently mangled.

**6.2 Fault injection** — `MemoryStore` can fail the *n*th operation, inject latency, return truncated bodies, or simulate eventual consistency. Every failure mode must leave recoverable state and converge on the next sync.

**6.3 Crash consistency** — `SIGKILL` at randomised points during upload, download, and manifest commit; on restart assert no corrupt files, nothing partial outside `.mirror/tmp`, no lost baseline, eventual convergence.

**6.4 Security tests** — Wrong passphrase fails fast and clearly; a flipped ciphertext byte fails authentication and writes nothing; a relocated object fails AAD validation; a rolled-back generation is rejected; a manifest entry containing `../../etc/passwd` is refused. All must **fail closed**.

**6.5 Performance** — `criterion` on hashing throughput and manifest merge at 100k entries. Targets: no-op sync over 100k files in a few seconds (stat-only), flat steady-state daemon memory.

**6.6 Release** — Cross-compile macOS (arm64/x86_64) and Linux (gnu/musl), checksummed archives, completions, man page, `CHANGELOG.md`, README covering the threat model, the no-recovery warning, and a restore drill.

---

## Cross-cutting

- **Idempotence everywhere** — crashes and retries guarantee every operation will be repeated.
- **Fail closed on crypto, fail open on cleanup** — never write unauthenticated data; never let failed cleanup block a sync.
- **The manifest is the crown jewel** — losing it loses filenames. Keep snapshot history; consider `rfm export-manifest` as an escape hatch.
- **Observability before optimisation** — structured spans around scan/plan/transfer make later performance work possible.

## Key files

- `crates/mirror-core/src/engine.rs` — pure reconcile; the correctness core
- `crates/mirror-core/src/crypto/{keys,content,names}.rs` — KDF/HKDF, STREAM AEAD, HMAC key derivation
- `crates/mirror-core/src/manifest/{entry,log,merge,compact}.rs` — delta log, snapshots, merge + conflict rules
- `crates/mirror-core/src/store/{mod,s3,memory}.rs` — `ObjectStore` trait, S3 impl, test fake
- `crates/mirror-core/src/{scanner,state,apply}.rs` — walk + BLAKE3, SQLite baseline, action executor
- `crates/mirror-core/src/daemon/{mod,watcher,loop}.rs` — watcher, debounce, single-flight loop
- `crates/mirror-cli/src/{main,commands/*}.rs` — clap surface
- `docker-compose.yml`, `justfile`, `.mirrorignore` example

## Verification

1. `cargo clippy --all-targets -- -D warnings` and `cargo test` clean at every phase boundary.
2. Round-trip property test across the size-boundary matrix.
3. MinIO integration: sync, mutate, re-sync, assert convergence; `mc ls --recursive` shows **no plaintext filename or content**.
4. Two-device test on one prefix: concurrent edits produce exactly one conflicted copy on both sides, trees identical.
5. `SIGKILL` mid-upload, restart, assert no corruption and no partial local files.
6. Bad-passphrase and tampered-ciphertext tests fail closed with a clear error.
7. Restore drill: from an empty machine with only the passphrase and config, reconstruct the tree and diff against the original.

## Decisions

- Append-only delta log over conditional PUT — CAS support is inconsistent across S3 clones; conditional PUT can be added later as an optimisation only.
- Deterministic HMAC object keys are required for coordination-free agreement. Accepted leakage: object count, sizes, timing, rewrite detection. Padding out of scope for v1.
- Lamport clocks over wall-clock ordering, because cross-machine skew is unreliable.
- Watcher events are hints confirmed by scanning, never the source of truth.
- Excluded from v1: sharing/links, LAN sync, block-level delta transfer, dedup, selective sync, GUI, file locking, xattr/permission preservation, symlink following, key rotation, plaintext migration.

## Further considerations

1. **Binary/crate name** — `rfm` is short but collides with a few tools. Option A: `rfm`. Option B: `mirror`. Option C: something distinct like `skiff`.
2. **Passphrase caching for the daemon** — Option A (recommended): zeroized in-memory key for the daemon's lifetime, prompted once at start. Option B: OS keychain via `keyring`. Option C: re-prompt via the control socket.
3. **Empty directories** — S3 has no real directories. Option A (recommended): marker entries in the manifest. Option B: ignore them entirely (simpler, slightly lossy).
