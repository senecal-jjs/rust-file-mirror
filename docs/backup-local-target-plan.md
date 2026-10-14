# Plan: back up to a local drive as well as the bucket

Let `rfm backup` write to a folder on an external drive (or any local or network
filesystem) as well as the S3 bucket. The drive is a second, independent repository
with its own snapshots, schedule and retention, and it can be restored from with
nothing but the drive and the passphrase.

## Decisions

These are the recommendations from the exploration. Say if any should change.

1. **Independent repositories.** Each target is a full repository written by its own
   backup run. Nothing is copied from S3 to the drive, which would mean downloading
   everything and depending on the bucket. And no single run writes both, which would
   tie their failures together: an unplugged drive would fail the bucket backup.
2. **Restore from the drive alone.** The drive keeps a copy of the vault's public
   header, so a restore needs no network.
3. **Schedule only, at first.** Backing up as soon as the drive is mounted is a later
   phase.
4. **Retention per target,** so the drive can keep more history than the bucket.

## What we have to work with

- **The backup code uses six storage operations:** `put_bytes`, `get`, `get_range`,
  `head`, `delete` and `list` (plus test hooks). All of them map directly onto files
  in a folder.
- **The repository format makes no S3 assumptions.** Objects are immutable files with
  hex names (`config`, `packs/<ab>/<id>`, `indexes/<id>`, `snapshots/<id>`,
  `locks/<id>`), and pack sizes (~16 MB) are well under any filesystem's limit.
- **The keys come from the vault:** `derive_enc_keys` loads `<prefix>vault.json` from
  the store, derives the subkeys from the passphrase with Argon2id, and checks them
  against the header's key check. `vault::load` is generic over the store, and the
  header holds no secrets (salt, KDF parameters, key check).
- **`repo::base(prefix)` is `<prefix>backup/`.** So a drive folder laid out like a
  bucket prefix (`vault.json` at its root, the repository under `backup/`) works with
  the existing vault and repository code given the prefix `""`.

## Drive layout

```
/Volumes/Backup/rfm/              ← the target's `path`
  vault.json                      copy of the bucket's vault header (no secrets)
  .metadata_never_index           keeps Spotlight out
  backup/
    config  packs/  indexes/  snapshots/  locks/
```

The same keys encrypt both repositories. That's safe, because each has its own random
ID and every object is bound to its own ID. It also means identical content gets the
same blob ID in both, which a later `rfm backup copy` could use to copy packs without
re-encrypting them.

## Design

### 1. A smaller storage trait

`ObjectStore` also carries the mirror's multipart machinery (`begin_put`,
`resume_put`, part sinks and sources). A drive store shouldn't have to fake that.

- **Add `BlobStore`** in `mirror_core::store` with the six operations backups use, and
  a blanket `impl<T: ObjectStore> BlobStore for T`, so `S3Store` and `MemoryStore` get
  it for free.
- **Make `backup-core` generic over `S: BlobStore`** instead of `ObjectStore`. This is
  mechanical: the bounds change, and the calls are identical.
- **`vault::load` and `vault::create` move to `BlobStore`** too.

### 2. `LocalStore`

`mirror_core::store::local::LocalStore`, rooted at a directory. Keys are relative
paths, rejecting `..`, absolute paths and empty components.

| Operation | Implementation |
|---|---|
| `put_bytes` | Write to `<dir>/.tmp-<random>`, `fsync`, rename onto the key, `fsync` the parent directory, so a drive unplugged mid-write never leaves a partial object under a real name |
| `get` | Read the file; missing → the same not-found error the other stores give |
| `get_range` | Positioned read (`read_exact_at`); errors past the end, like the other stores |
| `head` | `metadata`: size, and mtime as `last_modified` (locks use it, so ages are local-clock times, consistent on one machine) |
| `delete` | Remove the file, then empty parent directories up to the root; missing is fine |
| `list` | Recursive walk under the prefix's directory, keys returned relative to the root and sorted; temp files skipped |

Directories are created on demand, except the root (section 3).

### 3. Never create a repository by accident

When the drive isn't mounted, `/Volumes/Backup` doesn't exist, and creating it would
quietly fill the boot disk. So:

- `LocalStore::open(root)` requires `root` to exist and **never creates it**.
- Only `rfm backup init --to <target>` creates a target's repository. It requires the
  target's parent directory to exist, refuses a folder that's already a repository or
  isn't empty, then writes `vault.json`, `.metadata_never_index` and the repository
  config.
- Every other command requires `<path>/backup/config` to exist. Otherwise it reports
  "<target> isn't connected (no repository at <path>)". The daemon treats that as
  "skipped", not failed (section 6).
- Initialization also records the drive's volume UUID (`diskutil info -plist`) in a
  small `target.json` beside `vault.json`. Later runs warn if a different volume is
  mounted at the same path, which catches a different drive given the same name.

### 4. Keys for a drive target

- **When the bucket is reachable:** use the bucket's vault, as today. The drive's copy
  of `vault.json` is refreshed if it differs. That's normally never, since the vault
  doesn't change.
- **When it isn't, or for `--offline`:** load `vault.json` from the drive and derive
  the keys from it with the same passphrase resolution (`RFM_PASSPHRASE`, the saved
  passphrase file, or a prompt). Restore, list and verify from a drive then work with
  no network and no config beyond the target's path.
- **Disaster recovery:** `rfm backup restore --from-path /Volumes/Backup/rfm …` opens a
  drive repository given only its path, with no config at all. That's the "my laptop
  is gone" path, and it gets a README section.

### 5. Config and CLI

```toml
[backup]                     # the bucket target, unchanged
interval_hours = 24
[backup.keep]
daily = 7

[[backup.target]]
name = "drive"
path = "/Volumes/Backup/rfm"
interval_hours = 24          # each field defaults to [backup]'s
# paths, exclude, mirrorignore, offloaded: also default to [backup]'s
auto_prune = true
[backup.target.keep]
daily = 30
weekly = 12
monthly = 12
```

- `BackupConfig` gains `targets: Vec<BackupTarget>`. The bucket stays the implicit
  target `bucket`. Validation rejects duplicate or reserved names, relative paths,
  and `auto_prune` without keep rules.
- **Commands take `--to` / `--from <name>`:**
  - `rfm backup init --to drive` (creates the drive repository; the bucket's is still
    created on its first `create`);
  - `rfm backup create --to drive`;
  - `rfm backup list|restore|verify|prune --from drive`.
- **Defaults:** without a flag, commands act on the bucket, so nothing changes for
  existing users. `--to all` backs up every target in turn, skipping disconnected
  drives with a note.
- **Locking:** the per-root local backup lock is shared by all targets, so two backups
  never read the root at once. Each repository's own lock is separate.
- `rfm doctor` lists each target: connected or not, snapshot count, last backup.

### 6. Daemon and tray

- **The backup worker loops over targets** at each 5-minute check:
  - each due target is backed up in turn, never in parallel, because they share the
    local lock and the disk reads;
  - a disconnected drive is skipped silently and checked again next time;
  - `auto_prune` runs per target.
- **Status per target:** `DaemonStatus` and the wire `Snapshot` gain
  `targets: Vec<TargetStatus>` (name, connected, running, last backup). It defaults
  when missing, so older clients and newer daemons keep working. The existing
  `last_backup` field stays, meaning the bucket.
- **Display:**
  - `daemon status` gains a line per target, for example
    `drive: ok, 2 days ago (not connected)`;
  - the tray shows a line per target, and **Back Up Now** becomes a submenu (*All*,
    *Bucket*, *Drive*) when there's more than one target;
  - `rfm daemon backup [--to name]`.

### 7. Offloaded files

Offloaded files' content is reused only from the same repository's earlier snapshots.
So the first drive backup of each offloaded file fetches it from S3 through the
existing source, and later drive backups reuse it. This goes in the README.

## Edge cases

| Case | Behavior |
|---|---|
| Drive unplugged mid-backup | Writes fail; the run's sticky failure stops it and no snapshot is written. Atomic renames mean no partial objects. `LocalStore::open` deletes temp files over an hour old (`list` never shows them, so `prune` can't). Unreferenced packs are removed by `prune` as usual. |
| Drive full | Same as a failed write: no snapshot. `doctor` and the summary report free space when a write fails with `ENOSPC`. |
| Different drive at the same mount path | Volume UUID mismatch: refuse, with instructions (`rfm backup init` it, or fix the path) |
| Drive mounted read-only | The lock write fails: "drive is read-only"; restore and list still work |
| Network share (SMB/NFS) as a target | Works; `fsync` and rename semantics depend on the server. Documented as best effort. |
| Bucket unreachable, drive connected | Drive backups keep working (keys from the drive's vault copy) |
| The vault is re-initialized under a new prefix | The drive's vault copy is stale: the key check fails clearly; `rfm backup init --to drive` on a fresh folder starts over |

## Phases

1. **`BlobStore` and `LocalStore`.** The trait split, a generic `backup-core`, and
   `LocalStore` with path validation, atomic durable writes and recursive list.
   Tests: a store conformance suite run against `MemoryStore` and `LocalStore` (round
   trips, ranges past the end, list ordering and prefixes, delete pruning
   directories, a missing root refused, `..` refused). The existing archiver,
   restore, verify and prune tests also run against `LocalStore` in a temp dir.
2. **Drive repositories and keys.** The layout, `init` (vault copy, never-index marker,
   volume UUID), the existence checks, and key derivation from the drive's vault.
   Tests: init refuses unsafe folders; an unmounted path is reported as disconnected;
   a backup, then a restore using only the drive's vault and the passphrase, round
   trips.
3. **Config and CLI.** `[[backup.target]]`, `--to`/`--from`, `--to all`,
   `--from-path`, `doctor`. Tests: config parsing and inheritance, validation, and
   CLI output for a connected and a disconnected target.
4. **Daemon and tray.** Per-target scheduling, skip-when-disconnected, per-target
   status in the protocol and in `daemon status`, the tray's lines and the
   Back Up Now submenu. Tests: the scheduler skips disconnected targets and runs due
   ones in turn; tray snapshot tests with two targets, one disconnected; old and new
   hello messages both parse.
5. **Docs and a real-drive check.** README sections on drive targets, disaster
   recovery from a drive, and offloaded files. Then a manual run with a USB drive or
   a disk image (`hdiutil create -size 1g -fs APFS`, which also covers unmounting
   mid-backup): init, create, unmount, check the scheduled backup is skipped, remount,
   back up, restore with the network off.

Later, not in this plan:
- back up as soon as the drive is mounted (watching `/Volumes`, or DiskArbitration);
- `rfm backup copy --from bucket --to drive` (copying packs as they are, since the
  keys are shared);
- pack size tuning for local targets.

## Size

| Piece | Rough size |
|---|---|
| `BlobStore` split and generic `backup-core` | ~100 changed lines |
| `LocalStore` and conformance tests | ~250 plus ~200 tests |
| Drive init, checks, keys from the drive's vault | ~200 |
| Config, CLI, `doctor` | ~250 |
| Daemon and tray per-target | ~250 |
| Docs | a few README sections |
