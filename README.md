# Encrypted File Mirror (bring your own bucket)

Rust CLI, with daemon mode, to mirror a local root path to an S3 compatible bucket

## Install

```sh
brew install senecal-jjs/tools/rfm
```

Or build from source: `cargo install --path crates/mirror-cli`.

## Setup

**1. Configure S3 credentials.** `rfm` uses the AWS SDK's default credential chain, so the
simplest path is:

```sh
aws configure          # writes ~/.aws/credentials
```

For a named profile, use a profile at init time (below) or export `AWS_PROFILE`. Since
credentials come from `~/.aws`, not the shell environment, a user-level daemon
(launchd / `systemd --user`) picks them up automatically.

**2. Run `rfm init`.** It walks you through the bucket settings, writes a config to
`~/.config/rfm/config.toml`, then creates (or, on another device, verifies) the encrypted
vault and saves your passphrase locally so the daemon can run unattended:

```sh
rfm init
```

```text
S3 bucket: my-bucket
AWS region [us-east-1]:
Key prefix [rfm/]:
S3 endpoint URL (blank for AWS):
AWS profile (blank for default credential chain):
Local folder to mirror: /path/to/folder
Enter passphrase
Confirm passphrase
```

Non-interactive / scripted setups can pass everything as flags instead
(`rfm init --bucket my-bucket --root /path/to/folder --region us-east-1 …`), and
`rfm init --reconfigure` re-runs the prompts against an existing config.

> **No recovery:** if the passphrase is lost, the encrypted data cannot be decrypted.

Prefer to manage the config by hand? Edit `~/.config/rfm/config.toml` (or point at any path
with `--config` / `RFM_CONFIG`):

```toml
[remote]
bucket       = "my-bucket"
prefix       = "rfm/"                  # must end with '/'
region       = "us-east-1"
# endpoint   = "http://localhost:9000" # for MinIO / other S3-compatible stores
# path_style = true                    # required for MinIO
# profile    = "rfm"                   # optional named AWS profile

[local]
root = "/path/to/folder/to/mirror"

# [sync]                               # optional; defaults shown
# poll_interval_secs = 60
# debounce_secs = 2
```

## Usage

```sh
rfm sync            # one-shot: reconcile local <-> bucket
rfm watch           # foreground daemon: sync on local changes and on a poll interval
rfm watch --tui     # the same, with a live dashboard instead of log lines
rfm tui             # attach a live dashboard to an already-running `watch`
rfm status          # show what a sync would do
rfm daemon status   # query a running `watch` over its control socket
rfm daemon sync     # ask a running `watch` to sync now
rfm daemon backup   # ask a running `watch` to take a backup snapshot now
rfm daemon stop     # ask a running `watch` to shut down
rfm doctor          # check config/bucket, report orphaned multipart uploads
```

Run it as a background service with `brew services start rfm` (macOS launchd) or a
systemd user unit on Linux.

The dashboard (`watch --tui`, or `rfm tui` against a background service) shows the sync
status, in-flight transfers with progress, and a scrollable activity log. Keys: `q` quit,
`s` sync now, `↑`/`↓`/`PgUp`/`PgDn` scroll, `c` clear the log. Quitting `rfm tui` leaves
the daemon running. Set `RFM_LOG` (e.g. `RFM_LOG=mirror_core=debug`) to change what
reaches the activity log.

## Backups

The mirror copies deletions and overwrites to every device, so on its own it isn't a
backup. `rfm backup` adds encrypted, deduplicated point-in-time snapshots to the same
bucket, under `<prefix>backup/`, unlocked by the same vault passphrase:

```sh
rfm backup create                      # snapshot the mirrored root
rfm backup create ~/Projects --exclude node_modules --tag weekly
rfm backup list                        # every snapshot, newest first
rfm backup list latest                 # the files in one snapshot
rfm backup restore latest --target /tmp/restored
rfm backup restore a1b2c3d4 --target /tmp/restored --include '*.pdf'
rfm backup verify                      # cheap metadata check; run it routinely
rfm backup verify --read-data          # download and check every byte
rfm backup prune --keep-daily 7 --keep-weekly 4 --dry-run
rfm backup prune                       # by the [backup.keep] rules in the config
```

- **Incremental.** Unchanged files (same size, mtime, ctime, inode, and mode as in the
  last snapshot of the same paths from this host) aren't read again. Changed files are
  split into content-defined chunks, and only chunks the bucket doesn't already hold are
  uploaded, so an edit to a large file costs roughly the bytes around the edit.
- **Mirror-aware.** Backing up the mirrored root follows the mirror's rules: `.mirror/`
  (which holds the saved passphrase) is never backed up, and `.mirrorignore` patterns are
  honored (`--no-mirrorignore` to include them anyway).
- **Offloaded files are backed up too**, under their real names and with their real
  content. A file backed up before it was offloaded is matched by content hash and costs
  nothing. Otherwise its content is streamed from the mirror's copy in the bucket once,
  checked against the placeholder's hash, and reused from then on. Placeholders record
  the file's mode and mtime so restores get them back; placeholders made by older
  versions restore with mode `0644`. `--skip-offloaded` (or `offloaded = "skip"`) leaves
  them out.
- **Safe to interrupt.** Data is written first and the snapshot last, so a failed or
  cancelled (Ctrl-C) run never leaves a snapshot that can't be restored. Unreadable files
  are skipped with a warning; a failed upload stops the run.
- **Restores never write outside the target** and never replace existing files or links
  unless you pass `--overwrite`. Original absolute paths are recreated beneath the target.
- **Pruning** forgets snapshots by retention rules (`--keep-last`, `--keep-hourly`,
  `--keep-daily`, `--keep-weekly`, `--keep-monthly`, `--keep-yearly`), applied separately
  to each host and set of paths, then deletes data no remaining snapshot uses. Packs that
  are mostly unneeded are rewritten with only their live data. `--dry-run` shows what
  would go without deleting anything.
- **Safe across devices.** Backups and prunes coordinate through lock objects in the
  bucket: a prune waits until no backup is running anywhere, and a backup whose lock was
  removed while it ran (a laptop that slept for half an hour, say) refuses to publish
  its snapshot. Locks left by crashed processes expire after 30 minutes.
- Snapshot and index metadata is cached under your user cache directory
  (`~/Library/Caches/rfm/backup` on macOS); it's only an optimization, and `--no-cache`
  skips it.

### Scheduled backups

`rfm watch` takes backups on a schedule when `[backup]` sets an interval. The schedule
follows the latest snapshot's time in the bucket, so restarts and sleep don't reset it,
and backups run alongside syncs:

```toml
[backup]
interval_hours = 24            # 0 (the default) turns scheduled backups off
# paths   = ["/path/to/folder"]  # defaults to the mirrored root
# exclude = ["*.iso", "node_modules"]
# mirrorignore = true          # follow .mirrorignore when backing up the root
# offloaded = "include"        # back up offloaded files' content ("skip" to leave them out)
auto_prune = true              # prune by [backup.keep] after each scheduled backup

[backup.keep]
daily   = 7
weekly  = 4
monthly = 12
```

`rfm daemon status` and the dashboards show the last backup's result.

## How secrets are stored

`rfm init` writes your passphrase to `<root>/.mirror/passphrase` with `0600` permissions.
It's a plaintext-at-rest secret protected only by file permissions — consistent with the
threat model: **`rfm` protects your data at rest in the bucket, not against a compromised
local machine.** The passphrase can instead be supplied via `RFM_PASSPHRASE` or
`RFM_PASSPHRASE_FILE`. There is no OS keyring dependency, so the daemon runs headless on
both macOS and Linux.

## Cutting a New Release

Releases are automated. A single command bumps the version, runs the checks, and
pushes a tag; the `vX.Y.Z` tag triggers the GitHub Actions pipeline that builds
the binaries, publishes the release, and updates the Homebrew tap.

```sh
just release 0.2.0
```

The `just release <version>` recipe:

1. Refuses to run on a dirty working tree, so the tag captures exactly what's committed.
2. Bumps the version in `crates/mirror-cli/Cargo.toml` — this is what `rfm --version`
   reports (via clap) and **must** match the tag. Only the binary crate is versioned;
   `mirror-core` stays internal.
3. Runs `just check` (`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test -p mirror-core`, `cargo test -p mirror-cli`), which also refreshes `Cargo.lock`.
4. Commits, creates an annotated `vX.Y.Z` tag, and pushes the branch and the tag.

### What the pipeline does (on a `v*` tag push)

`.github/workflows/release.yml` runs three jobs:

1. **build** — compiles `rfm` natively on `macos-14` (arm64) and `macos-13` (x86_64),
   tarring each with a `.sha256`.
2. **release** — creates the GitHub Release `vX.Y.Z` with both tarballs + checksums.
3. **bump-cask** — regenerates `Casks/rfm.rb` in `senecal-jjs/homebrew-tools` with the
   new version and the two fresh shas, and commits it.

### One-time prerequisites

- `Cargo.lock` is committed (the build uses `--locked`).
- Repo secret `HOMEBREW_TAP_TOKEN`: a token with `contents:write` on
  `senecal-jjs/homebrew-tools` (the default `GITHUB_TOKEN` cannot push to another repo).

### Installing / updating (users)

```sh
brew update
brew upgrade rfm        # or: brew install senecal-jjs/homebrew-tools/rfm
rfm --version           # matches the released tag
```

### Amazon IAM policy Example
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BucketLevel",
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:ListBucketMultipartUploads"],
      "Resource": "bucket arn"
    },
    {
      "Sid": "Objects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload"
      ],
      "Resource": [
        "bucket-arn/rfm/*", (rfm is the prefix chosen during init)
      ]
    }
  ]
}
```

### Notes

- To fix a bad release, bump forward (e.g. `0.2.1`) rather than moving an existing tag —
  users who already pulled the old artifact won't re-download a moved tag.
- If `bump-cask` fails (e.g. an expired token), the GitHub Release is still published;
  re-run just that job after fixing the token.