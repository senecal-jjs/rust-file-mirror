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
rfm status          # show what a sync would do
rfm daemon status   # query a running `watch` over its control socket
rfm daemon stop     # ask a running `watch` to shut down
rfm doctor          # check config/bucket, report orphaned multipart uploads
```

Run it as a background service with `brew services start rfm` (macOS launchd) or a
systemd user unit on Linux.

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
   `cargo test -p mirror-core`), which also refreshes `Cargo.lock`.
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