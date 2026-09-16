# Encrypted File Mirror (bring your own bucket)

Rust CLI, with daemon mode, to mirror a local root path to an S3 compatible bucket

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
brew upgrade rfm        # or: brew install senecal-jjs/tools/rfm
rfm --version           # matches the released tag
```

### Notes

- To fix a bad release, bump forward (e.g. `0.2.1`) rather than moving an existing tag —
  users who already pulled the old artifact won't re-download a moved tag.
- If `bump-cask` fails (e.g. an expired token), the GitHub Release is still published;
  re-run just that job after fixing the token.