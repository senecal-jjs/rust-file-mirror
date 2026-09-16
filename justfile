# Run `just` to list recipes.
default:
    @just --list

# The pre-release / CI gate: formatting, lints, and unit tests.
check:
    cargo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test -p mirror-core

# Cut a release: bump the binary crate's version, gate, commit, tag, and push.
# The `vX.Y.Z` tag triggers .github/workflows/release.yml. Usage: `just release 0.2.0`
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    # Refuse to release from a dirty tree so the tag captures exactly what's committed.
    if [ -n "$(git status --porcelain)" ]; then
        echo "working tree is dirty; commit or stash first" >&2
        exit 1
    fi
    echo "running version match check" >&2
    # Only the binary crate is versioned for releases — it's what `rfm --version`
    # (clap) reports and must match the tag. mirror-core stays internal.
    perl -i -pe 's/^version = ".*"/version = "{{version}}"/' crates/mirror-cli/Cargo.toml
    # `check` also refreshes Cargo.lock via the build, so the commit below captures it.
    just check
    # Re-releasing the same version is a no-op bump, so only commit if something changed.
    if [ -n "$(git status --porcelain)" ]; then
        git commit -am "release: v{{version}}"
    else
        echo "no version change to commit; tagging current HEAD" >&2
    fi
    # Fail early with a clear message rather than a confusing git error.
    if git rev-parse -q --verify "refs/tags/v{{version}}" >/dev/null; then
        echo "tag v{{version}} already exists" >&2
        exit 1
    fi
    git tag -a "v{{version}}" -m "release v{{version}}"
    git push origin HEAD
    git push origin "v{{version}}"
