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
    # Only the binary crate is versioned for releases — it's what `rfm --version`
    # (clap) reports and must match the tag. mirror-core stays internal.
    perl -i -pe 's/^version = ".*"/version = "{{version}}"/' crates/mirror-cli/Cargo.toml
    # `check` also refreshes Cargo.lock via the build, so the commit below captures it.
    just check
    git commit -am "release: v{{version}}"
    git tag -a "v{{version}}" -m "release v{{version}}"
    git push origin HEAD
    git push origin "v{{version}}"
