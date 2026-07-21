# OpsClaw task runner. Install just: https://github.com/casey/just
# List recipes with: just   (or: just --list)

set dotenv-load := false

# Show available recipes.
default:
    @just --list

# Serve locally. OpsClaw's store is SQLite (no server to bring up); config is
# read from ~/.opsclaw/config.toml (or OPSCLAW_CONFIG) — see `opsclaw onboard`
# to create one. Live mode needs a reachable Hindsight (DESIGN.md §5, §7.6);
# point HINDSIGHT_URL at one (e.g. the docker-compose install) or run against
# fakes via the test suite instead of `serve` if you don't have one up.
serve:
    cargo run --bin opsclaw

# Run the operator CLI (pass args after the recipe, e.g. `just cli doctor`).
cli *ARGS:
    cargo run --quiet --bin opsclaw-cli -- {{ARGS}}

# Run the full test suite. No throwaway container needed: the repo parity
# suite runs unconditionally against SQLite under plain `cargo test`
# (AGENTS.md — this is the one thing gianna needed Postgres-in-CI for).
test:
    cargo test

# Format all code.
fmt:
    cargo fmt --all

# Check formatting without writing changes.
fmt-check:
    cargo fmt --all -- --check

# Lint with clippy, denying all warnings.
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Type-check without producing a binary.
check:
    cargo check --all-targets

# Supply-chain, licence, and advisory checks (requires cargo-deny).
deny:
    cargo deny check

# Assert applied migrations haven't drifted (a checksum mismatch crash-loops
# the daemon on boot — see AGENTS.md). Every migration file that existed at
# the last release tag must be byte-identical; new files are fine. Runs in CI
# and pre-release. Needs tags + history fetched to resolve the base ref.
check-migrations:
    ./scripts/check-migration-immutability.sh

# Everything CI should enforce.
ci: fmt-check clippy test deny check-migrations

# Cut a release end to end, e.g. `just release 0.3.0`: bump the version, run
# CI, commit master, then tag. No push — nothing here touches a remote; that
# stays an explicit separate step (AGENTS.md: never push without being asked).
# Idempotent on the bump (a no-op if Cargo.toml is already at the version), so
# a re-run after a mid-flight failure is safe.
release version:
    #!/usr/bin/env sh
    set -e
    v="{{version}}"
    case "$v" in v*) ;; *) v="v$v" ;; esac
    ver="${v#v}"
    if git rev-parse -q --verify "refs/tags/$v" >/dev/null; then
      echo "✗ tag $v already exists"; exit 1
    fi
    # Bump Cargo.toml + Cargo.lock to the target version (idempotent).
    crate="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')"
    if [ "$crate" != "$ver" ]; then
      sed -i.bak "0,/^version = \".*\"/s//version = \"$ver\"/" Cargo.toml && rm -f Cargo.toml.bak
      cargo update -p opsclaw --precise "$ver" >/dev/null 2>&1 || cargo check -q
      echo "bumped $crate → $ver"
    fi
    # A dirty worktree is allowed: only the version bump is committed below (the
    # release never sweeps up unrelated changes), so in-flight work can coexist.
    # The release tags whatever is on master — make sure intended work is COMMITTED
    # before releasing; uncommitted changes are excluded from the release by design.
    dirty="$(git status --porcelain -- ':!Cargo.toml' ':!Cargo.lock')"
    [ -z "$dirty" ] || { echo "⚠ uncommitted changes (NOT included in this release):"; echo "$dirty"; }
    # Run CI BEFORE committing/tagging, so a red tree never gets tagged.
    just ci
    # TODO(evals): once a live-eval workflow exists (gianna's Evals workflow,
    # IMPLEMENTATION plan / DESIGN.md §6 "Live eval tier"), add the hard gate
    # here: refuse to tag unless the last scheduled eval run is green, with an
    # EVALS_OVERRIDE=1 emergency bypass. No eval suite exists yet, so there is
    # nothing to gate on.
    if ! git diff --quiet -- Cargo.toml Cargo.lock; then
      git add Cargo.toml Cargo.lock
      git commit -q -m "chore(release): v$ver"
    fi
    last="$(git describe --tags --abbrev=0 2>/dev/null || true)"
    [ -n "$last" ] && range="$last..HEAD" || range="HEAD"
    echo; echo "Releasing $v with:"; git log --oneline "$range"; echo
    git tag -a "$v" -m "OpsClaw $v" -m "$(git log --format='- %s' "$range")"
    echo "✓ tagged $v locally — nothing pushed (push master and the tag explicitly when ready)"

# Build a release binary.
build:
    cargo build --release

# Remove build artifacts.
clean:
    cargo clean
