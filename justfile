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
# Live evals (tests/evals.rs) self-skip under plain `cargo test` — see `just
# evals` to actually run them.
test:
    cargo test

# Hits OpenRouter and spends tokens; needs OPENROUTER_API_KEY in the env or
# .env. Runs the live-eval tier (DESIGN.md §6 last bullet, docs/EVALS.md)
# against the SHIPPED provider chain (llm::build_chain from config/env — an
# eval against a different model than production ships is a comfortable
# lie). On an all-green run, writes .opsclaw-eval-marker, which `release`
# checks before tagging. The model pin comes from the single checked-in
# `.github/workflows/eval-models.env` (gianna's pattern) unless
# OPENROUTER_MODELS is already set — so local runs and the scheduled
# evals.yml workflow measure the SAME chain.
evals:
    #!/usr/bin/env sh
    set -e
    [ -f .env ] && { set -a; . ./.env; set +a; }
    [ -n "${OPENROUTER_API_KEY:-}" ] || { echo "✗ OPENROUTER_API_KEY not set (env or .env)"; exit 1; }
    if [ -z "${OPENROUTER_MODELS:-}" ]; then
      set -a; . ./.github/workflows/eval-models.env; set +a
    fi
    echo "↳ evals against OPENROUTER_MODELS=${OPENROUTER_MODELS:-<default>}"
    OPSCLAW_LIVE_EVALS=1 cargo test --test evals -- --nocapture

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
    # HARD eval gate (DESIGN.md §6 "Live eval tier"): refuse to tag unless
    # evals ran green RECENTLY. Two sources of evidence, strongest first:
    # (1) the scheduled evals.yml workflow's latest run, queried via `gh run
    #     list` (gianna's gate) — a scheduled run can't be faked by running
    #     evals once and tagging releases for months against a stale pass.
    #     Only consulted when the repo has a GitHub remote and `gh` is
    #     authenticated; this repo is currently local-only, so
    # (2) the local .opsclaw-eval-marker (written only on an all-green `just
    #     evals`), fresh = within the last 7 days — a stale marker is as
    #     unsafe as no marker (a model/prompt regression merged since would
    #     ship unchecked).
    # Emergency override: `EVALS_OVERRIDE=1 just release X.Y.Z` (the skip
    # reason is echoed so it's visible in the release output).
    if [ "${EVALS_OVERRIDE:-}" = "1" ]; then
      echo "⚠ EVALS_OVERRIDE=1 — skipping the eval-green gate (emergency release)."
    elif git remote get-url origin >/dev/null 2>&1 && command -v gh >/dev/null 2>&1 \
         && conclusion=$(gh run list --workflow evals.yml --event schedule --limit 1 \
              --json conclusion,updatedAt --jq '.[0].conclusion // empty' 2>/dev/null) \
         && [ -n "$conclusion" ]; then
      if [ "$conclusion" = "success" ]; then
        echo "✓ latest scheduled eval run is green (gh run list, evals.yml)"
      else
        echo "✗ latest scheduled eval run concluded: $conclusion — fix evals or"
        echo "  EVALS_OVERRIDE=1 just release $ver to bypass."
        exit 1
      fi
    elif [ ! -f .opsclaw-eval-marker ]; then
      echo "✗ no .opsclaw-eval-marker — evals have never run green. Run 'just evals'"
      echo "  (needs OPENROUTER_API_KEY), or EVALS_OVERRIDE=1 just release $ver to bypass."
      exit 1
    else
      age_days=$(( ($(date +%s) - $(date -r .opsclaw-eval-marker +%s 2>/dev/null || echo 0)) / 86400 ))
      if [ "$age_days" -gt 7 ]; then
        echo "✗ .opsclaw-eval-marker is $age_days days old (>7) — re-run 'just evals', or"
        echo "  EVALS_OVERRIDE=1 just release $ver to bypass."
        exit 1
      fi
      echo "✓ eval marker is fresh ($age_days day(s) old): $(cat .opsclaw-eval-marker)"
    fi
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
